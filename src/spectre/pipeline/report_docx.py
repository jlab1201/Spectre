"""
report_docx.py — native Word (.docx) forensic report rendering for Phase 6.

Design principles:
  - Same input as report_pdf.py: report.md is the single source of truth.
  - Native Word styles (Heading 1-3, tables) so Word's Navigation Pane,
    native TOC, and Track Changes work naturally for the reviewing examiner.
  - Classification (DRAFT/APPROVED, from gate_7 AND the findings' examiner
    decisions) is read via report_pdf._classification —
    never re-derived here.
  - "Hairline" visual system: typography-led, no filled color blocks. Rules,
    whitespace and a single teal accent carry the design. Nothing is drawn
    outside the normal page margins, so nothing depends on Word's margin
    behaviour (see the full-bleed post-mortem in the design spec).

Rendering path:
  report.md → lightweight markdown-block parser → python-docx objects → .docx
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ── Markdown block model ──────────────────────────────────────────────
@dataclass
class Heading:
    level: int
    text: str


@dataclass
class Paragraph:
    text: str


@dataclass
class BulletList:
    items: list = field(default_factory=list)


@dataclass
class Table:
    header: list = field(default_factory=list)
    rows: list = field(default_factory=list)


@dataclass
class HRule:
    pass


@dataclass
class Span:
    """One inline run of text plus the marks that apply to it."""
    text: str
    bold: bool = False
    italic: bool = False
    code: bool = False


_HEADING_RE = re.compile(r'^(#{1,6})\s+(.*)$')
_HR_RE = re.compile(r'^-{3,}$')
# Bold before italic: **x** must not be read as *(*x*)*. The final alternative
# is _underscore-italic_ (group 4) — report.md emits BLUF/summary lines wrapped
# in underscores ("_Bottom-line-up-front: …_"); without this they printed the
# literal delimiters. The lookbehind/lookahead keep it from firing intraword
# (finding_id, exec_id) the way CommonMark's emphasis rules do.
_INLINE_RE = re.compile(
    r'\*\*(.+?)\*\*'                                   # 1: **bold**
    r'|`([^`]+)`'                                      # 2: `code`
    r'|\*([^*]+)\*'                                    # 3: *italic*
    r'|(?<![A-Za-z0-9_])_([^_]+)_(?![A-Za-z0-9_])'     # 4: _italic_
)


def _is_special_line(stripped: str) -> bool:
    if _HR_RE.match(stripped):
        return True
    if _HEADING_RE.match(stripped):
        return True
    if stripped.startswith("|"):
        return True
    if stripped.startswith("- "):
        return True
    return False


def _split_table_row(stripped: str) -> list:
    """Split a pipe-table row into cells. A trailing "|" is optional — GFM
    itself doesn't require one, and upstream markdown generation can drop
    trailing whitespace/pipes on wrap; treating a missing trailing pipe as
    "not a table row" silently drops the row (or worse, splits one table
    into two headerless ones)."""
    return [c.strip() for c in stripped.strip("|").split("|")]


def _parse_inline_runs(text: str) -> list:
    """Split inline markdown into Spans on **bold**, `code`, *italic* and
    _italic_.

    The markers are consumed, not printed — report.md wraps IOC values in
    backticks and caveat lines in asterisks, and a stray ` or * on the page
    reads as corruption in a report an examiner will sign."""
    spans = []
    pos = 0
    for m in _INLINE_RE.finditer(text):
        if m.start() > pos:
            spans.append(Span(text[pos:m.start()]))
        if m.group(1) is not None:
            spans.append(Span(m.group(1), bold=True))
        elif m.group(2) is not None:
            spans.append(Span(m.group(2), code=True))
        elif m.group(3) is not None:
            spans.append(Span(m.group(3), italic=True))
        else:
            spans.append(Span(m.group(4), italic=True))
        pos = m.end()
    if pos < len(text):
        spans.append(Span(text[pos:]))
    return spans


def _parse_markdown_blocks(md_text: str) -> list:
    """Parse report.md into a flat block list. Only handles the constructs
    _merge_report_md itself emits — not a general CommonMark parser."""
    lines = md_text.split("\n")
    blocks: list = []
    i = 0
    n = len(lines)

    while i < n:
        stripped = lines[i].strip()

        if not stripped:
            i += 1
            continue

        if _HR_RE.match(stripped):
            blocks.append(HRule())
            i += 1
            continue

        m = _HEADING_RE.match(stripped)
        if m:
            blocks.append(Heading(level=len(m.group(1)), text=m.group(2).strip()))
            i += 1
            continue

        if stripped.startswith("|"):
            header = _split_table_row(stripped)
            i += 1
            if i < n and re.match(r'^\|?[\s:|-]+\|?$', lines[i].strip()):
                i += 1
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(_split_table_row(lines[i].strip()))
                i += 1
            blocks.append(Table(header=header, rows=rows))
            continue

        if stripped.startswith("- "):
            items = []
            while i < n and lines[i].strip().startswith("- "):
                item = [lines[i].strip()[2:].strip()]
                i += 1
                # A wrapped bullet continues on the following indented lines;
                # without this they fall through to the paragraph branch and
                # the item is torn in half (bullet + orphan paragraph).
                while (i < n and lines[i].strip()
                       and not _is_special_line(lines[i].strip())):
                    item.append(lines[i].strip())
                    i += 1
                items.append(" ".join(item))
            blocks.append(BulletList(items=items))
            continue

        para_lines = [stripped]
        i += 1
        while i < n and lines[i].strip() and not _is_special_line(lines[i].strip()):
            para_lines.append(lines[i].strip())
            i += 1
        blocks.append(Paragraph(text=" ".join(para_lines)))

    return blocks


# ── Schema-ordered OOXML insertion ───────────────────────────────────
#
# OOXML property containers (w:pPr, w:rPr, w:tblPr, w:tcPr, w:trPr) are
# xsd:sequence types: their children MUST appear in the order the schema
# declares. Microsoft Word enforces this and SILENTLY DISCARDS elements that
# arrive out of order; LibreOffice tolerates any order, so a wrong-order bug
# renders perfectly in LibreOffice and vanishes in real Word. Every raw-oxml
# property below therefore goes through _insert_ordered rather than a bare
# .append(). See ECMA-376 Part 1, §17.3.1.26 (CT_PPr), §17.3.2.28 (CT_RPr),
# §17.4.60 (CT_TblPr), §17.4.70 (CT_TcPr), §17.4.82 (CT_TrPr).

_PPR_ORDER = [
    'pStyle', 'keepNext', 'keepLines', 'pageBreakBefore', 'framePr',
    'widowControl', 'numPr', 'suppressLineNumbers', 'pBdr', 'shd', 'tabs',
    'suppressAutoHyphens', 'kinsoku', 'wordWrap', 'overflowPunct',
    'topLinePunct', 'autoSpaceDE', 'autoSpaceDN', 'bidi', 'adjustRightInd',
    'snapToGrid', 'spacing', 'ind', 'contextualSpacing', 'mirrorIndents',
    'suppressOverlap', 'jc', 'textDirection', 'textAlignment',
    'textboxTightWrap', 'outlineLvl', 'divId', 'cnfStyle', 'rPr', 'sectPr',
    'pPrChange',
]

_RPR_ORDER = [
    'rStyle', 'rFonts', 'b', 'bCs', 'i', 'iCs', 'caps', 'smallCaps', 'strike',
    'dstrike', 'outline', 'shadow', 'emboss', 'imprint', 'noProof',
    'snapToGrid', 'vanish', 'webHidden', 'color', 'spacing', 'w', 'kern',
    'position', 'sz', 'szCs', 'highlight', 'u', 'effect', 'bdr', 'shd',
    'fitText', 'vertAlign', 'rtl', 'cs', 'em', 'lang', 'eastAsianLayout',
    'specVanish', 'oMath',
]

_TBLPR_ORDER = [
    'tblStyle', 'tblpPr', 'tblOverlap', 'bidiVisual', 'tblStyleRowBandSize',
    'tblStyleColBandSize', 'tblW', 'jc', 'tblCellSpacing', 'tblInd',
    'tblBorders', 'shd', 'tblLayout', 'tblCellMar', 'tblLook', 'tblCaption',
    'tblDescription',
]

_TCPR_ORDER = [
    'cnfStyle', 'tcW', 'gridSpan', 'hMerge', 'vMerge', 'tcBorders', 'shd',
    'noWrap', 'tcMar', 'textDirection', 'tcFitText', 'vAlign', 'hideMark',
]

_TRPR_ORDER = [
    'cnfStyle', 'divId', 'gridBefore', 'gridAfter', 'wBefore', 'wAfter',
    'cantSplit', 'trHeight', 'tblHeader', 'tblCellSpacing', 'jc', 'hidden',
]


def _local_name(el) -> str:
    return el.tag.split('}')[-1]


def _insert_ordered(parent, el, order: list) -> None:
    """Insert ``el`` into ``parent`` at its schema-mandated position,
    replacing any existing element of the same tag."""
    from docx.oxml.ns import qn

    tag = _local_name(el)
    for existing in parent.findall(qn(f'w:{tag}')):
        parent.remove(existing)

    idx = order.index(tag)
    for child in parent:
        child_tag = _local_name(child)
        if child_tag in order and order.index(child_tag) > idx:
            child.addprevious(el)
            return
    parent.append(el)


def _make(tag: str, **attrs):
    """Build an OxmlElement with w:-namespaced attributes."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    el = OxmlElement(tag)
    for key, value in attrs.items():
        el.set(qn(f'w:{key}'), str(value))
    return el


def _emu_to_twips(emu) -> int:
    return int(emu / 914400 * 1440)


# ── OOXML helpers ────────────────────────────────────────────────────
def _shade_cell(cell, hex_fill: str) -> None:
    """Set a table cell's background fill (no python-docx API exists)."""
    tcPr = cell._tc.get_or_add_tcPr()
    _insert_ordered(tcPr, _make('w:shd', val='clear', fill=hex_fill), _TCPR_ORDER)


def _shade_run(run, bg_hex: str, fg_hex: str) -> None:
    """Give a run a colored background (badge fill) and font color."""
    from docx.shared import RGBColor

    run.font.color.rgb = RGBColor.from_string(fg_hex)
    rPr = run._element.get_or_add_rPr()
    _insert_ordered(rPr, _make('w:shd', val='clear', fill=bg_hex), _RPR_ORDER)


def _add_letter_spacing(run, twips: int) -> None:
    """Character spacing in twentieths of a point — the OOXML equivalent of
    CSS letter-spacing; no python-docx high-level API for this."""
    rPr = run._element.get_or_add_rPr()
    _insert_ordered(rPr, _make('w:spacing', val=twips), _RPR_ORDER)


def _set_para_borders(paragraph_or_style, **edges) -> None:
    """Apply paragraph borders. Each keyword is an edge (top/bottom/left/
    right) mapped to (hex_color, sz_eighths_of_a_point, space_points)."""
    element = getattr(paragraph_or_style, 'element',
                      getattr(paragraph_or_style, '_p', None))
    pPr = element.get_or_add_pPr()
    pBdr = _make('w:pBdr')
    for edge in ('top', 'left', 'bottom', 'right'):
        if edge not in edges:
            continue
        color, sz, space = edges[edge]
        pBdr.append(_make(f'w:{edge}', val='single', sz=sz, space=space,
                          color=color))
    _insert_ordered(pPr, pBdr, _PPR_ORDER)


def _set_table_borders(table, **edges) -> None:
    """Apply table-level borders. Edges not named are explicitly set to nil,
    so a table with no keywords is fully borderless."""
    tblPr = table._tbl.tblPr
    borders = _make('w:tblBorders')
    for edge in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        if edge in edges:
            color, sz = edges[edge]
            borders.append(_make(f'w:{edge}', val='single', sz=sz, space='0',
                                 color=color))
        else:
            borders.append(_make(f'w:{edge}', val='nil'))
    _insert_ordered(tblPr, borders, _TBLPR_ORDER)


def _set_row_bottom_border(row, hex_color: str, sz: int) -> None:
    """Hairline under a single table row (drawn as each cell's bottom edge)."""
    for cell in row.cells:
        tcPr = cell._tc.get_or_add_tcPr()
        borders = _make('w:tcBorders')
        borders.append(_make('w:bottom', val='single', sz=sz, space='0',
                             color=hex_color))
        _insert_ordered(tcPr, borders, _TCPR_ORDER)


def _set_cell_margins(table, top: int, left: int, bottom: int, right: int) -> None:
    """Table-wide cell padding, in twips."""
    tblPr = table._tbl.tblPr
    cell_mar = _make('w:tblCellMar')
    for edge, value in (('top', top), ('left', left),
                        ('bottom', bottom), ('right', right)):
        cell_mar.append(_make(f'w:{edge}', w=value, type='dxa'))
    _insert_ordered(tblPr, cell_mar, _TBLPR_ORDER)


def _set_table_full_width(table) -> None:
    """Force a table to span the full content width (python-docx leaves the
    default 'auto' width, which Word renders narrower than the text column)."""
    tblPr = table._tbl.tblPr
    _insert_ordered(tblPr, _make('w:tblW', w='5000', type='pct'), _TBLPR_ORDER)


def _set_column_widths(table, widths) -> None:
    """Pin column widths (EMU). Must set the grid AND every cell, or Word
    recomputes them."""
    table.autofit = False
    for gridCol, width in zip(table._tbl.tblGrid.findall(
            '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}gridCol'),
            widths):
        gridCol.set('{http://schemas.openxmlformats.org/wordprocessingml/2006'
                    '/main}w', str(_emu_to_twips(width)))
    for row in table.rows:
        for cell, width in zip(row.cells, widths):
            cell.width = width


def _mark_table_header_row(row) -> None:
    """Mark a row to repeat as a header row on every page a table spans."""
    trPr = row._tr.get_or_add_trPr()
    _insert_ordered(trPr, _make('w:tblHeader', val='true'), _TRPR_ORDER)


def _mark_row_cant_split(row) -> None:
    """Prevent a single row's content from splitting across a page break."""
    trPr = row._tr.get_or_add_trPr()
    _insert_ordered(trPr, _make('w:cantSplit'), _TRPR_ORDER)


def _keep_with_next(paragraph) -> None:
    """Keep this paragraph on the same page as what follows it — stops a
    heading from being orphaned at the foot of a page, above its table."""
    pPr = paragraph._p.get_or_add_pPr()
    _insert_ordered(pPr, _make('w:keepNext', val='true'), _PPR_ORDER)


def _insert_toc_field(paragraph) -> None:
    """Insert a native Word TOC field into an existing (empty) paragraph.
    Word will not paginate this until the user opens the doc and updates the
    field once (References > Update Table) — python-docx cannot run Word's
    pagination engine."""
    run_begin = paragraph.add_run()
    run_begin._r.append(_make('w:fldChar', fldCharType='begin'))

    run_instr = paragraph.add_run()
    instr = _make('w:instrText')
    instr.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
    instr.text = 'TOC \\o "1-2" \\h \\z \\u'
    run_instr._r.append(instr)

    run_sep = paragraph.add_run()
    run_sep._r.append(_make('w:fldChar', fldCharType='separate'))

    paragraph.add_run(
        'Right-click here and choose "Update Field" to populate '
        "the table of contents."
    )

    run_end = paragraph.add_run()
    run_end._r.append(_make('w:fldChar', fldCharType='end'))


def _add_page_number_field(paragraph):
    """A live PAGE field, so the footer paginates itself."""
    run = paragraph.add_run()
    run._r.append(_make('w:fldChar', fldCharType='begin'))
    instr = _make('w:instrText')
    instr.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
    instr.text = 'PAGE'
    run._r.append(instr)
    run._r.append(_make('w:fldChar', fldCharType='end'))
    return run


# ── "Hairline" palette ───────────────────────────────────────────────
_TEAL = "0F6E6E"       # single accent: rules, small caps, links to structure
_INK = "1F2933"        # body + titles
_MUTED = "6B7280"      # labels, secondary metadata
_HAIRLINE = "D8DEDE"   # table row separators, footer rule
_AMBER = "8A6D1D"      # INFERRED badge only
_CONFIRMED_BG = "E4F3F0"
_INFERRED_BG = "F5F0E3"

# Border weights are in eighths of a point.
_SZ_HAIRLINE = 4       # 0.5pt
_SZ_RULE = 8           # 1.0pt
_SZ_ACCENT = 16        # 2.0pt
_SZ_BAR = 24           # 3.0pt


# ── Dashboard palette (spec §3 — SAME hex tokens as report_pdf.py, so the two
# formats read as one system). RGBColor.from_string wants an uppercase hex with
# no leading '#'. Severity is a STATUS palette (always icon+label); magnitude
# is the single-hue blue sequential ramp. ──
# TODO: extract shared report_palette helper (cross-format parity is
# hand-enforced) — docx uses bare-hex uppercase, report_pdf.py uses
# '#'-prefixed lowercase, so keep these two ramps in sync manually until then.
_SEVERITY_STYLE = {
    "CRITICAL":      ("D03B3B", "▲"),
    "HIGH":          ("EC835A", "◆"),
    "MEDIUM":        ("FAB219", "●"),
    "LOW":           ("0CA30C", "▪"),
    "INFORMATIONAL": ("8A897F", "▫"),   # out-of-palette → muted, carried honestly
    "UNRATED":       ("8A897F", "▫"),   # ▫ hollow
}
_SEQ_RAMP = ["CDE2FB", "9EC5F4", "256ABF", "0D366B"]   # light → dark

# Block-glyph bar: magnitude is encoded as the COUNT of U+2588 blocks, never as
# cell width — Word and LibreOffice compute table-cell widths differently (see
# the LibreOffice≠Word verification gap), and the file already fights autofit.
# Colour is redundant reinforcement. The glyphs are pinned to a font that
# carries block elements so they never fall back to tofu.
_BLOCK = "█"            # █ full block
_GLYPH_FONT = "DejaVu Sans"  # carries U+2588/2580 reliably; Calibri is the fallback
_MAX_GLYPHS = 40             # track cap; beyond this, glyph count is proportional


def _sev_style(sev: str) -> tuple:
    return _SEVERITY_STYLE.get((sev or "").upper(), _SEVERITY_STYLE["UNRATED"])


def _seq_color(value: int, vmax: int) -> str:
    """Map a magnitude to a sequential-ramp step (light→dark with value) —
    identical bucketing to report_pdf._seq_color for cross-format parity."""
    if vmax <= 0:
        return _SEQ_RAMP[0]
    frac = value / vmax
    idx = min(len(_SEQ_RAMP) - 1, int(round(frac * (len(_SEQ_RAMP) - 1))))
    return _SEQ_RAMP[idx]


def _glyph_count(value: int, vmax: int) -> int:
    """Number of block glyphs for ``value``. When the largest value in the
    group fits the track (vmax ≤ _MAX_GLYPHS) the mapping is exact 1:1 — a
    count of N renders N blocks, the load-bearing encoding — otherwise it is
    scaled proportionally into the fixed track (a documented fixed-scale
    mapping, spec §9)."""
    if value <= 0:
        return 0
    if vmax <= _MAX_GLYPHS:
        return value
    return max(1, int(round(value / vmax * _MAX_GLYPHS)))


def _lighten(hex_color: str, factor: float) -> str:
    """Blend a hex colour toward white by ``factor`` (0=unchanged, 1=white).
    Used for the INFERRED (lighter) segment of a confidence-split bar so the
    two statuses stay distinguishable in grayscale as well as colour."""
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    r = int(r + (255 - r) * factor)
    g = int(g + (255 - g) * factor)
    b = int(b + (255 - b) * factor)
    return f"{r:02X}{g:02X}{b:02X}"


def _style_run(run, *, size=None, color=None, bold=None, name=None,
               caps=False, spacing=None):
    """One place to set a run's typography, so callers stay readable."""
    from docx.shared import Pt, RGBColor

    if name:
        run.font.name = name
    if size is not None:
        run.font.size = Pt(size)
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    if bold is not None:
        run.font.bold = bold
    if caps:
        run.font.all_caps = True
    if spacing is not None:
        _add_letter_spacing(run, spacing)
    return run


def _add_rule(container, hex_color: str, sz: int, space_before=0, space_after=0):
    """A horizontal rule: an empty paragraph carrying a bottom border, with its
    line box collapsed to 1pt. Without the EXACTLY rule the paragraph inherits
    Normal's ~12pt line height and the border floats that far below whatever it
    is supposed to underline. The most portable 'hr' in Word."""
    from docx.enum.text import WD_LINE_SPACING
    from docx.shared import Pt

    p = container.add_paragraph()
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    p.paragraph_format.line_spacing = Pt(1)
    p.add_run().font.size = Pt(1)
    _set_para_borders(p, bottom=(hex_color, sz, 0))
    return p


def _add_spacer(container, points: float):
    """Vertical whitespace of an exact height. Cover composition depends on
    deterministic gaps, and space_before/space_after are subject to
    paragraph-spacing collapse rules; an EXACTLY-sized empty line is not."""
    from docx.enum.text import WD_LINE_SPACING
    from docx.shared import Pt

    p = container.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    p.paragraph_format.line_spacing = Pt(points)
    p.add_run().font.size = Pt(1)
    return p


def _add_section_label(doc, text: str):
    """Small letter-spaced teal caps over a hairline — used for the standalone
    front/back-matter pages (Document Control, Contents, Sign-Off) that are not
    part of report.md's heading tree and so must not enter the TOC."""
    from docx.shared import Pt

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    _style_run(p.add_run(text), size=9, color=_TEAL, bold=True, caps=True,
               spacing=60)
    _keep_with_next(p)
    _add_rule(doc, _TEAL, _SZ_RULE, space_before=0, space_after=16)
    return p


def _apply_base_styles(doc) -> None:
    """Single-sans-family, Hairline palette, applied once per document."""
    from docx.shared import Pt, RGBColor

    normal = doc.styles['Normal']
    normal.font.name = 'Calibri'
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string(_INK)
    normal.paragraph_format.space_after = Pt(8)
    normal.paragraph_format.line_spacing = 1.15

    h1 = doc.styles['Heading 1']
    h1.font.name = 'Calibri Light'
    h1.font.size = Pt(19)
    h1.font.color.rgb = RGBColor.from_string(_INK)
    h1.font.bold = False
    h1.paragraph_format.space_before = Pt(22)
    h1.paragraph_format.space_after = Pt(8)
    h1.paragraph_format.keep_with_next = True
    _set_para_borders(h1, bottom=(_TEAL, _SZ_RULE, 6))

    h2 = doc.styles['Heading 2']
    h2.font.name = 'Calibri'
    h2.font.size = Pt(12)
    h2.font.color.rgb = RGBColor.from_string(_TEAL)
    h2.font.bold = True
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(4)
    h2.paragraph_format.keep_with_next = True

    h3 = doc.styles['Heading 3']
    h3.font.name = 'Calibri'
    h3.font.size = Pt(10.5)
    h3.font.color.rgb = RGBColor.from_string(_INK)
    h3.font.bold = True
    h3.paragraph_format.space_before = Pt(10)
    h3.paragraph_format.space_after = Pt(2)
    h3.paragraph_format.keep_with_next = True


def _metadata_grid(container, rows_data, label_width, value_width):
    """The spec-sheet: a borderless label/value grid with a hairline under each
    row. Used on the cover, the document-control page and the sign-off page, so
    all three read as one system.

    ``rows_data`` is a list of (label, fill_value) where ``fill_value`` is a
    callable taking the value cell's first paragraph — the caller owns the
    value's typography (monospace hashes, shaded badges, blank signature
    lines)."""
    from docx.shared import Pt

    table = container.add_table(rows=0, cols=2)
    _set_table_borders(table)
    _set_cell_margins(table, top=90, left=0, bottom=90, right=0)
    _set_table_full_width(table)

    for label, fill_value in rows_data:
        row = table.add_row()
        _mark_row_cant_split(row)
        _set_row_bottom_border(row, _HAIRLINE, _SZ_HAIRLINE)

        label_cell, value_cell = row.cells
        label_cell.text = ""
        p_label = label_cell.paragraphs[0]
        p_label.paragraph_format.space_after = Pt(0)
        _style_run(p_label.add_run(label), size=8, color=_MUTED, bold=True,
                   caps=True, spacing=50)

        value_cell.text = ""
        p_value = value_cell.paragraphs[0]
        p_value.paragraph_format.space_after = Pt(0)
        fill_value(p_value)

    _set_column_widths(table, [label_width, value_width])
    return table


def _classification_badge(paragraph, classification: str) -> None:
    """DRAFT (amber) / APPROVED (teal) as a shaded small-caps chip."""
    run = paragraph.add_run(f"  {classification}  ")
    _style_run(run, size=8.5, bold=True, caps=True, spacing=60)
    if classification == "APPROVED":
        _shade_run(run, _CONFIRMED_BG, _TEAL)
    else:
        _shade_run(run, _INFERRED_BG, _AMBER)


def _add_cover_page(doc, manifest: dict) -> None:
    """The cover: a top rule and kicker, a left-barred typographic hero, and
    the metadata spec-sheet. Deliberately built from type, whitespace and
    hairlines only — no filled color blocks, so it never depends on Word's
    page-edge/margin behaviour (see the full-bleed post-mortem in the spec)."""
    from datetime import datetime, timezone

    from docx.enum.text import WD_TAB_ALIGNMENT
    from docx.shared import Inches, Pt

    from spectre.pipeline.report_pdf import _classification, _evidence_rows

    classification = _classification(manifest)
    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    case_ref = f"{case_id}-{case_name}"
    profile = manifest.get("artifact_profile", "?")
    canary = manifest.get("canary_status", "?")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Masthead: hairline, then wordmark left / classification chip right.
    _add_rule(doc, _TEAL, _SZ_ACCENT, space_after=7)

    p_kicker = doc.add_paragraph()
    p_kicker.paragraph_format.space_after = Pt(0)
    p_kicker.paragraph_format.tab_stops.add_tab_stop(
        Inches(6.5), WD_TAB_ALIGNMENT.RIGHT)
    _style_run(p_kicker.add_run("Spectre"), size=10, color=_TEAL, bold=True,
               spacing=40)
    p_kicker.add_run("\t")
    _classification_badge(p_kicker, classification)

    _add_spacer(doc, 225)

    # Hero: one paragraph, so the teal bar runs unbroken down the whole block.
    p_hero = doc.add_paragraph()
    p_hero.paragraph_format.space_before = Pt(0)
    p_hero.paragraph_format.space_after = Pt(0)
    p_hero.paragraph_format.left_indent = Inches(0.26)
    p_hero.paragraph_format.line_spacing = 1.0
    _set_para_borders(p_hero, left=(_TEAL, _SZ_BAR, 16))

    _style_run(p_hero.add_run("Digital Forensic Examination"), size=9,
               color=_TEAL, bold=True, caps=True, spacing=70)

    title = _style_run(p_hero.add_run(), name="Calibri Light", size=34,
                       color=_INK)
    title.add_break()
    title.add_text("Forensic Investigation")
    title.add_break()
    title.add_text("Report")

    ref = _style_run(p_hero.add_run(), name="Consolas", size=11, color=_MUTED)
    ref.add_break()
    ref.add_text(f"Case {case_ref}")

    _add_spacer(doc, 44)

    # Spec-sheet.
    def _plain(text, *, mono=False, size=10.5):
        def fill(paragraph):
            _style_run(paragraph.add_run(str(text)), size=size, color=_INK,
                       name="Consolas" if mono else None)
        return fill

    def _evidence(name, sha):
        def fill(paragraph):
            _style_run(paragraph.add_run(name), size=10.5, color=_INK)
            if sha:
                run = _style_run(paragraph.add_run(), name="Consolas", size=7.5,
                                 color=_MUTED)
                run.add_break()
                run.add_text(f"SHA-256  {sha}")
        return fill

    rows_data = [("Case Reference", _plain(case_ref, mono=True, size=10))]
    for name, sha in _evidence_rows(manifest):
        rows_data.append(("Evidence", _evidence(name, sha)))
    rows_data.extend([
        ("Artifact Profile", _plain(profile)),
        ("Environment", _plain(canary)),
        ("Generated", _plain(now)),
    ])

    _metadata_grid(doc, rows_data, Inches(1.7), Inches(4.8))

    doc.add_page_break()


def _add_doc_control_page(doc, manifest: dict) -> None:
    """Document control: the integrity record — classification, evidence
    hashes, environment, provenance. Mirrors report_pdf._build_doc_control."""
    from datetime import datetime, timezone

    from docx.shared import Inches, Pt

    from spectre.pipeline.report_pdf import _classification, _evidence_rows, _status_line

    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    profile = manifest.get("artifact_profile", "?")
    canary = manifest.get("canary_status", "?")
    classification = _classification(manifest)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    _add_section_label(doc, "Document Control")

    def _plain(text, *, mono=False):
        def fill(paragraph):
            _style_run(paragraph.add_run(str(text)), size=10.5, color=_INK,
                       name="Consolas" if mono else None)
        return fill

    def _badge(paragraph):
        _classification_badge(paragraph, classification)

    def _evidence(name, sha):
        def fill(paragraph):
            _style_run(paragraph.add_run(name), size=10.5, color=_INK)
            if sha:
                run = _style_run(paragraph.add_run(), name="Consolas", size=7.5,
                                 color=_MUTED)
                run.add_break()
                run.add_text(f"SHA-256  {sha}")
        return fill

    rows_data = [
        ("Case", _plain(f"{case_id}-{case_name}", mono=True)),
        ("Classification", _badge),
    ]
    for name, sha in _evidence_rows(manifest):
        rows_data.append(("Evidence", _evidence(name, sha)))
    rows_data.extend([
        ("Artifact Profile", _plain(profile)),
        ("Canary", _plain(canary)),
        ("Generated", _plain(now)),
        ("Pipeline", _plain("Spectre — 7-Phase Forensic Pipeline")),
        ("Status", _plain(_status_line(manifest))),
    ])

    _metadata_grid(doc, rows_data, Inches(1.7), Inches(4.8))

    p_note = doc.add_paragraph()
    p_note.paragraph_format.space_before = Pt(14)
    _style_run(p_note.add_run(
        "Evidence is held read-only and hash-verified. Every tool invocation "
        "is recorded in a SHA-256-chained audit trail (audit.jsonl); the chain "
        "is verified before this report is issued."
    ), size=9, color=_MUTED)

    doc.add_page_break()


def _add_toc_page(doc) -> None:
    """Native Word TOC field page."""
    from docx.shared import Pt

    _add_section_label(doc, "Contents")

    toc_para = doc.add_paragraph()
    _insert_toc_field(toc_para)

    p_note = doc.add_paragraph()
    p_note.paragraph_format.space_before = Pt(10)
    _style_run(p_note.add_run(
        "Word populates this table on first open — right-click the table and "
        "choose Update Field."
    ), size=9, color=_MUTED)

    doc.add_page_break()


_BADGE_RE = re.compile(r'(CONFIRMED|INFERRED)')


def _add_inline_runs(paragraph, text: str, *, size=None) -> None:
    """Render text into a paragraph, applying bold spans, monospace code spans,
    and CONFIRMED/INFERRED badge shading regardless of which span they fall
    in."""
    from docx.shared import Pt

    for span in _parse_inline_runs(text):
        for part in _BADGE_RE.split(span.text):
            if not part:
                continue
            run = paragraph.add_run(part)
            run.bold = span.bold
            if size is not None:
                run.font.size = Pt(size)
            if span.italic:
                run.italic = True
                _style_run(run, color=_MUTED)
            if span.code:
                _style_run(run, name="Consolas",
                           size=(size - 1) if size else 9.5)
            if part == "CONFIRMED":
                _style_run(run, bold=True, spacing=30)
                _shade_run(run, _CONFIRMED_BG, _TEAL)
            elif part == "INFERRED":
                _style_run(run, bold=True, spacing=30)
                _shade_run(run, _INFERRED_BG, _AMBER)


_MIN_COL_INCHES = 0.7
_MAX_COL_WEIGHT = 45   # chars; beyond this a column stops earning more width


def _content_column_widths(block, total_inches: float = 6.5) -> list:
    """Size columns from their widest cell.

    An even split shreds IOC columns — a 48-character domain in a 1.6in column
    wraps across four lines while "Type" wastes the same 1.6in. Word's own
    autofit would handle this, but w:tblLayout="autofit" is honoured
    inconsistently across renderers, so the widths are computed here and pinned
    explicitly: every column gets a floor, and the slack is shared out in
    proportion to the longest string each column actually has to hold."""
    from docx.shared import Inches

    n_cols = len(block.header)
    widest = []
    for idx in range(n_cols):
        cells = [block.header[idx]] + [
            row[idx] for row in block.rows if idx < len(row)
        ]
        widest.append(min(max((len(c) for c in cells), default=1),
                          _MAX_COL_WEIGHT))

    slack = total_inches - (_MIN_COL_INCHES * n_cols)
    if slack <= 0:
        return [Inches(total_inches / n_cols)] * n_cols

    total_weight = sum(widest) or 1
    return [Inches(_MIN_COL_INCHES + slack * w / total_weight) for w in widest]


def _render_table(doc, block) -> None:
    """Editorial table: no box, no zebra. A teal rule under the small-caps
    header, hairlines between rows, and generous cell padding."""
    from docx.shared import Pt

    n_cols = len(block.header)
    table = doc.add_table(rows=1, cols=n_cols)
    _set_table_borders(table)
    _set_cell_margins(table, top=80, left=0, bottom=80, right=140)
    _set_table_full_width(table)

    header_row = table.rows[0]
    for idx, text in enumerate(block.header):
        cell = header_row.cells[idx]
        cell.text = ""
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        _style_run(p.add_run(text), size=8, color=_TEAL, bold=True, caps=True,
                   spacing=50)
    _set_row_bottom_border(header_row, _TEAL, _SZ_ACCENT)
    _mark_row_cant_split(header_row)
    _mark_table_header_row(header_row)

    for row_data in block.rows:
        row = table.add_row()
        _mark_row_cant_split(row)
        _set_row_bottom_border(row, _HAIRLINE, _SZ_HAIRLINE)
        for idx in range(n_cols):
            cell = row.cells[idx]
            cell.text = ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.1
            _add_inline_runs(p, row_data[idx] if idx < len(row_data) else "",
                             size=9.5)

    _set_column_widths(table, _content_column_widths(block))

    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _render_blocks(doc, blocks: list) -> None:
    """Render parsed report.md blocks into the document body. Assumes
    _apply_base_styles has already run on doc."""
    for block in blocks:
        if isinstance(block, Heading):
            if block.level <= 1:
                continue  # title: already on the cover + doc-control page
            doc.add_heading(block.text, level=min(block.level - 1, 3))
        elif isinstance(block, Paragraph):
            _add_inline_runs(doc.add_paragraph(), block.text)
        elif isinstance(block, BulletList):
            for item in block.items:
                _add_inline_runs(doc.add_paragraph(style="List Bullet"), item)
        elif isinstance(block, Table):
            _render_table(doc, block)
        elif isinstance(block, HRule):
            # A section break in the source markdown; a hairline in the doc.
            _add_rule(doc, _HAIRLINE, _SZ_HAIRLINE, space_before=6,
                      space_after=6)


def _add_signoff_page(doc, manifest: dict) -> None:
    """Formal examiner sign-off, tied to the Phase 7 gate_7.passed approval
    flow. This page has no equivalent in report_pdf.py."""
    from docx.shared import Inches, Pt

    from spectre.pipeline.report_pdf import _classification

    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    classification = _classification(manifest)

    doc.add_page_break()
    _add_section_label(doc, "Examiner Sign-Off")

    p_intro = doc.add_paragraph()
    _add_inline_runs(p_intro, (
        f"By signing below the examiner certifies that the findings in this "
        f"report for case **{case_id}-{case_name}** have been reviewed against "
        f"the underlying evidence, and records their disposition."
    ))

    def _blank(paragraph):
        _style_run(paragraph.add_run(" "), size=10.5)

    grid = _metadata_grid(
        doc,
        [("Examiner Name", _blank), ("Signature", _blank), ("Date", _blank)],
        Inches(1.7), Inches(4.8),
    )
    for row in grid.rows:
        row.height = Inches(0.42)

    p_disp = doc.add_paragraph()
    p_disp.paragraph_format.space_before = Pt(22)
    p_disp.paragraph_format.space_after = Pt(2)
    _style_run(p_disp.add_run("Findings Disposition"), size=9, color=_TEAL,
               bold=True, caps=True, spacing=60)
    _keep_with_next(p_disp)
    _add_rule(doc, _HAIRLINE, _SZ_HAIRLINE, space_after=10)

    for option in ("Approved", "Approved with modifications", "Rejected"):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.left_indent = Inches(0.1)
        _style_run(p.add_run("☐"), size=13, color=_MUTED)
        _style_run(p.add_run(f"   {option}"), size=10.5, color=_INK)

    p_status = doc.add_paragraph()
    p_status.paragraph_format.space_before = Pt(20)
    _style_run(p_status.add_run("Current status: "), size=9, color=_MUTED)
    _classification_badge(p_status, classification)
    from spectre.pipeline.report_pdf import _status_line
    _style_run(p_status.add_run("  " + _status_line(manifest)), size=9,
               color=_MUTED)


def _add_classification_footer(doc, manifest: dict) -> None:
    """Running footer on every page: hairline, classification + case on the
    left, live page number on the right. Text-only — no watermark.

    Built as a borderless two-cell table rather than a tab stop: a right-aligned
    tab inside the built-in Footer style is honoured by neither Word nor
    LibreOffice here (the emitted w:tabs is correct; the renderers collapse it),
    which ran the page number into the case reference. Cells always land where
    they are told."""
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt

    from spectre.pipeline.report_pdf import _classification

    classification = _classification(manifest)
    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")

    from spectre.pipeline.report_pdf import _status_line
    status_line = (f"DRAFT — {_status_line(manifest)}" if classification == "DRAFT"
                   else "APPROVED")

    footer = doc.sections[0].footer
    for stale in list(footer.paragraphs):
        stale._p.getparent().remove(stale._p)

    table = footer.add_table(rows=1, cols=2, width=Inches(6.5))
    _set_table_borders(table, top=(_HAIRLINE, _SZ_HAIRLINE))
    _set_cell_margins(table, top=60, left=0, bottom=0, right=0)
    _set_table_full_width(table)

    left_cell, right_cell = table.rows[0].cells
    left_cell.text = ""
    p_left = left_cell.paragraphs[0]
    p_left.paragraph_format.space_after = Pt(0)
    _style_run(p_left.add_run(f"{status_line} · Case {case_id}-{case_name}"),
               size=8, color=_MUTED, spacing=10)

    right_cell.text = ""
    p_right = right_cell.paragraphs[0]
    p_right.paragraph_format.space_after = Pt(0)
    p_right.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _style_run(p_right.add_run("Page "), size=8, color=_MUTED)
    _style_run(_add_page_number_field(p_right), size=8, color=_MUTED)

    _set_column_widths(table, [Inches(4.6), Inches(1.9)])


# ── Assessment Dashboard (TB-port T8b) ─────────────────────────────────
# The DOCX dashboard renders the SAME persisted _dashboard_metrics dict the PDF
# reads (single source of truth — no recompute, no drift). Every magnitude is
# a COUNT of block glyphs in a bordered table cell, not a cell width, so it is
# robust to the Word-vs-LibreOffice autofit divergence. Honesty amendments
# (TB-PORT A1-A6) mirror report_pdf: qualified headline, coverage warning and
# tile, predicate-driven legend, ordinal tactics strip, provenance stamp.

def _add_glyph_bar(paragraph, n_solid: int, solid_hex: str,
                   n_light: int = 0, light_hex: str | None = None,
                   size: float = 9) -> None:
    """Append a block-glyph bar: ``n_solid`` blocks in ``solid_hex`` then
    ``n_light`` blocks in ``light_hex``. The glyph font is pinned so the
    blocks never fall back to tofu."""
    if n_solid > 0:
        run = paragraph.add_run(_BLOCK * n_solid)
        _style_run(run, size=size, color=solid_hex, name=_GLYPH_FONT)
    if n_light > 0 and light_hex:
        run = paragraph.add_run(_BLOCK * n_light)
        _style_run(run, size=size, color=light_hex, name=_GLYPH_FONT)


def _dash_note(doc, text: str, *, color: str | None = None,
               bold: bool = False) -> None:
    from docx.shared import Pt

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    _style_run(p.add_run(text), size=9, color=color or _MUTED, bold=bold)


def _dash_subtitle(doc, text: str) -> None:
    from docx.shared import Pt

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(3)
    _style_run(p.add_run(text), size=9, color=_TEAL, bold=True, caps=True,
               spacing=50)
    _keep_with_next(p)


def _dash_tiles(metrics: dict) -> list:
    """Stat tiles, shared shape with report_pdf._stat_tiles_html."""
    k = metrics.get("kpis") or {}
    cov = metrics.get("coverage") or {}
    tiles = [
        (k.get("findings_total", 0), "Findings"),
        (k.get("confirmed", 0), "Confirmed"),
        (k.get("inferred", 0), "Inferred"),
        (k.get("corroborated", 0), "Multi-source corroborated"),
        (k.get("mitre_techniques", 0), "MITRE techniques"),
    ]
    if cov.get("total"):
        tiles.append((f"{cov.get('examined', 0)}/{cov['total']}",
                      "Evidence examined"))
    else:
        tiles.append((k.get("evidence_items", 0), "Evidence items"))
    return tiles


def _add_stat_tiles(doc, metrics: dict) -> None:
    """A single-row bordered table, one cell per KPI (hero number over a
    small letter-spaced label)."""
    from docx.shared import Inches, Pt

    tiles = _dash_tiles(metrics)
    table = doc.add_table(rows=1, cols=len(tiles))
    _set_table_borders(
        table,
        top=(_HAIRLINE, _SZ_HAIRLINE), bottom=(_HAIRLINE, _SZ_HAIRLINE),
        left=(_HAIRLINE, _SZ_HAIRLINE), right=(_HAIRLINE, _SZ_HAIRLINE),
        insideV=(_HAIRLINE, _SZ_HAIRLINE),
    )
    _set_cell_margins(table, top=80, left=80, bottom=80, right=80)
    _set_table_full_width(table)
    _mark_row_cant_split(table.rows[0])
    for cell, (value, label) in zip(table.rows[0].cells, tiles):
        cell.text = ""
        p_val = cell.paragraphs[0]
        p_val.paragraph_format.space_after = Pt(0)
        _style_run(p_val.add_run(str(value)), size=18, color=_INK, bold=True)
        p_lbl = cell.add_paragraph()
        p_lbl.paragraph_format.space_before = Pt(0)
        p_lbl.paragraph_format.space_after = Pt(0)
        # Tight tracking: "MULTI-SOURCE CORROBORATED" must wrap at the space,
        # never mid-word, in a 1/6-width cell.
        _style_run(p_lbl.add_run(label), size=6.5, color=_MUTED, caps=True,
                   spacing=5)
    _set_column_widths(table, [Inches(6.5 / len(tiles))] * len(tiles))
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _add_headline(doc, metrics: dict) -> None:
    """A1: the deterministic, status-qualified threat headline + top rule
    severity, and the leads-only qualifier."""
    from docx.shared import Pt

    headline = metrics.get("threat_headline") or ""
    if headline:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        _style_run(p.add_run(headline), size=11, color=_INK, bold=True)
    top = metrics.get("top_severity")
    if top:
        color, glyph = _sev_style(top)
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        _style_run(p.add_run("Top rule severity: "), size=9, color=_MUTED)
        _style_run(p.add_run(glyph + " "), size=9, color=color, name=_GLYPH_FONT)
        _style_run(p.add_run(top), size=9, color=_INK, bold=True)
    if metrics.get("verdict_class") == "leads_only":
        _dash_note(doc, "Leads only — no finding reached CONFIRMED status. "
                        "Severity is the detection rule's rating if confirmed, "
                        "not an assessment of this case.", color=_INK, bold=True)


def _add_coverage_warning(doc, metrics: dict) -> None:
    """A3: shown whenever any evidence item went unexamined."""
    cov = metrics.get("coverage") or {}
    state = cov.get("state")
    if state not in ("partial", "no_coverage"):
        return
    detail = []
    if cov.get("failed"):
        detail.append(f"{cov['failed']} EXTRACTION_FAILED")
    if cov.get("empty"):
        detail.append(f"{cov['empty']} EMPTY")
    extra = f" ({', '.join(detail)})" if detail else ""
    unexamined = int(cov.get("total") or 0) - int(cov.get("examined") or 0)
    head = ("No evidence was examined — no assessment possible."
            if state == "no_coverage" else
            f"Partial coverage — {unexamined} of {cov.get('total')} evidence "
            f"item(s) were not examined.")
    _dash_note(doc, f"{head} {unexamined} of {cov.get('total')} item(s) not "
                    f"examined{extra}. Nothing in this report establishes the "
                    f"contents of an unexamined item — see Forensic Blind "
                    f"Spots.", color="D03B3B", bold=True)


def _add_severity_distribution(doc, metrics: dict) -> None:
    """One row per present severity — glyph+label, a block-glyph bar split
    into solid (CONFIRMED) and lighter (INFERRED) runs, and the total."""
    from docx.shared import Inches, Pt

    severity_counts = metrics.get("severity_counts") or []
    if not severity_counts:
        return
    k = metrics.get("kpis") or {}
    inferred_note = ("INFERRED (single-source)"
                     if k.get("inferred_single_source", -1) == k.get("inferred")
                     else "INFERRED")
    _dash_subtitle(doc, "Severity distribution")
    _dash_note(doc, f"█ solid = CONFIRMED · █ lighter = {inferred_note}. "
                    "Severity is the detection rule's rating from the case "
                    "ruleset snapshot (“how bad if confirmed”; UNRATED = the "
                    "rule sets no level); confidence is a separate axis, "
                    "shown by fill.")

    vmax = max((r.get("total", 0) for r in severity_counts), default=0)
    table = doc.add_table(rows=0, cols=3)
    _set_table_borders(table)
    _set_cell_margins(table, top=40, left=0, bottom=40, right=120)
    _set_table_full_width(table)
    for row_data in severity_counts:
        sev = row_data.get("severity", "UNRATED")
        color, glyph = _sev_style(sev)
        confirmed = int(row_data.get("confirmed", 0))
        inferred = int(row_data.get("inferred", 0))
        total = int(row_data.get("total", confirmed + inferred))
        row = table.add_row()
        _mark_row_cant_split(row)
        label_cell, bar_cell, count_cell = row.cells
        label_cell.text = ""
        p_lbl = label_cell.paragraphs[0]
        p_lbl.paragraph_format.space_after = Pt(0)
        _style_run(p_lbl.add_run(glyph + " "), size=9, color=color,
                   name=_GLYPH_FONT)
        _style_run(p_lbl.add_run(sev), size=8.5, color=_INK, bold=True,
                   spacing=30)
        bar_cell.text = ""
        p_bar = bar_cell.paragraphs[0]
        p_bar.paragraph_format.space_after = Pt(0)
        _add_glyph_bar(p_bar, _glyph_count(confirmed, vmax), color,
                       _glyph_count(inferred, vmax), _lighten(color, 0.55))
        count_cell.text = ""
        p_cnt = count_cell.paragraphs[0]
        p_cnt.paragraph_format.space_after = Pt(0)
        _style_run(p_cnt.add_run(str(total)), size=9, color=_MUTED, bold=True)
    _set_column_widths(table, [Inches(1.6), Inches(4.3), Inches(0.6)])
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _add_tactic_coverage(doc, tactic_coverage: list) -> None:
    """One row per ATT&CK tactic — a block-glyph bar of distinct technique
    count, sequential-blue, with the count text."""
    from docx.shared import Inches, Pt

    if not tactic_coverage:
        return
    _dash_subtitle(doc, "MITRE ATT&CK tactic coverage")
    _dash_note(doc, "Distinct techniques observed per tactic, in ATT&CK "
                    "tactic order.")
    vmax = max((t.get("technique_count", 0) for t in tactic_coverage), default=0)
    table = doc.add_table(rows=0, cols=3)
    _set_table_borders(table)
    _set_cell_margins(table, top=40, left=0, bottom=40, right=120)
    _set_table_full_width(table)
    for t in tactic_coverage:
        count = int(t.get("technique_count", 0))
        row = table.add_row()
        _mark_row_cant_split(row)
        name_cell, bar_cell, count_cell = row.cells
        name_cell.text = ""
        p_name = name_cell.paragraphs[0]
        p_name.paragraph_format.space_after = Pt(0)
        _style_run(p_name.add_run(str(t.get("tactic", ""))), size=8.5, color=_INK)
        bar_cell.text = ""
        p_bar = bar_cell.paragraphs[0]
        p_bar.paragraph_format.space_after = Pt(0)
        _add_glyph_bar(p_bar, _glyph_count(count, vmax), _seq_color(count, vmax))
        count_cell.text = ""
        p_cnt = count_cell.paragraphs[0]
        p_cnt.paragraph_format.space_after = Pt(0)
        _style_run(p_cnt.add_run(str(count)), size=9, color=_MUTED, bold=True)
    _set_column_widths(table, [Inches(1.9), Inches(4.0), Inches(0.6)])
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _add_tactics_observed(doc, kill_chain: list) -> None:
    """A4: a single-row table of tactic cells in ATT&CK order (ordinal — NOT
    a sequence), each shaded by technique count, with the first-observed UTC
    timestamp."""
    from docx.shared import Inches, Pt

    if not kill_chain:
        return
    _dash_subtitle(doc, "Tactics observed (ATT&CK order)")
    _dash_note(doc, "Ordered by ATT&CK tactic, not by time. The timestamp in "
                    "each cell is that tactic's first observation (UTC); the "
                    "strip is not a sequence and implies no causal progression.")
    vmax = max((n.get("technique_count", 0) for n in kill_chain), default=0)
    table = doc.add_table(rows=1, cols=len(kill_chain))
    _set_table_borders(
        table,
        top=(_HAIRLINE, _SZ_HAIRLINE), bottom=(_HAIRLINE, _SZ_HAIRLINE),
        left=(_HAIRLINE, _SZ_HAIRLINE), right=(_HAIRLINE, _SZ_HAIRLINE),
        insideV=(_HAIRLINE, _SZ_HAIRLINE),
    )
    _set_cell_margins(table, top=70, left=70, bottom=70, right=70)
    _set_table_full_width(table)
    _mark_row_cant_split(table.rows[0])
    for cell, node in zip(table.rows[0].cells, kill_chain):
        count = int(node.get("technique_count", 0))
        fill = _seq_color(count, vmax)
        _shade_cell(cell, fill)
        fg = "FFFFFF" if fill in (_SEQ_RAMP[2], _SEQ_RAMP[3]) else _INK
        cell.text = ""
        p_tac = cell.paragraphs[0]
        p_tac.paragraph_format.space_after = Pt(0)
        _style_run(p_tac.add_run(str(node.get("tactic", ""))), size=7.5,
                   color=fg, bold=True)
        p_cnt = cell.add_paragraph()
        p_cnt.paragraph_format.space_before = Pt(0)
        p_cnt.paragraph_format.space_after = Pt(0)
        _style_run(p_cnt.add_run(f"{count} technique(s)"), size=7, color=fg)
        p_ts = cell.add_paragraph()
        p_ts.paragraph_format.space_before = Pt(0)
        p_ts.paragraph_format.space_after = Pt(0)
        _style_run(p_ts.add_run(str(node.get("first_seen") or "—")), size=6.5,
                   color=fg, name="Consolas")
    _set_column_widths(table, [Inches(6.5 / len(kill_chain))] * len(kill_chain))
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _add_dashboard_section(doc, metrics: dict | None, *,
                           standalone: bool) -> None:
    """Render the Assessment Dashboard from the persisted _dashboard_metrics
    dict. ``standalone`` (a bare report.md render with neither persisted
    metrics nor findings) shows an explicit unavailable notice. A blind or
    failed case (verdict_class no_coverage; EMPTY / EXTRACTION_FAILED items)
    never renders a clean dashboard (A3)."""
    doc.add_heading("Assessment Dashboard", level=1)
    if standalone:
        _dash_note(doc,
                   "Dashboard unavailable (standalone render) — the assessment "
                   "dashboard is computed from the case findings during Phase 6 "
                   "and is not available when rendering report.md on its own.")
        doc.add_page_break()
        return

    metrics = metrics or {}
    _dash_note(doc, metrics.get("provenance") or
               "Deterministic — computed from finding facts; no AI input")
    _add_coverage_warning(doc, metrics)

    if not (metrics.get("kpis") or {}).get("findings_total"):
        cov = metrics.get("coverage") or {}
        state = cov.get("state")
        if metrics.get("coverage"):
            _add_stat_tiles(doc, metrics)
        if metrics.get("verdict_class") == "no_coverage" or state == "no_coverage":
            _dash_note(doc, "No evidence was examined — no assessment possible. "
                            "The absence of findings here says nothing about "
                            "the evidence.", color=_INK, bold=True)
        elif state in ("full", "partial"):
            _dash_note(doc, f"No findings were produced from the "
                            f"{cov.get('examined')} of {cov.get('total')} "
                            f"evidence item(s) examined — there is nothing to "
                            f"chart. This is not a statement that the evidence "
                            f"is clean.")
        else:
            _dash_note(doc, "No findings were produced for this case — there "
                            "is nothing to chart.")
        doc.add_page_break()
        return

    _add_headline(doc, metrics)
    _add_stat_tiles(doc, metrics)
    if metrics.get("confidence_banner"):
        _dash_note(doc, f"Confidence: {metrics['confidence_banner']}")
    _add_severity_distribution(doc, metrics)
    _add_tactic_coverage(doc, metrics.get("tactic_coverage") or [])
    _add_tactics_observed(doc, metrics.get("kill_chain") or [])
    doc.add_page_break()


def _resolve_dashboard_metrics(report_md_path: str, manifest: dict | None,
                               findings: list | None):
    """Dashboard metrics for render_docx — SAME precedence as render_pdf:
    prefer the persisted manifest["report"]["dashboard_metrics"]; else compute
    via _dashboard_metrics when findings are supplied; else a bare standalone
    render. Returns (metrics_or_None, standalone_bool)."""
    if manifest:
        persisted = (manifest.get("report") or {}).get("dashboard_metrics")
        if persisted is not None:
            return persisted, False
    if findings is None:
        return None, True
    try:
        from spectre.pipeline.report_synthesize import _dashboard_metrics
        # report.md lives at case_dir/reports/report.md; ruleset.yaml at case_dir.
        case_dir = str(Path(report_md_path).resolve().parent.parent)
        return _dashboard_metrics(findings, manifest or {}, case_dir), False
    except Exception:
        # Never let dashboard computation break the render contract.
        return None, False


def render_docx(report_md_path: str, docx_path: str,
                 title: str = "Spectre Forensic Report",
                 manifest: dict | None = None,
                 findings: list | None = None) -> tuple:
    """Render report.md to a native Word (.docx) forensic report.

    ``manifest`` is the case manifest dict (preferred — Phase 6 has it in
    scope); when omitted, metadata is recovered from the markdown header via
    the same fallback report_pdf.py uses.

    ``findings`` (Phase 6) lets the Assessment Dashboard be computed when no
    metrics are persisted; persisted manifest["report"]["dashboard_metrics"]
    always wins, so PDF and DOCX agree (see _resolve_dashboard_metrics). A
    bare render with neither shows "dashboard unavailable".

    Returns (docx_path, None) on success or (None, reason) if skipped/failed.
    Never raises.
    """
    try:
        from docx import Document
    except Exception as e:
        return None, (f"DOCX skipped — optional 'report' extra not available "
                      f"({type(e).__name__}: {e}). Install with "
                      f"'pip install spectre-forensic[report]'.")

    try:
        from docx.shared import Inches

        from spectre.pipeline.report_pdf import _manifest_from_markdown

        md_text = Path(report_md_path).read_text()

        if manifest is None:
            manifest = _manifest_from_markdown(md_text)
        # Classification from the findings' actual examiner decisions (same
        # helper as render_pdf), on a shallow copy of the caller's manifest.
        from spectre.pipeline.report_pdf import _with_approval_state
        manifest = _with_approval_state(manifest, report_md_path, findings)

        doc = Document()
        doc.core_properties.title = title
        _apply_base_styles(doc)

        section = doc.sections[0]
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

        _add_cover_page(doc, manifest)
        _add_doc_control_page(doc, manifest)
        _add_toc_page(doc)

        # Assessment Dashboard (TB-port T8b) — the same persisted metrics the
        # PDF reads, rendered as shaded tables + block-glyph bars.
        metrics, standalone = _resolve_dashboard_metrics(
            report_md_path, manifest, findings)
        _add_dashboard_section(doc, metrics, standalone=standalone)

        _render_blocks(doc, _parse_markdown_blocks(md_text))

        _add_signoff_page(doc, manifest)
        _add_classification_footer(doc, manifest)

        doc.save(str(docx_path))
        return str(docx_path), None

    except Exception as e:
        return None, f"DOCX render failed ({type(e).__name__}: {e})"
