"""Tests for optional Markdown→DOCX report rendering."""

from spectre.pipeline.report_docx import (
    Heading, Paragraph, BulletList, Table, HRule, Span,
    _parse_markdown_blocks, _parse_inline_runs,
)


def _all_cell_text(tables):
    """Recursively collect cell text from tables, including nested tables
    (Document.tables/_Cell.tables do not recurse on their own)."""
    parts = []
    for t in tables:
        for row in t.rows:
            for cell in row.cells:
                parts.append(cell.text)
                parts.extend(_all_cell_text(cell.tables))
    return parts


_SAMPLE_MD = """# Forensic Investigation Report

**Case Reference:** 073-smbtest

---

## Executive Summary

Analysis identified opportunistic scanning against the monitored host
(F-073-001). Attribution confidence: LOW.

### Key Indicators

| Type | Value | Findings |
|------|-------|----------|
| ip | `203.161.44.208` | F-073-001 |
| domain | `evil-c2.example` | F-073-002 |

## 1. Threat Narrative

**Status:** CONFIRMED | **Confidence:** 0.60 | **MITRE:** T1595.002

**Forensic Caveats:**
- PCAP shows network I/O, not process execution or file writes
- Attribution based on IP reputation only
"""


def test_parse_headings():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    headings = [b for b in blocks if isinstance(b, Heading)]
    assert headings[0] == Heading(level=1, text="Forensic Investigation Report")
    assert headings[1] == Heading(level=2, text="Executive Summary")
    assert headings[2] == Heading(level=3, text="Key Indicators")
    assert headings[3] == Heading(level=2, text="1. Threat Narrative")


def test_parse_hrule():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    assert any(isinstance(b, HRule) for b in blocks)


def test_parse_table():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    tables = [b for b in blocks if isinstance(b, Table)]
    assert len(tables) == 1
    assert tables[0].header == ["Type", "Value", "Findings"]
    assert tables[0].rows == [
        ["ip", "`203.161.44.208`", "F-073-001"],
        ["domain", "`evil-c2.example`", "F-073-002"],
    ]


_RAGGED_TABLE_MD = """# Report

## 5. IOC Export

| Type | Value | Note |
|------|-------|------|
| domain | files.catbox.moe | first |
| ip | `10.0.0.1` | ragged
| domain | www.example.top | extra | cell |
"""


def test_parse_table_tolerates_row_missing_trailing_pipe():
    # A11-05 hardening: a data row that is missing its trailing "|" (e.g. from
    # upstream markdown generation dropping trailing whitespace) must still be
    # recognized as part of the SAME table, not silently dropped and not split
    # into a second, headerless table. Losing a row here is exactly the kind of
    # unreadable/wrong-shaped table an examiner cannot trust.
    blocks = _parse_markdown_blocks(_RAGGED_TABLE_MD)
    tables = [b for b in blocks if isinstance(b, Table)]
    assert len(tables) == 1, (
        f"expected one table, got {len(tables)}: ragged row split it in two"
    )
    assert tables[0].header == ["Type", "Value", "Note"]
    assert len(tables[0].rows) == 3, (
        f"expected 3 data rows, got {len(tables[0].rows)}: "
        "the trailing-pipe-less row was dropped"
    )
    assert tables[0].rows[1] == ["ip", "`10.0.0.1`", "ragged"]
    # A row with MORE cells than the header (ragged the other way) must not
    # crash the parser; extras are tolerated by the renderer.
    assert tables[0].rows[2][:3] == ["domain", "www.example.top", "extra"]


def test_parse_bullet_list():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    lists = [b for b in blocks if isinstance(b, BulletList)]
    assert len(lists) == 1
    assert lists[0].items == [
        "PCAP shows network I/O, not process execution or file writes",
        "Attribution based on IP reputation only",
    ]


def test_parse_paragraph_joins_wrapped_lines():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    paras = [b for b in blocks if isinstance(b, Paragraph)]
    joined = [p.text for p in paras if "opportunistic scanning" in p.text]
    assert joined == [
        "Analysis identified opportunistic scanning against the monitored host "
        "(F-073-001). Attribution confidence: LOW."
    ]


def test_parse_bold_metadata_paragraph_kept_intact():
    blocks = _parse_markdown_blocks(_SAMPLE_MD)
    paras = [b for b in blocks if isinstance(b, Paragraph)]
    assert any(
        p.text == "**Status:** CONFIRMED | **Confidence:** 0.60 | **MITRE:** T1595.002"
        for p in paras
    )


def test_parse_inline_runs_plain_text():
    assert _parse_inline_runs("plain text") == [Span("plain text")]


def test_parse_inline_runs_single_bold_span():
    assert _parse_inline_runs("**bold**") == [Span("bold", bold=True)]


def test_parse_inline_runs_mixed():
    result = _parse_inline_runs("**Status:** CONFIRMED | **MITRE:** T1595.002")
    assert result == [
        Span("Status:", bold=True),
        Span(" CONFIRMED | "),
        Span("MITRE:", bold=True),
        Span(" T1595.002"),
    ]


def test_parse_inline_runs_code_span_strips_backticks():
    # report.md wraps IOC values in backticks; a literal ` on the page reads
    # as corruption in a report an examiner signs.
    assert _parse_inline_runs("value `203.161.44.208` seen") == [
        Span("value "),
        Span("203.161.44.208", code=True),
        Span(" seen"),
    ]


def test_parse_inline_runs_italic_span_strips_asterisks():
    assert _parse_inline_runs("*caveat text*") == [
        Span("caveat text", italic=True)
    ]


def test_parse_inline_runs_bold_wins_over_italic():
    # **x** must not be read as *(*x*)*.
    assert _parse_inline_runs("**bold**") == [Span("bold", bold=True)]


import pytest


def _docx_deps_available() -> bool:
    try:
        import docx  # noqa: F401
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_shade_cell_sets_fill():
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _shade_cell

    doc = Document()
    table = doc.add_table(rows=1, cols=1)
    cell = table.cell(0, 0)
    _shade_cell(cell, "0F6E6E")
    tcPr = cell._tc.find(qn('w:tcPr'))
    shd = tcPr.find(qn('w:shd'))
    assert shd.get(qn('w:fill')) == "0F6E6E"


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_shade_run_sets_fill_and_font_color():
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _shade_run

    doc = Document()
    p = doc.add_paragraph()
    run = p.add_run("CONFIRMED")
    _shade_run(run, "E4F3F0", "0F6E6E")
    rPr = run._element.find(qn('w:rPr'))
    shd = rPr.find(qn('w:shd'))
    assert shd.get(qn('w:fill')) == "E4F3F0"
    assert run.font.color.rgb is not None
    assert str(run.font.color.rgb) == "0F6E6E"


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_insert_toc_field_adds_field_chars():
    from docx import Document
    from spectre.pipeline.report_docx import _insert_toc_field

    doc = Document()
    p = doc.add_paragraph()
    _insert_toc_field(p)
    xml = p._p.xml
    assert 'w:fldChar' in xml
    assert 'TOC' in xml


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_apply_base_styles_sets_calibri_and_heading_colors():
    from docx import Document
    from spectre.pipeline.report_docx import _apply_base_styles

    doc = Document()
    _apply_base_styles(doc)

    assert doc.styles['Normal'].font.name == 'Calibri'
    assert doc.styles['Heading 1'].font.name == 'Calibri Light'
    assert str(doc.styles['Heading 1'].font.color.rgb) == "1F2933"
    assert str(doc.styles['Heading 2'].font.color.rgb) == "0F6E6E"


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_cover_page_renders_case_and_classification():
    from docx import Document
    from spectre.pipeline.report_docx import _add_cover_page

    doc = Document()
    manifest = {
        "case_id": "073", "case_name": "smbtest",
        "artifact_profile": "pcap-focused",
        "evidence": [{"evidence_path": "/cases/evidence/seven-days.pcap",
                      "sha256": "f30ab49b4c7417b23523ffc085b884de7449e12aba1c799e822fa3152f24be91"}],
    }
    _add_cover_page(doc, manifest)

    all_text = "\n".join(p.text for p in doc.paragraphs)
    all_text += "\n" + "\n".join(_all_cell_text(doc.tables))
    assert "073-smbtest" in all_text
    assert "DRAFT" in all_text
    assert "pcap-focused" in all_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_cover_page_shows_approved_when_gate_7_passed():
    """APPROVED needs gate_7 AND every finding decided (see
    tests/test_report_approval_state.py for the pending cases)."""
    from docx import Document
    from spectre.pipeline.report_docx import _add_cover_page

    doc = Document()
    manifest = {"case_id": "073", "case_name": "smbtest", "gate_7": {"passed": True},
                "_approval_state": {"decided": 2, "total": 2, "all_decided": True}}
    _add_cover_page(doc, manifest)

    all_text = "\n".join(p.text for p in doc.paragraphs)
    all_text += "\n" + "\n".join(_all_cell_text(doc.tables))
    assert "APPROVED" in all_text
    assert "DRAFT" not in all_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_doc_control_page_lists_case_metadata():
    from docx import Document
    from spectre.pipeline.report_docx import _add_doc_control_page

    doc = Document()
    manifest = {
        "case_id": "073", "case_name": "smbtest",
        "artifact_profile": "pcap-focused", "canary_status": "FULL",
        "evidence": [{"evidence_path": "/cases/evidence/seven-days.pcap",
                      "sha256": "f30ab49b4c7417b23523ffc085b884de7449e12aba1c799e822fa3152f24be91"}],
    }
    _add_doc_control_page(doc, manifest)

    cell_text = "\n".join(
        cell.text for t in doc.tables for row in t.rows for cell in row.cells
    )
    assert "073-smbtest" in cell_text
    assert "pcap-focused" in cell_text
    assert "FULL" in cell_text
    assert "seven-days.pcap" in cell_text
    assert "f30ab49b" in cell_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_toc_page_inserts_toc_field():
    from docx import Document
    from spectre.pipeline.report_docx import _add_toc_page

    doc = Document()
    _add_toc_page(doc)

    full_xml = doc.element.body.xml
    assert 'w:fldChar' in full_xml
    assert 'TOC' in full_xml


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_confirmed_badge_is_shaded():
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    blocks = _parse_markdown_blocks(
        "**Status:** CONFIRMED | **Confidence:** 0.60\n"
    )
    _render_blocks(doc, blocks)

    shaded_runs = []
    for p in doc.paragraphs:
        for run in p.runs:
            rPr = run._element.find(qn('w:rPr'))
            if rPr is not None and rPr.find(qn('w:shd')) is not None:
                shaded_runs.append(run.text)
    assert "CONFIRMED" in shaded_runs


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_table_header_ruled_in_teal_not_filled():
    """The editorial table style marks the header with a teal rule beneath it,
    not a filled block — so the header cell carries a bottom border and no
    background shading."""
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    md = "| Type | Value |\n|------|-------|\n| ip | 1.2.3.4 |\n"
    _render_blocks(doc, _parse_markdown_blocks(md))

    assert len(doc.tables) == 1
    header_cell = doc.tables[0].rows[0].cells[0]
    tcPr = header_cell._tc.find(qn('w:tcPr'))

    assert tcPr.find(qn('w:shd')) is None, "header row must not be filled"

    bottom = tcPr.find(qn('w:tcBorders')).find(qn('w:bottom'))
    assert bottom.get(qn('w:color')) == "0F6E6E"
    assert bottom.get(qn('w:val')) == "single"


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_table_columns_sized_to_content():
    """A long IOC value must earn a wider column than a short 'Type' label,
    otherwise it wraps across four lines while 'Type' wastes the same width."""
    from docx import Document
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    long_domain = "3416337616.round2026-03-09.odns.m.dnsmeasure.top"
    md = (f"| Type | Value |\n|------|-------|\n"
          f"| ip | {long_domain} |\n")
    _render_blocks(doc, _parse_markdown_blocks(md))

    type_col, value_col = doc.tables[0].columns
    assert value_col.width > type_col.width


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_mark_row_cant_split_precedes_tbl_header_regardless_of_call_order():
    """OOXML's CT_TrPr schema requires w:cantSplit to precede w:tblHeader.

    Real Microsoft Word enforces this ordering strictly and silently ignores
    an out-of-order tblHeader element (LibreOffice tolerates the wrong order,
    which is why this was invisible until a real Word screenshot surfaced
    it). Regardless of which helper a caller invokes first, the resulting
    trPr must always have cantSplit before tblHeader.
    """
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _mark_table_header_row, _mark_row_cant_split

    doc = Document()
    table = doc.add_table(rows=1, cols=1)

    # Buggy call order from the reported bug: tblHeader marked first, then
    # cantSplit — this used to leave w:tblHeader before w:cantSplit in the XML.
    _mark_table_header_row(table.rows[0])
    _mark_row_cant_split(table.rows[0])

    trPr = table.rows[0]._tr.get_or_add_trPr()
    tags = [child.tag for child in list(trPr)]
    cant_idx = tags.index(qn('w:cantSplit'))
    header_idx = tags.index(qn('w:tblHeader'))
    assert cant_idx < header_idx


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_para_border_precedes_spacing_when_spacing_set_first():
    """Same bug class as cantSplit/tblHeader, different container: CT_PPr
    requires w:pBdr before w:spacing. Setting space_before via python-docx and
    then appending a border produced [spacing, pBdr] — which real Word drops on
    the floor, silently removing every heading rule in the document."""
    from docx import Document
    from docx.oxml.ns import qn
    from docx.shared import Pt
    from spectre.pipeline.report_docx import _set_para_borders

    doc = Document()
    p = doc.add_paragraph("x")
    p.paragraph_format.space_before = Pt(12)   # writes w:spacing first
    _set_para_borders(p, bottom=("0F6E6E", 8, 4))

    tags = [child.tag for child in list(p._p.find(qn('w:pPr')))]
    assert tags.index(qn('w:pBdr')) < tags.index(qn('w:spacing'))


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_letter_spacing_precedes_size_in_run_properties():
    """CT_RPr requires w:spacing before w:sz."""
    from docx import Document
    from docx.oxml.ns import qn
    from docx.shared import Pt
    from spectre.pipeline.report_docx import _add_letter_spacing

    doc = Document()
    run = doc.add_paragraph().add_run("x")
    run.font.size = Pt(9)                      # writes w:sz first
    _add_letter_spacing(run, 60)

    tags = [child.tag for child in list(run._element.find(qn('w:rPr')))]
    assert tags.index(qn('w:spacing')) < tags.index(qn('w:sz'))


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_headings_use_word_heading_styles():
    from docx import Document
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    md = "## Executive Summary\n\n### Key Indicators\n"
    blocks = _parse_markdown_blocks(md)
    _render_blocks(doc, blocks)

    styles_used = [p.style.name for p in doc.paragraphs if p.text]
    assert "Heading 1" in styles_used
    assert "Heading 2" in styles_used


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_bullet_list_uses_list_bullet_style():
    from docx import Document
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    blocks = _parse_markdown_blocks("- first caveat\n- second caveat\n")
    _render_blocks(doc, blocks)

    bullet_paragraphs = [p for p in doc.paragraphs if p.style.name == "List Bullet"]
    assert len(bullet_paragraphs) == 2


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_blocks_level1_heading_is_suppressed():
    """The report.md title (level-1 #) is already shown on the cover +
    doc-control page — rendering it again in the body would be redundant."""
    from docx import Document
    from spectre.pipeline.report_docx import _render_blocks, _parse_markdown_blocks

    doc = Document()
    blocks = _parse_markdown_blocks("# Forensic Investigation Report\n\nBody text.\n")
    _render_blocks(doc, blocks)

    all_text = [p.text for p in doc.paragraphs]
    assert "Forensic Investigation Report" not in all_text
    assert "Body text." in all_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_signoff_page_has_disposition_options_and_fields():
    from docx import Document
    from spectre.pipeline.report_docx import _add_signoff_page

    doc = Document()
    _add_signoff_page(doc, {"case_id": "073", "case_name": "smbtest"})

    all_text = "\n".join(p.text for p in doc.paragraphs)
    all_text += "\n" + "\n".join(
        cell.text for t in doc.tables for row in t.rows for cell in row.cells
    )
    assert "Examiner Name" in all_text
    assert "Signature" in all_text
    assert "Date" in all_text
    assert "Approved" in all_text
    assert "Approved with modifications" in all_text
    assert "Rejected" in all_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_classification_footer_shows_draft_text():
    from docx import Document
    from spectre.pipeline.report_docx import _add_classification_footer

    doc = Document()
    _add_classification_footer(doc, {"case_id": "073", "case_name": "smbtest"})

    # The footer is a two-cell table, not a paragraph: a right-aligned tab stop
    # inside the built-in Footer style is honoured by neither Word nor
    # LibreOffice, which ran the page number into the case reference.
    footer = doc.sections[0].footer
    footer_text = "\n".join(_all_cell_text(footer.tables))
    assert "DRAFT" in footer_text
    assert "073-smbtest" in footer_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_add_classification_footer_carries_live_page_number_field():
    from docx import Document
    from docx.oxml.ns import qn
    from spectre.pipeline.report_docx import _add_classification_footer

    doc = Document()
    _add_classification_footer(doc, {"case_id": "073", "case_name": "smbtest"})

    footer_xml = doc.sections[0].footer.tables[0]._tbl.xml
    assert "PAGE" in footer_xml
    assert qn('w:fldChar') in footer_xml or "fldChar" in footer_xml


from spectre.pipeline.report_docx import render_docx

_REAL_SHAPE_MD = """# Forensic Investigation Report

**Case Reference:** 073-smbtest
**Date:** 2026-07-02T00:00:00Z
**Evidence Examined:** Network Packet Capture (PCAP) (1 file(s))
**Classification:** DRAFT — pending examiner review

---

## Executive Summary

Analysis identified opportunistic scanning against the monitored host
(F-073-001). Attribution confidence: LOW.

### Key Indicators

| Type | Value | Findings | Ref Count |
|------|-------|----------|-----------|
| ip | `203.161.44.208` | F-073-001 | 1 |
| domain | `3416337616.round2026-03-09.odns.m.dnsmeasure.top` | F-073-002 | 1 |

## 1. Threat Narrative

All findings are INFERRED (single-source detection). Confidence: 0.60.

### F-073-001: Inbound scan

**Status:** CONFIRMED | **Confidence:** 0.60 | **MITRE:** T1595.002
**Timestamp:** 2026-03-11T00:30:00Z

**Forensic Caveats:**
- PCAP shows network I/O, not process execution or file writes

## 2. MITRE ATT&CK Map

| Technique ID | Technique Name | Finding IDs | Detection Rule |
|-------------|----------------|-------------|----------------|
| T1595.002 | Vulnerability Scanning | F-073-001 | pcap-exploit-probe |

## 3. Timeline

| Timestamp | Event | Finding |
|-----------|-------|---------|
| 2026-03-11 | Inbound scan | F-073-001 |

## 4. Forensic Blind Spots

| Question | Status | Why |
|----------|--------|-----|
| Was data exfiltrated? | UNVERIFIED | Full traffic content not inspected |

## 5. IOC Export

See iocs.csv.

## 6. Methodology

Automated pipeline, pcap profile, canary FULL.
"""


def test_render_docx_never_raises(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(_REAL_SHAPE_MD)
    docx_path = tmp_path / "report.docx"
    result = render_docx(str(md), str(docx_path))
    assert isinstance(result, tuple) and len(result) == 2


def test_render_docx_skips_gracefully_without_deps(tmp_path, monkeypatch):
    if _docx_deps_available():
        pytest.skip("python-docx is installed; skip-path not exercised")
    md = tmp_path / "report.md"
    md.write_text(_REAL_SHAPE_MD)
    docx_path = tmp_path / "report.docx"
    path, reason = render_docx(str(md), str(docx_path))
    assert path is None
    assert reason and "report" in reason
    assert not docx_path.exists()


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_docx_produces_valid_docx_when_deps_present(tmp_path):
    from docx import Document

    md = tmp_path / "report.md"
    md.write_text(_REAL_SHAPE_MD)
    docx_path = tmp_path / "report.docx"
    manifest = {
        "case_id": "073", "case_name": "smbtest",
        "artifact_profile": "pcap-focused", "canary_status": "FULL",
        "evidence": [{"evidence_path": "/cases/evidence/seven-days.pcap",
                      "sha256": "f30ab49b4c7417b23523ffc085b884de7449e12aba1c799e822fa3152f24be91"}],
    }
    path, reason = render_docx(str(md), str(docx_path), manifest=manifest)
    assert path == str(docx_path), reason
    assert docx_path.exists()
    assert docx_path.read_bytes()[:2] == b"PK"  # docx is a zip container

    reopened = Document(str(docx_path))
    all_text = "\n".join(p.text for p in reopened.paragraphs)
    all_text += "\n" + "\n".join(_all_cell_text(reopened.tables))
    assert "073-smbtest" in all_text
    assert "pcap-focused" in all_text
    assert "Examiner Name" in all_text  # sign-off page present
    assert "Threat Narrative" in all_text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_docx_renders_gfm_pipe_tables_as_native_word_tables(tmp_path):
    """A11-05 inverted repro: report.docx must render every GFM pipe-table in
    report.md as a real w:tbl (one w:tr per row, one w:tc per cell) — not one
    concatenated run of undelimited text. Reproduces the exact IOC Export
    shape from the finding (a 'files.catbox.moe' row) and asserts the domain
    value lands in its own cell, isolated from its Finding ID/Confidence
    neighbors, with the header/separator row not rendered as data."""
    from docx import Document

    md = tmp_path / "report.md"
    md.write_text(
        "# Forensic Investigation Report\n\n"
        "## 5. IOC Export\n\n"
        "### Malware C2 & Payload Hosts\n\n"
        "| Type | Value | Finding ID | Confidence |\n"
        "|------|-------|------------|------------|\n"
        "| domain | files.catbox.moe | F-001-001 | 0.60 |\n"
        "| domain | www.qmrcumg.top | F-001-002 | 0.60 |\n"
    )
    docx_path = tmp_path / "report.docx"
    manifest = {"case_id": "001", "case_name": "xloader",
                "artifact_profile": "auto", "canary_status": "FULL"}
    path, reason = render_docx(str(md), str(docx_path), manifest=manifest)
    assert path == str(docx_path), reason

    doc = Document(str(docx_path))
    # Cover-page table + doc-control table + sign-off table + exactly one
    # data table for the IOC Export block.
    assert len(doc.tables) == 4, (
        f"expected 4 w:tbl (3 scaffold tables + 1 IOC table), got "
        f"{len(doc.tables)}"
    )

    ioc_table = doc.tables[-2]  # scaffold order: cover, doc-control, IOC, sign-off
    assert [c.text for c in ioc_table.rows[0].cells] == [
        "Type", "Value", "Finding ID", "Confidence",
    ]
    assert len(ioc_table.rows) == 3  # header + 2 data rows; separator not a row

    data_row = ioc_table.rows[1].cells
    assert [c.text for c in data_row] == [
        "domain", "files.catbox.moe", "F-001-001", "0.60",
    ]
    # The regression this guards against: cells concatenated into one run
    # with no delimiter, e.g. "domainfiles.catbox.moeF-001-0010.60".
    assert data_row[1].text == "files.catbox.moe"
    assert "F-001-001" not in data_row[1].text
    assert "0.60" not in data_row[1].text


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_docx_fallback_regex_matches_real_header(tmp_path):
    from docx import Document

    md = tmp_path / "report.md"
    md.write_text(_REAL_SHAPE_MD)
    docx_path = tmp_path / "report.docx"
    path, reason = render_docx(str(md), str(docx_path))
    assert path is not None, f"render failed: {reason}"

    reopened = Document(str(docx_path))
    all_text = "\n".join(p.text for p in reopened.paragraphs)
    all_text += "\n" + "\n".join(_all_cell_text(reopened.tables))
    assert "?-?" not in all_text
    assert "073-smbtest" in all_text


# ══════════════════════════════════════════════════════════════════════
# TB-port T8a — underscore-italic regression. report.md emits BLUF lines
# like "_Bottom-line-up-front: …_" that previously printed raw underscores.
# ══════════════════════════════════════════════════════════════════════
def test_parse_inline_runs_underscore_italic_strips_underscores():
    assert _parse_inline_runs("_bottom line_") == [
        Span("bottom line", italic=True)
    ]


def test_parse_inline_runs_underscore_italic_at_paragraph_bounds():
    result = _parse_inline_runs(
        "_Bottom-line-up-front: highest-confidence findings first._"
    )
    assert result == [
        Span("Bottom-line-up-front: highest-confidence findings first.",
             italic=True)
    ]


def test_parse_inline_runs_intraword_underscore_is_literal():
    assert _parse_inline_runs("see finding_id here") == [
        Span("see finding_id here")
    ]
    assert _parse_inline_runs("a snake_case_name b") == [
        Span("a snake_case_name b")
    ]


def test_parse_inline_runs_underscore_inside_code_stays_code():
    assert _parse_inline_runs("`_x_`") == [Span("_x_", code=True)]


def test_parse_inline_runs_bold_still_wins_over_underscore():
    assert _parse_inline_runs("**bold**") == [Span("bold", bold=True)]


@pytest.mark.skipif(not _docx_deps_available(), reason="python-docx not installed")
def test_render_underscore_italic_produces_italic_run_no_literal_underscore():
    from docx import Document
    from spectre.pipeline.report_docx import _add_inline_runs

    doc = Document()
    p = doc.add_paragraph()
    _add_inline_runs(p, "_Bottom-line-up-front: see Detailed Findings._")
    assert not any("_" in run.text for run in p.runs)
    italic_runs = [r for r in p.runs if r.italic]
    assert italic_runs
    assert "Bottom-line-up-front" in "".join(r.text for r in italic_runs)
