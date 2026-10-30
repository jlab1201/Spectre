"""
report_pdf.py — professional forensic report PDF rendering for Phase 6.

Design principles:
  - Cover page with case metadata, classification, document control
  - Navy/steel-blue professional color palette
  - Color-coded status badges (CONFIRMED=green, INFERRED=amber)
  - Alternating table rows, monospace IOC columns
  - Running headers/footers with page numbers and classification
  - DRAFT diagonal watermark on every page
  - Minimalist but authoritative — no clutter, high information density

Rendering path:
  report.md → markdown library → semantic HTML post-processing → weasyprint → PDF
"""
from __future__ import annotations

import re
from pathlib import Path

# ── Validated visual system (spec §3; dataviz status + sequential palettes) ──
# Severity = a *status* palette: reserved, always shipped icon + label, and
# separated by lightness so it survives grayscale. Confidence is encoded INTO
# the mark (solid = confirmed/high-confidence, hollow = inferred/low-conf),
# never conflated with severity (spec §2 principle 4).
# TODO: extract shared report_palette helper (cross-format parity is
# hand-enforced) — report_pdf.py uses '#'-prefixed lowercase, report_docx.py uses
# bare-hex uppercase, so keep these two ramps in sync manually until then.
_SEVERITY_STYLE = {
    "CRITICAL":      {"color": "#d03b3b", "glyph": "▲"},  # ▲
    "HIGH":          {"color": "#ec835a", "glyph": "◆"},  # ◆
    "MEDIUM":        {"color": "#fab219", "glyph": "●"},  # ●
    "LOW":           {"color": "#0ca30c", "glyph": "▪"},  # ▪
    "INFORMATIONAL": {"color": "#8a897f", "glyph": "▫"},  # ▫ (out-of-palette → muted)
    "UNRATED":       {"color": "#8a897f", "glyph": "▫"},  # ▫ (hollow)
}
_UNRATED_STYLE = _SEVERITY_STYLE["UNRATED"]

# Magnitude = single-hue blue sequential ramp (lightness-monotonic, validated
# in spec §3): tactic-coverage bars, kill-chain nodes, confidence meters.
_SEQ_RAMP = ["#cde2fb", "#9ec5f4", "#256abf", "#0d366b"]


def _sev_style(sev: str) -> dict:
    return _SEVERITY_STYLE.get((sev or "").upper(), _UNRATED_STYLE)


def _seq_color(value: int, vmax: int) -> str:
    """Map a magnitude to a sequential-ramp step (light→dark with value)."""
    if vmax <= 0:
        return _SEQ_RAMP[0]
    frac = value / vmax
    idx = min(len(_SEQ_RAMP) - 1, int(round(frac * (len(_SEQ_RAMP) - 1))))
    return _SEQ_RAMP[idx]

# ── Professional CSS ───────────────────────────────────────────────────
_PROFESSIONAL_CSS = r"""
/* ── Design tokens (spec §3 — single light print surface, no dark mode) ── */
:root {
  --surface: #fcfcfb;
  --card: #ffffff;
  --ink: #0b0b0b;
  --ink-secondary: #52514e;
  --ink-muted: #8a897f;
  --navy: #1B2A4A;        /* structural only, never data */
  --accent: #256abf;      /* structural only, never data */
  --hairline: #e6e5e1;
  --border: #DEE2E6;

  /* severity status palette (icon+label always; never colour-alone) */
  --sev-critical: #d03b3b;
  --sev-high: #ec835a;
  --sev-medium: #fab219;
  --sev-low: #0ca30c;
  --sev-unrated: #8a897f;

  /* single-hue blue sequential ramp (magnitude) */
  --seq-1: #cde2fb;
  --seq-2: #9ec5f4;
  --seq-3: #256abf;
  --seq-4: #0d366b;

  --font-sans: "Lato", "DejaVu Sans", sans-serif;
  --font-body: "DejaVu Serif", "Liberation Serif", Georgia, serif;
  --font-mono: "DejaVu Sans Mono", "Noto Sans Mono", monospace;
}

/* ── Page geometry ─────────────────────────────────────────────── */
@page {
  size: A4;
  margin: 2cm 1.8cm 2.2cm 1.8cm;
  @bottom-center {
    content: "Page " counter(page);
    font-family: "Lato", "DejaVu Sans", sans-serif;
    font-size: 7.5pt;
    color: #8a897f;
  }
  @bottom-left {
    content: "SPECTRE FORENSIC REPORT — %CLASSIFICATION%";
    font-family: "Lato", "DejaVu Sans", sans-serif;
    font-size: 6.5pt;
    color: #b8b7af;
    text-transform: uppercase;
    letter-spacing: 1.5pt;
  }
  @bottom-right {
    content: string(case-id);
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 6.5pt;
    color: #b8b7af;
  }
}

@page cover {
  margin: 0;
  @bottom-center { content: none; }
  @bottom-left   { content: none; }
  @bottom-right  { content: none; }
}

/* ── Typography ────────────────────────────────────────────────── */
body {
  font-family: var(--font-body);
  font-size: 9.5pt;
  line-height: 1.45;
  color: var(--ink);
  background: var(--surface);
}

h1 {
  font-family: var(--font-sans);
  font-size: 16pt;
  color: var(--navy);
  border-bottom: 2pt solid var(--navy);
  padding-bottom: 4pt;
  margin-top: 0;
  page-break-before: avoid;
}

h2 {
  font-family: var(--font-sans);
  font-size: 12pt;
  color: var(--navy);
  margin-top: 14pt;
  margin-bottom: 6pt;
  padding-bottom: 2pt;
  border-bottom: 1pt solid var(--hairline);
  page-break-after: avoid;
}

h3 {
  font-family: var(--font-sans);
  font-size: 10.5pt;
  color: var(--navy);
  margin-top: 10pt;
  margin-bottom: 4pt;
  page-break-after: avoid;
}

h4 {
  font-family: var(--font-sans);
  font-size: 9.5pt;
  color: var(--ink);
  margin: 6pt 0 3pt 0;
  page-break-after: avoid;
}

p { margin: 3pt 0 5pt 0; }

code {
  font-family: var(--font-mono);
  font-size: 8.5pt;
  background: #f2f1ec;
  padding: 1pt 3pt;
  border-radius: 2pt;
  border: 0.5pt solid var(--hairline);
}

strong { color: var(--navy); }

/* ── Tables ────────────────────────────────────────────────────── */
table {
  border-collapse: collapse;
  width: 100%;
  margin: 8pt 0 10pt 0;
  font-size: 8.5pt;
  page-break-inside: avoid;
}

th {
  background: var(--navy);
  color: #ffffff;
  font-family: var(--font-sans);
  font-weight: 600;
  text-align: left;
  padding: 5pt 7pt;
  font-size: 8pt;
  text-transform: uppercase;
  letter-spacing: 0.5pt;
}

td {
  padding: 4pt 7pt;
  border-bottom: 0.5pt solid var(--hairline);
  vertical-align: top;
  word-break: break-word;
}

tr:nth-child(even) td { background: #f6f5f1; }
tr:nth-child(odd)  td { background: var(--card); }

/* ── Status badges (icon + label; colour is redundant) ─────────── */
.confirmed-badge {
  display: inline-block;
  background: #e5f2ea;
  color: #0ca30c;
  font-family: var(--font-sans);
  font-size: 8pt;
  font-weight: 700;
  padding: 1pt 6pt;
  border-radius: 3pt;
  border: 0.5pt solid #0ca30c;
}

.inferred-badge {
  display: inline-block;
  background: #fdf2e4;
  color: #b8601b;
  font-family: var(--font-sans);
  font-size: 8pt;
  font-weight: 700;
  padding: 1pt 6pt;
  border-radius: 3pt;
  border: 0.5pt solid #b8601b;
}

.confidence-high   { color: #0ca30c; font-weight: 700; }
.confidence-medium { color: #b8601b; font-weight: 600; }
.confidence-low    { color: var(--ink-muted); }

/* ── Evidence / IOC blocks ─────────────────────────────────────── */
.evidence-block {
  background: #f6f5f1;
  border-left: 2.5pt solid var(--accent);
  padding: 6pt 8pt;
  margin: 6pt 0;
  font-size: 8.5pt;
}

.ioc-value {
  font-family: var(--font-mono);
  font-size: 8pt;
  background: #eef2f7;
  padding: 1pt 3pt;
  border-radius: 2pt;
  word-break: break-all;
}

/* ══════════════════════════════════════════════════════════════════
   ASSESSMENT DASHBOARD (spec §5) — deterministic, print-static
   ══════════════════════════════════════════════════════════════════ */
.dashboard {
  margin: 4pt 0 10pt 0;
  page-break-inside: avoid;
}
.dash-section { margin: 10pt 0; page-break-inside: avoid; }
.dash-section-title {
  font-family: var(--font-sans);
  font-size: 8pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1.2pt;
  color: var(--ink-secondary);
  margin: 0 0 5pt 0;
}
.dash-legend {
  font-family: var(--font-sans);
  font-size: 7pt;
  color: var(--ink-muted);
  margin: 0 0 5pt 0;
}
.dash-unavailable {
  font-family: var(--font-sans);
  font-size: 9pt;
  color: var(--ink-muted);
  font-style: italic;
  border: 0.75pt dashed var(--border);
  border-radius: 3pt;
  padding: 10pt 12pt;
  margin: 8pt 0;
}

.dash-provenance {
  font-family: var(--font-sans);
  font-size: 7pt;
  color: var(--ink-muted);
  letter-spacing: 0.4pt;
  margin: 0 0 6pt 0;
}
.dash-warning {
  font-family: var(--font-sans);
  font-size: 8.5pt;
  color: #0b0b0b;
  background: rgba(208,59,59,0.08);
  border: 0.75pt solid #d03b3b;
  border-left-width: 4pt;
  border-radius: 3pt;
  padding: 7pt 10pt;
  margin: 0 0 8pt 0;
}
.dash-confidence {
  font-family: var(--font-sans);
  font-size: 8pt;
  color: var(--ink-secondary);
  margin: 4pt 0 2pt 0;
}

/* ── 5.1 Stat-tile row ── */
.stat-row {
  display: flex;
  flex-wrap: nowrap;
  gap: 5pt;
  margin: 0 0 4pt 0;
}
.stat-tile {
  flex: 1 1 0;
  background: var(--card);
  border: 0.75pt solid var(--border);
  border-radius: 3pt;
  padding: 6pt 7pt;
  min-width: 0;
}
.stat-tile .stat-value {
  font-family: var(--font-sans);
  font-size: 17pt;
  font-weight: 700;
  color: var(--navy);
  line-height: 1.05;
}
.stat-tile .stat-value.sev {
  font-size: 12pt;
}
.stat-tile .stat-label {
  font-family: var(--font-sans);
  font-size: 6.5pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1pt;
  color: var(--ink-muted);
  margin-top: 2pt;
}

/* ── 5.2 Severity distribution (horizontal bar, confidence-encoded) ── */
.sev-dist { margin: 0; }
.sev-row {
  display: flex;
  align-items: center;
  margin: 0 0 4pt 0;
}
.sev-row-label {
  flex: 0 0 78pt;
  font-family: var(--font-sans);
  font-size: 7.5pt;
  font-weight: 700;
  color: var(--ink);
}
.sev-row-label .glyph { font-size: 8pt; margin-right: 3pt; }
.sev-bar-track {
  flex: 1 1 auto;
  display: flex;
  align-items: center;
  height: 13pt;
}
/* rounded 4px data-end, square at the shared baseline (left) */
.sev-seg {
  height: 13pt;
  border-radius: 0 3pt 3pt 0;
}
.sev-seg.solid  { }                 /* confirmed / high-confidence: solid fill */
.sev-seg.hollow {                   /* inferred / low-confidence: outline + tint */
  background-color: transparent !important;
}
.sev-gap { width: 2pt; }            /* 2px surface gap between segments */
.sev-count {
  flex: 0 0 auto;
  font-family: var(--font-sans);
  font-size: 7.5pt;
  font-weight: 700;
  color: var(--ink-secondary);
  margin-left: 5pt;
  min-width: 16pt;
}

/* ── 5.3 MITRE tactic-coverage bar (sequential fill + count label) ── */
.tactic-bar { margin: 0; }
.tactic-row {
  display: flex;
  align-items: center;
  margin: 0 0 3.5pt 0;
}
.tactic-name {
  flex: 0 0 108pt;
  font-family: var(--font-sans);
  font-size: 7.5pt;
  color: var(--ink);
  text-align: right;
  padding-right: 7pt;
}
.tactic-track {
  flex: 1 1 auto;
  display: flex;
  align-items: center;
  height: 12pt;
}
.tactic-fill {
  height: 12pt;
  border-radius: 0 3pt 3pt 0;
  min-width: 1pt;
}
.tactic-count {
  font-family: var(--font-sans);
  font-size: 7.5pt;
  font-weight: 700;
  color: var(--ink-secondary);
  margin-left: 5pt;
}

/* ── 5.4 Kill-chain / attack-progression strip ── */
.killchain {
  display: flex;
  align-items: flex-start;
  flex-wrap: nowrap;
  margin: 2pt 0;
}
.kc-node {
  flex: 1 1 0;
  text-align: center;
  min-width: 0;
}
.kc-rail {
  position: relative;
  height: 22pt;
}
.kc-dot {
  position: absolute;
  top: 3pt;
  left: 50%;
  margin-left: -8pt;
  width: 16pt;
  height: 16pt;
  border-radius: 50%;
  border: 1pt solid #ffffff;
}
.kc-dot .kc-dot-count {
  display: block;
  font-family: var(--font-sans);
  font-size: 7pt;
  font-weight: 700;
  line-height: 16pt;
  text-align: center;
}
.kc-connector {
  position: absolute;
  top: 10pt;
  left: 50%;
  width: 100%;
  height: 3pt;
}
.kc-tactic {
  font-family: var(--font-sans);
  font-size: 6.5pt;
  font-weight: 700;
  color: var(--ink);
  margin-top: 2pt;
  line-height: 1.1;
}
.kc-time {
  font-family: var(--font-mono);
  font-size: 5.5pt;
  color: var(--ink-muted);
  margin-top: 1pt;
  word-break: break-all;
}

/* ── 5.5 Finding card (left severity rail) ── */
.finding-detail {
  background: var(--card);
  border: 0.5pt solid var(--border);
  border-left-width: 4pt;
  border-left-style: solid;
  border-left-color: var(--border);
  border-radius: 3pt;
  padding: 8pt 10pt;
  margin: 8pt 0;
  page-break-inside: avoid;
}
.finding-detail .meta-line {
  font-size: 9pt;
  color: var(--ink-secondary);
  margin: 2pt 0;
}

/* ── Cover page ────────────────────────────────────────────────── */
.cover-page {
  page: cover;
  width: 21cm;
  height: 29.7cm;
  box-sizing: border-box;
  padding: 3.2cm 2.4cm 2.4cm 2.4cm;
  background: linear-gradient(160deg, #101D36 0%, #1B2A4A 45%, #256abf 130%);
  color: #ffffff;
  page-break-after: always;
}
.cover-classification {
  font-family: var(--font-sans);
  font-size: 13pt;
  font-weight: 700;
  letter-spacing: 6pt;
  text-transform: uppercase;
  color: rgba(255,255,255,0.85);
  border: 1.5pt solid rgba(255,255,255,0.45);
  padding: 5pt 18pt;
  display: inline-block;
  margin-bottom: 1.6cm;
}
.cover-title {
  font-family: var(--font-sans);
  font-size: 30pt;
  font-weight: 300;
  color: #ffffff;
  margin: 0 0 8pt 0;
  line-height: 1.15;
}
.cover-case {
  font-family: var(--font-mono);
  font-size: 15pt;
  color: rgba(255,255,255,0.85);
  margin-bottom: 0.7cm;
}
.cover-headline {
  font-family: var(--font-sans);
  font-size: 12pt;
  font-weight: 400;
  line-height: 1.4;
  color: #ffffff;
  border-left: 3pt solid rgba(255,255,255,0.5);
  padding-left: 12pt;
  margin-bottom: 1.1cm;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.cover-qualifier {
  font-family: var(--font-sans);
  font-size: 9pt;
  line-height: 1.45;
  color: #ffffff;
  background: rgba(236,131,90,0.18);
  border: 0.75pt solid rgba(236,131,90,0.7);
  border-radius: 4pt;
  padding: 7pt 11pt;
  margin: -0.6cm 0 0.9cm 0;
}
.cover-kpi-strip {
  display: flex;
  gap: 10pt;
  margin-bottom: 1.4cm;
}
.cover-kpi {
  flex: 1 1 0;
  background: rgba(255,255,255,0.08);
  border: 0.75pt solid rgba(255,255,255,0.22);
  border-radius: 4pt;
  padding: 9pt 10pt;
}
.cover-kpi .kpi-value {
  font-family: var(--font-sans);
  font-size: 21pt;
  font-weight: 700;
  color: #ffffff;
  line-height: 1.05;
}
.cover-kpi .kpi-value.small { font-size: 13pt; }
.cover-kpi .kpi-label {
  font-family: var(--font-sans);
  font-size: 6.5pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1pt;
  color: rgba(255,255,255,0.7);
  margin-top: 3pt;
}
.cover-summary {
  background: rgba(255,255,255,0.08);
  border: 0.75pt solid rgba(255,255,255,0.25);
  border-radius: 4pt;
  padding: 12pt 16pt;
  margin-bottom: 1.2cm;
  font-family: var(--font-sans);
  font-size: 10pt;
  line-height: 1.8;
  color: rgba(255,255,255,0.9);
}
.cover-summary .stat { font-size: 20pt; font-weight: 700; color: #ffffff; }
.cover-meta {
  font-family: var(--font-sans);
  font-size: 9.5pt;
  color: rgba(255,255,255,0.65);
  line-height: 2;
}
.cover-baseline-badge {
  background: #b8601b;
  border: 1.5pt solid #fab219;
  border-radius: 4pt;
  padding: 8pt 14pt;
  margin-bottom: 1.2cm;
  font-family: var(--font-sans);
  font-size: 11pt;
  font-weight: 700;
  letter-spacing: 0.5pt;
  color: #ffffff;
  display: inline-block;
}
.cover-meta strong { color: rgba(255,255,255,0.92); font-weight: 600; }
.cover-meta .mono {
  font-family: var(--font-mono);
  font-size: 8pt;
  word-break: break-all;
}
.cover-footer {
  position: absolute;
  bottom: 2cm;
  left: 2.4cm;
  right: 2.4cm;
  border-top: 0.75pt solid rgba(255,255,255,0.3);
  padding-top: 8pt;
  font-family: var(--font-sans);
  font-size: 8pt;
  letter-spacing: 1.5pt;
  text-transform: uppercase;
  color: rgba(255,255,255,0.5);
}

/* ── Table of contents ─────────────────────────────────────────── */
.toc { page-break-after: always; }
.toc h2 { border-bottom: 2pt solid var(--navy); color: var(--navy); }
.toc ul { list-style: none; padding: 0; margin: 10pt 0; }
.toc li {
  font-family: var(--font-sans);
  font-size: 10.5pt;
  padding: 4pt 0;
  border-bottom: 0.5pt dotted var(--hairline);
}
.toc a { text-decoration: none; color: var(--ink); }
.toc a::after {
  content: target-counter(attr(href), page);
  float: right;
  color: var(--ink-muted);
  font-family: var(--font-mono);
  font-size: 9pt;
}

/* ── Section separators ────────────────────────────────────────── */
.section-hr {
  border: none;
  border-top: 1pt solid var(--hairline);
  margin: 16pt 0;
}

/* ── Caveat blocks (verbatim FK caveats) ───────────────────────── */
.caveat-block {
  background: #fdf7e8;
  border-left: 2.5pt solid #fab219;
  padding: 5pt 8pt;
  margin: 5pt 0;
  font-size: 8.5pt;
  color: #5f4d16;
}

/* ── Executive summary ─────────────────────────────────────────── */
.exec-summary { font-size: 10.5pt; line-height: 1.6; }

/* ── Watermark (content pages only) ── */
body::after {
  content: "%WATERMARK%";
  position: fixed;
  top: 11cm;
  left: 2.5cm;
  transform: rotate(-30deg);
  font-family: var(--font-sans);
  font-size: 72pt;
  font-weight: 900;
  letter-spacing: 14pt;
  color: rgba(208,59,59,0.05);
  z-index: -1;
  white-space: nowrap;
}

/* ── Print controls ────────────────────────────────────────────── */
h2 { page-break-before: auto; }
h2.appendix-header { page-break-before: always; }
"""


def _evidence_rows(manifest: dict) -> list[tuple[str, str]]:
    """Return [(filename, sha256)] from the manifest's evidence list."""
    rows = []
    for ev in manifest.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        path = ev.get("evidence_path") or ev.get("original_path") or ""
        name = Path(path).name if path else "?"
        rows.append((name, ev.get("sha256", "")))
    return rows


def _finding_stats(manifest: dict) -> tuple[int, int, int]:
    """Return (total, confirmed, inferred) from the manifest detection block."""
    fs = (manifest.get("detection") or {}).get("findings") or []
    confirmed = sum(1 for f in fs if isinstance(f, dict) and f.get("status") == "CONFIRMED")
    inferred = sum(1 for f in fs if isinstance(f, dict) and f.get("status") == "INFERRED")
    return len(fs), confirmed, inferred


def _classification(manifest: dict) -> str:
    """APPROVED only when gate_7 passed AND every active finding carries an
    examiner decision (report_synthesize.classification_for). The renderers
    attach the findings' actual approval state as manifest["_approval_state"]
    (on a shallow copy); without it the state is unknown → DRAFT."""
    from spectre.pipeline.report_synthesize import classification_for
    return classification_for(manifest, manifest.get("_approval_state"))


def _status_line(manifest: dict) -> str:
    from spectre.pipeline.report_synthesize import classification_status_line
    return classification_status_line(_classification(manifest),
                                      manifest.get("_approval_state"))


def _with_approval_state(manifest: dict, report_md_path: str,
                         findings: list | None) -> dict:
    """Shallow copy of ``manifest`` carrying the findings' approval state:
    from the on-disk case findings (case_dir = the report's grandparent) —
    the current truth, including decisions made after Phase 6 — else from
    ``findings``; None when neither exists (→ DRAFT)."""
    from spectre.pipeline.report_synthesize import approval_state, load_approval_state
    out = dict(manifest or {})
    try:
        state = load_approval_state(str(Path(report_md_path).resolve().parent.parent))
    except Exception:
        state = None
    if state is None and findings is not None:
        state = approval_state(findings)
    out["_approval_state"] = state
    return out


def _build_cover_html(manifest: dict, metrics: dict | None = None) -> str:
    """Build the full-page cover HTML.

    When ``metrics`` (the persisted _dashboard_metrics dict) is present the
    cover carries the deterministic, status-qualified threat headline and a
    KPI strip (Findings · Multi-source corroborated · Top rule severity ·
    MITRE techniques · Evidence examined). Honesty amendments (TB-PORT A1-A3):
    the headline always states its lead's status and corroboration axis, a
    leads-only case says so explicitly, and a blind/partial case states its
    coverage on the cover — the cover never reads cleaner than the Verdict.
    """
    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    profile = manifest.get("artifact_profile", "?")
    canary = manifest.get("canary_status", "?")
    classification = _classification(manifest)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total, confirmed, inferred = _finding_stats(manifest)

    headline_html = ""
    kpi_html = ""
    summary_html = ""
    qualifier_html = ""
    if metrics:
        vclass = metrics.get("verdict_class")
        cov = metrics.get("coverage") or {}
        notes = []
        if vclass == "no_coverage":
            states = []
            if cov.get("failed"):
                states.append(f"{cov['failed']} EXTRACTION_FAILED")
            if cov.get("empty"):
                states.append(f"{cov['empty']} EMPTY")
            notes.append(
                "No evidence was examined — no assessment possible. "
                f"{cov.get('total', 0)} registered evidence item(s) were left "
                "unanalyzed" + (f" ({', '.join(states)})" if states else "")
                + "; this report establishes nothing about their contents.")
        elif vclass == "leads_only":
            notes.append("Leads only — no finding reached CONFIRMED status. "
                         "Severity is the detection rule's rating if "
                         "confirmed, not an assessment of this case.")
        if vclass != "no_coverage" and cov.get("state") == "partial":
            notes.append(f"Coverage: {cov.get('examined')} of {cov.get('total')} "
                         f"evidence item(s) examined.")
        if notes:
            qualifier_html = ('\n  <div class="cover-qualifier">'
                              + "<br>".join(notes) + "</div>")
    if metrics and (metrics.get("kpis") or {}).get("findings_total"):
        k = metrics["kpis"]
        # Display cap only (the full, untruncated title is in Detailed
        # Findings); the qualifier prefix is never cut.
        raw_headline = metrics.get("threat_headline") or ""
        if len(raw_headline) > 220:
            raw_headline = raw_headline[:219].rstrip() + "…"
        headline = _esc(raw_headline)
        if headline:
            headline_html = f'\n  <div class="cover-headline">{headline}</div>'
        top_sev = metrics.get("top_severity") or "UNRATED"
        sev_style = _sev_style(top_sev)
        cov = metrics.get("coverage") or {}
        cov_tile = ""
        if cov.get("total"):
            cov_tile = (f'\n    <div class="cover-kpi"><div class="kpi-value">'
                        f'{cov.get("examined", 0)}/{cov.get("total")}</div>'
                        f'\n      <div class="kpi-label">Evidence examined</div></div>')
        kpi_html = f"""
  <div class="cover-kpi-strip">
    <div class="cover-kpi"><div class="kpi-value">{k['findings_total']}</div>
      <div class="kpi-label">Findings</div></div>
    <div class="cover-kpi"><div class="kpi-value">{k.get('corroborated', 0)}</div>
      <div class="kpi-label">Multi-source corroborated</div></div>
    <div class="cover-kpi"><div class="kpi-value small">
      <span style="color:{sev_style['color']}">{sev_style['glyph']}</span> {_esc(top_sev)}</div>
      <div class="kpi-label">Top rule severity</div></div>
    <div class="cover-kpi"><div class="kpi-value">{k.get('mitre_techniques', 0)}</div>
      <div class="kpi-label">MITRE techniques</div></div>{cov_tile}
  </div>"""
    elif total:
        # No metrics (e.g. a bare standalone render) — keep the legacy line.
        summary_html = f"""
  <div class="cover-summary">
    <span class="stat">{total}</span> finding(s) —
    {confirmed} CONFIRMED · {inferred} INFERRED
  </div>"""

    baseline_badge_html = ""
    if manifest.get("report", {}).get("ai_narrative") is False:
        baseline_badge_html = (
            '\n  <div class="cover-baseline-badge">'
            "DETERMINISTIC BASELINE — NO AI NARRATIVE</div>"
        )

    ev_lines = []
    for name, sha in _evidence_rows(manifest):
        ev_lines.append(
            f"<strong>Evidence:</strong> {name}<br>"
            + (f'<span class="mono">SHA-256: {sha}</span><br>' if sha else "")
        )
    ev_html = "\n    ".join(ev_lines)

    status_line = _status_line(manifest)
    return f"""<div class="cover-page">
  <div class="cover-classification">{classification}</div>
  <div class="cover-title">Forensic Investigation<br>Report</div>
  <div class="cover-case">Case {case_id}-{case_name}</div>{headline_html}{qualifier_html}{kpi_html}{summary_html}{baseline_badge_html}
  <div class="cover-meta">
    {ev_html}
    <strong>Artifact Profile:</strong> {profile}<br>
    <strong>Canary Status:</strong> {canary}<br>
    <strong>Generated:</strong> {now}<br>
    <strong>Classification:</strong> {classification} — {status_line}
  </div>
  <div class="cover-footer">Spectre — Deterministic Forensic Pipeline · 7-Phase Methodology</div>
</div>"""


# ── Dashboard rendering (spec §5) — deterministic, static, print-safe ──
def _esc(text) -> str:
    """Minimal HTML escaping for deterministic values placed into the DOM."""
    return (str(text)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    """#rrggbb → rgba() at the given alpha. Used for the hollow (inferred /
    low-confidence) severity segments — a light tint of the severity hue."""
    h = hex_color.lstrip("#")
    if len(h) != 6:
        return hex_color
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _dashboard_unavailable_html() -> str:
    """Bare standalone render (neither persisted metrics nor findings): an
    explicit unavailable notice rather than a manifest-only half-dashboard.
    (A render WITH persisted metrics shows the full dashboard — TB-PORT A7.)"""
    return (
        '<div class="dashboard"><h2>Assessment Dashboard</h2>'
        '<div class="dash-unavailable">Dashboard unavailable (standalone '
        'render) — the assessment dashboard is computed from the case '
        'findings during Phase 6 and is not available when rendering '
        'report.md on its own.</div></div>'
    )


def _coverage_notice_html(metrics: dict) -> str:
    """A3: the coverage warning a dashboard must carry whenever any evidence
    item went unexamined (EMPTY / EXTRACTION_FAILED / skipped). Empty when
    coverage is full or not recorded."""
    cov = metrics.get("coverage") or {}
    state = cov.get("state")
    if state not in ("partial", "no_coverage"):
        return ""
    detail = []
    if cov.get("failed"):
        detail.append(f"{cov['failed']} EXTRACTION_FAILED")
    if cov.get("empty"):
        detail.append(f"{cov['empty']} EMPTY")
    extra = f" ({', '.join(detail)})" if detail else ""
    unexamined = int(cov.get("total") or 0) - int(cov.get("examined") or 0)
    if state == "no_coverage":
        head = "No evidence was examined — no assessment possible."
    else:
        head = (f"Partial coverage — {unexamined} of {cov.get('total')} "
                f"evidence item(s) were not examined.")
    return (f'<div class="dash-warning"><strong>{_esc(head)}</strong> '
            f'{unexamined} of {cov.get("total")} item(s) not examined{extra}. '
            f'Nothing in this report establishes the contents of an unexamined '
            f'item — see Forensic Blind Spots.</div>')


def _provenance_html(metrics: dict) -> str:
    prov = metrics.get("provenance") or (
        "Deterministic — computed from finding facts; no AI input")
    return f'<div class="dash-provenance">{_esc(prov)}</div>'


def _stat_tiles_html(metrics: dict) -> str:
    k = metrics.get("kpis") or {}
    cov = metrics.get("coverage") or {}
    tiles = [
        (str(k.get("findings_total", 0)), "Findings"),
        (str(k.get("confirmed", 0)), "Confirmed"),
        (str(k.get("inferred", 0)), "Inferred"),
        (str(k.get("corroborated", 0)), "Multi-source corroborated"),
        (str(k.get("mitre_techniques", 0)), "MITRE techniques"),
    ]
    if cov.get("total"):
        tiles.append((f"{cov.get('examined', 0)}/{cov['total']}",
                      "Evidence examined"))
    else:
        tiles.append((str(k.get("evidence_items", 0)), "Evidence items"))
    return '<div class="stat-row">' + "".join(
        f'<div class="stat-tile"><div class="stat-value">{_esc(v)}</div>'
        f'<div class="stat-label">{_esc(label)}</div></div>'
        for v, label in tiles) + "</div>"


def _build_dashboard_html(metrics: dict) -> str:
    """Build the Assessment Dashboard HTML from the persisted _dashboard_metrics
    dict: stat tiles (incl. evidence coverage), the W4-B confidence banner,
    severity distribution (confidence-encoded solid/hollow), MITRE tactic
    coverage, and the tactics-observed strip. Deterministic — every number
    comes straight from ``metrics``; invents nothing. Stamped with its
    provenance (A6); carries a coverage warning whenever evidence went
    unexamined (A3)."""
    metrics = metrics or {}
    k = metrics.get("kpis") or {}
    head = '<div class="dashboard"><h2>Assessment Dashboard</h2>'

    if not k.get("findings_total"):
        cov = metrics.get("coverage") or {}
        state = cov.get("state")
        if metrics.get("verdict_class") == "no_coverage" or state == "no_coverage":
            body = ('<div class="dash-unavailable">No evidence was examined — '
                    'no assessment possible. The absence of findings here says '
                    'nothing about the evidence.</div>')
        elif state in ("full", "partial"):
            body = (f'<div class="dash-unavailable">No findings were produced '
                    f'from the {cov.get("examined")} of {cov.get("total")} '
                    f'evidence item(s) examined — there is nothing to chart. '
                    f'This is not a statement that the evidence is clean.</div>')
        else:
            body = ('<div class="dash-unavailable">No findings were produced '
                    'for this case — there is nothing to chart.</div>')
        tiles = _stat_tiles_html(metrics) if metrics.get("coverage") else ""
        return (head + _provenance_html(metrics) + _coverage_notice_html(metrics)
                + tiles + body + "</div>")

    parts: list[str] = [head, _provenance_html(metrics),
                        _coverage_notice_html(metrics), _stat_tiles_html(metrics)]
    banner = metrics.get("confidence_banner")
    if banner:
        parts.append(f'<div class="dash-confidence"><strong>Confidence:</strong> '
                     f'{_esc(banner)}</div>')

    # ── Severity distribution (confidence-encoded solid/hollow) ──
    sev_counts = metrics.get("severity_counts") or []
    if sev_counts:
        max_total = max((r["total"] for r in sev_counts), default=0) or 1
        inferred_note = ("INFERRED (single-source)"
                         if k.get("inferred_single_source", -1) == k.get("inferred")
                         else "INFERRED")
        parts.append('<div class="dash-section">')
        parts.append('<div class="dash-section-title">Severity distribution</div>')
        parts.append(
            f'<div class="dash-legend">solid = CONFIRMED · hollow = '
            f'{inferred_note}. Severity is the detection rule\'s rating from the '
            f'case ruleset snapshot ("how bad if confirmed"; UNRATED = the rule '
            f'sets no level); confidence is a separate axis shown by fill '
            f'style.</div>')
        parts.append('<div class="sev-dist">')
        for row in sev_counts:
            sev = row["severity"]
            style = _sev_style(sev)
            color, glyph = style["color"], style["glyph"]
            solid_pct = row["confirmed"] / max_total * 100
            hollow_pct = row["inferred"] / max_total * 100
            segs = []
            if row["confirmed"] > 0:
                segs.append(
                    f'<div class="sev-seg solid" style="width:{solid_pct:.2f}%;'
                    f'background-color:{color}"></div>')
            if row["confirmed"] > 0 and row["inferred"] > 0:
                segs.append('<div class="sev-gap"></div>')
            if row["inferred"] > 0:
                segs.append(
                    f'<div class="sev-seg hollow" style="width:{hollow_pct:.2f}%;'
                    f'border:0.75pt solid {color};'
                    f'background-color:{_hex_to_rgba(color, 0.18)}"></div>')
            parts.append(
                f'<div class="sev-row">'
                f'<div class="sev-row-label"><span class="glyph" '
                f'style="color:{color}">{glyph}</span>{_esc(sev)}</div>'
                f'<div class="sev-bar-track">{"".join(segs)}</div>'
                f'<div class="sev-count">{row["total"]}</div>'
                f'</div>')
        parts.append("</div></div>")

    # ── MITRE ATT&CK tactic coverage (sequential fill) ──
    tactics = metrics.get("tactic_coverage") or []
    if tactics:
        max_tc = max((t["technique_count"] for t in tactics), default=0) or 1
        parts.append('<div class="dash-section">')
        parts.append('<div class="dash-section-title">MITRE ATT&amp;CK tactic '
                     'coverage</div>')
        parts.append('<div class="dash-legend">distinct techniques observed per '
                     'tactic, in ATT&amp;CK tactic order.</div>')
        parts.append('<div class="tactic-bar">')
        for t in tactics:
            count = t["technique_count"]
            fill = _seq_color(count, max_tc)
            parts.append(
                f'<div class="tactic-row">'
                f'<div class="tactic-name">{_esc(t["tactic"])}</div>'
                f'<div class="tactic-track">'
                f'<div class="tactic-fill" style="width:{count / max_tc * 100:.2f}%;'
                f'background-color:{fill}"></div>'
                f'<div class="tactic-count">{count}</div>'
                f'</div></div>')
        parts.append("</div></div>")

    # ── Tactics observed (A4: ordinal ATT&CK order, NOT a sequence) ──
    kc = metrics.get("kill_chain") or []
    if kc:
        max_kc = max((n["technique_count"] for n in kc), default=0) or 1
        parts.append('<div class="dash-section">')
        parts.append('<div class="dash-section-title">Tactics observed '
                     '(ATT&amp;CK order)</div>')
        parts.append('<div class="dash-legend">Ordered by ATT&amp;CK tactic, not '
                     'by time. The timestamp under each tactic is its first '
                     'observation (UTC); the strip is not a sequence and '
                     'implies no causal progression.</div>')
        parts.append('<div class="killchain">')
        for i, node in enumerate(kc):
            count = node["technique_count"]
            fill = _seq_color(count, max_kc)
            txt_color = "#ffffff" if fill in (_SEQ_RAMP[2], _SEQ_RAMP[3]) else "#0b0b0b"
            first_seen = node.get("first_seen") or "—"
            connector = ""
            if i < len(kc) - 1:
                connector = (
                    '<div class="kc-connector">'
                    '<svg width="100%" height="3" preserveAspectRatio="none">'
                    '<line x1="0" y1="1.5" x2="100%" y2="1.5" '
                    'stroke="#cde2fb" stroke-width="2" stroke-dasharray="3,3"/>'
                    '</svg></div>')
            parts.append(
                f'<div class="kc-node">'
                f'<div class="kc-rail">{connector}'
                f'<div class="kc-dot" style="background-color:{fill}">'
                f'<span class="kc-dot-count" style="color:{txt_color}">{count}</span>'
                f'</div></div>'
                f'<div class="kc-tactic">{_esc(node["tactic"])}</div>'
                f'<div class="kc-time">{_esc(first_seen)}</div>'
                f'</div>')
        parts.append("</div></div>")

    parts.append("</div>")
    return "".join(parts)


_FID_RE = re.compile(r"\bF-[A-Za-z0-9_.-]+?-\d{3,}\b")


def _rail_style(fids: list[str], rails: dict | None) -> str:
    """A5: finding-card rail from finding DATA (status + rule severity), never
    from sniffing the card text (which mis-rails a card whose prose mentions
    both CONFIRMED and INFERRED). Solid only when every finding the card
    heading names is CONFIRMED; the hue is the lead finding's rule severity
    when rated, else neutral. No data → no inline rail (CSS neutral)."""
    if not rails:
        return ""
    known = [rails[f] for f in fids if f in rails]
    if not known:
        return ""
    solid = all(r.get("status") == "CONFIRMED" for r in known)
    sev = str(known[0].get("severity") or "UNRATED").upper()
    if sev in ("UNRATED", "INFORMATIONAL") or sev not in _SEVERITY_STYLE:
        color = "#256abf" if solid else "#8a897f"
    else:
        color = _SEVERITY_STYLE[sev]["color"]
    return (f"border-left-style:{'solid' if solid else 'dashed'};"
            f"border-left-color:{color};")


def _finding_rails(manifest: dict, metrics: dict | None,
                   findings: list | None) -> dict:
    """{finding_id: {status, severity}} for card rails: status from the
    findings (or the manifest's deterministic detection block on a
    standalone render), severity from the persisted metrics."""
    sev = (metrics or {}).get("finding_severity") or {}
    src = findings if findings is not None else (
        (manifest.get("detection") or {}).get("findings") or [])
    out = {}
    for f in src:
        if isinstance(f, dict) and f.get("finding_id"):
            out[f["finding_id"]] = {"status": f.get("status"),
                                    "severity": sev.get(f["finding_id"], "UNRATED")}
    return out


def _semantic_html(body_html: str, findings_count: int, report_md: str,
                   rails: dict | None = None) -> str:
    """Post-process raw markdown→HTML with semantic classes, status badges,
    and structural improvements for professional rendering. ``rails`` is the
    {finding_id: {status, severity}} map for finding-card rails (A5)."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(body_html, "html.parser")

    # ── Tag h2 with appendix-header for page-break ──
    for h2 in soup.find_all("h2"):
        text = h2.get_text(strip=True)
        if "appendix" in text.lower() or "finding index" in text.lower():
            h2["class"] = h2.get("class", []) + ["appendix-header"]

    # ── Color-code status badges in text ──
    import re
    from bs4 import NavigableString

    def _replace_status_badges(text_node):
        """Replace CONFIRMED / INFERRED text with styled spans."""
        if not isinstance(text_node, NavigableString):
            return
        raw = str(text_node)

        # Replace "CONFIRMED" (word boundary) with badge
        new = re.sub(
            r'\bCONFIRMED\b',
            '<span class="confirmed-badge">CONFIRMED</span>',
            raw
        )
        new = re.sub(
            r'\bINFERRED\b',
            '<span class="inferred-badge">INFERRED</span>',
            new
        )
        if new != raw:
            new_soup = BeautifulSoup(new, "html.parser")
            text_node.replace_with(*new_soup.contents)

    for text_node in soup.find_all(string=True):
        if "CONFIRMED" in text_node or "INFERRED" in text_node:
            _replace_status_badges(text_node)

    # ── Wrap "Forensic Caveats:" list items in caveat-block ──
    for strong in soup.find_all("strong"):
        if strong.get_text(strip=True).startswith("Forensic Caveats"):
            parent = strong.parent
            if parent and parent.name == "p":
                # Find subsequent <ul> or text
                next_el = parent.find_next_sibling()
                caveats = []
                while next_el and next_el.name in ("ul", "p"):
                    if next_el.name == "ul":
                        caveats.append(next_el)
                    next_el = next_el.find_next_sibling()
                if caveats:
                    wrapper = soup.new_tag("div", **{"class": "caveat-block"})
                    parent.wrap(wrapper)
                    for c in caveats:
                        wrapper.append(c.extract())

    # ── Wrap "Evidence:" paragraphs in evidence-block ──
    for strong in soup.find_all("strong"):
        if strong.get_text(strip=True) == "Evidence:":
            parent = strong.parent
            if parent:
                wrapper = soup.new_tag("div", **{"class": "evidence-block"})
                parent.wrap(wrapper)
                # Move any subsequent siblings into the wrapper
                next_el = wrapper.find_next_sibling()
                while next_el and next_el.name in ("p", "ul"):
                    sibling = next_el
                    next_el = next_el.find_next_sibling()
                    wrapper.append(sibling.extract())

    # ── Wrap each finding (h3 "F-…" appendix entries, h4 Detailed-Findings
    # cards and group cards naming F-IDs) in a finding card. Section headings
    # ("Detailed Findings", "Key Findings") are NOT cards. ──
    for hx in soup.find_all(["h3", "h4"]):
        text = hx.get_text(strip=True)
        fids = _FID_RE.findall(text)
        if not (text.startswith("F-") or (hx.name == "h4" and fids)):
            continue
        wrapper = soup.new_tag("div", **{"class": "finding-detail finding-card"})
        hx.wrap(wrapper)
        stop = ("h2", "h3") if hx.name == "h3" else ("h2", "h3", "h4", "hr")
        current = wrapper.find_next_sibling()
        while current and current.name not in stop:
            next_el = current.find_next_sibling()
            wrapper.append(current.extract())
            current = next_el
        style = _rail_style(fids, rails)
        if style:
            wrapper["style"] = style

    # ── Add confidence color classes to confidence mentions ──
    # Anchored number: '[\d.]+' would swallow the sentence period in
    # "Confidence: 0.60." and crash float().
    conf_re = re.compile(r'Confidence:\s*(\d+(?:\.\d+)?)')
    for text_node in soup.find_all(string=True):
        m = conf_re.search(str(text_node))
        if m:
            val = float(m.group(1))
            cls = "confidence-high" if val >= 0.75 else (
                "confidence-medium" if val >= 0.4 else "confidence-low"
            )
            parent = text_node.parent
            if parent:
                parent["class"] = parent.get("class", []) + [cls]

    # ── Style IOC table cells (monospace for values) ──
    for td in soup.find_all("td"):
        text = td.get_text(strip=True)
        # IP addresses, domains, filepaths, hashes → monospace
        if (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text)
                or re.match(r'^[a-f0-9]{32,}$', text.lower())
                or '\\' in text or '/' in text
                or re.match(r'^[\w.-]+\.[a-z]{2,}$', text)):
            span = soup.new_tag("span", **{"class": "ioc-value"})
            span.string = text
            td.string = ""
            td.append(span)

    # ── Change "## *." section headers to bold ──
    for h2 in soup.find_all("h2"):
        text = h2.get_text(strip=True)
        if text.startswith(("1.", "2.", "3.", "4.", "5.", "6.")):
            h2.string = text  # keep as-is

    return str(soup)


def _build_doc_control(manifest: dict) -> str:
    """Build the document control table for after the cover."""
    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    profile = manifest.get("artifact_profile", "?")
    canary = manifest.get("canary_status", "?")
    classification = _classification(manifest)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    ev_rows = ""
    for name, sha in _evidence_rows(manifest):
        ev_rows += (f'<tr><td><strong>Evidence</strong></td>'
                    f'<td>{name}'
                    + (f'<br><span class="ioc-value">SHA-256: {sha}</span>' if sha else "")
                    + '</td></tr>\n')

    status = _status_line(manifest)
    badge_style = ("background:#F8D7DA; color:#721C24; border-color:#721C24;"
                   if classification == "DRAFT"
                   else "background:#D4EDDA; color:#1B7340; border-color:#1B7340;")
    return f"""<table style="width:100%; margin-top:0;">
<tr><th colspan="2" style="text-align:center; font-size:10pt;">DOCUMENT CONTROL</th></tr>
<tr><td style="width:30%;"><strong>Case</strong></td><td>{case_id}-{case_name}</td></tr>
<tr><td><strong>Classification</strong></td><td><span class="confirmed-badge" style="{badge_style}">{classification}</span></td></tr>
{ev_rows}<tr><td><strong>Artifact Profile</strong></td><td>{profile}</td></tr>
<tr><td><strong>Canary</strong></td><td>{canary}</td></tr>
<tr><td><strong>Generated</strong></td><td>{now}</td></tr>
<tr><td><strong>Pipeline</strong></td><td>Spectre — 7-Phase Forensic Pipeline</td></tr>
<tr><td><strong>Status</strong></td><td>{status}</td></tr>
</table>
<div class="section-hr"></div>"""


def _manifest_from_markdown(md_text: str) -> dict:
    """Fallback for standalone rendering: recover metadata from the report
    header block that _merge_report_md writes."""
    import re
    case_id, case_name, profile, canary = "?", "?", "?", "?"
    m = re.search(r'\*\*Case(?: Reference)?:\*\*\s*(\d+)-(\S+)', md_text)
    if m:
        case_id, case_name = m.group(1), m.group(2)
    m = re.search(r'\*\*(?:Artifact Profile|Evidence Examined):\*\*\s*(.+)', md_text)
    if m:
        profile = m.group(1).strip()
    m = re.search(r'canary\s+([A-Z]+)', md_text)
    if m:
        canary = m.group(1)
    return {
        "case_id": case_id,
        "case_name": case_name,
        "artifact_profile": profile,
        "canary_status": canary,
    }


def _build_toc_html(soup) -> str:
    """Build a Contents block from the report's h2 headings (ids required)."""
    items = []
    for h2 in soup.find_all("h2"):
        hid = h2.get("id")
        text = h2.get_text(strip=True)
        if not hid or text.lower() in ("executive summary",):
            # Exec summary immediately follows the TOC — listing it is noise
            if hid and text.lower() == "executive summary":
                items.append(f'<li><a href="#{hid}">{text}</a></li>')
            continue
        items.append(f'<li><a href="#{hid}">{text}</a></li>')
    if not items:
        return ""
    return ('<div class="toc"><h2>Contents</h2><ul>'
            + "".join(items) + "</ul></div>")


def render_pdf(report_md_path: str, pdf_path: str,
               title: str = "Spectre Forensic Report",
               manifest: dict | None = None,
               findings: list[dict] | None = None) -> tuple[str | None, str | None]:
    """Render report.md to a professionally-styled forensic PDF.

    ``manifest`` is the case manifest dict (preferred — Phase 6 has it in
    scope); when omitted, metadata is recovered from the markdown header.

    The Assessment Dashboard (spec §5) uses the SAME precedence as
    report_docx._resolve_dashboard_metrics: prefer the persisted
    manifest["report"]["dashboard_metrics"] dict; else compute from ``findings``
    if given; else degrade to an explicit "dashboard unavailable" notice. So a
    standalone render (``findings`` is None) of a post-Phase-6 manifest that
    carries persisted metrics still shows the full dashboard — the two formats
    agree rather than disagreeing (a bare report.md render with neither persisted
    metrics nor findings is the only case that degrades).

    Returns (pdf_path, None) on success or (None, reason) if skipped/failed.
    Never raises.
    """
    try:
        import markdown
        from weasyprint import HTML
        from bs4 import BeautifulSoup  # noqa: F401 — availability probe for _semantic_html
    except Exception as e:
        return None, (f"PDF skipped — optional 'report' extra not available "
                      f"({type(e).__name__}: {e}). Install with "
                      f"'pip install spectre-forensic[report]'.")

    try:
        md_text = Path(report_md_path).read_text()

        if manifest is None:
            manifest = _manifest_from_markdown(md_text)
        manifest = _with_approval_state(manifest, report_md_path, findings)

        # ── Convert markdown to HTML ──
        body_html = markdown.markdown(
            md_text,
            extensions=["tables", "fenced_code", "codehilite"],
        )

        # ── Strip duplicate header (cover + doc control already provide this) ──
        from bs4 import BeautifulSoup as _BS
        soup = _BS(body_html, "html.parser")
        # Remove h1 "Spectre Forensic Investigation Report" and its metadata paragraph
        h1 = soup.find("h1")
        if h1 and "spectre forensic" in h1.get_text().lower():
            h1.decompose()
            # Also remove the next <p> (metadata) and <hr>
            for tag in soup.find_all(["p", "hr"], limit=3):
                text = tag.get_text(strip=True)
                if any(kw in text for kw in ["Case:", "Investigator:", "Date:",
                                               "Artifact Profile:", "Pipeline:",
                                               "Classification:"]):
                    tag.decompose()
                elif tag.name == "hr":
                    tag.decompose()
                else:
                    break
        # ── Give every h2 an id (TOC targets) ──
        used_ids: set[str] = set()
        for h2 in soup.find_all("h2"):
            base = re.sub(r"[^a-z0-9]+", "-", h2.get_text(strip=True).lower()).strip("-")
            hid = base or "section"
            n = 2
            while hid in used_ids:
                hid = f"{base}-{n}"
                n += 1
            used_ids.add(hid)
            h2["id"] = hid

        toc_html = _build_toc_html(soup)
        body_html = str(soup)
        findings_count = md_text.count("| F-")

        # ── Post-process HTML for semantics ──
        # (rails are attached after the dashboard metrics are resolved below)

        # ── Assessment Dashboard (spec §5): deterministic. SAME precedence as
        # report_docx._resolve_dashboard_metrics — PREFER the persisted metrics
        # dict (manifest["report"]["dashboard_metrics"], the single source of
        # truth Agent B writes before rendering), else compute from findings,
        # else degrade gracefully. A standalone render (findings is None) of a
        # post-Phase-6 manifest that carries dashboard_metrics thus shows the
        # full dashboard, matching DOCX rather than disagreeing with it. ──
        metrics = (manifest.get("report") or {}).get("dashboard_metrics")
        if metrics is not None:
            dashboard_html = _build_dashboard_html(metrics)
        elif findings is not None:
            # Not persisted (e.g. a direct render_pdf call) — compute via the
            # SAME helper. case_dir is the report's grandparent
            # (case_dir/reports/report.md); ruleset.yaml lives at case_dir.
            try:
                from spectre.pipeline.report_synthesize import _dashboard_metrics
                case_dir = str(Path(report_md_path).resolve().parent.parent)
                metrics = _dashboard_metrics(findings, manifest, case_dir)
            except Exception:
                metrics = None
            dashboard_html = _build_dashboard_html(metrics or {})
        else:
            dashboard_html = _dashboard_unavailable_html()

        body_html = _semantic_html(body_html, findings_count, md_text,
                                   _finding_rails(manifest, metrics, findings))

        # ── Build cover + doc control ──
        cover_html = _build_cover_html(manifest, metrics)
        doc_control_html = _build_doc_control(manifest)

        # ── Watermark: DRAFT until Phase 7 approval, then none ──
        classification = _classification(manifest)
        watermark = "DRAFT" if classification == "DRAFT" else ""
        css = (_PROFESSIONAL_CSS
               .replace("%WATERMARK%", watermark)
               .replace("%CLASSIFICATION%", classification))

        # ── Assemble full HTML ──
        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{cover_html}
<div class="doc-control-section">
{doc_control_html}
</div>
{dashboard_html}
{toc_html}
{body_html}
</body>
</html>"""

        # ── Render PDF ──
        HTML(string=full_html).write_pdf(
            str(pdf_path),
            presentational_hints=True,
        )
        return str(pdf_path), None

    except Exception as e:
        return None, f"PDF render failed ({type(e).__name__}: {e})"
