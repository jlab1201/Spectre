"""TB-port T8b: DOCX Assessment Dashboard (bordered tables + U+2588 glyph
bars; magnitude = glyph count, never cell width) with the TB-PORT honesty
amendments A1-A6. Verified with python-docx/LibreOffice only, not Word."""
from __future__ import annotations

import pytest

from spectre.pipeline.report_synthesize import _dashboard_metrics, _merge_report_md
from tests.test_dashboard_metrics import (
    _findings,
    _manifest,
    _write_ruleset,
)


@pytest.fixture()
def case_dir(tmp_path):
    _write_ruleset(tmp_path)
    (tmp_path / "reports").mkdir()
    return tmp_path

docx = pytest.importorskip("docx")

from spectre.pipeline.report_docx import (  # noqa: E402
    _BLOCK,
    _add_dashboard_section,
    _glyph_count,
    _resolve_dashboard_metrics,
    render_docx,
)


def _text(doc) -> str:
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for row in t.rows:
            for c in row.cells:
                parts.append(c.text)
    return "\n".join(parts)


def _dash(metrics, standalone=False):
    d = docx.Document()
    _add_dashboard_section(d, metrics, standalone=standalone)
    return d


def _extraction(*states):
    return {"results": {
        f"/ev/i{i}": {"module": "evtx", "extraction_status": st,
                      "events": 0 if st in ("EMPTY", "EXTRACTION_FAILED") else 5}
        for i, st in enumerate(states)}}


def test_glyph_count_exact_then_scaled():
    assert _glyph_count(0, 10) == 0
    assert _glyph_count(7, 40) == 7
    assert _glyph_count(80, 80) == 40
    assert _glyph_count(1, 1000) == 1


def test_dashboard_tiles_labels_and_provenance(case_dir):
    t = _text(_dash(_dashboard_metrics(_findings(), _manifest(), str(case_dir))))
    assert "Assessment Dashboard" in t
    assert "Multi-source corroborated" in t
    assert "Deterministic — computed from finding facts; no AI input" in t
    assert "Confidence:" in t


def test_dashboard_headline_is_qualified_leads_only(case_dir):
    fs = [dict(f, status="INFERRED") for f in _findings()]
    t = _text(_dash(_dashboard_metrics(fs, _manifest(), str(case_dir))))
    assert "Lead (INFERRED, single-source): Public-facing exploit" in t
    assert "Leads only" in t
    assert "Top rule severity" in t


def test_dashboard_severity_glyphs_are_counts(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    d = _dash(m)
    sev_table = next(t for t in d.tables
                     if "CRITICAL" in " ".join(c.text for r in t.rows for c in r.cells)
                     and _BLOCK in " ".join(c.text for r in t.rows for c in r.cells))
    got = {}
    for row in sev_table.rows:
        for r in m["severity_counts"]:
            if r["severity"] in row.cells[0].text:
                got[r["severity"]] = sum(c.text.count(_BLOCK) for c in row.cells)
    assert got == {r["severity"]: r["total"] for r in m["severity_counts"]}


def test_dashboard_tactics_observed_is_ordinal(case_dir):
    t = _text(_dash(_dashboard_metrics(_findings(), _manifest(), str(case_dir))))
    assert "Tactics observed (ATT&CK order)" in t
    assert "not a sequence" in t
    assert "Attack progression" not in t and "kill chain" not in t.lower()
    assert "2026-01-01T09:00:00Z" in t


def test_dashboard_legend_from_predicate(case_dir):
    fs = _findings()
    t = _text(_dash(_dashboard_metrics(fs, _manifest(), str(case_dir))))
    assert "lighter = INFERRED (single-source)" in t
    fs[2]["cross_validated"] = True
    t = _text(_dash(_dashboard_metrics(fs, _manifest(), str(case_dir))))
    assert "(single-source)" not in t.split("lighter = ")[1][:40]


def test_dashboard_partial_coverage_warning_and_tile(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("SUCCESS", "EMPTY")
    t = _text(_dash(_dashboard_metrics(_findings(), man, str(case_dir))))
    assert "1/2" in t and "Evidence examined" in t
    assert "Partial coverage" in t and "1 EMPTY" in t


def test_dashboard_no_coverage_never_clean(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("EMPTY", "EXTRACTION_FAILED")
    t = _text(_dash(_dashboard_metrics([], man, str(case_dir))))
    assert "No evidence was examined — no assessment possible" in t
    assert "0/2" in t
    assert "nothing to chart" not in t
    assert _BLOCK not in t


def test_dashboard_zero_findings_legacy_dict_is_honest():
    t = _text(_dash({"kpis": {"findings_total": 0}}))
    assert "nothing to chart" in t.lower()
    assert _BLOCK not in t


def test_dashboard_standalone_unavailable():
    t = _text(_dash(None, standalone=True))
    assert "unavailable" in t.lower() and _BLOCK not in t


def test_resolve_prefers_persisted_then_computes(case_dir):
    man = _manifest()
    md = case_dir / "reports" / "report.md"
    md.write_text(_merge_report_md(None, _findings(), man, str(case_dir), [], {}))
    m, standalone = _resolve_dashboard_metrics(str(md), man, None)
    assert standalone is False and m is man["report"]["dashboard_metrics"]
    man2 = _manifest()
    m2, s2 = _resolve_dashboard_metrics(str(md), man2, _findings())
    assert s2 is False and m2["kpis"]["findings_total"] == 8
    m3, s3 = _resolve_dashboard_metrics(str(md), _manifest(), None)
    assert m3 is None and s3 is True


def test_render_docx_end_to_end(case_dir):
    man = _manifest()
    md = case_dir / "reports" / "report.md"
    md.write_text(_merge_report_md(None, _findings(), man, str(case_dir), [], {}))
    out = case_dir / "reports" / "report.docx"
    path, reason = render_docx(str(md), str(out), manifest=man, findings=_findings())
    assert path == str(out), reason
    t = _text(docx.Document(str(out)))
    assert "Assessment Dashboard" in t and _BLOCK in t
    # the report body's _italic_ BLUF renders without literal underscores
    assert "_Bottom-line-up-front" not in t
