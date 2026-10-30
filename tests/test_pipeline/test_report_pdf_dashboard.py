"""TB-port T7: Threat-Briefing PDF cover + Assessment Dashboard, with the
honesty amendments of TB-PORT.md (A1-A6). The current design's guarantees
win: a leads-only case never headlines a bare CRITICAL, a blind/failed case
never renders a clean dashboard, the kill chain is ordinal (not a sequence),
and finding-card rails come from finding data, not text sniffing."""
from __future__ import annotations

from pathlib import Path

import pytest

from spectre.pipeline.report_pdf import (
    _build_cover_html,
    _build_dashboard_html,
    _dashboard_unavailable_html,
    _semantic_html,
    render_pdf,
)
from spectre.pipeline.report_synthesize import (
    _dashboard_metrics,
    _merge_report_md,
    _persist_dashboard_metrics,
)

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


def _leads_only():
    return [dict(f, status="INFERRED") for f in _findings()]


def _extraction(*states):
    return {"results": {
        f"/ev/i{i}": {"module": "evtx", "extraction_status": st,
                      "events": 0 if st in ("EMPTY", "EXTRACTION_FAILED") else 5}
        for i, st in enumerate(states)}}


def _report_md(case_dir: Path, findings=None, manifest=None) -> Path:
    findings = _findings() if findings is None else findings
    manifest = manifest or _manifest()
    md = _merge_report_md(None, findings, manifest, str(case_dir), [], {})
    p = case_dir / "reports" / "report.md"
    p.write_text(md)
    return p


# ── Cover (A1/A2) ──────────────────────────────────────────────────────
def test_cover_kpi_labels_are_honest(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    html = _build_cover_html(_manifest(), m)
    assert "Multi-source corroborated" in html
    assert "Confirmed multi-source" not in html
    assert "Top rule severity" in html


def test_cover_leads_only_headline_is_qualified(case_dir):
    m = _dashboard_metrics(_leads_only(), _manifest(), str(case_dir))
    html = _build_cover_html(_manifest(), m)
    assert "Lead (INFERRED, single-source): Public-facing exploit" in html
    assert "Leads only" in html


def test_cover_without_metrics_keeps_legacy_line():
    man = _manifest()
    html = _build_cover_html(man, None)
    assert "cover-kpi-strip" not in html
    assert "finding(s)" in html


def test_cover_no_coverage_says_so(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("EMPTY", "EXTRACTION_FAILED")
    m = _dashboard_metrics([], man, str(case_dir))
    html = _build_cover_html(man, m)
    assert "No evidence was examined" in html


# ── Dashboard (A2/A3/A4/A6) ────────────────────────────────────────────
def test_build_dashboard_html_has_all_components(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    html = _build_dashboard_html(m)
    assert "Assessment Dashboard" in html
    assert "stat-tile" in html
    assert "Severity distribution" in html
    assert "sev-seg solid" in html
    assert "sev-seg hollow" in html
    assert "tactic coverage" in html.lower()
    assert "▲" in html
    for r in m["severity_counts"]:
        assert r["severity"] in html


def test_dashboard_kill_chain_is_ordinal_not_sequence(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    html = _build_dashboard_html(m)
    assert "Tactics observed (ATT&amp;CK order)" in html
    assert "kill chain" not in html.lower()
    assert "not a sequence" in html


def test_dashboard_provenance_stamp(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    html = _build_dashboard_html(m)
    assert "Deterministic — computed from finding facts; no AI input" in html


def test_dashboard_confidence_banner_reused(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    assert m["confidence_banner"]
    html = _build_dashboard_html(m)
    assert m["confidence_banner"].split("(s)")[0] in html


def test_dashboard_legend_from_predicate(case_dir):
    fs = _findings()
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    assert "hollow = INFERRED (single-source)" in _build_dashboard_html(m)
    # an INFERRED finding corroborated by 2 methods → no blanket claim
    fs[2]["cross_validated"] = True
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    html = _build_dashboard_html(m)
    assert "(single-source)" not in html.split("Severity distribution")[1][:400]


def test_dashboard_coverage_tile_present(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("SUCCESS", "EMPTY")
    m = _dashboard_metrics(_findings(), man, str(case_dir))
    html = _build_dashboard_html(m)
    assert "1/2" in html and "Evidence examined" in html
    assert "not examined" in html   # partial-coverage warning


def test_dashboard_no_coverage_is_never_clean(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("EMPTY", "EXTRACTION_FAILED")
    m = _dashboard_metrics([], man, str(case_dir))
    html = _build_dashboard_html(m)
    assert "No evidence was examined — no assessment possible" in html
    assert "0/2" in html
    assert "EXTRACTION_FAILED" in html and "EMPTY" in html
    assert "nothing to chart" not in html


def test_dashboard_zero_findings_full_coverage_is_honest(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("SUCCESS")
    m = _dashboard_metrics([], man, str(case_dir))
    html = _build_dashboard_html(m)
    assert "No findings were produced" in html
    assert "1/1" in html
    assert "sev-seg" not in html


def test_build_dashboard_html_legacy_empty_dict_is_honest():
    html = _build_dashboard_html({"kpis": {"findings_total": 0}})
    assert "nothing to chart" in html
    assert "sev-seg" not in html


# ── Finding-card rail (A5) ─────────────────────────────────────────────
def _card_html(title="F-900-001: t", body="<p>text mentions INFERRED and CONFIRMED</p>"):
    return f"<h3>Detailed Findings</h3><h4>{title}</h4>{body}<h4>F-900-003: x</h4><p>y</p>"


def test_rail_is_data_driven_not_text_sniffed():
    pytest.importorskip("bs4")  # optional [report] extra
    rails = {"F-900-001": {"status": "INFERRED", "severity": "CRITICAL"},
             "F-900-003": {"status": "CONFIRMED", "severity": "UNRATED"}}
    out = _semantic_html(_card_html(), 0, "", rails)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(out, "html.parser")
    cards = soup.select("div.finding-card")
    assert len(cards) == 2
    s1, s2 = cards[0]["style"], cards[1]["style"]
    assert "dashed" in s1 and "#d03b3b" in s1        # INFERRED + CRITICAL hue
    assert "solid" in s2 and "#256abf" in s2         # CONFIRMED + UNRATED neutral


def test_rail_absent_without_data():
    pytest.importorskip("bs4")  # optional [report] extra
    out = _semantic_html(_card_html(), 0, "", None)
    assert "border-left-style" not in out


# ── Render (never raises; standalone precedence A7) ────────────────────
def test_render_pdf_with_findings_nonempty(case_dir):
    pytest.importorskip("weasyprint")
    md_path = _report_md(case_dir)
    manifest = _manifest()
    _persist_dashboard_metrics(_findings(), manifest, str(case_dir))
    out, reason = render_pdf(str(md_path), str(case_dir / "reports" / "r.pdf"),
                             manifest=manifest, findings=_findings())
    assert out is not None, reason
    assert Path(out).stat().st_size > 5000


def test_render_pdf_computes_metrics_when_not_persisted(case_dir):
    pytest.importorskip("weasyprint")
    md_path = _report_md(case_dir)
    manifest = _manifest()
    manifest.pop("report", None)
    out, reason = render_pdf(str(md_path), str(case_dir / "reports" / "r2.pdf"),
                             manifest=manifest, findings=_findings())
    assert out is not None, reason


def test_render_pdf_standalone_prefers_persisted_metrics(case_dir, monkeypatch):
    pytest.importorskip("weasyprint")
    import spectre.pipeline.report_pdf as rp
    md_path = _report_md(case_dir)
    manifest = _manifest()
    _persist_dashboard_metrics(_findings(), manifest, str(case_dir))
    calls = {"build": 0, "unavailable": 0}
    real_build, real_un = rp._build_dashboard_html, rp._dashboard_unavailable_html
    monkeypatch.setattr(rp, "_build_dashboard_html", lambda m: (
        calls.__setitem__("build", calls["build"] + 1), real_build(m))[1])
    monkeypatch.setattr(rp, "_dashboard_unavailable_html", lambda: (
        calls.__setitem__("unavailable", calls["unavailable"] + 1), real_un())[1])
    out, reason = rp.render_pdf(str(md_path), str(case_dir / "reports" / "s.pdf"),
                                manifest=manifest, findings=None)
    assert out is not None, reason
    assert calls == {"build": 1, "unavailable": 0}


def test_render_pdf_bare_standalone_shows_unavailable():
    assert "Dashboard unavailable" in _dashboard_unavailable_html()


def test_render_pdf_never_raises_on_bad_input(tmp_path):
    out, reason = render_pdf(str(tmp_path / "missing.md"),
                             str(tmp_path / "x.pdf"), findings=_findings())
    assert out is None and reason


def test_cover_no_coverage_has_no_markdown_and_states_counts(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("EMPTY")
    m = _dashboard_metrics([], man, str(case_dir))
    assert "**" not in m["coverage"]["sentence"]
    html = _build_cover_html(man, m)
    assert "**" not in html
    assert "1 EMPTY" in html
