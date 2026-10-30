"""Gate 6 predicate — integrity fails closed, availability degrades.

The gate previously recorded four real signals and then hardcoded
passed=True. These tests pin the assembled predicate.
"""
from spectre.pipeline.phase_runner import gate_6_passed


def _gate(**over):
    g = {
        "report_exists": True,
        "narrative_complete": True,
        "blindspots_populated": True,
        "iocs_exported": True,
        "verdict_class_consistent": True,
        "llm_used": True,
    }
    g.update(over)
    return g


def test_all_signals_good_passes():
    assert gate_6_passed(_gate()) is True


def test_missing_report_fails():
    assert gate_6_passed(_gate(report_exists=False)) is False


def test_missing_iocs_fails():
    assert gate_6_passed(_gate(iocs_exported=False)) is False


def test_empty_blindspots_fails():
    assert gate_6_passed(_gate(blindspots_populated=False)) is False


def test_verdict_contradiction_fails_closed():
    assert gate_6_passed(_gate(verdict_class_consistent=False)) is False


def test_dead_llm_degrades_but_passes():
    # Availability failure: no narrative, no LLM — the deterministic baseline
    # report is still a valid deliverable and must not block the case.
    assert gate_6_passed(
        _gate(llm_used=False, narrative_complete=False,
              verdict_class_consistent=True)) is True


def test_llm_used_but_no_narrative_fails():
    # Integrity failure: the model ran and produced nothing usable.
    assert gate_6_passed(_gate(llm_used=True, narrative_complete=False)) is False


def test_run_phase_6_returns_computed_gate_not_hardcoded(tmp_path, monkeypatch):
    """End-to-end: run_phase_6's *returned* gate_passed must track the
    computed predicate, not a hardcoded True.

    Forces gate_6_passed() to legitimately evaluate False (an integrity
    failure: the LLM claims to have run but produced no executive_summary)
    by monkeypatching synthesize_report, then asserts both that the gate
    genuinely failed and that the function's return value reflects it. A
    regression that re-hardcodes `"gate_passed": True` in the return dict
    would pass every other test in this repo (none else exercises a
    failing gate at the run_phase_6 level) but would fail this one.
    """
    import spectre.pipeline.report_synthesize as rs
    from spectre.pipeline.phase_runner import run_phase_6

    def _fake_synthesize_report(*args, **kwargs):
        return {
            "executive_summary": "",  # no narrative produced
            "threat_narrative": "",
            "verdict": "",
            "findings_narrative": [],
            "timeline_narrative": "",
            "methodology_narrative": "",
            "token_usage": {"prompt": 0, "completion": 0},
            "violations": [],
            "llm_used": True,  # ...yet the LLM claims to have run
            "api_error": None,
        }

    monkeypatch.setattr(rs, "synthesize_report", _fake_synthesize_report)

    case_dir = tmp_path / "998-gatefail"
    (case_dir / "findings").mkdir(parents=True)

    manifest = {
        "case_id": "998",
        "case_name": "gatefail",
        "artifact_profile": "pcap-focused",
        "canary_status": "FULL",
        "evidence": [],
    }
    result = run_phase_6(str(case_dir), manifest, skip_ai=False)

    # The predicate genuinely failed (integrity: llm_used but no narrative)...
    assert manifest["gate_6"]["passed"] is False
    # ...and the returned value must say so too, not a stale/hardcoded True.
    assert result["gate_passed"] is False
    assert result["gate_passed"] == manifest["gate_6"]["passed"]
    # "success" is the key runner.py's run_phase() actually gates on
    # (runner.py:95, checked at runner.py:433-437 before Phase 7). If it
    # stays hardcoded True, an integrity failure never blocks progression —
    # the gate computes the right answer and nothing consults it.
    assert result["success"] is False


def test_run_phase_6_success_true_on_availability_degrade(tmp_path, monkeypatch):
    """Availability failures must NOT block: this pins that `success` is
    True (not just `gate_passed`) when the LLM is unavailable/deferred and
    the deterministic baseline report is used instead — the host provider's
    default, non-degenerate path. This is the sibling to the integrity-
    failure test above, guarding against a fix that conflates "any
    degradation" with "block the case."
    """
    import spectre.pipeline.report_synthesize as rs
    from spectre.pipeline.phase_runner import run_phase_6

    def _fake_synthesize_report(*args, **kwargs):
        return {
            "executive_summary": "",
            "threat_narrative": "",
            "verdict": "",
            "findings_narrative": [],
            "timeline_narrative": "",
            "methodology_narrative": "",
            "token_usage": {"prompt": 0, "completion": 0},
            "violations": [],
            "llm_used": False,  # LLM unavailable/deferred — host default path
            "deferred": True,
            "api_error": "host mode — report synthesis deferred to orchestrating agent",
        }

    monkeypatch.setattr(rs, "synthesize_report", _fake_synthesize_report)

    case_dir = tmp_path / "999-degrade"
    (case_dir / "findings").mkdir(parents=True)

    manifest = {
        "case_id": "999",
        "case_name": "degrade",
        "artifact_profile": "pcap-focused",
        "canary_status": "FULL",
        "evidence": [],
    }
    result = run_phase_6(str(case_dir), manifest, skip_ai=False)

    # Availability failure degrades, it does not block.
    assert manifest["gate_6"]["passed"] is True
    assert result["gate_passed"] is True
    assert result["success"] is True
def test_run_phase_6_persists_dashboard_metrics_to_disk(tmp_path):
    """Regression: dashboard_metrics (persisted by _merge_report_md into
    manifest["report"]) must survive to the on-disk manifest.

    run_phase_6 rebuilds manifest["report"] near the end; a wholesale
    reassignment there silently drops dashboard_metrics before _save_manifest
    flushes it, so the dashboard's single persisted source never reaches disk
    (in-process renders still work, a standalone/disk re-read does not). This
    pins the in-place update.
    """
    import yaml
    from spectre.pipeline.phase_runner import run_phase_6

    case_dir = tmp_path / "777-persist"
    (case_dir / "findings").mkdir(parents=True)
    (case_dir / "findings" / "F-777-001.yaml").write_text(
        "finding_id: F-777-001\n"
        "status: INFERRED\n"
        "confidence: 0.5\n"
        "title: 'test-rule — sample finding'\n"
        "mitre_attack: T1218.011\n"
        "event_time: '2026-06-20T11:47:33.880Z'\n"
    )

    manifest = {
        "case_id": "777",
        "case_name": "persist",
        "artifact_profile": "fixture-test",
        "canary_status": "FULL",
        "evidence": [],
    }
    # skip_ai → deterministic baseline; no LLM seam needed.
    run_phase_6(str(case_dir), manifest, skip_ai=True)

    # In-memory: the reassignment must not have clobbered it.
    assert "dashboard_metrics" in manifest["report"]
    # On disk: it must round-trip through _save_manifest.
    disk = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert "dashboard_metrics" in (disk.get("report") or {}), \
        "dashboard_metrics was dropped before the manifest was saved"
    assert "kpis" in disk["report"]["dashboard_metrics"]


def test_run_phase_6_passes_findings_to_renderers(tmp_path, monkeypatch):
    """Regression: run_phase_6 must pass the case findings to render_pdf AND
    render_docx. Without it both renderers see findings=None, treat the run as
    a standalone render, and emit 'Dashboard unavailable' instead of the
    Assessment Dashboard — the dashboard silently never appears in the real
    pipeline output even though metrics are computed and persisted.
    """
    from pathlib import Path
    import spectre.pipeline.report_pdf as rp
    import spectre.pipeline.report_docx as rd
    from spectre.pipeline.phase_runner import run_phase_6

    captured = {}

    def _fake_render_pdf(md_path, out_path, title="", manifest=None, findings=None):
        captured["pdf_findings"] = findings
        Path(out_path).write_bytes(b"%PDF-1.7\n")  # run_phase_6 stat()s the file
        return out_path, None

    def _fake_render_docx(md_path, out_path, title="", manifest=None, findings=None):
        captured["docx_findings"] = findings
        Path(out_path).write_bytes(b"PK\x03\x04")  # minimal so stat() works
        return out_path, None

    monkeypatch.setattr(rp, "render_pdf", _fake_render_pdf)
    monkeypatch.setattr(rd, "render_docx", _fake_render_docx)

    case_dir = tmp_path / "776-wiring"
    (case_dir / "findings").mkdir(parents=True)
    (case_dir / "findings" / "F-776-001.yaml").write_text(
        "finding_id: F-776-001\nstatus: INFERRED\nconfidence: 0.5\n"
        "title: 'test-rule — sample'\nmitre_attack: T1218.011\n"
        "event_time: '2026-06-20T11:47:33.880Z'\n"
    )
    manifest = {
        "case_id": "776", "case_name": "wiring",
        "artifact_profile": "fixture-test", "canary_status": "FULL",
        "evidence": [],
    }
    run_phase_6(str(case_dir), manifest, skip_ai=True)

    # The regression is None (→ "Dashboard unavailable" standalone path) vs a
    # real list (→ dashboard renders from persisted/computed metrics). Both
    # renderers must receive a list, not None.
    assert captured.get("pdf_findings") is not None, "render_pdf got findings=None"
    assert captured.get("docx_findings") is not None, "render_docx got findings=None"
    assert isinstance(captured["pdf_findings"], list)
    assert isinstance(captured["docx_findings"], list)


def _p6_case(tmp_path, name="775-hash"):
    case_dir = tmp_path / name
    (case_dir / "findings").mkdir(parents=True)
    (case_dir / "findings" / f"F-{name[:3]}-001.yaml").write_text(
        f"finding_id: F-{name[:3]}-001\nstatus: INFERRED\nconfidence: 0.5\n"
        "title: 'test-rule — sample'\nmitre_attack: T1218.011\n"
        "event_time: '2026-06-20T11:47:33.880Z'\n"
    )
    manifest = {
        "case_id": name[:3], "case_name": name[4:],
        "artifact_profile": "fixture-test", "canary_status": "FULL",
        "evidence": [],
    }
    return case_dir, manifest


def _merge_rows(case_dir):
    import json
    rows = [json.loads(ln) for ln in
            (case_dir / "audit.jsonl").read_text().splitlines() if ln.strip()]
    return [r for r in rows if r.get("phase_step") == "S3-merge-report"]


def test_run_phase_6_audit_row_carries_dashboard_metrics_sha256(tmp_path):
    """TB-port A6: the Phase-6 report_synthesize audit row records the sha256
    of the persisted dashboard metrics (the mutable manifest copy the PDF/DOCX
    dashboards render from), on every S3-merge-report row."""
    import yaml
    from spectre.pipeline.phase_runner import run_phase_6
    from spectre.pipeline.report_synthesize import _dashboard_metrics_sha256

    case_dir, manifest = _p6_case(tmp_path)
    run_phase_6(str(case_dir), manifest, skip_ai=True)
    disk = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    want = _dashboard_metrics_sha256(disk["report"]["dashboard_metrics"])
    rows = _merge_rows(case_dir)
    assert rows
    for r in rows:
        assert r["params"]["dashboard_metrics_sha256"] == want


def test_verify_full_dashboard_metrics_advisory(tmp_path):
    """The advisory re-check passes on an untouched case and flags (without
    flipping ok on its own) a post-hoc edit to the persisted metrics."""
    import yaml
    from spectre.pipeline.audit import verify_full
    from spectre.pipeline.phase_runner import run_phase_6

    case_dir, manifest = _p6_case(tmp_path, "774-advis")
    run_phase_6(str(case_dir), manifest, skip_ai=True)
    rep = verify_full(str(case_dir))
    assert rep["checks"]["dashboard_metrics"]["passed"] is True
    ok_before = rep["ok"]

    mp = case_dir / "manifest.yaml"
    disk = yaml.safe_load(mp.read_text())
    disk["report"]["dashboard_metrics"]["kpis"]["confirmed"] = 99
    mp.write_text(yaml.safe_dump(disk))
    rep2 = verify_full(str(case_dir))
    assert rep2["checks"]["dashboard_metrics"]["passed"] is False
    assert "advisory" in rep2["checks"]["dashboard_metrics"]["detail"]
    assert rep2["ok"] == ok_before
