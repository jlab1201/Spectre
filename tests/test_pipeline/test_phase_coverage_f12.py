"""R1-F12: phase_coverage required a `report_generated` action that nothing
in src/ writes, so it failed on EVERY completed case and could never signal
a real gap. It now keys off the row Phase 6 actually writes (phase_step
S3-merge-report, chained after the finding's registration). A completed
case (one with a report row) with a real gap fails verify_full; an
in-progress case stays advisory. Superseded/excluded findings are exempt.
"""
import hashlib

import yaml

from spectre.pipeline.audit import append as audit_append, verify_full


def _case(tmp_path):
    case_dir = tmp_path / "003-cov"
    for sub in ("evidence", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True)
    return case_dir


def _finding(case_dir, fid):
    p = case_dir / "findings" / f"{fid}.yaml"
    p.write_text(yaml.safe_dump({"finding_id": fid, "status": "INFERRED"}))
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(p),
        "output_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        "result": "success", "finding_id": fid, "params": {"finding_id": fid},
        "phase": 3, "phase_step": "S1-emit"})


def _review(case_dir, fid):
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "adversarial_review",
        "tool": "phase5-grounding-probe", "case_id": case_dir.name,
        "result": "success", "finding_id": fid, "params": {"finding_id": fid},
        "phase": 5, "phase_step": "S5-grounding-probe"})


def _report(case_dir):
    rp = case_dir / "reports" / "report.md"
    rp.write_text("# report\n")
    audit_append(str(case_dir), {
        "actor": "spectre-lead", "action": "note",
        "tool": "report_synthesize._merge_report_md", "case_id": case_dir.name,
        "output_path": "reports/report.md",
        "output_sha256": hashlib.sha256(rp.read_bytes()).hexdigest(),
        "params": {"disclosed_coverage_gaps": []},
        "result": "success", "phase": 6, "phase_step": "S3-merge-report"})


def test_completed_case_passes_phase_coverage(tmp_path):
    cd = _case(tmp_path)
    _finding(cd, "F-003-001")
    _review(cd, "F-003-001")
    _report(cd)
    rep = verify_full(str(cd))
    assert rep["checks"]["phase_coverage"]["passed"], rep["checks"]["phase_coverage"]


def test_completed_case_with_unreviewed_finding_fails(tmp_path):
    cd = _case(tmp_path)
    _finding(cd, "F-003-001")
    _report(cd)
    rep = verify_full(str(cd))
    assert not rep["checks"]["phase_coverage"]["passed"]
    assert "adversarial_review" in rep["checks"]["phase_coverage"]["detail"]
    assert rep["ok"] is False


def test_finding_created_after_report_is_a_gap(tmp_path):
    cd = _case(tmp_path)
    _finding(cd, "F-003-001")
    _review(cd, "F-003-001")
    _report(cd)
    _finding(cd, "F-003-002")
    _review(cd, "F-003-002")
    rep = verify_full(str(cd))
    assert not rep["checks"]["phase_coverage"]["passed"]
    assert "F-003-002" in rep["checks"]["phase_coverage"]["detail"]


def test_in_progress_case_stays_advisory(tmp_path):
    cd = _case(tmp_path)
    _finding(cd, "F-003-001")
    rep = verify_full(str(cd))
    assert not rep["checks"]["phase_coverage"]["passed"]
    assert "advisory" in rep["checks"]["phase_coverage"]["detail"]


def test_superseded_finding_is_exempt(tmp_path):
    cd = _case(tmp_path)
    _finding(cd, "F-003-001")
    from spectre.pipeline.emit_finding import supersede_prior_findings
    from spectre.pipeline.phase_runner import _phase3_close_bracket, _phase3_open_bracket
    run = _phase3_open_bracket(str(cd))  # supersede is honoured only in a bracket
    assert supersede_prior_findings(str(cd), "test", run_id=run["run_id"])[
        "superseded"] == ["F-003-001"]
    _finding(cd, "F-003-002")
    _phase3_close_bracket(str(cd), run, 1)
    _review(cd, "F-003-002")
    _report(cd)
    rep = verify_full(str(cd))
    assert rep["checks"]["phase_coverage"]["passed"], rep["checks"]["phase_coverage"]
    assert rep["checks"]["supersede_batches"]["passed"], rep["checks"]["supersede_batches"]

