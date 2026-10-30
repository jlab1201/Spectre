"""report.md is the single source of truth and must be covered by the chain.

verify_full() re-hashed evidence but never the deliverable, so a post-Phase-6
rewrite of report.md was invisible to the integrity check.
"""
import hashlib
import json
from pathlib import Path

from spectre.pipeline.audit import verify_full


def _seed(case_dir, body="# Report\n\nOriginal.\n"):
    """Seed a report.md plus the S3-merge-report row that records its write.

    phase_step matters: check 6 scopes itself to "S3-merge-report" rows, which
    are the only ones that record the Phase 6 deliverable write. This mirrors
    what phase_runner.py actually appends.
    """
    reports = Path(case_dir) / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    rp = reports / "report.md"
    rp.write_text(body)
    sha = hashlib.sha256(body.encode()).hexdigest()
    row = {
        "actor": "spectre-lead", "action": "write", "tool": "report-writer",
        "case_id": Path(case_dir).name, "output_path": str(rp),
        "output_sha256": sha, "result": "success", "phase": 6,
        "phase_step": "S3-merge-report",
    }
    with open(Path(case_dir) / "audit.jsonl", "a") as f:
        f.write(json.dumps(row) + "\n")
    return rp


def test_unmodified_report_passes(temp_case_dir):
    _seed(temp_case_dir)
    result = verify_full(temp_case_dir)
    assert result["checks"]["report_integrity"]["passed"] is True


def test_modified_report_fails(temp_case_dir):
    rp = _seed(temp_case_dir)
    rp.write_text("# Report\n\nTampered.\n")
    result = verify_full(temp_case_dir)
    assert result["checks"]["report_integrity"]["passed"] is False
    assert "report.md" in result["checks"]["report_integrity"]["detail"]


def test_no_report_row_is_not_a_failure(temp_case_dir):
    # A case that never reached Phase 6 has nothing to verify.
    result = verify_full(temp_case_dir)
    assert result["checks"]["report_integrity"]["passed"] is True


def test_non_phase6_report_row_does_not_arm_check_6(temp_case_dir):
    # Check 6 is scoped to phase_step == "S3-merge-report" — the rows that
    # actually record the Phase 6 deliverable write. A row that merely happens
    # to name report.md from some other phase must not arm the check, because
    # its sha256 does not describe the deliverable. Without the scope this
    # abstain case reported a tamper verdict.
    reports = Path(temp_case_dir) / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "report.md").write_text("# Phase 5 stub\n")
    stub_row = {
        "actor": "spectre-lead", "action": "note", "tool": "llm:host",
        "case_id": Path(temp_case_dir).name,
        "output_path": str(reports / "report.md"),
        "output_sha256": "deadbeef" * 8, "result": "success", "phase": 5,
        "phase_step": "S1-explain-norm",
    }
    with open(Path(temp_case_dir) / "audit.jsonl", "a") as f:
        f.write(json.dumps(stub_row) + "\n")

    result = verify_full(temp_case_dir)
    integrity = result["checks"]["report_integrity"]
    assert integrity["passed"] is True
    assert "has not reached Phase 6" in integrity["detail"]


def test_scoping_does_not_weaken_real_tamper_detection(temp_case_dir):
    # A genuine S3-merge-report row whose hash no longer matches disk must
    # still fail closed, even with an unrelated later row present.
    rp = _seed(temp_case_dir)
    later_row = {
        "actor": "spectre-lead", "action": "note", "tool": "llm:host",
        "case_id": Path(temp_case_dir).name,
        "output_path": str(Path(temp_case_dir) / "findings" / "F-000-001.yaml"),
        "output_sha256": "", "result": "success", "phase": 5,
        "phase_step": "S1-explain-norm",
    }
    with open(Path(temp_case_dir) / "audit.jsonl", "a") as f:
        f.write(json.dumps(later_row) + "\n")
    rp.write_text("# Report\n\nTampered.\n")

    result = verify_full(temp_case_dir)
    assert result["checks"]["report_integrity"]["passed"] is False
    assert result["ok"] is False


def test_audited_but_missing_from_disk_fails(temp_case_dir):
    # A report.md that was audited but then deleted is a tamper signal.
    _seed(temp_case_dir)
    rp = Path(temp_case_dir) / "reports" / "report.md"
    rp.unlink()
    result = verify_full(temp_case_dir)
    assert result["checks"]["report_integrity"]["passed"] is False
    assert result["ok"] is False
