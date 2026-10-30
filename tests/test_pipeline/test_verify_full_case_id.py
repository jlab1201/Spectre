"""verify_full()'s case_id check false-positives on every case reaching
Phase 6 (A8-F2 bonus). Most audit rows record case_id = Path(case_dir).name
(e.g. "002-name"), but the Phase-6 report row historically used
case_id = manifest["case_id"] (bare "002"), tripping the mismatch check on
every untampered case that ever writes report.md.
"""
from pathlib import Path

from spectre.pipeline.audit import verify_full, append as audit_append


def _seed_case(case_dir: Path, bare_case_id: str = "002") -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    dir_name = case_dir.name  # e.g. "002-a8-sha-tamper"

    # A normal row, as most of the pipeline writes it.
    audit_append(str(case_dir), {
        "actor": "case_setup", "action": "evidence_register",
        "tool": "case_setup.py", "case_id": dir_name,
        "output_path": "", "output_sha256": "", "result": "success",
        "phase": 0, "phase_step": "S2-register",
    })
    # The Phase-6 report row, as phase_runner.py's run_phase_6 writes it.
    audit_append(str(case_dir), {
        "actor": "spectre-lead", "action": "note",
        "tool": "report_synthesize._merge_report_md", "case_id": bare_case_id,
        "output_path": str(case_dir / "reports" / "report.md"),
        "output_sha256": "", "result": "success",
        "phase": 6, "phase_step": "S3-merge-report",
    })


def test_case_reaching_phase_6_passes_case_id_check(tmp_path):
    case_dir = tmp_path / "002-a8-sha-tamper"
    _seed_case(case_dir, bare_case_id="002")

    report = verify_full(str(case_dir))
    assert report["checks"]["case_id"]["passed"] is True, report["checks"]["case_id"]


def test_genuinely_wrong_case_id_is_still_caught(tmp_path):
    case_dir = tmp_path / "002-a8-sha-tamper"
    _seed_case(case_dir, bare_case_id="002")
    audit_append(str(case_dir), {
        "actor": "attacker", "action": "note", "tool": "x",
        "case_id": "999-not-this-case",
        "output_path": "", "output_sha256": "", "result": "success",
        "phase": 0, "phase_step": "note",
    })

    report = verify_full(str(case_dir))
    assert report["checks"]["case_id"]["passed"] is False
