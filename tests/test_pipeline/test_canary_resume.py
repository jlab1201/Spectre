"""A8-F1: run_phase_0's docstring claims it "re-runs canary and verifies
case state", but the body only ever READ the stored manifest["canary_status"]
string -- a canary that was FULL when the case was created (tools present)
could go DEAD between analyst sessions (tools uninstalled, wrong venv, disk
full...) and a --phase N resume would never notice, because Phase 0 was
never re-invoked with a live canary check once gate_0 had passed once.

Fix: run_phase_0() now actually calls canary.run_canary() on every
invocation (including resume) and fails closed (gate_passed/success=False)
when the FRESH check comes back DEAD -- matching case-creation behavior
(case_setup.py's setup_case() -> canary.run_canary(), which itself
sys.exit(3)s on a real DEAD). A DEGRADED canary still proceeds, matching
creation-time behavior, and the freshly re-checked status is persisted into
the manifest either way (not just left as the stale value from creation).
"""
from pathlib import Path

import yaml

from spectre.pipeline import phase_runner
from spectre.pipeline import canary as canary_mod


def _case_with_passed_gate0(tmp_path, canary_status="FULL") -> Path:
    case_dir = tmp_path / "004-canary-resume"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "004", "case_name": "canary-resume",
        "canary_status": canary_status,
        "artifacts": ["evtx_4688"], "evidence": [],
        "gate_0": {"passed": True, "checked_at": "2026-01-01T00:00:00Z"},
    }
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    # R1-G3: Gate 0 now runs verify_chain(); a real case always has the
    # audit trail setup_case wrote.
    from spectre.pipeline.audit import append as _audit_append
    _audit_append(str(case_dir), {"actor": "case_setup", "action": "note",
                                  "case_id": case_dir.name, "phase": 0})
    return case_dir


def test_dead_canary_on_resume_fails_closed(tmp_path, monkeypatch):
    """The core A8-F1 repro: a case whose gate_0 already passed (canary was
    FULL at creation) is resumed while the environment's canary is now
    DEAD. run_phase_0 must re-check and stop, not trust the stale stored
    status."""
    case_dir = _case_with_passed_gate0(tmp_path, canary_status="FULL")
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())

    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "DEAD", "passed": 2, "failed": 8,
        "failed_tools": ["vol", "tshark", "mmls"],
    })

    result = phase_runner.run_phase_0(str(case_dir), manifest)

    assert result["success"] is False, (
        "a DEAD canary on resume must stop the pipeline, not silently pass "
        "through on the stale stored canary_status"
    )
    assert result["canary_status"] == "DEAD"

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["gate_0"]["passed"] is False
    assert saved["canary_status"] == "DEAD", "fresh status must be persisted, not the stale FULL"


def test_full_canary_on_resume_still_proceeds(tmp_path, monkeypatch):
    case_dir = _case_with_passed_gate0(tmp_path, canary_status="FULL")
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())

    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": [],
    })

    result = phase_runner.run_phase_0(str(case_dir), manifest)
    assert result["success"] is True
    assert result["canary_status"] == "FULL"


def test_degraded_canary_on_resume_still_proceeds_and_is_recorded(tmp_path, monkeypatch):
    """DEGRADED must still proceed (matches creation-time behavior) --
    only DEAD is a hard stop."""
    case_dir = _case_with_passed_gate0(tmp_path, canary_status="FULL")
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())

    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "DEGRADED", "passed": 14, "failed": 2, "failed_tools": ["yara"],
    })

    result = phase_runner.run_phase_0(str(case_dir), manifest)
    assert result["success"] is True
    assert result["canary_status"] == "DEGRADED"

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["canary_status"] == "DEGRADED"
    assert saved["gate_0"]["passed"] is True


def test_canary_actually_gets_invoked_not_just_read_from_manifest(tmp_path, monkeypatch):
    """Pins the actual bug: run_canary() must be CALLED, not skipped in
    favor of reading manifest["canary_status"]."""
    case_dir = _case_with_passed_gate0(tmp_path, canary_status="FULL")
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())

    calls = []

    def _spy(**kw):
        calls.append(kw)
        return {"status": "FULL", "passed": 16, "failed": 0, "failed_tools": []}

    monkeypatch.setattr(canary_mod, "run_canary", _spy)
    phase_runner.run_phase_0(str(case_dir), manifest)

    assert len(calls) == 1, "run_phase_0 must call canary.run_canary() exactly once per invocation"
