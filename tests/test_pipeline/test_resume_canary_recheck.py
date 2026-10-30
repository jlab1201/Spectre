"""MUST-FIX 1 (post-review): A8-F1 was NOT actually closed by run_phase_0's
DEAD-canary branch alone. That branch is correct WHEN REACHED, but it is
dead code on the resume path: missing_preceding_phases() returns only
phases whose gate hasn't passed yet, and once gate_0.passed=True (set at
case creation), Phase 0 is dropped from that list forever -- so a resumed
`spectre --case ... --phase N` (N > 0) run never calls run_phase_0 again
and never re-checks canary. Empirically: a case built to Phase 2, then
resumed with `--phase 6`, auto-ran only phases 3, 4, 5 -- canary was never
touched.

Fix: runner.py's --phase (and --from-phase) dispatch now forces a fresh
canary.run_canary() call unconditionally before any phase > 0 executes --
independent of missing_preceding_phases() -- and stops fail-closed (exit
3, before ANY phase or report) if the fresh check comes back DEAD.
FULL/DEGRADED proceed exactly as before.
"""
import sys
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import runner
from spectre.pipeline import canary as canary_mod


def _case_at_phase_2(tmp_path) -> Path:
    """A case whose gate_0/1/2 already passed (built to Phase 2), so
    missing_preceding_phases(manifest, 6) == [3, 4, 5] -- Phase 0 is NOT
    in that list, matching the exact bug scenario."""
    case_dir = tmp_path / "cases" / "007-resume-canary"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "007", "case_name": "resume-canary",
        "canary_status": "FULL", "artifacts": ["evtx_4688"], "evidence": [],
        "gate_0": {"passed": True}, "gate_1": {"passed": True},
        "gate_2": {"passed": True},
    }
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    # R1-G3: Gate 0 now runs verify_chain(); a real case always has the
    # audit trail setup_case wrote.
    from spectre.pipeline.audit import append as _audit_append
    _audit_append(str(case_dir), {"actor": "case_setup", "action": "note",
                                  "case_id": case_dir.name, "phase": 0})
    return case_dir


def test_dead_canary_on_resume_stops_pipeline_before_any_phase_runs(tmp_path, monkeypatch):
    """The exact repro: case at Phase 2, canary now DEAD, resume with
    --phase 6. Must stop (nonzero exit), before any of phases 3/4/5/6 run,
    and no report may be produced."""
    case_dir = _case_at_phase_2(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")

    canary_calls = []
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: (
        canary_calls.append(kw) or
        {"status": "DEAD", "passed": 2, "failed": 8, "failed_tools": ["vol", "tshark"]}
    ))

    phase_calls = []
    monkeypatch.setattr(runner, "run_phase", lambda cd, phase, skip_ai=False: (
        phase_calls.append(phase) or True
    ))
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "6"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code != 0, "a DEAD canary on resume must exit non-zero"
    assert len(canary_calls) >= 1, (
        "canary.run_canary() must actually be invoked on resume, "
        "independent of missing_preceding_phases()"
    )
    assert phase_calls == [], (
        "no phase (3, 4, 5, or the target 6) may run once a resume-time "
        "canary re-check comes back DEAD"
    )
    assert not (case_dir / "reports" / "report.md").exists()


def test_full_canary_on_resume_still_proceeds_through_all_phases(tmp_path, monkeypatch):
    """Regression guard: FULL/DEGRADED must still let the pipeline run --
    the new check must not block the happy path."""
    case_dir = _case_at_phase_2(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")

    canary_calls = []
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: (
        canary_calls.append(kw) or
        {"status": "FULL", "passed": 16, "failed": 0, "failed_tools": []}
    ))

    phase_calls = []
    monkeypatch.setattr(runner, "run_phase", lambda cd, phase, skip_ai=False: (
        phase_calls.append(phase) or True
    ))
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "6"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code == 0
    assert len(canary_calls) >= 1
    assert phase_calls == [3, 4, 5, 6], (
        "with a FULL canary, the missing preceding phases (3,4,5) plus "
        "the target phase (6) must all run, same as before this fix"
    )


def test_degraded_canary_on_resume_still_proceeds(tmp_path, monkeypatch):
    case_dir = _case_at_phase_2(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")

    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "DEGRADED", "passed": 14, "failed": 2, "failed_tools": ["yara"],
    })
    phase_calls = []
    monkeypatch.setattr(runner, "run_phase", lambda cd, phase, skip_ai=False: (
        phase_calls.append(phase) or True
    ))
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "6"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code == 0
    assert phase_calls == [3, 4, 5, 6]


def test_phase_0_target_is_unaffected_run_phase_0_already_checks_canary(tmp_path, monkeypatch):
    """`--phase 0` must not double up on this new guard -- run_phase_0
    itself already re-checks canary (prior fix). Confirm canary is
    invoked exactly once, not twice, for a `--phase 0` invocation."""
    case_dir = _case_at_phase_2(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")

    canary_calls = []
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: (
        canary_calls.append(kw) or
        {"status": "FULL", "passed": 16, "failed": 0, "failed_tools": []}
    ))
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "0"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code == 0
    assert len(canary_calls) == 1
