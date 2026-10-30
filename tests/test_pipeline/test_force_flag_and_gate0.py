"""A8-F4/F5:

F4 — phase_runner.py's run_phase_0 used to build a DISCONNECTED local
`gate0 = manifest.get("gate_0", {})` dict and then index back into
`manifest["gate_0"]["passed"]`, raising an unhandled KeyError on any
manifest missing the gate_0 key (a hand-edited or legacy manifest). Fixed
alongside A8-F1 (test_canary_resume.py) via manifest.setdefault("gate_0", {}).

F5 — the `spectre` console script (runner.py:main, the one pyproject.toml
actually registers) parses `--force` but never reads `args.force` anywhere
(`grep args.force` was 0 hits) — identical failure with or without the
flag, even though its own help text says "Skip gate checks from previous
phase" and phase_runner.py's OWN separate `main()` implements exactly that
semantic for its `--force`. Wired here: when a preceding phase's auto-run
fails, `--force` now lets the pipeline continue to the next phase instead
of hard-stopping (mirrors phase_runner.py's "run even if previous gate
failed").
"""
import sys
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import phase_runner
from spectre.pipeline import runner
from spectre.pipeline import canary as canary_mod


def _mock_full_canary(monkeypatch):
    """These tests drive runner.main() through the --phase dispatch, which
    (post MUST-FIX 1) now always re-checks canary before any phase runs —
    mock it FULL so these stay fast, deterministic unit tests instead of
    shelling out to session-canary.sh."""
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": [],
    })


# ── F4: gate_0 KeyError on a manifest missing the gate_0 key ────────────
def test_run_phase_0_no_longer_crashes_on_missing_gate_0_key(tmp_path, monkeypatch):
    case_dir = tmp_path / "004-no-gate0"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "004", "case_name": "no-gate0",
        "canary_status": "FULL", "artifacts": ["evtx_4688"], "evidence": [],
        # deliberately NO "gate_0" key at all
    }
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    # R1-G3: Gate 0 now runs verify_chain(); a real case always has the
    # audit trail setup_case wrote.
    from spectre.pipeline.audit import append as _audit_append
    _audit_append(str(case_dir), {"actor": "case_setup", "action": "note",
                                  "case_id": case_dir.name, "phase": 0})

    from spectre.pipeline import canary as canary_mod
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": [],
    })

    # Must not raise KeyError.
    result = phase_runner.run_phase_0(str(case_dir), manifest)
    assert result["success"] is True
    assert manifest["gate_0"]["passed"] is True


# ── F5: --force wiring in the spectre console script (runner.py) ────────
def _bare_case(tmp_path) -> Path:
    case_dir = tmp_path / "cases" / "005-force-test"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "005", "case_name": "force-test",
        "canary_status": "FULL", "artifacts": ["evtx_4688"], "evidence": [],
        # no gate_0 / gate_1 -> missing_preceding_phases(manifest, 2) == [0, 1]
    }
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return case_dir


def test_without_force_pipeline_hard_stops_at_first_failed_preceding_phase(tmp_path, monkeypatch):
    case_dir = _bare_case(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")
    _mock_full_canary(monkeypatch)

    calls = []

    def fake_run_phase(case_dir_arg, phase, skip_ai=False):
        calls.append(phase)
        return phase != 0  # phase 0 "fails", everything else "succeeds"

    monkeypatch.setattr(runner, "run_phase", fake_run_phase)
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "2"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code == 1
    assert calls == [0], (
        "without --force, phase 0 failing must hard-stop immediately -- "
        "phase 1 and the target phase 2 must never even be attempted"
    )


def test_force_flag_lets_pipeline_continue_past_a_failed_preceding_phase(tmp_path, monkeypatch):
    case_dir = _bare_case(tmp_path)
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path / "cases")
    _mock_full_canary(monkeypatch)

    calls = []

    def fake_run_phase(case_dir_arg, phase, skip_ai=False):
        calls.append(phase)
        return phase != 0  # phase 0 "fails", everything else "succeeds"

    monkeypatch.setattr(runner, "run_phase", fake_run_phase)
    monkeypatch.setattr(sys, "argv",
                        ["spectre", "--case", str(case_dir), "--phase", "2", "--force"])

    with pytest.raises(SystemExit) as exc:
        runner.main()

    assert exc.value.code == 0, "--force must let the pipeline reach and pass phase 2"
    assert calls == [0, 1, 2], (
        "--force must let phase 1 (also auto-run) and the target phase 2 "
        "run despite phase 0 having failed its gate"
    )


def test_force_flag_is_actually_read_by_main():
    """Direct pin of the F5 bug: `args.force` must be consulted somewhere
    in runner.py's main(). (grep-level regression guard, not behavioral --
    the behavioral coverage is above.)"""
    src = Path(runner.__file__).read_text()
    assert "args.force" in src, (
        "runner.py parses --force but never reads args.force anywhere — "
        "the flag is a documented no-op (A8-F5)"
    )
