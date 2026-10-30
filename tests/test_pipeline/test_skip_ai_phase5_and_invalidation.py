"""W4-3 / R1-F6.

(a) --skip-ai used to return True for Phase 5 without running it or writing
    gate_5, so the report carried no adversarial-review disclosure at all.
    Now Phase 5 runs through the null provider's deterministic path.
(b) A resume that re-ran Phase 5 AFTER Phase 6 left the report stale:
    gates were plain booleans with no dependency invalidation. Re-running
    phase k now invalidates gates > k, and the resume loop recomputes what
    is missing after every phase, so Phase 6 is regenerated.
"""
import sys
from pathlib import Path

import pytest
import yaml

from spectre.core import explain as explain_mod
from spectre.pipeline import canary as canary_mod
from spectre.pipeline import phase_runner, runner
from spectre.pipeline.report_synthesize import _phase5_disposition_line


def _case(tmp_path, gates=(0, 1, 2, 3, 4, 5, 6)):
    case_dir = tmp_path / "902-skipai"
    (case_dir / "findings").mkdir(parents=True)
    manifest = {"case_id": "902", "case_name": "skipai", "evidence": [],
                "artifacts": ["pcap_conn"], "canary_status": "FULL"}
    for g in gates:
        manifest[f"gate_{g}"] = {"passed": True}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return case_dir, manifest


def test_phase5_under_skip_ai_uses_null_provider_and_writes_gate5(tmp_path, monkeypatch):
    case_dir, manifest = _case(tmp_path)
    (case_dir / "findings" / "F-902-001.yaml").write_text(yaml.safe_dump(
        {"finding_id": "F-902-001", "title": "x", "status": "INFERRED",
         "corroboration": {"tools": ["zeek/pcap_conn"]}}))
    seen = []

    def _explain(finding_path, fk, mm, cd, adversarial=False, case_id=None,
                 phase=5, provider_name=None, **kw):
        seen.append(provider_name)
        return {"finding_id": "F-902-001", "output": None, "violations": [],
                "api_error": "null provider", "persist_refused": False}

    monkeypatch.setattr(explain_mod, "explain", _explain)
    result = phase_runner.run_phase_5(str(case_dir), manifest, skip_ai=True)

    assert result["success"] is True
    assert seen and set(seen) == {"null"}
    g5 = manifest["gate_5"]
    assert g5["skip_ai"] is True
    assert g5["substantive_review"] == "not-run"
    assert g5["grounding_probe"] == "not-run"
    assert "--skip-ai" in (g5.get("degraded_reason") or "")


def test_runner_no_longer_skips_phase5_under_skip_ai(tmp_path, monkeypatch):
    case_dir, _ = _case(tmp_path, gates=(0, 1, 2, 3, 4))
    called = {}

    def fake5(cd, manifest, skip_ai=False):
        called["skip_ai"] = skip_ai
        return {"success": True}

    monkeypatch.setattr(runner, "run_phase_5", fake5)
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)
    assert runner.run_phase(str(case_dir), 5, skip_ai=True) is True
    assert called == {"skip_ai": True}


def test_disposition_line_discloses_skip_ai():
    line = _phase5_disposition_line({"gate_5": {"substantive_review": "not-run",
                                                "skip_ai": True}})
    assert "--skip-ai" in line


def test_rerunning_phase_invalidates_later_gates(tmp_path, monkeypatch):
    case_dir, _ = _case(tmp_path)
    y = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    y["gate_7"] = {"passed": True}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(y))
    monkeypatch.setattr(runner, "run_phase_3", lambda cd, m: {"success": True})
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)

    assert runner.run_phase(str(case_dir), 3) is True
    m = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    for g in (0, 1, 2):
        assert m[f"gate_{g}"]["passed"] is True
    # gate_3 itself is re-earned by the phase (the stub never writes it).
    for g in (4, 5, 6, 7):
        assert not m.get(f"gate_{g}", {}).get("passed"), g
    assert m["gates_invalidated"][-1]["by_phase"] == 3


def test_failed_rerun_also_invalidates(tmp_path, monkeypatch):
    """W4 review MED-1 (supersedes the earlier "failed re-run keeps later
    gates" rule): gates k..7 are invalidated when phase k STARTS, so a
    failed or crashed re-run leaves them — and its own gate — not passed."""
    case_dir, _ = _case(tmp_path)
    monkeypatch.setattr(runner, "run_phase_3", lambda cd, m: {"success": False})
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)
    assert runner.run_phase(str(case_dir), 3) is False
    m = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert not m["gate_3"]["passed"] and not m["gate_6"]["passed"]
    assert m["gate_2"]["passed"] is True


def test_resume_reruns_phase6_after_missing_phase5(tmp_path, monkeypatch):
    """R1-F6 repro: gate_5 missing, gate_6 passed. `--phase 7` must run 5
    AND then 6 (5 invalidated it), in that order, before Phase 7."""
    case_dir, _ = _case(tmp_path, gates=(0, 1, 2, 3, 4, 6))
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": []})
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)
    calls = []

    def fake_run_phase(cd, phase, skip_ai=False):
        calls.append(phase)
        m = yaml.safe_load((Path(cd) / "manifest.yaml").read_text())
        m[f"gate_{phase}"] = {"passed": True}
        phase_runner.invalidate_later_gates(m, phase)
        (Path(cd) / "manifest.yaml").write_text(yaml.safe_dump(m))
        return True

    monkeypatch.setattr(runner, "run_phase", fake_run_phase)
    monkeypatch.setattr(runner, "verify_and_close", lambda cd, m: True)
    monkeypatch.setattr(runner, "print_summary", lambda cd, ok: None)
    monkeypatch.setattr(sys, "argv", ["spectre", "--case", str(case_dir), "--phase", "7"])
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code == 0
    assert calls == [5, 6]


def test_resume_with_force_does_not_loop_on_a_failing_phase(tmp_path, monkeypatch):
    case_dir, _ = _case(tmp_path, gates=(0, 1, 2, 3))
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": []})
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)
    calls = []

    def fake_run_phase(cd, phase, skip_ai=False):
        calls.append(phase)
        return phase != 4

    monkeypatch.setattr(runner, "run_phase", fake_run_phase)
    monkeypatch.setattr(sys, "argv", ["spectre", "--case", str(case_dir),
                                      "--phase", "6", "--force"])
    with pytest.raises(SystemExit):
        runner.main()
    assert calls == [4, 5, 6]
