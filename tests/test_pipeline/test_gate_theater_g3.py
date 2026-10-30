"""R1-G3 / F13: three gate checks were theater.

- Gate 0: `len(evidence) >= 0` (always true). It now requires the spec's
  `audit.verify_chain()` == ok (docs/phase-0-spec.md §Gate 0).
- Gate 3: `passed = True` hardcoded. It now requires verify_chain ok and
  every emitted finding file on disk (SKILL.md Gate 3).
- gate_6.mitre_map_complete: hardcoded True. It is now computed: every
  finding's MITRE IDs lie inside its own rule's mitre-map allowed set.
"""
import json
from pathlib import Path

import yaml

from spectre.pipeline import phase_runner
from spectre.pipeline.audit import append as audit_append


def _canary_full(monkeypatch):
    from spectre.pipeline import canary as canary_mod
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {
        "status": "FULL", "passed": 16, "failed": 0, "failed_tools": []})


def _p0_case(tmp_path):
    case_dir = tmp_path / "005-g0"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"case_id": "005", "case_name": "g0", "canary_status": "FULL",
                "artifacts": ["evtx_4688"], "evidence": []}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    audit_append(str(case_dir), {"actor": "case_setup", "action": "note",
                                 "case_id": case_dir.name, "phase": 0})
    audit_append(str(case_dir), {"actor": "case_setup", "action": "note",
                                 "case_id": case_dir.name, "phase": 0})
    return case_dir, manifest


def _break_chain(case_dir):
    ap = Path(case_dir) / "audit.jsonl"
    lines = ap.read_text().splitlines()
    row = json.loads(lines[0])
    row["actor"] = "someone-else"
    lines[0] = json.dumps(row)
    ap.write_text("\n".join(lines) + "\n")


def test_gate0_passes_with_intact_chain(tmp_path, monkeypatch):
    _canary_full(monkeypatch)
    case_dir, manifest = _p0_case(tmp_path)
    assert phase_runner.run_phase_0(str(case_dir), manifest)["success"] is True
    assert manifest["gate_0"]["audit_chain_valid"] is True


def test_gate0_fails_on_broken_chain(tmp_path, monkeypatch):
    _canary_full(monkeypatch)
    case_dir, manifest = _p0_case(tmp_path)
    _break_chain(case_dir)
    result = phase_runner.run_phase_0(str(case_dir), manifest)
    assert result["success"] is False
    assert manifest["gate_0"]["passed"] is False
    assert manifest["gate_0"]["audit_chain_valid"] is False


def test_gate0_fails_without_audit_trail(tmp_path, monkeypatch):
    _canary_full(monkeypatch)
    case_dir, manifest = _p0_case(tmp_path)
    (case_dir / "audit.jsonl").unlink()
    assert phase_runner.run_phase_0(str(case_dir), manifest)["success"] is False


# ── Gate 3 ────────────────────────────────────────────────────────────

def _p3_case(tmp_path):
    case_dir = tmp_path / "006-g3"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    (case_dir / "raw_extract" / "normalized_events.json").write_text("[]")
    (case_dir / "raw_extract" / "_handles.json").write_text("[]")
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))
    manifest = {"case_id": "006", "case_name": "g3", "artifact_profile": "auto",
                "canary_status": "FULL", "direction": "", "focus": False,
                "evidence": [], "artifacts": [], "triage": {}}
    return case_dir, manifest


def test_gate3_passes_on_intact_case(tmp_path, monkeypatch):
    monkeypatch.setattr(phase_runner, "_modules", lambda: {})
    case_dir, manifest = _p3_case(tmp_path)
    result = phase_runner._run_phase_3_live(str(case_dir), manifest)
    assert result["success"] is True
    assert manifest["gate_3"]["passed"] is True
    assert manifest["gate_3"]["audit_chain_valid"] is True


def test_gate3_fails_when_chain_broken(tmp_path, monkeypatch):
    monkeypatch.setattr(phase_runner, "_modules", lambda: {})
    case_dir, manifest = _p3_case(tmp_path)
    audit_append(str(case_dir), {"actor": "x", "action": "note",
                                 "case_id": case_dir.name, "phase": 2})
    ap = case_dir / "audit.jsonl"
    lines = ap.read_text().splitlines()
    row = json.loads(lines[-1])
    row["actor"] = "forged"
    lines[-1] = json.dumps(row)
    ap.write_text("\n".join(lines) + "\n")
    result = phase_runner._run_phase_3_live(str(case_dir), manifest)
    assert result["success"] is False
    assert manifest["gate_3"]["passed"] is False


# ── gate_6.mitre_map_complete ─────────────────────────────────────────

def test_mitre_map_complete_true_for_in_set_and_unmapped():
    mm = {"rules": {"r1": {"allowed": ["T1071.001"]}}}
    fs = [{"finding_id": "F-1", "rule_id": "r1", "mitre_attack": "T1071.001"},
          {"finding_id": "F-2", "rule_id": "sigma-x", "mitre_attack": "UNMAPPED"}]
    ok, bad = phase_runner._mitre_map_complete(fs, mm, case_dir=None)
    assert ok is True and bad == []


def test_mitre_map_complete_false_for_out_of_set():
    mm = {"rules": {"r1": {"allowed": ["T1071.001"]}}}
    fs = [{"finding_id": "F-1", "rule_id": "r1", "mitre_attack": "T1003.006"}]
    ok, bad = phase_runner._mitre_map_complete(fs, mm, case_dir=None)
    assert ok is False and bad == ["F-1"]


def test_gate6_fails_closed_on_incomplete_mitre_map():
    gate = {"report_exists": True, "iocs_exported": True,
            "blindspots_populated": True, "verdict_class_consistent": True,
            "llm_used": False, "mitre_map_complete": False}
    assert phase_runner.gate_6_passed(gate) is False
    gate["mitre_map_complete"] = True
    assert phase_runner.gate_6_passed(gate) is True
