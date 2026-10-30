"""W4 adversarial-review rework (W4-REVIEW.md), items owned by W4-A.

MED-1  a crash mid Phase-3 re-run left gates 3-7 passed after the prior
       findings were retired → a later --phase 6/7 gave a false clean
       verdict that verify_full accepted.
MED-3  zero parsed records from non-empty evidence (corrupt EVTX, header-
       only pcap) read as a successful, clean examination.
LOW    skipped-tool markers counted as successful runs; a 0-byte .mem was
       claimed as memory; a hand-moved finding was silently skipped on a
       re-run; a forged finding_supersede row could hide a finding.
"""
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import phase_runner, runner
from spectre.pipeline.audit import append as audit_append, verify_full
from spectre.pipeline.tool_runner import extraction_outcome
from tests.test_pipeline.test_phase3_rerun_supersede import _make_case, _module


def _active(case_dir):
    return sorted(p.stem for p in (Path(case_dir) / "findings").glob("F-*.yaml"))


def _set_gates(case_dir, upto=7):
    mp = Path(case_dir) / "manifest.yaml"
    m = yaml.safe_load(mp.read_text())
    for g in range(0, upto + 1):
        m[f"gate_{g}"] = {"passed": True}
    mp.write_text(yaml.safe_dump(m))


def _gates(case_dir):
    m = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
    return {g: bool((m.get(f"gate_{g}") or {}).get("passed")) for g in range(8)}


@pytest.fixture
def case(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake_mod": _module()})
    monkeypatch.setattr(runner, "_evidence_intact", lambda cd, p: True)
    assert runner.run_phase(case_dir, 3) is True
    _set_gates(case_dir)
    return case_dir


# ── MED-1 ────────────────────────────────────────────────────────────

def _crash_emit(monkeypatch):
    import spectre.pipeline.emit_finding as ef

    def boom(*a, **k):
        raise KeyboardInterrupt("simulated crash mid-emit")
    monkeypatch.setattr(ef, "emit_from_handle", boom)


def test_crash_mid_rerun_invalidates_gates_3_to_7(case, monkeypatch):
    _crash_emit(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        runner.run_phase(case, 3)
    g = _gates(case)
    assert g[0] and g[1] and g[2]
    assert not any(g[k] for k in range(3, 8)), g


def test_crash_mid_rerun_is_flagged_by_verify_full_and_blocks_phase6(case, monkeypatch):
    _crash_emit(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        runner.run_phase(case, 3)
    rep = verify_full(case)
    assert rep["ok"] is False
    assert not rep["checks"]["supersede_batches"]["passed"]
    m = yaml.safe_load((Path(case) / "manifest.yaml").read_text())
    res = phase_runner.run_phase_6(case, m, skip_ai=True)
    assert res["success"] is False
    assert "phase 3" in res["error"].lower()


def test_supersede_happens_after_detection(case, monkeypatch):
    """A crash during DETECTION (before emit) must not retire anything."""
    import spectre.pipeline.correlation as corr

    def boom(*a, **k):
        raise RuntimeError("detector crashed")
    monkeypatch.setattr(corr, "corroborate", boom)
    before = _active(case)
    assert runner.run_phase(case, 3) is False  # run_phase catches Exception
    assert _active(case) == before
    assert verify_full(case)["checks"]["supersede_batches"]["passed"]


def test_recovery_rerun_after_crash_verifies_clean(case, monkeypatch):
    first = _active(case)
    import spectre.pipeline.emit_finding as ef
    real = ef.emit_from_handle
    _crash_emit(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        runner.run_phase(case, 3)
    monkeypatch.setattr(ef, "emit_from_handle", real)
    assert runner.run_phase(case, 3) is True
    active = _active(case)
    assert len(active) == 2 and not set(active) & set(first)
    rep = verify_full(case)
    assert rep["checks"]["supersede_batches"]["passed"], rep["checks"]["supersede_batches"]
    assert rep["checks"]["finding_integrity"]["passed"], rep["checks"]["finding_integrity"]


# ── LOW: forged supersede rows ───────────────────────────────────────

def _forge_supersede(case_dir, fid, run_id=None):
    src = Path(case_dir) / "findings" / f"{fid}.yaml"
    dest = Path(case_dir) / "findings" / "superseded" / f"{fid}.yaml"
    dest.parent.mkdir(exist_ok=True)
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    params = {"finding_id": fid}
    if run_id:
        params["run_id"] = run_id
    audit_append(case_dir, {
        "actor": "deterministic-core", "action": "finding_supersede",
        "tool": "emit_finding.supersede_prior_findings", "case_id": Path(case_dir).name,
        "params": params, "output_path": str(dest), "output_sha256": sha,
        "result": "success", "finding_id": fid, "phase": 3,
        "phase_step": "S3-supersede"})
    shutil.move(src, dest)


def test_unbracketed_supersede_row_does_not_hide_a_finding(case):
    _forge_supersede(case, _active(case)[0])
    rep = verify_full(case)
    assert rep["ok"] is False
    assert not rep["checks"]["finding_integrity"]["passed"]


def test_supersede_with_start_row_but_no_completion_is_flagged(case):
    audit_append(case, {"actor": "deterministic-core", "action": "phase3_run_start",
                        "tool": "phase_runner", "case_id": Path(case).name,
                        "params": {"run_id": "forged-run"}, "phase": 3,
                        "phase_step": "S3-run-start"})
    _forge_supersede(case, _active(case)[0], run_id="forged-run")
    rep = verify_full(case)
    assert rep["ok"] is False


# ── LOW: hand-moved finding ──────────────────────────────────────────

def test_rerun_refuses_when_a_finding_was_moved_by_hand(case):
    fid = _active(case)[0]
    (Path(case) / "findings" / "superseded").mkdir(exist_ok=True)
    shutil.move(Path(case) / "findings" / f"{fid}.yaml",
                Path(case) / "findings" / "superseded" / f"{fid}.yaml")
    m = yaml.safe_load((Path(case) / "manifest.yaml").read_text())
    res = phase_runner._run_phase_3_live(case, m)
    assert res["success"] is False
    assert fid in res["error"]


def test_rerun_refuses_when_a_finding_was_deleted(case):
    fid = _active(case)[0]
    (Path(case) / "findings" / f"{fid}.yaml").unlink()
    m = yaml.safe_load((Path(case) / "manifest.yaml").read_text())
    res = phase_runner._run_phase_3_live(case, m)
    assert res["success"] is False and fid in res["error"]


# ── LOW: skipped-tool markers ────────────────────────────────────────

def _skip():
    return {"result": "skipped_tool_unavailable", "exit_code": -1,
            "line_count": 0, "size_bytes": 0, "artifact_type": "pcap_http"}


def test_skipped_marker_alone_is_not_a_successful_extraction():
    out = extraction_outcome([_skip()])
    assert out["status"] == "EXTRACTION_FAILED"
    assert out["handles_ok"] == 0


def test_skipped_marker_does_not_turn_partial_into_success():
    ok = {"result": "success", "exit_code": 0, "line_count": 3, "size_bytes": 9}
    out = extraction_outcome([ok, _skip()])
    assert out["handles_ok"] == 1


# ── LOW: 0-byte memory extension ─────────────────────────────────────

def test_zero_byte_mem_is_not_memory(tmp_path):
    from spectre.modules.memory import recognizer as r
    p = tmp_path / "empty.mem"
    p.write_bytes(b"")
    assert r._looks_like_memory(p) is False


# ── MED-3: zero parsed records from non-empty evidence ───────────────

def _p2_case(tmp_path, monkeypatch, handles, events):
    from spectre.core.base import AnalyzerModule
    from tests.test_pipeline.custody_helpers import chain_triage
    case_dir = tmp_path / "910-empty"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    ev = case_dir / "evidence" / "bad.evtx"
    ev.write_bytes(b"ElfFile\x00" + os.urandom(4096))
    mod = AnalyzerModule(name="evtx", artifact_type="evtx", required_tools=[],
                         recognizers=[], extract=lambda c, e: handles,
                         normalize=lambda h: events, rules=[])
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"evtx": mod})
    manifest = {"case_id": "910", "case_name": "empty", "artifact_profile": "auto",
                "canary_status": "FULL", "direction": "", "focus": False,
                "evidence": [], "artifacts": ["evtx"],
                "triage": {"evidence/bad.evtx": {"status": "RECOGNIZED", "module": "evtx",
                                                 "artifact_type": "evtx"}}}
    chain_triage(case_dir, manifest)
    return case_dir, manifest


def test_zero_records_from_nonempty_evidence_is_empty_not_success(tmp_path, monkeypatch):
    h = {"result": "success", "exit_code": 0, "line_count": 1, "size_bytes": 24,
         "artifact_type": "evtx", "path": "/x", "execution_id": "e",
         "stderr": "No records to export."}
    case_dir, manifest = _p2_case(tmp_path, monkeypatch, [h], [])
    res = phase_runner._run_phase_2_live(str(case_dir), manifest)
    rec = manifest["extraction"]["results"]["evidence/bad.evtx"]
    assert rec["extraction_status"] == "EMPTY"
    assert rec["empty_data"] == "UNVERIFIED"
    assert manifest["gate_2"]["extraction_empty"] == ["evidence/bad.evtx"]
    assert manifest["gate_2"]["degraded"] is True
    slim = json.loads((case_dir / "raw_extract" / "_handles.json").read_text())
    assert all(s["empty_data_status"] == "EMPTY" for s in slim)
    assert res["success"] is True  # ran, disclosed; never a clean verdict


def _empty_manifest():
    return {"case_id": "910", "case_name": "empty", "artifacts": ["evtx"],
            "extraction": {"results": {"evidence/bad.evtx": {
                "module": "evtx", "artifact_type": "evtx", "handles": 1,
                "handles_ok": 1, "handles_failed": 0, "events": 0,
                "empty_data": "UNVERIFIED", "extraction_status": "EMPTY"}}},
            "detection": {"plugins_run": [], "plugins_failed": ["evtx"]}}


def test_report_never_clean_on_empty_extraction():
    from spectre.pipeline.report_synthesize import (
        _absence_signals, _coverage_counts, _generate_verdict_section,
        _merge_report_md)
    m = _empty_manifest()
    text = "\n".join(_generate_verdict_section([], m))
    assert "No indicators of compromise were detected" not in text
    assert "zero records" in text.lower() or "no records" in text.lower()
    assert _coverage_counts(m) == (0, 1)
    assert _absence_signals([], {**m, "detection": {"plugins_run": ["evtx"]}}) == []
    md = _merge_report_md(None, [], m, "/tmp/x", [], {})
    row = [ln for ln in md.splitlines() if "event logs cleared" in ln][0]
    assert "INVESTIGATED" not in row


def test_empty_plugin_not_examined():
    ok, failed = phase_runner._plugins_examined(
        [{"artifact_type": "evtx", "empty_data_status": "EMPTY"}])
    assert ok == [] and failed == ["evtx"]


def test_coverage_gap_for_empty_extraction():
    from spectre.pipeline.coverage import gaps_from_manifest
    keys = [g["key"] for g in gaps_from_manifest(_empty_manifest())]
    assert any(k.startswith("EXTRACTION_EMPTY|") for k in keys), keys
