"""W4-1 / R1-F2: a tool failure must never count as DATA_PRESENT.

Repro (R1): 200 KB of /dev/urandom was triaged as a memory image, every vol
run errored, yet extraction said DATA_PRESENT, Gate 2 passed, and the report
said "No indicators of compromise were detected" and memory "INVESTIGATED".
"""
import os

from spectre.core.base import AnalyzerModule
from spectre.pipeline import phase_runner
from spectre.pipeline.tool_runner import empty_data_protocol, extraction_outcome
from tests.test_pipeline.custody_helpers import chain_triage


def _h(result="success", exit_code=0, lines=5, size=100, art="memory_pslist"):
    return {"result": result, "exit_code": exit_code, "line_count": lines,
            "size_bytes": size, "artifact_type": art, "path": "/x",
            "execution_id": "e"}


# ── (1) empty_data_protocol ──────────────────────────────────────────

def test_error_with_output_is_failed_not_data_present():
    assert empty_data_protocol(_h(result="error", exit_code=1)) == "FAILED"


def test_nonzero_exit_is_failed_even_if_result_missing():
    h = _h()
    h.pop("result")
    h["exit_code"] = 2
    assert empty_data_protocol(h) == "FAILED"


def test_memprocfs_failure_result_is_failed():
    assert empty_data_protocol(_h(result="failure", exit_code=1)) == "FAILED"


def test_success_with_data_and_success_empty():
    assert empty_data_protocol(_h()) == "DATA_PRESENT"
    assert empty_data_protocol(_h(lines=0, size=0)) == "UNVERIFIED"


def test_skipped_pass_is_unverified_not_failed():
    h = _h(result="skipped_tool_unavailable", exit_code=-1, lines=0, size=0)
    assert empty_data_protocol(h) == "UNVERIFIED"


def test_legacy_handle_without_result_or_exit_code_keeps_old_rule():
    assert empty_data_protocol({"line_count": 3, "size_bytes": 9}) == "DATA_PRESENT"


# ── aggregate over ALL handles, not handles[0] ───────────────────────

def test_outcome_all_failed():
    out = extraction_outcome([_h(result="error", exit_code=1)] * 3)
    assert out["status"] == "EXTRACTION_FAILED"
    assert out["empty_data"] == "FAILED"
    assert out["handles_ok"] == 0 and out["handles_failed"] == 3


def test_outcome_first_ok_rest_failed_is_partial():
    out = extraction_outcome([_h(), _h(result="error", exit_code=1)])
    assert out["status"] == "PARTIAL"
    assert out["empty_data"] == "DATA_PRESENT"


def test_outcome_first_failed_later_ok_uses_all_handles():
    out = extraction_outcome([_h(result="error", exit_code=1), _h()])
    assert out["empty_data"] == "DATA_PRESENT"
    assert out["status"] == "PARTIAL"


def test_outcome_all_ok_but_empty_is_unverified_success():
    out = extraction_outcome([_h(lines=0, size=0)])
    assert out["status"] == "SUCCESS"
    assert out["empty_data"] == "UNVERIFIED"


def test_outcome_no_handles():
    out = extraction_outcome([])
    assert out["status"] == "EXTRACTION_FAILED"
    assert out["empty_data"] == "UNVERIFIED"


# ── (2) Gate 2 counts only successful handles ────────────────────────

def _module(name, art, handles_fn):
    from spectre.core.base import NormEvent

    def norm(h):  # one parsed record per successful handle (W4 review MED-3:
        # zero records from non-empty evidence is EMPTY, not SUCCESS)
        if h.get("result") != "success":
            return []
        return [NormEvent(artifact_type=art, timestamp="2026-01-01T00:00:00Z",
                          source_file="x", record_id="1")]
    return AnalyzerModule(
        name=name, artifact_type=art, required_tools=[], recognizers=[],
        extract=handles_fn, normalize=norm, rules=[],
    )


def _case(tmp_path, triage):
    case_dir = tmp_path / "900-w4"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"case_id": "900", "case_name": "w4", "artifact_profile": "auto",
                "canary_status": "FULL", "direction": "", "focus": False,
                "evidence": [], "artifacts": ["memory"], "triage": triage}
    chain_triage(case_dir, manifest)
    return case_dir, manifest


def _failing(case_dir, ev):
    return [dict(_h(result="error", exit_code=1, art=f"memory_p{i}"),
                 stderr="Unsatisfied requirement: translation layer")
            for i in range(3)]


def test_gate2_fails_when_every_tool_run_errored(tmp_path, monkeypatch):
    monkeypatch.setattr(phase_runner, "_modules",
                        lambda: {"memory": _module("memory", "memory_image", _failing)})
    case_dir, manifest = _case(tmp_path, {
        "evidence/random.bin": {"status": "RECOGNIZED", "module": "memory",
                                "artifact_type": "memory_image"}})
    result = phase_runner._run_phase_2_live(str(case_dir), manifest)

    rec = manifest["extraction"]["results"]["evidence/random.bin"]
    assert rec["extraction_status"] == "EXTRACTION_FAILED"
    assert rec["empty_data"] == "FAILED"
    assert rec["handles_ok"] == 0
    assert manifest["gate_2"]["passed"] is False
    assert manifest["gate_2"]["handles_ok"] == 0
    assert result["success"] is False
    assert "random.bin" in result["error"]
    assert "fail" in result["error"].lower()


def test_gate2_degrades_when_one_artifact_failed(tmp_path, monkeypatch):
    ok = lambda cd, ev: [_h(art="evtx")]  # noqa: E731
    monkeypatch.setattr(phase_runner, "_modules", lambda: {
        "memory": _module("memory", "memory_image", _failing),
        "evtx": _module("evtx", "evtx", ok)})
    case_dir, manifest = _case(tmp_path, {
        "evidence/random.bin": {"status": "RECOGNIZED", "module": "memory",
                                "artifact_type": "memory_image"},
        "evidence/Security.evtx": {"status": "RECOGNIZED", "module": "evtx",
                                   "artifact_type": "evtx"}})
    result = phase_runner._run_phase_2_live(str(case_dir), manifest)

    g2 = manifest["gate_2"]
    assert g2["passed"] is True and result["success"] is True
    assert g2["degraded"] is True
    assert g2["extraction_failed"] == ["evidence/random.bin"]
    assert manifest["extraction"]["results"]["evidence/Security.evtx"][
        "extraction_status"] == "SUCCESS"


# ── Phase 3: plugins examined = successful handles only ──────────────

def test_plugins_examined_excludes_failed_handles():
    handles = [
        {"artifact_type": "memory_netscan", "empty_data_status": "FAILED"},
        {"artifact_type": "memory_pslist", "empty_data_status": "DATA_PRESENT"},
        {"artifact_type": "memory_malfind", "empty_data_status": "UNVERIFIED"},
    ]
    ok, failed = phase_runner._plugins_examined(handles)
    assert ok == ["memory_malfind", "memory_pslist"]
    assert failed == ["memory_netscan"]


# ── Phase 6: FK caveat sources only for artifact types in the case ──

def test_no_findings_means_no_fk_caveat_types():
    assert phase_runner._fk_caveat_types([]) == []


def test_findings_drive_fk_caveat_types():
    f = {"corroboration": {"tools": ["zeek/pcap_conn"]}}
    assert phase_runner._fk_caveat_types([f]) == ["pcap_conn"]


# ── (4) memory recognizer needs a structural signal ──────────────────

def test_random_bytes_are_not_claimed_as_memory(tmp_path):
    from spectre.pipeline.recognize import triage_one
    p = tmp_path / "random.bin"
    p.write_bytes(os.urandom(200 * 1024))
    rec = triage_one(str(p))
    assert rec.get("module") != "memory", rec


def test_random_bytes_with_mem_extension_not_claimed(tmp_path):
    from spectre.modules.memory import recognizer as r
    p = tmp_path / "random.mem"
    p.write_bytes(os.urandom(64 * 1024))
    assert r._looks_like_memory(p) is False


def test_raw_dump_with_zero_pages_is_still_memory(tmp_path):
    from spectre.modules.memory import recognizer as r
    p = tmp_path / "dump.raw"
    p.write_bytes(os.urandom(8192) + b"\x00" * 8192 + os.urandom(8192))
    assert r._looks_like_memory(p) is True


def test_windows_crash_dump_header_is_memory(tmp_path):
    from spectre.modules.memory import recognizer as r
    p = tmp_path / "MEMORY.DMP"
    p.write_bytes(b"PAGEDU64" + os.urandom(64 * 1024))
    assert r._looks_like_memory(p) is True


def test_tiny_zero_file_still_memory(tmp_path):
    # existing fixtures (e.g. test_pcap_extractor_availability) rely on this
    from spectre.modules.memory import recognizer as r
    p = tmp_path / "dump.mem"
    p.write_bytes(b"\x00" * 512)
    assert r._looks_like_memory(p) is True



def test_auxiliary_carve_success_does_not_rescue_failed_parser():
    # R1 repro shape: every vol plugin errored, the strings-style URL carve
    # (which succeeds on any bytes) did not — memory was NOT examined.
    carve = dict(_h(art="memory_url"), tool="carve_urls")
    out = extraction_outcome([_h(result="error", exit_code=1)] * 17 + [carve])
    assert out["status"] == "EXTRACTION_FAILED"
    assert out["empty_data"] == "FAILED"


def test_auxiliary_flag_excludes_handle_without_tool_name():
    aux = dict(_h(art="memory_url"), tool="some_other_sweep", auxiliary=True)
    out = extraction_outcome([_h(result="error", exit_code=1)] * 3 + [aux])
    assert out["status"] == "EXTRACTION_FAILED"
    assert out["primary_ok"] == 0


def test_unflagged_unknown_tool_still_counts_as_primary():
    other = dict(_h(art="memory_url"), tool="some_other_sweep")
    out = extraction_outcome([_h(result="error", exit_code=1), other])
    assert out["primary_ok"] == 1 and out["status"] == "PARTIAL"
