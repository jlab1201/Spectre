"""W4-1 / R1-F2 (3): absence signals, the "No IOCs" verdict and the
blindspot INVESTIGATED rows are gated on SUCCESSFUL extraction."""
from spectre.pipeline.report_synthesize import (
    _absence_signals, _coverage_counts, _generate_verdict_section,
    _merge_report_md,
)


def _failed_memory_manifest():
    return {
        "case_id": "901", "case_name": "urandom",
        "artifact_profile": "auto", "artifacts": ["memory"],
        "extraction": {"results": {
            "evidence/random.bin": {
                "module": "memory", "artifact_type": "memory_image",
                "handles": 17, "handles_ok": 0, "events": 0,
                "empty_data": "FAILED", "extraction_status": "EXTRACTION_FAILED",
            }}},
        "detection": {"plugins_run": [], "plugins_failed": ["memory_netscan",
                                                            "memory_pslist"]},
    }


def _partial_manifest():
    m = _failed_memory_manifest()
    m["extraction"]["results"]["evidence/Security.evtx"] = {
        "module": "evtx", "artifact_type": "evtx", "handles": 1,
        "handles_ok": 1, "events": 10, "empty_data": "DATA_PRESENT",
        "extraction_status": "SUCCESS"}
    return m


def test_failed_extraction_is_not_examined():
    assert _coverage_counts(_failed_memory_manifest()) == (0, 1)


def test_verdict_never_says_no_iocs_when_extraction_failed():
    text = "\n".join(_generate_verdict_section([], _failed_memory_manifest()))
    assert "No indicators of compromise were detected" not in text
    assert "extraction failed" in text.lower() or "no evidence was examined" in text.lower()


def test_verdict_scoped_when_some_extraction_failed():
    text = "\n".join(_generate_verdict_section([], _partial_manifest()))
    assert "No indicators of compromise were detected.**" not in text
    assert "successfully examined" in text.lower()


def test_verdict_clean_case_unchanged():
    m = _partial_manifest()
    del m["extraction"]["results"]["evidence/random.bin"]
    text = "\n".join(_generate_verdict_section([], m))
    assert "No indicators of compromise were detected" in text


def test_absence_signal_dropped_for_failed_plugin_even_if_listed_as_run():
    # A legacy/forged manifest that lists netscan as run but also failed.
    m = {"detection": {"plugins_run": ["memory_netscan"],
                       "plugins_failed": ["memory_netscan"]}}
    assert _absence_signals([], m) == []


def test_blindspot_memory_not_investigated_when_extraction_failed():
    md = _merge_report_md(None, [], _failed_memory_manifest(), "/tmp/x", [], {})
    row = [ln for ln in md.splitlines()
           if "additional malicious processes" in ln]
    assert row, md
    assert "INVESTIGATED" not in row[0]
    assert "No indicators of compromise were detected" not in md


def test_blindspot_memory_investigated_when_extraction_succeeded():
    m = _failed_memory_manifest()
    rec = m["extraction"]["results"]["evidence/random.bin"]
    rec.update(handles_ok=17, empty_data="DATA_PRESENT", extraction_status="SUCCESS")
    md = _merge_report_md(None, [], m, "/tmp/x", [], {})
    row = [ln for ln in md.splitlines() if "additional malicious processes" in ln]
    assert "INVESTIGATED" in row[0]


def _partial_runs_manifest():
    m = _partial_manifest()
    del m["extraction"]["results"]["evidence/random.bin"]
    rec = m["extraction"]["results"]["evidence/Security.evtx"]
    rec.update(handles=3, handles_ok=2, handles_failed=1, extraction_status="PARTIAL")
    return m


def test_verdict_scoped_when_some_tool_runs_failed():
    text = "\n".join(_generate_verdict_section([], _partial_runs_manifest()))
    assert "No indicators of compromise were detected.**" not in text
    assert "1 tool run" in text


def test_blindspot_memory_partial_is_not_plain_investigated():
    m = _failed_memory_manifest()
    rec = m["extraction"]["results"]["evidence/random.bin"]
    rec.update(handles_ok=10, handles_failed=7, empty_data="DATA_PRESENT",
               extraction_status="PARTIAL")
    md = _merge_report_md(None, [], m, "/tmp/x", [], {})
    row = [ln for ln in md.splitlines() if "additional malicious processes" in ln][0]
    assert "| PARTIAL |" in row and "7" in row
