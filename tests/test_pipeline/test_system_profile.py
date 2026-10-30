"""_load_system_profile: wires the Task 7 memory_systeminfo profile signal
from raw_extract/normalized_events.json into manifest["system_profile"] for
the report. memory_systeminfo has no rule in rules.py (see
modules/memory/normalize.py._normalize_systeminfo) and can NEVER emit a
finding — this is metadata only, and this helper must never be mistaken for
a finding/MITRE data path.
"""

import json

from spectre.pipeline.phase_runner import _load_system_profile


def _write_events(case_dir, events):
    raw = case_dir / "raw_extract"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "normalized_events.json").write_text(json.dumps(events))
    # Review LOW-2: the reader trusts only chained Phase-2 bytes.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))


def test_extracts_hostname_os_build_system_time(tmp_path):
    _write_events(tmp_path, [
        {"artifact_type": "memory_pslist", "data": {"pid": 4}},
        {"artifact_type": "memory_systeminfo", "timestamp": "2026-03-11T00:12:03Z",
         "data": {"hostname": "win-victim01", "os_build": "19041.1.amd64fre",
                   "system_time": "2026-03-11T00:12:03Z"}},
    ])
    profile = _load_system_profile(str(tmp_path))
    assert profile == {
        "hostname": "win-victim01",
        "os_build": "19041.1.amd64fre",
        "system_time": "2026-03-11T00:12:03Z",
    }


def test_empty_when_no_systeminfo_event(tmp_path):
    _write_events(tmp_path, [{"artifact_type": "memory_pslist", "data": {}}])
    assert _load_system_profile(str(tmp_path)) == {}


def test_empty_when_no_normalized_events_file(tmp_path):
    assert _load_system_profile(str(tmp_path)) == {}


def test_empty_when_systeminfo_event_carries_no_data(tmp_path):
    _write_events(tmp_path, [
        {"artifact_type": "memory_systeminfo", "data": {
            "hostname": "", "os_build": "", "system_time": ""}},
    ])
    assert _load_system_profile(str(tmp_path)) == {}


def test_tolerates_malformed_json(tmp_path):
    raw = tmp_path / "raw_extract"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "normalized_events.json").write_text("{not valid json")
    assert _load_system_profile(str(tmp_path)) == {}
