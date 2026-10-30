"""W5-3 — process refs reach the finding via the real Phase 3 call site,
and memory netscan rows keep their owning PID through normalize."""
import json
from pathlib import Path

import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.modules.memory.normalize import normalize as mem_normalize
from spectre.pipeline import phase_runner


def _make_case(tmp, events):
    case_dir = Path(tmp) / "001-procrefs"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))
    handle = {"execution_id": "", "line_count": 5, "size_bytes": 100,
              "tool": "faketool", "tool_version": "0.1", "exact_command": "faketool ...",
              "empty_data_status": "DATA_PRESENT", "evidence_path": "evidence/x.evtx",
              "path": "raw_extract/x.json"}
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps([handle]))
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))
    manifest = {"case_id": "001", "case_name": "procrefs",
                "artifact_profile": "auto", "canary_status": "FULL",
                "direction": "", "focus": False,
                "evidence": [], "artifacts": ["process_creation"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _module():
    def pred(e):
        if not e.data.get("flag"):
            return None
        return Anchor(rule_id="fake-proc-rule", artifact_type="process_creation",
                      event=e, title="flagged", mitre=[], confidence=0.9,
                      dedup_key=str(e.data.get("key", e.record_id)))
    rule = Rule(rule_id="fake-proc-rule", artifact_type="process_creation",
                predicate=pred, mitre=[], description="x",
                metadata=RuleMetadata(uuid="fake-proc-uuid", severity="low"))
    return AnalyzerModule(name="fake_proc_mod", artifact_type="process_creation",
                          required_tools=[], recognizers=[],
                          extract=lambda c, e: [], normalize=lambda h: [],
                          rules=[rule])


def _ev(rid, data, ts="2026-01-30T20:00:00Z"):
    return {"artifact_type": "process_creation", "timestamp": ts,
            "source_file": "evidence/x.evtx", "record_id": rid, "host": "WS01",
            "data": data}


def _findings(case_dir):
    return [yaml.safe_load(p.read_text())
            for p in sorted((Path(case_dir) / "findings").glob("F-*-*.yaml"))]


def test_process_refs_written_from_group_members(monkeypatch, tmp_path):
    events = [
        _ev("1", {"flag": True, "key": "k", "process_id": "0x4d2",
                  "image": r"C:\Users\a\evil.exe"}),
        _ev("2", {"flag": True, "key": "k", "process_id": "0x10",
                  "image": r"C:\Users\a\evil.exe"}, ts="2026-01-30T20:01:00Z"),
    ]
    case_dir, manifest = _make_case(tmp_path, events)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"m": _module()})
    phase_runner._run_phase_3_live(case_dir, manifest)
    (f,) = _findings(case_dir)
    assert f["process_refs"] == [
        {"pid": 16, "image": r"C:\Users\a\evil.exe", "host": "WS01",
         "start_time": "2026-01-30T20:01:00Z"},
        {"pid": 1234, "image": r"C:\Users\a\evil.exe", "host": "WS01",
         "start_time": "2026-01-30T20:00:00Z"},
    ]
    # correlation-only: never an IOC, never MITRE
    assert "process" not in (f.get("iocs") or {})


def test_no_process_refs_key_when_event_has_no_process(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path, [_ev("1", {"flag": True})])
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"m": _module()})
    phase_runner._run_phase_3_live(case_dir, manifest)
    (f,) = _findings(case_dir)
    assert "process_refs" not in f


def test_memory_netscan_normalize_keeps_owning_pid(tmp_path):
    raw = tmp_path / "netscan.json"
    raw.write_text(json.dumps([{"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49232,
                        "ForeignAddr": "45.1.2.3", "ForeignPort": 443,
                        "State": "ESTABLISHED", "Owner": "evil.exe", "PID": 1234}]))
    handle = {"artifact_type": "memory_netscan", "evidence_path": "mem.raw",
              "path": str(raw)}
    (e,) = mem_normalize(handle)
    assert e.data["pid"] == 1234
    assert e.data["owner"] == "evil.exe"
