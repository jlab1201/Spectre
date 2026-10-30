"""An event whose producing handle can't be identified must NOT be
attributed to an arbitrary handle (formerly handles[0]): that handle's
real tool_exec id would let the finding pass Phase 4's evidence_ref gate
while citing an extraction that never produced it. It gets an empty
execution_id instead, which Phase 4 treats as unresolved."""
import json
from pathlib import Path

import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.pipeline import phase_runner


def _pred(event):
    if event.artifact_type != "pcap_dns":
        return None
    return Anchor(rule_id="fake-dns-rule", artifact_type="pcap_dns", event=event,
                  title="Suspicious DNS query observed", mitre=[], confidence=0.6,
                  dedup_key=event.record_id)


def _module():
    rule = Rule(rule_id="fake-dns-rule", artifact_type="pcap_dns", predicate=_pred,
                mitre=[], description="fires on any pcap_dns event",
                metadata=RuleMetadata(uuid="fake-dns-uuid", severity="low"))
    return AnalyzerModule(name="pcap", artifact_type="pcap", required_tools=[],
                          recognizers=[], extract=lambda c, e: [],
                          normalize=lambda h: [], rules=[rule])


def test_unmatched_event_gets_empty_execution_id(tmp_path, monkeypatch):
    case_dir = tmp_path / "001-unmatched"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True)
    events = [{"artifact_type": "pcap_dns", "timestamp": "2026-07-09T03:00:00Z",
               "source_file": "evidence/other.pcap", "record_id": "D1",
               "host": "10.0.0.5", "data": {"dns_query": "evil.example.com"},
               "source_tool": "zeek", "source_execution_id": ""}]
    handles = [{"execution_id": "exec-conn", "evidence_path": "evidence/case.pcap",
                "tool": "tcpdump", "tool_version": "tcpdump", "engine": "tcpdump",
                "exact_command": "tcpdump -r evidence/case.pcap",
                "path": "raw_extract/conn.txt", "line_count": 10, "size_bytes": 100,
                "empty_data_status": "DATA_PRESENT"}]
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps(handles))
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))
    manifest = {"case_id": "001", "case_name": "unmatched", "artifact_profile": "auto",
                "canary_status": "FULL", "direction": "", "focus": False,
                "evidence": [], "artifacts": ["pcap_dns"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": _module()})

    phase_runner._run_phase_3_live(str(case_dir), manifest)

    findings = [yaml.safe_load(p.read_text())
                for p in Path(case_dir, "findings").glob("F-*-*.yaml")]
    assert len(findings) == 1
    eids = [r["execution_id"] for r in findings[0]["evidence_refs"]]
    assert "exec-conn" not in eids
    assert eids == [""]
