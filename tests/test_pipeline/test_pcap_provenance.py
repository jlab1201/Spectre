"""
test_pcap_provenance.py — chain-of-custody regression: a pcap finding must
record the tool/exact_command of the EXTRACT PASS that actually produced its
underlying event, not the last handle built for the evidence file.

Bug (gold-loop audit, 4 real cases): extract.py's pcap module runs multiple
passes over the same evidence_path — tcpdump for connections/dns/http/timing
and tshark only for the smb2-pipe pass. Phase 3 indexed handles by
evidence_path alone (`{h["evidence_path"]: h ...}`), so with 5 handles
sharing one evidence_path the LAST one built (smb2_pipes/tshark) silently
clobbered the rest in that dict. Every finding — including DNS/HTTP/conn
findings extracted with tcpdump — was then emitted with the SMB tshark
handle's tool ("tshark 4.2") and exact_command (`tshark ... smb2.cmd == 5`),
corrupting the audit trail for tcpdump-derived findings.

NormEvent now also carries source_execution_id — the execution_id of the
SPECIFIC handle that produced it (Phase 2 stamps it in
phase_runner._run_phase_2_live, alongside the pre-existing source_tool).
Phase 3 resolves a finding's provenance handle by that execution_id first,
since (source_file, source_tool) alone is still ambiguous when the SAME tool
runs multiple passes over one evidence file (pcap's tcpdump does exactly
this for connections/dns/http/timing).
"""

import json
import tempfile
from pathlib import Path

import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.pipeline import phase_runner


def _event(record_id, artifact_type, source_tool, data, source_execution_id="",
           ts="2026-07-09T03:00:00Z", source="evidence/case.pcap"):
    return {"artifact_type": artifact_type, "timestamp": ts,
            "source_file": source, "record_id": record_id, "host": "10.0.0.5",
            "data": data, "source_tool": source_tool,
            "source_execution_id": source_execution_id}


def _dns_rule_predicate(event):
    if event.artifact_type != "pcap_dns":
        return None
    return Anchor(
        rule_id="fake-dns-rule",
        artifact_type="pcap_dns",
        event=event,
        title="Suspicious DNS query observed",
        mitre=[],
        confidence=0.6,
        dedup_key=event.record_id,
    )


def _smb_rule_predicate(event):
    if event.artifact_type != "smb_pipe":
        return None
    return Anchor(
        rule_id="fake-smb-rule",
        artifact_type="smb_pipe",
        event=event,
        title="AD recon named pipe observed",
        mitre=[],
        confidence=0.7,
        dedup_key=event.record_id,
    )


def _make_pcap_module():
    dns_rule = Rule(
        rule_id="fake-dns-rule",
        artifact_type="pcap_dns",
        predicate=_dns_rule_predicate,
        mitre=[],
        description="fires on any pcap_dns event",
        metadata=RuleMetadata(uuid="fake-dns-uuid", severity="low"),
    )
    smb_rule = Rule(
        rule_id="fake-smb-rule",
        artifact_type="smb_pipe",
        predicate=_smb_rule_predicate,
        mitre=[],
        description="fires on any smb_pipe event",
        metadata=RuleMetadata(uuid="fake-smb-uuid", severity="medium"),
    )
    return AnalyzerModule(
        name="pcap",
        artifact_type="pcap",
        required_tools=[],
        recognizers=[],
        extract=lambda case_dir, evidence_path: [],
        normalize=lambda handle: [],
        rules=[dns_rule, smb_rule],
    )


def _make_case(tmp):
    case_dir = Path(tmp) / "001-pcapprov"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    events = [
        _event("D1", "pcap_dns", "tcpdump", {"dns_query": "evil.example.com"},
               source_execution_id="exec-dns"),
        _event("S1", "smb_pipe", "tshark", {"named_pipe": "\\PIPE\\samr"},
               source_execution_id="exec-smb"),
    ]
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))

    # Handles as extract.py actually builds them: multiple passes over the
    # SAME evidence_path, tcpdump for dns/conn/http/timing, tshark only for
    # the smb2-pipe pass — tshark's handle is appended LAST.
    handles = [
        {"execution_id": "exec-conn", "evidence_path": "evidence/case.pcap",
         "tool": "tcpdump", "tool_version": "tcpdump", "engine": "tcpdump",
         "exact_command": "tcpdump -nn -tttt -q -r evidence/case.pcap",
         "path": "raw_extract/conn.txt", "line_count": 10, "size_bytes": 100,
         "empty_data_status": "DATA_PRESENT"},
        {"execution_id": "exec-dns", "evidence_path": "evidence/case.pcap",
         "tool": "tcpdump", "tool_version": "tcpdump", "engine": "tcpdump",
         "exact_command": "tcpdump -nn -tttt port 53 -r evidence/case.pcap",
         "path": "raw_extract/dns.txt", "line_count": 4, "size_bytes": 40,
         "empty_data_status": "DATA_PRESENT"},
        {"execution_id": "exec-http", "evidence_path": "evidence/case.pcap",
         "tool": "tcpdump", "tool_version": "tcpdump", "engine": "tcpdump",
         "exact_command": "tcpdump -nn -tttt -A ... -r evidence/case.pcap",
         "path": "raw_extract/http.txt", "line_count": 6, "size_bytes": 60,
         "empty_data_status": "DATA_PRESENT"},
        {"execution_id": "exec-timing", "evidence_path": "evidence/case.pcap",
         "tool": "bash", "tool_version": "bash", "engine": "bash",
         "exact_command": "bash -c '...'",
         "path": "raw_extract/timing.txt", "line_count": 20, "size_bytes": 200,
         "empty_data_status": "DATA_PRESENT"},
        {"execution_id": "exec-smb", "evidence_path": "evidence/case.pcap",
         "tool": "tshark", "tool_version": "4.2", "engine": "tshark",
         "exact_command": 'tshark -r evidence/case.pcap -Y "smb2.cmd == 5"',
         "path": "raw_extract/smb.txt", "line_count": 2, "size_bytes": 20,
         "empty_data_status": "DATA_PRESENT"},
    ]
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps(handles))
    # W3-1: chain the hashes exactly as Phase 2 does, or Phase 3 refuses them.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))

    manifest = {"case_id": "001", "case_name": "pcapprov",
                "artifact_profile": "auto", "canary_status": "FULL",
                "direction": "", "focus": False,
                "evidence": [], "artifacts": ["pcap_dns", "smb_pipe"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _findings(case_dir):
    fdir = Path(case_dir) / "findings"
    return {f.stem: yaml.safe_load(f.read_text()) for f in fdir.glob("F-*-*.yaml")}


def test_finding_provenance_matches_producing_pass(monkeypatch):
    """A DNS finding must carry tcpdump provenance; an SMB finding must
    carry tshark provenance — even though both events share one
    evidence_path and the tshark handle was built LAST."""
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest = _make_case(tmp)

        modules = {"pcap": _make_pcap_module()}
        monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

        phase_runner._run_phase_3_live(case_dir, manifest)

        findings = _findings(case_dir)
        assert len(findings) == 2, findings

        dns_finding = next(f for f in findings.values()
                            if f["title"] == "Suspicious DNS query observed")
        smb_finding = next(f for f in findings.values()
                            if f["title"] == "AD recon named pipe observed")

        assert dns_finding["tool"].split()[0] == "tcpdump", dns_finding["tool"]
        assert "smb2.cmd" not in dns_finding["exact_command"]
        assert "port 53" in dns_finding["exact_command"]

        assert smb_finding["tool"].split()[0] == "tshark", smb_finding["tool"]
        assert "smb2.cmd" in smb_finding["exact_command"]
