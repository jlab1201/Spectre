"""A10 Finding 3 (tail): once extract.py stops discarding Zeek's handles
when tcpdump is unavailable (see tests/test_pcap/test_pcap_degraded_gap_fill.py
for the extract()-level fix), the REST of the pipeline must actually run to
completion on what Zeek did produce -- Phase 2 -> 3 -> 4 -> 6 must yield a
real findings/*.yaml and a non-empty reports/report.md, not just a
non-crashing extract() call.

Uses a fake pcap AnalyzerModule whose extract() returns exactly the shape
post-fix extract.py produces in the degraded scenario (one real Zeek handle
+ one "skipped_tool_unavailable" marker for the tcpdump gap-fill pass) —
the real spectre.modules.pcap.normalize.normalize dispatcher runs on it, and
a minimal fake rule (parity with tests/test_pipeline/test_pcap_provenance.py's
approach) proves a finding actually gets emitted and reaches the report.
"""
import json
from pathlib import Path

from tests.test_pipeline.custody_helpers import chain_triage
from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.modules.pcap.normalize import normalize as pcap_normalize
from spectre.pipeline import phase_runner


def _fire_on_conn(event):
    if event.artifact_type != "pcap_conn":
        return None
    return Anchor(
        rule_id="fake-degraded-rule",
        artifact_type="pcap_conn",
        event=event,
        title="Suspicious connection observed",
        mitre=["T1071"],
        confidence=0.6,
        dedup_key=event.record_id,
    )


def _make_module(extract_fn):
    rule = Rule(
        rule_id="fake-degraded-rule",
        artifact_type="pcap_conn",
        predicate=_fire_on_conn,
        mitre=["T1071"],
        description="fires on any pcap_conn event",
        metadata=RuleMetadata(uuid="fake-degraded-uuid", severity="medium"),
    )
    return AnalyzerModule(
        name="pcap", artifact_type="pcap_conn", required_tools=[],
        recognizers=[], extract=extract_fn, normalize=pcap_normalize,
        rules=[rule],
    )


def test_degraded_gap_fill_case_still_produces_findings_and_report(tmp_path, monkeypatch):
    case_dir = tmp_path / "003-degraded"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    (case_dir / "audit.jsonl").write_text("")

    conn_path = case_dir / "raw_extract" / "conn.log"
    conn_row = json.dumps({
        "ts": 1000.0, "uid": "C1",
        "id.orig_h": "10.1.13.175", "id.orig_p": 49000,
        "id.resp_h": "23.1.1.1", "id.resp_p": 443,
        "proto": "tcp", "orig_bytes": 10, "resp_bytes": 10,
        "orig_pkts": 1, "resp_pkts": 1,
    })
    conn_path.write_text(conn_row + "\n")

    def fake_degraded_extract(case_dir_arg, evidence_path):
        # Mirrors post-fix extract.py's zeek branch under a missing tcpdump:
        # Zeek's real, successful conn.log handle survives, plus a synthetic
        # skip marker for the http gap-fill pass that couldn't run.
        return [
            {"evidence_path": evidence_path, "artifact_type": "pcap_conn",
             "extract_pass": "zeek_conn", "tool": "zeek:conn.log",
             "tool_version": "zeek-8.0.9", "path": str(conn_path),
             "line_count": 1, "size_bytes": conn_path.stat().st_size,
             "empty_data_status": "DATA_PRESENT", "result": "success",
             "execution_id": "exec-conn"},
            {"evidence_path": evidence_path, "artifact_type": "pcap_http",
             "extract_pass": "http", "tool": "tcpdump", "tool_version": "tcpdump",
             "path": "", "line_count": 0, "size_bytes": 0,
             "empty_data_status": "UNVERIFIED",
             "result": "skipped_tool_unavailable",
             "skip_reason": "tcpdump unavailable/failed: "
                            "[Errno 2] No such file or directory: 'tcpdump'",
             "execution_id": ""},
        ]

    module = _make_module(fake_degraded_extract)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": module})

    manifest = {
        "case_id": "003", "case_name": "degraded", "artifact_profile": "auto",
        "canary_status": "DEGRADED", "direction": "", "focus": False,
        "evidence": [], "artifacts": ["pcap_conn"],
        "triage": {
            "evidence/case.pcap": {
                "status": "RECOGNIZED", "module": "pcap",
                "artifact_type": "pcap_conn",
            }
        },
    }

    chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
    p2 = phase_runner._run_phase_2_live(str(case_dir), manifest)
    assert p2["success"] is True, p2
    assert p2["handles"] == 2, "Zeek's handle + the skip marker must both survive"

    gap = manifest["extraction"]["results"]["evidence/case.pcap"].get("gap_fill_skipped")
    assert gap and gap[0]["tool"] == "tcpdump", (
        "the tcpdump gap-fill skip was not recorded (silent, undocumented blindspot)"
    )

    p3 = phase_runner._run_phase_3_live(str(case_dir), manifest)
    assert p3["success"] is True, p3

    finding_files = list((case_dir / "findings").glob("F-*.yaml"))
    assert finding_files, (
        "no findings produced even though Zeek's own handle carried a "
        "valid pcap_conn event -- the degraded gap-fill skip must not "
        "prevent detection on data Zeek DID successfully extract"
    )

    p4 = phase_runner.run_phase_4(str(case_dir), manifest)
    assert p4["success"] is True, p4

    p6 = phase_runner.run_phase_6(str(case_dir), manifest, skip_ai=True)
    assert p6["success"] is True, p6

    report_path = Path(manifest["report"]["report_md"])
    assert report_path.exists() and report_path.stat().st_size > 0, (
        "case must still produce a report.md, not the 'zero deliverables' "
        "outcome A10 Finding 3 documented"
    )
