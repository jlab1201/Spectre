"""A10 Finding 2 regression: under the Zeek engine, Phase 2 must resolve
monitored_ip from Zeek's own conn.log (not just the tcpdump "connections"
pass), so normalize_zeek_flows() stops no-op'ing and the pcap-large-transfer
/ pcap-staging-download rules (which key off pcap_flow events) get the same
chance to fire under Zeek that they already get under the manual engine.

This drives the REAL pcap normalize() dispatcher (spectre.modules.pcap.
normalize.normalize) through phase_runner._run_phase_2_live with a fake
extract() that hands back a Zeek-shaped handle (extract_pass="zeek_conn")
pointing at a small synthetic conn.log — the same shape zeek.extract()
produces in production, just without invoking the real zeek binary.
"""
import json
import tempfile
from pathlib import Path

from tests.test_pipeline.custody_helpers import chain_triage
from spectre.core.base import AnalyzerModule
from spectre.modules.pcap.normalize import normalize as pcap_normalize
from spectre.pipeline import phase_runner

VICTIM = "10.1.13.175"
STAGING_HOST = "108.181.20.35"


def _conn_row(ts, orig_h, orig_p, resp_h, resp_p, orig_b=0, resp_b=0,
              orig_pkts=1, resp_pkts=1):
    return json.dumps({
        "ts": ts, "uid": f"C{ts}",
        "id.orig_h": orig_h, "id.orig_p": orig_p,
        "id.resp_h": resp_h, "id.resp_p": resp_p,
        "proto": "tcp", "orig_bytes": orig_b, "resp_bytes": resp_b,
        "orig_pkts": orig_pkts, "resp_pkts": resp_pkts,
    })


def _conn_log_text() -> str:
    rows = [
        _conn_row(1000 + i, VICTIM, 49000 + i, dst, 443, orig_b=500, resp_b=9_000_000)
        for i, dst in enumerate(("23.1.1.1", "45.2.2.2", "67.3.3.3"))
    ]
    # Staging host: one peer, one connection, big download -- must lose the
    # monitored-host vote to the victim (3 distinct peers) even though it
    # moves more bytes/packets.
    rows.append(_conn_row(2000, STAGING_HOST, 443, VICTIM, 49500,
                           orig_b=1_400_000, resp_b=0,
                           orig_pkts=500, resp_pkts=500))
    return "\n".join(rows) + "\n"


def _make_case(tmp, conn_text):
    case_dir = Path(tmp) / "001-zeekflow"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    conn_path = case_dir / "raw_extract" / "conn.log"
    conn_path.write_text(conn_text)

    def fake_zeek_extract(case_dir_arg, evidence_path):
        return [{
            "execution_id": "exec-zeek-conn",
            "evidence_path": evidence_path,
            "path": str(conn_path),
            "tool": "zeek:conn.log",
            "tool_version": "zeek-8.0.9",
            "engine": "zeek",
            "exact_command": "zeek -C -r evidence/case.pcap LogAscii::use_json=T",
            "extract_pass": "zeek_conn",
            "artifact_type": "pcap_conn",
            "line_count": conn_text.count("\n"),
            "size_bytes": len(conn_text.encode()),
            "empty_data_status": "DATA_PRESENT",
        }]

    module = AnalyzerModule(
        name="pcap", artifact_type="pcap_conn", required_tools=[],
        recognizers=[], extract=fake_zeek_extract, normalize=pcap_normalize,
        rules=[],
    )

    manifest = {
        "case_id": "001", "case_name": "zeekflow", "artifact_profile": "auto",
        "canary_status": "FULL", "direction": "", "focus": False,
        "evidence": [], "artifacts": ["pcap_conn"],
        "triage": {
            "evidence/case.pcap": {
                "status": "RECOGNIZED", "module": "pcap",
                "artifact_type": "pcap_conn",
            }
        },
    }
    return str(case_dir), manifest, module


def test_zeek_engine_resolves_monitored_ip_and_emits_pcap_flow(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest, module = _make_case(tmp, _conn_log_text())
        monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": module})

        chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
        phase_runner._run_phase_2_live(case_dir, manifest)

        assert manifest.get("monitored_ip") == VICTIM, (
            "monitored_ip never resolved from the Zeek zeek_conn handle"
        )

        events = json.loads(
            (Path(case_dir) / "raw_extract" / "normalized_events.json").read_text()
        )
        flows = [e for e in events if e["artifact_type"] == "pcap_flow"]
        assert flows, (
            "no pcap_flow events emitted under the Zeek engine -- "
            "pcap-large-transfer / pcap-staging-download would never fire"
        )
        remote_ips = {f["data"]["remote_ip"] for f in flows}
        # The three C2-ish large-transfer peers and the staging host must
        # all show up as flows oriented against the victim.
        assert {"23.1.1.1", "45.2.2.2", "67.3.3.3", STAGING_HOST} <= remote_ips

        staging_flow = next(f for f in flows if f["data"]["remote_ip"] == STAGING_HOST)
        # Victim received the download (staging host was resp_h -> orig_b is
        # what the staging host sent -> bytes_in from the victim's view).
        assert staging_flow["data"]["bytes_in"] == 1_400_000


def test_manual_engine_unaffected_by_zeek_fallback(monkeypatch):
    """The fallback must never fire when a real "connections" (tcpdump) pass
    handle is present -- the pre-existing manual-engine path is untouched."""
    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "002-manual"
        for sub in ("evidence", "raw_extract", "findings", "reports"):
            (case_dir / sub).mkdir(parents=True, exist_ok=True)

        conn_path = case_dir / "raw_extract" / "conn.txt"
        conn_path.write_text(
            f"2026-01-01 00:00:00.1 IP {VICTIM}.49000 > 23.1.1.1.443: tcp 0\n"
            f"2026-01-01 00:00:00.2 IP {VICTIM}.49001 > 45.2.2.2.443: tcp 0\n"
        )

        def fake_manual_extract(case_dir_arg, evidence_path):
            return [{
                "execution_id": "exec-conn",
                "evidence_path": evidence_path,
                "path": str(conn_path),
                "tool": "tcpdump",
                "tool_version": "tcpdump",
                "engine": "tcpdump",
                "exact_command": "tcpdump -nn -tttt -q -r evidence/case.pcap",
                "extract_pass": "connections",
                "artifact_type": "pcap_conn",
                "line_count": 2,
                "size_bytes": conn_path.stat().st_size,
                "empty_data_status": "DATA_PRESENT",
            }]

        module = AnalyzerModule(
            name="pcap", artifact_type="pcap_conn", required_tools=[],
            recognizers=[], extract=fake_manual_extract, normalize=pcap_normalize,
            rules=[],
        )
        manifest = {
            "case_id": "002", "case_name": "manual", "artifact_profile": "auto",
            "canary_status": "FULL", "direction": "", "focus": False,
            "evidence": [], "artifacts": ["pcap_conn"],
            "triage": {
                "evidence/case.pcap": {
                    "status": "RECOGNIZED", "module": "pcap",
                    "artifact_type": "pcap_conn",
                }
            },
        }
        monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": module})
        chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
        phase_runner._run_phase_2_live(case_dir, manifest)
        assert manifest.get("monitored_ip") == VICTIM
