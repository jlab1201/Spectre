"""pcap/extract.py — capture extraction with a selectable engine.

PRIMARY engine is **Zeek** (structured JSON logs → zeek_normalize). The
tcpdump/tshark passes are the automatic **fallback** (when Zeek is absent)
and the on-demand **verification** path (verify()). Two tcpdump passes —
HTTP ASCII payload and the IP/TCP checksum tamper check — Zeek does not
cover by default, so they also run alongside Zeek to fill those gaps.

Engine is chosen by config.PCAP_ENGINE (auto | zeek | manual). "auto" uses
Zeek when its binary resolves, else the manual passes.
"""

from __future__ import annotations

import shlex
from datetime import datetime, timezone
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool, resolve_tool_version
from spectre.config import RAW_DIR, PCAP_ENGINE
from spectre.modules.pcap import zeek

TOOL = "tcpdump"
TOOL_VERSION = "tcpdump"


def _build_handle(handle: dict, evidence_path: str, artifact_type: str,
                  extract_pass: str, exact_command: str,
                  tool: str = TOOL, tool_version: str = TOOL_VERSION) -> dict:
    """Augment a run_tool handle with pcap-specific metadata fields."""
    handle["evidence_path"] = str(evidence_path)
    handle["artifact_type"] = artifact_type
    handle["extract_pass"] = extract_pass
    handle["tool"] = tool
    handle["tool_version"] = tool_version
    handle["exact_command"] = exact_command
    return handle


def _out(case_dir: str, ts: str, tool: str, tag: str, stem: str) -> str:
    return str(Path(case_dir) / RAW_DIR / f"{ts}_{tool}_{tag}_{stem}.txt")


# ── Individual manual passes (tcpdump / tshark) ───────────────────────
# Each is a self-contained pass returning one augmented handle, reused by
# the manual engine, the Zeek gap-fill, and verify().

def _pass_connections(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tcpdump", "conn", stem)
    cmd = [TOOL, "-nn", "-tttt", "-q", "-r", str(evidence_path)]
    h = run_tool(case_dir=case_dir, tool_name=TOOL, tool_version=resolve_tool_version(TOOL, "--version", TOOL_VERSION),
                 command=cmd, params={"artifact_type": "pcap_conn",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "connections"}, output_path=path,
                 timeout=600, output_format="text")
    return _build_handle(h, evidence_path, "pcap_conn", "connections",
                         f"{TOOL} -nn -tttt -q -r {evidence_path}")


def _pass_dns(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tcpdump", "dns", stem)
    cmd = [TOOL, "-nn", "-tttt", "port", "53", "-r", str(evidence_path)]
    h = run_tool(case_dir=case_dir, tool_name=TOOL, tool_version=resolve_tool_version(TOOL, "--version", TOOL_VERSION),
                 command=cmd, params={"artifact_type": "pcap_dns",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "dns"}, output_path=path,
                 timeout=300, output_format="text")
    return _build_handle(h, evidence_path, "pcap_dns", "dns",
                         f"{TOOL} -nn -tttt port 53 -r {evidence_path}")


def _pass_http(case_dir, evidence_path, ts, stem) -> dict:
    """HTTP ASCII payload pass. Supplies ascii_payload / http_server and the
    injected-URL detection that Zeek's http.log (structured, no bodies)
    lacks — so it runs in BOTH manual and Zeek modes."""
    path = _out(case_dir, ts, "tcpdump", "http", stem)
    cmd = [TOOL, "-nn", "-tttt", "-A",
           "tcp port 80 or tcp port 8080 or tcp port 443", "-r", str(evidence_path)]
    h = run_tool(case_dir=case_dir, tool_name=TOOL, tool_version=resolve_tool_version(TOOL, "--version", TOOL_VERSION),
                 command=cmd, params={"artifact_type": "pcap_http",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "http"}, output_path=path,
                 timeout=600, output_format="text")
    return _build_handle(h, evidence_path, "pcap_http", "http",
                         f"{TOOL} -nn -tttt -A \"tcp port 80 or tcp port 8080 or tcp port 443\" -r {evidence_path}")


def _pass_timing(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tcpdump", "timing", stem)
    # pipefail: without it the pipeline's exit code is awk's, so a failed
    # tcpdump yields an EMPTY log that still reports success — silent
    # evidence loss. The path is shell-quoted for the same reason it is in
    # zeek.py: case/evidence names routinely contain spaces.
    timing_cmd = (
        f"set -o pipefail; {TOOL} -nn -tttt -r {shlex.quote(str(evidence_path))} "
        f"'ip' 2>/dev/null | "
        f"awk '{{gsub(/:$/, \"\", $6); print $4 \",\" $6 \",\" $1,$2}}'"
    )
    h = run_tool(case_dir=case_dir, tool_name="bash", tool_version="bash",
                 command=["bash", "-c", timing_cmd],
                 params={"artifact_type": "pcap_timing",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "timing"}, output_path=path,
                 timeout=600, output_format="text")
    return _build_handle(h, evidence_path, "pcap_timing", "timing",
                         f"bash -c '{timing_cmd}'", tool="bash", tool_version="bash")


def _pass_smb(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tshark", "smb", stem)
    cmd = ["tshark", "-r", str(evidence_path), "-Y", "smb2.cmd == 5",
           "-T", "fields", "-e", "frame.time", "-e", "ip.src",
           "-e", "ip.dst", "-e", "smb2.filename"]
    h = run_tool(case_dir=case_dir, tool_name="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"),
                 command=cmd, params={"artifact_type": "smb_pipe",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "smb2_pipes"}, output_path=path,
                 timeout=300, output_format="text")
    return _build_handle(h, evidence_path, "smb_pipe", "smb2_pipes",
                         f"tshark -r {evidence_path} -Y \"smb2.cmd == 5\"",
                         tool="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"))


def _pass_drsuapi(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tshark", "drsuapi", stem)
    cmd = ["tshark", "-r", str(evidence_path), "-Y", "drsuapi",
           "-T", "fields", "-e", "frame.time", "-e", "ip.src",
           "-e", "ip.dst", "-e", "drsuapi.opnum"]
    h = run_tool(case_dir=case_dir, tool_name="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"),
                 command=cmd, params={"artifact_type": "drsuapi_call",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "drsuapi_opnum"}, output_path=path,
                 timeout=300, output_format="text")
    return _build_handle(h, evidence_path, "drsuapi_call", "drsuapi_opnum",
                         f"tshark -r {evidence_path} -Y \"drsuapi\" -T fields "
                         f"-e frame.time -e ip.src -e ip.dst -e drsuapi.opnum",
                         tool="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"))


def _pass_kerberos(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tshark", "kerberos", stem)
    cmd = ["tshark", "-r", str(evidence_path), "-Y", "kerberos.CNameString",
           "-T", "fields", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
           "-e", "udp.dstport", "-e", "tcp.dstport",
           "-e", "kerberos.CNameString", "-e", "kerberos.realm"]
    h = run_tool(case_dir=case_dir, tool_name="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"),
                 command=cmd, params={"artifact_type": "host_identity",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "kerberos_identity"}, output_path=path,
                 timeout=300, output_format="text")
    return _build_handle(h, evidence_path, "host_identity", "kerberos_identity",
                         f"tshark -r {evidence_path} -Y \"kerberos.CNameString\" -T fields "
                         f"-e frame.time -e ip.src -e ip.dst -e udp.dstport -e tcp.dstport "
                         f"-e kerberos.CNameString -e kerberos.realm",
                         tool="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"))


def _pass_dhcp(case_dir, evidence_path, ts, stem) -> dict:
    path = _out(case_dir, ts, "tshark", "dhcp", stem)
    cmd = ["tshark", "-r", str(evidence_path), "-Y", "dhcp.option.hostname",
           "-T", "fields", "-e", "frame.time", "-e", "dhcp.option.hostname",
           "-e", "dhcp.option.requested_ip_address", "-e", "dhcp.ip.your",
           "-e", "dhcp.hw.mac_addr", "-e", "dhcp.option.dhcp"]
    h = run_tool(case_dir=case_dir, tool_name="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"),
                 command=cmd, params={"artifact_type": "host_identity",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "dhcp_identity"}, output_path=path,
                 timeout=300, output_format="text")
    return _build_handle(h, evidence_path, "host_identity", "dhcp_identity",
                         f"tshark -r {evidence_path} -Y \"dhcp.option.hostname\" -T fields "
                         f"-e frame.time -e dhcp.option.hostname -e dhcp.option.requested_ip_address "
                         f"-e dhcp.ip.your -e dhcp.hw.mac_addr -e dhcp.option.dhcp",
                         tool="tshark", tool_version=resolve_tool_version("tshark", "--version", "4.2"))


def _pass_checksum(case_dir, evidence_path, ts, stem) -> dict:
    """IP/TCP checksum tamper check (inbound-only). Zeek does not validate
    L3/L4 checksums, so this tcpdump -v pass runs in BOTH engines."""
    path = _out(case_dir, ts, "tcpdump", "checksum", stem)
    cmd = [TOOL, "-nn", "-tttt", "-v", "tcp", "-r", str(evidence_path)]
    h = run_tool(case_dir=case_dir, tool_name=TOOL, tool_version=resolve_tool_version(TOOL, "--version", TOOL_VERSION),
                 command=cmd, params={"artifact_type": "pcap_checksum",
                 "evidence_path": str(evidence_path), "phase": "extraction",
                 "extract_pass": "checksum"}, output_path=path,
                 timeout=600, output_format="text")
    return _build_handle(h, evidence_path, "pcap_checksum", "checksum",
                         f"{TOOL} -nn -tttt -v tcp -r {evidence_path}")


# All manual passes, in order.
_MANUAL_PASSES = [
    _pass_connections, _pass_dns, _pass_http, _pass_timing, _pass_smb,
    _pass_drsuapi, _pass_kerberos, _pass_dhcp, _pass_checksum,
]

# artifact_type -> manual passes that produce it (for verify()).
_VERIFY_PASSES = {
    "pcap_conn": [_pass_connections],
    "pcap_flow": [_pass_connections],
    "pcap_timing": [_pass_timing],
    "pcap_dns": [_pass_dns],
    "pcap_http": [_pass_http],
    "smb_pipe": [_pass_smb],
    "drsuapi_call": [_pass_drsuapi],
    "host_identity": [_pass_kerberos, _pass_dhcp],
    "pcap_checksum": [_pass_checksum],
}


def _resolve_engine() -> str:
    """Choose the extraction engine per config, degrading gracefully."""
    if PCAP_ENGINE == "manual":
        return "manual"
    # "auto" or "zeek": use Zeek when its binary resolves, else fall back.
    if PCAP_ENGINE in ("auto", "zeek") and zeek.available():
        return "zeek"
    return "manual"


def _extract_manual(case_dir: str, evidence_path: str) -> list[dict]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(evidence_path).stem
    return [p(case_dir, evidence_path, ts, stem) for p in _MANUAL_PASSES]


def _skip_marker(evidence_path: str, artifact_type: str, extract_pass: str,
                  tool: str, exc: Exception) -> dict:
    """Synthetic handle recorded when an optional Zeek gap-fill pass
    (HTTP ASCII payload / checksum tamper verification) can't run because
    its tool is unavailable or the run otherwise fails (A10 Finding 3).

    Appending this instead of letting the exception propagate keeps Zeek's
    already-successful handles alive — the analyst gets an honest "not run"
    record instead of the whole case being silently discarded. Shaped like
    a real handle so downstream code treats it as inert data rather than
    crashing on a missing key: normalize()'s dispatcher no-ops on an empty
    `path`, and empty_data_protocol() reads line_count/size_bytes directly
    (not via .get), so both must be present.
    """
    return {
        "evidence_path": str(evidence_path),
        "artifact_type": artifact_type,
        "extract_pass": extract_pass,
        "tool": tool,
        "tool_version": tool,
        "exact_command": "",
        "path": "",
        "line_count": 0,
        "size_bytes": 0,
        "output_sha256": "",
        "is_json": False,
        "execution_id": "",
        "exit_code": -1,
        "duration_ms": 0,
        "result": "skipped_tool_unavailable",
        "empty_data_status": "UNVERIFIED",
        "stderr": str(exc)[:500],
        "skip_reason": f"{tool} unavailable/failed: {exc}",
    }


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    """Engine-dispatching extract. Zeek mode also runs the two tcpdump
    passes Zeek can't cheaply replace (HTTP ASCII payload, checksum tamper
    check). Each gap-fill pass is wrapped independently: if its tool is
    missing or the run otherwise fails, Zeek's already-successful handles
    must still be returned — not discarded by an uncaught exception from a
    later, non-essential pass in the same call (A10 Finding 3)."""
    if _resolve_engine() == "zeek":
        handles = zeek.extract(case_dir, evidence_path)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = Path(evidence_path).stem
        try:
            handles.append(_pass_http(case_dir, evidence_path, ts, stem))
        except Exception as e:
            handles.append(_skip_marker(evidence_path, "pcap_http", "http", TOOL, e))
        try:
            handles.append(_pass_checksum(case_dir, evidence_path, ts, stem))
        except Exception as e:
            handles.append(_skip_marker(evidence_path, "pcap_checksum", "checksum", TOOL, e))
        return handles
    return _extract_manual(case_dir, evidence_path)


def verify(case_dir: str, evidence_path: str,
           artifact_type: str | None = None) -> list[dict]:
    """On-demand manual cross-check of a Zeek result. Runs the tcpdump/
    tshark pass(es) that produce *artifact_type* (all manual passes when
    None) so their normalized events can be diffed against the Zeek engine's
    for the same capture. Returns the manual handles."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(evidence_path).stem
    passes = _VERIFY_PASSES.get(artifact_type, _MANUAL_PASSES) if artifact_type else _MANUAL_PASSES
    return [p(case_dir, evidence_path, ts, stem) for p in passes]
