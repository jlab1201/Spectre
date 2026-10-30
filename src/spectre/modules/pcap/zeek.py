"""pcap/zeek.py — run Zeek over a capture and register its JSON logs.

Zeek is the PRIMARY pcap engine. One `zeek -r <pcap>` run emits a set of
structured JSON logs (conn.log, dns.log, http.log, dce_rpc.log,
kerberos.log, dhcp.log, …). We:

  1. run Zeek through run_tool() — audited + exit-code/stderr captured as
     the invocation record (chain of custody for the run itself);
  2. register each produced log file with passthrough_handle() — hashing
     it in place and writing its own tool_exec audit row, so every log is
     independently tamper-evident;
  3. tag each handle with the extract_pass / artifact_type the dispatcher
     in normalize.py routes to zeek_normalize.

Host-neutral: the binary is config.ZEEK_PATH (env-overridable). Missing
Zeek is handled by the caller (extract.py) as a graceful fallback to the
tcpdump/tshark passes — this module assumes Zeek resolved.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool, passthrough_handle
from spectre.config import RAW_DIR, ZEEK_PATH, ZEEK_POLICY

TOOL = "zeek"

# Zeek log filename -> (extract_pass, artifact_type). The artifact_type is
# the PRIMARY type the log produces; conn.log also yields pcap_flow and
# pcap_timing (handled by the zeek_conn branch of the dispatcher).
_LOG_MAP = {
    "conn.log": ("zeek_conn", "pcap_conn"),
    "dns.log": ("zeek_dns", "pcap_dns"),
    "http.log": ("zeek_http", "pcap_http"),
    "dce_rpc.log": ("zeek_dce_rpc", "smb_pipe"),
    "kerberos.log": ("zeek_kerberos", "host_identity"),
    "dhcp.log": ("zeek_dhcp", "host_identity"),
}


def available() -> bool:
    """True if the resolved Zeek binary exists and is executable."""
    return bool(shutil.which(ZEEK_PATH) or (os.path.isfile(ZEEK_PATH) and os.access(ZEEK_PATH, os.X_OK)))


@lru_cache(maxsize=1)
def _zeek_version() -> str:
    """Real Zeek version string for the audit trail (e.g. "zeek-8.0.9").

    Chain of custody: a log is only reproducible if the audit row records
    WHICH Zeek produced it. Falls back to the bare tool name if the binary
    is missing or misbehaves — never raises, never blocks extraction.
    """
    try:
        out = subprocess.run([ZEEK_PATH, "--version"], capture_output=True,
                             text=True, timeout=15)
        token = (out.stdout or out.stderr).strip().split()
        # `zeek version 8.0.9` → take the last whitespace-delimited token.
        if token:
            return f"zeek-{token[-1]}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "zeek"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    """Run Zeek and return one handle per produced JSON log we consume."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(evidence_path).stem
    raw_dir = Path(case_dir) / RAW_DIR
    logdir = raw_dir / f"zeek_{ts}_{stem}"
    logdir.mkdir(parents=True, exist_ok=True)

    # Build the Zeek command. LogAscii::use_json=T makes every log JSON
    # (one object per line). -C skips checksum verification (offloaded NICs
    # emit bad checksums routinely; the dedicated tcpdump -v pass owns the
    # tamper check). Run inside logdir so logs land there; a bash wrapper is
    # already the module idiom (see the timing pass in extract.py).
    # Every interpolated path is shell-quoted: case dirs and evidence names
    # routinely contain spaces ("Case File 2026/evidence sample.pcap"), and an
    # unquoted path makes Zeek fail on the capture entirely.
    policy = f" {shlex.quote(ZEEK_POLICY)}" if ZEEK_POLICY else ""
    inner = (f"cd {shlex.quote(str(logdir))} && {shlex.quote(ZEEK_PATH)} "
             f"-C -r {shlex.quote(str(evidence_path))} "
             f"LogAscii::use_json=T{policy}")
    run_log = str(raw_dir / f"{ts}_zeek_run_{stem}.log")
    run_handle = run_tool(
        case_dir=case_dir,
        tool_name=TOOL,
        tool_version=_zeek_version(),
        command=["bash", "-c", inner],
        params={"artifact_type": "zeek_run", "evidence_path": str(evidence_path),
                "phase": "extraction", "extract_pass": "zeek_run",
                "logdir": str(logdir)},
        output_path=run_log,
        timeout=1200,
        output_format="text",
    )

    handles: list[dict] = []
    # If Zeek failed outright, surface the (audited) run handle so the
    # failure is visible; no logs to register.
    if run_handle.get("result") != "success":
        run_handle["evidence_path"] = str(evidence_path)
        run_handle["artifact_type"] = "zeek_run"
        run_handle["extract_pass"] = "zeek_run"
        run_handle["tool"] = TOOL
        run_handle["tool_version"] = _zeek_version()
        run_handle["exact_command"] = inner
        return [run_handle]

    for fname, (extract_pass, artifact_type) in _LOG_MAP.items():
        fpath = logdir / fname
        if not fpath.exists() or fpath.stat().st_size == 0:
            continue
        handle = passthrough_handle(
            case_dir=case_dir,
            tool_name=f"{TOOL}:{fname}",
            tool_version=_zeek_version(),
            evidence_path=str(fpath),
            params={"artifact_type": artifact_type, "evidence_path": str(evidence_path),
                    "phase": "extraction", "extract_pass": extract_pass},
            output_format="text",
        )
        handle["evidence_path"] = str(evidence_path)
        handle["artifact_type"] = artifact_type
        handle["extract_pass"] = extract_pass
        handle["tool"] = f"{TOOL}:{fname}"
        handle["tool_version"] = _zeek_version()
        handle["exact_command"] = inner
        handles.append(handle)

    return handles
