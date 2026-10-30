"""registry_hive/extract.py — RegRipper full-plugin sweep over a hive.

`rip.pl -r <hive> -a` auto-detects the hive type from its header (SYSTEM,
SAM, SOFTWARE, SECURITY, NTUSER.DAT, ...) and runs every applicable plugin,
printing each plugin's report to stdout. normalize.py only parses the
Run/RunOnce autostart sections it understands; the full dump still lands in
raw_extract/ so a human can read whatever else RegRipper surfaced — nothing
is discarded, only narrowly interpreted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool, resolve_tool_version
from spectre.config import RAW_DIR

TOOL = "rip.pl"
TOOL_VERSION = "regripper-3.0"
ARTIFACT = "registry_run"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    """Run RegRipper's `-a` (all-plugins) mode over a hive. Returns [handle]."""
    ev = str(evidence_path)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(ev).stem or Path(ev).name
    output_path = str(Path(case_dir) / RAW_DIR / f"{ts}_{TOOL}_{stem}.txt")

    handle = run_tool(
        case_dir=case_dir,
        tool_name=TOOL,
        tool_version=resolve_tool_version(TOOL, "-h", TOOL_VERSION),
        command=[TOOL, "-r", ev, "-a"],
        params={"artifact_type": ARTIFACT, "evidence_path": ev,
                "phase": "extraction"},
        output_path=output_path,
        timeout=300,
        output_format="text",
    )
    handle["evidence_path"] = ev
    handle["artifact_type"] = ARTIFACT
    handle["tool"] = TOOL
    handle["tool_version"] = resolve_tool_version(TOOL, "-h", TOOL_VERSION)
    handle["exact_command"] = f"{TOOL} -r {ev} -a"
    return [handle]
