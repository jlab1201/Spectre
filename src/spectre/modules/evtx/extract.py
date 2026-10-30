"""
evtx/extract.py — run evtxexport on a real .evtx file.

Routes through tool_runner.run_tool() so the invocation is audited
(SHA-256 + chained audit row) exactly like every other tool call. The
output is the raw evtxexport XML, written to the case output directory;
normalize.py parses it afterwards.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

# tool_runner is in pipeline/
from spectre.pipeline.tool_runner import run_tool, resolve_tool_version
from spectre.config import RAW_DIR

TOOL = "evtxexport"
TOOL_VERSION = "libevtx-20251118"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    """Extract a .evtx file to XML via evtxexport. Returns [handle]."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(evidence_path).stem
    output_path = str(Path(case_dir) / RAW_DIR / f"{ts}_evtx_{stem}.xml")

    handle = run_tool(
        case_dir=case_dir,
        tool_name=TOOL,
        tool_version=resolve_tool_version(TOOL, "-V", TOOL_VERSION),
        command=[TOOL, "-f", "xml", str(evidence_path)],
        params={
            "artifact_type": "process_creation",
            "evidence_path": str(evidence_path),
            "phase": "extraction",
            "format": "xml",
        },
        output_path=output_path,
        timeout=600,
        output_format="text",
    )
    # Carry provenance so normalize() and emit_from_handle() can use it.
    handle["evidence_path"] = str(evidence_path)
    handle["artifact_type"] = "process_creation"
    handle["tool"] = TOOL
    handle["tool_version"] = resolve_tool_version(TOOL, "-V", TOOL_VERSION)
    handle["exact_command"] = f"{TOOL} -f xml {evidence_path}"
    return [handle]
