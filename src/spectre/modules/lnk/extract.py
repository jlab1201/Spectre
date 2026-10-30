"""lnk/extract.py — pass-through extraction for Windows .lnk evidence.

A shortcut file is already a self-contained binary record; there is no
external tool to shell out to and no reason to copy the file — the parser
in normalize.py reads the bytes directly from the evidence path in place,
same pattern as prefetch/extract.py and logfile/extract.py.
"""

from __future__ import annotations

from spectre.pipeline.tool_runner import passthrough_handle

TOOL = "lnk"
TOOL_VERSION = "lnk-passthrough-1"
ARTIFACT = "lnk"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    handle = passthrough_handle(
        case_dir=case_dir,
        tool_name=TOOL,
        tool_version=TOOL_VERSION,
        evidence_path=str(evidence_path),
        params={"artifact_type": ARTIFACT, "evidence_path": str(evidence_path),
                "phase": "extraction"},
        output_format="binary",
    )
    handle["evidence_path"] = str(evidence_path)
    handle["artifact_type"] = ARTIFACT
    handle["tool"] = TOOL
    handle["tool_version"] = TOOL_VERSION
    handle["exact_command"] = f"passthrough:{TOOL} {evidence_path}"
    return [handle]
