"""logfile/extract.py — pass-through extraction for CSV / unix .log evidence.

The evidence file is already parseable text, so there is no external tool to
run and no reason to copy a potentially huge file. We register a tool_exec
audit row and return a handle that points at the evidence in place; the
streaming normalizer reads it without materializing the whole file.
"""

from __future__ import annotations

from pathlib import Path

from spectre.pipeline.tool_runner import passthrough_handle

TOOL = "logfile"
TOOL_VERSION = "logfile-passthrough-1"
ARTIFACT = "logfile_record"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    handle = passthrough_handle(
        case_dir=case_dir,
        tool_name=TOOL,
        tool_version=TOOL_VERSION,
        evidence_path=str(evidence_path),
        params={"artifact_type": ARTIFACT, "evidence_path": str(evidence_path),
                "phase": "extraction"},
        output_format="csv" if Path(evidence_path).suffix.lower() in
                      (".csv", ".tsv") else "text",
    )
    handle["evidence_path"] = str(evidence_path)
    handle["artifact_type"] = ARTIFACT
    handle["tool"] = TOOL
    handle["tool_version"] = TOOL_VERSION
    handle["exact_command"] = f"passthrough:{TOOL} {evidence_path}"
    return [handle]
