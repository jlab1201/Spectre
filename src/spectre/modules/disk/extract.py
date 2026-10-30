"""disk/extract.py — Sleuth Kit triage over a disk image.

mmls  -> partition layout (informational handle)
fls -r -m -> recursive filesystem timeline in body-file format

fls on a whole partitioned image may require a partition offset; for
single-filesystem images it works directly. A non-zero exit yields an
error handle and normalize() returns no events (honest, no fabrication).
plaso (log2timeline) is intentionally left as an optional follow-on.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone

from spectre.pipeline.tool_runner import run_tool
from spectre.config import RAW_DIR


def _run(case_dir, evidence_path, tool, version, command, artifact, fmt):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = Path(evidence_path).stem
    output_path = str(Path(case_dir) / RAW_DIR / f"{ts}_{tool}_{stem}.txt")
    handle = run_tool(
        case_dir=case_dir, tool_name=tool, tool_version=version,
        command=command, params={"artifact_type": artifact,
                                 "evidence_path": str(evidence_path),
                                 "phase": "extraction"},
        output_path=output_path, timeout=1800, output_format=fmt,
    )
    handle["evidence_path"] = str(evidence_path)
    handle["artifact_type"] = artifact
    handle["tool"] = tool
    handle["tool_version"] = version
    handle["exact_command"] = " ".join(command)
    return handle


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    ev = str(evidence_path)
    handles = []
    # Partition layout (informational; helps an analyst find offsets).
    handles.append(_run(case_dir, ev, "mmls", "sleuthkit",
                        ["mmls", ev], "disk_partitions", "text"))
    # Recursive filesystem timeline (body format). -z UTC pins the
    # timezone TSK uses to interpret on-disk timestamp fields that carry
    # no embedded offset (FAT/exFAT local wall-clock); NTFS is unaffected
    # (its on-disk FILETIME fields are already true UTC) but the flag is
    # harmless there (A6 Finding 5 — same defect class as Finding 1,
    # applied to disk evidence).
    handles.append(_run(case_dir, ev, "fls", "sleuthkit",
                        ["fls", "-r", "-m", "/", "-z", "UTC", ev],
                        "disk_file_entry", "text"))
    # Carve nested forensic artifacts (EVTX/hives/prefetch/LNK/$MFT) so the
    # pipeline can register them as derived evidence and re-triage them.
    from spectre.modules.disk.carve import carve_targets
    fls_handle = handles[-1]
    if fls_handle.get("result") == "success":
        fls_handle["derived_files"] = carve_targets(case_dir, ev,
                                                    fls_handle["path"])
    return handles
