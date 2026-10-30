"""disk/normalize.py — Sleuth Kit fls body-file output -> file_entry events.

Body format (fls -m):
  md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
Only the fls timeline handle yields events; mmls is informational.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from spectre.core.base import NormEvent


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _epoch_to_iso(raw: str) -> str:
    """Convert Sleuth Kit's raw Unix-epoch-seconds mtime to ISO8601-UTC —
    the shape every other module's NormEvent.timestamp uses (A6 Finding 4).
    A bare epoch string is unparseable by both report_synthesize's
    _parse_finding_ts and clustering's _parse_time, so left unconverted it
    silently sorts by string accident and never joins temporal correlation.

    Returns "" (undated, never fabricated) for 0/negative/non-numeric —
    epoch 0 is a common "never modified"/sparse body-file value and must
    not be rendered as a fake 1970-01-01 timestamp.
    """
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return ""
    if val <= 0:
        return ""
    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()


def normalize(handle: dict) -> list[NormEvent]:
    if handle.get("artifact_type") != "disk_file_entry":
        return []  # mmls / partition layout is informational only
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    source = handle.get("evidence_path", path)
    events: list[NormEvent] = []
    for i, line in enumerate(Path(path).read_text(errors="replace").splitlines()):
        parts = line.split("|")
        if len(parts) < 11:
            continue
        name = parts[1]
        events.append(NormEvent(
            artifact_type="disk_file_entry",
            timestamp=_epoch_to_iso(parts[8]),  # mtime (epoch -> ISO8601 UTC)
            source_file=source,
            record_id=parts[2],  # inode
            host="",
            data={
                "path": name,
                "basename": _basename(name),
                "size": parts[6],
                "atime": parts[7], "mtime": parts[8],
                "ctime": parts[9], "crtime": parts[10],
            },
        ))
    return events
