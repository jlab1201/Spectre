"""logfile/recognizer.py — claim generic CSV and unix .log / text logs.

Deliberately moderate confidence: binary modules (evtx/pcap/memory/disk) claim
their own formats via magic, so this only catches plain-text CSV/log evidence
that nothing more specific recognizes. A short text sniff guards against
mis-extensioned binaries.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "logfile_record"


def _sniff_text(path: Path) -> bool:
    """True if the first 4 KiB look like text (mostly printable, has a newline)."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
    except OSError:
        return False
    if not chunk:
        return False
    if b"\x00" in chunk:  # NUL → binary
        return False
    # Count non-text control bytes (allow tab/newline/carriage-return).
    text_bytes = bytes((7, 8, 9, 10, 12, 13, 27)) + bytes(range(0x20, 0x100))
    nontext = sum(1 for b in chunk if b not in text_bytes)
    return nontext / len(chunk) < 0.10


RECOGNIZERS = [
    Recognizer(
        module_name="logfile",
        artifact_type=ARTIFACT,
        extensions={".csv", ".tsv", ".log"},
        magic_patterns=["CSV text", "ASCII text", "Unicode text",
                        "UTF-8 Unicode text", "log text"],
        sniff=_sniff_text,
        confidence=0.82,
    ),
]
