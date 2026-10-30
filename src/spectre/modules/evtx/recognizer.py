"""
evtx/recognizer.py — claim Windows Event Log files.

Matches by extension (.evtx) and/or libmagic description, which for EVTX
reads like "MS Windows Vista-8.1 Event Log". A header sniff (the 'ElfFile'
magic at offset 0) confirms the claim and rejects look-alikes.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "process_creation"
_EVTX_MAGIC = b"ElfFile\x00"  # EVTX file signature at offset 0


def _sniff(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == _EVTX_MAGIC
    except OSError:
        return False


RECOGNIZERS = [
    Recognizer(
        module_name="evtx",
        artifact_type=ARTIFACT,
        extensions={".evtx"},
        magic_patterns=["Event Log"],
        sniff=_sniff,
        confidence=0.95,
    ),
]
