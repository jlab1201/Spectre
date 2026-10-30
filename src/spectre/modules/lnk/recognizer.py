"""lnk/recognizer.py — claim Windows shortcut (.lnk) files.

MS-SHLLINK shortcuts open with a fixed 20-byte prefix: a u32 HeaderSize
that is always `0x0000004C`, followed immediately by the fixed LinkCLSID
`{00021401-0000-0000-C000-000000000046}` (little-endian byte order:
`01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46`). Both fields are
invariant across every LNK on disk, so a `.lnk` extension is claimed only
after that exact 20-byte prefix is confirmed by sniff — an extensionless
or mis-signed file is never guessed at.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "lnk"

_HEADER_SIZE = b"\x4c\x00\x00\x00"
_LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _sniff(path: Path) -> bool:
    """True if the file starts with HeaderSize==0x4C followed by LinkCLSID."""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return False
    return head[:4] == _HEADER_SIZE and head[4:20] == _LINK_CLSID


RECOGNIZERS = [
    Recognizer(
        module_name="lnk",
        artifact_type=ARTIFACT,
        extensions={".lnk"},
        magic_patterns=["shortcut", "ms windows shortcut"],
        sniff=_sniff,
        confidence=0.9,
    ),
]
