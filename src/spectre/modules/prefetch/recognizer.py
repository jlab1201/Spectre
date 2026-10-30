"""prefetch/recognizer.py — claim Windows Prefetch (.pf) files.

Two on-disk shapes exist: the uncompressed layout used through Windows 8.1
(and optionally Win10), signed by the `SCCA` magic at offset 4, and the
Windows 10 default xpress-compressed layout, signed by `MAM\\x04` at offset
0. `.pf` extension alone is claimed only after one of the two signatures is
confirmed by sniff — an extensionless or mis-extensioned file is never
guessed at.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "prefetch"

_SCCA_MAGIC = b"SCCA"
_MAM_MAGIC = b"MAM\x04"


def _sniff(path: Path) -> bool:
    """True if the file starts with the SCCA (uncompressed) or MAM\\x04
    (Win10 compressed) prefetch signature."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return False
    return head[4:8] == _SCCA_MAGIC or head[:4] == _MAM_MAGIC


RECOGNIZERS = [
    Recognizer(
        module_name="prefetch",
        artifact_type=ARTIFACT,
        extensions={".pf"},
        magic_patterns=["prefetch"],
        sniff=_sniff,
        confidence=0.9,
    ),
]
