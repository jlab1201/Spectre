"""registry_hive/recognizer.py — claim Windows registry hive files (regf).

Hive files carved off a live system or a disk image are frequently
extensionless (SYSTEM, SAM, SOFTWARE, SECURITY, NTUSER.DAT), so extension
matching alone is not enough. The `regf` magic signature (first 4 bytes of
every Windows registry hive) plus libmagic's "registry file" description
together claim both named-extension hives (*.dat/*.hiv/*.hive) and bare
extensionless hives.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "registry_run"

_MAGIC_HEADER = b"regf"


def _sniff(path: Path) -> bool:
    """True if the file starts with the regf hive signature."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == _MAGIC_HEADER
    except OSError:
        return False


RECOGNIZERS = [
    Recognizer(
        module_name="registry_hive",
        artifact_type=ARTIFACT,
        extensions={".dat", ".hiv", ".hive"},
        # libmagic reports e.g. "MS Windows registry file, NT/2000 or above"
        magic_patterns=["registry file"],
        sniff=_sniff,
        confidence=0.9,
    ),
]
