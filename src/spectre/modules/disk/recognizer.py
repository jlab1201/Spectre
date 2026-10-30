"""disk/recognizer.py — claim disk images (raw/dd/E01).

Recognized by a partition/boot signature (MBR 0x55AA at offset 510) or an
EWF/Expert Witness header ("EVF\\x09" for .E01), plus disk extensions.
"""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "disk_image"
_DISK_EXTS = {".dd", ".img", ".raw", ".001", ".e01", ".aff", ".vmdk"}
_EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"


def _sniff(path: Path) -> bool:
    """Positive disk-image signatures. Extensions alone never suffice —
    a .dd of random text must not be claimed (it may be a mislabeled
    memory dump or plain data)."""
    try:
        with open(path, "rb") as f:
            head = f.read(24)
            if head.startswith(b"EVF\x09"):          # EWF / E01
                return True
            if head.startswith((b"KDMV", b"COWD")):  # VMDK sparse/COW extent
                return True
            if head.startswith(b"# Disk DescriptorFile"):  # VMDK descriptor
                return True
            if head.startswith(b"AFF"):              # Advanced Forensics Format
                return True
            f.seek(510)
            if f.read(2) == b"\x55\xaa":             # MBR boot signature
                return True
            f.seek(512)
            return f.read(8) == b"EFI PART"          # GPT header (LBA 1)
    except OSError:
        return False


RECOGNIZERS = [
    Recognizer(
        module_name="disk",
        artifact_type=ARTIFACT,
        extensions=_DISK_EXTS,
        magic_patterns=["DOS/MBR boot sector", "boot sector",
                        "Expert Witness", "EWF", "filesystem data"],
        sniff=_sniff,
        confidence=0.85,
    ),
]
