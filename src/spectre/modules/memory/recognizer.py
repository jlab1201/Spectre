"""memory/recognizer.py — claim memory images.

Memory dumps have no reliable libmagic signature (often just "data"), so
recognition is extension-led with a sniff that rejects disk images (which
also use .raw). A disk image carries an MBR boot signature (0x55AA at
offset 510); a raw memory dump does not. Positive memory-format signatures
(LiME, hibernation, VMware) are checked first and override the MBR heuristic.
"""

from __future__ import annotations

import math
from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "memory_image"
_MEM_EXTS = {".mem", ".vmem", ".lime", ".dmp", ".raw", ".bin", ".vmss", ".vmsn"}

# Positive memory-format signatures (checked before the MBR elimination
# heuristic — a signature match claims the file even if byte 510 happens
# to be 55AA in a multi-GB dump).
_MEM_MAGICS = (b"EMiL",              # LiME (little-endian 0x4C694D45)
               b"hibr", b"HIBR", b"WAKE",   # Windows hibernation
               b"\xd2\xbe\xd2\xbe")  # VMware saved state


def _has_memory_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) in _MEM_MAGICS
    except OSError:
        return False


def _has_mbr(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            f.seek(510)
            return f.read(2) == b"\x55\xaa"
    except OSError:
        return False


# Windows full/kernel crash dump headers (DUMP_HEADER32/64 signatures).
_CRASHDUMP_MAGICS = (b"PAGEDUMP", b"PAGEDU64")
_PAGE = 4096
_SAMPLES = 32
# Shannon entropy (bits/byte) below which a sampled page is "structured".
# A page of uniformly random bytes scores ~7.95; real RAM always holds
# zero-filled, sparse or code/text pages well below this.
_STRUCTURED_ENTROPY = 7.0


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _has_structure(path: Path) -> bool:
    """Structural signal before an extension-led claim (W4-1, R1-F2).

    A crash-dump header, or at least one sampled page that is not
    random-looking. 200 KB of /dev/urandom has neither; any real memory
    image (zero pages, page tables, code) has the second."""
    try:
        size = path.stat().st_size
        if size == 0:
            return False  # an empty file has no structure (entropy 0 ≠ RAM)
        with open(path, "rb") as f:
            if f.read(8) in _CRASHDUMP_MAGICS:
                return True
            pages = max(1, size // _PAGE)
            step = max(1, pages // _SAMPLES)
            for i in range(0, pages, step):
                f.seek(i * _PAGE)
                if _entropy(f.read(_PAGE)) < _STRUCTURED_ENTROPY:
                    return True
    except OSError:
        return False
    return False


def _looks_like_memory(path: Path) -> bool:
    if _has_memory_magic(path):
        return True
    # W4-1 (R1-F2): an extension alone is not enough — unstructured bytes
    # (random, encrypted, corrupt) are not a memory image, and claiming
    # them sent every vol run into an error that read as "clean".
    if not _has_structure(path):
        return False
    # Unambiguous memory extensions pass once structured.
    if path.suffix.lower() in {".mem", ".vmem", ".lime", ".vmss", ".vmsn"}:
        return True
    # Shared extensions (.raw/.bin/.dmp): accept only if NOT a disk image.
    return not _has_mbr(path)


RECOGNIZERS = [
    # Positive memory-format signature (LiME/hibernation/VMware saved
    # state): certain claim — must outrank the disk module's MBR-based
    # 0.85 when a dump coincidentally carries 55AA at offset 510.
    Recognizer(
        module_name="memory",
        artifact_type=ARTIFACT,
        extensions=_MEM_EXTS,
        magic_patterns=[],
        sniff=_has_memory_magic,
        confidence=0.95,
    ),
    Recognizer(
        module_name="memory",
        artifact_type=ARTIFACT,
        extensions=_MEM_EXTS,
        magic_patterns=[],
        sniff=_looks_like_memory,
        confidence=0.7,
    ),
]
