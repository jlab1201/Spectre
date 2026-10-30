"""disk/availability.py — Sleuth Kit capability probe, including EWF.

Moved here from recognize.py, where it lived as a second
`if analyzer.name == "disk"` special case. Unlike pcap's, this one is genuinely
PER-FILE: `fls` and `mmls` being present says nothing about whether this build
of Sleuth Kit was linked against libewf, and that only matters for an E01. A
raw .dd works either way.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from spectre.core.base import ModuleAvailability

_TOOLS = ("fls", "mmls")
_EWF_SUPPORT: bool | None = None  # cached probe result


def probe_ewf_support() -> bool:
    """True when the local Sleuth Kit build supports EWF (libewf linked).
    `fls -i list` prints supported image formats to stderr."""
    fls = shutil.which("fls")
    if not fls:
        return False
    try:
        out = subprocess.run([fls, "-i", "list"], capture_output=True,
                             text=True, timeout=10)
        return "ewf" in (out.stdout + out.stderr).lower()
    except Exception:
        return False


def ewf_supported() -> bool:
    global _EWF_SUPPORT
    if _EWF_SUPPORT is None:
        _EWF_SUPPORT = probe_ewf_support()
    return _EWF_SUPPORT


def is_ewf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"EVF\x09"
    except OSError:
        return False


def availability(path: Path | None = None) -> ModuleAvailability:
    """Module-level: fls and mmls must both resolve. Per-file: an EWF image
    additionally needs a libewf-linked build, and saying "fls is installed so
    this E01 is fine" would be a false RECOGNIZED."""
    for tool in _TOOLS:
        if shutil.which(tool) is None:
            return ModuleAvailability(
                available=False, missing=tool,
                detail=f"Sleuth Kit incomplete — {tool} not on PATH")

    if path is not None and is_ewf(Path(path)) and not ewf_supported():
        return ModuleAvailability(
            available=False, missing="libewf",
            detail="this Sleuth Kit build has no EWF support — an E01/EWF "
                   "image cannot be opened (raw .dd/.raw images are fine)")

    if not ewf_supported():
        return ModuleAvailability(
            available=True, degraded=True,
            detail="Sleuth Kit has no EWF support — raw images only, "
                   "E01/EWF evidence cannot be opened")
    return ModuleAvailability(available=True)
