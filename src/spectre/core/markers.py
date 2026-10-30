r"""core/markers.py — shared, pure path/name suspicion markers for rule packs.

Every marker here is a CONCRETE indicator (a temp or public-profile path, a
script host / LOLBin as a launcher, an encoded command, a known offensive tool
name, a Windows system-process name outside its home directory). None of them
fires on the plain presence of a file, service or registry row. The underlying
lists live in `knowledge/indicators/*.yaml`, so they are tuned in one place;
this module only composes them, so a rule pack can use them without importing
another module's private rules.

Callers pass LOWERCASED Windows paths / command lines.
"""

from __future__ import annotations

import re

from spectre.knowledge import load_indicator_list

# Temp-directory markers (same list the evtx rules use for process images).
TEMP_MARKERS: tuple[str, ...] = tuple(load_indicator_list("paths", "evtx_temp_markers"))

# The all-users public profile — world-writable, no legitimate installer
# stages executables there.
PUBLIC_PROFILE_MARKER = "\\users\\public\\"

STAGING_MARKERS: tuple[str, ...] = TEMP_MARKERS + (PUBLIC_PROFILE_MARKER,)

LOLBINS = frozenset(load_indicator_list("processes", "lolbins"))
COMMAND_SHELLS = frozenset(load_indicator_list("processes", "command_shells"))
# Launchers that make a service/autostart ImagePath suspicious by themselves.
SCRIPT_HOSTS_AND_LOLBINS = frozenset(LOLBINS | COMMAND_SHELLS)

OFFENSIVE_TOOLS: tuple[str, ...] = tuple(
    load_indicator_list("processes", "offensive_tools"))

SYSTEM_PROCESS_NAMES = frozenset(
    load_indicator_list("processes", "system_process_names"))

ENCODED_COMMAND_RE = re.compile(
    r"(-enc\b|-encodedcommand|frombase64string|-e\s+[a-z0-9+/=]{16,})")

PSEXEC_SERVICE_MARKER = "psexesvc"

# Directories a Windows system process legitimately runs from.
_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\",
                "\\windows\\winsxs\\")
# explorer.exe lives directly under %WINDIR%.
_WINDIR_ONLY = {"explorer"}


def basename(path: str) -> str:
    """Windows-aware basename (pathlib on Linux does not split on '\\')."""
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


# Admin-only install roots: a `\temp\` folder beneath them (e.g. Edge
# Update's `Program Files (x86)\Microsoft\Temp`) is not user-writable
# staging, so it is not a staging marker.
_ADMIN_ROOTS = ("\\program files\\", "\\program files (x86)\\")


def staging_marker(path_lower: str) -> str | None:
    """The temp/public-profile marker in a FILE path (not a command line),
    else None."""
    if any(r in path_lower for r in _ADMIN_ROOTS):
        return None
    return next((m for m in STAGING_MARKERS if m in path_lower), None)


def offensive_tool(basename_lower: str) -> str | None:
    """The offensive-tool indicator matching this basename, else None.

    An entry ending in `.exe` must equal the basename exactly (so
    `nc.exe` never matches `sync.exe`); a bare family name (e.g.
    `meterpreter`) matches as a substring.
    """
    for tool in OFFENSIVE_TOOLS:
        if tool.endswith(".exe"):
            if basename_lower == tool:
                return tool
        elif tool in basename_lower:
            return tool
    return None


def masquerades_as_system_process(path_lower: str) -> str | None:
    """The system-process name a binary borrows while living outside its
    legitimate directory, else None. Only full paths are judged — a bare
    filename (Win10 ShimCache 64-bit entries can lack a directory) is not.
    """
    if "\\" not in path_lower:
        return None
    name = basename(path_lower)
    stem = name[:-4] if name.endswith(".exe") else None
    if stem is None or stem not in SYSTEM_PROCESS_NAMES:
        return None
    if any(d in path_lower for d in _SYSTEM_DIRS):
        return None
    if stem in _WINDIR_ONLY and path_lower.endswith("\\windows\\" + name):
        return None
    return name


def launcher_markers(cmd_lower: str) -> list[str]:
    """Reasons a service/autostart command line is suspicious, in a fixed
    order. Empty list = nothing concrete (not flagged)."""
    reasons: list[str] = []
    # Whole command line, no admin-root exemption: a Program Files launcher
    # can still point its arguments at a temp/public-profile payload.
    if any(m in cmd_lower for m in STAGING_MARKERS):
        reasons.append("binary staged in a temp or public-profile path")
    if any(b in cmd_lower for b in sorted(SCRIPT_HOSTS_AND_LOLBINS)):
        reasons.append("launched via a command/script interpreter or LOLBin")
    if "%comspec%" in cmd_lower:
        reasons.append("invokes %COMSPEC%")
    if ENCODED_COMMAND_RE.search(cmd_lower):
        reasons.append("encoded/base64 command")
    return reasons


# ── Installer extraction context (demotion, never suppression) ────────────
#
# Installers unpack their own bootstrap into a per-run temp folder whose
# SHAPE is characteristic. Each pattern is matched against the path
# directly after a temp marker, so it only ever judges a staging path:
#   WiX Burn engine     \temp\{GUID}\.be\   \temp\{GUID}\.cr\   \temp\{GUID}\.ba\
#   VC++ / VS bootstrap \temp\{GUID}~setup\
#   VMware Tools setup  \temp\vmware-<user>\<hex>\
#   Inno / InstallShield-style \temp\<name>.tmp\
_GUID = r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}"
_INSTALLER_DIR_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("WiX Burn engine extraction dir",
     re.compile(r"\\temp\\" + _GUID + r"\\\.(?:be|cr|ba)\\[^\\]+$")),
    ("VC++/Visual Studio bootstrap extraction dir",
     re.compile(r"\\temp\\" + _GUID + r"~setup\\[^\\]+$")),
    ("VMware installer extraction dir",
     re.compile(r"\\temp\\vmware-[^\\]+\\[0-9a-f]+\\[^\\]+$")),
    ("installer .tmp extraction dir",
     re.compile(r"\\temp\\[^\\]+\.tmp\\[^\\]+$")),
)

INSTALLER_FILENAMES: tuple[str, ...] = tuple(
    load_indicator_list("processes", "installer_filenames"))


def _is_installer_filename(basename_lower: str) -> bool:
    for name in INSTALLER_FILENAMES:
        if name.endswith(".exe"):
            if basename_lower == name:
                return True
        elif basename_lower.startswith(name) and basename_lower.endswith(".exe"):
            return True
    return False


def installer_extraction_context(path_lower: str) -> str | None:
    """A description of the installer extraction pattern this path matches,
    else None. BOTH halves are required — a known installer filename AND an
    installer's characteristic extraction directory — so neither naming
    malware "vcredist" nor dropping it into a `{GUID}\\.be\\` folder is
    enough on its own. Callers DEMOTE, never drop: the pattern is
    reproducible by an attacker who knows it."""
    name = basename(path_lower)
    if not _is_installer_filename(name):
        return None
    for label, pattern in _INSTALLER_DIR_PATTERNS:
        if pattern.search(path_lower):
            return f"{label} + installer filename '{name}'"
    return None


# ── Anti-forensic tool names ──────────────────────────────────────────────

ANTI_FORENSIC_WIPERS: tuple[str, ...] = tuple(
    load_indicator_list("processes", "anti_forensic_wipers"))
ANTI_FORENSIC_TIMESTOMPERS: tuple[str, ...] = tuple(
    load_indicator_list("processes", "anti_forensic_timestompers"))


def _name_match(basename_lower: str, names: tuple[str, ...]) -> str | None:
    for n in names:
        if n.endswith(".exe"):
            if basename_lower == n:
                return n
        elif n in basename_lower:
            return n
    return None


def anti_forensic_tool(basename_lower: str) -> tuple[str, str] | None:
    """(kind, indicator) for a known anti-forensic tool name, else None.
    kind is "timestomp" or "wiper". Name-only: a renamed tool escapes it,
    and a benign file can share a name."""
    hit = _name_match(basename_lower, ANTI_FORENSIC_TIMESTOMPERS)
    if hit:
        return ("timestomp", hit)
    hit = _name_match(basename_lower, ANTI_FORENSIC_WIPERS)
    if hit:
        return ("wiper", hit)
    return None
