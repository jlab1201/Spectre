"""
denylist.py — command denylist enforcement.

Checks any command about to run against the allowlist/denylist.
This is the ONLY hard-block in the pipeline (not procedural/skills-based).

DENYLIST:
  - rm — file deletion
  - mkfs — filesystem creation
  - shred — secure deletion
  - wipe — secure deletion
  - fdisk (write mode) — partition manipulation
  - dd (only when of= targets evidence dirs — forensic acquisition is allowed)
  - mv/cp/chmod/redirection targeting evidence dirs

Wire into tool_runner.py: before subprocess.run(), check command[0].
If blocked: write audit row "tool_blocked" and refuse execution.
"""

import os
import re
import sys
from pathlib import Path

from spectre.config import CASES_DIR

# Build case-directory patterns from config
_CASE_PATH_STR = str(CASES_DIR)
_ALLOWED_CASE_PREFIXES = [
    _CASE_PATH_STR + "/",
    os.path.expanduser("~/spectre-cases/"),
    "/cases/",
]

# Regex to detect redirection into evidence paths
_REDIRECT_ESCAPED = re.escape(_CASE_PATH_STR)
REDIRECT_EVIDENCE_RE = re.compile(
    r'>[>]?\s*(' + _REDIRECT_ESCAPED + r'/|~/spectre-cases/|/cases/)'
)
FORBIDDEN_COMMANDS: set[str] = {
    "rm",
    "shred",
    "wipe",
    "mkfs",
    "mkfs.ext4",
    "mkfs.ntfs",
    "mkfs.fat",
    "mkfs.vfat",
}

# Commands forbidden only with certain flags (write mode)
CONDITIONAL_DENY: dict[str, list[str]] = {
    # dd with of= is allowed UNLESS targeting evidence dirs (forensic acquisition is OK)
    # fdisk is always destructive in our context
    "fdisk": [],
}

# Commands that are allowed but forbidden when targeting evidence directories
EVIDENCE_DIR_COMMANDS: set[str] = {
    "mv",
    "cp",
    "chmod",
    "chown",
    "touch",
    "dd",         # dd of= is allowed for acquisition, blocked when targeting evidence dirs
}


def _has_write_flag(command: list[str], bad_flags: list[str]) -> bool:
    """Check if command contains any forbidden flags."""
    cmd_str = " ".join(command)
    for flag in bad_flags:
        if flag in cmd_str:
            return True
    return False


def _case_dir_prefix(case_dir: str | None) -> str | None:
    """The active cases_dir prefix derived from an EFFECTIVE case_dir.

    Case dirs always live at {cases_dir}/{case_name} (case_setup.py,
    cross_case_index.py), so the parent of a given case_dir IS the active
    cases_dir. W1-3 fixed the same defect class for the case counter and
    the cross-case index (both now derive their path from the real, active
    directory instead of the import-time config.CASES_DIR global) — this
    was the one remaining leak: under a custom --cases-dir, evidence for
    THAT case lived outside `_ALLOWED_CASE_PREFIXES` (built once, at import
    time, from the global) and so was not hard-blocked at all. Returns
    None when case_dir is falsy — callers then fall back to the global-only
    patterns, same as before this fix.
    """
    if not case_dir:
        return None
    return str(Path(os.path.expanduser(str(case_dir))).parent) + "/"


def _evidence_patterns(case_dir: str | None) -> list[str]:
    """Global default prefixes plus, when an effective case_dir is given,
    that case's own active cases_dir — so a custom --cases-dir is covered
    on top of (never instead of) the global default store."""
    patterns = list(_ALLOWED_CASE_PREFIXES)
    case_prefix = _case_dir_prefix(case_dir)
    if case_prefix and case_prefix not in patterns:
        patterns.append(case_prefix)
    return patterns


def _redirect_hits_evidence(cmd_str: str, case_dir: str | None) -> bool:
    """Shell-redirection check (>/>> targets), extended to the effective
    case_dir's active cases_dir the same way _evidence_patterns() is."""
    if REDIRECT_EVIDENCE_RE.search(cmd_str):
        return True
    case_prefix = _case_dir_prefix(case_dir)
    if case_prefix and re.search(r'>[>]?\s*' + re.escape(case_prefix), cmd_str):
        return True
    return False


def _targets_evidence_dir(command: list[str], case_dir: str | None = None) -> bool:
    """Check if command WRITES to an evidence directory.

    Only inspects write-side arguments:
      - dd: only the of= argument (output file)
      - cp: only the last argument (destination); source from evidence is allowed
             (non-destructive read). NOTE: cp -t/--target-directory flags are
             NOT parsed — this is a known best-effort limitation; tool_runner
             typed parameters are the real enforcement.
      - mv: ANY argument — mv is destructive to the source (rename+delete).
             Moving evidence out silently destroys the registered original.
      - chmod/chown/touch: all arguments are write-side
      - redirection: >/>> targets

    `case_dir`, when given, is the EFFECTIVE case directory for this run
    (a caller's explicit --cases-dir, or the config default) — its parent
    (the active cases_dir) is added to the evidence patterns on top of the
    global defaults, see `_evidence_patterns()`.
    """
    evidence_patterns = _evidence_patterns(case_dir)

    def _matches_evidence(s: str) -> bool:
        for pat in evidence_patterns:
            if pat in s:
                return True
        return False

    cmd_name = os.path.basename(command[0])

    if cmd_name in ("dd",):
        # Only check of= (output file) — if= is read-side, always allowed
        for arg in command[1:]:
            if arg.startswith("of=") and _matches_evidence(arg):
                return True
        return False

    if cmd_name in ("cp",):
        # cp is non-destructive to source — only block writes to evidence
        # Last argument is the destination (unless -t/--target-directory,
        # which is a known limitation; covered by tool_runner typed params)
        if len(command) >= 3:
            dest = command[-1]
            if _matches_evidence(dest):
                return True
        return False

    if cmd_name in ("mv",):
        # mv IS destructive to source — a rename+delete. Block if ANY
        # argument touches an evidence dir. Moving evidence out silently
        # removes the registered original — chain-of-custody violation.
        cmd_str = " ".join(command)
        for pat in evidence_patterns:
            if pat in cmd_str:
                return True
        # Also check redirection
        if _redirect_hits_evidence(cmd_str, case_dir):
            return True
        return False

    # For chmod, chown, touch — all path args are write-side
    cmd_str = " ".join(command)
    for pat in evidence_patterns:
        if pat in cmd_str:
            return True

    # Also check for shell redirection (only applies if command runs in shell)
    if _redirect_hits_evidence(cmd_str, case_dir):
        return True

    return False


def check(
    command: list[str],
    case_dir: str | None = None,
) -> tuple[bool, str]:
    """
    Check if a command is allowed.

    Args:
        command: Command as list of strings (e.g., ["rm", "-rf", "/tmp/x"])
        case_dir: Case directory for context (optional)

    Returns:
        (allowed: bool, reason: str)
    """
    if not command:
        return True, "empty command"

    cmd_name = os.path.basename(command[0])

    # Check 1: Base denylist
    if cmd_name in FORBIDDEN_COMMANDS:
        return False, f"command '{cmd_name}' is on the permanent denylist"

    # Check 2: Conditional denylist
    if cmd_name in CONDITIONAL_DENY:
        bad_flags = CONDITIONAL_DENY[cmd_name]
        if not bad_flags or _has_write_flag(command, bad_flags):
            return False, f"command '{cmd_name}' is denied (write-mode)"

    # Check 3: Evidence-directory-targeting commands
    if cmd_name in EVIDENCE_DIR_COMMANDS and _targets_evidence_dir(command, case_dir):
        return False, f"command '{cmd_name}' targeting evidence directory is denied"

    return True, "ok"


def block_and_audit(
    command: list[str],
    case_dir: str,
    reason: str,
) -> None:
    """
    Write a chained `tool_blocked` audit row for a refused command.
    Uses audit.py's append for proper chaining. Does NOT raise or exit —
    the caller (tool_runner.run_tool) is the one that refuses execution,
    by raising PermissionError after this returns.
    """
    from spectre.pipeline.audit import append as audit_append

    entry = {
        "actor": "deterministic-core",
        "action": "tool_blocked",
        "tool": "denylist.py",
        "tool_version": "1.0",
        "exact_command": " ".join(command),
        "params": {"command": command, "reason": reason},
        "case_id": Path(case_dir).name,
        "output_path": "",
        "output_sha256": "",
        "output_format": "text",
        "output_line_count": 0,
        "output_size_bytes": 0,
        "result": "blocked",
        "exit_code": -1,
        "duration_ms": 0,
        "stderr": reason[:500],
        "finding_id": None,
    }
    audit_append(case_dir, entry)


# ── CLI ──
if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Command denylist check")
    parser.add_argument("--case", default=None, help="Case directory (for audit)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to check (e.g., 'rm --help')")
    args = parser.parse_args()

    # REMAINDER includes empty list if no args; strip leading empty strings
    cmd = [a for a in args.command if a]
    if not cmd:
        parser.error("no command provided")

    allowed, reason = check(cmd, case_dir=args.case)

    result = {
        "allowed": allowed,
        "reason": reason,
        "command": cmd,
    }

    if args.json:
        print(json.dumps(result))
    else:
        if allowed:
            print(f"ALLOWED: {reason}")
        else:
            print(f"BLOCKED: {reason}", file=sys.stderr)

    sys.exit(0 if allowed else 1)
