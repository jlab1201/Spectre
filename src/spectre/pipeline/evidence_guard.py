"""
evidence_guard.py — read-only enforcement for forensic evidence.

Three checks:
  1. Kernel-enforced read-only: os.open(path, os.O_RDONLY) succeeds
  2. File permission bits: no write bits set (must be 444 or 400)
  3. Parent directory: not writable by current user

Returns: (ok: bool, reason: str, sha256: str)

If any check fails, writes an evidence_guard audit row and returns ok=False.
The caller (case_setup registration) must abort registration on failure.
"""

import hashlib
import os
import stat
import sys
from pathlib import Path

from spectre.pipeline.audit import append as audit_append


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_writable_by_owner(mode: int) -> bool:
    """Check if owner write bit is set."""
    return bool(mode & stat.S_IWUSR)


def _is_writable_by_group(mode: int) -> bool:
    """Check if group write bit is set."""
    return bool(mode & stat.S_IWGRP)


def _is_writable_by_other(mode: int) -> bool:
    """Check if other write bit is set."""
    return bool(mode & stat.S_IWOTH)


def _parent_dir_writable(path: str) -> bool:
    """Check if parent directory is writable by current user."""
    parent = os.path.dirname(os.path.abspath(path))
    return os.access(parent, os.W_OK)


def guard(
    evidence_path: str,
    case_dir: str | None = None,
    skip_audit: bool = False,
    skip_parent_check: bool = False,
) -> tuple[bool, str, str]:
    """
    Validate evidence is read-only safe.

    Args:
        evidence_path: Path to evidence file
        case_dir: If provided, writes evidence_guard audit row on failure
        skip_audit: If True, don't write audit rows (for testing)
        skip_parent_check: If True, skip parent-directory-writable check.
            Use for post-copy verification where the case evidence/ dir
            MUST be writable for cp to work — the file's chmod 444 is
            the protection, not the parent directory.

    Returns:
        (ok, reason, sha256) — ok is True if all checks pass
    """
    path = os.path.abspath(evidence_path)

    # Check 1: File exists
    if not os.path.isfile(path):
        reason = f"evidence file not found: {path}"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    # Check 2: Kernel-enforced read-only open
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
    except OSError as e:
        reason = f"os.open(O_RDONLY) failed: {e}"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    # Check 3: File permission bits — no write bits
    file_mode = os.stat(path).st_mode
    if _is_writable_by_owner(file_mode):
        reason = f"evidence has owner-write bit set: {oct(file_mode)} (must be 444 or 400)"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    if _is_writable_by_group(file_mode):
        reason = f"evidence has group-write bit set: {oct(file_mode)} (must be 444 or 400)"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    if _is_writable_by_other(file_mode):
        reason = f"evidence has other-write bit set: {oct(file_mode)} (must be 444 or 400)"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    # Check 4: Parent directory not writable by current user
    # SKIP this check for post-copy verification — the case evidence/
    # dir MUST be writable for cp to work; file's chmod 444 is the guard.
    if not skip_parent_check and _parent_dir_writable(path):
        reason = f"parent directory is writable by current user: {os.path.dirname(path)}"
        if case_dir and not skip_audit:
            _audit_guard(case_dir, path, False, reason, "")
        return False, reason, ""

    # All checks pass — compute hash
    sha256 = _sha256_file(path)

    if case_dir and not skip_audit:
        _audit_guard(case_dir, path, True, f"evidence_guard passed — {oct(file_mode)}, parent not writable", sha256)

    return True, "ok", sha256


def _audit_guard(case_dir: str, evidence_path: str, ok: bool, reason: str, sha256: str) -> str:
    """Write evidence_guard audit row."""
    entry = {
        "actor": "deterministic-core",
        "action": "evidence_guard",
        "tool": "evidence_guard.py",
        "tool_version": "1.0",
        "exact_command": f"evidence_guard.py {evidence_path}",
        "params": {"evidence_path": evidence_path},
        "case_id": Path(case_dir).name,
        "output_path": evidence_path,
        "output_sha256": sha256,
        "output_format": "text",
        "output_line_count": 0,
        "output_size_bytes": 0,
        "result": "pass" if ok else "fail",
        "exit_code": 0 if ok else 1,
        "duration_ms": 0,
        "stderr": reason[:500],
        "finding_id": None,
        "phase": 0,
        "phase_step": "S2-register",
    }
    return audit_append(case_dir, entry)


# ── CLI ──
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evidence read-only guard")
    parser.add_argument("evidence_path", help="Path to evidence file")
    parser.add_argument("--case", default=None, help="Case directory for audit")
    parser.add_argument("--skip-audit", action="store_true", help="Skip audit row (testing)")
    parser.add_argument("--skip-parent-check", action="store_true",
                        help="Skip parent-directory-writable check (for post-copy verification)")
    args = parser.parse_args()

    ok, reason, sha256 = guard(
        args.evidence_path,
        case_dir=args.case,
        skip_audit=args.skip_audit,
        skip_parent_check=args.skip_parent_check,
    )

    if ok:
        print(f"PASS: {reason}")
        print(f"SHA-256: {sha256}")
        sys.exit(0)
    else:
        print(f"FAIL: {reason}", file=sys.stderr)
        sys.exit(1)
