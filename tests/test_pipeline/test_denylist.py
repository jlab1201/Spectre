"""Tests for pipeline/denylist.py -- "the ONLY hard-block in the pipeline".

Covers three things that had zero test coverage before this file (R6 F2 /
W1-5):

1. `check()` -- the core allow/block predicate (permanent denylist,
   conditional denylist, evidence-directory-targeting commands).
2. `block_and_audit()` -- the audit-row write on the BLOCK path. This was
   broken by an import that could never resolve (`from audit import
   append`, no top-level `audit` module exists outside the `spectre`
   package) -- every blocked command crashed with `ModuleNotFoundError`
   *before* its `tool_blocked` audit row was written, so a hard-blocked
   command left no chain-of-custody trail of having been blocked. Fixed to
   `from spectre.pipeline.audit import append`.
3. The `__main__` CLI path, exercised via subprocess (real process, so a
   `NameError`/`ModuleNotFoundError` on `sys`/`audit` actually surfaces as
   a nonzero exit + traceback, not just an import-time skip). `sys` was
   referenced (`sys.stderr`, `sys.exit`) but never imported -- ruff F821,
   confirmed to crash `BLOCKED` output on real CLI invocation.
"""
from __future__ import annotations

import json
import subprocess
import sys

from spectre.pipeline import denylist


# ── check(): permanent denylist ──

def test_rm_is_blocked():
    allowed, reason = denylist.check(["rm", "-rf", "/tmp/x"])
    assert allowed is False
    assert "rm" in reason


def test_shred_is_blocked():
    allowed, _ = denylist.check(["shred", "/tmp/x"])
    assert allowed is False


def test_mkfs_variant_is_blocked():
    allowed, _ = denylist.check(["mkfs.ext4", "/dev/sdb1"])
    assert allowed is False


def test_ordinary_read_command_is_allowed():
    allowed, reason = denylist.check(["ls", "-la", "/tmp"])
    assert allowed is True
    assert reason == "ok"


def test_empty_command_is_allowed():
    allowed, reason = denylist.check([])
    assert allowed is True


# ── check(): conditional denylist (fdisk) ──

def test_fdisk_is_always_denied():
    # CONDITIONAL_DENY["fdisk"] == [] -- "no bad_flags" means always denied
    # (write-mode is the ONLY mode this tool models fdisk having).
    allowed, reason = denylist.check(["fdisk", "/dev/sda"])
    assert allowed is False
    assert "fdisk" in reason


# ── check(): evidence-directory-targeting commands ──

def test_dd_writing_into_cases_dir_is_blocked():
    allowed, reason = denylist.check(["dd", "if=/dev/sda", "of=/cases/001/evidence/img.raw"])
    assert allowed is False
    assert "dd" in reason


def test_dd_reading_from_cases_dir_is_allowed():
    # if= is read-side; acquisition (image evidence INTO the case dir from
    # elsewhere) must stay allowed.
    allowed, _ = denylist.check(["dd", "if=/cases/001/evidence/img.raw", "of=/tmp/scratch.raw"])
    assert allowed is True


def test_mv_touching_cases_dir_is_blocked():
    # mv is destructive to its source -- ANY argument touching a case dir blocks.
    allowed, reason = denylist.check(["mv", "/cases/001/evidence/img.raw", "/tmp/moved.raw"])
    assert allowed is False
    assert "mv" in reason


def test_cp_from_cases_dir_is_allowed_nondestructive_read():
    # cp only inspects the destination (last arg); reading FROM a case dir
    # is non-destructive and must stay allowed.
    allowed, _ = denylist.check(["cp", "/cases/001/evidence/img.raw", "/tmp/copy.raw"])
    assert allowed is True


def test_cp_into_cases_dir_is_blocked():
    allowed, reason = denylist.check(["cp", "/tmp/x.txt", "/cases/001/notes.txt"])
    assert allowed is False
    assert "cp" in reason


def test_chmod_on_cases_dir_is_blocked():
    allowed, reason = denylist.check(["chmod", "777", "/cases/001/evidence/img.raw"])
    assert allowed is False
    assert "chmod" in reason


def test_unrelated_chmod_is_allowed():
    allowed, _ = denylist.check(["chmod", "755", "/tmp/scratch/script.sh"])
    assert allowed is True


# ── block_and_audit(): the audit-row write on the BLOCK path (R6 F2 / coordinator) ──

def test_block_and_audit_writes_tool_blocked_row_and_does_not_raise(tmp_path):
    case_dir = tmp_path / "case001"
    case_dir.mkdir()

    # Must not raise -- this is exactly the crash the broken `from audit
    # import append` produced: a blocked command took down the caller
    # (tool_runner.run_tool) with ModuleNotFoundError before the audit row
    # landed, so the block itself left no chain-of-custody trail.
    denylist.block_and_audit(["rm", "-rf", "/cases/001"], str(case_dir), "on permanent denylist")

    audit_path = case_dir / "audit.jsonl"
    assert audit_path.exists()
    rows = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    assert len(rows) == 1
    row = rows[0]
    assert row["action"] == "tool_blocked"
    assert row["result"] == "blocked"
    assert row["exit_code"] == -1
    assert "rm" in row["exact_command"]
    assert row["case_id"] == "case001"
    # entry_sha256 is written by audit.append() -- confirms the real
    # chaining code path ran, not a stub.
    assert "entry_sha256" in row


def test_block_and_audit_chains_a_second_blocked_command(tmp_path):
    case_dir = tmp_path / "case002"
    case_dir.mkdir()

    denylist.block_and_audit(["rm", "-rf", "/x"], str(case_dir), "denied")
    denylist.block_and_audit(["shred", "/y"], str(case_dir), "denied")

    rows = [json.loads(line) for line in (case_dir / "audit.jsonl").read_text().splitlines() if line.strip()]
    assert len(rows) == 2
    assert rows[0]["seq"] == 1
    assert rows[1]["seq"] == 2
    assert rows[1]["prev_sha256"] == rows[0]["entry_sha256"]


# ── __main__ CLI path (subprocess -- a real process surfaces the `sys` F821) ──

def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "spectre.pipeline.denylist", "--json", *args],
        capture_output=True, text=True, timeout=30,
    )


def test_cli_allowed_command_exits_zero():
    result = _run_cli(["ls", "-la"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["allowed"] is True


def test_cli_blocked_command_exits_one_and_does_not_crash():
    result = _run_cli(["rm", "-rf", "/tmp/x"])
    # Before the `import sys` fix, the non-JSON branch's `file=sys.stderr`
    # raised NameError; the JSON branch (used here) never reached that
    # line, so this specific invocation always worked -- the crash was
    # exercised by the human-readable branch below. Both are covered.
    assert result.returncode == 1, result.stderr
    payload = json.loads(result.stdout)
    assert payload["allowed"] is False
    assert "rm" in payload["reason"]


def test_cli_blocked_command_human_readable_branch_does_not_crash():
    # This is the exact code path that raised NameError: 'sys' is not
    # defined before `import sys` was added -- `print(..., file=sys.stderr)`
    # in the non-JSON branch of a blocked command.
    result = _run_cli_no_json(["rm", "-rf", "/tmp/x"])
    assert result.returncode == 1
    assert "NameError" not in result.stderr
    assert "BLOCKED" in result.stderr


def _run_cli_no_json(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "spectre.pipeline.denylist", *args],
        capture_output=True, text=True, timeout=30,
    )


def test_cli_no_command_errors_cleanly():
    result = subprocess.run(
        [sys.executable, "-m", "spectre.pipeline.denylist"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0


# ── W1 required fix 1: case_dir-aware protection under a custom
# --cases-dir. Before this fix, `_ALLOWED_CASE_PREFIXES` was built ONCE, at
# import time, from the global `config.CASES_DIR` (plus the hardcoded
# ~/spectre-cases/ and /cases/ defaults) and `check()` never looked at the
# `case_dir` argument at all -- so evidence living under a caller's
# explicit --cases-dir was NOT covered by "the ONLY hard-block in the
# pipeline". These tests use a tmp cases_dir that is NOT one of the
# hardcoded defaults, so a regression (case_dir ignored) is caught by the
# command coming back ALLOWED. ──

def test_dd_writing_into_custom_cases_dir_is_blocked(tmp_path):
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"
    evidence = case_dir / "evidence" / "img.raw"

    allowed, reason = denylist.check(
        ["dd", "if=/dev/sda", f"of={evidence}"], case_dir=str(case_dir)
    )
    assert allowed is False
    assert "dd" in reason


def test_mv_touching_custom_cases_dir_is_blocked(tmp_path):
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"
    evidence = case_dir / "evidence" / "img.raw"

    allowed, reason = denylist.check(
        ["mv", str(evidence), str(tmp_path / "moved.raw")], case_dir=str(case_dir)
    )
    assert allowed is False
    assert "mv" in reason


def test_cp_into_custom_cases_dir_is_blocked(tmp_path):
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"

    allowed, reason = denylist.check(
        ["cp", "/tmp/x.txt", str(case_dir / "notes.txt")], case_dir=str(case_dir)
    )
    assert allowed is False
    assert "cp" in reason


def test_chmod_on_custom_cases_dir_is_blocked(tmp_path):
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"
    evidence = case_dir / "evidence" / "img.raw"

    allowed, reason = denylist.check(
        ["chmod", "777", str(evidence)], case_dir=str(case_dir)
    )
    assert allowed is False
    assert "chmod" in reason


def test_redirection_into_custom_cases_dir_is_blocked(tmp_path):
    # The redirect regex only runs inside _targets_evidence_dir(), which
    # check() only calls for EVIDENCE_DIR_COMMANDS command names -- a
    # shell (bash/sh) invocation isn't one of those (pre-existing gap,
    # unrelated to this fix; tool_runner's typed params are the real
    # enforcement there). Exercise the redirect-regex extension itself via
    # one of the covered command names, argv-shaped with a redirect token,
    # same idiom the pre-existing global-store redirect check uses.
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"
    evidence = case_dir / "evidence" / "img.raw"

    allowed, reason = denylist.check(
        ["touch", ">>", str(evidence)], case_dir=str(case_dir)
    )
    assert allowed is False


def test_custom_cases_dir_evidence_allowed_without_matching_case_dir_arg(tmp_path):
    # Sanity check on the OLD behavior this fix must not remove: with no
    # case_dir passed at all, a path under an arbitrary custom cases_dir
    # (not one of the hardcoded defaults) is NOT covered -- this is the
    # known best-effort limitation the module docstring already documents
    # (tool_runner's typed params are the real enforcement there). This
    # pins that the fix only ADDS coverage when case_dir is supplied, and
    # doesn't change no-case_dir behavior.
    cases_dir = tmp_path / "not-the-default-store"
    evidence = cases_dir / "001-custom-case" / "evidence" / "img.raw"
    allowed, _ = denylist.check(["chmod", "777", str(evidence)], case_dir=None)
    assert allowed is True


def test_other_cases_are_not_affected_by_one_case_dirs_prefix(tmp_path):
    # The case_dir-derived prefix must be the ACTIVE cases_dir (the given
    # case_dir's parent), not the case_dir itself -- so a sibling case
    # under the same cases_dir is also protected (it shares the parent),
    # confirming the prefix is the cases_dir and not narrower.
    cases_dir = tmp_path / "not-the-default-store"
    case_dir = cases_dir / "001-custom-case"
    sibling_evidence = cases_dir / "002-other-case" / "evidence" / "img.raw"

    allowed, _ = denylist.check(
        ["chmod", "777", str(sibling_evidence)], case_dir=str(case_dir)
    )
    assert allowed is False


def test_custom_cases_dir_with_tilde_is_expanded(tmp_path, monkeypatch):
    # case_dir may be constructed from a literal "~"-prefixed string (as
    # case_setup.py did before its own expanduser fix) -- the case_dir
    # prefix must expanduser() it too, or the derived prefix would never
    # match a resolved evidence path.
    monkeypatch.setenv("HOME", str(tmp_path))
    case_dir = "~/not-the-default-store/001-custom-case"
    evidence = tmp_path / "not-the-default-store" / "001-custom-case" / "evidence" / "img.raw"

    allowed, _ = denylist.check(["chmod", "777", str(evidence)], case_dir=case_dir)
    assert allowed is False
