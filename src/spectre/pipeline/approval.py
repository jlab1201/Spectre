"""approval.py — the in-process Phase 7 examiner approval writer (W3-6, R1-F3).

Before this existed the only documented approval path (skills/methodology
Phase 7: append an ``approval`` row, then hand-edit the finding YAML) broke
``verify_full``'s finding_integrity check — the edited bytes matched no hash
authority. This writer keeps the custody record and the file in lock-step:

1. refuse unless the finding is registered and its bytes still equal its
   latest hash-authority row (never bless an already-tampered finding);
2. stage the new YAML bytes, fsync'd, in ``findings/.F-….yaml.approval-pending``;
3. append ONE chained ``approval`` row (actor ``examiner``, phase_step
   ``S7-approve``) carrying the decision AND the staged content hash — the
   audit row lands BEFORE the finding changes, as the methodology requires;
4. ``os.replace`` the staged file into place and re-check its hash.

If step 4 fails, the staged file (whose hash IS the new baseline) survives;
re-running the same ``approve_finding`` detects that and completes the
replace instead of refusing the finding forever (review LOW-5).

``("examiner", "approval", "S7-approve")`` is an allowlisted hash authority
(core/validators.py), so verify_full accepts the approved file. The decision
itself is examiner input, not a deterministic finding: this writer never
touches ``status``, ``confidence``, MITRE or caveats.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

DECISIONS = ("APPROVED", "REJECTED", "SUPERSEDED")
_APPROVAL_KEYS = ("approval", "approved_by", "approved_at", "approval_rationale",
                  "superseded_by")


def _strip_top_level_keys(text: str, keys) -> str:
    """Drop top-level ``key: ...`` entries (and any indented continuation
    lines) for ``keys``; every other byte of the file is preserved.
    A blank line does not end a skip: a quoted multi-line scalar holds
    literal empty lines inside it."""
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        c = line[:1]
        if c in (" ", "\t", "-"):
            pass  # continuation (indented, or a block sequence item)
        elif c in ("\n", "\r", ""):
            pass  # blank: leave ``skipping`` as is
        elif c == "#":
            skipping = False
        else:
            skipping = line.split(":", 1)[0].strip() in keys
        if not skipping:
            out.append(line)
    return "".join(out)


def approve_finding(case_dir: str, finding_id: str, *, examiner: str,
                    decision: str, rationale: str,
                    superseded_by: str | None = None) -> dict:
    """Record one examiner decision. Returns {"ok", "reason", ...}."""
    from spectre.core.validators import APPROVAL_AUTHORITY, finding_registry
    from spectre.pipeline.audit import append as audit_append
    from spectre.pipeline.custody import case_relative

    decision = (decision or "").upper()
    if decision not in DECISIONS:
        return {"ok": False, "reason": f"decision must be one of {DECISIONS}"}
    if not examiner or not rationale:
        return {"ok": False, "reason": "examiner and rationale are required"}
    if decision == "SUPERSEDED" and not superseded_by:
        return {"ok": False, "reason": "SUPERSEDED requires superseded_by"}

    case = Path(case_dir)
    fp = case / "findings" / f"{finding_id}.yaml"
    if not fp.is_file():
        return {"ok": False, "reason": f"{finding_id}: no findings/{fp.name}"}

    registry = finding_registry(case)
    if superseded_by and not _supersedes_registered(case, registry, superseded_by):
        return {"ok": False, "reason": (
            f"--superseded-by {superseded_by}: not a registered finding "
            f"(this case, or '<case_dir_name>/F-…' of a sibling case)")}
    info = registry.get(finding_id)
    if not info or not info.get("baseline"):
        return {"ok": False, "reason": f"{finding_id}: not registered by a "
                                       f"deterministic finding_create row"}
    if info.get("foreign_hash_rows"):
        return {"ok": False, "reason": f"{finding_id}: non-authority hash rows "
                                       f"exist — refusing to approve"}
    pending = fp.parent / f".{fp.name}.approval-pending"
    before = fp.read_bytes()
    pre_sha = hashlib.sha256(before).hexdigest()
    if pre_sha != info["baseline"] and pending.is_file() and not pending.is_symlink() \
            and hashlib.sha256(pending.read_bytes()).hexdigest() == info["baseline"]:
        # An earlier approval chained its row but the replace never landed.
        os.replace(pending, fp)
        return {"ok": True, "reason": "completed an interrupted approval "
                                      "(the chained row was already written)",
                "finding_id": finding_id, "decision": None,
                "previous_approval": None, "sha256": info["baseline"]}
    if pre_sha != info["baseline"]:
        return {"ok": False, "reason": (
            f"{finding_id}: file changed since its last recorded hash "
            f"(recorded {info['baseline'][:12]}…, found {pre_sha[:12]}…) — "
            f"refusing to approve a tampered finding")}

    text = before.decode("utf-8")
    current = yaml.safe_load(text) or {}
    previous = current.get("approval")  # None when never set (SKILL.md pitfall)
    approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    block = {"approval": decision, "approved_by": examiner,
             "approved_at": approved_at, "approval_rationale": rationale}
    if superseded_by:
        block["superseded_by"] = superseded_by
    body = _strip_top_level_keys(text, _APPROVAL_KEYS)
    if body and not body.endswith("\n"):
        body += "\n"
    new_text = body + yaml.safe_dump(block, sort_keys=False, allow_unicode=True,
                                     width=10**9, default_flow_style=False)
    new_bytes = new_text.encode("utf-8")
    new_sha = hashlib.sha256(new_bytes).hexdigest()

    # Step 2: stage the new bytes durably BEFORE the row.
    fd = os.open(str(pending), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                 os.stat(fp).st_mode & 0o777)
    with os.fdopen(fd, "wb") as f:
        f.write(new_bytes)
        f.flush()
        os.fsync(f.fileno())

    # Step 3: the chained decision (audit row before the finding changes).
    actor, action, step = APPROVAL_AUTHORITY
    cmd = (f"spectre approve --case {case} --finding {finding_id} "
           f"--examiner {examiner!r} --decision {decision} --rationale {rationale!r}"
           + (f" --superseded-by {superseded_by}" if superseded_by else ""))
    try:
        audit_append(str(case), {
            "actor": actor,
            "action": action,
            "tool": "spectre approve",
            "tool_version": "1.0",
            "exact_command": cmd,
            "params": {
                "examiner": examiner,
                "previous_approval": previous,
                "new_approval": decision,
                "decision_rationale": rationale,
                "superseded_by": superseded_by,
                "pre_sha256": pre_sha,
                "approved_at": approved_at,
            },
            "case_id": case.name,
            "finding_id": finding_id,
            "output_path": case_relative(case, fp),
            "output_sha256": new_sha,
            "output_format": "yaml",
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "phase": 7,
            "phase_step": step,
        })
    except Exception:
        pending.unlink(missing_ok=True)  # no row → nothing to complete
        raise

    # Step 4: land it. On failure the staged file stays for recovery.
    os.replace(pending, fp)
    written = hashlib.sha256(fp.read_bytes()).hexdigest()
    return {"ok": written == new_sha,
            "reason": "approved" if written == new_sha else "post-write hash mismatch",
            "finding_id": finding_id, "decision": decision,
            "previous_approval": previous, "sha256": written}


def _supersedes_registered(case: Path, registry: dict, ref: str) -> bool:
    """``ref`` names a registered finding: ``F-…`` in this case, or
    ``<case_dir_name>/F-…`` in a sibling case under the same cases-dir."""
    from spectre.core.validators import finding_registry

    if "/" not in ref:
        return bool(registry.get(ref, {}).get("baseline"))
    other_case, fid = ref.split("/", 1)
    if not other_case or "/" in fid or other_case in (".", ".."):
        return False
    other = case.parent / other_case
    if not other.is_dir():
        return False
    return bool(finding_registry(other).get(fid, {}).get("baseline"))


def pending_approvals(case_dir: str) -> list[str]:
    """Active findings with no examiner decision yet (Gate 7, advisory)."""
    fdir = Path(case_dir) / "findings"
    pending = []
    for fp in sorted(fdir.glob("F-*.yaml")) if fdir.exists() else []:
        try:
            data = yaml.safe_load(fp.read_text()) or {}
        except Exception:
            data = {}
        if data.get("approval") not in DECISIONS:
            pending.append(fp.stem)
    return pending


def main(argv: list[str] | None = None) -> int:
    """``spectre approve`` — record examiner decisions for one or more findings."""
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="spectre approve",
        description="Phase 7: record an examiner decision on finding(s). Writes "
                    "the chained approval row BEFORE the YAML edit and binds the "
                    "new content hash, so verify_full stays green.")
    ap.add_argument("--case", required=True, help="Case directory")
    ap.add_argument("--finding", action="append", required=True,
                    help="Finding ID (repeatable), e.g. F-884-003")
    ap.add_argument("--examiner", required=True, help="Examiner name / ID")
    ap.add_argument("--decision", required=True, type=str.upper, choices=DECISIONS)
    ap.add_argument("--rationale", required=True, help="Decision rationale")
    ap.add_argument("--superseded-by", default=None,
                    help="Replacing finding (required with SUPERSEDED)")
    args = ap.parse_args(argv)

    case_dir = os.path.expanduser(args.case)
    ok_all = True
    for fid in args.finding:
        res = approve_finding(case_dir, fid, examiner=args.examiner,
                              decision=args.decision, rationale=args.rationale,
                              superseded_by=args.superseded_by)
        mark = "OK " if res["ok"] else "FAIL"
        print(f"  [{mark}] {fid}: {res['reason']}", file=sys.stderr)
        ok_all = ok_all and res["ok"]
    return 0 if ok_all else 1
