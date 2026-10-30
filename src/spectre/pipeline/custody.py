"""custody.py — chain-of-custody helpers shared by case setup, the phase
runner, the CLI and ``audit.verify_full`` (Wave 3: W3-1, W3-2, W3-7).

Three concerns:

* **Case-relative paths (W3-7, R1-F10).** New audit rows record paths inside
  the case directory relative to it (``evidence/x.pcap``), so a case directory
  that is handed off, archived or restored somewhere else verifies ITS OWN
  bytes. ``resolve_case_path`` also re-roots legacy absolute rows into the
  current case directory (first by the case-dir name, then by a known case
  sub-directory), so old cases stay verifiable after a move.

* **Derived artifacts (W3-1, R2-04/R2-16).** ``normalized_events.json``,
  ``_handles.json`` and ``directives.json`` are what Phase 3 turns into
  findings. Each write is followed by a chained audit row carrying its
  sha256; ``verify_derived_artifact`` re-hashes before Phase 3 consumes the
  file and fails closed on a mismatch OR on a file with no hash row at all.

* **Evidence re-hash at phase entry (W3-2, R1-F8/R2-15).** ``enforce_evidence``
  re-hashes every evidence copy against its chained ``evidence_register``
  row (never the mutable manifest) and runs ``evidence_guard.guard`` on it
  (read-only bits unchanged — same semantics as at registration). A
  mismatch appends an ``evidence_tampered`` row and the caller stops.

Same-OS-user residual unchanged: an attacker who can rewrite audit.jsonl and
re-derive the chain can also re-bless these files; the journal/HMAC anchors
in audit.py are the defence for that, not this module.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

RAW_DIR = "raw_extract"

# Top-level case sub-directories used to re-root a legacy absolute path whose
# case directory was renamed (the case-dir name no longer appears in it).
_CASE_SUBDIRS = ("evidence", RAW_DIR, "findings", "reports")

# Audit actions whose output_path/output_sha256 describe a derived artifact
# Phase 3 consumes.
DERIVED_ACTIONS = ("derived_artifact", "directives_synthesized")

DERIVED_PHASE2_FILES = ("normalized_events.json", "_handles.json")


class CustodyError(RuntimeError):
    """A custody check failed closed (hash mismatch, or no chained hash)."""


# ── paths ────────────────────────────────────────────────────────────────
def case_relative(case_dir, path) -> str:
    """``path`` relative to ``case_dir`` (POSIX form) when it lies inside the
    case directory; otherwise ``str(path)`` unchanged."""
    if not path:
        return ""
    cd = os.path.abspath(str(case_dir))
    ap = os.path.abspath(str(path))
    if ap == cd or not ap.startswith(cd + os.sep):
        return str(path)
    return Path(os.path.relpath(ap, cd)).as_posix()


def resolve_case_path(case_dir, recorded) -> Path:
    """Where a recorded path lives in THIS case directory.

    - relative → ``case_dir / recorded`` (normalized);
    - absolute inside ``case_dir`` → unchanged;
    - absolute elsewhere (a legacy row from before W3-7, written at the
      case's original location) → re-rooted at the last path component equal
      to the case-dir name, else at the last known case sub-directory
      (``evidence``/``raw_extract``/``findings``/``reports``).

    Anything that does not land inside ``case_dir`` after normalization
    (``../`` traversal, an absolute path that cannot be re-rooted) raises
    CustodyError — a recorded path can never point a check outside the case.
    """
    if not recorded:
        raise CustodyError("empty recorded path")
    p = Path(str(recorded))
    cd = Path(os.path.abspath(str(case_dir)))
    if not p.is_absolute():
        return _inside(cd, cd / p, recorded)
    ap = Path(os.path.abspath(str(p)))
    if _is_within(cd, ap):
        return ap
    parts = ap.parts
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] == cd.name:
            return _inside(cd, cd.joinpath(*parts[i + 1:]), recorded)
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] in _CASE_SUBDIRS:
            return _inside(cd, cd.joinpath(*parts[i:]), recorded)
    raise CustodyError(f"recorded path is outside the case directory: {recorded}")


def try_resolve(case_dir, recorded) -> Path | None:
    """resolve_case_path, or None when the recorded path is refused."""
    try:
        return resolve_case_path(case_dir, recorded)
    except CustodyError:
        return None


def _is_within(cd: Path, path: Path) -> bool:
    return str(path) == str(cd) or str(path).startswith(str(cd) + os.sep)


def _inside(cd: Path, candidate: Path, recorded) -> Path:
    norm = Path(os.path.normpath(str(candidate)))
    if not _is_within(cd, norm) or norm == cd:
        raise CustodyError(f"recorded path escapes the case directory: {recorded}")
    return norm


def link_problem(case_dir, path: Path) -> str:
    """"" if ``path`` is a real file inside the case; else why not (W3-2
    rework: a symlink in evidence/ lets content be swapped without touching
    the 0555 directory)."""
    if path.is_symlink():
        return f"{path.name}: is a symlink — evidence copies must be regular files"
    real = os.path.realpath(str(path))
    root = os.path.realpath(str(case_dir))
    if not real.startswith(root + os.sep):
        return f"{path.name}: resolves outside the case directory ({real})"
    return ""


def _same_path(case_dir, a, b) -> bool:
    try:
        return resolve_case_path(case_dir, a) == resolve_case_path(case_dir, b)
    except CustodyError:
        return False


# Who may bless a derived artifact (review LOW-1): the core pipeline only.
DERIVED_AUTHORITIES = {
    ("deterministic-core", "derived_artifact", "S2-persist-derived"),
    ("deterministic-core", "directives_synthesized", "S1-synthesize-directives"),
}


def is_derived_authority(row: dict) -> bool:
    return (row.get("actor"), row.get("action"), row.get("phase_step")) in DERIVED_AUTHORITIES


# ── hashing / audit rows ─────────────────────────────────────────────────
def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_audit_rows(case_dir) -> list[dict]:
    path = Path(case_dir) / "audit.jsonl"
    rows: list[dict] = []
    if not path.exists():
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def record_derived_artifact(case_dir, path, *, phase: int, phase_step: str,
                            tool: str, action: str = "derived_artifact",
                            params: dict | None = None,
                            output_line_count: int | None = None) -> str:
    """Append a chained row binding ``path``'s current sha256. Returns it."""
    from spectre.pipeline.audit import append as audit_append

    p = Path(path)
    sha = sha256_file(p)
    row = {
        "actor": "deterministic-core",
        "action": action,
        "tool": tool,
        "tool_version": "1.0",
        "exact_command": f"{tool} — persist {p.name}",
        "params": dict(params or {}),
        "case_id": Path(case_dir).name,
        "output_path": case_relative(case_dir, p),
        "output_sha256": sha,
        "output_format": "json",
        "output_size_bytes": p.stat().st_size,
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "stderr": "",
        "phase": phase,
        "phase_step": phase_step,
    }
    if output_line_count is not None:
        row["output_line_count"] = output_line_count
    audit_append(str(case_dir), row)
    return sha


def record_derived_artifacts(case_dir) -> dict[str, str]:
    """Phase 2: chain the hash of every Phase-2 derived artifact that exists."""
    out = {}
    raw = Path(case_dir) / RAW_DIR
    for name in DERIVED_PHASE2_FILES:
        p = raw / name
        if p.exists():
            out[name] = record_derived_artifact(
                case_dir, p, phase=2, phase_step="S2-persist-derived",
                tool="phase_runner._run_phase_2_live")
    return out


def _latest_hash_row(case_dir, path, actions, rows) -> dict | None:
    """Latest AUTHORITY row recording ``path`` (non-core rows never count)."""
    latest = None
    for r in rows:
        if r.get("action") in actions and is_derived_authority(r) and \
                r.get("output_path") and _same_path(case_dir, r["output_path"], path):
            latest = r
    return latest


def read_verified(case_dir, path, *, actions=DERIVED_ACTIONS,
                  required: bool = True,
                  rows: list[dict] | None = None) -> bytes:
    """Read ``path`` ONCE, hash exactly those bytes against the latest
    authority row recording it, and return them — the caller parses the
    bytes that were verified, never a second read (review LOW-2 TOCTOU).

    Raises CustodyError when the bytes differ, or — if ``required`` — when no
    authority row with a hash exists (an unrecorded file is not trusted).
    """
    rows = read_audit_rows(case_dir) if rows is None else rows
    p = Path(path)
    data = p.read_bytes()
    row = _latest_hash_row(case_dir, p, actions, rows)
    recorded = (row or {}).get("output_sha256") or ""
    if not recorded:
        if required:
            raise CustodyError(
                f"{p.name}: no chained core-pipeline hash row records this file — "
                f"refusing to consume an unrecorded derived artifact (re-run the "
                f"phase that writes it)")
        return data
    actual = hashlib.sha256(data).hexdigest()
    if actual != recorded:
        raise CustodyError(
            f"{p.name}: content changed since it was recorded "
            f"(audited={recorded[:16]}…, actual={actual[:16]}…, "
            f"seq {row.get('seq', '?')})")
    return data


def verify_derived_artifact(case_dir, path, *, actions=DERIVED_ACTIONS,
                            required: bool = True,
                            rows: list[dict] | None = None) -> str:
    """Hash-check ``path`` (see read_verified); returns its sha256."""
    return hashlib.sha256(read_verified(case_dir, path, actions=actions,
                                        required=required, rows=rows)).hexdigest()


def derived_artifact_problems(case_dir, rows: list[dict]) -> tuple[int, list[str]]:
    """verify_full: re-hash every derived artifact against its latest row."""
    latest: dict[str, dict] = {}
    problems = []
    for r in rows:
        if r.get("action") in DERIVED_ACTIONS and r.get("output_path") \
                and r.get("output_sha256"):
            if not is_derived_authority(r):
                problems.append(
                    f"seq {r.get('seq', '?')}: non-authority {r.get('action')} row "
                    f"(actor={r.get('actor')!r}, step={r.get('phase_step')!r}) "
                    f"carries a hash for {r.get('output_path')}")
                continue
            try:
                key = str(resolve_case_path(case_dir, r["output_path"]))
            except CustodyError as e:
                problems.append(str(e))
                continue
            latest[key] = r
    for key, r in sorted(latest.items()):
        p = Path(key)
        if not p.exists():
            problems.append(f"{p.name}: recorded derived artifact missing on disk")
            continue
        try:
            actual = sha256_file(p)
        except OSError as e:
            problems.append(f"{p.name}: cannot read ({e})")
            continue
        if actual != r["output_sha256"]:
            problems.append(
                f"{p.name}: content changed since recorded "
                f"(audited={r['output_sha256'][:16]}…, actual={actual[:16]}…)")
    return len(latest), problems


def note_tamper(case_dir, action: str, phase: int, problems: list[str],
                tool: str) -> None:
    """Best-effort chained record of a custody failure (never raises)."""
    try:
        from spectre.pipeline.audit import append as audit_append
        audit_append(str(case_dir), {
            "actor": "deterministic-core",
            "action": action,
            "tool": tool,
            "tool_version": "1.0",
            "exact_command": f"{tool} — custody check failed; pipeline stopped",
            "params": {"problems": problems[:20]},
            "case_id": Path(case_dir).name,
            "output_path": "",
            "output_sha256": "",
            "result": "failure",
            "exit_code": 1,
            "duration_ms": 0,
            "stderr": "; ".join(problems)[:500],
            "phase": phase,
            "phase_step": "S0-custody-check",
        })
    except Exception:
        pass


# ── evidence ─────────────────────────────────────────────────────────────
EVIDENCE_ACTIONS = ("evidence_register", "derived_evidence_register")


def evidence_problems(case_dir, rows: list[dict] | None = None,
                      check_guard: bool = False) -> list[str]:
    """Re-hash every chained ``evidence_register`` copy AND every carved
    ``derived_evidence_register`` file (resolved into THIS case directory)
    against its recorded hash. A symlink, a path resolving outside the case,
    or a row whose path escapes the case is a problem. With ``check_guard``,
    also run evidence_guard.guard (read-only bits), parent check skipped."""
    rows = read_audit_rows(case_dir) if rows is None else rows
    problems = []
    for r in rows:
        if r.get("action") not in EVIDENCE_ACTIONS:
            continue
        recorded = r.get("output_sha256")
        if not r.get("output_path") or not recorded:
            continue
        try:
            ep = resolve_case_path(case_dir, r["output_path"])
        except CustodyError as e:
            problems.append(f"seq {r.get('seq', '?')}: {e}")
            continue
        if not ep.exists() and not ep.is_symlink():
            problems.append(f"{ep.name}: registered evidence missing on disk")
            continue
        lp = link_problem(case_dir, ep)
        if lp:
            problems.append(lp)
            continue
        try:
            cur = sha256_file(ep)
        except OSError as ex:
            problems.append(f"{ep.name}: cannot read ({ex})")
            continue
        if cur != recorded:
            problems.append(
                f"{ep.name}: content changed since registration "
                f"(audited={recorded[:16]}..., actual={cur[:16]}...)")
            continue
        if check_guard:
            from spectre.pipeline.evidence_guard import guard
            ok, reason, _ = guard(str(ep), case_dir=None, skip_audit=True,
                                  skip_parent_check=True)
            if not ok:
                problems.append(f"{ep.name}: evidence_guard failed ({reason})")
    return problems


def registered_evidence_paths(case_dir, rows: list[dict] | None = None) -> set[str]:
    """Paths (inside this case) of every chained evidence_register copy."""
    rows = read_audit_rows(case_dir) if rows is None else rows
    out = set()
    for r in rows:
        if r.get("action") == "evidence_register" and r.get("output_path") \
                and r.get("output_sha256"):
            try:
                out.add(str(resolve_case_path(case_dir, r["output_path"])))
            except CustodyError:
                continue
    return out


def enforce_evidence(case_dir, phase: int) -> list[str]:
    """Phase-entry / resume gate. Returns the problems (empty = OK). On any
    problem, appends a chained ``evidence_tampered`` row (SKILL.md: mismatch →
    evidence_tampered audit row + pipeline stops); the caller must stop."""
    problems = evidence_problems(case_dir, check_guard=True)
    if problems:
        note_tamper(case_dir, "evidence_tampered", phase, problems,
                    "custody.enforce_evidence")
    return problems
