"""
audit.py — tamper-evident JSONL audit trail with SHA-256 chaining.

Three functions:
  append(case_dir, entry: dict) -> str (entry_sha256)
  verify_chain(case_dir) -> (ok: bool, reason: str)
  verify_full(case_dir) -> dict (comprehensive integrity report)

Entry shape follows the v6 plan's audit.jsonl schema.
Uses json.dumps(sort_keys=True, separators=(",",":")) for canonical hashing.
Opens with "a" and fsync after each write. Never rewrites earlier lines.
"""

import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
from datetime import datetime, timezone

from spectre import config
from spectre.pipeline.custody import (
    derived_artifact_problems, evidence_problems, try_resolve,
)

# ── Shared shell logger (also used by direct subprocess calls) ──
try:
    from spectre.pipeline.shell_log import log_command as _shell_log
except ImportError:
    # Fallback if shell_log.py not available (shouldn't happen in pipeline)
    def _shell_log(*args, **kwargs):
        pass


def _utcnow_iso_millis() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
           f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _last_line(case_dir: str) -> dict | None:
    path = os.path.join(case_dir, "audit.jsonl")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, "r") as f:
        # seek to last non-empty line
        lines = f.readlines()
        for line in reversed(lines):
            stripped = line.strip()
            if stripped:
                return json.loads(stripped)
    return None


def _anchor_path(case_dir: str) -> str:
    return os.path.join(case_dir, "audit_chain_anchor.json")


def _update_chain_anchor(case_dir: str, seq: int, entry_sha256: str) -> None:
    """Best-effort external tail-truncation anchor (A8-F3).

    verify_chain() alone can only prove internal self-consistency of
    whatever rows remain in audit.jsonl — deleting the MOST RECENT row(s)
    leaves a chain that is still perfectly self-consistent from seq 1, so
    pure internal chain-walking can never detect it. After every append(),
    record the (seq, entry_sha256) we just wrote in a small sidecar file
    audit.py exclusively owns, so a later verify_chain() can notice the
    chain got SHORTER than the last time anything appended to it.

    Deliberately a standalone sidecar file, NOT a field folded into
    manifest.yaml: several phase_runner.py functions load manifest.yaml
    once at the top of a phase, call append() several times, then
    _save_manifest() that now-stale in-memory copy at the end — which
    would silently clobber a manifest-embedded anchor with each phase's
    round trip. A file only audit.py touches has no such writer race.

    Not cryptographic — this sidecar is an ordinary file a same-privilege
    attacker could edit too (see H2/H3's documented limits on this whole
    module's tamper-evidence). It only raises the bar against careless or
    partial tail deletion. Never raises: a write failure here must not
    break the audit append itself.

    KNOWN OPEN GAP (residual A, WS1a MUST-FIX review — NOT closed here,
    left for WS1b): this sidecar lives in the SAME case directory as
    audit.jsonl. An attacker who can truncate the chain can delete this
    file right alongside it, just as easily — verify_chain()'s tail check
    then has nothing to compare against and the check fails OPEN (silently
    skipped, not "no problem found"; see _read_chain_anchor() and the
    chain_anchor check in verify_full()). TODO(WS1b): the real close is an
    anchor that lives OUTSIDE the case directory and this OS-level trust
    boundary entirely — e.g. a signed/remote checkpoint, or an append-only
    external log (systemd-journal or similar) the case can write to but
    not truncate.
    """
    try:
        path = _anchor_path(case_dir)
        with open(path, "w") as f:
            json.dump({"seq": seq, "entry_sha256": entry_sha256}, f)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass


def _read_chain_anchor(case_dir: str) -> dict | None:
    """Read the sidecar anchor, if any. None (not an error) when absent —
    e.g. a chain built by writing audit.jsonl directly rather than through
    append() (common in tests), or a case predating this feature."""
    path = _anchor_path(case_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# ── External append-only anchor: systemd journal (WS1c(A)) ──────────────
# Closes the residual left by _update_chain_anchor() above: that sidecar
# lives INSIDE the case directory, so a same-OS-user attacker who can
# tamper audit.jsonl and re-derive prev_sha256/entry_sha256 forward (the
# A1-H2 CONFIRMED "ATTACK D") can delete or rewrite the sidecar too. A
# non-root user can APPEND to the systemd journal but cannot rewrite or
# delete entries already committed to it — so checkpointing the chain tail
# there on every append() gives verify_full() a witness outside the OS-user
# trust boundary the sidecar never had.
#
# Best-effort and fully graceful by design: hosts with no systemd/journald
# (CI, containers, macOS) must see no behavior change at all. Never raises.
_JOURNAL_TAG = "spectre-audit"

# Keys excluded from the canonical body used to compute entry_sha256. Both
# are the row's OWN derived fields — including them would make the hash
# depend on itself. entry_hmac (WS1c(B), below) is appended to a row AFTER
# entry_sha256 is computed, so it must be excluded from the hash input the
# same way entry_sha256 itself already is, or verify_chain()'s recompute
# would disagree with what append() originally wrote.
_HASH_EXCLUDED_KEYS = ("entry_sha256", "entry_hmac")


def case_nonce(case_dir: str) -> str:
    """The per-case-directory nonce minted into the genesis (seq 1) row by
    append() (W3-5, R2-10). "" for a legacy chain that predates it."""
    path = os.path.join(case_dir, "audit.jsonl")
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    return str(json.loads(line).get("case_nonce") or "")
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def _journal_write(case_id: str, seq: int, entry_sha256: str,
                   nonce: str = "", case_dir: str = "") -> None:
    """Best-effort checkpoint of (case_id, case_nonce, case_dir, seq,
    entry_sha256) into the systemd journal, tagged spectre-audit. The nonce
    plus the case directory's real path (W3-5) is what verify_full filters
    on, so two cases that share a case_id (a re-used name, a scratch
    --cases-dir, a test fixture) never witness each other — and neither do a
    case and a copy of it that has since diverged. Never raises."""
    if not config.audit_journal_anchor_enabled():
        return
    try:
        payload = {"case_id": case_id, "seq": seq, "entry_sha256": entry_sha256}
        if nonce:
            payload["case_nonce"] = nonce
        if case_dir:
            payload["case_dir"] = os.path.realpath(case_dir)
        _journal_emit(_canonical_json(payload))
    except Exception:
        pass


def _journal_emit(payload: str) -> None:
    """Send one payload line to the journal. Prefers systemd-cat (writes the
    journal directly); falls back to logger (goes via syslog, which
    journald normally ingests). Neither found -> silent no-op. Any failure
    at any step (missing binary, no journald socket, timeout, permission
    error) is swallowed -- this must NEVER break append()."""
    try:
        systemd_cat = shutil.which("systemd-cat")
        if systemd_cat:
            subprocess.run(
                [systemd_cat, "-t", _JOURNAL_TAG],
                input=payload.encode("utf-8"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return
        logger_bin = shutil.which("logger")
        if logger_bin:
            subprocess.run(
                [logger_bin, "--tag", _JOURNAL_TAG, "--", payload],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return
        # Neither tool found -- no systemd/journald on this host. Silent
        # no-op; verify_full()'s journal_anchor check treats this as
        # advisory, not a failure (see _journal_anchor_check()).
    except Exception:
        pass


def _journal_read_entries() -> list[dict] | None:
    """Read back every spectre-audit journal entry this host's journald
    knows about, across all cases (caller filters by case_id). Returns
    None (not an error) when journalctl isn't available, the read fails,
    or output can't be parsed -- verify_full() treats None as "can't check"
    (advisory), never as a failure. A real, empty result is a normal
    empty list, distinct from None."""
    journalctl_bin = shutil.which("journalctl")
    if not journalctl_bin:
        return None
    try:
        result = subprocess.run(
            [journalctl_bin, "-t", _JOURNAL_TAG, "--output=cat", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        entries = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
    except Exception:
        return None


def append(case_dir: str, entry: dict) -> str:
    """Append one entry to audit.jsonl. Returns entry_sha256."""
    path = os.path.join(case_dir, "audit.jsonl")

    last = _last_line(case_dir)
    if last:
        entry["seq"] = last["seq"] + 1
        entry["prev_sha256"] = last["entry_sha256"]
        nonce = case_nonce(case_dir)
    else:
        entry["seq"] = 1
        entry["prev_sha256"] = "0" * 64
        # W3-5 (R2-10): mint a random per-case-directory nonce into the
        # genesis row. It is inside the hash, so it is chained; the journal
        # anchor is keyed by it rather than by the (re-usable) case_id.
        entry.setdefault("case_nonce", secrets.token_hex(16))
        nonce = entry["case_nonce"]

    entry.setdefault("timestamp", _utcnow_iso_millis())
    entry.setdefault("token_usage", {"prompt": 0, "completion": 0})

    # Build canonical body WITHOUT entry_sha256 (or entry_hmac, see
    # _HASH_EXCLUDED_KEYS -- entry_hmac doesn't exist yet at this point
    # anyway, but excluding it here too keeps this in lock-step with
    # verify_chain()'s recompute).
    body = {k: v for k, v in entry.items() if k not in _HASH_EXCLUDED_KEYS}
    canon = _canonical_json(body)
    entry["entry_sha256"] = _sha256_hex(canon)

    # ── Opt-in HMAC anchor (WS1c(B)) ──
    # Off by default (config.audit_hmac_key() -> None when neither
    # SPECTRE_AUDIT_HMAC_KEY nor SPECTRE_AUDIT_HMAC_KEYFILE is set) --
    # entries are then byte-identical to before this feature existed.
    # When on, HMACs entry_sha256 (not the whole row) with a key sourced
    # from OUTSIDE the case directory. Defends the case-HAND-OFF attacker
    # (a copy of the case dir goes to a party without the key) -- NOT the
    # same-OS-user attacker who already has access to the key. Honest
    # limit (see config.audit_hmac_key()'s docstring): the hand-off
    # attacker can't RECOMPUTE a valid entry_hmac after tampering, but CAN
    # simply DELETE the field on the rows they touch -- verify_chain()
    # catches a PARTIAL strip (a monotonic-coverage gap) fail-closed when a
    # key is configured, but a FULL strip across every row is internally
    # indistinguishable from a chain that never used this feature; only
    # the external journal anchor closes that residual, when reachable.
    hmac_key = config.audit_hmac_key()
    if hmac_key:
        entry["entry_hmac"] = hmac.new(
            hmac_key, entry["entry_sha256"].encode("utf-8"), hashlib.sha256
        ).hexdigest()

    line = _canonical_json(entry) + "\n"
    with open(path, "a") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())

    # ── Also write human-readable execution.log ──
    _write_cmd_log(case_dir, entry)

    # ── External tail-truncation anchor (A8-F3) ──
    _update_chain_anchor(case_dir, entry["seq"], entry["entry_sha256"])

    # ── External append-only anchor: systemd journal (WS1c(A)) ──
    _journal_write(entry.get("case_id", ""), entry["seq"], entry["entry_sha256"],
                   nonce, case_dir)

    return entry["entry_sha256"]


_CMD_LOG_HEADER_WRITTEN: set[str] = set()


def _read_output_head(output_path: str, max_lines: int = 200, max_chars: int = 20_000) -> str:
    """Read first N lines of an output file. Returns '' if file missing/unreadable."""
    if not output_path or not os.path.exists(output_path):
        return ""
    try:
        with open(output_path, "r") as f:
            lines = []
            total_chars = 0
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n"))
                total_chars += len(line)
                if total_chars > max_chars:
                    break
            return "\n".join(lines)
    except (OSError, UnicodeDecodeError):
        return ""


def _write_cmd_log(case_dir: str, entry: dict) -> None:
    """Write audit entry to execution.log via the shared shell_log module.
    Reads the output file and includes its content inline in the log."""
    tool = entry.get("tool", "?")
    command = entry.get("exact_command", "")
    exit_code = entry.get("exit_code", 0)
    duration_ms = entry.get("duration_ms", 0)
    stderr = entry.get("stderr", "")
    output_path = entry.get("output_path", "")
    phase = entry.get("phase", 0)
    phase_step = entry.get("phase_step", "")

    # ── Read output file content for inline logging ──
    stdout = _read_output_head(output_path)

    # Build extra info
    extra_parts = []
    line_count = entry.get("output_line_count", 0)
    if line_count:
        if output_path:
            extra_parts.append(f"{line_count} rows → {os.path.basename(output_path)}")
        else:
            extra_parts.append(f"{line_count} rows")
    finding_id = entry.get("finding_id")
    if finding_id:
        extra_parts.append(f"finding={finding_id}")
    action = entry.get("action", "")
    if action == "note":
        tok = entry.get("token_usage", {})
        p_tok = tok.get("prompt", 0)
        c_tok = tok.get("completion", 0)
        if p_tok or c_tok:
            extra_parts.append(f"tokens={p_tok}+{c_tok}")

    extra = " | ".join(extra_parts) if extra_parts else ""

    _shell_log(
        case_dir=case_dir,
        tool=tool,
        command=command,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stderr=stderr,
        extra=extra,
        stdout=stdout,
        stdout_path=output_path,
        phase=phase,
        phase_step=phase_step,
    )


def verify_chain(case_dir: str) -> tuple[bool, str]:
    """Walk audit.jsonl line by line. Return (ok, reason)."""
    path = os.path.join(case_dir, "audit.jsonl")

    if not os.path.exists(path):
        return False, "audit.jsonl not found"

    with open(path, "r") as f:
        lines = f.readlines()

    expected_seq = 1
    prev_entry_sha256 = "0" * 64
    # Opt-in HMAC anchor (WS1c(B)) state, tracked across the whole walk:
    # read the key once (it doesn't change mid-walk), and track whether any
    # row so far carried entry_hmac, to enforce monotonic coverage below.
    hmac_key = config.audit_hmac_key()
    seen_entry_hmac = False

    for i, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue  # skip blank lines

        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError as e:
            return False, f"line {i}: invalid JSON: {e}"

        # Check seq
        stored_seq = entry.get("seq")
        if stored_seq != expected_seq:
            return False, f"line {i}: seq {stored_seq} != expected {expected_seq}"

        # Recompute entry_sha256
        stored_entry_sha = entry.get("entry_sha256", "")
        body = {k: v for k, v in entry.items() if k not in _HASH_EXCLUDED_KEYS}
        canon = _canonical_json(body)
        computed_entry_sha = _sha256_hex(canon)

        if stored_entry_sha != computed_entry_sha:
            return False, (
                f"line {i} (seq {stored_seq}): entry_sha256 mismatch — "
                f"stored={stored_entry_sha[:16]}..., "
                f"computed={computed_entry_sha[:16]}..."
            )

        # ── Opt-in HMAC check (WS1c(B)) ──
        # Only checkable when BOTH a key is configured in this process AND
        # the row itself carries an entry_hmac. A row with no entry_hmac
        # (chain predates the feature, or was appended while the key was
        # unset) is not itself a failure -- nothing to compare against,
        # same "can't prove, don't fail" stance as the finding-hash
        # backfill in verify_full()'s Check 8. A row WITH an entry_hmac
        # that disagrees with a freshly recomputed one IS a failure: it
        # means either the row's entry_sha256 changed since the HMAC was
        # computed (exactly what re-deriving the chain forward after a
        # tamper produces, since the attacker lacks the key to also forge
        # a matching HMAC), or the entry_hmac field itself was
        # corrupted/forged.
        stored_hmac = entry.get("entry_hmac")
        if stored_hmac:
            seen_entry_hmac = True
            if hmac_key:
                computed_hmac = hmac.new(
                    hmac_key, stored_entry_sha.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(computed_hmac, stored_hmac):
                    return False, (
                        f"line {i} (seq {stored_seq}): entry_hmac mismatch — "
                        f"the SHA-256 chain is internally self-consistent but "
                        f"disagrees with the HMAC anchor (tampered row, or a "
                        f"chain re-derived forward without the HMAC key — "
                        f"see A1-H2/H3)"
                    )
            # else: key not configured in this process -- can't verify;
            # advisory only, surfaced by verify_full()'s audit_hmac check.
        elif seen_entry_hmac and hmac_key:
            # ── Monotonic-coverage violation (field-strip downgrade) ──
            # entry_hmac is an ordinary, attacker-controlled JSON field --
            # a case-dir-write attacker who can't forge a valid HMAC after
            # tampering (no key) can instead just DELETE the field on the
            # rows they touch. Legitimate use only ever turns HMAC ON
            # partway through a case (no-HMAC rows, then HMAC rows --
            # non-decreasing coverage); a row missing entry_hmac AFTER an
            # earlier row already carried one is the strip signature
            # itself. Only fail-closed here when a key IS configured: that
            # proves this process can genuinely verify HMAC coverage, so a
            # gap is meaningful rather than an artifact of never having
            # had a key to check with. (A gap with NO key configured is
            # still reportable -- just not provably an attack -- see
            # verify_full()'s audit_hmac advisory / _hmac_advisory_check().)
            return False, (
                f"line {i} (seq {stored_seq}): entry_hmac missing after an "
                f"earlier row in this chain carried one — possible HMAC "
                f"downgrade/strip signal (an attacker who can't forge a "
                f"valid entry_hmac after tampering can delete it instead — "
                f"see A1-H2/H3)"
            )

        # Check prev_sha256 chain
        stored_prev = entry.get("prev_sha256", "")
        if stored_prev != prev_entry_sha256:
            return False, (
                f"line {i} (seq {stored_seq}): prev_sha256 mismatch — "
                f"stored={stored_prev[:16]}..., "
                f"expected={prev_entry_sha256[:16]}..."
            )

        prev_entry_sha256 = stored_entry_sha
        expected_seq += 1

    if expected_seq == 1:
        return False, "audit.jsonl has no entries"

    # ── Tail-truncation check against the external anchor (A8-F3) ──
    # The walk above only proves internal self-consistency of whatever
    # rows remain; it can't see that rows are MISSING off the end. The
    # anchor records what append() last wrote — if the chain we just
    # walked ends earlier (lower seq, or same seq with a different final
    # hash) than that, rows were deleted after the anchor was recorded.
    last_seq = expected_seq - 1
    anchor = _read_chain_anchor(case_dir)
    if anchor:
        anchor_seq = anchor.get("seq", 0)
        if anchor_seq > last_seq:
            return False, (
                f"chain is SHORTER than the last recorded anchor — chain ends "
                f"at seq {last_seq}, anchor expects seq {anchor_seq} "
                f"(possible tail truncation)"
            )
        if anchor_seq == last_seq and anchor.get("entry_sha256") != prev_entry_sha256:
            return False, (
                f"chain tail hash disagrees with the recorded anchor at seq {last_seq}"
            )

    return True, "ok"


def _narrative_grounding_check(case_dir: str) -> dict:
    """Drift detector bound to the CURRENT report (W3-4, R2-08).

    An AI narrative must have passed ``_validate_report`` for THIS report,
    not merely at some point in the case's history:

    - ``llm_used`` is true if EITHER the latest chained ``S3-merge-report``
      row's ``params.llm_used`` OR manifest ``report.ai_narrative`` says so —
      flipping the mutable manifest flag to False no longer skips the check.
    - The report.md bytes on disk must equal that latest S3 row's
      ``output_sha256`` (the narrative being vouched for is the one on disk).
    - An ``S2-validate-report`` row must sit AFTER the previous
      ``S3-merge-report`` row (i.e. inside the generation that produced the
      current report). A stale S2 row from an earlier run no longer counts.

    Still a drift detector, not an adversarial control: an agent that forges
    a fresh S2 row and a matching S3 row (or an S3 row claiming
    ``llm_used: false`` with the manifest flag cleared) defeats it — the
    same-user residual stated in this function's docstring."""
    from pathlib import Path
    import yaml

    case = Path(case_dir)
    try:
        manifest_path = case / "manifest.yaml"
        manifest = {}
        if manifest_path.exists():
            manifest = yaml.safe_load(manifest_path.read_text()) or {}
        manifest_flag = bool((manifest.get("report") or {}).get("ai_narrative", False))

        entries = []
        audit_path = case / "audit.jsonl"
        if audit_path.exists():
            with open(audit_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        s3_idx = [i for i, e in enumerate(entries)
                  if e.get("phase_step") == "S3-merge-report"]
        if not s3_idx:
            if not manifest_flag:
                return {"passed": True,
                        "detail": "deterministic baseline — no AI narrative to validate"}
            if (case / "reports" / "report.md").exists():
                return {"passed": False,
                        "detail": "AI narrative flagged but report.md is bound to no "
                                  "S3-merge-report row — cannot tie it to a validation"}
            # Pre-report (legacy shape): the validation row alone.
            if any(e.get("phase_step") == "S2-validate-report" for e in entries):
                return {"passed": True,
                        "detail": "AI narrative has a validation-record audit row "
                                  "(no report written yet)"}
            return {"passed": False,
                    "detail": "AI narrative present but no S2-validate-report row — "
                              "model prose may have bypassed the validator"}

        latest_i = s3_idx[-1]
        latest = entries[latest_i]
        row_flag = bool((latest.get("params") or {}).get("llm_used", False))
        if not (manifest_flag or row_flag):
            return {"passed": True,
                    "detail": "deterministic baseline — no AI narrative to validate"}

        recorded = latest.get("output_sha256") or ""
        rpath = try_resolve(case_dir, latest.get("output_path") or "reports/report.md")
        if not recorded or rpath is None or not rpath.exists():
            return {"passed": False,
                    "detail": "AI narrative: latest S3-merge-report row records no "
                              "report.md hash, or report.md is missing"}
        actual = hashlib.sha256(rpath.read_bytes()).hexdigest()
        if actual != recorded:
            return {"passed": False,
                    "detail": (f"AI narrative: report.md on disk ({actual[:12]}…) is not "
                               f"the report the latest S3 row recorded ({recorded[:12]}…)")}

        prev_i = s3_idx[-2] if len(s3_idx) > 1 else -1
        window = entries[prev_i + 1:latest_i]
        if any(e.get("phase_step") == "S2-validate-report" for e in window):
            return {"passed": True,
                    "detail": (f"AI narrative in the current report.md ({actual[:12]}…) "
                               f"has a validation row in its own generation")}
        stale = any(e.get("phase_step") == "S2-validate-report"
                    for e in entries[:prev_i + 1])
        return {"passed": False,
                "detail": ("AI narrative in the current report.md has no "
                           "S2-validate-report row since the previous report write"
                           + (" (only a stale row from an earlier run)" if stale else "")
                           + " — model prose may have bypassed the validator")}
    except Exception as e:  # degrade-don't-block
        return {"passed": False, "detail": f"narrative_grounding could not be evaluated ({e})"}


def _hmac_advisory_check(entries: list[dict]) -> dict:
    """Advisory-only companion to the fail-closed HMAC checks inside
    verify_chain() (both the per-row mismatch recompute and the monotonic-
    coverage/downgrade check). This function must NEVER claim rows were
    "checked" when they were in fact skipped -- an earlier version of this
    check said exactly that after a partial entry_hmac strip, which is a
    control silently misreporting green after a bypass (Opus review
    finding on WS1c). Always reports real coverage counts (K of N rows),
    and surfaces a monotonic gap even when there's no key to prove it's
    tampering (the non-monotonic SHAPE is visible without any key at all).

    A chain that never used the HMAC feature at all (the common case,
    since it's opt-in -- zero rows carry entry_hmac) is silent, not a
    loud warning; that is the only case where "not in use" is accurate.
    """
    total = len(entries)
    hmac_rows = [e for e in entries if e.get("entry_hmac")]
    count = len(hmac_rows)
    if count == 0:
        return {"passed": True, "detail": "no entry_hmac rows — HMAC anchor not in use for this chain"}

    # Monotonic-coverage scan: once any row carries entry_hmac, every row
    # after it should too (legitimate use only ever toggles ON partway
    # through a case, never OFF again) -- mirrors the walk in
    # verify_chain(), independent of whether a key is configured here.
    seen = False
    gap_seq = None
    for e in entries:
        if e.get("entry_hmac"):
            seen = True
        elif seen:
            gap_seq = e.get("seq", "?")
            break

    key = config.audit_hmac_key()

    if gap_seq is not None:
        if key:
            # verify_chain() already fails the "chain" check closed for
            # this exact condition when a key is configured (see the
            # elif seen_entry_hmac branch there) -- report["ok"] is
            # already False via that check. This still names the same
            # finding under its own check for visibility/diagnostics.
            return {
                "passed": False,
                "detail": (
                    f"possible HMAC downgrade — entry_hmac present on "
                    f"{count} of {total} rows but missing at seq {gap_seq} "
                    f"after an earlier row already had one (caught "
                    f"fail-closed by the chain check above; a key IS "
                    f"configured here)"
                ),
            }
        return {
            "passed": False,
            "detail": (
                f"possible HMAC downgrade — {count} of {total} rows carry "
                f"entry_hmac, but row at seq {gap_seq} does not, after an "
                f"earlier row already had one. No key is configured in "
                f"this process to cryptographically confirm tampering, but "
                f"this non-monotonic coverage pattern is itself reportable "
                f"(A1-H2/H3 field-strip signature)"
            ),
        }

    if key:
        return {
            "passed": True,
            "detail": (
                f"{count} of {total} rows carry entry_hmac and a key is "
                f"configured — checked as part of the chain check"
            ),
        }
    return {
        "passed": False,
        "detail": (
            f"{count} of {total} rows carry entry_hmac but no "
            f"SPECTRE_AUDIT_HMAC_KEY / SPECTRE_AUDIT_HMAC_KEYFILE is "
            f"configured in this process — cannot verify the HMAC layer "
            f"here (not proof of tampering by itself; the SHA-256 chain "
            f"above was still fully checked)"
        ),
    }


def _journal_anchor_check(case_dir: str, case_name: str, entries: list[dict]) -> dict:
    """External-witness check for the WS1c(A) systemd-journal anchor.

    Three distinct outcomes:
      - disabled (config) -> passed, silent.
      - journald unavailable, or no entries witnessed for THIS case ->
        advisory (passed=False so it's visible, but does NOT fail the
        report -- mirrors the chain_anchor stance: absence isn't proof of
        tampering, plenty of legitimate chains have no journal history,
        e.g. a case copied to a host with no journald at all).
      - a witnessed (case_nonce, seq) disagrees with what's on disk NOW ->
        fail-closed (violation=True): this is precisely the signature of
        the A1-H2 re-derive-forward attack, caught by a witness the
        attacker's own copy of the case directory has no power over.
      - the journal witnessed a seq ABOVE the chain's last seq -> fail-closed
        (W3-5, R2-09): tail truncation, even with the sidecar deleted.

    Entries are matched by the genesis row's chained ``case_nonce`` (W3-5,
    R2-10), so another case directory re-using this case_id is never
    compared. A legacy chain with no nonce keeps case_id keying (nonce-less
    journal lines only).
    """
    if not config.audit_journal_anchor_enabled():
        return {"passed": True, "detail": "disabled via SPECTRE_AUDIT_JOURNAL_ANCHOR", "violation": False}

    journal_entries = _journal_read_entries()
    if journal_entries is None:
        return {
            "passed": False,
            "detail": (
                "journald/journalctl unavailable on this host — external "
                "witness check skipped (advisory only; this control only "
                "helps when journald IS present to consult — see A1-H2)"
            ),
            "violation": False,
        }

    nonce = str((entries[0].get("case_nonce") if entries else "") or "")
    here = os.path.realpath(case_dir)
    # W3-5 rework (review HIGH-1): what the journal recorded for THIS case
    # directory is BINDING, whatever the chain now claims its nonce is —
    # otherwise rewriting or dropping the genesis nonce would opt a
    # re-derived chain out of the witness. Binding entries:
    #   - written from this directory's real path (case_dir == here);
    #   - HEAD-era lines (no case_dir, no nonce) whose case_id matches — the
    #     pre-W3 floor, unchanged;
    #   - interim lines (nonce, no case_dir) carrying this chain's nonce.
    # Lines written from ANOTHER path (a relocated or handed-off copy that
    # has since diverged) are never compared — advisory count only.
    def _binding(e: dict) -> bool:
        cd = e.get("case_dir")
        if cd:
            return cd == here
        en = e.get("case_nonce")
        if not en:
            return e.get("case_id") == case_name
        return bool(nonce) and en == nonce
    case_entries = [e for e in journal_entries if _binding(e)]
    elsewhere = sum(1 for e in journal_entries
                    if e.get("case_dir") and e.get("case_dir") != here
                    and (e.get("case_id") == case_name
                         or (nonce and e.get("case_nonce") == nonce)))
    if not case_entries:
        return {
            "passed": False,
            "detail": (
                "no spectre-audit journal entries found for this case — "
                "advisory only (case may predate this feature, journald may "
                "not retain history that far back, or this is a copy made "
                "on a host with no journald access at append() time)"
                + (f"; {elsewhere} entr(ies) for this case were written from "
                   f"another path (a relocated or copied case directory — the "
                   f"external witness is not applied to a moved case)"
                   if elsewhere else "")
            ),
            "violation": False,
        }

    witnessed_nonces = sorted({str(e.get("case_nonce")) for e in case_entries
                               if e.get("case_dir") == here and e.get("case_nonce")})
    nonce_problem = ""
    if witnessed_nonces and witnessed_nonces != [nonce]:
        nonce_problem = (
            f"genesis case_nonce rewritten — the journal witnessed "
            f"{', '.join(n[:12] + '…' for n in witnessed_nonces)} for this case "
            f"directory, the chain now has "
            f"{(nonce[:12] + '…') if nonce else 'no nonce'}")

    chain_by_seq = {e.get("seq"): e.get("entry_sha256") for e in entries if e.get("seq") is not None}
    last_seq = max((s for s in chain_by_seq if isinstance(s, int)), default=0)
    mismatches = []
    compared = 0
    max_witnessed = 0
    for je in case_entries:
        seq = je.get("seq")
        if isinstance(seq, int):
            max_witnessed = max(max_witnessed, seq)
        witnessed = je.get("entry_sha256")
        current = chain_by_seq.get(seq)
        if current is None:
            continue
        compared += 1
        if witnessed and witnessed != current:
            mismatches.append(
                f"seq {seq}: chain now has {current[:16]}..., journal witnessed {witnessed[:16]}..."
            )
    problems = [nonce_problem] if nonce_problem else []
    if max_witnessed > last_seq:
        # W3-5 (R2-09): the external witness saw rows the chain no longer
        # has — tail truncation (the sidecar anchor can be deleted with it).
        problems.append(
            f"chain is SHORTER than externally witnessed — chain ends at seq "
            f"{last_seq}, journal witnessed up to seq {max_witnessed} "
            f"(tail truncation)")
    if mismatches:
        problems.append(
            f"{len(mismatches)} disagreement(s) between the on-disk chain "
            f"and the external journal witness — A1-H2 re-derive signature: "
            f"{'; '.join(mismatches[:5])}")
    if problems:
        return {"passed": False, "detail": " | ".join(problems), "violation": True}
    return {
        "passed": True,
        "detail": (f"{compared} of {len(case_entries)} journal entries compared; "
                   f"all agree with the on-disk chain (last seq {last_seq})"),
        "violation": False,
    }


def _dashboard_metrics_check(manifest_path, entries: list[dict]) -> dict:
    """Advisory (never flips ``ok``): re-hash manifest["report"]
    ["dashboard_metrics"] — the mutable copy the PDF/DOCX dashboards render
    from — against the ``dashboard_metrics_sha256`` the latest Phase-6
    S3-merge-report row recorded. A mismatch means the persisted metrics were
    edited after the report was generated (or a host re-merge recomputed
    them); the report.md bytes themselves stay bound by report_integrity.
    Advisory because the dashboard is a deterministic re-aggregation of
    already-verified finding facts, not evidence in its own right."""
    rows = [e for e in entries if e.get("phase_step") == "S3-merge-report"
            and "dashboard_metrics_sha256" in (e.get("params") or {})]
    if not rows:
        return {"passed": True,
                "detail": "no recorded dashboard-metrics hash (pre-feature case "
                          "or no Phase 6 yet)"}
    want = rows[-1]["params"]["dashboard_metrics_sha256"]
    import yaml
    try:
        with open(manifest_path) as f:
            man = yaml.safe_load(f) or {}
        metrics = (man.get("report") or {}).get("dashboard_metrics") or {}
    except Exception as e:  # noqa: BLE001 — advisory, never raises
        return {"passed": False,
                "detail": f"advisory — manifest unreadable ({e})"}
    got = hashlib.sha256(
        json.dumps(metrics, sort_keys=True).encode("utf-8")).hexdigest()
    if got != want:
        return {"passed": False,
                "detail": (f"advisory — persisted dashboard_metrics changed since "
                           f"Phase 6 (recorded {want[:12]}…, found {got[:12]}…); "
                           f"regenerate the report before relying on the "
                           f"PDF/DOCX dashboard")}
    return {"passed": True, "detail": "ok (persisted dashboard metrics match "
                                      "the Phase-6 audit row)"}


def verify_full(case_dir: str) -> dict:
    """Comprehensive case integrity check. Returns a detailed report.

    Checks performed:
      1. verify_chain() — SHA-256 hash chain intact
      2. audit↔disk consistency — every finding_id in audit has a YAML on disk
         and every YAML on disk has a corresponding audit row
      3. case_id consistency — every audit row's case_id matches the directory name
      4. phase coverage — every active finding has finding_create,
         adversarial_review and a later S3-merge-report row (R1-F12);
         fails closed once the case has a report, advisory before
      5. evidence integrity — re-hash evidence files against manifest, and
         cross-check manifest.yaml's recorded sha256 against the chained
         evidence_register audit row (manifest.yaml is a plain mutable file;
         the audit row is chain-protected — see A1-H3)
      6. report integrity — deliverable report.md must match audited SHA-256
      7. derived evidence integrity — re-hash derived evidence files against manifest
      7b. derived artifacts (W3-1) — re-hash normalized_events.json, _handles.json
         and directives.json against their latest chained hash rows
      8. finding integrity — every F-*.yaml on disk must match the LATEST
         audit row that recorded a content hash for it (finding_create,
         finding_status, or an explain() rewrite) — see A1-H1
      9. coverage disclosure — every chained `coverage_gap` row must appear in
         the LATEST S3-merge-report row's params["disclosed_coverage_gaps"],
         at no smaller a count. Closes the **vacuous PASS**: coverage used to
         live only in manifest.yaml, written by log_command (which never
         touches audit.jsonl), and no check here inspected any triage or
         coverage data at all — so a report regenerated with its coverage
         disclosures dropped still PASSED every integrity check. Structural,
         not textual: it never greps report prose, because coupling this module
         to report wording would mean the first reword either breaks
         verification or silently disarms it.

    Plus advisory-only signals (do not affect "ok" by themselves, same as
    phase coverage):
      - chain_anchor — warns when audit.jsonl has rows but the (in-case-dir)
        tail-truncation anchor sidecar is missing.
      - audit_hmac — warns when rows carry the opt-in entry_hmac field but
        no key is configured in this process to check it (WS1c(B)), OR
        when entry_hmac coverage is non-monotonic (present, then absent —
        a possible field-strip downgrade; see below). Reports real K-of-N
        coverage counts; never claims rows were "checked" when a gap means
        they weren't.
      - journal_anchor — warns when the external systemd-journal witness is
        unavailable or has no entries for this case (WS1c(A)). Unlike the
        two warnings above, this check DOES fail closed (flips "ok") on an
        actual disagreement between the on-disk chain and what the journal
        witnessed for the same (case_id, seq) — that disagreement is the
        signature of the A1-H2 re-derive-forward attack.
    Residual E is now CLOSED: Check 5 also verifies every evidence file
    directly from its chained evidence_register audit row (source of truth),
    so emptying manifest.yaml's evidence[] no longer makes it vacuous.
    WS1c CLOSES the "STILL-OPEN" gap this docstring used to describe here
    (the chain_anchor sidecar living inside the case directory, and thus
    deletable alongside a truncated/re-derived chain) with two independent,
    additive, both-opt-in-or-graceful defenses — see _journal_anchor_check()
    and _hmac_advisory_check() above, and config.audit_journal_anchor_enabled()
    / config.audit_hmac_key(). Neither is sold as tamper-proof against a
    same-OS-user attacker who controls the whole machine AND (for HMAC) the
    configured key — journal_anchor helps only when journald is reachable
    and its history covers the tampered seq; audit_hmac helps only when
    HMAC was turned on before the tamper and the attacker lacks the key.

    HONEST RESIDUAL — HMAC full-strip (raised in the WS1c adversarial
    review): entry_hmac is an ordinary, attacker-controlled JSON field with
    no protection of its own presence. verify_chain()'s monotonic-coverage
    check (see the `elif seen_entry_hmac and hmac_key` branch there) catches
    a PARTIAL strip — entry_hmac present on some rows, then missing from a
    later one — fail-closed, whenever a key is configured. But if the
    attacker deletes entry_hmac from EVERY row in the chain, coverage goes
    from "0 of N" to "0 of N": monotonic holds vacuously, and the result is
    byte-for-byte indistinguishable from a chain that never used the HMAC
    feature at all. No amount of internal-only checking can close this —
    there is nothing left inside the case directory to compare against.
    The systemd-journal anchor (journal_anchor, above) is the actual
    backstop for a full strip, WHEN journald is reachable and its history
    covers the tampered seq: it independently witnessed entry_sha256 at
    append() time, which changes under any re-derive-forward tamper
    regardless of what happens to entry_hmac. When journald is not
    reachable (or has no history that far back) AND every entry_hmac was
    stripped, a full-strip A1-H2 attack is undetected by this module.

    Returns:
        {"ok": bool, "checks": {name: {"passed": bool, "detail": str}}, ...}
    """
    from pathlib import Path
    import yaml

    case_path = Path(case_dir)
    case_name = case_path.name
    report = {"ok": True, "case_dir": str(case_dir), "checks": {}}

    # ── Load audit entries ──
    audit_path = case_path / "audit.jsonl"
    entries = []
    if audit_path.exists():
        with open(audit_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    # ── Check 1: SHA-256 chain ──
    chain_ok, chain_reason = verify_chain(case_dir)
    report["checks"]["chain"] = {"passed": chain_ok, "detail": chain_reason}
    if not chain_ok:
        report["ok"] = False

    # ── Check 1b: chain-anchor presence (residual A, advisory only) ──
    # KNOWN OPEN GAP — see _update_chain_anchor()'s docstring: the anchor
    # sidecar lives in the same case directory as audit.jsonl, so deleting
    # it alongside a tail-truncated chain makes verify_chain()'s tail
    # check fail OPEN (silently skipped). Make that silence LOUD here
    # instead — a chain with rows but no anchor is a visible warning, not
    # a clean bill of health. Advisory only (does not flip report["ok"],
    # same stance as phase_coverage below): plenty of legitimate chains
    # never had an append()-written anchor to begin with — test fixtures
    # that write audit.jsonl directly, or cases predating this feature —
    # and must not be red-lined for that alone. The real close (an
    # anchor outside the case directory / OS trust boundary) is WS1b.
    if entries and not _read_chain_anchor(case_dir):
        report["checks"]["chain_anchor"] = {
            "passed": False,
            "detail": (
                "audit.jsonl has rows but audit_chain_anchor.json is "
                "missing — chain predates this feature, was built without "
                "append(), or the anchor was deleted; tail-truncation "
                "detection is silently unavailable either way (not "
                "cryptographically anchored — see WS1b)"
            ),
        }
    else:
        report["checks"]["chain_anchor"] = {"passed": True, "detail": "ok"}

    # ── Check 1c: external systemd-journal anchor (WS1c(A)) ──
    # See _journal_anchor_check()'s docstring. Unlike chain_anchor above
    # (a sidecar an attacker with case-dir write access can delete right
    # alongside a truncated/re-derived chain), this witness lives OUTSIDE
    # the case directory entirely — a same-OS-user attacker can append to
    # the journal but not rewrite it. Absence of journal data is advisory
    # (does not flip report["ok"]); an actual disagreement is fail-closed.
    case_name_for_journal = case_path.name
    journal_check = _journal_anchor_check(case_dir, case_name_for_journal, entries)
    report["checks"]["journal_anchor"] = {
        "passed": journal_check["passed"], "detail": journal_check["detail"],
    }
    if journal_check.get("violation"):
        report["ok"] = False

    # ── Check 1d: opt-in HMAC anchor advisory (WS1c(B)) ──
    # The fail-closed HMAC recompute already runs inside verify_chain()
    # above (folded into the "chain" check); this only surfaces the
    # separate "rows carry entry_hmac but no key is configured to check
    # it" state transparently, same advisory stance as chain_anchor.
    report["checks"]["audit_hmac"] = _hmac_advisory_check(entries)

    # ── Check 2: Audit↔disk consistency ──
    # Every finding_id in audit rows MUST have a YAML on disk
    findings_dir = case_path / "findings"
    yaml_finding_ids = set()
    if findings_dir.exists():
        for yf in sorted(findings_dir.glob("F-*.yaml")):
            yaml_finding_ids.add(yf.stem)
        # W4-5: a finding retired by a Phase-3 re-run still exists on disk.
        for yf in sorted((findings_dir / "superseded").glob("F-*.yaml")):
            yaml_finding_ids.add(yf.stem)

    audit_finding_ids = set()
    for e in entries:
        fid = e.get("finding_id")
        if fid:
            audit_finding_ids.add(fid)

    audit_only = audit_finding_ids - yaml_finding_ids
    disk_only = yaml_finding_ids - audit_finding_ids
    audit_disk_ok = len(audit_only) == 0 and len(disk_only) == 0
    audit_disk_detail = "ok"
    problems = []
    if audit_only:
        problems.append(f"{len(audit_only)} finding(s) in audit but not on disk: {sorted(audit_only)[:5]}")
    if disk_only:
        problems.append(f"{len(disk_only)} finding(s) on disk but not in audit: {sorted(disk_only)[:5]}")
    if problems:
        audit_disk_detail = "; ".join(problems)
    report["checks"]["audit_disk"] = {"passed": audit_disk_ok, "detail": audit_disk_detail}
    if not audit_disk_ok:
        report["ok"] = False

    # ── Check 3: case_id consistency ──
    # Most audit rows record case_id = Path(case_dir).name (e.g.
    # "002-a8-sha-tamper"); a few call sites instead pass the bare
    # manifest["case_id"] numeric prefix (e.g. "002") — both legitimately
    # identify the SAME case (A8-F2 bonus: this used to false-positive on
    # every case that reached Phase 6, since that row wrote the bare form).
    # Some of those call sites have been standardized on the directory-name
    # form (see phase_runner.py's audit_case_id), but rather than chase
    # every remaining bare-id writer across the codebase one at a time,
    # accept either form here — the check should only fire on a row that
    # names a genuinely DIFFERENT case, not a cosmetic id-format choice.
    case_num_prefix = case_name.split("-")[0] if "-" in case_name else case_name
    mismatched = []
    for e in entries:
        e_case = e.get("case_id", "")
        if e_case and e_case != case_name and e_case != case_num_prefix:
            mismatched.append(f"seq {e.get('seq', '?')}: audit={e_case} dir={case_name}")
    case_id_ok = len(mismatched) == 0
    case_id_detail = "ok" if case_id_ok else f"{len(mismatched)} mismatches: {'; '.join(mismatched[:5])}"
    report["checks"]["case_id"] = {"passed": case_id_ok, "detail": case_id_detail}
    if not case_id_ok:
        report["ok"] = False

    # ── Check 4: Phase coverage ──
    # R1-F12: every ACTIVE finding needs its finding_create (Phase 3) and
    # adversarial_review (Phase 5) rows, and a report row (phase_step
    # S3-merge-report — the row Phase 6 actually writes; the old
    # `report_generated` action was never written by anything) chained
    # AFTER its registration. Superseded (W4-5) and analyst-excluded
    # findings never reach Phases 5/6 and are exempt. On a COMPLETED case
    # (one that has a report row) a gap is a real inconsistency — e.g. a
    # stale report after a Phase-3 re-run — and fails closed; before
    # Phase 6 it is advisory (a finding in progress legitimately hasn't
    # reached every phase yet).
    from spectre.core.validators import finding_location as _floc
    from spectre.core.validators import supersede_brackets as _sbr
    _honored_cov = _sbr(entries)["honored"]
    _reg_rows: dict[str, int] = {}
    _loc: dict[str, str] = {}
    _reviewed: set[str] = set()
    _report_idx = [i for i, e in enumerate(entries)
                   if e.get("phase_step") == "S3-merge-report"]
    for i, e in enumerate(entries):
        fid = e.get("finding_id")
        if not fid:
            continue
        action = e.get("action", "")
        if action == "finding_create":
            _reg_rows[fid] = i
            _loc[fid] = _floc(e.get("output_path") or f"{fid}.yaml")
        elif action == "finding_supersede" and i in _honored_cov:
            _loc[fid] = _floc(e.get("output_path") or "")
        elif action == "adversarial_review":
            _reviewed.add(fid)

    phase_gaps = []
    for fid in sorted(audit_finding_ids):
        if fid not in _reg_rows:
            phase_gaps.append(f"{fid}: missing ['finding_create']")
            continue
        if _loc.get(fid, "").startswith(("superseded/", "excluded/")):
            continue
        missing = []
        if fid not in _reviewed:
            missing.append("adversarial_review")
        if not any(i > _reg_rows[fid] for i in _report_idx):
            missing.append("report (S3-merge-report)")
        if missing:
            phase_gaps.append(f"{fid}: missing {missing}")
    phase_ok = len(phase_gaps) == 0
    _completed = bool(_report_idx)
    if phase_ok:
        phase_detail = "ok"
    else:
        phase_detail = (f"{len(phase_gaps)} findings with gaps: "
                        + "; ".join(phase_gaps[:5]))
        if not _completed:
            phase_detail += " (advisory — case has no report yet)"
    report["checks"]["phase_coverage"] = {"passed": phase_ok, "detail": phase_detail}
    if not phase_ok and _completed:
        report["ok"] = False

    # ── Check 5: Evidence integrity ──
    # Residual E is now CLOSED by the audit-row-driven loop appended AFTER
    # this manifest block (which re-hashes every evidence_register row's
    # output_path independent of manifest.yaml). Historical context for the
    # manifest-driven portion below: this part is driven off manifest.yaml's
    # evidence[] list. manifest.yaml is a plain mutable file (H3's premise
    # elsewhere in this function already exploits that for the sha256
    # field specifically) — emptying the LIST ITSELF (manifest["evidence"]
    # = []) takes the `if evidence_list:` branch below to False and skips
    # this entire check, including the H3 cross-check against the chained
    # evidence_register row. The result is a vacuous PASS: real evidence
    # was registered (real evidence_register audit rows exist), but
    # nothing here ever looks at them unless manifest.yaml still lists the
    # path. TODO(WS1b): drive evidence verification from the
    # evidence_register audit rows themselves (source of truth, chain-
    # protected) rather than from manifest.yaml's evidence[] (mutable,
    # attacker-editable) — e.g. enumerate every evidence_register row's
    # output_path and re-hash each one directly, independent of whatever
    # manifest.yaml currently claims.
    manifest_path = case_path / "manifest.yaml"
    evidence_ok = True
    evidence_detail = "ok (no manifest or no evidence)"
    if manifest_path.exists():
        try:
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f) or {}
        except Exception:
            manifest = {}
        evidence_list = manifest.get("evidence", [])
        if evidence_list:
            mismatch_list = []
            # A1-H3: manifest.yaml is a plain, always-mutable file — not
            # chmod 444 like the evidence copy, not part of the SHA-256
            # audit chain. Tampering the evidence FILE and then rewriting
            # manifest.yaml's sha256 to match the new content defeats the
            # plain re-hash-vs-manifest check below (both agree with each
            # other), without touching audit.jsonl at all. Cross-check
            # against the chained evidence_register row for the same path
            # instead — it holds the hash recorded at ingest time and can't
            # be edited without breaking verify_chain(). A manifest entry
            # with NO matching audit row (legacy manifest, or a fixture
            # built outside case_setup.py's registration path) has nothing
            # to cross-check against — that's not itself a failure, same
            # "can't prove, don't fail" stance as the finding-hash backfill.
            # W3-7 (R1-F10): every recorded path is resolved into THIS case
            # directory (relative rows, and legacy absolute rows re-rooted),
            # so a relocated case verifies its own bytes, never the original
            # location's.
            registered_sha_by_path = {}
            for e in entries:
                if e.get("action") == "evidence_register" and e.get("output_path"):
                    _rp = try_resolve(case_dir, e["output_path"])
                    if _rp is not None:
                        registered_sha_by_path[str(_rp)] = e.get("output_sha256")
            for ev in evidence_list:
                ev_path_str = ev.get("evidence_relpath") or ev.get("evidence_path", "")
                ev_sha = ev.get("sha256", "")
                if ev_path_str and ev_sha:
                    ev_path = try_resolve(case_dir, ev_path_str)
                    if ev_path is None:
                        mismatch_list.append(
                            f"{Path(ev_path_str).name}: manifest path is outside the "
                            f"case directory — refused")
                        continue
                    if ev_path.exists():
                        try:
                            current_sha = hashlib.sha256(ev_path.read_bytes()).hexdigest()
                            if current_sha != ev_sha:
                                mismatch_list.append(
                                    f"{ev_path.name}: manifest={ev_sha[:16]}... actual={current_sha[:16]}..."
                                )
                        except Exception as e:
                            mismatch_list.append(f"{ev_path.name}: cannot read ({e})")
                    else:
                        mismatch_list.append(f"{ev_path.name}: file missing")

                    registered_sha = registered_sha_by_path.get(str(ev_path))
                    if registered_sha and registered_sha != ev_sha:
                        mismatch_list.append(
                            f"{ev_path.name}: manifest sha256 disagrees with chained "
                            f"evidence_register row (manifest={ev_sha[:16]}..., "
                            f"audited={registered_sha[:16]}...)"
                        )
            evidence_ok = len(mismatch_list) == 0
            evidence_detail = "ok" if evidence_ok else f"{len(mismatch_list)} mismatches: {'; '.join(mismatch_list[:5])}"

    # ── Residual E CLOSED (WS1b): verify from the chained evidence_register
    # rows directly, independent of manifest.yaml. These rows are inside the
    # SHA-256 chain (verify_chain protects them), so emptying or editing
    # manifest["evidence"] can no longer make evidence verification vacuous.
    # Re-hash every registered evidence copy against the hash recorded at
    # ingest; a missing or changed file fails closed even with no manifest.
    # W3-2/W3-7: the same helper gates every phase entry (runner.run_phase),
    # so Phase 7 and phase entry can never disagree about what "intact" means.
    audit_mismatch = evidence_problems(case_dir, entries)
    if audit_mismatch:
        evidence_ok = False
        extra = (f"{len(audit_mismatch)} audit-row mismatch(es): "
                 f"{'; '.join(audit_mismatch[:5])}")
        evidence_detail = extra if evidence_detail.startswith("ok") else f"{evidence_detail} | {extra}"

    report["checks"]["evidence"] = {"passed": evidence_ok, "detail": evidence_detail}
    if not evidence_ok:
        report["ok"] = False

    # ── Check 6: report.md integrity ──
    # report.md is the single source of truth for the case. Audit rows record
    # its sha256; nothing compared them to disk, so a post-Phase-6 rewrite was
    # invisible. Scoped to report.md only — report.docx is intentionally
    # examiner-edited during Phase 7 approval.
    #
    # Further scoped to phase_step == "S3-merge-report": those rows, and only
    # those, record the Phase 6 deliverable write (phase_runner.py appends them
    # after _merge_report_md; the host flow in skills/report-generator/SKILL.md
    # mirrors them). Any other row naming report.md carries a sha256 that does
    # not describe the deliverable, and must not arm the check.
    #
    # Scope only. Detection is unchanged: no S3-merge-report row still takes
    # the abstain branch below, and an S3 row whose hash misses still fails
    # closed. FIXED: the Phase-5-resume false positive this scoping used to
    # paper over is now fixed at the writer — `explain._write_report`, which
    # used to clobber report.md with a single-finding stub on every
    # explain(persist=True) call and audited no sha256, has been removed
    # entirely. Phase 6's `_merge_report_md` is the sole report.md writer, so
    # a Phase-5 resume under an API provider no longer rewrites the deliverable
    # out from under the S3-merge-report row, and this check no longer sees a
    # spurious mismatch to (not) mask.
    report_rows = [
        e for e in entries
        if str(e.get("output_path", "")).endswith("report.md")
        and e.get("output_sha256")
        and e.get("phase_step") == "S3-merge-report"
    ]
    if not report_rows:
        report["checks"]["report_integrity"] = {
            "passed": True,
            "detail": "no report.md audit row — case has not reached Phase 6",
        }
    else:
        latest = report_rows[-1]
        rpath = try_resolve(case_dir, latest["output_path"])
        if rpath is None:
            report["checks"]["report_integrity"] = {
                "passed": False,
                "detail": f"report.md row path is outside the case: {latest['output_path']}",
            }
            report["ok"] = False
        elif not rpath.exists():
            report["checks"]["report_integrity"] = {
                "passed": False,
                "detail": f"report.md recorded in audit but missing on disk: {rpath}",
            }
            report["ok"] = False
        else:
            try:
                actual = hashlib.sha256(rpath.read_bytes()).hexdigest()
                if actual == latest["output_sha256"]:
                    report["checks"]["report_integrity"] = {
                        "passed": True,
                        "detail": f"report.md matches audited sha256 ({actual[:12]}…)",
                    }
                else:
                    report["checks"]["report_integrity"] = {
                        "passed": False,
                        "detail": (f"report.md modified after audit — recorded "
                                   f"{latest['output_sha256'][:12]}…, found {actual[:12]}…"),
                    }
                    report["ok"] = False
            except Exception as e:
                report["checks"]["report_integrity"] = {
                    "passed": False,
                    "detail": f"report.md exists but cannot read ({e})",
                }
                report["ok"] = False

    # ── Check 6b: narrative grounding (drift detection) ──
    # See _narrative_grounding_check docstring: this is a drift detector, not
    # an adversarial control. It flags accidental omission of the
    # S2-validate-report row on an AI-narrative run; it does not defend
    # against an agent that forges both the report and a matching row.
    ng = _narrative_grounding_check(case_dir)
    report["checks"]["narrative_grounding"] = ng
    if not ng["passed"]:
        report["ok"] = False

    # ── Check 6c: dashboard-metrics binding (TB-port A6, advisory) ──
    report["checks"]["dashboard_metrics"] = _dashboard_metrics_check(
        manifest_path, entries)

    # ── Check 7: Derived evidence integrity ──
    # manifest["derived_evidence"] = {path: {sha256, derived_from, ...}} —
    # carved artifacts (e.g. an EVTX carved out of a disk image) are real
    # evidence in their own right and must be re-hashed on every verify,
    # same as primary manifest["evidence"].
    derived_ok = True
    derived_detail = "ok (no manifest or no derived evidence)"
    if manifest_path.exists():
        try:
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f) or {}
        except Exception:
            manifest = {}
        derived_map = manifest.get("derived_evidence", {})
        if derived_map:
            derived_mismatch_list = []
            for dpath_str, dinfo in derived_map.items():
                d_sha = dinfo.get("sha256", "") if isinstance(dinfo, dict) else ""
                if not d_sha:
                    continue
                dpath = try_resolve(case_dir, dpath_str)
                if dpath is None:
                    derived_mismatch_list.append(f"{dpath_str}: outside the case — refused")
                elif dpath.exists():
                    try:
                        current_sha = hashlib.sha256(dpath.read_bytes()).hexdigest()
                        if current_sha != d_sha:
                            derived_mismatch_list.append(
                                f"{dpath_str}: manifest={d_sha[:16]}... actual={current_sha[:16]}..."
                            )
                    except Exception as e:
                        derived_mismatch_list.append(f"{dpath_str}: cannot read ({e})")
                else:
                    derived_mismatch_list.append(f"{dpath_str}: file missing")
            derived_ok = len(derived_mismatch_list) == 0
            derived_detail = "ok" if derived_ok else \
                f"{len(derived_mismatch_list)} mismatches: {'; '.join(derived_mismatch_list[:5])}"
    report["checks"]["derived_evidence"] = {"passed": derived_ok, "detail": derived_detail}
    if not derived_ok:
        report["ok"] = False

    # ── Check 7b: derived artifacts Phase 3 consumes (W3-1, R2-04/R2-16) ──
    # normalized_events.json, _handles.json and directives.json each carry a
    # chained sha256 row (derived_artifact / directives_synthesized). Re-hash
    # the latest row per file; a changed or missing file fails closed — a
    # forged event stream would otherwise surface as a deterministic finding
    # with every other check green. Legacy cases with no such rows abstain.
    n_derived, derived_problems = derived_artifact_problems(case_dir, entries)
    if derived_problems:
        report["checks"]["derived_artifacts"] = {
            "passed": False,
            "detail": (f"{len(derived_problems)} mismatch(es): "
                       + "; ".join(derived_problems[:5])),
        }
        report["ok"] = False
    else:
        report["checks"]["derived_artifacts"] = {
            "passed": True,
            "detail": (f"ok ({n_derived} recorded derived artifact(s) match)"
                       if n_derived else
                       "ok (no derived-artifact rows — legacy case or pre-Phase-1)"),
        }

    # ── Check 8: Finding YAML content integrity ──
    # A finding's own YAML is chain-of-custody evidence (see the README Architecture
    # section on chain of custody), but no audit row recorded its content hash
    # until now — emit_finding.py hardcoded output_sha256="" — so a
    # post-creation edit (status, confidence, MITRE ID, deleted
    # forensic_caveats...) was invisible here (A1-H1).
    #
    # A finding file can legitimately be rewritten more than once (emit,
    # then explain()'s persisted description/mitre/caveats patch), each
    # leaving its own row naming the same output_path/finding_id. The
    # LATEST row (by seq, i.e. append order — `entries` is already in file
    # order) that carries a non-empty output_sha256 is authoritative.
    #
    # core/emit_finding.py's finding_create row is a special case: it is
    # written before the file exists, so its output_sha256 is empty. That
    # module's LATER finding_status row (written after the file is on disk)
    # carries the real hash instead, and is what this check finds as
    # "latest".
    #
    # Backfill: a finding with NO row carrying any hash at all (legacy
    # finding created before this existed, or a hand-built test fixture)
    # is a WARNING, not a failure — nothing to compare against. A row
    # WITH a hash that disagrees with current content IS a failure.
    finding_integrity_ok = True
    finding_integrity_problems = []
    finding_integrity_warnings = 0
    all_finding_files = []
    if findings_dir.exists():
        all_finding_files.extend(sorted(findings_dir.glob("F-*.yaml")))
        for _sub in ("excluded", "superseded"):
            _d = findings_dir / _sub
            if _d.exists():
                all_finding_files.extend(sorted(_d.glob("F-*.yaml")))

    # Hash authority (R2-13 / W2-A review round 2): once a case has any
    # deterministic `finding_create` registration, a finding file counts
    # only if it was registered, and its baseline may be advanced only by an
    # allowlisted authority row (emit, core finding_status, persisted
    # explain) chained AFTER that registration. A hash-bearing row from any
    # other writer is a violation (it would otherwise bless an edit), and an
    # unregistered finding file is a violation (planted). A case with no
    # registration rows at all keeps the legacy "latest hashed row" rule.
    from spectre.core.validators import (
        finding_location, finding_path_matches, is_finding_hash_authority,
        is_finding_registration, supersede_brackets,
    )
    _any_registration = any(is_finding_registration(e) for e in entries)
    # W4 review: a supersede row counts (as a hash authority AND a location
    # re-bind) only inside a completed Phase-3 re-run bracket.
    _brackets = supersede_brackets(entries)
    _honored_sup = _brackets["honored"]
    # B8: one finding ID at more than one path (e.g. an analyst-excluded
    # finding copied back from findings/excluded/ into findings/) is a
    # violation in its own right, whatever the bytes say.
    if _any_registration:
        _stems: dict[str, int] = {}
        for yf in all_finding_files:
            _stems[yf.stem] = _stems.get(yf.stem, 0) + 1
        for _fid, _n in sorted(_stems.items()):
            if _n > 1:
                finding_integrity_problems.append(
                    f"{_fid}: present at {_n} paths (findings/, excluded/, superseded/)")
                finding_integrity_ok = False
    for yf in all_finding_files:
        fid = yf.stem
        if _any_registration:
            reg_idx = None
            for i, e in enumerate(entries):
                if e.get("finding_id") == fid and is_finding_registration(e):
                    reg_idx = i
            if reg_idx is None:
                finding_integrity_problems.append(
                    f"{fid}: not registered by a deterministic finding_create row")
                finding_integrity_ok = False
                continue
            # B8: a registration is bound to the location it wrote (active
            # vs excluded/); a file anywhere else is not that finding. W4-5:
            # a later finding_supersede authority row re-binds it to
            # superseded/.
            _reg_op = str(entries[reg_idx].get("output_path") or "")
            for _j in range(reg_idx + 1, len(entries)):
                _e = entries[_j]
                if _e.get("finding_id") == fid and _j in _honored_sup \
                        and _e.get("output_path"):
                    _reg_op = str(_e["output_path"])
            if _reg_op and finding_location(_reg_op) != finding_location(yf):
                finding_integrity_problems.append(
                    f"{fid}: registered at findings/{finding_location(_reg_op)}, "
                    f"found at findings/{finding_location(yf)}")
                finding_integrity_ok = False
                continue
            # L2: compared on the RESOLVED path relative to case_dir, so a
            # symlink out of the case is not the registered finding.
            if not finding_path_matches(case_dir, yf,
                                        finding_location(_reg_op) if _reg_op else "",
                                        _reg_op):
                finding_integrity_problems.append(
                    f"{fid}: findings/{finding_location(yf)} resolves outside "
                    f"its registered location")
                finding_integrity_ok = False
                continue
            _after_idx = [j for j in range(reg_idx, len(entries))
                          if entries[j].get("finding_id") == fid
                          and entries[j].get("output_sha256")]
            after = [entries[j] for j in _after_idx]
            foreign = [entries[j] for j in _after_idx
                       if not (is_finding_hash_authority(entries[j])
                               or j in _honored_sup)]
            if foreign:
                finding_integrity_problems.append(
                    f"{fid}: {len(foreign)} non-authority row(s) carry a content "
                    f"hash (actor={foreign[-1].get('actor')!r}, "
                    f"step={foreign[-1].get('phase_step')!r})")
                finding_integrity_ok = False
                continue
            hashed_rows = after
        else:
            hashed_rows = [
                e for e in entries
                if e.get("finding_id") == fid and e.get("output_sha256")
            ]
        if not hashed_rows:
            finding_integrity_warnings += 1
            continue
        latest = hashed_rows[-1]
        try:
            actual = hashlib.sha256(yf.read_bytes()).hexdigest()
        except Exception as e:
            finding_integrity_problems.append(f"{fid}: cannot read ({e})")
            finding_integrity_ok = False
            continue
        if actual != latest["output_sha256"]:
            finding_integrity_problems.append(
                f"{fid}: recorded {latest['output_sha256'][:12]}…, found {actual[:12]}…"
            )
            finding_integrity_ok = False

    detail_parts = []
    if finding_integrity_problems:
        detail_parts.append(
            f"{len(finding_integrity_problems)} mismatch(es): "
            + "; ".join(finding_integrity_problems[:5])
        )
    if finding_integrity_warnings:
        detail_parts.append(
            f"{finding_integrity_warnings} finding(s) with no recorded hash (legacy, skipped)"
        )
    finding_integrity_detail = "; ".join(detail_parts) if detail_parts else "ok"
    report["checks"]["finding_integrity"] = {
        "passed": finding_integrity_ok,
        "detail": finding_integrity_detail,
    }
    if not finding_integrity_ok:
        report["ok"] = False

    # ── Check 8b: supersede batches (W4 review MED-1 / LOW) ──
    # Every finding_supersede row must sit in a Phase-3 re-run bracket that
    # COMPLETED (start row before, completion row after). And when a run
    # completes, every finding registered before it started must have been
    # retired by then — otherwise the case holds a half-replaced finding set
    # (a crash mid re-run) that a later report would present as the truth.
    sb_problems = []
    for _i in sorted(_brackets["unbracketed"]):
        sb_problems.append(f"{entries[_i].get('finding_id')}: finding_supersede "
                           f"row (seq {entries[_i].get('seq', '?')}) outside any "
                           f"Phase-3 run bracket")
    for _i in sorted(_brackets["open"]):
        sb_problems.append(f"{entries[_i].get('finding_id')}: superseded by Phase-3 "
                           f"run {(entries[_i].get('params') or {}).get('run_id')} "
                           f"that never completed")
    _reg_at = {}
    for _i, _e in enumerate(entries):
        if is_finding_registration(_e) and _e.get("finding_id"):
            _reg_at.setdefault(_e["finding_id"], _i)
    for _ci, _rid, _closes in _brackets["completes"]:
        _st = _brackets["starts"].get(_rid)
        if _st is None or _st > _ci:
            sb_problems.append(f"Phase-3 completion row (seq "
                               f"{entries[_ci].get('seq', '?')}) has no start row")
            continue
        _retired = {entries[j].get("finding_id") for j in _honored_sup if j < _ci}
        _left = sorted(f for f, ri in _reg_at.items() if ri < _st and f not in _retired)
        if _left:
            sb_problems.append(f"Phase-3 run {_rid} completed with "
                               f"{len(_left)} prior finding(s) still active: {_left[:5]}")
    report["checks"]["supersede_batches"] = {
        "passed": not sb_problems,
        "detail": "; ".join(sb_problems[:5]) if sb_problems else (
            "ok" if _brackets["completes"] or _brackets["honored"]
            else "ok (no Phase-3 re-run brackets)"),
    }
    if sb_problems:
        report["ok"] = False

    # ── Check 9: coverage disclosure (closes the vacuous PASS) ──
    # The chain records what was never examined (`coverage_gap` rows from
    # Phase 0 and Phase 2). The report's S3-merge-report row records what the
    # report disclosed. This asserts the second covers the first.
    #
    # Why this binding and not a prose grep: report_integrity already ties the
    # S3 row's hash to the report bytes on disk, so a report regenerated with a
    # disclosure removed cannot keep the old row, and a FRESH S3 row carrying a
    # shorter receipt fails HERE. Grepping the report text instead would couple
    # this module to report wording — the first reword would either break
    # verification or, worse, silently stop detecting anything.
    #
    # Fails closed on a shortfall. Abstains only when the case has not reached
    # Phase 6, or when the chain charged no gaps at all.
    from spectre.pipeline.coverage import chained_gaps

    charged = chained_gaps(entries)
    s3_rows = [e for e in entries if e.get("phase_step") == "S3-merge-report"]
    if not charged:
        coverage_ok, coverage_detail = True, (
            "ok (no coverage_gap rows — every registered evidence item was "
            "examined, or the case predates coverage chaining)")
    elif not s3_rows:
        coverage_ok, coverage_detail = True, (
            f"{len(charged)} coverage gap(s) chained; case has not reached "
            f"Phase 6, so there is no report to have disclosed them")
    else:
        receipt = (s3_rows[-1].get("params") or {}).get(
            "disclosed_coverage_gaps")
        if receipt is None:
            # Gaps are chained but the report writer recorded no receipt. Fail
            # closed: a missing receipt is exactly what dropping the
            # disclosures produces, and there is no way to tell the two apart
            # from here. A host-driven Phase 6 must write the field —
            # skills/report-generator/SKILL.md documents it.
            coverage_ok = False
            coverage_detail = (
                f"{len(charged)} coverage gap(s) chained but the "
                f"S3-merge-report row carries no disclosed_coverage_gaps "
                f"receipt — cannot confirm the report disclosed them")
        else:
            disclosed: dict[str, int] = {}
            for item in receipt:
                if not isinstance(item, dict):
                    continue
                key = item.get("key")
                if not key:
                    continue
                try:
                    n = int(item.get("count") or 0)
                except (TypeError, ValueError):
                    n = 0
                disclosed[key] = max(disclosed.get(key, 0), n)
            shortfalls = []
            for key, n in sorted(charged.items()):
                if key not in disclosed:
                    shortfalls.append(f"{key} (×{n}) not disclosed at all")
                elif disclosed[key] < n:
                    shortfalls.append(
                        f"{key}: chain charged ×{n}, report disclosed "
                        f"×{disclosed[key]}")
            coverage_ok = not shortfalls
            coverage_detail = (
                f"ok ({len(charged)} chained gap(s) all disclosed)"
                if coverage_ok else
                f"{len(shortfalls)} undisclosed coverage gap(s): "
                + "; ".join(shortfalls[:5]))
    report["checks"]["coverage_disclosure"] = {
        "passed": coverage_ok, "detail": coverage_detail,
    }
    if not coverage_ok:
        report["ok"] = False

    return report
