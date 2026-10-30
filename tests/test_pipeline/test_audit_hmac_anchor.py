"""WS1c(B) — opt-in stdlib HMAC over the audit chain (A1-H3 hand-off
attacker: the case directory is copied to a party with full read/write
access to their copy, e.g. opposing counsel). Without the key sourced from
OUTSIDE the case directory (SPECTRE_AUDIT_HMAC_KEY / SPECTRE_AUDIT_HMAC_KEYFILE
— see config.audit_hmac_key()), they cannot recompute a valid entry_hmac
after tampering a row and re-deriving prev_sha256/entry_sha256 forward the
way the A1-H2 attack does (see test_verify.py's test_tamper_breaks_verify_chain
and test_chain_tail_truncation.py for the established re-derive pattern this
mirrors).

Must NEVER be sold as defending the same-OS-user attacker who already has
the key available wherever Spectre read it from — only the hand-off
attacker who does not.

These tests force the journal anchor OFF (SPECTRE_AUDIT_JOURNAL_ANCHOR=0) so
they isolate the HMAC layer; the journal anchor has its own test module.
"""
import hashlib
import json

import pytest

from spectre.pipeline import audit
from spectre.pipeline.audit import append, verify_chain, verify_full


def _canon(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _rederive_forward(rows, from_index, strip_hmac):
    """Mimic the A1-H2 CONFIRMED attack: after tampering rows[from_index]'s
    content (caller does that before calling this), recompute
    prev_sha256/entry_sha256 forward for rows[from_index:] so the SHA-256
    chain stays internally self-consistent -- the attacker lacks the HMAC
    key, so they cannot also forge a matching entry_hmac. `strip_hmac`
    controls what they do instead: delete the (now-invalid) entry_hmac
    field on every row they touch, rather than leaving a stale one behind
    (leaving it stale is covered by test_hmac_detects_tamper_and_rederive_attack
    -- this helper is for the field-STRIP variant)."""
    prev_sha = rows[from_index - 1]["entry_sha256"] if from_index > 0 else "0" * 64
    for i in range(from_index, len(rows)):
        rows[i]["prev_sha256"] = prev_sha
        body = {k: v for k, v in rows[i].items() if k not in ("entry_sha256", "entry_hmac")}
        new_sha = hashlib.sha256(_canon(body).encode()).hexdigest()
        rows[i]["entry_sha256"] = new_sha
        prev_sha = new_sha
        if strip_hmac:
            rows[i].pop("entry_hmac", None)
    return rows


@pytest.fixture(autouse=True)
def _no_journal_anchor(monkeypatch):
    # Isolate: these tests exercise the HMAC layer only.
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "0")


@pytest.fixture(autouse=True)
def _no_hmac_key_by_default(monkeypatch):
    # Belt-and-suspenders: don't inherit a real developer key from the
    # ambient environment this test happens to run in.
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEYFILE", raising=False)


def _append_n(case_dir, n):
    for i in range(n):
        append(str(case_dir), {
            "actor": "test", "action": "note", "tool": "x",
            "case_id": case_dir.name, "output_path": "",
            "output_sha256": "", "result": "success",
            "phase": 0, "phase_step": f"row-{i}",
        })


def _read_rows(case_dir):
    rows = []
    with open(case_dir / "audit.jsonl") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ── Backward compatibility: no key configured ────────────────────────────
def test_no_key_no_entry_hmac_field_written(tmp_path):
    case_dir = tmp_path / "case-no-key"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    rows = _read_rows(case_dir)
    assert all("entry_hmac" not in r for r in rows), (
        "entry_hmac must not appear on rows when no HMAC key is configured"
    )
    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


def test_no_key_verify_full_unaffected(tmp_path):
    case_dir = tmp_path / "case-no-key-full"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    report = verify_full(str(case_dir))
    assert report["ok"] is True
    assert report["checks"]["chain"]["passed"] is True
    # No HMAC in use at all -> silent, not a loud advisory.
    assert report["checks"]["audit_hmac"]["passed"] is True


# ── Round trip with a key configured ─────────────────────────────────────
def test_hmac_round_trip_clean_chain_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", "correct-horse-battery-staple")
    case_dir = tmp_path / "case-hmac-clean"
    case_dir.mkdir()
    _append_n(case_dir, 4)

    rows = _read_rows(case_dir)
    assert all("entry_hmac" in r and r["entry_hmac"] for r in rows), (
        "every row should carry entry_hmac once a key is configured"
    )

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason

    report = verify_full(str(case_dir))
    assert report["ok"] is True
    assert report["checks"]["audit_hmac"]["passed"] is True


def test_hmac_value_matches_manual_computation(tmp_path, monkeypatch):
    import hmac as hmac_mod

    key = "another-test-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-hmac-value"
    case_dir.mkdir()
    _append_n(case_dir, 1)

    rows = _read_rows(case_dir)
    row = rows[0]
    expected = hmac_mod.new(
        key.encode("utf-8"), row["entry_sha256"].encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert row["entry_hmac"] == expected


# ── Key sourced from a keyfile outside the case dir ──────────────────────
def test_hmac_key_from_keyfile(tmp_path, monkeypatch):
    keyfile = tmp_path / "outside-case" / "secret.key"
    keyfile.parent.mkdir()
    keyfile.write_text("keyfile-secret\n")
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEYFILE", str(keyfile))

    case_dir = tmp_path / "case-hmac-keyfile"
    case_dir.mkdir()
    _append_n(case_dir, 2)

    rows = _read_rows(case_dir)
    assert all("entry_hmac" in r for r in rows)
    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


# ── The A1-H2/H3 attack: tamper a row, re-derive the SHA chain forward ──
def test_hmac_detects_tamper_and_rederive_attack(tmp_path, monkeypatch):
    """Mirrors test_verify.py's test_tamper_breaks_verify_chain, but the
    attacker here also re-derives prev_sha256/entry_sha256 forward for
    every row after the tampered one (the A1-H2 CONFIRMED attack) — without
    HMAC, that reconstruction makes verify_chain() pass. With a key
    configured (and NOT known to the attacker, i.e. entry_hmac fields are
    left stale from before the tamper), it must fail closed."""
    key = "hand-off-defense-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-hmac-attack"
    case_dir.mkdir()
    _append_n(case_dir, 5)

    ok_before, _ = verify_chain(str(case_dir))
    assert ok_before is True

    rows = _read_rows(case_dir)

    # Tamper a middle row's content.
    mid = len(rows) // 2
    rows[mid]["phase_step"] = "TAMPERED_BY_test_hmac_detects_tamper"

    # Attacker (without the key) re-derives the SHA-256 chain forward,
    # exactly as A1-H2 describes, but leaves entry_hmac untouched (they
    # have no way to compute a valid replacement without the key).
    def _canon(body):
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    prev_sha = rows[mid - 1]["entry_sha256"] if mid > 0 else "0" * 64
    for i in range(mid, len(rows)):
        rows[i]["prev_sha256"] = prev_sha
        body = {k: v for k, v in rows[i].items() if k not in ("entry_sha256", "entry_hmac")}
        new_sha = hashlib.sha256(_canon(body).encode()).hexdigest()
        rows[i]["entry_sha256"] = new_sha
        prev_sha = new_sha
        # entry_hmac deliberately left as-is (stale) — attacker lacks the key.

    tampered_dir = tmp_path / "tampered-hmac-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    ok_after, reason = verify_chain(str(tampered_dir))
    assert ok_after is False, (
        "HMAC-aware verify_chain() must fail closed on the re-derived "
        "(tampered) chain"
    )
    assert "hmac" in reason.lower(), (
        f"failure should be attributable to the HMAC layer, got: {reason}"
    )


def test_hmac_mismatch_reason_mentions_hmac(tmp_path, monkeypatch):
    key = "hand-off-defense-key-2"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-hmac-attack-reason"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    rows = _read_rows(case_dir)
    # Directly corrupt just the last row's entry_hmac (simulating a stale
    # or forged value that no longer matches its entry_sha256).
    rows[-1]["entry_hmac"] = "0" * 64

    def _canon(body):
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    tampered_dir = tmp_path / "tampered-hmac-reason-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    ok, reason = verify_chain(str(tampered_dir))
    assert ok is False
    assert "hmac" in reason.lower()


# ── Advisory: rows carry entry_hmac, but no key configured to check it ──
def test_hmac_rows_present_no_key_is_advisory_not_failure(tmp_path, monkeypatch):
    key = "temp-key-for-writing"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-hmac-review-copy"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    # Now simulate reviewing this chain in an environment that doesn't
    # have the key (e.g. the recipient of a case hand-off).
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEY", raising=False)

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, (
        f"rows carrying entry_hmac with no key configured must not fail "
        f"verify_chain() (can't verify != tampered): {reason}"
    )

    report = verify_full(str(case_dir))
    assert report["checks"]["audit_hmac"]["passed"] is False, (
        "verify_full must surface an advisory when entry_hmac rows exist "
        "but no key is configured to check them"
    )
    assert report["ok"] is True, (
        "the audit_hmac advisory must not flip report['ok'] by itself"
    )


# ── Field-strip downgrade (Opus review finding) ───────────────────────────
# entry_hmac is an ordinary, attacker-controlled JSON field. A case-dir-
# write attacker can't forge a valid one after tampering (no key), but CAN
# simply delete it. Deletion after an earlier row carried one is a
# monotonic-coverage violation: legitimate use only ever toggles HMAC ON
# partway through a case (no-HMAC rows, then HMAC rows -- non-decreasing),
# never OFF again.
def test_hmac_partial_strip_with_key_fails_closed(tmp_path, monkeypatch):
    """The exact repro: tamper a middle row, re-derive the SHA chain
    forward, and STRIP (not leave stale) entry_hmac on every row from the
    tamper point on. With a key configured at verify time, this must be
    caught fail-closed -- a missing entry_hmac after an earlier row had one
    is itself the tamper signal, cryptographically confirmed by the key
    being present to prove the earlier rows' coverage was real."""
    key = "downgrade-detection-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-partial-strip-key"
    case_dir.mkdir()
    _append_n(case_dir, 5)

    rows = _read_rows(case_dir)
    assert all("entry_hmac" in r for r in rows)  # sanity: all rows covered before tamper

    mid = len(rows) // 2
    rows[mid]["phase_step"] = "TAMPERED_BY_test_hmac_partial_strip_with_key"
    _rederive_forward(rows, mid, strip_hmac=True)

    tampered_dir = tmp_path / "tampered-partial-strip-key-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    ok, reason = verify_chain(str(tampered_dir))
    assert ok is False, (
        "a partial entry_hmac strip after earlier rows carried one must "
        "fail closed when a key is configured -- this is the field-strip "
        "bypass the review flagged"
    )
    assert "downgrade" in reason.lower() or "strip" in reason.lower(), (
        f"failure reason should name this a downgrade/strip signal, not a "
        f"generic mismatch: {reason}"
    )

    report = verify_full(str(tampered_dir))
    assert report["ok"] is False
    assert report["checks"]["chain"]["passed"] is False


def test_hmac_partial_strip_no_key_is_loud_advisory(tmp_path, monkeypatch):
    """Same field-strip attack, but the reviewer doesn't have the key (a
    hand-off recipient). Without the key, verify_chain() cannot
    cryptographically prove tampering, so it must NOT hard-fail -- but the
    non-monotonic entry_hmac PATTERN is visible without any key at all, so
    verify_full() must surface it as a loud, accurately-worded advisory,
    and must never claim rows were "checked" when they were skipped."""
    key = "temp-build-key-for-strip-test"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-partial-strip-no-key"
    case_dir.mkdir()
    _append_n(case_dir, 5)
    rows = _read_rows(case_dir)

    mid = len(rows) // 2
    rows[mid]["phase_step"] = "TAMPERED_BY_test_hmac_partial_strip_no_key"
    _rederive_forward(rows, mid, strip_hmac=True)

    tampered_dir = tmp_path / "tampered-partial-strip-no-key-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    # Reviewer has no key.
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEY", raising=False)

    ok, reason = verify_chain(str(tampered_dir))
    assert ok is True, (
        f"without a key, verify_chain() can't cryptographically prove the "
        f"strip -- must not hard-fail: {reason}"
    )

    report = verify_full(str(tampered_dir))
    audit_hmac = report["checks"]["audit_hmac"]
    assert audit_hmac["passed"] is False, "the non-monotonic pattern must be a loud advisory"
    detail_lower = audit_hmac["detail"].lower()
    assert "downgrade" in detail_lower or "gap" in detail_lower or "non-monotonic" in detail_lower, (
        f"advisory should name the downgrade pattern: {audit_hmac['detail']}"
    )
    assert "checked as part of the chain check" not in audit_hmac["detail"], (
        "must never claim the skipped rows were checked"
    )


def test_hmac_legit_mid_case_toggle_on_still_verifies_green(tmp_path, monkeypatch):
    """Legitimate pattern: HMAC gets turned on PARTWAY through a case
    (no-HMAC rows first, then HMAC rows) -- non-decreasing coverage, not a
    downgrade. Must verify clean, with an accurate (not vacuous) advisory
    detail reflecting partial coverage."""
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEY", raising=False)
    case_dir = tmp_path / "case-toggle-on-mid-case"
    case_dir.mkdir()
    _append_n(case_dir, 2)  # no key yet -> no entry_hmac

    key = "toggled-on-partway-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    _append_n(case_dir, 2)  # key now set -> entry_hmac from here on

    rows = _read_rows(case_dir)
    assert not any("entry_hmac" in r for r in rows[:2])
    assert all("entry_hmac" in r for r in rows[2:])

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, f"a legitimate mid-case toggle-ON must still verify green: {reason}"

    report = verify_full(str(case_dir))
    assert report["ok"] is True
    assert report["checks"]["audit_hmac"]["passed"] is True
    assert "2 of 4" in report["checks"]["audit_hmac"]["detail"]


# ── Full-strip residual: honestly NOT caught internally, journal is the ──
# ── backstop when reachable ──────────────────────────────────────────────
def test_hmac_full_strip_not_caught_internally(tmp_path, monkeypatch):
    """If the attacker strips entry_hmac from EVERY row (not just the
    tampered ones), the chain is internally indistinguishable from one that
    never used the HMAC feature at all -- monotonic coverage holds
    vacuously (0 rows have it, no gap to detect). This is a documented,
    honest residual (see config.audit_hmac_key()'s docstring and
    verify_full()'s), not a bug -- proven not-caught here, and proven
    caught by the journal backstop in the companion test below."""
    key = "full-strip-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-full-strip"
    case_dir.mkdir()
    _append_n(case_dir, 5)
    rows = _read_rows(case_dir)
    assert all("entry_hmac" in r for r in rows)

    mid = len(rows) // 2
    rows[mid]["phase_step"] = "TAMPERED_BY_test_hmac_full_strip"
    _rederive_forward(rows, mid, strip_hmac=True)
    # Also strip the (untouched-content) rows BEFORE the tamper point, to
    # simulate a full strip across the entire chain.
    for r in rows[:mid]:
        r.pop("entry_hmac", None)

    assert not any("entry_hmac" in r for r in rows)

    tampered_dir = tmp_path / "tampered-full-strip-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    ok, reason = verify_chain(str(tampered_dir))
    assert ok is True, (
        "a FULL entry_hmac strip is an accepted, documented residual -- "
        "internal checks alone cannot distinguish it from a chain that "
        "never used HMAC at all"
    )


def test_hmac_full_strip_caught_by_journal_backstop(tmp_path, monkeypatch):
    """Same full-strip attack as above, but now the external systemd-
    journal witness (WS1c(A)) is reachable and remembers the ORIGINAL
    (pre-tamper) entry_sha256 for the tampered seq. The journal doesn't
    care about entry_hmac at all -- it witnessed entry_sha256 directly at
    append() time -- so it catches the re-derivation regardless of what
    happened to entry_hmac. This proves the journal anchor is the real
    backstop for a full HMAC strip."""
    key = "full-strip-backstop-key"
    monkeypatch.setenv("SPECTRE_AUDIT_HMAC_KEY", key)
    case_dir = tmp_path / "case-full-strip-backstop"
    case_dir.mkdir()
    _append_n(case_dir, 5)
    rows = _read_rows(case_dir)

    # Capture what a real journal write WOULD have witnessed at append()
    # time, before any tampering -- these are the ORIGINAL, honest hashes.
    original_witness = [{"case_id": r["case_id"], "seq": r["seq"], "entry_sha256": r["entry_sha256"]} for r in rows]

    mid = len(rows) // 2
    rows[mid]["phase_step"] = "TAMPERED_BY_test_hmac_full_strip_backstop"
    _rederive_forward(rows, mid, strip_hmac=True)
    for r in rows[:mid]:
        r.pop("entry_hmac", None)

    tampered_dir = tmp_path / "tampered-full-strip-backstop-copy"
    tampered_dir.mkdir()
    with open(tampered_dir / "audit.jsonl", "w") as f:
        for r in rows:
            f.write(_canon(r) + "\n")

    # Now bring the journal anchor into play for verification only.
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: original_witness)

    report = verify_full(str(tampered_dir))
    assert report["checks"]["journal_anchor"]["passed"] is False
    assert report["ok"] is False, (
        "the journal anchor must catch a full HMAC strip via the "
        "entry_sha256 disagreement, even though HMAC itself could not"
    )
