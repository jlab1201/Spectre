"""WS1c(A) — external append-only anchor via the systemd journal.

Rationale (see audit.py's _update_chain_anchor()/verify_full() docstrings,
and the audit-chain description in the README Architecture section): a non-root same-OS-
user attacker can rewrite every file inside the case directory, including
the audit_chain_anchor.json sidecar, and can re-derive prev_sha256/
entry_sha256 forward after tampering a row (the A1-H2 CONFIRMED attack) to
produce a byte-for-byte self-consistent chain. They CANNOT rewrite prior
entries already committed to the systemd journal (they can only append).
Checkpointing the chain tail there on every append() gives verify_full() an
external witness that same-user re-derivation can't forge.

Must be fully graceful: on any host with no systemd/journald/logger (CI,
containers, macOS), append() must never raise, and verify_full() must treat
the absence of journal data as advisory, not a failure. These tests never
depend on a real journald being present — the "graceful no-op" tests mock
shutil.which to return None, and the "disagreement" test mocks the journal
reader directly, so they're deterministic in any CI environment regardless
of what's actually installed on the box running them.
"""
import json

import pytest

from spectre.pipeline import audit
from spectre.pipeline.audit import append, verify_chain, verify_full


@pytest.fixture(autouse=True)
def _journal_anchor_on_by_default(monkeypatch):
    """The suite-wide tests/conftest.py fixture defaults the journal
    anchor OFF (to keep unrelated tests from hitting a real, test-session-
    shared journald). This file exists specifically to exercise the
    feature, so opt back in here; individual tests below still override
    this locally (e.g. the "disabled via config" test) since a call inside
    the test body runs after fixture setup and wins."""
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")


@pytest.fixture(autouse=True)
def _never_write_the_real_journal(monkeypatch):
    """R2-10: tests must not pollute the host's real journal. Default the
    subprocess sink to a no-op; tests that assert on subprocess behaviour
    install their own stub in the test body, which wins."""
    monkeypatch.setattr(audit.subprocess, "run", lambda *a, **kw: None)


def _append_n(case_dir, n):
    for i in range(n):
        append(str(case_dir), {
            "actor": "test", "action": "note", "tool": "x",
            "case_id": case_dir.name, "output_path": "",
            "output_sha256": "", "result": "success",
            "phase": 0, "phase_step": f"row-{i}",
        })


# ── Graceful no-op when no systemd/journald/logger is available ─────────
def test_append_never_raises_with_no_journal_tooling(tmp_path, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", lambda name: None)
    case_dir = tmp_path / "case-no-tooling"
    case_dir.mkdir()

    # Must not raise.
    _append_n(case_dir, 3)

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


def test_verify_full_advisory_when_journalctl_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", lambda name: None)
    case_dir = tmp_path / "case-no-journalctl"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is False
    assert report["ok"] is True, (
        "journalctl being unavailable is advisory, not a hard failure"
    )


def test_append_does_not_invoke_subprocess_when_no_tooling(tmp_path, monkeypatch):
    monkeypatch.setattr(audit.shutil, "which", lambda name: None)
    called = {"n": 0}

    def _fail_if_called(*a, **kw):
        called["n"] += 1
        raise AssertionError("subprocess.run must not be invoked when no journal tooling is found")

    monkeypatch.setattr(audit.subprocess, "run", _fail_if_called)
    case_dir = tmp_path / "case-no-subprocess-call"
    case_dir.mkdir()
    _append_n(case_dir, 2)
    assert called["n"] == 0


# ── Feature toggle ────────────────────────────────────────────────────────
def test_journal_anchor_disabled_via_config_skips_subprocess(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "0")
    called = {"n": 0}

    def _fail_if_called(*a, **kw):
        called["n"] += 1
        raise AssertionError("subprocess must not run when the journal anchor is disabled")

    monkeypatch.setattr(audit.subprocess, "run", _fail_if_called)
    case_dir = tmp_path / "case-disabled"
    case_dir.mkdir()
    _append_n(case_dir, 2)
    assert called["n"] == 0

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is True
    assert "disabled" in report["checks"]["journal_anchor"]["detail"].lower()


def test_append_never_raises_even_if_subprocess_explodes(tmp_path, monkeypatch):
    """Best-effort really means best-effort: even a tool that IS found but
    then errors/raises at call time must not break append()."""
    monkeypatch.setattr(audit.shutil, "which", lambda name: "/usr/bin/systemd-cat")

    def _boom(*a, **kw):
        raise OSError("simulated failure")

    monkeypatch.setattr(audit.subprocess, "run", _boom)
    case_dir = tmp_path / "case-subprocess-boom"
    case_dir.mkdir()

    _append_n(case_dir, 2)  # must not raise

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


# ── Fail-closed disagreement (the A1-H2 re-derive attack, witnessed) ────
def test_verify_full_fails_closed_on_journal_disagreement(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-disagree"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    rows = []
    with open(case_dir / "audit.jsonl") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    real_last_seq = rows[-1]["seq"]
    real_last_hash = rows[-1]["entry_sha256"]
    assert real_last_hash  # sanity

    # Journal witnessed a DIFFERENT hash at the same seq than what's on
    # disk now — this is exactly the signature of the A1-H2 re-derive
    # attack (chain says X at seq N, external witness recorded Y).
    fake_journal_entries = [
        {"case_id": case_dir.name, "case_nonce": rows[0]["case_nonce"],
         "seq": real_last_seq, "entry_sha256": "f" * 64},
    ]
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: fake_journal_entries)

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is False
    assert report["ok"] is False, (
        "a chain/journal disagreement must fail closed, not just advise"
    )


def test_verify_full_passes_when_journal_agrees(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-agree"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    rows = []
    with open(case_dir / "audit.jsonl") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    fake_journal_entries = [
        {"case_id": case_dir.name, "case_nonce": rows[0]["case_nonce"],
         "seq": r["seq"], "entry_sha256": r["entry_sha256"]}
        for r in rows
    ]
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: fake_journal_entries)

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is True
    assert report["ok"] is True


def test_verify_full_advisory_when_no_entries_for_this_case(tmp_path, monkeypatch):
    """The journal has entries, but none tagged with THIS case's id — e.g.
    the case predates the feature, or journald hasn't retained history that
    far back. Advisory, not a failure."""
    case_dir = tmp_path / "case-no-match"
    case_dir.mkdir()
    _append_n(case_dir, 2)

    fake_journal_entries = [
        {"case_id": "some-other-case", "seq": 1, "entry_sha256": "a" * 64},
    ]
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: fake_journal_entries)

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is False
    assert report["ok"] is True


# ── Backward compat ───────────────────────────────────────────────────────
def test_existing_chain_with_no_journal_writes_still_verifies(tmp_path, monkeypatch):
    """A chain built by hand-writing audit.jsonl directly (bypassing
    append() entirely — as many existing fixtures do) has no journal
    entries at all. Must not be treated as tampering."""
    monkeypatch.setattr(audit.shutil, "which", lambda name: None)
    case_dir = tmp_path / "case-handwritten"
    case_dir.mkdir()

    import hashlib
    rows = []
    prev = "0" * 64
    for i in range(1, 3):
        body = {"seq": i, "prev_sha256": prev, "action": "note", "case_id": case_dir.name}
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canon.encode()).hexdigest()
        body["entry_sha256"] = sha
        rows.append(json.dumps(body))
        prev = sha
    (case_dir / "audit.jsonl").write_text("\n".join(rows) + "\n")

    report = verify_full(str(case_dir))
    assert report["checks"]["journal_anchor"]["passed"] is False  # advisory
    assert report["ok"] is True
