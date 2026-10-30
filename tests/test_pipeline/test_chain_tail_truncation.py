"""A8-F3: verify_chain() only proves internal self-consistency of whatever
rows remain -- it has no notion of "how many rows should exist," so
deleting the MOST RECENT row(s) is undetectable (a truncated chain is still
internally consistent from seq 1). Separately, run_phase_4's zero-findings
branch hardcoded gate_4 = {"verify_chain": True, "passed": True, ...}
WITHOUT ever calling verify_chain() -- so a case that stops at --phase 6
with zero findings never gets its audit chain examined at all.

Fix (a): append() now also writes a small sidecar anchor file
(audit_chain_anchor.json) recording the (seq, entry_sha256) of the row it
just wrote. This is deliberately NOT folded into manifest.yaml: several
phase_runner.py functions load manifest.yaml once at the top of a phase,
call audit.append() several times (each of which would update an in-memory
manifest's anchor on disk), then _save_manifest() the STALE in-memory copy
at the end -- which would silently clobber a manifest-embedded anchor. A
sidecar file audit.py exclusively owns avoids that entirely. verify_chain()
compares the chain's actual tail against this anchor and fails if the chain
is SHORTER than the last thing appended to it.

Fix (b): run_phase_4's zero-findings branch now actually calls
verify_chain() instead of hardcoding True.

Not cryptographic (the sidecar file is itself an ordinary file a same-
privilege attacker could edit too -- see H2/H3) -- it only raises the bar
against careless/partial tail deletion, the same class of protection as the
rest of this module's SHA-256 chaining.
"""
import json
from pathlib import Path


from spectre.pipeline.audit import append, verify_chain, verify_full
from spectre.pipeline import phase_runner


def _append_n(case_dir, n):
    for i in range(n):
        append(str(case_dir), {
            "actor": "deterministic-core", "action": "note", "tool": "x",
            "case_id": Path(case_dir).name, "output_path": "",
            "output_sha256": "", "result": "success",
            "phase": 0, "phase_step": f"row-{i}",
        })


# ── (a) Tail truncation ────────────────────────────────────────────────
def test_untampered_chain_passes(tmp_path):
    case_dir = tmp_path / "case-a"
    case_dir.mkdir()
    _append_n(case_dir, 4)
    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


def test_tail_deletion_is_detected(tmp_path):
    case_dir = tmp_path / "case-b"
    case_dir.mkdir()
    _append_n(case_dir, 4)

    # Sanity: passes before truncation.
    ok_before, _ = verify_chain(str(case_dir))
    assert ok_before is True

    lines = (case_dir / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 4
    (case_dir / "audit.jsonl").write_text("\n".join(lines[:-1]) + "\n")

    ok_after, reason = verify_chain(str(case_dir))
    assert ok_after is False, "tail-truncated chain was not detected"
    assert reason


def test_mid_chain_deletion_still_detected_by_existing_mechanism(tmp_path):
    """Regression guard: the new anchor check must not weaken or replace
    the existing seq/prev_sha256 walk, which already catches mid-chain
    deletion on its own."""
    case_dir = tmp_path / "case-c"
    case_dir.mkdir()
    _append_n(case_dir, 4)

    lines = (case_dir / "audit.jsonl").read_text().splitlines()
    del lines[1]  # remove a MIDDLE row
    (case_dir / "audit.jsonl").write_text("\n".join(lines) + "\n")

    ok, reason = verify_chain(str(case_dir))
    assert ok is False
    assert reason


def test_no_anchor_file_does_not_break_verify_chain(tmp_path):
    """A chain built by hand-writing audit.jsonl directly (never through
    append(), e.g. many existing test fixtures) has no anchor file at all --
    that must not be treated as a failure."""
    case_dir = tmp_path / "case-d"
    case_dir.mkdir()
    rows = []
    prev = "0" * 64
    import hashlib
    for i in range(1, 3):
        body = {"seq": i, "prev_sha256": prev, "action": "note",
                "case_id": case_dir.name}
        canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(canon.encode()).hexdigest()
        body["entry_sha256"] = sha
        rows.append(json.dumps(body))
        prev = sha
    (case_dir / "audit.jsonl").write_text("\n".join(rows) + "\n")

    ok, reason = verify_chain(str(case_dir))
    assert ok is True, reason


def test_verify_full_surfaces_tail_truncation_via_chain_check(tmp_path):
    case_dir = tmp_path / "case-e"
    case_dir.mkdir()
    _append_n(case_dir, 3)
    lines = (case_dir / "audit.jsonl").read_text().splitlines()
    (case_dir / "audit.jsonl").write_text("\n".join(lines[:-1]) + "\n")

    report = verify_full(str(case_dir))
    assert report["ok"] is False
    assert report["checks"]["chain"]["passed"] is False


# ── (b) gate_4 zero-findings branch actually calls verify_chain() ───────
def test_phase4_zero_findings_calls_verify_chain_and_fails_on_corruption(tmp_path):
    case_dir = tmp_path / "003-phase4-zero"
    case_dir.mkdir()
    (case_dir / "findings").mkdir()
    (case_dir / "reports").mkdir()
    _append_n(case_dir, 3)

    # Corrupt the chain (delete the last row) BEFORE Phase 4 runs.
    lines = (case_dir / "audit.jsonl").read_text().splitlines()
    (case_dir / "audit.jsonl").write_text("\n".join(lines[:-1]) + "\n")

    manifest = {"case_id": "003"}
    result = phase_runner.run_phase_4(str(case_dir), manifest)

    assert result["success"] is False, (
        "run_phase_4's zero-findings branch hardcoded gate_4.passed=True "
        "without ever calling verify_chain() — a corrupted chain must now "
        "fail this gate"
    )
    assert manifest["gate_4"]["verify_chain"] is False
    assert manifest["gate_4"]["passed"] is False


def test_phase4_zero_findings_passes_on_clean_chain(tmp_path):
    case_dir = tmp_path / "003-phase4-clean"
    case_dir.mkdir()
    (case_dir / "findings").mkdir()
    (case_dir / "reports").mkdir()
    _append_n(case_dir, 3)

    manifest = {"case_id": "003"}
    result = phase_runner.run_phase_4(str(case_dir), manifest)

    assert result["success"] is True
    assert manifest["gate_4"]["verify_chain"] is True
    assert manifest["gate_4"]["passed"] is True
