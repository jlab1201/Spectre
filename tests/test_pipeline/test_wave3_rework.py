"""Wave 3 rework — the adversarial review's PoCs as regression tests
(HIGH, MED and LOW severity cases)."""
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import audit, custody
from spectre.pipeline.audit import (
    _canonical_json, _sha256_hex, _update_chain_anchor, append as audit_append,
    verify_full,
)
from tests.test_pipeline.test_wave3_custody import (
    _note, _phase3_case, _registered_case, _rows, _sha,
)


@pytest.fixture
def _unlock_after(tmp_path):
    yield
    for p in tmp_path.rglob("evidence"):
        if p.is_dir():
            p.chmod(0o755)


# ─────────────────────────────────────────────────────────────────────────
# HIGH-1: a rewritten / dropped genesis nonce must NOT opt out of the journal
# ─────────────────────────────────────────────────────────────────────────
@pytest.fixture
def journal(monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    written: list[dict] = []
    monkeypatch.setattr(audit, "_journal_emit", lambda p: written.append(json.loads(p)))
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: list(written))
    return written


def _mk(base: Path, name: str) -> str:
    d = base / name
    d.mkdir(parents=True)
    for i in range(5):
        audit_append(str(d), {"actor": "deterministic-core", "action": "note",
                              "case_id": name, "phase": 0, "phase_step": "S0", "i": i})
    return str(d)


def _rederive(d: str, mutate_genesis):
    """j/nonce.py: edit row 3, mutate genesis, re-derive the chain forward."""
    p = os.path.join(d, "audit.jsonl")
    rows = [json.loads(line) for line in open(p) if line.strip()]
    rows[2]["i"] = 999
    mutate_genesis(rows[0])
    prev = "0" * 64
    for r in rows:
        r["prev_sha256"] = prev
        body = {k: v for k, v in r.items() if k not in ("entry_sha256", "entry_hmac")}
        r["entry_sha256"] = _sha256_hex(_canonical_json(body))
        prev = r["entry_sha256"]
    open(p, "w").write("".join(_canonical_json(r) + "\n" for r in rows))
    _update_chain_anchor(d, rows[-1]["seq"], rows[-1]["entry_sha256"])


@pytest.mark.parametrize("label,mutate", [
    ("keep", lambda g: None),
    ("new", lambda g: g.__setitem__("case_nonce", "ab" * 16)),
    ("drop", lambda g: g.pop("case_nonce")),
])
def test_high1_rederived_chain_fails_whatever_the_nonce(tmp_path, journal, label, mutate):
    d = _mk(tmp_path, f"90{len(label)}-nonce-{label}")
    assert verify_full(d)["ok"] is True
    _rederive(d, mutate)
    assert audit.verify_chain(d)[0] is True
    rep = verify_full(d)
    assert rep["ok"] is False, rep["checks"]["journal_anchor"]
    assert rep["checks"]["journal_anchor"]["passed"] is False


def test_high1_nonce_rewrite_alone_is_a_violation(tmp_path, journal):
    d = _mk(tmp_path, "910-nonce-only")
    _rederive(d, lambda g: g.__setitem__("case_nonce", "cd" * 16))
    # undo the row-3 edit's effect on detection: only the nonce differs at seq 1
    rep = verify_full(d)
    assert rep["ok"] is False
    assert "nonce" in rep["checks"]["journal_anchor"]["detail"]


def test_high1_head_floor_legacy_case_id_entries_still_bind(tmp_path, monkeypatch):
    """HEAD 23e6b17 keyed on case_id with no nonce / path: keep that floor."""
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    monkeypatch.setattr(audit, "_journal_emit", lambda p: None)
    d = _mk(tmp_path, "911-legacy-floor")
    rows = _rows(d)
    legacy = [{"case_id": "911-legacy-floor", "seq": r["seq"],
               "entry_sha256": r["entry_sha256"]} for r in rows]
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: legacy)
    assert verify_full(d)["ok"] is True
    _rederive(d, lambda g: g.pop("case_nonce"))
    assert verify_full(d)["ok"] is False


def test_high1_relocated_copy_stays_advisory(tmp_path, journal):
    d = _mk(tmp_path / "live", "912-reloc")
    copy = tmp_path / "handoff" / "912-reloc"
    shutil.copytree(d, copy)
    rep = verify_full(str(copy))
    assert rep["ok"] is True
    assert rep["checks"]["journal_anchor"]["passed"] is False  # advisory


def test_high1_journald_absent_stays_advisory(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    monkeypatch.setattr(audit, "_journal_emit", lambda p: None)
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: None)
    d = _mk(tmp_path, "913-nojd")
    _rederive(d, lambda g: g.pop("case_nonce"))
    assert verify_full(d)["ok"] is True


# ─────────────────────────────────────────────────────────────────────────
# MED: Phase 2 extracts ONLY registered evidence (inj/ PoC)
# ─────────────────────────────────────────────────────────────────────────
def test_med_phase2_refuses_unregistered_triage_entry(tmp_path, monkeypatch, _unlock_after):
    from spectre.pipeline import phase_runner

    case_dir, reg = _registered_case(tmp_path)
    outside = tmp_path / "src" / "extra.evtx"
    outside.write_bytes(b"not registered\n")
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    rec = {"status": "RECOGNIZED", "module": "fake", "artifact_type": "fake"}
    manifest["triage"] = {reg["evidence_path"]: dict(rec), str(outside): dict(rec)}

    extracted = []

    class _Mod:
        enrich = None

        @staticmethod
        def extract(cd, path):
            extracted.append(path)
            return [{"execution_id": "x", "path": "", "evidence_path": path,
                     "tool": "fake", "artifact_type": "fake",
                     "line_count": 0, "size_bytes": 0}]

        @staticmethod
        def normalize(h):
            return []

    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake": _Mod})
    res = phase_runner._run_phase_2_live(str(case_dir), manifest)
    assert [Path(p).name for p in extracted] == ["sample.log"]
    assert res["results"][str(outside)]["skipped"] == "UNREGISTERED"
    assert any(r.get("action") == "unregistered_evidence_refused" for r in _rows(case_dir))


# ─────────────────────────────────────────────────────────────────────────
# LOW 1: derived_artifact rows only from the core pipeline actor
# ─────────────────────────────────────────────────────────────────────────
def test_low1_host_agent_row_cannot_bless_forged_events(tmp_path):
    from spectre.pipeline import phase_runner
    case_dir, manifest = _phase3_case(tmp_path)
    ne = case_dir / "raw_extract" / "normalized_events.json"
    ne.write_text('[{"forged": 1}]')
    _note(case_dir, actor="host-agent", action="derived_artifact", phase=2,
          phase_step="S2-persist-derived", output_path="raw_extract/normalized_events.json",
          output_sha256=_sha(ne.read_bytes()))
    assert phase_runner._run_phase_3_live(str(case_dir), manifest)["success"] is False
    assert verify_full(str(case_dir))["checks"]["derived_artifacts"]["passed"] is False


# ─────────────────────────────────────────────────────────────────────────
# LOW 2: hash the bytes you parse; Phase 6 systeminfo reader verifies
# ─────────────────────────────────────────────────────────────────────────
def test_low2_read_verified_returns_the_hashed_bytes(tmp_path):
    case_dir, _ = _phase3_case(tmp_path)
    ne = case_dir / "raw_extract" / "normalized_events.json"
    assert custody.read_verified(str(case_dir), ne) == b"[]"
    ne.write_text("[1]")
    with pytest.raises(custody.CustodyError):
        custody.read_verified(str(case_dir), ne)


def test_low2_system_profile_ignores_unverified_events(tmp_path):
    from spectre.pipeline.phase_runner import _load_system_profile
    case_dir, _ = _phase3_case(tmp_path)
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps([
        {"artifact_type": "memory_systeminfo",
         "data": {"hostname": "forged-host", "os_build": "1", "system_time": "t"}}]))
    assert _load_system_profile(str(case_dir)) == {}


# ─────────────────────────────────────────────────────────────────────────
# LOW 3: symlinks in evidence/, carved-evidence rows at phase entry
# ─────────────────────────────────────────────────────────────────────────
def test_low3_symlinked_evidence_copy_refused_at_phase_entry(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    ev_dir = case_dir / "evidence"
    target = tmp_path / "elsewhere.log"
    target.write_bytes((ev_dir / "sample.log").read_bytes())  # same bytes
    target.chmod(0o444)
    ev_dir.chmod(0o755)
    (ev_dir / "sample.log").unlink()
    (ev_dir / "sample.log").symlink_to(target)
    ev_dir.chmod(0o555)
    problems = custody.enforce_evidence(str(case_dir), phase=3)
    assert problems and "symlink" in problems[0]


def test_low3_registration_refuses_symlink_in_evidence_dir(tmp_path, _unlock_after):
    from spectre.pipeline.case_setup import _register_evidence
    case_dir, _ = _registered_case(tmp_path)
    src = tmp_path / "src" / "planted.log"
    src.write_bytes(b"planted\n")
    ev_dir = case_dir / "evidence"
    ev_dir.chmod(0o755)
    (ev_dir / "planted.log").symlink_to(src)
    ev_dir.chmod(0o555)
    res = _register_evidence(str(src), str(case_dir))
    assert res["ok"] is False and "symlink" in res["reason"]


def test_low3_carved_evidence_rehashed_at_phase_entry(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    carved_dir = case_dir / "evidence" / "derived" / "img"
    carved_dir.mkdir(parents=True)
    carved = carved_dir / "Security.evtx"
    carved.write_bytes(b"carved\n")
    carved.chmod(0o444)
    _note(case_dir, actor="phase_runner", action="derived_evidence_register", phase=2,
          phase_step="S2-derive", output_path=custody.case_relative(case_dir, carved),
          output_sha256=_sha(b"carved\n"))
    assert custody.enforce_evidence(str(case_dir), phase=3) == []
    carved.chmod(0o644)
    carved.write_bytes(b"swapped\n")
    carved.chmod(0o444)
    assert custody.enforce_evidence(str(case_dir), phase=3)


# ─────────────────────────────────────────────────────────────────────────
# LOW 4: resolve_case_path never escapes the case dir; S3 row relative
# ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["../../etc/passwd", "evidence/../../x", "/etc/passwd"])
def test_low4_resolve_rejects_escape(tmp_path, bad):
    with pytest.raises(custody.CustodyError):
        custody.resolve_case_path(str(tmp_path / "900-x"), bad)


def test_low4_verify_full_fails_on_escaping_evidence_row(tmp_path):
    case_dir = tmp_path / "914-trav"
    case_dir.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    _note(case_dir, actor="case_setup", action="evidence_register",
          output_path="../outside.bin", output_sha256=_sha(b"x"))
    rep = verify_full(str(case_dir))
    assert rep["checks"]["evidence"]["passed"] is False


def test_low4_s3_report_row_is_case_relative(tmp_path):
    from spectre.pipeline.phase_runner import run_phase_6
    case_dir = tmp_path / "915-s3rel"
    (case_dir / "findings").mkdir(parents=True)
    manifest = {"case_id": "915", "case_name": "s3rel", "artifact_profile": "pcap-focused",
                "canary_status": "FULL", "evidence": []}
    run_phase_6(str(case_dir), manifest, skip_ai=True)
    s3 = [r for r in _rows(case_dir) if r.get("phase_step") == "S3-merge-report"]
    assert s3 and all(r["output_path"] == "reports/report.md" for r in s3)
    assert verify_full(str(case_dir))["checks"]["report_integrity"]["passed"] is True


# ─────────────────────────────────────────────────────────────────────────
# LOW 5: approval write ordering / recovery; --superseded-by validated
# ─────────────────────────────────────────────────────────────────────────
def test_low5_failed_replace_is_recoverable(tmp_path, monkeypatch):
    from spectre.pipeline import approval
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    real_replace = os.replace
    calls = {"n": 0}

    def _boom(a, b):
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(approval.os, "replace", _boom)
    with pytest.raises(OSError):
        approval.approve_finding(str(case_dir), fid, examiner="a",
                                 decision="APPROVED", rationale="r")
    monkeypatch.setattr(approval.os, "replace", real_replace)
    # The staged bytes survive; re-running completes the approval.
    res = approval.approve_finding(str(case_dir), fid, examiner="a",
                                   decision="APPROVED", rationale="r")
    assert res["ok"], res
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True
    assert sum(1 for r in _rows(case_dir) if r.get("action") == "approval") == 1


def test_low5_superseded_by_must_be_registered(tmp_path):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    bad = approve_finding(str(case_dir), fid, examiner="a", decision="SUPERSEDED",
                          rationale="r", superseded_by="F-000-999")
    assert bad["ok"] is False
    assert not any(r.get("action") == "approval" for r in _rows(case_dir))


def test_low5_superseded_by_registered_finding_ok(tmp_path):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    ok = approve_finding(str(case_dir), fid, examiner="a", decision="SUPERSEDED",
                         rationale="r", superseded_by=fid)
    assert ok["ok"], ok
