"""Wave 3 — close the chain-of-custody holes (PLAN.md W3-1 .. W3-7).

One section per plan item. Each test names the review finding it closes.
"""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import audit, custody
from spectre.pipeline.audit import append as audit_append, verify_full


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rows(case_dir) -> list[dict]:
    return [json.loads(line) for line in
            (Path(case_dir) / "audit.jsonl").read_text().splitlines() if line.strip()]


def _note(case_dir, **kw):
    row = {"actor": "test", "action": "note", "tool": "x",
           "case_id": Path(case_dir).name, "output_path": "", "output_sha256": "",
           "result": "success", "phase": 0, "phase_step": "t"}
    row.update(kw)
    return audit_append(str(case_dir), row)


# ─────────────────────────────────────────────────────────────────────────
# W3-1 (R2-04, R2-16): derived artifacts are hashed, chained, re-verified
# ─────────────────────────────────────────────────────────────────────────
def _phase3_case(tmp_path, name="301-derived"):
    case_dir = tmp_path / name
    raw = case_dir / "raw_extract"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    _note(case_dir, phase_step="genesis")
    (raw / "normalized_events.json").write_text("[]")
    (raw / "_handles.json").write_text("[]")
    custody.record_derived_artifacts(str(case_dir))
    manifest = {"case_id": "301", "case_name": "derived", "artifacts": [],
                "evidence": [], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return case_dir, manifest


def test_w3_1_phase2_artifacts_get_chained_hash_rows(tmp_path):
    case_dir, _ = _phase3_case(tmp_path)
    rows = [r for r in _rows(case_dir) if r.get("action") == "derived_artifact"]
    paths = {r["output_path"] for r in rows}
    assert paths == {"raw_extract/normalized_events.json", "raw_extract/_handles.json"}
    for r in rows:
        assert r["output_sha256"] == _sha(b"[]")


def test_w3_1_forged_normalized_events_fails_phase3_closed(tmp_path):
    from spectre.pipeline import phase_runner
    case_dir, manifest = _phase3_case(tmp_path)
    forged = [{"artifact_type": "pcap_dns", "timestamp": "2026-01-01T00:00:00Z",
               "source_file": "x", "data": {"query": "r2-forged-c2.xyz"}}]
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(forged))
    result = phase_runner._run_phase_3_live(str(case_dir), manifest)
    assert result["success"] is False
    assert "normalized_events.json" in result["error"]
    assert not list((case_dir / "findings").glob("F-*.yaml"))
    assert any(r.get("action") == "derived_artifact_tampered" for r in _rows(case_dir))


def test_w3_1_forged_handles_fails_phase3_closed(tmp_path):
    from spectre.pipeline import phase_runner
    case_dir, manifest = _phase3_case(tmp_path)
    (case_dir / "raw_extract" / "_handles.json").write_text('[{"tool": "forged"}]')
    result = phase_runner._run_phase_3_live(str(case_dir), manifest)
    assert result["success"] is False
    assert "_handles.json" in result["error"]


def test_w3_1_unrecorded_normalized_events_fails_closed(tmp_path):
    """A normalized_events.json with no chained hash row at all is not
    trusted either (it would otherwise be the easy way round the check)."""
    from spectre.pipeline import phase_runner
    case_dir = tmp_path / "302-unrecorded"
    (case_dir / "raw_extract").mkdir(parents=True)
    (case_dir / "findings").mkdir()
    _note(case_dir)
    (case_dir / "raw_extract" / "normalized_events.json").write_text("[]")
    result = phase_runner._run_phase_3_live(str(case_dir), {"triage": {}})
    assert result["success"] is False


def test_w3_1_verify_full_catches_forged_derived_artifact(tmp_path):
    case_dir, _ = _phase3_case(tmp_path)
    assert verify_full(str(case_dir))["checks"]["derived_artifacts"]["passed"] is True
    (case_dir / "raw_extract" / "normalized_events.json").write_text('[{"forged": 1}]')
    rep = verify_full(str(case_dir))
    assert rep["checks"]["derived_artifacts"]["passed"] is False
    assert rep["ok"] is False


def test_w3_1_directives_hashed_and_verified_on_load(tmp_path):
    from spectre.pipeline import directives, phase_runner
    case_dir = tmp_path / "303-directives"
    case_dir.mkdir()
    manifest = {"direction": "look for ip 10.1.2.3"}
    phase_runner.run_phase_1(str(case_dir), manifest, skip_ai=True)
    row = [r for r in _rows(case_dir) if r.get("action") == "directives_synthesized"][-1]
    dpath = case_dir / "raw_extract" / "directives.json"
    assert row["output_sha256"] == _sha(dpath.read_bytes())
    assert len(directives.load(str(case_dir))) >= 1
    # Inject an include directive after Phase 1 → load must refuse.
    specs = json.loads(dpath.read_text())
    specs.append(dict(specs[0], directive_id="dir-999"))
    dpath.write_text(json.dumps(specs))
    with pytest.raises(custody.CustodyError):
        directives.load(str(case_dir))
    assert verify_full(str(case_dir))["checks"]["derived_artifacts"]["passed"] is False


def test_w3_1_empty_direction_is_hashed_too(tmp_path):
    from spectre.pipeline import directives, phase_runner
    case_dir = tmp_path / "304-nodir"
    case_dir.mkdir()
    phase_runner.run_phase_1(str(case_dir), {"direction": ""}, skip_ai=True)
    assert directives.load(str(case_dir)) == []
    dpath = case_dir / "raw_extract" / "directives.json"
    dpath.write_text(json.dumps([{"directive_id": "dir-001", "type": "ioc_match",
                                  "polarity": "include",
                                  "params": {"ioc_type": "ip", "value": "1.2.3.4"}}]))
    with pytest.raises(custody.CustodyError):
        directives.load(str(case_dir))


# ─────────────────────────────────────────────────────────────────────────
# W3-2 (R1-F8, R2-15): every phase entry re-hashes evidence; evidence/ 0555
# ─────────────────────────────────────────────────────────────────────────
def _registered_case(tmp_path, name="305-evidence"):
    from spectre.pipeline.case_setup import _register_evidence, lock_evidence_dir
    src = tmp_path / "src" / "sample.log"
    src.parent.mkdir(parents=True)
    src.write_bytes(b"original evidence bytes\n")
    case_dir = tmp_path / "cases" / name
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    reg = _register_evidence(str(src), str(case_dir))
    assert reg["ok"], reg
    lock_evidence_dir(str(case_dir))
    manifest = {"case_id": "305", "case_name": "evidence", "canary_status": "FULL",
                "artifacts": [], "evidence": [reg],
                "gate_0": {"passed": True}, "gate_1": {"passed": True},
                "gate_2": {"passed": True}}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return case_dir, reg


def _swap_evidence(case_dir: Path, new: bytes = b"substituted bytes\n"):
    ev_dir = case_dir / "evidence"
    ev = ev_dir / "sample.log"
    ev_dir.chmod(0o755)
    ev.unlink()
    ev.write_bytes(new)
    ev.chmod(0o444)
    ev_dir.chmod(0o555)


@pytest.fixture
def _unlock_after(tmp_path):
    yield
    for p in tmp_path.rglob("evidence"):
        if p.is_dir():
            p.chmod(0o755)


def test_w3_2_evidence_dir_locked_0555_with_writable_derived(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    ev_dir = case_dir / "evidence"
    assert (ev_dir.stat().st_mode & 0o777) == 0o555
    assert os.access(ev_dir / "derived", os.W_OK), "carving writes into evidence/derived"


def test_w3_2_phase_entry_refuses_swapped_evidence(tmp_path, _unlock_after):
    from spectre.pipeline import runner
    case_dir, _ = _registered_case(tmp_path)
    _swap_evidence(case_dir)
    assert runner.run_phase(str(case_dir), 3) is False
    assert any(r.get("action") == "evidence_tampered" for r in _rows(case_dir))
    assert not list((case_dir / "findings").glob("F-*.yaml"))


def test_w3_2_phase_entry_passes_untouched_evidence(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    assert custody.enforce_evidence(str(case_dir), phase=3) == []


def test_w3_2_resume_exits_nonzero_on_tampered_evidence(tmp_path, monkeypatch, _unlock_after):
    from spectre.pipeline import runner
    from spectre.pipeline import canary as canary_mod
    case_dir, _ = _registered_case(tmp_path)
    _swap_evidence(case_dir)
    monkeypatch.setattr(canary_mod, "run_canary", lambda **kw: {"status": "FULL"})
    ran = []
    monkeypatch.setattr(runner, "run_phase", lambda cd, p, skip_ai=False: ran.append(p) or True)
    monkeypatch.setattr(sys, "argv", ["spectre", "--case", str(case_dir), "--phase", "6"])
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code != 0
    assert ran == []


def test_w3_2_register_more_evidence_into_locked_dir(tmp_path, _unlock_after):
    from spectre.pipeline.case_setup import _register_evidence
    case_dir, _ = _registered_case(tmp_path)
    extra = tmp_path / "src" / "second.log"
    extra.write_bytes(b"second\n")
    reg = _register_evidence(str(extra), str(case_dir))
    assert reg["ok"], reg
    assert ((case_dir / "evidence").stat().st_mode & 0o777) == 0o555


# ─────────────────────────────────────────────────────────────────────────
# W3-3 (R2-13): Check 8 trusts output_sha256 only from authority rows
# ─────────────────────────────────────────────────────────────────────────
def test_w3_3_generic_row_cannot_bless_a_finding_edit(tmp_path):
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    built = build_case000_case(case_dir)
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True
    fid = built["findings"][0]["finding_id"]
    fp = case_dir / "findings" / f"{fid}.yaml"
    fp.write_text(fp.read_text().replace("status: INFERRED", "status: CONFIRMED")
                  + "\n# edited\n")
    _note(case_dir, actor="anyone", phase_step="whatever", finding_id=fid,
          output_path=str(fp), output_sha256=_sha(fp.read_bytes()))
    rep = verify_full(str(case_dir))
    assert rep["checks"]["finding_integrity"]["passed"] is False
    assert "non-authority" in rep["checks"]["finding_integrity"]["detail"]


# ─────────────────────────────────────────────────────────────────────────
# W3-4 (R2-08): narrative_grounding binds to the CURRENT report.md
# ─────────────────────────────────────────────────────────────────────────
def _s2(case_dir):
    _note(case_dir, actor="deterministic-core", tool="report-validator",
          phase=6, phase_step="S2-validate-report", params={"violations_found": 0})


def _s3(case_dir, report: Path, llm_used=True):
    _note(case_dir, actor="spectre-lead", tool="report_synthesize._merge_report_md",
          phase=6, phase_step="S3-merge-report", output_path=str(report),
          output_sha256=_sha(report.read_bytes()),
          params={"llm_used": llm_used, "disclosed_coverage_gaps": []})


def _report_case(tmp_path, ai=True):
    case_dir = tmp_path / "306-report"
    (case_dir / "reports").mkdir(parents=True)
    report = case_dir / "reports" / "report.md"
    report.write_text("# Report\nValidated narrative.\n")
    _s2(case_dir)
    _s3(case_dir, report, llm_used=ai)
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump({"report": {"ai_narrative": ai}}))
    return case_dir, report


def test_w3_4_validated_current_report_passes(tmp_path):
    case_dir, _ = _report_case(tmp_path)
    assert audit._narrative_grounding_check(str(case_dir))["passed"] is True


def test_w3_4_stale_s2_row_does_not_cover_new_report(tmp_path):
    case_dir, report = _report_case(tmp_path)
    report.write_text(report.read_text() + "APT29 exfiltrated 40GB via DCSync (T1003.006).\n")
    _s3(case_dir, report, llm_used=True)
    ng = audit._narrative_grounding_check(str(case_dir))
    assert ng["passed"] is False
    assert verify_full(str(case_dir))["ok"] is False


def test_w3_4_manifest_flag_flip_does_not_skip_check(tmp_path):
    case_dir, report = _report_case(tmp_path)
    report.write_text(report.read_text() + "Fabricated.\n")
    _s3(case_dir, report, llm_used=True)
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump({"report": {"ai_narrative": False}}))
    assert audit._narrative_grounding_check(str(case_dir))["passed"] is False


def test_w3_4_unbound_report_bytes_fail_when_ai(tmp_path):
    case_dir, report = _report_case(tmp_path)
    report.write_text("edited after the S3 row\n")
    assert audit._narrative_grounding_check(str(case_dir))["passed"] is False


def test_w3_4_rerun_with_fresh_validation_passes(tmp_path):
    case_dir, report = _report_case(tmp_path)
    report.write_text("# Report v2\n")
    _s2(case_dir)
    _s3(case_dir, report, llm_used=True)
    assert audit._narrative_grounding_check(str(case_dir))["passed"] is True


def test_w3_4_baseline_report_needs_no_validation(tmp_path):
    case_dir, _ = _report_case(tmp_path, ai=False)
    assert audit._narrative_grounding_check(str(case_dir))["passed"] is True


# ─────────────────────────────────────────────────────────────────────────
# W3-5 (R2-09, R2-10): journal anchor — tail truncation + per-case nonce
# ─────────────────────────────────────────────────────────────────────────
@pytest.fixture
def _journal_on(monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    written = []
    # Never touch the real journal from tests (R2-10): capture payloads.
    monkeypatch.setattr(audit, "_journal_emit", lambda payload: written.append(json.loads(payload)))
    return written


def test_w3_5_genesis_row_carries_nonce_and_journal_payload_uses_it(tmp_path, _journal_on):
    case_dir = tmp_path / "307-nonce"
    case_dir.mkdir()
    for i in range(3):
        _note(case_dir, phase_step=f"r{i}")
    rows = _rows(case_dir)
    nonce = rows[0].get("case_nonce")
    assert nonce and len(nonce) >= 32
    assert audit.case_nonce(str(case_dir)) == nonce
    assert [w["case_nonce"] for w in _journal_on] == [nonce] * 3
    assert [w["seq"] for w in _journal_on] == [1, 2, 3]


def test_w3_5_tail_truncation_detected_against_journal(tmp_path, monkeypatch, _journal_on):
    case_dir = tmp_path / "308-trunc"
    case_dir.mkdir()
    for i in range(6):
        _note(case_dir, phase_step=f"r{i}")
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: list(_journal_on))
    assert verify_full(str(case_dir))["checks"]["journal_anchor"]["passed"] is True
    lines = (case_dir / "audit.jsonl").read_text().splitlines(keepends=True)
    (case_dir / "audit.jsonl").write_text("".join(lines[:4]))
    (case_dir / "audit_chain_anchor.json").unlink()
    assert audit.verify_chain(str(case_dir))[0] is True  # internally consistent
    rep = verify_full(str(case_dir))
    assert rep["checks"]["journal_anchor"]["passed"] is False
    assert "truncat" in rep["checks"]["journal_anchor"]["detail"]
    assert rep["ok"] is False


def test_w3_5_same_case_id_other_case_dir_does_not_cross_fail(tmp_path, monkeypatch, _journal_on):
    a = tmp_path / "a" / "309-same"
    b = tmp_path / "b" / "309-same"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    for i in range(3):
        _note(a, phase_step=f"a{i}")
    for i in range(5):
        _note(b, phase_step=f"b{i}")
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: list(_journal_on))
    for cd in (a, b):
        rep = verify_full(str(cd))
        assert rep["checks"]["journal_anchor"]["passed"] is True, rep["checks"]["journal_anchor"]
        assert rep["ok"] is True


def test_w3_5_journald_absent_is_advisory(tmp_path, monkeypatch, _journal_on):
    case_dir = tmp_path / "310-nojournal"
    case_dir.mkdir()
    _note(case_dir)
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: None)
    rep = verify_full(str(case_dir))
    assert rep["checks"]["journal_anchor"]["passed"] is False
    assert rep["ok"] is True


# ─────────────────────────────────────────────────────────────────────────
# W3-6 (R1-F3): in-process Phase 7 approval writer
# ─────────────────────────────────────────────────────────────────────────
def test_w3_6_approve_keeps_verify_full_green(tmp_path):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    built = build_case000_case(case_dir)
    fid = built["findings"][0]["finding_id"]
    res = approve_finding(str(case_dir), fid, examiner="alice",
                          decision="APPROVED", rationale="reviewed raw events")
    assert res["ok"], res
    data = yaml.safe_load((case_dir / "findings" / f"{fid}.yaml").read_text())
    assert data["approval"] == "APPROVED"
    assert data["approved_by"] == "alice"
    row = [r for r in _rows(case_dir) if r.get("action") == "approval"][-1]
    assert row["finding_id"] == fid and row["phase"] == 7
    assert row["params"]["previous_approval"] is None
    assert row["params"]["new_approval"] == "APPROVED"
    rep = verify_full(str(case_dir))
    assert rep["checks"]["finding_integrity"]["passed"] is True, rep["checks"]["finding_integrity"]


def test_w3_6_approve_refuses_a_tampered_finding(tmp_path):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    fp = case_dir / "findings" / f"{fid}.yaml"
    fp.write_text(fp.read_text() + "\n# tamper\n")
    res = approve_finding(str(case_dir), fid, examiner="alice",
                          decision="APPROVED", rationale="x")
    assert res["ok"] is False
    assert not any(r.get("action") == "approval" for r in _rows(case_dir))


def test_w3_6_cli_spectre_approve(tmp_path, monkeypatch):
    from spectre.pipeline import runner
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    monkeypatch.setattr(sys, "argv", [
        "spectre", "approve", "--case", str(case_dir), "--finding", fid,
        "--examiner", "alice", "--decision", "REJECTED", "--rationale", "benign admin"])
    with pytest.raises(SystemExit) as exc:
        runner.main()
    assert exc.value.code == 0
    data = yaml.safe_load((case_dir / "findings" / f"{fid}.yaml").read_text())
    assert data["approval"] == "REJECTED"
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True


# ─────────────────────────────────────────────────────────────────────────
# W3-7 (R1-F10): case-relative evidence paths; relocated case verifies
# ─────────────────────────────────────────────────────────────────────────
def test_w3_7_evidence_register_row_is_case_relative(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    row = [r for r in _rows(case_dir) if r.get("action") == "evidence_register"][-1]
    assert row["output_path"] == "evidence/sample.log"
    assert row["params"]["copy_path"] == "evidence/sample.log"


def test_w3_7_relocated_case_verifies_its_own_evidence(tmp_path, _unlock_after):
    case_dir, _ = _registered_case(tmp_path)
    moved = tmp_path / "archive" / "restored-case"
    shutil.copytree(case_dir, moved)
    assert verify_full(str(moved))["checks"]["evidence"]["passed"] is True
    # The relocated copy's OWN bytes are what get verified.
    _swap_evidence(moved)
    rep = verify_full(str(moved))
    assert rep["checks"]["evidence"]["passed"] is False
    assert verify_full(str(case_dir))["checks"]["evidence"]["passed"] is True


def test_w3_7_legacy_absolute_rows_reroot_into_moved_case(tmp_path):
    from tests.test_pipeline.test_manifest_evidence_crosscheck import _seed_registered_evidence
    case_dir = tmp_path / "orig" / "311-legacy"
    ev_path, _ = _seed_registered_evidence(case_dir)
    moved = tmp_path / "elsewhere" / "311-legacy"
    shutil.copytree(case_dir, moved)
    # Original disappears (archive restore on another host).
    ev_path.chmod(0o644)
    shutil.rmtree(tmp_path / "orig")
    assert verify_full(str(moved))["checks"]["evidence"]["passed"] is True


def test_w3_7_resolve_case_path_rules(tmp_path):
    cd = tmp_path / "900-x"
    assert custody.resolve_case_path(str(cd), "evidence/a.bin") == cd / "evidence" / "a.bin"
    assert custody.resolve_case_path(
        str(cd), "/old/root/900-x/evidence/a.bin") == cd / "evidence" / "a.bin"
    assert custody.resolve_case_path(
        str(cd), "/old/root/renamed/evidence/a.bin") == cd / "evidence" / "a.bin"
    assert custody.case_relative(str(cd), str(cd / "evidence" / "a.bin")) == "evidence/a.bin"
    assert custody.case_relative(str(cd), "/outside/a.bin") == "/outside/a.bin"


def test_w3_5_legacy_nonceless_chain_still_checked_by_case_id(tmp_path, monkeypatch):
    """Back-compat: a chain with no genesis nonce keeps the old case_id key."""
    case_dir = tmp_path / "312-legacy"
    case_dir.mkdir()
    prev = "0" * 64
    lines = []
    for i in (1, 2):
        body = {"seq": i, "prev_sha256": prev, "action": "note", "case_id": case_dir.name}
        sha = _sha(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        body["entry_sha256"] = sha
        lines.append(json.dumps(body))
        prev = sha
    (case_dir / "audit.jsonl").write_text("\n".join(lines) + "\n")
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1")
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: [
        {"case_id": case_dir.name, "seq": 2, "entry_sha256": "e" * 64}])
    rep = verify_full(str(case_dir))
    assert rep["checks"]["journal_anchor"]["passed"] is False
    assert rep["ok"] is False


def test_w3_6_reapproval_replaces_block_and_preserves_other_bytes(tmp_path):
    from spectre.pipeline.approval import approve_finding, pending_approvals
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    fp = case_dir / "findings" / f"{fid}.yaml"
    original = fp.read_text()
    assert fid in pending_approvals(str(case_dir))
    assert approve_finding(str(case_dir), fid, examiner="a", decision="APPROVED",
                           rationale="r1")["ok"]
    res = approve_finding(str(case_dir), fid, examiner="b", decision="SUPERSEDED",
                          rationale="r2", superseded_by=fid)
    assert res["ok"] and res["previous_approval"] == "APPROVED"
    text = fp.read_text()
    assert text.startswith(original)
    assert text.count("approval:") == 1
    data = yaml.safe_load(text)
    assert data["approved_by"] == "b" and data["superseded_by"] == fid
    assert fid not in pending_approvals(str(case_dir))
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True


def test_reapprove_multiline_rationale_preserves_yaml(tmp_path):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    fp = case_dir / "findings" / f"{fid}.yaml"
    before = yaml.safe_load(fp.read_text())
    assert approve_finding(str(case_dir), fid, examiner="a", decision="APPROVED",
                           rationale="line one\n\nline two")["ok"]
    assert approve_finding(str(case_dir), fid, examiner="a", decision="APPROVED",
                           rationale="second")["ok"]
    data = yaml.safe_load(fp.read_text())
    assert data["status"] == before["status"]
    assert data["approval_rationale"] == "second"
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True


@pytest.mark.parametrize("rationale", ["# not a comment", "ends with newline\n",
                                       "key: value, with colon-space", "a\n\nb: c\n# d"])
def test_reapprove_awkward_rationale_round_trips(tmp_path, rationale):
    from spectre.pipeline.approval import approve_finding
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir
    case_dir = make_case_dir(tmp_path)
    fid = build_case000_case(case_dir)["findings"][0]["finding_id"]
    fp = case_dir / "findings" / f"{fid}.yaml"
    before = yaml.safe_load(fp.read_text())
    for r in (rationale, rationale):
        assert approve_finding(str(case_dir), fid, examiner="a", decision="APPROVED",
                               rationale=r)["ok"]
    data = yaml.safe_load(fp.read_text())
    assert data["approval_rationale"] == rationale
    for k, v in before.items():
        assert data[k] == v
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True


def test_strip_top_level_keys_unit():
    from spectre.pipeline.approval import _strip_top_level_keys
    text = "status: X\napproval_rationale: 'a\n\n  b'\nother: 1\n"
    assert _strip_top_level_keys(text, {"approval_rationale"}) == "status: X\nother: 1\n"


def test_w3_5_diverged_copy_does_not_cross_fail_original(tmp_path, monkeypatch, _journal_on):
    """A handed-off copy shares the genesis nonce; once it appends, the two
    chains diverge. Neither may fail the other (entries are path-bound)."""
    orig = tmp_path / "live" / "313-fork"
    orig.mkdir(parents=True)
    for i in range(3):
        _note(orig, phase_step=f"o{i}")
    copy = tmp_path / "handoff" / "313-fork"
    shutil.copytree(orig, copy)
    _note(copy, phase_step="copy-only")          # copy diverges: seq 4 in copy
    monkeypatch.setattr(audit, "_journal_read_entries", lambda: list(_journal_on))
    r_orig = verify_full(str(orig))
    assert r_orig["checks"]["journal_anchor"]["passed"] is True
    assert r_orig["ok"] is True
    r_copy = verify_full(str(copy))
    assert r_copy["ok"] is True
    # ...and the original's own truncation is still caught.
    lines = (orig / "audit.jsonl").read_text().splitlines(keepends=True)
    (orig / "audit.jsonl").write_text("".join(lines[:2]))
    (orig / "audit_chain_anchor.json").unlink()
    assert verify_full(str(orig))["ok"] is False
