"""A finding's own YAML is chain-of-custody evidence (see README
Architecture: chain of custody) — but
until now no audit row recorded its content hash, so a post-creation edit
(status, confidence, MITRE ID, deleted forensic_caveats...) was invisible to
verify_full(). The hash must be recorded at creation so edits are detectable.

Covers both emit paths (core/emit_finding.py's `emit()` and
pipeline/emit_finding.py's `emit_from_handle()`) plus the explain() layer,
which is a THIRD writer of the same finding file (it patches in the AI
description/mitre/caveats and re-persists) — all three must leave behind a
row whose output_sha256 actually matches on-disk content, and the LATEST
such row is authoritative.
"""
import hashlib
import json

import yaml

from spectre.pipeline.audit import verify_full, append as audit_append
from spectre.pipeline.emit_finding import emit_from_handle


def _fk_yaml(tmp_path):
    p = tmp_path / "fk.yaml"
    p.write_text(yaml.safe_dump({"does_NOT_prove": ["placeholder caveat"]}))
    return str(p)


def _mitre_map(tmp_path):
    p = tmp_path / "mitre.yaml"
    p.write_text(yaml.safe_dump({"rules": {}, "fallback": "UNMAPPED"}))
    return str(p)


def _handle(exec_id: str = "exec-aaa") -> dict:
    return {
        "execution_id": exec_id,
        "tool": "test-tool",
        "tool_version": "0.1",
        "line_count": 1,
        "path": "/x/y.json",
        "exact_command": "test-tool --fixture",
    }


# ── Sub-task 1: pipeline/emit_finding.py records a real hash, and a
#    post-creation edit is detected by verify_full() ──────────────────────
def test_emit_from_handle_records_real_output_sha256(tmp_path):
    fk = _fk_yaml(tmp_path)
    mitre = _mitre_map(tmp_path)
    case_dir = tmp_path / "004-finding-hash"
    (case_dir / "findings").mkdir(parents=True)

    emit_from_handle(
        handle=_handle(), case_dir=str(case_dir), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-MASQ-01", title="rundll32 masquerade",
    )

    rows = [json.loads(l) for l in
            (case_dir / "audit.jsonl").read_text().splitlines() if l.strip()]
    create_rows = [r for r in rows if r.get("action") == "finding_create"]
    assert len(create_rows) == 1
    recorded = create_rows[0]["output_sha256"]
    assert recorded, "finding_create row still has an empty output_sha256"

    finding_path = case_dir / "findings" / "F-004-001.yaml"
    actual = hashlib.sha256(finding_path.read_bytes()).hexdigest()
    assert recorded == actual


def test_tampered_finding_yaml_fails_verify_full(tmp_path):
    """This is the exact A1-H1 repro: emit a finding, hand-edit its status/
    confidence/mitre on disk, and confirm verify_full() now flags it -- today
    (pre-fix) it returns ok=True because output_sha256 was always ""."""
    fk = _fk_yaml(tmp_path)
    mitre = _mitre_map(tmp_path)
    case_dir = tmp_path / "004-finding-tamper"
    (case_dir / "findings").mkdir(parents=True)

    emit_from_handle(
        handle=_handle(), case_dir=str(case_dir), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-MASQ-01", title="rundll32 masquerade",
    )

    finding_path = case_dir / "findings" / "F-004-001.yaml"
    finding = yaml.safe_load(finding_path.read_text())

    # Sanity: untampered finding passes.
    before = verify_full(str(case_dir))
    assert before["checks"]["finding_integrity"]["passed"] is True

    finding["status"] = "CONFIRMED"
    finding["confidence"] = 1.0
    finding["mitre_attack"] = "T1059.001"
    finding["forensic_caveats"] = []
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))

    after = verify_full(str(case_dir))
    assert after["checks"]["finding_integrity"]["passed"] is False
    assert after["ok"] is False


# ── core/emit_finding.py: the self-referencing emit path (evidence_refs
#    cites the finding_create row's OWN entry_sha256, so that row can't
#    also carry the file's hash without becoming circular -- see the
#    module's docstring). Its LATER finding_status row does carry the real
#    hash instead. ─────────────────────────────────────────────────────────
def test_core_emit_finding_status_row_records_real_hash(tmp_path):
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir

    case_dir = make_case_dir(tmp_path)
    result = build_case000_case(case_dir)
    finding = result["findings"][0]
    finding_path = case_dir / "findings" / f"{finding['finding_id']}.yaml"

    rows = [json.loads(l) for l in
            (case_dir / "audit.jsonl").read_text().splitlines() if l.strip()]
    status_rows = [r for r in rows if r.get("action") == "finding_status"]
    assert status_rows, "expected a finding_status row from core/emit_finding.py"
    recorded = status_rows[-1]["output_sha256"]
    assert recorded

    actual = hashlib.sha256(finding_path.read_bytes()).hexdigest()
    assert recorded == actual


def test_core_emit_finding_tamper_detected(tmp_path):
    from tests.test_pipeline.case000_core import build_case000_case, make_case_dir

    case_dir = make_case_dir(tmp_path)
    build_case000_case(case_dir)

    finding_files = sorted((case_dir / "findings").glob("F-*.yaml"))
    assert finding_files
    fp = finding_files[0]
    finding = yaml.safe_load(fp.read_text())
    finding["status"] = "CONFIRMED"
    fp.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))

    report = verify_full(str(case_dir))
    assert report["checks"]["finding_integrity"]["passed"] is False
    assert report["ok"] is False


# ── Backfill: a finding with NO recorded hash anywhere (pre-existing
#    fixture / legacy case) must WARN, not fail -- so old test fixtures and
#    real historical cases don't red-line the moment this check ships. ────
def test_legacy_finding_with_no_recorded_hash_is_not_a_failure(tmp_path):
    case_dir = tmp_path / "004-legacy"
    (case_dir / "findings").mkdir(parents=True)
    (case_dir / "findings" / "F-004-001.yaml").write_text(
        yaml.safe_dump({"finding_id": "F-004-001", "status": "INFERRED"})
    )
    # No audit.jsonl row at all references this finding.
    report = verify_full(str(case_dir))
    assert report["checks"]["finding_integrity"]["passed"] is True


def test_no_findings_is_not_a_failure(tmp_path):
    case_dir = tmp_path / "004-empty"
    case_dir.mkdir(parents=True)
    report = verify_full(str(case_dir))
    assert report["checks"]["finding_integrity"]["passed"] is True


# ── explain() persist=True rewrite is a legitimate THIRD writer; its own
#    row must carry the post-rewrite hash so the finding_integrity check
#    doesn't false-positive on a normal AI-narrative pass. ─────────────────
def test_explain_persist_rewrite_updates_recorded_hash(tmp_path):
    from spectre.core.explain import _finalize

    case_dir = tmp_path / "004-explain-rewrite"
    (case_dir / "findings").mkdir(parents=True)
    finding_path = case_dir / "findings" / "F-004-001.yaml"
    finding = {
        "finding_id": "F-004-001", "status": "INFERRED", "confidence": 0.5,
        "mitre_attack": "UNMAPPED", "forensic_caveats": [],
        "evidence_refs": [{"execution_id": "abc"}],
    }
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))

    # Seed the emit-time row (as emit_from_handle would have) so there is a
    # PRIOR (now-stale) recorded hash to supersede.
    stale_bytes = finding_path.read_bytes()
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(finding_path),
        "output_sha256": hashlib.sha256(stale_bytes).hexdigest(),
        "result": "success", "finding_id": "F-004-001",
        "phase": 3, "phase_step": "S1-emit",
    })

    _finalize(
        finding=dict(finding), finding_path=str(finding_path),
        fk_caveats=["placeholder caveat"], allowed_mitre=["UNMAPPED"],
        finding_id="F-004-001", case_dir_path=case_dir, case_id=case_dir.name,
        adversarial=False, phase=5,
        output={"description": "AI description.", "mitre_attack": "UNMAPPED",
                "caveats": ["placeholder caveat"], "next_evidence": []},
        token_usage={"prompt": 1, "completion": 1},
        provider_name="test-provider", model="test-model", persist=True,
    )

    # The file changed (description patched in) -- the OLD row's hash must
    # no longer match, but verify_full() must still pass because the NEW
    # (explain) row recorded the post-rewrite hash.
    report = verify_full(str(case_dir))
    assert report["checks"]["finding_integrity"]["passed"] is True

    rows = [json.loads(l) for l in
            (case_dir / "audit.jsonl").read_text().splitlines() if l.strip()]
    explain_rows = [r for r in rows if r.get("phase_step") == "S1-explain-norm"]
    assert explain_rows and explain_rows[-1]["output_sha256"]
    actual = hashlib.sha256(finding_path.read_bytes()).hexdigest()
    assert explain_rows[-1]["output_sha256"] == actual
