"""MUST-FIX 2 (Hunt D, post-review): explain()/ingest_host_output()'s
persist=True rewrite overwrites only description/mitre_attack/
forensic_caveats but PRESERVES whatever status/confidence/title/
corroboration/iocs/host/timestamps are on disk, then re-hashes the WHOLE
file and records that fresh hash on its own audit row. finding_integrity
then trusts that row as authoritative.

Repro (cheaper than H2 -- no chain re-forge needed): tamper a finding's
deterministic-owned fields directly (status -> CONFIRMED, confidence ->
1.0) so finding_integrity correctly fails; then run ONE valid explain
persist pass. Before the fix, explain blindly re-hashes the (still
tampered) file and finding_integrity flips back to PASSED -- the tamper
gets "laundered" through a legitimate-looking audit row.

Fix: before persisting, _finalize() re-hashes the on-disk bytes AS THEY
ARE RIGHT NOW and compares against the LATEST previously-recorded hash for
this finding_id (the same baseline finding_integrity itself trusts). A
mismatch means something changed the file since the last legitimate
writer -- persist is REFUSED (fail closed) rather than re-blessing
whatever is on disk. Only description/mitre_attack/forensic_caveats are
AI-owned and legitimately rewritable by explain(); refusing to persist at
all when the pre-image doesn't match is a conservative superset of "don't
let explain re-bless deterministic fields."
"""
import hashlib
import json

import yaml

from spectre.pipeline.audit import append as audit_append, verify_full
from spectre.core.explain import _finalize


def _seed_finding(case_dir, finding_id="F-004-001"):
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "findings").mkdir(parents=True, exist_ok=True)
    finding_path = case_dir / "findings" / f"{finding_id}.yaml"
    finding = {
        "finding_id": finding_id, "status": "INFERRED", "confidence": 0.5,
        "mitre_attack": "UNMAPPED", "forensic_caveats": [],
        "title": "original deterministic title",
        "corroboration": {"sources": 1, "tools": ["evtx"]},
        "evidence_refs": [{"execution_id": "abc"}],
    }
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))
    emit_sha = hashlib.sha256(finding_path.read_bytes()).hexdigest()

    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(finding_path), "output_sha256": emit_sha,
        "result": "success", "finding_id": finding_id,
        "phase": 3, "phase_step": "S1-emit",
    })
    return finding_path


def _run_explain_persist(case_dir, finding_path, finding_id):
    finding = yaml.safe_load(finding_path.read_text())
    return _finalize(
        finding=finding, finding_path=str(finding_path),
        fk_caveats=["placeholder caveat"], allowed_mitre=["UNMAPPED"],
        finding_id=finding_id, case_dir_path=case_dir, case_id=case_dir.name,
        adversarial=False, phase=5,
        output={"description": "AI description.", "mitre_attack": "UNMAPPED",
                "caveats": ["placeholder caveat"], "next_evidence": []},
        token_usage={"prompt": 1, "completion": 1},
        provider_name="test-provider", model="test-model", persist=True,
    )


def test_tampered_deterministic_fields_survive_explain_persist_as_still_failed(tmp_path):
    """The exact repro: tamper status/confidence on disk (no chain
    re-forge), confirm finding_integrity fails, then run ONE legitimate
    explain persist pass and confirm finding_integrity is STILL failed
    afterward -- the tamper must not be laundered by explain's re-hash."""
    case_dir = tmp_path / "004-hunt-d"
    finding_id = "F-004-001"
    finding_path = _seed_finding(case_dir, finding_id)

    # Sanity: untampered, finding_integrity passes.
    assert verify_full(str(case_dir))["checks"]["finding_integrity"]["passed"] is True

    # Tamper deterministic-owned fields directly (attacker, no chain forge).
    finding = yaml.safe_load(finding_path.read_text())
    finding["status"] = "CONFIRMED"
    finding["confidence"] = 1.0
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))

    # Confirm the tamper is detected BEFORE any explain call.
    pre = verify_full(str(case_dir))
    assert pre["checks"]["finding_integrity"]["passed"] is False

    # ONE legitimate explain/ingest persist pass.
    result = _run_explain_persist(case_dir, finding_path, finding_id)

    # The tampered status/confidence must still be on disk (explain never
    # overwrites deterministic fields) ...
    after_finding = yaml.safe_load(finding_path.read_text())
    assert after_finding["status"] == "CONFIRMED"
    assert after_finding["confidence"] == 1.0

    # ... and finding_integrity must NOT have flipped back to passing --
    # that would mean the tamper got laundered through explain's own hash.
    post = verify_full(str(case_dir))
    assert post["checks"]["finding_integrity"]["passed"] is False, (
        "explain() re-hashed a tampered finding and finding_integrity "
        "trusted it as authoritative -- the tamper was laundered (Hunt D)"
    )
    assert result.get("persist_refused") is True


def test_persist_is_actually_refused_file_left_byte_identical(tmp_path):
    """Refusal must not even touch the file -- not a partial/half rewrite,
    the tampered bytes are left exactly as the attacker left them (so a
    later legitimate recovery path has the untouched evidence to work
    from)."""
    case_dir = tmp_path / "004-hunt-d-bytes"
    finding_id = "F-004-001"
    finding_path = _seed_finding(case_dir, finding_id)

    finding = yaml.safe_load(finding_path.read_text())
    finding["status"] = "CONFIRMED"
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))
    tampered_bytes = finding_path.read_bytes()

    _run_explain_persist(case_dir, finding_path, finding_id)

    assert finding_path.read_bytes() == tampered_bytes


def test_refusal_is_audited_not_silent(tmp_path):
    case_dir = tmp_path / "004-hunt-d-audit"
    finding_id = "F-004-001"
    finding_path = _seed_finding(case_dir, finding_id)

    finding = yaml.safe_load(finding_path.read_text())
    finding["confidence"] = 1.0
    finding_path.write_text(yaml.safe_dump(finding, default_flow_style=False, sort_keys=False))

    _run_explain_persist(case_dir, finding_path, finding_id)

    rows = [json.loads(l) for l in
            (case_dir / "audit.jsonl").read_text().splitlines() if l.strip()]
    refusal_rows = [r for r in rows if r.get("result") == "refused"]
    assert refusal_rows, "a refused persist must leave an audit trail, not fail silently"


def test_untampered_explain_persist_still_works_and_updates_hash(tmp_path):
    """Regression guard: the guard must not block a LEGITIMATE persist --
    untampered finding, real explain pass, description/mitre/caveats
    change, hash updates, finding_integrity stays green."""
    case_dir = tmp_path / "004-hunt-d-clean"
    finding_id = "F-004-001"
    finding_path = _seed_finding(case_dir, finding_id)

    result = _run_explain_persist(case_dir, finding_path, finding_id)
    assert result.get("persist_refused") is not True

    after_finding = yaml.safe_load(finding_path.read_text())
    assert after_finding["description"] == "AI description."

    report = verify_full(str(case_dir))
    assert report["checks"]["finding_integrity"]["passed"] is True
