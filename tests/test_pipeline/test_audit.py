"""verify_full: derived-evidence re-verification (Finding 1, custody gap).

manifest["derived_evidence"] ({path: {sha256, derived_from, ...}}) is written
by phase_runner when disk carves nested artifacts out of an image. Those
carved files are real evidence — verify_full must re-hash them just like the
primary manifest["evidence"] list, or a tampered carve slips past custody
verification undetected.
"""
import hashlib
import os

import yaml

from spectre.pipeline.audit import append, verify_full


def _make_case(tmp_path):
    case = tmp_path / "case"
    (case / "evidence" / "derived").mkdir(parents=True)
    (case / "findings").mkdir()
    (case / "reports").mkdir()
    return case


def _seed_audit_row(case):
    """One valid audit row so verify_chain() passes too — keeps the test
    focused on the derived_evidence check rather than an incidental chain
    failure on an empty log."""
    append(str(case), {
        "actor": "test", "action": "note", "tool": "test", "tool_version": "1.0",
        "exact_command": "seed", "params": {}, "case_id": case.name,
        "result": "success", "exit_code": 0, "duration_ms": 0,
        "phase": 2, "phase_step": "S2-derive",
    })


def _write_manifest(case, derived_evidence):
    (case / "manifest.yaml").write_text(yaml.safe_dump({"derived_evidence": derived_evidence}))


def test_verify_full_passes_when_derived_evidence_hash_matches(tmp_path):
    case = _make_case(tmp_path)
    _seed_audit_row(case)

    carved = case / "evidence" / "derived" / "Security.evtx"
    carved.write_bytes(b"carved evtx bytes")
    sha = hashlib.sha256(carved.read_bytes()).hexdigest()

    _write_manifest(case, {
        str(carved): {"sha256": sha, "derived_from": str(case / "evidence" / "image.dd")},
    })

    report = verify_full(str(case))
    assert report["checks"]["derived_evidence"]["passed"] is True
    assert report["checks"]["derived_evidence"]["detail"] == "ok"


def test_verify_full_fails_when_derived_evidence_is_tampered(tmp_path):
    case = _make_case(tmp_path)
    _seed_audit_row(case)

    carved = case / "evidence" / "derived" / "Security.evtx"
    carved.write_bytes(b"carved evtx bytes")
    sha = hashlib.sha256(carved.read_bytes()).hexdigest()
    os.chmod(carved, 0o444)

    _write_manifest(case, {
        str(carved): {"sha256": sha, "derived_from": str(case / "evidence" / "image.dd")},
    })

    # Flip a byte in the read-only carved file, as a tamper would.
    os.chmod(carved, 0o644)
    data = bytearray(carved.read_bytes())
    data[0] ^= 0xFF
    carved.write_bytes(bytes(data))
    os.chmod(carved, 0o444)

    report = verify_full(str(case))
    assert report["checks"]["derived_evidence"]["passed"] is False
    assert str(carved) in report["checks"]["derived_evidence"]["detail"]
    assert report["ok"] is False


def test_verify_full_fails_when_recorded_sha_is_wrong(tmp_path):
    case = _make_case(tmp_path)
    _seed_audit_row(case)

    carved = case / "evidence" / "derived" / "Security.evtx"
    carved.write_bytes(b"carved evtx bytes")

    _write_manifest(case, {
        str(carved): {"sha256": "0" * 64, "derived_from": str(case / "evidence" / "image.dd")},
    })

    report = verify_full(str(case))
    assert report["checks"]["derived_evidence"]["passed"] is False
    assert str(carved) in report["checks"]["derived_evidence"]["detail"]


def test_verify_full_fails_when_derived_evidence_file_missing(tmp_path):
    case = _make_case(tmp_path)
    _seed_audit_row(case)

    missing = case / "evidence" / "derived" / "gone.evtx"

    _write_manifest(case, {
        str(missing): {"sha256": "a" * 64, "derived_from": str(case / "evidence" / "image.dd")},
    })

    report = verify_full(str(case))
    assert report["checks"]["derived_evidence"]["passed"] is False
    assert str(missing) in report["checks"]["derived_evidence"]["detail"]


def test_verify_full_passes_with_no_derived_evidence_key(tmp_path):
    """Back-compat: manifests written before this feature (no derived_evidence
    key at all) must not fail the new check."""
    case = _make_case(tmp_path)
    _seed_audit_row(case)
    (case / "manifest.yaml").write_text(yaml.safe_dump({"evidence": []}))

    report = verify_full(str(case))
    assert report["checks"]["derived_evidence"]["passed"] is True
