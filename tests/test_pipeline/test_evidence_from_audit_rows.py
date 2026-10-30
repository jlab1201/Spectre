"""WS1b — residual E closed: verify_full() verifies evidence from the chained
evidence_register audit rows directly, so emptying manifest.yaml's evidence[]
(a plain mutable file) can no longer make the evidence check vacuous."""


import yaml

from spectre.pipeline.audit import verify_full
from tests.test_pipeline.test_manifest_evidence_crosscheck import _seed_registered_evidence


def _empty_manifest_evidence(case_dir):
    mpath = case_dir / "manifest.yaml"
    m = yaml.safe_load(mpath.read_text())
    m["evidence"] = []          # the residual-E attack: drop the list entirely
    mpath.write_text(yaml.safe_dump(m))


def test_emptying_manifest_evidence_plus_tamper_is_still_caught(tmp_path):
    case_dir = tmp_path / "010-E-tamper"
    ev_path, _ = _seed_registered_evidence(case_dir)
    # Attack: tamper the evidence file AND empty manifest.evidence[] so the
    # manifest-driven check goes vacuous. The audit-row-driven check must
    # still catch the content change.
    ev_path.chmod(0o644)
    ev_path.write_bytes(b"tampered evidence bytes")
    ev_path.chmod(0o444)
    _empty_manifest_evidence(case_dir)

    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is False
    assert report["ok"] is False
    assert "changed since registration" in report["checks"]["evidence"]["detail"]


def test_emptying_manifest_evidence_plus_delete_is_still_caught(tmp_path):
    case_dir = tmp_path / "011-E-delete"
    ev_path, _ = _seed_registered_evidence(case_dir)
    ev_path.chmod(0o644)
    ev_path.unlink()
    _empty_manifest_evidence(case_dir)

    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is False
    assert "missing on disk" in report["checks"]["evidence"]["detail"]


def test_empty_manifest_but_intact_evidence_does_not_false_positive(tmp_path):
    case_dir = tmp_path / "012-E-clean"
    _seed_registered_evidence(case_dir)
    _empty_manifest_evidence(case_dir)     # manifest emptied, file untouched
    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is True
