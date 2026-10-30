"""A1-H3: verify_full()'s evidence check re-hashes evidence files against
manifest.yaml's evidence[].sha256 -- but manifest.yaml is a plain, always-
mutable file (not chmod 444 like the evidence copy, not part of the SHA-256
audit chain). The real H3 attack: tamper the evidence FILE, then update
manifest.yaml's recorded sha256 to match the new (tampered) content -- this
defeats the plain re-hash check because manifest and file now agree with
each other, even though neither matches what was true at registration time.

Fix: cross-check manifest.yaml's evidence[].sha256 against the immutable,
chained evidence_register (S2-register) audit row for that path -- which
still holds the ORIGINAL hash, since only the audit chain (not
manifest.yaml) is tamper-evident.
"""
import hashlib
from pathlib import Path

import yaml

from spectre.pipeline.audit import verify_full, append as audit_append


def _seed_registered_evidence(case_dir: Path, content: bytes = b"original evidence bytes"):
    """Build a case with one evidence file, registered exactly the way
    case_setup.py's _register_evidence() does: an evidence_register audit
    row carrying the true ingest-time hash, plus a manifest.yaml evidence[]
    entry that (at this point) agrees with it."""
    case_dir.mkdir(parents=True, exist_ok=True)
    ev_dir = case_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ev_path = ev_dir / "fake_evidence.log"
    ev_path.write_bytes(content)
    ev_path.chmod(0o444)
    true_sha = hashlib.sha256(content).hexdigest()

    audit_append(str(case_dir), {
        "actor": "case_setup", "action": "evidence_register",
        "tool": "case_setup.py", "case_id": case_dir.name,
        "params": {"original_path": str(ev_path), "copy_path": str(ev_path)},
        "output_path": str(ev_path), "output_sha256": true_sha,
        "result": "success", "phase": 0, "phase_step": "S2-register",
    })

    manifest = {"case_id": case_dir.name.split("-")[0],
                "evidence": [{"evidence_path": str(ev_path), "sha256": true_sha}]}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return ev_path, true_sha


def test_untampered_evidence_passes(tmp_path):
    case_dir = tmp_path / "002-h3-clean"
    _seed_registered_evidence(case_dir)
    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is True


def test_manifest_and_file_tampered_together_still_caught(tmp_path):
    """The real H3 attack: tamper the evidence file, then rewrite
    manifest.yaml's sha256 to match the NEW content -- the plain re-hash
    check alone is defeated by this (manifest now agrees with the file),
    but the chained evidence_register row still holds the original hash."""
    case_dir = tmp_path / "002-h3-attack"
    ev_path, true_sha = _seed_registered_evidence(case_dir)

    ev_path.chmod(0o644)
    ev_path.write_bytes(b"original evidence bytes\nINJECTED LINE evil=true\n")
    ev_path.chmod(0o444)
    tampered_sha = hashlib.sha256(ev_path.read_bytes()).hexdigest()
    assert tampered_sha != true_sha

    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    manifest["evidence"][0]["sha256"] = tampered_sha
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is False
    assert report["ok"] is False


def test_manifest_sha_tampered_alone_is_caught(tmp_path):
    """Simpler variant: manifest sha256 edited without touching the file at
    all. Already caught by the pre-existing re-hash-vs-file check; this pins
    that the new cross-check doesn't regress it."""
    case_dir = tmp_path / "002-h3-simple"
    ev_path, true_sha = _seed_registered_evidence(case_dir)

    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    manifest["evidence"][0]["sha256"] = "0" * 64
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is False
    assert report["ok"] is False


def test_manifest_entry_with_no_matching_audit_row_is_not_a_hard_failure(tmp_path):
    """A manifest evidence entry with no corresponding evidence_register row
    (legacy manifest, or a fixture built outside case_setup.py's
    registration path) has nothing to cross-check against -- this must not
    itself fail the check as long as the file still matches manifest."""
    case_dir = tmp_path / "002-h3-legacy"
    case_dir.mkdir(parents=True)
    ev_dir = case_dir / "evidence"
    ev_dir.mkdir(parents=True)
    ev_path = ev_dir / "legacy.log"
    content = b"legacy evidence, no registration row"
    ev_path.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    manifest = {"evidence": [{"evidence_path": str(ev_path), "sha256": sha}]}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    report = verify_full(str(case_dir))
    assert report["checks"]["evidence"]["passed"] is True
