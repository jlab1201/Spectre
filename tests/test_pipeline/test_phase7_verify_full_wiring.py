"""A8-F2: verify_full() -- the only function that re-hashes evidence against
the manifest -- was fully correct but never called anywhere in the
pipeline. Phase 7's verify_and_close() called only verify_chain() (SHA-256
chain-linkage), so hand-editing manifest.yaml's evidence sha256 sailed
through Phase 7 printing "Audit: VALID". Wire verify_full() in, keep
verify_chain() too, and fail the phase closed when verify_full() finds a
problem.

NOTE: verify_and_close() also calls cross_case_index.update_index(str(
runner.CASES_DIR), ...). runner.CASES_DIR is bound from spectre.config at
IMPORT time, not read fresh from the environment per-call, so the
conftest.py `isolate_filesystem` env-var monkeypatch (set after config.py
is first imported) does not redirect it. Every test here explicitly
monkeypatches spectre.pipeline.runner.CASES_DIR to tmp_path so this test
suite never touches the real ~/spectre-cases/index.md.
"""
import hashlib
from pathlib import Path

import yaml

from spectre.pipeline.audit import append as audit_append
from spectre.pipeline import runner


def _clean_case(case_dir: Path) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("evidence", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    ev_path = case_dir / "evidence" / "fake_evidence.log"
    content = b"real evidence bytes"
    ev_path.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()

    audit_append(str(case_dir), {
        "actor": "case_setup", "action": "evidence_register",
        "tool": "case_setup.py", "case_id": case_dir.name,
        "output_path": str(ev_path), "output_sha256": sha,
        "result": "success", "phase": 0, "phase_step": "S2-register",
    })

    manifest = {"case_id": case_dir.name.split("-")[0],
                "evidence": [{"evidence_path": str(ev_path), "sha256": sha}]}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return manifest


def test_untampered_case_passes_phase7(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-clean"
    manifest = _clean_case(case_dir)

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is True

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["gate_7"]["passed"] is True
    assert saved["gate_7"]["verify_full_ok"] is True


def test_tampered_manifest_evidence_sha_fails_phase7_closed(tmp_path, monkeypatch):
    """The exact A8-F2 repro: tamper manifest.yaml's evidence sha256, then
    run Phase 7 -- must now fail closed instead of printing VALID."""
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-a8-sha-tamper"
    manifest = _clean_case(case_dir)

    manifest["evidence"][0]["sha256"] = "0" * 64
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is False, "Phase 7 must fail closed on a tampered evidence sha256"

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["gate_7"]["passed"] is False
    assert saved["gate_7"]["verify_full_ok"] is False


def test_verify_chain_still_runs_and_is_recorded(tmp_path, monkeypatch):
    """verify_chain() must not be dropped in favor of verify_full() --
    both are recorded on the gate."""
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-chain-check"
    manifest = _clean_case(case_dir)

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is True
    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert "audit_chain_valid" in saved["gate_7"]
    assert saved["gate_7"]["audit_chain_valid"] is True


def test_phase_coverage_stays_advisory_and_does_not_fail_an_in_progress_case(tmp_path, monkeypatch):
    """phase_coverage is intentionally advisory inside verify_full() (an
    in-progress finding legitimately hasn't reached every phase yet) --
    confirm wiring verify_full() into Phase 7 does not turn that into a
    hard failure for an otherwise-clean, in-progress case."""
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-in-progress"
    manifest = _clean_case(case_dir)

    # A finding that only has a finding_create row (Phase 3) -- no
    # adversarial_review / report_generated rows, i.e. genuinely
    # mid-pipeline, not tampered.
    fid = "F-002-001"
    (case_dir / "findings" / f"{fid}.yaml").write_text(
        yaml.safe_dump({"finding_id": fid, "status": "INFERRED"})
    )
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(case_dir / "findings" / f"{fid}.yaml"),
        "output_sha256": "", "result": "success", "finding_id": fid,
        "phase": 3, "phase_step": "S1-emit",
    })

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is True, "phase_coverage must stay advisory, not fail-closed"
