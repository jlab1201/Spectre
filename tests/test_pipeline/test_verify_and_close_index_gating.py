"""W1-2: runner.verify_and_close() called cross_case_index.update_index()
unconditionally, even when the Phase-7 integrity result (verify_chain AND/OR
verify_full) was FAILED -- so a tampered case's findings still got written
into the shared cross-case index. Gate the write on the combined
`overall_ok` (verify_chain and verify_full both passing), and print a clear
"NOT updated" note (with the reason) on failure instead of silently skipping.

Follows the same tmp cases_dir isolation convention as
tests/test_pipeline/test_phase7_verify_full_wiring.py and
tests/test_pipeline/test_cross_case_containment.py.
"""
import hashlib
import json
from pathlib import Path

import yaml

from spectre.pipeline.audit import append as audit_append
from spectre.pipeline import runner


def _clean_case(case_dir: Path, sha_override: str | None = None) -> dict:
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

    manifest_sha = sha_override if sha_override is not None else sha
    manifest = {"case_id": case_dir.name.split("-")[0],
                "evidence": [{"evidence_path": str(ev_path), "sha256": manifest_sha}]}
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    return manifest


def _write_confirmed_finding(case_dir: Path, sha_ioc: str) -> None:
    data = {
        "finding_id": "F-002-001",
        "status": "CONFIRMED",
        "confidence": 0.75,
        "title": "test finding",
        "mitre_attack": "T1071.001",
        "evidence_refs": [{"execution_id": "abc123"}],
        "corroboration": {"sources": 2},
        "iocs": {"sha256": [sha_ioc]},
        "timestamp": "2026-08-01T00:00:00",
    }
    (case_dir / "findings" / "F-002-001.yaml").write_text(yaml.safe_dump(data))
    # verify_full()'s audit_disk check requires every on-disk finding YAML
    # to have a matching finding_id in audit.jsonl.
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(case_dir / "findings" / "F-002-001.yaml"),
        "output_sha256": "", "result": "success", "finding_id": "F-002-001",
        "phase": 3, "phase_step": "S1-emit",
    })


def test_index_not_updated_when_verify_full_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-tampered"
    manifest = _clean_case(case_dir)
    _write_confirmed_finding(case_dir, "a" * 64)

    # Tamper the manifest's evidence sha256 -- the exact A8-F2 repro.
    manifest["evidence"][0]["sha256"] = "0" * 64
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is False

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["gate_7"]["cross_case_updated"] is False, (
        "a case that fails Phase-7 integrity must never be written into "
        "the shared cross-case index"
    )

    index_path = tmp_path / "index.md"
    if index_path.exists():
        assert "a" * 64 not in index_path.read_text(), (
            "the tampered case's finding IOC must not reach the cross-case "
            "index"
        )

    captured = capsys.readouterr()
    assert "NOT updated" in captured.err
    assert "Cross-case index" in captured.err


def test_index_updated_when_integrity_ok(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-clean"
    manifest = _clean_case(case_dir)
    _write_confirmed_finding(case_dir, "b" * 64)

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is True

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["gate_7"]["cross_case_updated"] is True

    index_path = tmp_path / "index.md"
    assert index_path.exists()
    assert "b" * 64 in index_path.read_text()

    captured = capsys.readouterr()
    assert "Cross-case index: updated" in captured.err


# ── W1 required fix 4: audit row on skip + retraction of a prior OK run ──

def test_index_not_updated_writes_an_audit_row_recording_the_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-tampered"
    manifest = _clean_case(case_dir)
    _write_confirmed_finding(case_dir, "a" * 64)

    manifest["evidence"][0]["sha256"] = "0" * 64
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    ok = runner.verify_and_close(str(case_dir), manifest)
    assert ok is False

    rows = [json.loads(line) for line in
            (case_dir / "audit.jsonl").read_text().splitlines() if line.strip()]
    skip_rows = [r for r in rows if r.get("action") == "cross_case_index_skipped"]
    assert len(skip_rows) == 1, (
        "a Phase-7 integrity failure must land a chained audit row "
        "recording that the cross-case index was NOT updated, not only "
        "a stderr print"
    )
    row = skip_rows[0]
    assert row["params"]["audit_chain_valid"] is True
    assert row["params"]["verify_full_ok"] is False
    assert row["case_id"] == "002-tampered"
    assert "entry_sha256" in row
    assert row.get("finding_id") is None, (
        "a finding_id here would falsely register in verify_full()'s "
        "audit_disk check for a finding that isn't actually associated "
        "with this housekeeping row"
    )


def test_failed_run_retracts_stale_entries_from_a_prior_ok_run(tmp_path, monkeypatch):
    """A case indexed by an earlier OK Phase 7, then later found tampered
    on resume (e.g. re-verified after an edit), must have its rows removed
    from the shared cross-case index -- a stale row from the once-clean
    run must not keep contributing to every other case's narrative
    context after the case is known to have failed integrity."""
    monkeypatch.setattr(runner, "CASES_DIR", tmp_path)
    case_dir = tmp_path / "002-was-clean"
    manifest = _clean_case(case_dir)
    _write_confirmed_finding(case_dir, "c" * 64)

    ok1 = runner.verify_and_close(str(case_dir), manifest)
    assert ok1 is True
    index_path = tmp_path / "index.md"
    assert "c" * 64 in index_path.read_text()

    # Now tamper and re-run (the resume-and-tamper scenario).
    manifest["evidence"][0]["sha256"] = "0" * 64
    (case_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest))

    ok2 = runner.verify_and_close(str(case_dir), manifest)
    assert ok2 is False

    assert "c" * 64 not in index_path.read_text(), (
        "a case that FAILS Phase-7 integrity on a later run must have its "
        "earlier-indexed rows retracted, not just skipped going forward"
    )
