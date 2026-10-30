"""Integration test: Phase 6 wires the DOCX renderer alongside the PDF
renderer. No prior test exercised run_phase_6 end-to-end before this.

Note run_phase_6 returns a *result* dict and mutates the manifest it is handed
in place (then persists it); the report paths land on the manifest, not on the
return value.
"""
from pathlib import Path

import yaml

from spectre.pipeline.phase_runner import run_phase_6


def _minimal_manifest() -> dict:
    return {
        "case_id": "999",
        "case_name": "docxwiring",
        "artifact_profile": "pcap-focused",
        "canary_status": "FULL",
        "evidence": [],
    }


def test_phase_6_wires_docx_alongside_pdf(tmp_path):
    case_dir = tmp_path / "999-docxwiring"
    (case_dir / "findings").mkdir(parents=True)

    manifest = _minimal_manifest()
    result = run_phase_6(str(case_dir), manifest, skip_ai=True)

    assert result["success"] is True
    assert "report_docx" in manifest["report"]
    assert "report_pdf" in manifest["report"]  # unchanged sibling key

    docx_path = manifest["report"]["report_docx"]
    if docx_path is None:
        return  # the optional 'report' extra is not installed

    assert Path(docx_path).exists()
    # A .docx is a zip: the local file header magic is "PK".
    assert Path(docx_path).read_bytes()[:2] == b"PK"


def test_phase_6_persists_docx_path_to_manifest_on_disk(tmp_path):
    """Phase 7 reads the manifest back off disk, so the key has to survive the
    save — not just exist on the in-memory dict."""
    case_dir = tmp_path / "999-docxwiring"
    (case_dir / "findings").mkdir(parents=True)

    manifest = _minimal_manifest()
    run_phase_6(str(case_dir), manifest, skip_ai=True)

    saved = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    assert saved["report"]["report_docx"] == manifest["report"]["report_docx"]
