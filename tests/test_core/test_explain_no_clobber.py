from spectre.core import explain


def test_finalize_does_not_write_report_md(tmp_path):
    case_dir = tmp_path
    (case_dir / "reports").mkdir()
    sentinel = case_dir / "reports" / "report.md"
    sentinel.write_text("# REAL PHASE-6 MULTI-FINDING REPORT\n")

    finding = {"finding_id": "F-000-001", "title": "t", "status": "CONFIRMED",
               "mitre_attack": "UNMAPPED", "forensic_caveats": [], "evidence_refs": [],
               "iocs": {}}
    fpath = case_dir / "F-000-001.yaml"

    explain._finalize(
        finding=finding, finding_path=str(fpath), fk_caveats=[], allowed_mitre=[],
        finding_id="F-000-001", case_dir_path=case_dir, case_id="000-spike",
        adversarial=False, phase=5,
        output={"description": "d", "mitre_attack": "UNMAPPED", "caveats": [], "next_evidence": []},
        token_usage={"prompt": 0, "completion": 0}, provider_name="null", model="none",
        persist=True,
    )

    # The multi-finding Phase-6 report must NOT have been clobbered by a stub.
    assert sentinel.read_text() == "# REAL PHASE-6 MULTI-FINDING REPORT\n"
