"""Phase 4 gate: every evidence_ref execution_id of a surviving finding must
resolve to a chained deterministic-core tool_exec row in THIS case's
audit.jsonl. An unresolved finding is handled like one with empty
evidence_refs (failed correlation entry, excluded from clustering, gate_4
fails) plus one chained audit row naming it and its unresolved ids."""
import json

import yaml

from spectre.pipeline import phase_runner
from spectre.pipeline.audit import append, verify_chain


def _tool_exec(case_dir):
    return append(str(case_dir), {
        "actor": "deterministic-core", "action": "tool_exec", "tool": "tcpdump",
        "case_id": case_dir.name, "output_path": "", "output_sha256": "",
        "phase": 2, "phase_step": "S1-extract-tcpdump"})


def _finding(case_dir, fid, refs):
    (case_dir / "findings").mkdir(exist_ok=True)
    p = case_dir / "findings" / f"{fid}.yaml"
    p.write_text(yaml.safe_dump({
        "finding_id": fid, "status": "INFERRED", "host_ip": "10.0.0.5",
        "event_time": "2026-01-30 20:00:00", "evidence_refs": refs,
        "corroboration": {"sources": 1}, "confidence": 0.5, "iocs": {}}))
    return p


def _rows(case_dir):
    return [json.loads(l) for l in (case_dir / "audit.jsonl").read_text().splitlines()
            if l.strip()]


def _by_fid(result):
    return {r["finding_id"]: r for r in result["correlation"]}


def test_resolved_finding_passes(tmp_path):
    eid = _tool_exec(tmp_path)
    _finding(tmp_path, "F-1-001", [{"execution_id": eid, "source": "tool_exec"}])
    manifest = {}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)
    assert _by_fid(result)["F-1-001"]["passed"] is True
    assert manifest["gate_4"]["passed"] is True
    assert not [r for r in _rows(tmp_path) if r["action"] == "evidence_ref_unresolved"]


def test_unresolved_finding_fails_like_empty_refs_and_is_audited(tmp_path):
    eid = _tool_exec(tmp_path)
    reg = append(str(tmp_path), {"actor": "deterministic-core",
                                 "action": "finding_create", "phase": 3,
                                 "phase_step": "S1-emit", "case_id": tmp_path.name})
    good = _finding(tmp_path, "F-1-001", [{"execution_id": eid}])
    bad = _finding(tmp_path, "F-1-002", [{"execution_id": eid},
                                         {"execution_id": "mpfs-2026"},
                                         {"execution_id": reg},
                                         {"source": "tool_exec"}])
    before = bad.read_bytes()
    manifest = {}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)

    r = _by_fid(result)["F-1-002"]
    assert r["passed"] is False
    assert r["error"].startswith("UNRESOLVED")
    assert _by_fid(result)["F-1-001"]["passed"] is True
    assert manifest["gate_4"]["passed"] is False
    assert manifest["gate_4"]["all_have_sources"] is False
    assert bad.read_bytes() == before, "no YAML write outside the hash-authority path"
    assert good.exists() and bad.exists()

    rows = [x for x in _rows(tmp_path) if x["action"] == "evidence_ref_unresolved"]
    assert len(rows) == 1
    assert rows[0]["finding_id"] == "F-1-002"
    assert rows[0]["params"]["unresolved_execution_ids"] == [
        "mpfs-2026", reg, "<missing>"]
    assert rows[0]["phase"] == 4
    assert verify_chain(str(tmp_path))[0]


def test_unresolved_finding_excluded_from_clustering(tmp_path, monkeypatch):
    _finding(tmp_path, "F-1-001", [{"execution_id": "nope"}])
    seen = {}
    from spectre.pipeline.correlation import clustering

    def _spy(findings, ips):
        seen["fids"] = [f["finding_id"] for f in findings]
        return {"ioc_overlap": [], "temporal": []}
    monkeypatch.setattr(clustering, "cluster_findings", _spy)
    (tmp_path / "audit.jsonl").write_text("")
    phase_runner.run_phase_4(str(tmp_path), {})
    assert seen["fids"] == []


def test_broken_chain_makes_every_ref_unresolved(tmp_path):
    eid = _tool_exec(tmp_path)
    _finding(tmp_path, "F-1-001", [{"execution_id": eid}])
    # Corrupt the chain: edit a hashed field so verify_chain fails while the
    # row (and its entry_sha256) still parses.
    ap = tmp_path / "audit.jsonl"
    ap.write_text(ap.read_text().replace('"tcpdump"', '"tcpdumX"', 1))
    assert not verify_chain(str(tmp_path))[0]
    manifest = {}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)
    assert _by_fid(result)["F-1-001"]["passed"] is False
    assert manifest["gate_4"]["passed"] is False


def test_missing_audit_makes_every_ref_unresolved(tmp_path):
    _finding(tmp_path, "F-1-001", [{"execution_id": "a" * 64}])
    manifest = {}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)
    assert _by_fid(result)["F-1-001"]["passed"] is False


def test_fixture_profile_findings_cite_their_tool_exec_row(tmp_path):
    """The fixture-test profile (core emit) must cite the extraction's
    tool_exec row, not the finding's own finding_create row, so its findings
    pass the gate."""
    case_dir = tmp_path / "001-fixturegate"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True)
    manifest = {"case_id": "001", "case_name": "fixturegate",
                "artifact_profile": "fixture-test", "canary_status": "FULL",
                "artifacts": ["evtx_4688"], "evidence": [], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    phase_runner._run_phase_2_fixture(str(case_dir), manifest)
    phase_runner._run_phase_3_fixture(str(case_dir), manifest)
    assert list((case_dir / "findings").glob("F-*-*.yaml"))

    result = phase_runner.run_phase_4(str(case_dir), manifest)
    assert all(r["passed"] for r in result["correlation"]), result["correlation"]
    assert manifest["gate_4"]["passed"] is True
