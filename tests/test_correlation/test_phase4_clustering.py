import hashlib
import yaml
from spectre.pipeline import phase_runner
from spectre.pipeline.audit import append


def _tool_exec(d):
    """A chained tool_exec row for the findings to cite (Phase 4 resolves
    every evidence_ref execution_id against audit.jsonl)."""
    return append(str(d), {"actor": "deterministic-core", "action": "tool_exec",
                           "tool": "fixture", "case_id": d.name, "phase": 2,
                           "phase_step": "S1-extract-fixture"})


def _write_finding(d, fid, iocs, tools, host_ip="10.0.0.5", event_time="2026-01-30 20:00:00",
                    evidence_refs=None):
    if evidence_refs is None:
        evidence_refs = [{"execution_id": _tool_exec(d)}]
    (d / "findings").mkdir(exist_ok=True)
    p = d / "findings" / f"{fid}.yaml"
    p.write_text(yaml.safe_dump({
        "finding_id": fid, "iocs": iocs, "host_ip": host_ip, "event_time": event_time,
        "evidence_refs": evidence_refs,
        "corroboration": {"tools": tools, "sources": 1},
        "status": "INFERRED", "confidence": 0.5,
    }))
    return p


def test_phase4_populates_clusters_without_mutating_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f1 = _write_finding(tmp_path, "F-1-001", {"filepath": ["C:/evil.exe"]}, ["x/evtx"])
    f2 = _write_finding(tmp_path, "F-1-002", {"filepath": ["c:/evil.exe"]}, ["y/prefetch"])
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (f1, f2)}

    manifest = {"monitored_ip": "10.0.0.5"}
    phase_runner.run_phase_4(str(tmp_path), manifest)

    clusters = manifest["correlation_clusters"]
    assert len(clusters["ioc_overlap"]) == 1
    assert set(clusters["ioc_overlap"][0]["member_finding_ids"]) == {"F-1-001", "F-1-002"}
    # findings are NOT mutated (byte-identical)
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (f1, f2)}
    assert before == after
    # exactly one clustering audit row
    rows = [l for l in (tmp_path / "audit.jsonl").read_text().splitlines() if "S4-cluster" in l]
    assert len(rows) == 1


def test_phase4_excludes_dropped_no_evidence_finding_from_clustering(tmp_path, monkeypatch):
    """A finding sharing the same IOC but with no evidence_refs is dropped by
    Phase 4 before clustering ever sees it, so it must never appear as a
    cluster member."""
    monkeypatch.chdir(tmp_path)
    _write_finding(tmp_path, "F-1-001", {"filepath": ["C:/evil.exe"]}, ["x/evtx"])
    _write_finding(tmp_path, "F-1-002", {"filepath": ["c:/evil.exe"]}, ["y/prefetch"])
    _write_finding(tmp_path, "F-1-003", {"filepath": ["c:/evil.exe"]}, ["z/pcap"],
                         evidence_refs=[])

    manifest = {"monitored_ip": "10.0.0.5"}
    phase_runner.run_phase_4(str(tmp_path), manifest)

    clusters = manifest["correlation_clusters"]
    assert len(clusters["ioc_overlap"]) == 1
    all_members = set(clusters["ioc_overlap"][0]["member_finding_ids"])
    assert all_members == {"F-1-001", "F-1-002"}
    assert "F-1-003" not in all_members
