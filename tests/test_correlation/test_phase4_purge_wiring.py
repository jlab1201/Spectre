"""WS3's purge_dropped_findings() (spectre.pipeline.correlation) was built
but never wired into the live pipeline -- the natural call site, Phase 4
(it already globs findings/F-*-*.yaml before correlating), was left for a
follow-on. This wires it in: run_phase_4 must purge DROPPED-status finding
YAMLs from disk before/while correlating, so
skills/correlation-engine/SKILL.md's documented "0 sources -> DROPPED
(auto-purged)" claim is actually true of the live pipeline, not just the
standalone utility.
"""
import yaml

from spectre.pipeline import phase_runner


def _write_finding(d, fid, status="INFERRED", sources=1, evidence_refs=None,
                    host_ip="10.0.0.5", event_time="2026-01-30 20:00:00"):
    (d / "findings").mkdir(exist_ok=True)
    if evidence_refs is None:
        evidence_refs = [{"execution_id": "e1"}] if sources else []
    p = d / "findings" / f"{fid}.yaml"
    p.write_text(yaml.safe_dump({
        "finding_id": fid, "status": status, "host_ip": host_ip,
        "event_time": event_time, "evidence_refs": evidence_refs,
        "corroboration": {"tools": ["x/pcap"], "sources": sources},
        "confidence": 0.5, "iocs": {},
    }))
    return p


def test_run_phase_4_purges_dropped_finding_from_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "audit.jsonl").write_text("")
    kept = _write_finding(tmp_path, "F-1-001", status="INFERRED", sources=1)
    dropped = _write_finding(tmp_path, "F-1-002", status="DROPPED", sources=0,
                              evidence_refs=[])

    manifest = {"monitored_ip": "10.0.0.5"}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)

    assert kept.exists()
    assert not dropped.exists(), "DROPPED finding must be purged from disk by Phase 4"

    # The purged finding must not appear anywhere in Phase 4's own bookkeeping.
    fids = {r["finding_id"] for r in result["correlation"]}
    assert "F-1-002" not in fids
    assert "F-1-001" in fids


def test_run_phase_4_purge_runs_even_when_all_findings_dropped(tmp_path, monkeypatch):
    """The zero-findings-to-correlate branch must also purge -- a case
    where every finding was DROPPED must not leave stale YAMLs on disk."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "audit.jsonl").write_text("")
    dropped = _write_finding(tmp_path, "F-1-001", status="DROPPED", sources=0,
                              evidence_refs=[])

    manifest = {}
    result = phase_runner.run_phase_4(str(tmp_path), manifest)

    assert result["findings_correlated"] == 0
    assert not dropped.exists()
