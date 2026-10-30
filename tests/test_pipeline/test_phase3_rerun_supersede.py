"""W4-5 / R2-18: `--phase 3 --force` doubled the findings (13 → 27, every
title twice, both copies in the report).

A Phase-3 re-run now retires every registered prior finding into
findings/superseded/ with a chained `finding_supersede` row (bytes unchanged,
hash re-recorded at the new location) before emitting afresh. verify_full's
audit↔disk and finding_integrity checks accept a superseded finding, and
still fail on a tampered one.
"""
import json
from pathlib import Path

import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.pipeline import phase_runner
from spectre.pipeline.audit import verify_full
from spectre.pipeline.emit_finding import get_next_finding_number


def _make_case(tmp):
    case_dir = Path(tmp) / "001-rerun"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    events = [{"artifact_type": "fake_art", "timestamp": "2026-07-09T03:00:00Z",
               "source_file": "evidence/x.bin", "record_id": rid, "host": "WS01",
               "data": {"flag": True}} for rid in ("A", "B")]
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))
    handle = {"execution_id": "", "line_count": 5, "size_bytes": 100,
              "tool": "faketool", "tool_version": "0.1", "exact_command": "faketool",
              "empty_data_status": "DATA_PRESENT", "evidence_path": "evidence/x.bin",
              "path": "raw_extract/x.json", "artifact_type": "fake_art"}
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps([handle]))
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))
    manifest = {"case_id": "001", "case_name": "rerun", "artifact_profile": "auto",
                "canary_status": "FULL", "direction": "", "focus": False,
                "evidence": [], "artifacts": ["fake_art"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _module():
    def pred(e):
        if e.data.get("flag"):
            return Anchor(rule_id="fake-rule", artifact_type="fake_art", event=e,
                          title=f"flag {e.record_id}", mitre=[], confidence=0.9,
                          dedup_key=e.record_id)
        return None
    rule = Rule(rule_id="fake-rule", artifact_type="fake_art", predicate=pred,
                mitre=[], description="d",
                metadata=RuleMetadata(uuid="fake-uuid", severity="low"))
    return AnalyzerModule(name="fake_mod", artifact_type="fake_art",
                          required_tools=[], recognizers=[],
                          extract=lambda c, e: [], normalize=lambda h: [],
                          rules=[rule])


def _active(case_dir):
    return sorted(p.name for p in (Path(case_dir) / "findings").glob("F-*.yaml"))


def test_rerun_does_not_duplicate_findings(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake_mod": _module()})

    r1 = phase_runner._run_phase_3_live(case_dir, manifest)
    assert r1["success"] and len(_active(case_dir)) == 2
    first = _active(case_dir)

    r2 = phase_runner._run_phase_3_live(case_dir, manifest)
    assert r2["success"]
    active = _active(case_dir)
    assert len(active) == 2, active
    assert not set(active) & set(first), "IDs must not be reused"
    sup = sorted(p.name for p in (Path(case_dir) / "findings" / "superseded").glob("F-*.yaml"))
    assert sup == first
    for name in sup:
        fy = yaml.safe_load((Path(case_dir) / "findings" / "superseded" / name).read_text())
        assert fy["finding_id"] == name[:-5]

    rep = verify_full(case_dir)
    assert rep["checks"]["audit_disk"]["passed"], rep["checks"]["audit_disk"]
    assert rep["checks"]["finding_integrity"]["passed"], rep["checks"]["finding_integrity"]
    rows = [json.loads(ln) for ln in (Path(case_dir) / "audit.jsonl").read_text().splitlines()]
    sup_rows = [r for r in rows if r.get("action") == "finding_supersede"]
    assert sorted(r["finding_id"] for r in sup_rows) == [n[:-5] for n in first]


def test_next_number_counts_superseded(tmp_path):
    fdir = tmp_path / "findings"
    (fdir / "superseded").mkdir(parents=True)
    (fdir / "superseded" / "F-001-007.yaml").write_text("x: 1\n")
    (fdir / "F-001-002.yaml").write_text("x: 1\n")
    assert get_next_finding_number(str(fdir)) == 8


def test_tampered_prior_finding_blocks_rerun(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake_mod": _module()})
    phase_runner._run_phase_3_live(case_dir, manifest)
    victim = Path(case_dir) / "findings" / _active(case_dir)[0]
    victim.write_text(victim.read_text().replace("INFERRED", "CONFIRMED"))

    r2 = phase_runner._run_phase_3_live(case_dir, manifest)
    assert r2["success"] is False
    assert "tamper" in r2["error"].lower() or "hash" in r2["error"].lower()
    assert victim.exists(), "a tampered finding is never moved or re-blessed"
    assert not verify_full(case_dir)["checks"]["finding_integrity"]["passed"]


def test_superseded_file_edit_is_still_caught(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake_mod": _module()})
    phase_runner._run_phase_3_live(case_dir, manifest)
    phase_runner._run_phase_3_live(case_dir, manifest)
    s = next((Path(case_dir) / "findings" / "superseded").glob("F-*.yaml"))
    s.write_bytes(s.read_bytes() + b"# edited\n")
    assert not verify_full(case_dir)["checks"]["finding_integrity"]["passed"]


def test_superseded_copied_back_is_caught(monkeypatch, tmp_path):
    case_dir, manifest = _make_case(tmp_path)
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"fake_mod": _module()})
    phase_runner._run_phase_3_live(case_dir, manifest)
    phase_runner._run_phase_3_live(case_dir, manifest)
    s = next((Path(case_dir) / "findings" / "superseded").glob("F-*.yaml"))
    (Path(case_dir) / "findings" / s.name).write_bytes(s.read_bytes())
    assert not verify_full(case_dir)["checks"]["finding_integrity"]["passed"]

