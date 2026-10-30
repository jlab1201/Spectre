"""A7 Finding 2 side-note: DROPPED (0-source) findings must actually be
removed from disk, not just labeled. emit_finding.py always writes a
finding YAML regardless of status and is out of scope for WS3 (cannot be
touched) -- this exercises the standalone purge utility that implements
the "0 sources -> DROPPED (auto-purged)" claim in
skills/correlation-engine/SKILL.md / skills/report-generator/SKILL.md.
"""

import yaml

from spectre.pipeline.correlation import purge_dropped_findings


def _write_finding(findings_dir, fid, status, sources, evidence_refs=None):
    findings_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "finding_id": fid,
        "status": status,
        "corroboration": {"sources": sources},
        "evidence_refs": evidence_refs if evidence_refs is not None else (
            [] if sources == 0 else [{"execution_id": "abc"}]
        ),
    }
    p = findings_dir / f"{fid}.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_purge_removes_dropped_status_finding(tmp_path):
    findings_dir = tmp_path / "findings"
    dropped = _write_finding(findings_dir, "F-1-001", "DROPPED", 0)
    kept = _write_finding(findings_dir, "F-1-002", "INFERRED", 1)

    removed = purge_dropped_findings(str(tmp_path))

    assert str(dropped) in removed
    assert not dropped.exists()
    assert kept.exists()


def test_purge_keeps_inferred_and_confirmed_findings(tmp_path):
    findings_dir = tmp_path / "findings"
    inferred = _write_finding(findings_dir, "F-1-001", "INFERRED", 1)
    confirmed = _write_finding(findings_dir, "F-1-002", "CONFIRMED", 2)

    removed = purge_dropped_findings(str(tmp_path))

    assert removed == []
    assert inferred.exists()
    assert confirmed.exists()


def test_purge_removes_zero_source_finding_even_if_status_field_missing(tmp_path):
    # Defensive: a finding with 0 sources and no evidence_refs is DROPPED
    # in substance even if some older/legacy writer never set the literal
    # status string.
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    p = findings_dir / "F-1-001.yaml"
    p.write_text(yaml.safe_dump({
        "finding_id": "F-1-001",
        "corroboration": {"sources": 0},
        "evidence_refs": [],
    }))

    removed = purge_dropped_findings(str(tmp_path))

    assert removed == [str(p)]
    assert not p.exists()


def test_purge_no_findings_dir_returns_empty_list(tmp_path):
    assert purge_dropped_findings(str(tmp_path)) == []


def test_purge_ignores_unparseable_yaml(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    bad = findings_dir / "F-1-001.yaml"
    bad.write_text("{not: valid: yaml::")

    # Must not raise, and must not delete a file it can't safely evaluate.
    removed = purge_dropped_findings(str(tmp_path))
    assert removed == []
    assert bad.exists()
