from spectre.pipeline.report_synthesize import _merge_report_md


def _findings():
    return [{"finding_id": "F-1-001", "title": "Suspicious exec", "iocs": {}},
            {"finding_id": "F-1-002", "title": "Prefetch of exec", "iocs": {}}]


def _manifest(clusters):
    return {"profile": "auto", "correlation_clusters": clusters}


def test_correlated_findings_section_rendered():
    clusters = {"ioc_overlap": [{
        "cluster_id": "ioc_overlap-001", "type": "ioc_overlap",
        "member_finding_ids": ["F-1-001", "F-1-002"],
        "shared_entities": ["filepath:c:/evil.exe"],
        "artifact_span": {"filepath:c:/evil.exe": ["evtx", "prefetch"]}}],
        "temporal": []}
    md = _merge_report_md(None, _findings(), _manifest(clusters), "/tmp/x", [], {})
    assert "## Correlated Findings" in md
    assert "c:/evil.exe" in md
    assert "F-1-001" in md and "F-1-002" in md


def test_correlated_findings_absent_when_empty():
    md = _merge_report_md(None, _findings(), _manifest({"ioc_overlap": [], "temporal": []}), "/tmp/x", [], {})
    assert "## Correlated Findings" not in md


def test_correlated_findings_absent_when_key_missing():
    """manifest has no `correlation_clusters` key at all (not just empty
    lists) -- must render cleanly with no section and no exception."""
    manifest = {"profile": "auto"}  # no correlation_clusters key
    md = _merge_report_md(None, _findings(), manifest, "/tmp/x", [], {})
    assert "## Correlated Findings" not in md
