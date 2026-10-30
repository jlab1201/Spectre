"""WS4 sub-task 4 (A6 Finding 3) — clustering._parse_time must accept
offset-suffixed ISO8601 timestamps ('+00:00'), the shape LNK, Prefetch,
registry_hive, and (after A6 Finding 4's fix) disk all produce via
datetime.isoformat(). The old fixed 4-format strptime tuple silently
rejected every one of them, dropping those artifact types out of Spec B's
temporal-proximity clustering with no warning to the analyst.
"""
from datetime import datetime

from spectre.pipeline.correlation.clustering import _parse_time, cluster_findings


def test_parse_time_accepts_offset_suffixed_lnk_prefetch_shape():
    # datetime(1601,1,1,tzinfo=utc) + timedelta(...) .isoformat() shape
    dt = _parse_time({"event_time": "2024-08-17T03:24:33+00:00"})
    assert dt is not None
    assert dt == datetime(2024, 8, 17, 3, 24, 33)


def test_parse_time_accepts_offset_suffixed_registry_shape():
    dt = _parse_time({"event_time": "2026-01-15T10:22:33+00:00"})
    assert dt is not None
    assert dt == datetime(2026, 1, 15, 10, 22, 33)


def test_parse_time_still_accepts_legacy_space_and_t_formats():
    """No regression on the four formats the old code already handled."""
    assert _parse_time({"event_time": "2026-01-30 20:00:00"}) is not None
    assert _parse_time({"event_time": "2026-01-30 20:00:00.123456"}) is not None
    assert _parse_time({"event_time": "2026-01-30T20:00:00"}) is not None
    assert _parse_time({"event_time": "2026-01-30T20:00:00.123456"}) is not None


def test_parse_time_accepts_z_suffixed_evtx_shape():
    assert _parse_time({"event_time": "2026-01-30T20:00:00.000000Z"}) is not None


def test_parse_time_rejects_garbage_returns_none():
    assert _parse_time({"event_time": "not-a-timestamp"}) is None
    assert _parse_time({"event_time": ""}) is None


def test_lnk_offset_iso_now_participates_in_temporal_clustering():
    """End-to-end: two offset-suffixed findings 30s apart must cluster —
    previously they were silently excluded entirely."""
    findings = [
        {"finding_id": "F-1-001", "iocs": {}, "host_ip": "",
         "event_time": "2024-08-17T03:24:33+00:00",
         "corroboration": {"tools": []}},
        {"finding_id": "F-1-002", "iocs": {}, "host_ip": "",
         "event_time": "2024-08-17T03:25:03+00:00",  # +30s
         "corroboration": {"tools": []}},
    ]
    out = cluster_findings(findings, subject_ips=set(), window_s=60)
    assert len(out["temporal"]) == 1
    assert set(out["temporal"][0]["member_finding_ids"]) == {"F-1-001", "F-1-002"}
