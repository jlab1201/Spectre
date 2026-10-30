"""WS4 sub-task 3 (A6 Finding 4) — disk/normalize.py must convert Sleuth
Kit's raw Unix-epoch-seconds mtime to ISO8601-UTC, the shape every other
module's NormEvent.timestamp uses. A bare epoch string like "1735689600"
is unparseable by both report_synthesize._parse_finding_ts and
clustering._parse_time, so it silently sorts by string accident (A6
Finding 2) and never participates in temporal correlation (A6 Finding 3).

ID-stability note: disk/rules.py's only rule (executable_in_temp) never
sets Anchor.dedup_key, so Phase 3 falls back to the finding's title —
which does not embed the timestamp. Reshaping the timestamp format here
does not change correlation/dedup grouping.
"""

from spectre.modules.disk.normalize import normalize

# fls -m body format: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
_MTIME_EPOCH = 1735689600  # 2025-01-01T00:00:00Z


def _handle(tmp_path, body_text):
    p = tmp_path / "fls.txt"
    p.write_text(body_text)
    return {"artifact_type": "disk_file_entry", "path": str(p), "evidence_path": str(p)}


def test_epoch_mtime_converted_to_iso8601_utc(tmp_path):
    line = (f"md5|C:/evil.exe|5|r/r|0|0|1024|"
            f"{_MTIME_EPOCH - 100}|{_MTIME_EPOCH}|{_MTIME_EPOCH}|{_MTIME_EPOCH}\n")
    events = normalize(_handle(tmp_path, line))
    assert len(events) == 1
    ts = events[0].timestamp
    assert ts == "2025-01-01T00:00:00+00:00"
    # No longer a bare epoch integer string.
    assert ts != str(_MTIME_EPOCH)


def test_iso_timestamp_is_parseable_by_report_and_clustering_helpers(tmp_path):
    """The whole point: downstream consumers that previously silently
    dropped this value must now be able to parse it."""
    from spectre.pipeline.report_synthesize import _parse_finding_ts
    from spectre.pipeline.correlation.clustering import _parse_time

    line = (f"md5|name|5|r/r|0|0|0|{_MTIME_EPOCH}|{_MTIME_EPOCH}|"
            f"{_MTIME_EPOCH}|{_MTIME_EPOCH}\n")
    events = normalize(_handle(tmp_path, line))
    ts = events[0].timestamp

    assert _parse_finding_ts(ts) is not None
    assert _parse_time({"event_time": ts}) is not None


def test_epoch_zero_is_undated_not_1970(tmp_path):
    """mtime=0 (common for sparse/never-modified body-file rows) must not
    be rendered as a fabricated 1970-01-01 timestamp — treat as undated,
    same convention as every other module's 'no timestamp' case."""
    line = "md5|name|5|r/r|0|0|0|0|0|0|0\n"
    events = normalize(_handle(tmp_path, line))
    assert events[0].timestamp == ""


def test_non_numeric_epoch_handled_gracefully_not_a_crash(tmp_path):
    line = "md5|name|5|r/r|0|0|0|garbage|garbage|garbage|garbage\n"
    events = normalize(_handle(tmp_path, line))
    assert events[0].timestamp == ""
