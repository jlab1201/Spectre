"""tests/test_rule_field_check.py — unit tests for check_rule_fields()."""

from spectre.core.base import Rule, RuleMetadata, check_rule_fields, NormEvent


def test_rule_with_present_fields_passes():
    rule = Rule(
        "test-rule", "evtx", lambda e: None, ["T1234"],
        metadata=RuleMetadata(uuid="test", required_fields=["command_line"]),
    )
    events = [
        NormEvent(
            artifact_type="evtx",
            timestamp="2024-01-01T00:00:00Z",
            source_file="test.evtx",
            record_id="0",
            host=".",
            data={"command_line": "cmd.exe"},
        )
    ]
    ok, missing = check_rule_fields(rule, events)
    assert ok
    assert missing == []


def test_rule_with_missing_fields_fails():
    rule = Rule(
        "test-rule", "evtx", lambda e: None, ["T1234"],
        metadata=RuleMetadata(uuid="test", required_fields=["http_user_agent"]),
    )
    events = [
        NormEvent(
            artifact_type="evtx",
            timestamp="2024-01-01T00:00:00Z",
            source_file="test.evtx",
            record_id="0",
            host=".",
            data={"command_line": "cmd.exe"},
        )
    ]
    ok, missing = check_rule_fields(rule, events)
    assert not ok
    assert "http_user_agent" in missing


def test_rule_with_no_requirements_always_passes():
    rule = Rule(
        "test-rule", "evtx", lambda e: None, ["T1234"],
        metadata=RuleMetadata(uuid="test"),
    )
    ok, missing = check_rule_fields(rule, [])
    assert ok
    assert missing == []


def test_rule_with_none_metadata_always_passes():
    rule = Rule("test-rule", "evtx", lambda e: None, ["T1234"])
    ok, missing = check_rule_fields(rule, [])
    assert ok
    assert missing == []


def test_multiple_fields_partial_match():
    rule = Rule(
        "test-rule", "pcap", lambda e: None, ["T1071"],
        metadata=RuleMetadata(
            uuid="test-4", required_fields=["src_ip", "http_host"]
        ),
    )
    events = [
        NormEvent(
            artifact_type="pcap_conn",
            timestamp="2024-01-01T00:00:00Z",
            source_file="test.pcap",
            record_id="0",
            host=".",
            data={"src_ip": "1.2.3.4", "dst_port": "80"},
        )
    ]
    ok, missing = check_rule_fields(rule, events)
    assert not ok
    assert "http_host" in missing
    assert "src_ip" not in missing  # src_ip is present


def test_field_in_later_events_found():
    """Fields in event position 200+ are still found (no slicing bias)."""
    rule = Rule(
        "test-rule", "pcap", lambda e: None, ["T1071"],
        metadata=RuleMetadata(
            uuid="test-late", required_fields=["beacon_data"]
        ),
    )
    events = []
    # 200 pcap_conn events — no beacon_data
    for i in range(200):
        events.append(NormEvent(
            artifact_type="pcap_conn",
            timestamp="2024-01-01T00:00:00Z",
            source_file="test.pcap",
            record_id=str(i),
            host=".",
            data={"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"},
        ))
    # 1 pcap_timing event at position 200+ — has beacon_data
    events.append(NormEvent(
        artifact_type="pcap_timing",
        timestamp="2024-01-01T00:00:00Z",
        source_file="test.pcap",
        record_id="200",
        host=".",
        data={"beacon_data": "jitter=0.1s interval=60s"},
    ))
    ok, missing = check_rule_fields(rule, events)
    assert ok, f"beacon_data should be found; missing={missing}"
    assert missing == []
