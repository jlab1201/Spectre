"""
test_directives.py — directive compiler tests.

directives.compile(spec) turns a validated directive spec into a
CompiledDirective whose .matches(event) is a pure predicate over a NormEvent
and .to_anchor(event) yields a detection Anchor. IOC/field matching is
cross-artifact by design (a directed IP fires on pcap AND memory events).
"""

import json
import sys
import tempfile
import pytest
from pathlib import Path

from spectre.pipeline import directives  # noqa: E402
from spectre.core.base import NormEvent  # noqa: E402


def _ev(artifact_type, data, ts="2026-06-28T03:00:00Z"):
    return NormEvent(artifact_type=artifact_type, timestamp=ts,
                     source_file="evidence/x", record_id="1", data=data)


def _ioc_spec(value="192.158.12.1", polarity="include"):
    return {"directive_id": "dir-001", "type": "ioc_match", "polarity": polarity,
            "params": {"ioc_type": "ip", "value": value},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}


# ── ioc_match: cross-artifact ───────────────────────────────────────
def test_ioc_match_fires_on_pcap_event():
    c = directives.compile(_ioc_spec())
    assert c.matches(_ev("pcap_conn", {"dest_ip": "192.158.12.1", "proto": "tcp"}))


def test_ioc_match_fires_on_memory_event_cross_artifact():
    c = directives.compile(_ioc_spec())
    assert c.matches(_ev("memory_netscan", {"foreign_addr": "192.158.12.1:443"}))


def test_ioc_match_no_false_positive():
    c = directives.compile(_ioc_spec())
    assert not c.matches(_ev("pcap_conn", {"dest_ip": "10.0.0.5"}))


def test_to_anchor_populates_iocs_and_artifact_type():
    c = directives.compile(_ioc_spec())
    ev = _ev("pcap_conn", {"dest_ip": "192.158.12.1"})
    a = c.to_anchor(ev)
    assert a.artifact_type == "pcap_conn"
    assert a.rule_id == "dir-001"
    assert "192.158.12.1" in a.iocs["ip"]


# ── R2-05(b): exact per-type matching, not raw substring ─────────────
def test_ioc_match_ip_substring_no_longer_false_positive():
    """R2's own PoC: a directive for 185.220.101.4 must not fire on an
    event whose dst_ip is 185.220.101.42 — the old `val in _flatten(data)`
    substring check treated '185.220.101.4' as present inside
    '185.220.101.42'."""
    c = directives.compile(_ioc_spec(value="185.220.101.4"))
    assert not c.matches(_ev("pcap_conn", {"dst_ip": "185.220.101.42"}))


def test_ioc_match_ip_exact_still_fires():
    c = directives.compile(_ioc_spec(value="185.220.101.42"))
    assert c.matches(_ev("pcap_conn", {"dst_ip": "185.220.101.42"}))


def test_ioc_match_ip_strips_port_suffix():
    # "ip:port" fields (foreign_addr-style) must still match on the address.
    c = directives.compile(_ioc_spec(value="185.220.101.42"))
    assert c.matches(_ev("memory_netscan", {"foreign_addr": "185.220.101.42:443"}))


def _domain_spec(value="evil.com"):
    return {"directive_id": "dir-001", "type": "ioc_match", "polarity": "include",
            "params": {"ioc_type": "domain", "value": value},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}


def test_ioc_match_domain_proper_subdomain_matches():
    c = directives.compile(_domain_spec("evil.com"))
    assert c.matches(_ev("pcap_dns", {"query": "www.evil.com"}))


def test_ioc_match_domain_exact_matches():
    c = directives.compile(_domain_spec("evil.com"))
    assert c.matches(_ev("pcap_dns", {"query": "evil.com"}))


def test_ioc_match_domain_rejects_label_boundary_collisions():
    c = directives.compile(_domain_spec("evil.com"))
    assert not c.matches(_ev("pcap_dns", {"query": "notevil.com"}))
    assert not c.matches(_ev("pcap_dns", {"query": "eviloco.com"}))


def _hash_spec(value, ioc_type="sha256"):
    return {"directive_id": "dir-001", "type": "ioc_match", "polarity": "include",
            "params": {"ioc_type": ioc_type, "value": value},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}


def test_ioc_match_hash_case_insensitive_exact():
    h = "AB" * 32
    c = directives.compile(_hash_spec(h.lower()))
    assert c.matches(_ev("disk_file", {"sha256": h.upper()}))


def test_ioc_match_hash_rejects_substring_of_longer_run():
    h = "a" * 64
    c = directives.compile(_hash_spec(h))
    # 71 contiguous hex chars: target is a raw substring but not a
    # standalone 64-char token (no word boundary in the middle of a hex
    # run) — must not match.
    assert not c.matches(_ev("disk_file", {"sha256": "b" + h + "cccccc"}))


# ── R2-05(c): to_anchor records the OBSERVED value, not the directive's ──
def test_to_anchor_records_observed_domain_not_directive_value():
    c = directives.compile(_domain_spec("evil.com"))
    ev = _ev("pcap_dns", {"query": "www.evil.com"})
    a = c.to_anchor(ev)
    assert a.iocs["domain"] == ["www.evil.com"]
    assert "evil.com" not in a.iocs["domain"]


def test_to_anchor_records_observed_hash_casing_from_event():
    h_upper = "A" * 64
    h_lower = "a" * 64
    c = directives.compile(_hash_spec(h_upper))
    ev = _ev("disk_file", {"sha256": h_lower})
    a = c.to_anchor(ev)
    assert a.iocs["sha256"] == [h_lower]


# ── field_match ─────────────────────────────────────────────────────
def test_field_match_contains():
    spec = {"directive_id": "dir-001", "type": "field_match", "polarity": "include",
            "params": {"field": "command_line_lower", "op": "contains",
                       "value": "\\temp\\"},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}
    c = directives.compile(spec)
    assert c.matches(_ev("process_creation", {"command_line_lower": "x \\temp\\evil.dll"}))
    assert not c.matches(_ev("process_creation", {"command_line_lower": "c:\\windows\\x"}))


def test_field_match_in_list():
    spec = {"directive_id": "dir-001", "type": "field_match", "polarity": "include",
            "params": {"field": "image_basename", "op": "in",
                       "value": ["rundll32.exe", "regsvr32.exe"]},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}
    c = directives.compile(spec)
    assert c.matches(_ev("process_creation", {"image_basename": "rundll32.exe"}))
    assert not c.matches(_ev("process_creation", {"image_basename": "notepad.exe"}))


def test_field_match_absent_field_is_no_match():
    spec = {"directive_id": "dir-001", "type": "field_match", "polarity": "include",
            "params": {"field": "image_basename", "op": "eq", "value": "x.exe"},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}
    c = directives.compile(spec)
    assert not c.matches(_ev("pcap_conn", {"dest_ip": "1.2.3.4"}))


# ── lineage ─────────────────────────────────────────────────────────
def test_lineage_parent_match():
    spec = {"directive_id": "dir-001", "type": "lineage", "polarity": "include",
            "params": {"parent": "powershell.exe", "child": "*"},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}
    c = directives.compile(spec)
    assert c.matches(_ev("process_creation",
                         {"parent_basename": "powershell.exe", "image_basename": "x.exe"}))
    assert not c.matches(_ev("process_creation",
                             {"parent_basename": "cmd.exe", "image_basename": "x.exe"}))


# ── temporal modifier ANDs onto a base directive ────────────────────
def test_temporal_modifier_filters_by_window():
    spec = _ioc_spec()
    spec["modifiers"]["time_window"] = {"start": "02:00", "end": "04:00"}
    c = directives.compile(spec)
    in_win = _ev("pcap_conn", {"dest_ip": "192.158.12.1"}, ts="2026-06-28T03:00:00Z")
    out_win = _ev("pcap_conn", {"dest_ip": "192.158.12.1"}, ts="2026-06-28T05:30:00Z")
    assert c.matches(in_win)
    assert not c.matches(out_win)


def test_temporal_standalone_matches_any_event_in_window():
    spec = {"directive_id": "dir-001", "type": "temporal", "polarity": "include",
            "params": {"start": "02:00", "end": "04:00"},
            "modifiers": {"time_window": None, "artifact_scope": [], "host_scope": []}}
    c = directives.compile(spec)
    assert c.matches(_ev("process_creation", {"image_basename": "x.exe"},
                         ts="2026-06-28T03:30:00Z"))
    assert not c.matches(_ev("process_creation", {"image_basename": "x.exe"},
                             ts="2026-06-28T06:00:00Z"))


# ── load ────────────────────────────────────────────────────────────
def test_load_reads_directives_json():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "raw_extract"
        out.mkdir()
        (out / "directives.json").write_text(json.dumps([_ioc_spec()]))
        # W3-1 (R2-16): load() only trusts a file a chained
        # directives_synthesized row records — do what Phase 1 does.
        from spectre.pipeline.custody import record_derived_artifact
        record_derived_artifact(tmp, out / "directives.json", phase=1,
                                phase_step="S1-synthesize-directives",
                                tool="direction.py", action="directives_synthesized")
        compiled = directives.load(tmp)
        assert len(compiled) == 1
        assert compiled[0].directive_id == "dir-001"
        assert compiled[0].polarity == "include"


def test_load_refuses_unrecorded_nonempty_directives():
    from spectre.pipeline.custody import CustodyError
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "raw_extract"
        out.mkdir()
        (out / "directives.json").write_text(json.dumps([_ioc_spec()]))
        with pytest.raises(CustodyError):
            directives.load(tmp)


def test_load_missing_file_is_empty():
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "raw_extract").mkdir()
        assert directives.load(tmp) == []


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


# ── W2-B review: domain IOCs inside URLs/emails; IPv6 ─────────────────
def test_ioc_match_domain_inside_url():
    c = directives.compile(_domain_spec("evil.com"))
    assert c.matches(_ev("memory_url", {"url": "http://evil.com/a"}))


def test_ioc_match_domain_inside_email():
    c = directives.compile(_domain_spec("evil.com"))
    assert c.matches(_ev("evtx_event", {"sender": "user@evil.com"}))


def test_ioc_match_domain_url_with_port_records_hostname():
    c = directives.compile(_domain_spec("evil.com"))
    ev = _ev("memory_url", {"url": "https://www.evil.com:8080/x"})
    assert c.matches(ev)
    assert c.to_anchor(ev).iocs["domain"] == ["www.evil.com"]


def test_ioc_match_domain_url_label_boundary_still_enforced():
    c = directives.compile(_domain_spec("evil.com"))
    assert not c.matches(_ev("memory_url", {"url": "http://notevil.com/a"}))
    assert not c.matches(_ev("memory_url", {"url": "a@notevil.com"}))
    assert not c.matches(_ev("memory_url", {"url": "http://evil.com.au/a"}))


def test_ioc_match_ipv6_exact_and_bracketed_port():
    c = directives.compile(_ioc_spec(value="2001:db8::1"))
    assert c.matches(_ev("pcap_conn", {"dst_ip": "2001:db8::1"}))
    assert c.matches(_ev("pcap_conn", {"dst": "[2001:db8::1]:443"}))
    assert c.matches(_ev("pcap_conn", {"dst_ip": "2001:0db8:0000:0000:0000:0000:0000:0001"}))
    assert not c.matches(_ev("pcap_conn", {"dst_ip": "2001:db8::11"}))


def test_ioc_match_ipv6_records_observed_value():
    c = directives.compile(_ioc_spec(value="2001:db8::1"))
    ev = _ev("pcap_conn", {"dst": "[2001:db8::1]:443"})
    assert c.to_anchor(ev).iocs["ip"] == ["2001:db8::1"]
