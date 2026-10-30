"""W5-3 — `process` entity (pid:image, host- and start-time-scoped).

Correlation links EXISTING findings only: a process entity never creates a
finding or MITRE. PID reuse is real, so a bare PID never links; PID + image
links only when every attribute both sides know (host, start time, directory)
agrees, and an under-specified reference never bridges two distinct process
instances.
"""
from spectre.core.base import NormEvent
from spectre.pipeline.correlation.clustering import cluster_findings
from spectre.pipeline.correlation.process import (
    image_key, process_refs_for_events, process_refs_from_event,
)


def _ev(artifact_type, data, ts="", host=""):
    return NormEvent(artifact_type=artifact_type, timestamp=ts, source_file="x",
                     record_id="1", host=host, data=data)


def _f(fid, iocs=None, refs=None, corr_tools=None, host_ip=""):
    f = {"finding_id": fid, "iocs": iocs or {}, "host_ip": host_ip,
         "event_time": "", "corroboration": {"tools": corr_tools or []}}
    if refs is not None:
        f["process_refs"] = refs
    return f


# ── extraction from NormEvents ────────────────────────────────────────────
def test_pslist_ref_carries_start_time():
    e = _ev("memory_pslist", {"pid": 1234, "image": "Evil.exe",
                              "create_time": "2026-01-30T20:00:00+00:00"},
            ts="2026-01-30T20:00:00+00:00")
    assert process_refs_from_event(e) == [
        {"pid": 1234, "image": "Evil.exe", "host": "",
         "start_time": "2026-01-30T20:00:00+00:00"}]


def test_netscan_ref_has_no_start_time():
    # netscan's timestamp is the CONNECTION time, never the process start.
    e = _ev("memory_netscan", {"pid": 1234, "owner": "evil.exe",
                               "foreign_addr": "1.2.3.4"},
            ts="2026-01-30T20:05:00+00:00")
    assert process_refs_from_event(e) == [
        {"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}]


def test_4688_hex_pid_full_path_and_host():
    e = _ev("process_creation", {"event_id": 4688, "process_id": "0x4d2",
                                 "image": r"C:\Users\a\evil.exe"},
            ts="2026-01-30T20:00:00.4Z", host="WS01")
    assert process_refs_from_event(e) == [
        {"pid": 1234, "image": r"C:\Users\a\evil.exe", "host": "WS01",
         "start_time": "2026-01-30T20:00:00.4Z"}]


def test_sysmon_network_event_ref_without_start_time():
    e = _ev("evtx_event", {"event_id": 3,
                           "provider": "Microsoft-Windows-Sysmon",
                           "event_data": {"ProcessId": "1234",
                                          "Image": r"C:\Users\a\evil.exe"}},
            ts="2026-01-30T20:05:00Z", host="WS01")
    assert process_refs_from_event(e) == [
        {"pid": 1234, "image": r"C:\Users\a\evil.exe", "host": "WS01",
         "start_time": ""}]


def test_no_ref_without_pid_or_image_or_for_system_pids():
    assert process_refs_from_event(_ev("memory_netscan", {"owner": "evil.exe"})) == []
    assert process_refs_from_event(_ev("memory_netscan", {"pid": 1234, "owner": ""})) == []
    assert process_refs_from_event(_ev("memory_pslist", {"pid": 4, "image": "System"})) == []
    assert process_refs_from_event(_ev("memory_pslist", {"pid": "junk", "image": "a.exe"})) == []
    assert process_refs_from_event(_ev("pcap_conn", {"pid": 1, "image": "a.exe"})) == []


def test_refs_for_events_union_dedup_sorted():
    a = _ev("memory_netscan", {"pid": 20, "owner": "b.exe"})
    b = _ev("memory_netscan", {"pid": 10, "owner": "a.exe"})
    c = _ev("memory_netscan", {"pid": 20, "owner": "b.exe"})
    refs = process_refs_for_events([a, b, c])
    assert [r["pid"] for r in refs] == [10, 20]


def test_image_key_normalization():
    assert image_key(r"\Device\HarddiskVolume3\Windows\System32\EVIL.EXE") == \
        image_key(r"c:\windows\system32\evil.exe")
    # EPROCESS.ImageFileName is truncated to 14 chars in memory.
    assert image_key("SearchProtocol") == image_key(r"C:\Windows\SearchProtocolHost.exe")
    assert image_key("a.exe") != image_key("b.exe")


# ── clustering ────────────────────────────────────────────────────────────
def test_chain_pcap_to_netscan_to_4688():
    findings = [
        _f("F-1-001", iocs={"ip": ["45.1.2.3"]}, corr_tools=["zeek/pcap_conn"]),
        _f("F-1-002", iocs={"ip": ["45.1.2.3"]}, corr_tools=["volatility3/memory_netscan"],
           refs=[{"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}]),
        _f("F-1-003", corr_tools=["evtx/process_creation"],
           refs=[{"pid": 1234, "image": r"C:\Users\a\evil.exe", "host": "WS01",
                  "start_time": "2026-01-30T20:00:00Z"}]),
    ]
    out = cluster_findings(findings, subject_ips=set())
    ioc = out["ioc_overlap"]
    assert len(ioc) == 1
    assert ioc[0]["member_finding_ids"] == ["F-1-001", "F-1-002", "F-1-003"]
    proc = [e for e in ioc[0]["shared_entities"] if e.startswith("process:")]
    assert len(proc) == 1
    assert ioc[0]["artifact_span"][proc[0]] == ["memory_netscan", "process_creation"]


def test_pid_only_match_does_not_link():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "notepad.exe", "host": "", "start_time": ""}]),
    ]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_pid_reuse_different_start_times_does_not_link():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T20:00:00+00:00"}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T23:00:00+00:00"}]),
    ]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_start_times_within_tolerance_link_across_formats():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T20:00:00+00:00"}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": r"C:\x\EVIL.EXE", "host": "WS01",
                             "start_time": "2026-01-30T20:00:00.812Z"}]),
    ]
    ioc = cluster_findings(findings, subject_ips=set())["ioc_overlap"]
    assert len(ioc) == 1


def test_untimed_ref_never_bridges_two_instances():
    # Two distinct evil.exe instances reused PID 1234; a netscan ref with no
    # start time cannot tell which one it belongs to -> it links to neither,
    # and the two instances stay apart.
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T20:00:00+00:00"}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T23:00:00+00:00"}]),
        _f("F-1-003", refs=[{"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}]),
    ]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_timed_pair_still_links_when_instance_is_disambiguated():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T20:00:00+00:00"}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "evil.exe", "host": "WS01",
                             "start_time": "2026-01-30T20:00:01Z"}]),
        _f("F-1-003", refs=[{"pid": 1234, "image": "evil.exe", "host": "",
                             "start_time": "2026-01-30T23:00:00+00:00"}]),
        _f("F-1-004", refs=[{"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}]),
    ]
    ioc = cluster_findings(findings, subject_ips=set())["ioc_overlap"]
    assert [c["member_finding_ids"] for c in ioc] == [["F-1-001", "F-1-002"]]


def test_different_known_hosts_do_not_link():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "WS01", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "evil.exe", "host": "ws02", "start_time": ""}]),
    ]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_host_compare_is_case_insensitive():
    findings = [
        _f("F-1-001", refs=[{"pid": 1234, "image": "evil.exe", "host": "WS01", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": "evil.exe", "host": "ws01", "start_time": ""}]),
    ]
    assert len(cluster_findings(findings, subject_ips=set())["ioc_overlap"]) == 1


def test_directory_conflict_blocks_but_device_path_matches_drive_path():
    diff_dir = [
        _f("F-1-001", refs=[{"pid": 1234, "image": r"C:\Temp\evil.exe", "host": "", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": r"C:\Windows\evil.exe", "host": "", "start_time": ""}]),
    ]
    assert cluster_findings(diff_dir, subject_ips=set())["ioc_overlap"] == []
    same = [
        _f("F-1-001", refs=[{"pid": 1234, "image": r"\Device\HarddiskVolume2\Temp\evil.exe",
                             "host": "", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 1234, "image": r"C:\temp\EVIL.exe", "host": "", "start_time": ""}]),
    ]
    assert len(cluster_findings(same, subject_ips=set())["ioc_overlap"]) == 1


def test_one_finding_alone_never_forms_a_cluster():
    findings = [_f("F-1-001", refs=[
        {"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""},
        {"pid": 1234, "image": "evil.exe", "host": "", "start_time": ""}])]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_malformed_refs_are_ignored_not_fatal():
    findings = [
        _f("F-1-001", refs=[{"pid": "x", "image": "evil.exe"}, "junk", None]),
        _f("F-1-002", refs="not-a-list"),
    ]
    assert cluster_findings(findings, subject_ips=set())["ioc_overlap"] == []


def test_process_clustering_deterministic_under_input_order():
    base = [
        _f("F-1-003", refs=[{"pid": 7, "image": "a.exe", "host": "", "start_time": ""}]),
        _f("F-1-001", refs=[{"pid": 7, "image": "a.exe", "host": "", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 7, "image": "A.EXE", "host": "", "start_time": ""}]),
    ]
    a = cluster_findings(base, subject_ips=set())
    b = cluster_findings(list(reversed(base)), subject_ips=set())
    assert a == b and len(a["ioc_overlap"]) == 1


def test_findings_without_process_refs_are_unchanged():
    findings = [
        _f("F-1-001", iocs={"filepath": ["C:/evil.exe"]}, corr_tools=["x/evtx"]),
        _f("F-1-002", iocs={"filepath": ["c:/evil.exe"]}, corr_tools=["y/prefetch"]),
    ]
    out = cluster_findings(findings, subject_ips=set())
    assert out["ioc_overlap"][0]["shared_entities"] == ["filepath:c:/evil.exe"]


def test_clustering_never_mutates_findings():
    import copy
    findings = [
        _f("F-1-001", refs=[{"pid": 7, "image": "a.exe", "host": "", "start_time": ""}]),
        _f("F-1-002", refs=[{"pid": 7, "image": "a.exe", "host": "", "start_time": ""}]),
    ]
    snap = copy.deepcopy(findings)
    cluster_findings(findings, subject_ips=set())
    assert findings == snap


def test_padded_netscan_owner_is_cleaned():
    e = _ev("memory_netscan", {"pid": 2080, "owner":
        r"firefox.exe      ***  fffffa8001390cf0  \Device\HarddiskVolume2\Program Files (x86)\Mozilla Firefox\firefox.exe"})
    assert process_refs_from_event(e)[0]["image"] == "firefox.exe"
    assert process_refs_from_event(_ev("memory_netscan", {"pid": 9, "owner": "***"})) == []


def test_aggregate_finding_over_many_processes_is_not_a_hub():
    # An inherited env var dedups into ONE finding spanning many processes;
    # it must not glue otherwise-unrelated per-process findings together.
    hub = _f("F-1-001", refs=[{"pid": p, "image": f"p{p}.exe", "host": "", "start_time": ""}
                              for p in (10, 20, 30, 40)])
    a = _f("F-1-002", refs=[{"pid": 10, "image": "p10.exe", "host": "", "start_time": ""}])
    b = _f("F-1-003", refs=[{"pid": 20, "image": "p20.exe", "host": "", "start_time": ""}])
    assert cluster_findings([hub, a, b], subject_ips=set())["ioc_overlap"] == []


def test_finding_with_few_processes_still_links():
    two = _f("F-1-001", refs=[{"pid": p, "image": "a.exe", "host": "", "start_time": ""}
                              for p in (10, 20)])
    a = _f("F-1-002", refs=[{"pid": 10, "image": "a.exe", "host": "", "start_time": ""}])
    assert len(cluster_findings([two, a], subject_ips=set())["ioc_overlap"]) == 1
