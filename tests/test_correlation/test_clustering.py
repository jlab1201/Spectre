from spectre.pipeline.correlation.clustering import (
    _normalize_entity, _finding_entities, cluster_findings,
)


def _f(fid, iocs=None, host_ip="", event_time="", corr_tools=None):
    return {"finding_id": fid, "iocs": iocs or {}, "host_ip": host_ip,
            "event_time": event_time,
            "corroboration": {"tools": corr_tools or []}}


def test_normalize_entity_path_and_case():
    assert _normalize_entity("filepath", r"C:\Temp\A.exe") == "c:/temp/a.exe"
    assert _normalize_entity("domain", "Evil.COM") == "evil.com"
    assert _normalize_entity("ip", "10.0.0.5") == "10.0.0.5"


def test_finding_entities_excludes_subject_ip():
    f = _f("F-1-001", iocs={"ip": ["10.0.0.5", "1.2.3.4"]}, host_ip="10.0.0.5")
    ents = _finding_entities(f, subject_ips={"10.0.0.5"})
    assert "ip:1.2.3.4" in ents
    assert "ip:10.0.0.5" not in ents


def test_ioc_overlap_clusters_shared_executable():
    findings = [
        _f("F-1-001", iocs={"filepath": ["C:/evil.exe"]}, corr_tools=["x/evtx"]),
        _f("F-1-002", iocs={"filepath": ["c:/evil.exe"]}, corr_tools=["y/prefetch"]),
        _f("F-1-003", iocs={"domain": ["good.com"]}, corr_tools=["z/pcap_flow"]),
    ]
    out = cluster_findings(findings, subject_ips=set())
    ioc = out["ioc_overlap"]
    assert len(ioc) == 1
    assert set(ioc[0]["member_finding_ids"]) == {"F-1-001", "F-1-002"}
    assert ioc[0]["artifact_span"]["filepath:c:/evil.exe"] == ["evtx", "prefetch"]


def test_subject_ip_only_link_does_not_cluster():
    findings = [
        _f("F-1-001", iocs={"ip": ["10.0.0.5"]}, host_ip="10.0.0.5"),
        _f("F-1-002", iocs={"ip": ["10.0.0.5"]}, host_ip="10.0.0.5"),
    ]
    out = cluster_findings(findings, subject_ips={"10.0.0.5"})
    assert out["ioc_overlap"] == []


def test_temporal_window_and_exclusion():
    findings = [
        _f("F-1-001", event_time="2026-01-30 20:00:00"),
        _f("F-1-002", event_time="2026-01-30 20:00:30"),   # +30s -> linked
        _f("F-1-003", event_time="2026-01-30 21:00:00"),   # far -> alone
        _f("F-1-004", event_time=""),                        # no time -> excluded
    ]
    out = cluster_findings(findings, subject_ips=set(), window_s=60)
    temporal = out["temporal"]
    assert len(temporal) == 1
    assert set(temporal[0]["member_finding_ids"]) == {"F-1-001", "F-1-002"}


# ── A7 Finding 4: benign/ubiquitous shared entities must not cluster ──────

def test_benign_shared_system_binary_does_not_cluster():
    findings = [
        _f("F-1-001", iocs={"filepath": [r"C:\Windows\System32\svchost.exe"]}),
        _f("F-1-002", iocs={"filepath": [r"C:\Windows\System32\svchost.exe"]}),
    ]
    out = cluster_findings(findings, subject_ips=set())
    assert out["ioc_overlap"] == []


def test_benign_shared_public_dns_resolver_does_not_cluster():
    findings = [
        _f("F-1-001", iocs={"ip": ["8.8.8.8"]}),
        _f("F-1-002", iocs={"ip": ["8.8.8.8"]}),
    ]
    out = cluster_findings(findings, subject_ips=set())
    assert out["ioc_overlap"] == []


def test_benign_shared_generic_runkey_does_not_cluster():
    findings = [
        _f("F-1-001", iocs={"registry_key": [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]}),
        _f("F-1-002", iocs={"registry_key": [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]}),
    ]
    out = cluster_findings(findings, subject_ips=set())
    assert out["ioc_overlap"] == []


def test_genuine_shared_ioc_still_clusters_alongside_benign_noise():
    # A benign entity AND a genuine one are shared between two findings --
    # the genuine one must still drive clustering.
    findings = [
        _f("F-1-001", iocs={"filepath": [r"C:\Windows\System32\svchost.exe"],
                            "hash": ["deadbeefcafebabe"]}),
        _f("F-1-002", iocs={"filepath": [r"C:\Windows\System32\svchost.exe"],
                            "hash": ["deadbeefcafebabe"]}),
    ]
    out = cluster_findings(findings, subject_ips=set())
    ioc = out["ioc_overlap"]
    assert len(ioc) == 1
    assert set(ioc[0]["member_finding_ids"]) == {"F-1-001", "F-1-002"}
    assert ioc[0]["shared_entities"] == ["hash:deadbeefcafebabe"]


def test_cluster_id_deterministic():
    findings = [
        _f("F-1-002", iocs={"filepath": ["a.exe"]}),
        _f("F-1-001", iocs={"filepath": ["a.exe"]}),
    ]
    a = cluster_findings(findings, subject_ips=set())
    b = cluster_findings(list(reversed(findings)), subject_ips=set())
    assert a == b
    assert a["ioc_overlap"][0]["cluster_id"] == "ioc_overlap-001"
