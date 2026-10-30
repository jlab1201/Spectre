"""Tests for shared indicator-list loader (issue 5).

Verifies the loader works, caches, raises on missing, and — critically —
that the values moved into knowledge/indicators/ match the literals the rule
packs previously hardcoded (behaviour-preserving refactor).
"""
import pytest

from spectre import knowledge
from spectre.modules.memory import rules as mem_rules
from spectre.modules.evtx import rules as evtx_rules
from spectre.modules.disk import rules as disk_rules
from spectre.modules.pcap import rules as pcap_rules


def test_load_indicator_list_returns_values():
    lolbins = knowledge.load_indicator_list("processes", "lolbins")
    assert "rundll32.exe" in lolbins
    assert isinstance(lolbins, list)


def test_load_indicator_list_is_cached():
    a = knowledge._load_indicator_group("processes")
    b = knowledge._load_indicator_group("processes")
    assert a is b  # same cached object


def test_load_indicator_list_raises_on_missing_key():
    with pytest.raises(KeyError):
        knowledge.load_indicator_list("processes", "does_not_exist")


def test_load_indicator_group_raises_on_missing_group():
    with pytest.raises(FileNotFoundError):
        knowledge._load_indicator_group("nope_group")


def test_load_indicator_map_returns_mapping():
    m = knowledge.load_indicator_map("processes", "expected_process_parents")
    assert m["lsass.exe"] == "wininit.exe"


# ── Behaviour parity: values match the previous hardcoded literals ──

def test_memory_values_preserved():
    assert mem_rules._SUSPICIOUS_NAMES == frozenset(
        {"mimikatz.exe", "procdump.exe", "psexec.exe", "nc.exe", "ncat.exe",
         "meterpreter", "cobaltstrike"})
    assert mem_rules._ARCHIVE_EXT == (
        ".rar", ".zip", ".7z", ".tar", ".gz", ".cab", ".ace", ".arj")
    assert mem_rules._EXPECTED_PARENT == {
        "services.exe": "wininit.exe", "lsass.exe": "wininit.exe",
        "lsm.exe": "wininit.exe", "svchost.exe": "services.exe"}
    assert mem_rules._INTEREST_HOSTS[0] == "pastebin.com"
    assert "rentry.co" in mem_rules._INTEREST_HOSTS


def test_evtx_values_preserved():
    assert evtx_rules._LOLBINS == frozenset(
        {"rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe",
         "wscript.exe", "msbuild.exe", "installutil.exe", "regsvcs.exe"})
    assert evtx_rules._TEMP_MARKERS == (
        "\\temp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\")


def test_disk_values_preserved():
    assert disk_rules._TEMP_MARKERS == (
        "/temp/", "/tmp/", "/appdata/local/temp/", "\\temp\\")
    assert disk_rules._EXE_EXTS == (
        ".exe", ".dll", ".scr", ".ps1", ".bat", ".vbs", ".js")


def test_pcap_values_preserved():
    assert pcap_rules._SUSPICIOUS_PORTS == frozenset(
        {"4444", "4445", "1337", "31337", "5555", "6666", "12345"})
    # 27017 (MongoDB) is deliberately NOT a suspicious_port — an exposed
    # database service is detected as pcap-exposed-service (T1133), not as
    # offensive-tooling C2 (T1571). It lives in exposed_service_ports.
    assert "27017" in pcap_rules._EXPOSED_SERVICE_PORTS


# ── benign-infrastructure allowlist migration (issue Track C task 7) ────

def test_pcap_legitimate_ip_networks_are_narrow_cidrs_not_broad_octets():
    # A5 Finding 2 / A11 fix: the old bare single/double-octet string
    # prefixes ('13.', '20.', '40.', '52.', '104.' — each an entire /8,
    # 16.7M addresses) were replaced with real, narrow, parsed CIDR
    # networks. Generic multi-tenant Azure ranges were dropped entirely
    # rather than narrowed (no sub-block of them is safely "trusted").
    import ipaddress
    nets = pcap_rules._LEGITIMATE_IP_NETWORKS
    assert all(isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network))
               for n in nets)
    # None of the surviving networks may be broader than a /11 — the whole
    # point of the fix is no more blanket /8-sized suppression.
    assert all(n.prefixlen >= 11 for n in nets)
    # The old bare-octet Azure prefixes must not survive as any network in
    # the list (they were removed, not narrowed).
    net_strs = {str(n) for n in nets}
    assert not any(s.startswith(("13.", "20.", "40.", "52.", "104."))
                    for s in net_strs)


def test_pcap_c2_checkin_hosts_migrated_verbatim():
    assert pcap_rules._C2_CHECKIN_HOSTS == frozenset(
        {"api.ipify.org", "ipinfo.io", "ifconfig.me", "icanhazip.com"})


def test_pcap_benign_infra_domains_loaded():
    domains = knowledge.load_indicator_list("network", "benign_infra_domains")
    for expected in ("crl.microsoft.com", "ocsp.digicert.com", "o.lencr.org"):
        assert expected in domains
    assert pcap_rules._BENIGN_INFRA_DOMAINS == frozenset(domains)


def test_memory_benign_malfind_processes_excludes_injection_targets():
    # explorer.exe/wmiprvse.exe are injection TARGETS, not JIT processes —
    # intentionally excluded when the allowlist was narrowed (Track C).
    assert mem_rules._BENIGN_MALFIND == frozenset(
        {"chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"})
    assert "explorer.exe" not in mem_rules._BENIGN_MALFIND
    assert "wmiprvse.exe" not in mem_rules._BENIGN_MALFIND


def test_extension_lists_are_tuples_for_endswith():
    # str.endswith requires a tuple, not a set/list.
    assert isinstance(mem_rules._ARCHIVE_EXT, tuple)
    assert isinstance(disk_rules._EXE_EXTS, tuple)
    assert "x.zip".endswith(mem_rules._ARCHIVE_EXT)


def test_c2_user_agents_drops_overbroad_msie7():
    # The legacy-IE7/Adobe-updater prefix matched benign traffic (002
    # F-288-004 fired with an empty IOC). It must be gone.
    uas = knowledge.load_indicator_list("network", "c2_user_agents")
    assert not any("MSIE 7.0" in u for u in uas)
    # The comma-less KHTML fingerprint is a genuine narrow signal — keep it.
    assert "(KHTML like Gecko)" in uas
    # Real RAT signatures remain.
    assert "NetSupport Manager" in uas
