"""W4-4 / R1-F7: a host_identity event is attributed to the monitored host
ONLY when its own ip/mac binding matches. A foreign-MAC DHCP DISCOVER
(brads-MBP, no IP) must never become the victim."""

from spectre.modules.pcap import zeek_normalize as zn
from spectre.modules.pcap.normalize import (
    normalize_dhcp_identity,
    normalize_kerberos_identity,
)
from spectre.modules.pcap.rules import host_identity

MON = "10.2.28.88"

# Real dhcp.log rows from 2026-02-28-traffic-analysis-exercise.pcap
_ZEEK_DHCP = (
    '{"ts":1772308506.482909,"uids":["Cos9ce2uOL6mSDO645"],"mac":"00:e0:4c:68:08:00",'
    '"host_name":"brads-MBP","msg_types":["DISCOVER"],"duration":0.0}\n'
    '{"ts":1772308507.959671,"client_addr":"10.2.28.88","server_addr":"10.2.28.1",'
    '"mac":"00:19:d1:b2:4d:ad","host_name":"DESKTOP-TEYQ2NR",'
    '"requested_addr":"10.2.28.88","assigned_addr":"10.2.28.88",'
    '"msg_types":["REQUEST","REQUEST","ACK"],"duration":2.8}\n'
)


def _by_host(events):
    return {e.data["hostname"]: e for e in events}


def test_zeek_dhcp_foreign_mac_is_not_the_monitored_host():
    ev = _by_host(zn.normalize_zeek_dhcp(_ZEEK_DHCP, monitored_ip=MON))
    assert ev["DESKTOP-TEYQ2NR"].host == MON
    assert ev["DESKTOP-TEYQ2NR"].data["bound_to_monitored"] is True
    assert ev["brads-MBP"].host == ""
    assert ev["brads-MBP"].data["bound_to_monitored"] is False


def test_zeek_dhcp_mac_match_without_ip_is_attributed():
    # A later DISCOVER (no IP) from the monitored host's own MAC is still it.
    text = _ZEEK_DHCP + (
        '{"ts":1772309000.0,"mac":"00:19:d1:b2:4d:ad","host_name":"DESKTOP-ALIAS",'
        '"msg_types":["DISCOVER"]}\n')
    ev = _by_host(zn.normalize_zeek_dhcp(text, monitored_ip=MON))
    assert ev["DESKTOP-ALIAS"].host == MON


def test_zeek_dhcp_foreign_ip_keeps_no_victim_attribution():
    text = ('{"ts":1.0,"mac":"aa:bb:cc:dd:ee:ff","host_name":"OTHER-PC",'
            '"assigned_addr":"10.2.28.50"}\n')
    ev = zn.normalize_zeek_dhcp(text, monitored_ip=MON)[0]
    assert ev.host == ""
    assert ev.data["ip"] == "10.2.28.50"


def test_zeek_kerberos_attribution_by_client_ip():
    krb = (
        '{"ts":1.0,"id.orig_h":"10.2.28.88","id.resp_h":"10.2.28.2","id.resp_p":88,'
        '"client":"brolf/EASYAS123"}\n'
        '{"ts":2.0,"id.orig_h":"10.2.28.60","id.resp_h":"10.2.28.2","id.resp_p":88,'
        '"client":"alice/EASYAS123"}\n')
    ev = {e.data["account"]: e for e in zn.normalize_zeek_kerberos(krb, monitored_ip=MON)}
    assert ev["brolf@EASYAS123"].host == MON
    assert ev["alice@EASYAS123"].host == ""


# tshark path — same contract
_TSHARK_DHCP = (
    "t0\tbrads-MBP\t\t\t00:e0:4c:68:08:00\t1\n"
    "t1\tDESKTOP-TEYQ2NR\t10.2.28.88\t\t00:19:d1:b2:4d:ad\t3\n"
    "t2\t\t\t10.2.28.88\t00:19:d1:b2:4d:ad\t5\n"
)


def test_tshark_dhcp_foreign_mac_is_not_the_monitored_host():
    ev = _by_host(normalize_dhcp_identity(_TSHARK_DHCP, monitored_ip=MON))
    assert ev["DESKTOP-TEYQ2NR"].host == MON
    assert ev["brads-MBP"].host == ""
    assert ev["brads-MBP"].data["bound_to_monitored"] is False


def test_tshark_kerberos_foreign_client_not_attributed():
    krb = "t0\t10.2.28.60\t10.2.28.2\t88\t\talice\tEASYAS123\n"
    ev = normalize_kerberos_identity(krb, monitored_ip=MON)[0]
    assert ev.host == ""


def test_rule_summary_discloses_bystander():
    ev = _by_host(zn.normalize_zeek_dhcp(_ZEEK_DHCP, monitored_ip=MON))
    a = host_identity(ev["brads-MBP"])
    assert "not bound to the monitored host" in a.summary
    b = host_identity(ev["DESKTOP-TEYQ2NR"])
    assert "not bound" not in b.summary


def test_zeek_kerberos_prefers_fqdn_realm():
    # Parity with the tshark path: the FQDN realm (seen later) wins, so the
    # victim's AD DNS domain is observed (needed to scope wpad.<realm>).
    krb = (
        '{"ts":1.0,"id.orig_h":"10.2.28.88","id.resp_p":88,"client":"brolf/EASYAS123"}\n'
        '{"ts":2.0,"id.orig_h":"10.2.28.88","id.resp_p":88,"client":"brolf/EASYAS123.TECH"}\n')
    evs = zn.normalize_zeek_kerberos(krb, monitored_ip=MON)
    assert len(evs) == 1
    assert evs[0].data["account"] == "brolf@EASYAS123.TECH"
    assert evs[0].data["realm"] == "EASYAS123.TECH"
    assert evs[0].timestamp.startswith("1970-01-01 00:00:01")
