from spectre.core.base import NormEvent
from spectre.modules.pcap.normalize import (
    normalize_kerberos_identity,
    normalize_dhcp_identity,
)
from spectre.modules.pcap.rules import host_identity

# tshark -T fields: frame.time \t ip.src \t ip.dst \t udp.dstport \t tcp.dstport
#                   \t kerberos.CNameString \t kerberos.realm
_KRB = (
    "Feb 28, 2026 19:55:23.000000000 UTC\t10.2.28.88\t10.2.28.2\t88\t\tbrolf\tEASYAS123\n"
    "Feb 28, 2026 19:55:23.100000000 UTC\t10.2.28.2\t10.2.28.88\t\t\tbrolf\tEASYAS123.TECH\n"
)

# tshark -T fields: frame.time \t dhcp.option.hostname \t requested_ip
#                   \t dhcp.ip.your \t dhcp.hw.mac_addr \t dhcp.option.dhcp
_DHCP = (
    "Feb 28, 2026 19:50:00.0 UTC\tDESKTOP-TEYQ2NR\t10.2.28.88\t\t00:19:d1:b2:4d:ad,00:19:d1:b2:4d:ad\t3\n"
    "Feb 28, 2026 19:50:00.5 UTC\t\t\t10.2.28.88\t00:19:d1:b2:4d:ad,00:19:d1:b2:4d:ad\t5\n"
)


def test_kerberos_identity_binds_account_to_client_ip():
    events = normalize_kerberos_identity(_KRB, source_file="ev.pcap")
    assert len(events) == 1
    d = events[0].data
    assert d["account"] == "brolf@EASYAS123.TECH"   # FQDN realm preferred
    assert d["ip"] == "10.2.28.88"                    # dstport-88 client src
    assert d["source"] == "kerberos"
    assert events[0].artifact_type == "host_identity"


def test_dhcp_identity_binds_hostname_to_ip():
    events = normalize_dhcp_identity(_DHCP, source_file="ev.pcap")
    assert len(events) == 1
    d = events[0].data
    assert d["hostname"] == "DESKTOP-TEYQ2NR"
    assert d["ip"] == "10.2.28.88"
    assert d["mac"] == "00:19:d1:b2:4d:ad"            # comma-dup collapsed
    assert d["source"] == "dhcp"


def test_kerberos_empty_input_is_graceful():
    assert normalize_kerberos_identity("", source_file="ev.pcap") == []


def test_dhcp_empty_input_is_graceful():
    assert normalize_dhcp_identity("\n\n", source_file="ev.pcap") == []


def _identity_event(**data):
    base = {"hostname": "", "account": "", "realm": "", "ip": "", "mac": "",
            "source": "kerberos"}
    base.update(data)
    return NormEvent(artifact_type="host_identity", timestamp="t0",
                     source_file="ev.pcap", record_id="0", host="", data=base)


def test_host_identity_rule_populates_host_account_iocs():
    e = _identity_event(hostname="DESKTOP-TEYQ2NR", account="brolf@EASYAS123.TECH",
                        realm="EASYAS123.TECH", ip="10.2.28.88", source="dhcp")
    anchor = host_identity(e)
    assert anchor is not None
    assert anchor.rule_id == "pcap-host-identity"
    assert anchor.iocs["host"] == ["DESKTOP-TEYQ2NR"]
    assert anchor.iocs["account"] == ["brolf@EASYAS123.TECH"]
    assert anchor.iocs["ip"] == ["10.2.28.88"]
    assert anchor.mitre == []   # identity is context, not an attack technique


def test_host_identity_rule_ignores_empty_identity():
    assert host_identity(_identity_event()) is None
