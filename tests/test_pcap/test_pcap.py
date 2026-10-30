"""test_pcap.py — unit tests for the pcap analyzer module."""

import pytest

from spectre.core.base import NormEvent
from spectre.modules.pcap import PCAP_MODULE as pcap_module
from spectre.modules.pcap import rules as pcap_rules
from spectre.modules.pcap.rules import (
    ad_recon_pipe,
    beacon,
    dns_anomaly,
    exploit_probe,
    exposed_service,
)
from spectre.modules.pcap.normalize import (
    normalize_text,
    normalize_dns,
    normalize_http,
    normalize_beacon_timing,
    normalize_smb_pipes,
    normalize_drsuapi_calls,
    normalize_checksum_integrity,
    normalize,
)

_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 93.184.216.34.80: tcp 0\n"
    "2023-11-14 22:13:21.000000 IP 10.0.0.5.51001 > 45.77.12.9.4444: tcp 0\n"
    "garbage line that should be ignored\n"
)


def _detect(events):
    out = []
    for e in events:
        for r in pcap_module.rules:
            if r.artifact_type != e.artifact_type:
                continue
            a = r.predicate(e)
            if a:
                out.append(a)
    return out


def test_normalize_parses_connections():
    events = normalize_text(_TCPDUMP)
    assert len(events) == 2
    assert events[0].data["dst_port"] == "80"
    assert events[1].data["dst_ip"] == "45.77.12.9"


def test_suspicious_port_rule_fires_on_4444_only():
    anchors = _detect(normalize_text(_TCPDUMP))
    assert len(anchors) == 1
    assert anchors[0].rule_id == "pcap-suspicious-port"
    # outbound: remote address only — the monitored host is the victim,
    # never listed as an attacker IOC.
    assert anchors[0].iocs["ip"] == ["45.77.12.9"]


def test_benign_ports_no_detection():
    benign = "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 1.1.1.1.443: tcp 0\n"
    assert _detect(normalize_text(benign)) == []


def test_suspicious_port_dedup_key_collapses_same_dst():
    """Two connections from different sources to the SAME destination on
    a suspicious port must share a dedup_key so correlation collapses them."""
    data = (
        "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.4444: tcp 0\n"
        "2023-11-14 22:13:21.000000 IP 10.0.0.7.52000 > 45.77.12.9.4444: tcp 0\n"
        "2023-11-14 22:13:22.000000 IP 192.168.1.1.53000 > 93.184.216.34.5555: tcp 0\n"
    )
    events = normalize_text(data)
    anchors = _detect(events)
    # Three connections = three anchors (all fire the rule)
    assert len(anchors) == 3
    # But connections to 45.77.12.9 share the same dedup_key
    keys = [a.dedup_key for a in anchors]
    assert keys[0] == "outbound:45.77.12.9"
    assert keys[0] == keys[1], f"same dst_ip should share dedup_key, got {keys[0]} vs {keys[1]}"
    assert keys[2] == "outbound:93.184.216.34"


def test_suspicious_port_suppressed_on_well_known_src_port_reply():
    """ponytail guard: monitored host replying FROM a well-known port
    (e.g. 80) to a suspicious dst_port must be suppressed as a
    server-reply, not flagged as outbound C2."""
    data = (
        "2023-11-14 22:13:20.000000 IP 10.0.0.5.80 > 45.77.12.9.4444: tcp 0\n"
    )
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "outbound"
    assert _detect(events) == []


def test_suspicious_port_fires_on_ephemeral_src_port_outbound():
    """Real outbound C2: monitored host connects OUT from an ephemeral
    src_port to a suspicious dst_port — must not be suppressed by the
    server-reply guard."""
    data = (
        "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.4444: tcp 0\n"
    )
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "outbound"
    anchors = _detect(events)
    assert len(anchors) == 1
    assert anchors[0].rule_id == "pcap-suspicious-port"


def test_suspicious_port_fires_on_missing_src_port_fails_open():
    """A non-numeric/missing src_port must NOT suppress — the guard fails
    open so an unknown source port doesn't hide a real finding."""
    events = normalize_text(
        "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.4444: tcp 0\n",
        monitored_ip="10.0.0.5",
    )
    events[0].data["src_port"] = ""
    anchors = _detect(events)
    assert len(anchors) == 1
    assert anchors[0].rule_id == "pcap-suspicious-port"


def test_direction_with_monitored_ip():
    """When monitored_ip is provided, direction is based on monitored_ip
    rather than the private-IP heuristic — fixing 'unknown' for public-IP hosts."""
    data = (
        "2023-11-14 22:13:20.000000 IP 203.161.44.208.51000 > 93.184.216.34.80: tcp 0\n"
        "2023-11-14 22:13:21.000000 IP 45.77.12.9.4444 > 203.161.44.208.443: tcp 0\n"
        "2023-11-14 22:13:22.000000 IP 8.8.8.8.53 > 1.1.1.1.53: tcp 0\n"
    )
    events = normalize_text(data, monitored_ip="203.161.44.208")
    assert len(events) == 3
    # monitored IP as source → outbound
    assert events[0].data["direction"] == "outbound"
    # monitored IP as destination → inbound
    assert events[1].data["direction"] == "inbound"
    # neither matches monitored IP → unknown
    assert events[2].data["direction"] == "unknown"


def test_suspicious_port_inbound_iocs_list_remote_only():
    """Inbound: the remote prober (src_ip) is the IOC, not the monitored
    host being probed (dst_ip)."""
    data = "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.4444: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "inbound"
    anchors = _detect(events)
    assert len(anchors) == 1
    assert anchors[0].iocs["ip"] == ["45.77.12.9"]


# ── DNS: direction + host labeling ────────────────────────────────────

_DNS_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 8.8.8.8.53: 12345+ A? evil.example.com. (28)\n"
)


def test_normalize_dns_sets_direction_with_monitored_ip():
    """normalize_dns gains monitored_ip parity with the other normalizers —
    it must compute and stamp a direction, not leave dns events undirected."""
    events = normalize_dns(_DNS_TCPDUMP, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"


def test_normalize_dns_direct_call_unbroken_without_monitored_ip():
    """Direct callers that omit monitored_ip must not break (default '') —
    direction falls back to the private-IP heuristic, same as normalize_text."""
    events = normalize_dns(_DNS_TCPDUMP)
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"  # private src -> public dst


def test_normalize_dns_host_is_monitored_ip():
    events = normalize_dns(_DNS_TCPDUMP, monitored_ip="10.0.0.5")
    assert events[0].host == "10.0.0.5"


# ── host labeling across normalizers ────────────────────────────────────

def test_normalize_text_host_is_monitored_ip():
    events = normalize_text(_TCPDUMP, monitored_ip="10.0.0.5")
    assert all(e.host == "10.0.0.5" for e in events)


def test_normalize_text_host_empty_when_no_monitored_ip():
    events = normalize_text(_TCPDUMP)
    assert all(e.host == "" for e in events)


_HTTP_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 93.184.216.34.80: Flags [P.]\n"
    "\tGET /path HTTP/1.1\n"
    "\tHost: evil.example.com\n"
)


def test_normalize_http_host_is_monitored_ip():
    events = normalize_http(_HTTP_TCPDUMP, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].host == "10.0.0.5"


# ── BUG 2 (gold-002): tcpdump prints "options [mss 1460,nop,...]" inside
# every TCP SYN/ACK's option list. The old _HTTP_REQUEST regex,
# `(GET|POST|...|OPTIONS|...)\s+(\S+)`, matched the literal substring
# "options [" case-insensitively — mistaking a TCP option dump for the
# HTTP OPTIONS verb — and fabricated a pcap_http event out of a bare TCP
# handshake with no HTTP anywhere in it. ─────────────────────────────────

_TCP_SYN_ONLY_TCPDUMP = (
    "2026-02-28 19:55:24.026706 IP 10.2.28.88.59999 > 135.234.160.246.443: "
    "Flags [S], seq 426064873, win 65535, options [mss 1460,nop,wscale 8,"
    "sackOK,TS val 5801640 ecr 0], length 0\n"
    "2026-02-28 19:55:24.119014 IP 135.234.160.246.443 > 10.2.28.88.59999: "
    "Flags [S.], seq 915509984, ack 426064874, win 65535, options [mss 1376,"
    "nop,wscale 8,sackOK,TS val 1101320141 ecr 5801640], length 0\n"
)


def test_normalize_http_does_not_match_tcp_syn_options_as_http_request():
    """RED (gold-002): a bare TCP handshake with no HTTP traffic at all
    must not fabricate a pcap_http event just because tcpdump's TCP option
    dump contains the substring 'options ['."""
    events = normalize_http(_TCP_SYN_ONLY_TCPDUMP, monitored_ip="10.2.28.88")
    assert events == []


_HTTP_OPTIONS_VERB_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 93.184.216.34.80: Flags [P.]\n"
    "\tOPTIONS /cors-preflight HTTP/1.1\n"
    "\tHost: example.com\n"
)


def test_normalize_http_still_matches_real_options_verb_request():
    """A genuine HTTP OPTIONS request (a real request-line shape: METHOD SP
    path SP HTTP/1.x) must still be recognized — the fix tightens the
    regex, it doesn't remove OPTIONS support."""
    events = normalize_http(_HTTP_OPTIONS_VERB_TCPDUMP, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["http_method"].upper() == "OPTIONS"
    assert events[0].data["http_request_path"] == "/cors-preflight"


_TIMING_DATA = "\n".join(
    f"10.0.0.5.51000,10.0.0.9.443,2023-11-14 22:{i:02d}:00.000000" for i in range(12)
)


def test_normalize_beacon_timing_host_is_monitored_ip():
    events = normalize_beacon_timing(_TIMING_DATA, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].host == "10.0.0.5"
    assert events[0].data["monitored_host"] == "10.0.0.5"


def test_normalize_beacon_timing_direct_call_unbroken_without_monitored_ip():
    """Direct callers that omit monitored_ip must not break (default '')."""
    events = normalize_beacon_timing(_TIMING_DATA)
    assert len(events) == 1
    assert events[0].host == ""


def test_dispatcher_passes_monitored_ip_to_dns_and_timing(tmp_path):
    """The normalize() dispatcher must forward monitored_ip to normalize_dns
    and normalize_beacon_timing, not just normalize_text/normalize_http."""
    dns_path = tmp_path / "dns.txt"
    dns_path.write_text(_DNS_TCPDUMP)
    handle = {
        "path": str(dns_path),
        "extract_pass": "dns",
        "evidence_path": str(dns_path),
        "monitored_ip": "10.0.0.5",
    }
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"
    assert events[0].host == "10.0.0.5"

    timing_path = tmp_path / "timing.csv"
    timing_path.write_text(_TIMING_DATA)
    handle2 = {
        "path": str(timing_path),
        "extract_pass": "timing",
        "evidence_path": str(timing_path),
        "monitored_ip": "10.0.0.5",
    }
    events2 = normalize(handle2)
    assert len(events2) == 1
    assert events2[0].host == "10.0.0.5"


# ── BUG 3 (gold-003): beacon() had no direction awareness at all — an
# inbound scanner probing many ports still gets a reply from the monitored
# host's TCP/IP stack for every probe, producing the same regular per-IP
# timing signature as genuine beaconing. normalize_beacon_timing now
# threads the monitored host's own source port on each "outbound" sample
# through as beacon_data["monitored_is_client"], using the same
# ephemeral-vs-well-known-port discipline suspicious_port() already uses:
# a real beacon is the monitored host acting as a CLIENT (OS-assigned
# ephemeral src port); a scanner-triggered reply is the monitored host
# acting as a SERVER, replying from whatever (non-ephemeral) port it was
# probed on. ──────────────────────────────────────────────────────────

def _scan_reply_timing_csv(monitored_ip: str, remote_ip: str, remote_port: str,
                            start_port: int, count: int = 12) -> str:
    """Model case-003's 103.75.180.126 pattern: a remote scanner probes a
    NEW (incrementing, non-ephemeral) destination port on the monitored
    host each time; the monitored host's reply carries that same
    non-ephemeral port as ITS OWN source port."""
    lines = []
    for i in range(count):
        lines.append(
            f"{monitored_ip}.{start_port + i},{remote_ip}.{remote_port},"
            f"2026-03-11 09:{28 + i:02d}:00.000000"
        )
    return "\n".join(lines)


def test_normalize_beacon_timing_flags_scanner_reply_as_not_client():
    """RED (gold-003): the monitored host replying from a scanned,
    non-ephemeral port must be flagged monitored_is_client=False."""
    csv = _scan_reply_timing_csv("203.161.44.208", "103.75.180.126", "61234",
                                  start_port=5900)
    events = normalize_beacon_timing(csv, monitored_ip="203.161.44.208")
    assert len(events) == 1
    assert events[0].data["beacon_data"]["monitored_is_client"] is False


def _real_beacon_timing_csv(monitored_ip: str, remote_ip: str, remote_port: str,
                             src_port: str, count: int = 12) -> str:
    """Model case-002's NetSupport pattern: the monitored host, as CLIENT,
    reuses one OS-assigned ephemeral source port for a long-lived
    connection to the C2."""
    lines = [
        f"{monitored_ip}.{src_port},{remote_ip}.{remote_port},"
        f"2026-02-28 19:{i:02d}:00.000000"
        for i in range(count)
    ]
    return "\n".join(lines)


def test_normalize_beacon_timing_flags_genuine_client_as_client():
    """A monitored host reusing a single ephemeral source port to reach a
    remote IP repeatedly (a real outbound beacon/keep-alive session) must
    be flagged monitored_is_client=True."""
    csv = _real_beacon_timing_csv("10.2.28.88", "45.131.214.85", "443",
                                   src_port="51912")
    events = normalize_beacon_timing(csv, monitored_ip="10.2.28.88")
    assert len(events) == 1
    assert events[0].data["beacon_data"]["monitored_is_client"] is True


def test_normalize_beacon_timing_no_monitored_ip_leaves_client_unknown():
    """Without a resolved monitored_ip there is no way to know which side
    is 'us' — monitored_is_client must be None (unknown), not a guess."""
    csv = _scan_reply_timing_csv("203.161.44.208", "103.75.180.126", "61234",
                                  start_port=5900)
    events = normalize_beacon_timing(csv)
    assert len(events) == 1
    assert events[0].data["beacon_data"]["monitored_is_client"] is None


# ── c2_protocol: monitored host must never be listed as the IOC ────────

# BUG 1 (gold-002/gold-003): Checks 1-2 (plaintext-HTTP-on-443 and bare
# HTTP-on-443) used to fire unconditionally on ANY direction, including
# inbound — a remote scanner's plaintext HTTP request landing on our
# HTTPS port was indistinguishable from us doing C2 (gold-003:
# F-270-024/025/033, all inbound). They now carry the same
# `direction != "inbound"` guard as Checks 3-6.
_C2_INBOUND_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.443: Flags [P.]\n"
    "\tGET http://10.0.0.5/beacon HTTP/1.1\n"
)


def test_c2_protocol_plaintext_on_443_does_not_fire_on_inbound():
    """RED (gold-003): an inbound scanner probe with a plaintext HTTP
    request line on port 443 must not be labeled the monitored host's own
    C2 protocol — this is Checks 1-2's missing inbound guard."""
    events = normalize_http(_C2_INBOUND_TCPDUMP, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "inbound"
    anchors = _detect(events)
    c2_anchors = [a for a in anchors if a.rule_id == "pcap-c2-protocol"]
    assert c2_anchors == []


def test_c2_protocol_plaintext_on_443_fires_on_outbound_and_lists_remote_only():
    """Same plaintext-HTTP-on-443 signature, but the monitored host is the
    one issuing the request (outbound) — a real client-side evasion
    indicator, must still fire, with the remote (dst_ip) as the sole IOC."""
    text = (
        "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.443: Flags [P.]\n"
        "\tGET http://45.77.12.9/beacon HTTP/1.1\n"
    )
    events = normalize_http(text, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"
    anchors = _detect(events)
    c2_anchors = [a for a in anchors if a.rule_id == "pcap-c2-protocol"]
    assert len(c2_anchors) == 1
    assert c2_anchors[0].iocs["ip"] == ["45.77.12.9"]
    assert "10.0.0.5" not in c2_anchors[0].iocs["ip"]


# ── BUG 1a (gold-002): the "HTTP response on port 443 (non-TLS)" check
# used to match the bare substring "HTTP/1.1" anywhere in the raw dump —
# which also matches the literal ALPN protocol-name token ("h2, http/1.1")
# present in the TLS ClientHello/ServerHello extension of virtually every
# ordinary HTTPS connection. F-269-003 (watson.events.data.microsoft.com,
# genuine TLS, zero plaintext HTTP anywhere) was flagged purely off that
# ALPN text. ──────────────────────────────────────────────────────────

_TLS_ALPN_RAW = (
    "2026-02-28 19:55:24.129646 IP 10.2.28.88.59999 > 135.234.160.246.443: Flags [P.]\n"
    "\t.X......._...e;.6......\n"
    "\t.v.....\n"
    "\t.X..A..............i.H+...=.O...>.l\"x..05K.c...u.....$.,.+.0./.$.#.(.'.\n"
    "\t.\t.........=.<.5./.......%.#.. watson.events.data.microsoft.com..........\n"
    "\t...............................................#.........h2.http/1.1.........\n"
)


def _c2_http_event_raw(raw, dst_port="443", direction="outbound", ascii_payload=""):
    return NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": "", "dst_port": dst_port, "raw": raw,
            "ascii_payload": ascii_payload, "http_user_agent": "", "http_server": "",
            "direction": direction, "http_request_path": "",
        },
    )


def test_c2_protocol_does_not_fire_on_tls_alpn_http11_token():
    """RED (gold-002): the literal ALPN token 'http/1.1' inside a genuine
    TLS ClientHello must not be mistaken for a bare HTTP response line."""
    event = _c2_http_event_raw(_TLS_ALPN_RAW, dst_port="443", direction="outbound")
    assert pcap_rules.c2_protocol(event) is None


_BARE_HTTP_RESPONSE_RAW = (
    "2026-02-28 19:55:51.678147 IP 45.131.214.85.443 > 10.2.28.88.51912: Flags [P.]\n"
    "\tHTTP/1.1 200 OK\n"
    "\tServer: NetSupport Gateway/1.92 (Windows NT)\n"
    "\tContent-Type: application/x-www-form-urlencoded\n"
)


def test_c2_protocol_fires_on_genuine_bare_http_response_on_443():
    """A REAL bare HTTP status line on port 443 (no TLS handshake at all —
    the NetSupport RAT gateway's actual behavior in case 002) must still
    fire. Guards against over-tightening the ALPN fix into a false
    negative on the true positive."""
    event = _c2_http_event_raw(_BARE_HTTP_RESPONSE_RAW, dst_port="443", direction="outbound")
    a = pcap_rules.c2_protocol(event)
    assert a is not None
    assert "HTTP response on port 443" in a.title


def test_c2_protocol_bare_http_response_does_not_fire_on_inbound():
    """Same genuine bare-HTTP-response shape, but inbound — our server
    replying to a scanner is not us doing C2. Must not fire."""
    event = _c2_http_event_raw(_BARE_HTTP_RESPONSE_RAW, dst_port="443", direction="inbound")
    assert pcap_rules.c2_protocol(event) is None


def test_c2_protocol_netsupport_full_fingerprint_still_fires():
    """End-to-end regression: the real case-002 NetSupport RAT exchange
    (bare HTTP-on-443 response + NetSupport User-Agent + CMD=POLL/ENCD)
    must still produce a CONFIRMED-shaped multi-trigger finding after the
    ALPN/direction fixes — this is the true positive the fix must not
    regress."""
    text = (
        "2026-02-28 19:55:51.373340 IP 10.2.28.88.51912 > 45.131.214.85.443: Flags [P.]\n"
        "\tPOST http://45.131.214.85/fakeurl.htm HTTP/1.1\n"
        "\tUser-Agent: NetSupport Manager/1.3\n"
        "\tContent-Type: application/x-www-form-urlencoded\n"
        "\tHost: 45.131.214.85\n"
        "\tConnection: Keep-Alive\n"
        "\n"
        "\tCMD=POLL\n"
        "\tINFO=1\n"
        "\tACK=1\n"
    )
    events = normalize_http(text, monitored_ip="10.2.28.88")
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"
    a = pcap_rules.c2_protocol(events[0])
    assert a is not None
    assert "User-Agent matches: NetSupport Manager" in a.title
    assert "CMD=POLL/ENCD remote-access protocol" in a.title
    assert a.iocs["ip"] == ["45.131.214.85"]


# ── c2_protocol: client-fingerprint checks must not fire on inbound scans
# (gold-003: zgrab/Xpanse/libredtail/xfa1 scanning the monitored web server
# is opportunistic inbound scanning, not the monitored host beaconing out
# as a C2 client) ───────────────────────────────────────────────────────

_C2_SCANNER_UA_TCPDUMP_TEMPLATE = (
    "2023-11-14 22:13:20.000000 IP {src}.51000 > {dst}.80: Flags [P.]\n"
    "\tGET / HTTP/1.1\n"
    "\tUser-Agent: Mozilla/5.0 zgrab/0.x\n"
)


def test_c2_protocol_user_agent_check_does_not_fire_on_inbound_scan():
    """RED: an inbound scanner (zgrab) probing the monitored web server
    carries a known 'C2 User-Agent' signature, but the monitored host never
    sent that UA — it is being scanned, not beaconing. Must not fire."""
    text = _C2_SCANNER_UA_TCPDUMP_TEMPLATE.format(src="45.77.12.9", dst="10.0.0.5")
    events = normalize_http(text, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "inbound"
    assert pcap_rules.c2_protocol(events[0]) is None


def test_c2_protocol_user_agent_check_fires_on_outbound():
    """Same signature, but the monitored host is the one issuing the
    request (outbound) — real client-side C2 fingerprinting, must fire."""
    text = _C2_SCANNER_UA_TCPDUMP_TEMPLATE.format(src="10.0.0.5", dst="45.77.12.9")
    events = normalize_http(text, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"
    a = pcap_rules.c2_protocol(events[0])
    assert a is not None
    assert a.rule_id == "pcap-c2-protocol"


def test_c2_protocol_user_agent_check_fires_on_unknown_direction():
    """When direction cannot be determined (monitored_ip unresolved), do
    not suppress — only definitively inbound traffic is suppressed."""
    event = NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": "", "dst_port": "80", "raw": "",
            "ascii_payload": "", "http_user_agent": "Mozilla/5.0 zgrab/0.x",
            "http_server": "", "direction": "unknown",
            "http_request_path": "",
        },
    )
    a = pcap_rules.c2_protocol(event)
    assert a is not None
    assert a.rule_id == "pcap-c2-protocol"


_C2_OUTBOUND_TCPDUMP = (
    "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.8080: Flags [P.]\n"
    "\tGET /beacon HTTP/1.1\n"
    "\tCMD=POLL\n"
)


def test_c2_protocol_outbound_iocs_list_remote_only():
    """Outbound C2 traffic: the remote C2 server (dst_ip) is the IOC, not
    the monitored host initiating the connection (src_ip)."""
    events = normalize_http(_C2_OUTBOUND_TCPDUMP, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["direction"] == "outbound"
    anchors = _detect(events)
    c2_anchors = [a for a in anchors if a.rule_id == "pcap-c2-protocol"]
    assert len(c2_anchors) == 1
    assert c2_anchors[0].iocs["ip"] == ["45.77.12.9"]
    assert "10.0.0.5" not in c2_anchors[0].iocs["ip"]


# ── ad_recon_pipe: monitored host must never be listed as an IOC ───────

_SMB_LINE_TEXT = (
    "2023-11-14 22:13:20.000000\t10.0.0.5\t10.0.0.7\t\\PIPE\\samr\n"
)


def test_normalize_smb_pipes_host_is_monitored_ip():
    """normalize_smb_pipes gains monitored_ip parity with the other pcap
    normalizers — it must stamp NormEvent.host with monitored_ip, not the
    packet's src_ip. Uses a monitored_ip distinct from both packet
    addresses so a stale src_ip-as-host fallback cannot pass by accident."""
    events = normalize_smb_pipes(_SMB_LINE_TEXT, monitored_ip="10.0.0.99")
    assert len(events) == 1
    assert events[0].host == "10.0.0.99"


def test_dispatcher_passes_monitored_ip_to_smb_pipes(tmp_path):
    smb_path = tmp_path / "smb.tsv"
    smb_path.write_text(_SMB_LINE_TEXT)
    handle = {
        "path": str(smb_path),
        "extract_pass": "smb2_pipes",
        "evidence_path": str(smb_path),
        "monitored_ip": "10.0.0.99",
    }
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].host == "10.0.0.99"


def test_ad_recon_pipe_excludes_monitored_host_from_iocs():
    """The monitored host (10.0.0.5) issuing a SAMR query against a remote
    DC (10.0.0.7) must not appear in the finding's IOC list — only the
    remote endpoint should."""
    events = normalize_smb_pipes(_SMB_LINE_TEXT, monitored_ip="10.0.0.5")
    anchors = _detect(events)
    ad_anchors = [a for a in anchors if a.rule_id == "smb-ad-recon-pipe"]
    assert len(ad_anchors) == 1
    assert "10.0.0.5" not in ad_anchors[0].iocs["ip"]
    assert ad_anchors[0].iocs["ip"] == ["10.0.0.7"]


def test_ad_recon_pipe_keeps_both_ips_when_host_unknown():
    """When monitored_ip is unavailable, host is empty and we cannot tell
    which side is the victim — both IPs are kept (pre-existing behavior)."""
    events = normalize_smb_pipes(_SMB_LINE_TEXT)
    assert events[0].host == ""
    anchors = _detect(events)
    ad_anchors = [a for a in anchors if a.rule_id == "smb-ad-recon-pipe"]
    assert len(ad_anchors) == 1
    assert sorted(ad_anchors[0].iocs["ip"]) == ["10.0.0.5", "10.0.0.7"]


# ── drsuapi_opnum: DCSync (opnum 3) vs name-resolution (opnum 12) ──────
# gold-002: the drsuapi pipe rarely opens via SMB2 CREATE — DRSUAPI in that
# capture runs over a dynamic ncacn_ip_tcp port after an EPM lookup, so the
# pipe-open rule (ad_recon_pipe) never sees it. The opnum is only visible on
# the DCERPC/drsuapi payload itself, hence a dedicated artifact_type.

_DRSUAPI_LINE_DCSYNC = (
    "Feb 28, 2026 19:55:23.336143000 UTC\t10.0.0.5\t10.0.0.7\t3\n"
)
_DRSUAPI_LINE_NAMERES = (
    "Feb 28, 2026 19:55:23.334569000 UTC\t10.0.0.5\t10.0.0.7\t12\n"
)
_DRSUAPI_LINE_BIND = (
    "Feb 28, 2026 19:55:23.333834000 UTC\t10.0.0.5\t10.0.0.7\t0\n"
)


def test_normalize_drsuapi_calls_parses_opnum_as_int():
    events = normalize_drsuapi_calls(_DRSUAPI_LINE_DCSYNC, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].artifact_type == "drsuapi_call"
    assert events[0].data["opnum"] == 3
    assert events[0].host == "10.0.0.5"


def test_dispatcher_passes_monitored_ip_to_drsuapi(tmp_path):
    drsuapi_path = tmp_path / "drsuapi.tsv"
    drsuapi_path.write_text(_DRSUAPI_LINE_DCSYNC)
    handle = {
        "path": str(drsuapi_path),
        "extract_pass": "drsuapi_opnum",
        "evidence_path": str(drsuapi_path),
        "monitored_ip": "10.0.0.99",
    }
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].host == "10.0.0.99"


def test_dispatcher_passes_monitored_ip_to_checksum(tmp_path):
    cksum_path = tmp_path / "checksum.txt"
    cksum_path.write_text(_CHECKSUM_INBOUND_BAD)
    handle = {
        "path": str(cksum_path),
        "extract_pass": "checksum",
        "evidence_path": str(cksum_path),
        "monitored_ip": "10.0.0.5",
    }
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].host == "10.0.0.5"
    assert events[0].data["checksum_data"]["ip"] == "203.0.113.9"


def test_drsuapi_opnum_3_fires_dcsync_class_finding():
    """DsGetNCChanges (opnum 3) is the DCSync attack primitive — must be
    specialized to T1003.006 at raised confidence, distinct from ordinary
    name-resolution recon."""
    events = normalize_drsuapi_calls(_DRSUAPI_LINE_DCSYNC, monitored_ip="10.0.0.5")
    anchors = _detect(events)
    dcsync_anchors = [a for a in anchors if a.rule_id == "smb-drsuapi-opnum"]
    assert len(dcsync_anchors) == 1
    a = dcsync_anchors[0]
    assert a.mitre == ["T1003.006"]
    assert "DsGetNCChanges" in a.title
    assert "10.0.0.7" in a.iocs["ip"]
    assert "10.0.0.5" not in a.iocs["ip"]


def test_drsuapi_opnum_12_fires_name_resolution_recon_lead():
    """DsCrackNames (opnum 12) is the SharpHound/BloodHound name-resolution
    hallmark — a recon lead, not a DCSync claim, and must not carry
    T1003.006."""
    events = normalize_drsuapi_calls(_DRSUAPI_LINE_NAMERES, monitored_ip="10.0.0.5")
    anchors = _detect(events)
    nameres_anchors = [a for a in anchors if a.rule_id == "smb-drsuapi-opnum"]
    assert len(nameres_anchors) == 1
    a = nameres_anchors[0]
    assert a.mitre == ["T1087.002"]
    assert "T1003.006" not in a.mitre
    assert "DsCrackNames" in a.title


def test_drsuapi_opnum_3_confidence_exceeds_opnum_12():
    """DCSync-class must score strictly higher than name-resolution — the
    whole point of the granularity is that DCSync is the more severe claim."""
    dcsync_events = normalize_drsuapi_calls(_DRSUAPI_LINE_DCSYNC, monitored_ip="10.0.0.5")
    nameres_events = normalize_drsuapi_calls(_DRSUAPI_LINE_NAMERES, monitored_ip="10.0.0.5")
    dcsync_anchor = _detect(dcsync_events)[0]
    nameres_anchor = _detect(nameres_events)[0]
    assert dcsync_anchor.confidence > nameres_anchor.confidence


def test_drsuapi_bind_unbind_opnums_are_not_diagnostic():
    """DsBind/DsUnbind (opnums 0/1) are session churn, not a finding on
    their own — the rule must not fire on them."""
    events = normalize_drsuapi_calls(_DRSUAPI_LINE_BIND, monitored_ip="10.0.0.5")
    anchors = _detect(events)
    assert not [a for a in anchors if a.rule_id == "smb-drsuapi-opnum"]


# ── benign-infrastructure allowlist migration (YAML-backed) ────────────

def _beacon_event(ip, intervals):
    mean_interval = sum(intervals) / len(intervals)
    return NormEvent(
        artifact_type="pcap_timing", timestamp="", source_file="x.pcap",
        record_id="0",
        data={"beacon_data": {
            "ip": ip, "intervals": intervals,
            "sample_count": len(intervals), "mean_interval": mean_interval,
        }},
    )


def test_beacon_skips_genuine_akamai_cidr_block():
    # A11/A5 Finding 2 fix: benign_infra_ip_prefixes moved from bare
    # single/double-octet string prefixes ("23." blanket-matched all
    # 16.7M addresses in 23.0.0.0/8) to real, narrow, parsed CIDR blocks.
    # 23.32.5.9 sits inside Akamai's registered 23.32.0.0/11 — still
    # skipped.
    intervals = [60.0] * 12
    assert beacon(_beacon_event("23.32.5.9", intervals)) is None


def test_beacon_no_longer_blanket_skips_former_broad_azure_octet():
    """A5 Finding 2's core repro: '13.'/'20.'/'40.'/'52.'/'104.' each used
    to blanket-suppress an entire /8 (16.7M addresses) of generic,
    tenant-assignable Azure IP space — exactly the domain-fronting C2
    threat model pcap-c2-protocol's own T1090.004 mapping exists for.
    Multi-tenant hyperscale cloud ranges cannot be responsibly narrowed to
    a small "trusted" CIDR (any tenant, benign or malicious, can be
    assigned an address in them), so they are no longer allowlisted at
    all — a clean beacon to one of these addresses must now fire."""
    intervals = [60.0] * 12
    for ip in ("13.107.6.10", "20.42.0.5", "40.90.4.4", "52.184.10.5", "104.40.1.1"):
        a = beacon(_beacon_event(ip, intervals))
        assert a is not None, f"{ip} should no longer be blanket-suppressed"
        assert a.rule_id == "pcap-beacon"


def test_beacon_ip_outside_narrowed_akamai_cidr_still_fires():
    """23.1.2.3 sits OUTSIDE both narrowed Akamai blocks (23.32.0.0/11,
    23.192.0.0/11) — unlike the old bare '23.' prefix (which matched all
    of 23.0.0.0/8), it must now fire as a genuine beacon candidate."""
    intervals = [60.0] * 12
    a = beacon(_beacon_event("23.1.2.3", intervals))
    assert a is not None


def test_beacon_fires_on_non_legitimate_ip():
    intervals = [60.0] * 12
    a = beacon(_beacon_event("45.77.12.9", intervals))
    assert a is not None
    assert a.rule_id == "pcap-beacon"


def test_beacon_mitre_never_upgrades_on_port_443_dead_branch_removed():
    """Finding 3: normalize_beacon_timing's awk pipeline strips the port
    before it ever reaches this rule, so the old T1573.001
    "encrypted-channel" refinement (keyed on a port that never arrives)
    was dead code — removed rather than wired to a fake port source. Even
    a hand-crafted event carrying dst_port/beacon_data['port'] == '443'
    (something the real pipeline never produces) must not upgrade the
    mitre list; pcap-beacon always maps to the base technique alone."""
    intervals = [60.0] * 12
    event = _beacon_event("45.77.12.9", intervals)
    event.data["dst_port"] = "443"
    event.data["beacon_data"]["port"] = "443"
    a = beacon(event)
    assert a is not None
    assert a.mitre == ["T1071.001"]


# ── BUG 3 (gold-003): beacon() must not label an inbound scanner's
# regularly-timed probes as "C2 Beacon detected" for the monitored host.
# normalize_beacon_timing threads beacon_data["monitored_is_client"]
# through (True/False/None-unknown) — see the normalize-level tests above
# for how that signal is derived. ──────────────────────────────────────

def _beacon_event_with_client_flag(ip, intervals, monitored_is_client):
    mean_interval = sum(intervals) / len(intervals)
    return NormEvent(
        artifact_type="pcap_timing", timestamp="", source_file="x.pcap",
        record_id="0",
        data={"beacon_data": {
            "ip": ip, "intervals": intervals,
            "sample_count": len(intervals), "mean_interval": mean_interval,
            "monitored_is_client": monitored_is_client,
        }},
    )


def test_beacon_does_not_fire_when_monitored_is_not_client():
    """RED (gold-003): a remote IP whose regular timing is driven by the
    monitored host mechanically replying from a scanned (non-ephemeral)
    port — not by the monitored host initiating — must not be flagged as
    a C2 beacon (F-270-034: 103.75.180.126, an inbound port-scanner)."""
    intervals = [28.0] * 100
    event = _beacon_event_with_client_flag("103.75.180.126", intervals, False)
    assert beacon(event) is None


def test_beacon_fires_when_monitored_is_client_true():
    """The monitored host genuinely initiating (ephemeral src port) must
    still fire — the positive counterpart of the guard above."""
    intervals = [60.0] * 12
    event = _beacon_event_with_client_flag("45.131.214.85", intervals, True)
    a = beacon(event)
    assert a is not None
    assert a.rule_id == "pcap-beacon"


def test_beacon_fires_when_monitored_is_client_unknown():
    """monitored_is_client absent entirely (e.g. no monitored_ip was ever
    resolved) must fail OPEN, same discipline as the direction guards
    elsewhere in this module — this is exactly test_beacon_fires_on_non_
    legitimate_ip's fixture shape (no monitored_is_client key at all)."""
    intervals = [60.0] * 12
    a = beacon(_beacon_event("45.77.12.9", intervals))
    assert a is not None


def _c2_http_event(http_host):
    return NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": http_host, "dst_port": "80", "raw": "",
            "ascii_payload": "", "http_user_agent": "", "http_server": "",
            "direction": "outbound", "http_request_path": "",
        },
    )


def test_c2_protocol_still_fires_on_ipify_host_header_after_migration():
    """c2_checkin_hosts moved from a hardcoded set to YAML — behavior must
    be preserved: api.ipify.org still triggers the suspicious-Host-header
    check."""
    a = pcap_rules.c2_protocol(_c2_http_event("api.ipify.org"))
    assert a is not None
    assert "suspicious Host header" in a.title


# ── c2_protocol: Host-header domain harvesting (Track F) ──────────────────
# A request already classified C2 by a "host-is-attacker-infrastructure"
# trigger (UA / Server / POLL / campaign tag / plaintext-on-443) carries the
# C2 domain in its Host header. Harvest it as a domain IOC so normal-TLD C2
# domains surface (gold-001: ~46 domains previously invisible). Check-5
# (benign ip-discovery services) must NOT be harvested.

def _c2_ua_event(http_host, request_path="", ua="Mozilla/5.0 zgrab/0.x"):
    return NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": http_host, "dst_port": "80", "raw": "",
            "ascii_payload": "", "http_user_agent": ua, "http_server": "",
            "direction": "outbound", "http_request_path": request_path,
        },
    )


def test_c2_protocol_harvests_host_domain_on_ua_match():
    """Outbound request with a known C2 UA and a normal-TLD Host header:
    the Host names the C2 endpoint — harvest it as a domain IOC."""
    a = pcap_rules.c2_protocol(_c2_ua_event("www.unitedsharesbank.com"))
    assert a is not None
    assert "www.unitedsharesbank.com" in a.iocs["domain"]


def test_c2_protocol_harvests_host_domain_on_campaign_tag():
    """Campaign-tag check-in (z8=...) to a normal-TLD Host: harvest the Host."""
    a = pcap_rules.c2_protocol(
        _c2_ua_event("www.goranstaxi.se", request_path="/x?z8=MN12STGOG", ua="")
    )
    assert a is not None
    assert "www.goranstaxi.se" in a.iocs["domain"]


def test_c2_protocol_harvested_host_domain_is_normalized():
    """Host is lowercased and any :port suffix stripped before harvesting."""
    a = pcap_rules.c2_protocol(_c2_ua_event("WWW.365JIA.CN:8080"))
    assert a is not None
    assert "www.365jia.cn" in a.iocs["domain"]


def test_c2_protocol_does_not_harvest_ipify_checkin_host_as_domain():
    """Check-5-only firing: api.ipify.org is a benign IP-discovery service the
    malware abuses, NOT a C2 domain — it must fire but harvest no domain."""
    a = pcap_rules.c2_protocol(_c2_http_event("api.ipify.org"))
    assert a is not None
    assert a.iocs["domain"] == []


def test_c2_protocol_does_not_harvest_bare_ip_host_as_domain():
    """A bare-IP Host header already belongs in the ip IOC list; a domain IOC
    that is an IP literal is malformed and must not be harvested."""
    a = pcap_rules.c2_protocol(_c2_ua_event("45.77.12.9"))
    assert a is not None
    assert a.iocs["domain"] == []


# ── A11-01/02: dedup_key must incorporate the Host, not just the dst IP ──
# c2_protocol previously set dedup_key=ip alone, so two DISTINCT malicious
# domains sharing one hosting IP collapsed into a single finding in
# correlation.corroborate() (grouped by (rule_id, dedup_key)) — the second
# domain silently vanished. Real XLoader campaign: www.e9ebq23.store and
# www.cpcrayd.store both resolved to 8.212.120.56.

def _c2_ua_event_with_ip(http_host, dst_ip, ua="Mozilla/5.0 zgrab/0.x"):
    return NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": http_host, "dst_port": "80", "raw": "",
            "ascii_payload": "", "http_user_agent": ua, "http_server": "",
            "direction": "outbound", "http_request_path": "",
            "src_ip": "10.0.0.5", "dst_ip": dst_ip,
        },
    )


def test_c2_protocol_dedup_key_distinguishes_domains_sharing_one_ip():
    """Two distinct malicious Host headers sharing one dst_ip must get
    DIFFERENT dedup_keys, so correlation.corroborate() surfaces both as
    separate findings instead of collapsing the second into the first."""
    a1 = pcap_rules.c2_protocol(_c2_ua_event_with_ip("www.e9ebq23.store", "8.212.120.56"))
    a2 = pcap_rules.c2_protocol(_c2_ua_event_with_ip("www.cpcrayd.store", "8.212.120.56"))
    assert a1 is not None and a2 is not None
    assert a1.dedup_key != a2.dedup_key


def test_c2_protocol_dedup_key_still_collapses_true_repeats():
    """The SAME domain hitting the SAME IP repeatedly must still collapse
    to one dedup_key — this is not a wholesale removal of IP-based dedup,
    only a fix for the domain-collision case."""
    a1 = pcap_rules.c2_protocol(_c2_ua_event_with_ip("www.e9ebq23.store", "8.212.120.56"))
    a2 = pcap_rules.c2_protocol(_c2_ua_event_with_ip("www.e9ebq23.store", "8.212.120.56"))
    assert a1.dedup_key == a2.dedup_key


def test_c2_protocol_corroborate_surfaces_both_domains_on_shared_ip():
    """End-to-end through correlation.corroborate(): both C2 domains
    sharing one IP must yield two distinct claims/findings, and repeating
    an IP-sibling's exact (ip, host) pair again must not add a third."""
    from spectre.pipeline.correlation import corroborate

    events = [
        _c2_ua_event_with_ip("www.e9ebq23.store", "8.212.120.56"),
        _c2_ua_event_with_ip("www.cpcrayd.store", "8.212.120.56"),
        _c2_ua_event_with_ip("www.cpcrayd.store", "8.212.120.56"),  # repeat
    ]
    anchors = [pcap_rules.c2_protocol(e) for e in events]
    groups = corroborate(anchors)
    c2_groups = [g for g in groups if g.representative.rule_id == "pcap-c2-protocol"]
    assert len(c2_groups) == 2
    domains = {d for g in c2_groups for d in g.representative.iocs["domain"]}
    assert "www.e9ebq23.store" in domains
    assert "www.cpcrayd.store" in domains
    # the repeated cpcrayd hit collapsed into ONE group, not a third
    cpcrayd_group = next(g for g in c2_groups
                          if "www.cpcrayd.store" in g.representative.iocs["domain"])
    assert cpcrayd_group.occurrence_count == 2


def test_c2_protocol_does_not_harvest_decoy_host_on_443_evasion():
    """gold-003 pattern: bare HTTP-on-443 (Check 1, an evasion channel) with a
    forged decoy Host (Host: www.baidu.com while the real dst is an unrelated
    IP). Check 1 must fire but harvest NO domain — the Host is untrustworthy,
    the real C2 is the IP."""
    event = NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0",
        data={
            "http_host": "www.baidu.com", "dst_port": "443",
            "raw": "POST /upload.exe HTTP/1.1\nHost: www.baidu.com\n",
            "ascii_payload": "", "http_user_agent": "Mozilla/5.0",
            "http_server": "", "direction": "outbound",
            "http_request_path": "/upload.exe",
            "src_ip": "10.0.0.5", "dst_ip": "203.161.44.208",
        },
    )
    a = pcap_rules.c2_protocol(event)
    assert a is not None
    assert "port 443 (non-TLS)" in a.title
    assert a.iocs["domain"] == []


def _dns_event(domain):
    return NormEvent(
        artifact_type="pcap_dns", timestamp="", source_file="x.pcap",
        record_id="0", data={"dns_query": domain},
    )


def test_dns_anomaly_none_for_benign_infra_subdomain():
    """A DGA-pattern-looking subdomain of a known CRL/OCSP host must be
    suppressed by the benign_infra_domains guard (kills the Google/MS-CRL
    false-positive class)."""
    domain = "aaaaaaaaaaaaaaaaaaaa.crl.microsoft.com"
    assert dns_anomaly(_dns_event(domain)) is None


# ── Rule: exploit_probe IOC orientation (Finding 2) ──────────────────

def _exploit_probe_event(src_ip, dst_ip, direction, request_path="/config/getuser"):
    return NormEvent(
        artifact_type="pcap_http", timestamp="", source_file="x.pcap",
        record_id="0", host="10.0.0.5",
        data={
            "src_ip": src_ip, "dst_ip": dst_ip, "direction": direction,
            "http_request_path": request_path,
        },
    )


def test_exploit_probe_iocs_the_remote_attacker_not_the_monitored_host():
    """Exploit probes are typically inbound (attacker -> victim). dst_ip
    is the monitored host in that case — the IOC must be the attacker's
    src_ip, not the victim, and must never equal the monitored host."""
    monitored_ip = "10.0.0.5"
    attacker_ip = "203.0.113.9"
    event = _exploit_probe_event(
        src_ip=attacker_ip, dst_ip=monitored_ip, direction="inbound",
    )
    a = exploit_probe(event)
    assert a is not None
    assert a.iocs["ip"] == [attacker_ip]
    assert monitored_ip not in a.iocs["ip"]


# ── exposed_service: exposed listening service (case 003 — MongoDB 27017) ──
#
# exposed_service is the SOLE rule for a sensitive database/cache service port
# (27017/etc.) — it fires only when the monitored host is answering an INBOUND
# connection on such a port (the host is exposing the service). 27017 is NOT in
# suspicious_ports, so there is no T1571/C2 double-fire (Track D review fix).
#
# Extractor limitation (see rules.py exposed_service docstring): the
# connections pass runs `tcpdump -q`, which never emits TCP flags, so a true
# SYN/SYN-ACK handshake check is unavailable. The rule is scoped to what the
# normalized `direction` field actually provides — inbound-to-monitored-host
# on a sensitive port — not a confirmed completed handshake.

def test_exposed_service_fires_on_inbound_mongodb():
    """Case 003: a remote host connects inbound to the monitored host on
    27017 (MongoDB) — must fire as an exposed-service finding, not be
    silently absorbed into the generic suspicious-port bucket."""
    data = "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.27017: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "inbound"
    a = exposed_service(events[0])
    assert a is not None
    assert a.rule_id == "pcap-exposed-service"
    assert "T1133" in a.mitre
    assert "outbound" not in a.title.lower()
    assert "c2" not in a.title.lower()


def test_inbound_mongodb_does_not_double_fire_as_suspicious_port_c2():
    """Regression (Track D whole-branch review): 27017 was in BOTH
    suspicious_ports and exposed_service_ports, so an inbound MongoDB flow
    fired pcap-exposed-service (T1133) AND pcap-suspicious-port (T1571, C2
    framing) for the same packet. The T1571/C2 label on an inbound DB probe
    is exactly the misframing the T1133 rule was built to replace — it must
    not persist alongside it. suspicious_port must NOT fire on an exposed
    listening-service port; exposed_service owns that case."""
    data = "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.27017: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "inbound"
    assert exposed_service(events[0]) is not None
    assert pcap_rules.suspicious_port(events[0]) is None


def test_exposed_service_inbound_iocs_the_remote_prober_not_the_host():
    data = "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.27017: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    a = exposed_service(events[0])
    assert a is not None
    assert a.iocs["ip"] == ["45.77.12.9"]
    assert "10.0.0.5" not in a.iocs["ip"]


def test_exposed_service_does_not_fire_on_outbound_to_sensitive_port():
    """The monitored host reaching OUT to a remote MongoDB/Redis/Elastic
    service is a different risk (data staged on attacker infra) — must NOT
    be classified as an exposed listening service on our own host."""
    data = "2023-11-14 22:13:20.000000 IP 10.0.0.5.51000 > 45.77.12.9.27017: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert events[0].data["direction"] == "outbound"
    assert exposed_service(events[0]) is None


def test_exposed_service_does_not_fire_on_non_sensitive_inbound_port():
    """Ordinary inbound traffic (e.g. port 8080) is not a sensitive
    database/cache service — must not fire."""
    data = "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.8080: tcp 0\n"
    events = normalize_text(data, monitored_ip="10.0.0.5")
    assert exposed_service(events[0]) is None


def test_exposed_service_fires_on_elasticsearch_and_redis_ports():
    for port in ("9200", "6379"):
        data = f"2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.{port}: tcp 0\n"
        events = normalize_text(data, monitored_ip="10.0.0.5")
        a = exposed_service(events[0])
        assert a is not None, f"expected exposed_service to fire on port {port}"


def test_exposed_service_registered_in_pcap_rule_pack():
    rule_ids = [r.rule_id for r in pcap_module.rules]
    assert "pcap-exposed-service" in rule_ids


def test_exposed_service_dedup_key_collapses_same_target_service():
    """Multiple remote scanners probing the same exposed service on the
    same host must collapse to one finding via a shared dedup_key."""
    data = (
        "2023-11-14 22:13:20.000000 IP 45.77.12.9.51000 > 10.0.0.5.27017: tcp 0\n"
        "2023-11-14 22:13:21.000000 IP 8.8.4.4.51000 > 10.0.0.5.27017: tcp 0\n"
    )
    events = normalize_text(data, monitored_ip="10.0.0.5")
    a1 = exposed_service(events[0])
    a2 = exposed_service(events[1])
    assert a1 is not None and a2 is not None
    assert a1.dedup_key == a2.dedup_key


def test_benign_adobe_ie7_ua_does_not_fire_c2():
    # Adobe Acrobat updater uses a legacy MSIE 7.0 UA by design — outbound,
    # must NOT match any c2_user_agent signature after the tuning.
    ua = ("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; "
          "Trident/7.0; .NET4.0C; .NET4.0E)")
    assert not any(sig.lower() in ua.lower()
                   for sig in pcap_rules._C2_USER_AGENTS)


def test_netsupport_ua_still_fires_c2():
    ua = "NetSupport Manager 12.01"
    assert any(sig.lower() in ua.lower()
               for sig in pcap_rules._C2_USER_AGENTS)


# ── ad_recon_pipe: every pipe open also evidences SMB Admin Shares ─────

def _pipe_event(pipe):
    return NormEvent(
        artifact_type="smb_pipe", timestamp="t0", source_file="ev.pcap",
        record_id="0", host="10.2.28.2",
        data={"src_ip": "10.2.28.88", "dst_ip": "10.2.28.2",
              "named_pipe": pipe, "pipe_normalized": pipe.lower(),
              "direction": "outbound", "raw": pipe},
    )


def test_ad_recon_pipe_netlogon_confidence_below_confirm_threshold():
    """A5 Finding 3 Claim B: netlogon secure-channel traffic (NRPC
    authentication) is automatic, frequent, background traffic on every
    domain-joined Windows host — not evidence of enumeration — unlike
    drsuapi_opnum's opnum-level discrimination, this rule has no way to
    tell a routine machine-account handshake from genuine domain-trust
    recon on a bare pipe-open. Its confidence must stay below the
    CONFIRMED threshold (0.6) until/unless opnum discrimination is added."""
    anchor = ad_recon_pipe(_pipe_event("netlogon"))
    assert anchor is not None
    assert anchor.confidence < 0.6


def test_ad_recon_pipe_does_not_unconditionally_stack_t1021_002():
    """A5 Finding 3 / task 5 fix: a single RPC bind to a named pipe over
    IPC$ (e.g. a SAMR enumeration query) evidences discovery/recon, not
    lateral movement — no remote execution, service creation, or file
    transfer is observed. Unconditionally stacking T1021.002 (SMB/Windows
    Admin Shares, a lateral-movement technique) onto EVERY pipe hit
    overclaimed what the evidence supports; the rule now emits only the
    per-pipe technique it actually justified."""
    anchor = ad_recon_pipe(_pipe_event("samr"))
    assert anchor is not None
    assert anchor.mitre == ["T1087.002"]
    assert "T1021.002" not in anchor.mitre


# ── R1 F4 / W1-B task 3: _AD_RECON_PIPES["drsuapi"] must not claim DCSync ──
#
# `_AD_RECON_PIPES["drsuapi"]` used to tag EVERY drsuapi pipe bind as
# T1003.006 (DCSync) at confidence 0.90, regardless of which drsuapi
# operation (if any) was actually observed. On the 002 capture,
# dce_rpc.log showed only DRSBind/DRSCrackNames/DRSUnbind — zero
# DRSGetNCChanges — yet this rule still made "DCSync" the #1 key finding.
# The sibling smb-drsuapi-opnum rule (drsuapi_opnum(), tested above via
# test_drsuapi_opnum_3_fires_dcsync_class_finding /
# test_drsuapi_opnum_12_fires_name_resolution_recon_lead) already
# discriminates correctly by reading the actual opnum. These tests drive
# ad_recon_pipe() (the pipe-level rule) directly with synthetic
# NormEvents to confirm: (1) a bare bind, with no opnum visible at the
# pipe layer at all, no longer claims T1003.006; (2) when the Zeek
# normalizer HAS resolved a diagnostic opnum onto the same smb_pipe event
# (drsuapi_opnum in {3, 12} -- see zeek_normalize.normalize_zeek_dce_rpc),
# the pipe-level rule defers entirely to smb-drsuapi-opnum instead of
# emitting a second, less-specific finding for the same RPC call.

def _drsuapi_pipe_event(drsuapi_opnum=None):
    data = {"src_ip": "10.2.28.88", "dst_ip": "10.2.28.2",
            "named_pipe": "drsuapi", "pipe_normalized": "drsuapi",
            "direction": "outbound", "raw": "drsuapi"}
    if drsuapi_opnum is not None:
        data["drsuapi_opnum"] = drsuapi_opnum
    return NormEvent(
        artifact_type="smb_pipe", timestamp="t0", source_file="ev.pcap",
        record_id="0", host="10.2.28.2", data=data,
    )


def test_drsuapi_pipe_bind_only_no_opnum_visible_does_not_claim_dcsync():
    """Bind-only: no opnum information reaches the pipe-level rule at all
    (e.g. the tcpdump/tshark fallback path, which has no opnum
    correlation) -- must still fire (it's the only signal available) but
    as a generic, honest lead, never T1003.006."""
    anchor = ad_recon_pipe(_drsuapi_pipe_event())
    assert anchor is not None
    assert anchor.rule_id == "smb-ad-recon-pipe"
    assert "T1003.006" not in anchor.mitre
    assert anchor.mitre == ["T1087.002"]
    assert anchor.confidence < 0.6  # below CONFIRMED threshold on evidence this thin


def test_drsuapi_pipe_with_non_diagnostic_opnum_still_fires_generic_lead():
    """A resolved-but-non-diagnostic opnum (0=DRSBind, 1=DRSUnbind -- the
    only values drsuapi_opnum() itself declines to score, as session
    churn) must NOT be suppressed: no more-specific finding exists for
    it, so the generic pipe-level lead is still the only signal."""
    anchor = ad_recon_pipe(_drsuapi_pipe_event(drsuapi_opnum=0))
    assert anchor is not None
    assert anchor.rule_id == "smb-ad-recon-pipe"
    assert "T1003.006" not in anchor.mitre


def test_drsuapi_pipe_with_getncchanges_opnum_defers_to_opnum_rule():
    """opnum 3 (DsGetNCChanges, DCSync) is diagnostic -- smb-drsuapi-opnum
    already emits the specific, correctly-attributed finding for this
    exact row. The pipe-level rule must return None rather than duplicate
    it with a second, less-specific finding."""
    anchor = ad_recon_pipe(_drsuapi_pipe_event(drsuapi_opnum=3))
    assert anchor is None


def test_drsuapi_pipe_with_namares_opnum_defers_to_opnum_rule():
    """opnum 12 (DsCrackNames) is likewise diagnostic -- same deferral."""
    anchor = ad_recon_pipe(_drsuapi_pipe_event(drsuapi_opnum=12))
    assert anchor is None


# ── Track L: full User-Agent capture + OS derivation (gold gap G2) ─────────

_XLOADER_UA = (
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
    "(KHTML like Gecko) Chrome/35.0.1916.114 Safari/537.36"
)


def test_os_from_ua_maps_nt61_to_win7_with_wow64():
    """NT 6.1 + WOW64 → Windows 7 name, raw NT token, and the WOW64 note."""
    os_str = pcap_rules._os_from_ua(_XLOADER_UA)
    assert "Windows 7" in os_str
    assert "NT 6.1" in os_str
    assert "WOW64" in os_str


def test_os_from_ua_maps_nt100_to_win10():
    os_str = pcap_rules._os_from_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    assert "Windows 10" in os_str
    assert "NT 10.0" in os_str


def test_os_from_ua_empty_when_no_nt_token():
    """A UA with no 'Windows NT x.y' token derives nothing (no fabrication)."""
    assert pcap_rules._os_from_ua("Microsoft-CryptoAPI/10.0") == ""
    assert pcap_rules._os_from_ua("") == ""


def test_c2_protocol_emits_full_ua_and_os_in_summary_not_title():
    """When the UA check fires, the full header + derived OS ride the finding
    summary (corroboration.artifacts), while the title stays short."""
    a = pcap_rules.c2_protocol(_c2_ua_event("www.unitedsharesbank.com", ua=_XLOADER_UA))
    assert a is not None
    assert f"host User-Agent (full): {_XLOADER_UA}" in a.summary
    assert "host OS (from UA): Windows 7" in a.summary
    # Title must not be bloated with the ~90-char header.
    assert "Mozilla/5.0" not in a.title


def test_c2_protocol_omits_os_clause_when_ua_has_no_os_token():
    """UA matches a C2 signature but carries no NT token → full-UA clause is
    present, OS clause is omitted (never fabricated)."""
    a = pcap_rules.c2_protocol(_c2_ua_event("evil.example", ua="Mozilla/5.0 zgrab/0.x"))
    assert a is not None
    assert "host User-Agent (full): Mozilla/5.0 zgrab/0.x" in a.summary
    assert "host OS (from UA):" not in a.summary


_CHECKSUM_INBOUND_BAD = (
    "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 4660, offset 0, "
    "flags [none], proto TCP (6), length 40)\n"
    "    203.0.113.9.51234 > 10.0.0.5.445: Flags [S], "
    "cksum 0x5ee4 (incorrect -> 0xa11b), seq 1000, win 64240, length 0\n"
    "2023-11-14 22:13:20.000001 IP (tos 0x0, ttl 64, id 4660, offset 0, "
    "flags [none], proto TCP (6), length 40)\n"
    "    10.0.0.5.445 > 203.0.113.9.51234: Flags [S], "
    "cksum 0xa11b (correct), seq 1000, win 64240, length 0\n"
)


def test_checksum_integrity_flags_inbound_bad_tcp_checksum_only():
    """Packet 1 is inbound (remote -> monitored host) with a bad TCP
    checksum -> counted. Packet 2 is the monitored host's own correct
    outbound reply -> not counted, and outbound is excluded anyway."""
    events = normalize_checksum_integrity(
        _CHECKSUM_INBOUND_BAD, monitored_ip="10.0.0.5"
    )
    assert len(events) == 1
    assert events[0].artifact_type == "pcap_checksum"
    cd = events[0].data["checksum_data"]
    assert cd["ip"] == "203.0.113.9"
    assert cd["bad_count"] == 1


def test_checksum_integrity_ignores_outbound_bad_checksum():
    """Outbound bad checksums are routine NIC TX-checksum-offload noise —
    must never be counted, even though the string 'incorrect' appears."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    10.0.0.5.51234 > 203.0.113.9.445: Flags [S], "
        "cksum 0x1111 (incorrect -> 0x2222), seq 1000, win 64240, length 0\n"
    )
    events = normalize_checksum_integrity(data, monitored_ip="10.0.0.5")
    assert events == []


def test_checksum_integrity_flags_bad_ip_checksum():
    """A bad IP-header checksum (the 'bad cksum ... !)' marker on the
    header line) counts even when the TCP checksum on the same packet is
    fine."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40, bad cksum 7f82 (->807d)!)\n"
        "    203.0.113.9.51234 > 10.0.0.5.445: Flags [S], "
        "cksum 0xa11b (correct), seq 1000, win 64240, length 0\n"
    )
    events = normalize_checksum_integrity(data, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["checksum_data"]["bad_count"] == 1


def test_checksum_integrity_no_findings_on_all_correct():
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51234 > 10.0.0.5.445: Flags [S], "
        "cksum 0xa11b (correct), seq 1000, win 64240, length 0\n"
    )
    assert normalize_checksum_integrity(data, monitored_ip="10.0.0.5") == []


def test_checksum_integrity_aggregates_multiple_bad_packets_same_ip():
    data = _CHECKSUM_INBOUND_BAD + (
        "2023-11-14 22:13:21.000000 IP (tos 0x0, ttl 64, id 2, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51235 > 10.0.0.5.445: Flags [S], "
        "cksum 0x5ee5 (incorrect -> 0xa11c), seq 1000, win 64240, length 0\n"
    )
    events = normalize_checksum_integrity(data, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["checksum_data"]["bad_count"] == 2


def test_checksum_integrity_ignores_truncated_trailing_header():
    """A header line with nothing following it (truncated input) must not
    crash — the trailing bare header line has no paired detail line."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
    )
    assert normalize_checksum_integrity(data, monitored_ip="10.0.0.5") == []


def test_checksum_integrity_direction_fallback_without_monitored_ip():
    """Without monitored_ip, direction falls back to the private/public
    heuristic: a bad-checksum packet from a public src to a private dst
    is inbound and must be counted."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51234 > 10.0.0.5.445: Flags [S], "
        "cksum 0x5ee4 (incorrect -> 0xa11b), seq 1000, win 64240, length 0\n"
    )
    events = normalize_checksum_integrity(data)  # no monitored_ip passed
    assert len(events) == 1
    assert events[0].data["checksum_data"]["ip"] == "203.0.113.9"


def test_checksum_integrity_skips_non_header_garbage_lines():
    """A stray line that doesn't match the header regex, appearing before
    a valid record, must be skipped (not crash, not misparsed)."""
    data = (
        "garbage line that is not a tcpdump header\n"
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51234 > 10.0.0.5.445: Flags [S], "
        "cksum 0x5ee4 (incorrect -> 0xa11b), seq 1000, win 64240, length 0\n"
    )
    events = normalize_checksum_integrity(data, monitored_ip="10.0.0.5")
    assert len(events) == 1
    assert events[0].data["checksum_data"]["bad_count"] == 1


def test_checksum_integrity_skips_header_with_unparseable_detail_line():
    """A valid header line followed by a line that does NOT match the
    src.port > dst.port detail pattern must be skipped, not crash."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40, bad cksum 7f82 (->807d)!)\n"
        "    not a src.port > dst.port line at all\n"
    )
    assert normalize_checksum_integrity(data, monitored_ip="10.0.0.5") == []


def test_checksum_integrity_direction_unknown_when_monitored_ip_matches_neither():
    """monitored_ip is set, but neither src nor dst matches it -> direction
    is 'unknown', not inbound, so the bad checksum must not be counted."""
    data = (
        "2023-11-14 22:13:20.000000 IP (tos 0x0, ttl 64, id 1, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51234 > 198.51.100.7.445: Flags [S], "
        "cksum 0x5ee4 (incorrect -> 0xa11b), seq 1000, win 64240, length 0\n"
    )
    assert normalize_checksum_integrity(data, monitored_ip="10.0.0.5") == []


# ── evidence_tampered: post-capture tampering detection (Task 3) ────────

from spectre.modules.pcap.rules import evidence_tampered


def test_evidence_tampered_fires_on_inbound_bad_checksum():
    events = normalize_checksum_integrity(
        _CHECKSUM_INBOUND_BAD, monitored_ip="10.0.0.5"
    )
    anchors = _detect(events)
    assert len(anchors) == 1
    assert anchors[0].rule_id == "pcap-evidence-tampered"
    assert anchors[0].mitre == []
    assert "203.0.113.9" in anchors[0].title
    assert anchors[0].dedup_key == "cksum:203.0.113.9"


def test_evidence_tampered_no_finding_without_checksum_data():
    e = NormEvent(
        artifact_type="pcap_checksum", timestamp="", source_file="",
        record_id="1", data={},
    )
    assert evidence_tampered(e) is None


def test_evidence_tampered_confidence_scales_with_bad_count():
    one = normalize_checksum_integrity(_CHECKSUM_INBOUND_BAD, monitored_ip="10.0.0.5")
    two_text = _CHECKSUM_INBOUND_BAD + (
        "2023-11-14 22:13:21.000000 IP (tos 0x0, ttl 64, id 2, offset 0, "
        "flags [none], proto TCP (6), length 40)\n"
        "    203.0.113.9.51235 > 10.0.0.5.445: Flags [S], "
        "cksum 0x5ee5 (incorrect -> 0xa11c), seq 1000, win 64240, length 0\n"
    )
    two = normalize_checksum_integrity(two_text, monitored_ip="10.0.0.5")
    conf_one = evidence_tampered(one[0]).confidence
    conf_two = evidence_tampered(two[0]).confidence
    assert conf_two > conf_one


def test_evidence_tampered_no_finding_with_zero_bad_count():
    """Defensive guard: checksum_data exists but bad_count is 0 must return None."""
    e = NormEvent(
        artifact_type="pcap_checksum", timestamp="", source_file="",
        record_id="1", data={"checksum_data": {"ip": "203.0.113.9", "bad_count": 0}},
    )
    assert evidence_tampered(e) is None


# ── Robust beacon scorer (replaces the clean-interval allowlist) ───────
# The old _beacon_confidence gated on {30,60,120,180,300,600,900,1800,3600}
# with a +/-5s ABSOLUTE tolerance. Measured against
# ~/spectre-cases/samples/2026-01-15-XLoader-infection.pcap it produced ZERO
# findings on a live infection carrying 285 C2 requests. These lock the
# behaviour that fixed it. See modules/pcap/beacon_score.py.

@pytest.mark.parametrize("period,label", [
    (206.0, "XLoader real C2 period"),
    (45.0, "not on the old allowlist"),
    (90.0, "not on the old allowlist"),
    (7200.0, "2h, beyond the old allowlist"),
])
def test_beacon_fires_on_periods_the_old_allowlist_rejected(period, label):
    a = beacon(_beacon_event("45.77.12.9", [period] * 15))
    assert a is not None, f"{label}: {period}s beacon must fire"
    assert a.rule_id == "pcap-beacon"


def test_beacon_fires_on_cobalt_strike_default_jitter():
    """`sleep 60 jitter 37` -> one-sided uniform over [37.8, 60]: mean ~48.9s,
    which sits 11.1s off the nearest allowlist entry (60) and so scored
    exactly 0.0 under the old gate."""
    import random
    rng = random.Random(42)
    intervals = [60 * (1 - rng.uniform(0, 0.37)) for _ in range(40)]
    a = beacon(_beacon_event("45.77.12.9", intervals))
    assert a is not None
    assert a.confidence >= 0.6


def test_beacon_survives_outliers_that_inflate_stdev_beyond_mean():
    """Regression for the removed `stdev > mean_interval` guard, which
    rejected 6 of the 7 genuine XLoader beacons. This is the real interval
    series for 151.243.184.14 (www.m0d2ap.info, POST /yiti/): sigma 128.2
    against mu 101.1, but a MAD of 0.03 around a 2.6s median."""
    intervals = ([2.6] * 8 + [484.8] + [2.6] * 8 + [36.0] + [2.6] * 8
                 + [280.5, 205.3, 224.2])
    import statistics
    assert statistics.stdev(intervals) > statistics.mean(intervals)  # old guard tripped
    a = beacon(_beacon_event("151.243.184.14", intervals))
    assert a is not None
    assert a.confidence >= 0.9


def test_beacon_rejects_random_exponential_traffic():
    """The false-positive side: Poisson arrivals must not score."""
    import random
    rng = random.Random(1337)
    intervals = [rng.expovariate(1 / 60.0) for _ in range(200)]
    assert beacon(_beacon_event("45.77.12.9", intervals)) is None


def test_beacon_summary_records_scorer_version_and_inputs():
    """A confidence value must be reproducible: the finding carries the
    scorer identity and every input it was derived from (reaches the finding
    as corroboration_note). Without this, changing the scorer silently
    changes what an already-issued report would produce."""
    a = beacon(_beacon_event("45.77.12.9", [60.0] * 12))
    assert a is not None
    assert "scorer=robust-mad-1" in a.summary
    for token in ("median=", "MAD=", "rCV="):
        assert token in a.summary


if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
