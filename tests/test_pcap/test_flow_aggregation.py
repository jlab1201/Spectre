"""test_flow_aggregation.py — flow aggregation, DNS answer parsing, and the
staging-download / large-transfer detection rules built on top of pcap_flow
events (Track C Task 6).
"""

from spectre.modules.pcap import PCAP_MODULE as pcap_module
from spectre.modules.pcap.enrich import enrich_events
from spectre.modules.pcap.normalize import normalize_dns, normalize_flows, normalize_text

MONITORED_IP = "10.0.0.5"

# ── Flow 1: catbox.moe staging download — 1.5MB inbound, small outbound ──
_STAGING_FLOW = (
    "2026-01-15 22:19:45.100 IP 10.0.0.5.49723 > 108.181.20.35.443: "
    "Flags [P.], seq 1:200, ack 1, win 502, length 200\n"
    "2026-01-15 22:19:45.300 IP 108.181.20.35.443 > 10.0.0.5.49723: "
    "Flags [P.], seq 1:700001, ack 200, win 502, length 700000\n"
    "2026-01-15 22:19:45.600 IP 108.181.20.35.443 > 10.0.0.5.49723: "
    "Flags [P.], seq 700001:1500001, ack 200, win 502, length 800000\n"
)

# ── Flow 2: unmapped 9.6MB secondary-C2 transfer to 23.205.110.9 ──
_LARGE_TRANSFER_FLOW = (
    "2026-01-15 22:20:10.000 IP 10.0.0.5.49800 > 23.205.110.9.443: "
    "Flags [P.], seq 1:200000, ack 1, win 502, length 200000\n"
    "2026-01-15 22:20:15.000 IP 23.205.110.9.443 > 10.0.0.5.49800: "
    "Flags [P.], seq 1:9400001, ack 200000, win 502, length 9400000\n"
)

_TWO_FLOWS = _STAGING_FLOW + _LARGE_TRANSFER_FLOW

_DNS_TEXT = (
    "2026-01-15 22:19:44.000000 IP 10.0.0.5.51000 > 8.8.8.8.53: "
    "43981+ A? files.catbox.moe. (32)\n"
    "2026-01-15 22:19:44.050000 IP 8.8.8.8.53 > 10.0.0.5.51000: "
    "43981 1/0/0 A 108.181.20.35 (48)\n"
)


def _flow_events(text=_TWO_FLOWS, monitored_ip=MONITORED_IP):
    return normalize_text(text, monitored_ip=monitored_ip) + normalize_flows(
        text, monitored_ip=monitored_ip
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


# ── Flow aggregation: orientation, no-monitored-ip guard ──────────────

def test_no_monitored_ip_emits_no_flow_events():
    events = _flow_events(monitored_ip="")
    flows = [e for e in events if e.artifact_type == "pcap_flow"]
    assert flows == []


def test_flow_orientation_bytes_in_out_per_monitored_ip():
    events = _flow_events(_STAGING_FLOW)
    flows = [e for e in events if e.artifact_type == "pcap_flow"]
    assert len(flows) == 1
    f = flows[0]
    assert f.data["remote_ip"] == "108.181.20.35"
    assert f.data["remote_port"] == "443"
    assert f.data["bytes_out"] == 200
    assert f.data["bytes_in"] == 700000 + 800000
    assert f.data["packets"] == 3
    assert f.host == MONITORED_IP


def test_flow_direction_ratio_and_two_distinct_remote_flows():
    events = _flow_events(_TWO_FLOWS)
    flows = {e.data["remote_ip"]: e for e in events if e.artifact_type == "pcap_flow"}
    assert set(flows) == {"108.181.20.35", "23.205.110.9"}

    staging = flows["108.181.20.35"]
    assert staging.data["direction_ratio"] == 1500000 / 200

    large = flows["23.205.110.9"]
    assert large.data["bytes_in"] == 9400000
    assert large.data["bytes_out"] == 200000


# ── DNS answer parsing ─────────────────────────────────────────────────

def test_dns_answers_parsed_onto_response_event():
    events = normalize_dns(_DNS_TEXT, monitored_ip=MONITORED_IP)
    responses = [e for e in events if e.data.get("answers")]
    assert len(responses) == 1
    assert responses[0].data["answers"] == ["108.181.20.35"]
    # query name carried on the response event too (id-matched)
    assert responses[0].data["dns_query"] == "files.catbox.moe"

    queries = [e for e in events if not e.data.get("answers")]
    assert len(queries) == 1
    assert queries[0].data["dns_query"] == "files.catbox.moe"


# ── enrich.py: resolved_domain stamping ─────────────────────────────────

def test_enrich_stamps_resolved_domain_onto_matching_flow():
    dns_events = normalize_dns(_DNS_TEXT, monitored_ip=MONITORED_IP)
    flow_events = _flow_events(_TWO_FLOWS)
    all_events = dns_events + flow_events
    enrich_events(all_events)

    flows = {e.data["remote_ip"]: e for e in all_events if e.artifact_type == "pcap_flow"}
    assert flows["108.181.20.35"].data["resolved_domain"] == "files.catbox.moe"
    # unmapped IP must not get a resolved_domain stamped
    assert "resolved_domain" not in flows["23.205.110.9"].data


# ── Rule: pcap-staging-download ─────────────────────────────────────────

def test_staging_download_fires_with_domain_and_ip_iocs():
    dns_events = normalize_dns(_DNS_TEXT, monitored_ip=MONITORED_IP)
    flow_events = _flow_events(_TWO_FLOWS)
    all_events = dns_events + flow_events
    enrich_events(all_events)

    anchors = _detect(all_events)
    staging = [a for a in anchors if a.rule_id == "pcap-staging-download"]
    assert len(staging) == 1
    a = staging[0]
    assert a.mitre == ["T1105"]
    assert a.iocs["ip"] == ["108.181.20.35"]
    assert a.iocs["domain"] == ["files.catbox.moe"]
    assert "files.catbox.moe" in a.title
    assert "108.181.20.35" in a.title


def test_staging_download_does_not_fire_without_domain_resolution():
    # The 9.6MB flow's remote IP is never DNS-resolved in this fixture.
    flow_events = _flow_events(_LARGE_TRANSFER_FLOW)
    anchors = _detect(flow_events)
    staging = [a for a in anchors if a.rule_id == "pcap-staging-download"]
    assert staging == []


# ── Rule: pcap-large-transfer ────────────────────────────────────────────

def test_large_transfer_fires_on_unmapped_9_6mb_flow_and_staging_does_not():
    flow_events = _flow_events(_LARGE_TRANSFER_FLOW)
    anchors = _detect(flow_events)

    large = [a for a in anchors if a.rule_id == "pcap-large-transfer"]
    staging = [a for a in anchors if a.rule_id == "pcap-staging-download"]
    assert len(large) == 1
    assert staging == []

    a = large[0]
    # bytes_in (9.4M) > bytes_out (0.2M) -> inbound-dominant -> T1105
    assert a.mitre == ["T1105"]
    assert a.iocs["ip"] == ["23.205.110.9"]
    assert a.dedup_key == "23.205.110.9"


def test_large_transfer_outbound_dominant_maps_to_t1041():
    text = (
        "2026-01-15 22:21:00.000 IP 10.0.0.5.49900 > 198.51.100.7.443: "
        "Flags [P.], seq 1:6000000, ack 1, win 502, length 6000000\n"
        "2026-01-15 22:21:05.000 IP 198.51.100.7.443 > 10.0.0.5.49900: "
        "Flags [P.], seq 1:1000, ack 6000000, win 502, length 1000\n"
    )
    events = _flow_events(text)
    anchors = _detect(events)
    large = [a for a in anchors if a.rule_id == "pcap-large-transfer"]
    assert len(large) == 1
    assert large[0].mitre == ["T1041"]


def test_large_transfer_below_threshold_does_not_fire():
    events = _flow_events(_STAGING_FLOW)  # totals 1.5MB, below 5MB
    anchors = _detect(events)
    large = [a for a in anchors if a.rule_id == "pcap-large-transfer"]
    assert large == []


# ── Lines without a parseable length count packets only ─────────────────

def test_line_without_length_counts_packet_but_no_bytes():
    text = (
        "2026-01-15 22:22:00.000 IP 10.0.0.5.50000 > 203.0.113.5.22: "
        "Flags [S], seq 0, win 502\n"
    )
    events = _flow_events(text)
    flows = [e for e in events if e.artifact_type == "pcap_flow"]
    assert len(flows) == 1
    assert flows[0].data["packets"] == 1
    assert flows[0].data["bytes_out"] == 0
    assert flows[0].data["bytes_in"] == 0


# ── Real extractor output (Finding 1, CRITICAL) ──────────────────────────
#
# extract.py's connections pass runs `tcpdump -nn -tttt -q -r <pcap>` — WITH
# -q. In that mode tcpdump never prints the verbose "length N" field; it
# prints "tcp N" for TCP and "UDP, length N" for UDP. The fixtures above are
# all hand-written in the verbose format, which the real extractor never
# emits — they cannot catch a normalizer that only understands "length N".
# These fixtures are built in tcpdump's actual -q format.

def _build_real_q_staging_download(n_lines=1050, bytes_per_line=1448):
    """~1050 lines of real `tcpdump -q` TCP output, remote -> monitored
    host, totalling >= 1.5MB of bytes_in. Modeled on a catbox.moe download:
    a TCP handshake (tcp 0 control packets) followed by n_lines of payload
    from the remote server back to the monitored host."""
    lines = [
        "2026-01-15 22:19:45.000000 IP 10.0.0.5.49723 > 108.181.20.35.443: tcp 0",
        "2026-01-15 22:19:45.050000 IP 108.181.20.35.443 > 10.0.0.5.49723: tcp 0",
        "2026-01-15 22:19:45.100000 IP 10.0.0.5.49723 > 108.181.20.35.443: tcp 0",
    ]
    for i in range(n_lines):
        ts = f"2026-01-15 22:19:{45 + (i // 1000):02d}.{(i % 1000) * 1000:06d}"
        lines.append(
            f"{ts} IP 108.181.20.35.443 > 10.0.0.5.49723: tcp {bytes_per_line}"
        )
    lines.append(
        "2026-01-15 22:19:59.999000 IP 10.0.0.5.49723 > 108.181.20.35.443: tcp 0"
    )
    return "\n".join(lines) + "\n"


_REAL_Q_STAGING_TEXT = _build_real_q_staging_download()


def test_real_q_format_tcp_n_bytes_counted_as_bytes_in():
    """Proves the crux of Finding 1: fed the actual `tcpdump -q` 'tcp N'
    format (not the hand-written 'length N' fixtures), bytes_in must
    reflect the real payload volume, not 0."""
    events = _flow_events(_REAL_Q_STAGING_TEXT)
    flows = [e for e in events if e.artifact_type == "pcap_flow"]
    assert len(flows) == 1
    f = flows[0]
    assert f.data["bytes_in"] >= 1_500_000
    assert f.data["packets"] == 1050 + 4  # payload lines + 4 tcp-0 control packets


def test_real_q_format_staging_download_rule_fires():
    """End-to-end: real -q flow text + DNS resolution to a paste-share
    domain must fire pcap-staging-download — the headline gold-001 rule
    that Finding 1 reported as permanently dead on real evidence."""
    dns_events = normalize_dns(_DNS_TEXT, monitored_ip=MONITORED_IP)
    flow_events = _flow_events(_REAL_Q_STAGING_TEXT)
    all_events = dns_events + flow_events
    enrich_events(all_events)

    anchors = _detect(all_events)
    staging = [a for a in anchors if a.rule_id == "pcap-staging-download"]
    assert len(staging) == 1
    assert staging[0].iocs["ip"] == ["108.181.20.35"]
    assert staging[0].iocs["domain"] == ["files.catbox.moe"]


def test_real_q_format_udp_length_bytes_counted():
    """`UDP, length N` (the -q UDP form) must also be counted."""
    text = (
        "2026-01-15 22:19:45.000000 IP 10.0.0.5.53000 > 1.2.3.4.9999: "
        "UDP, length 100\n"
    )
    events = _flow_events(text)
    flows = [e for e in events if e.artifact_type == "pcap_flow"]
    assert len(flows) == 1
    assert flows[0].data["bytes_out"] == 100
