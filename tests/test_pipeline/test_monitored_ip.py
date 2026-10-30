"""Monitored-host detection: distinct-peer-count, not packet-count.

Regression for the gold-001 failure where a 1.5 MB download from a staging
server dominated the packet-count vote and the staging server (one peer) was
misidentified as the monitored host — flipping flow direction and stamping
the wrong host_ip on every finding.
"""
import json

from spectre.pipeline.phase_runner import _detect_monitored_ip, _detect_monitored_ip_zeek


def _line(ts, src, sport, dst, dport):
    return f"{ts} IP {src}.{sport} > {dst}.{dport}: tcp 100"


def test_empty_input_returns_empty():
    assert _detect_monitored_ip("") == ""
    assert _detect_monitored_ip("garbage\nno ip lines here") == ""


def test_internal_victim_beats_high_volume_download_peer():
    # Victim 10.1.13.175 reaches 3 distinct C2 servers (few packets each);
    # a staging server 108.181.20.35 sends the victim a huge download (many
    # packets, ONE peer). Distinct-peer-count must pick the victim.
    lines = []
    for dst in ("23.1.1.1", "45.2.2.2", "67.3.3.3"):
        lines.append(_line("t", "10.1.13.175", "49001", dst, "443"))
    # 500 download packets from the staging server to the victim
    for _ in range(500):
        lines.append(_line("t", "108.181.20.35", "443", "10.1.13.175", "49500"))
    got = _detect_monitored_ip("\n".join(lines))
    assert got == "10.1.13.175", got


def test_public_web_server_victim_is_detected():
    # A public-IP web server contacted by many distinct scanners is the
    # monitored host even though it has no private address.
    lines = [_line("t", f"9.9.{i}.{i}", "50000", "203.161.44.208", "80")
             for i in range(1, 40)]
    assert _detect_monitored_ip("\n".join(lines)) == "203.161.44.208"


def test_rfc1918_tiebreak():
    # Two hosts each with the same distinct-peer count: the private one wins.
    lines = [
        _line("t", "10.0.0.5", "40000", "8.8.8.8", "53"),
        _line("t", "10.0.0.5", "40001", "1.1.1.1", "53"),
        _line("t", "203.0.113.9", "40002", "8.8.8.8", "53"),
        _line("t", "203.0.113.9", "40003", "1.1.1.1", "53"),
    ]
    # 10.0.0.5 and 203.0.113.9 both have 2 peers; private wins the tiebreak.
    assert _detect_monitored_ip("\n".join(lines)) == "10.0.0.5"


# ── Zeek conn.log (JSON lines) variant — A10 Finding 2 ────────────────────
# Under the Zeek engine there is no tcpdump "connections" pass; the
# equivalent signal is Zeek's own structured conn.log. Same distinct-peer
# algorithm, different (JSON) grammar.

def _zeek_row(ts, orig_h, orig_p, resp_h, resp_p, orig_pkts=1, resp_pkts=1):
    return json.dumps({
        "ts": ts, "uid": f"C{ts}",
        "id.orig_h": orig_h, "id.orig_p": orig_p,
        "id.resp_h": resp_h, "id.resp_p": resp_p,
        "proto": "tcp", "orig_pkts": orig_pkts, "resp_pkts": resp_pkts,
    })


def test_zeek_empty_input_returns_empty():
    assert _detect_monitored_ip_zeek("") == ""
    assert _detect_monitored_ip_zeek("not json\n{not json either") == ""


def test_zeek_internal_victim_beats_high_volume_download_peer():
    lines = [_zeek_row(1000 + i, "10.1.13.175", 49000 + i, dst, 443)
             for i, dst in enumerate(("23.1.1.1", "45.2.2.2", "67.3.3.3"))]
    # staging server: one peer, 500 packets -- must not win the vote.
    lines.append(_zeek_row(2000, "108.181.20.35", 443, "10.1.13.175", 49500,
                            orig_pkts=500, resp_pkts=500))
    got = _detect_monitored_ip_zeek("\n".join(lines))
    assert got == "10.1.13.175", got


def test_zeek_public_web_server_victim_is_detected():
    lines = [_zeek_row(t, f"9.9.{t}.{t}", 50000, "203.161.44.208", 80)
             for t in range(1, 40)]
    assert _detect_monitored_ip_zeek("\n".join(lines)) == "203.161.44.208"


def test_zeek_rfc1918_tiebreak():
    lines = [
        _zeek_row(1, "10.0.0.5", 40000, "8.8.8.8", 53),
        _zeek_row(2, "10.0.0.5", 40001, "1.1.1.1", 53),
        _zeek_row(3, "203.0.113.9", 40002, "8.8.8.8", 53),
        _zeek_row(4, "203.0.113.9", 40003, "1.1.1.1", 53),
    ]
    assert _detect_monitored_ip_zeek("\n".join(lines)) == "10.0.0.5"


def test_zeek_skips_malformed_and_non_dict_lines():
    lines = [
        "not json",
        json.dumps(["a", "list", "not", "a", "dict"]),
        _zeek_row(1, "10.0.0.5", 40000, "8.8.8.8", 53),
    ]
    assert _detect_monitored_ip_zeek("\n".join(lines)) == "10.0.0.5"
