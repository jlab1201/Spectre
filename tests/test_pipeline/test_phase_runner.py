"""Tests for capture-scale metadata plumbing in phase_runner.py (Track E3 Task 1).

These are deterministic capture-metadata helpers — distinct counts of what
was captured, never findings, confidence, or verdict language.
"""
from spectre.pipeline.phase_runner import _conn_distinct_counts, _persist_capture_scale


def test_conn_distinct_counts_counts_src_ips_and_dst_ports():
    conn = (
        "10:00:00.1 IP 1.1.1.1.5555 > 9.9.9.9.80: tcp 0\n"
        "10:00:00.2 IP 2.2.2.2.6666 > 9.9.9.9.443: tcp 0\n"
        "10:00:00.3 IP 1.1.1.1.7777 > 9.9.9.9.80: tcp 0\n"   # dup src, dup port
        "10:00:00.4 IP 3.3.3.3.8888 > 9.9.9.9.22: tcp 0\n"
    )
    src, ports = _conn_distinct_counts(conn)
    assert src == 3          # 1.1.1.1, 2.2.2.2, 3.3.3.3
    assert ports == 3        # 80, 443, 22


def test_conn_distinct_counts_empty():
    assert _conn_distinct_counts("") == (0, 0)
    assert _conn_distinct_counts("garbage line with no IP token") == (0, 0)


def test_persist_capture_scale_populates_manifest():
    manifest = {
        "evidence_metadata": {
            "/ev/x.pcap": {
                "type": "pcap_conn",
                "total_packets": 313954,
                "file_size_bytes": 52696108,
                "capture_duration_seconds": 604766.33,
            }
        }
    }
    conn = ("10:00:00.1 IP 1.1.1.1.5 > 9.9.9.9.80: tcp 0\n"
            "10:00:00.2 IP 2.2.2.2.6 > 9.9.9.9.443: tcp 0\n")
    _persist_capture_scale(manifest, conn, monitored_ip="9.9.9.9")
    assert manifest["monitored_ip"] == "9.9.9.9"
    cs = manifest["capture_scale"]
    assert cs["total_packets"] == 313954
    assert cs["file_size_bytes"] == 52696108
    assert cs["capture_duration_seconds"] == 604766.33
    assert cs["distinct_src_ips"] == 2
    assert cs["distinct_dst_ports"] == 2


def test_persist_capture_scale_no_metadata_still_writes_counts():
    manifest = {}
    conn = "10:00:00.1 IP 1.1.1.1.5 > 9.9.9.9.80: tcp 0\n"
    _persist_capture_scale(manifest, conn, monitored_ip="")
    # monitored_ip empty -> not persisted; counts still recorded
    assert "monitored_ip" not in manifest
    assert manifest["capture_scale"]["distinct_src_ips"] == 1
    assert manifest["capture_scale"]["distinct_dst_ports"] == 1
    assert "total_packets" not in manifest["capture_scale"]


def test_persist_capture_scale_merges_across_multi_evidence_iterations():
    """Regression: a multi-evidence case (e.g. memory + pcap) calls
    _persist_capture_scale once per evidence file in the Phase 2 loop. The
    pcap iteration records distinct_src_ips/distinct_dst_ports; a LATER
    non-pcap iteration (empty conn_text, empty monitored_ip) must never wipe
    those counts by rebuilding capture_scale from scratch."""
    manifest = {
        "evidence_metadata": {
            "/ev/x.pcap": {
                "type": "pcap_conn",
                "total_packets": 313954,
                "file_size_bytes": 52696108,
                "capture_duration_seconds": 604766.33,
            }
        }
    }
    pcap_conn = ("10:00:00.1 IP 1.1.1.1.5 > 9.9.9.9.80: tcp 0\n"
                 "10:00:00.2 IP 2.2.2.2.6 > 9.9.9.9.443: tcp 0\n")
    # First iteration: pcap evidence, records distinct counts.
    _persist_capture_scale(manifest, pcap_conn, monitored_ip="9.9.9.9")
    assert manifest["capture_scale"]["distinct_src_ips"] == 2
    assert manifest["capture_scale"]["distinct_dst_ports"] == 2

    # Second iteration: later non-pcap evidence (e.g. memory image) — no
    # connections text, no monitored IP detected from this file.
    _persist_capture_scale(manifest, "", monitored_ip="")

    # The counts recorded by the pcap iteration must survive.
    cs = manifest["capture_scale"]
    assert cs["distinct_src_ips"] == 2
    assert cs["distinct_dst_ports"] == 2
    assert cs["total_packets"] == 313954
    assert cs["file_size_bytes"] == 52696108
    assert cs["capture_duration_seconds"] == 604766.33
    # monitored_ip previously set must not be clobbered by an empty value.
    assert manifest["monitored_ip"] == "9.9.9.9"
