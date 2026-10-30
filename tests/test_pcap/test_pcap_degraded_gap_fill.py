"""A10 Finding 3 regression: when tcpdump (the tool behind the Zeek
engine's optional HTTP-ASCII-payload / checksum-tamper gap-fill passes) is
unavailable or fails, Zeek's own already-successful extraction must
survive -- not be discarded by an uncaught exception from the *same*
extract() call.

Before the fix: extract()'s zeek branch called `_pass_http` /
`_pass_checksum` unguarded; a FileNotFoundError from either one propagated
out of extract() entirely, so the 3 already-built Zeek handles (conn/dns/
http logs) were never returned to the caller and Phase 2 produced zero
handles, zero findings, zero reports.
"""
import importlib

extmod = importlib.import_module("spectre.modules.pcap.extract")


def _fake_zeek_handles(case_dir, evidence_path):
    return [
        {"evidence_path": evidence_path, "artifact_type": "pcap_conn",
         "extract_pass": "zeek_conn", "tool": "zeek:conn.log",
         "tool_version": "zeek-8.0.9", "path": "/tmp/conn.log",
         "line_count": 5, "size_bytes": 500, "empty_data_status": "DATA_PRESENT",
         "result": "success"},
        {"evidence_path": evidence_path, "artifact_type": "pcap_dns",
         "extract_pass": "zeek_dns", "tool": "zeek:dns.log",
         "tool_version": "zeek-8.0.9", "path": "/tmp/dns.log",
         "line_count": 3, "size_bytes": 300, "empty_data_status": "DATA_PRESENT",
         "result": "success"},
        {"evidence_path": evidence_path, "artifact_type": "pcap_http",
         "extract_pass": "zeek_http", "tool": "zeek:http.log",
         "tool_version": "zeek-8.0.9", "path": "/tmp/http.log",
         "line_count": 2, "size_bytes": 200, "empty_data_status": "DATA_PRESENT",
         "result": "success"},
    ]


def _raise_missing_tcpdump(*args, **kwargs):
    raise FileNotFoundError("[Errno 2] No such file or directory: 'tcpdump'")


def test_missing_tcpdump_does_not_discard_zeek_handles(tmp_path, monkeypatch):
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "zeek")
    monkeypatch.setattr(extmod.zeek, "extract", _fake_zeek_handles)
    monkeypatch.setattr(extmod, "run_tool", _raise_missing_tcpdump)

    handles = extmod.extract(str(tmp_path), "evidence/case.pcap")

    zeek_handles = [h for h in handles if h.get("extract_pass", "").startswith("zeek_")]
    assert len(zeek_handles) == 3, "Zeek's successful handles were discarded"

    skipped = [h for h in handles if h.get("result") == "skipped_tool_unavailable"]
    assert len(skipped) == 2, f"expected 2 skipped gap-fill passes, got {skipped}"
    skipped_passes = {h["extract_pass"] for h in skipped}
    assert skipped_passes == {"http", "checksum"}
    for h in skipped:
        assert "tcpdump" in h.get("skip_reason", "")
        assert h.get("path") in ("", None)
        # required keys for downstream code that indexes without .get()
        assert h["line_count"] == 0
        assert h["size_bytes"] == 0


def test_missing_tcpdump_marker_normalizes_to_no_events(tmp_path, monkeypatch):
    from spectre.modules.pcap.normalize import normalize as pcap_normalize
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "zeek")
    monkeypatch.setattr(extmod.zeek, "extract", _fake_zeek_handles)
    monkeypatch.setattr(extmod, "run_tool", _raise_missing_tcpdump)

    handles = extmod.extract(str(tmp_path), "evidence/case.pcap")
    skipped = [h for h in handles if h.get("result") == "skipped_tool_unavailable"]
    assert skipped
    for h in skipped:
        assert pcap_normalize(h) == []


def test_zeek_run_failure_plus_missing_tcpdump_still_returns_without_raising(tmp_path, monkeypatch):
    """Even when Zeek's own run also failed (e.g. corrupted capture), the
    gap-fill passes must not additionally crash extract() outright."""
    def _fail_run_handle(case_dir, evidence_path):
        return [{"result": "error", "artifact_type": "zeek_run",
                 "extract_pass": "zeek_run", "tool": "zeek",
                 "evidence_path": evidence_path, "path": "", "line_count": 0,
                 "size_bytes": 0}]

    monkeypatch.setattr(extmod, "PCAP_ENGINE", "zeek")
    monkeypatch.setattr(extmod.zeek, "extract", _fail_run_handle)
    monkeypatch.setattr(extmod, "run_tool", _raise_missing_tcpdump)

    handles = extmod.extract(str(tmp_path), "evidence/case.pcap")
    assert any(h.get("result") == "error" for h in handles)
    assert any(h.get("result") == "skipped_tool_unavailable" for h in handles)
