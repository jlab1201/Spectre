"""test_zeek_extract.py — engine selection + end-to-end Zeek/manual parity.

The unit tests (no external tools) cover the engine selector and verify()
routing. The integration test runs the REAL pipeline (Zeek + tcpdump) on a
sample capture and asserts the Zeek engine reproduces the manual engine's
key detections — the core parity guarantee of the migration. It is
skip-guarded on tool + fixture availability so CI without Zeek/samples
stays green.
"""

import importlib
import os
import shutil
from pathlib import Path

import pytest

from spectre.modules.pcap import PCAP_MODULE as pcap_module
from spectre.modules.pcap import zeek

extmod = importlib.import_module("spectre.modules.pcap.extract")


# ── Unit: engine selector + verify routing (no tools needed) ──────────
def test_manual_engine_forced(monkeypatch):
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "manual")
    assert extmod._resolve_engine() == "manual"


def test_auto_falls_back_when_zeek_absent(monkeypatch):
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(extmod.zeek, "available", lambda: False)
    assert extmod._resolve_engine() == "manual"


def test_auto_prefers_zeek_when_present(monkeypatch):
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(extmod.zeek, "available", lambda: True)
    assert extmod._resolve_engine() == "zeek"


def test_verify_routes_by_artifact_type():
    assert extmod._VERIFY_PASSES["pcap_dns"] == [extmod._pass_dns]
    # host_identity is produced by two manual passes (kerberos + dhcp)
    assert len(extmod._VERIFY_PASSES["host_identity"]) == 2


# ── Integration: real Zeek vs manual parity on a sample capture ───────
def _find_sample() -> str | None:
    env = os.environ.get("SPECTRE_TEST_PCAP")
    if env and Path(env).is_file():
        return env
    samples = Path.home() / "spectre-cases" / "samples"
    if samples.is_dir():
        for p in sorted(samples.glob("*.pcap")):
            if "XLoader" in p.name:  # known plaintext-C2 capture
                return str(p)
        pcaps = sorted(samples.glob("*.pcap"))
        if pcaps:
            return str(pcaps[0])
    return None


_SAMPLE = _find_sample()
_TOOLS = zeek.available() and shutil.which("tcpdump")


def _normalize_all(handles, monitored_ip):
    events = []
    for h in handles:
        h["monitored_ip"] = monitored_ip
        events.extend(pcap_module.normalize(h))
    if pcap_module.enrich:
        pcap_module.enrich(events)
    return events


def _anchors(events):
    out = set()
    for e in events:
        for r in pcap_module.rules:
            if r.artifact_type != e.artifact_type:
                continue
            a = r.predicate(e)
            if a:
                out.add((a.rule_id, a.dedup_key))
    return out


@pytest.mark.skipif(not (_SAMPLE and _TOOLS),
                    reason="needs Zeek + tcpdump + a sample .pcap")
def test_zeek_engine_produces_events_and_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(extmod, "PCAP_ENGINE", "zeek")
    case = tmp_path / "case"
    case.mkdir()
    handles = extmod.extract(str(case), _SAMPLE)
    # Zeek logs + the two gap passes (http payload, checksum) at minimum.
    assert any(h.get("extract_pass", "").startswith("zeek_") for h in handles)
    events = _normalize_all(handles, monitored_ip="10.1.13.175")
    assert events, "Zeek engine produced no normalized events"
    kinds = {e.artifact_type for e in events}
    # conn.log is always present → pcap_conn must appear.
    assert "pcap_conn" in kinds


# ── Shell-safety: evidence paths are attacker/case-controlled strings ─
# Case directories routinely contain spaces ("Case File 2026/"). Any pass
# that interpolates a path into `bash -c` must quote it, or the run either
# fails outright (Zeek) or silently produces an EMPTY log while still
# reporting success (the piped timing pass) — silent evidence loss.
@pytest.mark.skipif(not (_SAMPLE and _TOOLS),
                    reason="needs Zeek + tcpdump + a sample .pcap")
def test_zeek_extract_handles_paths_with_spaces(tmp_path):
    spaced = tmp_path / "Case File 2026"
    spaced.mkdir()
    ev = spaced / "evidence sample.pcap"
    shutil.copy(_SAMPLE, ev)
    case = tmp_path / "case"
    case.mkdir()

    handles = zeek.extract(str(case), str(ev))

    assert not any(h.get("result") == "error" for h in handles), \
        "Zeek run failed on a path containing spaces (unquoted interpolation)"
    assert any(h.get("extract_pass", "").startswith("zeek_")
               and h.get("extract_pass") != "zeek_run" for h in handles), \
        "no Zeek logs registered for a spaced path"


@pytest.mark.skipif(not (_SAMPLE and _TOOLS),
                    reason="needs Zeek + tcpdump + a sample .pcap")
def test_timing_pass_handles_paths_with_spaces(tmp_path):
    spaced = tmp_path / "Case File 2026"
    spaced.mkdir()
    ev = spaced / "evidence sample.pcap"
    shutil.copy(_SAMPLE, ev)
    case = tmp_path / "case"
    (case / "raw_extract").mkdir(parents=True)

    h = extmod._pass_timing(str(case), str(ev), "20260802_000000", "evidence sample")

    # The pipeline's exit code is awk's, so a failed tcpdump still reports
    # success — assert on the DATA, not the status.
    assert Path(h["path"]).stat().st_size > 0, \
        "timing pass produced an empty log for a spaced path (silent data loss)"


@pytest.mark.skipif(not (_SAMPLE and _TOOLS),
                    reason="needs Zeek + tcpdump + a sample .pcap")
def test_zeek_reproduces_manual_dns_and_conn_detections(tmp_path, monkeypatch):
    case = tmp_path / "case"
    case.mkdir()
    mon = "10.1.13.175"

    monkeypatch.setattr(extmod, "PCAP_ENGINE", "zeek")
    zeek_anchors = _anchors(_normalize_all(extmod.extract(str(case), _SAMPLE), mon))

    monkeypatch.setattr(extmod, "PCAP_ENGINE", "manual")
    manual_anchors = _anchors(_normalize_all(extmod.extract(str(case), _SAMPLE), mon))

    # Parity contract: Zeek (primary + retained payload/checksum passes) must
    # find at least the DNS-anomaly and connection-level detections the manual
    # engine finds. Zeek may find MORE (it is more thorough); it must not find
    # fewer for these deterministic, non-body artifact types.
    for kind_prefix in ("pcap-dns-anomaly", "pcap-suspicious-port", "pcap-c2-protocol"):
        manual_hits = {a for a in manual_anchors if a[0] == kind_prefix}
        zeek_hits = {a for a in zeek_anchors if a[0] == kind_prefix}
        missing = manual_hits - zeek_hits
        assert not missing, f"Zeek missed {kind_prefix} detections: {missing}"
