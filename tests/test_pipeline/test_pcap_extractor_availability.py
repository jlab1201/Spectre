"""
test_pcap_extractor_availability.py — recognize.py's pcap-availability check
must be engine-aware (Zeek-primary), not a blind `shutil.which("tcpdump")`.

Bug: the pcap module's required_tools=["tcpdump"] made triage_one() mark a
pcap file EXTRACTOR_PENDING on a host that has Zeek but not tcpdump, even
though config.PCAP_ENGINE defaults to "auto" and extract.py is Zeek-primary
— a false "can't process this evidence" triage. Conversely, PCAP_ENGINE=
"manual" genuinely does require tcpdump.

Fix: availability is decided from the actual configured engine
(config.PCAP_ENGINE) plus a fresh call to config._resolve_zeek(), instead of
the generic _tools_available() check.

Stage S-D moved that decision out of recognize.py — where it was an
`if analyzer.name == "pcap"` branch — into the pcap module's own
`availability()` hook, because recognize.py was not its only caller: the canary
asked the same question and got the naive answer, reporting pcap unavailable on
exactly the Zeek-primary host this branch exists for. The behaviour asserted
here is unchanged; the patch targets are now the real config and shutil modules
rather than recognize's re-exports of them.
"""

import shutil

from spectre import config
from spectre.pipeline import recognize

_PCAP_MAGIC = b"\xa1\xb2\xc3\xd4"


def _write_pcap(tmp_path):
    p = tmp_path / "case.pcap"
    p.write_bytes(_PCAP_MAGIC + b"\x00" * 64)
    return p


def _write_memory(tmp_path):
    # .mem extension, no MBR -> claimed by the memory module, whose
    # required_tools=["vol"]; used to prove the pcap branch is scoped.
    p = tmp_path / "dump.mem"
    p.write_bytes(b"\x00" * 512)
    return p


# ── engine auto/zeek: Zeek resolvable, tcpdump absent -> RECOGNIZED ───────

def test_pcap_auto_engine_zeek_resolvable_no_tcpdump_is_recognized(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)
    fake_zeek = tmp_path / "zeek"
    fake_zeek.write_text("#!/bin/sh\n")
    fake_zeek.chmod(0o755)

    monkeypatch.setattr(config, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: str(fake_zeek))
    monkeypatch.setattr(shutil, "which",
                         lambda t: None if t == "tcpdump" else "/usr/bin/" + t)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "RECOGNIZED", rec


def test_pcap_zeek_engine_zeek_resolvable_no_tcpdump_is_recognized(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)
    fake_zeek = tmp_path / "zeek"
    fake_zeek.write_text("#!/bin/sh\n")
    fake_zeek.chmod(0o755)

    monkeypatch.setattr(config, "PCAP_ENGINE", "zeek")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: str(fake_zeek))
    monkeypatch.setattr(shutil, "which", lambda t: None)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "RECOGNIZED", rec


# ── engine manual: tcpdump absent -> EXTRACTOR_PENDING, tool tcpdump ─────

def test_pcap_manual_engine_no_tcpdump_is_extractor_pending(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)
    fake_zeek = tmp_path / "zeek"
    fake_zeek.write_text("#!/bin/sh\n")
    fake_zeek.chmod(0o755)

    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    # Zeek IS resolvable here -- manual mode must still require tcpdump.
    monkeypatch.setattr(config, "_resolve_zeek", lambda: str(fake_zeek))
    monkeypatch.setattr(shutil, "which", lambda t: None)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "EXTRACTOR_PENDING", rec
    assert rec["tool"] == "tcpdump", rec


# ── engine zeek, Zeek unresolvable, tcpdump absent -> EXTRACTOR_PENDING, tool zeek ─

def test_pcap_zeek_engine_unresolvable_no_tcpdump_is_extractor_pending(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)

    monkeypatch.setattr(config, "PCAP_ENGINE", "zeek")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "zeek")  # unresolved fallback
    monkeypatch.setattr(shutil, "which", lambda t: None)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "EXTRACTOR_PENDING", rec
    assert rec["tool"] == "zeek", rec


def test_pcap_auto_engine_unresolvable_no_tcpdump_is_extractor_pending(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)

    monkeypatch.setattr(config, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "zeek")
    monkeypatch.setattr(shutil, "which", lambda t: None)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "EXTRACTOR_PENDING", rec
    assert rec["tool"] == "zeek", rec


# ── tcpdump present, any engine -> RECOGNIZED (no regression) ────────────

def test_pcap_tcpdump_present_any_engine_is_recognized(tmp_path, monkeypatch):
    p = _write_pcap(tmp_path)

    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "zeek")
    monkeypatch.setattr(shutil, "which",
                         lambda t: "/usr/bin/tcpdump" if t == "tcpdump" else None)

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "pcap"
    assert rec["status"] == "RECOGNIZED", rec


# ── non-pcap module unaffected by the pcap branch ─────────────────────────

def test_non_pcap_module_unaffected_by_pcap_branch(tmp_path, monkeypatch):
    p = _write_memory(tmp_path)

    monkeypatch.setattr(config, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "/some/zeek")
    monkeypatch.setattr(shutil, "which", lambda t: None)  # "vol" absent

    rec = recognize.triage_one(str(p))
    assert rec["module"] == "memory"
    assert rec["status"] == "EXTRACTOR_PENDING", rec
    assert rec["tool"] == "vol", rec
