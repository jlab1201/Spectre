"""Track B2 Task 6: prefetch analyzer module (stdlib parser).

Covers: v23 uncompressed .pf parsing (exe name, run count, ISO timestamp),
honest handling of Win10 MAM-compressed prefetch (one event, content never
guessed), recognizer claims (.pf + SCCA@4 sniff, .pf + MAM\\x04 sniff), the
prefetch-suspicious-execution rule (double-extension + known-offensive-tool
set, silent on benign, None on unparsed compressed content), and module
discovery.
"""

import struct


def _pf_v23(exe="EVIL.EXE", run_count=5, ft=132000000000000000):
    buf = bytearray(0x100)
    struct.pack_into("<I", buf, 0, 23)
    buf[4:8] = b"SCCA"
    name = exe.encode("utf-16-le")
    buf[0x10:0x10 + len(name)] = name
    struct.pack_into("<Q", buf, 0x80, ft)
    struct.pack_into("<I", buf, 0x98, run_count)
    return bytes(buf)


def _handle(path):
    return {"path": str(path), "evidence_path": str(path)}


# ── normalize: uncompressed v23 ──

def test_normalize_v23_parses_exe_run_count_and_timestamp(tmp_path):
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "EVIL.EXE-1A2B3C4D.pf"
    p.write_bytes(_pf_v23())
    events = normalize(_handle(p))
    assert len(events) == 1
    e = events[0]
    assert e.artifact_type == "prefetch"
    assert e.data["exe_name"] == "EVIL.EXE"
    assert e.data["run_count"] == 5
    assert e.data["version"] == 23
    assert e.data["compressed"] is False
    assert e.timestamp != ""
    assert e.timestamp.startswith("20")  # ISO8601


def test_normalize_v23_zero_filetime_yields_empty_timestamp(tmp_path):
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "ZERO.EXE-11111111.pf"
    p.write_bytes(_pf_v23(exe="ZERO.EXE", run_count=1, ft=0))
    events = normalize(_handle(p))
    assert events[0].timestamp == ""
    # A legitimately-absent timestamp must NOT carry the parse-error marker.
    assert "ts_parse_error" not in events[0].data


# ── A9: near-max FILETIME must not crash the parser, and must be traceable ──

def test_normalize_v23_overflow_filetime_does_not_raise_and_is_marked(tmp_path):
    """A9 repro: ft=0xFFFFFFFFFFFFFFFF overflows datetime's representable
    range. Must not raise, must yield "" timestamp, and MUST carry a
    forensic marker distinguishing it from a legitimately-empty timestamp
    (byte-identical manifest entries silently lost the evidence, A9 HIGH)."""
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "OVERFLOW.EXE-DEADBEEF.pf"
    p.write_bytes(_pf_v23(exe="OVERFLOW.EXE", run_count=3, ft=0xFFFFFFFFFFFFFFFF))
    events = normalize(_handle(p))  # must not raise OverflowError
    assert len(events) == 1
    e = events[0]
    assert e.timestamp == ""
    assert e.data["last_run"] == ""
    assert e.data["ts_parse_error"] is True
    assert "ts_caveat" in e.data
    # the rest of the record must still be intact — not dropped wholesale
    assert e.data["exe_name"] == "OVERFLOW.EXE"
    assert e.data["run_count"] == 3


def test_normalize_v23_normal_filetime_regression(tmp_path):
    """Regression: a normal in-range FILETIME must still convert correctly
    and must NOT be marked as a parse error."""
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "NORMAL.EXE-CAFEBABE.pf"
    p.write_bytes(_pf_v23(exe="NORMAL.EXE", run_count=7, ft=132000000000000000))
    events = normalize(_handle(p))
    assert len(events) == 1
    e = events[0]
    assert e.timestamp != ""
    assert e.timestamp.startswith("20")
    assert "ts_parse_error" not in e.data


def test_normalize_mixed_batch_bad_file_marked_good_files_unaffected(tmp_path):
    """A directory containing one hostile/corrupted .pf among several good
    ones must not lose the good records — each file is normalized
    independently, only the bad one's record carries the marker."""
    from spectre.modules.prefetch.normalize import normalize

    good1 = tmp_path / "GOOD1.EXE-11111111.pf"
    good1.write_bytes(_pf_v23(exe="GOOD1.EXE", run_count=1, ft=132000000000000000))
    bad = tmp_path / "BAD.EXE-22222222.pf"
    bad.write_bytes(_pf_v23(exe="BAD.EXE", run_count=2, ft=0xFFFFFFFFFFFFFFFF))
    good2 = tmp_path / "GOOD2.EXE-33333333.pf"
    good2.write_bytes(_pf_v23(exe="GOOD2.EXE", run_count=3, ft=132000000000000000))

    results = {f.name: normalize(_handle(f)) for f in (good1, bad, good2)}

    assert all(len(evs) == 1 for evs in results.values()), "no file's record was dropped"
    assert "ts_parse_error" not in results["GOOD1.EXE-11111111.pf"][0].data
    assert "ts_parse_error" not in results["GOOD2.EXE-33333333.pf"][0].data
    assert results["BAD.EXE-22222222.pf"][0].data["ts_parse_error"] is True
    assert results["GOOD1.EXE-11111111.pf"][0].timestamp != ""
    assert results["GOOD2.EXE-33333333.pf"][0].timestamp != ""
    assert results["BAD.EXE-22222222.pf"][0].timestamp == ""


# ── normalize: MAM-compressed honesty contract ──

def test_normalize_mam_compressed_is_honest_single_event(tmp_path):
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "MIMIKATZ.EXE-9F8E7D6C.pf"
    p.write_bytes(b"MAM\x04" + b"\x00" * 60)
    events = normalize(_handle(p))
    assert len(events) == 1
    e = events[0]
    assert e.data["compressed"] is True
    assert e.data["exe_name"] == "MIMIKATZ.EXE"
    assert e.data["run_count"] is None
    assert e.data["last_run"] == ""
    assert "not parsed" in e.data["note"]


def test_normalize_missing_file_returns_empty():
    from spectre.modules.prefetch.normalize import normalize
    assert normalize({"path": "/no/such/file.pf"}) == []


def test_normalize_v23_long_double_extension_name_within_field_width(tmp_path):
    """The exe-name field is 60 BYTES (29 usable UTF-16 chars + NUL) per the
    libscca "Windows Prefetch File (PF) format" spec — not 60 characters.
    A 28-char double-extension name fits comfortably and must still be
    parsed in full (not truncated) so the $-anchored masquerade regex in
    rules.py can match it."""
    from spectre.modules.prefetch.normalize import normalize
    long_name = "A" * 20 + ".pdf.exe"  # 28 chars, well within the 29-char max
    assert len(long_name) == 28
    p = tmp_path / "LONG.pf"
    p.write_bytes(_pf_v23(exe=long_name))
    events = normalize(_handle(p))
    assert len(events) == 1
    assert events[0].data["exe_name"] == long_name

    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    a = prefetch_suspicious_execution(events[0])
    assert a is not None
    assert "double-extension masquerade" in a.title


# ── recognizer ──

def test_recognizer_claims_uncompressed_scca(tmp_path):
    from spectre.modules.prefetch.recognizer import RECOGNIZERS
    p = tmp_path / "NOTEPAD.EXE-AAAAAAAA.pf"
    p.write_bytes(_pf_v23())
    score = RECOGNIZERS[0].match(p, "data")
    assert score > 0


def test_recognizer_claims_mam_compressed(tmp_path):
    from spectre.modules.prefetch.recognizer import RECOGNIZERS
    p = tmp_path / "NOTEPAD.EXE-AAAAAAAA.pf"
    p.write_bytes(b"MAM\x04" + b"\x00" * 60)
    score = RECOGNIZERS[0].match(p, "data")
    assert score > 0


def test_recognizer_rejects_non_prefetch(tmp_path):
    from spectre.modules.prefetch.recognizer import RECOGNIZERS
    p = tmp_path / "NOTEPAD.EXE-AAAAAAAA.pf"
    p.write_bytes(b"\x00" * 64)
    assert RECOGNIZERS[0].match(p, "data") == 0.0


# ── rules ──

def test_rule_fires_on_double_extension_masquerade():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="prefetch", timestamp="2026-01-01T00:00:00+00:00",
                  source_file="p", record_id="1",
                  data={"exe_name": "INVOICE.PDF.EXE", "run_count": 1,
                        "last_run": "2026-01-01T00:00:00+00:00", "version": 23,
                        "compressed": False, "source_pf": "INVOICE.PDF.EXE-X.pf"})
    a = prefetch_suspicious_execution(e)
    assert a is not None
    assert a.rule_id == "prefetch-suspicious-execution"
    assert a.mitre == ["T1204.002"]


def test_rule_fires_on_known_offensive_tool():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="prefetch", timestamp="", source_file="p",
                  record_id="2", data={"exe_name": "mimikatz.exe", "run_count": 2,
                                        "last_run": "", "version": 23,
                                        "compressed": False, "source_pf": "m.pf"})
    a = prefetch_suspicious_execution(e)
    assert a is not None
    assert a.rule_id == "prefetch-suspicious-execution"


# ── A4-03 fix: known-offensive-tool branch must not reuse T1204.002 (User
# Execution: Malicious File) — that describes a user being socially
# engineered into running something disguised as benign, the OPPOSITE of
# an overtly-named tool like mimikatz.exe running under its own name. Each
# known tool now maps to the technique its OWN execution actually
# evidences, while the double-extension masquerade branch correctly keeps
# T1204.002.

def _prefetch_event(exe_name, record_id="9"):
    from spectre.core.base import NormEvent
    return NormEvent(artifact_type="prefetch", timestamp="", source_file="p",
                      record_id=record_id,
                      data={"exe_name": exe_name, "run_count": 3,
                            "last_run": "", "version": 23,
                            "compressed": False, "source_pf": f"{exe_name}.pf"})


def test_masquerade_branch_keeps_t1204_002():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    a = prefetch_suspicious_execution(_prefetch_event("INVOICE.PDF.EXE"))
    assert a is not None
    assert a.mitre == ["T1204.002"]


def test_known_tool_branch_does_not_use_t1204_002():
    """None of the known-offensive-tool names should be mischaracterized as
    'User Execution: Malicious File' — they ran under their own overt
    name, not disguised as a document."""
    from spectre.modules.prefetch.rules import (
        prefetch_suspicious_execution, _OFFENSIVE_TOOLS,
    )
    for exe in _OFFENSIVE_TOOLS:
        a = prefetch_suspicious_execution(_prefetch_event(exe))
        assert a is not None, exe
        assert "T1204.002" not in a.mitre, f"{exe} still mapped to T1204.002"


def test_known_tool_mitre_mapping_is_tool_specific():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    expect = {
        "mimikatz.exe": "T1003.001",
        "procdump.exe": "T1003.001",
        "lazagne.exe": "T1555",
        "psexec.exe": "T1569.002",
        "psexesvc.exe": "T1569.002",
        "sharphound.exe": "T1087.002",
        "rubeus.exe": "T1558.003",
        "nc.exe": "T1105",
        "ncat.exe": "T1105",
    }
    for exe, tid in expect.items():
        a = prefetch_suspicious_execution(_prefetch_event(exe))
        assert a is not None, exe
        assert a.mitre == [tid], f"{exe}: expected [{tid}], got {a.mitre}"


def test_rule_silent_on_benign_binary():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="prefetch", timestamp="", source_file="p",
                  record_id="3", data={"exe_name": "CHROME.EXE", "run_count": 40,
                                        "last_run": "", "version": 23,
                                        "compressed": False, "source_pf": "c.pf"})
    assert prefetch_suspicious_execution(e) is None


def test_rule_never_judges_unparsed_compressed_content():
    from spectre.modules.prefetch.rules import prefetch_suspicious_execution
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="prefetch", timestamp="", source_file="p",
                  record_id="4", data={"exe_name": "MIMIKATZ.EXE", "run_count": None,
                                        "last_run": "", "compressed": True,
                                        "note": "Win10 xpress-compressed prefetch; "
                                                "content not parsed",
                                        "source_pf": "MIMIKATZ.EXE-X.pf"})
    assert prefetch_suspicious_execution(e) is None


# ── module discovery ──

def test_module_discovered():
    from spectre.modules import registry as reg
    mods = reg.discover()
    assert "prefetch" in mods
    assert mods["prefetch"].artifact_type == "prefetch"


def test_mam_exe_name_keeps_hyphens(tmp_path):
    from spectre.modules.prefetch.normalize import normalize
    p = tmp_path / "MY-SETUP.EXE-1A2B3C4D.pf"
    p.write_bytes(b"MAM\x04" + b"\x00" * 60)
    events = normalize(_handle(p))
    assert len(events) == 1
    assert events[0].data["exe_name"] == "MY-SETUP.EXE"
