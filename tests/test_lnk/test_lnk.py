"""Track B2 Task 7: LNK analyzer module (stdlib MS-SHLLINK parser).

Covers: header + LinkInfo parse (target path, drive type, network flag),
the lnk-suspicious-target rule (T1091 removable / T1021.002 network /
T1204.002 temp-executable / silent on benign fixed-drive Program Files),
honest truncation handling (malformed -> emit NOTHING), recognizer CLSID
sniff (accept real header, reject a `.lnk` without the LinkCLSID magic),
and module discovery.
"""

import struct

_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _lnk(target=b"E:\\payload.exe", drive_type=2, flags=0x02, li_flags=0x01,
         network=False, write_ft=0):
    if network:
        li_flags |= 0x02
    header = struct.pack("<I", 0x4C) + _CLSID + struct.pack("<I", flags)
    header += b"\x00" * (76 - len(header))
    header = bytearray(header)
    struct.pack_into("<Q", header, 44, write_ft)
    header = bytes(header)
    # LinkInfo: size(4) hdrsize(4) flags(4) volid_off(4) lbp_off(4) cnrl_off(4)
    vol_off, lbp_off = 28, 44
    volume = struct.pack("<II", 16, drive_type) + b"\x00" * 8   # size, DriveType
    li = struct.pack("<IIIIII", lbp_off + len(target) + 1, 28, li_flags,
                     vol_off, lbp_off, 0)
    li += b"\x00" * (vol_off - len(li)) + volume
    li += b"\x00" * (lbp_off - len(li)) + target + b"\x00"
    return header + li


def _handle(path):
    return {"path": str(path), "evidence_path": str(path)}


# ── normalize: header + LinkInfo parse ──

def test_normalize_parses_target_path_and_removable_drive_type(tmp_path):
    from spectre.modules.lnk.normalize import normalize
    p = tmp_path / "payload.lnk"
    p.write_bytes(_lnk(target=b"E:\\payload.exe", drive_type=2))
    events = normalize(_handle(p))
    assert len(events) == 1
    e = events[0]
    assert e.artifact_type == "lnk"
    assert e.data["target_path"] == "E:\\payload.exe"
    assert e.data["drive_type"] == 2
    assert e.data["network_link"] is False
    assert e.data["source_lnk"] == "payload.lnk"


def test_normalize_missing_file_returns_empty():
    from spectre.modules.lnk.normalize import normalize
    assert normalize({"path": "/no/such/file.lnk"}) == []


def test_normalize_truncated_file_returns_empty(tmp_path):
    from spectre.modules.lnk.normalize import normalize
    p = tmp_path / "truncated.lnk"
    full = _lnk()
    p.write_bytes(full[:20])  # only the fixed CLSID prefix, no full header
    events = normalize(_handle(p))
    assert events == []


# ── A9: near-max FILETIME WriteTime must not crash the parser ──

def test_normalize_overflow_write_ft_does_not_raise_and_is_marked(tmp_path):
    """A9 repro: WriteTime=0xFFFFFFFFFFFFFFFF overflows datetime's
    representable range. Must not raise OverflowError, must yield ""
    write_time/timestamp, and MUST carry a forensic marker so the record
    is distinguishable from a legitimately-zero WriteTime (both otherwise
    collapse to the same empty-timestamp, byte-identical manifest entry,
    A9 HIGH)."""
    from spectre.modules.lnk.normalize import normalize
    p = tmp_path / "overflow.lnk"
    p.write_bytes(_lnk(target=b"E:\\payload.exe", drive_type=2,
                        write_ft=0xFFFFFFFFFFFFFFFF))
    events = normalize(_handle(p))  # must not raise
    assert len(events) == 1
    e = events[0]
    assert e.timestamp == ""
    assert e.data["write_time"] == ""
    assert e.data["ts_parse_error"] is True
    assert "ts_caveat" in e.data
    # the rest of the record must still be intact — not dropped wholesale
    assert e.data["target_path"] == "E:\\payload.exe"
    assert e.data["drive_type"] == 2


def test_normalize_normal_write_ft_regression(tmp_path):
    """Regression: a normal in-range FILETIME must still convert correctly
    and must NOT be marked as a parse error."""
    from spectre.modules.lnk.normalize import normalize
    p = tmp_path / "normal.lnk"
    p.write_bytes(_lnk(target=b"C:\\Program Files\\app.exe", drive_type=3,
                        write_ft=132000000000000000))
    events = normalize(_handle(p))
    assert len(events) == 1
    e = events[0]
    assert e.timestamp != ""
    assert e.timestamp.startswith("20")
    assert "ts_parse_error" not in e.data


def test_normalize_mixed_batch_bad_file_marked_good_files_unaffected(tmp_path):
    """A directory containing one hostile/corrupted .lnk among several good
    ones must not lose the good records — each file is normalized
    independently, only the bad one's record carries the marker."""
    from spectre.modules.lnk.normalize import normalize

    good1 = tmp_path / "good1.lnk"
    good1.write_bytes(_lnk(target=b"E:\\g1.exe", write_ft=132000000000000000))
    bad = tmp_path / "bad.lnk"
    bad.write_bytes(_lnk(target=b"E:\\bad.exe", write_ft=0xFFFFFFFFFFFFFFFF))
    good2 = tmp_path / "good2.lnk"
    good2.write_bytes(_lnk(target=b"E:\\g2.exe", write_ft=132000000000000000))

    results = {f.name: normalize(_handle(f)) for f in (good1, bad, good2)}

    assert all(len(evs) == 1 for evs in results.values()), "no file's record was dropped"
    assert "ts_parse_error" not in results["good1.lnk"][0].data
    assert "ts_parse_error" not in results["good2.lnk"][0].data
    assert results["bad.lnk"][0].data["ts_parse_error"] is True
    assert results["good1.lnk"][0].timestamp != ""
    assert results["good2.lnk"][0].timestamp != ""
    assert results["bad.lnk"][0].timestamp == ""


# ── rules ──

def test_rule_fires_t1091_on_removable_drive():
    from spectre.modules.lnk.rules import lnk_suspicious_target
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="lnk", timestamp="", source_file="p",
                  record_id="1",
                  data={"target_path": "E:\\payload.exe", "drive_type": 2,
                        "network_link": False, "file_size": 0,
                        "write_time": "", "source_lnk": "payload.lnk"})
    a = lnk_suspicious_target(e)
    assert a is not None
    assert a.rule_id == "lnk-suspicious-target"
    assert a.mitre == ["T1091"]


def test_rule_fires_t1021_002_on_network_link():
    from spectre.modules.lnk.rules import lnk_suspicious_target
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="lnk", timestamp="", source_file="p",
                  record_id="2",
                  data={"target_path": "\\\\fileserver\\share\\doc.docx",
                        "drive_type": 4, "network_link": True,
                        "file_size": 0, "write_time": "",
                        "source_lnk": "doc.lnk"})
    a = lnk_suspicious_target(e)
    assert a is not None
    assert a.mitre == ["T1021.002"]


def test_rule_fires_t1204_002_on_temp_exe_target():
    from spectre.modules.lnk.rules import lnk_suspicious_target
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="lnk", timestamp="", source_file="p",
                  record_id="3",
                  data={"target_path":
                        "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe",
                        "drive_type": 3, "network_link": False,
                        "file_size": 0, "write_time": "",
                        "source_lnk": "evil.lnk"})
    a = lnk_suspicious_target(e)
    assert a is not None
    assert a.mitre == ["T1204.002"]


def test_rule_silent_on_program_files_fixed_drive():
    from spectre.modules.lnk.rules import lnk_suspicious_target
    from spectre.core.base import NormEvent
    e = NormEvent(artifact_type="lnk", timestamp="", source_file="p",
                  record_id="4",
                  data={"target_path": "C:\\Program Files\\Vendor\\app.exe",
                        "drive_type": 3, "network_link": False,
                        "file_size": 0, "write_time": "",
                        "source_lnk": "app.lnk"})
    assert lnk_suspicious_target(e) is None


# ── recognizer ──

def test_recognizer_accepts_real_lnk_header(tmp_path):
    from spectre.modules.lnk.recognizer import RECOGNIZERS
    p = tmp_path / "shortcut.lnk"
    p.write_bytes(_lnk())
    score = RECOGNIZERS[0].match(p, "data")
    assert score > 0


def test_recognizer_rejects_lnk_without_clsid(tmp_path):
    from spectre.modules.lnk.recognizer import RECOGNIZERS
    p = tmp_path / "notreally.lnk"
    p.write_bytes(struct.pack("<I", 0x4C) + b"\x00" * 72)
    assert RECOGNIZERS[0].match(p, "data") == 0.0


# ── module discovery ──

def test_module_discovered():
    from spectre.modules import registry as reg
    mods = reg.discover()
    assert "lnk" in mods
    assert mods["lnk"].artifact_type == "lnk"
