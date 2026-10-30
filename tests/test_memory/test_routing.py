"""
test_routing.py — cross-module recognition / routing tests.

Verifies the registry discovers every module and that recognize.triage
routes each evidence type to the correct module. Memory/disk use
synthetic headers (no real images needed); EVTX/pcap use real-ish bytes.
"""

import struct
import sys
import tempfile
from pathlib import Path

from spectre.modules import registry
from spectre.pipeline.recognize import triage_one


def test_registry_discovers_all_modules():
    mods = registry.discover()
    assert {"evtx", "pcap", "memory", "disk"} <= set(mods), mods.keys()


def _write(tmp, name, data):
    p = Path(tmp) / name
    p.write_bytes(data)
    return str(p)


def test_routing_each_type():
    with tempfile.TemporaryDirectory() as tmp:
        # EVTX: ElfFile magic.
        evtx = _write(tmp, "x.evtx", b"ElfFile\x00" + b"\x00" * 64)
        # pcap: libpcap magic.
        pcap = _write(tmp, "x.pcap", struct.pack("<I", 0xa1b2c3d4) + b"\x00" * 64)
        # disk: raw image with MBR boot signature at 510.
        disk_bytes = bytearray(b"\x00" * 512)
        disk_bytes[510:512] = b"\x55\xaa"
        disk = _write(tmp, "x.raw", bytes(disk_bytes))
        # memory: .mem extension, no MBR.
        mem = _write(tmp, "x.mem", b"\x00" * 512)
        # unknown.
        unk = _write(tmp, "x.sqlite", b"SQLite format 3\x00")

        assert triage_one(evtx)["module"] == "evtx"
        assert triage_one(pcap)["module"] == "pcap"
        assert triage_one(disk)["module"] == "disk"
        assert triage_one(mem)["module"] == "memory"
        assert triage_one(unk)["status"] == "UNRECOGNIZED"


def test_raw_disk_vs_raw_memory_disambiguation():
    """A .raw with an MBR is a disk; a .raw without one is memory."""
    with tempfile.TemporaryDirectory() as tmp:
        d = bytearray(b"\x00" * 512)
        d[510:512] = b"\x55\xaa"
        disk = _write(tmp, "img.raw", bytes(d))
        memraw = _write(tmp, "dump.raw", b"\x00" * 512)
        assert triage_one(disk)["module"] == "disk"
        assert triage_one(memraw)["module"] == "memory"


def test_lime_signature_beats_coincidental_mbr(tmp_path):
    # A LiME dump whose bytes happen to contain 55AA at offset 510 must
    # still be claimed as memory (positive signature wins over elimination).
    from spectre.modules.memory.recognizer import _looks_like_memory
    blob = bytearray(b"EMiL" + b"\x00" * 1020)
    blob[510:512] = b"\x55\xaa"
    p = tmp_path / "dump.raw"
    p.write_bytes(bytes(blob))
    assert _looks_like_memory(p) is True


def test_hiberfil_signature_recognized(tmp_path):
    from spectre.modules.memory.recognizer import _looks_like_memory
    p = tmp_path / "hiberfil.dmp"
    p.write_bytes(b"hibr" + b"\x00" * 1024)
    assert _looks_like_memory(p) is True


def test_plain_raw_disk_still_rejected(tmp_path):
    from spectre.modules.memory.recognizer import _looks_like_memory
    blob = bytearray(b"\x00" * 512)
    blob[510:512] = b"\x55\xaa"
    p = tmp_path / "disk.raw"
    p.write_bytes(bytes(blob))
    assert _looks_like_memory(p) is False


def test_lime_with_coincidental_mbr_routes_to_memory_module(tmp_path):
    # Routing-level guarantee: a positive memory signature must beat the
    # disk module's MBR heuristic in the triage contest, not just pass
    # _looks_like_memory.
    from spectre.pipeline.recognize import triage_one
    blob = bytearray(b"EMiL" + b"\x00" * 1020)
    blob[510:512] = b"\x55\xaa"
    p = tmp_path / "dump.raw"
    p.write_bytes(bytes(blob))
    rec = triage_one(str(p))
    assert rec["module"] == "memory", f"misrouted: {rec}"
    assert rec["confidence"] > 0.85


if __name__ == "__main__":
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
