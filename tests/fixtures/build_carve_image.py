"""Build a small ext2 image containing carveable Windows artifacts.

No root needed: mkfs.ext2 creates the fs, debugfs -w writes files in.
Sleuth Kit's fls/icat read ext2 natively, so the disk module's carve
pass exercises the REAL tool path end-to-end.
"""
import subprocess
from pathlib import Path

MKFS = "/usr/sbin/mkfs.ext2"
DEBUGFS = "/usr/sbin/debugfs"

_EVTX = b"ElfFile\x00" + b"\x00" * 4088


def _pf_v23(exe="EVIL.EXE", run_count=5):
    import struct
    buf = bytearray(0x100)
    struct.pack_into("<I", buf, 0, 23)
    buf[4:8] = b"SCCA"
    name = exe.encode("utf-16-le")
    buf[0x10:0x10 + len(name)] = name
    struct.pack_into("<Q", buf, 0x80, 132000000000000000)
    struct.pack_into("<I", buf, 0x98, run_count)
    return bytes(buf)


def build(tmp: Path) -> Path:
    img = tmp / "host.dd"
    subprocess.run([MKFS, "-q", "-b", "1024", str(img), "16384"], check=True)
    # ext2's own superblock lives at byte offset 1024, so the boot-block
    # bytes at 510-511 (reserved, unused by ext2) are free. Stamp an MBR
    # boot signature there so the disk module's recognizer sniff (which
    # looks for a real disk-image signature, not just an extension) claims
    # this the way it would a real dd capture of a bootable disk.
    with open(img, "r+b") as f:
        f.seek(510)
        f.write(b"\x55\xaa")
    src_evtx = tmp / "Security.evtx"
    src_evtx.write_bytes(_EVTX)
    src_pf = tmp / "CALC.EXE-12345678.pf"
    src_pf.write_bytes(_pf_v23("CALC.EXE"))
    cmds = "\n".join([
        "mkdir /Windows", "mkdir /Windows/System32",
        "mkdir /Windows/System32/winevt", "mkdir /Windows/System32/winevt/Logs",
        "mkdir /Windows/Prefetch",
        f"write {src_evtx} /Windows/System32/winevt/Logs/Security.evtx",
        f"write {src_pf} /Windows/Prefetch/CALC.EXE-12345678.pf",
    ])
    subprocess.run([DEBUGFS, "-w", "-f", "-", str(img)],
                   input=cmds, text=True, check=True, capture_output=True)
    return img
