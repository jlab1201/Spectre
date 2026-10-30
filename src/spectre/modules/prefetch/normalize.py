"""prefetch/normalize.py — stdlib binary parser for Windows Prefetch (.pf).

Two on-disk shapes, two very different honesty postures:

* Uncompressed (`SCCA` magic at offset 4; versions 17/23/26/30 map to
  WinXP-2003 / Vista-7 / Win8.1 / Win10-uncompressed) — a narrow,
  version-keyed offset table is used to pull exactly three fields: the
  executable name, the last-run FILETIME, and the run count. Nothing else
  in the file is interpreted.
* Compressed (`MAM\\x04` magic at offset 0, the Windows 10 default) — the
  xpress-compressed body is NEVER decompressed or guessed at. Exactly one
  honest event is emitted per file, with `exe_name` sourced from the
  filename (APPNAME-HASH.pf) rather than parsed content, `run_count=None`,
  and a note explaining why. This is deliberately weaker evidence than a
  parsed uncompressed record, and the note says so.

Unknown/unrecognized versions or truncated files return no events — this
parser never guesses at a layout it hasn't been told about.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from spectre.core.base import NormEvent

ARTIFACT = "prefetch"

# version -> (last_run_filetime_offset, run_count_offset)
_VERSION_OFFSETS = {
    17: (0x78, 0x90),  # WinXP/2003
    23: (0x80, 0x98),  # Vista/7
    26: (0x80, 0xD0),  # Win8.1
    30: (0x80, 0xD0),  # Win10 (uncompressed)
}

_EXE_NAME_OFFSET = 0x10
# 60 BYTES, not 60 characters. Per the libscca / Joachim Metz "Windows
# Prefetch File (PF) format" spec, the executable-filename field in the
# uncompressed SCCA header is UTF-16LE, offset 0x10, size 60 bytes — i.e.
# a maximum of 29 usable characters plus a NUL terminator (30 UTF-16LE
# code units x 2 bytes = 60). This is corroborated structurally by
# _VERSION_OFFSETS[23]: last_run_filetime sits at 0x80, which is only
# 0x70 (112) bytes past this field's start — a 120-byte field (0x10..0x88)
# would overlap it, which is impossible. Do not "fix" this to 120.
_EXE_NAME_MAX_BYTES = 60

_MAM_MAGIC = b"MAM\x04"
_SCCA_MAGIC = b"SCCA"
_MAM_NOTE = "Win10 xpress-compressed prefetch; content not parsed"


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _read_utf16_cstr(buf: bytes, offset: int, max_bytes: int) -> str:
    chunk = buf[offset:offset + max_bytes]
    text = chunk.decode("utf-16-le", errors="ignore")
    nul = text.find("\x00")
    return text[:nul] if nul != -1 else text


_TS_OVERFLOW_CAVEAT = (
    "last_run FILETIME value does not fit in a representable timestamp "
    "(overflow/out-of-range) — this field is unparseable, not legitimately "
    "absent; treat the record as having a corrupted or hostile timestamp."
)


def _filetime_to_iso(ft: int) -> tuple[str, bool]:
    """FILETIME (100ns intervals since 1601-01-01) -> (ISO8601, parse_error).

    Returns ("", False) for ft == 0 — a legitimately absent timestamp.
    Returns ("", True) when ft is structurally a valid 64-bit value but
    doesn't fit in datetime's representable range (e.g. a crafted/corrupted
    near-max FILETIME, A9). That case must NOT raise — the pipeline must
    never abort or silently drop an evidence file over one bad timestamp —
    but it also must not look identical to a legitimately-absent timestamp,
    hence the separate bool: callers use it to attach a forensic marker.
    """
    if not ft:
        return "", False
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.isoformat(), False
    except (OverflowError, ValueError, OSError):
        return "", True


def normalize(handle: dict) -> list[NormEvent]:
    """Module entrypoint: read a .pf file's bytes directly from disk."""
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    source = handle.get("evidence_path", path)
    data = Path(path).read_bytes()
    try:
        return _parse(data, source)
    except (struct.error, IndexError, OverflowError, ValueError, OSError):
        # Defense-in-depth: _filetime_to_iso already contains the FILETIME
        # overflow case (A9) without raising. This outer guard exists so a
        # malformed/hostile file can never abort or silently vanish the
        # whole case over some other unanticipated parse failure either —
        # mirrors the guard lnk/normalize.py already had.
        return []


def _parse(data: bytes, source: str) -> list[NormEvent]:
    if data[:4] == _MAM_MAGIC:
        return _parse_mam(source)
    if len(data) >= 8 and data[4:8] == _SCCA_MAGIC:
        return _parse_uncompressed(data, source)
    return []  # not a recognized prefetch signature — don't guess


def _parse_mam(source: str) -> list[NormEvent]:
    basename = _basename(source)
    exe_name = basename.rsplit("-", 1)[0] if basename else ""
    return [NormEvent(
        artifact_type=ARTIFACT,
        timestamp="",
        source_file=source,
        record_id="1",
        data={
            "exe_name": exe_name,
            "run_count": None,
            "last_run": "",
            "version": None,
            "compressed": True,
            "note": _MAM_NOTE,
            "source_pf": basename,
        },
    )]


def _parse_uncompressed(data: bytes, source: str) -> list[NormEvent]:
    version = struct.unpack_from("<I", data, 0)[0]
    offsets = _VERSION_OFFSETS.get(version)
    if offsets is None:
        return []  # unrecognized version — don't guess at its layout
    last_run_off, run_count_off = offsets
    if len(data) < max(last_run_off + 8, run_count_off + 4):
        return []  # truncated — nothing honest to report

    exe_name = _read_utf16_cstr(data, _EXE_NAME_OFFSET, _EXE_NAME_MAX_BYTES)
    ft = struct.unpack_from("<Q", data, last_run_off)[0]
    run_count = struct.unpack_from("<I", data, run_count_off)[0]
    timestamp, ts_parse_error = _filetime_to_iso(ft)
    basename = _basename(source)

    record_data = {
        "exe_name": exe_name,
        "run_count": run_count,
        "last_run": timestamp,
        "version": version,
        "compressed": False,
        "source_pf": basename,
    }
    if ts_parse_error:
        # Forensic marker (A9 fix): distinguishes "timestamp field failed to
        # parse" from "timestamp field was legitimately 0/absent" — both
        # otherwise collapse to timestamp == "". Never leave this silent.
        record_data["ts_parse_error"] = True
        record_data["ts_caveat"] = _TS_OVERFLOW_CAVEAT

    return [NormEvent(
        artifact_type=ARTIFACT,
        timestamp=timestamp,
        source_file=source,
        record_id="1",
        data=record_data,
    )]
