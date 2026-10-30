"""lnk/normalize.py — stdlib binary parser for Windows shortcuts (MS-SHLLINK).

Minimal and honest: only the fields a triage analyst actually needs are
pulled — target path, drive type, network-link flag, file size, and write
time — from the fixed 76-byte ShellLinkHeader and (when present) the
LinkInfo block. Nothing else in the file (LinkTargetIDList contents,
ExtraData blocks, icon locations, command-line arguments, ...) is
interpreted; unknown/unrecognized or truncated structures return no
events rather than a partial guess.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from spectre.core.base import NormEvent

ARTIFACT = "lnk"

_HEADER_SIZE = 76
_EXPECTED_HEADER_FIELD = 0x4C

_FLAG_HAS_LINK_TARGET_ID_LIST = 0x01
_FLAG_HAS_LINK_INFO = 0x02

_LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x01
_LINK_INFO_FLAG_COMMON_NETWORK_RELATIVE_LINK = 0x02


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


_TS_OVERFLOW_CAVEAT = (
    "write_time FILETIME value does not fit in a representable timestamp "
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


def _read_cstr_cp1252(buf: bytes, offset: int) -> str:
    nul = buf.find(b"\x00", offset)
    chunk = buf[offset:nul] if nul != -1 else buf[offset:]
    return chunk.decode("cp1252", errors="replace")


def normalize(handle: dict) -> list[NormEvent]:
    """Module entrypoint: read a .lnk file's bytes directly from disk."""
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    source = handle.get("evidence_path", path)
    data = Path(path).read_bytes()
    try:
        return _parse(data, source)
    except (struct.error, IndexError, OverflowError, ValueError, OSError):
        # OverflowError/ValueError/OSError added for A9: _filetime_to_iso
        # already contains the FILETIME overflow case without raising, but
        # this outer guard stays broadened defense-in-depth so no future
        # arithmetic on parsed fields can abort or silently vanish the file.
        return []


def _parse(data: bytes, source: str) -> list[NormEvent]:
    if len(data) < _HEADER_SIZE:
        return []  # truncated header — nothing honest to report

    header_size = struct.unpack_from("<I", data, 0)[0]
    if header_size != _EXPECTED_HEADER_FIELD:
        return []  # not a recognized ShellLinkHeader — don't guess

    link_flags = struct.unpack_from("<I", data, 20)[0]
    write_ft = struct.unpack_from("<Q", data, 44)[0]
    file_size = struct.unpack_from("<I", data, 52)[0]

    offset = _HEADER_SIZE

    if link_flags & _FLAG_HAS_LINK_TARGET_ID_LIST:
        if len(data) < offset + 2:
            return []
        id_list_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + id_list_size
        if len(data) < offset:
            return []

    target_path = ""
    drive_type = None
    network_link = False

    if link_flags & _FLAG_HAS_LINK_INFO:
        li_start = offset
        if len(data) < li_start + 20:
            return []  # LinkInfo header itself is truncated
        link_info_flags = struct.unpack_from("<I", data, li_start + 8)[0]
        volume_id_offset = struct.unpack_from("<I", data, li_start + 12)[0]
        local_base_path_offset = struct.unpack_from("<I", data, li_start + 16)[0]

        network_link = bool(link_info_flags & _LINK_INFO_FLAG_COMMON_NETWORK_RELATIVE_LINK)

        if link_info_flags & _LINK_INFO_FLAG_VOLUME_ID_AND_LOCAL_BASE_PATH:
            vol_pos = li_start + volume_id_offset
            if len(data) < vol_pos + 8:
                return []
            drive_type = struct.unpack_from("<I", data, vol_pos + 4)[0]

            lbp_pos = li_start + local_base_path_offset
            if lbp_pos > len(data):
                return []
            target_path = _read_cstr_cp1252(data, lbp_pos)

    write_time, ts_parse_error = _filetime_to_iso(write_ft)
    basename = _basename(source)

    record_data = {
        "target_path": target_path,
        "drive_type": drive_type,
        "network_link": network_link,
        "file_size": file_size,
        "write_time": write_time,
        "source_lnk": basename,
    }
    if ts_parse_error:
        # Forensic marker (A9 fix): distinguishes "timestamp field failed to
        # parse" from "timestamp field was legitimately 0/absent" — both
        # otherwise collapse to timestamp == "". Never leave this silent.
        record_data["ts_parse_error"] = True
        record_data["ts_caveat"] = _TS_OVERFLOW_CAVEAT

    return [NormEvent(
        artifact_type=ARTIFACT,
        timestamp=write_time,
        source_file=source,
        record_id="1",
        data=record_data,
    )]
