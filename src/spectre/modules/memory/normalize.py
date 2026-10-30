"""memory/normalize.py — volatility3 JSON rows -> NormEvents.

vol -r json emits a JSON array of row dicts whose keys are the plugin's
column names (e.g. PsList: PID, PPID, ImageFileName, CreateTime). We map
each plugin to a stable schema so rules stay decoupled from vol's exact
column casing.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from spectre.core.base import NormEvent

logger = logging.getLogger(__name__)


def _rows(handle: dict) -> list[dict]:
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    try:
        data = json.loads(Path(path).read_text(errors="replace") or "[]")
    except json.JSONDecodeError as exc:
        logger.warning("memory rows: corrupt JSON in %s (%s); returning no rows", path, exc)
        return []
    return data if isinstance(data, list) else data.get("rows", [])


def _g(row: dict, *names, default=""):
    """Fetch the first present key (vol column names vary by version)."""
    for n in names:
        if n in row and row[n] is not None:
            return row[n]
    return default


# ── Cross-engine canonicalization ────────────────────────────────────────
#
# Extractors TRANSCRIBE what their tool emitted (a chain-of-custody property:
# the audited raw file must stay a faithful rendering of its source). This
# module CANONICALIZES, and rules read the canonical fields. Without that,
# two engines observing one fact produce different dedup_keys and can never
# corroborate -- which is why only 2 of 40 findings on case 272-004-memory
# reached sources: 2.
#
# Rule of thumb for future engines: canonicalize here, keep the raw form
# alongside for display/provenance, and pass unrecognized input through
# VERBATIM rather than guessing at it.

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S UTC",   # MemProcFS
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
)


def _canon_ts(raw) -> str:
    """ISO-8601 UTC. Unrecognized input is returned unchanged.

    vol emits "2019-08-19T14:40:07+00:00"; MemProcFS emits
    "2019-08-19 14:40:07 UTC". Left alone, one process carries two different
    timestamps depending on engine, which corrupts a corroborated group's
    first_seen/last_seen. NEVER substitute wall-clock time for an
    unparseable value -- an undated event is honest, a back-dated one is not.
    """
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    if dt is None:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# Hive-file renderings seen from volatility3 printkey, mapped to a canonical
# root. Measured on real output; see tests/test_memory/.
_HIVE_PREFIXES = (
    (r"\systemroot\system32\config\\", "HKLM\\"),
    (r"\registry\machine\\", "HKLM\\"),
)
_NTUSER = re.compile(
    r"^\\\?\?\\[a-z]:\\(?:users|windows\\serviceprofiles)\\([^\\]+)"
    r"\\ntuser\.dat\\(.*)$")


def _canon_regkey(raw) -> str:
    """Canonical registry path, or the input unchanged if unrecognized.

    The same key is rendered three ways across our engines:
      vol   \\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\...\\Winlogon
      vol   \\??\\C:\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT\\...
      mpfs  HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon
    Canonical form is HKLM\\... or HKU\\<profile>\\..., case-folded. The user
    profile is PRESERVED -- which user a Run key belongs to is forensically
    meaningful and must not be flattened away.
    """
    s = str(raw or "").strip().replace("/", "\\")
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    s = s.rstrip("\\")
    if not s:
        return ""
    low = s.lower()

    m = _NTUSER.match(low)
    if m:
        return f"hku\\{m.group(1)}\\{m.group(2)}"
    for prefix, root in _HIVE_PREFIXES:
        p = prefix.replace("\\\\", "\\")
        if low.startswith(p):
            return (root + s[len(p):]).lower()
    if low.startswith(("hklm\\", "hku\\", "hkcu\\", "hkey_")):
        return low
    return low


def _canon_regvalue(raw) -> str:
    """Strip one layer of surrounding quotes -- vol quotes the value, the
    MemProcFS registry export does not. Used for identity only; the displayed
    value_data keeps the tool's own rendering."""
    s = str(raw or "").strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s


_PAGE = 0x1000


def _canon_addr(raw) -> str:
    """Page-aligned address as fixed-width hex, or "" if unparseable.

    vol malfind renders the region start as a DECIMAL int (63832064);
    MemProcFS renders hex. Aligning down to the 4 KiB page is the smallest
    granularity that lets two engines agree on "the same region" without
    merging genuinely distinct neighbouring regions.
    """
    if raw is None or raw == "":
        return ""
    try:
        v = raw if isinstance(raw, int) else (
            int(str(raw), 16) if str(raw).lower().startswith("0x")
            else int(str(raw), 10))
    except (TypeError, ValueError):
        try:
            v = int(str(raw), 16)
        except (TypeError, ValueError):
            return ""
    return f"0x{(v - (v % _PAGE)):012x}"


# One service start type, three renderings: the raw registry DWORD, vol's
# SERVICE_* constant, and MemProcFS's short form. Identity must not depend on
# which tool spoke.
_START_CANON = {
    "0": "boot", "boot_start": "boot", "service_boot_start": "boot",
    "1": "system", "system_start": "system", "service_system_start": "system",
    "2": "auto", "auto": "auto", "auto_start": "auto",
    "service_auto_start": "auto",
    "3": "demand", "demand": "demand", "demand_start": "demand",
    "service_demand_start": "demand",
    "4": "disabled", "disabled": "disabled", "service_disabled": "disabled",
}


def _canon_start(raw) -> str:
    """Canonical service start type, or "" if the rendering is unrecognised.

    Unrecognised deliberately yields "" rather than a best guess: a wrong
    guess that happens to land on "auto" would put a persistence claim on a
    service that does not start at boot.
    """
    if raw is None or raw == "":
        return ""
    return _START_CANON.get(str(raw).strip().lower(), "")


def _pe_header_present(hexdump: str) -> bool:
    """True if a malfind region begins with an MZ/PE header.

    vol renders the region as a hexdump line like
    "0x... 4d 5a 90 00 ...  MZ......"; the "4d 5a" (MZ) magic appears in the
    first bytes. Check a generous prefix so the leading address offset
    doesn't hide it.
    """
    h = hexdump.lower()[:80]
    return "4d 5a" in h or h.lstrip().startswith("mz")


_NO_EXIT_TIME = frozenset({"n/a", "-", "none"})


def _normalize_systeminfo(rows: list[dict], source: str) -> list[NormEvent]:
    """windows.info.Info rows -> ONE system-profile NormEvent.

    Unlike every other plugin here, vol's windows.info renders as a flat
    Variable/Value table (one row per fact), not one row per observation —
    so this collapses all rows into a single aggregate record rather than
    the usual one-event-per-row loop.

    This is a PROFILE SIGNAL, not a finding: memory_systeminfo has no rule
    in rules.py, so no MITRE finding can ever be emitted from it (the
    inviolable rule — only the deterministic core's rule packs produce
    findings). Host/OS attribution stays metadata for the report to surface.
    """
    if not rows:
        return []
    info: dict[str, str] = {}
    for row in rows:
        var = str(_g(row, "Variable", default=""))
        if var:
            info[var] = str(_g(row, "Value", default=""))

    os_build = info.get("NTBuildLab") or info.get("NtBuildLab") or ""
    if not os_build:
        major = info.get("NtMajorVersion", "")
        minor = info.get("NtMinorVersion", "")
        if major or minor:
            os_build = f"{major}.{minor}"
    hostname = info.get("Hostname") or info.get("ComputerName") or ""
    system_time = info.get("SystemTime", "")

    data = {
        "os_build": os_build,
        "hostname": hostname,
        "system_time": system_time,
        "is_64bit": info.get("Is64Bit", ""),
        "nt_major_version": info.get("NtMajorVersion", ""),
        "nt_minor_version": info.get("NtMinorVersion", ""),
        "system_root": info.get("NtSystemRoot", ""),
        "kernel_base": info.get("Kernel Base", ""),
        "num_processors": info.get("KeNumberProcessors", ""),
        "machine_type": info.get("MachineType", ""),
        "product_type": info.get("NtProductType", ""),
    }
    return [NormEvent(
        artifact_type="memory_systeminfo",
        timestamp=system_time,
        source_file=source,
        record_id="0",
        host=hostname.lower(),
        data=data,
    )]


def _process_row(row: dict, pid_to_image: dict, image_counts: dict) -> dict:
    """Shared pslist/psscan row shape: pid/ppid/image + parent/instance
    enrichment. psscan walks pool tags instead of the linked list (it can
    surface unlinked/hidden processes pslist misses), but the row shape is
    identical, so both artifact types share this helper — no duplication.
    """
    image = str(_g(row, "ImageFileName", "Name", "Process"))
    ppid = str(_g(row, "PPID", "Ppid"))
    # psscan pool-scanning also surfaces TERMINATED processes (freed
    # EPROCESS blocks) — those are legitimately absent from pslist and are
    # NOT hidden. ExitTime is set for them; vol renders "still running" as
    # "N/A"/"-"/"None" depending on version, which we normalize to "".
    exit_time = str(_g(row, "ExitTime", default="")).strip()
    if exit_time.lower() in _NO_EXIT_TIME:
        exit_time = ""
    return {
        "pid": _g(row, "PID", "Pid"),
        "ppid": _g(row, "PPID", "Ppid"),
        "image_basename": image.lower(),
        "image": image,
        "create_time": _canon_ts(_g(row, "CreateTime")),
        "exit_time": _canon_ts(exit_time),
        # Enrichment: parent image name (resolved within this handle)
        # and how many processes share this image name. These let the
        # parent/child + masquerade rules reason without cross-event I/O.
        "parent_image": pid_to_image.get(ppid, "").lower(),
        "instance_count": image_counts.get(image.lower(), 1),
    }


def normalize(handle: dict) -> list[NormEvent]:
    artifact = handle.get("artifact_type", "")
    source = handle.get("evidence_path", handle.get("path", ""))
    rows = _rows(handle)

    if artifact == "memory_systeminfo":
        # Aggregate record, not the usual one-event-per-row shape — handled
        # entirely by the helper (see its docstring for why).
        return _normalize_systeminfo(rows, source)

    # pslist/psscan: precompute cross-row context (PPID -> image, per-image
    # count) so the parent/child and masquerade rules stay PURE single-event
    # predicates. Shared across both artifact types via _process_row.
    pid_to_image: dict[str, str] = {}
    image_counts: dict[str, int] = {}
    if artifact in ("memory_pslist", "memory_psscan"):
        for r in rows:
            pid = str(_g(r, "PID", "Pid"))
            img = str(_g(r, "ImageFileName", "Name", "Process"))
            if pid:
                pid_to_image[pid] = img
            image_counts[img.lower()] = image_counts.get(img.lower(), 0) + 1

    events: list[NormEvent] = []
    for i, row in enumerate(rows):
        if artifact == "memory_url":
            # rows are plain URL strings, not dicts.
            url = str(row)
            host = ""
            try:
                from urllib.parse import urlparse
                host = (urlparse(url).hostname or "").lower()
            except Exception:
                host = ""
            events.append(NormEvent(
                artifact_type="memory_url", timestamp="", source_file=source,
                record_id=str(i), host=host, data={"url": url, "host": host}))
            continue
        if artifact in ("memory_pslist", "memory_psscan"):
            data = _process_row(row, pid_to_image, image_counts)
        elif artifact == "memory_netscan":
            data = {
                "proto": _g(row, "Proto", "Protocol"),
                "local_addr": _g(row, "LocalAddr"),
                "local_port": _g(row, "LocalPort"),
                "foreign_addr": _g(row, "ForeignAddr"),
                "foreign_port": _g(row, "ForeignPort"),
                "state": _g(row, "State"),
                "owner": _g(row, "Owner"),
                # W5-3: owning PID -- lets correlation tie the connection to
                # one process instance (pid + image), not just a name.
                "pid": _g(row, "PID", "Pid"),
            }
        elif artifact == "memory_cmdline":
            data = {
                "pid": _g(row, "PID", "Pid"),
                "process": _g(row, "Process"),
                "args": _g(row, "Args", "Cmd"),
            }
        elif artifact == "memory_envar":
            data = {
                "pid": _g(row, "PID", "Pid"),
                "process": _g(row, "Process"),
                "variable": _g(row, "Variable"),
                "value": _g(row, "Value"),
            }
        elif artifact == "memory_filescan":
            name = str(_g(row, "Name"))
            data = {"path": name, "basename": name.replace("\\", "/").rsplit("/", 1)[-1].lower(),
                    "offset": _g(row, "Offset")}
        elif artifact == "memory_malfind":
            hexdump = str(_g(row, "Hexdump", "Disasm", default=""))
            data = {
                "pid": _g(row, "PID", "Pid"),
                "process": _g(row, "Process"),
                "address": _g(row, "Start VPN", "Start", "Address"),
                # vol renders the region start as a DECIMAL int; a second
                # engine renders hex. Identity uses the page-aligned form.
                "address_canonical": _canon_addr(
                    _g(row, "Start VPN", "Start", "Address", default="")),
                "protection": str(_g(row, "Protection")),
                "tag": _g(row, "Tag"),
                "has_pe_header": _pe_header_present(hexdump),
                # vol always dumps the region; the MemProcFS path reads it from
                # the mount and can fail. Without this, a False has_pe_header
                # from a region nobody read is indistinguishable from one that
                # was read and had no MZ -- an inference wearing an
                # observation's clothes. Absent key defaults to True so
                # volatility3 rows are unaffected.
                "region_bytes_read": bool(
                    _g(row, "RegionBytesRead", default=True)),
            }
        elif artifact == "memory_svcscan":
            binary = str(_g(row, "Binary", default=""))
            data = {
                "service": _g(row, "Name"),
                "display": _g(row, "Display"),
                "binary": binary,
                "binary_lower": binary.lower(),
                "state": _g(row, "State"),
                "start": _g(row, "Start"),
                "start_canonical": _canon_start(_g(row, "Start", default="")),
                "pid": _g(row, "Pid", "PID"),
            }
        elif artifact == "memory_dlllist":
            data = {
                "pid": _g(row, "Pid", "PID"),
                "process": _g(row, "Process"),
                "dll_path": _g(row, "Path"),
                "dll_base": _g(row, "Base"),
            }
        elif artifact == "memory_modules":
            data = {
                "module": _g(row, "Name"),
                "path": _g(row, "Path"),
                "base": _g(row, "Base"),
            }
        elif artifact == "memory_hivelist":
            data = {
                "hive_path": _g(row, "FileFullPath", "Hive"),
            }
        elif artifact == "memory_regkey":
            # printkey emits both subkey rows (Type == "Key") and value rows;
            # we keep value rows (those carry the autostart command in Data).
            # vol names the column "Data"; MemProcFS's FUSE registry export
            # names it "Value". Reading only "Data" silently discarded every
            # MemProcFS autostart artifact at the rule layer (rules.py's
            # registry_persistence early-returns on empty value_data), which
            # cost the single most valuable dual-engine corroboration pair.
            _raw_key = _g(row, "Key")
            _raw_val = str(_g(row, "Data", "Value", default=""))
            data = {
                "key": _raw_key,
                # Canonical forms exist so the two engines' renderings of ONE
                # key produce one identity; the raw forms stay for display.
                "key_canonical": _canon_regkey(_raw_key),
                "value_name": _g(row, "Name"),
                "value_data": _raw_val,
                "value_canonical": _canon_regvalue(_raw_val),
                "type": _g(row, "Type"),
            }
        else:
            data = dict(row)
        events.append(NormEvent(
            artifact_type=artifact,
            timestamp=_canon_ts(_g(row, "CreateTime", default="")),
            source_file=source,
            record_id=str(i),
            host="",
            data=data,
        ))
    return events
