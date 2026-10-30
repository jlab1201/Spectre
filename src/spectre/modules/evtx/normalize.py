"""
evtx/normalize.py — parse evtxexport XML output into NormEvents.

evtxexport -f xml emits a leading version banner, then a sequence of
<Event>...</Event> blocks (Windows Event XML, default namespace). This
module parses each block and maps several schemas into unified,
source-agnostic NormEvent shapes so detection rules never touch raw XML:

  - Sysmon EventID 1 / Security 4688 (process creation)    -> process_creation
  - Security 1102 / System 104      (audit/system log cleared) -> evtx_log_cleared
  - System 7045                     (service installed)     -> evtx_service_install
  - Microsoft-Windows-PowerShell/Operational 4104 (scriptblock) -> evtx_scriptblock

Security 4624/4625 (logon success/failure) are NOT given a per-event schema:
a single logon or logon-failure event is rarely interesting on its own and a
per-event rule would flood a finding per authentication attempt. Instead this
module aggregates them across the whole file (per source IP for 4625
brute-force, per source-IP+account for a non-local 4624 RDP logon) into ONE
synthetic NormEvent per group, emitted alongside (not instead of) their raw
generic form.

Any other event ID is emitted as a generic `evtx_event` NormEvent carrying
its raw System + EventData fields, so nothing is silently dropped.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from spectre.core.base import NormEvent

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.DOTALL)

# EventIDs we lift into the unified process_creation schema.
_SYSMON_PROCESS_CREATE = 1
_SECURITY_PROCESS_CREATE = 4688

# EventIDs given their own dedicated per-event schema.
_SECURITY_LOG_CLEARED = 1102
_SYSTEM_LOG_CLEARED = 104
_SECURITY_SERVICE_INSTALL = 7045
_POWERSHELL_SCRIPTBLOCK = 4104

# EventIDs that feed the cross-event logon aggregation pass instead of a
# dedicated per-event schema (see module docstring).
_LOGON_SUCCESS = 4624
_LOGON_FAILURE = 4625

# Windows logon type code for RDP / Terminal Services (Interactive=2,
# Network=3, RemoteInteractive=10). Only 10 is treated as a lateral-movement
# lead here.
_LOGON_TYPE_RDP = "10"

# Values IpAddress carries for a local/loopback logon (no real source host to
# report) — never counted as a "non-local source" for the RDP lead.
_LOCAL_LOGON_SOURCES = {"-", "", "127.0.0.1", "::1", "localhost"}

# Brute-force aggregation thresholds (evtx-bruteforce-logon rule). Kept here,
# not in rules.py, because the aggregation itself (which groups raw 4625
# records into one synthetic NormEvent) has to apply the same window before a
# rule ever sees the data — the rule just reads the group's count field.
BRUTE_FORCE_MIN_FAILURES = 10
BRUTE_FORCE_WINDOW_MINUTES = 10

# Channels _map_record can structurally produce a dedicated (non-generic)
# NormEvent from. A channel outside this set that shows seen>0, parsed==0 is
# genuinely unsupported; a channel inside this set with the same stats simply
# had no matching events in the file (an evidence fact, not a parser
# limitation).
_SUPPORTED_CHANNELS = {
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
}


def _localname(tag: str) -> str:
    """Strip XML namespace: '{ns}EventID' -> 'EventID'."""
    return tag.rsplit("}", 1)[-1]


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _parse_event(block: str) -> dict | None:
    """Parse one <Event> XML block into a flat dict of System + EventData."""
    try:
        root = ET.fromstring(block)
    except ET.ParseError:
        return None

    system: dict = {}
    event_data: dict = {}
    for child in root:
        name = _localname(child.tag)
        if name == "System":
            for s in child:
                sname = _localname(s.tag)
                if sname == "TimeCreated":
                    system["TimeCreated"] = s.attrib.get("SystemTime", "")
                elif sname == "Provider":
                    system["Provider"] = s.attrib.get("Name", "")
                elif sname == "Execution":
                    system["ProcessID"] = s.attrib.get("ProcessID", "")
                elif sname == "Security":
                    system["UserID"] = s.attrib.get("UserID", "")
                else:
                    system[sname] = (s.text or "").strip()
        elif name == "EventData":
            for d in child:
                key = d.attrib.get("Name")
                if key:
                    event_data[key] = (d.text or "").strip()
        elif name == "UserData":
            # Events such as 1102/104 keep their fields here, as a flat set of
            # named child elements under one wrapper (e.g. <LogFileCleared>).
            for wrapper in child:
                for d in wrapper:
                    if len(d) == 0:
                        event_data.setdefault(_localname(d.tag), (d.text or "").strip())
    return {"System": system, "EventData": event_data}


# (channel, provider) guards for events with a dedicated schema. A None
# provider means only the channel is checked. EventIDs are not unique across
# channels/providers (any application may log 104 to Application), so the ID
# alone must never route a record.
_EVENT_GUARDS: dict[int, tuple[str, str | None]] = {
    _SECURITY_LOG_CLEARED: ("Security", "Microsoft-Windows-Eventlog"),
    _SYSTEM_LOG_CLEARED: ("System", "Microsoft-Windows-Eventlog"),
    _SECURITY_SERVICE_INSTALL: ("System", "Service Control Manager"),
    _POWERSHELL_SCRIPTBLOCK: ("Microsoft-Windows-PowerShell/Operational", None),
    _LOGON_SUCCESS: ("Security", None),
    _LOGON_FAILURE: ("Security", None),
}


def _guard_ok(rec: dict, event_id: int) -> bool:
    guard = _EVENT_GUARDS.get(event_id)
    if guard is None:
        return True
    channel, provider = guard
    sysd = rec["System"]
    if sysd.get("Channel", "") != channel:
        return False
    return provider is None or sysd.get("Provider", "") == provider


def _to_process_creation(rec: dict, source_file: str, event_id: int) -> NormEvent:
    """Map Sysmon-1 or Security-4688 into the unified process_creation schema."""
    sysd = rec["System"]
    ed = rec["EventData"]

    if event_id == _SYSMON_PROCESS_CREATE:
        image = ed.get("Image", "")
        cmdline = ed.get("CommandLine", "")
        parent_image = ed.get("ParentImage", "")
        parent_cmd = ed.get("ParentCommandLine", "")
        pid = ed.get("ProcessId", "")
        ppid = ed.get("ParentProcessId", "")
        user = ed.get("User", "")
        integrity = ed.get("IntegrityLevel", "")
        hashes = ed.get("Hashes", "")
    else:  # Security 4688
        image = ed.get("NewProcessName", "")
        cmdline = ed.get("CommandLine", "")
        parent_image = ed.get("ParentProcessName", "")
        parent_cmd = ""
        pid = ed.get("NewProcessId", "")
        ppid = ed.get("ProcessId", "")
        user = ed.get("SubjectUserName", "")
        integrity = ed.get("MandatoryLabel", "")
        hashes = ""

    data = {
        "event_id": event_id,
        "provider": sysd.get("Provider", ""),
        "channel": sysd.get("Channel", ""),
        "image": image,
        "image_basename": _basename(image),
        "command_line": cmdline,
        "command_line_lower": cmdline.lower(),
        "parent_image": parent_image,
        "parent_basename": _basename(parent_image),
        "parent_command_line": parent_cmd,
        "process_id": pid,
        "parent_process_id": ppid,
        "user": user,
        "integrity_level": integrity,
        "hashes": hashes,
    }
    return NormEvent(
        artifact_type="process_creation",
        timestamp=sysd.get("TimeCreated", ""),
        source_file=source_file,
        record_id=sysd.get("EventRecordID", ""),
        host=sysd.get("Computer", ""),
        data=data,
    )


def _to_log_cleared(rec: dict, source_file: str, event_id: int) -> NormEvent:
    """1102 (Security audit log cleared) / 104 (System: any log cleared)."""
    sysd = rec["System"]
    ed = rec["EventData"]
    # 104 carries the name of the cleared channel in UserData/LogFileCleared;
    # never assume it (the 104 record itself lives in System). 1102 is specific
    # to the Security log by definition.
    cleared_channel = ed.get("Channel", "") or (
        "Security" if event_id == _SECURITY_LOG_CLEARED else "")
    data = {
        "event_id": event_id,
        "provider": sysd.get("Provider", ""),
        "channel": sysd.get("Channel", ""),
        "cleared_channel": cleared_channel,
        "subject_user": ed.get("SubjectUserName", ""),
        "subject_domain": ed.get("SubjectDomainName", ""),
        "backup_path": ed.get("BackupPath", ""),
    }
    return NormEvent(
        artifact_type="evtx_log_cleared",
        timestamp=sysd.get("TimeCreated", ""),
        source_file=source_file,
        record_id=sysd.get("EventRecordID", ""),
        host=sysd.get("Computer", ""),
        data=data,
    )


def _to_service_install(rec: dict, source_file: str) -> NormEvent:
    """7045 (Service Control Manager: a new service was installed)."""
    sysd = rec["System"]
    ed = rec["EventData"]
    image_path = ed.get("ImagePath", "")
    service_name = ed.get("ServiceName", "")
    data = {
        "event_id": _SECURITY_SERVICE_INSTALL,
        "provider": sysd.get("Provider", ""),
        "channel": sysd.get("Channel", ""),
        "service_name": service_name,
        "service_name_lower": service_name.lower(),
        "image_path": image_path,
        "image_path_lower": image_path.lower(),
        "service_type": ed.get("ServiceType", ""),
        "start_type": ed.get("StartType", ""),
        "account_name": ed.get("AccountName", ""),
    }
    return NormEvent(
        artifact_type="evtx_service_install",
        timestamp=sysd.get("TimeCreated", ""),
        source_file=source_file,
        record_id=sysd.get("EventRecordID", ""),
        host=sysd.get("Computer", ""),
        data=data,
    )


def _to_scriptblock(rec: dict, source_file: str) -> NormEvent:
    """4104 (PowerShell ScriptBlock logging)."""
    sysd = rec["System"]
    ed = rec["EventData"]
    text = ed.get("ScriptBlockText", "")
    data = {
        "event_id": _POWERSHELL_SCRIPTBLOCK,
        "provider": sysd.get("Provider", ""),
        "channel": sysd.get("Channel", ""),
        "script_block_text": text,
        "script_block_text_lower": text.lower(),
        "script_block_id": ed.get("ScriptBlockId", ""),
        "user_sid": sysd.get("UserID", ""),
        "message_number": ed.get("MessageNumber", ""),
        "message_total": ed.get("MessageTotal", ""),
        "path": ed.get("Path", ""),
    }
    return NormEvent(
        artifact_type="evtx_scriptblock",
        timestamp=sysd.get("TimeCreated", ""),
        source_file=source_file,
        record_id=sysd.get("EventRecordID", ""),
        host=sysd.get("Computer", ""),
        data=data,
    )


def _parse_ts(ts: str) -> datetime | None:
    """Parse a Windows Event XML TimeCreated SystemTime into a datetime.

    Returns None on anything unparseable — the caller drops that record from
    windowing (it is never dropped from the raw/generic event stream, only
    from the aggregate this parses for).
    """
    if not ts:
        return None
    t = ts.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return None


def _collect_logon_record(rec: dict) -> dict | None:
    """Pull the fields the logon aggregation passes need from a 4624/4625
    record. Returns None when TimeCreated cannot be parsed (fail-safe: that
    record simply cannot be windowed, but it was already preserved via
    _to_generic elsewhere)."""
    sysd = rec["System"]
    ed = rec["EventData"]
    ts = _parse_ts(sysd.get("TimeCreated", ""))
    if ts is None:
        return None
    return {
        "ts": ts,
        "host": sysd.get("Computer", ""),
        "logon_type": ed.get("LogonType", ""),
        "ip": (ed.get("IpAddress", "") or "").strip(),
        "account": ed.get("TargetUserName", ""),
        "domain": ed.get("TargetDomainName", ""),
    }


def _max_window(times: list[datetime], window: timedelta):
    """Return (count, first, last) for the densest window of length `window`
    in a SORTED list of datetimes. Deterministic: a strict `>` comparison
    means the first (earliest) window to reach a given count wins ties."""
    if not times:
        return None
    best = (1, times[0], times[0])
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, times[left], times[right])
    return best


def _aggregate_failed_logons(records: list[dict], source_file: str) -> list[NormEvent]:
    """Group 4625 (logon failure) records by source IP; emit ONE aggregate
    NormEvent per source IP whose densest BRUTE_FORCE_WINDOW_MINUTES window
    reaches BRUTE_FORCE_MIN_FAILURES failures (evtx-bruteforce-logon, T1110).

    Failures with no real source (blank, "-", loopback) are excluded: they
    have no attributable source host, so pooling them would fabricate a
    "source".
    """
    groups: dict[str, list[dict]] = {}
    for r in records:
        ip = r["ip"]
        if not ip or ip in _LOCAL_LOGON_SOURCES:
            continue
        groups.setdefault(ip, []).append(r)

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    out: list[NormEvent] = []
    for ip in sorted(groups):
        recs = sorted(groups[ip], key=lambda r: r["ts"])
        best = _max_window([r["ts"] for r in recs], window)
        if best is None or best[0] < BRUTE_FORCE_MIN_FAILURES:
            continue
        count, first, last = best
        accounts = sorted({r["account"] for r in recs if r["account"]})
        out.append(NormEvent(
            artifact_type="evtx_4625_aggregate",
            timestamp=last.isoformat(),
            source_file=source_file,
            record_id="",
            host=recs[0]["host"],
            data={
                "event_id": _LOGON_FAILURE,
                "source_ip": ip,
                "count": count,
                "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
                "first_seen": first.isoformat(),
                "last_seen": last.isoformat(),
                "target_accounts": accounts,
            },
        ))
    return out


def _aggregate_rdp_logons(records: list[dict], source_file: str) -> list[NormEvent]:
    """Group 4624 (logon success) records with LogonType 10 (RemoteInteractive
    / RDP) from a non-local source by (source IP, account); emit ONE
    aggregate NormEvent per group (evtx-rdp-remote-logon, T1021.001).

    No minimum count — a single RDP logon from a remote address is already
    the honest lead; the aggregation exists only to avoid one finding per
    session-keepalive/reconnect event, not to gate on volume.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in records:
        if r["logon_type"] != _LOGON_TYPE_RDP:
            continue
        ip = r["ip"]
        if not ip or ip in _LOCAL_LOGON_SOURCES:
            continue
        groups.setdefault((ip, r["account"] or ""), []).append(r)

    out: list[NormEvent] = []
    for key in sorted(groups):
        ip, account = key
        recs = sorted(groups[key], key=lambda r: r["ts"])
        first, last = recs[0]["ts"], recs[-1]["ts"]
        out.append(NormEvent(
            artifact_type="evtx_4624_rdp_aggregate",
            timestamp=last.isoformat(),
            source_file=source_file,
            record_id="",
            host=recs[0]["host"],
            data={
                "event_id": _LOGON_SUCCESS,
                "logon_type": _LOGON_TYPE_RDP,
                "source_ip": ip,
                "account": account,
                "count": len(recs),
                "first_seen": first.isoformat(),
                "last_seen": last.isoformat(),
            },
        ))
    return out


def _to_generic(rec: dict, source_file: str, event_id: int) -> NormEvent:
    sysd = rec["System"]
    return NormEvent(
        artifact_type="evtx_event",
        timestamp=sysd.get("TimeCreated", ""),
        source_file=source_file,
        record_id=sysd.get("EventRecordID", ""),
        host=sysd.get("Computer", ""),
        data={
            "event_id": event_id,
            "provider": sysd.get("Provider", ""),
            "channel": sysd.get("Channel", ""),
            "event_data": rec["EventData"],
        },
    )


def normalize_text_with_stats(
    xml_text: str, source_file: str = ""
) -> tuple[list[NormEvent], dict[str, dict[str, int]]]:
    """Parse the full evtxexport XML output text into NormEvents, plus
    per-channel seen/parsed accounting.

    "seen" counts every record encountered for that Channel. "parsed" counts
    records mapped into one of this module's dedicated per-event schemas
    (process_creation, evtx_log_cleared, evtx_service_install,
    evtx_scriptblock). 4624/4625 (logon) deliberately do NOT bump "parsed"
    here even though this module does read them (into the cross-event
    aggregation pass below): they have no 1:1 per-event schema of their own,
    only a whole-file aggregate, so per-event they are honestly "seen" in a
    supported channel rather than "parsed". Any other event ID/channel still
    emits a generic `evtx_event` NormEvent (nothing is dropped), reported as
    seen-not-parsed so unsupported channels stay visible instead of silently
    no-op'ing.
    """
    events: list[NormEvent] = []
    logon_records: list[dict] = []
    stats: dict[str, dict[str, int]] = {}
    for block in _EVENT_RE.findall(xml_text):
        rec = _parse_event(block)
        if rec is None:
            continue
        try:
            event_id = int(rec["System"].get("EventID", "0") or 0)
        except ValueError:
            event_id = 0
        channel = rec["System"].get("Channel", "?") or "?"
        chan_stats = stats.setdefault(
            channel,
            {"seen": 0, "parsed": 0, "supported": channel in _SUPPORTED_CHANNELS},
        )
        chan_stats["seen"] += 1
        if event_id in (_SYSMON_PROCESS_CREATE, _SECURITY_PROCESS_CREATE):
            events.append(_to_process_creation(rec, source_file, event_id))
            chan_stats["parsed"] += 1
        elif event_id in (_SECURITY_LOG_CLEARED, _SYSTEM_LOG_CLEARED) and _guard_ok(rec, event_id):
            events.append(_to_log_cleared(rec, source_file, event_id))
            chan_stats["parsed"] += 1
        elif event_id == _SECURITY_SERVICE_INSTALL and _guard_ok(rec, event_id):
            events.append(_to_service_install(rec, source_file))
            chan_stats["parsed"] += 1
        elif event_id == _POWERSHELL_SCRIPTBLOCK and _guard_ok(rec, event_id):
            events.append(_to_scriptblock(rec, source_file))
            chan_stats["parsed"] += 1
        else:
            events.append(_to_generic(rec, source_file, event_id))
            if event_id in (_LOGON_SUCCESS, _LOGON_FAILURE) and _guard_ok(rec, event_id):
                logon_rec = _collect_logon_record(rec)
                if logon_rec is not None:
                    logon_records.append(logon_rec)

    events.extend(_aggregate_failed_logons(logon_records, source_file))
    events.extend(_aggregate_rdp_logons(logon_records, source_file))
    return events, stats


def normalize_text(xml_text: str, source_file: str = "") -> list[NormEvent]:
    """Parse the full evtxexport XML output text into NormEvents.

    Thin back-compat wrapper around `normalize_text_with_stats` — kept for
    direct callers (tests, other modules) that only want the event list.
    """
    events, _stats = normalize_text_with_stats(xml_text, source_file=source_file)
    return events


def normalize(handle: dict) -> list[NormEvent]:
    """Module entrypoint: read an extraction handle's output file."""
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    xml_text = Path(path).read_text(errors="replace")
    source = handle.get("evidence_path", path)
    events, stats = normalize_text_with_stats(xml_text, source_file=source)
    handle["channel_stats"] = stats
    return events
