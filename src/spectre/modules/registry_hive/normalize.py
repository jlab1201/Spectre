"""registry_hive/normalize.py — parse RegRipper `-a` text into registry_run
NormEvents.

RegRipper's `run` plugin (and its Run/RunOnce-reporting siblings) prints each
autostart key under a non-indented key-path header — typically
`Software\\Microsoft\\Windows\\CurrentVersion\\Run`, but plugins vary and some
prefix it with a hive root (`HKLM\\...\\Run`, `NTUSER.DAT\\...\\RunOnce`). The
header is followed by a `LastWrite Time ...` line and then one indented
`  <value name> - <value data>` line per autostart entry, or a lone
`(empty)` marker when the key has no values.

This parser is deliberately narrow: it only tracks a "current key" while
inside a header line ending in `\\Run` or `\\RunOnce`, and it emits nothing
for anything else — unrecognized headers, the `(empty)` marker, or entry
lines that don't match the `name - data` shape. RegRipper output for other
plugins (autostart services, shellbags, etc.) passes through untouched;
future plugins get their own parser instead of this one guessing at their
shape.

W5-2 adds three such plugin parsers, each keyed on RegRipper's plugin banner
(`<name> v.<YYYYMMDD>`) and bounded by its dashed separator line:

  - `services`              -> `registry_service` NormEvents (one per service)
  - `appcompatcache`/`shimcache` -> `shimcache` NormEvents (one per cache row;
    both plugins print the SAME cache, so rows are de-duplicated)
  - `amcache`               -> `amcache` NormEvents (InventoryApplicationFile
    rows on Win10+, `File Reference` rows on the older Win8-era format)

Each emits nothing for lines it does not recognise. appcompatcache.pl walks a
Perl hash (`keys %files`), so its line order is neither stable run to run nor
the cache's real insertion order — no cache position is recorded, and every
section's events are emitted in a sorted, deterministic order.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from spectre.core.base import NormEvent

ARTIFACT = "registry_run"

# Header line for an autostart key: any non-indented line ending in
# \Run or \RunOnce. The prefix (Software\, HKLM\, NTUSER.DAT\, ...) varies
# by plugin/hive; only the trailing key name is stable enough to key off.
_KEY_RE = re.compile(r".+\\(Run|RunOnce)$", re.IGNORECASE)

# One autostart value: "<name> - <data>" (RegRipper's standard delimiter).
_ENTRY_RE = re.compile(r"^(.+?)\s+-\s+(.+)$")

_EMPTY_MARKERS = {"(empty)", ""}


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _parse_lastwrite_time(raw_ts: str) -> str:
    """Convert RegRipper timestamp to ISO8601 UTC.

    Handles:
    - "2026-01-15 10:22:33Z" (ISO-like with Z)
    - "Mon Jan 15 10:22:33 2026 (UTC)" (day-name format)

    Returns ISO8601 UTC ("YYYY-MM-DDTHH:MM:SS+00:00") or "" if unparseable.
    """
    if not raw_ts or not raw_ts.strip():
        return ""

    raw_ts = raw_ts.strip()

    # Format 1: "2026-01-15 10:22:33Z"
    if raw_ts.endswith("Z") and " " in raw_ts:
        try:
            dt = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%SZ")
            return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        except ValueError:
            pass

    # Format 2: "Mon Jan 15 10:22:33 2026 (UTC)" or similar
    # Remove the trailing "(UTC)" or "(utc)" if present
    ts_clean = raw_ts
    if "(" in ts_clean and ")" in ts_clean:
        ts_clean = ts_clean[: ts_clean.rfind("(")].strip()

    # Try to parse with weekday
    try:
        dt = datetime.strptime(ts_clean, "%a %b %d %H:%M:%S %Y")
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    except ValueError:
        pass

    return ""


def normalize(handle: dict) -> list[NormEvent]:
    """Module entrypoint: read RegRipper's `-a` text output."""
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    source = handle.get("evidence_path", path)
    hive = _basename(source)
    text = Path(path).read_text(errors="replace")
    return (_parse(text, source, hive)
            + _parse_plugin_sections(text, source, hive))


def _parse(text: str, source: str, hive: str) -> list[NormEvent]:
    events: list[NormEvent] = []
    current_key: str | None = None
    current_ts = ""
    current_ts_raw = ""
    n = 0
    for raw in text.splitlines():
        if not raw.strip():
            # Blank line ends the current section.
            current_key = None
            current_ts = ""
            current_ts_raw = ""
            continue

        stripped = raw.strip()

        # RegRipper does not always indent the "LastWrite Time" line under
        # its key header, so this is checked before the indentation test —
        # it must not be mistaken for a new (unrecognized) header, which
        # would drop the current_key and orphan the entries that follow.
        if stripped.lower().startswith("lastwrite time"):
            parts = stripped.split(None, 2)
            raw_ts = parts[2] if len(parts) == 3 else ""
            current_ts_raw = raw_ts
            current_ts = _parse_lastwrite_time(raw_ts)
            continue

        indented = raw[:1] in (" ", "\t")

        if not indented:
            current_key = stripped if _KEY_RE.match(stripped) else None
            current_ts = ""
            current_ts_raw = ""
            continue

        if current_key is None:
            continue  # indented line outside any recognized key — ignore

        if stripped in _EMPTY_MARKERS:
            continue

        m = _ENTRY_RE.match(stripped)
        if not m:
            continue  # doesn't match "name - data" — don't guess

        value_name, value_data = m.group(1).strip(), m.group(2).strip()
        if not value_name or not value_data:
            continue

        n += 1
        events.append(NormEvent(
            artifact_type=ARTIFACT,
            timestamp=current_ts,
            source_file=source,
            record_id=str(n),
            data={
                "key": current_key,
                "value_name": value_name,
                "value_data": value_data,
                "hive": hive,
                "lastwrite_raw": current_ts_raw,
            },
        ))
    return events


# ── W5-2: plugin-section parsers (services / shimcache / amcache) ─────────

_BANNER_RE = re.compile(r"^([A-Za-z0-9_]+) v\.(\d{8})\s*$")
_SEPARATOR_RE = re.compile(r"^-{20,}\s*$")

_SERVICES_PLUGINS = {"services"}
_SHIMCACHE_PLUGINS = {"appcompatcache", "shimcache"}
_AMCACHE_PLUGINS = {"amcache"}

# "Tue Apr 15 09:06:00 2025 Z" (Perl gmtime; single-digit days are
# space-padded: "Thu Mar  6 ...").
_GMTIME_RE = re.compile(
    r"^[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4}(?: Z)?$")
_KV_RE = re.compile(r"^\s+([A-Za-z]+)\s*=\s?(.*)$")
_ISO_RE = re.compile(r"(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)Z?")

# ShimCache row: a path (drive, UNC, \??\, SYSVOL\ or env-var rooted)
# followed by double-space separated fields.
_SHIM_PATH_START = re.compile(r"^(?:[A-Za-z]:\\|\\\\|\\\?\?\\|SYSVOL\\|%)")

# Amcache InventoryApplicationFile row: "<path>  LastWrite: <iso>Z"
_AMC_INV_RE = re.compile(r"^(.+?)\s+LastWrite:\s+(.+)$")
_AMC_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 -]*?)\s*:\s(.*)$")


def _iso(raw: str) -> str:
    """'2025-03-20 08:56:52Z' / '2025-03-20T08:56:52' -> ISO8601 UTC, or ''."""
    m = _ISO_RE.search(raw or "")
    if not m:
        return ""
    return f"{m.group(1)}T{m.group(2)}+00:00"


def _gmtime_iso(raw: str) -> str:
    parts = raw.replace(" Z", "").split()
    try:
        dt = datetime.strptime(" ".join(parts), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _sections(text: str) -> list[tuple[str, list[str]]]:
    """[(plugin_name_lower, body_lines)] in output order."""
    out: list[tuple[str, list[str]]] = []
    name: str | None = None
    body: list[str] = []
    for raw in text.splitlines():
        m = _BANNER_RE.match(raw)
        if m and not raw[:1].isspace():
            if name is not None:
                out.append((name, body))
            name, body = m.group(1).lower(), []
            continue
        if _SEPARATOR_RE.match(raw):
            if name is not None:
                out.append((name, body))
            name, body = None, []
            continue
        if name is not None:
            body.append(raw)
    if name is not None:
        out.append((name, body))
    return out


def _parse_plugin_sections(text: str, source: str, hive: str) -> list[NormEvent]:
    svc: list[dict] = []
    shim: dict[tuple[str, str], dict] = {}
    amc: dict[tuple[str, str, str], dict] = {}
    for name, body in _sections(text):
        if name in _SERVICES_PLUGINS:
            svc.extend(_services_rows(body))
        elif name in _SHIMCACHE_PLUGINS:
            for row in _shimcache_rows(body):
                shim.setdefault((row["path_lower"], row["file_mtime"]), row)
        elif name in _AMCACHE_PLUGINS:
            for row in _amcache_rows(body):
                amc.setdefault((row["path_lower"], row["timestamp"],
                                row["sha1"]), row)

    events: list[NormEvent] = []
    svc_sorted = sorted(svc, key=lambda r: (r["key"], r["service_name_lower"],
                                            r["timestamp"], r["image_path_lower"]))
    seen_svc: set[tuple] = set()
    n = 0
    for r in svc_sorted:
        k = (r["key"], r["service_name_lower"], r["timestamp"], r["image_path_lower"])
        if k in seen_svc:
            continue
        seen_svc.add(k)
        n += 1
        ts = r.pop("timestamp")
        events.append(NormEvent(artifact_type="registry_service", timestamp=ts,
                                source_file=source, record_id=f"svc-{n}",
                                data={**r, "hive": hive}))
    for n, key in enumerate(sorted(shim), start=1):
        r = shim[key]
        events.append(NormEvent(artifact_type="shimcache", timestamp=r["file_mtime"],
                                source_file=source, record_id=f"shim-{n}",
                                data={**r, "hive": hive}))
    for n, key in enumerate(sorted(amc), start=1):
        r = dict(amc[key])
        ts = r.pop("timestamp")
        events.append(NormEvent(artifact_type="amcache", timestamp=ts,
                                source_file=source, record_id=f"amc-{n}",
                                data={**r, "key_lastwrite": ts, "hive": hive}))
    return events


_SVC_FIELDS = {"name": "service_name", "display": "display_name",
               "imagepath": "image_path", "type": "service_type",
               "start": "start_type", "group": "group",
               "failurecommand": "failure_command"}


def _services_rows(body: list[str]) -> list[dict]:
    rows: list[dict] = []
    key = ""
    ts = ""
    ts_raw = ""
    cur: dict | None = None

    def flush():
        nonlocal cur
        if cur and cur.get("service_name"):
            cur.setdefault("image_path", "")
            cur.setdefault("failure_command", "")
            rows.append({
                "key": key,
                "service_name": cur["service_name"],
                "service_name_lower": cur["service_name"].lower(),
                "display_name": cur.get("display_name", ""),
                "image_path": cur["image_path"],
                "image_path_lower": cur["image_path"].lower(),
                "service_type": cur.get("service_type", ""),
                "start_type": cur.get("start_type", ""),
                "group": cur.get("group", ""),
                "failure_command": cur["failure_command"],
                "lastwrite_raw": cur["lastwrite_raw"],
                "timestamp": cur["timestamp"],
            })
        cur = None

    for raw in body:
        stripped = raw.strip()
        if not stripped:
            flush()
            continue
        if raw[:1].isspace():
            m = _KV_RE.match(raw)
            if not m:
                continue
            field = _SVC_FIELDS.get(m.group(1).lower())
            if field is None:
                continue
            if field == "service_name":
                flush()
                cur = {"lastwrite_raw": ts_raw, "timestamp": ts}
            if cur is None:
                continue
            cur[field] = m.group(2).strip()
            continue
        # Non-indented: a LastWrite group header or the Services key path.
        if _GMTIME_RE.match(stripped):
            flush()
            ts_raw = stripped
            ts = _gmtime_iso(stripped)
        elif stripped.lower().endswith("\\services"):
            key = stripped
    flush()
    return rows


def _shimcache_rows(body: list[str]) -> list[dict]:
    rows: list[dict] = []
    key_lastwrite = ""
    controlset = ""
    for raw in body:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or "\t" in line:
            continue  # blank / UWP package row
        if stripped.startswith("***") and stripped.endswith("***"):
            controlset = stripped.strip("* ").strip()
            continue
        if stripped.lower().startswith("lastwrite time"):
            key_lastwrite = _iso(stripped)
            continue
        if not _SHIM_PATH_START.match(stripped):
            continue  # description, key path, Signature:, OS banner, ...
        parts = [p.strip() for p in stripped.split("  ") if p.strip()]
        path = parts[0]
        rest = parts[1:]
        mtime = ""
        if rest and _ISO_RE.match(rest[0]):
            mtime = _iso(rest[0])
            rest = rest[1:]
        executed = None
        if any(p.lower() == "executed" for p in rest):
            executed = True
        rows.append({
            "path": path,
            "path_lower": path.lower(),
            "basename_lower": _basename(path).lower(),
            "file_mtime": mtime,
            "executed_flag": executed,
            "controlset": controlset,
            "key_lastwrite": key_lastwrite,
        })
    # Win7/2008R2 caches carry an execution flag; when any row in this
    # cache has it, an absent flag is an explicit "not flagged" (False),
    # not "unknown" (None, the Win8+/Win10 case with no flag at all).
    if any(r["executed_flag"] for r in rows):
        for r in rows:
            if r["executed_flag"] is None:
                r["executed_flag"] = False
    return rows


def _amcache_rows(body: list[str]) -> list[dict]:
    rows: list[dict] = []
    mode = ""
    inv: dict | None = None
    legacy: dict | None = None

    def flush_legacy():
        nonlocal legacy
        if legacy and legacy.get("path"):
            rows.append(_amc_row(legacy["path"], legacy.get("lastwrite", ""),
                                 legacy.get("sha1", ""), "File",
                                 compile_time=legacy.get("compile_time", "")))
        legacy = None

    for raw in body:
        stripped = raw.strip()
        if stripped.startswith("***") and stripped.endswith("***"):
            flush_legacy()
            mode = stripped.strip("*")
            continue
        if mode == "InventoryApplicationFile":
            if stripped.lower().startswith("hash:") and inv is not None:
                inv["sha1"] = stripped.split(":", 1)[1].strip()
                rows.append(_amc_row(inv["path"], inv["lastwrite"], inv["sha1"],
                                     "InventoryApplicationFile"))
                inv = None
                continue
            m = _AMC_INV_RE.match(stripped)
            if m:
                if inv is not None:  # previous row had no Hash: line
                    rows.append(_amc_row(inv["path"], inv["lastwrite"], "",
                                         "InventoryApplicationFile"))
                inv = {"path": m.group(1).strip(), "lastwrite": _iso(m.group(2))}
            continue
        if mode == "Files":
            if not stripped:
                flush_legacy()
                continue
            m = _AMC_FIELD_RE.match(stripped)
            if not m:
                continue
            fname, val = m.group(1).strip().lower(), m.group(2).strip()
            if fname == "file reference":
                flush_legacy()
                legacy = {}
            elif legacy is None:
                continue
            elif fname == "lastwrite":
                legacy["lastwrite"] = _iso(val)
            elif fname == "path":
                legacy["path"] = val
            elif fname == "sha-1":
                legacy["sha1"] = val
            elif fname == "compile time":
                legacy["compile_time"] = _iso(val)
    if inv is not None:
        rows.append(_amc_row(inv["path"], inv["lastwrite"], "",
                             "InventoryApplicationFile"))
    flush_legacy()
    return rows


def _amc_row(path: str, lastwrite: str, sha1: str, fmt: str,
             compile_time: str = "") -> dict:
    sha1 = (sha1 or "").strip().lower()
    if len(sha1) == 44 and sha1.startswith("0000"):
        sha1 = sha1[4:]  # FileId / value 101 carry a 4-zero prefix
    return {
        "path": path,
        "path_lower": path.lower(),
        "basename_lower": _basename(path).lower(),
        "sha1": sha1,
        "entry_format": fmt,
        "compile_time": compile_time,
        "timestamp": lastwrite,
    }
