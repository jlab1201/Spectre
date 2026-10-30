"""W5-3 — the `process` correlation entity. Pure, no I/O, no AI.

A process reference is ``{pid, image, host, start_time}`` read verbatim off
the NormEvents behind a finding (memory pslist/psscan/netscan/cmdline/
envars/malfind/dlllist, EVTX 4688 / Sysmon 1 ``process_creation``, and any
Sysmon event carrying ``ProcessId`` + ``Image``). Phase 3 records the refs on
the finding (``process_refs``); Phase 4 clustering links findings that
reference the SAME process instance. This only LINKS existing findings: it
never creates a finding, a MITRE ID or a caveat.

Identity rules (PID reuse is real, so they are deliberately conservative):

* A ref needs a PID and an image. PID 0/4 (Idle/System) carry no identity.
* Two refs can only refer to one process if the PID and the image key
  agree. The image key is the lower-cased basename truncated to 14 chars,
  because a memory EPROCESS.ImageFileName holds only 14 characters while
  EVTX carries the full path. A bare PID match never links.
* Any other attribute KNOWN ON BOTH sides must also agree: host
  (case-insensitive), process start time (within ``START_TOLERANCE_S``) and
  the image directory when both refs carry a full path. ``\\Device\\
  HarddiskVolumeN\\`` and ``X:\\`` volume prefixes are both stripped before
  the directory compare -- the volume-to-letter mapping is not known, so the
  prefix can neither prove nor disprove a match; only the rest of the path
  is used, and only ever to BLOCK a link.
* An under-specified ref never bridges two distinct instances: if the refs
  sharing a (pid, image key) disagree on an attribute, only refs that carry
  that attribute are linked (so an untimed netscan ref for a reused PID
  links to nothing rather than joining two unrelated processes).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

START_TOLERANCE_S = 2.0
_IMAGE_KEY_LEN = 14   # EPROCESS.ImageFileName: 15 bytes incl. NUL
_NO_IDENTITY_PIDS = frozenset({0, 4})

_VOLUME_PREFIX = re.compile(
    r"^(?:\\\\\?\\|\\\?\?\\)?(?:\\device\\harddiskvolume\d+\\|[a-z]:\\)", re.I)

# artifact_type -> (pid field, image field, start-time field or None)
_MEMORY_FIELDS = {
    "memory_pslist": ("pid", "image", "create_time"),
    "memory_psscan": ("pid", "image", "create_time"),
    "memory_netscan": ("pid", "owner", None),
    "memory_cmdline": ("pid", "process", None),
    "memory_envar": ("pid", "process", None),
    "memory_malfind": ("pid", "process", None),
    "memory_dlllist": ("pid", "process", None),
}


def parse_pid(raw) -> int | None:
    """Decimal or 0x-hex (EVTX 4688 NewProcessId) -> int; else None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    s = str(raw or "").strip().lower()
    if not s:
        return None
    try:
        v = int(s, 16) if s.startswith("0x") else int(s, 10)
    except ValueError:
        return None
    return v if v >= 0 else None


def _clean_image(raw) -> str:
    s = str(raw or "").strip()
    # volatility pads some netscan owners as 'name   ***  ffff…  \Device\…';
    # the process name is what precedes the '***' padding (an owner of just
    # '***' has no process).
    if "***" in s:
        s = s.split("***", 1)[0].strip()
    return s


def image_key(image: str) -> str:
    base = str(image or "").replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
    return base.strip().lower()[:_IMAGE_KEY_LEN]


def image_dir(image: str) -> str:
    """Directory of a FULL path minus its volume prefix, lower-cased; ""
    when the image is a bare name (memory) or its volume is unrecognised."""
    s = str(image or "").replace("/", "\\").strip()
    if "\\" not in s:
        return ""
    m = _VOLUME_PREFIX.match(s)
    if not m:
        return ""
    rest = s[m.end():]
    return rest.rsplit("\\", 1)[0].lower() if "\\" in rest else "\\"


def parse_start(raw) -> datetime | None:
    s = str(raw or "").strip()
    if not s:
        return None
    s = s[:-1] + "+00:00" if s.endswith("Z") else s
    s = s[:-4] + "+00:00" if s.endswith(" UTC") else s
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ref(pid_raw, image_raw, host, start) -> list[dict]:
    pid = parse_pid(pid_raw)
    image = _clean_image(image_raw)
    if pid is None or pid in _NO_IDENTITY_PIDS or not image:
        return []
    return [{"pid": pid, "image": image, "host": str(host or "").strip(),
             "start_time": str(start or "").strip()}]


def process_refs_from_event(event) -> list[dict]:
    """The process instance(s) a single NormEvent is about. Only the
    process's OWN identity -- never its parent (a parent PID resolved from a
    later snapshot is exactly where reuse bites)."""
    at = getattr(event, "artifact_type", "")
    data = getattr(event, "data", None) or {}
    host = getattr(event, "host", "") or ""
    if at in _MEMORY_FIELDS:
        pid_f, img_f, start_f = _MEMORY_FIELDS[at]
        start = data.get(start_f, "") if start_f else ""
        return _ref(data.get(pid_f), data.get(img_f), host, start)
    if at == "process_creation":
        # 4688 / Sysmon 1: the event IS the creation, so its time is the
        # process start time.
        return _ref(data.get("process_id"), data.get("image"), host,
                    getattr(event, "timestamp", ""))
    if at == "evtx_event":
        ed = data.get("event_data") or {}
        if not isinstance(ed, dict):
            return []
        return _ref(ed.get("ProcessId"), ed.get("Image"), host, "")
    return []


def process_refs_for_events(events) -> list[dict]:
    """Union of refs over a corroborated group's member events, de-duplicated
    and sorted for byte-stable finding YAML."""
    seen: dict[tuple, dict] = {}
    for e in events:
        for r in process_refs_from_event(e):
            seen.setdefault((r["pid"], r["image"], r["host"], r["start_time"]), r)
    return [seen[k] for k in sorted(seen, key=lambda k: (k[0], k[1].lower(), k[2], k[3]))]


# ── clustering side ───────────────────────────────────────────────────────
def _coerce_ref(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    pid = parse_pid(raw.get("pid"))
    image = _clean_image(raw.get("image"))
    if pid is None or pid in _NO_IDENTITY_PIDS or not image:
        return None
    return {"pid": pid, "key": image_key(image), "dir": image_dir(image),
            "host": str(raw.get("host") or "").strip().lower(),
            "start": parse_start(raw.get("start_time"))}


def _conflicts(a: dict, b: dict) -> set[str]:
    out = set()
    if a["host"] and b["host"] and a["host"] != b["host"]:
        out.add("host")
    if a["start"] and b["start"] and \
            abs((a["start"] - b["start"]).total_seconds()) > START_TOLERANCE_S:
        out.add("start")
    if a["dir"] and b["dir"] and a["dir"] != b["dir"]:
        out.add("dir")
    return out


# A finding whose refs span more distinct process instances than this is an
# aggregate over processes (e.g. one inherited env var deduped across 19
# processes), not a statement about one process. Its refs stay on the finding
# as recorded facts, but it is not allowed to act as a hub that glues
# otherwise-unrelated per-process findings into one cluster.
MAX_PROCESSES_PER_FINDING = 3


def process_entity_groups(findings: dict[str, dict]) -> dict[str, set[str]]:
    """Map a deterministic ``process:<image> pid=<n>[ host=][ start=]`` label -> finding_ids that reference
    that one process instance (only sets with >= 2 findings are returned)."""
    by_identity: dict[tuple, list[tuple[str, dict]]] = {}
    for fid in sorted(findings):
        raw_refs = findings[fid].get("process_refs")
        if not isinstance(raw_refs, list):
            continue
        refs = [r for r in (_coerce_ref(x) for x in raw_refs) if r is not None]
        if len({(r["pid"], r["key"]) for r in refs}) > MAX_PROCESSES_PER_FINDING:
            continue
        for r in refs:
            by_identity.setdefault((r["pid"], r["key"]), []).append((fid, r))

    out: dict[str, set[str]] = {}
    for (pid, key), refs in sorted(by_identity.items()):
        n = len(refs)
        conflicting: set[str] = set()
        for i in range(n):
            for j in range(i + 1, n):
                conflicting |= _conflicts(refs[i][1], refs[j][1])

        def _usable(r: dict) -> bool:
            return all(r[attr] for attr in conflicting)

        # union-find over compatible, sufficiently-specified refs
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i in range(n):
            if not _usable(refs[i][1]):
                continue
            for j in range(i + 1, n):
                if _usable(refs[j][1]) and not _conflicts(refs[i][1], refs[j][1]):
                    parent[find(j)] = find(i)

        comps: dict[int, list[int]] = {}
        for i in range(n):
            if _usable(refs[i][1]):
                comps.setdefault(find(i), []).append(i)
        for members in comps.values():
            fids = {refs[i][0] for i in members}
            if len(fids) < 2:
                continue
            rs = [refs[i][1] for i in members]
            hosts = sorted({r["host"] for r in rs if r["host"]})
            starts = sorted(r["start"] for r in rs if r["start"])
            # Self-describing after the report strips the "process:" kind.
            label = f"process:{key} pid={pid}"
            if hosts:
                label += f" host={hosts[0]}"
            if starts:
                label += f" start={starts[0].strftime('%Y-%m-%dT%H:%M:%SZ')}"
            out.setdefault(label, set()).update(fids)
    return out
