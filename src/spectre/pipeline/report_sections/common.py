"""Shared report helpers: artifact-coverage maps, time/size formatting,
finding-timestamp parsing, finding→rule_id lookup and finding grouping.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone



# ── Artifact coverage map for case-specific blind spots ──────────────
FULL_ARTIFACT_SET = {
    "evtx": "Windows Event Logs (Security, System, Application)",
    "prefetch": "Windows Prefetch files",
    "amcache": "Windows Amcache.hve",
    "mft": "NTFS Master File Table",
    "registry": "Windows Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)",
    "memory": "Memory dump (.raw/.mem) for process/memory analysis",
    "pcap": "Network packet capture (PCAP)",
    "logfile": "Application/server log files (IIS, Apache, etc.)",
    "disk": "Disk image / filesystem forensics",
}


# ── Relevant artifact gaps per evidence type ─────────────────────────
# When building coverage gaps, only list artifacts that would realistically
# accompany the evidence present.
RELEVANT_GAPS = {
    "pcap": ["pcap", "logfile", "memory"],
    "memory": ["memory", "disk", "evtx", "registry", "prefetch", "amcache"],
    "evtx": ["evtx", "registry", "prefetch", "amcache", "disk"],
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _human_bytes(n: int) -> str:
    """Human-readable byte size (base 1024). Descriptive metadata only."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _human_duration(seconds: float) -> str:
    """Human-readable capture span. Descriptive metadata only."""
    s = float(seconds)
    if s >= 86400:
        return f"~{s / 86400:.1f} days"
    if s >= 3600:
        return f"~{s / 3600:.1f} hours"
    if s >= 60:
        return f"~{s / 60:.1f} minutes"
    return f"~{s:.0f} seconds"


def _parse_finding_ts(ts) -> "datetime | None":
    """Parse an ISO-8601 finding timestamp (event_time / first_seen / last_seen).

    Returns a datetime, or None when the value is empty or unparseable — the
    caller then omits any span rather than fabricating one. Trailing 'Z' is
    normalised to '+00:00' for datetime.fromisoformat (stdlib; no new date
    library, per the inviolable-rule scope note in the spec).
    """
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    # Normalise to UTC-naive so span arithmetic never mixes aware+naive
    # datetimes (which would raise TypeError at subtraction/max/min and abort
    # report generation). Findings usually share a tz-format, but this makes
    # the coarse span robust to a mixed pair rather than crashing Phase 6.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _finding_rule_ids(findings: list[dict], manifest: dict) -> dict[str, str]:
    """Map finding_id -> the rule_id that actually produced it.

    Two sources, preferred in order:
      1. finding['rule_id'] directly, when present (not written by today's
         emit_finding.py, but kept as the natural place a future schema
         addition — or a test fixture — would put it).
      2. manifest['detection']['findings'][*]['rule_id'] — the SAME
         per-finding record phase_runner.py's Phase 3 loop builds as
         findings_summary and stamps onto the manifest. This is the actual
         deterministic ground truth for every real case: finding YAMLs on
         disk carry forensic_caveats/mitre_attack/etc but never persist
         rule_id, so this is the only place it survives past Phase 3.

    Callers must treat a missing entry as "unknown", never guess — that is
    exactly the case-268-001 bug (a MITRE-technique-level guess silently
    standing in for the finding's real rule, misattributing pcap-c2-protocol
    findings to pcap-suspicious-port and the pcap-large-transfer marquee
    finding to pcap-staging-download, because both technique groups happen
    to share a rule keyed on the SAME MITRE technique).
    """
    out: dict[str, str] = {}
    for f in findings:
        fid = f.get("finding_id")
        rid = f.get("rule_id")
        if fid and rid:
            out[fid] = rid
    for rec in (manifest.get("detection") or {}).get("findings") or []:
        fid = rec.get("finding_id")
        rid = rec.get("rule_id")
        if fid and rid:
            out.setdefault(fid, rid)
    return out


def _build_finding_groups(findings: list[dict]) -> dict[str, dict]:
    """Group findings by (mitre_attack, dedup_category).
    Returns {group_label: {findings: [...], technique: str, confidence_range: str}}."""
    groups: dict[str, dict] = defaultdict(lambda: {"findings": [], "technique": "", "max_conf": 0.0})
    for f in findings:
        mitre = f.get("mitre_attack", "UNMAPPED")
        # Category: first segment of the title (before any colon or paren)
        title = f.get("title", "?")
        category = title.split(":")[0].split("(")[0].strip()
        group_key = f"{mitre}:{category}" if category else mitre
        g = groups[group_key]
        g["findings"].append(f)
        g["technique"] = mitre
        g["max_conf"] = max(g["max_conf"], f.get("confidence", 0))
    return dict(groups)
