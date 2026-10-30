"""Cross-artifact clustering (Spec B). Pure, no I/O.

Links findings across evidence types by shared normalized entity (IOC overlap)
and by temporal proximity, via connected components. Surfaces relationships as
FACTS only — never mutates findings or their confidence (see the design spec's
inviolable-rule constraint).
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

from spectre.core.validators import finding_artifact_types
from spectre.pipeline.correlation.process import process_entity_groups

_ENTITY_KEYS = ("filepath", "ip", "domain", "hash", "registry_key", "host", "account")
_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                 "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")

_logger = logging.getLogger(__name__)

# A7 Finding 4 — benign/ubiquitous shared entities must not, by
# themselves, link two findings into a cluster. `_finding_entities()`
# previously excluded only the case's own subject IP(s); a shared generic
# system binary (svchost.exe), a shared public DNS resolver, or a shared
# generic autorun registry key container said nothing about the two
# findings being related, yet drove connected-component clustering exactly
# like a genuine shared IOC would.
#
# System-binary basenames are reused from the shared processes indicator
# list (knowledge/indicators/processes.yaml::system_process_names) rather
# than a second copy maintained here. Import is best-effort: clustering
# must never hard-fail if the knowledge base is unavailable in a stripped
# test environment -- it just fails open (no filter) in that case.
try:
    from spectre.knowledge import load_indicator_list

    def _load_benign_basenames() -> frozenset:
        names = load_indicator_list("processes", "system_process_names")
        return frozenset(n if n.endswith(".exe") else f"{n}.exe" for n in names)

    _BENIGN_SYSTEM_BASENAMES = _load_benign_basenames()
except Exception:  # pragma: no cover - defensive, not expected in prod
    _BENIGN_SYSTEM_BASENAMES = frozenset()

# Well-known public DNS resolver IPs. Deliberately small and conservative:
# an operator's own infrastructure should never land here by accident, and
# this list only needs to cover the case that actually produces false
# clusters -- two findings that both happen to touch the SAME public
# resolver purely because it's ubiquitous, not because they're related.
_BENIGN_PUBLIC_DNS_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",                # Google Public DNS
    "1.1.1.1", "1.0.0.1",                # Cloudflare
    "9.9.9.9", "149.112.112.112",        # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
})

# Generic autorun registry key CONTAINERS (no specific value name) present
# on virtually every Windows host. Sharing the *container* proves nothing;
# a shared specific VALUE under one of these (e.g. the same malicious
# executable path as a Run value) is a different, non-benign entity kind
# (filepath) and is unaffected by this list.
_BENIGN_GENERIC_RUNKEYS = frozenset({
    r"hklm\software\microsoft\windows\currentversion\run",
    r"hklm\software\microsoft\windows\currentversion\runonce",
    r"hkcu\software\microsoft\windows\currentversion\run",
    r"hkcu\software\microsoft\windows\currentversion\runonce",
    r"hklm\software\wow6432node\microsoft\windows\currentversion\run",
    r"hklm\software\wow6432node\microsoft\windows\currentversion\runonce",
    r"hklm\system\currentcontrolset\control\session manager",
})


def _is_benign_entity(kind: str, normalized_value: str) -> bool:
    """True if this normalized (kind, value) is too common/ubiquitous to
    be meaningful evidence that two findings are related."""
    if kind == "filepath":
        basename = normalized_value.rsplit("/", 1)[-1]
        return basename in _BENIGN_SYSTEM_BASENAMES
    if kind == "ip":
        return normalized_value in _BENIGN_PUBLIC_DNS_IPS
    if kind == "registry_key":
        return normalized_value.lower().strip("\\") in _BENIGN_GENERIC_RUNKEYS
    return False


def _normalize_entity(kind: str, value: str) -> str:
    v = str(value).strip()
    if not v:
        return ""
    if kind == "filepath":
        return v.replace("\\", "/").rstrip("/").lower()
    if kind in ("domain", "hash", "host", "account"):
        return v.lower()
    return v  # ip, registry_key: exact


def _finding_entities(finding: dict, subject_ips: set[str]) -> set[str]:
    """Namespaced normalized entities (`kind:value`), minus subject IPs and
    benign/ubiquitous common entities (see _is_benign_entity)."""
    ents: set[str] = set()
    iocs = finding.get("iocs") or {}
    for k in _ENTITY_KEYS:
        for raw in (iocs.get(k) or []):
            n = _normalize_entity(k, raw)
            if not n:
                continue
            if k == "ip" and n in subject_ips:
                continue
            if _is_benign_entity(k, n):
                _logger.debug(
                    "clustering: filtered benign entity %s:%s from %s "
                    "(too common to imply relatedness)",
                    k, n, finding.get("finding_id"))
                continue
            ents.add(f"{k}:{n}")
    return ents


def _parse_time(finding: dict):
    raw = str(finding.get("event_time") or finding.get("first_seen") or "").strip()
    if not raw:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except (ValueError, TypeError):
            continue
    # Offset-aware ISO8601 fallback (A6 Finding 3): LNK/Prefetch's
    # datetime.isoformat() and registry_hive's _parse_lastwrite_time both
    # append '+00:00'; EVTX's SystemTime carries a trailing 'Z'. Neither
    # matches the fixed strptime tuple above, so those artifact types were
    # silently excluded from temporal-proximity clustering entirely.
    # datetime.fromisoformat handles both once 'Z' is normalized the same
    # way report_synthesize._parse_finding_ts does.
    s = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None  # honest: unparseable -> excluded from temporal clustering
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _components(node_links: dict[str, set[str]], all_nodes: list[str]) -> list[list[str]]:
    """Connected components (size >= 2) over an undirected link map, returned
    sorted by their lexicographically-smallest member for determinism."""
    seen: set[str] = set()
    comps: list[list[str]] = []
    for start in sorted(all_nodes):
        if start in seen or start not in node_links:
            continue
        stack, comp = [start], set()
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            comp.add(x)
            stack.extend(node_links.get(x, set()) - seen)
        if len(comp) >= 2:
            comps.append(sorted(comp))
    comps.sort(key=lambda c: c[0])
    return comps


def _artifact_type(finding: dict) -> str:
    types = finding_artifact_types([finding])
    return types[0] if types else "unknown"


def cluster_findings(findings: list[dict], subject_ips: set[str],
                     window_s: int | None = None) -> dict:
    if window_s is None:
        window_s = int(os.environ.get("SPECTRE_TEMPORAL_WINDOW_S", "60"))
    subject_ips = {str(x) for x in subject_ips if x}
    # finding_ids are assumed unique (F-{case}-{NNN}); duplicates would be
    # silently deduped last-write-wins.
    by_id = {f.get("finding_id"): f for f in findings if f.get("finding_id")}

    # ── IOC/entity overlap ──
    ent_to_fids: dict[str, set[str]] = defaultdict(set)
    for fid, f in by_id.items():
        ents = _finding_entities(f, subject_ips)
        for e in ents:
            ent_to_fids[e].add(fid)
    # W5-3: process instances (pid + image, host/start-time scoped). Not a
    # plain shared-string entity -- see correlation/process.py for why a bare
    # PID never links and an under-specified ref never bridges instances.
    for label, fids in process_entity_groups(by_id).items():
        ent_to_fids[label] |= fids

    ioc_links: dict[str, set[str]] = defaultdict(set)
    for e, fids in ent_to_fids.items():
        if len(fids) >= 2:
            fl = sorted(fids)
            for a in fl:
                ioc_links[a].update(x for x in fl if x != a)

    ioc_clusters = []
    for i, comp in enumerate(_components(ioc_links, list(by_id)), start=1):
        shared = sorted(e for e, fids in ent_to_fids.items()
                        if len(fids & set(comp)) >= 2)
        span = {e: sorted({_artifact_type(by_id[fid])
                           for fid in (ent_to_fids[e] & set(comp))})
                for e in shared}
        ioc_clusters.append({
            "cluster_id": f"ioc_overlap-{i:03d}",
            "type": "ioc_overlap",
            "member_finding_ids": comp,
            "shared_entities": shared,
            "artifact_span": span,
        })

    # ── Temporal ──
    timed = {fid: t for fid in by_id if (t := _parse_time(by_id[fid])) is not None}
    temporal_links: dict[str, set[str]] = defaultdict(set)
    ids = sorted(timed)
    for a_i in range(len(ids)):
        for b_i in range(a_i + 1, len(ids)):
            a, b = ids[a_i], ids[b_i]
            if abs((timed[a] - timed[b]).total_seconds()) <= window_s:
                temporal_links[a].add(b)
                temporal_links[b].add(a)

    temporal_clusters = []
    for i, comp in enumerate(_components(temporal_links, list(timed)), start=1):
        times = sorted(timed[fid] for fid in comp)
        temporal_clusters.append({
            "cluster_id": f"temporal-{i:03d}",
            "type": "temporal",
            "member_finding_ids": comp,
            "time_range": [times[0].isoformat(sep=" "), times[-1].isoformat(sep=" ")],
        })

    return {"ioc_overlap": ioc_clusters, "temporal": temporal_clusters}
