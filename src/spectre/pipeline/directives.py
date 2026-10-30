"""
directives.py — compile validated directive specs into pure predicates over
NormEvents, and apply them in Phase 3.

A CompiledDirective wraps one spec and exposes:
  .matches(event) -> bool        : does this event satisfy the directive?
  .to_anchor(event) -> Anchor    : build a detection Anchor for an include hit

Matching is deterministic and cross-artifact: an `ioc_match` flattens the
event's data and searches every value, so a directed IP fires on pcap_conn,
memory_netscan, memory_url … alike. A `modifiers.time_window` ANDs a temporal
constraint onto any directive.

Polarity is carried but NOT applied here — Phase 3 decides what a match means:
  include -> emit a finding (rule_origin: user_directed)
  exclude -> tag the finding analyst_excluded and retain it (never delete)
  boost   -> raise analyst_priority on the finding
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from spectre.core.base import Anchor, NormEvent
from spectre.config import RAW_DIR


# ── time helpers ────────────────────────────────────────────────────
_RE_HHMM = re.compile(r"(?<!\d)([01]?\d|2[0-3]):([0-5]\d)(?!\d)")


def _hhmm(s: str) -> str | None:
    """Pull an HH:MM time-of-day out of a timestamp or a bound string."""
    m = _RE_HHMM.search(s or "")
    if not m:
        return None
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def _in_window(ts: str, start: str, end: str) -> bool:
    """True if event timestamp falls within [start, end].

    When both bounds look like HH:MM, compare time-of-day; otherwise fall back
    to lexical ISO comparison (ISO-8601 sorts chronologically).
    """
    s_hm, e_hm = _hhmm(start), _hhmm(end)
    if s_hm and e_hm:
        ev_hm = _hhmm(ts)
        if ev_hm is None:
            return False
        return s_hm <= ev_hm <= e_hm
    return (start or "") <= (ts or "") <= (end or "")


# ── value matching ──────────────────────────────────────────────────
def _values_in(data: dict):
    """Yield every scalar value in an event's data dict, cross-artifact
    (a directed IP must fire on pcap_conn, memory_netscan, memory_url …
    alike), flattening list-valued fields."""
    for v in (data or {}).values():
        if isinstance(v, (list, tuple)):
            for x in v:
                yield str(x)
        else:
            yield str(v)


# R2-05(b): the old `_compile_ioc` did `val in _flatten(data)` — raw
# substring matching over every field value concatenated together. That let
# a directive for "185.220.101.4" fire on an event whose dst_ip was
# "185.220.101.42" (the directive value is a substring of the observed one).
# Below: per-ioc-type EXACT matching — IP by address equality, domain by
# exact match or proper subdomain on a label boundary, hash by
# case-insensitive exact equality — never a raw `in` check.
_RE_IOC_IPV4 = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")


# W2-B review (M3): IPv6. A candidate is a maximal run of hex/colon/dot
# chars (so `[v6]:port`, `v6%zone`, `v6,` all delimit cleanly) with at
# least two colons that `ipaddress` accepts as an IPv6Address; equality is
# then by address (expanded/compressed/case forms all compare equal). The
# length bound + run-start lookbehind keep the scan linear.
_RE_IOC_IPV6_RUN = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f:.]{2,45}(?![0-9A-Za-z:.])")


def _ipv6_candidates(raw: str) -> list[str]:
    out = []
    for tok in _RE_IOC_IPV6_RUN.findall(raw):
        if tok.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(tok)
        except ValueError:
            continue
        out.append(tok)
    return out


def _ip_candidates(raw: str) -> list[str]:
    """Pull IPv4-shaped substrings out of a field value (e.g. the address
    half of "1.2.3.4:443"; the trailing ':port' cannot join the match
    because ':' is a non-word boundary), plus IPv6 addresses (bare,
    `[v6]:port`, `v6%zone`)."""
    return _RE_IOC_IPV4.findall(raw) + _ipv6_candidates(raw)


def _hash_candidates(raw: str, length: int) -> list[str]:
    """Pull exactly-`length`-hex-char tokens out of a field value. `\\b` on
    both ends means a longer, unbroken hex run (all hex digits are word
    chars) can only match if its TOTAL length is exactly `length` — a
    64-char target can never match inside a 70-char hex blob."""
    return re.findall(rf"\b[a-fA-F0-9]{{{length}}}\b", raw)


# W2-B review (M2): extract HOSTNAMES (dotted label runs) rather than
# splitting on a fixed delimiter set, so a domain IOC matches inside a URL
# (`http://evil.com/a`, `https://www.evil.com:8080/x`) or an email
# (`user@evil.com`) and the recorded observed value is the bare hostname
# (`www.evil.com`, never `//www.evil.com`). A candidate always spans a
# whole run (lookbehind excludes label chars and `.`), so `_domain_eq`'s
# label-boundary rule still rejects `notevil.com` / `evil.com.au`.
_RE_HOSTNAME = re.compile(
    r"(?<![\w.\-])[\w\-]{1,63}(?:\.[\w\-]{1,63})+(?![\w\-]|\.[\w\-])")


def _domain_candidates(raw: str) -> list[str]:
    return [h.strip("-") for h in _RE_HOSTNAME.findall(raw) if h.strip("-")]


def _generic_candidates(raw: str) -> list[str]:
    return [t for t in re.split(r"\s+", raw.strip()) if t]


def _ip_eq(target: str, candidate: str) -> bool:
    try:
        return ipaddress.ip_address(target.strip()) == ipaddress.ip_address(candidate.strip())
    except ValueError:
        return target.strip() == candidate.strip()


def _domain_eq(target: str, candidate: str) -> bool:
    t = target.strip().strip(".").lower()
    c = candidate.strip().strip(".").lower()
    if not t or not c:
        return False
    # Exact match, or a proper subdomain on a label boundary
    # (www.evil.com matches evil.com; notevil.com / eviloco.com do not).
    return c == t or c.endswith("." + t)


def _hash_eq(target: str, candidate: str) -> bool:
    return target.strip().lower() == candidate.strip().lower()


def _path_eq(target: str, candidate: str) -> bool:
    def norm(s: str) -> str:
        return str(s).strip().strip("\"'").lower().replace("/", "\\")
    return norm(target) == norm(candidate)


def _generic_eq(target: str, candidate: str) -> bool:
    return str(target).strip().lower() == str(candidate).strip().lower()


_IOC_CANDIDATES: dict[str, Callable[[str], list[str]]] = {
    "ip": _ip_candidates,
    "domain": _domain_candidates,
    "sha256": lambda s: _hash_candidates(s, 64),
    "md5": lambda s: _hash_candidates(s, 32),
}
_IOC_EQ: dict[str, Callable[[str, str], bool]] = {
    "ip": _ip_eq,
    "domain": _domain_eq,
    "sha256": _hash_eq,
    "md5": _hash_eq,
    "filepath": _path_eq,
    "registry_key": _path_eq,
}


def _find_ioc_observed(ioc_type: str, target: str, data: dict) -> str | None:
    """Return the actual event-data value that satisfies `target` under
    `ioc_type`'s exact-match rule, or None. This is also what R2-05(c)
    needs: the *observed* value, never the directive's own value, because
    that is what to_anchor() must record in the finding's iocs."""
    if not target:
        return None
    eq = _IOC_EQ.get(ioc_type, _generic_eq)
    cand_fn = _IOC_CANDIDATES.get(ioc_type)
    for raw in _values_in(data):
        candidates = cand_fn(raw) if cand_fn else ([raw] + _generic_candidates(raw))
        for cand in candidates:
            if eq(target, cand):
                return cand
    return None


def _field_op(value, op: str, target) -> bool:
    if value is None:
        return False
    sval = str(value)
    if op == "eq":
        return sval.lower() == str(target).lower()
    if op == "contains":
        return str(target).lower() in sval.lower()
    if op == "regex":
        try:
            return re.search(str(target), sval, re.IGNORECASE) is not None
        except re.error:
            return False
    if op == "in":
        targets = target if isinstance(target, (list, tuple)) else [target]
        return sval.lower() in {str(t).lower() for t in targets}
    return False


def _basename(s: str) -> str:
    return re.split(r"[\\/]", str(s or ""))[-1].lower()


# ── compiled directive ──────────────────────────────────────────────
@dataclass
class CompiledDirective:
    spec: dict
    _predicate: Callable[[NormEvent], bool]

    @property
    def directive_id(self) -> str:
        return self.spec.get("directive_id", "dir-?")

    @property
    def polarity(self) -> str:
        return self.spec.get("polarity", "include")

    @property
    def type(self) -> str:
        return self.spec.get("type", "")

    def matches(self, event: NormEvent) -> bool:
        # Time-window modifier ANDs onto the base predicate.
        tw = (self.spec.get("modifiers") or {}).get("time_window")
        if tw and not _in_window(event.timestamp, tw.get("start", ""), tw.get("end", "")):
            return False
        return self._predicate(event)

    def to_anchor(self, event: NormEvent) -> Anchor:
        p = self.spec.get("params", {})
        iocs = {"filepath": [], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        if self.type == "ioc_match":
            it, val = p.get("ioc_type"), p.get("value")
            # R2-05(c): record the value actually OBSERVED in this event's
            # data, never the directive's own value verbatim — otherwise an
            # IOC that never appeared in evidence (an LLM hallucination, or
            # merely a near-miss the old substring matcher accepted) would
            # still land in the finding's iocs, iocs.csv and the cross-case
            # index. Falls back to the directive value only if, somehow,
            # this event no longer re-matches (defensive; matches() already
            # guarantees a match before to_anchor is called).
            observed = _find_ioc_observed(it, str(val), event.data) or val
            if it == "md5":
                iocs.setdefault("md5", []).append(observed)
            elif it in iocs:
                iocs[it].append(observed)
        title = _title(self.spec)
        return Anchor(
            rule_id=self.directive_id,
            artifact_type=event.artifact_type,
            event=event,
            title=title,
            mitre=p.get("mitre", []) if isinstance(p.get("mitre"), list) else [],
            confidence=0.5,
            iocs=iocs,
            summary=(f"[directed:{self.spec.get('polarity')}] {title} — "
                     f"matched {event.artifact_type} record {event.record_id}"),
            dedup_key=f"{self.directive_id}:{event.source_file}:{event.record_id}",
        )


def _title(spec: dict) -> str:
    t, p = spec["type"], spec.get("params", {})
    pol = spec.get("polarity", "include")
    verb = {"include": "Analyst-directed", "exclude": "Analyst-excluded",
            "boost": "Analyst-prioritized"}.get(pol, "Directed")
    if t == "ioc_match":
        return f"{verb} {p.get('ioc_type')} {p.get('value')}"
    if t == "field_match":
        return f"{verb} {p.get('field')} {p.get('op')} {p.get('value')}"
    if t == "lineage":
        return f"{verb} child of {p.get('parent')}"
    if t == "temporal":
        return f"{verb} activity {p.get('start')}–{p.get('end')}"
    if t == "scope":
        return f"{verb} scope"
    return f"{verb} directive"


# ── compilers per type ──────────────────────────────────────────────
def _compile_ioc(spec) -> Callable[[NormEvent], bool]:
    ioc_type = spec["params"].get("ioc_type", "")
    val = str(spec["params"].get("value", ""))

    def pred(e: NormEvent) -> bool:
        if not val:
            return False
        return _find_ioc_observed(ioc_type, val, e.data) is not None
    return pred


def _compile_field(spec) -> Callable[[NormEvent], bool]:
    p = spec["params"]
    field, op, target = p.get("field"), p.get("op"), p.get("value")

    def pred(e: NormEvent) -> bool:
        if field not in (e.data or {}):
            return False
        return _field_op(e.data.get(field), op, target)
    return pred


def _compile_lineage(spec) -> Callable[[NormEvent], bool]:
    p = spec["params"]
    parent = (p.get("parent") or "*")
    child = (p.get("child") or "*")
    parent_bn = _basename(parent) if parent != "*" else "*"
    child_bn = _basename(child) if child != "*" else "*"

    def pred(e: NormEvent) -> bool:
        d = e.data or {}
        if "parent_basename" not in d and "image_basename" not in d:
            return False
        if parent_bn != "*" and _basename(d.get("parent_basename", "")) != parent_bn:
            return False
        if child_bn != "*" and _basename(d.get("image_basename", "")) != child_bn:
            return False
        return True
    return pred


def _compile_temporal(spec) -> Callable[[NormEvent], bool]:
    p = spec["params"]
    start, end = p.get("start", ""), p.get("end", "")

    def pred(e: NormEvent) -> bool:
        return _in_window(e.timestamp, start, end)
    return pred


def _compile_scope(spec) -> Callable[[NormEvent], bool]:
    p = spec["params"]
    arts = {str(a).lower() for a in (p.get("artifact_types") or [])}
    hosts = {str(h).lower() for h in (p.get("hosts") or [])}

    def pred(e: NormEvent) -> bool:
        if arts and e.artifact_type.lower() not in arts:
            return False
        if hosts and (e.host or "").lower() not in hosts:
            return False
        return bool(arts or hosts)
    return pred


_COMPILERS = {
    "ioc_match": _compile_ioc,
    "field_match": _compile_field,
    "lineage": _compile_lineage,
    "temporal": _compile_temporal,
    "scope": _compile_scope,
}


def compile(spec: dict) -> CompiledDirective:  # noqa: A001 (mirrors module verb)
    """Compile a validated directive spec into a CompiledDirective."""
    builder = _COMPILERS.get(spec.get("type"))
    if builder is None:
        raise ValueError(f"unknown directive type: {spec.get('type')}")
    return CompiledDirective(spec=spec, _predicate=builder(spec))


def load(case_dir: str) -> list[CompiledDirective]:
    """Load and compile raw_extract/directives.json for a case (empty if absent).

    W3-1 (R2-16): the file is re-hashed against the latest chained
    ``directives_synthesized`` row first. A mismatch, or a NON-EMPTY file no
    row records, raises ``custody.CustodyError`` — an include directive
    planted between Phase 1 and Phase 3 must not yield user-directed findings.
    """
    from spectre.pipeline.custody import verify_derived_artifact

    path = Path(case_dir) / RAW_DIR / "directives.json"
    if not path.exists():
        return []
    specs = json.loads(path.read_text())
    verify_derived_artifact(case_dir, path, actions=("directives_synthesized",),
                            required=bool(specs))
    return [compile(s) for s in specs]


# ── Phase-3 application helpers ─────────────────────────────────────
def collect_include_anchors(events: list[NormEvent],
                            compiled: list[CompiledDirective]) -> list[Anchor]:
    """Anchors for every include/boost directive that matches an event."""
    anchors = []
    for d in compiled:
        if d.polarity not in ("include", "boost"):
            continue
        for e in events:
            if d.matches(e):
                anchors.append(d.to_anchor(e))
    return anchors


def excluded_by(anchor_event: NormEvent,
                compiled: list[CompiledDirective]) -> Optional[str]:
    """Return the directive_id of the first matching exclude directive, else None."""
    for d in compiled:
        if d.polarity == "exclude" and d.matches(anchor_event):
            return d.directive_id
    return None


def boosted_by(anchor_event: NormEvent,
               compiled: list[CompiledDirective]) -> Optional[str]:
    for d in compiled:
        if d.polarity == "boost" and d.matches(anchor_event):
            return d.directive_id
    return None
