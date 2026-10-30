"""
direction.py — Phase 1 (Direction): turn an investigator's natural-language
tasking into validated, JSON-serializable *directive specs*.

Deterministic-first. Literal IOCs, process lineage, time windows and known
analytic concepts are parsed with regex + a curated concept map — no LLM, so
they work under --skip-ai and are fully reproducible. Truly fuzzy phrasing is
handed to an LLM seam (`llm_specs`); when no LLM is available the unparsed
fragment is surfaced as a recorded warning, never silently guessed.

A directive spec is a plain dict (persisted to raw_extract/directives.json):

    {
      "directive_id": "dir-001",
      "type": "ioc_match" | "field_match" | "lineage" | "temporal" | "scope",
      "polarity": "include" | "exclude" | "boost",
      "params": { ... type-specific ... },
      "modifiers": {"time_window": {...}|None, "artifact_scope": [], "host_scope": []},
      "origin": "deterministic" | "concept_map" | "llm",
      "source_direction": "<verbatim text this came from>",
      "applies_to_artifact_types": []        # resolved at compile time
    }
"""

from __future__ import annotations

import re

from spectre.llm import get_provider

# ── Vocabulary ──────────────────────────────────────────────────────
DIRECTIVE_TYPES = {"ioc_match", "field_match", "lineage", "temporal", "scope"}
POLARITIES = {"include", "exclude", "boost"}
IOC_TYPES = {"ip", "domain", "sha256", "md5", "filepath", "registry_key"}

# Words that flip a directive from "hunt for" to "scope out". Matched as
# whole words so 'note' does not trip 'not'.
_NEGATION = ("exclude", "ignore", "except", "without", "filter out", "drop", "not ")

# Conservative TLD allowlist so file names (.exe/.dll) are never read as domains.
_TLDS = {"com", "net", "org", "io", "ru", "cn", "info", "biz", "co", "uk",
         "de", "xyz", "top", "online", "site", "gov", "edu"}

# ── Regexes ─────────────────────────────────────────────────────────
_RE_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_FILEPATH = re.compile(r"[A-Za-z]:\\[^\s,\"']+")
_RE_REGKEY = re.compile(r"\b(HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\[^\s,\"']+)")
_RE_DOMAIN = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)
_RE_LINEAGE = re.compile(
    r"(?:spawned|launched|started|created)\s+by\s+([^\s,;]+)", re.IGNORECASE)
_RE_CHILDREN = re.compile(r"child(?:ren)?\s+of\s+([^\s,;]+)", re.IGNORECASE)
_RE_TEMPORAL = re.compile(
    r"(?:between|from)\s+([0-9:apm\-/ ]+?)\s+(?:and|to|-)\s+([0-9:apm\-/]+)",
    re.IGNORECASE)


# ── Curated concept map (deterministic concept -> directives) ───────
# Known analytic concepts expand to concrete, compilable directives with no
# LLM. Unknown concepts fall through to the LLM seam.
CONCEPT_MAP: dict[str, dict] = {
    "suspicious-executable": {
        "aliases": ["suspicious executable", "suspicious executables",
                    "suspicious exe", "suspicious binary", "suspicious binaries"],
        "directives": [
            {"type": "field_match",
             "params": {"field": "command_line_lower", "op": "contains",
                        "value": "\\temp\\"}},
            {"type": "field_match",
             "params": {"field": "image_basename", "op": "in",
                        "value": ["rundll32.exe", "regsvr32.exe", "mshta.exe",
                                  "cscript.exe", "wscript.exe"]}},
        ],
    },
    "credential-theft": {
        "aliases": ["credential theft", "credential dumping", "cred theft",
                    "credential access", "lsass dump"],
        "directives": [
            {"type": "field_match",
             "params": {"field": "image_basename", "op": "in",
                        "value": ["mimikatz.exe", "procdump.exe"]}},
            {"type": "field_match",
             "params": {"field": "command_line_lower", "op": "contains",
                        "value": "lsass"}},
        ],
    },
}


def _new_modifiers() -> dict:
    return {"time_window": None, "artifact_scope": [], "host_scope": []}


def _spec(dtype: str, params: dict, polarity: str, origin: str,
          source: str) -> dict:
    return {
        "type": dtype,
        "polarity": polarity,
        "params": params,
        "modifiers": _new_modifiers(),
        "origin": origin,
        "source_direction": source,
        "applies_to_artifact_types": [],
    }


def _polarity_for(text: str) -> str:
    low = text.lower()
    return "exclude" if any(n in low for n in _NEGATION) else "include"


def _looks_like_domain(candidate: str) -> bool:
    tld = candidate.rsplit(".", 1)[-1].lower()
    return tld in _TLDS


def _extract_iocs(text: str, polarity: str, source: str) -> list[dict]:
    specs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str):
        key = (ioc_type, value)
        if key in seen:
            return
        seen.add(key)
        specs.append(_spec("ioc_match",
                           {"ioc_type": ioc_type, "value": value},
                           polarity, "deterministic", source))

    # Hash before domain so 64/32-hex strings aren't mistaken for hostnames.
    for m in _RE_SHA256.findall(text):
        add("sha256", m)
    # md5: skip anything already claimed as part of a sha256.
    sha_blob = " ".join(_RE_SHA256.findall(text))
    for m in _RE_MD5.findall(text):
        if m not in sha_blob:
            add("md5", m)
    for m in _RE_REGKEY.findall(text):
        add("registry_key", m)
    for m in _RE_FILEPATH.findall(text):
        add("filepath", m)
    ips = _RE_IPV4.findall(text)
    for m in ips:
        add("ip", m)
    for m in _RE_DOMAIN.findall(text):
        if m in ips:
            continue
        if _looks_like_domain(m):
            add("domain", m)
    return specs


def _extract_lineage(text: str, polarity: str, source: str) -> list[dict]:
    specs = []
    for m in _RE_LINEAGE.finditer(text):
        parent = m.group(1).strip(".,;\"'")
        specs.append(_spec("lineage",
                           {"parent": parent, "child": "*"},
                           polarity, "deterministic", source))
    for m in _RE_CHILDREN.finditer(text):
        parent = m.group(1).strip(".,;\"'")
        specs.append(_spec("lineage",
                           {"parent": parent, "child": "*"},
                           polarity, "deterministic", source))
    return specs


def _extract_temporal(text: str) -> dict | None:
    m = _RE_TEMPORAL.search(text)
    if not m:
        return None
    return {"start": m.group(1).strip(), "end": m.group(2).strip()}


def _expand_concepts(text: str, polarity: str, source: str) -> list[dict]:
    low = text.lower()
    specs = []
    for concept, cfg in CONCEPT_MAP.items():
        if any(alias in low for alias in cfg["aliases"]):
            for d in cfg["directives"]:
                spec = _spec(d["type"], dict(d["params"]), polarity,
                             "concept_map", source)
                spec["params"]["concept"] = concept
                specs.append(spec)
    return specs


# Connectives that separate independent clauses. A compound tasking can mix
# polarity ("hunt X and exclude Y"), so each clause is parsed on its own.
_RE_CONNECT = re.compile(r"\s*(?:;|,|\band\b|\bbut\b|\bthen\b|\balso\b)\s*",
                         re.IGNORECASE)


def _mask_temporal(text: str) -> tuple[str, dict]:
    """Replace 'between A and B' ranges with placeholders so the clause split
    on 'and' never breaks a time window."""
    restore: dict[str, str] = {}

    def repl(m: "re.Match") -> str:
        key = f"\x00T{len(restore)}\x00"
        restore[key] = m.group(0)
        return key

    return _RE_TEMPORAL.sub(repl, text), restore


def _unmask(s: str, restore: dict) -> str:
    for k, v in restore.items():
        s = s.replace(k, v)
    return s


def _parse_clause(clause: str, source: str) -> list[dict]:
    """Parse a single clause; polarity is decided per clause."""
    clause = clause.strip()
    if not clause:
        return []
    polarity = _polarity_for(clause)
    specs: list[dict] = []
    specs += _expand_concepts(clause, polarity, source)
    specs += _extract_lineage(clause, polarity, source)
    specs += _extract_iocs(clause, polarity, source)

    # Temporal: standalone directive, unless exactly one other directive exists
    # in this clause — then it scopes that directive as a modifier.
    tw = _extract_temporal(clause)
    if tw:
        if len(specs) == 1:
            specs[0]["modifiers"]["time_window"] = tw
        else:
            specs.append(_spec("temporal", dict(tw), polarity,
                               "deterministic", source))
    return specs


def parse_deterministic(text: str) -> tuple[list[dict], list[str]]:
    """Parse a tasking string into directive specs with no LLM.

    The text is split into clauses on connectives (',', 'and', ';', 'but', …)
    so a single compound sentence can carry mixed polarity — "hunt X and
    exclude Y". 'between A and B' time ranges are protected from the split.
    Returns (specs, unparsed_fragments); nothing matched -> whole text unparsed.
    """
    text = (text or "").strip()
    if not text:
        return [], []

    masked, restore = _mask_temporal(text)
    specs: list[dict] = []
    for raw_clause in _RE_CONNECT.split(masked):
        specs += _parse_clause(_unmask(raw_clause, restore), text)

    unparsed = [] if specs else [text]
    return specs, unparsed


def validate(spec: dict) -> bool:
    """Per-type schema / whitelist validation. Reject anything off-grammar."""
    if not isinstance(spec, dict):
        return False
    if spec.get("type") not in DIRECTIVE_TYPES:
        return False
    if spec.get("polarity") not in POLARITIES:
        return False
    p = spec.get("params") or {}
    t = spec["type"]
    if t == "ioc_match":
        return p.get("ioc_type") in IOC_TYPES and bool(p.get("value"))
    if t == "field_match":
        return bool(p.get("field")) and p.get("op") in {"eq", "contains", "regex", "in"} \
            and p.get("value") not in (None, "", [])
    if t == "lineage":
        parent = p.get("parent") or ""
        child = p.get("child") or ""
        return bool((parent and parent != "*") or (child and child != "*"))
    if t == "temporal":
        return bool(p.get("start") or p.get("end"))
    if t == "scope":
        return bool(p.get("artifact_types") or p.get("hosts") or p.get("files"))
    return False


def llm_specs(unparsed: list[str], skip_ai: bool) -> tuple[list[dict], list[str], bool]:
    """LLM seam for fuzzy direction the deterministic parser couldn't handle.

    Deterministic-first means this is rarely reached. When skip_ai is set, or
    no LLM client is wired (_call_llm returns None), unparsed fragments are
    surfaced as warnings rather than guessed.

    Returns (specs, warnings, deferred). deferred=True means the LLM was
    unavailable (host mode or no API key) and fragments were not parsed.
    """
    if not unparsed:
        return [], [], False
    if skip_ai:
        return [], [f"unparsed direction (skip-ai, not guessed): {u}"
                    for u in unparsed], False
    specs, warnings = [], []
    any_deferred = False
    for frag in unparsed:
        produced, deferred, notes = _call_llm(frag)
        warnings.extend(notes)
        if deferred:
            any_deferred = True
            warnings.append(f"unparsed direction (no LLM available): {frag}")
        elif produced:
            specs.extend(produced)
        elif not notes:
            warnings.append(f"unparsed direction (LLM returned no output): {frag}")
    return specs, warnings, any_deferred


_DIRECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "specs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "polarity": {"enum": ["include", "exclude"]},
                    "params": {"type": "object"},
                },
                "required": ["type", "params"],
            },
        }
    },
    "required": ["specs"],
}


# ── R2-05(a): bind LLM-produced directive values to the analyst fragment ──
# A model asked to expand a fuzzy fragment ("look at the tor stuff") can
# hallucinate a concrete IOC that was never in the analyst's text. Because
# directives.py's to_anchor() copies the directive's *value* straight into
# the finding's iocs (not the matched event's value), an invented IOC here
# would otherwise become a "fact" in the finding, iocs.csv and the cross-
# case index. Every literal value an LLM-origin spec carries must appear,
# verbatim after normalization, in the fragment it was parsed from.
_DEFANG_SUBS = (
    ("[.]", "."), ("(.)", "."), ("[dot]", "."), (" dot ", "."),
    ("[:]", ":"), ("[at]", "@"), (" at ", "@"),
    ("hxxps://", "https://"), ("hxxp://", "http://"), ("hxxp", "http"),
)


def _normalize_for_grounding(s: str) -> str:
    """Lowercase + defang-reverse a string so a defanged fragment IOC still
    matches a plain-text directive value (and vice versa)."""
    low = str(s or "").lower()
    for old, new in _DEFANG_SUBS:
        low = low.replace(old, new)
    return low


# Types whose literal param values must be verbatim-grounded in the
# fragment, vs. types validated on shape/semantics instead (see the
# "orchestrator follow-up" note below _spec_grounded_in_fragment).
_STRICT_GROUNDED_TYPES = {"ioc_match", "field_match", "lineage"}

# params keys, per directive type, whose values must be literally present in
# the source fragment. Structural keys (ioc_type, field, op, artifact type
# names taken from a closed vocabulary) are not checked here.
_GROUNDED_PARAM_KEYS = {
    "ioc_match": ["value"],
    "field_match": ["value"],
    "lineage": ["parent", "child"],
}


def _literal_values(spec: dict) -> list[str]:
    """Flatten the value(s) of a spec's grounded param keys into strings,
    skipping wildcards and empties (nothing to hallucinate there)."""
    p = spec.get("params") or {}
    out: list[str] = []
    for key in _GROUNDED_PARAM_KEYS.get(spec.get("type"), []):
        v = p.get(key)
        if v in (None, "", "*"):
            continue
        vals = v if isinstance(v, (list, tuple)) else [v]
        for item in vals:
            s = str(item)
            if s and s != "*":
                out.append(s)
    return out


# W2-B review (L1): grounding is TOKEN-bounded, not a raw substring test —
# otherwise a fragment naming only 185.220.101.42 "grounds" a model-emitted
# 185.220.101.4, and "notevil.com" grounds "evil.com". Where the value
# begins/ends with a word char, the neighbouring fragment char must not be a
# word char or `-`, nor a `.` joined to another word char (a longer dotted
# token). A sentence-ending "." after the value is still a boundary.
_GROUND_CH = r"[\w\-]"


def _value_in_fragment(val_norm: str, frag_norm: str) -> bool:
    if not val_norm:
        return True
    left = rf"(?<!{_GROUND_CH})(?<!{_GROUND_CH}\.)" if re.match(r"[\w\-]", val_norm[0]) else ""
    right = rf"(?!{_GROUND_CH})(?!\.{_GROUND_CH})" if re.match(r"[\w\-]", val_norm[-1]) else ""
    return re.search(left + re.escape(val_norm) + right, frag_norm) is not None


def _spec_grounded_in_fragment(spec: dict, fragment: str) -> bool:
    """True iff every literal value the spec carries appears, verbatim
    (case-insensitive, defang-aware) and as a whole token (see
    _value_in_fragment), in the fragment it was derived from."""
    frag_norm = _normalize_for_grounding(fragment)
    for val in _literal_values(spec):
        if not _value_in_fragment(_normalize_for_grounding(val), frag_norm):
            return False
    return True


# ── Orchestrator follow-up on R2-05: temporal/scope are not IOC-shaped ──
# Verified against directives.py + phase_runner.py's Phase-3 consumption
# (collect_include_anchors -> emit_from_handle):
#   - ioc_match/field_match/lineage values are copied into Anchor.iocs and
#     land in a finding's `iocs` field (iocs.csv, cross-case index) — these
#     stay strictly verbatim-grounded, unchanged above.
#   - temporal directives (polarity include/boost) DO create a finding (one
#     per matched event), and to_anchor()'s title embeds start/end as text
#     ("Analyst-directed activity {start}-{end}") — but to_anchor() never
#     writes them into `iocs` (only the ioc_match branch does), and the
#     predicate that selected the matched events used those SAME start/end
#     values, so the window shown is exactly the window that was applied —
#     never a fabricated fact about evidence content. Verbatim-grounding an
#     LLM's correctly-interpreted "since last Tuesday" -> ISO date against
#     the fragment text over-drops legitimate analyst intent for no
#     integrity benefit. Accept any semantically valid range instead, and
#     record the interpretation for the analyst to verify (see
#     _valid_temporal_range and its call site).
#   - scope directives create a finding per matching event too, but
#     to_anchor()'s title for scope is the constant "Analyst-directed
#     scope" — none of artifact_types/hosts/files ever reaches a finding
#     field. Shape/type validation is enough; verbatim grounding buys
#     nothing here either.
def _parse_temporal_bound(s: str):
    """Parse one temporal bound as an HH:MM time-of-day or an ISO-8601
    datetime (UTC-normalized). Returns (kind, comparable_value) or None."""
    s = (s or "").strip()
    if not s:
        return None
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", s)
    if m:
        return ("hhmm", f"{int(m.group(1)):02d}:{m.group(2)}")
    from datetime import datetime, timezone
    iso = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return ("datetime", dt)


def _valid_temporal_range(start: str, end: str) -> bool:
    """Accept any temporal spec whose non-empty bounds each parse as a
    valid HH:MM time-of-day or ISO-8601 datetime, with start <= end when
    both bounds are the same comparable kind (cross-kind bounds, e.g. one
    HH:MM and one full date, cannot be strictly ordered here — each bound
    is still individually validated)."""
    if not start and not end:
        return False
    sb = _parse_temporal_bound(start) if start else None
    if start and sb is None:
        return False
    eb = _parse_temporal_bound(end) if end else None
    if end and eb is None:
        return False
    if sb and eb and sb[0] == eb[0]:
        return sb[1] <= eb[1]
    return True


# Different scope keys hold differently-shaped strings — an identifier
# (artifact_types), a hostname (hosts), or a filesystem path (files) — so
# each gets its own permissive-but-sane pattern. All three just reject
# empty/oversized/control-character garbage; none requires fragment text.
_RE_SCOPE_SHAPE = {
    "artifact_types": re.compile(r"^[a-z][a-z0-9_]{0,63}$"),
    "hosts": re.compile(r"^[A-Za-z0-9_.\-]{1,253}$"),
    "files": re.compile(r"^[^\x00-\x1f]{1,4096}$"),
}


def _valid_scope_shape(spec: dict) -> bool:
    """Shape/type check for a scope directive's lists. No fragment
    grounding — these values never reach a finding field (see above)."""
    p = spec.get("params") or {}
    any_list = False
    for key, pattern in _RE_SCOPE_SHAPE.items():
        vals = p.get(key)
        if not vals:
            continue
        if not isinstance(vals, (list, tuple)):
            return False
        any_list = True
        for v in vals:
            if not isinstance(v, str) or not pattern.match(v):
                return False
    return any_list


def _call_llm(fragment: str) -> tuple[list[dict] | None, bool, list[str]]:
    """LLM-assisted intent parsing for a fragment the deterministic parser missed.

    Routes through the platform-agnostic provider (spectre.llm). Under the
    default "host"/"null" providers this returns (None, True) (deferred / no
    output), preserving deterministic-first behavior — callers treat None as
    "surface a warning" rather than guessing. A direct provider
    (deepseek/anthropic/…) expands the fragment into the same directive-spec
    schema.

    Returns (specs_or_None, was_deferred, notes). When deferred=True, the
    LLM provided no useful output (host mode or no API key). `notes` mixes
    two kinds of entries, both surfaced as warnings (flowing into
    manifest/audit via synthesize()): drop-reasons for a spec the model
    produced but that was rejected (failed schema validation, R2-05
    ungrounded IOC/field/lineage value, or an invalid temporal/scope
    shape), and — for an ACCEPTED temporal spec — an informational note
    naming the LLM's interpreted window against the original fragment,
    since that value is validated for well-formedness rather than
    verbatim-grounded (see _valid_temporal_range).
    """
    system = (
        "You convert a single forensic-investigation direction fragment into "
        "directive specs. Output JSON only: "
        '{"specs": [{"type": "...", "polarity": "'
        + "|".join(sorted(POLARITIES)) + '", "params": {...}}]}. '
        "Valid types and their params (specs that don't match are discarded): "
        'ioc_match {"ioc_type": ' + "|".join(sorted(IOC_TYPES)) + ', "value"}; '
        'field_match {"field", "op": eq|contains|regex|in, "value"}; '
        'lineage {"parent", "child"} (at least one, not "*"); '
        'temporal {"start", "end"} (at least one); '
        'scope {"artifact_types" | "hosts" | "files": [...]}. '
        "Do not invent IOCs or scope not present in the fragment."
    )
    resp = get_provider().complete(system, fragment, max_tokens=512,
                                   schema=_DIRECTION_SCHEMA)
    if resp.deferred:
        # Host provider deferred and no orchestrating agent will fulfil it
        # (standalone CLI). No implicit fallback to a direct API provider —
        # that used to happen silently whenever a direct-provider key was
        # discoverable in the environment or ~/.spectre.env, which is real,
        # undisclosed network egress with case data (R2-06/W1-1). The
        # fragment stays unparsed and is surfaced as a warning by the
        # caller; API-assisted parsing now requires explicitly setting
        # SPECTRE_LLM_PROVIDER=<deepseek|anthropic|openai|local>.
        return None, True, []
    if resp.parsed is None:
        return None, False, []
    specs: list[dict] = []
    notes: list[str] = []
    for raw in resp.parsed.get("specs", []):
        spec = _spec(
            raw.get("type", ""),
            raw.get("params", {}) or {},
            raw.get("polarity") or _polarity_for(fragment),
            origin="llm",
            source=fragment,
        )
        if not validate(spec):
            continue
        t = spec.get("type")
        if t in _STRICT_GROUNDED_TYPES:
            if not _spec_grounded_in_fragment(spec, fragment):
                # R2-05(a): the model introduced a literal value (IOC,
                # field_match value, or lineage parent/child) not present
                # in the analyst's own fragment. These values are copied
                # into Anchor.iocs / the finding's fields — drop rather
                # than let a hallucinated fact reach a finding.
                notes.append(
                    f"dropped ungrounded LLM directive: {t} "
                    f"{spec.get('params')} (value not found in fragment: {fragment!r})"
                )
                continue
        elif t == "temporal":
            p = spec.get("params") or {}
            start, end = p.get("start", ""), p.get("end", "")
            if not _valid_temporal_range(start, end):
                notes.append(
                    f"dropped invalid LLM temporal directive: start={start!r} "
                    f"end={end!r} (fragment: {fragment!r})"
                )
                continue
            # Not verbatim-grounded (see module note above) — a temporal
            # window only narrows which real events match; it never
            # becomes an IOC. Still, surface the interpretation so an
            # analyst can catch a misreading of "since last Tuesday".
            notes.append(
                f"LLM-interpreted temporal window from fragment {fragment!r}: "
                f"start={start!r} end={end!r} (not verbatim-grounded; verify)"
            )
        elif t == "scope" and not _valid_scope_shape(spec):
            notes.append(
                f"dropped malformed LLM scope directive: {spec.get('params')} "
                f"(fragment: {fragment!r})"
            )
            continue
        specs.append(spec)
    return specs or None, False, notes


def synthesize(text: str, skip_ai: bool = False) -> dict:
    """Full Phase 1 synthesis: parse -> (llm) -> validate -> id-assign.

    Returns {"directives": [valid specs with directive_id], "warnings": [...],
             "deferred": bool, "llm_used": bool}.
    deferred=True means the LLM was unavailable (host mode / no API key) and
    fuzzy fragments could not be expanded. llm_used=True means the LLM
    produced at least one directive spec.
    """
    specs, unparsed = parse_deterministic(text)
    extra, warnings, deferred = llm_specs(unparsed, skip_ai)
    specs += extra

    valid: list[dict] = []
    for s in specs:
        if validate(s):
            valid.append(s)
        else:
            warnings.append(f"dropped invalid directive: {s.get('type')} {s.get('params')}")

    for i, s in enumerate(valid, start=1):
        s["directive_id"] = f"dir-{i:03d}"

    # llm_used: LLM was called AND produced at least one directive.
    llm_used = bool(extra) and not skip_ai

    return {"directives": valid, "warnings": warnings,
            "deferred": deferred, "llm_used": llm_used}
