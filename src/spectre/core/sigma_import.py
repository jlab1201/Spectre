"""sigma_import.py — compile community Sigma rules into native Rules (Phase 3).

Sigma is the community on-ramp for **log-style** evidence. `compile_sigma`
turns a Sigma `process_creation` rule into the same native `Rule` object every
other rule compiles to — one engine runs everything, and the compiled rule
lands in the unified `ruleset.yaml` catalog tagged `rule_format: sigma`.

Design stance: **honest failure, never silent.** We support a documented
common subset (the constructs real process_creation rules actually use).
Anything outside it — an unmapped field, an unsupported modifier, an
aggregation/correlation condition — is REJECTED with a clear
`SigmaUnsupportedError`, never best-guessed. A Sigma rule can therefore never
miscompile into a wrong forensic finding; it either compiles faithfully or it
does not compile at all.

Supported subset
  * logsource: category `process_creation`.
  * named selections: `field|modifiers: value` or `field|modifiers: [v1, v2]`,
    and a list-of-maps selection (OR of maps).
  * modifiers: `contains`, `startswith`, `endswith`, `re`, and `all`
    (combined with at most one of the string modifiers).
  * condition: names combined with `and`/`or`/`not`/parentheses, and the
    quantifiers `N of <glob|them>` / `all of <glob|them>`.
  * fields: the mapped process_creation fields below.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

import yaml

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata

ARTIFACT = "process_creation"

# Sigma field -> Spectre normalized process_creation field. Full-path fields
# (image, parent_image) are used so Sigma's `|endswith: '\\foo.exe'` works.
SIGMA_FIELD_MAP = {
    "Image": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image",
    "ParentCommandLine": "parent_command_line",
    "User": "user",
    "IntegrityLevel": "integrity_level",
    "Hashes": "hashes",
}

_STRING_MODIFIERS = {"contains", "startswith", "endswith", "re"}
_ALL_MODIFIERS = _STRING_MODIFIERS | {"all"}
_SUPPORTED_CATEGORIES = {"process_creation"}
_LEVELS = {"critical", "high", "medium", "low", "informational"}
_LEVEL_CONFIDENCE = {
    "critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3, "informational": 0.1,
}
_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


class SigmaUnsupportedError(ValueError):
    """A Sigma rule uses a construct outside the supported subset.

    Raised instead of guessing, so a rule never silently miscompiles into a
    wrong finding. The caller (rule discovery) skips the file with a warning.
    """


# ────────────────────────────────────────────────────────────────────
# Field- and selection-level matchers
# ────────────────────────────────────────────────────────────────────
def _match_one(mod: str, field_value: str, target) -> bool:
    if target is None:
        # `field: null` (existence/null test) is outside the subset.
        raise SigmaUnsupportedError("null match values are not supported")
    if mod == "re":
        return re.search(str(target), field_value, re.IGNORECASE) is not None
    fv = field_value.lower()
    tv = str(target).lower()
    if mod == "contains":
        return tv in fv
    if mod == "startswith":
        return fv.startswith(tv)
    if mod == "endswith":
        return fv.endswith(tv)
    return fv == tv  # default: equality


def _build_field_matcher(key: str, value) -> Callable[[NormEvent], bool]:
    parts = key.split("|")
    field = parts[0]
    mods = parts[1:]

    unknown = set(mods) - _ALL_MODIFIERS
    if unknown:
        raise SigmaUnsupportedError(f"unsupported modifier(s): {sorted(unknown)}")
    if field not in SIGMA_FIELD_MAP:
        raise SigmaUnsupportedError(f"unmapped Sigma field: {field!r}")

    string_mods = [m for m in mods if m in _STRING_MODIFIERS]
    if len(string_mods) > 1:
        raise SigmaUnsupportedError(
            f"only one string modifier supported, got {string_mods}")
    mod = string_mods[0] if string_mods else "equals"
    use_all = "all" in mods

    spectre_field = SIGMA_FIELD_MAP[field]
    values = value if isinstance(value, list) else [value]
    if any(isinstance(v, (dict, list)) for v in values):
        raise SigmaUnsupportedError(f"nested value not supported for {field!r}")

    def matcher(e: NormEvent) -> bool:
        fv = str(e.data.get(spectre_field, "") or "")
        results = [_match_one(mod, fv, v) for v in values]
        return all(results) if use_all else any(results)

    return matcher


def _build_selection_matcher(seldef) -> Callable[[NormEvent], bool]:
    if isinstance(seldef, dict):
        specs = [_build_field_matcher(k, v) for k, v in seldef.items()]
        return lambda e: all(s(e) for s in specs)  # AND across fields
    if isinstance(seldef, list):
        subs = [_build_selection_matcher(d) for d in seldef]
        return lambda e: any(s(e) for s in subs)  # OR across maps
    raise SigmaUnsupportedError("selection must be a map or list of maps")


# ────────────────────────────────────────────────────────────────────
# Condition parser (recursive descent over the supported grammar)
# ────────────────────────────────────────────────────────────────────
def _tokenize(condition: str) -> list[str]:
    # Keep parens as their own tokens; everything else is whitespace-split.
    # An aggregation pipe (`| count()`) survives as a stray token and is
    # rejected downstream, which is exactly what we want.
    return re.findall(r"\(|\)|[^\s()]+", condition)


def _parse_condition(condition: str,
                     sel_names: list[str]) -> Callable[[dict], bool]:
    if not isinstance(condition, str):
        raise SigmaUnsupportedError("condition must be a single string")
    if "|" in condition:
        raise SigmaUnsupportedError("aggregation conditions are not supported")
    tokens = _tokenize(condition)
    if not tokens:
        raise SigmaUnsupportedError("empty condition")
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos] if pos < len(tokens) else None

    def consume() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def resolve_glob(target: str) -> list[str]:
        if target == "them":
            names = list(sel_names)
        elif target.endswith("*"):
            prefix = target[:-1]
            names = [n for n in sel_names if n.startswith(prefix)]
        elif target in sel_names:
            names = [target]
        else:
            raise SigmaUnsupportedError(f"unknown selection: {target!r}")
        if not names:
            raise SigmaUnsupportedError(f"no selection matches {target!r}")
        return names

    def parse_atom() -> Callable[[dict], bool]:
        tok = peek()
        if tok is None:
            raise SigmaUnsupportedError("unexpected end of condition")
        if tok == "(":
            consume()
            node = parse_or()
            if peek() != ")":
                raise SigmaUnsupportedError("missing closing parenthesis")
            consume()
            return node
        # quantifier:  (N | all) of (glob | them)
        if (tok == "all" or tok.isdigit()) and \
                pos + 1 < len(tokens) and tokens[pos + 1] == "of":
            q = consume()
            consume()  # 'of'
            if peek() is None:
                raise SigmaUnsupportedError("quantifier missing target")
            names = resolve_glob(consume())
            if q == "all":
                return lambda m: all(m[n] for n in names)
            need = int(q)
            return lambda m: sum(bool(m[n]) for n in names) >= need
        # bare selection name
        if tok in ("and", "or", "not", "of", ")"):
            raise SigmaUnsupportedError(f"unexpected token: {tok!r}")
        if tok not in sel_names:
            raise SigmaUnsupportedError(f"unknown selection: {tok!r}")
        consume()
        return lambda m: bool(m[tok])

    def parse_not() -> Callable[[dict], bool]:
        if peek() == "not":
            consume()
            inner = parse_not()
            return lambda m: not inner(m)
        return parse_atom()

    def _and(left, right):
        return lambda m: left(m) and right(m)

    def _or(left, right):
        return lambda m: left(m) or right(m)

    def parse_and() -> Callable[[dict], bool]:
        node = parse_not()
        while peek() == "and":
            consume()
            node = _and(node, parse_not())
        return node

    def parse_or() -> Callable[[dict], bool]:
        node = parse_and()
        while peek() == "or":
            consume()
            node = _or(node, parse_and())
        return node

    node = parse_or()
    if pos != len(tokens):
        raise SigmaUnsupportedError(f"unparsed condition tokens: {tokens[pos:]}")
    return node


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────
def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "sigma-rule"


def _mitre_from_tags(tags: list[str]) -> list[str]:
    out: list[str] = []
    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        candidate = tag.split(".", 1)[1]  # drop the 'attack.' prefix
        if _TECHNIQUE_RE.match(candidate):
            tech = candidate.upper()
            if tech not in out:
                out.append(tech)
    return out


def compile_sigma(yaml_text: str) -> Rule:
    """Compile a Sigma rule into a native `Rule`, or raise.

    Raises `SigmaUnsupportedError` for anything outside the supported subset so
    the rule is never silently miscompiled into a wrong finding.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise SigmaUnsupportedError(f"invalid Sigma YAML: {e}") from e
    if not isinstance(doc, dict):
        raise SigmaUnsupportedError("Sigma rule must be a YAML mapping")

    logsource = doc.get("logsource") or {}
    category = logsource.get("category") if isinstance(logsource, dict) else None
    if category not in _SUPPORTED_CATEGORIES:
        raise SigmaUnsupportedError(
            f"unsupported logsource category: {category!r} "
            f"(supported: {sorted(_SUPPORTED_CATEGORIES)})")

    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaUnsupportedError("detection block must define a condition")
    condition = detection["condition"]
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaUnsupportedError("detection defines no selections")

    sel_matchers = {name: _build_selection_matcher(defn)
                    for name, defn in selections.items()}
    cond_eval = _parse_condition(condition, list(selections.keys()))

    # ── metadata / identity ──
    title = str(doc.get("title") or "untitled sigma rule")
    description = str(doc.get("description") or title)
    uuid = str(doc.get("id") or "")
    level = str(doc.get("level") or "").lower()
    # An absent/unknown level is UNRATED (None), never an unassessed
    # "medium"; confidence keeps its neutral 0.5 default in that case.
    severity = level if level in _LEVELS else None
    confidence = _LEVEL_CONFIDENCE.get(severity, 0.5)
    references = [str(r) for r in (doc.get("references") or [])]
    raw_tags = [str(t) for t in (doc.get("tags") or [])]
    false_positives = [str(f) for f in (doc.get("falsepositives") or [])]
    mitre = _mitre_from_tags(raw_tags)
    rule_id = _slug(title)

    metadata = RuleMetadata(
        uuid=uuid, name=title, author=str(doc.get("author") or ""),
        date=str(doc.get("date") or ""), version=str(doc.get("version") or ""),
        references=references, false_positives=false_positives,
        severity=severity, tags=raw_tags, rule_format="sigma",
        rule_source=f"sigma:{title}",
    )

    def predicate(e: NormEvent) -> Optional[Anchor]:
        if e.artifact_type != ARTIFACT:
            return None
        matched = {name: m(e) for name, m in sel_matchers.items()}
        if not cond_eval(matched):
            return None
        return Anchor(
            rule_id=rule_id,
            artifact_type=ARTIFACT,
            event=e,
            title=title,
            mitre=list(mitre),
            confidence=confidence,
            summary=(f"sigma '{title}': {e.data.get('image_basename')} "
                     f"(rec {e.record_id}) cmd={e.data.get('command_line')}"),
        )

    return Rule(
        rule_id=rule_id,
        artifact_type=ARTIFACT,
        predicate=predicate,
        mitre=list(mitre),
        description=description,
        metadata=metadata,
    )
