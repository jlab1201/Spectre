"""
base.py — core dataclasses and the AnalyzerModule protocol for the
modular Spectre evidence pipeline.

An *analyzer module* is a self-contained capability for one evidence type
(EVTX, memory, pcap, disk, ...). It owns four type-specific concerns:

  1. recognition  — Recognizer signatures that claim a dropped file
  2. extraction   — extract(case_dir, evidence_path) -> list[handle]   (via tool_runner.run_tool)
  3. normalization— normalize(handle) -> list[NormEvent]
  4. detection    — rules: list[Rule] (a per-module rule pack)

The pipeline (recognize.py + phase_runner) owns everything generic:
file triage, dispatch, finding emission, correlation, reporting.

A module is *complete* when all four parts exist, and is independently
testable: drop its sample evidence, assert extract -> normalize -> rules.
The pipeline runs with as few as ONE module registered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ────────────────────────────────────────────────────────────────────
# Normalized event — the common currency every module produces and
# every detection rule consumes.
# ────────────────────────────────────────────────────────────────────
@dataclass
class NormEvent:
    """A single normalized observation from any evidence type.

    `artifact_type` identifies the schema of `data` (e.g. "evtx_4688",
    "memory_pslist", "pcap_conn"). Detection rules declare which
    artifact_type they consume and read type-specific fields from `data`.
    """
    artifact_type: str
    timestamp: str
    source_file: str
    record_id: str
    host: str = ""
    data: dict = field(default_factory=dict)
    # Provenance: the tool/engine that produced this observation (e.g.
    # "volatility3", "memprocfs"). Set in Phase 2 from the extraction handle.
    # Rules stay engine-agnostic and never branch on it; only the correlation
    # layer reads it, to count distinct sources for the same claim.
    source_tool: str = ""
    # Provenance: the execution_id of the SPECIFIC extraction handle that
    # produced this event. Set in Phase 2 alongside source_tool. Unlike
    # source_tool (which only distinguishes different engines, e.g.
    # volatility3 vs memprocfs), this distinguishes different PASSES by the
    # SAME tool over the SAME evidence file (e.g. pcap's tcpdump runs four
    # separate passes — connections/dns/http/timing — that all share one
    # evidence_path and one tool name). Phase 3 uses it to recover the exact
    # handle (and therefore the exact tool/exact_command) that produced this
    # event, so a finding's provenance is never inherited from an unrelated
    # pass over the same evidence file.
    source_execution_id: str = ""


# ────────────────────────────────────────────────────────────────────
# Detection — Anchor (a hit) and Rule (a predicate).
# ────────────────────────────────────────────────────────────────────
def _empty_iocs() -> dict:
    return {"filepath": [], "ip": [], "domain": [], "sha256": [],
            "registry_key": [], "host": [], "account": []}


@dataclass
class Anchor:
    """A deterministic detection hit. Generic over evidence type."""
    rule_id: str
    artifact_type: str
    event: NormEvent
    title: str
    mitre: list[str] = field(default_factory=list)
    confidence: float = 0.5
    iocs: dict = field(default_factory=_empty_iocs)
    # Human-readable one-line summary of the corroborating artifact,
    # written verbatim into the finding's corroboration.artifacts list.
    summary: str = ""
    # Stable key for collapsing duplicate hits of the same rule (e.g. the
    # same env var inherited by many processes, or the same URL). When set,
    # Phase 3 emits ONE finding per (rule_id, dedup_key). Empty -> use title.
    dedup_key: str = ""


@dataclass
class RuleMetadata:
    """A rule's defensibility / identity card.

    Purely descriptive — it never affects what a predicate matches. It records
    who authored a rule, how severe a hit is, the references that justify it,
    its known false positives, free-form tags, and the format it was authored
    in (``python`` for a native predicate, ``sigma`` for a compiled Sigma
    rule). It is optional on a Rule (legacy rules omit it) and is surfaced in
    the per-case ``ruleset.yaml`` catalog so a reviewer can judge each rule.
    """
    uuid: str = ""
    name: str = ""
    author: str = ""
    date: str = ""
    version: str = ""
    references: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    # critical | high | medium | low | informational | None.
    # Defaults to None (NOT "medium") so "author assessed medium" is
    # distinguishable from "author set no level"; display consumers map
    # None -> UNRATED. A rule that genuinely means medium sets it explicitly.
    severity: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    # python | sigma — how the rule was authored.
    rule_format: str = "python"
    # provenance: where the rule came from (file path, Sigma title, doc, ...).
    rule_source: str = ""
    # Data fields from NormEvent.data that this rule reads. The pipeline
    # checks these before detection; a rule whose required fields are
    # absent from the normalized output is reported as NOT_EVALUATED
    # instead of silently returning empty.
    required_fields: list[str] = field(default_factory=list)


@dataclass
class Rule:
    """A single detection rule.

    `predicate(event) -> Optional[Anchor]`: return an Anchor when the
    event matches, else None. Predicates MUST be pure (no I/O) so they
    are trivially unit-testable against sample NormEvents.
    """
    rule_id: str
    artifact_type: str
    predicate: Callable[[NormEvent], Optional[Anchor]]
    mitre: list[str] = field(default_factory=list)
    description: str = ""
    # Optional defensibility card. None on legacy rules — nothing breaks.
    metadata: Optional[RuleMetadata] = None


# ────────────────────────────────────────────────────────────────────
# Recognition — a signature that claims a dropped file for a module.
# ────────────────────────────────────────────────────────────────────
@dataclass
class Recognizer:
    """Signature used to triage a dropped file to a module.

    A file is claimed if its extension is in `extensions` OR any string
    in `magic_patterns` is a (case-insensitive) substring of the
    libmagic description, optionally confirmed by `sniff(path) -> bool`.
    """
    module_name: str
    artifact_type: str
    extensions: set[str] = field(default_factory=set)
    magic_patterns: list[str] = field(default_factory=list)
    sniff: Optional[Callable[[Path], bool]] = None
    confidence: float = 0.9

    def match(self, path: Path, magic_desc: str) -> float:
        """Return a confidence score in [0, 1]; 0.0 means no claim."""
        ext_hit = path.suffix.lower() in {e.lower() for e in self.extensions}
        magic_hit = any(p.lower() in magic_desc.lower() for p in self.magic_patterns)
        if not (ext_hit or magic_hit):
            return 0.0
        if self.sniff is not None:
            try:
                if not self.sniff(path):
                    return 0.0
            except Exception:
                return 0.0
        # Extension + magic agreement is strongest; either alone is fine.
        score = self.confidence
        if ext_hit and magic_hit:
            score = min(1.0, self.confidence + 0.05)
        return score


# ────────────────────────────────────────────────────────────────────
# Availability — can this module actually extract, on this host?
# ────────────────────────────────────────────────────────────────────
@dataclass
class ModuleAvailability:
    """Answer to "can this module do its job here?", with a reason.

    A tool list is the wrong question. pcap declares
    `required_tools=["tcpdump"]` deliberately minimally, yet a host with Zeek
    and no tcpdump extracts pcaps completely; disk needs `fls`/`mmls` but a
    Sleuth Kit built without libewf cannot open an E01 specifically. Both used
    to be `if analyzer.name == ...` special cases inside recognize.py, which
    meant the canary — a different caller — got the naive answer and reported
    the module unavailable on the very host it works on.

    Three states, not two: `available=False` (cannot extract at all),
    `available=True, degraded=True` (works, with fewer passes or reduced
    fidelity), and plain available. `missing` names the ONE tool worth putting
    in front of a reader; `detail` is the human sentence.
    """
    available: bool
    missing: str = ""
    detail: str = ""
    degraded: bool = False


# ────────────────────────────────────────────────────────────────────
# The module itself.
# ────────────────────────────────────────────────────────────────────
@dataclass
class AnalyzerModule:
    name: str
    artifact_type: str
    required_tools: list[str]
    recognizers: list[Recognizer]
    # extract(case_dir, evidence_path) -> list[handle dicts from run_tool]
    extract: Callable[[str, str], list[dict]]
    # normalize(handle) -> list[NormEvent]
    normalize: Callable[[dict], list[NormEvent]]
    rules: list[Rule] = field(default_factory=list)
    description: str = ""
    # Optional cross-event enrichment, run once over the FULL event list
    # (all modules' events, not just this module's) before detection.
    # enrich(events) -> None; mutates event.data IN PLACE to stamp
    # computable facts (e.g. "has a hidden-process peer") so rules stay
    # pure single-event predicates. MUST NOT add/remove events — Phase 3
    # asserts the length is unchanged and raises if it isn't (deterministic
    # core; an enrichment bug must be loud, not silently swallowed).
    # Defaults to None so all pre-existing modules stay valid unchanged.
    enrich: Optional[Callable[[list], None]] = None
    # Optional host-capability probe: availability(path=None) ->
    # ModuleAvailability. Called with no path for a module-level verdict (the
    # canary) and with a path when triaging one specific file (recognize.py),
    # because some capabilities are per-file — a Sleuth Kit without libewf
    # handles a raw .dd and not an .E01. Defaults to None, in which case
    # callers fall back to "every required_tool resolves on PATH", so all
    # pre-existing modules stay valid unchanged (the `enrich` precedent).
    availability: Optional[Callable[..., ModuleAvailability]] = None


def check_rule_fields(rule: Rule, sample_normevents: list) -> tuple[bool, list[str]]:
    """Check if a rule's required fields exist in the normalized output.

    Iterates ALL sample events (no slicing) so that fields unique to
    later artifact types (e.g. pcap_dns, pcap_http, pcap_timing) are
    not missed. A rule with no requirements always returns (True, []).
    """
    required = rule.metadata.required_fields if rule.metadata else []
    if not required:
        return True, []

    # Gather all field names from every sample event (cross-artifact-type sampling)
    available: set[str] = set()
    for event in sample_normevents:
        available.update(event.data.keys())

    missing = [f for f in required if f not in available]
    return len(missing) == 0, missing
