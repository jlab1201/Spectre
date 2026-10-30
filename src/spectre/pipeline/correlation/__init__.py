"""Forensic correlation engine — corroboration scoring (v6 formula).

Implements the mechanical confidence layer specified in
`skills/correlation-engine/SKILL.md`: distinct sources detecting the SAME claim
raise the finding from INFERRED to CONFIRMED. No LLM involvement.

This module owns the pure, testable core. The Phase 3 dispatcher calls
`corroborate()` over its anchors instead of blindly de-duplicating them, so the
fact that two engines (volatility3 + memprocfs) agreed survives into the
finding instead of being discarded.

A "source" is a distinct ``(source_tool, artifact_type)`` pair — which captures
both cross-tool corroboration (vol pslist + mpfs pslist) and, later,
cross-artifact corroboration (pslist + netscan) under one rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from spectre.core.base import Anchor

# Source count → (status, confidence). Authoritative copy of the v6 formula;
# kept in lock-step with skills/correlation-engine/SKILL.md and the
# SOURCE_TO_STATUS tables in the emit_finding modules.
SOURCE_TO_STATUS = {
    0: ("DROPPED", 0.0),
    1: ("INFERRED", 0.50),
    2: ("CONFIRMED", 0.75),
    3: ("CONFIRMED", 1.00),
}


def score_corroboration(sources: int) -> tuple[str, float]:
    """Map a source count to (status, confidence), capped at 3."""
    return SOURCE_TO_STATUS[min(max(sources, 0), 3)]


@dataclass
class CorroboratedGroup:
    """One claim, with every anchor that asserted it across sources."""
    representative: Anchor          # first anchor seen — drives title/iocs/mitre
    members: list[Anchor] = field(default_factory=list)
    sources: int = 1                # distinct (source_tool, artifact_type) count
    source_labels: list[str] = field(default_factory=list)

    @property
    def cross_validated(self) -> bool:
        return self.sources >= 2

    @property
    def occurrence_count(self) -> int:
        """How many raw anchors collapsed into this one claim."""
        return len(self.members)

    @property
    def first_seen(self) -> str:
        """Timestamp of the earliest member. Members are appended in
        evidence order, so members[0] is chronologically first — this
        avoids lexically sorting timestamp strings, which is wrong for
        tshark's 'Feb 28, 2026 …' frame.time format."""
        return self.members[0].event.timestamp if self.members else ""

    @property
    def last_seen(self) -> str:
        return self.members[-1].event.timestamp if self.members else ""


def _source_label(anchor: Anchor) -> str:
    tool = getattr(anchor.event, "source_tool", "") or "unknown"
    return f"{tool}/{anchor.event.artifact_type}"


# A7 Finding 1 fix — "distinct source" must mean independently-derived
# evidence, not "the same evidence file viewed twice in one pipeline run."
#
# `(source_tool, artifact_type)` is normally the right unit: it captures
# genuine cross-tool/cross-artifact corroboration (vol pslist + memprocfs
# pslist; EVTX 4688 + Prefetch). But pcap's shipped default engine breaks
# that invariant by design: `modules/pcap/extract.py` runs Zeek AND
# *also* retains a tcpdump gap-fill pass over the IDENTICAL evidence file
# in the SAME extraction run (Zeek is the primary engine; tcpdump's HTTP
# ASCII-payload and checksum passes fill gaps Zeek's structured logs don't
# cover). Zeek, tcpdump, and tshark all just re-parse the same captured
# packets out of the same .pcap file with libpcap underneath — they are
# different TEXTUAL RENDERINGS of one observation, not independently
# derived evidence. When a rule reads a field both renderings populate
# identically (e.g. HTTP User-Agent/Host header), it fires once per
# rendering for the identical transaction, and naively counting distinct
# source_tool values manufactures a second "source" out of nothing.
#
# The fix: tools that belong to one of the families below are ADDITIONALLY
# scoped by `source_file` when computing source identity, so multiple
# built-in passes of the SAME parsing family over the SAME evidence file
# collapse into one source — while the same family over two DIFFERENT
# evidence files (genuinely two capture files) still counts as two, and a
# tool NOT listed here is unaffected.
#
# This must NOT collapse `spectre_memory.py`'s dual-engine mode
# (volatility3 + MemProcFS over one memory image — see
# `modules/memory/__init__.py`'s `extract(..., engine="both")` default).
# That IS legitimate independent corroboration: two unrelated codebases
# independently walking kernel structures, deliberately run side-by-side
# for confidence scoring, not one tool's incidental gap-fill pass.
# "volatility3" and "memprocfs" are not members of any family below, so
# they always fall through to the normal (tool, artifact_type) identity
# and are always counted as distinct sources — see
# tests/test_correlation/test_corroboration.py::
# test_memory_dual_engine_same_file_still_two_sources for the regression
# guard.
_SHARED_EVIDENCE_TOOL_FAMILIES: dict[str, frozenset] = {
    "pcap-capture": frozenset({"tcpdump", "tshark", "zeek"}),
}


def _tool_family(tool: str) -> str:
    """Canonical family for a source_tool value, used only to decide
    source independence (see _SHARED_EVIDENCE_TOOL_FAMILIES above).
    "zeek:http" / "zeek:conn" (Zeek's per-log-file tool naming) reduce to
    "zeek". Anything not listed in a family falls back to the raw tool
    string, so it is never accidentally merged with another tool."""
    base = tool.split(":", 1)[0]
    for family, members in _SHARED_EVIDENCE_TOOL_FAMILIES.items():
        if base in members:
            return family
    return tool


def _source_identity(anchor: Anchor) -> tuple:
    """The unit counted as one distinct source for a claim.

    Normally (tool, artifact_type). For tools in a same-evidence family
    (pcap capture-layer parsers), additionally scoped by source_file, so
    incidental multi-pass parsing of ONE file collapses to one source
    while the same family over genuinely different files does not.
    """
    tool = getattr(anchor.event, "source_tool", "") or "unknown"
    family = _tool_family(tool)
    if family in _SHARED_EVIDENCE_TOOL_FAMILIES:
        return (family, anchor.event.artifact_type, anchor.event.source_file)
    return (tool, anchor.event.artifact_type)


def corroborate(anchors: list[Anchor]) -> list[CorroboratedGroup]:
    """Group anchors by claim ``(rule_id, dedup_key or title)`` and count the
    distinct sources behind each. Insertion order is preserved; the first
    anchor of each claim is the representative.
    """
    groups: dict[tuple, CorroboratedGroup] = {}
    order: list[tuple] = []
    for a in anchors:
        key = (a.rule_id, a.dedup_key or a.title)
        if key not in groups:
            groups[key] = CorroboratedGroup(representative=a)
            order.append(key)
        groups[key].members.append(a)

    for key in order:
        g = groups[key]
        # source_labels: every raw (tool, artifact_type) label seen, kept
        # for transparency in the finding's corroboration.tools field even
        # when two labels collapse to one source below.
        g.source_labels = sorted({_source_label(a) for a in g.members})
        g.sources = len({_source_identity(a) for a in g.members})
    return [groups[k] for k in order]


def purge_dropped_findings(case_dir: str) -> list[str]:
    """Remove DROPPED-status finding YAMLs from disk (A7 Finding 2 side-note).

    `pipeline/emit_finding.py` writes a finding YAML for EVERY anchor
    regardless of status, including DROPPED (0-source) findings, and no
    code path anywhere in the repository ever unlinks one — contradicting
    `skills/correlation-engine/SKILL.md` / `skills/report-generator/
    SKILL.md`'s documented claim "0 sources -> DROPPED (auto-purged)".
    `emit_finding.py` itself is out of scope for this change (WS3), so
    this is a standalone cleanup pass: point it at a case directory (after
    Phase 3/detection has written findings) and it deletes every finding
    whose persisted state is DROPPED in substance — literal
    ``status == "DROPPED"``, OR ``corroboration.sources == 0``, OR no
    ``evidence_refs`` at all (the same "0 resolvable sources" signal
    `phase_runner.py`'s `run_phase_4` already checks, just now acted on
    instead of only reported).

    NOT YET WIRED into the live pipeline: the natural call site is
    `phase_runner.py`'s Phase 3 (right after emit) or Phase 4 (which
    already loads every finding file), both out of scope for WS3. Call
    this explicitly, or wire it in from an in-scope entry point, to make
    the purge actually run for a live case.

    Returns the list of file paths removed.
    """
    findings_dir = Path(case_dir) / "findings"
    if not findings_dir.exists():
        return []

    removed: list[str] = []
    for fp in sorted(findings_dir.glob("F-*-*.yaml")):
        try:
            finding = yaml.safe_load(fp.read_text())
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(finding, dict):
            continue
        sources = (finding.get("corroboration") or {}).get("sources")
        is_dropped = (
            finding.get("status") == "DROPPED"
            or sources == 0
            or finding.get("evidence_refs") == []
        )
        if is_dropped:
            fp.unlink()
            removed.append(str(fp))
    return removed
