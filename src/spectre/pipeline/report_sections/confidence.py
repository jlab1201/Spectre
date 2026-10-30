"""Corroboration/confidence predicates and the Executive Summary
"Confidence Assessment" table.
"""

from __future__ import annotations

from spectre.pipeline.report_sections.common import (
    _build_finding_groups,
    _finding_rule_ids,
)
from spectre.pipeline.report_sections.iocs import _is_identity_finding


def _is_cross_validated(finding: dict) -> bool:
    """True corroboration signal: is this finding independently corroborated
    by 2+ detection methods?

    ``cross_validated`` is the authoritative field — emit_finding.py sets it
    as ``sources >= 2``, computed from the correlation layer's source count,
    independent of the rule-level confidence that drives ``status``. A
    finding can be CONFIRMED (status reflects the deterministic
    corroboration threshold — source-count / rule confidence >= 0.6) while
    cross_validated is False and
    corroboration.sources == 1 — CONFIRMED status must never be read as
    "corroborated by multiple methods".

    Falls back to counting corroboration.sources / corroboration.tools when
    the top-level field is absent (older/synthetic finding dicts) — never
    infers corroboration from status.
    """
    if "cross_validated" in finding:
        return bool(finding.get("cross_validated"))
    corr = finding.get("corroboration") or {}
    sources = corr.get("sources")
    if isinstance(sources, (list, tuple, set)):
        if len(sources) >= 2:
            return True
    elif isinstance(sources, (int, float)) and sources >= 2:
        return True
    tools = corr.get("tools") or []
    if isinstance(tools, (list, tuple, set)) and len(tools) >= 2:
        return True
    return False


def _corroborated_count(findings: list[dict]) -> int:
    """Count of findings genuinely corroborated by multiple independent
    detection methods (see _is_cross_validated). This is the ONLY honest
    basis for a "corroborated by multiple detection methods" claim in the
    report — never the CONFIRMED-status count."""
    return sum(1 for f in findings if _is_cross_validated(f))


def _overall_confidence(findings: list[dict]) -> str:
    """Deterministic overall-confidence tier for the report banner. Mirrors
    the Verdict tiering; introduces no new confidence scale. HIGH when any
    finding is corroborated across independent methods; MEDIUM when any is
    CONFIRMED but none corroborated; LOW otherwise (single-source / none)."""
    if any(_is_cross_validated(f) for f in findings):
        return "HIGH"
    if any(f.get("status") == "CONFIRMED" for f in findings):
        return "MEDIUM"
    return "LOW"


# W4-2 / R1-F5: two independent, deterministic confidence axes. The old
# single tier collapsed every single-evidence case to "LOW" — even a 0.90
# rule — so the headline carried no signal. Detection strength comes from
# the rule's own confidence; corroboration from _is_cross_validated only.
def _detection_strength(conf) -> str:
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return "weak"
    if c >= 0.8:
        return "strong"
    if c >= 0.6:
        return "moderate"
    return "weak"


# W4 review LOW: context-only rules (identity facts, evidence-integrity flags)
# carry a confidence but are not detections — they never set headline strength.
_CONTEXT_RULES = frozenset({"pcap-host-identity", "pcap-evidence-tampered"})


def _is_context_finding(f: dict, rule_ids: dict | None = None) -> bool:
    rid = (rule_ids or {}).get(f.get("finding_id", ""), "") or f.get("rule_id", "")
    return rid in _CONTEXT_RULES or _is_identity_finding(f, rid)


def _confidence_label(findings: list[dict], rule_ids: dict | None = None) -> str:
    """"Strong single-source indicator" etc. A multi-source label is graded
    ONLY by the corroborated findings, so a strong single-source finding can
    never lend its strength to a weak corroborated one (honesty). Context
    findings are excluded from the strength basis."""
    if not findings:
        return "No findings"
    detections = [f for f in findings if not _is_context_finding(f, rule_ids)]
    if not detections:
        return "Context only (not a detection)"
    corroborated = [f for f in detections if _is_cross_validated(f)]
    basis = corroborated or detections
    top = max((f.get("confidence") or 0.0) for f in basis)
    axis = "multi-source" if corroborated else "single-source"
    return f"{_detection_strength(top).capitalize()} {axis} indicator"


def _overall_confidence_banner(findings: list[dict], rule_ids: dict | None = None) -> str:
    """Header banner text: the strongest detection label plus the
    corroboration count. Context-only findings never set the strength."""
    if not findings:
        return "No findings"
    detections = [f for f in findings if not _is_context_finding(f, rule_ids)]
    if not detections:
        return (f"No detection findings — {len(findings)} context-only finding(s) "
                f"(identity / evidence-integrity facts)")
    n_corr = _corroborated_count(detections)
    top = max((f.get("confidence") or 0.0) for f in detections)
    return (f"{_confidence_label(detections, rule_ids)}(s) — top detection confidence "
            f"{top:.2f}; {n_corr} of {len(detections)} detection finding(s) corroborated "
            f"by an independent source")


def _fid_list(findings: list[dict], limit: int = 8) -> str:
    ids = sorted({f.get("finding_id", "?") for f in findings})
    shown = ", ".join(ids[:limit])
    return shown + (f" (+{len(ids) - limit} more)" if len(ids) > limit else "")


def _section_confidence_assessment(findings: list[dict], manifest: dict) -> list[str]:
    """Executive Summary > Confidence Assessment table (per-claim rollup)."""
    lines = []

    # ── Confidence Assessment (per-claim rollup — deterministic grades from
    # status/corroboration; raw numeric floats stay in the Appendix). ──
    conf_groups = _build_finding_groups(findings)
    if conf_groups:
        lines.append("### Confidence Assessment\n")
        lines.append("| Claim | Findings | Confidence | Basis |")
        lines.append("|-------|----------|------------|-------|")
        # W4-2: collapse groups sharing a claim title (e.g. one recon title
        # under several MITRE ids) into one row that lists the finding IDs.
        by_claim: dict[str, list[dict]] = {}
        for group_label, g in conf_groups.items():
            claim = group_label.split(":", 1)[-1].strip() or group_label
            by_claim.setdefault(claim, []).extend(g["findings"])
        for claim, gf in by_claim.items():
            corr = [f for f in gf if _is_cross_validated(f)]
            confs = [float(f.get("confidence") or 0.0) for f in gf]
            rng = (f"{min(confs):.2f}" if min(confs) == max(confs)
                   else f"{min(confs):.2f}–{max(confs):.2f}")
            if corr and len(corr) == len(gf):
                basis = "corroborated by multiple independent methods"
            elif corr:
                basis = (f"corroborated only for {_fid_list(corr)}; "
                         f"others single-source")
            elif any(f.get("status") == "CONFIRMED" for f in gf):
                basis = "CONFIRMED (single detection source)"
            else:
                basis = "single-source lead (INFERRED)"
            label = _confidence_label(gf, _finding_rule_ids(findings, manifest))
            if label.startswith("Context only"):
                basis, rng_txt = "context fact (identity / evidence integrity)", ""
            else:
                rng_txt = f"; detection confidence {rng}"
            lines.append(f"| {claim} | {_fid_list(gf)} | {label} | {basis}{rng_txt}. |")
        lines.append("")
    return lines
