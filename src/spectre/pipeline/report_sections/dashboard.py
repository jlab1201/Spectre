"""Dashboard metrics (TB-port T5): computed once, persisted into the
manifest, read by report.md and the PDF/DOCX dashboards.
"""

from __future__ import annotations

import hashlib
import json
import yaml
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from spectre.pipeline.report_sections.common import _finding_rule_ids, _parse_finding_ts
from spectre.pipeline.report_sections.confidence import (
    _confidence_label,
    _corroborated_count,
    _detection_strength,
    _is_context_finding,
    _is_cross_validated,
    _overall_confidence_banner,
)
from spectre.pipeline.report_sections.intake import (
    _coverage_counts,
    _coverage_sentence,
    _extraction_records,
)
from spectre.pipeline.report_sections.mitre import _load_mitre_tactics, _tactic_rank
from spectre.pipeline.report_sections.verdict import _finding_mitre_ids, verdict_class


# ── Dashboard metric helper (TB-port T5: single, persisted source of truth) ──
# Canonical display-severity vocabulary. A ruleset severity string resolves to
# one of these (uppercased); anything null/absent/unresolved → UNRATED.
# Order is the render order for the severity-distribution bar (CRITICAL →
# UNRATED). "INFORMATIONAL" is a real ruleset value outside the 5-colour
# palette; it is carried honestly (never up-graded) and styled muted.
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
    "UNRATED": 5,
}


# A6: stamped on every dashboard, mirroring _narrative_provenance_line.
DASHBOARD_PROVENANCE = ("Deterministic — computed from finding facts; "
                        "no AI input")


def _severity_rank(sev: str) -> int:
    """Rank a display-severity for ordering/argmax. Unknown → last."""
    return _SEVERITY_RANK.get(sev, len(_SEVERITY_RANK))


def _load_ruleset_severities(case_dir: str) -> dict[str, "str | None"]:
    """{rule_id: severity_or_None} from the case-local ``ruleset.yaml``.

    The snapshot is the chain-of-custody-frozen record of the rule pack that
    ran DURING the case (Phase 3 writes it via build_ruleset_snapshot); the
    report reads severity from it, NOT from the live registry, so it reflects
    what actually ran. A missing file, unparseable YAML, or a rule with
    no/blank severity all map to None → UNRATED. Never raises.
    """
    if not case_dir:
        return {}
    path = Path(case_dir) / "ruleset.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (yaml.YAMLError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, "str | None"] = {}
    for rule in (data.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        rid = rule.get("rule_id")
        if not rid:
            continue
        sev = rule.get("severity")
        out[rid] = sev if (isinstance(sev, str) and sev.strip()) else None
    return out


def _resolve_finding_severity(
    finding: dict,
    rule_ids: dict[str, str],
    ruleset_sev: dict[str, "str | None"],
) -> str:
    """Resolve ONE finding to a display severity:

      1. finding → rule_id via _finding_rule_ids (passed in as ``rule_ids``).
      2. rule_id → severity from the case-local ruleset.yaml snapshot.
      3. snapshot absent / rule unresolved / severity null → UNRATED.

    NEVER derives severity from confidence or status — severity ("how bad if
    confirmed") and confidence/status ("how sure are we") are orthogonal.
    """
    fid = finding.get("finding_id")
    rid = rule_ids.get(fid) if fid else None
    if not rid:
        return "UNRATED"
    sev = ruleset_sev.get(rid)
    if not sev:
        return "UNRATED"
    return sev.strip().upper()


def _utc_iso(dt: "datetime") -> str:
    """UTC-naive datetime (from _parse_finding_ts) → ISO string with 'Z'."""
    return dt.isoformat() + "Z"


def _coverage_block(manifest: dict) -> dict:
    """A3: the coverage picture the dashboard must show, from the SAME
    W4-A functions the Verdict uses (_coverage_counts / _coverage_sentence /
    _extraction_records), so a blind or failed case can never look clean.

    state: "no_coverage" (items registered, none examined — EMPTY and
    EXTRACTION_FAILED both count as unexamined), "partial", "full", or
    "not_recorded" (no extraction results at all — no coverage claim is
    possible either way)."""
    examined, total = _coverage_counts(manifest)
    recs = _extraction_records(manifest)
    failed = sum(1 for r in recs if r["extraction_status"] == "EXTRACTION_FAILED")
    empty = sum(1 for r in recs if r["extraction_status"] == "EMPTY")
    if total == 0:
        state = "not_recorded"
    elif examined == 0:
        state = "no_coverage"
    elif examined < total:
        state = "partial"
    else:
        state = "full"
    return {
        "examined": examined,
        "total": total,
        "state": state,
        "failed": failed,
        "empty": empty,
        # Plain text (markdown emphasis stripped) — rendered verbatim by the
        # PDF/DOCX dashboards, which are not markdown surfaces.
        "sentence": _coverage_sentence(manifest).replace("**", "").strip(),
    }


def _dashboard_metrics(findings: list[dict], manifest: dict, case_dir: str) -> dict:
    """Aggregate existing finding facts for the PDF/DOCX dashboard AND the
    counts the executive-summary prose states. Deterministic; invents nothing
    (no finding, no MITRE ID, no caveat — pure aggregation over facts the
    deterministic core already produced). Persisted into
    manifest["report"]["dashboard_metrics"] so every consumer reads the SAME
    value.

    Honesty amendments over the TB branch (TB-PORT.md A1/A3/A4/A6):
      - ``verdict_class`` (the Validator-11 class) rides along; the headline
        always carries its lead's status + corroboration axis, so a
        leads-only case never headlines a bare "CRITICAL" title (A1).
      - ``coverage`` reuses _coverage_counts/_coverage_sentence (EMPTY and
        EXTRACTION_FAILED are unexamined) (A3).
      - kill-chain ``first_seen`` is UTC-normalised via _parse_finding_ts and
        is ordinal (ATT&CK order), never a claimed sequence (A4).
      - ``provenance`` stamp; the sha256 is recorded in the Phase-6 audit
        row (A6, see _dashboard_metrics_sha256).
    Confidence wording reuses the W4-B predicates (_confidence_label,
    _overall_confidence_banner, _detection_strength, _is_cross_validated) —
    never a separately derived confidence scale.

    Shape (all JSON/YAML-serialisable):
      kpis: findings_total, confirmed, inferred, corroborated,
            inferred_single_source, mitre_techniques, evidence_items
      finding_severity: {finding_id: display severity} (finding-card rails)
      severity_counts: [{severity, confirmed, inferred, total}] CRITICAL→UNRATED
      top_severity: str | None
      headline: {finding_id, title, severity, status, corroboration,
                 detection_strength, qualifier} | None
      threat_headline: str  ("<qualifier>: <title>", "" if none)
      verdict_class, coverage, confidence_label, confidence_banner
      tactic_coverage: [{tactic, rank, technique_count, techniques}]
      kill_chain: [{tactic, rank, first_seen, technique_count}]
      kill_chain_basis: "attck_order"
      provenance: str
    """
    findings = findings or []
    manifest = manifest or {}
    rule_ids = _finding_rule_ids(findings, manifest)
    ruleset_sev = _load_ruleset_severities(case_dir)

    # ── KPIs (status counts + the one corroboration predicate) ──
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    inferred = sum(1 for f in findings if f.get("status") == "INFERRED")
    distinct_techniques: set[str] = set()
    for f in findings:
        distinct_techniques.update(_finding_mitre_ids(f))
    evidence_items = len([
        ev for ev in (manifest.get("evidence") or []) if isinstance(ev, dict)
    ])
    kpis = {
        "findings_total": len(findings),
        "confirmed": confirmed,
        "inferred": inferred,
        "corroborated": _corroborated_count(findings),
        # A2: the "(single-source)" legend is shown only when this equals
        # `inferred` — read from _is_cross_validated, never hard-coded.
        "inferred_single_source": sum(
            1 for f in findings
            if f.get("status") == "INFERRED" and not _is_cross_validated(f)),
        "mitre_techniques": len(distinct_techniques),
        "evidence_items": evidence_items,
    }

    # ── Severity distribution, split by status ──
    sev_split: dict[str, dict[str, int]] = defaultdict(
        lambda: {"confirmed": 0, "inferred": 0, "total": 0})
    per_finding_sev: dict[str, str] = {}
    for f in findings:
        sev = _resolve_finding_severity(f, rule_ids, ruleset_sev)
        fid = f.get("finding_id")
        if fid:
            per_finding_sev[fid] = sev
        bucket = sev_split[sev]
        bucket["total"] += 1
        if f.get("status") == "CONFIRMED":
            bucket["confirmed"] += 1
        elif f.get("status") == "INFERRED":
            bucket["inferred"] += 1
    severity_counts = [
        {"severity": sev, "confirmed": v["confirmed"],
         "inferred": v["inferred"], "total": v["total"]}
        for sev, v in sorted(sev_split.items(),
                             key=lambda kv: _severity_rank(kv[0]))
    ]
    top_severity = severity_counts[0]["severity"] if severity_counts else None

    # ── Headline (A1): highest severity, then highest confidence, over
    # DETECTION findings (context-only identity/integrity facts never set the
    # headline, same rule as _confidence_label). Always qualified. ──
    headline = None
    threat_headline = ""
    candidates = [f for f in findings if not _is_context_finding(f, rule_ids)]
    if candidates:
        def _headline_key(f: dict) -> tuple:
            sev = per_finding_sev.get(f.get("finding_id"), "UNRATED")
            try:
                conf = float(f.get("confidence") or 0.0)
            except (TypeError, ValueError):
                conf = 0.0
            return (_severity_rank(sev), -conf, str(f.get("finding_id") or ""))
        lead = min(candidates, key=_headline_key)
        status = str(lead.get("status") or "UNKNOWN")
        corroboration = ("multi-source corroborated" if _is_cross_validated(lead)
                         else "single-source")
        role = "Lead" if status != "CONFIRMED" else "Finding"
        qualifier = f"{role} ({status}, {corroboration})"
        title = str(lead.get("title") or "").strip()
        headline = {
            "finding_id": lead.get("finding_id"),
            "title": title,
            "severity": per_finding_sev.get(lead.get("finding_id"), "UNRATED"),
            "status": status,
            "corroboration": corroboration,
            "detection_strength": _detection_strength(lead.get("confidence")),
            "qualifier": qualifier,
        }
        threat_headline = f"{qualifier}: {title}" if title else qualifier

    # ── Tactic coverage + kill-chain (the same tid→tactic map the MITRE-map
    # section uses; adds no technique and no mapping). A4: first_seen is the
    # UTC-normalised min event_time; nodes are in ATT&CK order, which is NOT a
    # claimed sequence. ──
    tactics_map = _load_mitre_tactics()
    tactic_techs: dict[str, set[str]] = defaultdict(set)
    tactic_first: dict[str, "datetime"] = {}
    for f in findings:
        ev_dt = _parse_finding_ts(f.get("event_time"))
        for tid in _finding_mitre_ids(f):
            tactic = tactics_map.get(tid)
            if not tactic:
                continue  # no tactic entry → contributes nothing (never guessed)
            tactic_techs[tactic].add(tid)
            if ev_dt is not None:
                cur = tactic_first.get(tactic)
                if cur is None or ev_dt < cur:
                    tactic_first[tactic] = ev_dt
    ordered = sorted(tactic_techs, key=lambda t: (_tactic_rank(t), t))
    tactic_coverage = [
        {"tactic": t, "rank": _tactic_rank(t),
         "technique_count": len(tactic_techs[t]),
         "techniques": sorted(tactic_techs[t])}
        for t in ordered
    ]
    kill_chain = [
        {"tactic": t, "rank": _tactic_rank(t),
         "first_seen": (_utc_iso(tactic_first[t]) if t in tactic_first
                        else None),
         "technique_count": len(tactic_techs[t])}
        for t in ordered
    ]

    return {
        "kpis": kpis,
        "severity_counts": severity_counts,
        "top_severity": top_severity,
        "finding_severity": per_finding_sev,
        "headline": headline,
        "threat_headline": threat_headline,
        "verdict_class": verdict_class(findings, manifest),
        "coverage": _coverage_block(manifest),
        "confidence_label": _confidence_label(findings, rule_ids),
        "confidence_banner": _overall_confidence_banner(findings, rule_ids),
        "tactic_coverage": tactic_coverage,
        "kill_chain": kill_chain,
        "kill_chain_basis": "attck_order",
        "provenance": DASHBOARD_PROVENANCE,
    }


def _dashboard_metrics_sha256(metrics: dict) -> str:
    """A6: sha256 of the canonical JSON of the metrics dict. Recorded in the
    Phase-6 audit row so a post-hoc edit to the (mutable) manifest copy the
    PDF/DOCX dashboards render from is detectable."""
    return hashlib.sha256(
        json.dumps(metrics, sort_keys=True).encode("utf-8")).hexdigest()


def _persist_dashboard_metrics(
    findings: list[dict], manifest: dict, case_dir: str
) -> dict:
    """Compute _dashboard_metrics ONCE and persist it into
    manifest["report"]["dashboard_metrics"] (idempotent per Phase-6 run).
    Both the report.md prose and the PDF/DOCX dashboards read it, so there is
    a single computation and no drift. Returns the dict."""
    metrics = _dashboard_metrics(findings, manifest, case_dir)
    manifest.setdefault("report", {})["dashboard_metrics"] = metrics
    return metrics
