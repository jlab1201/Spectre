"""Examiner approval state and report classification (DRAFT/APPROVED),
the deterministic-baseline banner and the narrative-provenance line.
"""

from __future__ import annotations

import yaml
from pathlib import Path



# ── Examiner approval state (the report classification's single source) ──
# A report is APPROVED only when Phase-7 verification passed (gate_7) AND every
# active finding (findings/F-*.yaml — excluded/ and superseded/ are out of
# scope) carries an examiner decision written by approval.py (`spectre
# approve`). gate_7 alone used to mark a re-rendered PDF/DOCX APPROVED while
# findings still awaited a decision. Unknown state → DRAFT (fail safe).
def approval_state(findings: list[dict]) -> dict:
    """{decided, total, pending, all_decided} over ``findings``' ``approval``
    field; a value outside approval.DECISIONS is undecided."""
    from spectre.pipeline.approval import DECISIONS
    pending = [str(f.get("finding_id") or "?") for f in findings or []
               if isinstance(f, dict) and f.get("approval") not in DECISIONS]
    total = len([f for f in findings or [] if isinstance(f, dict)])
    return {"decided": total - len(pending), "total": total,
            "pending": pending, "all_decided": not pending}


def load_approval_state(case_dir: str | None) -> dict | None:
    """approval_state over the case's active findings on disk, or None when
    there is no findings directory (a bare report.md render)."""
    if not case_dir:
        return None
    fdir = Path(case_dir) / "findings"
    if not fdir.is_dir():
        return None
    findings = []
    for fp in sorted(fdir.glob("F-*.yaml")):
        try:
            data = yaml.safe_load(fp.read_text()) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("finding_id", fp.stem)
        findings.append(data)
    return approval_state(findings)


def classification_for(manifest: dict, approval: dict | None) -> str:
    """APPROVED iff gate_7 passed AND every active finding is decided."""
    if approval is None or not approval.get("all_decided"):
        return "DRAFT"
    if not ((manifest or {}).get("gate_7") or {}).get("passed"):
        return "DRAFT"
    return "APPROVED"


def classification_status_line(classification: str, approval: dict | None) -> str:
    counts = (f"{approval['decided']} of {approval['total']} decided"
              if approval is not None else "")
    if classification == "APPROVED":
        return "Examiner Approved (Phase 7)" + (f" — {counts}" if counts else "")
    return "Pending Examiner Approval" + (f" ({counts})" if counts else "")


def deterministic_baseline_banner() -> str:
    """Loud, deterministic markdown callout prepended to report.md when
    Phase 6 produced findings but no AI narrative was available (the LLM
    provider was unavailable/deferred with no fallback, or synthesis
    otherwise failed). Never wall-clock-derived — the text is fixed so the
    banner is byte-identical across runs.

    This exists so a report generated without an AI narrative is
    impossible to mistake for a fully-narrated one: the findings below are
    complete and deterministic, but nobody has written prose around them.
    """
    return (
        "> ## ⚠ DETERMINISTIC BASELINE — NO AI NARRATIVE\n"
        ">\n"
        "> This report contains **no AI-generated narrative**. The AI "
        "synthesis seam was unavailable, deferred, or failed with no "
        "fallback for this run. Every finding below was produced by the "
        "deterministic detection core and is complete and unmodified — "
        "only the prose explaining them is missing.\n"
        ">\n"
        "> Do not mistake this for an examiner-narrated report. Findings, "
        "MITRE mappings, IOCs, and caveats are authoritative; section "
        "narratives are template-generated, not analyst prose.\n"
    )


def _narrative_provenance_line(llm_output: dict | None) -> str:
    """One-line, un-missable disclosure of where the report narrative came
    from (WS7a sub-task 3 / A2-1).

    Before this, `report.md` never disclosed whether its prose was (a)
    deterministic template text, (b) an LLM narrative that passed
    `_validate_report()`'s guardrails, or (c) raw host-agent prose written
    straight into the merge with zero validation — all three rendered with
    identical formatting and identical authority. A courtroom reader has no
    other way to tell them apart from the deliverable itself.

    Derives entirely from `llm_output` — the same dict `_merge_report_md`
    already receives as its first argument — so no caller (phase_runner.py's
    automated Phase 6, or an agent following skills/report-generator/
    SKILL.md's manual host flow) needs to pass anything new: `synthesize_report()`
    /`ingest_host_report()` both return `provider`/`validated` via
    `_finalize_report()`, and that return value IS the `llm_output` callers
    already pass straight through to `_merge_report_md()`.

    Fails closed: `llm_output` present but missing/false `validated` (e.g. a
    hand-built dict that skipped `ingest_host_report()`/`ingest_host_output()`
    entirely — the documented, not-technically-preventable host-path gap)
    renders the explicit "NOT validated" warning rather than silently
    defaulting to an authoritative-looking line. This is still a procedural
    control, not a technical one: nothing stops a non-compliant caller from
    also forging `validated: True` in the dict it hands to `_merge_report_md`.
    """
    if not llm_output:
        return (
            "Deterministic baseline — no AI narrative was generated for this "
            "report. Findings, MITRE mappings, and caveats below are complete "
            "and deterministic; no analyst prose was written around them."
        )
    provider = (llm_output.get("provider") or "").strip()
    validated = bool(llm_output.get("validated"))
    if validated and provider and provider != "host":
        return (
            f"AI narrative — validated by in-process guardrails "
            f"(`report_synthesize._validate_report()`), provider={provider}."
        )
    if validated and provider == "host":
        return (
            "AI narrative — host-authored (via `ingest_host_report()`), "
            "validated by in-process guardrails "
            "(`report_synthesize._validate_report()`)."
        )
    return (
        "AI narrative — host-authored, **NOT validated in-process**. This "
        "narrative was merged into the report without passing through "
        "`report_synthesize._validate_report()`'s guardrails. Findings/MITRE/"
        "caveats stated in the prose below have not been checked against the "
        "deterministic finding data and must be cross-verified against the "
        "Detailed Findings appendix before reliance."
    )
