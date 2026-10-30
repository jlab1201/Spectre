"""
report_synthesize.py — LLM-driven forensic report synthesis.

Feeds validated findings + FK context + MITRE map to an LLM provider
(spectre.llm). The model writes narrative sections; deterministic code
handles counts, tables, IOCs, and evidence references. Guardrails enforce:
no invented findings, MITRE only from allowed list, grounded IOCs only,
confidence immutability, no "clean" claims.

Caveat verbatim-from-FK-YAML is enforced for per-finding descriptions by
core/explain.py's `_validate_output()`, AND for the report narrative by this
module's `_validate_report()` Validator 5: any caveat-shaped sentence
(matching `_CAVEAT_SIGNAL_RE`) in the narrative must reproduce an FK
does_NOT_prove caveat verbatim, or a known template scoping sentence
(`_STANDARD_SCOPING_CAVEATS`) — otherwise it is stripped and recorded as a
violation. Fail-closed WITHIN the signal vocabulary: a caveat-shaped
sentence that reproduces no allowed caveat verbatim is stripped. A
limitation phrased outside that vocabulary (e.g. "does not indicate
compromise", "is not conclusive", "cannot rule out") is not scrutinized —
the trigger is deliberately narrow to keep false positives low. So this
catches fabricated/paraphrased caveats that use the recognized limitation
phrasing, not every conceivable one.

Two paths:
  --skip-ai set  → deterministic template dump (current behavior)
  --skip-ai unset → LLM synthesis with guardrails; falls back to template
                    on API failure (graceful degradation)

Layout (Wave-6 split; this module stays the public import surface):
  report_synthesize.py       — orchestrator: synthesize_report / _finalize_report /
                               ingest_host_report / _audit_synthesize, and
                               _merge_report_md, which only composes sections.
  report_validators.py       — _validate_report() + V1–V11 (security seam).
  report_prompt.py           — LLM system/user prompt construction.
  report_sections/*.py       — one module per report section / concern.
Every name that used to live here is re-imported below (see __all__), so
`from spectre.pipeline.report_synthesize import X` keeps working. Names a test
monkeypatches (get_provider, synthesize_report) are still defined/looked up
HERE, so patching them on this module keeps taking effect.
"""

from __future__ import annotations

import os
import time
import yaml
from pathlib import Path

from spectre.core import grounding
from spectre.core.validators import (
    FindingIntegrityError,  # noqa: F401 — re-exported: ingest_host_report fails closed with it
    case_allowed_mitre as _case_allowed_mitre,
    guardrail_context as _guardrail_context,
    load_verified_findings as _load_verified_findings,
    finding_artifact_types as _get_finding_artifact_types,  # noqa: F401 — re-exported for phase_runner/tests
    load_fk_caveats as _load_fk_caveats,  # noqa: F401 — re-exported for phase_runner/tests
    mitre_in_allowed,
)
from spectre.pipeline.audit import append as audit_append
from spectre.llm import get_provider

from spectre.pipeline.report_sections.common import (
    FULL_ARTIFACT_SET,
    RELEVANT_GAPS,
    _build_finding_groups,
    _finding_rule_ids,
    _human_bytes,
    _human_duration,
    _parse_finding_ts,
    _sha256,
    _utcnow,
)
from spectre.pipeline.report_sections.intake import (
    _UNEXAMINED,
    _coverage_counts,
    _coverage_sentence,
    _extraction_all_failed,
    _extraction_any_empty,
    _extraction_any_failed,
    _extraction_records,
    _failed_tool_runs,
    _generate_intake_section,
    _module_extraction_status,
    _outcome_cell,
)
from spectre.pipeline.report_sections.approval import (
    _narrative_provenance_line,
    approval_state,
    classification_for,
    classification_status_line,
    deterministic_baseline_banner,
    load_approval_state,
)
from spectre.pipeline.report_sections.mitre import (
    _MITRE_CELL_ID_CAP,
    _TACTIC_ORDER,
    _cap_finding_ids,
    _load_mitre_tactics,
    _load_mitre_technique_labels,
    _resolve_mitre_labels,
    _resolve_tactic,
    _section_mitre_map,
    _tactic_rank,
)
from spectre.pipeline.report_sections.iocs import (
    _C2_PAYLOAD_RULES,
    _CAMPAIGN_TAG_EXCLUDE,
    _CAMPAIGN_TAG_RE,
    _EXPOSED_RULES,
    _LOCAL_DOMAIN_SUFFIXES,
    _NO_GROUNDED_ROLE,
    _OS_FROM_UA_RE,
    _PUBLIC_SUFFIXES,
    _RECOVERED_CRED_MARKERS,
    _SCANNER_RULES,
    _UA_FULL_RE,
    _UA_SIGNATURE_RE,
    _build_campaign_tags_table,
    _build_deduped_ioc_table,
    _build_host_iocs_table,
    _dedupe_domains,
    _generate_iocs_csv,
    _identity_source,
    _ioc_role,
    _is_bystander_identity,
    _is_identity_finding,
    _is_internal_domain,
    _is_internal_ip,
    _is_org_domain_candidate,
    _norm_domain,
    _recovered_credential_values,
    _section_ioc_export,
    _section_key_indicators,
    _segment_iocs,
    _tld_histogram,
    _victim_context,
)
from spectre.pipeline.report_sections.timeline import (
    _section_timeline,
)
from spectre.pipeline.report_sections.blindspots import (
    GAP_FILL_QUESTION_MAP,
    PROFILE_BLIND_SPOTS,
    _CARVE_CAP_HINT,
    _carve_cap_hits,
    _forensic_gap_question,
    _gap_fill_skips,
    _generate_blindspots_md,
    _intake_blindspot_lines,
    _is_single_evidence_source_case,
    _max_corroboration_sources,
    _section_blind_spots,
)
from spectre.pipeline.report_sections.confidence import (
    _CONTEXT_RULES,
    _confidence_label,
    _corroborated_count,
    _detection_strength,
    _fid_list,
    _is_context_finding,
    _is_cross_validated,
    _overall_confidence,
    _overall_confidence_banner,
    _section_confidence_assessment,
)
from spectre.pipeline.report_sections.actions import (
    _recommended_actions,
    _section_recommended_actions,
)
from spectre.pipeline.report_sections.verdict import (
    _ABSENCE_CATEGORIES,
    _absence_signals,
    _finding_artifact_types_single,
    _finding_mitre_ids,
    _generate_verdict_section,
    verdict_class,
)
from spectre.pipeline.report_prompt import (
    _INBOUND_RE,
    _build_system_prompt,
    _build_user_prompt,
    _monitored_host,
)
from spectre.pipeline.report_validators import (
    _ASSERTIVE_COMPROMISE_RE,
    _CAVEAT_SIGNAL_RE,
    _FORBIDDEN_ABSENCE_RE,
    _NEGATION_HEDGE_RE,
    _REPORT_MITRE_RE,
    _SENTENCE_SPLIT_RE,
    _STANDARD_SCOPING_CAVEATS,
    _coerce_narrative_str,
    _map_str,
    _normalize_narrative_obj,
    _validate_report,
    _verdict_contradicts_class,
)
from spectre.pipeline.report_sections.dashboard import (
    DASHBOARD_PROVENANCE,
    _SEVERITY_RANK,
    _coverage_block,
    _dashboard_metrics,
    _dashboard_metrics_sha256,
    _load_ruleset_severities,
    _persist_dashboard_metrics,
    _resolve_finding_severity,
    _severity_rank,
    _utc_iso,
)
from spectre.pipeline.report_sections.methodology import (
    _phase5_disposition_line,
    _section_evidence_intake,
    _section_methodology,
    _section_phase5_disposition,
)
from spectre.pipeline.report_sections.findings import (
    _KEY_FINDINGS_TOP_N,
    _append_finding_evidence_block,
    _deterministic_threat_chain,
    _finding_scale_phrase,
    _key_findings_digest,
    _render_correlated_findings,
    _rollup_scale_lines,
    _section_detailed_findings,
    _section_finding_index,
    _section_threat_narrative,
    _severity_line,
)
from spectre.pipeline.report_sections.executive import (
    _describe_profile,
    _section_draft_notice,
    _section_executive_summary,
    _section_header,
    _section_system_profile,
)

# Pre-split import surface: every name above is re-exported from here.
__all__ = [
    "DASHBOARD_PROVENANCE",
    "FULL_ARTIFACT_SET",
    "FindingIntegrityError",
    "GAP_FILL_QUESTION_MAP",
    "PROFILE_BLIND_SPOTS",
    "RELEVANT_GAPS",
    "REPORT_SCHEMA",
    "_ABSENCE_CATEGORIES",
    "_ASSERTIVE_COMPROMISE_RE",
    "_C2_PAYLOAD_RULES",
    "_CAMPAIGN_TAG_EXCLUDE",
    "_CAMPAIGN_TAG_RE",
    "_CARVE_CAP_HINT",
    "_CAVEAT_SIGNAL_RE",
    "_CONTEXT_RULES",
    "_EXPOSED_RULES",
    "_FORBIDDEN_ABSENCE_RE",
    "_INBOUND_RE",
    "_KEY_FINDINGS_TOP_N",
    "_LOCAL_DOMAIN_SUFFIXES",
    "_MITRE_CELL_ID_CAP",
    "_NEGATION_HEDGE_RE",
    "_NO_GROUNDED_ROLE",
    "_OS_FROM_UA_RE",
    "_PUBLIC_SUFFIXES",
    "_RECOVERED_CRED_MARKERS",
    "_REPORT_MITRE_RE",
    "_SCANNER_RULES",
    "_SENTENCE_SPLIT_RE",
    "_SEVERITY_RANK",
    "_STANDARD_SCOPING_CAVEATS",
    "_TACTIC_ORDER",
    "_UA_FULL_RE",
    "_UA_SIGNATURE_RE",
    "_UNEXAMINED",
    "_absence_signals",
    "_append_finding_evidence_block",
    "_audit_synthesize",
    "_build_campaign_tags_table",
    "_build_deduped_ioc_table",
    "_build_finding_groups",
    "_build_host_iocs_table",
    "_build_system_prompt",
    "_build_user_prompt",
    "_cap_finding_ids",
    "_carve_cap_hits",
    "_case_allowed_mitre",
    "_coerce_narrative_str",
    "_confidence_label",
    "_corroborated_count",
    "_coverage_block",
    "_coverage_counts",
    "_coverage_sentence",
    "_dashboard_metrics",
    "_dashboard_metrics_sha256",
    "_dedupe_domains",
    "_describe_profile",
    "_detection_strength",
    "_deterministic_threat_chain",
    "_extraction_all_failed",
    "_extraction_any_empty",
    "_extraction_any_failed",
    "_extraction_records",
    "_failed_tool_runs",
    "_fid_list",
    "_finalize_report",
    "_finding_artifact_types_single",
    "_finding_mitre_ids",
    "_finding_rule_ids",
    "_finding_scale_phrase",
    "_forensic_gap_question",
    "_gap_fill_skips",
    "_generate_blindspots_md",
    "_generate_intake_section",
    "_generate_iocs_csv",
    "_generate_verdict_section",
    "_get_finding_artifact_types",
    "_guardrail_context",
    "_human_bytes",
    "_human_duration",
    "_identity_source",
    "_intake_blindspot_lines",
    "_ioc_role",
    "_is_bystander_identity",
    "_is_context_finding",
    "_is_cross_validated",
    "_is_identity_finding",
    "_is_internal_domain",
    "_is_internal_ip",
    "_is_org_domain_candidate",
    "_is_single_evidence_source_case",
    "_key_findings_digest",
    "_load_fk_caveats",
    "_load_mitre_tactics",
    "_load_mitre_technique_labels",
    "_load_ruleset_severities",
    "_load_verified_findings",
    "_map_str",
    "_max_corroboration_sources",
    "_merge_report_md",
    "_module_extraction_status",
    "_monitored_host",
    "_narrative_provenance_line",
    "_norm_domain",
    "_normalize_narrative_obj",
    "_outcome_cell",
    "_overall_confidence",
    "_overall_confidence_banner",
    "_parse_finding_ts",
    "_persist_dashboard_metrics",
    "_phase5_disposition_line",
    "_recommended_actions",
    "_recovered_credential_values",
    "_render_correlated_findings",
    "_resolve_finding_severity",
    "_resolve_mitre_labels",
    "_resolve_tactic",
    "_rollup_scale_lines",
    "_section_blind_spots",
    "_section_confidence_assessment",
    "_section_detailed_findings",
    "_section_draft_notice",
    "_section_evidence_intake",
    "_section_executive_summary",
    "_section_finding_index",
    "_section_header",
    "_section_ioc_export",
    "_section_key_indicators",
    "_section_methodology",
    "_section_mitre_map",
    "_section_phase5_disposition",
    "_section_recommended_actions",
    "_section_system_profile",
    "_section_threat_narrative",
    "_section_timeline",
    "_segment_iocs",
    "_severity_line",
    "_severity_rank",
    "_sha256",
    "_tactic_rank",
    "_tld_histogram",
    "_utc_iso",
    "_utcnow",
    "_validate_report",
    "_verdict_contradicts_class",
    "_victim_context",
    "approval_state",
    "classification_for",
    "classification_status_line",
    "deterministic_baseline_banner",
    "grounding",
    "ingest_host_report",
    "load_approval_state",
    "mitre_in_allowed",
    "synthesize_report",
    "verdict_class",
]


# ── JSON schema the report LLM must return ───────────────────────────
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "threat_narrative": {"type": "string"},
        "findings_narrative": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "narrative": {"type": "string"},
                },
                "required": ["finding_id", "narrative"],
            },
        },
        "timeline_narrative": {"type": "string"},
        "methodology_narrative": {"type": "string"},
        "verdict": {"type": "string"},
    },
    "required": [
        "executive_summary",
        "threat_narrative",
        "findings_narrative",
        "timeline_narrative",
        "methodology_narrative",
        "verdict",
    ],
}


def _merge_report_md(
    llm_output: dict | None,
    findings: list[dict],
    manifest: dict,
    case_dir: str,
    violation_log: list[str],
    mitre_map: dict,
) -> str:
    """
    Merge deterministic data (counts, tables, IOCs) with LLM narrative
    into the final report.md content. Designed for leadership audience:
    narrative synthesis in body, detail in appendix.

    Composition only: every section is rendered by a builder in
    ``spectre.pipeline.report_sections``; the call order below IS the
    report order. Behaviour (and bytes) are unchanged from the single-
    function version this replaced.
    """
    profile = manifest.get("artifact_profile", "?")

    # ── Dashboard metrics (TB-port T5): compute ONCE and persist. The
    # executive-summary counts below and the PDF/DOCX dashboards read the
    # persisted dict, so there is a single arithmetic and no drift. The
    # Verdict / verdict_class keep their own count so Validator 11's contract
    # is not coupled to the dashboard (same predicates, same values). ──
    metrics = _persist_dashboard_metrics(findings, manifest, case_dir)

    # MITRE label lookup — per-technique canonical names, NOT a rule's
    # composite label (see _load_mitre_technique_labels docstring).
    mitre_labels = _load_mitre_technique_labels()

    evidence_type = _describe_profile(profile, findings, manifest)

    lines = []
    lines.extend(_section_header(llm_output, findings, manifest, evidence_type))
    lines.extend(_section_executive_summary(
        llm_output, findings, manifest, metrics, mitre_labels, evidence_type))
    lines.extend(_section_confidence_assessment(findings, manifest))
    lines.extend(_section_system_profile(manifest))
    lines.extend(_section_key_indicators(findings))
    lines.extend(_section_draft_notice())
    lines.extend(_section_threat_narrative(llm_output, findings))
    lines.extend(_section_detailed_findings(llm_output, findings, metrics, mitre_labels))
    lines.extend(_section_mitre_map(findings, manifest, mitre_map, mitre_labels))
    lines.extend(_section_timeline(llm_output, findings))
    lines.extend(_render_correlated_findings(manifest, findings))
    lines.extend(_section_blind_spots(findings, manifest))
    lines.extend(_section_ioc_export(findings, manifest))
    lines.extend(_section_methodology(llm_output, findings))
    lines.extend(_section_phase5_disposition(manifest))
    lines.extend(_section_evidence_intake(manifest))

    # ── 7. Verdict ──
    lines.extend(_generate_verdict_section(
        findings, manifest, llm_output, mitre_labels))
    lines.extend(_section_recommended_actions(findings, manifest))
    lines.extend(_section_finding_index(findings, case_dir))

    return "\n".join(lines) + "\n"


# ── Main synthesis function ──────────────────────────────────────────
def synthesize_report(
    findings: list[dict],
    manifest: dict,
    case_dir: str,
    skip_ai: bool = False,
    provider_name: str | None = None,
) -> dict:
    """
    Synthesize a narrative forensic report from validated findings.

    Args:
        findings: List of finding dicts (loaded from F-*.yaml files)
        manifest: Case manifest.yaml as dict
        case_dir: Path to case directory
        skip_ai: If True, return deterministic template data only (no LLM call)
        provider_name: LLM provider override

    Returns:
        {
            "executive_summary": str,
            "threat_narrative": str,
            "findings_narrative": [{"finding_id": str, "narrative": str}],
            "timeline_narrative": str,
            "methodology_narrative": str,
            "token_usage": {"prompt": N, "completion": N},
            "violations": [str],
            "llm_used": bool,
            "api_error": str | None,
            # Present only in host mode (provider_name="host", the default),
            # in place of a finished narrative:
            "deferred": bool,       # True — synthesis deferred to the
                                    #   orchestrating agent
            "request": {"system": str, "user": str, "schema": dict},
                                    # prompt + schema for the agent to fill
            "ingest": {"case_dir": str, "case_id": str},
                                    # NOT a splat target — pass this plus the
                                    #   caller's own `findings`/`manifest` to
                                    #   ingest_host_report(); see that
                                    #   function's docstring
        }
    """
    if skip_ai or not findings:
        return {
            "executive_summary": "",
            "threat_narrative": "",
            "verdict": "",
            "findings_narrative": [],
            "timeline_narrative": "",
            "methodology_narrative": "",
            "token_usage": {"prompt": 0, "completion": 0},
            "violations": [],
            "llm_used": False,
            "api_error": None,
            "provider": None,
            "validated": False,
        }

    case_dir_path = Path(case_dir)
    case_id = manifest.get("case_id", "?")

    # Load MITRE map — kept as a local for prompt-building below. The
    # allow-list + FK-caveats derivation is shared with the host-ingest
    # path via _guardrail_context (see that function's docstring for why).
    from spectre.config import MITRE_MAP_PATH

    mitre_map = {}
    if MITRE_MAP_PATH.exists():
        mitre_map = yaml.safe_load(MITRE_MAP_PATH.read_text()) or {}

    allowed_mitre, fk_caveats_map = _guardrail_context(findings, case_dir=case_dir)

    # Build detection summary
    detection_summary = manifest.get("detection", {})

    # Build prompts
    system_prompt = _build_system_prompt()
    user_prompt = _build_user_prompt(
        findings,
        manifest,
        mitre_map,
        fk_caveats_map,
        detection_summary,
        manifest.get("artifact_profile", "unknown"),
        allowed_mitre=allowed_mitre,
    )

    # Call LLM — retry once on a transient failure (DeepSeek intermittently
    # returns malformed JSON; a silent template fallback undermines the report).
    provider = get_provider(provider_name)
    start_ms = int(time.time() * 1000)
    from spectre.config import LLM_MAX_TOKENS_SYNTH
    resp = provider.complete(
        system_prompt, user_prompt, max_tokens=LLM_MAX_TOKENS_SYNTH,
        schema=REPORT_SCHEMA,
    )
    # A refusal is deterministic for the same request and model — don't
    # re-send it; it is surfaced below as the api_error.
    if (resp.parsed is None and not resp.deferred
            and resp.finish_reason != "refusal"):
        resp = provider.complete(
            system_prompt, user_prompt, max_tokens=LLM_MAX_TOKENS_SYNTH,
            schema=REPORT_SCHEMA,
        )
    elapsed_ms = int(time.time() * 1000) - start_ms

    # Handle deferred (host) mode
    if resp.deferred:
        return {
            "executive_summary": "",
            "threat_narrative": "",
            "verdict": "",
            "findings_narrative": [],
            "timeline_narrative": "",
            "methodology_narrative": "",
            "token_usage": {"prompt": 0, "completion": 0},
            "violations": [],
            "llm_used": False,
            "api_error": "host mode — report synthesis deferred to orchestrating agent",
            "provider": None,
            "validated": False,
            "deferred": True,
            "request": resp.request,
            # NOT a splat-ready call handle, unlike explain's deferred bundle:
            # ingest_host_report() also requires `findings` and `manifest`,
            # which the caller already holds (they are synthesize_report's own
            # inputs) — pass them through explicitly rather than assuming
            # `**result["ingest"]` works. case_id is carried alongside
            # case_dir so the caller doesn't have to re-derive it from the
            # manifest.
            "ingest": {"case_dir": case_dir, "case_id": case_id},
        }

    token_usage = {
        "prompt": resp.usage.get("prompt_tokens", 0),
        "completion": resp.usage.get("completion_tokens", 0),
    }

    # Handle API error — a truncated response counts: brace-repair can salvage
    # a dict that silently lost executive_summary/verdict (case 079).
    # Providers normalize to "length"; "max_tokens" (Anthropic's raw value)
    # is accepted too so a provider that doesn't map it can't disarm the guard.
    truncated = (resp.finish_reason in ("length", "max_tokens")
                 and resp.parsed is not None
                 and not str(resp.parsed.get("executive_summary", "") or "").strip())
    if truncated:
        resp.parsed = None
        resp.error = ("LLM output truncated at max_tokens "
                      f"(finish_reason={resp.finish_reason}) "
                      "— raise SPECTRE_LLM_MAX_TOKENS_SYNTH")
    if resp.parsed is None:
        api_error = resp.error or "no output from LLM provider"
        _audit_synthesize(
            case_dir_path,
            case_id,
            len(findings),
            provider.name,
            resp.model,
            False,
            token_usage,
            elapsed_ms,
            "error",
        )
        return {
            "executive_summary": "",
            "threat_narrative": "",
            "verdict": "",
            "findings_narrative": [],
            "timeline_narrative": "",
            "methodology_narrative": "",
            "token_usage": token_usage,
            "violations": [],
            "llm_used": False,
            "api_error": api_error,
            "provider": provider.name,
            "validated": False,
        }

    return _finalize_report(resp.parsed, findings, fk_caveats_map, allowed_mitre,
                            case_dir_path, case_id, provider.name, resp.model,
                            token_usage, elapsed_ms, manifest=manifest)


def _finalize_report(parsed: dict, findings: list[dict], fk_caveats_map: dict,
                     allowed_mitre: list[str], case_dir_path: Path, case_id: str,
                     provider_name: str, model: str, token_usage: dict,
                     elapsed_ms: int, entry_point: str = "synthesize_report",
                     manifest: dict | None = None) -> dict:
    """Validate report output, audit it, and return the result dict.

    Single source of truth for the direct-API path and the host-ingest path —
    the guardrails run identically regardless of who produced `parsed`.
    Mirrors explain._finalize.

    `entry_point` names the function the caller actually entered through, and
    is stamped into the audit row's `exact_command`. It is not cosmetic: a
    chain-of-custody row naming a function that did not execute is a false
    record. The host path arrives via ingest_host_report() and never enters
    synthesize_report(), so it must not claim to have.
    """
    cleaned, violations = _validate_report(
        parsed, findings, fk_caveats_map, allowed_mitre, manifest
    )

    _audit_synthesize(case_dir_path, case_id, len(findings), provider_name,
                      model, True, token_usage, elapsed_ms, "success",
                      entry_point)

    # Unconditional "validation ran" marker. verify_full's narrative_grounding
    # drift check keys off the PRESENCE of an S2-validate-report row to confirm
    # the model narrative passed through _validate_report. The per-violation
    # rows below fire only when there ARE violations, so without this row a
    # CLEAN validated run (zero violations) would be indistinguishable from a
    # run that bypassed the validator entirely.
    audit_append(str(case_dir_path), {
        "actor": "deterministic-core",
        "action": "note",
        "tool": "report-validator",
        "tool_version": "0.1",
        "exact_command": "report_synthesize._validate_report() — deterministic validator",
        "params": {"violations_found": len(violations)},
        "case_id": case_id,
        "output_path": "",
        "output_sha256": "",
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "token_usage": {"prompt": 0, "completion": 0},
        "phase": 6,
        "phase_step": "S2-validate-report",
    })

    for v in violations:
        audit_append(str(case_dir_path), {
            "actor": "deterministic-core",
            "action": "note",
            "tool": "report-validator",
            "tool_version": "0.1",
            "exact_command": "report_synthesize._validate_report() — deterministic validator",
            "params": {"violation": v},
            "case_id": case_id,
            "output_path": "",
            "output_sha256": "",
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "token_usage": {"prompt": 0, "completion": 0},
            "phase": 6,
            "phase_step": "S2-validate-report",
        })

    return {
        "executive_summary": cleaned.get("executive_summary", ""),
        "threat_narrative": cleaned.get("threat_narrative", ""),
        "verdict": cleaned.get("verdict", ""),
        "findings_narrative": cleaned.get("findings_narrative", []),
        "timeline_narrative": cleaned.get("timeline_narrative", ""),
        "methodology_narrative": cleaned.get("methodology_narrative", ""),
        "token_usage": token_usage,
        "violations": violations,
        "llm_used": True,
        "api_error": None,
        # WS7a sub-task 3 (A2-1): provenance markers so a caller that merges
        # this dict straight into report.md (_merge_report_md reads them off
        # `llm_output`) can disclose whether the narrative came from a direct
        # API provider or a host agent, and — the only value that actually
        # matters here — that it passed through _validate_report() to get
        # this far. `validated` is always True on this return path: it is
        # only reached after the call above. There is no path through
        # _finalize_report that returns validated=False; a caller that wants
        # to claim "AI narrative" without ever calling this function (i.e.
        # the documented known gap) simply won't have these keys at all,
        # which _merge_report_md treats as unvalidated by default — see
        # _narrative_provenance_line().
        "provider": provider_name,
        "validated": True,
    }


def ingest_host_report(*args, **kwargs) -> dict:
    """Finalize a host-produced report narrative (provider="host").

    ``ingest_host_report(case_dir, host_json)``

    The orchestrating agent fills the bundle returned by synthesize_report()
    and passes its JSON here with the case directory. It runs through the
    SAME validators as a direct API call — no host can bypass the grounding,
    MITRE, or verdict-class guardrails.

    Every validator input comes from disk, never from the caller (W2-2,
    R2-03): findings are loaded from ``case_dir/findings/F-*.yaml`` and each
    is re-hashed against the latest audit row carrying its content hash
    (the baseline verify_full's finding_integrity trusts). A mismatch raises
    FindingIntegrityError (fail closed). A finding file with NO hashed audit
    row was never produced by the pipeline and is EXCLUDED from the grounded
    set (recorded as a violation). The manifest is ``case_dir/manifest.yaml``.
    The MITRE allow-list is case-scoped (union of each finding's own
    per-rule set).

    Deprecated shim: the old ``ingest_host_report(findings, manifest,
    case_dir, host_json)`` call still works, but the passed findings and
    manifest are IGNORED (DeprecationWarning).

    Validates but does NOT persist: returns the validated dict only. The
    caller merges it into ``reports/report.md`` via ``_merge_report_md()``
    (pass it the findings this function validated against — they are in
    the returned dict under ``"validated_findings"`` as finding IDs).
    """
    import warnings

    # Accepted forms (findings/manifest are IGNORED in every form):
    #   ingest_host_report(case_dir, host_json)                 — current
    #   ingest_host_report(findings, manifest, case_dir, host_json)  — legacy
    #   any of the above with case_dir/host_json/findings/manifest as keywords
    unknown = kwargs.keys() - {"case_dir", "host_json", "findings", "manifest"}
    if unknown:
        raise TypeError(f"ingest_host_report(): unexpected keyword(s) {sorted(unknown)}")
    pos = list(args)
    legacy = bool(pos) and not isinstance(pos[0], (str, os.PathLike))
    if legacy:
        pos = pos[2:]  # drop positional findings, manifest
    names = ["case_dir", "host_json"]
    if len(pos) > len(names):
        raise TypeError("ingest_host_report(case_dir, host_json): too many arguments")
    bound = dict(zip(names, pos))
    for k in names:
        if k in kwargs:
            if k in bound:
                raise TypeError(f"ingest_host_report(): multiple values for {k!r}")
            bound[k] = kwargs[k]
    if legacy or "findings" in kwargs or "manifest" in kwargs:
        warnings.warn(
            "ingest_host_report(): passed findings/manifest are ignored — they "
            "are loaded from disk; call ingest_host_report(case_dir, host_json).",
            DeprecationWarning, stacklevel=2)
    case_dir, host_json = bound.get("case_dir"), bound.get("host_json")
    if case_dir is None or host_json is None:
        raise TypeError("ingest_host_report() requires case_dir and host_json")

    case_dir_path = Path(case_dir)
    manifest: dict = {}
    mp = case_dir_path / "manifest.yaml"
    if mp.exists():
        manifest = yaml.safe_load(mp.read_text()) or {}
    case_id = manifest.get("case_id", case_dir_path.name)

    findings, unregistered = _load_verified_findings(case_dir_path)

    allowed_mitre, fk_caveats_map = _guardrail_context(findings, case_dir=case_dir_path)

    result = _finalize_report(host_json, findings, fk_caveats_map, allowed_mitre,
                              case_dir_path, case_id, "host", "agent",
                              {"prompt": 0, "completion": 0}, 0,
                              entry_point="ingest_host_report",
                              manifest=manifest)
    for fid in unregistered:
        msg = (f"excluded unregistered finding {fid} (no finding_create registration or hash baseline) "
               f"from the grounded set")
        result["violations"].append(msg)
        audit_append(str(case_dir_path), {
            "actor": "deterministic-core",
            "action": "note",
            "tool": "report-validator",
            "tool_version": "0.1",
            "exact_command": "report_synthesize.ingest_host_report() — "
                             "disk-loaded findings",
            "params": {"violation": msg},
            "case_id": case_id,
            "output_path": "",
            "output_sha256": "",
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "token_usage": {"prompt": 0, "completion": 0},
            "phase": 6,
            "phase_step": "S2-validate-report",
        })
    result["validated_findings"] = [f.get("finding_id") for f in findings]
    return result


def _audit_synthesize(
    case_dir_path: Path,
    case_id: str,
    findings_count: int,
    provider_name: str,
    model: str,
    success: bool,
    token_usage: dict,
    elapsed_ms: int,
    result: str,
    entry_point: str = "synthesize_report",
) -> None:
    """Write audit row for report synthesis.

    `entry_point` is the originating public function — the row must name the
    code path that actually ran, not a sibling that didn't.
    """
    audit_append(str(case_dir_path), {
        "actor": "spectre-lead",
        "action": "note",
        "tool": f"llm:{provider_name}",
        "tool_version": model or provider_name,
        "exact_command": (f"report_synthesize.{entry_point}() — "
                          f"LLM report synthesis call, no CLI"),
        "params": {
            "findings_count": findings_count,
            "provider": provider_name,
        },
        "case_id": case_id,
        "output_path": "",
        "output_sha256": "",
        "result": result,
        "exit_code": 0,
        "duration_ms": elapsed_ms,
        "token_usage": token_usage,
        "phase": 6,
        "phase_step": "S1-synthesize-report",
    })
