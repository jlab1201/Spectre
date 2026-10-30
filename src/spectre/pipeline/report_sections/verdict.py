"""Verdict class, grounded absence signals and the "7. Verdict" section."""

from __future__ import annotations

from spectre.pipeline.report_sections.confidence import _corroborated_count
from spectre.pipeline.report_sections.intake import (
    _coverage_counts,
    _coverage_sentence,
    _extraction_all_failed,
    _extraction_any_empty,
    _extraction_any_failed,
    _failed_tool_runs,
)
from spectre.pipeline.report_sections.iocs import _build_deduped_ioc_table
from spectre.pipeline.report_sections.mitre import _resolve_mitre_labels


# ── Markdown merger ───────────────────────────────────────────────────
def _generate_verdict_section(findings: list[dict], manifest: dict,
                              llm_output: dict | None = None,
                              mitre_labels: dict | None = None) -> list[str]:
    """Build the '## 7. Verdict' section lines.

    Extracted from _merge_report_md so the branch chain is directly
    testable. The model-authored branch is the one that most needs
    pinning: under SPECTRE_LLM_PROVIDER=host its prose reaches disk with
    no _validate_report seam anywhere in the path.
    """
    lines: list[str] = []
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    corroborated = _corroborated_count(findings)
    # ── 7. Verdict ──
    lines.append("---\n")
    lines.append("## 7. Verdict\n")
    lines.append("")

    inferred = sum(1 for f in findings if f.get("status") == "INFERRED")
    techniques = sorted(set(
        f.get("mitre_attack", "UNMAPPED") for f in findings
        if f.get("mitre_attack") != "UNMAPPED"
    ))
    ioc_rows = _build_deduped_ioc_table(findings)
    top_ips = [v for t, v, _, _ in ioc_rows if t == "ip"][:5]

    # Grounded negatives from the deterministic layer — only weighed into the
    # verdict when no CONFIRMED (high-confidence) malicious finding dominates
    # the picture. A confirmed malicious finding stands on its own; a benign
    # or single-source-lead case should read as such rather than defaulting
    # to compromise-shaped language just because the model filled the silence.
    absence = _absence_signals(findings, manifest) if confirmed == 0 else []
    absence_sentence = (
        " Cross-artifact analysis found: " + "; ".join(absence)
        if absence else ""
    )

    if llm_output and str(llm_output.get("verdict", "") or "").strip():
        # Grounded negatives are deterministic output and belong in every
        # branch — the model's prose does not get to suppress what the
        # deterministic layer looked for and did not find.
        lines.append(llm_output["verdict"].rstrip() + absence_sentence)
        lines.append("")
    elif confirmed == 0 and len(findings) == 0 and _extraction_all_failed(manifest):
        # W4-1 (R1-F2): nothing was successfully extracted — a tool error
        # is not a clean bill. No verdict about the evidence is supportable.
        if _extraction_any_empty(manifest):
            # W4 review MED-3: tools ran but parsed zero records.
            lines.append("**No verdict: no records were examined.** Extraction "
                         "failed or parsed zero records from the registered "
                         "evidence (corrupt, truncated or empty contents), so "
                         "nothing was examined. The absence of findings says "
                         "nothing about the evidence. ")
        else:
            lines.append("**No verdict: extraction failed.** Every tool run against "
                         "the registered evidence failed, so nothing was examined. "
                         "The absence of findings says nothing about the evidence. ")
    elif confirmed == 0 and len(findings) == 0 and _extraction_any_failed(manifest):
        lines.append("**No indicators of compromise were detected in the "
                     "successfully examined evidence.** Extraction failed or "
                     "parsed zero records for part of the evidence, which "
                     "remains unexamined — see "
                     "'4. Forensic Blind Spots'." + absence_sentence + " ")
    elif confirmed == 0 and len(findings) == 0 and _failed_tool_runs(manifest):
        _nf = _failed_tool_runs(manifest)
        lines.append("**No indicators of compromise were detected in the "
                     f"successfully examined evidence.** {_nf} tool run(s) "
                     "failed; what they would have examined remains "
                     "unexamined — see '4. Forensic Blind Spots'."
                     + absence_sentence + " ")
    elif confirmed == 0 and len(findings) == 0:
        lines.append("**No indicators of compromise were detected.** "
                     "The automated analysis found no evidence of malicious activity "
                     "in the examined evidence." + absence_sentence + " ")
    elif confirmed == 0 and inferred > 0:
        max_c = max((f.get("confidence", 0) for f in findings), default=0)
        lines.append(f"**No corroborated findings.** All {len(findings)} "
                     f"observations are single-source at confidence ≤{max_c:.0%}. "
                     f"Without multi-source corroboration, these are investigative leads, "
                     f"not conclusive indicators of compromise." + absence_sentence + " ")
    elif confirmed > 0 and inferred == 0:
        if corroborated > 0:
            lines.append(f"**Evidence consistent with malicious activity.** "
                         f"{corroborated} finding(s) are corroborated by multiple "
                         f"independent detection methods. ")
        else:
            lines.append(f"**Evidence consistent with malicious activity per "
                         f"deterministic review.** {confirmed} finding(s) carry "
                         f"CONFIRMED status, but none are corroborated by multiple "
                         f"independent detection methods — each rests on a single "
                         f"detection source. ")
        if tech_labels := list(dict.fromkeys(_resolve_mitre_labels(t, mitre_labels or {}) for t in techniques[:3])):
            lines.append(f"Activity maps to: {', '.join(tech_labels)}. ")
    else:
        if corroborated > 0:
            lines.append(f"**Evidence suggests malicious activity.** "
                         f"{corroborated} finding(s) corroborated by multiple "
                         f"independent detection methods, {inferred} single-source. ")
        else:
            lines.append(f"**Evidence suggests malicious activity.** "
                         f"{confirmed} finding(s) CONFIRMED (single detection method "
                         f"each, none independently corroborated), {inferred} "
                         f"single-source INFERRED. ")
        if tech_labels := list(dict.fromkeys(_resolve_mitre_labels(t, mitre_labels or {}) for t in techniques[:3])):
            lines.append(f"Primary techniques: {', '.join(tech_labels)}. ")

    # Coverage is deterministic and applies to EVERY branch above,
    # including the model-authored one — same reasoning as
    # absence_sentence, and the only placement that holds under
    # SPECTRE_LLM_PROVIDER=host, where no _validate_report seam runs at
    # all. Unconditional by construction so a future branch cannot
    # silently omit it.
    coverage_sentence = _coverage_sentence(manifest)
    if coverage_sentence:
        lines.append(coverage_sentence.lstrip())

    if top_ips:
        lines.append(f"Key IOCs: {', '.join(top_ips[:5])}. ")

    lines.append("")
    lines.append("**Recommendation:** Findings require examiner review and "
                 "correlation with endpoint telemetry before final determination. "
                 "Confidence scores reflect detection method reliability, not "
                 "certainty of compromise. ")

    if corroborated > 0:
        lines.append("Prioritize corroborated findings for incident response actions.")
    elif confirmed > 0 or inferred > 0:
        lines.append("Treat as investigative leads; gather additional evidence before "
                     "declaring compromise.")
    else:
        lines.append("No immediate action indicated based on automated analysis alone.")

    lines.append("\n")
    lines.append("")
    return lines


# ── Cross-artifact absence signals (D4: verdict tempering) ───────────
# A "grounded negative" — e.g. "no outbound connections observed" — is only
# honest if the pipeline actually examined the artifact that would have
# shown it. `plugins_run` (manifest["detection"]["plugins_run"], written by
# Phase 3 from the extraction handles) is the deterministic record of which
# plugins/passes were executed against this evidence, independent of
# whether they produced any events. Absence-of-examination is NEVER treated
# as a grounded negative: each category below only fires when at least one
# of its `gate_artifact_types` is present in `plugins_run`.
#
# Each category is additionally suppressed when a finding already exists
# for it (its own artifact_type, or a MITRE technique in its family) — a
# positive finding, not silence, so no negative claim is made about it.
_ABSENCE_CATEGORIES: list[dict] = [
    {
        "name": "outbound",
        "gate_artifact_types": {"memory_netscan"},
        "positive_artifact_types": {"memory_netscan"},
        "positive_mitre": {"T1071", "T1571", "T1041", "T1105", "T1567"},
        "text": "No outbound network connections observed indicating "
                "command-and-control or exfiltration",
    },
    {
        "name": "persistence",
        "gate_artifact_types": {"memory_pslist", "memory_regkey", "memory_svcscan"},
        "positive_artifact_types": {"memory_regkey", "memory_svcscan"},
        "positive_mitre": {"T1547", "T1543", "T1053"},
        "text": "No persistence findings (no autostart/service/registry-run finding)",
    },
    {
        "name": "injection",
        "gate_artifact_types": {"memory_malfind"},
        "positive_artifact_types": {"memory_malfind"},
        "positive_mitre": {"T1055", "T1027.002"},
        "text": "No code-injection findings (malfind examined; no injection indicators)",
    },
    {
        "name": "credential_access",
        "gate_artifact_types": {"memory_envar", "memory_cmdline", "memory_filescan"},
        "positive_artifact_types": {"memory_envar"},
        "positive_mitre": {"T1003", "T1552", "T1555"},
        "text": "No credential-access findings",
    },
]


def _finding_artifact_types_single(finding: dict) -> set[str]:
    """Every artifact type a single finding is grounded in — direct
    ``artifact_type`` key (real emit_finding output and test fixtures alike),
    plus ``corroboration.tools`` and ``evidence_refs`` (see
    ``_get_finding_artifact_types`` for why those are the real-world source)."""
    types: set[str] = set()
    direct = finding.get("artifact_type")
    if direct:
        types.add(str(direct))
    for t in (finding.get("corroboration") or {}).get("tools") or []:
        art = str(t).rsplit("/", 1)[-1]
        if art:
            types.add(art)
    for ref in finding.get("evidence_refs", []) or []:
        art = ref.get("artifact_type", "")
        if art:
            types.add(art)
    return types


def _finding_mitre_ids(finding: dict) -> list[str]:
    """A finding's mitre_attack field can be a composite comma-separated
    string (e.g. "T1071.001, T1095"); split it into individual technique IDs."""
    raw = str(finding.get("mitre_attack", "") or "")
    return [t.strip() for t in raw.split(",") if t.strip() and t.strip() != "UNMAPPED"]


def verdict_class(findings: list[dict],
                  manifest: dict | None = None) -> str:
    """Classify the evidence picture. The deterministic layer owns this call.

    Returns one of:
      "none"       — no findings at all
      "leads_only" — findings exist, none CONFIRMED
      "confirmed"  — at least one CONFIRMED, none INFERRED
      "mixed"      — both CONFIRMED and INFERRED present

    Invariant: each finding's status must be "CONFIRMED" or "INFERRED" (the
    values emit_finding assigns). Any finding with a different or missing
    status contributes to neither tally, so a list of only such findings
    classifies as "leads_only".

    The model may phrase the verdict; a phrasing that contradicts this class
    is rejected by _validate_report (Validator 11).
    """
    # "no_coverage" outranks every finding-derived class: if nothing was
    # examined, no verdict about the evidence is supportable, and folding that
    # into "none" (which reads as "examined, found nothing") is exactly the
    # misstatement this class exists to prevent. manifest is optional so every
    # pre-existing caller keeps its behaviour.
    if manifest is not None:
        examined, total = _coverage_counts(manifest)
        if total > 0 and examined == 0:
            return "no_coverage"
    if not findings:
        return "none"
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    inferred = sum(1 for f in findings if f.get("status") == "INFERRED")
    if confirmed == 0:
        return "leads_only"
    if inferred == 0:
        return "confirmed"
    return "mixed"


def _absence_signals(findings: list[dict], manifest: dict) -> list[str]:
    """Human-readable grounded negatives derived ONLY from deterministic
    data: which plugins the pipeline actually ran (manifest["detection"]
    ["plugins_run"]) and which findings actually fired. Never invents a
    negative for a plugin/artifact that was not examined.

    W4-1 (R1-F2): a plugin whose tool run FAILED was not examined — any
    type in detection["plugins_failed"] is dropped, whatever plugins_run
    says, and an all-failed extraction grounds no negative at all.
    """
    detection = manifest.get("detection") or {}
    plugins_run = (set(detection.get("plugins_run") or [])
                   - set(detection.get("plugins_failed") or []))
    if not plugins_run or _extraction_all_failed(manifest):
        return []

    signals: list[str] = []
    for cat in _ABSENCE_CATEGORIES:
        examined = cat["gate_artifact_types"] & plugins_run
        if not examined:
            continue  # not examined -> not a grounded negative

        suppressed = False
        for f in findings:
            if _finding_artifact_types_single(f) & cat["positive_artifact_types"]:
                suppressed = True
                break
            mids = _finding_mitre_ids(f)
            if any(m.startswith(p) for m in mids for p in cat["positive_mitre"]):
                suppressed = True
                break
        if suppressed:
            continue

        signals.append(
            f"{cat['text']} (examined via {', '.join(sorted(examined))})."
        )
    return signals
