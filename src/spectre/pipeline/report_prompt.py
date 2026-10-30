"""report_prompt.py — system/user prompt construction for the Phase-6 report
LLM call (split out of report_synthesize.py; re-exported there).
"""

from __future__ import annotations

import json
import re
import yaml
from collections import defaultdict
from pathlib import Path

from spectre.core.validators import case_allowed_mitre as _case_allowed_mitre
from spectre.pipeline.report_sections.common import FULL_ARTIFACT_SET, _utcnow
from spectre.pipeline.report_sections.mitre import _load_mitre_technique_labels
from spectre.pipeline.report_sections.verdict import _absence_signals


# ── Prompt builders ───────────────────────────────────────────────────
def _build_system_prompt() -> str:
    """System prompt with guardrail rules for the report writer LLM."""
    return """You are a forensic report writer for the Spectre analysis pipeline. You write
narrative sections of an investigation report. The findings were produced
deterministically by forensic tools — you explain them, you do NOT create them.

RULES (enforced by validators after your response):
1. Write clear, professional forensic prose. Use plain language suitable for
   an examiner reviewing findings. Write like a senior forensic analyst:
   name the threat picture (e.g. "opportunistic internet-wide scanning",
   "targeted AD reconnaissance"), never just count indicators.
2. Every factual claim MUST cite a finding_id (e.g., "as shown in F-004-001").
3. MITRE ATT&CK technique IDs MUST come from the provided list only. Include
   technique names from the provided MITRE map.
4. Caveats MUST be reproduced VERBATIM from the provided FK YAML caveat lists.
   No paraphrasing, no new caveats.
5. Do NOT invent findings, IOCs, timestamps, IP addresses, domains, file paths,
   or any factual data not present in the provided findings.
6. Do NOT state numeric confidence scores in prose. They are computed
   deterministically and live in the tables. Qualitative attribution
   confidence (LOW / MEDIUM / HIGH) in the verdict is required.
7. Never say "clean" or "no malware found." Use "UNVERIFIED" for gaps.
   Evidence-grounded negatives ARE allowed and encouraged when the data
   supports them: "no evidence of successful compromise was observed in the
   examined traffic" is correct analyst language when findings show only
   failed inbound probes.
8. The report is DRAFT until examiner approval. State this clearly.
9. The verdict MUST judge directionality from the evidence: distinguish
   inbound scanning/probing hitting a monitored host from outbound activity
   initiated by it. Inbound-only probes with no successful outbound follow-up
   are NOT command-and-control.
10. Keep raw IOC literals out of the executive summary (5 max) — reference
   the IOC table instead.

Output valid JSON matching the provided schema exactly."""


def _build_user_prompt(
    findings: list[dict],
    manifest: dict,
    mitre_map: dict,
    fk_caveats_map: dict[str, list[str]],
    detection_summary: dict,
    artifact_profile: str,
    allowed_mitre: list[str] | None = None,
) -> str:
    """Build the user prompt containing all findings data and context."""

    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    canary = manifest.get("canary_status", "?")

    # Allowed MITRE list — case-scoped: the union of each finding's own
    # per-rule set, never the whole mitre-map (R2-01). synthesize_report
    # passes the same set _validate_report will enforce.
    if allowed_mitre is None:
        allowed_mitre = _case_allowed_mitre(findings, mitre_map)

    # MITRE label lookup — per-technique canonical names, NOT a rule's
    # composite label (see _load_mitre_technique_labels docstring).
    mitre_labels = _load_mitre_technique_labels()

    # Build findings data section — compact but rich enough for real synthesis
    findings_text = []
    inbound = outbound = 0
    day_counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        fid = finding.get("finding_id", "?")
        desc = finding.get("description") or ""
        if len(desc) > 400:
            desc = desc[:397] + "..."
        corr = finding.get("corroboration") or {}
        sources = corr.get("sources", 1)
        artifacts = corr.get("artifacts") or []
        excerpt = str(artifacts[0])[:160] if artifacts else ""
        # Direction tags come from the deterministic extractor ("[inbound]")
        if any("[inbound]" in str(a) for a in artifacts):
            inbound += 1
        elif any("[outbound]" in str(a) for a in artifacts):
            outbound += 1
        event_time = finding.get("event_time", "")
        if event_time:
            day_counts[str(event_time)[:10]] += 1
        # Undated findings (artifact type carries no evidence time) get an
        # explicit marker in the prompt — never omitted, never left for the
        # model to infer or invent a timestamp for.
        time_display = event_time if event_time else "(no evidence timestamp)"

        ioc_parts = []
        for values in (finding.get("iocs") or {}).values():
            for v in (values if isinstance(values, list) else [values]):
                if v:
                    ioc_parts.append(str(v))
        fdata = (
            f"FID={fid} STATUS={finding.get('status','?')} "
            f"CONF={finding.get('confidence',0):.2f} SOURCES={sources} "
            f"MITRE={finding.get('mitre_attack','UNMAPPED')} "
            f"TITLE={finding.get('title','?')[:160]}\n"
            f"  TIME={time_display}\n"
            + (f"  DESC={desc}\n" if desc else "")
            + (f"  EVIDENCE={excerpt}\n" if excerpt else "")
            + (f"  IOCS={', '.join(ioc_parts[:6])}\n" if ioc_parts else "")
        )
        findings_text.append(fdata)

    # Monitored host = destination IP of inbound evidence. Naming it stops the
    # narrative from calling the server its own attacker (gap C1).
    monitored_host = _monitored_host(findings)
    direction_text = (
        f"- inbound: {inbound} finding(s) with inbound-direction evidence\n"
        f"- outbound: {outbound} finding(s) with outbound-direction evidence"
    )
    if monitored_host:
        direction_text += (
            f"\n- monitored host (the analyzed system, destination of inbound "
            f"traffic): {monitored_host}. Remote source IPs are the external "
            f"parties; do NOT describe the monitored host as an attacker."
        )
    day_lines = [f"  {day}: {n} finding(s)" for day, n in sorted(day_counts.items())]
    per_day_text = "\n".join(day_lines) if day_lines else "  (no event timestamps)"

    # Build FK caveats section
    fk_section = []
    for artifact_type, caveats in fk_caveats_map.items():
        fk_section.append(f"\n### {artifact_type}")
        for i, c in enumerate(caveats):
            fk_section.append(f"  {i + 1}. {c}")

    # Build detection summary
    det_text = yaml.dump(detection_summary, default_flow_style=False, sort_keys=False)

    # Cross-artifact absence signals — grounded negatives ("no outbound
    # connections", "no persistence findings", ...), each backed by a plugin
    # the pipeline actually ran (never inferred from silence alone). Feed
    # them to the model so a benign case reads as benign instead of the
    # narrative filling the silence with an implied compromise.
    absence_signals = _absence_signals(findings, manifest)
    absence_text = (
        "\n".join(f"  - {s}" for s in absence_signals)
        if absence_signals else "  (none — insufficient plugin coverage to ground a negative)"
    )

    # Coverage gaps
    covered = set()
    profile_artifacts = manifest.get("artifacts", [])
    if isinstance(profile_artifacts, list) and profile_artifacts:
        for art in profile_artifacts:
            if isinstance(art, str):
                covered.add(art.lower())
    # Also check gate_0
    gate0 = manifest.get("gate_0", {})
    fk_loaded = gate0.get("fk_yamls_loaded", [])
    if isinstance(fk_loaded, list):
        for fk_name in fk_loaded:
            # Derive artifact type from FK YAML name
            base = Path(str(fk_name)).stem
            covered.add(base.lower().replace("_4688", ""))

    uncovered = []
    for art_key, art_label in sorted(FULL_ARTIFACT_SET.items()):
        # Fuzzy match: evtx vs evtx_4688, etc.
        if not any(art_key in c or c in art_key for c in covered):
            uncovered.append(f"  - {art_label}")

    coverage_text = "\n".join(uncovered) if uncovered else "  (full coverage)"

    # Token budget: cap detailed findings for the LLM prompt.
    # Findings are ~2 lines each (stripped format), 30 keeps it manageable.
    MAX_DETAIL = 60
    if len(findings_text) > MAX_DETAIL:
        omitted = len(findings_text) - MAX_DETAIL
        findings_text = findings_text[:MAX_DETAIL]
        findings_text.append(
            f"\n# {omitted} additional findings omitted from LLM prompt for context budget.\n"
            f"# Reference the evidence section for details. All {len(findings)} findings are\n"
            f"# reflected in the deterministic IOC tables and MITRE map below.\n"
        )

    # Track K: name the monitored/subject host so the model can refer to it.
    # Deterministic manifest fact (== host_ip on every finding), so it is
    # already grounded — the model may name it; Validator 10 still strips any
    # OTHER, ungrounded IP. Pcap-only; absent → no line, no instruction effect.
    monitored_ip = (manifest.get("monitored_ip") or "").strip()
    subject_host_line = (
        f"- Subject Host (monitored): {monitored_ip}\n" if monitored_ip else ""
    )

    return f"""# Spectre Forensic Report Synthesis

## Case Metadata
- Case ID: {case_id}-{case_name}
- Artifact Profile: {artifact_profile}
- Canary Status: {canary}
{subject_host_line}- Generated: {_utcnow()}

## Findings ({len(findings)} total)

{chr(10).join(findings_text)}

## Traffic Direction Summary (deterministic)
{direction_text}

## Findings Per Day (deterministic)
{per_day_text}

## MITRE ATT&CK Map
Allowed technique IDs: {json.dumps(allowed_mitre)}
Labels:
{yaml.dump(mitre_labels, default_flow_style=False, sort_keys=False)}

## FK YAML Caveats (reproduce VERBATIM)
{"".join(fk_section)}

## Detection Summary
{det_text}

## Cross-Artifact Absence Signals (deterministic)
These are grounded negatives — the pipeline examined the stated plugin(s)
and no matching finding fired. Use this language verbatim (or a close
paraphrase) where it applies; do NOT contradict it by implying compromise
in an area where an absence signal says otherwise, and do NOT state a
negative for anything NOT listed here.
{absence_text}

## Artifact Coverage Gaps (not examined)
{coverage_text}

## Instructions

Write a complete forensic investigation report with these sections:

1. **executive_summary**: 2-3 paragraph narrative synthesizing all findings.
   Name the overall threat picture (campaign class / activity type) — do not
   just count indicators. State what happened, to/from whom, and with what
   certainty. At most 5 raw IOC literals; reference the IOC table for the
   rest. Cite finding_ids throughout. End with blind-spots awareness.
   If a "Subject Host (monitored)" is listed in Case Metadata above, name it
   by that IP as the monitored host — it is the subject the report is about.
   Never introduce any other host IP that is not present in the findings.

2. **threat_narrative**: A causal attack chain — NOT a restated list of
   findings and NOT the same as the timeline. Write it as ordered steps
   (e.g. delivery → execution → command-and-control → exfiltration, using
   only the phases the evidence actually supports). Each step MUST:
   - cite the finding_id(s) it rests on (e.g. "(F-004-001)"),
   - carry the finding's TIME value verbatim when one exists (never invent
     a timestamp; for undated findings say so),
   - describe causation — how one step led to or enabled the next ("this
     download was immediately followed by...", "which in turn..."). Judge
     directionality from the Traffic Direction Summary. Use ONLY timestamps,
     IPs, domains, and paths present in the findings above.

3. **findings_narrative**: For each finding, write an ASSESSMENT paragraph —
   a senior analyst's interpretation of what the finding means and why it
   matters. It is rendered as the "Assessment" of a Detailed Findings entry
   (the Evidence and Confidence are filled in deterministically), so do NOT
   restate the raw IOCs/counts — interpret them. Cite the finding_id. Include
   the MITRE technique with full label from the map above. Mention caveats
   verbatim from the FK list. Do not introduce any IP/domain/path/User-Agent
   not already present in that finding.

4. **timeline_narrative**: Chronological prose describing the event sequence
   across all findings. Order by timestamp; use the per-day counts above.

5. **methodology_narrative**: Description of the investigative approach —
   what was examined, what tools were used, and what gaps remain.
   Mention the artifact profile and canary status.

6. **verdict**: The senior-analyst judgment. Must include: (a) the overall
   determination grounded in the findings (e.g. "opportunistic internet-wide
   scanning against an exposed server; no evidence of successful compromise
   observed in the examined traffic" — only when the data supports it) —
   when no CONFIRMED (high-confidence) malicious finding dominates, weigh
   the Cross-Artifact Absence Signals above into this determination so a
   benign or inconclusive case reads as such rather than implying a
   compromise the deterministic layer never found, (b) directionality: use
   the Traffic Direction Summary — inbound-only
   probes are NOT command-and-control, (c) attribution confidence stated
   qualitatively as LOW, MEDIUM, or HIGH with one sentence of reasoning,
   (d) a recommendation. Cite finding_ids. No numeric confidence scores.

Output only valid JSON: an object with string fields executive_summary,
threat_narrative, timeline_narrative, methodology_narrative and verdict, and
findings_narrative as a list of {{"finding_id": "...", "narrative": "..."}}
objects."""


_INBOUND_RE = re.compile(
    r">\s*(\d{1,3}(?:\.\d{1,3}){3})", )


def _monitored_host(findings: list[dict]) -> str:
    """The analyzed system's IP — the destination of inbound-tagged evidence
    ('SRC.port > DST.port'), taken by majority vote across findings."""
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        for a in (f.get("corroboration") or {}).get("artifacts") or []:
            a = str(a)
            if "[inbound]" not in a:
                continue
            m = _INBOUND_RE.search(a)
            if m:
                counts[m.group(1)] += 1
    if not counts:
        return ""
    return max(counts, key=counts.get)
