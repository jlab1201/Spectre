"""Report header and the Executive Summary sections (subject host, capture
scale, deterministic summary prose, system profile, DRAFT notice).
"""

from __future__ import annotations

from spectre.pipeline.report_sections.approval import (
    _narrative_provenance_line,
    approval_state,
    classification_for,
)
from spectre.pipeline.report_sections.common import (
    _finding_rule_ids,
    _human_bytes,
    _human_duration,
    _utcnow,
)
from spectre.pipeline.report_sections.confidence import _overall_confidence_banner
from spectre.pipeline.report_sections.findings import (
    _key_findings_digest,
    _rollup_scale_lines,
)
from spectre.pipeline.report_sections.iocs import _build_deduped_ioc_table
from spectre.pipeline.report_sections.mitre import _resolve_mitre_labels


# ── IOC deduplication helpers ──────────────────────────────────────────


def _describe_profile(profile: str, findings: list[dict], manifest: dict) -> str:
    """Return a human-readable description of what evidence was examined."""
    profile_labels = {
        "pcap": "Network Packet Capture (PCAP)",
        "evtx": "Windows Event Logs (EVTX)",
        "memory": "Memory Dump",
        "disk": "Disk Image",
        "fixture-test": "Test Fixture Data",
        "logfile": "Application Log Files",
        "auto": "Auto-Detected Evidence",
    }
    label = profile_labels.get(profile, profile.upper())
    ev = manifest.get("evidence_refs", [])
    if ev:
        return f"{label} ({len(ev)} file(s))"
    return label


def _section_header(
    llm_output: dict | None,
    findings: list[dict],
    manifest: dict,
    evidence_type: str,
) -> list[str]:
    """Title block: case reference, date, evidence, classification, confidence, provenance."""
    lines = []

    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")

    lines.append("# Forensic Investigation Report\n")
    lines.append(f"**Case Reference:** {case_id}-{case_name}")
    lines.append(f"**Date:** {_utcnow()}")
    lines.append(f"**Evidence Examined:** {evidence_type}")
    _appr = approval_state(findings)
    if classification_for(manifest, _appr) == "APPROVED":
        lines.append(f"**Classification:** APPROVED — examiner decisions recorded "
                     f"for all {_appr['total']} findings (as of report generation)")
    else:
        # report.md is hash-bound at generation; the PDF/DOCX cover and
        # document control re-derive the LIVE state on every render.
        lines.append(f"**Classification:** DRAFT — pending examiner review "
                     f"(as of report generation: {_appr['decided']} of "
                     f"{_appr['total']} findings decided)")
    lines.append(f"**Overall Confidence:** "
                 f"{_overall_confidence_banner(findings, _finding_rule_ids(findings, manifest))}")
    lines.append(
        "**Timestamp Basis:** All evidence timestamps in this report are "
        "UTC unless explicitly noted otherwise (e.g. syslog-style entries "
        "with no year or timezone, flagged inline where they occur)."
    )
    # WS7a sub-task 3 (A2-1): un-missable disclosure of whether this
    # narrative is deterministic, validated AI, or unvalidated host prose —
    # see _narrative_provenance_line()'s docstring for why this belongs here
    # rather than only in the negative-case baseline banner.
    lines.append(f"**Narrative Provenance:** {_narrative_provenance_line(llm_output)}")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def _section_executive_summary(
    llm_output: dict | None,
    findings: list[dict],
    manifest: dict,
    metrics: dict,
    mitre_labels: dict,
    evidence_type: str,
) -> list[str]:
    """Executive Summary: subject host, key-findings digest, volume roll-up, capture scale, prose."""
    lines = []

    # ponytail: composite "T1071.001, T1095" strings need per-TID resolution
    def _resolve_mitre(mt_string: str) -> str:
        return _resolve_mitre_labels(mt_string, mitre_labels)

    # ── Executive Summary ──
    lines.append("## Executive Summary\n")

    # ── Subject Host (Track K): name the monitored host up top, the way a
    # forensic report names its subject. Deterministic manifest fact
    # (monitored_ip == the host_ip carried by every finding); descriptive
    # metadata — no MITRE, no confidence, no finding language. Pcap-only;
    # absent (memory/disk, no single monitored host) → skip. ──
    monitored_ip = (manifest.get("monitored_ip") or "").strip()
    if monitored_ip:
        lines.append(f"**Subject Host:** {monitored_ip} (monitored host)\n")

    # ── C4: Key Findings BLUF digest — scannable top-N by confidence, at the
    # very top of the Executive Summary. Absent when there are no findings. ──
    lines.extend(_key_findings_digest(findings))

    # ── C1: Activity Volume roll-up (deterministic occurrence_count totals per
    # rule group). Empty when findings carry no real scale data. ──
    lines.extend(_rollup_scale_lines(findings, manifest))

    # ── Capture Scale (deterministic capture metadata — describes the
    # evidence, NOT a finding: no MITRE, no confidence, no verdict).
    # Distinct-count values are neutral observations, never malice. ──
    scale = manifest.get("capture_scale") or {}
    scale_rows = []
    if scale.get("total_packets"):
        scale_rows.append(("Total packets", f"{scale['total_packets']:,}"))
    if scale.get("file_size_bytes"):
        scale_rows.append(("Capture size", _human_bytes(scale["file_size_bytes"])))
    if scale.get("capture_duration_seconds"):
        scale_rows.append(("Capture span", _human_duration(scale["capture_duration_seconds"])))
    if scale.get("distinct_src_ips"):
        scale_rows.append(("Distinct source IPs observed", f"{scale['distinct_src_ips']:,}"))
    if scale.get("distinct_dst_ports"):
        scale_rows.append(("Distinct destination ports observed", f"{scale['distinct_dst_ports']:,}"))
    if scale_rows:
        lines.append("### Capture Scale\n")
        lines.append("_Descriptive capture metadata — not findings; no counted "
                     "value is asserted to be malicious._\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        for label, val in scale_rows:
            lines.append(f"| {label} | {val} |")
        lines.append("")

    if llm_output and llm_output.get("executive_summary"):
        lines.append(llm_output["executive_summary"])
        lines.append("")
    else:
        # Deterministic prose — forensic analysis language, not tool output.
        # Counts come from the persisted dashboard metrics (one arithmetic).
        confirmed = metrics["kpis"]["confirmed"]
        inferred = metrics["kpis"]["inferred"]
        corroborated = metrics["kpis"]["corroborated"]
        ioc_rows = _build_deduped_ioc_table(findings)
        unique_ips = [v for t, v, _, _ in ioc_rows if t == "ip"]
        unique_domains = [v for t, v, _, _ in ioc_rows if t == "domain"]
        techniques = sorted(set(
            f.get("mitre_attack", "UNMAPPED") for f in findings
            if f.get("mitre_attack") != "UNMAPPED"
        ))
        technique_labels = [_resolve_mitre(t) for t in techniques]

        # Opening — what was analyzed
        lines.append(
            f"Analysis of the provided {evidence_type.lower()} identified "
            f"**{len(findings)} indicators** requiring further investigation.\n"
        )

        # Status breakdown. CONFIRMED status (met the deterministic corroboration
        # threshold — source-count / rule-level confidence) is reported separately
        # from multi-method corroboration (cross_validated) — a CONFIRMED finding
        # can still rest on a single detection source. NOTE: "corroboration
        # threshold" is deliberately distinct from the Phase-5 adversarial review;
        # the two must never share the word "adversarial" in report prose.
        if confirmed > 0:
            lines.append(
                f"**{confirmed} observation(s) have CONFIRMED status** (met the "
                f"deterministic corroboration threshold). "
            )
        if corroborated > 0:
            lines.append(
                f"**{corroborated} observation(s) are corroborated** by multiple "
                f"independent detection methods. "
            )
        elif confirmed > 0 or inferred > 0:
            lines.append(
                "**No observations are corroborated by multiple independent "
                "detection methods** — each finding rests on a single "
                "detection method. "
            )
        if inferred > 0:
            lines.append(
                f"**{inferred} observations are based on single-source detection** "
                f"and require additional evidence to confirm. "
            )

        # Key IOCs in narrative form
        if unique_ips:
            top_ips = unique_ips[:5]
            lines.append(
                f"Suspicious destination IPs include "
                f"{', '.join(top_ips)}"
                + (f" (+{len(unique_ips)-5} additional)" if len(unique_ips) > 5 else "") + ". "
            )
        if unique_domains:
            top_domains = unique_domains[:5]
            lines.append(
                f"Anomalous domains contacted include "
                f"{', '.join(top_domains)}"
                + (f" (+{len(unique_domains)-5} additional)" if len(unique_domains) > 5 else "") + ". "
            )

        if techniques:
            lines.append(
                f"Observed activity maps to the following MITRE ATT&CK "
                f"techniques: {', '.join(technique_labels[:5])}"
                + (f" (+{len(techniques)-5} additional)" if len(techniques) > 5 else "") + ".\n"
            )

        # Threat assessment — honest, no false confidence
        if not confirmed and inferred > 0:
            actual_confs = [f.get("confidence", 0) for f in findings if f.get("status") == "INFERRED"]
            min_conf = min(actual_confs) if actual_confs else 0
            max_conf = max(actual_confs) if actual_confs else 0
            lines.append(
                f"\n**Assessment:** All {len(findings)} observations are derived from a single "
                f"evidence source (network traffic capture only). Without corroboration from "
                f"endpoint telemetry, memory analysis, or disk forensics, these indicators "
                f"cannot be confirmed as malicious activity. They represent investigative "
                f"leads requiring follow-up, not conclusive proof of compromise. "
                f"Detection confidence ranges from {min_conf:.0%} to {max_conf:.0%}.\n"
            )
        elif confirmed > 0 and corroborated > 0:
            lines.append(
                f"\n**Assessment:** {corroborated} observation(s) are corroborated by "
                f"multiple independent detection methods, indicating a higher degree of "
                f"confidence. These should be prioritized for incident response actions.\n"
            )
        elif confirmed > 0:
            lines.append(
                f"\n**Assessment:** {confirmed} observation(s) carry CONFIRMED status "
                f"(met the deterministic corroboration threshold), but none are corroborated by "
                f"an independent detection method — each rests on a single tool/source. "
                f"Treat as investigative leads requiring additional evidence, not as "
                f"multi-source-confirmed compromise.\n"
            )
        lines.append("")
    return lines


def _section_system_profile(manifest: dict) -> list[str]:
    """System Profile (host/OS metadata; never a finding)."""
    lines = []

    # ── System Profile (Task 7 data path: memory_systeminfo profile
    # signal). Metadata only — memory_systeminfo has no rule in rules.py
    # and can NEVER emit a finding (the inviolable rule), so this section
    # must never carry a MITRE mapping or read as a finding. Rendered only
    # when manifest["system_profile"] carries at least one usable field. ──
    system_profile = manifest.get("system_profile") or {}
    if any(system_profile.get(k) for k in ("hostname", "os_build", "system_time")):
        lines.append("## System Profile\n")
        lines.append(
            "_Host/OS identification extracted from the evidence, for "
            "context only. This is metadata, not a finding — it carries "
            "no MITRE mapping and no confidence score._\n"
        )
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        if system_profile.get("hostname"):
            lines.append(f"| Hostname | {system_profile['hostname']} |")
        if system_profile.get("os_build"):
            lines.append(f"| OS Build | {system_profile['os_build']} |")
        if system_profile.get("system_time"):
            lines.append(
                f"| System Time (evidence capture) | {system_profile['system_time']} |"
            )
        lines.append("")
        lines.append("---\n")
    return lines


def _section_draft_notice() -> list[str]:
    """DRAFT notice closing the Executive Summary."""
    lines = []

    lines.append("*This report is DRAFT and subject to examiner review.*")
    lines.append("")
    lines.append("---\n")
    return lines
