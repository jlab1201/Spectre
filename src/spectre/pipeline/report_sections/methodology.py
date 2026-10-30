""""6. Methodology", the Phase-5 disposition line and the Evidence Intake block."""

from __future__ import annotations

from spectre.pipeline.report_sections.confidence import _corroborated_count
from spectre.pipeline.report_sections.intake import _generate_intake_section
from spectre.pipeline.report_validators import _STANDARD_SCOPING_CAVEATS


def _phase5_disposition_line(manifest: dict) -> str:
    """Honest one-liner naming Phase 5's real substantive-review disposition.

    WS7e made `manifest["gate_5"]["substantive_review"]` an honest tri-state
    ("ran" | "deferred-to-host" | "not-run") — before that, the report
    narrative never said whether a real case-level adversarial review
    (counter-hypotheses, evidence/citation gaps) actually happened, so a
    reader had no way to tell a genuine Phase-5 pass from a deterministic-
    only run or a host-deferred one. This only reads the manifest key back
    verbatim; it never fabricates a review, a count, or a caveat.

    Returns "" when `gate_5` (or its `substantive_review` key) is absent —
    i.e. Phase 5 did not record a disposition in this manifest — so no line
    is printed rather than a false "not-run" claim.
    """
    gate_5 = manifest.get("gate_5")
    if not isinstance(gate_5, dict) or "substantive_review" not in gate_5:
        return ""
    state = gate_5.get("substantive_review")
    if state == "ran":
        count = gate_5.get("counter_hypotheses_count", 0)
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0
        return (
            "**Adversarial Review:** A substantive Phase 5 adversarial "
            f"review ran and produced {count} counter-hypothes"
            f"{'is' if count == 1 else 'es'} against the findings above."
        )
    if state == "deferred-to-host":
        return (
            "**Adversarial Review:** The substantive Phase 5 adversarial "
            "review was deferred to the orchestrating agent (host LLM "
            "provider mode); its result is not reflected in this "
            "narrative."
        )
    if state == "not-run" and gate_5.get("skip_ai"):
        # W4-3 (R1-F6): name the operator's choice, not a missing provider.
        return (
            "**Adversarial Review:** No substantive Phase 5 adversarial "
            "review was performed for this case — the run used --skip-ai "
            "(deterministic-only; Phase 5 ran on the null provider)."
        )
    if state == "not-run":
        return (
            "**Adversarial Review:** No substantive Phase 5 adversarial "
            "review was performed for this case (deterministic-only run — "
            "no narrative provider configured)."
        )
    return ""


def _section_methodology(llm_output: dict | None, findings: list[dict]) -> list[str]:
    """6. Methodology."""
    lines = []

    # ── 6. Methodology ──
    lines.append("## 6. Methodology\n")

    if llm_output and llm_output.get("methodology_narrative"):
        lines.append(llm_output["methodology_narrative"])
        lines.append("")
    else:
        lines.append(
            "The following forensic methods were applied to the evidence:\n"
        )

    # Describe actual forensic techniques used, based on findings and manifest
    art_types = set()
    for f in findings:
        for ref in f.get("evidence_refs", []):
            at = ref.get("artifact_type", "")
            if at:
                art_types.add(at)

    method_items = []
    if any("pcap" in a for a in art_types):
        method_items.append(
            "**Network Traffic Analysis:** Packet capture was inspected for "
            "connections to known-malicious ports, statistical beacon patterns "
            "(periodic callbacks at regular intervals), C2 protocol fingerprinting "
            "(HTTP-on-nonstandard-ports, known RAT signatures), and DNS anomalies "
            "(suspicious TLDs, DGA-like domain patterns)."
        )
    if any("evtx" in a for a in art_types):
        method_items.append(
            "**Windows Event Log Analysis:** Security event log (4688 process "
            "creation) examined for suspicious parent-child process relationships, "
            "encoded command-line arguments, and execution from non-standard paths."
        )
    if any("mft" in a for a in art_types):
        method_items.append(
            "**Filesystem Timeline Analysis:** Master File Table ($MFT) parsed "
            "for file creation, modification, and deletion timestamps within the "
            "incident window. NTFS metadata examined for timestomping indicators."
        )
    if any("registry" in a for a in art_types):
        method_items.append(
            "**Registry Analysis:** Windows Registry hives examined for persistence "
            "mechanisms (Run keys, services), user activity artifacts, and "
            "program execution evidence."
        )
    if any("memory" in a for a in art_types):
        method_items.append(
            "**Memory Forensics:** Memory dump analyzed for active processes, "
            "network connections, injected code, and hidden modules via process "
            "listing, VAD tree walking, and cross-view detection."
        )

    if method_items:
        for item in method_items:
            lines.append(f"- {item}")
    else:
        lines.append("- Automated forensic analysis of provided evidence files.")

    # Correlation note — keyed to the real cross_validated signal, not
    # CONFIRMED status (which can be single-source; see _is_cross_validated).
    confirmed = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    corroborated = _corroborated_count(findings)
    if corroborated > 0:
        lines.append(
            f"- **Cross-Artifact Correlation:** {corroborated} observation(s) were "
            f"corroborated across multiple independent detection methods, increasing "
            f"confidence."
        )
    elif confirmed > 0:
        lines.append(
            f"- **Cross-Artifact Correlation:** {confirmed} finding(s) carry CONFIRMED "
            f"status, but none were corroborated across multiple independent detection "
            f"methods — each rests on a single source."
        )

    # Evidence coverage
    evidence_available = [a for a in art_types] if art_types else ["provided evidence"]
    lines.append(f"\n**Evidence Sources:** {', '.join(sorted(evidence_available))}.\n")

    # Standard caveat (single source shared with Validator 5's allowlist)
    lines.append(f"*{_STANDARD_SCOPING_CAVEATS[0]}*")
    lines.append("")
    return lines


def _section_phase5_disposition(manifest: dict) -> list[str]:
    """Phase 5 disposition line (only when the manifest recorded one)."""
    lines = []

    # ── Phase 5 disposition (WS9): honest, only printed when the manifest
    # actually recorded one — see _phase5_disposition_line docstring.
    disposition_line = _phase5_disposition_line(manifest)
    if disposition_line:
        lines.append(disposition_line)
        lines.append("")
    return lines


def _section_evidence_intake(manifest: dict) -> list[str]:
    """Evidence Intake (deterministic, never LLM-authored)."""
    lines = []

    # ── Evidence Intake (Track B1: deterministic, never LLM-authored) ──
    intake_md = _generate_intake_section(manifest)
    if intake_md:
        lines.append("---\n")
        lines.append(intake_md)
    return lines
