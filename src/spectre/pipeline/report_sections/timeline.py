"""The "3. Timeline" section."""

from __future__ import annotations

from spectre.pipeline.report_sections.common import _parse_finding_ts


def _section_timeline(llm_output: dict | None, findings: list[dict]) -> list[str]:
    """3. Timeline (model narrative, else dated/undated table)."""
    lines = []

    # ── 3. Timeline ──
    lines.append("## 3. Timeline\n")

    if llm_output and llm_output.get("timeline_narrative"):
        lines.append(llm_output["timeline_narrative"])
        lines.append("")
    else:
        # Fallback timeline table — sorted by evidence event_time.
        # Findings whose artifact type carries no evidence timestamp (e.g.
        # memory netscan/cmdline/malfind) are NEVER stamped with the
        # analysis run-time — they render in a trailing, explicitly-labeled
        # "Undated findings" block instead of masquerading as dated events.
        # Sort by PARSED datetime, never the raw event_time string (A6
        # Finding 2 — a string sort inverts chronology across artifact
        # types). A finding is "dated" only when _parse_finding_ts can
        # actually parse its event_time; anything else (empty, or an
        # unparseable shape like a bare epoch integer or yearless syslog
        # fragment) renders in the honest "Undated findings" block below
        # rather than being sorted by accident of string shape.
        _parsed = [(f, _parse_finding_ts(f.get("event_time"))) for f in findings]
        dated_findings = [f for f, ts in sorted(
            (p for p in _parsed if p[1] is not None), key=lambda p: p[1]
        )]
        undated_findings = [f for f, ts in _parsed if ts is None]
        lines.append("| Timestamp | Event | Finding |")
        lines.append("|-----------|-------|---------|")
        for finding in dated_findings:
            fid = finding.get("finding_id", "?")
            event_time = finding.get("event_time", "")
            title = (finding.get("title") or "?")[:80]
            lines.append(f"| {event_time} | {title} | {fid} |")
        lines.append("")

        if undated_findings:
            lines.append(
                "**Undated findings** (no evidence timestamp — artifact "
                "type carries no event time):"
            )
            for finding in undated_findings:
                fid = finding.get("finding_id", "?")
                title = (finding.get("title") or "?")[:80]
                lines.append(f"- {fid} — {title}")
            lines.append("")

    lines.append("---")
    lines.append("")
    return lines
