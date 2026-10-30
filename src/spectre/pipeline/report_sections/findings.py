"""Per-finding rendering: scale phrases, evidence blocks, the deterministic
threat chain, correlated findings, key-findings digest, and the
"1. Threat Narrative", "Detailed Findings" and "Appendix: Finding Index" sections.
"""

from __future__ import annotations

from collections import defaultdict

from spectre.pipeline.report_sections.common import (
    _build_finding_groups,
    _finding_rule_ids,
    _human_duration,
    _parse_finding_ts,
)
from spectre.pipeline.report_sections.confidence import _is_cross_validated
from spectre.pipeline.report_sections.dashboard import _severity_rank
from spectre.pipeline.report_sections.iocs import _recovered_credential_values
from spectre.pipeline.report_sections.mitre import _resolve_mitre_labels


def _finding_scale_phrase(finding: dict) -> str:
    """Coarse volume+span phrase from a finding's OWN occurrence_count/first_seen/
    last_seen. Empty string when occurrence_count <= 1 (nothing to quantify).
    Renders '<N> observations' always, ' from <first> to <last>' when both
    timestamps are present, and ' over <duration>' ONLY when both parse and the
    span is positive. Never invents a count or a span.
    """
    try:
        count = int(finding.get("occurrence_count") or 1)
    except (TypeError, ValueError):
        count = 1
    if count <= 1:
        return ""
    phrase = f"{count:,} observations"
    first = str(finding.get("first_seen") or "")
    last = str(finding.get("last_seen") or "")
    if first and last:
        phrase += f" from {first} to {last}"
        d0, d1 = _parse_finding_ts(first), _parse_finding_ts(last)
        if d0 and d1:
            delta = (d1 - d0).total_seconds()
            if delta > 0:
                phrase += f" over {_human_duration(delta)}"
    return phrase


def _rollup_scale_lines(findings: list[dict], manifest: dict) -> list[str]:
    """Executive-summary roll-up: total observations + overall span per rule
    group. Sums only real occurrence_count values (findings without the field
    contribute their default of 1). A group is rendered ONLY when its total
    exceeds its member count (i.e. at least one member carries real scale) — so
    a case with no occurrence_count data emits nothing. Span shown only from
    members with parseable timestamps. Returns [] when there is nothing to roll
    up. Introduces no count the findings did not carry.
    """
    rule_ids = _finding_rule_ids(findings, manifest)
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        rid = rule_ids.get(f.get("finding_id"))
        if rid:
            groups[rid].append(f)
    rows: list[tuple[int, str, int, str]] = []
    for rid, members in groups.items():
        try:
            total = sum(int(m.get("occurrence_count") or 1) for m in members)
        except (TypeError, ValueError):
            total = len(members)
        if total <= len(members):
            continue  # no real scale beyond the default-1 per finding
        firsts = [d for d in (_parse_finding_ts(m.get("first_seen", "")) for m in members) if d]
        lasts = [d for d in (_parse_finding_ts(m.get("last_seen", "")) for m in members) if d]
        span = ""
        if firsts and lasts:
            delta = (max(lasts) - min(firsts)).total_seconds()
            if delta > 0:
                span = f" over {_human_duration(delta)}"
        rows.append((total, rid, len(members), span))
    if not rows:
        return []
    rows.sort(key=lambda r: (-r[0], r[1]))
    out = [
        "### Activity Volume\n",
        "_Aggregated observation counts from the findings' own `occurrence_count` "
        "fields — descriptive scale, not new findings._\n",
    ]
    for total, rid, k, span in rows:
        out.append(f"- **{total:,} observations** across {k} finding(s) attributed to `{rid}`{span}")
    out.append("")
    return out


def _severity_line(severity: str) -> str:
    """TB-port T9: the deterministic per-finding severity line. Severity is the
    detection rule's own rating from the case ruleset snapshot ("how bad if
    confirmed"), never derived from confidence or status."""
    sev = (severity or "UNRATED").upper()
    if sev == "UNRATED":
        return "**Severity:** UNRATED (detection rule sets no severity level)"
    return f"**Severity:** {sev} (rule-assessed)"


def _append_finding_evidence_block(lines: list[str], finding: dict, mitre_labels: dict,
                                   caveat_tracker: dict | None = None,
                                   severity: str | None = None) -> None:
    """Append a compact evidence block for one finding. NOT the full YAML dump.

    caveat_tracker maps tuple(caveats) → finding_id of the first finding that
    rendered them; identical caveat lists are referenced, not repeated.
    severity (T9): the finding's resolved display severity (from the persisted
    dashboard metrics); None → no severity line (callers without metrics).
    """
    fid = finding.get("finding_id", "?")
    status = finding.get("status", "?")
    confidence = finding.get("confidence", 0.0)
    mitre = finding.get("mitre_attack", "UNMAPPED")
    # ponytail: composite "T1071.001, T1095" → resolve per-TID, dedupe shared labels
    label = ""
    if mitre and mitre != "UNMAPPED":
        label = _resolve_mitre_labels(mitre, mitre_labels)
        if label == mitre:
            label = ""
    # ponytail: finding["timestamps"] (plural) is never written by
    # emit_finding.py — findings carry "event_time" (real evidence time,
    # "" when the artifact type carries none) and "timestamp" (analysis
    # run-time). Reading the honest event_time here; never fabricate a
    # run-time stamp with _utcnow().
    event_time = finding.get("event_time", "")

    lines.append(f"**Status:** {status} | **Confidence:** {confidence:.2f} "
                 f"| **MITRE:** {mitre}" + (f" — {label}" if label else ""))
    if severity is not None:
        lines.append(_severity_line(severity))
    if event_time:
        lines.append(f"**Timestamp:** {event_time}")
    else:
        lines.append("**Timestamp:** _(no evidence timestamp)_")
    # A10 Finding 2 (MED transparency gap): emit_finding.py already writes
    # finding["tool"] (e.g. "zeek:http.log zeek-8.0.9" vs "tcpdump
    # tcpdump") and audit.jsonl already carries it, but report.md never
    # said which engine produced which observation. Deterministic — read
    # verbatim from the finding, never inferred.
    tool = finding.get("tool", "")
    if tool:
        lines.append(f"**Source:** {tool}")
    scale_phrase = _finding_scale_phrase(finding)
    if scale_phrase:
        lines.append(f"**Scale:** {scale_phrase}")
    lines.append("")

    # Evidence refs (compact)
    refs = finding.get("evidence_refs", [])
    if refs:
        lines.append("**Evidence:**")
        for ref in refs[:3]:
            eid = ref.get("execution_id", "?")
            lines.append(f"- execution_id: `{eid[:16]}...`")
        if len(refs) > 3:
            lines.append(f"- *(+{len(refs)-3} more evidence references)*")
        lines.append("")

    # IOCs (compact)
    iocs = finding.get("iocs", {})
    if iocs:
        parts = []
        for ioc_type, values in iocs.items():
            vals = values if isinstance(values, list) else [values]
            for v in vals:
                if v:
                    parts.append(f"`{v}`")
        if parts:
            lines.append(f"**IOCs:** {', '.join(parts[:10])}")
            if len(parts) > 10:
                lines[-1] += f" *(+{len(parts)-10} more)*"
            lines.append("")

    # C3: allowlisted recovered credentials (e.g. an archive password) from
    # this finding's own corroboration.artifacts — never a raw blob.
    creds = _recovered_credential_values(finding)
    if creds:
        lines.append("**Recovered Credentials:** "
                     + ", ".join(f"`{c}`" for c in creds))
        lines.append("")

    # Caveats (max 3 most important) — verbatim-identical lists render once
    caveats = finding.get("forensic_caveats", [])
    if caveats:
        caveat_key = tuple(caveats)
        first_fid = caveat_tracker.get(caveat_key) if caveat_tracker is not None else None
        if first_fid and first_fid != fid:
            lines.append(f"**Forensic Caveats:** *same caveats as {first_fid} — "
                         f"see §4 Forensic Blind Spots.*")
            lines.append("")
        else:
            if caveat_tracker is not None:
                caveat_tracker[caveat_key] = fid
            lines.append("**Forensic Caveats:**")
            for c in caveats[:3]:
                lines.append(f"- {c}")
            if len(caveats) > 3:
                lines.append(f"- *(+{len(caveats)-3} more caveats — see YAML)*")
            lines.append("")


def _deterministic_threat_chain(findings: list[dict]) -> list[str]:
    """Deterministic fallback for the §1 Threat Narrative when no model prose
    is available (skip-ai / host-deferred / synthesis failure).

    Produces NO fabricated causation — only anchors the sequence to the real
    earliest/latest dated findings (finding_id + event_time, both
    deterministic) and points the reader at Detailed Findings and the
    Timeline. Honest by construction: it never claims a causal link the
    deterministic layer did not observe.
    """
    # Sort by PARSED datetime (never the raw string — a lexicographic sort
    # inverts chronology whenever findings from different artifact types use
    # incompatible event_time shapes, e.g. a space-separated pcap-fallback
    # timestamp vs. a 'T'-separated ISO one). Unparseable values (bare epoch
    # integers, yearless syslog fragments, ...) are excluded here — they are
    # "undated" for this narrative's purposes, never guessed at.
    _parsed = [(f, _parse_finding_ts(f.get("event_time"))) for f in findings]
    dated = [f for f, ts in sorted((p for p in _parsed if p[1] is not None),
                                    key=lambda p: p[1])]
    out: list[str] = []
    if not dated:
        out.append(
            "No dated observations were available to order into a causal "
            "sequence. See the Detailed Findings below for the per-indicator "
            "assessment."
        )
    elif len(dated) == 1:
        f = dated[0]
        out.append(
            f"A single dated observation anchors the sequence: "
            f"{f.get('finding_id', '?')} at {f.get('event_time')}. A causal "
            f"attack-chain narrative was not synthesized for this run; see the "
            f"Detailed Findings below for its assessment."
        )
    else:
        first, last = dated[0], dated[-1]
        out.append(
            f"The examined evidence spans from {first.get('finding_id', '?')} "
            f"at {first.get('event_time')} to {last.get('finding_id', '?')} at "
            f"{last.get('event_time')}, with {len(dated)} dated observation(s) "
            f"in the sequence. A causal attack-chain narrative was not "
            f"synthesized for this run; the per-indicator assessment is in the "
            f"Detailed Findings below and the full chronology in the Timeline "
            f"section."
        )
    out.append("")
    return out


def _render_correlated_findings(manifest: dict, findings: list[dict]) -> list[str]:
    """Deterministic '## Correlated Findings' lines from manifest cluster data.
    Returns [] when there are no clusters (nothing invented)."""
    clusters = manifest.get("correlation_clusters") or {}
    ioc = clusters.get("ioc_overlap") or []
    temporal = clusters.get("temporal") or []
    if not ioc and not temporal:
        return []
    titles = {f.get("finding_id"): f.get("title", "") for f in findings}

    def _member_line(fid: str) -> str:
        return f"  - `{fid}` — {titles.get(fid, '')}".rstrip(" —")

    lines = ["## Correlated Findings\n"]
    if ioc:
        lines.append("**Shared-entity clusters** (same indicator across artifacts):\n")
        for c in ioc:
            ents = ", ".join(e.split(":", 1)[-1] for e in c.get("shared_entities", []))
            spans = "; ".join(f"{e.split(':', 1)[-1]} in {', '.join(a)}"
                              for e, a in (c.get("artifact_span") or {}).items())
            lines.append(f"- **{c['cluster_id']}** — shared: {ents}"
                         + (f" ({spans})" if spans else ""))
            for fid in c["member_finding_ids"]:
                lines.append(_member_line(fid))
        lines.append("")
    if temporal:
        lines.append("**Temporal clusters** (findings close in time):\n")
        for c in temporal:
            tr = c.get("time_range", ["", ""])
            lines.append(f"- **{c['cluster_id']}** — {tr[0]} → {tr[1]}")
            for fid in c["member_finding_ids"]:
                lines.append(_member_line(fid))
        lines.append("")
    return lines


# C4: Key Findings BLUF digest size (top-N by confidence).
_KEY_FINDINGS_TOP_N = 5


def _key_findings_digest(findings: list[dict], top_n: int = _KEY_FINDINGS_TOP_N) -> list[str]:
    """Bottom-line-up-front digest: the top-N findings by confidence (tie-broken
    deterministically by finding_id), each a one-line
    'title — status, confidence[, <count> observations]'. Pure selection and
    formatting over existing findings — no prose synthesis, no new finding.
    Returns [] for empty findings (no empty header)."""
    if not findings:
        return []
    ranked = sorted(
        findings,
        key=lambda f: (-float(f.get("confidence") or 0.0), str(f.get("finding_id", ""))),
    )
    out = [
        "### Key Findings\n",
        "_Bottom-line-up-front: highest-confidence findings first. See Detailed "
        "Findings for the full per-indicator assessment._\n",
    ]
    for f in ranked[:top_n]:
        title = f.get("title") or f.get("finding_id", "?")
        status = f.get("status", "?")
        conf = float(f.get("confidence") or 0.0)
        line = f"- **{title}** — {status}, confidence {conf:.2f}"
        try:
            count = int(f.get("occurrence_count") or 1)
        except (TypeError, ValueError):
            count = 1
        if count > 1:
            line += f", {count:,} observations"
        out.append(line)
    out.append("")
    return out


def _section_threat_narrative(
    llm_output: dict | None,
    findings: list[dict],
) -> list[str]:
    """1. Threat Narrative (model narrative, else deterministic causal chain)."""
    lines = []

    # ── 1. Threat Narrative (causal attack chain) ──
    # The model-written threat_narrative is a causal chain (delivery → C2 →
    # …) with timestamps + F-ID cross-refs (gold parity). It is grounded by
    # _validate_report Validator 10 before it ever reaches here. Per-finding
    # detail moves below into "### Detailed Findings" so this section reads as
    # a narrative, not a list.
    lines.append("## 1. Threat Narrative\n")

    if llm_output and str(llm_output.get("threat_narrative") or "").strip():
        lines.append(llm_output["threat_narrative"])
        lines.append("")
    else:
        lines.extend(_deterministic_threat_chain(findings))
    return lines


def _section_detailed_findings(
    llm_output: dict | None,
    findings: list[dict],
    metrics: dict,
    mitre_labels: dict,
) -> list[str]:
    """1. > Detailed Findings (per finding: Evidence / Assessment / Confidence)."""
    lines = []

    # ponytail: composite "T1071.001, T1095" strings need per-TID resolution
    def _resolve_mitre(mt_string: str) -> str:
        return _resolve_mitre_labels(mt_string, mitre_labels)

    # Shared across all evidence blocks: identical caveat lists render once
    caveat_tracker: dict[tuple, str] = {}

    # ── Detailed Findings (per finding: Evidence / Assessment / Confidence) ──
    # Assessment = the grounded, model-written findings_narrative prose.
    # Evidence + Confidence come from _append_finding_evidence_block
    # (deterministic — never model output). The model's Assessment is already
    # grounded per-item by Validator 10; this only changes how it renders.
    lines.append("### Detailed Findings\n")

    _fsev = metrics.get("finding_severity") or {}

    def _sev_of(f: dict) -> str:
        return _fsev.get(f.get("finding_id"), "UNRATED")

    def _sev_conf_key(f: dict) -> tuple:
        try:
            conf = float(f.get("confidence") or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        return (_severity_rank(_sev_of(f)), -conf, str(f.get("finding_id") or ""))

    fn = llm_output.get("findings_narrative") if llm_output else None
    if isinstance(fn, str) and fn.strip():
        # ponytail: LLM may return one prose string instead of a list
        lines.append(fn)
        lines.append("")
    elif isinstance(fn, list) and any(
            isinstance(i, dict) and i.get("narrative") for i in fn):
        for item in fn:
            if not isinstance(item, dict):
                continue
            fid = item.get("finding_id", "")
            narrative = item.get("narrative", "")
            if not narrative:
                continue
            match = next((f for f in findings if f.get("finding_id") == fid), None)
            title = (match.get("title") if match else "") or ""
            lines.append(f"#### {fid}: {title}\n" if title else f"#### {fid}\n")
            lines.append(f"**Assessment:** {narrative}")
            lines.append("")
            # Deterministic Evidence + Confidence block for this finding
            if match is not None:
                _append_finding_evidence_block(lines, match, mitre_labels,
                                               caveat_tracker, _sev_of(match))
            lines.append("---\n")
    else:
        # Deterministic: group findings by technique/target, write prose per group
        groups = _build_finding_groups(findings)
        # T9: within each group, most severe (rule rating) first, then most
        # confident — so a group's representative is its most severe member.
        for _g in groups.values():
            _g["findings"].sort(key=_sev_conf_key)
        # Sort groups: CONFIRMED findings first, then most severe member, then
        # by count desc (severity never outranks the CONFIRMED-first tier).
        sorted_groups = sorted(
            groups.items(),
            key=lambda kv: (
                0 if any(f.get("status") == "CONFIRMED" for f in kv[1]["findings"]) else 1,
                _sev_conf_key(kv[1]["findings"][0])[0],
                -len(kv[1]["findings"]),
            )
        )

        DETAIL_CAP = 5  # Only detail the top 5 most significant findings
        detailed_count = 0

        for group_key, group in sorted_groups:
            gfindings = group["findings"]
            technique = group["technique"]
            label = _resolve_mitre(technique) if technique != "UNMAPPED" else technique
            count = len(gfindings)

            if count == 1:
                f = gfindings[0]
                if detailed_count < DETAIL_CAP:
                    lines.append(f"#### {f['finding_id']}: {f.get('title','?')}\n")
                    _append_finding_evidence_block(lines, f, mitre_labels,
                                                   caveat_tracker, _sev_of(f))
                    detailed_count += 1
                else:
                    fid = f.get("finding_id", "?")
                    lines.append(
                        f"- **{fid}**: {f.get('title','?')} "
                        f"({f.get('status','?')}, {f.get('confidence',0):.2f}) "
                        f"— {label}\n"
                    )
            else:
                # Group narrative
                confs = [f.get("confidence", 0) for f in gfindings]
                statuses = set(f.get("status", "?") for f in gfindings)
                fid_list = [f.get("finding_id", "?") for f in gfindings]
                fids_abbrev = fid_list[0] if count <= 3 else f"{fid_list[0]} through {fid_list[-1]}"

                lines.append(f"#### {label} — {count} findings ({fids_abbrev})\n")
                lines.append(
                    f"**{count} detection(s)** of {group_key.split(':')[-1].lower()} "
                    f"were identified, mapped to MITRE {technique}"
                    + (f" ({label})" if label != technique else "") + ". "
                )
                if "CONFIRMED" in statuses:
                    group_corroborated = sum(1 for f in gfindings if _is_cross_validated(f))
                    if group_corroborated > 0:
                        lines.append(
                            f"{group_corroborated} of these are corroborated by multiple "
                            f"independent detection methods. "
                        )
                    else:
                        lines.append(
                            "Some findings carry CONFIRMED status (met the deterministic "
                            "corroboration threshold), but none are corroborated by an "
                            "independent detection method — each rests on a single "
                            "source. "
                        )
                else:
                    lines.append("All findings are INFERRED (single-source detection). ")
                if min(confs) == max(confs):
                    lines.append(f"Confidence: {min(confs):.2f}.\n")
                else:
                    lines.append(f"Confidence range: {min(confs):.2f}–{max(confs):.2f}.\n")

                # Detail first finding as representative
                if detailed_count < DETAIL_CAP:
                    rep = gfindings[0]
                    lines.append(f"**Representative finding — {rep['finding_id']}:**\n")
                    _append_finding_evidence_block(lines, rep, mitre_labels,
                                                   caveat_tracker, _sev_of(rep))
                    detailed_count += 1
                    if count > 1:
                        remaining_ids = ", ".join(f.get("finding_id","?") for f in gfindings[1:6])
                        if count > 6:
                            remaining_ids += f", ... (+{count-6} more)"
                        lines.append(f"*Additional findings in this group: {remaining_ids}.*\n")
                else:
                    lines.append(f"*See appendix for full detail on these {count} findings.*\n")

                lines.append("---\n")

    lines.append("")
    return lines


def _section_finding_index(findings: list[dict], case_dir: str) -> list[str]:
    """Appendix: Finding Index."""
    lines = []

    # ── Appendix: Finding Index ──
    lines.append("---\n")
    lines.append("## Appendix: Finding Index\n")
    lines.append("| Finding ID | Status | Confidence | MITRE | Title |")
    lines.append("|------------|--------|------------|-------|-------|")
    for f in findings:
        fid = f.get("finding_id", "?")
        status = f.get("status", "?")
        conf = f.get("confidence", 0.0)
        mitre = f.get("mitre_attack", "?")
        title = (f.get("title") or "")[:80]
        lines.append(f"| {fid} | {status} | {conf:.2f} | {mitre} | {title} |")
    lines.append("")
    lines.append(f"*Full findings at: {case_dir}/findings/F-*.yaml*")
    lines.append("")
    return lines
