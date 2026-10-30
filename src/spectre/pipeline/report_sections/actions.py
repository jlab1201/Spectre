"""Deterministic recommended IR actions and the "Recommended Actions" section."""

from __future__ import annotations

from spectre.pipeline.report_sections.common import _finding_rule_ids
from spectre.pipeline.report_sections.iocs import _ioc_role, _victim_context


def _recommended_actions(findings: list[dict], manifest: dict) -> tuple[list[str], list[str]]:
    """Deterministic IR actions keyed to rules that actually fired. Returns
    (immediate, followup). Each action references only IOC values/ports that
    already appear in findings — no new IOCs, no MITRE tags. This is advice
    derived from what the deterministic core produced, the same category as
    the Verdict's generic recommendation, only specific and actionable."""
    rule_ids = _finding_rule_ids(findings, manifest)
    fired = set(rule_ids.values())
    ctx = _victim_context(findings, manifest)
    immediate: list[str] = []
    followup: list[str] = []
    # Deliberately excludes pcap-dns-anomaly (domain IOCs, no egress-blockable IP) —
    # unlike _C2_PAYLOAD_RULES used for segmentation.
    _c2_rules = {"pcap-c2-protocol", "pcap-payload-host", "pcap-staging-download",
                 "pcap-large-transfer", "pcap-beacon"}

    if "pcap-exposed-service" in fired:
        svc_vals: list[str] = []
        for f in findings:
            if rule_ids.get(f.get("finding_id", "")) == "pcap-exposed-service":
                for values in (f.get("iocs") or {}).values():
                    for v in (values if isinstance(values, list) else [values]):
                        if v:
                            svc_vals.append(str(v))
        detail = ", ".join(list(dict.fromkeys(svc_vals))[:5]) if svc_vals else "the exposed service"
        immediate.append(f"Firewall or authenticate the exposed service(s) ({detail}) "
                         f"— reachable from untrusted networks.")

    if fired & _c2_rules:
        c2_ips: list[str] = []
        pivot_ips: list[str] = []
        for f in findings:
            if rule_ids.get(f.get("finding_id", "")) in _c2_rules:
                for v in (f.get("iocs") or {}).get("ip", []) or []:
                    # W4-4: never tell anyone to block the victim or own DC.
                    if v and _ioc_role("ip", str(v), ctx) == "remote":
                        c2_ips.append(str(v))
                    elif v and _ioc_role("ip", str(v), ctx) == "internal":
                        pivot_ips.append(str(v))
        c2_ips = list(dict.fromkeys(c2_ips))[:5]
        detail = ", ".join(c2_ips) if c2_ips else "the identified hosts"
        immediate.append(f"Block the identified C2/payload hosts ({detail}) at the network "
                         f"egress and alert on further connections.")
        if pivot_ips:
            # W4 review LOW: an internal address a C2/payload rule flagged is a
            # possible internal pivot — investigate it, never egress-block it.
            immediate.append("Investigate internal address(es) flagged by C2/payload rules ("
                             + ", ".join(list(dict.fromkeys(pivot_ips))[:5])
                             + ") as a possible internal pivot or relay.")

    # W4-4 / R1-F7: only identities bound to the monitored host (ip/mac
    # match at normalize time) are contained; a bystander device observed on
    # the segment is flagged for ownership follow-up, never "isolate".
    id_hosts = sorted(ctx["victim_hosts"])
    id_accts = sorted(ctx["victim_accounts"])
    if id_hosts or id_accts:
        parts = []
        if id_hosts:
            parts.append("isolate host(s) " + ", ".join(list(dict.fromkeys(id_hosts))[:3]))
        if id_accts:
            parts.append("review account(s) " + ", ".join(list(dict.fromkeys(id_accts))[:3]))
        immediate.append("Contain the affected identity: " + "; ".join(parts) + ".")

    others = sorted(ctx["bystander_hosts"] | ctx["bystander_accounts"])
    if others:
        followup.append("Identify the owner of other device(s)/account(s) observed on "
                        "the segment (" + ", ".join(others[:5]) + ") — not attributed "
                        "to the monitored host; do not treat as compromised without "
                        "further evidence.")
    # W4 review LOW: no binding either way (e.g. a no-IP DHCP DISCOVER when the
    # monitored host's MAC is unknown) — may be the victim itself; say so.
    unattributed = sorted(ctx["unattributed_hosts"] | ctx["unattributed_accounts"])
    if unattributed:
        followup.append("Resolve the binding of identity(ies) " + ", ".join(unattributed[:5])
                        + " — unattributed: the capture neither ties them to nor rules "
                        "them out from the monitored host (check DHCP/ARP/endpoint "
                        "records).")

    if fired & {"pcap-suspicious-port", "pcap-exploit-probe"}:
        followup.append("Rate-limit and geo-block the top scanning networks; review the "
                        "exposed-service inventory.")

    if fired & {"pcap-staging-download", "pcap-large-transfer"}:
        followup.append("Preserve the host for disk imaging and review data-at-rest for the "
                        "transferred content.")

    followup.append("Correlate with endpoint telemetry, memory, and disk evidence before "
                    "final determination.")
    return immediate, followup


def _section_recommended_actions(findings: list[dict], manifest: dict) -> list[str]:
    """Recommended Actions."""
    lines = []

    # ── Recommended Actions (deterministic IR actions keyed to rules that
    # fired; never empty — the baseline follow-up always applies). ──
    lines.append("## Recommended Actions\n")
    rec_immediate, rec_followup = _recommended_actions(findings, manifest)
    if rec_immediate:
        lines.append("**Immediate:**\n")
        for i, action in enumerate(rec_immediate, 1):
            lines.append(f"{i}. {action}")
        lines.append("")
    if rec_followup:
        lines.append("**Follow-Up:**\n")
        for i, action in enumerate(rec_followup, 1):
            lines.append(f"{i}. {action}")
        lines.append("")
    lines.append("---")
    lines.append("")
    return lines
