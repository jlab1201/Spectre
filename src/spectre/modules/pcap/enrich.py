"""pcap/enrich.py — DNS answer cross-referencing onto flow events.

normalize_dns resolves query/response pairs into pcap_dns events; when a
response event carries both a resolved domain name (dns_query, id-matched
against the earlier query) and its answer IPs (data["answers"]), that is
enough to build an ip -> domain map. Flow events (pcap_flow) only ever see
raw IP addresses — this enrich hook cross-references the two so
downstream rules can reason about "download from files.catbox.moe" instead
of just "download from 108.181.20.35".

Pure cross-referencing of already-extracted facts: no findings are
invented here, only an ip->domain label stamped onto existing flow data.
"""

from __future__ import annotations


def enrich_events(events: list) -> None:
    """Stamp `resolved_domain` onto pcap_flow events whose remote_ip
    matches a DNS-resolved answer IP elsewhere in the same event list.

    Mutates event.data in place; never adds/removes events (required by
    the Phase 3 enrich-hook contract).
    """
    ip_to_domain: dict[str, str] = {}
    for e in events:
        if e.artifact_type != "pcap_dns":
            continue
        domain = e.data.get("dns_query", "")
        answers = e.data.get("answers") or []
        if not domain:
            continue
        resolved = domain.rstrip(".")
        for ip in answers:
            ip_to_domain.setdefault(ip, resolved)

    for e in events:
        if e.artifact_type != "pcap_flow":
            continue
        remote_ip = e.data.get("remote_ip", "")
        domain = ip_to_domain.get(remote_ip)
        if domain:
            e.data["resolved_domain"] = domain
