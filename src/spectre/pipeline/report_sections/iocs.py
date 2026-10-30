"""IOC extraction, victim context and segmentation, host-IOC / campaign-tag
tables, iocs.csv, and the "Key Indicators" and "5. IOC Export" sections.
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict

from spectre.pipeline.report_sections.common import _finding_rule_ids


def _build_deduped_ioc_table(findings: list[dict]) -> list[tuple[str, str, list[str], int]]:
    """Return deduplicated IOC rows: [(type, value, [finding_ids], count)].
    Sorted by count descending (most-referenced IOCs first)."""
    ioc_map: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in findings:
        fid = f.get("finding_id", "?")
        for ioc_type, values in f.get("iocs", {}).items():
            for v in (values if isinstance(values, list) else [values]):
                if v:
                    ioc_map[(ioc_type, v)].add(fid)
    rows = [(typ, val, sorted(fids), len(fids)) for (typ, val), fids in ioc_map.items()]
    rows.sort(key=lambda r: -r[3])  # most-referenced first
    return rows


# IOC role segmentation (Track E3). Roles key off each finding's REAL
# rule_id (via _finding_rule_ids) — never a MITRE-technique guess. dns
# anomalies are suspicious domains the host contacted (C2-adjacent), so
# they sit with C2/payload, not scanner infrastructure.
_C2_PAYLOAD_RULES = frozenset({
    "pcap-c2-protocol", "pcap-payload-host", "pcap-staging-download",
    "pcap-large-transfer", "pcap-beacon", "pcap-dns-anomaly",
})


_SCANNER_RULES = frozenset({"pcap-suspicious-port", "pcap-exploit-probe"})


_EXPOSED_RULES = frozenset({"pcap-exposed-service"})


# ── W4-4 / R1-F7: victim / internal / remote IOC roles ────────────────
# The org's own infrastructure and the victim's identities are NEVER block-list
# material. Deterministic: RFC1918/loopback/link-local IPs, the monitored IP,
# identities bound to the monitored host (host_ip set by the pcap normalizer
# only on an ip/mac match), the AD realm(s) those identities carry and names
# under them (incl. wpad.<realm>), and local-only suffixes. No inference beyond these equalities.
_LOCAL_DOMAIN_SUFFIXES = (".local", ".lan", ".internal", ".home.arpa",
                          ".localdomain", ".localhost")


def _is_internal_ip(value: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


# W4 review MED-2: a realm that is only a public suffix (COM, CO.UK, ...) can
# never be an org domain. Small zero-dep list — rejection only, so a missing
# entry can only fail to trust a realm (safe), and corroboration is required
# on top anyway.
_PUBLIC_SUFFIXES = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro",
    "io", "co", "me", "tv", "cc", "ws", "xyz", "top", "online", "site", "store",
    "app", "dev", "cloud", "tech", "shop", "club", "live", "icu", "vip", "work",
    "us", "uk", "de", "fr", "ru", "cn", "jp", "br", "in", "au", "ca", "nl", "eu",
    "it", "es", "pl", "se", "no", "fi", "dk", "ch", "at", "be", "cz", "pt", "gr",
    "tr", "ir", "kr", "tw", "hk", "sg", "my", "id", "th", "vn", "ph", "mx", "ar",
    "cl", "za", "ng", "ua", "su", "nz", "ie", "il", "sa", "ae", "pk", "bd", "ro",
    "hu", "bg", "sk", "lt", "lv", "ee", "by", "kz", "ly", "to", "ai", "gg", "la",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "com.br", "net.br", "com.cn", "net.cn",
    "org.cn", "com.tw", "com.hk", "com.sg", "com.my", "co.in", "net.in",
    "co.za", "com.mx", "com.ar", "com.tr", "co.kr", "or.kr", "com.ru", "com.ua",
    "co.il", "com.sa", "com.pk", "co.id", "co.th", "com.vn", "com.ph",
})


def _norm_domain(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _is_org_domain_candidate(d: str) -> bool:
    """>=2 labels and not itself a public suffix."""
    return "." in d and d not in _PUBLIC_SUFFIXES


def _is_identity_finding(f: dict, rid: str = "") -> bool:
    iocs = f.get("iocs") or {}
    return rid == "pcap-host-identity" or bool(iocs.get("host") or iocs.get("account"))


def _identity_source(f: dict) -> str:
    """'kerberos' | 'dhcp' | '' — from the rule's own artifact text
    ("identity [dhcp]: ..."); falls back to the IOC shape."""
    for a in (f.get("corroboration") or {}).get("artifacts") or []:
        m = re.match(r"identity \[(\w+)\]", str(a))
        if m:
            return m.group(1).lower()
    iocs = f.get("iocs") or {}
    if iocs.get("account"):
        return "kerberos"
    return "dhcp" if iocs.get("host") else ""


def _is_bystander_identity(f: dict) -> bool:
    """True only when the normalizer positively ruled the identity foreign
    (bound_to_monitored False → "bystander device" in its artifact text)."""
    return any("bystander device" in str(a)
               for a in (f.get("corroboration") or {}).get("artifacts") or [])


def _victim_context(findings: list[dict], manifest: dict | None = None) -> dict:
    """Deterministic victim/internal identity sets for IOC role labelling.

    Org (internal) domains (W4 review MED-2): a Kerberos realm counts ONLY
    when (1) its identity is bound to the monitored host, (2) it has >=2
    labels and is not a public suffix, and (3) a SECOND victim-bound source
    — the DHCP client FQDN suffix / domain option — names the same domain
    (or a parent/child of it). Anything else leaves domains remote, and the
    realm is recorded in ctx["realm_notes"] so the report can say why.
    """
    manifest = manifest or {}
    rule_ids = _finding_rule_ids(findings, manifest)
    monitored = (manifest.get("monitored_ip") or "").strip()
    if not monitored:
        counts: dict[str, int] = defaultdict(int)
        for f in findings:
            h = str(f.get("host_ip") or "").strip()
            if h:
                counts[h] += 1
        monitored = max(counts, key=counts.get) if counts else ""
    ctx = {"monitored": monitored, "victim_hosts": set(), "victim_accounts": set(),
           "bystander_hosts": set(), "bystander_accounts": set(),
           "unattributed_hosts": set(), "unattributed_accounts": set(),
           "internal_domains": set(), "realm_notes": []}
    realms: set[str] = set()
    dns_domains: set[str] = set()
    for f in findings:
        if not _is_identity_finding(f, rule_ids.get(f.get("finding_id", ""), "")):
            continue
        iocs = f.get("iocs") or {}
        host_ip = str(f.get("host_ip") or "").strip()
        bound = bool(host_ip) and (not monitored or host_ip == monitored)
        hosts = {str(v) for v in iocs.get("host") or [] if v}
        accts = {str(v) for v in iocs.get("account") or [] if v}
        if bound:
            ctx["victim_hosts"] |= hosts
            ctx["victim_accounts"] |= accts
        elif _is_bystander_identity(f):
            ctx["bystander_hosts"] |= hosts
            ctx["bystander_accounts"] |= accts
        else:
            ctx["unattributed_hosts"] |= hosts
            ctx["unattributed_accounts"] |= accts
        if not bound:
            continue   # a bystander's realm/domain never shapes org scope
        doms = {_norm_domain(v) for v in iocs.get("domain") or [] if v}
        if _identity_source(f) == "kerberos":
            realms |= doms
            realms |= {_norm_domain(a.split("@", 1)[1]) for a in accts if "@" in a}
        else:
            dns_domains |= {d for d in doms if _is_org_domain_candidate(d)}
    for r in sorted(realms):
        if "." not in r:
            continue   # short NetBIOS-style realm; never used for suffix matching
        if r in _PUBLIC_SUFFIXES:
            ctx["realm_notes"].append((r.upper(), "is a public suffix"))
            continue
        if any(d == r or d.endswith("." + r) or r.endswith("." + d) for d in dns_domains):
            ctx["internal_domains"].add(r)
        else:
            ctx["realm_notes"].append(
                (r.upper(), "not corroborated by a second victim-bound source "
                            "(DHCP client FQDN / domain)"))
    return ctx


def _is_internal_domain(value: str, ctx: dict) -> bool:
    d = _norm_domain(value)
    if not d:
        return False
    if d.endswith(_LOCAL_DOMAIN_SUFFIXES):
        return True
    if "." not in d:
        return d not in _PUBLIC_SUFFIXES   # single-label (NetBIOS) name
    # wpad.X is internal ONLY via this rule (X == / under the victim's
    # corroborated AD/DNS domain): wpad.evil.tld or a wpad.<tld> collision is
    # WPAD hijack infrastructure and must keep its normal (remote) role.
    return any(d == r or d.endswith("." + r) for r in ctx["internal_domains"])


def _ioc_role(ioc_type: str, value: str, ctx: dict) -> str:
    """'victim' | 'internal' | 'remote' for one IOC value."""
    v = str(value).strip()
    if ioc_type == "ip":
        if ctx["monitored"] and v == ctx["monitored"]:
            return "victim"
        return "internal" if _is_internal_ip(v) else "remote"
    if ioc_type == "host":
        if v in ctx["victim_hosts"]:
            return "victim"
        return ("internal" if v in ctx["bystander_hosts"] | ctx["unattributed_hosts"]
                else "remote")
    if ioc_type == "account":
        if v in ctx["victim_accounts"]:
            return "victim"
        return ("internal" if v in ctx["bystander_accounts"] | ctx["unattributed_accounts"]
                else "remote")
    if ioc_type == "domain" and _is_internal_domain(v, ctx):
        return "internal"
    return "remote"


def _segment_iocs(findings: list[dict], manifest: dict) -> dict[str, list[tuple[str, str, str, float]]]:
    """Group IOC rows into role segments for the human report. Returns an
    ordered dict {segment: [(ioc_type, value, finding_id, confidence)]}.
    Role derives from the finding's real rule_id + ioc type + the monitored
    host; an unknown rule_id lands in 'Other' (never guessed into a specific
    role). Nothing is dropped."""
    rule_ids = _finding_rule_ids(findings, manifest)
    monitored = (manifest.get("monitored_ip") or "").strip()
    ctx = _victim_context(findings, manifest)
    segments: dict[str, list] = {
        "Monitored Host": [],
        "Malware C2 & Payload Hosts": [],
        "Scanner Infrastructure": [],
        "Exposed Services": [],
        "Host & Account Identity": [],
        "Internal Infrastructure": [],
        "Other": [],
    }
    for f in findings:
        fid = f.get("finding_id", "?")
        conf = f.get("confidence", 0.0)
        rid = rule_ids.get(fid, "")
        for ioc_type, values in (f.get("iocs") or {}).items():
            for v in (values if isinstance(values, list) else [values]):
                if not v:
                    continue
                row = (ioc_type, str(v), fid, conf)
                if monitored and str(v) == monitored:
                    segments["Monitored Host"].append(row)
                elif ioc_type in ("host", "account"):
                    segments["Host & Account Identity"].append(row)
                elif rid not in _EXPOSED_RULES and \
                        not (ioc_type == "ip" and (rid in _C2_PAYLOAD_RULES
                                                   or rid in _SCANNER_RULES)) and \
                        _ioc_role(ioc_type, str(v), ctx) != "remote":
                    # W4-4: own DC / RFC1918 / corroborated realm / WPAD names
                    # are never block-list material. W4 review LOW: a private
                    # IP that a C2/beacon/scanner rule itself flagged STAYS in
                    # its section (internal pivot) — annotated at render time.
                    segments["Internal Infrastructure"].append(row)
                elif rid in _EXPOSED_RULES:
                    segments["Exposed Services"].append(row)
                elif rid in _C2_PAYLOAD_RULES:
                    segments["Malware C2 & Payload Hosts"].append(row)
                elif rid in _SCANNER_RULES:
                    segments["Scanner Infrastructure"].append(row)
                else:
                    segments["Other"].append(row)
    # Track K: the monitored host lives in each finding's host_ip, never in
    # iocs, so the loop above can never match it. Surface it from the manifest
    # fact when nothing else populated the segment — descriptive subject
    # metadata, not a finding claim (marked "(subject host)"). Fixes E3
    # Component 3 for pcap cases; pcap-only (monitored absent → no seed).
    if monitored and not segments["Monitored Host"]:
        segments["Monitored Host"].append(("ip", monitored, "(subject host)", 0.0))
    return segments


# ── Track H: Host-Based IOCs + Campaign Tags tables ───────────────────
# Both helpers are pure text parsers over corroboration.artifacts — the
# exact strings the deterministic rule pack already wrote (e.g. pcap
# rules.py Checks 2/6). Nothing here looks up a malware-intel database,
# an indicator YAML, or gold's report; every cell is traceable to a
# finding's own artifact text. See
# the track-H case001 report-tables design spec.
# NB: [^,;] stops the captured fragment at the first comma/semicolon. All current
# _C2_USER_AGENTS signatures are comma-free, so this captures them whole; a future
# signature containing a comma would be under-captured (truncated), never
# over-captured — so this can only ever surface LESS than the finding holds, never
# fabricate. If comma-bearing signatures are added, widen this pattern.
_UA_SIGNATURE_RE = re.compile(r"User-Agent matches:\s*([^,;|]+)")


# Track L: the pcap rule pack now also emits the FULL User-Agent header and an
# OS derived from its "Windows NT x.y" token, pipe-delimited on the finding
# summary. Capture each up to the next pipe (or end of string).
_UA_FULL_RE = re.compile(r"host User-Agent \(full\):\s*([^|]+)")


_OS_FROM_UA_RE = re.compile(r"host OS \(from UA\):\s*([^|]+)")


# Matches "Campaign tag KEY=VALUE (family)" or "C2 parameter KEY=VALUE" as
# written by pcap/rules.py Check 6. VALUE excludes , ; ( ) and whitespace —
# the same delimiters the rule pack joins triggers with.
_CAMPAIGN_TAG_RE = re.compile(
    r"(?:Campaign tag|C2 parameter)\s+([A-Za-z0-9][A-Za-z0-9-]*)=([^,;()\s]+)"
    r"(?:\s*\(([^)]+)\))?"
)


# T1-0 carries the encrypted base64 C2 payload, not a rotating campaign/config
# tag (see spec) — excluded from the Campaign Tags table.
_CAMPAIGN_TAG_EXCLUDE = frozenset({"T1-0"})


_NO_GROUNDED_ROLE = "Rotating C2 parameter (role not independently confirmed)"


# C3: allowlist of high-value artifact fields surfaced from corroboration.artifacts.
# Conservative marker allowlist — recovered archive/credential passwords ONLY.
# An un-marked blob is never matched, so the report stays a curated document.
# NB: the exact producer marker for case 004's RAR password is not present in
# this worktree; these markers cover the documented shapes and MUST be reconciled
# with the disk rule pack's actual emission before relying on it in production.
_RECOVERED_CRED_MARKERS = re.compile(
    r"(?:archive password recovered|recovered archive password|password recovered"
    r"|recovered password|rar password|zip password|archive password)"
    r"\s*[:=]\s*([^,;|\n\r]+)",
    re.IGNORECASE,
)


def _recovered_credential_values(finding: dict) -> list[str]:
    """Allowlisted recovered-credential values from a finding's own
    corroboration.artifacts text. De-duplicated, order-preserving. Matches only
    the explicit _RECOVERED_CRED_MARKERS shapes — never dumps a raw blob."""
    out: list[str] = []
    seen: set[str] = set()
    for a in (finding.get("corroboration") or {}).get("artifacts") or []:
        m = _RECOVERED_CRED_MARKERS.search(str(a))
        if m:
            v = m.group(1).strip()
            if v and v not in seen:
                seen.add(v)
                out.append(v)
    return out


def _dedupe_domains(findings: list[dict]) -> list[str]:
    """Case-insensitively de-duplicated, lower-cased iocs.domain values across
    findings, in first-seen order. Arithmetic over existing IOC values only."""
    seen: set[str] = set()
    out: list[str] = []
    for f in findings:
        for d in (f.get("iocs") or {}).get("domain") or []:
            if not d:
                continue
            key = str(d).strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _tld_histogram(domains: list[str]) -> list[tuple[str, int]]:
    """Count domains by top-level label, sorted by count desc then TLD asc.
    A domain with no dot counts under '(none)'. Pure arithmetic; no new domain."""
    counts: dict[str, int] = defaultdict(int)
    for d in domains:
        parts = d.rsplit(".", 1)
        tld = parts[-1] if len(parts) == 2 and parts[-1] else "(none)"
        counts[tld] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _build_host_iocs_table(findings: list[dict]) -> list[tuple[str, str, str]]:
    """Return [(fact_type, value, note)] rows for host-based facts inferable
    from network traffic — grounded ONLY in corroboration.artifacts text.

    Track L: when the pcap rule pack captured the FULL User-Agent header and
    derived an OS from it (`host User-Agent (full):` / `host OS (from UA):`
    markers), surface those as real rows and suppress the old signature-
    fragment row (its "not captured" note is then false). When only the
    fragment marker is present (older findings, other UA signatures), keep the
    fragment row exactly as before — full back-compat. No OS-version, URI, or
    filename row is ever invented; each cell traces to a finding's own text."""
    fragments: dict[str, None] = {}
    full_uas: dict[str, None] = {}
    os_strings: dict[str, None] = {}
    for f in findings:
        for a in (f.get("corroboration") or {}).get("artifacts") or []:
            text = str(a)
            m = _UA_SIGNATURE_RE.search(text)
            if m:
                fragments.setdefault(m.group(1).strip(), None)
            fm = _UA_FULL_RE.search(text)
            if fm:
                full_uas.setdefault(fm.group(1).strip(), None)
            om = _OS_FROM_UA_RE.search(text)
            if om:
                os_strings.setdefault(om.group(1).strip(), None)

    rows: list[tuple[str, str, str]] = []
    for value in full_uas:
        rows.append((
            "Host User-Agent (full header)", value,
            "Full HTTP User-Agent the monitored host sent. A genuine WebKit "
            "browser writes '(KHTML, like Gecko)'; the missing comma here "
            "matched the known-C2 User-Agent indicator list.",
        ))
    for value in os_strings:
        rows.append((
            "Host OS (derived from User-Agent)", value,
            "Derived from the 'Windows NT x.y' token in the User-Agent header.",
        ))
    # Only fall back to the fragment row when no full header was captured.
    if not full_uas:
        for value in fragments:
            rows.append((
                "C2 User-Agent (signature fragment)", value,
                "Partial match against known C2 User-Agent indicator list — "
                "full header string was not captured by the detecting module",
            ))
    return rows


def _build_campaign_tags_table(findings: list[dict]) -> list[tuple[str, str, str]]:
    """Return [(tag, value, interpretation)] rows, one per distinct campaign-
    tag key seen in corroboration.artifacts (excludes the T1-0 encrypted-
    payload parameter). Interpretation is the finding-text family name when
    the rule pack already wrote one (currently only z8); otherwise a neutral,
    non-fabricated label — no per-tag semantic guess not grounded in a
    finding field."""
    tags: dict[str, tuple[str, str]] = {}  # key -> (value, interpretation)
    for f in findings:
        for a in (f.get("corroboration") or {}).get("artifacts") or []:
            for key, value, family in _CAMPAIGN_TAG_RE.findall(str(a)):
                if key in _CAMPAIGN_TAG_EXCLUDE or key in tags:
                    continue
                interpretation = family.strip() if family else _NO_GROUNDED_ROLE
                tags[key] = (value.strip(), interpretation)
    return [(key, value, interp) for key, (value, interp) in tags.items()]


def _section_key_indicators(findings: list[dict]) -> list[str]:
    """Executive Summary > Key Indicators (deduplicated IOC summary, capped at 20)."""
    lines = []

    # ── Compact IOC summary (deduplicated) ──
    ioc_rows = _build_deduped_ioc_table(findings)
    if ioc_rows:
        lines.append("### Key Indicators\n")
        lines.append("| Type | Value | Findings | Ref Count |")
        lines.append("|------|-------|----------|-----------|")
        for typ, val, fids, count in ioc_rows[:20]:  # cap at 20 rows
            if len(fids) == 1:
                fid_str = fids[0]
            elif len(fids) <= 4:
                fid_str = ", ".join(fids)
            else:
                fid_str = f"{fids[0]} (+{len(fids)-1})"
            lines.append(f"| {typ} | `{val}` | {fid_str} | {count} |")
        if len(ioc_rows) > 20:
            lines.append(f"| ... | *{len(ioc_rows)-20} additional IOCs* | *(see appendix)* | |")
        lines.append("")
    return lines


def _section_ioc_export(findings: list[dict], manifest: dict) -> list[str]:
    """5. IOC Export (segmented IOCs, domains, credentials, host IOCs, campaign tags)."""
    lines = []

    # ── 5. IOC Export ──
    lines.append("## 5. IOC Export\n")
    ioc_segments = _segment_iocs(findings, manifest)
    _ioc_ctx = _victim_context(findings, manifest)
    if not any(rows for rows in ioc_segments.values()):
        lines.append("_No IOCs were extracted from the examined evidence._\n")
    else:
        for seg_name, rows in ioc_segments.items():
            if not rows:
                continue
            lines.append(f"### {seg_name}\n")
            lines.append("| Type | Value | Finding ID | Confidence |")
            lines.append("|------|-------|------------|------------|")
            for ioc_type, value, fid, conf in rows:
                shown = value
                if (seg_name in ("Malware C2 & Payload Hosts", "Scanner Infrastructure")
                        and ioc_type == "ip" and _is_internal_ip(value)):
                    # W4 review LOW: internal pivot C2 stays visible, flagged.
                    shown = f"{value} _(internal address — investigate the internal host)_"
                lines.append(f"| {ioc_type} | {shown} | {fid} | {conf:.2f} |")
            lines.append("")

    # W4 review MED-2: say why an observed victim realm was NOT trusted to mark
    # domains internal (they stay remote / block-listable).
    for realm, why in _victim_context(findings, manifest)["realm_notes"]:
        lines.append(f"_Note: Kerberos realm {realm} {why}; domains under it are "
                     f"left remote (not treated as internal)._\n")

    # C3: deduped domain list + TLD histogram — pure arithmetic over iocs.domain.
    domains = _dedupe_domains(findings)
    if domains:
        lines.append("### Domain Indicators (deduplicated)\n")
        lines.append(f"_{len(domains)} unique domain(s), case-normalized._\n")
        dctx = _victim_context(findings, manifest)
        for d in domains:
            # W4-4: the org's own realm / WPAD / local names are inventory,
            # never block-list material — say so on the line.
            tag = (" _(internal — not for block-listing)_"
                   if _ioc_role("domain", d, dctx) != "remote" else "")
            lines.append(f"- `{d}`{tag}")
        lines.append("")
        hist = _tld_histogram(domains)
        lines.append("**TLD distribution:**\n")
        lines.append("| TLD | Count |")
        lines.append("|-----|-------|")
        for tld, n in hist:
            label = tld if tld == "(none)" else f".{tld}"
            lines.append(f"| {label} | {n} |")
        lines.append("")

    # C3: aggregated recovered credentials across findings (allowlisted only).
    cred_rows: list[tuple[str, str]] = []
    cred_seen: set[str] = set()
    for f in findings:
        for v in _recovered_credential_values(f):
            if v not in cred_seen:
                cred_seen.add(v)
                cred_rows.append((v, f.get("finding_id", "?")))
    if cred_rows:
        lines.append("### Recovered Credentials & Archive Passwords\n")
        lines.append("| Value | Source Finding |")
        lines.append("|-------|----------------|")
        for value, fid in cred_rows:
            lines.append(f"| `{value}` | {fid} |")
        lines.append("")

    # Host-Based IOCs + Campaign Tags (Track H) — deterministic aggregation
    # over corroboration.artifacts text; omitted entirely when empty, never
    # rendered with a placeholder row.
    host_ioc_rows = _build_host_iocs_table(findings)
    if host_ioc_rows:
        lines.append("### Host-Based IOCs (Inferred from Network Traffic)\n")
        lines.append("| Type | Value | Notes |")
        lines.append("|------|-------|-------|")
        for fact_type, value, note in host_ioc_rows:
            lines.append(f"| {fact_type} | {value} | {note} |")
        lines.append("")

    campaign_tag_rows = _build_campaign_tags_table(findings)
    if campaign_tag_rows:
        lines.append("### Campaign Tags (from C2 Parameters)\n")
        lines.append("| Tag | Value | Interpretation |")
        lines.append("|-----|-------|----------------|")
        for tag, value, interpretation in campaign_tag_rows:
            lines.append(f"| {tag} | {value} | {interpretation} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    return lines


# ── IOC CSV generator ─────────────────────────────────────────────────
def _generate_iocs_csv(findings: list[dict], iocs_path: str) -> None:
    """Generate iocs.csv from findings.

    Adds a deterministic ``role`` column (W4-4 / R1-F7): "victim" for the
    monitored IP and identities bound to it; "internal" for RFC1918 /
    loopback / link-local IPs, bystander identities, the AD realm(s), WPAD
    and local-only names; "remote" otherwise. See _ioc_role — equality and
    fixed address/suffix tests only, no inference.
    """
    ctx = _victim_context(findings)
    with open(iocs_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["finding_id", "ioc_type", "value", "confidence", "role"])
        for finding in findings:
            fid = finding.get("finding_id", "?")
            confidence = finding.get("confidence", 0.0)
            host_ip = finding.get("host_ip", "")
            iocs = finding.get("iocs", {})
            for ioc_type, values in iocs.items():
                if isinstance(values, list):
                    for v in values:
                        safe_v = v.replace("|", "\\|")
                        role = ("victim" if (ioc_type == "ip" and host_ip and v == host_ip)
                                else _ioc_role(ioc_type, v, ctx))
                        writer.writerow([fid, ioc_type, safe_v, f"{confidence:.2f}", role])
                elif values:
                    safe_v = str(values).replace("|", "\\|")
                    role = ("victim" if (ioc_type == "ip" and host_ip and values == host_ip)
                            else _ioc_role(ioc_type, str(values), ctx))
                    writer.writerow([fid, ioc_type, safe_v, f"{confidence:.2f}", role])
