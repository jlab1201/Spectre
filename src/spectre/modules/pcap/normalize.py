"""pcap/normalize.py — parse tcpdump output into typed NormEvents.

Multi-pass aware: normalizes connections, DNS, HTTP payload, and per-IP timing.
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from spectre.core.base import NormEvent

# ────────────────────────────────────────────────────────────────────
# Connection summary parser (existing — unchanged)
# ────────────────────────────────────────────────────────────────────

# 2024-01-01 13:00:00.000000 IP 10.0.0.1.1234 > 10.0.0.2.80: tcp 0
_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+IP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s*(?P<rest>.*)$"
)

# Payload-host IP embedded in an injected command URL, e.g.
# "...wget http://110.39.249.68:45221/Mozi.a...". Match the IP host only.
_PAYLOAD_URL_IP = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?![.\d])")


def extract_payload_hosts(text: str) -> list[str]:
    """Return dotted-quad IP hosts of http(s):// URLs embedded in *text*,
    order-preserving and deduplicated. Domain-host URLs are ignored — these
    injections reference payloads by raw IP."""
    out: list[str] = []
    for m in _PAYLOAD_URL_IP.finditer(text or ""):
        ip = m.group(1)
        if any(int(octet) > 255 for octet in ip.split(".")):
            continue
        if ip not in out:
            out.append(ip)
    return out


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


def _compute_direction(src_ip: str, dst_ip: str) -> str:
    """Heuristic direction label for a connection.

    *internal*  – both sides are private
    *outbound*  – private src → public dst (internal host reaching out)
    *inbound*   – public src → private dst (external host reaching in)
    *unknown*   – both sides are public
    """
    src_priv = _is_private(src_ip)
    dst_priv = _is_private(dst_ip)
    if src_priv and dst_priv:
        return "internal"
    if src_priv and not dst_priv:
        return "outbound"
    if not src_priv and dst_priv:
        return "inbound"
    return "unknown"


def normalize_text(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Parse tcpdump brief connection summaries into ``pcap_conn`` NormEvents.

    When *monitored_ip* is set, direction is derived by comparing src/dst
    against it; otherwise the private-IP heuristic is used.
    """
    events: list[NormEvent] = []
    for i, line in enumerate(text.splitlines()):
        m = _LINE.match(line.strip())
        if not m:
            continue
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        proto = (m.group("rest").split() or ["ip"])[0].lower()
        if monitored_ip:
            if src_ip == monitored_ip:
                direction = "outbound"
            elif dst_ip == monitored_ip:
                direction = "inbound"
            else:
                direction = "unknown"
        else:
            direction = _compute_direction(src_ip, dst_ip)
        events.append(NormEvent(
            artifact_type="pcap_conn",
            timestamp=m.group("ts"),
            source_file=source_file,
            record_id=str(i),
            host=monitored_ip,
            data={
                "src_ip": src_ip,
                "src_port": m.group("sport"),
                "dst_ip": dst_ip,
                "dst_port": m.group("dport"),
                "proto": proto,
                "direction": direction,
                "raw": line.strip(),
            },
        ))
    return events


# ────────────────────────────────────────────────────────────────────
# Flow aggregation (connections pass) — per-remote-endpoint byte
# volumes, oriented against monitored_ip.
#
# extract.py's connections pass runs `tcpdump -nn -tttt -q -r <pcap>`
# (note -q). In that mode tcpdump prints the byte count differently per
# protocol and NEVER emits the verbose "length N" field:
#   TCP: "... 10.0.0.5.49723 > 108.181.20.35.443: tcp 1448"
#   UDP: "... 10.0.0.5.53 > 1.2.3.4.9999: UDP, length 100"
# The verbose (non -q) "length N" form is kept as a fallback for any
# caller that feeds verbose tcpdump output through this parser.
# ────────────────────────────────────────────────────────────────────

_LENGTH_TCP_RE = re.compile(r"\btcp\s+(\d+)\b")
_LENGTH_UDP_RE = re.compile(r"\bUDP,\s+length\s+(\d+)\b")
_LENGTH_VERBOSE_RE = re.compile(r"\blength\s+(\d+)\b")


def _parse_byte_length(rest: str) -> int:
    """Extract the packet byte count from the tail of a tcpdump line,
    trying the `-q` TCP form, then the `-q` UDP form, then the verbose
    `length N` form. Returns 0 if none match (e.g. a bare TCP control
    packet like ``tcp 0``, or an unparseable line)."""
    m = _LENGTH_TCP_RE.search(rest)
    if m:
        return int(m.group(1))
    m = _LENGTH_UDP_RE.search(rest)
    if m:
        return int(m.group(1))
    m = _LENGTH_VERBOSE_RE.search(rest)
    if m:
        return int(m.group(1))
    return 0


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


def normalize_flows(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Aggregate connections-pass packets into per-remote-endpoint
    ``pcap_flow`` NormEvents, reading the byte count from whichever form
    tcpdump emitted (see :func:`_parse_byte_length`).

    Orientation (bytes_in vs bytes_out) requires *monitored_ip* to know
    which side of each packet is the monitored host — with no
    monitored_ip this returns NO flow events rather than guess a side.
    Lines with no parseable byte-count token still count toward
    ``packets`` but contribute 0 bytes.
    """
    if not monitored_ip:
        return []

    flows: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        src_port = m.group("sport")
        dst_port = m.group("dport")
        ts = m.group("ts")

        if src_ip == monitored_ip:
            remote_ip, remote_port, is_outbound = dst_ip, dst_port, True
        elif dst_ip == monitored_ip:
            remote_ip, remote_port, is_outbound = src_ip, src_port, False
        else:
            continue  # neither side is the monitored host

        key = (remote_ip, remote_port)
        length = _parse_byte_length(m.group("rest"))

        if key not in flows:
            flows[key] = {
                "remote_ip": remote_ip, "remote_port": remote_port,
                "bytes_in": 0, "bytes_out": 0, "packets": 0,
                "first_ts": ts, "last_ts": ts,
            }
            order.append(key)
        f = flows[key]
        f["packets"] += 1
        if is_outbound:
            f["bytes_out"] += length
        else:
            f["bytes_in"] += length
        if ts < f["first_ts"]:
            f["first_ts"] = ts
        if ts > f["last_ts"]:
            f["last_ts"] = ts

    events: list[NormEvent] = []
    for i, key in enumerate(order):
        f = flows[key]
        first_dt = _parse_ts(f["first_ts"])
        last_dt = _parse_ts(f["last_ts"])
        duration_s = (last_dt - first_dt).total_seconds() if first_dt and last_dt else 0.0
        direction_ratio = f["bytes_in"] / max(f["bytes_out"], 1)
        events.append(NormEvent(
            artifact_type="pcap_flow",
            timestamp=f["first_ts"],
            source_file=source_file,
            record_id=str(i),
            host=monitored_ip,
            data={
                "remote_ip": f["remote_ip"],
                "remote_port": f["remote_port"],
                "bytes_in": f["bytes_in"],
                "bytes_out": f["bytes_out"],
                "packets": f["packets"],
                "first_ts": f["first_ts"],
                "last_ts": f["last_ts"],
                "duration_s": duration_s,
                "direction_ratio": direction_ratio,
            },
        ))
    return events


# ────────────────────────────────────────────────────────────────────
# DNS normalizer (tcpdump -v port 53 output)
# ────────────────────────────────────────────────────────────────────

# 2024-01-01 13:00:00.000000 IP 10.0.0.1.1234 > 8.8.8.8.53: 12345+ A? example.com. (28)
_DNS_QUERY = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+IP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+"
    r"(?P<id>\d+)\+?\s+A\?\s+(?P<domain>[^\s.]+(?:\.[^\s.]+)+)",
)

# 2024-01-01 13:00:00.050000 IP 8.8.8.8.53 > 10.0.0.1.1234: 12345 1/0/0 A 93.184.216.34 (46)
# ancount/nscount/arcount may be followed by one or more "A <ip>" answers.
_DNS_RESPONSE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+IP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+"
    r"(?P<id>\d+)\s+\d+/\d+/\d+\s+(?P<answers>.*)$",
)
_ANSWER_IP = re.compile(r"\bA\s+(\d{1,3}(?:\.\d{1,3}){3})\b")


def normalize_dns(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Parse tcpdump verbose DNS output into ``pcap_dns`` NormEvents.

    Direction parity with the other pcap normalizers: when *monitored_ip*
    is set, direction is derived by comparing src/dst against it.

    Response lines (``id ancount/nscount/arcount A <ip> [A <ip> ...]``)
    are id-matched against a query seen earlier in the same text so the
    response event carries both ``dns_query`` (the resolved name) and
    ``data["answers"]`` (the list of resolved IPs).
    """
    def _direction(src_ip: str, dst_ip: str) -> str:
        if monitored_ip:
            if src_ip == monitored_ip:
                return "outbound"
            elif dst_ip == monitored_ip:
                return "inbound"
            return "unknown"
        return _compute_direction(src_ip, dst_ip)

    events: list[NormEvent] = []
    query_domains: dict[str, str] = {}
    for i, line in enumerate(text.splitlines()):
        stripped = line.strip()

        m = _DNS_QUERY.match(stripped)
        if m:
            domain = m.group("domain")
            query_domains[m.group("id")] = domain
            src_ip = m.group("src")
            dst_ip = m.group("dst")
            events.append(NormEvent(
                artifact_type="pcap_dns",
                timestamp=m.group("ts"),
                source_file=source_file,
                record_id=str(i),
                host=monitored_ip,
                data={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dns_query": domain,
                    "proto": "dns",
                    "direction": _direction(src_ip, dst_ip),
                    "raw": stripped,
                },
            ))
            continue

        m = _DNS_RESPONSE.match(stripped)
        if m:
            answers = _ANSWER_IP.findall(m.group("answers"))
            if not answers:
                continue
            src_ip = m.group("src")
            dst_ip = m.group("dst")
            domain = query_domains.get(m.group("id"), "")
            events.append(NormEvent(
                artifact_type="pcap_dns",
                timestamp=m.group("ts"),
                source_file=source_file,
                record_id=str(i),
                host=monitored_ip,
                data={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dns_query": domain,
                    "answers": answers,
                    "proto": "dns",
                    "direction": _direction(src_ip, dst_ip),
                    "raw": stripped,
                },
            ))
    return events


# ────────────────────────────────────────────────────────────────────
# HTTP payload normalizer (tcpdump -A output)
# ────────────────────────────────────────────────────────────────────

# Require a genuine HTTP request-line shape: METHOD, then exactly ONE
# whitespace-delimited path token, then " HTTP/1.x" immediately after —
# not a bare "METHOD SP token" anywhere in the text. Deliberately NOT
# anchored to the start of a line: tcpdump -A dumps a packet's raw header
# bytes and its payload on the same wrapped text, so a request line's
# METHOD routinely lands mid-line, right after a run of binary-garbage
# characters (e.g. "..X-..U.....eW..k%.P...;...POST http://host/path
# HTTP/1.1") — anchoring to line-start silently stopped matching every
# real request line. The old, looser pattern (no trailing " HTTP/1.x"
# requirement) matched the literal substring "options [" that tcpdump
# prints inside EVERY TCP SYN/ACK's option list ("options [mss
# 1460,nop,wscale 8,sackOK,...]"), mistaking a TCP option dump for the
# HTTP OPTIONS verb and fabricating a pcap_http event out of a bare TCP
# handshake with no HTTP anywhere in it (gold-002). Requiring METHOD to be
# followed by exactly one token and then a real "HTTP/1.x" suffix rules
# that out: a TCP option list has many space-separated tokens between
# "options" and anything resembling "HTTP/1.x" (if it appears at all).
_HTTP_REQUEST = re.compile(
    r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]\b',
    re.IGNORECASE,
)
_HTTP_HOST = re.compile(r'Host:\s*(\S+)', re.IGNORECASE)
_HTTP_UA = re.compile(r'User-Agent:\s*(.+)', re.IGNORECASE)
_HTTP_SERVER = re.compile(r'Server:\s*(.+)', re.IGNORECASE)

# Each HTTP connection starts with a line like:
#  2024-01-01 13:00:00.000000 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], ...
_CONN_START = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+IP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+Flags\s+"
)


def normalize_http(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Parse tcpdump ASCII HTTP output into ``pcap_http`` NormEvents.

    Groups lines by connection (srcIP.sport > dstIP.dport) and extracts one
    NormEvent per HTTP request found in each connection block.
    """
    events: list[NormEvent] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Look for a new connection header
        m = _CONN_START.match(line)
        if not m:
            i += 1
            continue

        conn_ts = m.group("ts")
        conn_src = m.group("src")
        conn_sport = m.group("sport")
        conn_dst = m.group("dst")
        conn_dport = m.group("dport")
        conn_key = f"{conn_src}.{conn_sport}>{conn_dst}.{conn_dport}"

        # Compute direction using monitored_ip (same logic as normalize_text)
        if monitored_ip:
            if conn_src == monitored_ip:
                direction = "outbound"
            elif conn_dst == monitored_ip:
                direction = "inbound"
            else:
                direction = "unknown"
        else:
            direction = _compute_direction(conn_src, conn_dst)

        # Gather all lines for this connection (keep raw for payload detection)
        block_lines: list[str] = [line]
        i += 1
        while i < len(lines):
            next_raw = lines[i]
            next_stripped = next_raw.strip()
            # A new connection header ends the block
            if _CONN_START.match(next_stripped):
                break
            block_lines.append(next_raw)
            i += 1

        # Concatenate ASCII payload lines — tcpdump -A indents payload with
        # a leading tab or ≥4 spaces.  Check the RAW line before stripping.
        payload_lines = [
            ln for ln in block_lines
            if ln.startswith("\t") or ln.startswith("    ")
        ]
        ascii_payload = "\n".join(ln.strip() for ln in payload_lines)

        # Also check the raw block for HTTP headers mixed in
        raw_block = "\n".join(block_lines)

        # ponytail: one event per HTTP request (keep-alive connections)
        host_match = _HTTP_HOST.search(raw_block)
        http_host = host_match.group(1) if host_match else ""
        ua_match = _HTTP_UA.search(raw_block)
        http_user_agent = ua_match.group(1).strip() if ua_match else ""
        svr_match = _HTTP_SERVER.search(raw_block)
        http_server = svr_match.group(1).strip() if svr_match else ""

        for http_match in _HTTP_REQUEST.finditer(raw_block):
            http_method = http_match.group(1)
            http_request_path = http_match.group(2)
            events.append(NormEvent(
                artifact_type="pcap_http",
                timestamp=conn_ts,
                source_file=source_file,
                record_id=conn_key,
                host=monitored_ip,
                data={
                    "src_ip": conn_src,
                    "src_port": conn_sport,
                    "dst_ip": conn_dst,
                    "dst_port": conn_dport,
                    "proto": "tcp",
                    "direction": direction,
                    "http_method": http_method,
                    "http_request_path": http_request_path,
                    "http_host": http_host,
                    "http_user_agent": http_user_agent,
                    "http_server": http_server,
                    "ascii_payload": ascii_payload,
                    "raw": raw_block,
                },
            ))

    return events


# ────────────────────────────────────────────────────────────────────
# Beacon timing normalizer (src.port,dst.port,timestamp triples)
# ────────────────────────────────────────────────────────────────────

# ponytail (gold-003): mirrors rules.py's _EPHEMERAL_MIN — a source port
# below this is a well-known/service port (the host answering as a
# server, e.g. replying to a scan from whatever port it was probed on),
# not an OS-assigned ephemeral client port (the host initiating as a
# client). See beacon()'s monitored_is_client guard in rules.py.
_EPHEMERAL_MIN = 49152


def _split_host_port(token: str) -> tuple[str, str]:
    """Split a tcpdump ``ip.port`` token into ``(ip, port)``.

    tcpdump appends ".port" to IPv4 endpoints that have one (TCP/UDP); ICMP
    endpoints have no port at all. Only strip a trailing component when it
    is genuinely a 5th, all-digit segment — a bare 4-octet IPv4 address
    (no port) is returned unchanged. This also fixes a latent bug in the
    old blind ``\\.[0-9]*$`` port-strip, which corrupted bare IPs (ICMP
    lines) by chopping off their last octet.
    """
    parts = token.split(".")
    if len(parts) == 5 and parts[4].isdigit():
        return ".".join(parts[:4]), parts[4]
    return token, ""


def normalize_beacon_timing(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Parse per-connection ``src.port,dst.port,timestamp`` triples into
    ``pcap_timing`` NormEvents, one per remote IP with enough samples for
    beacon detection (≥10 timestamps).

    Only samples where the MONITORED HOST is the packet's source ("outbound"
    toward the remote IP) accumulate into a beacon's interval series — a
    remote IP that only ever appears as source (inbound scanning/probing
    us) contributes no samples here.

    An inbound scanner probing many ports still gets a reply from the
    monitored host's TCP/IP stack for EVERY probe, which produces the same
    regular per-IP timing signature as genuine beaconing — an "outbound
    sample count" alone can't distinguish the monitored host genuinely
    INITIATING a connection (a real beacon) from it mechanically REPLYING
    to an inbound probe. We thread the monitored host's own source port on
    each outbound sample through as beacon_data["monitored_is_client"]:
    True when a majority of those ports are OS-assigned ephemeral ports
    (>= _EPHEMERAL_MIN, consistent with the host acting as a CLIENT), False
    when a majority are well-known/non-ephemeral (consistent with the host
    acting as a SERVER replying from whatever port it was probed on), and
    None when the signal is unavailable (see below). See rules.py:beacon()
    for the consuming guard.

    *monitored_ip*, when set, is stamped onto NormEvent.host and
    data["monitored_host"] — the machine under analysis, not the
    beaconing remote IP. When unset, the historical (direction-blind)
    behavior is preserved: the destination column is used verbatim as the
    group key and monitored_is_client is left unknown (None), since there
    is no way to tell which side is "us" without it.
    """
    ip_timestamps: dict[str, list[str]] = defaultdict(list)
    ip_ports: dict[str, list[str]] = defaultdict(list)

    for line in text.splitlines():
        parts = line.strip().split(",", 2)
        if len(parts) < 3:
            continue
        src_token, dst_token, ts = parts
        src_ip, src_port = _split_host_port(src_token.strip())
        dst_ip, dst_port = _split_host_port(dst_token.strip())
        ts = ts.strip()
        if not ts:
            continue

        if monitored_ip:
            if src_ip == monitored_ip:
                remote_ip, my_port = dst_ip, src_port
            elif dst_ip == monitored_ip:
                # Remote-initiated (inbound) sample — not "us reaching
                # out"; excluded from the beacon interval series.
                continue
            else:
                continue  # neither side is the monitored host
        else:
            remote_ip, my_port = dst_ip, ""

        if not remote_ip:
            continue
        ip_timestamps[remote_ip].append(ts)
        if my_port:
            ip_ports[remote_ip].append(my_port)

    events: list[NormEvent] = []
    for ip, timestamps in ip_timestamps.items():
        if len(timestamps) < 10:
            continue  # Need enough samples for reliable beacon detection

        # Parse timestamps to datetime objects, sorted chronologically —
        # input order is no longer guaranteed pre-sorted (see extract.py).
        dts: list[datetime] = []
        for ts in timestamps:
            try:
                dts.append(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f"))
            except ValueError:
                continue

        if len(dts) < 10:
            continue
        dts.sort()

        # Compute inter-arrival intervals in seconds
        intervals: list[float] = []
        for j in range(1, len(dts)):
            intervals.append((dts[j] - dts[j - 1]).total_seconds())

        if not intervals:
            continue

        mean_interval = statistics.mean(intervals)

        ports = ip_ports.get(ip, [])
        if ports:
            ephemeral = sum(
                1 for p in ports if p.isdigit() and int(p) >= _EPHEMERAL_MIN
            )
            monitored_is_client = (ephemeral / len(ports)) > 0.5
        else:
            monitored_is_client = None

        events.append(NormEvent(
            artifact_type="pcap_timing",
            timestamp=dts[0].strftime("%Y-%m-%d %H:%M:%S.%f") if dts else "",
            source_file=source_file,
            record_id=ip,
            host=monitored_ip,
            data={
                "beacon_data": {
                    "ip": ip,
                    "intervals": intervals,
                    "sample_count": len(timestamps),
                    "mean_interval": mean_interval,
                    "monitored_is_client": monitored_is_client,
                },
                "monitored_host": monitored_ip,
                "raw": "",
            },
        ))

    return events


# ────────────────────────────────────────────────────────────────────
# Main normalize entry-point — routes by extract_pass
# ────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────
# SMB2 named pipe normalizer (tshark -T fields output)
# ────────────────────────────────────────────────────────────────────

# tshark -T fields: frame.time\tip.src\tip.dst\tsmb2.filename
_SMB_LINE = re.compile(
    r"^(?P<ts>.+?)\t(?P<src>[^\t]+)\t(?P<dst>[^\t]+)\t(?P<pipe>[^\t]*)$"
)


def normalize_smb_pipes(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Parse tshark SMB2 named-pipe fields into smb_pipe NormEvents.

    Host/direction parity with the other pcap normalizers: NormEvent.host
    is stamped with *monitored_ip* (the machine under analysis), not the
    packet's src_ip — the monitored host must never masquerade as the
    "host" for one side of the conversation only by accident of which
    address happened to be the SMB client. When *monitored_ip* is unset,
    host stays "" (unknown), same as normalize_text/normalize_dns/etc.
    """
    events: list[NormEvent] = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        m = _SMB_LINE.match(line)
        if not m:
            continue
        pipe = m.group("pipe").strip()
        if not pipe:
            continue
        pipe_lower = pipe.lower().replace("\\", "/")
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        if monitored_ip:
            if src_ip == monitored_ip:
                direction = "outbound"
            elif dst_ip == monitored_ip:
                direction = "inbound"
            else:
                direction = "unknown"
        else:
            direction = _compute_direction(src_ip, dst_ip)
        events.append(NormEvent(
            artifact_type="smb_pipe",
            timestamp=m.group("ts"),
            source_file=source_file,
            record_id=str(i),
            host=monitored_ip,
            data={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "named_pipe": pipe,
                "pipe_normalized": pipe_lower,
                "direction": direction,
                "raw": line.strip(),
            },
        ))
    return events

# ────────────────────────────────────────────────────────────────────
# DRSUAPI opnum normalizer (tshark -T fields output, "drsuapi" filter)
# ────────────────────────────────────────────────────────────────────

# tshark -T fields: frame.time\tip.src\tip.dst\tdrsuapi.opnum
_DRSUAPI_LINE = re.compile(
    r"^(?P<ts>.+?)\t(?P<src>[^\t]+)\t(?P<dst>[^\t]+)\t(?P<opnum>[^\t]*)$"
)


def normalize_drsuapi_calls(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Parse tshark DRSUAPI opnum fields into drsuapi_call NormEvents.

    Distinct from smb_pipe/normalize_smb_pipes: a drsuapi RPC call is not
    guaranteed to appear as a named-pipe OPEN (ncacn_np) — it may run over a
    dynamic ncacn_ip_tcp port reached via an EPM lookup, in which case the
    named-pipe rule never sees it. This normalizer reads the opnum directly
    off the DRSUAPI payload (via tshark's drsuapi dissector), which is
    present regardless of transport, so the granularity between DsGetNCChanges
    (opnum 3 — DCSync) and DsCrackNames (opnum 12 — name resolution) survives
    even when there is no corresponding smb_pipe event.

    Host/direction parity with the other pcap normalizers — see
    normalize_smb_pipes for the rationale.
    """
    events: list[NormEvent] = []
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        m = _DRSUAPI_LINE.match(line)
        if not m:
            continue
        opnum_str = m.group("opnum").strip()
        if not opnum_str:
            continue
        try:
            opnum = int(opnum_str)
        except ValueError:
            continue
        src_ip = m.group("src")
        dst_ip = m.group("dst")
        if monitored_ip:
            if src_ip == monitored_ip:
                direction = "outbound"
            elif dst_ip == monitored_ip:
                direction = "inbound"
            else:
                direction = "unknown"
        else:
            direction = _compute_direction(src_ip, dst_ip)
        events.append(NormEvent(
            artifact_type="drsuapi_call",
            timestamp=m.group("ts"),
            source_file=source_file,
            record_id=str(i),
            host=monitored_ip,
            data={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "opnum": opnum,
                "direction": direction,
                "raw": line.strip(),
            },
        ))
    return events


# ────────────────────────────────────────────────────────────────────
# Host/account identity normalizers (tshark -T fields output)
# ────────────────────────────────────────────────────────────────────

def _first_field(value: str) -> str:
    """tshark repeats a field per matching layer, comma-joined
    (e.g. a MAC seen in both a request and its echo). Take the first."""
    return value.split(",")[0].strip()


def _identity_attribution(ip: str, mac: str, monitored_ip: str,
                          monitored_macs: set[str]) -> tuple[str, bool | None]:
    """W4-4 / R1-F7: (host, bound_to_monitored) for a host_identity event.

    An identity is attributed to the monitored host ONLY when its own IP, or
    a MAC already bound to the monitored IP in the same log, matches. Anything
    else (a foreign-MAC DHCP DISCOVER, another workstation's Kerberos AS-REQ)
    gets host="" — it is a bystander, never the victim. bound_to_monitored is
    None (unattributed) when there is nothing to compare against: no
    monitored IP, or no IP on the event and no MAC known for the monitored host.
    """
    if not monitored_ip:
        return "", None
    if (ip and ip == monitored_ip) or (mac and mac.lower() in monitored_macs):
        return monitored_ip, True
    if ip or (mac and monitored_macs):
        # A different IP, or a MAC other than the monitored host's known MAC.
        return "", False
    # No IP and no known monitored MAC to compare with: unattributed, NOT a
    # bystander (W4 review LOW — it may well be the victim's own DISCOVER).
    return "", None


def normalize_kerberos_identity(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Bind a Kerberos principal to the workstation IP that authenticated it.

    A row whose destination port is 88 is a client->KDC request, so its
    ip.src is the authenticating workstation. The FQDN realm (EASYAS123.TECH)
    appears on the KDC response side; the request side often carries only the
    short realm (EASYAS123), so realm is taken as the longest observed for the
    account across all rows.
    """
    bindings: dict[tuple, str] = {}   # (account, client_ip) -> first timestamp
    realms: dict[str, str] = {}       # account -> longest realm string
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        ts, src, dst, udport, tcport, cname, realm = (p.strip() for p in parts[:7])
        account = _first_field(cname)
        if not account:
            continue
        realm = _first_field(realm)
        if realm and len(realm) > len(realms.get(account, "")):
            realms[account] = realm
        dstport = _first_field(udport) or _first_field(tcport)
        if dstport == "88" and src:
            bindings.setdefault((account, src), ts)

    events: list[NormEvent] = []
    for i, ((account, ip), ts) in enumerate(bindings.items()):
        realm = realms.get(account, "")
        principal = f"{account}@{realm}" if realm else account
        host, bound = _identity_attribution(ip, "", monitored_ip, set())
        events.append(NormEvent(
            artifact_type="host_identity",
            timestamp=ts,
            source_file=source_file,
            record_id=f"krb-{i}",
            host=host,
            data={"hostname": "", "account": principal, "realm": realm,
                  "ip": ip, "mac": "", "source": "kerberos",
                  "bound_to_monitored": bound},
        ))
    return events


def normalize_dhcp_identity(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Bind a DHCP hostname to its assigned IP.

    A DHCP REQUEST (option 53 == 3) carries hostname + requested-IP + MAC;
    the ACK (== 5) confirms the assigned yiaddr for that MAC. Prefer the
    requested-IP on the hostname-bearing row; fall back to the ACK's yiaddr
    correlated by MAC.
    """
    mac_to_yiaddr: dict[str, str] = {}
    host_rows: list[tuple] = []       # (ts, hostname, requested_ip, mac)
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        ts, hostname, req_ip, yiaddr, mac, dtype = (p.strip() for p in parts[:6])
        mac = _first_field(mac)
        yiaddr = _first_field(yiaddr)
        dtype = _first_field(dtype)
        if dtype == "5" and mac and yiaddr:
            mac_to_yiaddr[mac] = yiaddr
        hostname = _first_field(hostname)
        if hostname:
            host_rows.append((ts, hostname, _first_field(req_ip), mac))

    resolved = [(ts, hostname, req_ip or mac_to_yiaddr.get(mac, ""), mac)
                for ts, hostname, req_ip, mac in host_rows]
    monitored_macs = {mac.lower() for _, _, ip, mac in resolved
                      if mac and monitored_ip and ip == monitored_ip}
    monitored_macs |= {m.lower() for m, y in mac_to_yiaddr.items()
                       if monitored_ip and y == monitored_ip}
    events: list[NormEvent] = []
    seen: set[tuple] = set()
    for i, (ts, hostname, ip, mac) in enumerate(resolved):
        key = (hostname, ip)
        if key in seen:
            continue
        seen.add(key)
        host, bound = _identity_attribution(ip, mac, monitored_ip, monitored_macs)
        events.append(NormEvent(
            artifact_type="host_identity",
            timestamp=ts,
            source_file=source_file,
            record_id=f"dhcp-{i}",
            host=host,
            data={"hostname": hostname, "account": "", "realm": "",
                  "ip": ip, "mac": mac, "source": "dhcp",
                  "bound_to_monitored": bound},
        ))
    return events


# ────────────────────────────────────────────────────────────────────
# Checksum integrity (evidence-tampering check)
#
# tcpdump -v validates the IP and TCP checksums itself and annotates any
# mismatch inline: a bad IP-header checksum shows as "bad cksum XXXX
# (->YYYY)!" inside the IP-header line's parenthetical; a bad TCP
# checksum shows as "cksum 0xXXXX (incorrect -> 0xYYYY)" on the
# following indented protocol-detail line (vs. "cksum 0xXXXX (correct)"
# when it's fine). Each TCP packet in -v output is exactly these two
# physical lines.
#
# NIC TX-checksum-offload means OUTBOUND (locally-generated) packets
# routinely show bad checksums in a genuine, untampered capture — the
# kernel hands tcpdump the packet before the NIC computes the real
# checksum in hardware. INBOUND packets already crossed the wire with a
# checksum some other stack computed (and the link layer's own frame
# CRC would normally have dropped a corrupted frame before delivery) —
# a bad checksum there is not a capture artifact, it means the bytes
# were altered after the fact. Only inbound mismatches are counted.
# ────────────────────────────────────────────────────────────────────

_CHECKSUM_HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+IP\s+\((?P<hdr>.*)\)\s*$"
)
_CHECKSUM_DETAIL_RE = re.compile(
    r"^\s+(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s*(?P<rest>.*)$"
)
_BAD_IP_CKSUM_RE = re.compile(r"\bbad cksum\b", re.IGNORECASE)
_BAD_TCP_CKSUM_RE = re.compile(r"cksum 0x[0-9a-f]+\s*\(incorrect", re.IGNORECASE)


def normalize_checksum_integrity(
    text: str, source_file: str = "", monitored_ip: str = ""
) -> list[NormEvent]:
    """Parse verbose ``tcpdump -v`` output into a per-source-IP
    evidence-integrity aggregate. Only INBOUND checksum failures are
    counted — see module comment above for why outbound ones are routine
    NIC checksum-offload noise. IPv4 + TCP only (V1 scope)."""
    per_ip: dict[str, dict] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m_hdr = _CHECKSUM_HEADER_RE.match(lines[i])
        if not m_hdr:
            i += 1
            continue
        ts = m_hdr.group("ts")
        ip_bad = bool(_BAD_IP_CKSUM_RE.search(m_hdr.group("hdr")))
        if i + 1 >= len(lines):
            break
        m_detail = _CHECKSUM_DETAIL_RE.match(lines[i + 1])
        i += 2
        if not m_detail:
            continue
        tcp_bad = bool(_BAD_TCP_CKSUM_RE.search(m_detail.group("rest")))
        if not (ip_bad or tcp_bad):
            continue

        src_ip = m_detail.group("src")
        dst_ip = m_detail.group("dst")
        if monitored_ip:
            if src_ip == monitored_ip:
                direction = "outbound"
            elif dst_ip == monitored_ip:
                direction = "inbound"
            else:
                direction = "unknown"
        else:
            direction = _compute_direction(src_ip, dst_ip)

        if direction != "inbound":
            continue  # outbound bad checksums are TX-offload noise, not tampering

        bucket = per_ip.setdefault(src_ip, {
            "ip": src_ip, "bad_count": 0, "last_ts": ts, "samples": [],
        })
        bucket["bad_count"] += 1
        bucket["last_ts"] = ts
        if len(bucket["samples"]) < 3:
            kinds = "+".join(k for k, bad in (("IP", ip_bad), ("TCP", tcp_bad)) if bad)
            bucket["samples"].append(
                f"{ts} {src_ip}.{m_detail.group('sport')} > "
                f"{dst_ip}.{m_detail.group('dport')} bad {kinds} checksum"
            )

    events: list[NormEvent] = []
    for idx, (src_ip, data) in enumerate(sorted(per_ip.items())):
        events.append(NormEvent(
            artifact_type="pcap_checksum",
            timestamp=data["last_ts"],
            source_file=source_file,
            record_id=f"cksum-{idx}",
            host=monitored_ip,
            data={"checksum_data": data},
        ))
    return events


def normalize(handle: dict) -> list[NormEvent]:
    """Dispatch to the appropriate normalizer based on the extract_pass field."""
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []

    extract_pass = handle.get("extract_pass", "connections")
    text = Path(path).read_text(errors="replace")
    source_file = handle.get("evidence_path", path)
    monitored_ip = handle.get("monitored_ip", "")

    # ── Zeek engine passes (structured JSON logs) ──────────────────────
    # Imported lazily: zeek_normalize imports helpers from this module.
    if extract_pass.startswith("zeek_"):
        from spectre.modules.pcap import zeek_normalize as zn
        if extract_pass == "zeek_conn":
            # conn.log feeds per-conn, flow-aggregate, AND beacon-timing.
            return (zn.normalize_zeek_conn(text, source_file=source_file, monitored_ip=monitored_ip)
                    + zn.normalize_zeek_flows(text, source_file=source_file, monitored_ip=monitored_ip)
                    + zn.normalize_zeek_beacon(text, source_file=source_file, monitored_ip=monitored_ip))
        elif extract_pass == "zeek_dns":
            return zn.normalize_zeek_dns(text, source_file=source_file, monitored_ip=monitored_ip)
        elif extract_pass == "zeek_http":
            return zn.normalize_zeek_http(text, source_file=source_file, monitored_ip=monitored_ip)
        elif extract_pass == "zeek_dce_rpc":
            return zn.normalize_zeek_dce_rpc(text, source_file=source_file, monitored_ip=monitored_ip)
        elif extract_pass == "zeek_kerberos":
            return zn.normalize_zeek_kerberos(text, source_file=source_file, monitored_ip=monitored_ip)
        elif extract_pass == "zeek_dhcp":
            return zn.normalize_zeek_dhcp(text, source_file=source_file, monitored_ip=monitored_ip)
        return []

    if extract_pass == "dns":
        return normalize_dns(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "http":
        return normalize_http(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "timing":
        return normalize_beacon_timing(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "smb2_pipes":
        return normalize_smb_pipes(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "drsuapi_opnum":
        return normalize_drsuapi_calls(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "kerberos_identity":
        return normalize_kerberos_identity(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "dhcp_identity":
        return normalize_dhcp_identity(text, source_file=source_file, monitored_ip=monitored_ip)
    elif extract_pass == "checksum":
        return normalize_checksum_integrity(text, source_file=source_file, monitored_ip=monitored_ip)

    elif extract_pass == "connections":
        return normalize_text(
            text, source_file=source_file, monitored_ip=monitored_ip
        ) + normalize_flows(text, source_file=source_file, monitored_ip=monitored_ip)
    else:
        # Unknown extract_pass — fall back to connection-text parser
        return normalize_text(text, source_file=source_file, monitored_ip=monitored_ip)
