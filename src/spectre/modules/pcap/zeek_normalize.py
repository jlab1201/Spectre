"""pcap/zeek_normalize.py — parse Zeek JSON logs into the SAME typed
NormEvents the legacy tcpdump/tshark parsers (normalize.py) produce.

Zeek is the primary pcap engine; these normalizers read its structured
JSON logs (conn.log, dns.log, http.log, dce_rpc.log, kerberos.log,
dhcp.log) instead of regex-parsing CLI text. The contract is PARITY: each
event carries the identical `artifact_type` + `data` field names the rule
pack in rules.py consumes (see RuleMetadata.required_fields), so all
existing detection rules keep firing unchanged.

Field names were verified against real Zeek 8 output on the project sample
captures — notably Zeek's DRS-prefixed drsuapi operation names
(DRSGetNCChanges / DRSCrackNames), not the Ds* forms.

Timestamps: Zeek emits epoch floats; we render them to the same
"%Y-%m-%d %H:%M:%S.%f" (UTC) string the tcpdump parsers use, so downstream
sorting/parsing (normalize_flows, beacon) and the report are consistent.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone

from spectre.core.base import NormEvent
from spectre.modules.pcap.normalize import _compute_direction, _EPHEMERAL_MIN, _identity_attribution

_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _ts(epoch) -> str:
    """Render a Zeek epoch float as the tcpdump-parser timestamp string."""
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(_TS_FMT)
    except (TypeError, ValueError, OSError):
        return ""


def _direction(src_ip: str, dst_ip: str, monitored_ip: str) -> str:
    if monitored_ip:
        if src_ip == monitored_ip:
            return "outbound"
        if dst_ip == monitored_ip:
            return "inbound"
        return "unknown"
    return _compute_direction(src_ip, dst_ip)


def _rows(text: str):
    """Yield parsed JSON objects, one per non-blank line; skip junk."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ── conn.log → pcap_conn ──────────────────────────────────────────────
def normalize_zeek_conn(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """One pcap_conn per conn.log row (per connection, not per packet)."""
    events: list[NormEvent] = []
    for i, d in enumerate(_rows(text)):
        src_ip = d.get("id.orig_h", "")
        dst_ip = d.get("id.resp_h", "")
        if not src_ip or not dst_ip:
            continue
        events.append(NormEvent(
            artifact_type="pcap_conn",
            timestamp=_ts(d.get("ts")),
            source_file=source_file,
            record_id=d.get("uid", str(i)),
            host=monitored_ip,
            data={
                "src_ip": src_ip,
                "src_port": str(d.get("id.orig_p", "")),
                "dst_ip": dst_ip,
                "dst_port": str(d.get("id.resp_p", "")),
                "proto": str(d.get("proto", "ip")).lower(),
                "direction": _direction(src_ip, dst_ip, monitored_ip),
                "raw": json.dumps(d),
            },
        ))
    return events


# ── conn.log → pcap_flow (per remote endpoint, oriented by monitored_ip) ─
def normalize_zeek_flows(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Aggregate conn.log rows into per-(remote_ip, remote_port) pcap_flow
    events. Orientation needs monitored_ip (which side is 'us'); without it
    we return no flows rather than guess — parity with normalize_flows."""
    if not monitored_ip:
        return []

    flows: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for d in _rows(text):
        orig_h = d.get("id.orig_h", "")
        resp_h = d.get("id.resp_h", "")
        orig_b = int(d.get("orig_bytes") or 0)
        resp_b = int(d.get("resp_bytes") or 0)
        ts = _ts(d.get("ts"))
        if orig_h == monitored_ip:
            remote_ip, remote_port = resp_h, str(d.get("id.resp_p", ""))
            bytes_out, bytes_in = orig_b, resp_b
        elif resp_h == monitored_ip:
            remote_ip, remote_port = orig_h, str(d.get("id.orig_p", ""))
            bytes_out, bytes_in = resp_b, orig_b
        else:
            continue
        if not remote_ip:
            continue
        key = (remote_ip, remote_port)
        if key not in flows:
            flows[key] = {"remote_ip": remote_ip, "remote_port": remote_port,
                          "bytes_in": 0, "bytes_out": 0, "packets": 0,
                          "first_ts": ts, "last_ts": ts}
            order.append(key)
        f = flows[key]
        f["bytes_in"] += bytes_in
        f["bytes_out"] += bytes_out
        f["packets"] += int(d.get("orig_pkts") or 0) + int(d.get("resp_pkts") or 0)
        if ts and (not f["first_ts"] or ts < f["first_ts"]):
            f["first_ts"] = ts
        if ts and ts > f["last_ts"]:
            f["last_ts"] = ts

    events: list[NormEvent] = []
    for i, key in enumerate(order):
        f = flows[key]
        first_dt = _parse_ts(f["first_ts"])
        last_dt = _parse_ts(f["last_ts"])
        duration_s = (last_dt - first_dt).total_seconds() if first_dt and last_dt else 0.0
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
                "direction_ratio": f["bytes_in"] / max(f["bytes_out"], 1),
            },
        ))
    return events


def _parse_ts(ts: str):
    try:
        return datetime.strptime(ts, _TS_FMT)
    except (TypeError, ValueError):
        return None


# ── conn.log → pcap_timing (beacon) ───────────────────────────────────
def normalize_zeek_beacon(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Per-remote beacon timing from conn.log start-times. Each check-in is
    its own connection, so conn.log start-times ARE the beacon series —
    cleaner than the legacy per-packet awk timing pass. Only outbound
    (monitored host = originator) samples accumulate; see normalize.py's
    normalize_beacon_timing for the monitored_is_client rationale."""
    ip_timestamps: dict[str, list[str]] = defaultdict(list)
    ip_ports: dict[str, list[str]] = defaultdict(list)
    for d in _rows(text):
        orig_h = d.get("id.orig_h", "")
        resp_h = d.get("id.resp_h", "")
        ts = _ts(d.get("ts"))
        if not ts:
            continue
        if monitored_ip:
            if orig_h == monitored_ip:
                remote_ip, my_port = resp_h, str(d.get("id.orig_p", ""))
            elif resp_h == monitored_ip:
                continue  # inbound — not us reaching out
            else:
                continue
        else:
            remote_ip, my_port = resp_h, ""
        if not remote_ip:
            continue
        ip_timestamps[remote_ip].append(ts)
        if my_port:
            ip_ports[remote_ip].append(my_port)

    events: list[NormEvent] = []
    for ip, timestamps in ip_timestamps.items():
        if len(timestamps) < 10:
            continue
        dts = [dt for dt in (_parse_ts(t) for t in timestamps) if dt]
        if len(dts) < 10:
            continue
        dts.sort()
        intervals = [(dts[j] - dts[j - 1]).total_seconds() for j in range(1, len(dts))]
        if not intervals:
            continue
        ports = ip_ports.get(ip, [])
        if ports:
            ephemeral = sum(1 for p in ports if p.isdigit() and int(p) >= _EPHEMERAL_MIN)
            monitored_is_client = (ephemeral / len(ports)) > 0.5
        else:
            monitored_is_client = None
        events.append(NormEvent(
            artifact_type="pcap_timing",
            timestamp=dts[0].strftime(_TS_FMT),
            source_file=source_file,
            record_id=ip,
            host=monitored_ip,
            data={
                "beacon_data": {
                    "ip": ip,
                    "intervals": intervals,
                    "sample_count": len(timestamps),
                    "mean_interval": statistics.mean(intervals),
                    "monitored_is_client": monitored_is_client,
                },
                "monitored_host": monitored_ip,
                "raw": "",
            },
        ))
    return events


# ── dns.log → pcap_dns ────────────────────────────────────────────────
def normalize_zeek_dns(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    events: list[NormEvent] = []
    for i, d in enumerate(_rows(text)):
        query = d.get("query", "")
        if not query:
            continue
        src_ip = d.get("id.orig_h", "")
        dst_ip = d.get("id.resp_h", "")
        # Keep only IPv4 answers so enrich's ip->domain map is not polluted
        # by CNAME / non-address answer records (parity with _ANSWER_IP).
        answers = [a for a in (d.get("answers") or []) if isinstance(a, str) and _is_ipv4(a)]
        data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dns_query": query,
            "proto": "dns",
            "direction": _direction(src_ip, dst_ip, monitored_ip),
            "raw": json.dumps(d),
        }
        if answers:
            data["answers"] = answers
        events.append(NormEvent(
            artifact_type="pcap_dns",
            timestamp=_ts(d.get("ts")),
            source_file=source_file,
            record_id=d.get("uid", str(i)),
            host=monitored_ip,
            data=data,
        ))
    return events


# ── http.log → pcap_http ──────────────────────────────────────────────
def normalize_zeek_http(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """One pcap_http per http.log transaction. Zeek gives structured
    host/uri/user-agent/method/status — enough for the C2 UA/Host/campaign
    and exploit-probe checks. It does NOT capture request/response BODIES;
    the body-dependent C2 sub-checks (plaintext-on-443, Server header,
    CMD=POLL, injected wget/curl) run on the retained tcpdump -A pass's
    pcap_http events, which carry `ascii_payload`. Both engines dedup by
    (rule_id, dst_ip). We still emit the ascii_payload/http_server KEYS
    (empty) so RuleMetadata.required_fields coverage holds."""
    events: list[NormEvent] = []
    for i, d in enumerate(_rows(text)):
        src_ip = d.get("id.orig_h", "")
        dst_ip = d.get("id.resp_h", "")
        events.append(NormEvent(
            artifact_type="pcap_http",
            timestamp=_ts(d.get("ts")),
            source_file=source_file,
            record_id=d.get("uid", str(i)),
            host=monitored_ip,
            data={
                "src_ip": src_ip,
                "src_port": str(d.get("id.orig_p", "")),
                "dst_ip": dst_ip,
                "dst_port": str(d.get("id.resp_p", "")),
                "proto": "tcp",
                "direction": _direction(src_ip, dst_ip, monitored_ip),
                "http_method": d.get("method", ""),
                "http_request_path": d.get("uri", ""),
                "http_host": d.get("host", ""),
                "http_user_agent": d.get("user_agent", ""),
                "http_server": "",       # Zeek http.log has no Server header by default
                "ascii_payload": "",     # bodies not captured — see docstring
                "raw": json.dumps(d),
            },
        ))
    return events


# ── dce_rpc.log → smb_pipe + drsuapi_call ─────────────────────────────
# Zeek DCE-RPC operation names use the DRS* prefix (verified against real
# output); map the diagnostic ones to MS-DRSR opnums the rule consumes.
_DRS_OPNUMS = {
    "DRSBind": 0, "DRSUnbind": 1, "DRSReplicaSync": 2, "DRSGetNCChanges": 3,
    "DRSUpdateRefs": 4, "DRSReplicaAdd": 5, "DRSReplicaDel": 6,
    "DRSReplicaModify": 7, "DRSVerifyNames": 8, "DRSGetMemberships": 9,
    "DRSInterDomainMove": 10, "DRSGetNT4ChangeLog": 11, "DRSCrackNames": 12,
    "DRSWriteSPN": 13, "DRSRemoveDsServer": 14, "DRSRemoveDsDomain": 15,
    "DRSDomainControllerInfo": 16, "DRSAddEntry": 17, "DRSExecuteKCC": 18,
    "DRSGetReplInfo": 19, "DRSAddSidHistory": 20, "DRSGetMemberships2": 21,
    "DRSReplicaVerifyObjects": 22, "DRSGetObjectExistence": 23,
    "DRSQuerySitesByCost": 24,
}


def normalize_zeek_dce_rpc(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """dce_rpc.log carries the RPC endpoint (samr/lsarpc/drsuapi/…) — the
    AD-recon named-pipe signal — and the operation name. Emit an smb_pipe
    event per row (endpoint as the pipe name) and, for drsuapi rows, a
    drsuapi_call event with the operation mapped to its opnum."""
    events: list[NormEvent] = []
    for i, d in enumerate(_rows(text)):
        endpoint = (d.get("endpoint") or "").strip()
        if not endpoint:
            continue
        src_ip = d.get("id.orig_h", "")
        dst_ip = d.get("id.resp_h", "")
        direction = _direction(src_ip, dst_ip, monitored_ip)

        pipe_data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "named_pipe": endpoint,
            "pipe_normalized": endpoint.lower().replace("\\", "/"),
            "direction": direction,
            "raw": json.dumps(d),
        }

        drsuapi_opnum = None
        if endpoint.lower() == "drsuapi":
            drsuapi_opnum = _DRS_OPNUMS.get(d.get("operation", ""))
            if drsuapi_opnum is not None:
                # Carry the resolved opnum onto the smb_pipe event too, so
                # rules.ad_recon_pipe() can see that THIS SAME row also
                # produces a drsuapi_call event below (and, when the opnum
                # is diagnostic, a more specific smb-drsuapi-opnum finding)
                # and decline to emit a second, generic finding for it.
                pipe_data["drsuapi_opnum"] = drsuapi_opnum

        events.append(NormEvent(
            artifact_type="smb_pipe",
            timestamp=_ts(d.get("ts")),
            source_file=source_file,
            record_id=str(i),
            host=monitored_ip,
            data=pipe_data,
        ))

        if drsuapi_opnum is not None:
            events.append(NormEvent(
                artifact_type="drsuapi_call",
                timestamp=_ts(d.get("ts")),
                source_file=source_file,
                record_id=f"drs-{i}",
                host=monitored_ip,
                data={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "opnum": drsuapi_opnum,
                    "direction": direction,
                    "raw": json.dumps(d),
                },
            ))
    return events


# ── kerberos.log → host_identity ──────────────────────────────────────
def normalize_zeek_kerberos(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Bind a Kerberos principal to the workstation IP that authenticated
    it. A row to KDC port 88 has ip.orig_h = the client workstation; Zeek's
    `client` field is 'account/REALM'."""
    bindings: dict[tuple, tuple] = {}  # (account, ip) -> (ts, realm)
    for d in _rows(text):
        if str(d.get("id.resp_p", "")) != "88":
            continue
        client = (d.get("client") or "").strip()
        src = d.get("id.orig_h", "")
        if not client or not src:
            continue
        account, _, realm = client.partition("/")
        account = account.strip()
        realm = realm.strip()
        if not account:
            continue
        prev = bindings.get((account, src))
        if prev is None:
            bindings[(account, src)] = (_ts(d.get("ts")), realm)
        elif len(realm) > len(prev[1]):
            # Keep the first timestamp but the longest (FQDN) realm — parity
            # with the tshark path; exposes the AD DNS domain (W4-4 wpad scope).
            bindings[(account, src)] = (prev[0], realm)

    events: list[NormEvent] = []
    for i, ((account, ip), (ts, realm)) in enumerate(bindings.items()):
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


# ── dhcp.log → host_identity ──────────────────────────────────────────
def normalize_zeek_dhcp(text: str, source_file: str = "", monitored_ip: str = "") -> list[NormEvent]:
    """Bind a DHCP host_name to its assigned IP. Zeek aggregates the DORA
    exchange into one row carrying host_name + assigned_addr + mac."""
    rows = list(_rows(text))

    def _ip(d):
        return (d.get("assigned_addr") or d.get("requested_addr")
                or d.get("client_addr") or "")

    # MACs this log binds to the monitored IP (W4-4): a later no-IP DISCOVER
    # from one of these is still the monitored host; any other MAC is not.
    monitored_macs = {(d.get("mac") or "").lower() for d in rows
                      if monitored_ip and _ip(d) == monitored_ip and d.get("mac")}
    events: list[NormEvent] = []
    seen: set[tuple] = set()
    idx = 0
    for d in rows:
        hostname = (d.get("host_name") or "").strip()
        if not hostname:
            continue
        ip = _ip(d)
        key = (hostname, ip)
        if key in seen:
            continue
        seen.add(key)
        mac = d.get("mac", "")
        host, bound = _identity_attribution(ip, mac, monitored_ip, monitored_macs)
        # W4 review MED-2: the client's own FQDN suffix and the DHCP domain
        # option are victim-bound DNS-domain sources that can corroborate a
        # Kerberos realm before it is trusted as the org domain.
        fqdn = (d.get("client_fqdn") or "").strip().rstrip(".")
        dns_domain = fqdn.split(".", 1)[1] if "." in fqdn else ""
        dhcp_domain = (d.get("domain") or "").strip().rstrip(".")
        events.append(NormEvent(
            artifact_type="host_identity",
            timestamp=_ts(d.get("ts")),
            source_file=source_file,
            record_id=f"dhcp-{idx}",
            host=host,
            data={"hostname": hostname, "account": "", "realm": "",
                  "ip": ip, "mac": mac, "source": "dhcp",
                  "bound_to_monitored": bound,
                  "dns_domain": dns_domain, "dhcp_domain": dhcp_domain},
        ))
        idx += 1
    return events
