"""test_zeek_normalize.py — Zeek JSON-log normalizers → same NormEvents /
same rule anchors as the legacy tcpdump/tshark parsers.

Fixtures are REAL Zeek 8 JSON log lines captured from the project sample
pcaps (XLoader infection, traffic-analysis-exercise), plus a few crafted
lines that use the verified Zeek field names to exercise specific rules.
The whole point of the Zeek engine is parity: a Zeek event must carry the
same data keys the rules require so every existing rule keeps firing.
"""

from spectre.modules.pcap import PCAP_MODULE as pcap_module
from spectre.modules.pcap.enrich import enrich_events
from spectre.modules.pcap import zeek_normalize as zn


def _detect(events):
    out = []
    for e in events:
        for r in pcap_module.rules:
            if r.artifact_type != e.artifact_type:
                continue
            a = r.predicate(e)
            if a:
                out.append(a)
    return out


MON = "10.1.13.175"

# ── conn.log ──────────────────────────────────────────────────────────
_CONN = "\n".join([
    # real benign DNS (udp/53)
    '{"ts":1768515585.529328,"uid":"a","id.orig_h":"10.1.13.175",'
    '"id.orig_p":59972,"id.resp_h":"10.1.13.1","id.resp_p":53,'
    '"proto":"udp","duration":0.28,"orig_bytes":66,"resp_bytes":164}',
    # crafted: monitored host → 45.77.12.9:4444 (offensive port)
    '{"ts":1768515586.0,"uid":"b","id.orig_h":"10.1.13.175",'
    '"id.orig_p":51001,"id.resp_h":"45.77.12.9","id.resp_p":4444,'
    '"proto":"tcp","duration":1.0,"orig_bytes":10,"resp_bytes":20}',
])


def test_conn_fields_and_direction():
    events = zn.normalize_zeek_conn(_CONN, monitored_ip=MON)
    assert len(events) == 2
    assert events[0].artifact_type == "pcap_conn"
    assert events[1].data["dst_ip"] == "45.77.12.9"
    assert events[1].data["dst_port"] == "4444"
    assert events[1].data["proto"] == "tcp"
    assert events[1].data["direction"] == "outbound"


def test_suspicious_port_rule_fires_via_zeek_conn():
    anchors = _detect(zn.normalize_zeek_conn(_CONN, monitored_ip=MON))
    ids = [a.rule_id for a in anchors]
    assert "pcap-suspicious-port" in ids
    hit = next(a for a in anchors if a.rule_id == "pcap-suspicious-port")
    assert hit.iocs["ip"] == ["45.77.12.9"]


# ── conn.log → flow aggregation ───────────────────────────────────────
def test_flows_aggregate_bytes_oriented_by_monitored_ip():
    events = zn.normalize_zeek_flows(_CONN, monitored_ip=MON)
    # only conns involving the monitored host; oriented so bytes_out is what
    # the monitored host sent (orig_bytes) and bytes_in is what it received.
    f = next(e for e in events if e.data["remote_ip"] == "45.77.12.9")
    assert f.data["bytes_out"] == 10
    assert f.data["bytes_in"] == 20


def test_flows_need_monitored_ip():
    assert zn.normalize_zeek_flows(_CONN, monitored_ip="") == []


# ── dns.log (real XLoader line) ───────────────────────────────────────
_DNS = (
    '{"ts":1768515585.529328,"uid":"a","id.orig_h":"10.1.13.175",'
    '"id.orig_p":59972,"id.resp_h":"10.1.13.1","id.resp_p":53,"proto":"udp",'
    '"query":"files.catbox.moe","qtype_name":"A","rcode_name":"NOERROR",'
    '"answers":["108.181.20.35"],"TTLs":[72.0]}'
)


def test_dns_query_and_answers():
    events = zn.normalize_zeek_dns(_DNS, monitored_ip=MON)
    assert len(events) == 1
    assert events[0].data["dns_query"] == "files.catbox.moe"
    assert events[0].data["answers"] == ["108.181.20.35"]


def test_dns_answers_are_ip_filtered_for_enrich():
    # A CNAME answer must not pollute the ip->domain map.
    line = (
        '{"ts":1.0,"id.orig_h":"10.1.13.175","id.resp_h":"10.1.13.1",'
        '"query":"x.example.com","qtype_name":"A",'
        '"answers":["cdn.example.net","93.184.216.34"]}'
    )
    ev = zn.normalize_zeek_dns(line, monitored_ip=MON)[0]
    assert ev.data["answers"] == ["93.184.216.34"]


# ── http.log (real XLoader C2 line, z8 campaign param) ────────────────
_HTTP = (
    '{"ts":1768515619.269835,"uid":"c","id.orig_h":"10.1.13.175",'
    '"id.orig_p":63455,"id.resp_h":"198.251.89.229","id.resp_p":80,'
    '"method":"GET","host":"www.unitedsharesbank.com",'
    '"uri":"/060g/?T1-0=abc&z8=MN12STGOG","version":"1.1",'
    '"user_agent":"Mozilla/5.0 (Windows NT 6.1)","status_code":404}'
)


def test_http_fields():
    ev = zn.normalize_zeek_http(_HTTP, monitored_ip=MON)[0]
    assert ev.data["http_host"] == "www.unitedsharesbank.com"
    assert ev.data["http_request_path"] == "/060g/?T1-0=abc&z8=MN12STGOG"
    assert ev.data["http_user_agent"].startswith("Mozilla")
    assert ev.data["dst_port"] == "80"
    assert ev.data["direction"] == "outbound"
    # ascii_payload/http_server keys MUST exist (rule required_fields coverage)
    assert "ascii_payload" in ev.data
    assert "http_server" in ev.data


def test_c2_campaign_param_fires_via_zeek_http():
    anchors = _detect(zn.normalize_zeek_http(_HTTP, monitored_ip=MON))
    assert any(a.rule_id == "pcap-c2-protocol" for a in anchors)


# ── enrich: dns answers → flow resolved_domain (cross-normalizer) ─────
def test_enrich_stamps_resolved_domain_on_zeek_flow():
    conn = (
        '{"ts":1.0,"id.orig_h":"10.1.13.175","id.orig_p":63453,'
        '"id.resp_h":"108.181.20.35","id.resp_p":443,"proto":"tcp",'
        '"orig_bytes":100,"resp_bytes":2000000}'
    )
    events = zn.normalize_zeek_dns(_DNS, monitored_ip=MON) + \
        zn.normalize_zeek_flows(conn, monitored_ip=MON)
    enrich_events(events)
    flow = next(e for e in events if e.artifact_type == "pcap_flow")
    assert flow.data.get("resolved_domain") == "files.catbox.moe"


# ── beacon (conn.log start-times grouped per remote) ──────────────────
def test_beacon_from_conn_start_times():
    lines = []
    for i in range(12):
        lines.append(
            '{"ts":%d.0,"id.orig_h":"10.1.13.175","id.orig_p":%d,'
            '"id.resp_h":"203.0.113.9","id.resp_p":443,"proto":"tcp",'
            '"orig_bytes":100,"resp_bytes":100}' % (1000 + i * 60, 50000 + i)
        )
    events = zn.normalize_zeek_beacon("\n".join(lines), monitored_ip=MON)
    assert len(events) == 1
    bd = events[0].data["beacon_data"]
    assert bd["sample_count"] == 12
    assert bd["monitored_is_client"] is True
    assert abs(bd["mean_interval"] - 60.0) < 0.01


# ── dce_rpc.log → smb_pipe + drsuapi_call (real traffic-analysis line) ─
_DCE = "\n".join([
    '{"ts":1772308523.234777,"id.orig_h":"10.2.28.88","id.orig_p":59988,'
    '"id.resp_h":"10.2.28.2","id.resp_p":445,"named_pipe":"\\\\pipe\\\\lsass",'
    '"endpoint":"samr","operation":"SamrConnect5"}',
    '{"ts":1772308523.333834,"id.orig_h":"10.2.28.88","id.orig_p":59994,'
    '"id.resp_h":"10.2.28.2","id.resp_p":49671,"named_pipe":"49671",'
    '"endpoint":"drsuapi","operation":"DRSCrackNames"}',
])


def test_dce_rpc_produces_smb_pipe_and_drsuapi():
    events = zn.normalize_zeek_dce_rpc(_DCE, monitored_ip="10.2.28.88")
    kinds = {e.artifact_type for e in events}
    assert "smb_pipe" in kinds
    assert "drsuapi_call" in kinds
    drs = next(e for e in events if e.artifact_type == "drsuapi_call")
    assert drs.data["opnum"] == 12  # DRSCrackNames


def test_ad_recon_and_drsuapi_rules_fire_via_zeek_dce_rpc():
    anchors = _detect(zn.normalize_zeek_dce_rpc(_DCE, monitored_ip="10.2.28.88"))
    ids = {a.rule_id for a in anchors}
    # smb-ad-recon-pipe fires from the FIRST row (samr, unaffected by the
    # drsuapi duplicate-suppression fix below); smb-drsuapi-opnum fires
    # from the second row (drsuapi/DRSCrackNames, opnum 12).
    assert "smb-ad-recon-pipe" in ids
    assert "smb-drsuapi-opnum" in ids


# ── R1 F4 / W1-B task 3: drsuapi pipe-level rule must not claim DCSync,
# and must not duplicate smb-drsuapi-opnum's finding for the same row ──

_DCE_DRSUAPI_GETNCCHANGES = (
    '{"ts":1772308523.4,"id.orig_h":"10.2.28.88","id.orig_p":59995,'
    '"id.resp_h":"10.2.28.2","id.resp_p":49671,"named_pipe":"49671",'
    '"endpoint":"drsuapi","operation":"DRSGetNCChanges"}'
)

_DCE_DRSUAPI_BIND_ONLY = (
    '{"ts":1772308523.5,"id.orig_h":"10.2.28.88","id.orig_p":59996,'
    '"id.resp_h":"10.2.28.2","id.resp_p":49672,"named_pipe":"49672",'
    '"endpoint":"drsuapi","operation":"DRSBind"}'
)


def test_zeek_dce_rpc_drsuapi_call_carries_opnum_on_the_smb_pipe_event_too():
    """normalize_zeek_dce_rpc must surface the resolved opnum on the
    smb_pipe event itself (data["drsuapi_opnum"]), not only on the
    separate drsuapi_call event -- ad_recon_pipe() needs it to detect
    that a more specific finding already covers this exact row."""
    events = zn.normalize_zeek_dce_rpc(_DCE_DRSUAPI_GETNCCHANGES, monitored_ip="10.2.28.88")
    pipe_ev = next(e for e in events if e.artifact_type == "smb_pipe")
    assert pipe_ev.data["drsuapi_opnum"] == 3


def test_getncchanges_row_fires_only_the_opnum_rule_not_the_pipe_rule():
    """DsGetNCChanges (opnum 3, DCSync) is diagnostic: the pipe-level
    smb-ad-recon-pipe rule must defer entirely to smb-drsuapi-opnum for
    this row -- one finding, not two, for one underlying RPC call."""
    events = zn.normalize_zeek_dce_rpc(_DCE_DRSUAPI_GETNCCHANGES, monitored_ip="10.2.28.88")
    anchors = _detect(events)
    ids = [a.rule_id for a in anchors]
    assert ids == ["smb-drsuapi-opnum"]
    a = anchors[0]
    assert a.mitre == ["T1003.006"]


def test_drsuapi_bind_only_row_fires_only_the_generic_pipe_rule_without_dcsync():
    """DRSBind (opnum 0) is non-diagnostic: drsuapi_opnum() intentionally
    does not score it (session churn), so it must NOT be suppressed from
    the pipe-level rule -- that generic lead is the only signal for it,
    and it must not claim T1003.006 (DCSync) for a bare bind."""
    events = zn.normalize_zeek_dce_rpc(_DCE_DRSUAPI_BIND_ONLY, monitored_ip="10.2.28.88")
    anchors = _detect(events)
    ids = [a.rule_id for a in anchors]
    assert ids == ["smb-ad-recon-pipe"]
    a = anchors[0]
    assert "T1003.006" not in a.mitre


# ── W1 required fix 6: real R1 dce_rpc op mix, end to end through ALL
# rules (not ad_recon_pipe in isolation) -- R1's actual capture was
# DRSBind x57, DRSCrackNames x62, DRSUnbind x57, ZERO DRSGetNCChanges: the
# textbook false-positive DCSync the old rule produced. A second case adds
# exactly one DsGetNCChanges row and asserts T1003.006 appears exactly
# once -- the only honest path to that technique. ──────────────────────

def _dce_row(op: str, i: int) -> str:
    return (
        '{"ts":%f,"id.orig_h":"10.2.28.88","id.orig_p":%d,'
        '"id.resp_h":"10.2.28.2","id.resp_p":49671,"named_pipe":"49671",'
        '"endpoint":"drsuapi","operation":"%s"}'
        % (1772308523.0 + i * 0.01, 60000 + i, op)
    )


def _r1_op_mix(bind_n=57, crack_n=62, unbind_n=57, getncchanges_n=0) -> str:
    lines = []
    i = 0
    for _ in range(bind_n):
        lines.append(_dce_row("DRSBind", i))
        i += 1
    for _ in range(crack_n):
        lines.append(_dce_row("DRSCrackNames", i))
        i += 1
    for _ in range(unbind_n):
        lines.append(_dce_row("DRSUnbind", i))
        i += 1
    for _ in range(getncchanges_n):
        lines.append(_dce_row("DRSGetNCChanges", i))
        i += 1
    return "\n".join(lines)


def test_r1_real_op_mix_zero_getncchanges_never_claims_dcsync():
    """R1's actual capture: Bind x57 / CrackNames x62 / Unbind x57, zero
    DRSGetNCChanges. No anchor from any rule may claim T1003.006 (DCSync)
    anywhere in this mix -- that was the exact over-attribution R1 flagged
    (the report's #1 key finding claiming DCSync with zero GetNCChanges
    calls observed)."""
    text = _r1_op_mix(bind_n=57, crack_n=62, unbind_n=57, getncchanges_n=0)
    events = zn.normalize_zeek_dce_rpc(text, monitored_ip="10.2.28.88")
    anchors = _detect(events)

    assert anchors, "expected findings from the Bind/CrackNames rows"
    all_mitre = [m for a in anchors for m in a.mitre]
    assert "T1003.006" not in all_mitre, (
        "DCSync (T1003.006) must never be claimed when dce_rpc.log shows "
        "zero DsGetNCChanges (opnum 3) calls"
    )
    # DsCrackNames rows are diagnostic (opnum 12) -> smb-drsuapi-opnum,
    # T1087.002 name-resolution recon; DsBind/DsUnbind are non-diagnostic
    # session churn with no dedicated opnum finding, so the generic
    # smb-ad-recon-pipe pipe-bind lead covers them instead (also T1087.002,
    # per _AD_RECON_PIPES["drsuapi"]).
    rule_ids = {a.rule_id for a in anchors}
    assert "smb-drsuapi-opnum" in rule_ids
    assert "smb-ad-recon-pipe" in rule_ids


def test_r1_op_mix_with_one_getncchanges_row_fires_dcsync_exactly_once():
    text = _r1_op_mix(bind_n=57, crack_n=62, unbind_n=57, getncchanges_n=1)
    events = zn.normalize_zeek_dce_rpc(text, monitored_ip="10.2.28.88")
    anchors = _detect(events)

    dcsync_anchors = [a for a in anchors if "T1003.006" in a.mitre]
    assert len(dcsync_anchors) == 1, (
        "exactly one DsGetNCChanges row must fire exactly one T1003.006 "
        "finding -- the only honest path to DCSync"
    )
    assert dcsync_anchors[0].rule_id == "smb-drsuapi-opnum"
    assert dcsync_anchors[0].mitre == ["T1003.006"]


# ── kerberos.log → host_identity (real traffic-analysis line) ─────────
_KRB = (
    '{"ts":1772308523.048086,"id.orig_h":"10.2.28.88","id.orig_p":59985,'
    '"id.resp_h":"10.2.28.2","id.resp_p":88,"request_type":"AS",'
    '"client":"brolf/EASYAS123","service":"krbtgt/EASYAS123"}'
)


def test_kerberos_identity():
    ev = zn.normalize_zeek_kerberos(_KRB, monitored_ip="10.2.28.88")[0]
    assert ev.artifact_type == "host_identity"
    assert ev.data["account"] == "brolf@EASYAS123"
    assert ev.data["ip"] == "10.2.28.88"
    assert ev.data["source"] == "kerberos"


# ── dhcp.log → host_identity (real traffic-analysis line) ─────────────
_DHCP = (
    '{"ts":1772308600.0,"mac":"00:19:d1:b2:4d:ad","host_name":"DESKTOP-TEYQ2NR",'
    '"assigned_addr":"10.2.28.88","msg_types":["REQUEST","ACK"],"duration":0.1}'
)


def test_dhcp_identity():
    ev = zn.normalize_zeek_dhcp(_DHCP, monitored_ip="")[0]
    assert ev.data["hostname"] == "DESKTOP-TEYQ2NR"
    assert ev.data["ip"] == "10.2.28.88"
    assert ev.data["source"] == "dhcp"
