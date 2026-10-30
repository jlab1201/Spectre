r"""W5-2: registry_hive parses and detects on Services, ShimCache
(AppCompatCache) and AmCache.

Fixtures below reproduce RegRipper's real `rip.pl -r <hive> -a` output shape
(3.0 plugins: services v.20191024, appcompatcache/shimcache v.20220921,
amcache v.20200515; plus the 4.0 `services` variant with FailureCommand),
including the noise that ships with it: UWP package rows (tab-separated), the
same cache printed twice (appcompatcache AND shimcache), the per-plugin
dashed separator, and Amcache's InventoryApplication program lines.

Principle under test: rules fire on concrete markers only — never on the
plain presence of a service, a ShimCache row, or an Amcache row.
"""
from __future__ import annotations

import yaml

from spectre.core.base import NormEvent

SEP = "-" * 40

_SERVICES_RR3 = f"""\
services v.20191024
(System) Lists services/drivers in Services key by LastWrite times

ControlSet001\\Services
Lists services/drivers in Services key by LastWrite times

Tue Apr 15 09:06:00 2025 Z
  Name      = BITS
  Display   = @%SystemRoot%\\system32\\qmgr.dll,-1000
  ImagePath = %SystemRoot%\\System32\\svchost.exe -k netsvcs -p
  Type      = Share_Process
  Start     = Auto Start
  Group     =

Tue Apr 15 08:54:30 2025 Z
  Name      = Sysmon
  Display   = Sysmon
  ImagePath = C:\\Windows\\Sysmon.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =

  Name      = UpdSvc
  Display   = Windows Update Helper
  ImagePath = C:\\Users\\bob\\AppData\\Local\\Temp\\updsvc.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =

Thu Mar  6 19:50:12 2025 Z
  Name      = BcastDVRUserService
  Display   = @%SystemRoot%\\system32\\bcastdvruserservice.dll,-100
  ImagePath = C:\\Windows\\system32\\svchost.exe -k BcastDVRUserService
  Type      =
  Start     = Manual
  Group     =

  Name      = PSEXESVC
  Display   = PSEXESVC
  ImagePath = %SystemRoot%\\PSEXESVC.exe
  Type      = Own_Process
  Start     = Manual
  Group     =

  Name      = WinDefendHelper
  Display   = WinDefendHelper
  ImagePath = %COMSPEC% /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA
  Type      = Own_Process
  Start     = Auto Start
  Group     =

{SEP}
"""

_SERVICES_RR4 = f"""\
services v.20220614
(System) Lists services/drivers in Services key by LastWrite times
MITRE: T1543.003 (Persistence)

ControlSet001\\Services
Lists services/drivers in Services key by LastWrite times

Tue Apr 15 09:06:00 2025 Z
  Name           = Spooler
  Display        = @%systemroot%\\system32\\spoolsv.exe,-1
  ImagePath      = %SystemRoot%\\System32\\spoolsv.exe
  Type           = Own_Process
  Start          = Auto Start
  Group          = SpoolerGroup
  FailureCommand = rundll32.exe C:\\ProgramData\\x.dll,Start

{SEP}
"""

_SHIM_BODY = """\
C:\\Windows\\system32\\AppHostRegistrationVerifier.exe  2021-04-09 13:49:10
00000009\t000e00006bed0000\t000a0000273a0000\t8664\tMicrosoft.VCLibs.140.00.UWPDesktop\t8wekyb3d8bbwe\t
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe  2021-04-09 13:50:46
C:\\Users\\bob\\AppData\\Local\\Temp\\storePwd.exe  2025-03-20 08:46:10
C:\\Windows\\explorer.exe  2021-04-09 13:50:01
C:\\Users\\Public\\svchost.exe  2025-03-20 09:01:02
C:\\Tools\\mimikatz.exe  2025-03-20 09:05:00
C:\\Program Files\\WindowsApps\\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe\\Application  2025-03-20 08:53:48
"""

_SHIMCACHE = f"""\
appcompatcache v.20220921
(System) Parse files from System hive AppCompatCache

ControlSet001\\Control\\Session Manager\\AppCompatCache
LastWrite Time: 2025-03-20 08:56:52Z
Signature: 0x34
{_SHIM_BODY}{SEP}
shimcache v.20220921
(System) Parse file refs from System hive AppCompatCache data

*** ControlSet001 ***
ControlSet001\\Control\\Session Manager\\AppCompatCache
LastWrite Time: 2025-03-20 08:56:52Z
Signature: 0x34
{_SHIM_BODY}{SEP}
"""

_SHIMCACHE_WIN7 = f"""\
appcompatcache v.20220921
(System) Parse files from System hive AppCompatCache

ControlSet001\\Control\\Session Manager\\AppCompatCache
LastWrite Time: 2014-02-11 11:10:31Z
Win2K8R2/Win7, 64-bit
C:\\Windows\\Temp\\p.exe  2014-02-10 22:01:12  Executed
C:\\Windows\\system32\\net1.exe  2009-07-14 01:14:22
{SEP}
"""

_AMCACHE = f"""\
amcache v.20200515
(amcache) Parse AmCache.hve file

***InventoryApplicationFile***
c:\\program files\\wireshark\\capinfos.exe  LastWrite: 2025-04-15 08:56:02Z
Hash: cb462057ba345dc0b9f6a32daddee699a23753c7

c:\\users\\bob\\appdata\\local\\temp\\upgrader.exe  LastWrite: 2025-03-20 08:46:12Z
Hash: 1111111111111111111111111111111111111111

c:\\programdata\\lsass.exe  LastWrite: 2025-03-20 08:47:00Z
Hash: 2222222222222222222222222222222222222222

c:\\windows\\system32\\compattelrunner.exe  LastWrite: 2025-03-20 08:51:41Z
Hash: b4108c1d6832f0d036eedcd3d2f684d43be04996

Tue Apr 15 08:55:56 2025 - Google Chrome v.135.0.7049.85
Tue Apr 15 08:56:02 2025 - Wireshark 4.2.11 x64 v.4.2.11
{SEP}
"""

_AMCACHE_LEGACY = f"""\
amcache v.20200515
(amcache) Parse AmCache.hve file

***Files***
{{3a7b6b4c-0000-0000-0000-100000000000}}
File Reference: 1e0000000c9a4
LastWrite     : 2016-03-01 10:11:12Z
Path          : C:\\Users\\bob\\Downloads\\psexec.exe
Company Name  : Sysinternals - www.sysinternals.com
SHA-1         : 0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Compile Time  : 2016-02-20 01:02:03Z

File Reference: 1e0000000c9a5
LastWrite     : 2016-03-01 10:11:13Z
Path          : C:\\Windows\\System32\\notepad.exe
SHA-1         : 0000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

{SEP}
"""


def _norm(tmp_path, text, evidence="/case/evidence/SYSTEM"):
    from spectre.modules.registry_hive.normalize import normalize
    out = tmp_path / "rip.txt"
    out.write_text(text)
    return normalize({"path": str(out), "evidence_path": evidence,
                      "artifact_type": "registry_run", "result": "success"})


def _of(events, art):
    return [e for e in events if e.artifact_type == art]


# ── normalize: Services ──────────────────────────────────────────────────

def test_services_blocks_parse_with_inherited_timestamp(tmp_path):
    evs = _of(_norm(tmp_path, _SERVICES_RR3), "registry_service")
    names = [e.data["service_name"] for e in evs]
    assert sorted(names) == sorted(["BITS", "Sysmon", "UpdSvc", "BcastDVRUserService",
                                    "PSEXESVC", "WinDefendHelper"])
    by = {e.data["service_name"]: e for e in evs}
    # UpdSvc has no timestamp line of its own: it shares the LastWrite of the
    # preceding header (RegRipper groups services by LastWrite time).
    assert by["UpdSvc"].timestamp == "2025-04-15T08:54:30+00:00"
    assert by["BcastDVRUserService"].timestamp == "2025-03-06T19:50:12+00:00"
    assert by["UpdSvc"].data["image_path"] == r"C:\Users\bob\AppData\Local\Temp\updsvc.exe"
    assert by["UpdSvc"].data["image_path_lower"] == by["UpdSvc"].data["image_path"].lower()
    assert by["UpdSvc"].data["start_type"] == "Auto Start"
    assert by["UpdSvc"].data["key"] == r"ControlSet001\Services"
    assert by["UpdSvc"].data["hive"] == "SYSTEM"


def test_services_rr4_failure_command(tmp_path):
    (e,) = _of(_norm(tmp_path, _SERVICES_RR4), "registry_service")
    assert e.data["service_name"] == "Spooler"
    assert e.data["failure_command"].startswith("rundll32.exe")


def test_services_section_does_not_produce_run_events(tmp_path):
    assert _of(_norm(tmp_path, _SERVICES_RR3), "registry_run") == []


# ── normalize: ShimCache ─────────────────────────────────────────────────

def test_shimcache_entries_parse_and_dedupe_across_both_plugins(tmp_path):
    evs = _of(_norm(tmp_path, _SHIMCACHE), "shimcache")
    paths = [e.data["path"] for e in evs]
    # appcompatcache + shimcache print the same cache: one event per entry.
    assert len(paths) == len(set(p.lower() for p in paths)) == 7
    assert not any("\t" in p for p in paths)  # UWP package rows are skipped
    by = {e.data["path"]: e for e in evs}
    e = by[r"C:\Users\bob\AppData\Local\Temp\storePwd.exe"]
    assert e.data["basename_lower"] == "storepwd.exe"
    assert e.data["file_mtime"] == "2025-03-20T08:46:10+00:00"
    assert e.timestamp == "2025-03-20T08:46:10+00:00"
    assert e.data["executed_flag"] is None  # Win10 carries no execution flag
    assert "cache_position" not in e.data  # RegRipper output order is a Perl hash walk
    assert e.data["key_lastwrite"] == "2025-03-20T08:56:52+00:00"


def test_shimcache_win7_executed_flag(tmp_path):
    evs = {e.data["path"]: e for e in _of(_norm(tmp_path, _SHIMCACHE_WIN7), "shimcache")}
    assert evs[r"C:\Windows\Temp\p.exe"].data["executed_flag"] is True
    assert evs[r"C:\Windows\system32\net1.exe"].data["executed_flag"] is False


def test_shimcache_order_is_deterministic(tmp_path):
    """appcompatcache.pl walks a Perl hash (`keys %files`), so line order
    varies run to run. Events are emitted in a stable (path, mtime) order."""
    body_lines = _SHIM_BODY.splitlines(keepends=True)
    shuffled = "".join(reversed(body_lines))
    a = _of(_norm(tmp_path, _SHIMCACHE), "shimcache")
    b = _of(_norm(tmp_path, _SHIMCACHE.replace(_SHIM_BODY, shuffled)), "shimcache")
    key = lambda evs: [(e.record_id, e.data["path"]) for e in evs]  # noqa: E731
    assert key(a) == key(b)


# ── normalize: AmCache ───────────────────────────────────────────────────

def test_amcache_inventory_file_entries(tmp_path):
    evs = _of(_norm(tmp_path, _AMCACHE, "/case/evidence/Amcache.hve"), "amcache")
    by = {e.data["path"]: e for e in evs}
    assert len(evs) == 4  # program-inventory lines are not file entries
    e = by[r"c:\users\bob\appdata\local\temp\upgrader.exe"]
    assert e.data["sha1"] == "1111111111111111111111111111111111111111"
    assert e.data["basename_lower"] == "upgrader.exe"
    assert e.timestamp == "2025-03-20T08:46:12+00:00"
    assert e.data["entry_format"] == "InventoryApplicationFile"
    assert e.data["hive"] == "Amcache.hve"


def test_amcache_legacy_file_entries(tmp_path):
    evs = {e.data["path"]: e for e in _of(_norm(tmp_path, _AMCACHE_LEGACY), "amcache")}
    e = evs[r"C:\Users\bob\Downloads\psexec.exe"]
    assert e.data["sha1"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert e.data["entry_format"] == "File"
    assert e.data["compile_time"] == "2016-02-20T01:02:03+00:00"
    assert e.timestamp == "2016-03-01T10:11:12+00:00"


def test_record_ids_unique_across_sections(tmp_path):
    from tests.test_registry_hive.test_registry_hive import _RIP_OUTPUT
    evs = _norm(tmp_path, _RIP_OUTPUT + _SERVICES_RR3 + _SHIMCACHE + _AMCACHE)
    ids = [(e.artifact_type, e.record_id) for e in evs]
    assert len(ids) == len(set(ids))
    assert len(_of(evs, "registry_run")) == 2  # Run parsing unchanged


def test_normalize_is_deterministic(tmp_path):
    text = _SERVICES_RR3 + _SHIMCACHE + _AMCACHE
    a = [(e.artifact_type, e.record_id, e.data) for e in _norm(tmp_path, text)]
    b = [(e.artifact_type, e.record_id, e.data) for e in _norm(tmp_path, text)]
    assert a == b


# ── rules ────────────────────────────────────────────────────────────────

def _fire(evs, rule_id):
    from spectre.modules.registry_hive import RULES
    rules = [r for r in RULES if r.rule_id == rule_id]
    assert rules, rule_id
    out = []
    for e in evs:
        for r in rules:
            if r.artifact_type == e.artifact_type:
                a = r.predicate(e)
                if a:
                    out.append(a)
    return out


def test_services_rule_fires_only_on_markers(tmp_path):
    evs = _of(_norm(tmp_path, _SERVICES_RR3), "registry_service")
    hits = {a.event.data["service_name"]: a for a in _fire(evs, "registry-services")}
    # BITS/Sysmon/BcastDVRUserService are plain presence — never flagged.
    assert set(hits) == {"UpdSvc", "PSEXESVC", "WinDefendHelper"}
    assert hits["UpdSvc"].mitre == ["T1543.003"]
    assert hits["PSEXESVC"].mitre == ["T1543.003", "T1569.002"]
    assert "encoded" in hits["WinDefendHelper"].title
    for a in hits.values():
        assert a.rule_id == "registry-services"
        assert a.artifact_type == "registry_service"
        assert a.iocs["filepath"] == [a.event.data["image_path"]]


def test_services_rule_checks_failure_command(tmp_path):
    evs = _of(_norm(tmp_path, _SERVICES_RR4), "registry_service")
    (a,) = _fire(evs, "registry-services")
    assert "FailureCommand" in a.title


def test_shimcache_rules_fire_only_on_markers(tmp_path):
    evs = _of(_norm(tmp_path, _SHIMCACHE), "shimcache")
    path_hits = {a.event.data["basename_lower"]: a
                 for a in _fire(evs, "shimcache-suspicious-path")}
    masq = {a.event.data["basename_lower"]: a for a in _fire(evs, "shimcache-masquerade")}
    assert set(path_hits) == {"storepwd.exe", "mimikatz.exe", "svchost.exe"}
    assert set(masq) == {"svchost.exe"}  # explorer.exe in \Windows is legit
    assert masq["svchost.exe"].mitre == ["T1036.005"]
    assert path_hits["storepwd.exe"].mitre == ["T1105"]
    for a in list(path_hits.values()) + list(masq.values()):
        text = (a.title + " " + a.summary).lower()
        assert "executed" not in text and "execution of" not in text
        assert a.confidence < 0.6  # single-artifact presence is lead-grade


def test_shimcache_dedup_collapses_same_file_same_mtime(tmp_path):
    evs = [
        NormEvent("shimcache", "", "SYSTEM", "shim-1", data={
            "path": r"C:\Users\BOB~1\AppData\Local\Temp\x.exe",
            "path_lower": r"c:\users\bob~1\appdata\local\temp\x.exe",
            "basename_lower": "x.exe", "file_mtime": "2025-01-01T00:00:00+00:00",
            "hive": "SYSTEM"}),
        NormEvent("shimcache", "", "SYSTEM", "shim-2", data={
            "path": r"C:\Users\Bob Smith\AppData\Local\Temp\x.exe",
            "path_lower": r"c:\users\bob smith\appdata\local\temp\x.exe",
            "basename_lower": "x.exe", "file_mtime": "2025-01-01T00:00:00+00:00",
            "hive": "SYSTEM"}),
    ]
    a, b = _fire(evs, "shimcache-suspicious-path")
    assert a.dedup_key == b.dedup_key


def test_amcache_rules_fire_only_on_markers(tmp_path):
    evs = _of(_norm(tmp_path, _AMCACHE + _AMCACHE_LEGACY), "amcache")
    path_hits = {a.event.data["basename_lower"] for a in _fire(evs, "amcache-suspicious-path")}
    masq = {a.event.data["basename_lower"]: a for a in _fire(evs, "amcache-mismatch")}
    assert path_hits == {"upgrader.exe", "psexec.exe"}
    assert set(masq) == {"lsass.exe"}
    assert masq["lsass.exe"].mitre == ["T1036.005"]
    for a in _fire(evs, "amcache-suspicious-path"):
        assert a.event.data["sha1"] in a.summary
        assert a.iocs["filepath"] == [a.event.data["path"]]
        assert "executed" not in (a.title + a.summary).lower()


def test_new_rule_mitre_is_within_the_map():
    from spectre.config import MITRE_MAP_PATH
    from spectre.modules.registry_hive import RULES
    rules = yaml.safe_load(MITRE_MAP_PATH.read_text())["rules"]
    for r in RULES:
        assert r.rule_id in rules, r.rule_id
        assert set(r.mitre) <= set(rules[r.rule_id]["allowed"]), r.rule_id


def test_rule_uuids_unique():
    from spectre.modules.registry_hive import RULES
    uuids = [r.metadata.uuid for r in RULES if r.metadata]
    assert len(uuids) == len(set(uuids)) == len(RULES)


# ── knowledge routing + honest caveats ───────────────────────────────────

def test_fk_routes_each_registry_artifact_to_its_own_yaml():
    from spectre.pipeline import fk_routing
    fk = fk_routing.artifact_fk_files()
    assert fk["registry_run"] == "registry_run.yaml"
    assert fk["registry_service"] == "registry_services.yaml"
    assert fk["shimcache"] == "shimcache.yaml"
    assert fk["amcache"] == "amcache.yaml"


def _fk(name):
    from spectre.knowledge import load_fk_yaml
    return load_fk_yaml(name)


def test_shimcache_fk_does_not_claim_execution():
    fk = _fk("shimcache")
    assert not any("executed" in p.lower() for p in fk["proves"])
    dnp = " ".join(fk["does_NOT_prove"]).lower()
    assert "windows 10" in dnp and "execution" in dnp


def test_amcache_fk_does_not_claim_execution():
    fk = _fk("amcache")
    assert not any("execution" in p.lower() for p in fk["proves"])
    assert any("not proof" in c.lower() and "execut" in c.lower()
               for c in fk["does_NOT_prove"])


def test_services_fk_exists_with_caveats():
    fk = _fk("registry_services")
    assert fk["does_NOT_prove"]
    assert any("ran" in c.lower() or "started" in c.lower() for c in fk["does_NOT_prove"])


def test_program_files_temp_is_not_user_writable_staging():
    from spectre.core import markers
    assert markers.staging_marker(
        r"c:\program files (x86)\microsoft\temp\euff10.tmp\microsoftedgeupdate.exe") is None
    assert markers.staging_marker(r"c:\windows\temp\x\a.exe") == "\\temp\\"
    # Command lines are judged whole: a Program Files launcher pointing at a
    # temp payload is still flagged.
    assert markers.launcher_markers(
        r'"c:\program files\x\host.exe" c:\users\public\p.dll')


def test_masquerade_helper_edges():
    from spectre.core import markers
    assert markers.masquerades_as_system_process(r"c:\windows\explorer.exe") is None
    assert markers.masquerades_as_system_process(r"c:\windows\svchost.exe") == "svchost.exe"
    assert markers.masquerades_as_system_process(r"c:\windows\syswow64\svchost.exe") is None
    assert markers.masquerades_as_system_process("svchost.exe") is None  # no dir
    assert markers.offensive_tool("sync.exe") is None
    assert markers.offensive_tool("nc.exe") == "nc.exe"
