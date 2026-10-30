r"""WS7 — service and Winlogon persistence (SANS: AutoStart + Services).

The GIAC persistence doctrine this encodes: AutoStart locations plus Services
account for the large majority of real-world persistence, and two checks carry
most of that weight --

  * a service configured to start automatically whose binary is somewhere a
    service binary has no business being, and
  * Winlogon's `Userinit`, which must reference `userinit.exe` and nothing
    else. Anything appended after a comma runs at every interactive logon.

`memory_svcscan` has been extracted by volatility3 since the module was
written and **nothing consumed it** -- 863 rows on Challenge.raw, zero rules.
MemProcFS publishes the same table at `sys/services/services.txt`, so the two
rules land alongside a second engine for the artifact type.

Note on Challenge.raw: neither rule fires on it. Every auto-start service on
that image is a stock svchost/system32 binary and its Userinit is clean, which
is the correct result on a benign reference image -- so these rules are tested
against constructed evidence, with the real fixture pinning the parser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spectre.modules.memory.extract_memprocfs import (
    _collect_services,
    _parse_svcinfo,
)
from spectre.modules.memory.normalize import normalize
from spectre.pipeline.correlation import corroborate
import spectre.modules.memory.rules as memrules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "memprocfs"
SVCINFO = FIXTURES / "svcinfo"


def _svcinfo(name: str) -> dict:
    return _parse_svcinfo((SVCINFO / f"{name}.txt").read_text())


def _events(tmp_path, artifact, rows, source_tool="volatility3", name="a.json"):
    p = tmp_path / name
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": artifact, "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    for e in evs:
        e.source_tool = source_tool
    return evs


def _svc(tmp_path, **over):
    row = {"Name": "EvilSvc", "Display": "Evil Service",
           "Binary": r"C:\Users\Jaffa\AppData\Local\Temp\svc.exe",
           "State": "SERVICE_RUNNING", "Start": "SERVICE_AUTO_START", "PID": 0}
    row.update(over)
    return _events(tmp_path, "memory_svcscan", [row])[0]


# ── the MemProcFS services parser ──

def test_name_and_display_are_read_as_key_value():
    r = _svcinfo("auto_share_process")
    assert r["Name"] == "AudioSrv"
    assert r["Display"] == "Windows Audio"
    assert r["PID"] == 780
    assert r["User"] == "LOCAL SERVICE"


def test_binary_comes_from_path_not_image_path():
    r"""`Image Path:` is empty for all 393 services on the reference image;
    `Path:` carries the command line. A parser that reads Image Path returns
    no binaries at all -- and a service-persistence rule with no binaries
    never fires, silently."""
    assert _svcinfo("auto_share_process")["Binary"] == (
        r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted")
    assert _svcinfo("auto_own_process")["Binary"] == r"C:\Windows\System32\spoolsv.exe"
    assert _svcinfo("boot_kernel_driver")["Binary"] == r"\Driver\ACPI"


def test_enum_fields_keep_both_the_constant_and_its_value():
    r = _svcinfo("auto_share_process")
    assert r["Start"] == "SERVICE_AUTO_START"
    assert r["StartValue"] == "0x2"
    assert r["State"] == "SERVICE_RUNNING"
    assert r["Type"] == "SERVICE_WIN32_SHARE_PROCESS"


def test_combined_type_flags_survive_intact():
    assert _svcinfo("auto_own_process")["Type"] == (
        "SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS")


def test_a_demand_start_service_is_read_as_such():
    r = _svcinfo("demand_share_process")
    assert r["Name"] == "Appinfo"
    assert r["Start"] == "SERVICE_DEMAND_START"


def test_a_record_without_a_service_name_is_dropped():
    assert _parse_svcinfo("Ordinal:  7\nDisplay Name:  orphan\n") == {}
    assert _parse_svcinfo("") == {}


def test_collect_services_walks_the_by_name_tree(tmp_path):
    base = tmp_path / "sys" / "services" / "by-name"
    for i, name in enumerate(["auto_share_process", "boot_kernel_driver"]):
        d = base / f"svc-{i}"
        d.mkdir(parents=True)
        (d / "svcinfo.txt").write_text((SVCINFO / f"{name}.txt").read_text())
    (base / "stray.txt").write_text("not a directory")

    rows = _collect_services(str(tmp_path))
    assert {r["Name"] for r in rows} == {"AudioSrv", "ACPI"}


def test_collect_services_on_a_mount_without_services_is_empty(tmp_path):
    assert _collect_services(str(tmp_path)) == []


# ── start-type canonicalisation ──

@pytest.mark.parametrize("raw", [
    "SERVICE_AUTO_START", "AUTO_START", "Auto", "auto", 2, "2",
])
def test_every_engines_rendering_of_auto_start_canonicalises_the_same(tmp_path, raw):
    e = _svc(tmp_path, Start=raw)
    assert e.data["start_canonical"] == "auto"


@pytest.mark.parametrize("raw,expected", [
    ("SERVICE_DEMAND_START", "demand"), ("DEMAND_START", "demand"),
    ("SERVICE_DISABLED", "disabled"), (0, "boot"), (1, "system"),
    ("", ""), ("something new", ""),
])
def test_other_start_types_canonicalise_or_pass_through_empty(tmp_path, raw, expected):
    """An unrecognised rendering yields "" -- never a guess that happens to
    read as auto-start."""
    assert _svc(tmp_path, Start=raw).data["start_canonical"] == expected


# ── memory-service-persistence ──

def test_auto_start_service_running_from_a_user_writable_path_fires(tmp_path):
    a = memrules.service_persistence(_svc(tmp_path))
    assert a is not None
    assert a.mitre == ["T1543.003"]
    assert a.dedup_key == "evilsvc"


def test_stock_auto_start_services_do_not_fire(tmp_path):
    for binary in [
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        r"C:\Windows\System32\spoolsv.exe",
        r"\SystemRoot\System32\drivers\acpi.sys",
    ]:
        assert memrules.service_persistence(_svc(tmp_path, Binary=binary)) is None


def test_a_suspicious_binary_that_is_not_auto_start_does_not_fire(tmp_path):
    """Persistence is the claim. A demand-start service in a temp directory is
    worth noting elsewhere, but it does not survive a reboot on its own."""
    assert memrules.service_persistence(
        _svc(tmp_path, Start="SERVICE_DEMAND_START")) is None
    assert memrules.service_persistence(
        _svc(tmp_path, Start="SERVICE_DISABLED")) is None


@pytest.mark.parametrize("binary", [
    r"C:\Users\Jaffa\evil.exe",
    r"C:\Windows\Temp\evil.exe",
    r"C:\Users\Jaffa\AppData\Roaming\evil.exe",
    r"C:\ProgramData\evil.exe",
])
def test_user_writable_locations_fire(tmp_path, binary):
    assert memrules.service_persistence(_svc(tmp_path, Binary=binary)) is not None


def test_a_bare_relative_binary_fires(tmp_path):
    """A service ImagePath with no directory resolves against the service
    controller's working directory -- the relative-path hijack."""
    assert memrules.service_persistence(_svc(tmp_path, Binary="evil.exe")) is not None


def test_an_unquoted_path_with_a_space_fires(tmp_path):
    r"""`C:\Program Files\Sub Dir\svc.exe` unquoted lets a planted
    `C:\Program.exe` win. The quoted form is correctly configured."""
    assert memrules.service_persistence(
        _svc(tmp_path, Binary=r"C:\Program Files\Vendor App\svc.exe")) is not None
    assert memrules.service_persistence(
        _svc(tmp_path, Binary=r'"C:\Program Files\Vendor App\svc.exe"')) is None


def test_a_lolbin_service_host_fires(tmp_path):
    assert memrules.service_persistence(
        _svc(tmp_path, Binary=r"C:\Windows\System32\rundll32.exe evil.dll,Start")
    ) is not None


def test_the_service_dedup_key_is_engine_invariant(tmp_path):
    """volatility3 renders SERVICE_AUTO_START and resolves %SystemRoot%;
    MemProcFS renders AUTO_START and its own command line. One service, one
    claim."""
    vol = _events(tmp_path, "memory_svcscan", [{
        "Name": "EvilSvc", "Display": "Evil Service",
        "Binary": r"C:\Users\Jaffa\AppData\Local\Temp\svc.exe",
        "Binary (Registry)": r"%USERPROFILE%\AppData\Local\Temp\svc.exe",
        "State": "SERVICE_RUNNING", "Start": "SERVICE_AUTO_START", "PID": 0,
    }], "volatility3", "vol.json")
    mpfs = _events(tmp_path, "memory_svcscan", [{
        "Name": "EvilSvc", "Display": "Evil Service",
        "Binary": r"C:\Users\Jaffa\AppData\Local\Temp\svc.exe -k run",
        "State": "RUNNING", "Start": "AUTO_START", "PID": 0,
    }], "memprocfs", "mpfs.json")

    anchors = [a for a in (memrules.service_persistence(e)
                           for e in vol + mpfs) if a]
    assert len(anchors) == 2
    groups = corroborate(anchors)
    assert len(groups) == 1
    assert groups[0].sources == 2


# ── memory-winlogon-userinit-hijack ──

WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def _reg(tmp_path, name, data, key=WINLOGON):
    return _events(tmp_path, "memory_regkey", [{
        "Key": key, "Name": name, "Type": "REG_SZ", "Data": data}])[0]


@pytest.mark.parametrize("value", [
    r"C:\Windows\system32\userinit.exe,",
    r"C:\Windows\system32\userinit.exe",
    r"C:\Windows\System32\Userinit.exe,",
    r'"C:\Windows\system32\userinit.exe",',
])
def test_a_clean_userinit_does_not_fire(tmp_path, value):
    """The trailing comma is Windows' own default rendering, not an empty
    second entry. A rule that flags it flags every healthy Windows host."""
    assert memrules.winlogon_userinit_hijack(_reg(tmp_path, "Userinit", value)) is None


@pytest.mark.parametrize("value", [
    r"C:\Windows\system32\userinit.exe,C:\Users\Jaffa\AppData\evil.exe",
    r"C:\Windows\system32\userinit.exe, powershell.exe -enc SQBFAFgA",
    r"C:\Temp\evil.exe",
    r"C:\Windows\system32\userinit32.exe,",
])
def test_anything_other_than_userinit_alone_fires(tmp_path, value):
    a = memrules.winlogon_userinit_hijack(_reg(tmp_path, "Userinit", value))
    assert a is not None
    assert a.mitre == ["T1547.004"]
    assert a.confidence == 0.75


def test_only_the_userinit_value_is_examined(tmp_path):
    assert memrules.winlogon_userinit_hijack(
        _reg(tmp_path, "Shell", r"explorer.exe,evil.exe")) is None
    assert memrules.winlogon_userinit_hijack(
        _reg(tmp_path, "Userinit", r"C:\evil.exe,",
             key=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) is None


def test_an_empty_userinit_does_not_fire(tmp_path):
    """An empty or absent value is a gap in what was recovered from the hive,
    not an observation that Userinit was tampered with."""
    assert memrules.winlogon_userinit_hijack(_reg(tmp_path, "Userinit", "")) is None


def test_registry_persistence_does_not_double_count_userinit(tmp_path):
    """`userinit` is on _BENIGN_AUTOSTART so memory-registry-persistence skips
    it; this rule owns the value. One hijacked Userinit must not produce two
    findings."""
    e = _reg(tmp_path, "Userinit",
             r"C:\Windows\system32\userinit.exe,C:\Users\Jaffa\evil.exe")
    assert memrules.registry_persistence(e) is None
    assert memrules.winlogon_userinit_hijack(e) is not None


def test_the_userinit_dedup_key_is_engine_invariant(tmp_path):
    """The same hijack seen through volatility3's hive-file path and
    MemProcFS's HKLM rendering is one claim."""
    evil = r"C:\Windows\system32\userinit.exe,C:\Users\Jaffa\evil.exe"
    vol = _events(tmp_path, "memory_regkey", [{
        "Key": r"\SystemRoot\System32\Config\SOFTWARE\Microsoft"
               r"\Windows NT\CurrentVersion\Winlogon",
        "Name": "Userinit", "Type": "REG_SZ", "Data": evil}],
        "volatility3", "vol.json")
    mpfs = _events(tmp_path, "memory_regkey", [{
        "Key": "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon",
        "Name": "Userinit", "Type": "REG_SZ", "Value": evil}],
        "memprocfs", "mpfs.json")

    anchors = [a for a in (memrules.winlogon_userinit_hijack(e)
                           for e in vol + mpfs) if a]
    assert len(anchors) == 2
    groups = corroborate(anchors)
    assert len(groups) == 1
    assert groups[0].sources == 2
