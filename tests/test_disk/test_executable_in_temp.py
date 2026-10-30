"""W5-4: unit coverage for the disk `executable_in_temp` rule."""
import pytest

from spectre.core.base import NormEvent
from spectre.modules.disk.rules import RULES, executable_in_temp


def _ev(path, size=10):
    return NormEvent(artifact_type="disk_file_entry", timestamp="2025-01-01T00:00:00+00:00",
                     source_file="img", record_id="1", data={"path": path, "size": size})


@pytest.mark.parametrize("path", [
    "C:/Users/bob/AppData/Local/Temp/evil.exe",
    "/Users/bob/AppData/Local/Temp/x.dll",
    "C:/Windows/Temp/payload.exe",
    "C:/Windows/Temp/a.ps1",
    "/tmp/dropper.exe",
    "/var/tmp/run.bat",
    "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe",
    "C:\\Temp\\s.vbs",
    "C:/temp/s.scr",
    "/tmp/x.js",
])
def test_positive(path):
    a = executable_in_temp(_ev(path))
    assert a is not None
    assert a.rule_id == "disk-executable-in-temp"
    assert a.mitre == ["T1105"]
    assert a.iocs["filepath"] == [path]


@pytest.mark.parametrize("path", [
    "C:/Users/bob/AppData/Local/TEMP/EVIL.EXE",
    "/TMP/Dropper.Exe",
    "C:/WINDOWS/TEMP/X.DLL",
])
def test_case_insensitive(path):
    assert executable_in_temp(_ev(path)) is not None


@pytest.mark.parametrize("path", [
    "C:/Users/bob/AppData/Local/Temp/readme.txt",
    "/tmp/photo.jpg",
    "C:/Windows/Temp/log.tmp",
    "/tmp/archive.zip",
    "/tmp/exe",                       # no extension
    "C:/Windows/System32/cmd.exe",    # exe, not temp
    "C:/Program Files/app/app.dll",
    "C:/Users/bob/Desktop/tool.exe",
    "/tmp/evil.exe.txt",              # executable ext not final
    "C:/Users/bob/templates/run.exe", # 'temp' prefix without separators
    "",
])
def test_negative(path):
    assert executable_in_temp(_ev(path)) is None


def test_missing_path_key_is_safe():
    e = NormEvent("disk_file_entry", "", "img", "1", data={})
    assert executable_in_temp(e) is None


def test_rule_registration_consistent():
    (r,) = RULES
    assert r.rule_id == "disk-executable-in-temp"
    assert r.artifact_type == "disk_file_entry"
    assert r.mitre == ["T1105"]
