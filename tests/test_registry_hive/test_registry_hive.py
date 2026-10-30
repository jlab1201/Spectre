"""Track B2 Task 5: registry_hive analyzer module (RegRipper)."""

_RIP_OUTPUT = """\
run v.20200511
(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive

Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time 2026-01-15 10:22:33Z
  OneDrive - "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background
  Updater - C:\\Users\\bob\\AppData\\Roaming\\svchost.exe

Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
LastWrite Time 2026-01-15 10:22:33Z
  (empty)
"""


def test_normalize_extracts_run_entries(tmp_path):
    from spectre.modules.registry_hive.normalize import normalize
    out = tmp_path / "rip.txt"
    out.write_text(_RIP_OUTPUT)
    handle = {"path": str(out), "artifact_type": "registry_run",
              "evidence_path": "/case/evidence/NTUSER.DAT", "result": "success"}
    events = normalize(handle)
    assert len(events) == 2
    e = {ev.data["value_name"]: ev for ev in events}
    assert "svchost.exe" in e["Updater"].data["value_data"]
    assert e["Updater"].data["key"].endswith("CurrentVersion\\Run")
    assert e["Updater"].artifact_type == "registry_run"


def test_rule_fires_on_appdata_executable():
    from spectre.modules.registry_hive.rules import run_key_persistence
    from spectre.core.base import NormEvent
    ev = NormEvent(artifact_type="registry_run", timestamp="", source_file="h",
                   record_id="1", data={
                       "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                       "value_name": "Updater",
                       "value_data": r"C:\Users\bob\AppData\Roaming\svchost.exe",
                       "hive": "NTUSER.DAT"})
    a = run_key_persistence(ev)
    assert a is not None
    assert a.rule_id == "registry-run-persistence"
    assert a.mitre == ["T1547.001"]


# ── A4-04 fix: narrow allowlist for known-benign AppData consumer apps.
# Principle: never suppress SILENTLY (a downgrade + explanatory note, not a
# vanished finding) and never suppress when a strong malicious signal
# (a LOLBIN/script-host token) co-occurs.

def _run_key_event(value_data, value_name="Updater", hive="NTUSER.DAT"):
    from spectre.core.base import NormEvent
    return NormEvent(artifact_type="registry_run", timestamp="", source_file="h",
                      record_id="1", data={
                          "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                          "value_name": value_name,
                          "value_data": value_data,
                          "hive": hive})


def test_known_vendor_appdata_path_is_downgraded_not_silently_dropped():
    """OneDrive's stock, vendor-recommended AppData install path must not
    reach the CONFIRMED-eligible 0.6 confidence bar reserved for genuine
    signal — but it must still surface as a (low-confidence) finding, with
    an explanatory note, rather than vanishing outright."""
    from spectre.modules.registry_hive.rules import run_key_persistence
    ev = _run_key_event(
        r'"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background',
        value_name="OneDrive")
    a = run_key_persistence(ev)
    assert a is not None, "allowlisted vendor entries are downgraded, never silently suppressed"
    assert a.confidence < 0.6
    assert "allowlist" in (a.title + a.summary).lower()


def test_known_vendor_path_with_lolbin_token_is_not_suppressed():
    """A strong co-occurring malicious signal (a script-host/LOLBIN token
    in the SAME value data) must override the vendor allowlist entirely —
    full confidence, no downgrade."""
    from spectre.modules.registry_hive.rules import run_key_persistence
    ev = _run_key_event(
        r'powershell -enc ZgBvAG8A '
        r'C:\Users\bob\AppData\Local\Discord\Update.exe',
        value_name="Discord")
    a = run_key_persistence(ev)
    assert a is not None
    assert a.confidence == 0.6


def test_non_vendor_appdata_path_unaffected_by_allowlist():
    """A path under AppData that does NOT match a known-benign vendor stays
    at full confidence — the allowlist is narrow, not a blanket AppData
    exemption."""
    from spectre.modules.registry_hive.rules import run_key_persistence
    ev = _run_key_event(r"C:\Users\bob\AppData\Roaming\svchost.exe")
    a = run_key_persistence(ev)
    assert a is not None
    assert a.confidence == 0.6


def test_rule_ignores_program_files_entry():
    from spectre.modules.registry_hive.rules import run_key_persistence
    from spectre.core.base import NormEvent
    ev = NormEvent(artifact_type="registry_run", timestamp="", source_file="h",
                   record_id="1", data={
                       "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                       "value_name": "Vendor",
                       "value_data": r"C:\Program Files\Vendor\agent.exe --daemon",
                       "hive": "SOFTWARE"})
    assert run_key_persistence(ev) is None


def test_recognizer_claims_extensionless_hive(tmp_path):
    from spectre.modules.registry_hive.recognizer import RECOGNIZERS
    p = tmp_path / "SYSTEM"
    p.write_bytes(b"regf" + b"\x00" * 128)
    score = RECOGNIZERS[0].match(p, "MS Windows registry file, NT/2000 or above")
    assert score > 0


def test_module_discovered():
    from spectre.modules import registry as reg
    mods = reg.discover()
    assert "registry_hive" in mods
    assert mods["registry_hive"].artifact_type == "registry_run"


def test_lastwrite_iso8601_format1(tmp_path):
    """LastWrite Time in ISO8601 UTC format (with Z suffix)."""
    from spectre.modules.registry_hive.normalize import normalize
    rip_output = """\
run v.20200511
Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time 2026-01-15 10:22:33Z
  Updater - C:\\Users\\bob\\AppData\\Roaming\\svchost.exe
"""
    out = tmp_path / "rip.txt"
    out.write_text(rip_output)
    handle = {"path": str(out), "artifact_type": "registry_run",
              "evidence_path": "/case/evidence/NTUSER.DAT", "result": "success"}
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].timestamp == "2026-01-15T10:22:33+00:00"
    assert events[0].data["lastwrite_raw"] == "2026-01-15 10:22:33Z"


def test_lastwrite_iso8601_format2(tmp_path):
    """LastWrite Time in RegRipper's day-name format."""
    from spectre.modules.registry_hive.normalize import normalize
    rip_output = """\
run v.20200511
Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time Mon Jan 15 10:22:33 2026 (UTC)
  Updater - C:\\Users\\bob\\AppData\\Roaming\\svchost.exe
"""
    out = tmp_path / "rip.txt"
    out.write_text(rip_output)
    handle = {"path": str(out), "artifact_type": "registry_run",
              "evidence_path": "/case/evidence/NTUSER.DAT", "result": "success"}
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].timestamp == "2026-01-15T10:22:33+00:00"
    assert events[0].data["lastwrite_raw"] == "Mon Jan 15 10:22:33 2026 (UTC)"


def test_lastwrite_unparseable(tmp_path):
    """LastWrite Time in unparseable format → empty timestamp."""
    from spectre.modules.registry_hive.normalize import normalize
    rip_output = """\
run v.20200511
Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time garbage-value
  Updater - C:\\Users\\bob\\AppData\\Roaming\\svchost.exe
"""
    out = tmp_path / "rip.txt"
    out.write_text(rip_output)
    handle = {"path": str(out), "artifact_type": "registry_run",
              "evidence_path": "/case/evidence/NTUSER.DAT", "result": "success"}
    events = normalize(handle)
    assert len(events) == 1
    assert events[0].timestamp == ""
    assert events[0].data["lastwrite_raw"] == "garbage-value"
