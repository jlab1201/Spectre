r"""Registry follow-ups to W5-2.

1. ShimCache/Amcache installer noise: an installer's own extraction
   directory (WiX Burn `{GUID}\.be|.cr\`, the VC++ `{GUID}~setup\` bootstrap,
   VMware Tools' `vmware-<user>\<hex>\`, Inno/InstallShield `*.tmp\`) holding
   a known installer filename is DEMOTED (lower confidence + an explicit
   note), never dropped. Neither half alone demotes: a "vcredist" name
   straight in Temp, or an unknown name inside a Burn dir, stays lead-grade.
2. The mitre-map stubs: `shimcache-anti-forensics` is implemented on known
   wiper/timestomp tool names; `amcache-unknown-hash` and
   `shimcache-unknown-binary` need a reputation/known-good source Spectre
   does not have offline, so they are removed rather than faked.
"""
from __future__ import annotations

import yaml

from spectre.core.base import NormEvent

LEAD = 0.4


def _ev(path: str, art: str = "shimcache", mtime: str = "2025-03-20T08:51:39+00:00"):
    low = path.lower()
    return NormEvent(art, mtime, "SYSTEM", f"{art}-{abs(hash(path))}", data={
        "path": path, "path_lower": low,
        "basename_lower": low.replace("\\", "/").rsplit("/", 1)[-1],
        "file_mtime": mtime, "hive": "SYSTEM", "sha1": "ab" * 20})


def _fire(ev, rule_id):
    from spectre.modules.registry_hive import RULES
    (rule,) = [r for r in RULES if r.rule_id == rule_id]
    return rule.predicate(ev) if rule.artifact_type == ev.artifact_type else None


# ── 1. installer-noise demotion ──────────────────────────────────────────

_INSTALLER_NOISE = [
    r"C:\Windows\Temp\{40B5D875-E4D6-49CB-A115-01B50B447127}\.cr\vcredist_x86.exe",
    r"C:\Windows\Temp\{38C6F32D-132F-48E4-A85F-7CF8904CF096}\.be\VC_redist.x64.exe",
    r"C:\Users\bob\AppData\Local\Temp\{1FF5D624-5515-4343-837A-E54C101573E6}~setup\vcredist_x64.exe",
    r"C:\Users\bob\AppData\Local\Temp\vmware-bob\000032f6\setup.exe",
    r"C:\Users\bob\AppData\Local\Temp\vmware-bob\000032f6\setup64.exe",
    r"C:\Users\bob\AppData\Local\Temp\is-K3B9Q.tmp\setup.exe",
]


def test_installer_extraction_noise_is_demoted_not_dropped():
    for p in _INSTALLER_NOISE:
        a = _fire(_ev(p), "shimcache-suspicious-path")
        assert a is not None, p                      # still emitted
        assert a.confidence < LEAD, p                 # but below lead grade
        assert "installer-context-demoted" in a.title, p
        assert "installer-context-demoted" in a.summary, p
        assert a.mitre == ["T1105"]


def test_real_leads_directly_in_temp_stay_lead_grade():
    for p in (r"C:\Users\bob\AppData\Local\Temp\storePwd.exe",
              r"C:\Users\bob\AppData\Local\Temp\upgrader.exe"):
        a = _fire(_ev(p), "shimcache-suspicious-path")
        assert a is not None and a.confidence == LEAD, p
        assert "demoted" not in a.title


def test_installer_name_alone_does_not_demote():
    # Malware named like an installer, but not in an installer's extraction dir.
    for p in (r"C:\Users\bob\AppData\Local\Temp\vcredist_x64.exe",
              r"C:\Users\bob\AppData\Local\Temp\setup.exe",
              r"C:\Users\Public\vc_redist.x64.exe"):
        a = _fire(_ev(p), "shimcache-suspicious-path")
        assert a is not None and a.confidence == LEAD, p


def test_extraction_dir_alone_does_not_demote():
    for p in (r"C:\Windows\Temp\{40B5D875-E4D6-49CB-A115-01B50B447127}\.cr\evil.exe",
              r"C:\Users\bob\AppData\Local\Temp\vmware-bob\000032f6\beacon.exe",
              r"C:\Users\bob\AppData\Local\Temp\is-K3B9Q.tmp\payload.exe"):
        a = _fire(_ev(p), "shimcache-suspicious-path")
        assert a is not None and a.confidence == LEAD, p


def test_offensive_tool_is_never_demoted():
    a = _fire(_ev(r"C:\Windows\Temp\{40B5D875-E4D6-49CB-A115-01B50B447127}\.be\psexec.exe"),
              "shimcache-suspicious-path")
    assert a is not None and a.confidence >= 0.5
    assert "demoted" not in a.title


def test_amcache_gets_the_same_demotion():
    a = _fire(_ev(_INSTALLER_NOISE[0].lower(), art="amcache"), "amcache-suspicious-path")
    assert a is not None and a.confidence < LEAD
    assert "installer-context-demoted" in a.title


def test_installer_context_helper():
    from spectre.core import markers
    assert markers.installer_extraction_context(_INSTALLER_NOISE[0].lower())
    assert markers.installer_extraction_context(
        r"c:\users\bob\appdata\local\temp\storepwd.exe") is None
    # Program Files Edge-update temp is not staging at all; helper agnostic.
    assert markers.installer_extraction_context("vcredist_x64.exe") is None


# ── 2. shimcache-anti-forensics ──────────────────────────────────────────

def test_anti_forensics_fires_on_known_wiper_and_timestomp_names():
    wipe = _fire(_ev(r"C:\Tools\sdelete64.exe"), "shimcache-anti-forensics")
    stomp = _fire(_ev(r"C:\Users\bob\Downloads\SetMACE.exe"), "shimcache-anti-forensics")
    clean = _fire(_ev(r"C:\Program Files\CCleaner\CCleaner64.exe"), "shimcache-anti-forensics")
    assert wipe and stomp and clean
    assert wipe.mitre == ["T1070.004"]
    assert clean.mitre == ["T1070.004"]
    assert stomp.mitre == ["T1070.006"]
    for a in (wipe, stomp, clean):
        text = (a.title + " " + a.summary).lower()
        assert "executed" not in text and "execution of" not in text
        assert "records" in a.title.lower()
        assert a.confidence < 0.6
        assert a.iocs["filepath"] == [a.event.data["path"]]


def test_anti_forensics_ignores_ordinary_binaries():
    for p in (r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\cipher.exe",
              r"C:\Windows\System32\wevtutil.exe", r"C:\Tools\deleter.exe"):
        assert _fire(_ev(p), "shimcache-anti-forensics") is None, p


def test_anti_forensics_only_on_shimcache():
    assert _fire(_ev(r"C:\Tools\sdelete.exe", art="amcache"),
                 "shimcache-anti-forensics") is None


# ── stubs: implemented or removed, never faked ───────────────────────────

def _map():
    from spectre.config import MITRE_MAP_PATH
    return yaml.safe_load(MITRE_MAP_PATH.read_text())["rules"]


def test_unimplementable_stubs_are_removed_from_the_map():
    rules = _map()
    assert "amcache-unknown-hash" not in rules
    assert "shimcache-unknown-binary" not in rules


def test_anti_forensics_rule_is_real_and_within_the_map():
    from spectre.modules.registry_hive import RULES
    (rule,) = [r for r in RULES if r.rule_id == "shimcache-anti-forensics"]
    assert set(rule.mitre) <= set(_map()["shimcache-anti-forensics"]["allowed"])
    assert rule.metadata and rule.metadata.false_positives


def test_removed_stubs_are_documented_in_rules_docstring():
    from spectre.modules.registry_hive import rules
    doc = rules.__doc__
    assert "amcache-unknown-hash" in doc and "shimcache-unknown-binary" in doc
