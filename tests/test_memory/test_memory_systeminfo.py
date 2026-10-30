"""test_memory_systeminfo.py — windows.info system-profile signal.

Track D (gold case 004): the image is attributed to a host/OS profile via
`windows.info` (NTBuildLab, hostname, SystemTime). This is a PROFILE SIGNAL,
NOT a finding — the inviolable rule (deterministic core produces findings;
the AI only explains them) means `memory_systeminfo` must never be wired to
a detection rule. These tests pin: (1) extract.py now runs windows.info.Info,
(2) normalize() turns its Variable/Value rows into ONE system-profile
NormEvent carrying OS build + hostname + capture time, and (3) no rule in
the memory rule pack can ever fire against a memory_systeminfo event.
"""

import json
import tempfile

from spectre.modules.memory.extract import PLUGINS
from spectre.modules.memory.normalize import normalize
from spectre.modules.memory.rules import RULES


def _write_handle(rows, artifact):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(rows, tmp)
    tmp.close()
    return {"path": tmp.name, "artifact_type": artifact, "evidence_path": "mem.raw"}


# Shape volatility3's windows.info.Info actually emits: a flat list of
# {"Variable": ..., "Value": ...} rows, not a single dict.
_INFO_ROWS = [
    {"Variable": "Kernel Base", "Value": "0xf80612a1f000"},
    {"Variable": "DTB", "Value": "0x1aa000"},
    {"Variable": "Symbols", "Value": "file:///symbols/windows.json.xz"},
    {"Variable": "Is64Bit", "Value": "True"},
    {"Variable": "NtBuildLab", "Value": "7601.24544.amd64fre.win7sp1_ldr.191010-1503"},
    {"Variable": "NtSystemRoot", "Value": r"C:\Windows"},
    {"Variable": "NtProductType", "Value": "NtProductWinNt"},
    {"Variable": "NtMajorVersion", "Value": "6"},
    {"Variable": "NtMinorVersion", "Value": "1"},
    {"Variable": "SystemTime", "Value": "2026-07-01 03:15:20"},
    {"Variable": "KeNumberProcessors", "Value": "2"},
    {"Variable": "MachineType", "Value": "34404"},
    {"Variable": "Hostname", "Value": "Jaffa"},
]


# ── extract.py wiring ────────────────────────────────────────────────
def test_windows_info_plugin_registered():
    assert PLUGINS.get("windows.info.Info") == "memory_systeminfo"


# ── normalize() ──────────────────────────────────────────────────────
def test_normalize_systeminfo_produces_single_profile_event():
    events = normalize(_write_handle(_INFO_ROWS, "memory_systeminfo"))
    assert len(events) == 1
    e = events[0]
    assert e.artifact_type == "memory_systeminfo"
    assert e.data["os_build"] == "7601.24544.amd64fre.win7sp1_ldr.191010-1503"
    assert e.data["hostname"] == "Jaffa"
    assert e.host == "jaffa"
    assert e.data["system_time"] == "2026-07-01 03:15:20"
    assert e.timestamp == "2026-07-01 03:15:20"


def test_normalize_systeminfo_falls_back_to_major_minor_when_no_buildlab():
    rows = [r for r in _INFO_ROWS if r["Variable"] != "NtBuildLab"]
    events = normalize(_write_handle(rows, "memory_systeminfo"))
    assert events[0].data["os_build"] == "6.1"


def test_normalize_systeminfo_no_hostname_row_is_blank_not_fabricated():
    rows = [r for r in _INFO_ROWS if r["Variable"] != "Hostname"]
    events = normalize(_write_handle(rows, "memory_systeminfo"))
    assert events[0].data["hostname"] == ""
    assert events[0].host == ""


def test_normalize_systeminfo_empty_rows_produces_no_event():
    events = normalize(_write_handle([], "memory_systeminfo"))
    assert events == []


# ── the inviolable rule: no rule may consume memory_systeminfo ────────
def test_no_rule_targets_memory_systeminfo_artifact_type():
    """The deterministic core must never emit a finding from this profile
    signal. Guard at the rule-registration level: if a future change wires
    a rule to memory_systeminfo, this test fails loudly."""
    offending = [r.rule_id for r in RULES if r.artifact_type == "memory_systeminfo"]
    assert offending == []


def test_no_rule_predicate_fires_on_systeminfo_event():
    """Belt-and-suspenders: even if a rule were mistakenly pointed at this
    artifact_type, run every predicate against the normalized event and
    confirm none produce an Anchor (finding)."""
    events = normalize(_write_handle(_INFO_ROWS, "memory_systeminfo"))
    assert len(events) == 1
    for rule in RULES:
        anchor = rule.predicate(events[0])
        assert anchor is None, (
            f"rule {rule.rule_id} fired on a memory_systeminfo event — "
            "profile signals must never produce findings"
        )
