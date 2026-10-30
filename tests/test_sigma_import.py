"""test_sigma_import.py — Sigma -> native Rule compilation (Phase 3).

`compile_sigma(yaml_text) -> Rule` is the community on-ramp: it turns a Sigma
process_creation rule into the same native `Rule` object every other rule
compiles to (one engine underneath). It supports a documented common subset
and — crucially — REJECTS anything outside that subset with a clear error,
rather than best-guessing and silently miscompiling into a wrong finding.
"""

import textwrap

import pytest

from spectre.core.base import NormEvent
from spectre.core.sigma_import import SigmaUnsupportedError, compile_sigma


def _evt(**data) -> NormEvent:
    return NormEvent("process_creation", "t", "f", "1", data=data)


RUNDLL_SIGMA = textwrap.dedent("""
    title: Rundll32 Loading DLL From Temp
    id: 11111111-2222-3333-4444-555555555555
    status: experimental
    level: high
    references:
        - https://attack.mitre.org/techniques/T1218/011/
    tags:
        - attack.defense_evasion
        - attack.t1218.011
    falsepositives:
        - installers staging a DLL in temp
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            Image|endswith: '\\rundll32.exe'
            CommandLine|contains: '.dll'
        condition: selection
""")


def test_compiles_to_native_rule_with_metadata():
    rule = compile_sigma(RUNDLL_SIGMA)
    assert rule.artifact_type == "process_creation"
    md = rule.metadata
    assert md.rule_format == "sigma"
    assert md.name == "Rundll32 Loading DLL From Temp"
    assert md.severity == "high"
    assert md.uuid == "11111111-2222-3333-4444-555555555555"
    assert md.references == ["https://attack.mitre.org/techniques/T1218/011/"]
    assert "attack.t1218.011" in md.tags
    assert md.false_positives == ["installers staging a DLL in temp"]


def test_mitre_derived_from_attack_tags():
    rule = compile_sigma(RUNDLL_SIGMA)
    # the rule's own attack.* technique tags become its candidate MITRE
    assert rule.mitre == ["T1218.011"]


def test_fires_on_malicious_silent_on_benign():
    rule = compile_sigma(RUNDLL_SIGMA)
    hit = _evt(image="C:\\Windows\\System32\\rundll32.exe",
               command_line="rundll32.exe C:\\Temp\\evil.dll,Start")
    miss_wrong_image = _evt(image="C:\\Windows\\explorer.exe",
                            command_line="explorer.exe C:\\Temp\\evil.dll")
    miss_no_dll = _evt(image="C:\\Windows\\System32\\rundll32.exe",
                       command_line="rundll32.exe")
    assert rule.predicate(hit) is not None
    assert rule.predicate(miss_wrong_image) is None
    assert rule.predicate(miss_no_dll) is None


def test_anchor_carries_rule_identity():
    rule = compile_sigma(RUNDLL_SIGMA)
    a = rule.predicate(_evt(image="x\\rundll32.exe", command_line="a .dll b"))
    assert a.rule_id == rule.rule_id
    assert a.mitre == ["T1218.011"]
    assert a.artifact_type == "process_creation"


def test_list_value_is_or():
    y = textwrap.dedent("""
        title: LOLBin
        logsource:
            category: process_creation
        detection:
            selection:
                Image|endswith:
                    - '\\rundll32.exe'
                    - '\\regsvr32.exe'
            condition: selection
    """)
    rule = compile_sigma(y)
    assert rule.predicate(_evt(image="a\\regsvr32.exe")) is not None
    assert rule.predicate(_evt(image="a\\rundll32.exe")) is not None
    assert rule.predicate(_evt(image="a\\notepad.exe")) is None


def test_all_modifier_is_and():
    y = textwrap.dedent("""
        title: Both substrings
        logsource:
            category: process_creation
        detection:
            selection:
                CommandLine|contains|all:
                    - '-enc'
                    - 'bypass'
            condition: selection
    """)
    rule = compile_sigma(y)
    assert rule.predicate(_evt(command_line="powershell -enc xx -ExecutionPolicy bypass")) is not None
    assert rule.predicate(_evt(command_line="powershell -enc xx")) is None


def test_and_not_filter_condition():
    y = textwrap.dedent("""
        title: sel and not filter
        logsource:
            category: process_creation
        detection:
            selection:
                Image|endswith: '\\powershell.exe'
            filter:
                CommandLine|contains: 'Get-Help'
            condition: selection and not filter
    """)
    rule = compile_sigma(y)
    assert rule.predicate(_evt(image="a\\powershell.exe", command_line="iwr evil")) is not None
    assert rule.predicate(_evt(image="a\\powershell.exe", command_line="Get-Help")) is None


def test_one_of_selection_glob():
    y = textwrap.dedent("""
        title: one of
        logsource:
            category: process_creation
        detection:
            selection_a:
                Image|endswith: '\\rundll32.exe'
            selection_b:
                Image|endswith: '\\regsvr32.exe'
            condition: 1 of selection_*
    """)
    rule = compile_sigma(y)
    assert rule.predicate(_evt(image="x\\rundll32.exe")) is not None
    assert rule.predicate(_evt(image="x\\regsvr32.exe")) is not None
    assert rule.predicate(_evt(image="x\\cmd.exe")) is None


# ── Honest failure: out-of-subset rules are rejected, never miscompiled ──

def test_rejects_unsupported_logsource():
    y = textwrap.dedent("""
        title: dns
        logsource:
            category: dns_query
        detection:
            selection:
                QueryName|contains: 'evil'
            condition: selection
    """)
    with pytest.raises(SigmaUnsupportedError):
        compile_sigma(y)


def test_rejects_unmapped_field():
    y = textwrap.dedent("""
        title: weird field
        logsource:
            category: process_creation
        detection:
            selection:
                TotallyUnknownField|contains: 'x'
            condition: selection
    """)
    with pytest.raises(SigmaUnsupportedError):
        compile_sigma(y)


def test_rejects_unsupported_modifier():
    y = textwrap.dedent("""
        title: base64 modifier
        logsource:
            category: process_creation
        detection:
            selection:
                CommandLine|base64offset|contains: 'x'
            condition: selection
    """)
    with pytest.raises(SigmaUnsupportedError):
        compile_sigma(y)


def test_rejects_exotic_condition():
    y = textwrap.dedent("""
        title: exotic
        logsource:
            category: process_creation
        detection:
            selection:
                Image|endswith: '\\x.exe'
            condition: selection | count() > 5
    """)
    with pytest.raises(SigmaUnsupportedError):
        compile_sigma(y)



@pytest.mark.parametrize("replacement", ["", "level: bogus\n"])
def test_unknown_or_missing_level_is_unrated_not_medium(replacement):
    """TB-port T4: an absent/unknown Sigma level must not be coerced to
    "medium" — the rule author never assessed it (UNRATED at display)."""
    assert "level: high\n" in RUNDLL_SIGMA
    rule = compile_sigma(RUNDLL_SIGMA.replace("level: high\n", replacement))
    assert rule.metadata.severity is None
