"""test_rule_metadata.py — the RuleMetadata identity card on a Rule.

RuleMetadata is the defensibility card every rule can carry: who wrote it,
its severity, references that justify it, known false positives, tags, and
the format it was authored in (python|sigma). It is purely descriptive —
it never affects what a predicate matches — and it is optional, so existing
Rules that omit it keep working unchanged.
"""

from spectre.core.base import NormEvent, Rule, RuleMetadata


def test_metadata_is_optional_on_rule():
    # A Rule built the legacy way (no metadata) is still valid.
    r = Rule("r-1", "process_creation", lambda e: None, ["T1059"], "desc")
    assert r.metadata is None


def test_metadata_carries_the_defensibility_card():
    md = RuleMetadata(
        uuid="11111111-2222-3333-4444-555555555555",
        name="rundll32 from temp",
        author="blue-team",
        date="2026-06-28",
        version="1.0",
        references=["https://attack.mitre.org/techniques/T1218/011/"],
        false_positives=["legit installers staging DLLs in %TEMP%"],
        severity="high",
        tags=["attack.defense_evasion", "attack.t1218.011"],
        rule_format="python",
        rule_source="modules/evtx/rules.py",
    )
    r = Rule("rundll32-from-temp", "process_creation", lambda e: None,
             ["T1218.011"], "desc", metadata=md)
    assert r.metadata.severity == "high"
    assert r.metadata.rule_format == "python"
    assert "attack.t1218.011" in r.metadata.tags
    assert r.metadata.references[0].startswith("https://")


def test_metadata_defaults_are_safe_empty_collections():
    md = RuleMetadata(name="minimal")
    assert md.references == []
    assert md.false_positives == []
    assert md.tags == []
    # TB-port T4: unset severity is None (UNRATED at display), never an
    # implied "medium" the rule author did not assess.
    assert md.severity is None
    assert md.rule_format == "python"
    assert md.uuid == ""


def test_metadata_does_not_alter_predicate_behavior():
    # The card is descriptive only; the predicate still decides matches.
    hit = NormEvent("process_creation", "t", "f", "1", data={"x": 1})

    def pred(e):
        return None if e.data.get("x") else "matched"

    r = Rule("r", "process_creation", pred, [], "", metadata=RuleMetadata())
    assert r.predicate(hit) is None
    assert r.predicate(NormEvent("process_creation", "t", "f", "2")) == "matched"
