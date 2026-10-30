"""Rule severity coverage. pcap-payload-host now declares a rule-assessed
severity. Any registered rule that still lacks one is listed EXPLICITLY here
(so a new unrated rule is a visible decision, not a silent UNRATED); no
severity is invented for them."""
from spectre.modules import registry

# Deliberately unrated: identity context, not a detection (mitre=[]).
KNOWN_UNRATED = {"pcap-host-identity"}


def _rules():
    return {r.rule_id: r for m in registry.discover().values() for r in m.rules}


def test_pcap_payload_host_is_high_like_its_t1105_sibling():
    rules = _rules()
    md = rules["pcap-payload-host"].metadata
    assert md is not None and md.severity == "high"
    # same technique and tier as pcap-staging-download (T1105, high)
    assert rules["pcap-staging-download"].metadata.severity == md.severity
    # metadata added for severity only — rule evaluation is unchanged
    assert md.required_fields == []


def test_only_known_rules_lack_a_severity():
    unrated = {rid for rid, r in _rules().items()
               if r.metadata is None or not r.metadata.severity}
    assert unrated == KNOWN_UNRATED
