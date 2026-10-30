from spectre.core.base import Anchor, NormEvent
from spectre.pipeline.correlation import corroborate


def _anchor(ts):
    e = NormEvent(artifact_type="drsuapi_call", timestamp=ts, source_file="ev.pcap",
                  record_id=ts, host="", data={})
    return Anchor(rule_id="smb-drsuapi-opnum", artifact_type="drsuapi_call",
                  event=e, title="DsCrackNames", dedup_key="opnum12")


def test_group_occurrence_count_and_span_follow_evidence_order():
    anchors = [_anchor("t-first"), _anchor("t-mid"), _anchor("t-last")]
    groups = corroborate(anchors)
    assert len(groups) == 1
    g = groups[0]
    assert g.occurrence_count == 3
    assert g.first_seen == "t-first"     # members[0], not lexical min
    assert g.last_seen == "t-last"       # members[-1], not lexical max


def test_singleton_group_span_is_the_one_event():
    g = corroborate([_anchor("only")])[0]
    assert g.occurrence_count == 1
    assert g.first_seen == "only"
    assert g.last_seen == "only"
