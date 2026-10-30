"""Corroboration core: distinct tools detecting the same claim raise confidence.

These exercise the pure grouping/scoring layer (no I/O), the seam where
dual-engine cross-validation is decided.
"""

from spectre.core.base import NormEvent, Anchor
from spectre.pipeline.correlation import corroborate, score_corroboration


def _anchor(rule_id, dedup_key, source_tool, artifact_type="memory_pslist"):
    ev = NormEvent(
        artifact_type=artifact_type,
        timestamp="",
        source_file="/cases/x/evidence/dump.raw",
        record_id="0",
        source_tool=source_tool,
    )
    return Anchor(rule_id=rule_id, artifact_type=artifact_type, event=ev,
                  title=f"{rule_id} hit", dedup_key=dedup_key)


def test_score_corroboration_matches_v6_formula():
    assert score_corroboration(0) == ("DROPPED", 0.0)
    assert score_corroboration(1) == ("INFERRED", 0.50)
    assert score_corroboration(2) == ("CONFIRMED", 0.75)
    assert score_corroboration(3) == ("CONFIRMED", 1.00)
    assert score_corroboration(7) == ("CONFIRMED", 1.00)  # capped at 3


def test_two_engines_same_claim_corroborate_into_one_group():
    anchors = [
        _anchor("MEM-MASQ-01", "pid:4012", "volatility3"),
        _anchor("MEM-MASQ-01", "pid:4012", "memprocfs"),
    ]
    groups = corroborate(anchors)
    assert len(groups) == 1
    g = groups[0]
    assert g.sources == 2
    assert g.cross_validated is True
    assert g.source_labels == ["memprocfs/memory_pslist",
                               "volatility3/memory_pslist"]


def test_single_source_is_not_cross_validated():
    groups = corroborate([_anchor("MEM-MASQ-01", "pid:4012", "volatility3")])
    assert len(groups) == 1
    assert groups[0].sources == 1
    assert groups[0].cross_validated is False


def test_same_engine_duplicate_counts_as_one_source():
    # Two hits of the same rule from the SAME engine (e.g. one env var across
    # many processes) must NOT inflate the source count to 2.
    anchors = [
        _anchor("MEM-ENV-01", "VAR=secret", "volatility3"),
        _anchor("MEM-ENV-01", "VAR=secret", "volatility3"),
    ]
    groups = corroborate(anchors)
    assert len(groups) == 1
    assert groups[0].sources == 1
    assert groups[0].cross_validated is False


def test_distinct_claims_stay_separate():
    anchors = [
        _anchor("MEM-MASQ-01", "pid:4012", "volatility3"),
        _anchor("MEM-MASQ-01", "pid:9001", "volatility3"),
    ]
    groups = corroborate(anchors)
    assert len(groups) == 2


def test_group_preserves_first_anchor_as_representative():
    a1 = _anchor("MEM-MASQ-01", "pid:4012", "volatility3")
    a2 = _anchor("MEM-MASQ-01", "pid:4012", "memprocfs")
    groups = corroborate([a1, a2])
    assert groups[0].representative is a1
    assert groups[0].members == [a1, a2]


# ── A7 Finding 1: pcap same-file, two-parser double-count ─────────────────
#
# The shipped default pcap engine runs Zeek AND retains a tcpdump gap-fill
# pass over the SAME evidence file in ONE extraction run (see
# modules/pcap/extract.py). Rules that read fields both engines populate
# identically (HTTP User-Agent / Host header) fire on BOTH engines' events
# for the identical transaction, producing two anchors with the same
# rule_id/dedup_key but different source_tool. Those must NOT count as two
# independent sources -- one evidence file parsed twice in one run is not
# independent corroboration.

def _pcap_ev(tool):
    e = NormEvent(artifact_type="pcap_http", timestamp="2026-01-01 00:00:00",
                  source_file="x.pcap", record_id="1")
    e.source_tool = tool
    return e


def test_pcap_same_file_zeek_and_tcpdump_is_one_source_not_two():
    a1 = Anchor(rule_id="pcap-c2-protocol", artifact_type="pcap_http", event=_pcap_ev("zeek"),
                title="C2 UA match (1.2.3.4)", dedup_key="1.2.3.4", confidence=0.85)
    a2 = Anchor(rule_id="pcap-c2-protocol", artifact_type="pcap_http", event=_pcap_ev("tcpdump"),
                title="C2 UA match (1.2.3.4)", dedup_key="1.2.3.4", confidence=0.85)
    g = corroborate([a1, a2])[0]

    assert g.sources == 1, (
        "one pcap file parsed by zeek AND tcpdump in one run must be ONE "
        "source, not two -- else INFERRED wrongly flips to CONFIRMED with "
        "no independent evidence"
    )
    assert g.cross_validated is False
    assert score_corroboration(g.sources) == ("INFERRED", 0.50)
    # Both raw tool labels are still visible for transparency, even though
    # they collapse to one source.
    assert g.source_labels == ["tcpdump/pcap_http", "zeek/pcap_http"]


def test_pcap_same_family_different_files_still_two_sources():
    # Same claim, same rule/dedup_key, but from TWO DIFFERENT pcap files --
    # this genuinely is two independent pieces of evidence and must still
    # count as two sources.
    e1 = NormEvent(artifact_type="pcap_http", timestamp="2026-01-01 00:00:00",
                   source_file="a.pcap", record_id="1", source_tool="zeek")
    e2 = NormEvent(artifact_type="pcap_http", timestamp="2026-01-01 00:00:00",
                   source_file="b.pcap", record_id="1", source_tool="tcpdump")
    a1 = Anchor(rule_id="pcap-c2-protocol", artifact_type="pcap_http", event=e1,
                title="C2 UA match (1.2.3.4)", dedup_key="1.2.3.4", confidence=0.85)
    a2 = Anchor(rule_id="pcap-c2-protocol", artifact_type="pcap_http", event=e2,
                title="C2 UA match (1.2.3.4)", dedup_key="1.2.3.4", confidence=0.85)
    g = corroborate([a1, a2])[0]

    assert g.sources == 2
    assert g.cross_validated is True


def test_memory_dual_engine_same_file_still_two_sources():
    # Sanity guard for A7 Finding 5: volatility3 + MemProcFS over the SAME
    # memory image is genuine, explicitly-designed dual-engine corroboration
    # (different codebases/algorithms; see modules/memory/__init__.py's
    # default engine="both"). It must NOT be collapsed by the pcap fix
    # above, even though it also shares one source_file/artifact_type/
    # dedup_key across two source_tool values.
    e1 = NormEvent(artifact_type="memory_pslist", timestamp="", record_id="0",
                   source_file="/cases/x/evidence/dump.raw", source_tool="volatility3")
    e2 = NormEvent(artifact_type="memory_pslist", timestamp="", record_id="0",
                   source_file="/cases/x/evidence/dump.raw", source_tool="memprocfs")
    a1 = Anchor(rule_id="MEM-MASQ-01", artifact_type="memory_pslist", event=e1,
                title="masquerade", dedup_key="pid:4012")
    a2 = Anchor(rule_id="MEM-MASQ-01", artifact_type="memory_pslist", event=e2,
                title="masquerade", dedup_key="pid:4012")
    g = corroborate([a1, a2])[0]

    assert g.sources == 2
    assert g.cross_validated is True


def test_beacon_scored_twice_over_same_capture_is_one_source():
    """Beacon-scorer guard (companion to the memory dual-engine test above).

    A statistical re-score of the SAME capture is not a second source. Zeek
    and tcpdump are two textual renderings of one packet stream, so a beacon
    seen through both must stay at sources==1 (INFERRED), never be promoted
    to CONFIRMED. This is the property that makes it mandatory for
    pcap-beacon to keep ONE rule_id: corroborate() groups by
    (rule_id, dedup_key), so splitting the scorer into a second rule_id
    would emit a duplicate finding about the same host rather than
    corroborate the original.

    Contrast with volatility3 + MemProcFS above: those are unrelated
    codebases independently walking kernel structures, which is why they are
    deliberately NOT members of the pcap-capture family.
    """
    ev_zeek = NormEvent(artifact_type="pcap_timing", timestamp="",
                        source_file="/cases/x/evidence/cap.pcap",
                        record_id="45.77.12.9", source_tool="zeek:conn.log")
    ev_tcpdump = NormEvent(artifact_type="pcap_timing", timestamp="",
                           source_file="/cases/x/evidence/cap.pcap",
                           record_id="45.77.12.9", source_tool="tcpdump")
    a1 = Anchor(rule_id="pcap-beacon", artifact_type="pcap_timing",
                event=ev_zeek, title="C2 Beacon detected: 45.77.12.9",
                dedup_key="45.77.12.9", confidence=0.95)
    a2 = Anchor(rule_id="pcap-beacon", artifact_type="pcap_timing",
                event=ev_tcpdump, title="C2 Beacon detected: 45.77.12.9",
                dedup_key="45.77.12.9", confidence=0.95)

    groups = corroborate([a1, a2])
    assert len(groups) == 1, "same rule_id + dedup_key must group into one claim"
    assert groups[0].sources == 1
    assert groups[0].cross_validated is False
    assert score_corroboration(groups[0].sources) == ("INFERRED", 0.50)


def test_beacon_over_two_distinct_captures_is_two_sources():
    """The family collapse is scoped by source_file, so the same beacon
    independently present in two genuinely different captures (e.g. two
    collection points) still counts as two."""
    e1 = NormEvent(artifact_type="pcap_timing", timestamp="",
                   source_file="/cases/x/evidence/edge.pcap",
                   record_id="45.77.12.9", source_tool="zeek:conn.log")
    e2 = NormEvent(artifact_type="pcap_timing", timestamp="",
                   source_file="/cases/x/evidence/core.pcap",
                   record_id="45.77.12.9", source_tool="zeek:conn.log")
    a1 = Anchor(rule_id="pcap-beacon", artifact_type="pcap_timing", event=e1,
                title="C2 Beacon detected: 45.77.12.9", dedup_key="45.77.12.9")
    a2 = Anchor(rule_id="pcap-beacon", artifact_type="pcap_timing", event=e2,
                title="C2 Beacon detected: 45.77.12.9", dedup_key="45.77.12.9")
    g = corroborate([a1, a2])[0]
    assert g.sources == 2
