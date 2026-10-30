"""Cross-check the pcap beacon scorer against RITA v5.1.2 on real evidence.

Unit tests prove the scorer computes what we said it computes. They cannot tell
us whether *what we said* is the right thing to compute. This module answers the
Daubert "known error rate" question by comparing our output, on a real XLoader
infection capture, against the published reference tool for the same job.

The fixture (``tests/fixtures/rita-xloader-crosscheck.json``) records RITA's
``threat_mixtape`` table verbatim alongside the per-destination-IP interval
series Zeek produced from the same pcap, so this runs with no pcap, no Zeek, no
Docker and no ClickHouse.

Two grouping conventions are being compared, and the difference is the point:

* RITA groups candidates by **SNI / HTTP Host** (``beacon_type='sni'``).
* ``pcap-beacon`` groups by **destination IP** from ``conn.log``.

``ip_to_fqdn`` in the fixture is the join key, taken from Zeek ``http.log``
Host headers on the same capture.

The honest summary of the comparison, asserted below:

1. Every beacon Spectre reports is also a beacon RITA reports. No Spectre
   finding is unknown to RITA.
2. RITA's top-scored beacon is one Spectre finds. Rank agreement is *not*
   claimed — see ``test_ritas_top_beacon_is_detected``.
3. RITA reports 12 threat-scored beacons; Spectre reports 4. Investigating that
   gap produced the substantive result of this cross-check: the misses are not
   aperiodic traffic. ``normalize_zeek_beacon`` builds its series from every row
   of ``conn.log``, including connections that never completed, and those
   attempts shred the interval series. Restricted to established connections,
   five of the eight misses collapse onto the true ~206 s XLoader period.
   The shipped rule does not do that filtering; the measurement is pinned here.
4. Spectre produces nothing for the benign telemetry endpoints RITA scores but
   does not treat as threats.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spectre.modules.pcap.beacon_score import MIN_SAMPLES, score_beacon

_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "rita-xloader-crosscheck.json"


@pytest.fixture(scope="module")
def crosscheck() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scored(crosscheck: dict) -> dict[str, dict]:
    """score_beacon() over every recorded per-IP interval series."""
    return {
        ip: score_beacon(intervals)
        for ip, intervals in crosscheck["spectre_intervals_by_ip"].items()
    }


def test_scorer_reproduces_the_shipped_findings(crosscheck, scored):
    """The recorded intervals must score exactly the IPs the pipeline emitted.

    This is the anchor for everything else here: if it fails, the fixture has
    drifted from the rule and no other assertion in this module means anything.
    """
    flagged = {ip for ip, s in scored.items() if s["confidence"] > 0.0}
    assert flagged == set(crosscheck["spectre_findings"])


def test_every_spectre_beacon_is_also_a_rita_beacon(crosscheck, scored):
    """No Spectre finding is invisible to the reference tool."""
    rita_fqdns = {row["fqdn"] for row in crosscheck["rita_beacons"]}
    rita_fqdns |= {row["fqdn"] for row in crosscheck["rita_scored_but_not_threat"]}

    for ip in crosscheck["spectre_findings"]:
        fqdn = crosscheck["ip_to_fqdn"][ip]
        assert fqdn in rita_fqdns, f"{ip} ({fqdn}) has no counterpart in RITA's output"


def test_ritas_top_beacon_is_detected(crosscheck, scored):
    """RITA's highest-scored beacon is one Spectre finds.

    Note what is *not* claimed: rank agreement. RITA emits a continuous
    beacon_score and orders by it; ``score_beacon`` emits a banded confidence and
    puts all four hits in the same 0.95 band, so Spectre asserts no ordering over
    them. Ranking the flagged set by rCV ascending would in fact put
    66.235.200.146 first, not RITA's pick — because rCV rewards the tight ~2.6 s
    burst cadence over the ~206 s sleep cycle. Neither ordering is wrong; they
    measure different things, and the rule only claims membership.
    """
    rita_top = max(crosscheck["rita_beacons"], key=lambda r: r["beacon_score"])["fqdn"]
    detected = {crosscheck["ip_to_fqdn"][ip] for ip in crosscheck["spectre_findings"]}
    assert rita_top in detected

    # And it is detected as the long-period C2 channel, not an intra-burst cadence.
    ip = next(k for k, v in crosscheck["ip_to_fqdn"].items() if v == rita_top)
    assert 200.0 < scored[ip]["median_interval"] < 215.0


def test_missed_beacons_are_ones_rita_also_scores_low_on_timing(crosscheck, scored):
    """Investigate the disagreement rather than waving it through.

    For every FQDN RITA threat-scores that Spectre has interval data for and did
    not flag, RITA's *timing* subscore must itself be weak. If RITA ever reports
    a cleanly-periodic beacon that we miss, that is a scoring defect and this
    test must fail.
    """
    by_fqdn = {row["fqdn"]: row for row in crosscheck["rita_beacons"]}
    missed = [
        (ip, crosscheck["ip_to_fqdn"][ip])
        for ip, s in scored.items()
        if s["confidence"] == 0.0 and crosscheck["ip_to_fqdn"][ip] in by_fqdn
    ]
    assert missed, "fixture should contain at least one investigated disagreement"

    for ip, fqdn in missed:
        ts_score = by_fqdn[fqdn]["ts_score"]
        assert ts_score < 0.5, (
            f"RITA calls {fqdn} timing-regular (ts_score={ts_score}) but "
            f"pcap-beacon rejected {ip} — that is a scoring defect, not a "
            f"coverage gap"
        )


def test_missed_beacons_carry_the_true_period_under_non_established_noise(
    crosscheck, scored
):
    """Name the actual cause of the misses: unfiltered connection attempts.

    This is the substantive result of the cross-check. ``normalize_zeek_beacon``
    builds its interval series from *every* row of ``conn.log``, including
    half-open (SH), reset (RSTO) and other (OTH) connections that never carried a
    request. www.qmrcumg.top is the clearest case: 97 connections to
    43.226.78.180, of which only 20 completed. Those 77 extra timestamps shred
    the interval series.

    Restricting the same captures to established connections collapses the missed
    hosts onto the genuine ~206 s XLoader period at rCV under 0.15 — they were
    periodic all along.

    The shipped rule does NOT do this filtering. The assertion below pins the
    measurement so the improvement is on the record, and so it cannot silently
    regress if someone changes the scorer.
    """
    established = crosscheck["established_only_intervals_by_ip"]
    rita_flagged = {row["fqdn"] for row in crosscheck["rita_beacons"]}

    recovered, still_missed = {}, set()
    for ip, s in scored.items():
        fqdn = crosscheck["ip_to_fqdn"][ip]
        if s["confidence"] > 0.0 or fqdn not in rita_flagged:
            continue
        clean = score_beacon(established[ip])
        if clean["confidence"] > 0.0:
            recovered[fqdn] = clean
        else:
            still_missed.add(fqdn)

    assert set(recovered) == {
        "www.365jia.cn",
        "www.viptaka.cloud",
        "www.rperformr.ru",
        "www.terraero.my",
        "www.goranstaxi.se",
    }

    for fqdn, clean in recovered.items():
        assert 195.0 < clean["median_interval"] < 220.0, (
            f"{fqdn} recovered at {clean['median_interval']:.1f}s, not the "
            f"~206s XLoader period"
        )
        assert clean["rcv"] < 0.15

    # www.qmrcumg.top does not recover, and the reason is on the record: 60 of its
    # 97 connections are half-open (SH) or OTH, so even the established subset is
    # too sparse to reconstruct the period. Pinned so a future claim of "the
    # filter recovers everything RITA finds" fails here.
    assert still_missed == {"www.qmrcumg.top"}


def test_established_filter_costs_one_true_positive(crosscheck, scored):
    """The filter is not free, and the cost is recorded rather than glossed.

    66.235.200.146 (www.knowledgeisnice.com) is a true positive today off 17
    intervals. Only 2 of its 18 connections reach SF — the rest are RSTO/RSTR —
    so the established subset falls to 9 intervals, one short of MIN_SAMPLES, and
    the beacon disappears. Its rCV stays excellent throughout; this is a
    sample-count casualty, not a scoring failure.

    Net effect on this capture is still 4 detections to 8. Anyone acting on the
    measurement needs both halves of that trade in front of them.
    """
    ip = "66.235.200.146"
    assert scored[ip]["confidence"] > 0.0

    clean = score_beacon(crosscheck["established_only_intervals_by_ip"][ip])
    assert clean["sample_count"] < MIN_SAMPLES
    assert clean["confidence"] == 0.0
    assert clean["rcv"] < 0.01, "the series is still textbook-regular, just short"


def test_established_filter_does_not_invent_beacons(crosscheck):
    """The connection-state filter must not manufacture periodicity.

    download.windowsupdate.com is benign bulk transfer in the same capture. If
    filtering to established connections turned it into a beacon, the filter
    would be trading recall for precision and the measurement above would be
    worthless.
    """
    ip = next(
        k for k, v in crosscheck["ip_to_fqdn"].items()
        if v == "download.windowsupdate.com"
    )
    for series in ("spectre_intervals_by_ip", "established_only_intervals_by_ip"):
        assert score_beacon(crosscheck[series][ip])["confidence"] == 0.0


def test_benign_telemetry_scored_by_rita_produces_no_spectre_finding(crosscheck, scored):
    """RITA's beacon_score alone would flag Windows/Office telemetry.

    RITA gates those out with a separate threat score. Spectre has no such second
    stage, so its first stage has to be selective enough on its own. Verify that
    for the telemetry endpoint we hold intervals for.
    """
    benign = {row["fqdn"] for row in crosscheck["rita_scored_but_not_threat"]}
    benign -= {crosscheck["ip_to_fqdn"][ip] for ip in crosscheck["spectre_findings"]}

    for ip, s in scored.items():
        if crosscheck["ip_to_fqdn"][ip] in benign:
            assert s["confidence"] == 0.0, (
                f"{ip} is benign telemetry in RITA's ranking but pcap-beacon "
                f"scored it {s['confidence']}"
            )


def test_short_series_rejected_where_rita_reports_a_beacon(crosscheck):
    """MIN_SAMPLES is a deliberate divergence from RITA, not an oversight.

    RITA reports www.clocosis.com as a beacon (0.57) off 6 connections whose
    intervals are 210/436/555/805/964 s — nothing like a period. Spectre requires
    MIN_SAMPLES intervals before it will assign any confidence at all, which
    rejects this. Recorded here so the divergence is a decision on the record.
    """
    clocosis = next(
        row for row in crosscheck["rita_beacons"] if row["fqdn"] == "www.clocosis.com"
    )
    assert clocosis["conns"] < MIN_SAMPLES

    score = score_beacon([210.0, 436.0, 555.0, 805.0, 964.0])
    assert score["sample_count"] < MIN_SAMPLES
    assert score["confidence"] == 0.0
