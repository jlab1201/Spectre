"""Tests for the robust beacon periodicity scorer.

The numbers asserted here are not invented: the XLoader series and the
threshold bands come from replaying Spectre's own extraction path over
~/spectre-cases/samples/2026-01-15-XLoader-infection.pcap (see
test_scores_real_xloader_c2_series). Keep them in sync with
beacon_score.SCORER_VERSION.
"""
import statistics

import pytest

from spectre.modules.pcap.beacon_score import (
    SCORER_VERSION,
    median_abs_deviation,
    robust_cv,
    score_beacon,
)


# ── median_abs_deviation ─────────────────────────────────────────────
def test_mad_of_constant_series_is_zero():
    assert median_abs_deviation([5.0] * 10) == 0.0


def test_mad_hand_computed():
    # median = 3; deviations = [2,1,0,1,2]; median of those = 1
    assert median_abs_deviation([1, 2, 3, 4, 5]) == 1.0


def test_mad_ignores_extreme_outliers():
    """The whole point of MAD over stdev: a few huge values must not move it."""
    clean = [10.0] * 20
    with_outliers = clean + [5000.0, 9000.0, 12000.0]
    assert median_abs_deviation(with_outliers) == 0.0
    assert statistics.stdev(with_outliers) > 1000  # stdev, by contrast, explodes


def test_mad_of_empty_or_single_is_zero():
    assert median_abs_deviation([]) == 0.0
    assert median_abs_deviation([42.0]) == 0.0


# ── robust_cv ────────────────────────────────────────────────────────
def test_robust_cv_of_perfect_beacon_is_zero():
    assert robust_cv([60.0] * 15) == 0.0


def test_robust_cv_is_scale_invariant():
    """The defect in the old scorer was absolute-seconds thresholds. A 30s
    beacon and a 3600s beacon with the same *proportional* jitter must score
    identically."""
    short = [30.0, 31.0, 29.0, 30.0, 31.0, 29.0, 30.0, 31.0, 29.0, 30.0]
    long = [x * 120 for x in short]  # same shape, 120x the scale
    assert robust_cv(short) == pytest.approx(robust_cv(long))


def test_robust_cv_zero_median_does_not_divide_by_zero():
    assert robust_cv([0.0] * 10) == 0.0


def test_robust_cv_empty_is_zero():
    assert robust_cv([]) == 0.0


# ── score_beacon ─────────────────────────────────────────────────────
def test_score_beacon_reports_its_inputs_not_just_a_number():
    """The deterministic core must show its work — the AI layer is never
    allowed to supply the reasoning behind a confidence value."""
    result = score_beacon([60.0] * 12)
    for key in ("scorer_version", "sample_count", "median_interval",
                "mad", "rcv", "confidence"):
        assert key in result, f"missing {key}"
    assert result["scorer_version"] == SCORER_VERSION
    assert result["sample_count"] == 12
    assert result["median_interval"] == 60.0


def test_score_beacon_below_minimum_samples_scores_zero():
    assert score_beacon([60.0] * 9)["confidence"] == 0.0


def test_score_beacon_at_minimum_samples_scores():
    assert score_beacon([60.0] * 10)["confidence"] > 0.0


def test_perfect_beacon_scores_highest_band():
    assert score_beacon([60.0] * 20)["confidence"] == 0.95


def test_random_traffic_does_not_score():
    """Exponentially-distributed arrivals are the canonical non-beacon."""
    import random
    rng = random.Random(1337)
    intervals = [rng.expovariate(1 / 60.0) for _ in range(200)]
    assert score_beacon(intervals)["confidence"] == 0.0


# ── the cases the OLD scorer silently missed ─────────────────────────
@pytest.mark.parametrize("period", [45.0, 90.0, 206.0, 240.0, 7200.0])
def test_periods_outside_the_old_clean_interval_allowlist_now_score(period):
    """The old scorer hard-coded {30,60,120,180,300,600,900,1800,3600} with a
    +/-5s absolute tolerance, so these all returned exactly 0.0. XLoader's real
    period is ~206s, which is why Spectre found nothing in a live infection."""
    assert score_beacon([period] * 15)["confidence"] >= 0.9


def test_cobalt_strike_default_jitter_is_detected():
    """`sleep 60 jitter 37` -> one-sided uniform over [37.8, 60].
    Measured rCV ~0.117. The old scorer returned 0.0 for this."""
    import random
    rng = random.Random(42)
    intervals = [60 * (1 - rng.uniform(0, 0.37)) for _ in range(40)]
    result = score_beacon(intervals)
    assert result["rcv"] == pytest.approx(0.117, abs=0.03)
    assert result["confidence"] >= 0.6


def test_extreme_70pct_jitter_still_scores_something():
    import random
    rng = random.Random(42)
    intervals = [60 * (1 - rng.uniform(0, 0.70)) for _ in range(40)]
    assert score_beacon(intervals)["confidence"] > 0.0


def test_long_period_low_jitter_beats_short_period_same_absolute_jitter():
    """Old scorer bug: a 3600s beacon with sigma=1.5s (textbook) scored 0.50,
    the same as a 30s beacon with sigma=1.5s (marginal). Proportional
    dispersion must rank them correctly."""
    long_tight = [3600.0 + (1.5 if i % 2 else -1.5) for i in range(20)]
    short_loose = [30.0 + (1.5 if i % 2 else -1.5) for i in range(20)]
    assert score_beacon(long_tight)["confidence"] > score_beacon(short_loose)["confidence"]


# ── real evidence ────────────────────────────────────────────────────
def test_scores_real_xloader_c2_series():
    """Real inter-arrival intervals for 151.243.184.14 (www.m0d2ap.info,
    POST /yiti/) from the XLoader sample. Mean/stdev rejects this series
    (CV 1.27) because three outliers dominate; median/MAD accepts it."""
    intervals = ([2.6] * 8 + [484.8] + [2.6] * 8 + [36.0] + [2.6] * 8
                 + [280.5, 205.3, 224.2])
    result = score_beacon(intervals)
    assert result["median_interval"] == pytest.approx(2.6, abs=0.1)
    assert result["rcv"] < 0.05
    assert result["confidence"] >= 0.9
    # and the reason the old approach failed:
    cv = statistics.stdev(intervals) / statistics.mean(intervals)
    assert cv > 1.0
