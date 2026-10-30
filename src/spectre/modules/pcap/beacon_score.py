"""Robust beacon periodicity scoring.

Pure functions over an interval series. No I/O, stdlib only.

WHY MEDIAN/MAD AND NOT MEAN/STDEV
---------------------------------
The previous scorer gated on a hard-coded allowlist of "clean" intervals
({30,60,120,180,300,600,900,1800,3600}) with a +/-5s ABSOLUTE tolerance, then
graded confidence off raw sigma in seconds. Measured against real evidence
that approach found **zero** beacons in a live XLoader infection carrying 285
C2 requests, because:

  * XLoader's actual period is ~206s. Nearest allowlist entry is 180, off by
    26s, so it scored exactly 0.0. No widening of the tolerance could fix
    that -- the allowlist itself was the defect.
  * The absolute tolerance means max survivable jitter is 10/T: 16.7% at 60s
    but 0.28% at 3600s. Cobalt Strike's default `sleep 60 jitter 37` scored
    0.0.
  * Real C2 interval series contain outliers (a missed check-in, a network
    drop). Three outliers in 42 samples move the coefficient of variation by
    ~75x, so mean/stdev rejects genuine beacons:

        151.243.184.14 (www.m0d2ap.info, POST /yiti/)
        mean 101.1  stdev 128.2 -> CV  1.268  (rejected)
        median 2.6  MAD   0.00  -> rCV 0.017  (textbook beacon)

Median absolute deviation has a 50% breakdown point, so it is unmoved by that
minority of outliers, and dividing by the median makes the measure
proportional -- a 30s beacon and a 3600s beacon with the same relative jitter
score identically, which the absolute-seconds approach could never do.

These are Bowley/Hampel-era descriptive statistics (MAD dates to 1816), not a
reimplementation of any particular tool. That matters for admissibility: the
computation is inspectable and reproducible from the interval series alone.

CALIBRATION
-----------
Bands were fitted against the sample corpus, not chosen by taste:

    XLoader infection    7 true positives at rCV <= 0.015, all confirmed C2
                         (next candidate sits at 0.350 -- a 23x gap)
    7-day scan capture   0 false positives
    traffic-analysis     0 false positives

Cobalt Strike jitter maps onto the bands as:
    10% -> 0.028   20% -> 0.043   37% -> 0.117   50% -> 0.174   70% -> 0.248

KNOWN LIMITATION
----------------
Scoring treats one global distribution per remote IP across the whole
capture, so genuinely bimodal traffic (e.g. a fast rotation burst plus a slow
steady phase) drives the median between the two modes and scores poorly. MAD
does not fix multi-modality; windowing/segmentation would. This is a
documented residual, not a solved problem.
"""
import statistics

# Bump when the scoring changes in any way that could alter a confidence
# value. Findings record this so a past case stays reproducible.
SCORER_VERSION = "robust-mad-1"

# Below this many intervals the dispersion estimate is not meaningful.
# Matches the pre-existing floor in normalize (>= 10 samples).
MIN_SAMPLES = 10

# (max rCV, confidence). First match wins; above the last band, no finding.
_BANDS: tuple[tuple[float, float], ...] = (
    (0.02, 0.95),
    (0.05, 0.90),
    (0.12, 0.75),
    (0.20, 0.60),
    (0.30, 0.45),
)


def median_abs_deviation(values) -> float:
    """Median of absolute deviations from the median.

    Unlike stdev this has a 50% breakdown point -- a minority of arbitrarily
    large outliers cannot move it.
    """
    vals = list(values)
    if len(vals) < 2:
        return 0.0
    med = statistics.median(vals)
    return float(statistics.median([abs(v - med) for v in vals]))


def robust_cv(values) -> float:
    """MAD / median -- dispersion normalised by scale.

    Returns 0.0 when the median is 0 (no scale to normalise against), which
    also keeps a degenerate all-zero series from dividing by zero.
    """
    vals = list(values)
    if not vals:
        return 0.0
    med = statistics.median(vals)
    if med == 0:
        return 0.0
    return median_abs_deviation(vals) / med


def score_beacon(intervals) -> dict:
    """Score an inter-arrival interval series for periodicity.

    Returns the confidence AND the values it was derived from, so a finding
    can show its work. The deterministic core owns this reasoning; the AI
    layer must never be the thing that explains where a number came from.

    A confidence of 0.0 means "not periodic enough to report" -- callers
    treat it as no finding.
    """
    vals = [float(v) for v in intervals]
    med = statistics.median(vals) if vals else 0.0
    mad = median_abs_deviation(vals)
    rcv = robust_cv(vals)

    confidence = 0.0
    if len(vals) >= MIN_SAMPLES:
        for max_rcv, band_confidence in _BANDS:
            if rcv < max_rcv:
                confidence = band_confidence
                break

    return {
        "scorer_version": SCORER_VERSION,
        "sample_count": len(vals),
        "median_interval": med,
        "mad": mad,
        "rcv": rcv,
        "confidence": confidence,
    }
