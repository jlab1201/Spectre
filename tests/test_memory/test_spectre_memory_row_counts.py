"""`spectre-memory --engine both` was minting CONFIRMED from a row count.

`_cross_validate()` compared per-artifact row totals between volatility3 and
MemProcFS and labelled the result `CONFIRMED` (delta <= 5%) or `FLAGGED`. Those
two words are load-bearing elsewhere in Spectre: `CONFIRMED` is a *finding's*
corroboration status, reached when two independent sources produced the same
claim and a Spectre predicate judged both. A row-count comparison judges no
claim at all — 53 processes on each side says nothing about whether they are
the *same* 53, and the two engines can agree on the total while disagreeing on
every entry.

Printing that word into the same tool's output as the finding-level one gives a
reader two meanings for one term, with the weaker meaning carrying the more
confident-sounding label. The comparison is still worth reporting; only the
vocabulary was wrong.

Also fixed here: the human-readable summary read `delta_pct` off the top-level
dict, where the key is `max_delta_pct`, so every run printed `delta=?%`.
"""

from __future__ import annotations

import json
import sys

import pytest

from spectre.pipeline import spectre_memory

# Words reserved for finding-level corroboration status.
_RESERVED = ("CONFIRMED", "FLAGGED", "INFERRED", "cross_validated")


def _handle(atype: str, engine: str, rows: int) -> dict:
    return {"artifact_type": atype, "engine": engine, "result": "success",
            "line_count": rows}


# ── the comparison itself ──

def test_agreeing_row_counts_are_reported_without_a_verdict_word():
    out = spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 53),
        _handle("memory_pslist", "memprocfs", 53),
    ])
    assert out is not None
    assert out["max_delta_pct"] == 0.0
    blob = json.dumps(out)
    for word in _RESERVED:
        assert word not in blob, (
            f"{word!r} is a finding-level corroboration term; a row-count "
            f"comparison must not mint it")


def test_a_large_delta_is_reported_without_a_verdict_word():
    out = spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 100),
        _handle("memory_pslist", "memprocfs", 40),
    ])
    assert out["max_delta_pct"] == 60.0
    blob = json.dumps(out)
    for word in _RESERVED:
        assert word not in blob


def test_the_two_outcomes_are_distinguishable():
    """Dropping the verdict words must not drop the signal with them."""
    agree = spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 53),
        _handle("memory_pslist", "memprocfs", 53),
    ])
    diverge = spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 100),
        _handle("memory_pslist", "memprocfs", 40),
    ])
    assert agree["row_counts"] != diverge["row_counts"]


def test_only_types_both_engines_produced_are_compared():
    """memory_url and memory_filescan are volatility3-only. Comparing them
    against an absent MemProcFS side would report a 100% delta on every run."""
    out = spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 53),
        _handle("memory_pslist", "memprocfs", 53),
        _handle("memory_url", "volatility3", 300),
    ])
    assert [d["artifact_type"] for d in out["deltas"]] == ["memory_pslist"]


def test_nothing_comparable_returns_none():
    assert spectre_memory._row_count_deltas([
        _handle("memory_url", "volatility3", 300)]) is None


def test_a_failed_handle_is_not_compared():
    """A crashed engine produces a zero-row failure handle. Treating that as a
    100% delta would report engine disagreement where there was no engine."""
    failed = _handle("memory_pslist", "memprocfs", 0)
    failed["result"] = "failure"
    assert spectre_memory._row_count_deltas([
        _handle("memory_pslist", "volatility3", 53), failed]) is None


# ── the summary line ──

def test_the_summary_prints_a_real_delta(tmp_path, monkeypatch, capsys):
    """The human summary read `delta_pct` from a dict whose key is
    `max_delta_pct`, so it printed `delta=?%` on every run."""
    import spectre.modules.memory as memmod

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    evidence = tmp_path / "dump.raw"
    evidence.write_bytes(b"\x00" * 64)

    monkeypatch.setattr(memmod, "extract", lambda cd, ev, engine="both": [
        _handle("memory_pslist", "volatility3", 100),
        _handle("memory_pslist", "memprocfs", 40),
    ])
    monkeypatch.setattr(sys, "argv", [
        "spectre-memory", "--case", str(case_dir),
        "--evidence", str(evidence), "--engine", "both", "--no-audit",
    ])

    with pytest.raises(SystemExit):
        spectre_memory.main()

    err = capsys.readouterr().err
    assert "60.0" in err, err
    assert "?%" not in err, err


# ── engines_used (R3-01/R3-02 defect class: bare set->list order jitter) ──

def test_engines_used_is_sorted_regardless_of_handle_order():
    handles_a = [
        _handle("memory_pslist", "memprocfs", 40),
        _handle("memory_netscan", "volatility3", 12),
    ]
    handles_b = list(reversed(handles_a))

    assert spectre_memory._engines_used(handles_a) == ["memprocfs", "volatility3"]
    assert spectre_memory._engines_used(handles_a) == spectre_memory._engines_used(handles_b)


def test_engines_used_dedupes_a_single_engine():
    handles = [
        _handle("memory_pslist", "volatility3", 40),
        _handle("memory_netscan", "volatility3", 12),
    ]
    assert spectre_memory._engines_used(handles) == ["volatility3"]
