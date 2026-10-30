"""`SPECTRE_MEMORY_ENGINE` — one seam, and a typo that must not silence a run.

Every other engine choice in Spectre is env-overridable (`SPECTRE_PCAP_ENGINE`,
`SPECTRE_LLM_PROVIDER`); memory was not, so the only way to run one engine was
the standalone `spectre-memory` CLI — which is not the pipeline. The knob is
read *inside* `modules.memory.extract` via a `None` sentinel rather than
threaded through `phase_runner`, so every caller honours it through one seam
and an explicit argument still wins.

The second half of this file is the part that matters more. `extract()` gated
each engine on `engine in ("vol", "both")`, so an unrecognized value ran
*neither* engine and returned an empty handle list. With the value now
reachable from the environment, `SPECTRE_MEMORY_ENGINE=volatility3` would give
a case with zero memory artifacts, no error, and a report that found nothing
because nothing looked.
"""

from __future__ import annotations

import pytest

from spectre import config
from spectre.modules import memory as memmod


@pytest.fixture
def engines_run(monkeypatch):
    """Record which engines a call to extract() actually invoked."""
    ran: list[str] = []
    monkeypatch.setattr(memmod, "extract_vol",
                        lambda cd, ev: (ran.append("vol"), [{"path": ""}])[1])
    monkeypatch.setattr(memmod, "_run_mpfs_subprocess",
                        lambda cd, ev: (ran.append("memprocfs"), [{"path": ""}])[1])
    return ran


def test_the_default_still_runs_both_engines(engines_run, monkeypatch):
    monkeypatch.setattr(config, "MEMORY_ENGINE", "")
    memmod.extract("/tmp/case", "/tmp/dump.raw")
    assert engines_run == ["vol", "memprocfs"]


def test_the_env_knob_selects_a_single_engine(engines_run, monkeypatch):
    monkeypatch.setattr(config, "MEMORY_ENGINE", "vol")
    memmod.extract("/tmp/case", "/tmp/dump.raw")
    assert engines_run == ["vol"]


def test_an_explicit_argument_beats_the_env_knob(engines_run, monkeypatch):
    """The `spectre-memory --engine` flag and any future caller must be able to
    override the environment, not be overridden by it."""
    monkeypatch.setattr(config, "MEMORY_ENGINE", "vol")
    memmod.extract("/tmp/case", "/tmp/dump.raw", engine="memprocfs")
    assert engines_run == ["memprocfs"]


def test_the_knob_is_case_and_whitespace_insensitive(engines_run, monkeypatch):
    monkeypatch.setattr(config, "MEMORY_ENGINE", "  MemProcFS \n")
    memmod.extract("/tmp/case", "/tmp/dump.raw")
    assert engines_run == ["memprocfs"]


def test_an_unrecognized_engine_runs_both_rather_than_nothing(
        engines_run, monkeypatch, capsys):
    """A typo used to mean "run neither engine" — an empty extraction that
    looks exactly like an image with nothing in it."""
    monkeypatch.setattr(config, "MEMORY_ENGINE", "volatility3")
    handles = memmod.extract("/tmp/case", "/tmp/dump.raw")

    assert engines_run == ["vol", "memprocfs"], (
        "an unrecognized engine silently skipped extraction entirely")
    assert handles, "extraction returned no handles"
    assert "volatility3" in capsys.readouterr().err, (
        "the bad value was corrected silently; the examiner never learns their "
        "setting was ignored")


def test_an_unrecognized_explicit_argument_is_also_corrected(
        engines_run, monkeypatch):
    monkeypatch.setattr(config, "MEMORY_ENGINE", "")
    memmod.extract("/tmp/case", "/tmp/dump.raw", engine="mpfs")
    assert engines_run == ["vol", "memprocfs"]


def test_the_cli_defers_to_the_env_knob_when_no_flag_is_given(
        tmp_path, monkeypatch, capsys):
    """`--engine` defaulted to the string "both", which silently outranked the
    environment for every unflagged invocation."""
    import sys

    import spectre.modules.memory as mem
    from spectre.pipeline import spectre_memory

    monkeypatch.setattr(config, "MEMORY_ENGINE", "vol")
    seen = {}
    def _fake_extract(cd, ev, engine=None):
        seen["engine"] = engine
        return []

    monkeypatch.setattr(mem, "extract", _fake_extract)

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    evidence = tmp_path / "dump.raw"
    evidence.write_bytes(b"\x00" * 16)
    monkeypatch.setattr(sys, "argv", [
        "spectre-memory", "--case", str(case_dir), "--evidence", str(evidence),
        "--no-audit", "--json",
    ])

    with pytest.raises(SystemExit):
        spectre_memory.main()

    assert seen["engine"] == "vol"


def test_the_engine_choice_is_recorded_in_the_environment_row(monkeypatch):
    """Which engines were available and which were asked for bounds what the
    examination could see — so it belongs in the chained S0-environment row,
    next to pcap_engine, not only in a shell history somewhere."""
    from spectre.pipeline import environment

    monkeypatch.setattr(config, "MEMORY_ENGINE", "vol")
    snap = environment.environment_snapshot()
    assert snap["config"]["memory_engine"] == "vol"
