"""Tests for console verbosity gating + step titles in execution.log (issue 6)."""
from pathlib import Path

import pytest

from spectre.pipeline import console, shell_log


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset verbosity + shell_log process-local state between tests."""
    console.set_verbosity(0)
    shell_log._HEADER_WRITTEN.clear()
    shell_log._SEQ_COUNTERS.clear()
    yield
    console.set_verbosity(0)


def test_set_verbosity_clamps():
    console.set_verbosity(99)
    assert console.get_verbosity() == 3
    console.set_verbosity(-5)
    assert console.get_verbosity() == 0


def test_detail_hidden_by_default(capsys):
    console.set_verbosity(0)
    console.detail("per-item progress")
    assert "per-item progress" not in capsys.readouterr().err


def test_detail_shown_at_vv(capsys):
    console.set_verbosity(2)
    console.detail("per-item progress")
    assert "per-item progress" in capsys.readouterr().err


def test_step_hidden_from_stdout_by_default_but_logged(capsys, tmp_path):
    """At level 0 the step title is NOT on stderr but IS in execution.log."""
    console.set_verbosity(0)
    console.step("Session canary", case_dir=str(tmp_path), phase=0, step_id="S1")
    assert "Session canary" not in capsys.readouterr().err
    log = Path(tmp_path, "execution.log").read_text()
    assert "[P0:S1] Session canary" in log


def test_step_shown_on_stderr_at_v(capsys, tmp_path):
    console.set_verbosity(1)
    console.step("Session canary", case_dir=str(tmp_path), phase=0, step_id="S1")
    assert "Session canary" in capsys.readouterr().err


def test_phase_banner_always_shown_and_logged(capsys, tmp_path):
    console.set_verbosity(0)
    console.phase_banner("Phase 2: Raw Events Extraction",
                         case_dir=str(tmp_path), phase=2)
    assert "Raw Events Extraction" in capsys.readouterr().err
    log = Path(tmp_path, "execution.log").read_text()
    assert "[P2] Phase 2: Raw Events Extraction" in log


def test_step_marker_not_counted_as_command_entry(tmp_path):
    """Step markers must not inflate the command sequence counter."""
    console.step("a step", case_dir=str(tmp_path), phase=1, step_id="S1")
    # First real command after a step still gets sequence 1.
    seq = shell_log.log_command(str(tmp_path), tool="t", command="cmd", phase=1)
    assert seq == 1
