"""Tests for shell_log.py — execution.log append-on-resume behaviour (issue 4).

The bug: header-writing was gated on a *process-local* set (_HEADER_WRITTEN),
so a fresh phase invocation (new Python process) re-opened execution.log with
mode "w" and truncated phases 0-1. These tests pin the fix: header is written
once per *file* (on-disk state), resuming appends, and the sequence counter
continues from the existing log rather than restarting at 1.
"""
from pathlib import Path

from spectre.pipeline import shell_log


def _new_process():
    """Simulate a fresh Python process: clear shell_log's module-local state."""
    shell_log._HEADER_WRITTEN.clear()
    shell_log._SEQ_COUNTERS.clear()


def _read_log(case_dir: str) -> str:
    return Path(case_dir, "execution.log").read_text()


def test_fresh_case_writes_header(tmp_path):
    case_dir = str(tmp_path)
    shell_log.log_command(case_dir, tool="vol", command="vol pslist", phase=0)
    log = _read_log(case_dir)
    assert "Spectre Execution Log" in log
    assert "vol pslist" in log


def test_resume_preserves_prior_entries(tmp_path):
    """Phase 0 then (new process) phase 2 must keep the phase-0 line."""
    case_dir = str(tmp_path)
    shell_log.log_command(case_dir, tool="vol", command="phase0 cmd", phase=0)

    _new_process()  # simulate resuming in a fresh process
    shell_log.log_command(case_dir, tool="evtx", command="phase2 cmd", phase=2)

    log = _read_log(case_dir)
    assert "phase0 cmd" in log
    assert "phase2 cmd" in log


def test_header_written_only_once_across_processes(tmp_path):
    case_dir = str(tmp_path)
    shell_log.log_command(case_dir, tool="vol", command="phase0 cmd", phase=0)
    _new_process()
    shell_log.log_command(case_dir, tool="evtx", command="phase2 cmd", phase=2)

    log = _read_log(case_dir)
    assert log.count("Spectre Execution Log") == 1


def test_seq_counter_seeds_from_existing_log(tmp_path):
    """On resume, the next sequence number continues past prior entries."""
    case_dir = str(tmp_path)
    shell_log.log_command(case_dir, tool="a", command="cmd one", phase=0)
    shell_log.log_command(case_dir, tool="b", command="cmd two", phase=0)

    _new_process()
    seq = shell_log.log_command(case_dir, tool="c", command="cmd three", phase=2)
    assert seq == 3


def test_same_process_does_not_retruncate(tmp_path):
    """Two calls in the same process keep both entries (regression guard)."""
    case_dir = str(tmp_path)
    shell_log.log_command(case_dir, tool="a", command="first cmd", phase=0)
    shell_log.log_command(case_dir, tool="b", command="second cmd", phase=0)
    log = _read_log(case_dir)
    assert "first cmd" in log
    assert "second cmd" in log
    assert log.count("Spectre Execution Log") == 1
