"""A timed-out MemProcFS run left a live FUSE mount over the evidence.

`memprocfs` is a *grandchild* of the pipeline: `_run_mpfs_subprocess` spawns a
Python child (`extract_memprocfs.py`), and that child `Popen`s the memprocfs
daemon, which holds a FUSE mount open for the life of the read.
`subprocess.run(timeout=...)` SIGKILLs only the direct child. So on timeout the
daemon survived — still mounted, still backed by the read-only evidence file,
outliving the case that created it. Nothing in the case dir records that it is
there, and the next run mounts the same image again alongside it.

Two more defects in the same branch:

- `duration_ms = 300_000` was hardcoded on the timeout path. That number goes
  into an audit row, which is supposed to attest to what happened. If the
  timeout ceiling ever changes, or the wait is cut short, the row states a
  duration that was never measured.
- the ceiling itself was hardcoded in three places (the call, the log line, the
  failure message), so they could disagree.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from spectre import config
from spectre.modules import memory as memmod
from spectre.modules.memory import extract_memprocfs as mpfs


# ── the teardown itself, against a real process tree ──

def _spawn_tree() -> tuple[subprocess.Popen, int]:
    """Start a child in its own session that spawns a long-lived grandchild.

    Mirrors the real shape: our Python child holds a `Popen` on a daemon that
    would keep running if only the child were killed. Returns (child, gpid).
    """
    code = (
        "import subprocess,sys,time\n"
        "g = subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])\n"
        "print(g.pid, flush=True)\n"
        "time.sleep(120)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code],
                            stdout=subprocess.PIPE, text=True,
                            start_new_session=True)
    grandchild_pid = int(proc.stdout.readline().strip())
    return proc, grandchild_pid


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def test_the_grandchild_daemon_does_not_survive_the_teardown():
    child, grandchild = _spawn_tree()
    try:
        memmod._terminate_process_group(child, grace=3.0)
        deadline = time.time() + 10
        while time.time() < deadline and _alive(grandchild):
            time.sleep(0.1)
        assert not _alive(grandchild), (
            f"pid {grandchild} (the memprocfs stand-in) outlived the timeout "
            f"teardown — a live FUSE mount over read-only evidence")
        assert child.poll() is not None, "the direct child is still running"
    finally:
        for pid in (grandchild, child.pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            child.wait(timeout=5)
        except Exception:
            pass


def test_the_teardown_does_not_signal_our_own_process_group():
    """`killpg` on a process that never got its own session would take out the
    test runner (and, in production, the whole pipeline). The guard is
    `start_new_session=True` at spawn; assert the teardown refuses rather than
    trusting it blindly."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    # deliberately NOT start_new_session: shares our group
    try:
        assert os.getpgid(proc.pid) == os.getpgid(0)
        memmod._terminate_process_group(proc, grace=2.0)
        assert proc.poll() is not None, "the child itself should still be killed"
    finally:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


# ── how the subprocess is spawned ──

class _FakeProc:
    """Stands in for the extraction subprocess."""

    def __init__(self, *, timeout_on_wait=False, stdout="[]", returncode=0):
        self.pid = 424242
        self.returncode = returncode
        self._timeout = timeout_on_wait
        self._stdout = stdout
        self.communicate_calls = 0

    def communicate(self, timeout=None):
        self.communicate_calls += 1
        if self._timeout and self.communicate_calls == 1:
            raise subprocess.TimeoutExpired(cmd="memprocfs", timeout=timeout)
        return self._stdout, ""

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def _capture_popen(monkeypatch, proc):
    seen = {}

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        return proc

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return seen


def test_the_extraction_subprocess_gets_its_own_session(tmp_path, monkeypatch):
    """Without this the daemon shares our process group and cannot be killed
    as a unit — the teardown above has nothing to aim at."""
    proc = _FakeProc()
    seen = _capture_popen(monkeypatch, proc)
    monkeypatch.setattr(memmod, "_audit_mpfs_handles", lambda *a, **k: None)

    memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "dump.raw"))

    assert seen["kwargs"].get("start_new_session") is True, seen["kwargs"]


def test_a_timeout_tears_down_the_whole_group(tmp_path, monkeypatch):
    proc = _FakeProc(timeout_on_wait=True)
    _capture_popen(monkeypatch, proc)
    torn = {}
    monkeypatch.setattr(memmod, "_terminate_process_group",
                        lambda p, **kw: torn.setdefault("proc", p))

    handles = memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "d.raw"))

    assert torn.get("proc") is proc, "timeout did not tear down the group"
    assert handles[0]["result"] == "failure"


def test_the_timeout_row_reports_measured_time_not_the_ceiling(tmp_path, monkeypatch):
    """`duration_ms = 300_000` was written into an audit row regardless of how
    long the run actually took."""
    proc = _FakeProc(timeout_on_wait=True)
    _capture_popen(monkeypatch, proc)
    monkeypatch.setattr(memmod, "_terminate_process_group", lambda p, **kw: None)

    logged = {}
    import spectre.pipeline.shell_log as shell_log
    monkeypatch.setattr(shell_log, "log_command",
                        lambda **kw: logged.update(kw))

    memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "d.raw"))

    assert logged, "no execution.log row was written for the timeout"
    assert logged["duration_ms"] != 300_000, (
        "the timeout row still reports a hardcoded ceiling, not elapsed time")
    assert logged["duration_ms"] < 60_000, logged["duration_ms"]


def test_the_timeout_ceiling_is_configurable_and_reported_consistently(
        tmp_path, monkeypatch):
    """The ceiling was hardcoded at three sites (the wait, the log line, the
    failure message) which could drift apart. Pin them to one source."""
    monkeypatch.setattr(config, "MEMPROCFS_TIMEOUT", 777)
    proc = _FakeProc(timeout_on_wait=True)
    _capture_popen(monkeypatch, proc)
    monkeypatch.setattr(memmod, "_terminate_process_group", lambda p, **kw: None)

    handles = memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "d.raw"))

    assert "777" in handles[0]["stderr"], handles[0]["stderr"]


def test_a_successful_run_still_returns_tagged_handles(tmp_path, monkeypatch):
    """The switch from subprocess.run to Popen must not change the happy path."""
    proc = _FakeProc(stdout='[{"artifact_type": "memory_pslist", '
                            '"result": "success", "path": ""}]')
    _capture_popen(monkeypatch, proc)
    monkeypatch.setattr(memmod, "_audit_mpfs_handles", lambda *a, **k: None)

    handles = memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "d.raw"))

    assert len(handles) == 1
    assert handles[0]["engine"] == "memprocfs"


def test_a_crash_signal_is_still_reported_as_a_crash(tmp_path, monkeypatch):
    proc = _FakeProc(returncode=-11, stdout="")
    _capture_popen(monkeypatch, proc)

    handles = memmod._run_mpfs_subprocess(str(tmp_path), str(tmp_path / "d.raw"))

    assert handles[0]["result"] == "failure"
    assert "SIGSEGV" in handles[0]["stderr"]


# ── the child's side of the handshake ──

def test_the_child_unwinds_on_sigterm_instead_of_dying_in_place():
    """Python's default SIGTERM action terminates without running `finally`,
    so `extract()`'s `_unmount_dump` would never run and the mount would leak
    even though we asked politely first."""
    previous = signal.getsignal(signal.SIGTERM)
    try:
        mpfs._install_sigterm_unmount()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler), "SIGTERM is still on its default action"
        with pytest.raises(SystemExit):
            handler(signal.SIGTERM, None)
    finally:
        signal.signal(signal.SIGTERM, previous)
