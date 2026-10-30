"""A failed `fusermount -u` stranded the mount permanently, and said nothing.

Found by verifying the WS1.6 timeout fix: after a clean, successful run over
the 2 GB crash dump, `/proc/self/mounts` still carried

    /dev/fuse on /tmp/mpfs_9tysmlxq type fuse (rw,nosuid,nodev,...)

and the path answered `Transport endpoint is not connected`. This is the
*success* path, not the timeout path, so it happens on ordinary cases.

`_unmount_dump` ran `fusermount -u`, discarded its exit code, then killed the
daemon regardless. When the unmount failed — a busy mount, an unflushed
handle — killing the daemon turned a recoverable busy mount into a permanently
stale one, and nothing retried once the daemon (the thing making it busy) was
gone. `os.rmdir` then failed into a bare `except OSError: pass`, so the leak
left no trace anywhere: no stderr line, no audit row, no return value.

A stranded FUSE mount over read-only evidence is the same custody problem the
timeout teardown exists to prevent. It must be retried after the daemon exits,
escalated to a lazy unmount, and — if it still survives — said out loud.
"""

from __future__ import annotations

import subprocess

import pytest

from spectre.modules.memory import extract_memprocfs as mpfs


class _FakeDaemon:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0 if self.terminated else None

    def kill(self):
        self.terminated = True


@pytest.fixture
def fuse(monkeypatch, tmp_path):
    """Record fusermount invocations; let each test script their outcomes."""
    calls: list[list[str]] = []
    state = {"exit_codes": [0], "mounted": True}

    def fake_run(cmd, **kwargs):
        if cmd and cmd[0] == "fusermount":
            calls.append(list(cmd))
            idx = min(len(calls) - 1, len(state["exit_codes"]) - 1)
            rc = state["exit_codes"][idx]
            if rc == 0:
                state["mounted"] = False
            return subprocess.CompletedProcess(cmd, rc, b"", b"busy")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(mpfs.subprocess, "run", fake_run)
    monkeypatch.setattr(mpfs, "_is_mounted", lambda p: state["mounted"])
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)

    point = tmp_path / "mpfs_fixture"
    point.mkdir()
    return {"calls": calls, "state": state, "point": str(point)}


def test_is_mounted_reads_the_kernel_not_the_path(tmp_path):
    """`os.path.ismount` lstat()s the path, and a stale FUSE mount answers
    ENOTCONN — so it reports "not mounted" for exactly the case we must
    detect. Read /proc/self/mounts instead."""
    assert mpfs._is_mounted("/") is True
    assert mpfs._is_mounted(str(tmp_path / "definitely-not-mounted")) is False


def test_a_clean_unmount_needs_no_retry(fuse):
    daemon = _FakeDaemon()
    released = mpfs._unmount_dump(fuse["point"], daemon)

    assert released is True
    assert len(fuse["calls"]) == 1, fuse["calls"]
    assert daemon.terminated


def test_a_busy_unmount_is_retried_once_the_daemon_is_gone(fuse):
    """The daemon is what holds the mount busy. The old code killed it and
    then never tried again."""
    fuse["state"]["exit_codes"] = [1, 0]
    daemon = _FakeDaemon()

    released = mpfs._unmount_dump(fuse["point"], daemon)

    assert released is True, "a busy mount was abandoned instead of retried"
    assert len(fuse["calls"]) >= 2, fuse["calls"]
    assert daemon.terminated, "the retry must come after the daemon is reaped"


def test_a_stubborn_mount_escalates_to_a_lazy_unmount(fuse):
    fuse["state"]["exit_codes"] = [1, 1, 0]
    mpfs._unmount_dump(fuse["point"], _FakeDaemon())

    lazy = [c for c in fuse["calls"] if any(a.startswith("-u") and "z" in a
                                            for a in c)]
    assert lazy, f"never escalated to a lazy unmount: {fuse['calls']}"


def test_a_stranded_mount_is_reported_not_swallowed(fuse, capsys):
    """The whole failure mode was silence. If the mount survives every
    attempt, the examiner must learn that a FUSE view of the evidence is
    still live on this host."""
    fuse["state"]["exit_codes"] = [1]
    released = mpfs._unmount_dump(fuse["point"], _FakeDaemon())

    assert released is False
    err = capsys.readouterr().err
    assert fuse["point"] in err, err
    assert "mount" in err.lower(), err


def test_the_mount_point_is_removed_only_once_released(fuse, tmp_path):
    """rmdir on a live mount point cannot succeed, and rmdir on a released one
    must — leaving /tmp littered with mpfs_* directories is how the leak was
    invisible for so long."""
    import os

    released = mpfs._unmount_dump(fuse["point"], _FakeDaemon())
    assert released
    assert not os.path.exists(fuse["point"])


def test_a_failed_mount_still_unmounts_before_removing_the_directory(
        monkeypatch, tmp_path):
    """`_mount_dump`'s give-up path killed the daemon and called rmdir with no
    unmount attempt at all. If FUSE came up but `sys/` never appeared, that
    strands the mount exactly as above."""
    seen = {}
    daemon = _FakeDaemon()

    monkeypatch.setattr(mpfs.subprocess, "Popen", lambda *a, **k: daemon)
    monkeypatch.setattr(mpfs.tempfile, "mkdtemp",
                        lambda **k: str(tmp_path / "mp"))
    (tmp_path / "mp").mkdir()
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)
    # Advance the clock rather than burning the real 30s readiness deadline.
    clock = iter([0.0] + [float(i) for i in range(1, 200)])
    monkeypatch.setattr(mpfs.time, "time", lambda: next(clock))
    # never becomes ready
    monkeypatch.setattr(mpfs.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(mpfs, "_unmount_dump",
                        lambda point, proc=None: seen.setdefault("point", point))

    mount, proc = mpfs._mount_dump("/tmp/nonexistent.raw")

    assert mount is None
    assert seen.get("point") == str(tmp_path / "mp"), (
        "the give-up path removed the directory without unmounting it")
