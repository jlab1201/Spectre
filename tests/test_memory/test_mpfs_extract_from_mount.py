r"""WS4 — exercise the MemProcFS extractor without FUSE and without a dump.

`extract()` was 200 lines reachable only by mounting a real memory image, so
the engine that produces half of Spectre's memory evidence had no test at all.
`extract_from_mount(case_dir, evidence_path, mount)` takes a directory path,
so a fixture tree stands in for the mount.

What these tests are actually protecting:

  * **every artifact is written, even when its source is missing.** A zero-row
    artifact with `result: success` records that we looked and found nothing.
    That is a different fact from never having looked, and only the first
    belongs in the audit trail as a successful read. Silently skipping the
    handle would make a partial extraction indistinguishable from a complete
    one.
  * **`output_sha256` is non-empty**, computed in the process that wrote the
    file. The audit row has to attest to the bytes this code produced.
  * **a missing subtree degrades, it does not raise.** A dump that yields no
    network table must still produce pslist.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from spectre.config import RAW_DIR
from spectre.modules.memory import extract_memprocfs as mpfs

FIXTURES = Path(__file__).parent.parent / "fixtures" / "memprocfs"

# Every artifact_type extract_from_mount is contracted to emit, whatever the
# mount contains. memory_regkey appears three times (Run/RunOnce/Winlogon).
EXPECTED_TYPES = {
    "memory_pslist", "memory_netscan", "memory_cmdline", "memory_envar",
    "memory_malfind", "memory_svcscan", "memory_regkey", "memory_modules",
}


def _build_mount(root: Path) -> str:
    """A minimal but realistic MemProcFS tree, using the captured fixtures."""
    (root / "sys" / "proc").mkdir(parents=True)
    (root / "sys" / "proc" / "proc-time.txt").write_text(
        (FIXTURES / "proc-time.txt").read_text())

    (root / "sys" / "net").mkdir(parents=True)
    (root / "sys" / "net" / "netstat-v.txt").write_text(
        "   #    PID Proto  State        Src                           Dst"
        "                          Process              Time"
        "                     Object Address    Process Path\n"
        "-------------------------------------------------------------\n"
        "0012   1944 TCPv4  ESTABLISHED  10.0.2.15:49232               "
        "172.217.160.131:80             explorer.exe        "
        "2019-08-19 14:42:39 UTC fffffa8002cfa810    C:\\Windows\\explorer.exe\n"
    )

    svc = root / "sys" / "services" / "by-name" / "AudioSrv-27"
    svc.mkdir(parents=True)
    (svc / "svcinfo.txt").write_text(
        (FIXTURES / "svcinfo" / "auto_share_process.txt").read_text())

    pid = root / "pid" / "1944"
    (pid / "memmap").mkdir(parents=True)
    (pid / "memmap" / "vad.txt").write_text(
        (FIXTURES / "vad_1944_explorer.txt").read_text())
    (pid / "vmemd").mkdir()
    (pid / "vmemd" / f"0x{0x4320000:016x}.vvmem").write_bytes(
        bytes.fromhex("41ba8000000048b8"))
    (pid / "win-environment.txt").write_text(
        (FIXTURES / "win-environment_1944.txt").read_text())
    (pid / "name.txt").write_text("explorer.exe   \n")
    (pid / "ppid.txt").write_text("1900\n")
    (pid / "win-cmdline.txt").write_text("C:\\Windows\\Explorer.EXE\n")
    (pid / "time-create.txt").write_text("2019-08-19 14:40:19 UTC\n")

    mods = pid / "modules"
    mods.mkdir()
    (mods / "ntdll.dll.txt").write_text("fffff8000\nC:\\Windows\\System32\\ntdll.dll\n")
    (mods / "(_readme_).txt").write_text("ignore me")

    reg = root / "registry" / "HKLM" / "SOFTWARE" / "Microsoft" / "Windows" / \
        "CurrentVersion" / "Run"
    reg.mkdir(parents=True)
    (reg / "VBoxTray.txt").write_text(
        "0x1234\nREG_SZ\nC:\\Windows\\System32\\VBoxTray.exe\n")
    (reg / "(_Key_).txt").write_text("metadata, not a value")

    return str(root)


@pytest.fixture
def extracted(tmp_path):
    case = tmp_path / "case"
    handles = mpfs.extract_from_mount(
        str(case), "/ev/dump.raw", _build_mount(tmp_path / "mnt"))
    return case, handles


# ── the contract ──

def test_every_artifact_type_is_emitted(extracted):
    _, handles = extracted
    assert {h["artifact_type"] for h in handles} == EXPECTED_TYPES


def test_the_declared_artifact_types_match_what_is_actually_emitted(extracted):
    """`EMITTED_ARTIFACT_TYPES` is what the FK `parser:` provenance guard
    checks against (tests/test_memory/test_fk_parser_truth.py). If it can drift
    below what the engine emits, that guard silently stops covering the
    difference — so pin it to the handles a real pass produces, not to the
    literal above."""
    _, handles = extracted
    assert mpfs.EMITTED_ARTIFACT_TYPES == {h["artifact_type"] for h in handles}


def test_every_handle_reports_success_and_a_digest(extracted):
    case, handles = extracted
    for h in handles:
        assert h["result"] == "success", h["artifact_type"]
        assert h["exit_code"] == 0
        assert len(h["output_sha256"]) == 64, h["artifact_type"]
        assert h["tool"] == "memprocfs"
        assert h["params"]["engine"] == "memprocfs"
        assert Path(h["path"]).is_file()
        assert Path(h["path"]).parent == case / RAW_DIR


def test_the_digest_matches_the_bytes_on_disk(extracted):
    """The audit row must attest to what was actually written, not to a
    plausible re-hash of it later."""
    import hashlib
    _, handles = extracted
    for h in handles:
        actual = hashlib.sha256(Path(h["path"]).read_bytes()).hexdigest()
        assert h["output_sha256"] == actual, h["artifact_type"]


def test_row_counts_match_the_files_written(extracted):
    _, handles = extracted
    for h in handles:
        rows = json.loads(Path(h["path"]).read_text())
        assert h["line_count"] == len(rows), h["artifact_type"]


def test_the_output_directory_is_created_if_absent(tmp_path):
    case = tmp_path / "does" / "not" / "exist"
    handles = mpfs.extract_from_mount(
        str(case), "/ev/dump.raw", _build_mount(tmp_path / "mnt"))
    assert (case / RAW_DIR).is_dir()
    assert handles


# ── what actually got read ──

def _rows(handles, artifact_type):
    h = next(h for h in handles if h["artifact_type"] == artifact_type)
    return json.loads(Path(h["path"]).read_text())


def test_processes_come_from_proc_time(extracted):
    _, handles = extracted
    rows = _rows(handles, "memory_pslist")
    assert len(rows) == 53
    assert not any(r["ImageFileName"].startswith("-") for r in rows)


def test_the_injected_region_is_found_and_its_bytes_read(extracted):
    _, handles = extracted
    rows = _rows(handles, "memory_malfind")
    assert len(rows) == 2
    read = next(r for r in rows if r["RegionBytesRead"])
    assert read["Address"] == "0x0000000004320000"
    assert read["Hexdump"].startswith("41 ba 80")
    # The other region has no .vvmem in the fixture tree.
    assert any(r["RegionBytesRead"] is False for r in rows)


def test_registry_metadata_entries_are_not_treated_as_values(extracted):
    _, handles = extracted
    rows = _rows(handles, "memory_regkey")
    assert [r["Name"] for r in rows] == ["VBoxTray"]


def test_module_readme_entries_are_skipped(extracted):
    _, handles = extracted
    rows = _rows(handles, "memory_modules")
    assert [r["Name"] for r in rows] == ["ntdll.dll"]
    assert rows[0]["Path"] == r"C:\Windows\System32\ntdll.dll"


def test_services_are_read_from_the_by_name_tree(extracted):
    _, handles = extracted
    assert [r["Name"] for r in _rows(handles, "memory_svcscan")] == ["AudioSrv"]


# ── degraded mounts ──

def test_an_empty_mount_still_writes_every_artifact(tmp_path):
    """The dump mounted but published nothing we recognise. That is a
    successful read of an empty source, and it must be recorded as one --
    not as a crash, and not as silence."""
    case = tmp_path / "case"
    empty = tmp_path / "empty"
    empty.mkdir()
    handles = mpfs.extract_from_mount(str(case), "/ev/dump.raw", str(empty))
    assert {h["artifact_type"] for h in handles} == EXPECTED_TYPES
    assert all(h["result"] == "success" for h in handles)
    assert all(h["line_count"] == 0 for h in handles)


def test_a_missing_network_table_does_not_lose_the_process_list(tmp_path):
    case = tmp_path / "case"
    mount = Path(_build_mount(tmp_path / "mnt"))
    (mount / "sys" / "net" / "netstat-v.txt").unlink()
    handles = mpfs.extract_from_mount(str(case), "/ev/dump.raw", str(mount))
    assert _rows(handles, "memory_netscan") == []
    assert len(_rows(handles, "memory_pslist")) == 53


def test_proc_txt_is_used_when_proc_time_is_absent(tmp_path):
    """proc-time.txt is preferred, but older builds publish only the
    tree-rendered proc.txt -- which must still yield all 53 processes with
    clean names, not 48 with tree glyphs baked in."""
    case = tmp_path / "case"
    mount = Path(_build_mount(tmp_path / "mnt"))
    (mount / "sys" / "proc" / "proc-time.txt").unlink()
    (mount / "sys" / "proc" / "proc.txt").write_text(
        (FIXTURES / "proc.txt").read_text())
    handles = mpfs.extract_from_mount(str(case), "/ev/dump.raw", str(mount))
    rows = _rows(handles, "memory_pslist")
    assert len(rows) == 53
    assert not any(r["ImageFileName"].startswith("-") for r in rows)


def test_an_unreadable_pid_directory_does_not_abort_the_pass(tmp_path):
    """A pid/ entry that is not a directory (or vanishes mid-walk) must cost
    that process, not the whole extraction."""
    case = tmp_path / "case"
    mount = Path(_build_mount(tmp_path / "mnt"))
    (mount / "pid" / "not-a-pid").write_text("junk")
    (mount / "pid" / "9999").mkdir()
    handles = mpfs.extract_from_mount(str(case), "/ev/dump.raw", str(mount))
    cmdlines = _rows(handles, "memory_cmdline")
    assert {r["PID"] for r in cmdlines} == {1944, 9999}


# ── failure paths ──

def test_a_failed_mount_produces_one_failure_handle(monkeypatch, tmp_path):
    monkeypatch.setattr(mpfs, "_mount_dump", lambda ev: (None, None))
    handles = mpfs.extract(str(tmp_path), "/ev/dump.raw")
    assert len(handles) == 1
    assert handles[0]["result"] == "failure"
    assert handles[0]["exit_code"] == 1
    assert "FUSE mount failed" in handles[0]["stderr"]


def test_extract_always_unmounts_even_when_reading_raises(monkeypatch, tmp_path):
    """The mount is a writable view of read-only evidence. Leaving it behind
    on an error is a chain-of-custody problem, not just untidiness."""
    unmounted = []
    monkeypatch.setattr(mpfs, "_mount_dump", lambda ev: ("/fake/mnt", "proc-obj"))
    monkeypatch.setattr(mpfs, "_unmount_dump",
                        lambda m, p=None: unmounted.append((m, p)))

    def boom(*a, **kw):
        raise RuntimeError("read failed")

    monkeypatch.setattr(mpfs, "extract_from_mount", boom)
    with pytest.raises(RuntimeError):
        mpfs.extract(str(tmp_path), "/ev/dump.raw")
    assert unmounted == [("/fake/mnt", "proc-obj")]


def test_an_error_mid_extraction_is_recorded_as_a_failure_handle(
        monkeypatch, tmp_path):
    monkeypatch.setattr(mpfs, "_collect_services",
                        lambda mount: (_ for _ in ()).throw(RuntimeError("boom")))
    handles = mpfs.extract_from_mount(
        str(tmp_path / "case"), "/ev/dump.raw", _build_mount(tmp_path / "mnt"))
    failures = [h for h in handles if h["result"] == "failure"]
    assert len(failures) == 1
    assert "boom" in failures[0]["stderr"]
    # Everything read before the error is still reported.
    assert "memory_pslist" in {h["artifact_type"] for h in handles}


# ── mount lifecycle ──
#
# The mount is a writable FUSE view over read-only evidence and the daemon
# outlives the call that started it, so every exit path has to reclaim both
# the mount point and the process. None of this can be exercised with a real
# dump in the default test run, so the subprocess boundary is stubbed.

class _FakeProc:
    def __init__(self, alive=True):
        self._alive = alive
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self):
        return None if self._alive else 1

    def terminate(self):
        self.terminated = True
        self._alive = False

    def kill(self):
        self.killed = True
        self._alive = False

    def wait(self, timeout=None):
        self.waited = True
        return 0


def test_mount_returns_the_point_once_sys_appears(monkeypatch, tmp_path):
    made = tmp_path / "mpfs_x"
    made.mkdir()
    (made / "sys").mkdir()
    proc = _FakeProc()
    monkeypatch.setattr(mpfs.tempfile, "mkdtemp", lambda prefix: str(made))
    monkeypatch.setattr(mpfs.subprocess, "Popen", lambda *a, **kw: proc)

    mount, got = mpfs._mount_dump("/ev/dump.raw")
    assert mount == str(made)
    assert got is proc


def test_a_daemon_that_exits_before_mounting_is_reported_as_failure(
        monkeypatch, tmp_path):
    """memprocfs died -- no sys/ ever appeared. Returning a mount point here
    would hand the caller a path that reads as an empty dump."""
    made = tmp_path / "mpfs_y"
    made.mkdir()
    proc = _FakeProc(alive=False)
    monkeypatch.setattr(mpfs.tempfile, "mkdtemp", lambda prefix: str(made))
    monkeypatch.setattr(mpfs.subprocess, "Popen", lambda *a, **kw: proc)
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)

    mount, got = mpfs._mount_dump("/ev/dump.raw")
    assert (mount, got) == (None, None)
    assert not made.exists(), "the empty mount point must not be left behind"


def test_a_missing_binary_is_reported_as_failure(monkeypatch, tmp_path):
    made = tmp_path / "mpfs_z"
    made.mkdir()
    monkeypatch.setattr(mpfs.tempfile, "mkdtemp", lambda prefix: str(made))

    def no_binary(*a, **kw):
        raise FileNotFoundError("memprocfs")

    monkeypatch.setattr(mpfs.subprocess, "Popen", no_binary)
    assert mpfs._mount_dump("/ev/dump.raw") == (None, None)
    assert not made.exists()


def test_unmount_releases_the_mount_and_the_daemon(monkeypatch, tmp_path):
    made = tmp_path / "mpfs_u"
    made.mkdir()
    calls = []

    def ok(*a, **kw):
        calls.append(a[0])
        # A real subprocess.run returns a CompletedProcess; _unmount_dump reads
        # its exit code now, because discarding it is what stranded mounts.
        return subprocess.CompletedProcess(a[0], 0, b"", b"")

    monkeypatch.setattr(mpfs.subprocess, "run", ok)
    monkeypatch.setattr(mpfs, "_is_mounted", lambda p: False)
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)
    proc = _FakeProc()

    mpfs._unmount_dump(str(made), proc)
    assert calls == [["fusermount", "-u", str(made)]]
    assert proc.terminated and proc.waited
    assert not made.exists()


def test_a_daemon_that_ignores_terminate_is_killed(monkeypatch, tmp_path):
    made = tmp_path / "mpfs_k"
    made.mkdir()
    monkeypatch.setattr(
        mpfs.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, b"", b""))
    monkeypatch.setattr(mpfs, "_is_mounted", lambda p: False)
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)

    class _Stubborn(_FakeProc):
        def terminate(self):
            raise OSError("refused")

    proc = _Stubborn()
    mpfs._unmount_dump(str(made), proc)
    assert proc.killed, "a daemon holding a view of evidence must not survive"


def test_unmount_survives_fusermount_being_absent(monkeypatch, tmp_path):
    made = tmp_path / "mpfs_f"
    made.mkdir()

    def no_fusermount(*a, **kw):
        raise FileNotFoundError("fusermount")

    monkeypatch.setattr(mpfs.subprocess, "run", no_fusermount)
    monkeypatch.setattr(mpfs.time, "sleep", lambda s: None)
    mpfs._unmount_dump(str(made), None)
    assert not made.exists()


# ── netscan: the short-row fallback ──

def test_a_connection_row_without_a_timestamp_still_parses():
    """Listening sockets and dead SYN_SENT entries carry no time and no
    process path. They are still connections and must not be dropped."""
    rows = mpfs._parse_netstat_v(
        "   #    PID Proto  State        Src   Dst   Process\n"
        "-------------------------------------------------\n"
        "0000      0 TCPv4  SYN_SENT     ***:0                         ***\n"
        "0003    500 TCPv4  LISTENING    [::]:445                      ***\n"
    )
    assert len(rows) == 2
    assert rows[0]["State"] == "SYN_SENT"
    assert (rows[0]["LocalAddr"], rows[0]["LocalPort"]) == ("*", "0")
    assert rows[0]["Owner"] == ""
    assert rows[0]["CreateTime"] == ""
    assert (rows[1]["LocalAddr"], rows[1]["LocalPort"]) == ("::", "445")
    assert rows[1]["PID"] == 500


def test_unparseable_lines_are_skipped_not_fatal():
    rows = mpfs._parse_netstat_v(
        "   #    PID Proto  State        Src   Dst   Process\n"
        "-------------------------------------------------\n"
        "garbage that matches nothing\n"
    )
    assert rows == []
