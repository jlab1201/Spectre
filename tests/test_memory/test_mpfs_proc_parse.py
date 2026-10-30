"""WS2 — the MemProcFS process parser.

`sys/proc/proc.txt` is a TREE-INDENTED rendering. The original parser sliced
it at fixed offsets, which produced three defects measured on the real
Challenge.raw artifact (see ~/spectre-cases/272-004-memory):

  * 38 of 48 names kept their tree glyphs ('-- svchost.exe'), so every rule
    keyed on image_basename silently failed to match volatility's rows;
  * 10 rows parsed PPID as 0 (firefox.exe 2080 is really parented by 3060),
    so memory-anomalous-parent could not fire at all;
  * 5 processes at tree depth 4 were dropped entirely, because the extra
    indentation pushed the PID out of the sliced window.

MemProcFS also publishes `sys/proc/proc-time.txt` -- flat, no tree glyphs,
and carrying Exit Time and the full image path. It is available WITHOUT
forensic mode, so it is the correct primary source.

The 5 dropped PIDs are asserted by name below because the delta they created
(53 vol vs 48 memprocfs) looks exactly like a rootkit hiding indicator; the
FK YAML tells an examiner to escalate it. It must never reappear.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spectre.modules.memory.extract_memprocfs import _parse_proc_txt

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "memprocfs"

# Present in volatility's pslist; dropped by the original fixed-offset parser
# because each sits at process-tree depth 4.
DEPTH_4_PIDS = {1008, 1868, 1876, 2292, 2896}


@pytest.fixture
def proc_time_rows():
    return _parse_proc_txt((FIXTURES / "proc-time.txt").read_text())


def test_every_process_is_parsed(proc_time_rows):
    assert len(proc_time_rows) == 53


def test_depth_4_processes_are_not_dropped(proc_time_rows):
    pids = {r["PID"] for r in proc_time_rows}
    missing = DEPTH_4_PIDS - pids
    assert not missing, f"tree-depth-4 processes dropped again: {sorted(missing)}"


def test_names_carry_no_tree_glyphs(proc_time_rows):
    dirty = [r["ImageFileName"] for r in proc_time_rows
             if r["ImageFileName"] != r["ImageFileName"].strip()
             or r["ImageFileName"].startswith("-")]
    assert not dirty, f"tree glyphs leaked into image names: {dirty}"


@pytest.mark.parametrize("pid,expected_ppid", [
    (4, 0),          # System
    (2080, 3060),    # firefox.exe -- parsed as 0 by the original parser
    (4084, 1944),    # DumpIt.exe  -- parsed as 0 by the original parser
    (2292, 608),     # WmiPrvSE.exe at depth 4 -- dropped entirely before
    (1008, 780),     # audiodg.exe at depth 4  -- dropped entirely before
])
def test_parent_pid_matches_volatility(proc_time_rows, pid, expected_ppid):
    row = next(r for r in proc_time_rows if r["PID"] == pid)
    assert row["PPID"] == expected_ppid


def test_user_with_a_space_is_not_split(proc_time_rows):
    """"NETWORK SERVICE" / "LOCAL SERVICE" must survive column slicing."""
    users = {r.get("User") for r in proc_time_rows}
    assert "NETWORK SERVICE" in users
    assert "LOCAL SERVICE" in users


def test_exit_time_is_empty_for_live_processes(proc_time_rows):
    """MemProcFS renders "still running" as ***. enrich.py's hidden-process
    guard treats a non-empty exit_time as "legitimately terminated", so a
    literal *** would suppress every genuine hidden-process finding."""
    assert all(r.get("ExitTime", "") == "" for r in proc_time_rows)


def test_create_time_is_preserved(proc_time_rows):
    row = next(r for r in proc_time_rows if r["PID"] == 4)
    assert "2019-08-19" in row["CreateTime"]


def test_tree_indented_proc_txt_is_still_parsed_correctly():
    """The legacy source stays supported as a fallback -- and must now strip
    its own tree glyphs rather than baking them into the process name."""
    rows = _parse_proc_txt((FIXTURES / "proc.txt").read_text())
    pids = {r["PID"] for r in rows}
    assert DEPTH_4_PIDS <= pids, "fallback parser still drops depth-4 rows"
    assert not [r for r in rows if r["ImageFileName"].startswith("-")]
    assert next(r for r in rows if r["PID"] == 2080)["PPID"] == 3060
