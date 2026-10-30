r"""WS5 — MemProcFS VAD as a real second source for code injection.

Measured on case 839-900-mpfs-verify: 38 of 40 findings were single-source
purely because MemProcFS produced no rows for their artifact type. Three of
those 38 are `memory_malfind`. MemProcFS *does* observe the same regions --
it just publishes them as `pid/<n>/memmap/vad.txt` rather than as a malfind
verdict -- so the fix is to transcribe that observation, not to import a
verdict from `forensic/findevil.csv` (see the observation-vs-verdict doctrine
in skills/correlation-engine/SKILL.md).

Ground truth, captured live from Challenge.raw on 2026-08-07:

  * 21 VAD regions across 53 processes are private+executable (`p-rwx-`).
  * Of those, exactly 4 have a non-zero Commit -- and those 4 are precisely
    the 4 rows volatility3's windows.malfind reported, at byte-identical
    addresses.
  * The other 17 are the WOW64 thunk regions at 0x77410000 / 0x77510000,
    present identically in 11 unrelated processes with Commit == 0. Emitting
    them would manufacture 17 injection findings on a benign image, so the
    committed test is load-bearing, not a tidiness filter.

Fixtures under tests/fixtures/memprocfs/vad_*.txt are byte-exact excerpts of
the live mount (contiguous line runs, header included, nothing retyped).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spectre.modules.memory.extract_memprocfs import (
    _collect_vad_regions,
    _is_injection_candidate,
    _parse_vad_txt,
    _read_region_head,
    _vad_protection,
)
from spectre.modules.memory.normalize import normalize
from spectre.pipeline.correlation import corroborate
import spectre.modules.memory.rules as memrules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "memprocfs"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# ── the parser ──

def test_header_and_rule_are_not_rows():
    rows = _parse_vad_txt(_fixture("vad_1944_explorer.txt"))
    assert len(rows) == 20, "22 lines in the excerpt: 2 header, 20 data rows"
    assert all(r["pid"] == 1944 for r in rows)


def test_range_is_parsed_as_start_and_end_ints():
    rows = _parse_vad_txt(_fixture("vad_1944_explorer.txt"))
    r = next(r for r in rows if r["index"] == "0071")
    assert r["start"] == 0x3CE0000
    assert r["end"] == 0x3CE0FFF
    # 63832064 is exactly what vol's windows.malfind reported as Start VPN.
    assert r["start"] == 63832064


def test_pages_and_commit_are_hexadecimal():
    """MemProcFS renders Pages/Commit in hex with no 0x prefix. Row 0005 spans
    0x60000-0x15ffff = 0x100 pages and prints "100"; reading that as decimal
    would understate the region by 156 pages."""
    rows = _parse_vad_txt(_fixture("vad_1944_explorer.txt"))
    r = next(r for r in rows if r["index"] == "0005")
    assert r["pages"] == 0x100
    assert r["commit"] == 0x100
    assert (r["end"] - r["start"] + 1) // 0x1000 == r["pages"]


def test_optional_type_column_splits_from_flags_and_description():
    rows = {r["index"]: r for r in _parse_vad_txt(_fixture("vad_1944_explorer.txt"))}
    # File-backed, with a path description
    assert rows["0006"]["type"] == "File"
    assert rows["0006"]["flags"] == "--r---"
    assert rows["0006"]["description"] == r"\Windows\System32\locale.nls"
    # Heap, with a bracketed description containing a space
    assert rows["0000"]["type"] == "Heap"
    assert rows["0000"]["description"] == "HEAP-01 [NtSegment]"
    # Blank Type column -- must not swallow the flags token
    assert rows["0071"]["type"] == ""
    assert rows["0071"]["flags"] == "p-rwx-"
    assert rows["0071"]["description"] == ""


def test_flag_positions_match_the_observed_vocabulary():
    """Confirmed over every vad.txt on the live mount: position 0 is p(rivate),
    1 is unused, 2-4 are r/w/x, 5 is c(opy-on-write)."""
    rows = {r["index"]: r for r in _parse_vad_txt(_fixture("vad_1944_explorer.txt"))}
    assert rows["008b"]["flags"] == "---w-c"
    assert rows["0005"]["flags"] == "p-rw--"


# ── the selection predicate ──

def test_committed_private_executable_region_is_a_candidate():
    rows = _parse_vad_txt(_fixture("vad_1944_explorer.txt"))
    hits = [r for r in rows if _is_injection_candidate(r)]
    assert [r["start"] for r in hits] == [0x3CE0000, 0x4320000]


def test_uncommitted_wow64_thunks_are_not_candidates():
    """The 0x77410000/0x77510000 pair is private+rwx in 11 unrelated processes
    with Commit == 0. vol reported none of them. Dropping the committed test
    would put 17 false injection findings on a benign image."""
    rows = _parse_vad_txt(_fixture("vad_4084_dumpit.txt"))
    assert len(rows) == 2
    assert all(r["flags"] == "p-rwx-" for r in rows)
    assert all(r["commit"] == 0 for r in rows)
    assert [r for r in rows if _is_injection_candidate(r)] == []


def test_heap_labelled_region_is_still_a_candidate():
    """MemProcFS annotates PID 2292's region as HEAP-06; vol tagged the same
    region VadS and reported it. The label is MemProcFS's own annotation, not
    a file backing -- excluding it would lose a real dual-engine pair."""
    rows = _parse_vad_txt(_fixture("vad_2292_wmiprvse.txt"))
    assert rows[0]["type"] == "Heap"
    assert _is_injection_candidate(rows[0])


def test_file_backed_and_non_executable_regions_are_not_candidates():
    rows = {r["index"]: r for r in _parse_vad_txt(_fixture("vad_1944_explorer.txt"))}
    assert not _is_injection_candidate(rows["0006"])   # File, --r---
    assert not _is_injection_candidate(rows["008b"])   # File, ---w-c
    assert not _is_injection_candidate(rows["0005"])   # Heap, p-rw-- (no x)
    assert not _is_injection_candidate(rows["0004"])   # private rw, no x


# ── protection rendering ──

@pytest.mark.parametrize("flags,expected", [
    ("p-rwx-", "PAGE_EXECUTE_READWRITE"),
    ("--r-x-", "PAGE_EXECUTE_READ"),
    ("---wxc", "PAGE_EXECUTE_WRITECOPY"),
    ("----x-", "PAGE_EXECUTE"),
    ("p-rw--", "PAGE_READWRITE"),
    ("--r---", "PAGE_READONLY"),
    ("p-----", "PAGE_NOACCESS"),
])
def test_protection_is_rendered_from_the_observed_flag_bits(flags, expected):
    """The flag string IS the observation; this only re-renders it in the
    vocabulary the rule already reads. Nothing is inferred."""
    assert _vad_protection(flags) == expected


# ── region bytes ──

def _mount_with_region(tmp_path, pid, start, payload, suffix=""):
    d = tmp_path / "pid" / str(pid) / "vmemd"
    d.mkdir(parents=True)
    (d / f"0x{start:016x}{suffix}.vvmem").write_bytes(payload)
    return str(tmp_path)


def test_region_head_is_read_from_the_mount(tmp_path):
    mount = _mount_with_region(tmp_path, 1944, 0x4320000,
                               bytes.fromhex("41ba800000004"
                                             "8b838a186fffe0700"))
    head, ok = _read_region_head(mount, 1944, 0x4320000, "")
    assert ok is True
    assert head.startswith("41 ba 80 00 00 00 48 b8")


def test_region_head_matches_the_vmemd_filename_description_suffix(tmp_path):
    """MemProcFS appends the region description to the vmemd filename, e.g.
    `0x0000000001bd0000-HEAP-06 [NtSegment].vvmem`. Matching on the bare
    address alone finds nothing for exactly the regions that carry a label."""
    mount = _mount_with_region(tmp_path, 2292, 0x1BD0000,
                               bytes.fromhex("0000000000000000af3a72cb08c60001"),
                               suffix="-HEAP-06 [NtSegment]")
    head, ok = _read_region_head(mount, 2292, 0x1BD0000, "HEAP-06 [NtSegment]")
    assert ok is True
    assert head.startswith("00 00 00 00 00 00 00 00 af 3a 72 cb")


def test_unreadable_region_is_reported_as_unread_not_as_absence_of_a_pe(tmp_path):
    """`has_pe_header=False` derived from a region we never read is an
    inference, not an observation. The caller must be able to tell them apart."""
    (tmp_path / "pid" / "9" / "vmemd").mkdir(parents=True)
    head, ok = _read_region_head(str(tmp_path), 9, 0x1000, "")
    assert head == ""
    assert ok is False


# ── the emitted rows ──

def test_collected_rows_carry_everything_the_rule_requires(tmp_path):
    """`check_rule_fields` pools required field names globally, so a row that
    omits one of protection/has_pe_header/pid/process/address makes the rule
    NOT_EVALUATE and silently drops every hit."""
    mount = tmp_path / "mnt"
    (mount / "pid" / "1944" / "memmap").mkdir(parents=True)
    (mount / "pid" / "1944" / "memmap" / "vad.txt").write_text(
        _fixture("vad_1944_explorer.txt"))
    (mount / "pid" / "1944" / "vmemd").mkdir(parents=True)
    (mount / "pid" / "1944" / "vmemd" / f"0x{0x4320000:016x}.vvmem").write_bytes(
        bytes.fromhex("4d5a90000300000004000000"))

    rows = _collect_vad_regions(str(mount), 1944, "explorer.exe")
    assert len(rows) == 2
    by_addr = {r["Address"]: r for r in rows}

    pe = by_addr["0x0000000004320000"]
    assert pe["PID"] == 1944
    assert pe["Process"] == "explorer.exe"
    assert pe["Protection"] == "PAGE_EXECUTE_READWRITE"
    assert pe["Hexdump"].startswith("4d 5a 90 00")
    assert pe["RegionBytesRead"] is True

    unread = by_addr["0x0000000003ce0000"]
    assert unread["Hexdump"] == ""
    assert unread["RegionBytesRead"] is False


def test_collected_rows_normalize_into_events_the_rule_fires_on(tmp_path):
    mount = tmp_path / "mnt"
    (mount / "pid" / "1944" / "memmap").mkdir(parents=True)
    (mount / "pid" / "1944" / "memmap" / "vad.txt").write_text(
        _fixture("vad_1944_explorer.txt"))

    rows = _collect_vad_regions(str(mount), 1944, "explorer.exe")
    p = tmp_path / "mpfs_malfind.json"
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": "memory_malfind", "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    assert len(evs) == 2
    anchors = [a for a in (memrules.injected_code(e) for e in evs) if a]
    assert len(anchors) == 2
    assert {a.dedup_key for a in anchors} == {
        "1944:0x000003ce0000", "1944:0x000004320000"}


# ── the point of the exercise: cross-engine corroboration ──

# Real rows, copied out of
# ~/spectre-cases/839-900-mpfs-verify/raw_extract/*_vol_memory_malfind.json.
VOL_EXPLORER_ROWS = [
    {"PID": 1944, "Process": "explorer.exe", "Start VPN": 63832064,
     "End VPN": 63836159, "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS",
     "CommitCharge": 1, "PrivateMemory": 1,
     "Hexdump": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"},
    {"PID": 1944, "Process": "explorer.exe", "Start VPN": 70385664,
     "End VPN": 70451199, "Protection": "PAGE_EXECUTE_READWRITE", "Tag": "VadS",
     "CommitCharge": 16, "PrivateMemory": 1,
     "Hexdump": "41 ba 80 00 00 00 48 b8 38 a1 86 ff fe 07 00 00"},
]


def _events(tmp_path, rows, source_tool, name):
    p = tmp_path / name
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": "memory_malfind", "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    for e in evs:
        e.source_tool = source_tool
    return evs


def test_the_same_injected_region_from_both_engines_is_one_two_source_claim(tmp_path):
    """vol renders the region start as a decimal int (63832064); MemProcFS
    renders it as 0x0000000003ce0000. Same region, same claim -- so it must
    collapse to one CONFIRMED finding, not two INFERRED ones."""
    mount = tmp_path / "mnt"
    (mount / "pid" / "1944" / "memmap").mkdir(parents=True)
    (mount / "pid" / "1944" / "memmap" / "vad.txt").write_text(
        _fixture("vad_1944_explorer.txt"))

    vol = _events(tmp_path, VOL_EXPLORER_ROWS, "volatility3", "vol.json")
    mpfs = _events(tmp_path, _collect_vad_regions(str(mount), 1944, "explorer.exe"),
                   "memprocfs", "mpfs.json")

    anchors = [a for a in (memrules.injected_code(e) for e in vol + mpfs) if a]
    assert len(anchors) == 4

    groups = corroborate(anchors)
    assert len(groups) == 2, "two regions, not four findings"
    for g in groups:
        assert g.sources == 2
        assert g.cross_validated
        assert sorted(g.source_labels) == ["memprocfs/memory_malfind",
                                           "volatility3/memory_malfind"]


def test_addresses_agree_exactly_between_engines_on_real_evidence(tmp_path):
    """No widening was needed to make these match: the page-alignment in
    _canon_addr is a no-op here because both engines report the same VAD base.
    If a future change makes this pass only by coarsening the key, that is
    fabricated corroboration and this test should be the one that notices."""
    mount = tmp_path / "mnt"
    (mount / "pid" / "1944" / "memmap").mkdir(parents=True)
    (mount / "pid" / "1944" / "memmap" / "vad.txt").write_text(
        _fixture("vad_1944_explorer.txt"))
    mpfs_starts = {int(r["Address"], 16)
                   for r in _collect_vad_regions(str(mount), 1944, "explorer.exe")}
    vol_starts = {r["Start VPN"] for r in VOL_EXPLORER_ROWS}
    assert mpfs_starts == vol_starts
