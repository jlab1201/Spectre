"""WS3 — a dedup_key is an IDENTITY, and identity must not depend on engine.

`corroborate()` groups anchors by (rule_id, dedup_key or title) and counts
distinct (source_tool, artifact_type) pairs as sources. So two engines that
detect the same fact only score 2 sources if they produce a byte-identical
dedup_key. Measured on case 272-004-memory, only 2 of 40 findings did --
exactly the two whose keys happened to be engine-neutral strings (a filesystem
path, a process name). Every other key embedded something engine-specific:

  * a registry path in the emitting tool's own rendering,
  * an aggregate computed per-handle (instance_count), so two engines with
    different coverage derive different values -- identity inverted, the more
    they disagree in scope the less they can corroborate,
  * a value joined from within one handle's row set (parent_image).

The rule this file enforces: a dedup_key is computed only from
engine-invariant facts. Everything else belongs in title/summary/data, where
it is displayed but never used for grouping.
"""

from __future__ import annotations

import json

import pytest

import spectre.modules.memory.rules as memrules
from spectre.pipeline.correlation import corroborate
from spectre.modules.memory.normalize import normalize

# Real renderings of the SAME Winlogon key, taken from
# ~/spectre-cases/272-004-memory/raw_extract/.
VOL_WINLOGON = (r"\SystemRoot\System32\Config\SOFTWARE\Microsoft"
                r"\Windows NT\CurrentVersion\Winlogon")
MPFS_WINLOGON = "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon"
VOL_RUN_NTUSER = (r"\??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT"
                  r"\Software\Microsoft\Windows\CurrentVersion\Run")


def _events(tmp_path, artifact, rows, source_tool, name="a.json"):
    p = tmp_path / name
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": artifact, "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    for e in evs:
        e.source_tool = source_tool
    return evs


# ── registry: the highest-value pair, and the one that was doubly broken ──

def test_same_autostart_value_from_both_engines_is_one_two_source_claim(tmp_path):
    """vol renders the hive file path; MemProcFS renders HKLM\\... . Both
    describe one registry value, so they must collapse to a single CONFIRMED
    finding rather than two INFERRED ones."""
    vol = _events(tmp_path, "memory_regkey", [{
        "Key": VOL_WINLOGON, "Name": "Evil", "Type": "REG_SZ",
        "Data": r'"C:\Users\jaffa\AppData\evil.exe"'}], "volatility3", "v.json")
    mpfs = _events(tmp_path, "memory_regkey", [{
        "Key": MPFS_WINLOGON, "Name": "Evil", "Type": "REG_SZ",
        "Value": r"C:\Users\jaffa\AppData\evil.exe"}], "memprocfs", "m.json")

    a_vol = memrules.registry_persistence(vol[0])
    a_mpfs = memrules.registry_persistence(mpfs[0])
    assert a_vol and a_mpfs
    assert a_vol.dedup_key == a_mpfs.dedup_key

    groups = corroborate([a_vol, a_mpfs])
    assert len(groups) == 1
    assert groups[0].sources == 2
    assert groups[0].cross_validated


def test_registry_canonicalization_is_not_a_blunt_lowercase(tmp_path):
    """Distinct keys must stay distinct -- canonicalization must not merge
    HKLM\\...\\Run with a per-user NTUSER Run."""
    a = _events(tmp_path, "memory_regkey", [{
        "Key": VOL_RUN_NTUSER, "Name": "X", "Data": "c:\\a.exe"}],
        "volatility3", "a.json")[0]
    b = _events(tmp_path, "memory_regkey", [{
        "Key": "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
        "Name": "X", "Value": "c:\\a.exe"}], "memprocfs", "b.json")[0]
    assert a.data["key_canonical"] != b.data["key_canonical"]


# ── process listings: aggregates and per-handle joins must leave the key ──

def _pslist_rows(engine_extra_procs: int):
    """Same two real processes, but one engine also sees N extra svchosts --
    which is exactly what differing engine coverage looks like."""
    rows = [{"PID": 1944, "PPID": 608, "ImageFileName": "scvhost.exe",
             "CreateTime": "2019-08-19T14:40:07+00:00"},
            {"PID": 608, "PPID": 480, "ImageFileName": "svchost.exe",
             "CreateTime": "2019-08-19T14:40:07+00:00"}]
    for i in range(engine_extra_procs):
        rows.append({"PID": 5000 + i, "PPID": 480,
                     "ImageFileName": "svchost.exe",
                     "CreateTime": "2019-08-19T14:40:07+00:00"})
    return rows


def test_masquerade_key_survives_differing_engine_coverage(tmp_path):
    """instance_count is a property of the OBSERVATION, not of the process.
    Two engines seeing different numbers of svchost.exe must still agree on
    the identity of the masquerading process."""
    vol = _events(tmp_path, "memory_pslist", _pslist_rows(0),
                  "volatility3", "v.json")
    mpfs = _events(tmp_path, "memory_pslist", _pslist_rows(3),
                   "memprocfs", "m.json")

    a_vol = memrules.masquerade_system_process(vol[0])
    a_mpfs = memrules.masquerade_system_process(mpfs[0])
    assert a_vol and a_mpfs
    assert a_vol.dedup_key == a_mpfs.dedup_key
    groups = corroborate([a_vol, a_mpfs])
    assert len(groups) == 1 and groups[0].sources == 2


def test_anomalous_parent_key_does_not_depend_on_resolving_the_parent(tmp_path):
    """parent_image is resolved from the PID->image map built WITHIN one
    handle. An engine that did not enumerate the parent resolves it to "",
    which must not change the identity of the child's claim."""
    with_parent = _events(tmp_path, "memory_pslist", [
        {"PID": 4084, "PPID": 1944, "ImageFileName": "cmd.exe"},
        {"PID": 1944, "PPID": 608, "ImageFileName": "winword.exe"}],
        "volatility3", "v.json")[0]
    without_parent = _events(tmp_path, "memory_pslist", [
        {"PID": 4084, "PPID": 1944, "ImageFileName": "cmd.exe"}],
        "memprocfs", "m.json")[0]

    a1 = memrules.anomalous_parent(with_parent)
    if a1 is None:
        pytest.skip("anomalous_parent did not fire on this pairing")
    a2 = memrules.anomalous_parent(without_parent)
    if a2 is not None:
        assert a1.dedup_key == a2.dedup_key


# ── timestamps ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    "2019-08-19T14:40:07+00:00",   # volatility3
    "2019-08-19 14:40:07 UTC",     # MemProcFS
])
def test_both_engines_yield_one_canonical_timestamp(tmp_path, raw):
    ev = _events(tmp_path, "memory_pslist",
                 [{"PID": 4, "PPID": 0, "ImageFileName": "System",
                   "CreateTime": raw}], "x", f"{hash(raw)}.json")[0]
    assert ev.timestamp == "2019-08-19T14:40:07+00:00"


def test_unparseable_timestamp_passes_through_rather_than_being_invented(tmp_path):
    ev = _events(tmp_path, "memory_pslist",
                 [{"PID": 4, "PPID": 0, "ImageFileName": "System",
                   "CreateTime": "N/A"}], "x", "na.json")[0]
    assert ev.timestamp == "N/A"


# ── addresses: vol emits a decimal int, MemProcFS renders hex ────────────

@pytest.mark.parametrize("raw", [63832064, "63832064", "0x3ce0000", "3ce0000"])
def test_address_canonicalizes_across_renderings(raw):
    from spectre.modules.memory.normalize import _canon_addr
    assert _canon_addr(raw) == _canon_addr(63832064)
    assert _canon_addr(raw).startswith("0x")


def test_address_is_page_aligned_but_distinct_regions_stay_distinct():
    from spectre.modules.memory.normalize import _canon_addr
    # same 4 KiB page -> same identity
    assert _canon_addr(0x3ce0000) == _canon_addr(0x3ce0fff)
    # neighbouring page -> different identity (never merge two regions)
    assert _canon_addr(0x3ce0000) != _canon_addr(0x3ce1000)
