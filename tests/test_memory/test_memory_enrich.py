"""test_memory_enrich.py — hidden-process cross-check (pslist vs psscan)
and process-derived CreateTime join (Track D, gold case 004 timeline fix).

`enrich_events()` cross-references psscan pids against a pslist baseline
scoped to the SAME (source_file, source_tool). psscan walks pool tags
directly and can surface processes unlinked from the active-process list
(DKOM-style hiding) that pslist — which walks the EPROCESS linked list —
misses entirely. The comparison must stay scoped per evidence file +
engine, and absence of a pslist baseline for a given file+tool must NOT
be treated as "everything is hidden" — that would fabricate a finding
from a missing baseline, not a real signal.

It also joins process-derived events that carry no CreateTime of their own
(malfind rows have no CreateTime column) against the pslist/psscan
CreateTime baseline by PID, scoped the same way, so the report timeline
(which keys off event_time) is populated with the real process creation
time instead of dropping these findings into "Undated". A PID with no
resolvable CreateTime must stay undated — never wall-clock stamped.
"""

from spectre.core.base import NormEvent
from spectre.modules.memory.enrich import enrich_events


def _pslist(pid, source_file="mem.raw", source_tool="volatility3", create_time=""):
    return NormEvent(
        artifact_type="memory_pslist", timestamp=create_time, source_file=source_file,
        record_id=f"pslist-{pid}", source_tool=source_tool,
        data={"pid": pid, "image": "x.exe", "image_basename": "x.exe",
              "create_time": create_time},
    )


def _psscan(pid, source_file="mem.raw", source_tool="volatility3", create_time=""):
    return NormEvent(
        artifact_type="memory_psscan", timestamp=create_time, source_file=source_file,
        record_id=f"psscan-{pid}", source_tool=source_tool,
        data={"pid": pid, "image": "x.exe", "image_basename": "x.exe",
              "create_time": create_time},
    )


def _malfind(pid, source_file="mem.raw", source_tool="volatility3"):
    return NormEvent(
        artifact_type="memory_malfind", timestamp="", source_file=source_file,
        record_id=f"malfind-{pid}", source_tool=source_tool,
        data={"pid": pid, "process": "notepad.exe", "address": "0x5000000",
              "protection": "PAGE_EXECUTE_READWRITE", "has_pe_header": True},
    )


def test_psscan_pid_absent_from_pslist_is_stamped():
    events = [
        _pslist(1), _pslist(2), _pslist(3),
        _psscan(1), _psscan(2), _psscan(3), _psscan(666),
    ]
    enrich_events(events)

    stamped = [e for e in events
               if e.artifact_type == "memory_psscan" and e.data.get("hidden_from_pslist")]
    assert [e.data["pid"] for e in stamped] == [666]

    # Matched pids must NOT be stamped at all (no False-stamping either).
    for e in events:
        if e.artifact_type == "memory_psscan" and e.data["pid"] != 666:
            assert "hidden_from_pslist" not in e.data


def test_no_pslist_baseline_stamps_nothing():
    # No pslist events at all for this file+tool -> absence of a baseline
    # must not fabricate "hidden".
    events = [_psscan(1), _psscan(2)]
    enrich_events(events)
    assert all("hidden_from_pslist" not in e.data for e in events)


def test_baseline_is_scoped_per_source_file_and_tool():
    events = [
        _pslist(1, source_file="a.raw"),
        _psscan(1, source_file="a.raw"),
        _psscan(999, source_file="a.raw"),   # hidden in a.raw (has a baseline)
        _psscan(1, source_file="b.raw"),     # no pslist baseline for b.raw
    ]
    enrich_events(events)

    a_hidden = [e for e in events if e.source_file == "a.raw" and e.data["pid"] == 999][0]
    assert a_hidden.data.get("hidden_from_pslist") is True

    a_matched = [e for e in events if e.source_file == "a.raw" and e.data["pid"] == 1][0]
    assert "hidden_from_pslist" not in a_matched.data

    b = [e for e in events if e.source_file == "b.raw"][0]
    assert "hidden_from_pslist" not in b.data


def test_baseline_is_scoped_per_source_tool():
    # Same file, different engines: a memprocfs psscan-shaped event (were
    # one ever to exist) must not be cleared by a volatility3 pslist
    # baseline for the same file.
    events = [
        _pslist(1, source_file="mem.raw", source_tool="volatility3"),
        _psscan(2, source_file="mem.raw", source_tool="memprocfs"),
    ]
    enrich_events(events)
    assert "hidden_from_pslist" not in events[1].data


def test_enrich_does_not_add_or_remove_events():
    events = [_pslist(1), _psscan(1), _psscan(2)]
    n_before = len(events)
    enrich_events(events)
    assert len(events) == n_before


# ── process-derived CreateTime join (Track D, gold case 004 timeline) ────
def test_malfind_gets_create_time_from_pslist_pid_join():
    events = [
        _pslist(1337, create_time="2019-05-14 10:15:00"),
        _malfind(1337),
    ]
    enrich_events(events)
    malfind = [e for e in events if e.artifact_type == "memory_malfind"][0]
    assert malfind.timestamp == "2019-05-14 10:15:00"


def test_malfind_stays_undated_when_pid_not_resolvable():
    # No pslist/psscan baseline at all for this PID -> must NOT be stamped
    # with analysis wall-clock time; it stays undated.
    events = [_pslist(1, create_time="2019-05-14 10:15:00"), _malfind(9999)]
    enrich_events(events)
    malfind = [e for e in events if e.artifact_type == "memory_malfind"][0]
    assert malfind.timestamp == ""


def test_malfind_create_time_scoped_per_source_file_and_tool():
    # Same PID number in an unrelated evidence file must not leak its
    # CreateTime into this file's malfind event.
    events = [
        _pslist(1337, source_file="other.raw", create_time="2019-05-14 10:15:00"),
        _malfind(1337, source_file="mem.raw"),
    ]
    enrich_events(events)
    malfind = [e for e in events if e.artifact_type == "memory_malfind"][0]
    assert malfind.timestamp == ""


def test_malfind_create_time_falls_back_to_psscan_for_hidden_process():
    # A hidden process (absent from pslist) is only visible via psscan;
    # its CreateTime must still resolve for a malfind hit on the same PID.
    events = [
        _psscan(666, create_time="2019-05-14 11:00:00"),
        _malfind(666),
    ]
    enrich_events(events)
    malfind = [e for e in events if e.artifact_type == "memory_malfind"][0]
    assert malfind.timestamp == "2019-05-14 11:00:00"


def test_existing_malfind_timestamp_never_overwritten():
    # If an event already carries its own timestamp, the PID join must not
    # clobber it with a different (or same) pslist CreateTime.
    malfind = _malfind(1337)
    malfind.timestamp = "2020-01-01 00:00:00"
    events = [_pslist(1337, create_time="2019-05-14 10:15:00"), malfind]
    enrich_events(events)
    assert malfind.timestamp == "2020-01-01 00:00:00"
