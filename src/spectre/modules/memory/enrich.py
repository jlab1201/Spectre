"""memory/enrich.py — hidden-process cross-check (pslist vs psscan) and
process-derived CreateTime join.

pslist walks the EPROCESS active-process linked list; psscan walks pool
tags directly and can surface processes that have been unlinked from that
list — a classic DKOM-style hiding technique (T1564.001) — which pslist
misses entirely. Comparing the two listings for the SAME evidence file and
SAME engine (source_tool) is the standard cross-view hidden-process check.

The comparison is scoped per (source_file, source_tool): different memory
images, or the same image seen through different engines, are not directly
comparable. Critically, a psscan run with NO corresponding pslist baseline
for the same file+tool must NOT be treated as "everything is hidden" — an
absent baseline is a gap in coverage, not a finding, so we stamp nothing
in that case rather than fabricate a claim from missing data.

Track D (gold case 004): process-derived artifacts that carry no CreateTime
of their own (malfind rows have no CreateTime column) leave their finding's
event_time empty, so the report timeline drops them into "Undated" even
though pslist/psscan know exactly when the process was created. This module
joins those events to the pslist/psscan CreateTime baseline by PID, scoped
the same way as the hidden-process check. A PID with no resolvable
CreateTime is left alone — this must NEVER fall back to analysis wall-clock
time; an undated finding is honest, a wall-clock-stamped one is not.

Why here and not normalize.py: extract() runs pslist/malfind/psscan as
SEPARATE tool invocations, each producing its own handle, and phase_runner
calls `module.normalize(handle)` once per handle — so a single normalize()
call for the malfind handle never sees the pslist handle's rows. enrich(),
by contrast, runs once over the FULL cross-artifact event list for the
whole case (after all handles for all evidence files have been normalized,
before rules run), which is exactly the join this needs and is the seam
the module protocol already provides for cross-event facts (see the
hidden-process check above, same pattern).
"""

from __future__ import annotations

from collections import defaultdict

# Artifacts that carry their own authoritative process CreateTime (set on
# NormEvent.timestamp by normalize.py). Both are valid join sources: pslist
# is canonical, psscan additionally covers processes hidden from pslist.
_PROCESS_LISTING_TYPES = ("memory_pslist", "memory_psscan")


def enrich_events(events: list) -> None:
    """Stamp `hidden_from_pslist=True` on psscan events whose pid is
    absent from the pslist baseline for the same (source_file, source_tool),
    and stamp `timestamp` on undated process-derived events (e.g. malfind)
    by joining their PID against the pslist/psscan CreateTime baseline.

    Mutates event.data/event.timestamp in place; never adds/removes events
    (required by the Phase 3 enrich-hook contract).
    """
    pslist_pids: dict[tuple[str, str], set] = defaultdict(set)
    # PID -> CreateTime, scoped per (source_file, source_tool). pslist is
    # recorded first so it wins ties; psscan only fills gaps for PIDs
    # pslist never saw (hidden processes).
    pid_create_time: dict[tuple[str, str], dict] = defaultdict(dict)

    def _remember_create_time(e) -> None:
        pid = e.data.get("pid")
        create_time = e.data.get("create_time") or e.timestamp
        if pid is None or not create_time:
            return
        pid_create_time[(e.source_file, e.source_tool)].setdefault(pid, create_time)

    for e in events:
        if e.artifact_type != "memory_pslist":
            continue
        pid = e.data.get("pid")
        if pid is not None:
            pslist_pids[(e.source_file, e.source_tool)].add(pid)
        _remember_create_time(e)

    for e in events:
        if e.artifact_type != "memory_psscan":
            continue
        baseline = pslist_pids.get((e.source_file, e.source_tool))
        if baseline and e.data.get("pid") not in baseline:
            e.data["hidden_from_pslist"] = True
        # No baseline at all for this file+engine is a coverage gap, not a
        # finding (see module docstring) — but CreateTime join is unrelated
        # to that guard, so psscan rows always contribute to the map.
        _remember_create_time(e)

    for e in events:
        if e.timestamp:
            continue  # never overwrite a timestamp the artifact already has
        pid = e.data.get("pid")
        if pid is None:
            continue
        create_time = pid_create_time.get((e.source_file, e.source_tool), {}).get(pid)
        if create_time:
            e.timestamp = str(create_time)
