"""logfile/normalize.py — stream CSV rows / unix log lines into NormEvents.

Memory-bounded: rows/lines are pulled one at a time from core.streaming
generators, never the whole file. A configurable cap (config.LOGFILE_MAX_EVENTS)
protects the still-materializing downstream phases; when a file exceeds it, the
remainder is reported as un-analyzed via a console warning — never silently
dropped (Empty Data Protocol).
"""

from __future__ import annotations

import re
from pathlib import Path

from spectre.config import LOGFILE_MAX_EVENTS
from spectre.core.base import NormEvent
from spectre.core.streaming import iter_csv_rows, iter_log_lines, count_remaining

ARTIFACT = "logfile_record"

# Column names (case-insensitive) commonly carrying an event timestamp.
_TS_COLUMNS = ("timestamp", "time", "date", "datetime", "@timestamp", "ts",
               "_time", "eventtime", "event_time", "created", "logged")

# syslog/auth.log line: "Jun 28 16:18:20 host proc[123]: message"
_SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$")

# BSD-syslog carries no year and no timezone (conventionally local time on
# the *originating* host, which Spectre has no way to determine). It also
# fails report_synthesize._parse_finding_ts and clustering._parse_time, so
# it silently falls into the "undated"/unclustered bucket — this caveat
# tells the analyst WHY, instead of leaving it silent (A6 Finding 7).
_SYSLOG_TS_CAVEAT = (
    "Timestamp has no year and no timezone (classic BSD-syslog format); "
    "conventionally local time on the originating host, which cannot be "
    "determined from this evidence alone — treat as ambiguous, not "
    "resolved to a specific UTC instant.")


def _csv_timestamp(row: dict) -> str:
    for key in row:
        if key and key.strip().lower() in _TS_COLUMNS:
            return str(row.get(key) or "")
    return ""


def _is_csv(path: str) -> bool:
    return Path(path).suffix.lower() in (".csv", ".tsv")


def normalize(handle: dict, max_events: int | None = None) -> list[NormEvent]:
    """Stream the evidence into NormEvents (capped). Constant memory during read.

    `max_events` overrides config.LOGFILE_MAX_EVENTS for tests; 0 means no cap.
    """
    path = handle.get("path")
    if not path or not Path(path).exists():
        return []
    source = handle.get("evidence_path", path)
    cap = LOGFILE_MAX_EVENTS if max_events is None else max_events

    if _is_csv(path):
        gen = iter_csv_rows(path)
        events = _consume_csv(gen, source, cap)
    else:
        gen = iter_log_lines(path)
        events = _consume_log(gen, source, cap)
    return events


def _capped(gen, cap: int, build, source: str):
    """Shared cap/truncation loop. `build` maps (num, record) -> NormEvent."""
    events: list[NormEvent] = []
    for num, record in gen:
        if cap and len(events) >= cap:
            # Surface the un-analyzed remainder; never drop silently.
            remaining = count_remaining(gen, max_count=cap) + 1
            _warn_truncated(source, len(events), remaining)
            break
        events.append(build(num, record))
    return events


def _consume_csv(gen, source: str, cap: int) -> list[NormEvent]:
    def build(num, row):
        return NormEvent(
            artifact_type=ARTIFACT,
            timestamp=_csv_timestamp(row),
            source_file=source,
            record_id=str(num),
            data={"_kind": "csv", **{k: v for k, v in row.items() if k is not None}},
        )
    return _capped(gen, cap, build, source)


def _consume_log(gen, source: str, cap: int) -> list[NormEvent]:
    def build(num, line):
        m = _SYSLOG.match(line)
        if m:
            data = {"_kind": "log", "host": m.group("host"),
                    "message": m.group("msg"), "raw": line,
                    "ts_caveat": _SYSLOG_TS_CAVEAT}
            return NormEvent(ARTIFACT, m.group("ts"), source, str(num),
                             host=m.group("host"), data=data)
        return NormEvent(ARTIFACT, "", source, str(num),
                         data={"_kind": "log", "message": line, "raw": line})
    return _capped(gen, cap, build, source)


def _warn_truncated(source: str, processed: int, remaining_at_least: int) -> None:
    try:
        from spectre.pipeline import console
        console.note(
            f"logfile: {source} exceeds cap — analyzed first {processed} "
            f"record(s); >= {remaining_at_least} remaining were NOT analyzed "
            f"(raise SPECTRE_LOGFILE_MAX_EVENTS to cover more).")
    except Exception:
        pass
