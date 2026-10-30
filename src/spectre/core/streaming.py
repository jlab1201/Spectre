"""
streaming.py — memory-bounded readers for large line-oriented / CSV evidence.

These are plain generators: they hold one row/line at a time, never the whole
file, so a normalizer can process gigabyte-scale CSV or unix .log evidence
without materializing it. The logfile module is the first consumer; any module
that reads large text evidence can reuse them.

Partitioning model: callers iterate the generator and decide when to stop
(e.g. at a configured event cap). Because the generator is lazy, a caller that
stops early never reads the remainder — that is the partitioning. To report an
honest "processed N, M remaining" truncation, use `count_remaining()` on the
live generator after stopping (it drains cheaply without building objects).
"""

from __future__ import annotations

import csv as _csv
from typing import Iterator, Optional


def iter_log_lines(path: str) -> Iterator[tuple[int, str]]:
    """Yield (lineno, line) for each non-blank line. Constant memory.

    lineno is 1-based and counts every physical line (so it still maps back to
    the source file even when blank lines are skipped). Decoding errors are
    replaced rather than raised — forensic evidence is often dirty.
    """
    with open(path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if line.strip():
                yield lineno, line


def iter_csv_rows(path: str) -> Iterator[tuple[int, dict]]:
    """Yield (rownum, row_dict) using the header row as keys. Constant memory.

    rownum is 1-based over data rows (the header is row 0). Uses csv.DictReader
    so quoting/embedded-delimiter handling is correct. The dialect is sniffed
    from a sample; falls back to comma on failure.
    """
    with open(path, "r", newline="", errors="replace") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            dialect = _csv.Sniffer().sniff(sample, delimiters=",\t;|")
        except _csv.Error:
            dialect = _csv.excel
        reader = _csv.DictReader(fh, dialect=dialect)
        for rownum, row in enumerate(reader, start=1):
            yield rownum, row


def count_remaining(gen: Iterator, max_count: Optional[int] = None) -> int:
    """Drain a generator counting items, without building a list.

    Used after stopping early at a cap to report how many records went
    un-analyzed. If `max_count` is given, stop counting once reached and return
    that value (so we never walk an unbounded remainder fully) — the caller can
    treat the value as "at least this many".
    """
    n = 0
    for _ in gen:
        n += 1
        if max_count is not None and n >= max_count:
            break
    return n
