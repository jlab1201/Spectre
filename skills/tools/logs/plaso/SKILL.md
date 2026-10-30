---
name: tools/logs/plaso
description: "Execute plaso log2timeline and psort with typed parameters. CSV/JSON output, 1800s timeout, stream-handle for large timeline DBs."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, plaso, timeline, tool]
metadata:
  hermes:
    tags: [forensic, spectre, plaso, timeline, tool]
---

# Forensic Tool: plaso (log2timeline + psort)

Execute plaso super-timeline generation and querying with typed parameters. Plaso output is streamed — never loaded entirely into agent context.

## When to use

- Building a super-timeline from disk images, memory dumps, or log files
- Querying existing plaso storage for specific time ranges or event types
- Cross-referencing timeline events with other artifacts
- Part of any investigation requiring temporal correlation

## Required inputs

- `evidence_path`: Path to evidence (disk image, directory, log file)
- `case_dir`: Case directory path
- `storage_path`: Path to plaso storage file (.plaso)
- Optional: `time_start`, `time_end`: ISO-8601 time range filter
- Optional: `filter_pattern`: grep pattern for timeline filtering

## Steps

### 1. Create timeline (log2timeline)

```python
from spectre.pipeline.tool_runner import run_tool

handle = run_tool(
    case_dir=case_dir,
    tool_name="plaso_log2timeline",
    tool_version="20260119",
    command=[
        "log2timeline.py",
        "--storage-file", storage_path,
        evidence_path,
    ],
    params={
        "evidence_path": evidence_path,
        "storage_path": storage_path,
    },
    output_path=f"{case_dir}/timeline/log2timeline.stdout",
    timeout=1800,
    output_format="text",
)
```

### 2. Export timeline (psort)

```python
handle = run_tool(
    case_dir=case_dir,
    tool_name="plaso_psort",
    tool_version="20260119",
    command=[
        "psort.py",
        "-o", "l2tcsv",
        "-w", output_csv_path,
        storage_path,
    ],
    params={
        "storage_path": storage_path,
        "output_format": "l2tcsv",
    },
    output_path=output_csv_path,
    timeout=1800,
    output_format="csv",
)
```

### 3. Filter timeline (psort with time range)

```bash
psort.py -o l2tcsv -w <output> <storage> "date > '2026-06-27T00:00:00' AND date < '2026-06-28T00:00:00'"
```

### 4. Apply size gate — MANDATORY

Plaso timelines are MASSIVE (100K+ lines for even modest evidence). NEVER read directly.
Filter first:

```bash
# Extract specific event types
grep -i '4688\|4624\|4625\|process' timeline.csv > filtered/process_events.csv

# Time window
awk -F',' '$1 >= "2026-06-27T10:00" && $1 <= "2026-06-27T12:00"' timeline.csv > filtered/window.csv

# Specific paths
grep -i 'Temp\|AppData\|Downloads' timeline.csv > filtered/suspicious_paths.csv
```

## Output handle

```json
{
  "path": "cases/001/timeline/timeline.csv",
  "line_count": 245321,
  "size_bytes": 48720000,
  "output_sha256": "abc123...",
  "is_json": false,
  "fk_envelope": null,
  "execution_id": "def456...",
  "exit_code": 0,
  "duration_ms": 452000,
  "result": "success",
  "stderr": ""
}
```

## Pipeline pattern

```
log2timeline → .plaso storage → psort → .csv → grep/awk filter → filtered/subset.csv → agent context
```

The RAW .csv NEVER enters agent context. Only filtered subsets do.

## Audit

Every execution writes `tool_exec` row:
- log2timeline: tool="plaso_log2timeline"
- psort: tool="plaso_psort"

## Pitfalls

- **Plaso is SLOW.** 1800s timeout for log2timeline on large evidence. Expect multi-hour runs for full disk images.
- **Storage files can be 10+ GB.** Ensure sufficient disk space (67 GB free on SIFT host — acceptable).
- **Do NOT run psort without time filter on large timelines.** The CSV output alone can be 50+ GB.
- **psort queries are string-based, not SQL.** Use double quotes: `"date > '2026-01-01'"`.
- **l2tcsv format has these columns:** date, time, timezone, MACB, source, source_type, type, user, host, short_desc, long_desc, filename, inode.
- **Filtered output goes to `filtered/`, not `raw_extract/`.** Keep raw in raw_extract/, filtered subsets in filtered/.
- **Plaso is not a module-declared tool, so `spectre-canary` does not check it.** Run `log2timeline.py --version` yourself before relying on it; plaso is an optional follow-on to disk triage, not part of the deterministic pipeline.
