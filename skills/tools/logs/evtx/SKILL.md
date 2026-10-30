---
name: tools/logs/evtx
description: "Extract Windows EVTX logs with evtxexport (XML), normalize to NormEvent, size-gate the output, and write the audit row."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, evtx, event-log, tool]
metadata:
  hermes:
    tags: [forensic, spectre, evtx, event-log, tool]
---

# Forensic Tool: EVTX (evtxexport)

Execute Windows Event Log extraction with typed parameters. The module (`src/spectre/modules/evtx/`) runs `evtxexport -f xml`, normalizes to `NormEvent`, and returns a typed handle.

## When to use

- Extracting Windows EVTX files for analysis
- Filtering specific Event IDs (4624, 4625, 4688, 5140, 5156, 7045)
- Converting EVTX to XML for downstream detection
- Part of any artifact profile that includes event logs

## Required inputs

- `evtx_path`: Absolute path to .evtx file
- `case_dir`: Case directory path (for audit trail)
- Optional: `output_path`: Custom output path (default: case_dir/raw_extract/YYYYMMDD_HHMMSS_evtx_<stem>.xml)

## Steps

### 1. Validate EVTX file exists and is readable

```bash
file <evtx_path>  # Should report "MS Windows Vista Event Log"
```

### 2. Execute evtxexport

tool_runner.py is a Python library (import, not CLI). Call from Python:

```python
from spectre.pipeline.tool_runner import run_tool

handle = run_tool(
    case_dir=case_dir,
    tool_name="evtxexport",
    tool_version="libevtx-20251118",
    command=["evtxexport", "-f", "xml", evtx_path],
    params={"artifact_type": "process_creation", "evidence_path": evtx_path,
            "phase": "extraction", "format": "xml"},
    output_path=f"{case_dir}/raw_extract/{timestamp}_evtx_{stem}.xml",
    timeout=600,
    output_format="text",
)
```

### 3. Check the output

Output is XML text; filter by Event ID with grep/xmllint after extraction. If the handle's `result` is not `success`, read `stderr`.

### 4. Apply size gate

If line_count > 500: flag as "NEEDS_FILTERING" — do NOT read into agent context.
Use grep or xmllint to extract specific Event IDs or time ranges.

### 5. Normalize to NormEvent (optional, for detection)

```python
from spectre.modules.evtx.normalize import normalize

events = normalize(handle)   # reads handle["path"], returns list[NormEvent]
```

`NormEvent` (`spectre.core.base`) carries `artifact_type, timestamp, source_file, record_id, host, data, source_tool, source_execution_id`; the event-specific fields (event id, process names, command line, user, IPs, logon type) live in `data`. Field names are defined in `modules/evtx/normalize.py`.

## Output handle

```json
{
  "path": "cases/001/raw_extract/20260627_143000_evtx_Security.xml",
  "line_count": 245,
  "size_bytes": 48210,
  "output_sha256": "def456...",
  "execution_id": "abc123...",
  "exit_code": 0,
  "duration_ms": 2340,
  "result": "success",
  "stderr": ""
}
```

## Empty Data Protocol

If evtxexport returns 0 events: the handle will have line_count=0.
Apply `empty_data_protocol(handle)` → returns "UNVERIFIED".
Never report "no suspicious events" or "clean" — this is an evidence gap, not a conclusion.

## Audit

Every execution writes a `tool_exec` audit row via tool_runner → audit.py:
- Tool: "evtxexport", version from `evtxexport -V`
- Exact command string
- Output SHA-256
- Duration, exit code, result

## FK YAML routing

Extraction attaches no FK envelope. FK YAML (for example `src/spectre/knowledge/artifacts/windows/evtx_4688.yaml`) is routed per finding by `pipeline/fk_routing.py`. It supplies:
- What EVTX 4688 proves (process creation, parent/child, command line)
- What it does NOT prove (DLL still on disk, user intent, single-source limitation)
- Corroboration targets (Prefetch, Amcache, MFT, ShimCache)
- Discipline reminder (injected at explain time, not in findings)

## Pitfalls

- **EVTX 4688 needs audit policy enabled.** If command line is empty string in events, command-line auditing was off. Flag as degraded evidence.
- **Large EVTX files (>100MB) can produce massive XML.** Filter by Event ID before reading any of it.
- **evtxexport emits XML, one `<Event>` per record.** `modules/evtx/normalize.py` parses it.
- **Event ID 4688 was NOT extractable from Hunt-Evil poster text (graphical element).** The FK YAML covers it, but KB search for "4688" will return 0 hits. Use FK YAML directly.
- **Do NOT read raw EVTX XML into agent context.** Always size-gate first. If >500 lines, filter with grep/xmllint for the Event ID.
