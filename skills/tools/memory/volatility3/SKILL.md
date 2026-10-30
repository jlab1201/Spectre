---
name: tools/memory/volatility3
description: "Execute volatility3 plugins with typed parameters — pslist, pstree, cmdline, netscan, malfind, psscan. JSON output, 300s timeout, audit trail per execution."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, volatility3, memory-forensics, tool]
metadata:
  hermes:
    tags: [forensic, spectre, volatility3, memory-forensics, tool]
---

# Forensic Tool: volatility3

Execute volatility3 memory analysis plugins with typed parameters. All plugin output goes through the shared tool_runner for audit, JSON validation, and FK envelope injection.

## When to use

- Analyzing Windows memory dumps (.raw, .vmem, .mem)
- Process listing and tree analysis (pslist, pstree)
- Command-line reconstruction (cmdline)
- Network connection analysis (netscan)
- Malicious code detection (malfind)
- Hidden process detection (psscan)
- Extended analysis: dlllist, handles, modules, svcscan, filescan, vadinfo

## Required inputs

- `image_path`: Absolute path to memory dump
- `plugin`: Volatility3 plugin name (e.g. "windows.pslist")
- `case_dir`: Case directory path
- Optional: `pid`: Filter by process ID
- Optional: `output_path`: Custom output path

## Steps

### 1. Verify image is valid

```bash
vol -f <image_path> windows.info 2>&1 | head -20
```

Check for "Windows" in output. If vol can't parse the image, it's corrupted or wrong format.

### 2. Execute plugin

```python
from spectre.pipeline.tool_runner import run_tool

handle = run_tool(
    case_dir=case_dir,
    tool_name=f"vol:{plugin}",
    tool_version="2.7.0",
    command=[
        "vol",
        "-q",
        "-r", "json",
        "-f", image_path,
        plugin,           # e.g. "windows.pslist"
    ],
    params={
        "image_path": image_path,
        "plugin": plugin,
    },
    output_path=output_path,
    timeout=300,
    output_format="json",
)
```

### 3. Plugin-specific commands

| Plugin | Command | What it returns |
|--------|---------|----------------|
| windows.pslist | `vol -r json -f <img> windows.pslist` | Process list (PID, PPID, name, start time) |
| windows.pstree | `vol -r json -f <img> windows.pstree` | Process tree (parent-child hierarchy) |
| windows.cmdline | `vol -r json -f <img> windows.cmdline` | Full command lines per process |
| windows.cmdline --pid | `vol -f <img> windows.cmdline --pid <PID>` | Command line for specific PID |
| windows.netscan | `vol -r json -f <img> windows.netscan` | Network connections (TCP/UDP, state, IPs) |
| windows.malfind | `vol -r json -f <img> windows.malfind` | Injected code / hidden DLLs |
| windows.malfind --pid | `vol -f <img> windows.malfind --pid <PID>` | Malfind for specific process |
| windows.psscan | `vol -r json -f <img> windows.psscan` | Physical process scan (finds hidden/terminated) |
| windows.dlllist --pid | `vol -f <img> windows.dlllist --pid <PID>` | Loaded DLLs per process |
| windows.handles --pid | `vol -f <img> windows.handles --pid <PID>` | Open handles per process |
| windows.svcscan | `vol -r json -f <img> windows.svcscan` | Windows services |
| windows.filescan | `vol -r json -f <img> windows.filescan` | Open file objects (file paths, inodes) |

### 4. Apply size gate

Volatility JSON output can be large. Always check:
- pslist/pstree: usually <200 lines (safe)
- netscan: usually <500 lines (safe)
- cmdline: depends on process count (often safe)
- malfind: can be VERY large for infected systems (NEEDS_FILTERING)

### 5. Cross-validation

For critical findings, run both pslist and psscan and compare PID lists.
Delta >5% → flag as possible hidden processes.

## Output handle

Every handle carries an `engine` metadata field (`"volatility3"` or `"memprocfs"`) for provenance tracking. When both engines run, `spectre-memory` prints a per-artifact row-count comparison (`agree`/`diverge` at a 5% tolerance). That is an extraction-health signal only; corroboration status is decided on finding anchors in `correlation.corroborate()`.

```json
{
  "path": "cases/001/raw_extract/20260627_143500_vol_memory_pslist.json",
  "line_count": 87,
  "size_bytes": 12340,
  "output_sha256": "abc123...",
  "is_json": true,
  "fk_envelope": null,
  "execution_id": "def456...",
  "exit_code": 0,
  "duration_ms": 4520,
  "result": "success",
  "stderr": "",
  "engine": "volatility3"
}
```

## Dual-engine alternative: MemProcFS

The pipeline runs MemProcFS as a second engine over the same image, in the same case, so matching claims corroborate. **This is the default** — `--engine both` is what you get without the flag. See the `tools/memory/memprocfs` skill.

```bash
# volatility3 only
spectre-memory --evidence dump.raw --case ~/cases/015-test --engine vol

# Both engines (the default)
spectre-memory --evidence dump.raw --case ~/cases/015-test --engine both
```

Not every artifact type is dual-engine: `memory_url` (strings carving) and `memory_filescan` (a FILE_OBJECT scan of physical memory, which MemProcFS has no equivalent of) are volatility3-only and stay single-source.

MemProcFS runs in a subprocess sandbox — its native .so libraries can SIGSEGV on non-Windows dumps, so a crash produces a failure handle instead of killing the pipeline.

## Audit

Every plugin execution writes `tool_exec` row with:
- Tool: `vol:<plugin>` (for example `vol:windows.pslist.PsList`)
- Version: from `vol_version()`
- Plugin name in params
- Output SHA-256
- Duration

## Pitfalls

- **8 GB RAM on SIFT host is tight for large memory dumps.** Use `--pid` to target specific processes. For full scans, expect swapping.
- **vol must be in PATH.** Session canary checks this. If DEGRADED, skip volatility analysis.
- **JSON output: use `-r json`** and let `run_tool(output_path=...)` capture stdout. Without it vol prints a text table, which fails JSON validation.
- **malfind output can be 10K+ lines on infected systems.** Always size-gate. Filter with grep for suspicious indicators: `grep -i 'protection\|inject\|VAD'`.
- **Volatility runs as user, not root.** Memory dumps are files — no elevated privileges needed.
- **netscan shows ALL connections including terminated.** Filter by state: `jq 'select(.State == "ESTABLISHED")'`.
- **Do NOT run all plugins blindly.** Start with pslist → pstree → cmdline → netscan. Only run malfind if suspicious processes detected.
