---
name: tools/memory/memprocfs
description: "Execute MemProcFS memory forensics — FUSE mount for process listing, network connections, VAD maps, services, and registry access. Filesystem metaphor for memory dumps."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, memprocfs, memory-forensics, tool]
metadata:
  hermes:
    tags: [forensic, spectre, memprocfs, memory-forensics, tool]
---

# Forensic Tool: MemProcFS

MemProcFS (Memory Process File System) by Ulf Frisk provides a filesystem-like interface to memory dumps. Files and directories represent processes, modules, VADs, registry hives, and kernel structures.

Two entry points exist — the FUSE mount and a Python API. **Spectre uses the FUSE mount only**, deliberately: the native `vmm.so` can SIGSEGV on some dumps when driven through `Vmm()`, and a SIGSEGV cannot be caught in-process. The Python API is documented below for interactive use, not for the pipeline.

## When to use

- Browsing memory dumps like a filesystem (FUSE mount mode)
- Cross-validating volatility3 findings (dual-tool corroboration)
- YARA scanning within process memory
- Reading Windows registry from memory
- PE header analysis (import/export tables, sections)
- Handles, threads, heaps per process

## Prerequisites

- MemProcFS binary: `/opt/memprocfs/memprocfs` (v5.17.8)
- Dependencies: `libusb-1.0`, `libfuse2`, `lz4` (all installed on SIFT)
- Python API: add `/opt/memprocfs` to `sys.path`

## Installation (SIFT Workstation)

```bash
# Already installed at /opt/memprocfs/
# To reinstall or update:
cd /tmp
curl -sL -o mpfs.tar.gz \
  "https://github.com/ufrisk/MemProcFS/releases/download/v5.17/MemProcFS_files_and_binaries_v5.17.8-linux_x64-20260611.tar.gz"
sudo mkdir -p /opt/memprocfs
cd /opt/memprocfs
sudo tar xzf /tmp/mpfs.tar.gz
sudo chmod +x /opt/memprocfs/memprocfs
```

## Usage Modes

### Mode 1: FUSE Mount (what Spectre uses)

```bash
# Mount a memory dump as a virtual filesystem
mkdir -p /mnt/mem
/opt/memprocfs/memprocfs -device /path/to/dump.raw -mount /mnt/mem

# Browse like a normal filesystem
ls /mnt/mem/                              # Root: pid/, name/, sys/, registry/, forensic/
cat /mnt/mem/sys/proc/proc-time.txt       # Process list, flat, with Exit Time
cat /mnt/mem/sys/proc/proc.txt            # Same set, rendered as a tree
cat /mnt/mem/sys/net/netstat-v.txt        # Network connections, verbose
cat /mnt/mem/pid/1944/win-cmdline.txt     # Command line
cat /mnt/mem/pid/1944/win-environment.txt # Environment block
cat /mnt/mem/pid/1944/memmap/vad.txt      # VAD map (the malfind observation)
ls  /mnt/mem/sys/services/by-name/        # One directory per service

# Unmount when done
fusermount -u /mnt/mem
```

The mount is **writable**, and the daemon outlives the shell that started it. Always unmount — a live view over read-only evidence that survives the analysis is a chain-of-custody liability. Spectre's `extract()` unmounts in a `finally`.

### Mode 2: Python API (NOT used by Spectre)

Available for interactive work. Do not reach for it in pipeline code — see the SIGSEGV pitfall below.

```python
import sys
sys.path.insert(0, "/opt/memprocfs")
import memprocfs

# Initialize with a memory dump
vmm = memprocfs.Vmm(["-device", "/path/to/dump.raw"])

# Process listing
for p in vmm.process_list():
    print(f"PID={p.pid} PPID={p.ppid} Name={p.name}")

# Get a specific process
explorer = vmm.process("explorer.exe")
print(f"SID: {explorer.sid}")
print(f"Path: {explorer.pathkernel}")

# Network connections
for conn in vmm.maps.net():
    print(f"{conn.proto} {conn.local_addr}:{conn.local_port} -> "
          f"{conn.foreign_addr}:{conn.foreign_port} [{conn.state}]")

# Virtual File System (after plugin init)
vmm.initialize_plugins()
for entry in vmm.vfs.list('/'):
    print(entry)

# Read raw memory
data = vmm.memory.read(0x1000, 0x100)  # phys addr 0x1000, 256 bytes

# Process memory read
pe_data = explorer.memory.read(explorer.module("explorer.exe").base, 0x200)

# YARA scanning
rule = 'rule mz_header { strings: $mz = "MZ" condition: $mz at 0 }'
search = explorer.search_yara([rule])
print(search.result())
```

## Artifact Mapping (what Spectre's extractor actually reads)

Every row here is a mount path `extract_memprocfs.extract_from_mount()` opens. The
authoritative list of emitted types is `extract_memprocfs.EMITTED_ARTIFACT_TYPES`,
which `tests/test_memory/test_fk_parser_truth.py` checks the FK YAMLs against.

| MemProcFS mount path | volatility3 plugin | artifact_type |
|---|---|---|
| `sys/proc/proc-time.txt` (`proc.txt` fallback) | windows.pslist | memory_pslist |
| `sys/net/netstat-v.txt` | windows.netscan | memory_netscan |
| `pid/<n>/win-cmdline.txt` | windows.cmdline | memory_cmdline |
| `pid/<n>/win-environment.txt` | windows.envars | memory_envar |
| `pid/<n>/memmap/vad.txt` + `pid/<n>/vmemd/*.vvmem` | windows.malfind | memory_malfind |
| `sys/services/by-name/<svc>/svcinfo.txt` | windows.svcscan | memory_svcscan |
| `registry/HKLM/...` (Run, RunOnce, Winlogon) | windows.registry.printkey | memory_regkey |
| `pid/<n>/modules/` | windows.dlllist | memory_modules |

Reading the VAD map is what makes `memory_malfind` dual-engine. Note what is *not*
here: `forensic/findevil.csv` states a verdict and carries neither a protection nor
a byte preview, so a Spectre rule could only "confirm" it by asserting facts nobody
observed. Read `memmap/vad.txt` — malfind's criterion in raw form — instead.

**Not produced, and not substitutable:**

| volatility3 plugin | why MemProcFS is not a second source |
|---|---|
| windows.filescan | `pid/<n>/handles/handles.txt` is a table of *open handles*; filescan scans physical memory for FILE_OBJECTs whether or not anyone holds them. Different populations, not two views of one. |
| windows.strings / URL carving | no equivalent surface |

## Integration with Spectre Pipeline

The memory module (`src/spectre/modules/memory/`) supports three engines. See `references/memprocfs-integration.md` for the SIGSEGV reproduction, subprocess sandbox pattern, and shell_log integration.

All MemProcFS commands appear in `commands.log` alongside volatility3 invocations — the shared `shell_log.py` logger is called after every subprocess run, and `audit.py` delegates to it on every `append()` call.

```bash
# volatility3 only
spectre-memory --evidence dump.raw --case ~/cases/015-test --engine vol

# MemProcFS only (subprocess sandbox — survives SIGSEGV)
spectre-memory --evidence dump.raw --case ~/cases/015-test --engine memprocfs

# Both engines (the DEFAULT — omitting --engine gives you this)
spectre-memory --evidence dump.raw --case ~/cases/015-test --engine both
```

`--engine both` also prints a per-artifact **row-count comparison**. That is an
extraction-health signal, nothing more: equal totals do not mean the same rows, and
the engines can agree on 53 processes while disagreeing on which 53. It reports
`agree`/`diverge` against a 5% tolerance and deliberately does not use the words
CONFIRMED or FLAGGED — those are a *finding's* corroboration status, decided in
`correlation.corroborate()` on anchors a Spectre rule produced.

## Output

All extraction produces JSON files in `case_dir/raw_extract/` matching volatility3 schema, so the normalize and rules pipeline works identically regardless of engine.

Handle metadata includes `engine` field (`volatility3` or `memprocfs`) for provenance tracking.

## Pitfalls

- **CRITICAL — SIGSEGV risk, and why Spectre is FUSE-only**: The native leechcore.so/vmm.so libraries can crash (SIGSEGV/SIGABRT) on non-Windows or malformed dumps, and Python cannot catch a SIGSEGV — it kills the interpreter. Spectre therefore drives the FUSE **binary**, in a subprocess, so a crash produces a failure handle instead of killing the pipeline. Never call `memprocfs.Vmm()` in pipeline code.
- **Always unmount**: the mount is writable and the daemon is a separate process that outlives its parent. Leaving one behind leaves a live, writable view over read-only evidence.
- **Column layouts are not stable across files**: `sys/proc/proc.txt` is tree-indented (glyphs land in the name column if you split on fixed offsets); `sys/services/services.txt` is fixed-width and runs a full-width display name into the next column. Prefer the flat/per-entity files — `proc-time.txt`, `by-name/<svc>/svcinfo.txt`.
- **`vad.txt` Pages and Commit are hex without an `0x` prefix**, and the Type column is frequently blank — anchor parsing on the fixed 16-16 hex address range, not on column index.
- **`svcinfo.txt`: the binary is `Path:`, not `Image Path:`** — the latter is empty for every service, so a parser reading it fails silently rather than loudly.
- **Python API path**: Must add `/opt/memprocfs` to `sys.path` BEFORE importing `memprocfs`.
- **FUSE mount requires fuse kernel module**: `modprobe fuse` if not loaded.
- **Large memory dumps**: symbol tables load into RAM. An 8 GB SIFT host may swap on >4 GB dumps.
- **memprocfs is AGPL v3**: Review license terms for commercial use cases.
- **Windows-only memory dumps**: MemProcFS primarily targets Windows memory. Linux/macOS support is limited.
- **Binary `-version` flag returns exit code 1**: The memprocfs binary uses `-version` (single dash, not `--version`), and it prints the version correctly but exits with code 1. Do NOT use the binary's exit code as a health check — use `[ -x /opt/memprocfs/memprocfs ]` instead.
- **Not installable as a Python package**: MemProcFS is NOT pip-installable. The Python API module lives at `/opt/memprocfs/memprocfs.py`.
- **Health check**: `spectre-canary` covers this tool. Check the binary's presence, not its exit code, and do not gate on the Python API import — Spectre does not use it, so a failing import is not a degraded pipeline.
  ```bash
  [ -x /opt/memprocfs/memprocfs ] && echo OK
  ```
