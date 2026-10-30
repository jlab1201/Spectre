---
name: tools/disk/sleuthkit
description: "Execute Sleuth Kit tools (mmls, fls, fsstat, istat, icat) with typed parameters. 300s timeout, audit trail per execution."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, sleuthkit, disk-forensics, tool]
metadata:
  hermes:
    tags: [forensic, spectre, sleuthkit, disk-forensics, tool]
---

# Forensic Tool: Sleuth Kit (mmls, fls, fsstat, istat, icat)

Execute Sleuth Kit disk forensics tools with typed parameters. Layer over raw disk images or E01 files.

## When to use

- Analyzing disk images (raw, E01, AFF) for partition layout, filesystem metadata, and file extraction
- Part of disk-light or full-windows artifact profiles
- Extracting specific files by inode for deeper analysis

## Required inputs

- `image_path`: Path to disk image
- `tool`: Which sleuthkit tool (mmls, fls, fsstat, istat, icat)
- `case_dir`: Case directory path
- Optional: `offset`: Partition offset (from mmls output)
- Optional: `inode`: Inode number (for istat, icat, fls)

## Steps

### 1. Partition layout (mmls)

```python
from spectre.pipeline.tool_runner import run_tool

handle = run_tool(
    case_dir=case_dir,
    tool_name="mmls",
    tool_version="4.11.1",
    command=["mmls", image_path],
    params={"image_path": image_path},
    output_path=f"{case_dir}/raw_extract/{ts}_mmls.txt",
    timeout=60,
    output_format="text",
)
```

Output shows partition table: slot, start sector, end sector, length, description.
Note the start sector of the main NTFS partition (usually the largest).

### 2. Filesystem metadata (fsstat)

```bash
fsstat -o <partition_offset> <image_path>
```

Shows: volume label, cluster size, sector size, total sectors, MFT location, last mount time.

### 3. File listing (fls)

```bash
fls -r -o <partition_offset> <image_path>          # recursive
fls -r -o <partition_offset> <image_path> <inode>  # specific directory
```

Output: inode|type|size|name — one file/dir per line.
- r/r = regular file
- d/d = directory
- r/r * = deleted file
- File names with * suffix = deleted

### 4. Inode details (istat)

```bash
istat -o <partition_offset> <image_path> <inode>
```

Shows: MFT entry details — timestamps (4x: SI + FN), attributes, data runs, resident/non-resident.

### 5. File extraction (icat)

Never write into `<case_dir>/evidence/` (locked `0555` after registration). Only
Phase 2 carving (`modules/disk/carve.py`) writes `evidence/derived/<image_stem>/`, and
only `phase_runner` registers those files (`derived_evidence_register` row, hashed,
`chmod 444`). Never hand-append that row. An ad-hoc extraction is NOT registered
evidence: run it through `tool_runner.run_tool()` into `raw_extract/` so it gets a
`tool_exec` row with its sha256:

```bash
python3 -c 'import sys; from spectre.pipeline.tool_runner import run_tool; from spectre.config import ICAT_PATH; c, img, off, ino = sys.argv[1:5]; h = run_tool(case_dir=c, tool_name="icat", tool_version="sleuthkit", command=[ICAT_PATH, "-o", off, img, ino], params={"inode": ino, "partition_offset": off, "evidence_path": img}, output_path=f"{c}/raw_extract/icat_{ino}.bin", output_format="binary"); print(h["result"], h.get("output_sha256"), h.get("execution_id"), h.get("stderr", ""))' <case_dir> <case_dir>/evidence/<image_name> <partition_offset> <inode>
```

Extracts file content by inode. Output is binary.
Verify with: `file <case_dir>/raw_extract/icat_<inode>.bin` and `sha256sum` it against
the printed `output_sha256`.

### 6. Apply size gate

- mmls output: always safe (<20 lines)
- fsstat output: always safe (<50 lines)
- fls output: can be 100K+ lines — MUST filter: `grep -i 'Temp\|AppData\|Downloads\|ProgramData'`
- istat output: always safe (<30 lines per inode)
- icat output: binary, use `file` and `sha256sum` on result, NOT content read

## Output handle

```json
{
  "path": "cases/001/raw_extract/20260627_144000_fls.txt",
  "line_count": 87234,
  "size_bytes": 5200000,
  "output_sha256": "abc123...",
  "is_json": false,
  "fk_envelope": null,
  "execution_id": "def456...",
  "exit_code": 0,
  "duration_ms": 3420,
  "result": "success",
  "stderr": ""
}
```

## Audit

Each tool writes `tool_exec` row:
- Pipeline extraction (`modules/disk/extract.py`) audits `tool="mmls"` and `tool="fls"` (`fls -r -m / -z UTC`, body-file format).
- Use the same bare tool names (`fsstat`, `istat`, `icat`) for ad-hoc runs so rows stay greppable alongside the pipeline's.

## Corroboration pattern

- **MFT entry (istat)** + **fls listing** — cross-validate file existence
- **fsstat volume info** + **mmls partition table** — validate correct offset
- **icat extracted file** + **sha256sum** — integrity check post-extraction

Delta >5% between tools → flag as possible filesystem manipulation.

## Pitfalls

- **Always use `-o <offset>` with fls/fsstat/istat/icat.** Without offset, tools operate on the raw disk (wrong results).
- **Offset must match EXACTLY from mmls.** Sectors, not bytes. Multiply by 512 for byte offset if needed by other tools.
- **icat extracts BINARY — never read into context.** Use `file` command and `sha256sum` on the extracted file.
- **fls -r on large drives produces 100K+ lines.** Always filter with grep before reading.
- **Sleuthkit works on E01 directly (via libewf).** No need to convert E01 to raw.
- **Deleted files have * suffix in fls output.** Filter with: `grep '\*' fls_output.txt`
