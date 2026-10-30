---
name: tools/scanner/yara
description: "Execute YARA scans with typed parameters — rules file, target path, timeout. 600s timeout, match output parsing, audit trail."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, yara, malware, tool]
metadata:
  hermes:
    tags: [forensic, spectre, yara, malware, tool]
---

# Forensic Tool: YARA

Execute YARA rule scans against files, directories, or memory dumps. Parses match output and returns structured results.

No Spectre module runs yara and `spectre.config` has no YARA constant (rules directory or binary path); pass `rules_path` explicitly.

## When to use

- Scanning extracted files for malware signatures
- Scanning memory dumps for known malware patterns
- Running custom YARA rules for IOCs
- Part of any investigation requiring signature-based detection

## Required inputs

- `rules_path`: Path to YARA rules file or directory
- `target_path`: Path to scan (file, directory, or memory dump)
- `case_dir`: Case directory path
- Optional: `recursive`: Scan directories recursively (-r flag)
- Optional: `timeout`: Max seconds (default 600)

## Steps

### 1. Verify rules compile

```bash
yara -C <rules_path> /dev/null 2>&1
```

If rules don't compile, fix syntax before scanning.

### 2. Execute scan

```python
from spectre.pipeline.tool_runner import run_tool

handle = run_tool(
    case_dir=case_dir,
    tool_name="yara",
    tool_version="4.5.0",
    command=[
        "yara",
        "-r",                    # recursive
        "-w",                    # disable warnings
        "-s",                    # print matched strings
        rules_path,
        target_path,
    ],
    params={
        "rules_path": rules_path,
        "target_path": target_path,
        "recursive": True,
        "print_strings": True,
    },
    output_path=f"{case_dir}/raw_extract/{ts}_yara.txt",
    timeout=600,
    output_format="text",
)
```

### 3. Parse match output

YARA output format per match:
```
rule_name target_path
0xOFFSET:$string_name: matched_string_value
```

Parse with:
```python
import re
matches = []
for line in handle_output.split('\n'):
    if ':' not in line or line.startswith('0x'):
        continue
    rule, target = line.split(' ', 1)
    matches.append({"rule": rule, "target": target})
```

### 4. Apply Empty Data Protocol

If no matches found (line_count=0): apply empty_data_protocol → "UNVERIFIED".
Never report "clean" or "no malware found" — this is a detection gap, not a conclusion.

### 5. Size gate

YARA output is usually small (<200 lines even for many matches). If >500 lines, filter by rule severity or target path.

## Output handle

```json
{
  "path": "cases/001/raw_extract/20260627_150000_yara.txt",
  "line_count": 12,
  "size_bytes": 840,
  "output_sha256": "abc123...",
  "is_json": false,
  "fk_envelope": null,
  "execution_id": "def456...",
  "exit_code": 0,
  "duration_ms": 45200,
  "result": "success",
  "stderr": ""
}
```

## Known rules locations on SIFT

- `/usr/share/yara/` — system-wide rules
- SANS poster IOCs can be converted to YARA rules

## Audit

Every scan writes `tool_exec` row:
- Tool: "yara"
- Version: from `yara --version`
- Rules path + target path in params
- Match count in params["match_count"] (parsed from output)
- Output SHA-256

## Pitfalls

- **YARA scanning large directories is SLOW.** Use `-r` only when needed. For targeted scans, specify individual files.
- **Memory dump scanning: YARA scans the file as raw bytes.** Volatility plugins (malfind) are more precise for in-memory patterns.
- **Rules must match the target type.** Windows PE rules won't match Linux ELF binaries and vice versa.
- **0 matches is NOT "clean."** Always apply Empty Data Protocol. The rules may not cover the malware family.
- **Keep custom rules outside `/usr/share/yara/`.** SIFT system rules there are maintained by apt and will be overwritten.
- **yara-python is the Python binding.** `python3 -c "import yara; print(yara.YARA_VERSION)"` should report 4.5.0.
