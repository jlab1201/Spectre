# Hardcoded Path Inventory — Spectre Forensic Project

Scanned 2026-06-27. This is the complete inventory of every hardcoded path found
across the project. Use this as a checklist when executing the restructuring.

> **STATUS: HISTORICAL — the restructuring described here is done.** Every
> `forensic-kb/...` path below is the *pre-move* location and no longer exists;
> the tree is now `src/spectre/` (`scripts/` → `pipeline/`, `modules/` →
> `modules/`, `artifacts/` → `knowledge/artifacts/`), paths resolve through
> `src/spectre/config.py`, and `scripts/session-canary.sh` was replaced by the
> `spectre-canary` console script. Kept as the record of what the audit found,
> not as a map of the current tree — do not follow these paths, and do not
> "correct" them either, or the record stops matching what was audited.

## Group A: `Path.home() / "forensic-kb" / ...` (30 occurrences, 14 files)

| # | File | Line | What it references |
|---|------|------|-------------------|
| 1 | forensic-kb/scripts/run.py | 16 | `SCRIPTS_DIR = Path.home() / "forensic-kb" / "scripts"` |
| 2 | forensic-kb/scripts/run.py | 17 | `CASES_DIR = Path.home() / "cases"` |
| 3 | forensic-kb/scripts/run.py | 18 | `SPIKE_DIR = Path.home() / "spike"` |
| 4 | forensic-kb/scripts/phase_runner.py | 33 | `SCRIPTS_DIR` |
| 5 | forensic-kb/scripts/phase_runner.py | 34 | `FK_DIR = Path.home() / "forensic-kb" / "artifacts" / "windows"` |
| 6 | forensic-kb/scripts/phase_runner.py | 35 | `MITRE_MAP_PATH` |
| 7 | forensic-kb/scripts/phase_runner.py | 36 | `SPIKE_DIR` |
| 8 | forensic-kb/scripts/phase_runner.py | 121 | `hash_db = Path.home() / "forensic-kb" / "hashes" / "known-bad.json"` |
| 9 | forensic-kb/scripts/phase_runner.py | 122 | `ip_db` |
| 10 | forensic-kb/scripts/phase_runner.py | 164 | `_MODULES_DIR` |
| 11 | forensic-kb/scripts/phase_runner.py | 166 | FK windows dir |
| 12 | forensic-kb/scripts/phase_runner.py | 167 | FK network dir |
| 13 | forensic-kb/scripts/phase_runner.py | 710 | cases dir |
| 14 | forensic-kb/scripts/case_setup.py | 26 | `CASES_DIR` |
| 15 | forensic-kb/scripts/case_setup.py | 27 | `SCRIPTS_DIR` |
| 16 | forensic-kb/scripts/case_setup.py | 29 | FK windows dir |
| 17 | forensic-kb/scripts/case_setup.py | 30 | FK network dir |
| 18 | forensic-kb/scripts/case_setup.py | 32 | `MITRE_MAP` |
| 19 | forensic-kb/scripts/build_index.py | 12 | `REFERENCES` |
| 20 | forensic-kb/scripts/build_index.py | 13 | `INDEX_DB` |
| 21 | forensic-kb/scripts/cross_case_index.py | 22 | `DEFAULT_CASES_DIR` |
| 22 | forensic-kb/scripts/recognize.py | 26 | `_MODULES_DIR` |
| 23 | forensic-kb/scripts/spectre-memory | 27 | `SCRIPTS_DIR` |
| 24 | forensic-kb/scripts/spectre-memory | 28 | `MODULES_DIR` |
| 25 | forensic-kb/scripts/extract_posters.py | 7 | `desktop` |
| 26 | forensic-kb/scripts/extract_posters.py | 8 | `output_dir` |
| 27 | forensic-kb/modules/evtx/extract.py | 17 | `_SCRIPTS_DIR` |
| 28 | forensic-kb/modules/memory/extract.py | 14 | `_SCRIPTS_DIR` |
| 29 | forensic-kb/modules/memory/extract.py | 26 | `SYMBOLS_DIR` |
| 30 | forensic-kb/modules/memory/extract.py | 51 | `_CARVE_SCRIPT` |
| 31 | forensic-kb/modules/memory/extract_memprocfs.py | 28 | `_SCRIPTS_DIR` |
| 32 | forensic-kb/modules/disk/extract.py | 18 | `_SCRIPTS_DIR` |
| 33 | forensic-kb/modules/pcap/extract.py | 9 | `_SCRIPTS_DIR` |
| 34 | spike/core/audit.py | 23 | `_SCRIPTS_DIR` |
| 35 | forensic-kb/modules/evtx/tests/test_evtx.py | 17 | `_SCRIPTS` |
| 36 | forensic-kb/modules/tests/test_memory_rules.py | 19 | `_SCRIPTS` |
| 37 | forensic-kb/modules/tests/test_routing.py | 15 | `_SCRIPTS` |
| 38 | forensic-kb/modules/pcap/tests/test_pcap.py | 8 | `_SCRIPTS` |

## Group B: absolute home-directory literal strings (5 files)

| # | File | What |
|---|------|------|
| 1 | forensic-kb/scripts/denylist.py:57,85-87 | Regex patterns for case dirs |
| 2 | forensic-kb/scripts/shell_log.py:20 | Default case dir in argparse |
| 3 | forensic-kb/scripts/subagent_templates.py:467 | index.db path in subagent prompt |
| 4 | forensic-kb/scripts/subagent_templates.py:628 | FK YAML path in subagent prompt |
| 5 | cases/e2e_test.py:11,12,19,21,22,25 | All paths hardcoded as strings |

## Group C: `sys.path.insert(...)` (25 occurrences, 17 files)

Every module that needs a cross-directory import uses sys.path.insert instead of
proper package imports. All 25 become `from spectre.X import Y` after restructuring.

Files affected:
- forensic-kb/modules/registry.py:31
- forensic-kb/modules/evtx/tests/test_evtx.py:18-19
- forensic-kb/modules/evtx/extract.py:19
- forensic-kb/modules/memory/extract_memprocfs.py:30,34
- forensic-kb/modules/memory/extract.py:16
- forensic-kb/modules/tests/test_memory_rules.py:20-21
- forensic-kb/modules/tests/test_routing.py:16-17
- forensic-kb/modules/disk/extract.py:20
- forensic-kb/modules/pcap/tests/test_pcap.py:7-8
- forensic-kb/modules/pcap/extract.py:11
- forensic-kb/scripts/run.py:20-21,415
- forensic-kb/scripts/phase_runner.py:41-42,198
- forensic-kb/scripts/evidence-register.sh:53 (script since removed; registration is `case_setup`)
- forensic-kb/scripts/spectre-memory:29-30
- forensic-kb/scripts/tool_runner.py:26
- forensic-kb/scripts/session-canary.sh:46
- forensic-kb/scripts/recognize.py:27
- forensic-kb/scripts/case_setup.py:116,138,228
- forensic-kb/scripts/emit_finding.py:27
- forensic-kb/scripts/canary.py:23
- forensic-kb/scripts/evidence_guard.py:21
- spike/core/run_spike.py:14
- spike/core/audit.py:25
- spike/core/verify.py:22
- cases/e2e_test.py:11-12

## Group D: `/opt/` paths (3 files, acceptable as defaults)

These reference actual system install locations. Keep as overridable defaults
via environment variables.

| # | File | What |
|---|------|------|
| 1 | forensic-kb/modules/memory/extract_memprocfs.py:32 | `_MEMPROCFS_DIR = "/opt/memprocfs"` |
| 2 | forensic-kb/modules/memory/extract.py:24 | Comment about `/opt/volatility3` |
| 3 | forensic-kb/scripts/session-canary.sh:45 | `[ -x /opt/memprocfs/memprocfs ]` |

## Group E: `~/spectre-venv` (2 files, remove)

Auto-activation logic that `pip install -e .` makes obsolete.

| # | File | What |
|---|------|------|
| 1 | forensic-kb/scripts/run.py:268 | `venv_python = os.path.expanduser("~/spectre-venv/bin/python3")` |
| 2 | forensic-kb/scripts/phase_runner.py:1029,1032,1034 | Venv warning + auto-activation |

## Replacement Pattern

Every hardcoded path becomes:

```python
from spectre.config import CASES_DIR, CACHE_DIR, KNOWLEDGE_DIR, MITRE_MAP_PATH

# Old:
SCRIPTS_DIR = Path.home() / "forensic-kb" / "scripts"

# New:
from spectre.config import CASES_DIR  # or the specific config value needed
```

All config values are overridable via environment variables:
- `SPECTRE_CASES_DIR` (default: `~/spectre-cases/`)
- `SPECTRE_CACHE_DIR` (default: `~/.cache/spectre/`)
- `SPECTRE_VOL_PATH`, `SPECTRE_MEMPROCFS_DIR`, etc.
