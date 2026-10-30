---
name: core
description: "Spectre Phase 0.5 vertical-slice spike — the proven base pattern for adding new forensic artifact support."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, spike, pipeline]
metadata:
  hermes:
    tags: [forensic, spectre, spike, pipeline]
---

# Spectre Vertical-Slice Spike Pattern

After successfully implementing and verifying the Phase 0.5 spike, this documents
the pattern for adding new artifact support later. Every new artifact follows this
same structure.

> **Naming:** this skill (`core`) documents the vertical-slice workflow. Shared code lives under `src/spectre/core/` (base classes, normalize, detect, emit, explain), per-artifact analyzers under `src/spectre/modules/<artifact>/`, and FK YAML + the MITRE map under `src/spectre/knowledge/`.

## Directory layout

```
src/spectre/core/
  base.py           # NormEvent, Anchor, Rule, Recognizer, AnalyzerModule
  normalize.py / detect.py / emit_finding.py / explain.py
src/spectre/modules/<artifact>/
  module.yaml       # registration, fk_yamls
  recognizer.py  extract.py  normalize.py  rules.py | rules/
src/spectre/knowledge/
  artifacts/<domain>/<artifact>.yaml   # FK YAML
  mitre-map.yaml                       # rule → allowed MITRE IDs
tests/fixtures/
```

## Build order

Each step is independently testable against sample evidence before the next:

1. `module.yaml` + `recognizer.py` — recognize the evidence type
2. `extract.py` — run the tool through `tool_runner.run_tool()` (audited handle)
3. `normalize.py` — tool output → `NormEvent` (canonical fields; keep `<field>_raw`)
4. Rule pack — `rules.py` or `rules/*.py` (see `docs/contributing-rules.md`), plus a
   `mitre-map.yaml` entry per rule
5. FK YAML under `src/spectre/knowledge/artifacts/<domain>/`, listed in `module.yaml` `fk_yamls`

`modules/registry.py` discovers the module from the filesystem; no other edits are needed.

## Key constraints

- audit.py: use json.dumps(sort_keys=True, separators=(",",":")) for canonical hashing
- normalize.py: _basename handles Windows backslash paths on Linux (replace \\, rsplit /)
- detect.py: raw docstrings for paths containing backslashes (SyntaxWarning on Python 3.12)
- emit_finding.py: discipline_reminder is NOT a caveat; it goes to the explain prompt
- explain.py: validator #4 uses exact string match after whitespace-strip; caveats must be verbatim
- Path resolution: use `from spectre.config import ...` instead of hardcoded `Path.home() / "..."` (post-restructuring). Pre-restructuring, `run_spike.py` uses `BASE = Path(__file__).parent.parent`.
- verify.py: case-insensitive parent match; dll_path check uses list membership not str()

## Pass criteria (8 checks)

1. Exactly 1 finding; record NNNN only
2. must_not_flag_records NOT flagged
3. status, confidence, mitre match oracle
4. execution_id resolves to audit row
5. audit.verify_chain() == True; tamper → False
6. Explanation contains no invented findings/MITRE; confidence unchanged
7. Adversarial claim stripped and logged
8. report.md exists and ties to finding_id

## Pitfalls encountered

- pathlib.Path on Linux doesn't treat backslash as separator → hand-rolled _basename
- YAML dump of paths with backslashes → verify.py must use list membership check
- DeepSeek may wrap JSON in markdown → extract from ```json blocks or {…} patterns
- DeepSeek may truncate JSON at max_tokens → auto-close braces, increase max_tokens for adversarial
- DeepSeek v4-pro may resist mild adversarial prompts → use stronger prompt with fake network details
  to guarantee a C2/network claim the validator can strip
- Python 3.12 SyntaxWarning on backslash in non-raw docstring → use r"""docstring"""
- verify.py Check 7 must verify the adversarial pass row specifically (params.adversarial=True,
  result=success), not any "stripped unsupported claim" note
- Tamper test must be automated in verify.py (corrupt a copy, assert verify_chain returns False)
- **Re-run idempotency: run_spike.py is NOT idempotent.** Each invocation creates a new finding
  (F-SPECTRE-NNN increments), which breaks verify.py Check 1 (expected count 1, actual grows).
  Before re-running: delete old findings with `rm cases/000/findings/F-SPECTRE-*.yaml` and
  remove audit rows beyond the first N. Or use a fresh case directory. For production, the
  end-to-end runner under ~/cases/ (not ~/spike/cases/) uses a fresh case per run.
- **The fixture emit path cites `finding_create`.** `core/emit_finding.emit()` (used by the
  `fixture-test` profile) stores the `finding_create` row's entry_sha256 in `evidence_refs`, so
  provenance is finding → finding_create → tool_exec via prev_sha256. The production path
  (`pipeline/emit_finding.emit_from_handle()`) cites the `tool_exec` row directly.

## Related skills

- **kb** — FK YAML authoring pattern, MITRE map maintenance, and knowledge base
  ingestion. The FK YAML template used in the spike (evtx_4688.yaml) is the canonical
  format extended there for every artifact. When adding a new artifact's FK
  YAML or detection rules, load kb for the authoring guidelines and pitfalls
  (FTS5 indexing, YAML quoting for Windows paths, verification checklist).
