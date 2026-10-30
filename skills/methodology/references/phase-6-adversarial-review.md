# Phase 6 Adversarial Review — Defects Found and Fixed

Session: 2026-06-27. Two rounds of adversarial review on the first full
7-phase pipeline run. The reviewer was correct on every claim.

## Round 1 — Four defects found

### Defect 1: case_id mis-attribution (CRITICAL)
**Finding:** 5 of 7 audit rows stamped `case_id=000-spike`, only 2 had `case_id=004-phase6-test`.
**Root cause:** `spike/core/emit_finding.py:82` and `spike/core/explain.py:309,356,376,410` hardcoded `"000-spike"`.
**Fix:** Added `case_id` parameter to `emit()` and `explain()`. Both default to `Path(case_dir).name` if omitted, but callers pass it explicitly.
**Lesson:** Hash-linkage validity (prev_hash chain) ≠ attribution validity. `verify_chain()` checks only the hash chain, not whether case_id matches the directory.

### Defect 2: EVTX extraction non-functional
**Finding:** `evtx_dump.py` run against JSON fixture produces 77 bytes of empty XML. Real extraction was never demonstrated.
**Fix:** Honest labeling — tool renamed to `evtx_dump_fixture`, exact_command is `cat /path/to/fixture.json`.
**Status:** Real `.evtx` extraction via `evtx_dump.py` remains undemonstrated. The tool exists at `/opt/python-evtx/lib/python3.12/site-packages/evtx_scripts/evtx_dump.py` but has never been exercised in this pipeline on real evidence.

### Defect 3: exact_command not reproducible
**Finding:** Audit rows and finding YAML recorded `detect.py --rule rundll32-from-temp` — but `detect.py` has no `__main__`, making the command fictional.
**Fix:** Changed to `emit_finding.py emit(anchor, rule='...', dll='...') — module call, no CLI`. Applied to both audit rows (line 89, 163) and finding YAML (line 137).
**Lesson:** For forensic audit trails, `exact_command` must be a command an examiner can actually reproduce. Fictional CLI commands are an integrity defect.

### Defect 4: FK YAMLs empty in report
**Finding:** report.md §6 showed `FK YAMLs:` with nothing after.
**Root cause:** `fk_yamls_loaded` is nested inside `gate_0`, not at the manifest top level. The report generator read the wrong key.
**Fix:** Changed to `manifest.get('artifacts', [])` (top-level key).

## Round 2 — Three additional findings

### Defect 5: Finding YAML exact_command still wrong (INCOMPLETE fix #3)
**Finding:** Fix #3 was applied to audit rows but NOT to the finding YAML at `emit_finding.py:137`, which still had the fictional CLI AND hardcoded `tests/fixtures/case-000.events.json` path.
**Fix:** Rewrote line 137 to `emit_finding.py emit(anchor, rule=..., dll=...) — module call, no CLI`.

### Defect 6: Internal inconsistency from reruns
**Finding:** emit() was run 3 times during debugging. audit.jsonl references F-001/002/003 but only F-003.yaml exists on disk. `verify_chain()` still returns (True, 'ok') — it only checks hash linkage, not artifact existence or finding-id uniqueness.
**Fix:** Full case reset and single clean end-to-end run. After any code fix, reset the case directory and run once.
**Lesson:** `verify_chain()` is necessary but not sufficient. Must also verify audit↔disk consistency (audit finding_ids match YAML files on disk) and that every finding went through Phase 5 (adversarial review).

### Defect 7: Surviving finding skipped adversarial review
**Finding:** F-SPECTRE-003 was the only YAML on disk, but its audit rows showed only `finding_create` + `finding_status` — no explain/validator rows. The finding that survived had `description: ''` and never passed the safety-critical Phase 5.
**Fix:** Clean run ensures every finding goes through all phases.

### Defect 8 (minor): Bare-label exact_commands persisted
**Finding:** `finding_status` and explain audit rows still had bare labels (`emit_finding.py`, `explain.py`, `explain.py validator`).
**Fix:** All audit rows now have descriptive commands: `emit_finding.py emit() — finding_status audit row (module call, no CLI)`, `explain.py explain(finding_path, ...) — DeepSeek API call, no CLI`, `explain.py _validate_output() — deterministic validator, no CLI`.

## Clean run verification pattern

After any fix to the pipeline, run this:
```
1. rm -rf ~/cases/NNN-name && echo "N-1" > ~/cases/.case-counter
2. case_setup.py → Phase 0
3. phase_runner.py --phase 1-6 (in order, no --force unless re-running a phase)
4. Verify: audit case_ids all match, finding_ids in audit match YAMLs on disk,
   every finding has explain/validator audit rows, exact_commands are honest
```

## Key anti-patterns learned

- **Never rerun emit without resetting the case.** audit.jsonl is append-only; findings/ overwrites. You'll get phantom references.
- **Audit chain VALID ≠ case consistent.** `verify_chain()` is a hash integrity check, not a forensic consistency check.
- **Fix both audit rows AND artifact YAML.** Two code paths produce the same field (audit entries and finding YAML) — fix both.
- **Test what survives, not what was produced.** After fixes, the finding that EXISTS on disk must be the one that passed all phases.
