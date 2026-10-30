# Phase 6 Fixture Execution Pattern

## Proven workflow for running the 7-phase pipeline against case-000.events.json

This is the Blitz-DFIR testing order: deterministic pipeline first, then full AI.

### Prerequisites

- Activate the Spectre venv: `source ~/spectre-venv/bin/activate`
- Fixture and oracle ship in the repo: `tests/fixtures/case-000.events.json`,
  `tests/fixtures/case-000-truth.yaml` (`phase_runner.FIXTURE_PATH` / `TRUTH_PATH`)
- FK YAML and MITRE map resolve through `spectre.config` (`src/spectre/knowledge/`)

### Step 1: Case Setup (Phase 0)

```bash
python3 -m spectre.pipeline.case_setup --name "phase6-test" --profile fixture-test
```

Expected output: `{"case_id": "00N", "canary_status": "FULL", "success": true}`

### Step 2: Run Phases 1-6 sequentially

```bash
for phase in 1 2 3 4 5 6; do
  echo "=== Phase $phase ==="
  python3 -m spectre.pipeline.phase_runner \
    --case ~/spectre-cases/00N-phase6-test \
    --phase $phase
done
```

### Step 3: Verify against truth

```python
import yaml
truth = yaml.safe_load(open('~/spike/tests/fixtures/case-000-truth.yaml'))
finding = yaml.safe_load(open('~/cases/00N-phase6-test/findings/F-SPECTRE-001.yaml'))

assert finding['status'] == 'INFERRED'
assert finding['confidence'] == 0.5
assert finding['mitre_attack'] == 'T1218.011'
assert 'evil.dll' in str(finding['iocs']['filepath'])
assert finding['corroboration']['sources'] == 1
assert len(finding['forensic_caveats']) >= 2
assert len(finding['evidence_refs']) >= 1
```

### Step 4: Phase 7 — Memory + Index

```bash
# Audit verification
python3 -c "
import sys; sys.path.insert(0,'~/forensic-kb')
from scripts.audit import verify_chain
ok, reason = verify_chain('~/cases/00N-phase6-test')
print(f'Audit: {\"VALID\" if ok else \"INVALID\"} ({reason})')
"

# Cross-case index is written in Phase 7 (post-approval, CONFIRMED findings only).
# Save memory entry via the orchestrating agent's memory tool (≤350 chars):
# "Case 00N-phase6-test: F-SPECTRE-001 INFERRED(0.50): rundll32-from-temp (T1218.011), evil.dll in C:\Windows\Temp, parent winword.exe."
```

## Critical Pitfall: JSON Fixtures vs Real EVTX

`evtx_dump.py` (the actual evtx_dump tool) expects a binary .evtx file.
When given a JSON fixture like `case-000.events.json`, it produces empty XML:

```xml
<?xml version="1.1" encoding="utf-8" standalone="yes" ?>
<Events>
</Events>
```

This breaks the extraction→normalize chain because `normalize()` expects
EVTX-shaped JSON records, not empty XML documents.

### Fix (built into phase_runner.py Phase 2)

1. Write fixture data DIRECTLY to the output file (skip the evtx_dump.py subprocess call)
2. THEN create the tool handle via `run_tool()` for audit trail

```python
# CORRECT pattern for JSON fixtures:
fixture_data = json.loads(fixture_path.read_text())
with open(output_path, "w") as f:
    json.dump(fixture_data, f)

handle = run_tool(
    case_dir=case_dir,
    tool_name="evtx_dump_fixture",
    command=["cat", str(fixture_path)],
    params={"note": "JSON fixture loaded directly (no real EVTX)"},
    output_path=output_path,
    timeout=30,
    output_format="json",
)
```

This gives us both correct output AND an audit trail.

## Expected Audit Row Counts

For a single-fixture case with one finding:
- `note`: 3 (canary note, guard note, phase note)
- `tool_exec`: 2 (fixture write + detection)
- `finding_create`: 1
- `finding_status`: 1
- Total: ~7 rows

## Recovery from Previous Run Failures

If the initial Phase 2 run produced a stale/empty output file:

```bash
# Clean up stale output
rm ~/cases/00N-phase6-test/raw_extract/*_evtx_dump.json

# Re-run Phase 2 with --force
python3 ~/forensic-kb/scripts/phase_runner.py \
  --case ~/cases/00N-phase6-test --phase 2 --force
```

The `phase_runner.py` Phase 2 handler auto-detects stale files (<500 bytes)
and removes them before creating the new output.

## Re-Run from Scratch After Audit-Affecting Fix

When a fix changes audit row content (case_id, exact_command, finding data),
do NOT attempt to patch audit rows in place. Audit rows are tamper-evident
by design — modifying them breaks the SHA-256 chain. Instead:

```bash
# 1. Delete the entire case directory
rm -rf ~/cases/00N-phase6-test

# 2. Reset the case counter (if needed)
echo "N" > ~/cases/.case-counter

# 3. Re-run the full pipeline from Phase 0
python3 ~/forensic-kb/scripts/case_setup.py --name "phase6-test" --profile "fixture-test"
for phase in 1 2 3 4 5 6; do
  python3 ~/forensic-kb/scripts/phase_runner.py --case ~/cases/00N-phase6-test --phase $phase
done
```

This is the ONLY way to verify that fixes produce correct audit rows
end-to-end. A hash chain that validates with wrong case_ids is still wrong.
See Pattern 2 in `plan-review/references/forensic-review-patterns.md`.

## Audit Attribution Verification

After every pipeline run, verify that ALL audit rows attribute to the
correct case. Hash-chain validity does NOT imply attribution validity:

```bash
cat ~/cases/00N-phase6-test/audit.jsonl | python3 -c "
import sys, json
rows = [json.loads(line) for line in sys.stdin if line.strip()]
for i, r in enumerate(rows):
    cid = r.get('case_id', 'MISSING')
    action = r.get('action', '?')
    print(f'  [{i}] case_id={cid} action={action}')
"
```

All rows must show the same case_id matching the case directory name
(e.g., `004-phase6-test`). If any rows show a different case_id
(e.g., `000-spike`), the pipeline has a mis-attribution bug that must
be fixed before ANY findings are considered chain-of-custody valid.
