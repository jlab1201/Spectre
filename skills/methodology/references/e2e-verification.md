# End-to-End Architecture Verification Script

Proven at `~/cases/e2e_test.py` — exercises the full Phase 2
pipeline through the new tool_runner architecture (not the legacy spike run_spike.py).

## What it exercises

1. `tool_runner.run_tool()` — typed parameter → subprocess → audit row → typed handle
2. `spike.core.normalize` — EVTX records → NormEvent
3. `spike.core.detect` — NormEvent → Anchor (detection rule match)
4. `spike.core.emit_finding` — Anchor → Finding YAML + audit rows + confidence
5. `spike.core.explain` — DeepSeek explanation + adversarial probe
6. Report generation — finding → report.md
7. Audit chain verification — SHA-256 chain intact, tamper detection

## Provenance chain

```
tool_runner.run_tool() → tool_exec audit row (seq=1)
  ↓ prev_sha256 chain
emit_finding.emit() → finding_create audit row (seq=2)
  ↓
finding.evidence_refs[0].execution_id = finding_create.entry_sha256
  ↓
verify: walk prev_sha256 from seq=2 → seq=1 = tool_exec row
```

The finding cites the finding_create row's entry_sha256, which is SHA-256 chained
to the tool_exec row. Full provenance is traceable through the audit chain.

## Key properties verified

- Typed handle has all 11 documented keys (path, line_count, size_bytes,
  output_sha256, is_json, fk_envelope, execution_id, exit_code, duration_ms,
  result, stderr)
- Audit chain is SHA-256 chained and tamper-evident
- Execution ID resolves to a real audit row
- Empty Data Protocol working (UNVERIFIED for 0-output, DATA_PRESENT otherwise)
- Size gate working (safe/needs_filtering based on line count)
- DeepSeek explain layer produces narrative without inventing findings
- Adversarial probe strips unsupported C2 claims
- Report generated with all required sections

## Running

```bash
cd ~/spike && source ~/spectre-venv/bin/activate
python3 ~/cases/e2e_test.py
```

Output: `~/cases/002-e2e-test/` with audit.jsonl, findings/, and reports/report.md.

## Why this is NOT the legacy spike

The legacy `run_spike.py` (under ~/spike/core/) executes tools directly through
subprocess without going through tool_runner. Its audit rows are spectre-core,
not tool_exec. This e2e test routes EVERY tool call through tool_runner.run_tool(),
which writes proper tool_exec audit rows with typed parameters and output SHA-256.
