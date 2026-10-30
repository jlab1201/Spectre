# Phase 3 Guard Infrastructure

Session canary hardening + evidence guard + audit trail hardening + denylist
enforcement + empty data protocol hardening. All modules live in
`src/spectre/pipeline/` (`canary.py`, `evidence_guard.py`, `denylist.py`, `tool_runner.py`,
`emit_finding.py`).

## Script Inventory

| Script | Purpose | Type |
|--------|---------|------|
| `canary.py` | Pure-Python environment canary, inventory derived from each module's `module.yaml` + `availability()` hook; FULL/DEGRADED/DEAD states | Guard |
| `evidence_guard.py` | Kernel-enforced read-only: os.open(O_RDONLY), no write bits, parent-dir check | Guard |
| `denylist.py` | Command allowlist/denylist; only hard-block in the pipeline | Guard |
| `emit_finding.py` | Production finding emission; evidence_refs → tool_exec (single-hop) | Core |
| `tool_runner.py` | (modified) Denylist check before subprocess.run; auto-applies empty_data_protocol | Core |
| `case_setup.py` (Phase 0) | Registers evidence: hashes the source, copies into `evidence/`, `chmod 444`, guards the copy (parent check skipped), writes `evidence_register` audit row. The old `evidence-register.sh` was removed | Pipeline |

## Canary States

```
FULL      — all checks pass → investigation proceeds normally
DEGRADED  — something is missing but >=1 module can extract → continue with
            canary_status="DEGRADED" marker
DEAD      — a core-infrastructure check failed (interpreter, pyyaml, libmagic,
            module discovery) OR no module can extract → pipeline STOPS (exit 3)
```

Canary runs at: Phase 0 (mandatory) + before Phase 4 (mid-investigation re-check).

Audit row written on: DEGRADED and DEAD. (DEAD writes the audit row BEFORE
`sys.exit(3)` — this was fixed in review after the initial implementation
exited without leaving a chain-of-custody record for the fatal event.)
FULL writes no audit row (nothing to record).

## Evidence Guard Checks

1. File exists and is readable
2. `os.open(path, os.O_RDONLY)` succeeds (kernel-enforced)
3. No owner-write, group-write, or other-write bits (must be 444 or 400)
4. Parent directory not writable by current user — **skipped for post-copy verification**

Returns `(ok: bool, reason: str, sha256: str, skip_parent_check: bool = False)`.

**Critical design rule:** Check 4 (parent-directory writable) is for SOURCE evidence
only. The post-copy guard on the destination file MUST use `skip_parent_check=True`
because the case `evidence/` directory MUST be writable for `cp` to work.
The file's `chmod 444` is the protection on the copy, not the parent directory.
Skipping this check on the post-copy guard is the correct design — it was a
showstopper bug in the initial Phase 3 implementation where both guards ran the
full check suite.

## Denylist

**Permanently blocked:** `rm`, `shred`, `wipe`, `mkfs`, `mkfs.*`
**Conditionally blocked:** `fdisk` (always destructive)
**Evidence-dir blocked:** `dd`, `mv`, `cp`, `chmod`, `chown`, `touch` targeting `/cases/`

`dd if=/dev/sda of=/tmp/acquire.raw` is ALLOWED — forensic acquisition.
`dd of=/cases/.../evidence/` is BLOCKED — writing into evidence dirs.
This was fixed in Phase 3 review: the initial implementation unconditionally
blocked `dd of=`, which broke standard disk imaging workflows.

Denylist is wired into `tool_runner.run_tool()` before `subprocess.run()`.
Blocked commands write `tool_blocked` audit row and raise `PermissionError`.

This is the ONLY hard-block. Skills are procedural gates only.

## Audit Chain Verification

`verify_chain()` from `audit.py` must pass at every phase gate transition:
- Gate 0 (case setup)
- Gate 3 (detection complete)
- Gate 4 (correlation complete)
- Gate 5 (adversarial review complete)
- Gate 7 (case close)

New audit row types from Phase 3:
- `canary_result` — canary status at investigation start/mid-point
- `evidence_guard` — guard check pass/fail on each registration
- `tool_blocked` — denylist refusal

## Empty Data Protocol (Phase 3 hardening)

Auto-applied in `tool_runner._build_handle()` — every returned handle has
`empty_data_status`: `"DATA_PRESENT"` or `"UNVERIFIED"`.

Never say "clean" — absence of evidence is not evidence of absence.

## evidence_refs Provenance (Phase 3 fix)

Production path: `emit_finding.emit_from_handle()` sets
`evidence_refs[0].execution_id = handle["execution_id"]` which is the
`tool_exec` audit row `entry_sha256`. Direct single-hop provenance:
`finding → tool_exec`.

Legacy spike path (`~/spike/core/emit_finding.py`): uses `finding_create`
audit row as execution_id — two-hop provenance. Not used in production.

## Verification

```python
from spectre.pipeline.canary import run_canary
from spectre.pipeline.evidence_guard import guard
from spectre.pipeline.denylist import check
from spectre.pipeline.audit import verify_chain
from spectre.pipeline.emit_finding import emit_from_handle
from spectre.pipeline.tool_runner import run_tool
```

The regression suite for these guards runs under `pytest`.
