---
name: evidence-pipeline
description: "Spectre evidence pipeline — case directory setup, evidence registration (SHA-256 + chmod 444), chain-of-custody manifest, and case state tracking."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, evidence, case-management, pipeline]
metadata:
  hermes:
    tags: [forensic, spectre, evidence, case-management, pipeline]
---

# Forensic Evidence Pipeline

Phase 0 of every investigation: case creation, evidence registration (SHA-256 + `chmod 444` on the copy), chain-of-custody manifest, and case state. All of it is implemented in `src/spectre/pipeline/case_setup.py` and `evidence_guard.py`; paths resolve through `spectre.config` (`SPECTRE_CASES_DIR`, default `~/spectre-cases/`). The authoritative spec is `docs/phase-0-spec.md`; the orchestration context is `skills/methodology/SKILL.md`.

## When to use

- Starting a new forensic investigation
- Registering evidence into a case
- Choosing an artifact profile
- Checking case state before resuming work

## Required inputs

- Case name (short slug, e.g. `suspected-intrusion`)
- Evidence path(s), absolute; files or directories (directories are walked recursively, symlinks are never followed and are recorded as skips)
- Optional: profile (default `auto` when `--evidence` is given)

## Steps

### 1. Create the case and register evidence (one command)

```bash
spectre --name "suspected-intrusion" --profile auto --phase 0 \
        --evidence /path/to/memory.raw /path/to/Security.evtx
```

`--phase 0` runs Phase 0 only. The same step is available standalone as `python3 -m spectre.pipeline.case_setup --name NAME --profile PROFILE [--evidence PATH...] [--cases-dir DIR] [--auto-extend] [--direction TEXT] [--focus]`. If a prior case with the same name and evidence exists, `spectre --name ... --phase N` offers to resume it (`--resume` / `--new-case` decide without prompting); `--case DIR` targets a case explicitly.

What Phase 0 does, in order: increments `<cases-dir>/.case-counter` and creates `<cases-dir>/NNN-name/` (`evidence/`, `raw_extract/`, `findings/`, `reports/`); runs the session canary; for each evidence file runs `evidence_guard` on the source, copies it into `evidence/`, sets `chmod 444`, re-runs the guard on the copy, and appends chained `evidence_guard` / `evidence_register` audit rows; locks `evidence/` to `0555`; loads the FK YAMLs for the profile; runs cross-case recall; writes `manifest.yaml`.

### 2. Evidence guard on its own (optional pre-check)

```bash
python3 -m spectre.pipeline.evidence_guard /path/to/evidence.raw [--case CASE_DIR] [--skip-audit] [--skip-parent-check]
```

Exit 0 = PASS (prints the SHA-256), exit 1 = FAIL. It checks: file exists and opens `O_RDONLY`, no write permission bits, parent directory not writable (skipped with `--skip-parent-check`, used for the post-copy check), and computes SHA-256. With `--case` it appends an `evidence_guard` audit row. A failed guard rejects the evidence; fix the permissions and retry. Registration itself (copy, `chmod 444`, post-copy guard, `evidence_register` audit row) is done only by Phase 0 / `case_setup`; there is no separate register script.

### 3. Pick an artifact profile

```bash
spectre --list-profiles
```

Current profiles: `auto` (artifacts derived from dropped-file recognition), `quick-triage`, `memory-only`, `disk-light`, `evtx-focused`, `full-windows`, `fixture-test`, `network-only`, `pcap-focused`. Artifact lists live in `PROFILES` in `case_setup.py`; `--list-profiles` is the source of truth.

### 4. Health check and later phases

```bash
spectre-canary --case CASE_DIR        # FULL / DEGRADED / DEAD; Phase 0 already runs it
spectre --case CASE_DIR --phase 7     # run up to phase N; earlier unfinished phases run first
spectre approve --case CASE_DIR --finding F-NNN-001 --examiner NAME \
        --decision APPROVED --rationale "..."   # Phase 7 examiner decision (see `spectre approve --help`)
```

There is no separate zero-knowledge-check or KB-load command; FK YAMLs are loaded by Phase 0 and routed per finding by `pipeline/fk_routing.py`.

## Output

`<cases-dir>/NNN-name/manifest.yaml` (case metadata, evidence refs with `evidence_path` and `evidence_relpath`, profile, triage), `audit.jsonl` (SHA-256 chained), `execution.log`, and the four subdirectories above. Phase 0 prints a JSON result on stdout.

## Audit

Every action goes through `audit.append()`. Phase 0 writes the canary result, `evidence_guard`, and `evidence_register` rows (plus `derived_evidence_register` for carved files later). `verify_full()` in Phase 7 re-checks the chain, evidence hashes, and findings.

## Pitfalls

- **Do NOT modify evidence after registration.** chmod 444 is enforced. A re-hash that differs from the chained `evidence_register` row is tampering: the pipeline writes `evidence_tampered` and stops; do not re-register over it.
- **Evidence guard is MANDATORY.** Never skip evidence_guard.py. It's the only kernel-level read-only enforcement. If it fails, STOP and fix permissions.
- **Guard checks differ for source vs. copy.** Pre-copy guard checks parent directory is not writable (protects source integrity). Post-copy guard uses `--skip-parent-check` because the case `evidence/` directory is writable while `cp` runs. The file's `chmod 444` is the copy's protection. Both guards must pass. After registration `case_setup.lock_evidence_dir()` makes `evidence/` `0555` (W3-2), so a 444 copy can no longer be swapped by `mv`/`rm`; `evidence/derived/` stays writable for Phase 2 carving, and registering more evidence re-opens the directory only for the copy.
- **Never hand-write audit rows.** All audit rows must go through `audit.py`'s `append()` for proper SHA-256 chaining. A bare JSONL line with `seq:0, prev_sha256:0*64, entry_sha256:""` breaks `verify_chain()` on the next row.
- **Case counter is `<cases-dir>/.case-counter`**, read and incremented by `case_setup._read_counter()` (no file lock, so do not create cases from two sessions at the same instant; it takes the max of the counter and the highest case directory on disk, so it never reuses an id).
- **Profile selection is binding for the investigation.** Changing profile mid-investigation requires a new case.
- **Evidence paths in audit rows are case-relative** (`evidence/<name>`, W3-7), resolved against the current case directory by `custody.resolve_case_path()`, so a handed-off or archived case verifies its own copy. Legacy absolute rows are re-rooted into the current case dir. Source paths given to `--evidence` may be anything; the manifest keeps the absolute `evidence_path` plus `evidence_relpath`.
- **Deleting a case needs `chmod -R u+w <case>/evidence` first** (evidence/ is 0555, copies 0444) — `rm -rf` alone fails. Never do this to a case in scope without the examiner's go-ahead.
- **Phase 2 extracts registered evidence only.** A path in `manifest["triage"]` that does not resolve to a chained `evidence_register` copy (or is a symlink) is refused and an `unregistered_evidence_refused` row is chained. Symlinks in evidence/ are refused at registration and at phase entry; carved `derived_evidence_register` files are re-hashed at phase entry.
- **On case RESUME and at every phase entry, evidence is re-hashed** against the chained `evidence_register` rows (not manifest.yaml) by `custody.enforce_evidence()`. Mismatch → `evidence_tampered` audit row + pipeline stop.
- **Resolve paths through `from spectre.config import ...`** (env-overridable: `SPECTRE_CASES_DIR`, `SPECTRE_CACHE_DIR`, `SPECTRE_VOL_PATH`, `SPECTRE_MEMPROCFS_DIR`); never hardcode `~/...` locations.
