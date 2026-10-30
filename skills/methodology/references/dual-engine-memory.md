# Dual-Engine Memory Analysis (volatility3 + MemProcFS)

## Pattern

The Spectre memory module (`src/spectre/modules/memory/`) uses a dispatcher
pattern: one `extract()` function that can invoke either or both memory
forensics engines, producing identically-schemed JSON output.

**Both engines run over one image inside one case.** That is the whole
mechanism: `corroborate()` can only score two engines as 2 sources when both
appear in the same case directory, so a "parallel run" into two cases would
destroy corroboration rather than strengthen it.

```
                    ┌─────────────────┐
                    │  memory/extract  │  engine='vol'|'memprocfs'|'both'
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌─────────────┐  ┌──────────┐
     │ extract.py │  │extract_mpfs │  │  both +  │
     │ (vol only) │  │   (mpfs)    │  │cross-val │
     └─────┬──────┘  └──────┬──────┘  └────┬─────┘
           │                │               │
           ▼                ▼               ▼
     ┌─────────────────────────────────────────┐
     │  Identical JSON schema per artifact_type │
     │  {PID, PPID, ImageFileName, ...}         │
     └────────────────────┬────────────────────┘
                          │
                          ▼
     ┌─────────────────────────────────────────┐
     │  normalize() → NormEvents               │
     │  rules.py → Anchors                     │
     │  (unchanged — no engine awareness)       │
     └─────────────────────────────────────────┘
```

## Key design decisions

1. **Schema compatibility over API fidelity.** MemProcFS produces rows in the
   same JSON shape that volatility3's `--renderer json` emits. This means
   `normalize.py` and `rules.py` work without modification — they never know
   which engine produced the data.

2. **Handle metadata carries `engine`; provenance flows to the finding.**
   Every output handle has `engine: "volatility3"` or `engine: "memprocfs"`.
   Phase 2 stamps this onto each `NormEvent.source_tool`, so the correlation
   layer can tell which engine produced a given detection. **Detection rules
   stay engine-agnostic** — they never read `source_tool`; only the
   corroboration step does. (This refines the original "engine is the only
   provenance marker" design: provenance now reaches findings so that two
   engines detecting the same claim score as 2 sources → CONFIRMED.)

3. **MemProcFS runs in a subprocess sandbox, never in-process.** The native
   leechcore.so/vmm.so libraries can SIGSEGV on non-Windows or malformed
   dumps, and Python cannot catch a SIGSEGV. The module invokes
   `extract_memprocfs.py` via `subprocess.run()`, and that module drives the
   **FUSE binary** rather than the Python API for the same reason. A crash
   returns a failure handle; the pipeline continues.

   **The default engine is `both`** — `modules/memory/__init__.py` defaults to
   it and `phase_runner` passes no engine argument, so MemProcFS runs on every
   memory case without opt-in.

4. **Two comparisons run when both engines run — and only one is
   corroboration.**
   - *Per-claim (Phase 3), the real one:* when both engines fire the same
     detection rule on the same entity, `pipeline/correlation.corroborate()`
     collapses them into one finding with `corroboration.sources: 2`,
     `cross_validated: true`, both tool labels, and both engines' `tool_exec`
     rows in `evidence_refs` → CONFIRMED via the v6 formula. This works only
     when the `dedup_key` is engine-invariant; see "Engine-invariant identity".
   - *Per-artifact (coarse), an extraction-health signal:* the `spectre-memory`
     wrapper compares row counts per artifact type and reports `agree`/`diverge`
     against a 5% tolerance. It judges no claim — equal totals do not mean the
     same rows — so it deliberately does not mint CONFIRMED or FLAGGED.

## Engine-invariant identity

A second engine only corroborates if its anchor lands in the same
`corroborate()` group, and grouping is on `(rule_id, dedup_key or title)`. So:

> A `dedup_key` is the canonical identity of the entity or claim, computed only
> from engine-invariant facts. It must never embed an engine-derived aggregate,
> a value joined from within one handle's row set, a formatted sentence, or a
> raw tool-specific rendering of an address, path, key, or timestamp.

Canonicalization belongs in `normalize.py` — extractors transcribe verbatim (so
the audited raw artifact stays a faithful rendering of what the tool emitted),
`normalize.py` canonicalizes, rules read canonical fields only. Everything
excluded from the key still appears in `title` / `summary` / `event.data`.
Pinned by `tests/test_memory/test_dedup_key_engine_invariance.py`, which builds
each fact in both engines' actual renderings.

## Observation vs verdict

**A second source must contribute independently-derived *observations* that a
Spectre predicate then judges. A source that contributes a *verdict* is not a
second source** — it is one judgment restated, and counting it launders another
tool's heuristics into Spectre's confidence score without any Spectre rule
seeing the underlying facts.

This is why MemProcFS's FindEvil is not used to corroborate `memory_malfind`:
its CSV states a classification and carries neither a protection nor a byte
preview, while the rule requires both. "Confirming" it would mean synthesizing
the facts nobody observed. The VAD map (`pid/<n>/memmap/vad.txt`) is used
instead — it is malfind's criterion in raw form.

It is also the correct reason vol+MemProcFS counts as two sources while
zeek+tcpdump does not: the memory engines demonstrably observe independently
(they disagree, and the disagreements are real), whereas zeek and tcpdump
re-render one libpcap decode.

## Artifact mapping

Mount paths `extract_memprocfs.extract_from_mount()` opens. Authoritative list:
`extract_memprocfs.EMITTED_ARTIFACT_TYPES`, checked against the FK YAMLs'
`parser:` provenance lines by `tests/test_memory/test_fk_parser_truth.py`.

| MemProcFS mount path | volatility3 plugin | artifact_type |
|---|---|---|
| `sys/proc/proc-time.txt` (`proc.txt` fallback) | `windows.pslist` | `memory_pslist` |
| `sys/net/netstat-v.txt` | `windows.netscan` | `memory_netscan` |
| `pid/<n>/win-cmdline.txt` | `windows.cmdline` | `memory_cmdline` |
| `pid/<n>/win-environment.txt` | `windows.envars` | `memory_envar` |
| `pid/<n>/memmap/vad.txt` + `pid/<n>/vmemd/*.vvmem` | `windows.malfind` | `memory_malfind` |
| `sys/services/by-name/<svc>/svcinfo.txt` | `windows.svcscan` | `memory_svcscan` |
| `registry/HKLM/…` (Run, RunOnce, Winlogon) | `windows.registry.printkey` | `memory_regkey` |
| `pid/<n>/modules/` | `windows.dlllist` | `memory_modules` |

Single-engine, and not fixable by pointing at a nearby MemProcFS file:
`memory_filescan` (handle tables enumerate open handles; filescan scans physical
memory for FILE_OBJECTs — different populations) and `memory_url` (strings
carving, no equivalent surface). Still gaps in the SANS six-step method:
handles, rootkit checks, and process dumping.

## Files

| File | Role |
|---|---|
| `src/spectre/modules/memory/__init__.py` | Dispatcher: `extract(case_dir, evidence, engine="both")` |
| `src/spectre/modules/memory/extract.py` | volatility3 extraction |
| `src/spectre/modules/memory/extract_memprocfs.py` | MemProcFS FUSE extraction (`extract` mounts; `extract_from_mount` reads) |
| `src/spectre/modules/memory/normalize.py` | Canonicalization — the engine-invariance layer |
| `src/spectre/pipeline/spectre_memory.py` | `spectre-memory` console script |

## CLI usage

```bash
# volatility3 only
spectre-memory --evidence /cases/dump.raw --case ~/cases/015-test --engine vol

# MemProcFS only (subprocess sandbox)
spectre-memory --evidence dump.mem --case ~/cases/016-test --engine memprocfs

# Both engines (the DEFAULT — omitting --engine gives you this)
spectre-memory --evidence dump.vmem --case ~/cases/017-test --engine both
```

## Environment check

`spectre-canary` covers both engines. MemProcFS resolves through
`config.MEMPROCFS_BIN` rather than PATH — its install (`/opt/memprocfs`) is not
on PATH, so the canary asks config the same question the extractor asks it, and
checks that the binary exists and is executable. It does **not** check the
binary's exit code (`-version` prints correctly but exits 1) and does not check
the Python API import, which Spectre does not use.

## Why this pattern matters

Before this integration, memory analysis was single-engine (volatility3 only).
If volatility3 failed on a particular memory dump format, the entire memory
analysis path was dead. Now:

- Different engine, same pipeline — no code fork needed
- Dual-tool corroboration is architectural, not prompt-based
- Engine selection is a runtime flag, not a code change
- New engines can be added by writing a new `extract_<engine>.py` that
  produces the same JSON schema — no other code changes needed

## Command logging

All engine invocations appear in `execution.log` automatically:

- **volatility3**: via `tool_runner.py` → `audit.py append()` → `shell_log.log_command()`
- **MemProcFS**: via direct `shell_log.log_command()` call in `_run_mpfs_subprocess()`
- **Any future engine**: just call `shell_log.log_command(case_dir, tool, command, exit_code, duration_ms, stderr, extra)`

The shared logger (`src/spectre/pipeline/shell_log.py`) is thread-safe, auto-sequences,
writes full command lines, and produces a summary footer at pipeline end.
