# Spectre Phase 0: Case Setup — Specification

> **Version:** 1.8.0 | **Last updated:** 2026-09-30
> **Status:** Authoritative — code and methodology skill reference this document.
> **Maintainer:** Update this spec WHENEVER Phase 0 code changes. Do not let it drift.

---

## Purpose

Phase 0 creates a new forensic case directory, validates the analysis environment,
registers evidence, loads forensic knowledge (FK YAMLs), and produces the case
manifest. Every subsequent phase depends on Phase 0 being complete and passing
Gate 0.

**Entry point:** `spectre --phase 0` (or `python3 -m spectre.pipeline.case_setup`)

---

## What Phase 0 Produces

| File | Purpose | Format |
|---|---|---|
| `cases/NNN-name/` | Case directory with subdirectories | Filesystem |
| `manifest.yaml` | Case dashboard: metadata, evidence refs, profile, gate status | YAML |
| `fk_context.yaml` | Loaded FK YAMLs for all recognized artifact types | YAML |
| `audit.jsonl` | Tamper-evident chain-of-custody audit trail | JSONL + SHA-256 |
| `execution.log` | Human-readable execution transcript (see §Execution Log) | Plain text |

Subdirectories created: `evidence/`, `raw_extract/`, `findings/`, `reports/`

---

## Step-by-Step Execution

### Step 0: Case Counter

Read `$CASES_DIR/.case-counter`, increment by 1, write back.
Case ID = zero-padded counter (e.g., `004`).
Case directory = `$CASES_DIR/{case_id:03d}-{name}` (e.g., `004-new-mem`).

### Step 1: Create Directory Structure

```
{cases_dir}/{NNN}-{name}/
  evidence/     ← read-only copies of evidence files
  raw_extract/  ← extraction output (JSON, handles)
  findings/     ← F-{case_id}-{NNN}.yaml per finding
  reports/      ← report.md, iocs.csv, blindspots.md
```

### Step 2: Session Canary

Run `spectre.pipeline.canary.run_canary(case_dir=...)`. Pure Python — no bash
script (`scripts/session-canary.sh` is deleted; it was never in the wheel, so
resolving it made every non-editable install exit 3). Use
`canary.probe_environment()` for the same result without the DEAD hard-stop.

The inventory is **derived from the analyzer modules**, not hardcoded: each
module ships a `module.yaml` (`name`, `artifact`, `summary`, `tools`,
`tool_optional`, `optional_tools`, `python_deps`, `python_deps_optional`), read
without importing the module so a module with a broken dependency can still be
described. A module may also ship an `availability(path=None)` hook
(`core.base.ModuleAvailability`), which is authoritative when present — pcap's
decides from `config.PCAP_ENGINE`, because `required_tools=["tcpdump"]` would
report the module unavailable on a Zeek-only host that extracts pcaps fine.

Four tiers:

| Tier | Contents | Worst outcome |
|------|----------|---------------|
| 1. Core infrastructure | interpreter ≥3.11, pyyaml, **live libmagic probe**, module discovery | DEAD |
| 2. Per-module required tools | `module.yaml: tools`, unless `tool_optional` | module UNAVAILABLE |
| 3. Per-module python deps | `module.yaml: python_deps` via `find_spec` | module UNAVAILABLE |
| 4. Optional tools + project extras | `optional_tools`, `python_deps_optional`, the `report` extra | DEGRADED |

Three possible outcomes:
- **FULL:** every check passed. Proceed normally.
- **DEGRADED:** something is missing but at least one module can extract.
  Findings get `canary_status: DEGRADED`. Proceed; every gap is disclosed in
  the report's Forensic Blind Spots section.
- **DEAD:** a core-infrastructure check failed, **or** no module can extract at
  all. Pipeline STOPS (exit 3). Note what this no longer is: the old rule was
  `vol_failed and other_failures >= 3`, which sent a pcap-only examiner to DEAD
  and made the stated use case unable to start.

libmagic is core because without it every extensionless artifact (a bare
`SYSTEM` hive, a raw disk image) triages `UNRECOGNIZED` and the report calls
its contents unverified — a false statement about the evidence, not a degraded
analysis. The probe calls `magic.from_file` for real, since the pure-python
wrapper imports cleanly with `libmagic.so` absent.

Canary result written to manifest. A DEGRADED or DEAD result writes an audit
row carrying `usable_modules` and `unavailable_modules`.

### Step 3: Evidence Registration

**Intake expansion:** `--evidence` accepts files or directories. Before
registration, `_expand_evidence_paths()` walks every argument: files pass
through unchanged; directories are walked recursively (`Path.rglob`), sorted
for determinism. Nothing is silently dropped — missing paths, symlinks
(never followed — evidence must be the real bytes, not a link), empty files,
and non-regular files are recorded as skip entries (`{path, reason}`) in
`manifest["intake_skipped"]` and logged via `console.detail()`. Only the
resulting flat list of regular files proceeds to registration below.

For each `--evidence <path>`:

1. Compute SHA-256 of source file (chain of custody starts here)
2. Copy to `{case_dir}/evidence/{filename}` — **collision-safe, content-addressed:**
   two same-named files from different hosts can never overwrite each other.
   If `{filename}` is already staged:
   - same SHA-256 as the staged copy → **duplicate re-submission**: reuse the
     existing staged copy (no second copy written); the registration succeeds
     with `"reason": "duplicate of already-staged evidence (same sha256)"` and
     the audit row's `params.duplicate_reuse` is `true`.
   - different SHA-256 → **genuine collision**: stage as
     `{stem}__{sha256[:8]}{ext}` (e.g. a second `Security.evtx` becomes
     `Security__a1b2c3d4.evtx`) instead of overwriting the first.
3. `chmod 444` the copy (read-only protection) — a no-op on an already-444
   duplicate-reuse target
4. Run `evidence_guard.guard()` on the copy (verify permissions, hash integrity)
5. Verify copy hash matches source hash
6. Write `action: evidence_register` audit row (`params.duplicate_reuse` records
   whether this call reused an existing staged copy). `output_path` and
   `params.copy_path` are **case-relative** (`evidence/<name>`, W3-7) so a
   handed-off or archived case directory verifies its own copy; the returned
   ref / manifest entry keeps the absolute `evidence_path` and adds
   `evidence_relpath`. Legacy absolute rows are re-rooted into the current
   case directory by `custody.resolve_case_path()`.

After all evidence is registered, `case_setup.lock_evidence_dir()` creates the
writable `evidence/derived/` (Phase 2 carve target) and then `chmod 0555`s
`evidence/` itself (W3-2): a 444 copy can no longer be swapped with `mv`/`rm`
without an explicit chmod. Registering more evidence into an existing case
re-opens `evidence/` only for the copy and re-locks it. From Phase 1 on, every
phase entry and every resume re-hashes each copy against its chained
`evidence_register` row (`custody.enforce_evidence()`, plus `evidence_guard`),
and a mismatch writes an `evidence_tampered` row and stops the pipeline. A
symlink in `evidence/` is refused at registration and at phase entry; carved
(`derived_evidence_register`) files are re-hashed at phase entry too; Phase 2
extracts only paths that resolve to a chained `evidence_register` copy.
Deleting a case therefore needs `chmod -R u+w <case>/evidence` first.

On failure: evidence rejected, audit row logged, STOP.

### Step 4: Evidence Recognition (Triage)

For each registered evidence file, run `recognize.triage_one()`:

1. Read file extension + libmagic description
2. Query all registered analyzer modules for a match
3. Return highest-confidence claim: `{module, artifact_type, confidence, status}`

Status values:
- `RECOGNIZED` — module identified, tool available
- `EXTRACTOR_PENDING` — module identified, tool NOT available
- `UNRECOGNIZED` — no module claims this file
- `MISSING` — file doesn't exist

**EWF (E01) Capability Probe:**

When an E01 (Encase image) is recognized by the disk module with all tools available,
`triage_one()` probes the local Sleuth Kit build to verify libewf support:
- Runs `fls -i list` (prints supported image formats to stderr)
- Checks if `ewf` appears in the output
- Result cached in module-level `_EWF_SUPPORT` (checked only once per session)

If the E01 is recognized but the build lacks libewf, the status is downgraded from
`RECOGNIZED` to `EXTRACTOR_PENDING` with `tool: "libewf"`. This surfaces the dependency
at Phase 0 instead of failing mid-Phase-2 extraction. Audit row records the probe result.

Triage records stored in manifest under `triage:`.

**Derived evidence (Phase 2, carved from disk images):**

Recognition is not limited to what the analyst drops. During Phase 2 extraction the
disk module carves well-known nested artifacts (EVTX under `winevt/Logs`,
SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT hives, `Prefetch/*.pf`, user-profile `.lnk`,
`$MFT`) out of recognized disk images via `icat` (capped at 200 per image, output
names inode-prefixed so duplicate in-image paths never collide). Each carved file is
sha256-hashed, `chmod 444`, audit-chained (`action: derived_evidence_register` with
parent linkage), recorded in `manifest["derived_evidence"]` with
`derived_from`/`in_image_path`, then re-triaged through this same recognition step
and analyzed by its matching module. Derived evidence is never re-carved (depth
bound). `audit.verify_full()` re-hashes derived evidence exactly like primary
evidence.

### Step 5: Extract Evidence Metadata

For each registered evidence file, run lightweight extraction tools to answer
"WHAT is this evidence?":

- **Memory images:** `vol windows.info.Info` → OS build, architecture (x64/x86),
  system time, kernel base, system root, processor count
- **EVTX files:** First event timestamp, estimated event count from file size
- **PCAP files:** `capinfos` → packet count, duration, data rate

Results stored in `manifest["evidence_metadata"]`. Errors are non-fatal —
metadata extraction failure does not block the pipeline.

### Step 6: Load FK YAMLs (Forensic Knowledge Context)

For each artifact in the effective artifact list, load its FK YAML.

**Artifact list derivation:**

- **Static profiles** (`quick-triage`, `memory-only`, etc.): use the profile's hardcoded `artifacts` list.
- **`auto` profile**: derive from triage. Map recognized `artifact_type` → FK YAML
  names via `ARTIFACT_FK`, which is **derived from each module's `module.yaml`
  `fk_yamls` key** (`pipeline/fk_routing.py`) — not a hand-maintained table:
  - `memory_image` → all 13 `memory_*.yaml` files (memory's manifest lists them)
  - `process_creation` → `evtx_4688.yaml`
  - `pcap_conn` → `pcap.yaml`
  - Unmapped types → attempt direct FK YAML lookup by artifact_type name

  A second, separate map routes the **event-level** artifact_type a rule emits
  (`pcap_dns`, `memory_psscan`, …) to the FK YAML a *finding* carries. It is
  derived from the same manifests: `fk_by_artifact` when the module declares one,
  otherwise its single `fk_yamls` entry. Both were hand-written dicts —
  `case_setup.ARTIFACT_FK` (8 entries) and `phase_runner.ARTIFACT_FK` (~25) — so
  a 9th module needed two central edits and nothing stopped them disagreeing.
  `tests/test_fk_routing.py` fails if any artifact type a rule emits has no
  route, instead of letting it fall through to `_DEFAULT_FK = evtx_4688.yaml`,
  which pastes Windows 4688 caveats onto findings with no 4688 event.

Loaded FK YAMLs written to `fk_context.yaml` (NOT blank — see §Known Issues).

**Important:** FK YAMLs describe ARTIFACTS, not tools. The `parser:` field inside each
FK YAML lists all known extraction tools for that artifact type (e.g., `volatility3` and
`MemProcFS` for `memory_pslist`). Provenance — which tool was ACTUALLY used — is recorded
in each finding's `tool` field and in the `tool_exec` audit rows, not in the FK YAML.
This separation keeps knowledge (what the artifact proves) independent of implementation
(which tool extracted it).

### Step 7: Cross-Case Episodic Recall

Run `cross_case_index.search_index()` across all IOC types.
Matches are advisory only — they inform but do not decide.
Results written to manifest under `cross_case_recall:`.

### Step 8: Build and Write Manifest

`manifest.yaml` schema:

```yaml
case_id: "004"                    # zero-padded
case_name: "new-mem"              # from --name
created: "2026-06-27T17:30:39Z"   # UTC ISO 8601
artifact_profile: "auto"          # from --profile
artifact_profile_desc: "..."      # from PROFILES dict
canary_status: "FULL"             # from canary result
evidence:                         # from registration
  - ok: true
    sha256: "..."
    evidence_path: "..."
    original_path: "..."
artifacts: []                     # effective artifact list
phase: 0
gate_0:
  canary_known: true
  canary_status: "FULL"
  evidence_registered: 1
  manifest_exists: true
  fk_yamls_loaded: 8             # count of loaded FK YAMLs
  passed: true                    # canary not DEAD AND (fk_yamls > 0 OR evidence > 0)
triage:                           # from recognition
  /path/to/evidence:
    path: "..."
    magic: "..."                  # libmagic description
    module: "memory"
    artifact_type: "memory_image"
    confidence: 0.7
    tool: "vol"
    status: "RECOGNIZED"
intake_skipped:                   # from intake expansion (Step 3) — never silently dropped
  - path: "/path/to/dump/empty.log"
    reason: "empty file (0 bytes)"
cross_case_recall: {}             # from episodic recall
evidence_metadata: {}             # populated by Step 5 (metadata extraction)
```

### Step 9: Verify Audit Chain

Run `audit.verify_chain(case_dir)` — must return `(True, "ok")` before Gate 0 passes.

The genesis (seq 1) row of every new chain carries a random `case_nonce` (W3-5).
It is inside the row hash, so it is chained, and the systemd-journal anchor is
keyed by it plus the case directory's real path (not by the re-usable case_id):
two case directories that share a case_id — or a case and a diverged copy of it —
never witness each other, and a chain shorter than the highest seq the journal
witnessed for that key fails `verify_full()` closed (tail truncation). Entries
from this directory's path are binding: a rewritten or dropped genesis nonce is a
violation. With journald absent, or for a relocated case directory, the check is
advisory.

**Note:** `verify_chain()` validates SHA-256 linkage only. It does NOT check audit↔disk consistency, phase coverage, or case_id correctness. `verify_full()` covers all these checks — it is implemented AND, as of the integrity remediation, wired into Phase 7 where it fails closed (see §Known Issues). Its tamper-evidence is internal-only: a same-user full re-derive of the chain is not detectable without an external anchor (documented follow-up).

---

## Gate 0 — MUST PASS Before Phase 1

- [ ] Session canary status known and recorded (FULL / DEGRADED)
- [ ] Case directory exists with `manifest.yaml`
- [ ] All evidence passed evidence_guard + registered with SHA-256 (case-relative row paths)
- [ ] `evidence/` is `0555` (only `evidence/derived/` writable)
- [ ] `audit.verify_chain()` returns `(True, "ok")`
- [ ] Artifact profile selected and recorded
- [ ] FK YAMLs loaded for recognized artifacts (`fk_context.yaml` is NOT `{}`)
- [ ] Evidence metadata extracted (OS, arch, time range — at minimum, errors are non-fatal)
- [ ] Audit chain verified (`verify_chain()` returns ok)

---

## Execution Log (`execution.log`)

`execution.log` is the human-readable execution transcript. Every tool invocation,
every pipeline step, every subprocess call — with stdout output inline.

### Format

```
==============================================================================
Spectre Execution Log — Phase-by-Phase Transcript
Case: NNN-name
Started: 2026-06-27T17:30:39Z
Each entry: phase + step identifier, command line, stdout output (truncated at 200 lines / 20000 chars)
Full output files under raw_extract/ — see stdout_path references
==============================================================================

[17:30:40] [P2:S3] vol:windows.pslist.PsList  PASS  723ms  | 745 rows → raw_extract/pslist.json
  vol -q -r json -s ... -f .../Challenge.raw windows.pslist.PsList
  ── stdout (full output: raw_extract/pslist.json) ──
  │ [{"CreateTime": "...", "ImageFileName": "System", "PID": 4}, ...]
  │ ... (truncated at 200 lines), see raw_extract/pslist.json
  ── end stdout ──
```

### Phase + Step Identifiers

Every entry carries a `[PX:SY]` tag:

- `P0` — Phase 0 (Case Setup)
- `P1` — Phase 1 (Direction)
- `P2` — Phase 2 (Extraction)
- `P3` — Phase 3 (Detection)
- `P4` — Phase 4 (Correlation)
- `P5` — Phase 5 (Adversarial Review)
- `P6` — Phase 6 (Synthesis + Report)
- `P7` — Phase 7 (Memory + Approval)

Step identifiers are short action names: `S1-canary`, `S2-register`, `S3-triage`, `S4-fk-load`, etc.

### Produced By

`audit.py` → `_write_cmd_log()` → `shell_log.log_command()`

Every `audit.append()` call automatically writes to `execution.log`. No extra code
needed. Phase and step are sourced from `phase` and `phase_step` fields on each
audit entry, set at the call site:

- `tool_exec` rows → `phase=2, phase_step=S1-extract-<tool>` (set by `tool_runner.py`)
- `finding_create` rows → `phase=3, phase_step=S1-emit` (set by `emit_finding.py`)
- `explain.py` rows → `phase=3` (normal) or `phase=5` (adversarial), with step tags
- `evidence_register` → `phase=0` (default)

If `phase` is absent from the audit entry, it defaults to 0 (Phase 0 — Case Setup).

---

## Evidence Metadata (Phase 0 Extracts)

Evidence metadata describes WHAT the evidence IS. Phase 0 extracts structural
metadata using lightweight, deterministic tools (<10s per file) BEFORE loading
FK YAMLs — because the OS version may affect which FK YAMLs apply.

Phase 1 supplements with hash lookups and IP reputation on top of this base.

### Memory Image Metadata

```yaml
evidence_metadata:
  /path/to/memory.raw:
    type: memory_image
    sha256: "abc123..."              # File-level: SHA-256 of the evidence file
    file_size_bytes: 1073741824      # File-level: os.stat().st_size
    file_created: "2026-06-27T..."   # File-level: os.stat().st_ctime (copy date)
    file_modified: "2026-06-27T..."  # File-level: os.stat().st_mtime
    os: "Windows 10"
    os_build: "19041"
    architecture: x64
    capture_method: vm_snapshot
    capture_time: "2019-08-19T14:40:07Z"  # SystemTime from the memory image (was system_time)
    uptime_seconds: 86400
    physical_memory_gb: 4
    kdbg_offset: "0x..."
    profile: "Win10x64_19041"
```

File-level fields (`sha256`, `file_size_bytes`, `file_created`, `file_modified`) are
common to ALL evidence types — extracted from `os.stat()` + `_sha256_file()` before
type-specific metadata extraction. They describe the evidence FILE itself, not
what's inside it. `capture_time` (formerly `system_time`) is the SystemTime reported
by the memory image — the moment the dump was taken, not the analysis workstation time.

### EVTX Metadata

```yaml
evidence_metadata:
  /path/to/Security.evtx:
    type: evtx
    hostname: "WS01"
    ip_address: "192.168.1.100"
    time_range_start: "2019-08-19T00:00:00Z"
    time_range_end: "2019-08-19T23:59:59Z"
    total_events: 45000
    providers: ["Microsoft-Windows-Security-Auditing"]
    tampered: false
```

### Disk Image Metadata

```yaml
evidence_metadata:
  /path/to/disk.raw:
    type: disk_image
    filesystem: NTFS
    partitions: 3
    volume_label: "OS"
    volume_serial: "1234-ABCD"
    os_installations: ["Windows 10 Pro (C:\Windows)"]
    sector_size: 512
    total_sectors: 209715200
```

### PCAP Metadata

```yaml
evidence_metadata:
  /path/to/traffic.pcap:
    type: pcap
    capture_duration_seconds: 3600
    total_packets: 150000
    data_rate_mbps: 2.5
    link_type: "Ethernet"
    snaplen: 65535
```

---

## Artifact Profiles

Profiles declare which artifacts are in scope. They serve two purposes:

1. **Pre-select FK YAMLs** when the evidence type is known in advance
2. **Scope the investigation** — an examiner saying `--profile evtx-focused` is
   deliberately excluding memory/disk artifacts

### Available Profiles

| Profile | Artifacts | Use Case |
|---|---|---|
| `auto` | Derived at runtime from recognition | Default — let the pipeline figure it out |
| `quick-triage` | evtx_4688, prefetch, amcache, registry_run, mft, lnk, shimcache, srum | Windows IR triage |
| `memory-only` | memory_pslist, memory_netscan, memory_cmdline | Memory dump only |
| `disk-light` | mft, lnk, prefetch, amcache, registry_run | Disk image light |
| `evtx-focused` | evtx_4688 | EVTX-only deep dive |
| `full-windows` | Same as quick-triage (currently identical) | Full Windows artifact coverage |
| `fixture-test` | evtx_4688 | Pipeline testing with known fixtures |
| `network-only` | pcap, firewall, ids | Network traffic analysis |
| `pcap-focused` | pcap | PCAP deep-dive |

### Auto-Extend Flag

`--auto-extend` flag: use the profile as a minimum scope, but also include
any additional artifacts discovered by the recognizer. Without this flag,
a static profile constrains the scope to its listed artifacts only.

Example: `--profile evtx-focused --auto-extend` with a memory dump will
include both `evtx_4688` (from profile) and all memory FK YAMLs (from recognizer).

The `auto_extend: true` field in manifest.yaml records whether this was used.

---

## Findings File Naming

**Format:** `F-{case_id_prefix}-{per_case_NNN}.yaml` (e.g., `F-004-001.yaml`)

- `case_id_prefix`: numeric case ID extracted from directory name (e.g., `004` from `004-new-mem`)
- `per_case_NNN`: sequential counter within the case, zero-padded to 3 digits
- Finding ID in YAML and audit.jsonl uses this same format

Rationale:
- Per-case counter means `F-004-001` is globally unique — no collision with `F-005-001`
- Case ID prefix tells you which case owns the finding at a glance
- Sequential within case is append-only and deterministic
- Backward compatible: glob `F-*-*.yaml` matches both old `F-SPECTRE-NNN` and new `F-NNN-NNN`

---

## Artifact Files Per Case (Complete)

| File | Format | Produced By | Purpose |
|---|---|---|---|
| `manifest.yaml` | YAML | Phase 0 (case_setup) | Case dashboard and metadata |
| `fk_context.yaml` | YAML | Phase 0 (case_setup) | Loaded FK YAMLs for recognized artifacts |
| `audit.jsonl` | JSONL + SHA-256 | Phases 0-7 (audit.py) | Machine-readable tamper-evident chain of custody |
| `execution.log` | Plain text | Phases 0-7 (shell_log.py) | Human-readable execution transcript with stdout |
| `raw_extract/_handles.json` | JSON | Phase 2 (extraction) | Tool execution handles with paths and execution_ids |
| `raw_extract/*.json` | JSON | Phase 2 (extraction) | Raw extraction output per tool invocation |
| `findings/F-{case_id}-{NNN}.yaml` | YAML | Phase 3 (emit_finding) | Per-finding structured output |
| `reports/report.md` | Markdown | Phase 6 (report generation) | Narrative report with MITRE map, timeline, blind spots |
| `reports/iocs.csv` | CSV | Phase 6 (report generation) | Structured IOC export |
| `reports/blindspots.md` | Markdown | Phase 6 (report generation) | Standalone blind-spots matrix |

---

## Known Issues

### FK Context Blank for Memory (`fk_context.yaml = {}`)

**Status:** FIXED in case_setup.py v1.2.0

When profile is `auto` and evidence is a memory image, the recognizer returns
`artifact_type: memory_image`. The `ARTIFACT_FK` map had no entry for `memory_image`,
so `fk_yamls` stayed empty → `fk_context.yaml` = `{}`.

**Fix:** Added `memory_image` → loads ALL `memory_*.yaml` files from
`src/spectre/knowledge/artifacts/windows/`. **Generalized (S-G):** the map is no
longer hand-written — it is derived from each module's `module.yaml`, so the class
of bug ("the map had no entry for X") cannot recur by omission. Adding a key was
the fix three separate times (`memory_image` here, the pcap types in case
268-001, then registry_hive/prefetch/lnk/disk in A4-01); `memory_psscan` was
still missing when the map was replaced.

### Magic Bytes Not Captured — MITIGATED by Step 5

`recognize.py` calls `magic.from_file()` but the result is often empty for large
binary files (memory dumps, disk images). The `magic` field in triage records may
be blank. **Step 5 evidence metadata extraction fills this gap** by running
`vol windows.info.Info` (memory) or `capinfos` (PCAP) to extract structured OS,
architecture, and capture metadata regardless of libmagic limitations.

### verify_chain() Is Necessary But Not Sufficient — RESOLVED in v1.2.0

`audit.verify_chain()` validates SHA-256 linkage only. Use `audit.verify_full()`
which additionally checks:
- Audit↔disk consistency (finding YAMLs match audit rows)
- case_id consistency (no cross-case attribution errors)
- Phase coverage (every finding has audit rows for critical phases) — advisory
  only; does not fail `report["ok"]`, since an in-progress finding legitimately
  has not reached Phase 6
- Evidence integrity (re-hash against manifest)
- report.md integrity (re-hash the deliverable against the sha256 recorded by
  the Phase 6 `S3-merge-report` audit row; abstains when no such row exists)
- Derived evidence integrity (re-hash carved artifacts recorded in
  `manifest["derived_evidence"]`)

`verify_chain()` remains the fast path for chain validation; `verify_full()` is
the comprehensive examiner-grade check.

### Methodology Skill Paths Are Stale

The `forensic-methodology` skill references `~/forensic-kb/scripts/case_setup.py`
and other pre-restructuring paths that no longer exist. The code is at
`~/spectre-forensic/src/spectre/pipeline/`.

**Status:** Known. Full path cleanup pending.

---

## Verification

After Phase 0 completes, verify:

```bash
# 1. Manifest exists and is valid YAML
python3 -c "import yaml; yaml.safe_load(open('manifest.yaml'))" && echo "OK"

# 2. FK context is NOT empty
python3 -c "import yaml; ctx = yaml.safe_load(open('fk_context.yaml')); assert ctx, 'FK context is empty!'; print(f'OK: {len(ctx)} FK YAMLs loaded')"

# 3. Audit chain is intact
python3 -c "from spectre.pipeline.audit import verify_chain; ok, reason = verify_chain('.'); print(f'Chain: {reason}')"

# 4. Evidence is read-only
ls -la evidence/* | awk '{print $1, $NF}' | grep -v '^-r--'

# 5. All subdirectories exist
ls -d evidence raw_extract findings reports
```

---

## Changelog

| Date | Version | Changes |
|---|---|---|
| 2026-09-30 | 1.8.0 | Wave 3 custody: evidence_register rows record case-relative paths (+ `evidence_relpath` in the manifest ref); `evidence/` locked 0555 after registration (`evidence/derived/` stays writable); every phase entry and resume re-hash evidence against the chained rows (`evidence_tampered` row + stop on mismatch); genesis row carries a chained `case_nonce` that keys the journal anchor, which now also detects tail truncation. |
| 2026-07-10 | 1.7.0 | Derived evidence: disk images carve nested artifacts (EVTX/hives/prefetch/LNK/$MFT) in Phase 2; carved files hashed + chmod 444 + `derived_evidence_register` audit rows + `manifest["derived_evidence"]` parent linkage, re-triaged through the module registry (depth-bounded). Three new analyzer modules: registry_hive (RegRipper), prefetch (stdlib parser, honest MAM handling), lnk (minimal MS-SHLLINK). `verify_full()` re-hashes derived evidence. |
| 2026-07-09 | 1.6.1 | EWF/libewf capability probe: `triage_one()` detects when local Sleuth Kit lacks libewf support (via `fls -i list`). E01 files recognized but unsupported downgrade to EXTRACTOR_PENDING(libewf) at Phase 0 triage, surfacing the dependency before extraction fails mid-Phase-2. Cached per-session via `_EWF_SUPPORT`. |
| 2026-07-09 | 1.6.0 | `--evidence` accepts directories: `_expand_evidence_paths()` walks them recursively before registration. Skipped entries (missing/symlink/empty/non-regular) recorded in `manifest["intake_skipped"]` instead of being silently dropped. |
| 2026-06-27 | 1.5.0 | execution.log phase tagging: tool_runner (P2), emit_finding (P3), explain.py (P3/P5). Phase headers standardized (runner.py provides `──` wrapper; phase_runner functions no longer print `===` banners). evidence_metadata: added sha256, file_size_bytes, file_created, file_modified. Renamed system_time → capture_time. FK YAML artifact-vs-tool distinction clarified. Spec version header fixed. |
| 2026-06-27 | 1.4.0 | Evidence metadata extraction moved to Phase 0 Step 5 (vol windows.info.Info for memory, capinfos for PCAP). Magic bytes gap mitigated. |
| 2026-06-27 | 1.3.0 | Methodology skill: stale paths cleaned. |
| 2026-06-27 | 1.2.0 | verify_full() implemented — 5 comprehensive integrity checks beyond SHA-256 chain. |
| 2026-06-27 | 1.1.0 | Findings file naming: F-SPECTRE-NNN → F-{case_id}-NNN. execution.log rename + [PX:SY] tags. |
| 2026-06-27 | 1.0.0 | Initial spec. Captured all Phase 0 decisions from analyst review. |
