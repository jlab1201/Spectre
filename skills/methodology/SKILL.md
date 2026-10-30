---
name: methodology
description: "7-phase forensic investigation orchestrator — case setup through memory+approval. Quality gates between phases, context budget monitoring, subagent dispatch."
version: 2.1.1
author: Spectre
license: MIT
tags: [forensic, spectre, methodology, orchestrator, pipeline]
metadata:
  hermes:
    tags: [forensic, spectre, methodology, orchestrator, pipeline]
---

# Forensic Methodology (7-Phase Orchestrator)

Master orchestrator for Spectre forensic investigations. Implements the full 7-phase pipeline with quality gates between every phase. Dispatches subagents for parallel deep-dive, adversarial review, KB retrieval, and timeline building.

> **Host adaptation (platform-agnostic):** This skill speaks in actions, not in any one
> agent's API — Hermes, Claude Code, or any orchestrating agent can drive it. The in-process
> AI seams (`explain`, `direction`, `report_synthesize`) route through `spectre.llm`, selected by
> `SPECTRE_LLM_PROVIDER` (default `host` = defer to *you*, the orchestrating agent). In host
> mode `explain()` returns a prompt+schema bundle; produce the JSON and feed it back via
> `explain.ingest_host_output()`, which runs the same guardrails. Likewise, `synthesize_report()`
> defers to you for the report narrative; feed your JSON back via
> `report_synthesize.ingest_host_report()`.

## When to use

- Starting ANY forensic investigation
- Resuming a paused investigation (checks case state first)
- Every phase transition must pass through a quality gate
- The ONLY entry point for forensic work — no ad-hoc tool use

## The 7 Phases

```
PHASE 0: CASE SETUP ──────► GATE 0 ──────►
PHASE 1: DIRECTION ────────► GATE 1 ──────►
PHASE 2: EXTRACTION ───────► GATE 2 ──────►
PHASE 3: DETECTION+HYPOTH ─► GATE 3 ──────►
PHASE 4: CORRELATION+VERIFY ► GATE 4 ──────►
PHASE 5: ADVERSARIAL REVIEW ► GATE 5 ──────►
PHASE 6: SYNTHESIS+REPORT ──► GATE 6 ──────►
PHASE 7: MEMORY+APPROVAL ───► DONE
```

## Phase 0: Case Setup

**Unified entry point:** `case_setup.py` — runs all of Phase 0 in one command.

```
python3 -m spectre.pipeline.case_setup --name "<case-name>" --profile <artifact-profile> [--evidence <path>...]
```

Artifact profiles (`case_setup.PROFILES`): `auto` (the default when `--evidence` is given; artifacts derived from file recognition), `quick-triage`, `full-windows`, `memory-only`, `disk-light`, `evtx-focused`, `network-only`, `pcap-focused`, `fixture-test`. FK YAMLs are loaded from every directory in `config.FK_DIRS` (`artifacts/windows/`, `network/`, `logs/`, `disk/`).

For PCAP/network cases, case_setup.py handles Phase 0 automatically (`spectre --name NAME --profile pcap-focused --phase 0 --evidence X.pcap`). Do not hand-build a case directory: registration, the `.case-counter`, the chained `evidence_register` rows and the `0555` lock on `evidence/` only happen through `case_setup`; a hand-made case has none of those (not tested against `verify_full`).

Phase 2 extraction for PCAP runs through the pcap module (`src/spectre/modules/pcap/`: Zeek primary, tcpdump/tshark fallback, all via `tool_runner.run_tool()`).
See `references/pcap-triage.md` for manual tcpdump verification commands.

`case_setup.py` orchestrates:
  1. Auto-increments case counter → creates `~/spectre-cases/NNN-name/` (`SPECTRE_CASES_DIR`)
  2. Creates subdirectories: `evidence/`, `raw_extract/`, `findings/`, `reports/`
  3. Runs session canary: `canary.py --case <case_dir>` → FULL/DEGRADED/DEAD
  4. Registers evidence in-process (`_register_evidence`: guard on source, copy, `chmod 444`, guard on copy, chained audit rows)
  5. Loads FK YAMLs for all artifacts in the selected profile
  6. Runs cross-case episodic recall against `cross_case_index.py`
  7. Writes `manifest.yaml` with case metadata, evidence refs, FK context
  8. Returns JSON: `{case_dir, case_id, canary_status, manifest_path, success}`

For manual Phase 0 execution, the individual steps are:
1. Session canary (mandatory): `spectre-canary --case ~/spectre-cases/NNN-name`
   - If FULL: investigation proceeds normally
   - If DEGRADED: investigation continues but all findings get `canary_status: "DEGRADED"` marker; canary audit row written
   - If DEAD: pipeline STOPS — volatility3 + 3+ other tools failed; do not proceed
2. Create case directory structure with `evidence/`, `raw_extract/`, `findings/`, `reports/`
3. Register evidence: `python3 -m spectre.pipeline.evidence_guard <evidence_path> --case ~/spectre-cases/NNN-name` is the optional pre-check only; registration itself is done by `case_setup` (Phase 0: `spectre --name NAME --phase 0 --evidence PATH`)
   - If guard FAILS: evidence rejected, audit row logged, STOP — fix file permissions before proceeding
4. Select artifact profile (see the `case_setup.PROFILES` list above; `auto` when evidence is given)
5. Zero-Knowledge check: strip CTF metadata if present
6. Load KB context: FK YAMLs for all artifacts in profile
7. Cross-case episodic recall: use `cross_case_index.py search` directly for programmatic access:
   - `python3 -m spectre.pipeline.cross_case_index search --ioc-type <type> --value <value>`
   - Use `--search-all` to search across all IOC types: `cross_case_index.py search --search-all --value <value>`
   - If matches found: inject a "Cross-Case Recall" section into the case manifest
     listing which past cases share IOCs, what was found, and confidence
   - Format: "Prior case NNN found <ioc> in <finding> with confidence <X>"
   - Cross-case matches are ADVISORY — they inform, they do not decide
8. Write `manifest.yaml` with case metadata, evidence refs, artifact profile, FK context
9. Verify audit chain: `python3 -c "from spectre.pipeline.audit import verify_chain; print(verify_chain('<case_dir>'))"` — must pass before proceeding
10. On case RESUME **and at every phase entry**: `runner.run_phase()` / `_resume_canary_recheck()` call
    `custody.enforce_evidence()`, which re-hashes every evidence copy against its chained
    `evidence_register` row (NOT manifest.yaml, which is mutable) and re-runs `evidence_guard`
    on it; mismatch → `evidence_tampered` audit row + pipeline stops (resume exits 4). After
    registration `evidence/` is `0555` (only `evidence/derived/` stays writable, for carving).
    Evidence rows record case-relative paths (`evidence/<name>`), so a copied/archived case
    verifies its own bytes.
11. Load episodic memory: the orchestrating agent's memory tool (e.g. Hermes `memory`, Claude Code memory) auto-injects agent notes into context.
    Memory entries from past cases appear in the system prompt — no explicit lookup needed.
    But DO search index.md for precision (memory is fuzzy, index.md is exact)

**Gate 0 (MUST PASS before Phase 1):**
- [ ] Session canary status known and recorded (FULL / DEGRADED)
- [ ] Case directory exists with manifest.yaml
- [ ] All evidence passed evidence_guard + registered with SHA-256
- [ ] Audit chain verified (verify_chain passed)
- [ ] Artifact profile selected
- [ ] FK YAMLs loaded for selected artifacts

## Phase 1: Direction

**Skills loaded:** (none — pure Python, with an optional LLM assist)

`run_phase_1()` (`src/spectre/pipeline/phase_runner.py`) synthesizes the investigator's
free-text tasking (`manifest["direction"]`) into structured, deterministic-first directive
specs that Phase 3 applies additively during detection:

1. Read `manifest["direction"]` — the analyst's natural-language investigative tasking.
   Empty direction is a clean, honest pass-through (writes `[]`, gate still passes).
2. Run LLM preflight (`llm.preflight()`) and record status in `manifest["llm"]`. If the
   provider is DEAD, narrative seams go inert but Phase 1 does not block.
3. Parse the direction text into validated directive specs via `direction.synthesize()` —
   deterministic-first; the LLM is used only for fuzzy-phrasing expansion, and is skipped
   entirely under `--skip-ai`.
4. Write directives to `raw_extract/directives.json`.
5. Audit the synthesis (`directives_synthesized` action, tagged `[P1:S1-synthesize-directives]`
   in execution.log) BEFORE Phase 3 runs, so every directed finding is reproducible.

**This is not zero-LLM-tokens.** Unlike a purely deterministic phase, Phase 1 CAN call an
LLM (`direction.synthesize`) when direction text is present and `--skip-ai` is not set.

**Gate 1** (per `gate_1` written by `run_phase_1`):
- [ ] `directives_synthesized`: count of directive specs produced (0 is valid when direction
      text is empty, or when the LLM was unavailable and deferred — see `degraded_reason`)
- [ ] `llm_used`: whether the LLM was actually invoked for this run
- [ ] `degraded_reason`: set (non-null) when direction text was present but the LLM was
      unavailable, so no directives could be synthesized — Gate 1 still records this as a
      DEGRADED pass, not a hard failure
- [ ] `passed`: `True` when either no direction text was given, or at least one directive
      was synthesized

## Phase 2: Extraction

**Skills loaded:** tools/logs/evtx, tools/memory/volatility3, tools/memory/memprocfs, tools/logs/plaso, tools/disk/sleuthkit, tools/scanner/yara

Execute tools per artifact profile. All invocations through tool_runner.py:

1. For each artifact in profile:
   - Build typed command via tool skill
   - Execute via `run_tool()` → returns typed handle
   - Apply size gate: if >500 lines, flag NEEDS_FILTERING
   - Apply Empty Data Protocol: 0 output → UNVERIFIED
   - Write audit row
2. FK YAML envelope injected on each result

**Parallel execution** via subagent dispatch:
- Subagent 1: EVTX extraction (evtx module: `evtxexport` via `run_tool()`, XML parsed by `modules/evtx/normalize.py`)
- Subagent 2: Disk forensics (mmls → fls → fsstat chain)
- Subagent 3: Memory forensics (dual-engine: volatility3 + MemProcFS via `spectre-memory`)

Memory forensics supports three engine modes via `spectre-memory`:
  - `--engine vol` — volatility3 only (fast, well-tested)
  - `--engine memprocfs` — MemProcFS only (FUSE mount, filesystem metaphor)
  - `--engine both` — **the default**; both engines over the same image, in the
    same case, so matching claims corroborate. Also prints a per-artifact
    row-count comparison, which is an extraction-health signal only — it judges
    no claim and does not feed confidence.
  The pipeline (`phase_runner`) passes no engine argument, so it gets `both`.
  Both engines produce identically-schemed JSON output so normalize() and rules
  work unchanged. Handles carry an `engine` metadata field for provenance.
  See `references/dual-engine-memory.md` for the full integration pattern.

For `network-only` / `pcap-focused` profiles, Phase 2 extraction runs the pcap
module (Zeek primary; tcpdump/tshark fallback when Zeek is absent), routed
through `tool_runner.run_tool()` like every other tool. `references/pcap-triage.md`
holds manual tcpdump commands for verifying what the module extracted.

**Gate 2:**
- [ ] All profile artifacts have execution attempts
- [ ] Each execution has audit row with execution_id
- [ ] Size gate applied to all outputs
- [ ] Empty Data Protocol applied (UNVERIFIED markers where applicable)
- [ ] All output_sha256 recorded
- [ ] `execution.log` exists in case directory — human-readable command log with timestamps, durations, row counts, and full command lines

## Phase 3: Detection + Hypothesis

**Skills loaded:** knowledge-retriever

**Mismatched profile (e.g., PCAP evidence run under quick-triage):** Phase 2
  extracted fixture data because the profile has no handler for the real evidence
  type, so Phase 3 emits F-SPECTRE-001 from fixture anchors. That finding is real
  pipeline output but unrelated to the evidence. Do NOT add the real-evidence
  findings yourself: findings come only from the rule packs that `spectre --phase 3`
  runs. Never call `emit_from_handle()` or any other `emit_finding` function by
  hand, never pick a rule_id, title or IOCs, and never write a finding YAML. Rebuild the case with a profile
  that extracts the real evidence (`--profile auto`, `network-only` or
  `pcap-focused` for PCAP) and run the phases in order.

**Something no rule covers:** record it as an investigative lead for the examiner
  (report it in the session: what you saw, the exact command that showed it, and the
  artifact) — it is not a finding and does not go in `findings/`. You may propose a
  new rule for it following the vertical-slice pattern in `skills/core/SKILL.md`
  (recognizer → extract → normalize → rule pack → FK YAML, test first); once that
  rule lands, Phase 3 produces the finding deterministically.

1. Run each analyzer module's rule pack on normalized events (`modules/<m>/rules.py` or `rules/`, discovered by `core/rule_discovery.py`)
2. Each detection produces an Anchor (rule_id, record_number, candidate_mitre)
3. Load FK YAML for each anchor's artifact type
4. Rank hypotheses (2-5) by severity/confidence
5. Query KB: any known patterns matching detected behavior?
6. Anti-forensics checks: timestomping, log clearing, prefetch anomalies
7. **For network profiles only:** the pcap module's rules (`pcap-beacon`, `pcap-dns-anomaly`,
   `pcap-c2-protocol`, `pcap-exploit-probe`, …) run here automatically.
   `references/pcap-triage.md` §Phase 3 has manual tcpdump commands for verifying them.

**Gate 3:**
- [ ] Detection produced anchors (or EXPLICIT "no detections raised")
- [ ] Each anchor has FK YAML loaded
- [ ] Hypotheses ranked and documented
- [ ] Anti-forensics checks complete
- [ ] Audit chain verified (verify_chain passed — Phase 3 gate)

## Phase 4: Correlation + Verification

**Skills loaded:** correlation-engine

**BEFORE Phase 4: Mid-investigation session canary re-check (Phase 3 hardening)**
- Run `spectre-canary --case <case_dir>`
- Tools can fail mid-session (disk full, OOM kill); stale canary = false confidence
- If DEGRADED: flag all subsequent findings with canary_status="DEGRADED"; write canary_result audit row
- If DEAD: pipeline STOPS — cannot proceed to correlation without core tools

1. Cross-artifact correlation:
   - Process → Network (EVTX 4688 + netscan)
   - Process → File (EVTX 4688 + Prefetch/MFT/Amcache)
   - Process → Registry (EVTX 4688 + Registry Run keys)
2. Temporal clustering (±60s window by default)
3. Corroboration scoring per finding (source-count formula)
4. Finding validation (provenance gate, MITRE gate, FK envelope gate)
5. Dual-tool cross-validation where available (delta >5% flagged)

**Dispatch subagents (from subagent_templates.py):**
- For each CONFIRMED finding: dispatch deep-dive analyst subagent (parallel, up to 3 at a time)
  `from spectre.pipeline.subagent_templates import build_deep_dive_context`
  `ctx = build_deep_dive_context(finding, fk_yaml_path, kb_hits, cross_case_matches)`
  Then `delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=['terminal', 'file', 'web'])`
- Subagent: Cross-artifact correlation (gets all tool handles + FK YAMLs)
- Subagent: Temporal clustering (gets timeline data)
- Subagent: Validation (gets findings + audit log)

The cross-case index is NOT updated here: Phase 7 (`runner.verify_and_close()`) writes it after
approval, and only CONFIRMED (+approved) findings are indexed.

**Gate 4:**
- [ ] Every finding has source count ≥ 1 (0-source findings auto-DROPPED)
- [ ] Every finding's evidence_refs[0].execution_id resolves to a tool_exec audit row (NOT finding_create)
- [ ] MITRE techniques in allowed set
- [ ] Confidence matches source-count formula
- [ ] Cross-validation deltas documented
- [ ] Audit chain verified (verify_chain passed — Phase 4 gate)

## Phase 5: Adversarial Review

**Skills loaded:** report-generator (for explain guardrails)

`phase_runner.py --phase 5` runs TWO independent, differently-named mechanisms.
Do not conflate them — they answer different questions and fail differently:

**Mechanism A — `grounding_probe`.** Per finding, `explain(adversarial=True)`
injects a fixed, fabricated C2 claim (an outbound connection to a hardcoded
IP) into the prompt and re-runs it through the SAME Validator #5 that
guards the normal explain pass. Its success criterion is that the claim
gets stripped — this is an integrity self-test of the validator, not a
forensic review of the case. Meaningful only when a real API provider
(`deepseek`/`anthropic`/`openai`/`local`) ran the pass; under `host` or
`null` it honestly reports `deferred-to-host` / `not-run` rather than
silently passing. If the poison ever SURVIVES into a probe output's
description, Gate 5 FAILS closed (`manifest["gate_5"]["status"] == "FAIL"`,
blocks Phase 6) — Validator #5 itself is broken and nothing downstream can
be trusted to have been grounded correctly.

**Mechanism B — `substantive_review`.** The real devil's-advocate pass —
counter-hypotheses, evidence gaps, citation gaps, alternative timeline —
built from `build_adversarial_context()` (below) and run case-level
(all findings at once, not per-finding). It is always advisory: the result
lives only at `manifest["gate_5"]["adversarial_review"]`, is validated by
`explain._validate_adversarial()` (an unknown finding_id drops the whole
counter-hypothesis, an out-of-set MITRE token is redacted, an ungrounded
IP/domain literal is stripped, any `confidence` key is rejected), and is
NEVER written to a finding YAML or passed to `explain._finalize()`. It
never blocks Phase 6 by itself — surfaced evidence/citation gaps DEGRADE
the gate (an honesty label) but do not FAIL it.

**Automated path (`phase_runner.py --phase 5`):** `_run_substantive_adversarial()`
in `phase_runner.py` calls `build_adversarial_context()` for you and
branches on `SPECTRE_LLM_PROVIDER` through the same `spectre.llm` registry
every other seam uses:
- A direct API provider runs the call and validates the result inline —
  `substantive_review: "ran"`, real `counter_hypotheses_count`.
- `host` (the default) returns `substantive_review: "deferred-to-host"` and
  does NOT fabricate a review. If you are the orchestrating agent driving
  this phase, fill the returned `request` bundle (`system`/`user` prompt +
  `schema=ADVERSARIAL_SCHEMA`) yourself and finalize with:
  ```python
  from spectre.core.explain import ingest_host_adversarial
  result = ingest_host_adversarial(
      all_findings=findings,        # the same finding dicts passed in
      allowed_mitre=allowed_mitre,  # from mitre-map.yaml's rules[*].allowed
      host_json=your_filled_json,   # your JSON, matching ADVERSARIAL_SCHEMA
      case_dir=case_dir,
  )
  ```
  This runs through the identical `_validate_adversarial()` guardrails as
  the direct-API path — no host can bypass the no-invented-findings /
  no-new-MITRE / no-confidence-mutation rules by writing prose instead of
  calling an API. Do not hand-write `manifest["gate_5"]["adversarial_review"]`
  directly; always route through `ingest_host_adversarial()`.
- `null` returns `substantive_review: "not-run"` with a `degraded_reason`
  naming it deterministic-only — never a silent pass.

**Manual/subagent dispatch** (for a deeper, interactive devil's-advocate
pass beyond what an automated single API call produces) still works the
same way it always did:
```
from spectre.pipeline.subagent_templates import build_adversarial_context
ctx = build_adversarial_context(
    all_findings=findings,
    evidence_manifest=manifest,
    artifact_profile=profile_name,
    fk_blind_spots=collected_blind_spots,
    tool_exec_log=tool_exec_summary,
)
delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=['terminal', 'file', 'web'])
```
Goal: Challenge the primary narrative.
Context: All CONFIRMED findings + evidence manifest + audit log.

1. Counter-hypotheses for each CONFIRMED finding
2. Evidence gaps: which tools were applicable but never invoked?
3. Citation gaps: which evidence was indexed but never cited?
4. Alternative timeline: could events have happened differently?
5. Confidence adjustment recommendations (advisory only — no code path ever
   applies a confidence change from this pass; if you write the subagent's
   findings into the report by hand, run them through `_validate_adversarial()`
   or `ingest_host_adversarial()` first, same as the automated path does)

**Gate 5:**
- [ ] Grounding probe ran for every finding (or honestly reports
      `deferred-to-host` / `not-run`) and the poison never survived
- [ ] Substantive review ran, or honestly reports why it didn't
      (`deferred-to-host` / `not-run`) — never silently skipped
- [ ] Counter-hypotheses documented (when substantive review ran)
- [ ] Coverage gaps listed
- [ ] Citation gaps listed
- [ ] Review findings kept advisory (not modifying finding originals)
- [ ] Audit chain verified (verify_chain passed — Phase 5 gate)
- [ ] Verify audit↔disk consistency: every finding in audit has a YAML on disk and vice versa
- [ ] Every finding has an `action="adversarial_review"` audit row (phase_coverage,
      audit.py Check 4) — written per-finding by the grounding-probe loop regardless
      of provider

For the full catalog of defects caught by adversarial review during Phase 6 development
(case_id mis-attribution, exact_command dishonesty, internal inconsistency, unreviewed findings),
see `references/phase-6-adversarial-review.md`.

## Phase 6: Synthesis + Report

**Skills loaded:** report-generator, knowledge-retriever

**Automated execution:** `phase_runner.py --case <case_dir> --phase 6`
This generates `reports/report.md`, `reports/iocs.csv`, and `reports/blindspots.md`
from the findings in `findings/F-*-*.yaml`. All gate checks are automatic.

**Manual/targeted synthesis** (Spectre Lead Agent):

**Dispatch KB retriever subagents** for any artifact types needing deeper context:
```
from spectre.pipeline.subagent_templates import build_kb_retriever_context
ctx = build_kb_retriever_context(query="T1218.011 rundll32", artifact_type="evtx", phase="Phase 6")
delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=['terminal', 'file'])
```

**Spectre Lead Agent** (this session):

1. Narrative explanation of all CONFIRMED + INFERRED findings
2. MITRE ATT&CK mapping per finding (from allowed set only)
3. Timeline reconstruction
4. Forensic Blind Spots matrix
5. Cross-case episodic recall (has this artifact appeared before?)
6. Report generation:
   - `reports/report.md` (authoritative)
   - `reports/report.html` (optional)
   - `reports/iocs.csv` (structured export)
   - `reports/blindspots.md` (standalone)

**Explain layer guardrails enforced:**
- Caveats verbatim from FK YAML `does_NOT_prove`
- MITRE from mitre-map allowed set only
- Every claim cites finding_id
- No invented findings (stripped + logged)
- Confidence immutable
- Empty Data Protocol respected

**Gate 6:**
- [ ] report.md exists with all sections
- [ ] Every CONFIRMED finding has narrative explanation
- [ ] MITRE map complete (no findings missing mapping)
- [ ] Blind spots matrix populated
- [ ] IOC table exported
- [ ] Explain layer violations = 0 (or all stripped + logged)

## Phase 7: Memory + Approval

1. All findings are DRAFT until examiner approves
2. Examiner reviews each finding → APPROVED | REJECTED | SUPERSEDED, recorded with the
   in-process writer (W3-6) — **never** by hand-editing the YAML:
   ```
   spectre approve --case <case_dir> --finding F-NNN-003 [--finding F-NNN-004 ...] \
       --examiner "<name>" --decision APPROVED|REJECTED|SUPERSEDED \
       --rationale "<reason>" [--superseded-by NNN-case/F-NNN-001]
   ```
   (Python: `spectre.pipeline.approval.approve_finding(case_dir, fid, examiner=..., decision=...,
   rationale=...)`.) It refuses a finding whose bytes no longer match its latest hash-authority
   row, stages the new YAML (`approval`, `approved_by`, `approved_at`, `approval_rationale`,
   + `superseded_by`) in an fsync'd `findings/.F-….yaml.approval-pending` file, appends ONE
   chained `approval` row (actor `examiner`, phase 7, phase_step `S7-approve`) carrying the
   decision, `previous_approval` (null when never set) and the staged content hash, and only
   then `os.replace`s the finding. If that last step fails, re-run the same command: it
   completes the replace. `--superseded-by` must be a registered finding (`F-…` in this case
   or `<case_dir_name>/F-…` of a sibling case). The row is an allowlisted finding hash
   authority, so `verify_full()` stays green.
   The old procedure (append an `approval` row yourself, then edit the YAML) FAILS
   `verify_full`'s `finding_integrity` check — the edited bytes match no authority row.
3. Update cross-case index: `python3 -m spectre.pipeline.cross_case_index update <case_name>`
4. Save episodic memory entry via the orchestrating agent's memory tool (e.g. Hermes `memory`, Claude Code memory):
   - Format: "Case NNN-name: N findings, top technique: <MITRE>, key IOC: <distinctive_ioc>"
   - Target: 'memory' (agent notes), not 'user'
   - Max 350 chars — enough for recall, not full case summary
   - Example: "Case 002-e2e-test: MFT anomaly + EVTX 4688 rundll32-from-temp (T1218.011). IOC: C:\\Windows\\Temp\\evil.dll. INFERRED (0.5)."
5. Audit trail verified AFTER approvals: `python3 -c "from spectre.pipeline.audit import verify_full; print(verify_full(case_dir)['ok'])"` must print `True` (or re-run `spectre --case <dir> --phase 7`)
6. Case closed

**Gate 7:**
- [ ] All findings have approval status (APPROVED/REJECTED/SUPERSEDED) — Phase 7 prints and records `gate_7.approval_pending` (advisory; verification runs before sign-off)
- [ ] Every approval decision has a corresponding audit row (action=approval in audit.jsonl)
- [ ] cases/index.md updated
- [ ] Audit chain verified (SHA-256 chain intact)
- [ ] Audit↔disk consistency: every finding_id in audit has a YAML on disk and vice versa
- [ ] Episodic memory saved
- [ ] Evidence remains read-only (chmod 444 verified)

`audit.verify_full(case_dir)` (run by `spectre --case <dir> --phase 7`) performs the Phase 7
integrity checks in one pass: chain, audit↔disk, case_id, phase coverage, evidence re-hash,
report/finding integrity, coverage disclosure. `references/phase-7-verification.md` is an
older manual script kept for reference.

## Context Budget Management

Keep the lead agent's context to case state, findings and synthesis. Hand per-finding deep
dives, adversarial review, KB retrieval and timeline building to subagents (templates below),
each with a fresh context. Raw tool output goes to files under `raw_extract/`, never into context.

## Subagent Dispatch Patterns

All three template builders are in `src/spectre/pipeline/subagent_templates.py`.
Import and call the builder, then dispatch a subagent with your host's subagent tool, passing
`ctx['goal']` as its task and `ctx['context']` as its context. `delegate_task(...)` in the
examples below is Hermes' name for that tool; `toolsets` is a Hermes hint other hosts can ignore.

### Deep-dive Analyst
```
from spectre.pipeline.subagent_templates import build_deep_dive_context
ctx = build_deep_dive_context(
    finding=finding_dict,
    fk_yaml_path="/path/to/fk_yaml.yaml",
    kb_hits=kb_search_results,
    cross_case_matches=recall_results,
)
delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=ctx['toolsets'])
```

### Adversarial Reviewer
```
from spectre.pipeline.subagent_templates import build_adversarial_context
ctx = build_adversarial_context(
    all_findings=findings_list,
    evidence_manifest=manifest,
    artifact_profile="quick-triage",
    fk_blind_spots=collected_does_not_prove,
)
delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=ctx['toolsets'])
```

### KB Retriever
```
from spectre.pipeline.subagent_templates import build_kb_retriever_context
ctx = build_kb_retriever_context(
    query="<search terms>",
    artifact_type="<artifact>",
    phase="<phase>",
)
delegate_task(goal=ctx['goal'], context=ctx['context'], toolsets=ctx['toolsets'])
```

**Validation:** `python3 -m spectre.pipeline.subagent_templates validate` — must show all PASS before dispatch.

## Pipeline Automation Scripts

Two scripts automate phase execution. Both live in `src/spectre/pipeline/`.

### case_setup.py — Phase 0 orchestrator

```
python3 -m spectre.pipeline.case_setup --name "<case-name>" --profile <profile> [--evidence <path>...]
```

Creates case directory, runs canary, registers evidence, loads FK YAMLs, writes manifest.
Returns JSON with `case_dir`, `case_id`, `canary_status`, `success`.
Defined artifact profiles: see `case_setup.PROFILES` (listed under Phase 0).

### phase_runner.py — Single-phase runner (Phases 0-6)

**Note:** this is a direct, lower-level entry point distinct from the `spectre` console
script (`spectre.pipeline.runner:main`). Both accept `--force`: here it skips the
previous-gate-passed check; on `spectre` it continues past a failed preceding phase.

```
python3 -m spectre.pipeline.phase_runner --case <case_dir> --phase <0-6> [--force]
```

Runs one phase at a time with quality gate checks between phases.
Use `--force` to skip the previous-gate-passed check (e.g., re-running a phase after fixing a bug).
For the full fixture execution pattern (Blitz-DFIR: deterministic first, then AI),
see `references/phase-6-fixture-execution.md`.

## Visual Reference

A full pipeline architecture diagram is at `~/spectre-pipeline-architecture.html`.
Open it in any browser (`xdg-open ~/spectre-pipeline-architecture.html`).
It shows the complete two-layer design (Deterministic Core above the split,
AI Explainer below), all 7 phases with quality gates, subagent dispatch
patterns, the audit trail, cross-case index, FK YAML knowledge injection,
and the architectural anti-hallucination guarantee. Use this as a companion
to the phase descriptions above — the diagram is authoritative on layout.

## Verifying the Architecture

The end-to-end pipeline is verified by the test suite (`pytest`) and `spectre-canary`.
`references/e2e-verification.md` describes the retired spike-era script (`spike.core.*`,
two-hop provenance) and is historical only.

For the Phase 3 guard infrastructure (canary, evidence_guard, denylist,
empty_data_protocol, evidence_refs provenance), see
`references/phase-3-guards.md` — includes the full script inventory,
canary state machine, guard checks, and verification commands.

For PCAP/network forensic triage (tcpdump command catalog, beacon detection,
DNS anomaly patterns, C2 fingerprinting), see `references/pcap-triage.md`.

Key property: every tool call produces a `tool_exec` audit row (not
`spectre-core`). The finding's `evidence_refs[0].execution_id` resolves
directly to the `tool_exec` row's `entry_sha256` — provenance is direct:
finding → tool_exec (single hop).

## Pitfalls

- **NEVER skip a gate.** If a gate fails, fix the issue and re-run the phase.
- **Subagents are leaf.** They cannot delegate further. Give them everything they need.
- **All findings are DRAFT until Phase 7.** Never present findings as final.
- **Tool invocations go through skills only — with a PCAP carve-out.** Disk, memory, and EVTX tools route through their respective skills (forensic-tool-volatility3, etc.) via tool_runner. For PCAP analysis, tcpdump + capinfos are invoked directly via terminal() — no tool_runner wrapper exists yet for these. This is acceptable; tcpdump is deterministic and its output goes to files (never raw into context) like any other extraction tool. If a tcpdump tool skill is later created, switch to tool_runner.
- **Session canary before EVERY case.** Don't assume tools still work from last session.
- **Mid-investigation canary re-check before Phase 4.** Tools can fail mid-session (disk full, OOM).
- **Phase order is strict.** Don't jump to Phase 4 before Phase 2 extraction completes.
- **Gate failures stop the pipeline.** Document the failure, fix it, re-enter at the failed phase.
- **Parallel dispatch is not required.** Sequential is preferred when API rate limits are a concern.
- **Denylist is the only hard-block.** Skills are procedural gates; denylist in tool_runner is the only kernel-level refusal. `rm`, `shred`, `mkfs`, and evidence-targeting operations (`dd`, `mv`, `cp`, `chmod` into evidence dirs) are permanently blocked. `dd` for forensic acquisition (`of=/tmp/acquire.raw`) is allowed — only blocked when targeting evidence directories.
- **Evidence guard runs BEFORE registration.** If guard fails (writable evidence, writable parent dir), registration is refused. Fix file permissions first.
- **Post-copy guard uses --skip-parent-check.** The case evidence/ dir MUST be writable for cp to work. The file's chmod 444 is the protection on the copy, not the parent directory. Pre-registration guard runs full check; post-copy guard skips parent-dir check.
- **Guard must not contradict the operation it guards.** If a safety check makes the success path impossible, the guard is wrong. Test both rejection AND acceptance paths. See plan-review references/forensic-review-patterns.md for the full case study.
- **mv is destructive to source — blocked in ALL directions.** Unlike cp (non-destructive), mv deletes the source. Moving evidence out silently removes the registered original — chain-of-custody violation. Denylist blocks mv whenever any argument touches an evidence dir.
- **evidence_refs[0].execution_id = tool_exec row, NOT finding_create.** Direct provenance: finding → tool_exec (single hop). Verified at Gate 4.
- **venv shadowing: system tools invisible.** If `~/spectre-venv/` has `include-system-site-packages = false` (the default), system-installed forensic packages (yara-python via dpkg, etc.) cannot be imported. Fix by installing the package inside the venv: `pip install yara-python==4.5.0`. The session canary catches this — if a tool fails, check whether it's a venv-shadowing issue before assuming it's uninstalled.
- **Cross-case index is plain Markdown — no database.** index.md lives at `{cases_dir}/index.md` (default `~/spectre-cases/index.md`). Rebuilt with `cross_case_index.py rebuild`, updated per-case with `cross_case_index.py update <name>`. Search with `cross_case_index.py search --ioc-type <type> --value <value>` or `cross_case_index.py search --search-all --value <value>`. All searches are exact-match, not substring. Pipe characters (`|`) in IOC values are escaped and round-trip correctly.
- **Episodic recall is deterministic (zero LLM tokens).** `cross_case_index.py search` is a pure lookup — no AI involved. Memory tool entries complement this with fuzzy recall.
- **Subagent templates are data, not agents.** `subagent_templates.py` produces dicts for `delegate_task()`. The lead agent calls `delegate_task()` with the produced dict. Templates do not dispatch subagents themselves.
- **Memory entries are compact (≤350 chars).** Save only critical cross-case facts: case ID, name, top findings, top MITRE, most distinctive IOC. Do not save full case summaries to memory — that belongs in index.md.
- **Adversarial reviewer MUST NOT invent findings.** The template enforces this in the context instructions. If a reviewer invents findings, strip them and log a violation.
- **Deep-dive analyst MUST include verbatim caveats.** The template enforces this with explicit instruction and the VERBATIM keyword. This is structural anti-hallucination, not optional.
- **JSON fixtures (case-000.events.json) are NOT real EVTX.** `evtx_dump.py` run via `tool_runner.run_tool()` will produce empty XML when given a JSON fixture. For fixture-based testing: write the fixture data directly to the output file, THEN create the tool handle via `run_tool()` for the audit trail. The `phase_runner.py` Phase 2 handles this automatically — see `references/phase-6-fixture-execution.md` for the pattern.
- **Real EVTX goes through the evtx module.** `modules/evtx/extract.py` runs `evtxexport` via `run_tool()` and `modules/evtx/normalize.py` parses its XML; only the `fixture-test` profile bypasses it (see the JSON-fixture pitfall above).
- **The grounding-probe explain pass (Mechanism A, formerly called "the adversarial explain pass") makes a real API call when a direct provider is configured.**

## Artifacts Produced Per Case

Every case directory contains these investigator-facing artifacts:

| File | Format | Purpose |
|---|---|---|
| `audit.jsonl` | JSONL + SHA-256 chain | Machine-readable tamper-evident audit trail |
| `execution.log` | Plain text | Human-readable command log — one line per tool invocation with timestamp, duration, row count, exit status, and full command. Auto-generated by `audit.py` on every `append()` call. Analysts read this; machines read audit.jsonl. |
| `manifest.yaml` | YAML | Case metadata, evidence refs, artifact profile, gate status |
| `raw_extract/_handles.json` | JSON | Tool execution handles with paths, execution_ids, row counts |
| `findings/F-{case_id}-{NNN}.yaml` | YAML | Per-finding structured output (deterministic core produces; AI explains). `F-SPECTRE-NNN.yaml` is the old format, kept only for backward-compatible globbing. |
| `reports/report.md` | Markdown | Narrative report with MITRE map, timeline, blind spots |
| `reports/iocs.csv` | CSV | Structured IOC export |
| `reports/blindspots.md` | Markdown | Standalone blind-spots matrix |

The `execution.log` is produced automatically — no extra code needed in any phase. Every `audit.py append()` call writes to both `audit.jsonl` and `execution.log`. The log format:

```
==============================================================================
Spectre Execution Log — Phase-by-Phase Transcript
Case: 017-cmdlog-test
Started: 2026-06-27 14:41:37
Each entry: YYYY-MM-DD HH:MM:SS [PX:SY] [step] command → result; stdout follows
(truncated at 200 lines / 20000 chars)
Full output files under raw_extract/ — see stdout_path references
==============================================================================

2026-06-27 14:41:38 [P2:S3] [pslist] vol -q -r json -s ... -f .../Challenge.raw windows.pslist.PsList → PASS 1164ms | 745 rows → 20260627_144137_pslist_memory_pslist.json
```

## Subprocess Sandbox for Native-Code Tools

Tools with native `.so` libraries (MemProcFS, and potentially others) can SIGSEGV on malformed input. A Python `try/except` cannot catch SIGSEGV — it kills the process. The pattern for integrating such tools:

1. **Never call the native API directly in the pipeline process.** Always invoke via `subprocess.run()`.
2. **Provide a CLI entry point in the extraction module** (`extract_foo.py --case-dir --evidence`).
3. **Check for negative exit codes** — `-11` = SIGSEGV, `-6` = SIGABRT. Return a failure handle, not a crash.
4. **Prefer the tool's own binary over its language bindings** where one exists. MemProcFS ships a FUSE binary as well as a Python API; Spectre drives the binary, so the crash lands in a process it already treats as failable. Reserve "default to the safe engine and require opt-in" for tools with no such entry point — memory defaults to `engine="both"` precisely because the sandbox makes the risky engine safe to run unattended.

Example from `memory/__init__.py`:
```python
def _run_mpfs_subprocess(case_dir, evidence_path):
    result = subprocess.run(
        [sys.executable, "extract_memprocfs.py", "--case-dir", case_dir, "--evidence", evidence_path],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode < 0:  # SIGSEGV/SIGABRT
        sig = -result.returncode
        return [_failure_handle(evidence_path, f"crashed ({sig_name})")]
    return json.loads(result.stdout)
```

## More Pitfalls

- **Grounding-probe cost.** The grounding probe injects a fabricated C2 network claim (`explain.ADVERSARIAL_POISON_IP`:`ADVERSARIAL_POISON_PORT`) into the prompt, then the deterministic validator strips any unsupported factual claims. This is NOT a mock — it costs real API tokens (typically 1200-1300 prompt / 800-900 completion). Budget ~2K tokens per finding for the grounding probe, plus one additional case-level call for the substantive review (Mechanism B).
- **Cross-case IOC search is deterministic.** `cross_case_index.py search` is a pure lookup. Use `from spectre.pipeline.cross_case_index import search_index` for programmatic access, or `cross_case_index.py search --search-all --value <value>` for CLI. All searches are exact-match, not substring.
- **emit_finding.py and explain.py accept optional `case_id` parameter.** Always pass it from the caller (e.g., `case_id=Path(case_dir).name`). Both default to the directory name if omitted, but explicit is safer.
- **Audit `exact_command` must be reproducible.** Do not record fictional CLI commands (e.g., `detect.py --rule ...` when detect.py has no __main__). Record the actual Python function call instead: `emit_finding.py emit(anchor, case_dir='...', fk='...') — Python function call, no CLI`. An examiner copy-pasting `exact_command` must get the same result.
- **entry_sha256 is a true SHA-256 hash** of the serialized JSON entry (with sort_keys=True for deterministic output). Verified in audit.py. The prev_hash chain links entries correctly — but hash-linkage validity does NOT imply attribution validity. Always verify case_id in audit rows matches the case directory name.
- **Manifest FK YAMLs key location.** `fk_yamls_loaded` is nested inside `gate_0`, not at the manifest top level. Use `manifest.get('artifacts', [])` for the artifact list in reports. `manifest['gate_0']['fk_yamls_loaded']` holds the count.
- **After any code fix, reset and run once.** audit.jsonl is append-only; findings/ overwrites. Re-running emit multiple times during debugging produces phantom references — audit claims N findings exist but only 1 YAML file remains on disk. `verify_chain()` checks hash linkage only, not audit↔disk consistency. After fixing pipeline code, always: `chmod -R u+w ~/spectre-cases/NNN-name/evidence && rm -rf ~/spectre-cases/NNN-name && echo "N-1" > ~/spectre-cases/.case-counter` then run all phases in order once.
- **Phase 7 approval goes through `spectre approve` only.** It writes the chained `approval` row (with the new content hash) before the YAML edit. A hand-written `approval` row plus a YAML edit fails `verify_full` (`finding_integrity`): the edited bytes match no hash-authority row. Any later YAML edit (e.g. flipping APPROVED→REJECTED by hand) fails the same check.
- **`previous_approval` is recorded by `spectre approve`:** `null` when the finding YAML had no `approval:` field, `DRAFT` only when `approval: DRAFT` was explicitly set — the row states what actually changed.
- **YAML↔audit agreement is enforced by content hash.** The approval row binds the approved file's sha256; `verify_full`'s `finding_integrity` re-hashes every finding against its latest authority row, so a later YAML edit is detected (same-user residual: a forged authority-shaped row — see `src/spectre/core/validators.py`).
- **Report figures must be verified against actual audit data.** Never report row counts, mis-attribution counts, or violation classifications from memory or from a prior report's assertion; run the checks against the actual audit.jsonl and report the measured values.
- **verify_chain() is necessary but NOT sufficient.** It validates the SHA-256 prev_hash chain but does NOT check: (a) whether finding_ids in audit rows match YAML files on disk, (b) whether every finding went through all safety-critical phases (especially Phase 5 adversarial review), (c) whether case_id in audit rows matches the case directory name. Run `audit.verify_full(case_dir)` for those (Check 2 audit↔disk, Check 3 case_id, Check 4 phase coverage).

- **Network cases and the canary.** A DEGRADED canary (e.g. volatility3 or yara missing) does not block a PCAP case as long as the pcap module can extract.

- **FK YAML caveats are artifact-specific — mismatched caveats are incorrect, not cosmetic.** A finding emitted with an FK YAML from the wrong artifact type (e.g. `evtx_4688.yaml` for a network finding) carries wrong `forensic_caveats` / `does_NOT_prove` fields and wrong report blind spots, which misleads examiners. Network FK YAMLs exist under `knowledge/artifacts/network/` (pcap, firewall, ids); use the one that matches the evidence.

- **Non-standard mount evidence registration.** Evidence on vmblock-fuse, NFS, CIFS, or other non-native mounts fails the standalone pre-check (`python3 -m spectre.pipeline.evidence_guard <evidence_path>`) because the mount's parent directory is writable, regardless of the file's own perms. That pre-check is optional; do not hand-copy evidence into the case to get around it. Register through Phase 0 instead: `spectre --name <case-name> --phase 0 --evidence <source_path>` (or `python3 -m spectre.pipeline.case_setup --name <case-name> --profile auto --evidence <source_path>`). `case_setup` hashes the SOURCE at ingest, copies it into `evidence/`, sets `chmod 444`, guards the copy with the parent check skipped, refuses on a hash mismatch, and writes chained `evidence_guard`/`evidence_register` audit rows; `evidence/` is then locked `0555`. Custody: run `sha256sum <source_path>` yourself before registration and confirm it equals `output_sha256` in the `evidence_register` row of `audit.jsonl`. If the mount is unstable, first `cp` to a `mktemp -d` dir, `chmod 444` the copy and `chmod 555` the dir, verify `sha256sum` on both, register the temp copy, and record the original source path in the case notes. Clean up afterwards with `chmod 755 "$tmpdir" && rm -rf "$tmpdir"`.

- **Quick-triage profile on non-Windows evidence produces fixture data, not real extraction.** When case_setup.py runs with `--profile quick-triage` and the evidence is PCAP (not Windows disk/memory), Phase 2 will extract fixture EVTX JSON (from the pipeline's internal test fixture), NOT from the actual evidence. The pipeline will then run Phases 3-6 on fixture data, producing a `F-SPECTRE-001` finding about `rundll32-from-temp` / `evil.dll` that has nothing to do with the real evidence. This is NOT an error to fix — it's the pipeline running correctly against the wrong data. Do NOT inject the real-evidence findings by hand (no `emit_from_handle()`, no hand-picked rule_id/IOCs, no hand-written YAML): findings come only from `spectre --phase 3` rule packs. Rebuild the case under a profile that extracts the real evidence (`--profile auto`, `network-only` or `pcap-focused`) and run the phases in order; anything no rule covers goes to the examiner as an investigative lead.

  **If the examiner points out the contamination:** Do NOT try to surgically fix the case (remove one finding, edit audit rows). Audit is append-only and findings are hash-chained. The correct remediation is: `chmod -R u+w ~/spectre-cases/NNN-name/evidence && rm -rf ~/spectre-cases/NNN-name`, reset the counter, and rebuild the entire case from scratch under a profile that extracts the real evidence. The rebuild should produce exactly one set of findings from the actual evidence — no fixture artifacts. This is the same pattern as "After any code fix, reset and run once" but triggered by an examiner quality catch rather than a code bug.

