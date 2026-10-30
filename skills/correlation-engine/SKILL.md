---
name: correlation-engine
description: "Cross-artifact correlation engine — corroboration scoring (v6 formula), finding evidence_refs check, cross-artifact clustering, temporal correlation."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, correlation, corroboration, validation, clustering]
metadata:
  hermes:
    tags: [forensic, spectre, correlation, corroboration, validation, clustering]
---

# Forensic Correlation Engine

Cross-artifact correlation, corroboration scoring, and the Phase 4 evidence_refs check. This is the mechanical confidence layer — no LLM involvement.

## When to use

- After detection produces anchors → score corroboration before explanation
- Checking that every finding carries evidence_refs and a source count
- Clustering findings by artifact type, time window, or IOC overlap

## Corroboration Scoring (v6 formula)

Source count → status + confidence (mechanical, not LLM-asserted):

| Sources | Status    | Confidence |
|---------|-----------|------------|
| 0       | DROPPED   | 0.00       |
| 1       | INFERRED  | 0.50       |
| 2       | CONFIRMED | 0.75       |
| 3+      | CONFIRMED | 1.00       |

Implementation:
```python
SOURCE_TO_STATUS = {
    0: ("DROPPED", 0.0),
    1: ("INFERRED", 0.50),
    2: ("CONFIRMED", 0.75),
    3: ("CONFIRMED", 1.00),  # capped at 3
}

def score_corroboration(sources: int) -> tuple[str, float]:
    clamped = min(sources, 3)
    return SOURCE_TO_STATUS[clamped]
```

**Per-source confidence weights are DOCUMENTED but INACTIVE in v1.** Source-count is the only active scoring dimension. Per-source weights (evtx=1.00, amcache=0.75, lnk=0.60, mft=0.50) are informational only.

## What counts as a source

The formula above turns a source *count* into a confidence number, so what
qualifies as a source is the whole load-bearing question. Two rules decide it.

### 1. Observation, not verdict

> **A second source must contribute independently-derived *observations* that a
> Spectre predicate then judges. A source that contributes a *verdict* is not a
> second source** — it is one judgment restated, and counting it launders
> another tool's heuristics into Spectre's confidence score without any Spectre
> rule seeing the underlying facts.

Two consequences, both live in the code:

- **MemProcFS's FindEvil does not corroborate `memory_malfind`.** Its CSV is
  `PID,ProcessName,Type,Address,Description` — a classification, with no
  protection column and no byte preview, while the rule requires both.
  "Confirming" it would mean synthesizing the facts nobody observed. The VAD map
  (`pid/<n>/memmap/vad.txt`) is used instead: it is malfind's criterion in raw
  form, so a Spectre predicate does the judging.
- **volatility3 + MemProcFS *do* count as two sources; zeek + tcpdump do not**
  (`correlation/__init__.py`, with a regression test in
  `tests/test_correlation/test_corroboration.py`). Not because of "different
  codebases" — because the memory engines observe independently and
  demonstrably disagree, whereas zeek and tcpdump re-render one libpcap decode.

### 2. Engine-invariant identity

`corroborate()` groups on `(rule_id, dedup_key or title)`, so two engines that
observed the same thing only score as 2 if their keys match exactly:

> A `dedup_key` is the canonical identity of the entity or claim, computed only
> from engine-invariant facts. It must never embed an engine-derived aggregate
> (an instance count), a value joined from within one handle's row set (a parent
> image name), a formatted sentence, or a raw tool-specific rendering of an
> address, path, registry key, or timestamp.

Canonicalization belongs in `normalize.py`: **extractors transcribe verbatim**
(so the audited raw artifact stays a faithful rendering of what the tool
emitted), normalize canonicalizes, rules read canonical fields only. Keep
`<field>_raw` for provenance; unrecognized forms pass through verbatim, never
guessed. Everything excluded from the key still appears in `title` / `summary` /
`event.data`.

**Never widen a key to force a match.** Coarsening a key until two anchors
collide manufactures corroboration — the number goes up while the evidence for
it does not.

## Finding Validation (what Phase 4 enforces)

`run_phase_4` (`pipeline/phase_runner.py`) does exactly this, and nothing more:

1. `correlation.purge_dropped_findings(case_dir)` deletes every finding YAML whose
   `status` is `DROPPED`, whose `corroboration.sources` is 0, or that has no
   `evidence_refs`.
2. `audit.verify_chain(case_dir)` (hash linkage only).
3. For each remaining finding: a finding with an empty `evidence_refs` list is recorded
   `DROPPED: 0 source findings` / `passed: False`.
4. Every `evidence_refs[].execution_id` must equal the `entry_sha256` of an
   `actor: deterministic-core`, `action: tool_exec` row in this case's `audit.jsonl`
   (`core/validators.py:resolvable_execution_ids` / `unresolved_evidence_refs`). A ref with
   no string `execution_id` (`<missing>`), a malformed ref (`<unparseable>`), an id of any
   other row (e.g. `finding_create`), or any ref while the chain fails verification is
   unresolved. Such a finding is recorded `UNRESOLVED evidence_refs: …` / `passed: False`
   and, when the chain verifies, gets one `evidence_ref_unresolved` row (`phase_step:
   S4-evidence-refs`, `finding_id`, `params.unresolved_execution_ids`). The YAML is not
   touched.
5. Otherwise `passed` is `corroboration.sources >= 1`.

Only passed-check findings reach clustering. `manifest["gate_4"].passed` = chain valid AND
every finding passed.

The check proves each cited id is a real extraction row in the chain; it does not prove
that extraction produced the specific record the finding describes.

Checked elsewhere, not in Phase 4:
- **MITRE**: set at emit to the rule's `mitre-map.yaml` `allowed` list ∩ the anchor's
  candidates (`emit_finding._get_allowed_mitre`); the model cannot change it
  (`core/validators.py:allowed_mitre_for_finding()`, explain Validator 1).
- **Status/confidence**: computed at emit from the source count (`emit_finding.py`);
  Phase 4 does not recompute them.
- **FK envelope**: Phase 4 does not check it. A finding whose artifact has no FK YAML is
  caveatless — flag it to the KB maintainer.

## Cross-Artifact Clustering

`correlation.clustering.cluster_findings(findings, subject_ips, window_s=None)` runs in Phase 4
and writes `manifest["correlation_clusters"]`; it never modifies findings or their source
counts. It returns two cluster lists:

- `ioc_overlap`: findings sharing a non-benign IOC entity (subject IPs excluded) or a process
  instance (`correlation/process.py`: pid + image, host/start-time scoped)
- `temporal`: findings whose timestamps fall within `window_s` seconds (default 60,
  `SPECTRE_TEMPORAL_WINDOW_S`)

Clustering is narrative context, not corroboration: only `corroborate()` (same `rule_id` +
`dedup_key`, independent sources) changes a source count.

## Output

Per finding, Phase 4 records `{finding_id, sources, status, confidence, evidence_refs,
source_count_ok, passed}` in `manifest["correlation"]`; the gate summary is
`manifest["gate_4"]` and clusters are `manifest["correlation_clusters"]`.

## Audit

Phase 4 appends one `note` row (`tool: correlation-clustering`, `phase_step: S4-cluster`) with
the cluster counts, plus one `evidence_ref_unresolved` row per finding with an unresolved
`execution_id`. Corroboration is recorded on each finding at emit time
(`corroboration.sources` and source labels).

## Pitfalls

- **0 sources = DROPPED, not "low confidence."** This is a hard rule. Fabricated findings are dropped, not labeled.
- **Source-count formula is mechanical.** Never let the LLM assert confidence. It must match the formula exactly.
- **Per-source weights are inactive in v1.** They exist in FK YAML but do not affect scoring yet. This will change in a future phase.
- **Temporal clustering ±60s is a heuristic.** Adjust window based on case context (long-running attacks may need 300s).
- **execution_id resolution proves the extraction, not the record.** Phase 4 resolves each ref to a chained `tool_exec` row; it does not tie the finding to a line in that row's output.
- **MITRE is fixed at emit.** The model cannot change a finding's `mitre_attack`; explain always persists the deterministic value.
