---
name: report-generator
description: "Generate forensic reports — MD narrative, HTML export, MITRE ATT&CK map, timeline visualization, blind-spots matrix, IOC table. Explain layer guardrails enforced."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, report, narrative, findings]
metadata:
  hermes:
    tags: [forensic, spectre, report, narrative, findings]
---

# Forensic Report Generator

Generate investigation reports from deterministic findings. The LLM explains — it does not create findings. Guardrails enforce: caveats from FK YAML only (verbatim), MITRE from mitre-map only, narrative must cite finding_id.

## When to use

- After correlation phase completes — all findings scored and validated
- Generating the final case report (Phase 6: Synthesis + Report)
- Exporting IOCs for sharing/blocking
- Creating blind-spots matrix (what couldn't be verified)

## Required inputs

- `case_dir`: everything else is loaded from disk — verified findings
  (`validators.load_verified_findings`), `manifest.yaml` (profile, evidence, coverage) and
  `audit.jsonl`. Host-mode callers pass only `case_dir` and their JSON (see below).

## Report sections

`report.md` is rendered deterministically: `_merge_report_md()` composes one builder per
section from `src/spectre/pipeline/report_sections/`, and its call order is the report order —
header, Executive Summary (confidence assessment, System Profile, key indicators), draft notice,
1. Threat Narrative, detailed findings, 2. MITRE ATT&CK Map, 3. Timeline, Correlated Findings,
4. Forensic Blind Spots (coverage gaps, per-artifact caveats), 5. IOC Export, 6. Methodology,
Phase 5 disposition, Evidence Intake, 7. Verdict, Recommended Actions, Appendix: Finding Index.
Finding IDs are `F-{case_id}-{NNN}`. The LLM supplies only the narrative fields; tables, counts,
IOCs and caveats come from deterministic data.

## Explain Layer Guardrails

The LLM narrative MUST observe these constraints. All 6 items are enforced by
`report_synthesize._validate_report()` (11 validators, including Validator 5 for
item 1; the code lives in `src/spectre/pipeline/report_validators.py` and is re-exported by
`report_synthesize`, which is where it is called from) — but only for an in-process **API provider** (`deepseek`/`anthropic`/`openai`/`local`).
See "Host mode: no in-process prevention" below for the `host` provider, where this enforcement
does not apply unless you deliberately route through it.

1. **Caveat verbatim rule**: Every forensic caveat must be verbatim from FK YAML `does_NOT_prove`.
   No paraphrasing. Enforced for report-narrative text by `_validate_report()`'s Validator 5, and
   for per-finding *descriptions* by `core/explain.py`'s `_validate_output()`. Both seams are live.
2. **MITRE-source rule**: MITRE technique MUST be in allowed set from mitre-map.yaml. Free-typed IDs rejected.
3. **Citation rule**: Every factual claim must cite a finding_id (e.g., "as shown in F-SPECTRE-001").
4. **No-invention rule**: If the LLM adds a claim not in any finding (e.g., "the attacker used C2 server at 10.0.0.99"), it is stripped and logged as an adversarial claim.
5. **Confidence immutability**: The LLM may NOT adjust confidence. What the formula produced is final.
6. **Empty Data Protocol**: Never say "clean" or "no malware found." Use "UNVERIFIED" for evidence gaps.

### Host mode: no in-process prevention

In host mode (`SPECTRE_LLM_PROVIDER=host`, the default), `synthesize_report()` returns a
deferred prompt+schema bundle instead of a finished report — nothing calls the validators for
you. **This is a routing convention, not a technical control.** You (the orchestrating agent)
hold a file-write tool; nothing stops you from writing prose straight to `reports/report.md`,
skipping every guardrail above. The only things standing between that and an unvalidated report
are: (a) you following this routing instruction, and (b) `audit.verify_full()`'s
`narrative_grounding` check (W3-4). When the latest `S3-merge-report` row's `params.llm_used` OR
`manifest["report"]["ai_narrative"]` is true, it requires (1) `report.md` on disk to hash to that
latest S3 row's `output_sha256`, and (2) an `S2-validate-report` row chained AFTER the previous
`S3-merge-report` row — i.e. validation in the same generation as the current report. A stale S2
row from an earlier run no longer covers a rewritten report, and clearing the manifest flag no
longer skips the check. It remains a drift detector: an agent that deliberately forges a fresh S2
row plus a matching S3 row still defeats it.

To get real validation, pass the case directory and your JSON to
`report_synthesize.ingest_host_report(case_dir, host_json)` so it runs through the same validators
as a direct API call. It takes **no** findings or manifest from you: it loads
`case_dir/findings/F-*.yaml` and `case_dir/manifest.yaml` from disk, trusts only findings
registered by a deterministic `finding_create` audit row whose bytes match their latest
hash-authority row (raising `FindingIntegrityError` on a mismatch), excludes any unregistered
finding file, and validates MITRE against the case's own findings'
per-rule techniques. The old `ingest_host_report(findings, manifest, case_dir, host_json)` form
still works but ignores the passed lists (DeprecationWarning).

**`ingest_host_report()` validates but does not persist the report — it returns a validated
dict and does not write `report.md`.** This differs from the `explain` seam:
`explain.ingest_host_output(finding_path, fk_yaml_path, mitre_map_path, case_dir, host_json)`
validates *and* persists the finding YAML (description, MITRE, caveats) — it never writes
`report.md`. Its `fk_yaml_path`/`mitre_map_path` arguments are ignored: the MITRE map comes from
`config.MITRE_MAP_PATH` and the FK YAML is routed from the finding's own artifact type inside
`config.FK_DIRS`; it refuses to persist a finding with no `finding_create` registration; and the
persisted `mitre_attack` is always the deterministic value (the model cannot add, drop or
reorder techniques — disagreement is logged as a violation). The report
seam deliberately splits the two steps, so getting the validated dict into `reports/report.md`
is your responsibility as the caller: merge it with `report_synthesize._merge_report_md()` (the
same helper `phase_runner.py`'s automated Phase 6 run uses) and write the result yourself — never
write the raw, unvalidated JSON directly to `reports/report.md`. Note also that if you are
driving Phase 6 via `phase_runner.py --phase 6` (the automated path), `report.md` is already
written deterministically before this bundle ever reaches you; this ingest path matters for the
manual/targeted synthesis flow where you call `synthesize_report()` yourself.

### The full host flow — validate, merge, write, **audit**

All four steps are mandatory. Skipping the audit row leaves `report.md` on disk with no
recorded sha256, and `audit.verify_full()`'s `report_integrity` check reports
`passed == False`. Writing the file is not the last step.

```python
import hashlib, yaml
from pathlib import Path
from spectre.config import MITRE_MAP_PATH
from spectre.pipeline.report_synthesize import ingest_host_report, _merge_report_md
from spectre.pipeline.audit import append as audit_append

from spectre.core.validators import load_verified_findings

# 1. Validate your JSON through the same guardrails as a direct API call.
#    Findings + manifest are loaded (and hash-verified) from disk inside.
result = ingest_host_report(case_dir, host_json)

# Load the SAME verified findings and on-disk manifest for the merge.
findings, _unregistered = load_verified_findings(case_dir)
manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text()) or {}

# 2. Merge the validated narrative with the deterministic tables.
#    _merge_report_md(llm_output, findings, manifest, case_dir, violation_log, mitre_map) -> str
#    It takes SIX positional arguments and loads none of them for you.
mitre_map = {}
if MITRE_MAP_PATH.exists():
    mitre_map = yaml.safe_load(MITRE_MAP_PATH.read_text()) or {}
report_md = _merge_report_md(
    result,             # llm_output  — the dict ingest_host_report() returned
    findings,           # findings    — the verified on-disk findings loaded above
    manifest,           # manifest    — same manifest (supplies case_id, case_name, profile)
    case_dir,           # case_dir    — case directory path, as a str
    result["violations"],  # violation_log — validator violations, rendered in the report
    mitre_map,          # mitre_map   — parsed knowledge/mitre-map.yaml (load it yourself)
)

# 3. Write it.
report_path = Path(case_dir) / "reports" / "report.md"
report_path.write_text(report_md)

# 4. Audit the write — MANDATORY. Mirrors phase_runner.py's S3-merge-report row.
audit_append(case_dir, {
    "actor": "spectre-lead",
    "action": "note",
    "tool": "report_synthesize._merge_report_md",
    "tool_version": "0.1",
    "exact_command": "report_synthesize._merge_report_md() — deterministic markdown merge",
    "params": {
        "findings_count": len(findings),
        "llm_used": True,
        "skip_ai": False,
        # MANDATORY when the chain holds any coverage_gap row. verify_full()'s
        # check 9 (coverage_disclosure) FAILS CLOSED if this receipt is absent
        # or covers fewer gaps than Phase 0/2 charged. Do not hand-build it —
        # derive it, so the receipt cannot claim a disclosure your prose omits:
        "disclosed_coverage_gaps":
            __import__("spectre.pipeline.coverage", fromlist=["x"])
            .disclosed_from_manifest(manifest),
    },
    "case_id": manifest.get("case_id", ""),
    "output_path": str(report_path),                                  # must end in report.md
    "output_sha256": hashlib.sha256(report_md.encode()).hexdigest(),  # hash of what you wrote
    "result": "success",
    "exit_code": 0,
    "duration_ms": 0,
    "token_usage": result.get("token_usage", {}),
    "phase": 6,
    "phase_step": "S3-merge-report",                                  # check 6 filters on this
})
```

`output_path`, `output_sha256`, `phase`, and `phase_step` are the four fields
`verify_full()`'s check 6 reads. `phase_step` must be exactly `"S3-merge-report"` — check 6
scopes itself to those rows, so a row with any other `phase_step` will not register your write
and the check will report "case has not reached Phase 6". If you re-write `report.md`, append
a new row; the check compares against the latest one. If that rewrite carries AI narrative, run
`ingest_host_report()` again first — `narrative_grounding` needs an `S2-validate-report` row
between the previous S3 row and the new one. Relative `output_path` values (e.g.
`reports/report.md`) are accepted and resolved against the case directory.

`params["disclosed_coverage_gaps"]` is read by check 9 (`coverage_disclosure`). Phase 0 and
Phase 2 append chained `coverage_gap` rows, and check 9 asserts this receipt covers every one of
them at no smaller a count, so a report regenerated with its coverage disclosures dropped fails.
Three consequences for you:

- **Omitting the field fails the case.** A missing receipt is indistinguishable from a stripped
  one, so it is treated the same way. This is one of the few places the host path fails closed.
- **Appending a fresh row cannot launder it.** Check 9 reads the receipt on the latest row, so a
  new row with a shorter receipt is exactly what it catches.
- **Derive it, never hand-write it.** `coverage.disclosed_from_manifest()` and the report's
  `_intake_blindspot_lines()` come from the same gap model, so a derived receipt cannot claim a
  disclosure the reader will not find in section 4. A hand-written one can, and that is a false
  statement about the evidence in a chained row.

`_merge_report_md` (Phase 6) is the sole writer of `report.md`; re-running `--phase 5` after
Phase 6 does not touch it.

## Output paths

```
case_dir/reports/report.md      # Primary markdown report
case_dir/reports/report.html    # HTML export (optional)
case_dir/reports/iocs.csv       # IOC export
case_dir/reports/blindspots.md  # Blind spots matrix (standalone)
```

## Pitfalls

- **Never generate report before correlation completes.** Ungated findings in a report is premature.
- **Blind spots are mandatory.** Every report MUST include what couldn't be verified.
- **Caveats from FK YAML only.** If FK YAML is missing, findings get no caveats — flag to KB maintainer.
- **HTML is secondary.** MD report is the authoritative format. HTML is convenience only.
- **Report cites execution_ids, not file paths.** Evidence references must resolve to audit.jsonl rows, not raw file paths.
- **DROPPED findings do NOT appear in reports.** They are auto-purged at the provenance gate.
- **Long reports:** with many findings, detail CONFIRMED ones and summarize INFERRED ones.
