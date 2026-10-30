"""
coverage.py — what the examination did NOT look at, as chained facts.

Spec: the module-selection design spec §3.7, §5.5.

The defect this closes: coverage was not chain-protected. `canary_status` and
`gate_0.passed` were written by `log_command`, which touches `execution.log`
only and never `audit.jsonl` (shell_log.py) — mutable manifest fields with no
hash behind them. And `verify_full()`'s checks inspected no triage or coverage
data at all. So a case could be regenerated with its coverage disclosures
quietly dropped and still PASS every integrity check: a **vacuous PASS**.

The fix has three parts, and this module is the shared middle of it:

  1. Phase 0 and Phase 2 append `coverage_gap` rows through `audit.append()`,
     so the gaps are inside the SHA-256 chain.
  2. Phase 6 records, on its `S3-merge-report` row, which gaps the report
     discloses — and `report_integrity` already binds that row's hash to the
     bytes on disk.
  3. `verify_full()`'s `coverage_disclosure` check asserts every chained gap
     appears in that list, at no smaller a count. Regenerating a report with a
     disclosure removed then fails closed.

**One gap model, two consumers.** `gaps_from_manifest()` is the single
derivation, used both to emit the rows and to render the report's Forensic
Blind Spots section. They agree by construction rather than by discipline —
tests/test_pipeline/test_coverage_chain.py asserts every gap the model produces
is actually named in the rendered prose, so the audit row can never claim a
disclosure the reader cannot find.

Deliberately NOT a textual check. `audit.py` grepping report prose would
couple the integrity layer to report wording, and the first reword would
either break verification or silently disarm it.
"""

from __future__ import annotations

import os
from collections import defaultdict

# Triage statuses that mean "this evidence item was never analyzed". A status
# absent from here is treated as a gap anyway (see gaps_from_manifest) — the
# tuple gates elsewhere in the pipeline silently drop unknown statuses, and
# doing that HERE would mean a new status quietly stops being disclosed.
NOT_EXAMINED = ("UNRECOGNIZED", "EXTRACTOR_PENDING", "MISSING")

PRIMARY = "primary"


def gap_key(status: str, artifact_type: str, parent: str) -> str:
    """Stable identity for a CATEGORY of gap.

    Count is deliberately excluded. Phase 2 can legitimately carve more
    artifacts out of an image after Phase 0 has already charged a gap, so a
    count-bearing key would make honest growth look like a missing disclosure.
    The count travels alongside as row content, and the verifier requires the
    disclosed count to be >= the largest count the chain charged — growth
    passes, shrinkage fails.
    """
    return f"{status or 'UNKNOWN'}|{artifact_type or 'unknown'}|{parent or PRIMARY}"


def _add(bucket: dict, status: str, artifact: str, parent: str,
         name: str, tool: str) -> None:
    key = gap_key(status, artifact, parent)
    entry = bucket.setdefault(key, {
        "key": key, "status": status or "UNKNOWN",
        "artifact_type": artifact or "unknown", "parent": parent or PRIMARY,
        "count": 0, "items": [], "tool": tool or "",
    })
    entry["count"] += 1
    if len(entry["items"]) < 25:  # bounded: 200 carved files must not make a
        entry["items"].append(name)  # 200-name audit row
    if tool and not entry["tool"]:
        entry["tool"] = tool


def gaps_from_manifest(manifest: dict) -> list[dict]:
    """Every category of unexamined evidence this manifest records.

    Three sources, matching where the pipeline actually puts the information:

      - `manifest["triage"]` — primary evidence, triaged in Phase 0.
      - `manifest["extraction"]["results"]` with `skipped` — recognized-but-not
        extracted, including carved artifacts re-triaged in Phase 2 (which
        never reach manifest["triage"]).
      - the same results with `error` — extraction was attempted and failed, so
        the contents are exactly as unverified as if it had been skipped. The
        honest direction, matching _coverage_counts.

    Returned sorted by key so row order and report order are deterministic.
    """
    bucket: dict[str, dict] = {}

    for path, rec in (manifest.get("triage") or {}).items():
        rec = rec or {}
        status = rec.get("status") or "UNKNOWN"
        if status == "RECOGNIZED":
            continue
        _add(bucket, status, rec.get("artifact_type") or "unknown", PRIMARY,
             os.path.basename(path), rec.get("tool") or "")

    results = (manifest.get("extraction") or {}).get("results") or {}
    for path, rec in results.items():
        if not isinstance(rec, dict):
            continue
        parent = rec.get("derived_from") or PRIMARY
        if parent != PRIMARY:
            parent = os.path.basename(parent)
        if rec.get("skipped"):
            _add(bucket, str(rec["skipped"]),
                 rec.get("artifact_type") or "unknown", parent,
                 os.path.basename(path), rec.get("tool") or "")
        elif rec.get("error"):
            _add(bucket, "EXTRACTION_ERROR",
                 rec.get("artifact_type") or "unknown", parent,
                 os.path.basename(path), rec.get("tool") or "")
        elif rec.get("extraction_status") == "EMPTY":
            # W4 review MED-3: the tool ran but parsed zero records from
            # non-empty evidence — as unexamined as a failure.
            _add(bucket, "EXTRACTION_EMPTY",
                 rec.get("artifact_type") or "unknown", parent,
                 os.path.basename(path), rec.get("tool") or "")

    return [bucket[k] for k in sorted(bucket)]


def disclosed_from_manifest(manifest: dict) -> list[dict]:
    """The compact form recorded on the S3-merge-report row.

    Only key and count: the row is a disclosure receipt, not a second copy of
    the manifest, and it has to stay small enough to sit in an audit row.
    """
    return [{"key": g["key"], "count": g["count"]}
            for g in gaps_from_manifest(manifest)]


def append_gap_rows(case_dir: str, case_id: str, phase: int, phase_step: str,
                    manifest: dict) -> list[dict]:
    """Append one chained `coverage_gap` row per gap CATEGORY.

    Aggregated by (status, artifact_type, parent) on purpose: a disk image that
    carves 200 EVTX files none of which can be extracted must produce ONE row,
    not 200. Each `audit.append()` also triggers a best-effort journald write,
    so 200 rows would be 200 external writes for a single fact.

    Returns the gaps it charged, so a caller can report them.
    """
    from spectre.pipeline.audit import append as audit_append

    gaps = gaps_from_manifest(manifest)
    for gap in gaps:
        audit_append(case_dir, {
            "actor": "deterministic-core",
            "action": "coverage_gap",
            "tool": "coverage.gaps_from_manifest",
            "tool_version": "1.0",
            "exact_command": f"coverage_gap {gap['key']}",
            "params": {
                "key": gap["key"],
                "status": gap["status"],
                "artifact_type": gap["artifact_type"],
                "parent": gap["parent"],
                "count": gap["count"],
                "example_items": gap["items"],
                "missing_tool": gap["tool"],
            },
            "case_id": case_id,
            "output_path": "",
            "output_sha256": "",
            "output_format": "json",
            "output_line_count": 0,
            "output_size_bytes": 0,
            "result": "not_examined",
            "exit_code": 0,
            "duration_ms": 0,
            "stderr": "",
            "finding_id": None,
            "phase": phase,
            "phase_step": phase_step,
        })
    return gaps


def chained_gaps(entries: list[dict]) -> dict[str, int]:
    """{gap key: largest count charged} across every `coverage_gap` row.

    Largest, not latest: Phase 0 and Phase 2 both charge, a resumed phase can
    charge again, and the report must cover the worst of what the chain says.
    """
    worst: dict[str, int] = defaultdict(int)
    for e in entries:
        if e.get("action") != "coverage_gap":
            continue
        params = e.get("params") or {}
        key = params.get("key")
        if not key:
            continue
        try:
            count = int(params.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        worst[key] = max(worst[key], count)
    return dict(worst)
