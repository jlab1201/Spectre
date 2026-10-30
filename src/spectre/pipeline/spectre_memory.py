#!/usr/bin/env python3
"""
spectre-memory — Unified memory forensics launcher.

Runs volatility3, MemProcFS, or both against a memory dump, producing
structured output handles and, for `--engine both`, a coarse per-artifact
row-count comparison.

That comparison is an extraction-health signal only. Claim-level agreement
between the two engines is scored in `correlation.corroborate()`, on anchors a
Spectre rule produced — not here. See `_row_count_deltas`.

Usage:
    spectre-memory --evidence dump.raw --case ~/cases/015-test
    spectre-memory --evidence dump.raw --engine vol        # volatility3 only
    spectre-memory --evidence dump.raw --engine memprocfs  # MemProcFS only
    spectre-memory --evidence dump.raw --engine both       # both (default, runs both engines)

Output:
    JSON summary printed to stdout.
    Full handles written to case_dir/raw_extract/_handles.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from spectre.pipeline.audit import append as audit_append

# Row-count divergence above this is worth a human look. It is a triage
# threshold for extraction health, not a confidence input — nothing downstream
# reads it.
_DELTA_TOLERANCE_PCT = 5


def main():
    parser = argparse.ArgumentParser(
        prog="spectre-memory",
        description="Unified memory forensics — volatility3 + MemProcFS",
        epilog="""
Examples:
  %(prog)s --evidence /cases/dump.raw --case ~/cases/015-test
  %(prog)s --evidence dump.mem --engine memprocfs --case ~/cases/016-test
  %(prog)s --evidence dump.vmem --engine vol --case ~/cases/017-test

Engine selection:
  vol         volatility3 only (fast, well-tested)
  memprocfs   MemProcFS only (FUSE mount; filesystem metaphor)
  both        Both engines + a row-count comparison (default)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    required = parser.add_argument_group("required")
    required.add_argument("--evidence", required=True,
                          help="Path to memory dump (.raw/.mem/.vmem/.dmp)")
    required.add_argument("--case", required=True,
                          help="Case directory (e.g. ~/cases/015-test)")

    parser.add_argument("--engine", choices=["vol", "memprocfs", "both"],
                        default=None,
                        help="Memory analysis engine (default: SPECTRE_MEMORY_ENGINE, "
                             "else both — two engines over one image lets matching "
                             "claims corroborate; memprocfs runs in a subprocess "
                             "sandbox)")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON only (no human-readable summary)")
    parser.add_argument("--no-audit", action="store_true",
                        help="Skip audit logging")

    args = parser.parse_args()

    # Resolve here so the summary, the row-count gate and the extraction all
    # name the same engine -- `--engine` unset defers to SPECTRE_MEMORY_ENGINE.
    from spectre.modules.memory import _resolve_engine
    args.engine = _resolve_engine(args.engine)

    case_dir = os.path.expanduser(args.case)
    evidence_path = os.path.expanduser(args.evidence)

    # Validate inputs
    if not os.path.isdir(case_dir):
        print(f"ERROR: Case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(evidence_path):
        print(f"ERROR: Evidence file not found: {evidence_path}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print("Spectre Memory Analysis", file=sys.stderr)
        print(f"  Engine:    {args.engine}", file=sys.stderr)
        print(f"  Evidence:  {evidence_path}", file=sys.stderr)
        print(f"  Case:      {case_dir}", file=sys.stderr)
        print(file=sys.stderr)

    # Run extraction. This MUST be the package-level dispatcher, not
    # extract.py's volatility-only extract() -- the latter takes
    # (case_dir, evidence_path) and raises TypeError on `engine`, which
    # made every spectre-memory invocation fail regardless of --engine.
    from spectre.modules.memory import extract as memory_extract

    start = datetime.now(timezone.utc)
    handles = memory_extract(case_dir, evidence_path, engine=args.engine)
    elapsed = (datetime.now(timezone.utc) - start).total_seconds()

    # Audit each handle
    if not args.no_audit:
        for h in handles:
            audit_entry = {
                "actor": "deterministic-core",
                "action": "extraction",
                "tool": h.get("tool", "unknown"),
                "tool_version": h.get("tool_version", ""),
                "exact_command": h.get("exact_command", ""),
                "params": h.get("params", {}),
                "case_id": Path(case_dir).name,
                "output_path": h.get("path", ""),
                "output_sha256": h.get("output_sha256", ""),
                "output_format": h.get("output_format", "json") if h.get("is_json") else "text",
                "output_line_count": h.get("line_count", 0),
                "output_size_bytes": h.get("size_bytes", 0),
                "result": h.get("result", "unknown"),
                "exit_code": h.get("exit_code", 0),
                "duration_ms": int(elapsed * 1000 / max(len(handles), 1)),
                "stderr": h.get("stderr", ""),
                "finding_id": None,
            }
            audit_append(case_dir, audit_entry)

    # Coarse extraction-health signal (when both engines ran). Not corroboration
    # — see _row_count_deltas.
    row_counts = _row_count_deltas(handles) if args.engine == "both" else None

    # Build summary
    results = {
        "engine": args.engine,
        "evidence": evidence_path,
        "case_dir": case_dir,
        "handles": len(handles),
        "success": sum(1 for h in handles if h.get("result") == "success"),
        "failure": sum(1 for h in handles if h.get("result") != "success"),
        "elapsed_s": round(elapsed, 2),
        "engines_used": _engines_used(handles),
        "row_count_comparison": row_counts,
        "handles_list": [
            {
                "artifact_type": h.get("artifact_type"),
                "engine": h.get("engine", "?"),
                "result": h.get("result"),
                "rows": h.get("line_count", 0),
                "path": h.get("path", ""),
            }
            for h in handles
        ],
    }

    if not args.json:
        # Human-readable summary
        print("Results:", file=sys.stderr)
        print(f"  Handles:   {results['handles']} ({results['success']} ok, "
              f"{results['failure']} failed)", file=sys.stderr)
        print(f"  Elapsed:   {results['elapsed_s']}s", file=sys.stderr)
        print(f"  Engines:   {', '.join(results['engines_used'])}", file=sys.stderr)
        if row_counts:
            print(f"  Row counts: {row_counts['row_counts']} "
                  f"(max delta {row_counts['max_delta_pct']}%, tolerance "
                  f"{row_counts['tolerance_pct']}%)", file=sys.stderr)
        print(file=sys.stderr)

        for h in handles:
            tag = "OK" if h.get("result") == "success" else "FAIL"
            eng = h.get("engine", "?")
            art = h.get("artifact_type", "?")
            rows = h.get("line_count", 0)
            print(f"  [{tag}] {eng:12s} {art:20s} {rows:>5d} rows", file=sys.stderr)

    print(json.dumps(results, indent=2))
    sys.exit(0 if results["failure"] == 0 else 1)


def _engines_used(handles: list[dict]) -> list[str]:
    """Distinct engine names across `handles`, sorted.

    `list(set(...))` here would order-jitter across PYTHONHASHSEED values
    for the same handles -- same defect class as R3-01/R3-02 (see
    tests/test_pipeline/test_determinism.py). `sorted()` makes the
    `engines_used` field in the CLI's JSON output byte-identical run to run
    for identical extraction results.
    """
    return sorted({h.get("engine", "?") for h in handles})


def _row_count_deltas(handles: list[dict]) -> dict | None:
    """Compare vol vs memprocfs ROW COUNTS for the same artifact types.

    This is a coarse extraction-health signal, not corroboration. It judges no
    claim: 53 processes on each side does not say they are the same 53, and the
    engines can agree on a total while disagreeing on every entry. Claim-level
    agreement happens in `correlation.corroborate()`, on anchors a Spectre
    predicate produced.

    So this deliberately does NOT return `CONFIRMED`/`FLAGGED`. Those words are
    a finding's corroboration status; reusing them here would give one term two
    meanings in one tool's output, with the weaker one wearing the more
    confident label.
    """
    by_type = {}
    for h in handles:
        if h.get("result") != "success":
            continue
        atype = h.get("artifact_type", "")
        eng = h.get("engine", "")
        key = f"{atype}:{eng}"
        by_type[key] = h

    deltas = []
    for atype in set(h.get("artifact_type", "") for h in handles):
        vol_h = by_type.get(f"{atype}:volatility3")
        mpfs_h = by_type.get(f"{atype}:memprocfs")
        if vol_h and mpfs_h:
            vol_rows = vol_h.get("line_count", 0)
            mpfs_rows = mpfs_h.get("line_count", 0)
            if vol_rows > 0:
                delta = abs(vol_rows - mpfs_rows) / vol_rows * 100
                deltas.append({
                    "artifact_type": atype,
                    "vol_rows": vol_rows,
                    "memprocfs_rows": mpfs_rows,
                    "delta_pct": round(delta, 1),
                })

    if not deltas:
        return None

    max_delta = max(d["delta_pct"] for d in deltas)
    return {
        "row_counts": "agree" if max_delta <= _DELTA_TOLERANCE_PCT else "diverge",
        "tolerance_pct": _DELTA_TOLERANCE_PCT,
        "max_delta_pct": max_delta,
        "deltas": deltas,
    }


if __name__ == "__main__":
    main()
