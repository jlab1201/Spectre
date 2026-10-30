"""
recognize.py — file-type recognition / triage for dropped evidence.

Given one or more evidence file paths, inspect each (extension +
libmagic description + optional per-module sniff) and decide which
analyzer module should handle it. Produces a triage table that Phase 2
uses to route each file to the correct extractor.

Nothing here ever fabricates data: a file no module claims is reported
as UNRECOGNIZED; a recognized type whose tool is unavailable is reported
EXTRACTOR_PENDING. Neither produces findings.

Usage:
    python3 recognize.py <file> [<file> ...]
    # or import triage([...]) -> dict
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from spectre.modules import registry

try:
    import magic  # python-magic (libmagic)
    _HAVE_MAGIC = True
except Exception:  # pragma: no cover - magic is installed in this env
    _HAVE_MAGIC = False


def _magic_desc(path: Path) -> str:
    if _HAVE_MAGIC:
        try:
            return magic.from_file(str(path))
        except Exception:
            return ""
    return ""


def _tools_available(required: list[str]) -> bool:
    return all(shutil.which(t) is not None for t in required)


def _extractor_status(analyzer, path: Path) -> tuple[bool, str | None]:
    """Can this module extract THIS file, and if not, which tool is missing?

    Two module-specific answers used to live here as `if analyzer.name ==
    "pcap"` / `== "disk"` branches. Both are now the module's own
    `availability(path)` hook (spectre.core.base.ModuleAvailability), because
    recognize.py was not their only caller — the canary asked the same question
    and got the naive `shutil.which(required_tools)` answer, which reports pcap
    unavailable on a Zeek-only host and an E01 openable by a Sleuth Kit with no
    libewf. One authority per module, two callers.

    Modules with no hook keep the generic behaviour unchanged.
    """
    hook = getattr(analyzer, "availability", None)
    if hook is None:
        return _tools_available(analyzer.required_tools), None
    try:
        av = hook(path)
    except Exception:
        # A capability probe must never turn into a triage crash. Fall back to
        # the generic answer rather than dropping the file.
        return _tools_available(analyzer.required_tools), None
    return bool(av.available), (av.missing or None)


def triage_one(path: str) -> dict:
    """Recognize a single file. Returns a triage record."""
    p = Path(path)
    rec = {
        "path": str(p),
        "exists": p.exists(),
        "magic": "",
        "module": None,
        "artifact_type": None,
        "confidence": 0.0,
        "tool": None,
        "status": "UNRECOGNIZED",
    }
    if not p.exists():
        rec["status"] = "MISSING"
        return rec

    rec["magic"] = _magic_desc(p)

    # Ask every recognizer; keep the highest-confidence claim.
    best = None
    best_score = 0.0
    modules = registry.discover()
    for analyzer in modules.values():
        for r in analyzer.recognizers:
            score = r.match(p, rec["magic"])
            if score > best_score:
                best_score = score
                best = (analyzer, r)

    if best is None:
        return rec  # UNRECOGNIZED

    analyzer, r = best
    rec["module"] = analyzer.name
    rec["artifact_type"] = r.artifact_type
    rec["confidence"] = round(best_score, 3)
    rec["tool"] = analyzer.required_tools[0] if analyzer.required_tools else None

    available, missing_tool = _extractor_status(analyzer, p)

    if available:
        rec["status"] = "RECOGNIZED"
    else:
        rec["status"] = "EXTRACTOR_PENDING"
        if missing_tool:
            rec["tool"] = missing_tool

    return rec


def triage(paths: list[str]) -> dict:
    """Recognize many files. Returns {path: triage_record} plus a summary."""
    records = {}
    for path in paths:
        records[str(Path(path))] = triage_one(path)
    return records


def derived_artifacts(triage_records: dict) -> list[str]:
    """The set of artifact_types to extract, derived from triage."""
    out: list[str] = []
    for rec in triage_records.values():
        at = rec.get("artifact_type")
        if at and rec.get("status") in ("RECOGNIZED", "EXTRACTOR_PENDING") and at not in out:
            out.append(at)
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: recognize.py <file> [<file> ...]", file=sys.stderr)
        sys.exit(2)
    result = triage(sys.argv[1:])
    print(json.dumps(result, indent=2))
    for rec in result.values():
        mark = {"RECOGNIZED": "✓", "EXTRACTOR_PENDING": "~",
                "UNRECOGNIZED": "✗", "MISSING": "!"}.get(rec["status"], "?")
        print(f"  {mark} {Path(rec['path']).name:30s} -> "
              f"{rec['module'] or '—'}/{rec['artifact_type'] or '—'} "
              f"[{rec['status']}] ({rec['magic'][:40]})", file=sys.stderr)
