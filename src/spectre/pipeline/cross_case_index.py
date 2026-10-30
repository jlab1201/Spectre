#!/usr/bin/env python3
"""
cross_case_index.py — Cross-case IOC index in plain Markdown.

Four operations:
  update_index(cases_dir, case_name)   — add/refresh one case's entries
  retract_case(cases_dir, case_name)   — remove one case's entries (no re-add)
  search_index(index_path, ioc_type, value) — exact-match lookup
  rebuild_index(cases_dir)             — scan all cases, rebuild index.md from scratch

index.md is plain Markdown with structured tables — grep/awk-parseable, no database.

WS8 / A7 Finding 2 (HIGH): index.md is a single store SHARED across every
case in `cases_dir`. Two invariants keep that shared store from becoming a
cross-case-contamination or premature-disclosure risk, enforced HERE (not
left to call-site discipline) so they hold for every caller, including the
host-agent path:

  1. Status/approval gate — `_finding_is_indexable()` below. Only CONFIRMED
     findings (and, when a finding YAML already carries the documented
     `approval:` field, only APPROVED ones) are ever pulled into the index.
     INFERRED and DROPPED findings never reach it. See that function's
     docstring for why this does NOT invent an approval requirement the
     rest of the codebase can't yet satisfy.
  2. Retraction — `retract_case()` gives the orchestrator an explicit way
     to undo whatever `update_index()` wrote for a case whose findings are
     later REJECTED, or that is abandoned/never approved.

Callers (phase_runner.py / runner.py) are responsible for WHEN this module
is invoked and WHICH cases_dir to pass — this module is responsible for
WHAT gets written once invoked. As of WS8, the only pipeline call site is
Phase 7 (post-approval, `runner.verify_and_close()`), not Phase 4
(pre-approval) — see A7 Finding 2.

cases-dir isolation (WS8): `runner.verify_and_close()` now passes
`str(Path(case_dir).parent)` — the case's ACTUAL parent cases-dir — to
`update_index()`, not the import-time `runner.CASES_DIR` global, so a run
under a custom `--cases-dir` writes its index THERE and never silently
targets the default `~/spectre-cases` store. Every function in THIS module
(`update_index`, `retract_case`, `rebuild_index`) acts strictly on whatever
`cases_dir` it is given and never falls back to its own `DEFAULT_CASES_DIR`
/ `INDEX_PATH` module constants once a caller passes one explicitly, so both
the call site and this module's own parameterization are sound.

CONTAINMENT SURFACE (procedural, host-agent gap class — see the README Architecture section): the
specificity filter + advisory labelling that keep loose cross-case matches
out of narratives live at the RECALL/format boundary
(`subagent_templates._format_cross_case_matches`), NOT in this store. The
raw `search_index()` API and the `search` CLI return unfiltered, unlabelled
rows (including `mitre_attack`) by design, for an analyst's direct lookup.
A host agent that pastes raw `search`/`search_index` output straight into a
finding or report narrative re-opens the A7 Finding 2 leak — cross-case
matches reaching a narrative MUST go through `_format_cross_case_matches`.
The store also still records `mitre_attack` rows for CONFIRMED findings;
harmless because they never render through the contained recall path.
"""

import json
import os
import re
import yaml
from datetime import datetime, timezone
from collections import defaultdict

from spectre.config import CASES_DIR, RAW_DIR
DEFAULT_CASES_DIR = str(CASES_DIR)
INDEX_PATH = os.path.join(DEFAULT_CASES_DIR, "index.md")

# ── helpers ──────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _parse_finding_yaml(finding_path: str) -> dict | None:
    """Load a finding YAML and return its dict, or None on failure."""
    try:
        with open(finding_path, "r") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        return None


def _scan_case_findings(case_dir: str) -> list[dict]:
    """Return all parsed finding dicts from a case's findings/ directory."""
    findings_dir = os.path.join(case_dir, "findings")
    if not os.path.isdir(findings_dir):
        return []

    findings = []
    for fname in sorted(os.listdir(findings_dir)):
        if fname.startswith("F-") and fname.endswith(".yaml"):
            fpath = os.path.join(findings_dir, fname)
            data = _parse_finding_yaml(fpath)
            if data:
                data["_case"] = os.path.basename(case_dir)
                data["_path"] = fpath
                findings.append(data)
    return findings


# ── IOC extraction ───────────────────────────────────────────────────

IOC_SECTIONS = [
    ("sha256",      "## SHA-256 Hashes"),
    ("ip",          "## IP Addresses"),
    ("domain",      "## Domains"),
    ("filepath",    "## File Paths"),
    ("registry_key","## Registry Keys"),
    ("mitre_attack","## MITRE Techniques"),
]

IOC_TABLE_HEADER = {
    "sha256":       "| Hash | Case | Finding | Date |",
    "ip":           "| IP | Case | Finding | Date |",
    "domain":       "| Domain | Case | Finding | Date |",
    "filepath":     "| Path | Case | Finding | Date |",
    "registry_key": "| Key | Case | Finding | Date |",
    "mitre_attack": "| Technique | Case | Finding | Date |",
}

IOC_TABLE_SEP = {
    "sha256":       "|------|------|---------|------|",
    "ip":           "|----|------|---------|------|",
    "domain":       "|--------|------|---------|------|",
    "filepath":     "|------|------|---------|------|",
    "registry_key": "|-----|------|---------|------|",
    "mitre_attack": "|-----------|------|---------|------|",
}


def _finding_is_indexable(fdata: dict) -> bool:
    """
    WS8 gate (A7 Finding 2 — HIGH): only CONFIRMED, examiner-approved
    findings may ever reach the shared cross-case index.

    Approval representation, as it actually exists today: the
    deterministic pipeline (emit_finding.py) has no in-process approval
    writer — there is no `approve_finding.py` anywhere in src/spectre/.
    `skills/methodology/SKILL.md`'s Phase 7 section documents the
    *intended* convention — the orchestrating agent (examiner-driven, not
    code) writes an `approval: APPROVED|REJECTED|SUPERSEDED` field onto the
    finding YAML plus a matching `action=approval` audit row — but nothing
    in this codebase writes or requires that field yet. Per WS8 scope, we
    do NOT invent an approval requirement the rest of the codebase can't
    satisfy: CONFIRMED status alone is the enforceable gate today.

    What IS enforced: if a finding YAML already carries the documented
    `approval:` field (an examiner/orchestrator wrote one by hand, per
    SKILL.md), a non-APPROVED value (REJECTED / SUPERSEDED / DRAFT)
    excludes the finding even though it's CONFIRMED. That's read-only
    respect for an existing, documented signal — not fabrication of a new
    one — and it's the reason `retract_case()` exists as a belt-and-braces
    undo for cases where this soft check didn't catch a later rejection
    (e.g. approval decided after the index write already ran).

    TODO(orchestrator): once an in-process approval writer exists, tighten
    this to REQUIRE `approval == "APPROVED"` — stop treating a missing
    field as index-eligible on CONFIRMED status alone.
    """
    if fdata.get("status") != "CONFIRMED":
        return False
    approval = fdata.get("approval")
    if approval is not None and approval != "APPROVED":
        return False
    return True


def _extract_iocs(findings: list[dict]) -> dict[str, list[tuple]]:
    """
    Return: {ioc_type: [(value, case, finding_id, date), ...]}
    Where ioc_type is one of sha256/ip/domain/filepath/registry_key/mitre_attack.

    Only findings passing `_finding_is_indexable()` (CONFIRMED + approved,
    see that docstring) contribute IOCs — INFERRED and DROPPED findings
    are excluded here regardless of what upstream callers pass in, so this
    filter holds even for a caller that forgets to pre-filter.
    """
    iocs: dict[str, list[tuple]] = defaultdict(list)

    for fdata in findings:
        if not _finding_is_indexable(fdata):
            continue
        case = fdata.get("_case", "unknown")
        finding_id = fdata.get("finding_id", "UNKNOWN")
        date = fdata.get("timestamp", _utcnow())

        # IOCs from finding
        ioc_dict = fdata.get("iocs", {})
        for ioc_type in ["sha256", "ip", "domain", "filepath", "registry_key"]:
            values = ioc_dict.get(ioc_type, [])
            if not isinstance(values, list):
                values = []
            for v in values:
                if v and str(v).strip():
                    iocs[ioc_type].append((str(v).strip(), case, finding_id, date[:10] if date else _utcnow()))

        # MITRE technique (always a single string in finding schema)
        mitre = fdata.get("mitre_attack", "")
        if mitre and mitre not in ("UNMAPPED", "", None):
            iocs["mitre_attack"].append((str(mitre), case, finding_id, date[:10] if date else _utcnow()))

    return dict(iocs)


# ── Index I/O ────────────────────────────────────────────────────────

def _build_markdown(all_iocs: dict[str, list[tuple]]) -> str:
    """Build complete index.md Markdown from IOC dict."""
    lines = [
        "# Cross-Case Artifact Index",
        "",
        f"*Auto-generated by cross_case_index.py — last rebuilt: {_utcnow()}*",
        "",
    ]

    for ioc_type, heading in IOC_SECTIONS:
        entries = sorted(set(all_iocs.get(ioc_type, [])))  # deduplicate

        lines.append(heading)
        lines.append("")
        lines.append(IOC_TABLE_HEADER[ioc_type])
        lines.append(IOC_TABLE_SEP[ioc_type])

        if not entries:
            lines.append("| *(none)* | | | |")
        else:
            for value, case, finding_id, date in entries:
                # Escape pipes in values
                safe_value = value.replace("|", "\\|")
                lines.append(f"| {safe_value} | {case} | {finding_id} | {date} |")

        lines.append("")

    return "\n".join(lines) + "\n"


def rebuild_index(cases_dir: str = DEFAULT_CASES_DIR) -> str:
    """
    Scan all case directories for findings and rebuild index.md from scratch,
    entirely from CONFIRMED (+approved, see `_finding_is_indexable()`)
    findings currently on disk.

    Because this discards everything previously in index.md and re-derives
    it fresh from findings/, it is also the purge path for a polluted
    index (e.g. one written before WS8's status/approval gate existed, or
    one containing stale entries for a case whose findings were later
    edited/rejected out-of-band): rebuilding drops anything that no longer
    qualifies. `cases_dir` is always an explicit parameter — never resolve
    the default global cases dir implicitly inside a caller; pass the
    ACTUAL active cases dir (see module docstring / WS8 isolation note).

    Returns the path to index.md.
    """
    all_findings = []
    for entry in sorted(os.listdir(cases_dir)):
        case_path = os.path.join(cases_dir, entry)
        if not os.path.isdir(case_path):
            continue
        # Skip hidden/non-case dirs
        if entry.startswith(".") or entry in ("evidence", RAW_DIR, "findings", "reports", "timeline"):
            continue
        findings = _scan_case_findings(case_path)
        all_findings.extend(findings)

    all_iocs = _extract_iocs(all_findings)
    md = _build_markdown(all_iocs)

    index_path = os.path.join(cases_dir, "index.md")
    with open(index_path, "w") as f:
        f.write(md)

    print(f"rebuild_index: {len(all_findings)} findings → {index_path}")
    for ioc_type, _heading in IOC_SECTIONS:
        count = len(all_iocs.get(ioc_type, []))
        print(f"  {ioc_type}: {count} entries")

    return index_path


def update_index(cases_dir: str, case_name: str) -> dict:
    """
    Add/refresh entries for a single case. Reads existing index.md, removes old
    entries for this case, adds new ones from its CONFIRMED (+approved, see
    `_finding_is_indexable()`) findings only — INFERRED/DROPPED findings
    never contribute rows, and a re-run after a finding's status/approval
    changes will drop rows for findings that no longer qualify (they're
    removed in the "old entries" pass and not re-added in the "new
    entries" pass, since `_extract_iocs()` won't have produced them).

    WS8 (A7 Finding 2): call this from Phase 7 (post-approval), not Phase 4
    — see `runner.verify_and_close()`. This function itself acts strictly
    on the `cases_dir` argument it's given (never the module-level default
    global — see the module docstring's isolation note); callers are
    responsible for passing the case's ACTUAL active cases dir so an
    isolated/alternate cases dir never touches the real shared store. As
    of WS8, `runner.verify_and_close()` passes `Path(case_dir).parent` —
    the case's real parent cases-dir — so a run under a custom `--cases-dir`
    is correctly isolated (see this file's module docstring).

    Returns {"added": N, "removed": N, "case": case_name}.
    """
    case_dir = os.path.join(cases_dir, case_name)
    findings = _scan_case_findings(case_dir)
    new_iocs = _extract_iocs(findings)

    index_path = os.path.join(cases_dir, "index.md")

    # Read existing index
    existing_iocs: dict[str, list[tuple]] = defaultdict(list)
    if os.path.exists(index_path):
        existing_iocs = _parse_index(index_path)

    # Remove old entries for this case from existing
    removed = 0
    for ioc_type in existing_iocs:
        before = len(existing_iocs[ioc_type])
        existing_iocs[ioc_type] = [
            (v, c, f, d) for v, c, f, d in existing_iocs[ioc_type]
            if c != case_name
        ]
        removed += before - len(existing_iocs[ioc_type])

    # Merge new entries
    added = 0
    for ioc_type, entries in new_iocs.items():
        existing_set = set(existing_iocs.get(ioc_type, []))
        new_set = set(entries)
        existing_iocs[ioc_type] = sorted(existing_set | new_set)
        added += len(new_set - existing_set)

    md = _build_markdown(existing_iocs)
    with open(index_path, "w") as f:
        f.write(md)

    print(f"update_index({case_name}): +{added} new, -{removed} old → {index_path}")
    return {"added": added, "removed": removed, "case": case_name}


def retract_case(cases_dir: str, case_name: str) -> dict:
    """
    Remove a case's rows from index.md entirely — no re-add, unlike
    `update_index()`. Every other case's rows are left untouched.

    WS8 (A7 Finding 2): use this when a case's findings are REJECTED at
    Phase 7 approval, or the case is abandoned / never reaches approval,
    to undo whatever `update_index()` previously wrote for it. Safe to
    call on a case that was never indexed, or when index.md doesn't exist
    yet (returns removed=0 either way — never raises for that).

    Returns {"removed": N, "case": case_name}.
    """
    index_path = os.path.join(cases_dir, "index.md")
    if not os.path.exists(index_path):
        return {"removed": 0, "case": case_name}

    existing_iocs = _parse_index(index_path)

    removed = 0
    for ioc_type in list(existing_iocs.keys()):
        before = len(existing_iocs[ioc_type])
        existing_iocs[ioc_type] = [
            (v, c, f, d) for v, c, f, d in existing_iocs[ioc_type]
            if c != case_name
        ]
        removed += before - len(existing_iocs[ioc_type])

    md = _build_markdown(existing_iocs)
    with open(index_path, "w") as f:
        f.write(md)

    print(f"retract_case({case_name}): -{removed} entries → {index_path}")
    return {"removed": removed, "case": case_name}


def _parse_index(index_path: str) -> dict[str, list[tuple]]:
    """
    Parse an existing index.md back into IOC dict.
    Handles the structured table format.
    """
    if not os.path.exists(index_path):
        return defaultdict(list)

    with open(index_path) as f:
        text = f.read()

    iocs: dict[str, list[tuple]] = defaultdict(list)

    for ioc_type, heading in IOC_SECTIONS:
        # Find this section in the markdown
        pattern = re.escape(heading) + r"\n\n\|.*?\|\n\|[-| ]+\|\n((?:\|.*\|\n)*)"
        match = re.search(pattern, text)
        if not match:
            continue

        table_body = match.group(1)
        for line in table_body.strip().split("\n"):
            line = line.strip()
            if not line or "*(none)*" in line:
                continue
            # Parse: | value | case | finding_id | date |
            # Handle escaped pipes in values — split on | not preceded by backslash
            inner = line[1:-1]  # strip leading/trailing |
            parts = re.split(r"(?<!\\)\|", inner)
            if len(parts) >= 4:
                value = parts[0].strip().replace("\\|", "|")
                case = parts[1].strip()
                finding_id = parts[2].strip()
                date = parts[3].strip()
                if value and case:
                    iocs[ioc_type].append((value, case, finding_id, date))

    return dict(iocs)


def search_index(index_path: str | None = None,
                 ioc_type: str = "",
                 value: str = "") -> list[dict]:
    """
    Search index.md for an exact IOC match.

    Args:
        index_path: Path to index.md. Defaults to ~/cases/index.md.
        ioc_type: One of sha256/ip/domain/filepath/registry_key/mitre_attack
        value: The exact value to search for.

    Returns:
        List of matching entries: [{"case": str, "finding_id": str, "date": str, "ioc_type": str, "value": str}, ...]

    ⚠ CONTAINMENT WARNING: this returns RAW, UNFILTERED, UNLABELLED rows —
    including loose `mitre_attack` matches near-certain to be unrelated in a
    large store. It is for an analyst's direct lookup only. Cross-case matches
    destined for a finding or report NARRATIVE must NOT come from here; route
    them through `subagent_templates._format_cross_case_matches()`, which drops
    non-specific types and stamps every match with the advisory "different
    matter" label (WS8 / A7 Finding 2). Pasting raw search output into a
    narrative re-opens the contamination leak this workstream closed.
    """
    if index_path is None:
        index_path = INDEX_PATH

    if ioc_type not in dict(IOC_SECTIONS):
        return []

    iocs = _parse_index(index_path)
    entries = iocs.get(ioc_type, [])

    # Exact match
    matches = []
    for v, case, finding_id, date in entries:
        if v.lower() == value.lower():
            matches.append({
                "ioc_type": ioc_type,
                "value": v,
                "case": case,
                "finding_id": finding_id,
                "date": date,
            })

    return matches


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cross-case artifact index")
    sub = parser.add_subparsers(dest="command")

    rebuild_p = sub.add_parser("rebuild", help="Rebuild index.md from all cases")
    rebuild_p.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)

    update_p = sub.add_parser("update", help="Update entries for one case")
    update_p.add_argument("case_name")
    update_p.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)

    retract_p = sub.add_parser("retract", help="Remove one case's entries (no re-add) — "
                                                "use after REJECTED findings or an abandoned case")
    retract_p.add_argument("case_name")
    retract_p.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)

    search_p = sub.add_parser("search", help="Search index for exact IOC match")
    search_p.add_argument("--ioc-type",
                          choices=["sha256", "ip", "domain", "filepath", "registry_key", "mitre_attack"])
    search_p.add_argument("--value", required=True)
    search_p.add_argument("--index", default=INDEX_PATH)
    search_p.add_argument("--search-all", action="store_true",
                          help="Search across all IOC types")

    args = parser.parse_args()

    if args.command == "rebuild":
        rebuild_index(args.cases_dir)
    elif args.command == "update":
        update_index(args.cases_dir, args.case_name)
    elif args.command == "retract":
        retract_case(args.cases_dir, args.case_name)
    elif args.command == "search":
        if args.search_all:
            all_matches = []
            for ioc_type in ["sha256", "ip", "domain", "filepath", "registry_key", "mitre_attack"]:
                all_matches.extend(search_index(args.index, ioc_type, args.value))
            results = all_matches
        elif args.ioc_type:
            results = search_index(args.index, args.ioc_type, args.value)
        else:
            parser.error("Must specify --ioc-type or --search-all")
        if results:
            print(json.dumps(results, indent=2))
        else:
            print(f"No matches for {args.value}")
    else:
        parser.print_help()
