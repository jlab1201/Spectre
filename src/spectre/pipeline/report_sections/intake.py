"""Evidence intake table and extraction/coverage predicates over the manifest."""

from __future__ import annotations

import os



# ── Evidence intake helper ────────────────────────────────────────────
def _outcome_cell(res: dict, rec: dict, status: str = None) -> str:
    """Render the Extraction column from extraction result and triage record.
    Handles events, errors, skipped, channel stats, and extractor_pending."""
    if "events" in res:
        outcome = f"{res['events']} events"
        # W4 review MED-3: never let "0 events" read as a clean examination.
        if res.get("extraction_status") == "EMPTY":
            outcome += " — EMPTY: tool ran but parsed zero records"
        elif res.get("extraction_status") == "EXTRACTION_FAILED":
            outcome += " — EXTRACTION_FAILED"
    elif "error" in res:
        outcome = f"ERROR: {res['error']}"
    elif "skipped" in res:
        outcome = f"skipped ({res['skipped']})"
    else:
        outcome = "not extracted"
    if status == "EXTRACTOR_PENDING":
        outcome += f" — requires `{rec.get('tool') or '?'}`"
    channel_stats = res.get("channel_stats") or {}
    if channel_stats:
        parts = []
        for ch, s in sorted(channel_stats.items()):
            seen = s.get("seen", 0)
            parsed = s.get("parsed", 0)
            part = f"{ch}: {parsed}/{seen}"
            if seen > 0 and parsed == 0:
                if s.get("supported", False):
                    part += " (no process-creation events)"
                else:
                    part += " (channel not supported)"
            parts.append(part)
        outcome += "; " + ", ".join(parts)
    return outcome


# ── Evidence intake generator ──────────────────────────────────────────
def _generate_intake_section(manifest: dict) -> str:
    """Evidence Intake table: one row per submitted file with its triage
    outcome and extraction result, plus skipped-at-intake entries, plus
    derived evidence (carved from images).
    Facts only — an unrecognized file is reported, never interpreted.
    Returns "" for legacy manifests with no triage data."""
    triage = manifest.get("triage") or {}
    skipped = manifest.get("intake_skipped") or []
    derived = manifest.get("derived_evidence") or {}
    if not triage and not skipped and not derived:
        return ""
    results = (manifest.get("extraction") or {}).get("results") or {}
    lines = ["## Evidence Intake\n",
             "| File | Triage | Module/Artifact | Extraction |",
             "|------|--------|-----------------|------------|"]
    for path, rec in sorted(triage.items()):
        name = os.path.basename(path)
        status = rec.get("status", "?")
        mod = rec.get("module") or "—"
        art = rec.get("artifact_type") or "—"
        res = results.get(path) or {}
        outcome = _outcome_cell(res, rec, status)
        lines.append(f"| {name} | {status} | {mod}/{art} | {outcome} |")
    if skipped:
        lines.append("\n**Skipped at intake:**\n")
        for s in skipped:
            lines.append(f"- `{s.get('path')}` — {s.get('reason')}")
    if derived:
        lines.append("\n**Derived evidence (carved from images):**\n")
        lines.append("| Carved name | Parent image | Triage | Extraction |")
        lines.append("|-------------|--------------|--------|------------|")
        for path, rec in sorted(derived.items()):
            name = os.path.basename(path)
            parent = os.path.basename(rec.get("derived_from", "?"))
            status = rec.get("status", "?")
            res = results.get(path) or {}
            outcome = _outcome_cell(res, rec, status)
            lines.append(f"| {name} | {parent} | {status} | {outcome} |")
    return "\n".join(lines) + "\n"


# ── Intake-fed blind spot helpers (Track B intake -> case-specific,
# never boilerplate) ───────────────────────────────────────────────────
def _extraction_records(manifest: dict) -> list[dict]:
    """Extraction result records that actually ran a module (W4-1)."""
    results = (manifest.get("extraction") or {}).get("results") or {}
    return [r for r in results.values()
            if isinstance(r, dict) and "extraction_status" in r]


# W4 review MED-3: EMPTY (zero records parsed from non-empty evidence) is
# as unexamined as EXTRACTION_FAILED for every verdict/coverage purpose.
_UNEXAMINED = ("EXTRACTION_FAILED", "EMPTY")


def _extraction_any_failed(manifest: dict) -> bool:
    return any(r["extraction_status"] in _UNEXAMINED
               for r in _extraction_records(manifest))


def _extraction_any_empty(manifest: dict) -> bool:
    return any(r["extraction_status"] == "EMPTY"
               for r in _extraction_records(manifest))


def _failed_tool_runs(manifest: dict) -> int:
    """Tool runs that failed inside artifacts that otherwise extracted."""
    return sum(int(r.get("handles_failed") or 0)
               for r in _extraction_records(manifest)
               if r["extraction_status"] == "PARTIAL")


def _extraction_all_failed(manifest: dict) -> bool:
    recs = _extraction_records(manifest)
    return bool(recs) and all(r["extraction_status"] in _UNEXAMINED
                              for r in recs)


def _module_extraction_status(manifest: dict, module: str) -> tuple[str | None, int]:
    """(best outcome, failed runs) for `module`: SUCCESS if any record fully
    succeeded, else PARTIAL, else EMPTY, else EXTRACTION_FAILED; None when
    no W4-1 outcome is recorded (legacy manifest)."""
    recs = [r for r in _extraction_records(manifest)
            if str(r.get("module") or "") == module]
    if not recs:
        return None, 0
    states = {r["extraction_status"] for r in recs}
    failed = sum(int(r.get("handles_failed") or 0) for r in recs)
    for best in ("SUCCESS", "PARTIAL", "EMPTY"):
        if best in states:
            return best, failed
    return "EXTRACTION_FAILED", failed


def _coverage_counts(manifest: dict) -> tuple[int, int]:
    """(examined, total) evidence items, derived/carved evidence included.

    An item is EXAMINED only when extraction actually ran and produced a
    normalized-event count. A record carrying "skipped" (UNRECOGNIZED /
    EXTRACTOR_PENDING / anything else) was never opened; a record carrying
    "error" was attempted and failed, so its contents are equally
    unverified. Both count as NOT examined — the honest direction.
    Sourced from manifest["extraction"]["results"], the same dict
    _gap_fill_skips reads.
    """
    results = (manifest.get("extraction") or {}).get("results") or {}
    total = len(results)
    # W4-1 (R1-F2): an item whose every tool run failed was NOT examined,
    # even though it carries an "events" count (of zero).
    examined = sum(
        1 for r in results.values()
        if isinstance(r, dict) and "events" in r
        and r.get("extraction_status") not in ("EXTRACTION_FAILED", "EMPTY")
    )
    return examined, total


def _coverage_sentence(manifest: dict) -> str:
    """Deterministic coverage disclosure for the Verdict section.

    Returned with a LEADING SPACE so it appends to a verdict sentence the
    same way absence_sentence does. Empty when every registered evidence
    item was examined (nothing to disclose) or when no evidence was
    registered at all (a fixture/KB-only run, where a coverage claim would
    be meaningless).

    This is deterministic output and belongs in EVERY verdict branch,
    including the model-authored one: under SPECTRE_LLM_PROVIDER=host there
    is no _validate_report seam, so a validator cannot be relied on to add
    it after the fact.
    """
    examined, total = _coverage_counts(manifest)
    if total == 0 or examined >= total:
        return ""
    if examined == 0:
        return (f" **No evidence was examined.** All {total} registered "
                f"evidence item(s) were left unanalyzed — see "
                f"'4. Forensic Blind Spots'. This report establishes "
                f"nothing about their contents.")
    return (f" **Coverage: {total - examined} of {total} evidence item(s) "
            f"were not examined** — see '4. Forensic Blind Spots'.")
