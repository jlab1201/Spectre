#!/usr/bin/env python3
"""
subagent_templates.py — Context templates for Spectre's three subagent types.

Each builder returns a dict compatible with delegate_task(goal=..., context=...):
  {
    "goal": "<one-line task description>",
    "context": "<multi-line context with all injected data>",
    "toolsets": ["terminal", "file", "web"]  # optional, suggested toolsets
  }

Templates produce dicts for dispatch — the lead agent calls delegate_task() with them.
The subagents themselves are responsible for executing their tasks. These builders are
host-neutral: any orchestrating agent (Claude Code, Hermes, …) dispatches them.
"""

import json
import sys
import yaml
from pathlib import Path
from typing import Any


# ── Helpers ──────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    """Load YAML safely, return empty dict on failure."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _finding_summary(finding: dict) -> str:
    """Produce a compact one-line summary of a finding."""
    fid = finding.get("finding_id", "?")
    status = finding.get("status", "?")
    confidence = finding.get("confidence", "?")
    title = finding.get("title", "?")
    mitre = finding.get("mitre_attack", "?")
    return f"{fid} [{status}/{confidence}] {title} (MITRE: {mitre})"


def _format_finding_for_context(finding: dict) -> str:
    """Format a full finding as YAML-ish text for subagent context injection."""
    lines = []
    lines.append(f"Finding ID: {finding.get('finding_id', '?')}")
    lines.append(f"Status: {finding.get('status', '?')}")
    lines.append(f"Confidence: {finding.get('confidence', '?')}")
    lines.append(f"Title: {finding.get('title', '?')}")
    lines.append(f"MITRE ATT&CK: {finding.get('mitre_attack', '?')}")
    lines.append(f"Tool: {finding.get('tool', '?')}")
    lines.append(f"Command: {finding.get('exact_command', '?')}")

    # Evidence refs
    refs = finding.get("evidence_refs", [])
    if refs:
        lines.append("Evidence References:")
        for r in refs:
            lines.append(f"  - execution_id: {r.get('execution_id', '?')}")

    # IOCs
    iocs = finding.get("iocs", {})
    if iocs:
        lines.append("IOCs:")
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"  {ioc_type}: {', '.join(values)}")

    # Caveats
    caveats = finding.get("forensic_caveats", [])
    if caveats:
        lines.append("Forensic Caveats (from FK YAML does_NOT_prove):")
        for c in caveats:
            lines.append(f"  - {c}")

    # Corroboration
    corr = finding.get("corroboration", {})
    if corr:
        sources = corr.get("sources", 0)
        artifacts = corr.get("artifacts", [])
        lines.append(f"Corroboration: {sources} source(s)")
        if artifacts:
            for a in artifacts:
                lines.append(f"  - {a}")

    return "\n".join(lines)


def _format_fk_envelope(fk_yaml: dict) -> str:
    """Format FK YAML as structured context."""
    lines = []
    lines.append(f"Artifact: {fk_yaml.get('artifact', '?')}")
    lines.append(f"Artifact ID: {fk_yaml.get('artifact_id', '?')}")
    lines.append(f"Source: {fk_yaml.get('source', '?')}")
    lines.append(f"Parser: {fk_yaml.get('parser', '?')}")

    proves = fk_yaml.get("proves", [])
    if proves:
        lines.append("\nWhat this artifact PROVES:")
        for p in proves:
            lines.append(f"  + {p}")

    does_not = fk_yaml.get("does_NOT_prove", [])
    if does_not:
        lines.append("\nWhat this artifact does NOT prove:")
        for d in does_not:
            lines.append(f"  - {d}")

    corroborate = fk_yaml.get("corroborate_with", [])
    if corroborate:
        lines.append("\nCorroborate with:")
        for c in corroborate:
            lines.append(f"  → {c}")

    reminder = fk_yaml.get("discipline_reminder", "")
    if reminder:
        lines.append(f"\nDiscipline Reminder: {reminder}")

    confidence = fk_yaml.get("confidence_weight", "?")
    lines.append(f"\nConfidence Weight: {confidence}")

    return "\n".join(lines)


def _format_kb_hits(kb_hits: list) -> str:
    """Format KB search results for context injection."""
    if not kb_hits:
        return "(No KB results)"

    lines = []
    for i, hit in enumerate(kb_hits[:5], 1):
        if isinstance(hit, dict):
            poster = hit.get("poster_name", hit.get("source", "?"))
            section = hit.get("section_title", hit.get("title", "?"))
            snippet = hit.get("chunk_text", hit.get("snippet", ""))
            tags = hit.get("artifact_tags", hit.get("tags", ""))

            lines.append(f"\n  [{i}] {poster} — {section}")
            if tags:
                lines.append(f"      Tags: {tags}")
            # Truncate long snippets
            if len(snippet) > 500:
                snippet = snippet[:500] + "..."
            lines.append(f"      {snippet[:300]}")
        elif isinstance(hit, str):
            lines.append(f"\n  [{i}] {hit[:200]}")

    return "\n".join(lines) if lines else "(No KB results)"


# WS8 (A7 Finding 2 — HIGH): specificity filter at the recall/format
# boundary. Only IOC types that are near-unique identifiers of the SAME
# artifact/sample/infrastructure may ever be rendered into any narrative
# context. A `mitre_attack` cross-case "match" is just two cases both
# involving a common ATT&CK technique (SKILL.md's own audit found
# T1071.001 alone in ~1,681 rows across a real 270-case store) — it is
# near-guaranteed to be an unrelated matter, not corroboration. filepath
# and registry_key are excluded too: both are frequently generic/benign
# (a shared C:\Windows\System32\svchost.exe path or a common Run-key)
# rather than case-specific identifiers (see A7 Finding 4). This filter
# is enforced HERE, at the format/render boundary, so it holds no matter
# which caller passes matches in — including the host-agent path, which
# has no other in-process seam (see the README Architecture section).
CROSS_CASE_SPECIFIC_TYPES = {"sha256", "domain", "ip"}

# Advisory label — MUST accompany every rendered cross-case match, always,
# so cross-case content can never appear unlabelled in a finding/report
# narrative. Kept as a module constant (not inlined per call site) so it
# can't accidentally drift between call sites or get silently dropped.
CROSS_CASE_ADVISORY_LABEL = (
    "ADVISORY ONLY — from a DIFFERENT matter, NOT evidence in this case"
)


def _format_cross_case_matches(matches: list) -> str:
    """Format cross-case recall results for narrative-context injection.

    WS8 (A7 Finding 2): two hard rules enforced unconditionally, not left
    to caller discipline:
      1. Specificity filter — only sha256 / exact-domain / exact-IP
         matches (`CROSS_CASE_SPECIFIC_TYPES`) are ever rendered. Anything
         else (mitre_attack, filepath, registry_key, or a match missing/
         lacking a recognized `ioc_type`) is silently dropped here — it
         never reaches the subagent's context, let alone a narrative.
      2. Advisory labelling — every match that does render carries
         `CROSS_CASE_ADVISORY_LABEL`, unconditionally, in both the header
         and every individual line (so the label survives truncation of
         any one line and can't be edited out of a single entry).
    """
    specific = [
        m for m in matches
        if isinstance(m, dict) and m.get("ioc_type") in CROSS_CASE_SPECIFIC_TYPES
    ]
    if not specific:
        return "(No prior cross-case matches)"

    lines = [
        f"{len(specific)} prior case(s) with matching high-specificity IOCs "
        f"({CROSS_CASE_ADVISORY_LABEL}):"
    ]
    for m in specific:
        lines.append(
            f"  - [{CROSS_CASE_ADVISORY_LABEL}] Case {m.get('case', '?')}: "
            f"{m.get('finding_id', '?')} "
            f"[{m.get('ioc_type', '?')}: {m.get('value', '?')}] "
            f"({m.get('date', '?')})"
        )
    return "\n".join(lines)


# ── Builder 1: Deep-Dive Analyst ─────────────────────────────────────

def build_deep_dive_context(
    finding: dict,
    fk_yaml_path: str | None = None,
    fk_envelope: dict | None = None,
    kb_hits: list | None = None,
    cross_case_matches: list | None = None,
    related_findings: list | None = None,
) -> dict[str, Any]:
    """
    Build context for a deep-dive analyst subagent.

    The subagent explains a single finding in detail.
    It does NOT create new findings — it only explains what exists.

    Args:
        finding: The finding dict (matching Spectre finding schema)
        fk_yaml_path: Path to FK YAML (loaded if fk_envelope not provided)
        fk_envelope: Pre-loaded FK YAML dict
        kb_hits: FTS5 KB search results (list of dicts with poster_name, section_title, chunk_text)
        cross_case_matches: Results from cross_case_index.search_index()
        related_findings: Other findings from same case

    Returns:
        Dict with keys: goal, context, toolsets
    """
    # Load FK YAML if path given and envelope not provided
    if fk_envelope is None and fk_yaml_path:
        fk_envelope = _load_yaml(fk_yaml_path)

    # Format injected context
    parts = []

    parts.append("=== FINDING TO ANALYZE ===\n")
    parts.append(_format_finding_for_context(finding))

    if fk_envelope:
        parts.append("\n=== FORENSIC KNOWLEDGE (FK YAML) ===\n")
        parts.append(_format_fk_envelope(fk_envelope))

    if related_findings:
        parts.append("\n=== RELATED FINDINGS (same case) ===\n")
        for rf in related_findings:
            parts.append(f"  {_finding_summary(rf)}")

    if kb_hits:
        parts.append("\n=== KNOWLEDGE BASE RESULTS ===\n")
        parts.append(_format_kb_hits(kb_hits))

    if cross_case_matches:
        parts.append("\n=== CROSS-CASE EPISODIC RECALL ===\n")
        parts.append(_format_cross_case_matches(cross_case_matches))

    # Critical instruction block
    parts.append("\n=== INSTRUCTIONS ===\n")
    parts.append(
        "You are a forensic deep-dive analyst. Analyze the finding above and produce:\n"
        "\n"
        "1. PLAIN-LANGUAGE EXPLANATION (2-3 sentences):\n"
        "   What does this finding mean? What event occurred?\n"
        "\n"
        "2. MITRE ATT&CK EXPLANATION:\n"
        "   Explain what this technique is, why it fits this finding,\n"
        "   and what the attacker was trying to accomplish.\n"
        "\n"
        "3. CONFIDENCE ASSESSMENT:\n"
        "   Do the sources support the conclusion? Are there gaps?\n"
        "   The confidence score was computed deterministically (source count).\n"
        "   Explain what the score means and what additional evidence would\n"
        "   strengthen it.\n"
        "\n"
        "4. ADDITIONAL EVIDENCE:\n"
        "   What would strengthen this finding? Which artifacts should\n"
        "   be examined next?\n"
        "\n"
        "5. ALTERNATIVE EXPLANATIONS:\n"
        "   What else could explain these observations? Consider benign\n"
        "   explanations, tool artifacts, and false positives.\n"
        "\n"
        "6. VERBATIM CAVEATS (CRITICAL):\n"
        "   Copy EVERY caveat from 'Forensic Caveats' above VERBATIM.\n"
        "   Do not paraphrase. Do not omit. These are the does_NOT_prove\n"
        "   entries from the FK YAML and are mandatory.\n"
        "\n"
        "CONSTRAINTS:\n"
        "- Do NOT create new findings. Only explain what exists.\n"
        "- Do NOT invent evidence or citations.\n"
        "- Do NOT change the confidence score.\n"
        "- The caveats section MUST be verbatim from the FK YAML.\n"
        "- If you are uncertain, say so explicitly.\n"
    )

    context = "\n".join(parts)

    goal = (
        f"Analyze finding {finding.get('finding_id', '?')}: "
        f"{finding.get('title', 'forensic finding')} "
        f"and produce a detailed forensic explanation. "
        f"Do NOT create new findings — only explain what the deterministic pipeline found."
    )

    return {
        "goal": goal,
        "context": context,
        "toolsets": ["terminal", "file", "web"],
    }


# ── Builder 2: Adversarial Reviewer ──────────────────────────────────

def build_adversarial_context(
    all_findings: list[dict],
    evidence_manifest: dict | None = None,
    audit_summary: dict | None = None,
    artifact_profile: str | None = None,
    fk_blind_spots: list[str] | None = None,
    tool_exec_log: list[dict] | None = None,
) -> dict[str, Any]:
    """
    Build context for an adversarial reviewer subagent.

    The adversarial reviewer challenges the primary narrative — it is the
    devil's advocate. It searches for disconfirming evidence.

    Args:
        all_findings: All findings from the case (at minimum: finding_id, title, status, confidence, mitre_attack)
        evidence_manifest: Case evidence manifest (what was examined)
        audit_summary: Summary of audit log
        artifact_profile: Which artifact profile was used (quick-triage, full, etc.)
        fk_blind_spots: Known blind spots from FK YAMLs (collected does_NOT_prove entries)
        tool_exec_log: Which tools ran, their results

    Returns:
        Dict with keys: goal, context, toolsets
    """
    parts = []

    # Findings summary (compact — not full YAMLs)
    parts.append("=== FINDINGS TO CHALLENGE ===\n")
    confirmed = [f for f in all_findings if f.get("status") == "CONFIRMED"]
    inferred = [f for f in all_findings if f.get("status") == "INFERRED"]
    dropped = [f for f in all_findings if f.get("status") == "DROPPED"]

    parts.append(f"CONFIRMED ({len(confirmed)}):")
    for f in confirmed:
        parts.append(f"  {_finding_summary(f)}")

    parts.append(f"\nINFERRED ({len(inferred)}):")
    for f in inferred:
        parts.append(f"  {_finding_summary(f)}")

    if dropped:
        parts.append(f"\nDROPPED ({len(dropped)}):")
        for f in dropped:
            parts.append(f"  {_finding_summary(f)}")

    # Evidence manifest
    if evidence_manifest:
        parts.append("\n=== EVIDENCE MANIFEST ===\n")
        parts.append(f"Evidence examined: {json.dumps(evidence_manifest, indent=2)[:1000]}")

    # Artifact profile
    if artifact_profile:
        parts.append(f"\nArtifact profile used: {artifact_profile}")

    # Tool execution log
    if tool_exec_log:
        parts.append("\n=== TOOL EXECUTION LOG ===\n")
        for t in tool_exec_log:
            tool_name = t.get("tool", "?")
            result = t.get("result", "?")
            exit_code = t.get("exit_code", "?")
            parts.append(f"  {tool_name}: result={result} exit_code={exit_code}")
    elif audit_summary:
        parts.append("\n=== AUDIT SUMMARY ===\n")
        parts.append(json.dumps(audit_summary, indent=2)[:1500])

    # Known blind spots
    if fk_blind_spots:
        parts.append("\n=== KNOWN BLIND SPOTS (from FK YAMLs) ===\n")
        for bs in fk_blind_spots:
            parts.append(f"  - {bs}")

    # Instructions
    parts.append("\n=== INSTRUCTIONS ===\n")
    parts.append(
        "You are the DEVIL'S ADVOCATE in a forensic investigation.\n"
        "Your job is to challenge the primary narrative. Assume it might be wrong.\n"
        "\n"
        "Produce:\n"
        "\n"
        "1. COUNTER-HYPOTHESES (for each CONFIRMED finding):\n"
        "   Could X be explained by Y instead? Consider:\n"
        "   - Benign software exhibiting the same behavior\n"
        "   - Tool artifacts or false positives\n"
        "   - Legitimate admin activity\n"
        "   - Coincidence / unrelated events\n"
        "\n"
        "2. EVIDENCE GAPS:\n"
        "   Which tools were APPLICABLE but NEVER INVOKED?\n"
        "   Example: If rundll32-from-temp was found but Prefetch was never parsed,\n"
        "   that's a gap. If netscan was never run, that's a gap.\n"
        "\n"
        "3. CITATION GAPS:\n"
        "   Which evidence was INDEXED but never CITED in any finding?\n"
        "   Look for evidence files that were registered but never referenced.\n"
        "\n"
        "4. ALTERNATIVE TIMELINE:\n"
        "   Could events have happened in a different order?\n"
        "   Consider time stomping, clock skew, and tool timing artifacts.\n"
        "\n"
        "5. CONFIDENCE ADJUSTMENT RECOMMENDATIONS (advisory only):\n"
        "   Based on your review, should any confidence scores be adjusted?\n"
        "   Note: YOU CANNOT modify findings. These are recommendations only.\n"
        "\n"
        "ABSOLUTE CONSTRAINTS:\n"
        "- DO NOT invent new findings.\n"
        "- DO NOT create new evidence.\n"
        "- Only critique EXISTING findings.\n"
        "- Be specific: cite finding IDs, not vague doubts.\n"
        "- If you find NO issues, say so explicitly — don't fabricate criticism.\n"
    )

    context = "\n".join(parts)

    goal = (
        "Challenge the primary forensic narrative. You are the devil's advocate. "
        "Assume the primary narrative is wrong and find every reason it might be. "
        "Produce counter-hypotheses, identify evidence gaps, citation gaps, "
        "offer an alternative timeline, and recommend confidence adjustments. "
        "Do NOT invent new findings — only critique existing ones. "
        "Be specific and cite finding IDs."
    )

    return {
        "goal": goal,
        "context": context,
        "toolsets": ["terminal", "file", "web"],
    }


# ── Builder 3: KB Retriever ──────────────────────────────────────────

def build_kb_retriever_context(
    query: str,
    artifact_type: str = "",
    phase: str = "",
    fk_yaml_path: str | None = None,
    max_results: int = 5,
) -> dict[str, Any]:
    """
    Build context for a KB retriever subagent.

    Searches the FTS5 index for relevant reference material.

    Args:
        query: Search terms (IOC, technique, artifact name, etc.)
        artifact_type: Artifact category (prefetch, evtx, amcache, etc.)
        phase: Investigation phase for relevance filtering
        fk_yaml_path: Optional FK YAML for discipline reminders
        max_results: Maximum KB results to return

    Returns:
        Dict with keys: goal, context, toolsets
    """
    parts = []

    parts.append("=== KB SEARCH QUERY ===\n")
    parts.append(f"Query: {query}")
    if artifact_type:
        parts.append(f"Artifact type: {artifact_type}")
    if phase:
        parts.append(f"Phase: {phase}")

    # Load FK YAML for discipline reminders if provided
    if fk_yaml_path:
        fk = _load_yaml(fk_yaml_path)
        reminder = fk.get("discipline_reminder", "")
        caveats = fk.get("does_NOT_prove", [])
        if reminder or caveats:
            parts.append("\n=== FK YAML CONTEXT ===\n")
            if reminder:
                parts.append(f"Discipline Reminder: {reminder}")
            if caveats:
                parts.append("Caveats (does_NOT_prove):")
                for c in caveats:
                    parts.append(f"  - {c}")

    parts.append("\n=== INSTRUCTIONS ===\n")
    parts.append(
        "You are a forensic knowledge base retriever. Search the FTS5 index\n"
        f"at ~/.cache/spectre/index.db for reference material about: {query}\n"
        "\n"
        "Use this command to search:\n"
        "  python3 -c \"\n"
        "  import sqlite3\n"
        "  conn = sqlite3.connect(str(Path.home() / '.cache' / 'spectre' / 'index.db'))\n"
        "  results = conn.execute(\n"
        "      \\\"SELECT poster_name, section_title, chunk_text, artifact_tags \\\"\n"
        "      \\\"FROM poster_fts WHERE poster_fts MATCH ? LIMIT ?\\\",\n"
        "      ('QUERY_HERE', LIMIT)\n"
        "  ).fetchall()\n"
        "  for r in results:\n"
        "      print(f'Src: {r[0]} | Section: {r[1]}')\n"
        "      print(f'Tags: {r[3]}')\n"
        "      print(r[2][:400])\n"
        "      print('---')\n"
        "  conn.close()\n"
        "  \"\n"
        "\n"
        "Also try LIKE queries on the chunks table for exact IOCs:\n"
        "  SELECT poster_name, section_title FROM chunks\n"
        "  WHERE chunk_text LIKE '%SEARCH_TERM%'\n"
        "\n"
        "Produce:\n"
        "1. Top {max_results} FTS5 results with source attribution\n"
        "2. Any matching LIKE results (exact IOC matches)\n"
        "3. Highlight any discipline reminders or caveats relevant to the query\n"
        "4. Note any gaps: if the KB has nothing relevant, say so\n"
        f"\nReturn at most {max_results} results.\n"
    )

    context = "\n".join(parts)

    goal = (
        f"Search the forensic knowledge base (FTS5 index) for reference "
        f"material about '{query}'"
        + (f" related to {artifact_type}" if artifact_type else "")
        + ". Return top results with source attribution, "
        "and highlight any relevant discipline reminders or caveats."
    )

    return {
        "goal": goal,
        "context": context,
        "toolsets": ["terminal", "file"],
    }


# ── Validation ───────────────────────────────────────────────────────

def validate_templates() -> dict[str, bool]:
    """
    Validate all three template builders produce valid delegate_task dicts.

    Returns: {"deep_dive": bool, "adversarial": bool, "kb_retriever": bool}
    """
    results = {}

    # Deep-dive
    try:
        dummy_finding = {
            "finding_id": "F-000-001",
            "status": "CONFIRMED",
            "confidence": 0.75,
            "title": "Test finding",
            "mitre_attack": "T1218.011",
            "tool": "test 1.0",
            "exact_command": "test --cmd",
            "evidence_refs": [{"execution_id": "abc123"}],
            "iocs": {"filepath": ["C:\\test.dll"]},
            "forensic_caveats": ["Test caveat"],
            "corroboration": {"sources": 2, "artifacts": ["EVTX 4688"]},
        }
        result = build_deep_dive_context(dummy_finding)
        assert "goal" in result, "Missing goal"
        assert "context" in result, "Missing context"
        assert "Do NOT create new findings" in result["context"], "Missing constraint"
        assert "VERBATIM" in result["context"], "Missing verbatim caveats instruction"
        results["deep_dive"] = True
    except Exception as e:
        print(f"Deep-dive validation FAILED: {e}")
        results["deep_dive"] = False

    # Adversarial
    try:
        result = build_adversarial_context(
            all_findings=[dummy_finding],
            artifact_profile="quick-triage",
            fk_blind_spots=["Prefetch does not prove file still exists"],
        )
        assert "goal" in result, "Missing goal"
        assert "context" in result, "Missing context"
        assert "DO NOT invent new findings" in result["context"], "Missing constraint"
        assert "DEVIL'S ADVOCATE" in result["context"], "Missing role framing"
        results["adversarial"] = True
    except Exception as e:
        print(f"Adversarial validation FAILED: {e}")
        results["adversarial"] = False

    # KB retriever
    try:
        result = build_kb_retriever_context(
            query="rundll32 T1218.011",
            artifact_type="evtx",
            phase="Phase 3",
        )
        assert "goal" in result, "Missing goal"
        assert "context" in result, "Missing context"
        assert "FTS5" in result["context"], "Missing FTS5 instruction"
        results["kb_retriever"] = True
    except Exception as e:
        print(f"KB retriever validation FAILED: {e}")
        results["kb_retriever"] = False

    return results


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Subagent template builder and validator")
    sub = parser.add_subparsers(dest="command")

    validate_p = sub.add_parser("validate", help="Validate all three template builders")
    validate_p.add_argument("--json", action="store_true", help="Output as JSON")

    show_p = sub.add_parser("show", help="Show a template (for inspection)")
    show_p.add_argument("template", choices=["deep-dive", "adversarial", "kb-retriever"])
    show_p.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.command == "validate":
        results = validate_templates()
        if hasattr(args, "json") and args.json:
            print(json.dumps(results, indent=2))
        else:
            all_ok = all(results.values())
            print(f"Validation: {'ALL PASS' if all_ok else 'FAILURES DETECTED'}")
            for name, ok in results.items():
                print(f"  {name}: {'PASS' if ok else 'FAIL'}")
            sys.exit(0 if all_ok else 1)

    elif args.command == "show":
        dummy = {
            "finding_id": "F-000-001",
            "status": "CONFIRMED",
            "confidence": 0.75,
            "title": "rundll32-from-temp: rundll32 loading DLL from Temp (parent: winword.exe)",
            "mitre_attack": "T1218.011",
            "tool": "spectre-core 0.1",
            "exact_command": "detect.py --rule rundll32-from-temp",
            "evidence_refs": [{"execution_id": "7f9926de949ff840..."}],
            "iocs": {"filepath": ["C:\\Windows\\Temp\\evil.dll"]},
            "forensic_caveats": [
                "Process creation (4688) proves the process was launched, not that the DLL is still on disk.",
                "A single 4688 is one source; corroborate with Prefetch/Amcache/MFT.",
            ],
            "corroboration": {"sources": 1, "artifacts": ["EVTX 4688: rundll32.exe PID 4521"]},
        }

        if args.template == "deep-dive":
            result = build_deep_dive_context(
                finding=dummy,
                fk_yaml_path=str(Path(__file__).parent.parent / "knowledge" / "artifacts" / "windows" / "evtx_4688.yaml"),
                cross_case_matches=[{
                    # WS8: filepath is filtered out by the specificity
                    # gate in _format_cross_case_matches() (too generic to
                    # ever reach a narrative) — sha256 is one of the three
                    # types that does. Demo reflects that filter.
                    "ioc_type": "sha256",
                    "value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "case": "002-e2e-test",
                    "finding_id": "F-000-001",
                    "date": "2026-06-27",
                }],
            )
        elif args.template == "adversarial":
            result = build_adversarial_context(
                all_findings=[dummy],
                artifact_profile="quick-triage",
                fk_blind_spots=["Prefetch does not prove file still exists"],
            )
        elif args.template == "kb-retriever":
            result = build_kb_retriever_context("rundll32", artifact_type="evtx", phase="Phase 3")

        if hasattr(args, "json") and args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"GOAL: {result['goal']}")
            print(f"\nCONTEXT ({len(result['context'])} chars):")
            print(result["context"][:2000])
            if len(result["context"]) > 2000:
                print(f"\n... ({len(result['context']) - 2000} more chars)")
            print(f"\nTOOLSETS: {result.get('toolsets', [])}")

    else:
        parser.print_help()
