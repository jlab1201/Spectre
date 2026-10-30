"""Forensic blind spots: intake blind-spot lines, blindspots.md and the
"4. Forensic Blind Spots" section.
"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path

from spectre.pipeline.report_sections.common import (
    FULL_ARTIFACT_SET,
    RELEVANT_GAPS,
    _finding_rule_ids,
    _utcnow,
)
from spectre.pipeline.report_sections.intake import (
    _generate_intake_section,
    _module_extraction_status,
)


# ── Profile-specific blind spot questions ────────────────────────────
PROFILE_BLIND_SPOTS = {
    "pcap": [
        ("Was HTTP payload on port 443 plaintext (HTTP) or encrypted (TLS)?", "UNVERIFIED",
         "Full port 443 ASCII payload extraction needed"),
        ("Were DNS queries captured and analyzed for suspicious TLDs?", "UNVERIFIED",
         "DNS extraction pass needed for TLD and DGA analysis"),
        ("What was the data volume per external IP (exfiltration assessment)?", "UNVERIFIED",
         "Per-IP byte count analysis not performed"),
        ("Are there beacon patterns (regular intervals) from any monitored IP?", "UNVERIFIED",
         "Beacon timing analysis not performed"),
        ("Were TCP sessions completed (3-way handshake) or just SYN probes?", "UNVERIFIED",
         "TCP flag analysis not performed on all connections"),
    ],
    "memory": [
        ("Were injected processes or shellcode detected in memory?", "UNVERIFIED",
         "Memory injection analysis (malfind) not performed"),
        ("Were hidden or unlinked processes present?", "UNVERIFIED",
         "Process hiding detection (psscan vs pslist delta) not performed"),
    ],
}


# ── Gap-fill pass -> blind-spot question mapping (A11-08) ─────────────
# Maps a pcap `extract_pass` name (pcap/extract.py) to the
# PROFILE_BLIND_SPOTS["pcap"] question index(es) it would answer. When
# Phase 2 records that pass as skipped (manifest["extraction"]["results"]
# [*]["gap_fill_skipped"] — an optional gap-fill pass whose tool was
# unavailable this run, A10 Finding 3), the matching question(s) must say
# so explicitly: a named, KNOWN engine/tool limitation of THIS run, never
# the generic "not performed" boilerplate that reads like an ordinary
# scope decision (A11-08).
GAP_FILL_QUESTION_MAP: dict[str, dict[str, tuple[int, ...]]] = {
    "pcap": {
        "http": (0,),          # HTTP payload plaintext/TLS
        "dns": (1,),           # DNS queries / suspicious TLDs
        "connections": (2, 4),  # per-IP byte volume; TCP session completion
        "timing": (3,),        # beacon timing
        "checksum": (4,),      # TCP flag/checksum verification
    },
}


# Mirrors modules/disk/carve.py's _CARVE_CAP. Not imported — the pipeline
# stays generic over which module produced derived_evidence (host
# neutrality / module boundary); this is a report-side hint, not a shared
# constant, so a change to the disk module's cap doesn't silently break
# report rendering — only the caveat text below would need adjustment.
_CARVE_CAP_HINT = 200


def _forensic_gap_question(art_key: str, art_label: str) -> str:
    """Return a forensic question for a missing evidence type."""
    questions = {
        "evtx": "Were suspicious processes or logons recorded in Windows Event Logs?",
        "prefetch": "Were suspicious executables executed (Prefetch evidence)?",
        "amcache": "Were suspicious executables present on the system (Amcache)?",
        "mft": "Were files created, modified, or deleted during the incident window?",
        "registry": "Were persistence mechanisms installed in the Windows Registry?",
        "memory": "Were malicious processes or injected code resident in memory?",
        "pcap": "Was command-and-control traffic or data exfiltration observed?",
        "logfile": "Were suspicious requests or errors logged by applications?",
        "disk": "Were malicious files or artifacts present on disk?",
    }
    return questions.get(art_key, f"Was {art_label} evidence available for analysis?")


def _section_blind_spots(findings: list[dict], manifest: dict) -> list[str]:
    """4. Forensic Blind Spots."""
    lines = []

    # ── 4. Forensic Blind Spots ──
    lines.append("## 4. Forensic Blind Spots\n")

    # Case-specific intake blind spots (Track B): unrecognized files,
    # extractor-pending files, carve-cap hits — named, never boilerplate.
    intake_bsp_lines = _intake_blindspot_lines(manifest)
    if intake_bsp_lines:
        lines.append("**Case-specific intake blind spots:**\n")
        lines.extend(intake_bsp_lines)
        lines.append("")

    lines.append("| Question | Status | Why |")
    lines.append("|----------|--------|-----|")

    # ── Case-specific deterministic negatives (Track E3). Derived from the
    # findings the core produced, not a re-reading of raw data. ──
    _e3_mitre: set[str] = set()
    for f in findings:
        for part in str(f.get("mitre_attack", "")).split(","):
            part = part.strip()
            if part and part != "UNMAPPED":
                _e3_mitre.add(part)
    if "T1087.002" in _e3_mitre and "T1003.006" not in _e3_mitre:
        lines.append("| Was DCSync (credential replication) attempted? | NOT OBSERVED | "
                     "Active Directory account-enumeration activity was observed "
                     "(T1087.002) but no DCSync (T1003.006) finding fired; cannot rule out "
                     "credential replication outside the capture window. |")
    _e3_arts: set[str] = set()
    for art in manifest.get("artifacts", []) or []:
        if isinstance(art, str) and art:
            _e3_arts.add(art.split("_")[0])
    if len(_e3_arts) == 1:
        _e3_only = next(iter(_e3_arts))
        lines.append(f"| Corroboration across evidence types | LIMITED | Single evidence "
                     f"source ({_e3_only}); no independent evidence of a different type "
                     f"(endpoint/memory/disk/network) to corroborate these observations. |")

    # Per-artifact caveats from FK YAML — deduplicated by text
    seen_caveats: dict[str, list[str]] = {}  # caveat_text → [finding_ids]
    for finding in findings:
        fid = finding.get("finding_id", "?")
        for c in finding.get("forensic_caveats", []):
            seen_caveats.setdefault(c, []).append(fid)

    for caveat_text, fids in seen_caveats.items():
        if len(fids) <= 3:
            fid_ref = ", ".join(fids)
        else:
            fid_ref = f"{fids[0]} (+{len(fids)-1} findings)"
        lines.append(f"| (applies to {fid_ref}) | CAVEAT | {caveat_text} |")

    # Coverage gaps — filtered to relevant companion artifacts
    covered = set()
    profile_artifacts = manifest.get("artifacts", [])
    if isinstance(profile_artifacts, list) and profile_artifacts:
        for art in profile_artifacts:
            if isinstance(art, str):
                covered.add(art.lower())
    gate0 = manifest.get("gate_0", {})
    fk_loaded = gate0.get("fk_yamls_loaded", [])
    if isinstance(fk_loaded, list):
        for fk_name in fk_loaded:
            base = Path(str(fk_name)).stem
            covered.add(base.lower().replace("_4688", ""))

    # Determine relevant gap keys based on evidence present
    profile_name = manifest.get("artifact_profile", "").lower()
    relevant_keys = set()
    for art in covered:
        if art in RELEVANT_GAPS:
            relevant_keys.update(RELEVANT_GAPS[art])
    if profile_name in RELEVANT_GAPS:
        relevant_keys.update(RELEVANT_GAPS[profile_name])
    relevant_keys.update(covered)

    for art_key, art_label in sorted(FULL_ARTIFACT_SET.items()):
        if relevant_keys and art_key not in relevant_keys:
            continue
        if not any(art_key in c or c in art_key for c in covered):
            question = _forensic_gap_question(art_key, art_label)
            lines.append(f"| {question} | UNVERIFIED | {art_label} not available for analysis |")

    # Standard forensic gaps (evidence-aware)
    if any("pcap" in c for c in covered):
        lines.append("| Was data exfiltrated from the network? | UNVERIFIED | Full traffic content not inspected |")
    else:
        lines.append("| Was data exfiltrated? | UNVERIFIED | No network traffic capture available |")
    # W4-1 (R1-F2): INVESTIGATED only when that module's extraction
    # actually succeeded — a profile/FK entry is not an examination.
    _mem, _mem_nf = _module_extraction_status(manifest, "memory")
    _disk_ok = _module_extraction_status(manifest, "disk")[0]
    _disk_ok = None if _disk_ok is None else _disk_ok not in ("EXTRACTION_FAILED", "EMPTY")
    _log_ok = [v for v in (_module_extraction_status(manifest, "evtx")[0],
                           _module_extraction_status(manifest, "logfile")[0])
               if v is not None]
    _log_ok = (any(v not in ("EXTRACTION_FAILED", "EMPTY") for v in _log_ok)
               if _log_ok else None)
    if _mem == "EXTRACTION_FAILED":
        lines.append("| Are there additional malicious processes? | UNVERIFIED | Memory extraction failed — every tool run errored; nothing was examined |")
    elif _mem == "EMPTY":
        lines.append("| Are there additional malicious processes? | UNVERIFIED | Memory tools ran but parsed zero records; nothing was examined |")
    elif _mem == "PARTIAL":
        lines.append(f"| Are there additional malicious processes? | PARTIAL | Memory analysis performed, but {_mem_nf} tool run(s) failed; see findings |")
    elif any("memory" in c for c in covered):
        lines.append("| Are there additional malicious processes? | INVESTIGATED | Memory analysis performed; see findings |")
    else:
        lines.append("| Are there additional malicious processes? | UNVERIFIED | No memory dump available for process analysis |")
    if _disk_ok is False:
        lines.append("| Was file timestomping used? | UNVERIFIED | Disk extraction failed or parsed zero records — MFT timestamps not examined |")
    elif any("mft" in c for c in covered):
        lines.append("| Was file timestomping used? | INVESTIGATED | MFT timestamp analysis performed |")
    else:
        lines.append("| Was timestomping used? | UNKNOWN | No MFT data available for timestamp comparison |")
    if _log_ok is False:
        lines.append("| Were event logs cleared or tampered with? | UNVERIFIED | Log extraction failed or parsed zero records — nothing was examined |")
    elif any("evtx" in c or "logfile" in c for c in covered):
        lines.append("| Were event logs cleared or tampered with? | INVESTIGATED | Log gap analysis performed |")
    else:
        lines.append("| Were event logs cleared? | UNKNOWN | No event log data available for gap analysis |")
    lines.append("")

    lines.append("---")
    lines.append("")
    return lines


def _carve_cap_hits(manifest: dict) -> list[str]:
    """Parent evidence paths (images) whose carved derived-evidence count
    reached the disk module's carve cap (see _CARVE_CAP_HINT). A cap hit
    means nested-artifact carving (disk/carve.py) was truncated for that
    image — additional forensic artifacts may exist there, uncarved.
    Sourced from manifest["derived_evidence"] (Track B), the same dict
    _generate_intake_section already renders per-file."""
    derived = manifest.get("derived_evidence") or {}
    counts: dict[str, int] = defaultdict(int)
    for rec in derived.values():
        parent = (rec or {}).get("derived_from", "")
        if parent:
            counts[parent] += 1
    return sorted(p for p, n in counts.items() if n >= _CARVE_CAP_HINT)


def _intake_blindspot_lines(manifest: dict) -> list[str]:
    """Case-specific intake blind spots, named — never boilerplate.

    Surfaces unrecognized files, extractor-pending files (with the missing
    tool named), and carve-cap hits — all sourced from Track-B intake data
    already on the manifest (manifest["triage"], manifest["derived_evidence"]).
    Shared by both the in-report '## 4. Forensic Blind Spots' section and
    the standalone blindspots.md so the two never diverge.
    """
    lines: list[str] = []
    triage = manifest.get("triage") or {}
    unrecognized = sorted(
        os.path.basename(p) for p, r in triage.items()
        if (r or {}).get("status") == "UNRECOGNIZED"
    )
    pending = sorted(
        (os.path.basename(p), (r or {}).get("tool") or "?")
        for p, r in triage.items() if (r or {}).get("status") == "EXTRACTOR_PENDING"
    )
    if unrecognized:
        lines.append(
            "- **Unrecognized evidence** (no analyzer module claimed it — "
            "contents UNVERIFIED): " + ", ".join(f"`{n}`" for n in unrecognized)
        )
    if pending:
        lines.append(
            "- **Recognized but not extracted** (required tool unavailable "
            "— contents UNVERIFIED): "
            + ", ".join(f"`{n}` (requires `{t}`)" for n, t in pending)
        )
    # Derived/carved evidence is re-triaged in Phase 2, long after Phase 0,
    # and its status lands in extraction results rather than manifest
    # ["triage"] — so reading triage alone silently omits every carved
    # artifact we could not analyze. Keyed on derived_from so top-level
    # evidence, already covered by the triage-driven lines above, is not
    # double-reported.
    results = (manifest.get("extraction") or {}).get("results") or {}
    derived_skipped = sorted(
        (os.path.basename(p), r.get("derived_from") or "?",
         r.get("skipped") or "?", r.get("tool") or "")
        for p, r in results.items()
        if isinstance(r, dict) and r.get("skipped") and r.get("derived_from")
    )
    if derived_skipped:
        parts = []
        for name, parent, status, tool in derived_skipped:
            suffix = f" (requires `{tool}`)" if tool else ""
            parts.append(f"`{name}` from `{os.path.basename(parent)}` "
                         f"[{status}]{suffix}")
        lines.append(
            "- **Carved evidence not analyzed** (contents UNVERIFIED): "
            + ", ".join(parts)
        )
    # A module that failed to import contributes no recognizer and no rules,
    # so its evidence types silently stop being analyzed. registry only warns
    # to stderr, which reaches no report — disclose it here.
    from spectre.modules import registry as _registry
    _, load_errors = _registry.discover_with_errors()
    if load_errors:
        lines.append(
            "- **Analyzer module(s) failed to load** (evidence of these types "
            "was NOT analyzed): "
            + ", ".join(f"`{m}` ({e})" for m, e in sorted(load_errors.items()))
        )
    # Registered evidence that is no longer on disk. Not a triage nicety: the
    # audit chain charged a coverage_gap for it (recognize.py:135 sets MISSING),
    # and until now nothing rendered it, so the report was silent about
    # evidence it had been handed and could not find.
    missing = sorted(
        os.path.basename(p) for p, r in triage.items()
        if (r or {}).get("status") == "MISSING"
    )
    if missing:
        lines.append(
            "- **Registered evidence not found on disk** (nothing could be "
            "read from it — contents UNVERIFIED): "
            + ", ".join(f"`{n}`" for n in missing)
        )
    # Extraction that was attempted and failed. Its contents are exactly as
    # unverified as a file that was never opened — _coverage_counts already
    # counts these as not-examined, so leaving them out of Blind Spots made the
    # count and the named list disagree.
    errored = sorted(
        (os.path.basename(p), str(r.get("error"))[:120])
        for p, r in results.items()
        if isinstance(r, dict) and r.get("error") and not r.get("skipped")
    )
    if errored:
        lines.append(
            "- **Extraction failed** (attempted, did not complete — contents "
            "UNVERIFIED): "
            + ", ".join(f"`{n}` ({e})" for n, e in errored)
        )
    cap_hits = _carve_cap_hits(manifest)
    if cap_hits:
        lines.append(
            "- **Carve cap reached** (nested-artifact carving truncated at "
            f"{_CARVE_CAP_HINT} hits; additional artifacts may exist "
            "uncarved) in: "
            + ", ".join(f"`{os.path.basename(p)}`" for p in cap_hits)
        )
    return lines


def _gap_fill_skips(manifest: dict) -> list[dict]:
    """Every gap-fill-pass skip recorded during extraction (manifest
    ["extraction"]["results"][*]["gap_fill_skipped"] — see pcap/extract.py's
    _skip_marker() and phase_runner.py's Phase 2 loop, A10 Finding 3). A
    capability recorded here failed to run because its tool was unavailable
    THIS run — a KNOWN engine/tool limitation, not an ordinary scope
    decision (A11-08). Deduplicated by (extract_pass, tool) and returned in
    a stable sorted order so blindspots.md text never depends on dict/set
    iteration order.
    """
    results = (manifest.get("extraction") or {}).get("results") or {}
    seen: dict[tuple[str, str], dict] = {}
    for res in results.values():
        for skip in (res or {}).get("gap_fill_skipped") or []:
            key = (str(skip.get("extract_pass", "")), str(skip.get("tool", "")))
            seen.setdefault(key, skip)
    return [seen[k] for k in sorted(seen)]


def _max_corroboration_sources(findings: list[dict]) -> int:
    """Highest corroboration.sources value across findings. Missing or
    malformed corroboration is treated as 1 (single source) — never assumed
    multi-source, the same fail-safe direction as _is_cross_validated."""
    best = 0
    for f in findings:
        corr = f.get("corroboration") or {}
        sources = corr.get("sources")
        if isinstance(sources, (list, tuple, set)):
            sources = len(sources)
        if not isinstance(sources, (int, float)):
            sources = 1
        best = max(best, int(sources))
    return best


def _is_single_evidence_source_case(findings: list[dict]) -> bool:
    """True when this case never achieved genuine multi-source corroboration
    on ANY finding — WS2/WS3 made CONFIRMED require corroboration.sources
    >= 2 (two parsers/engines over the SAME evidence file collapse to one
    source; see correlation/__init__.py's _source_identity), so a case where
    sources never exceeds 1 is, by construction, single-evidence-source.
    Grounds the CONFIRMED->INFERRED reader-framing caveat in real per-run
    finding data instead of a hardcoded "single pcap" assumption. Empty
    findings list -> False (nothing to caveat)."""
    if not findings:
        return False
    return _max_corroboration_sources(findings) <= 1


# ── Blind spots generator ─────────────────────────────────────────────
def _generate_blindspots_md(
    findings: list[dict],
    manifest: dict,
    mitre_map: dict,
    fk_caveats_map: dict[str, list[str]],
    case_dir: str,
) -> str:
    """Generate case-specific blindspots.md."""
    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")

    lines = []
    lines.append(f"# Forensic Blind Spots — {case_id}-{case_name}\n")
    lines.append(f"Generated: {_utcnow()}\n")

    # ── Confidence framing: INFERRED vs CONFIRMED ─────────────────────
    # WS2/WS3 made CONFIRMED require genuine multi-source corroboration (2+
    # independent evidence sources — two parsers/engines reading the SAME
    # evidence file collapse to one source, not two). A case whose findings
    # never reach 2 sources is therefore ALL INFERRED even when the
    # detections themselves are strong — correct anti-fabrication behavior,
    # but a reader who equates INFERRED with "weak / nothing found"
    # misreads it. Only rendered when the actual finding data shows this
    # case never achieved multi-source corroboration — never boilerplate.
    if _is_single_evidence_source_case(findings):
        lines.append("## Confidence Framing: INFERRED vs CONFIRMED\n")
        lines.append(
            "Every finding in this case is labeled **INFERRED**, not "
            "CONFIRMED. This is not a weak or inconclusive result: "
            "CONFIRMED requires corroboration by 2+ genuinely independent "
            "evidence sources (two parsers/engines reading the SAME "
            "evidence file count as one source, not two), and this case "
            "had only one evidence source available. **INFERRED here means "
            "high-confidence single-source detection** — the per-finding "
            "confidence value (not the CONFIRMED/INFERRED label) reflects "
            "detection strength. Reaching CONFIRMED status would require "
            "corroborating these findings against a genuinely independent "
            "evidence source."
        )
        lines.append("")

    # Per-artifact caveats from FK YAML
    lines.append("## Per-Artifact Caveats\n")
    for finding in findings:
        fid = finding.get("finding_id", "?")
        caveats = finding.get("forensic_caveats", [])
        if caveats:
            lines.append(f"### {fid}\n")
            for c in caveats:
                lines.append(f"- {c}")
            lines.append("")

    # ── Unparseable timestamps (WS9) ────────────────────────────────
    # A finding whose source record's timestamp field failed to parse
    # (e.g. lnk/prefetch FILETIME overflow) is a blind spot in its own
    # right — the reader needs to know a record's event_time may be
    # absent not because nothing happened, but because the evidence
    # itself carried a corrupted/hostile/out-of-range timestamp. Driven
    # only by the deterministic `ts_parse_error` flag emit_finding.py
    # stamped from the normalizer's own NormEvent.data — never inferred
    # here.
    ts_parse_error_findings = [f for f in findings if f.get("ts_parse_error")]
    if ts_parse_error_findings:
        lines.append("## Unparseable Timestamps\n")
        lines.append(
            "The following finding(s) trace to a source record whose "
            "timestamp field could not be parsed (e.g. a FILETIME value "
            "out of representable range) — the record's timestamp is "
            "unparseable, not legitimately absent:\n"
        )
        for f in ts_parse_error_findings:
            lines.append(f"- {f.get('finding_id', '?')}")
        lines.append("")

    # Per-FK-YAML caveat sources
    lines.append("## FK YAML Caveat Sources\n")
    for art_type, caveats in sorted(fk_caveats_map.items()):
        lines.append(f"### {art_type}\n")
        for c in caveats:
            lines.append(f"- {c}")
        lines.append("")

    # Coverage gaps — derived from artifact profile, filtered to relevant companions
    lines.append("## Coverage Gaps\n")
    covered = set()
    profile_artifacts = manifest.get("artifacts", [])
    if isinstance(profile_artifacts, list) and profile_artifacts:
        for art in profile_artifacts:
            if isinstance(art, str):
                covered.add(art.lower())
    gate0 = manifest.get("gate_0", {})
    fk_loaded = gate0.get("fk_yamls_loaded", [])
    if isinstance(fk_loaded, list):
        for fk_name in fk_loaded:
            base = Path(str(fk_name)).stem
            covered.add(base.lower().replace("_4688", ""))

    # Determine which artifact types are relevant based on evidence present
    profile_name = manifest.get("artifact_profile", "").lower()
    relevant_keys = set()
    for art in covered:
        if art in RELEVANT_GAPS:
            relevant_keys.update(RELEVANT_GAPS[art])
    if profile_name in RELEVANT_GAPS:
        relevant_keys.update(RELEVANT_GAPS[profile_name])
    # Always include artifacts that ARE covered so they aren't flagged as gaps
    relevant_keys.update(covered)

    for art_key, art_label in sorted(FULL_ARTIFACT_SET.items()):
        # Only show gaps for artifacts relevant to this evidence type
        if relevant_keys and art_key not in relevant_keys:
            continue
        if not any(art_key in c or c in art_key for c in covered):
            lines.append(
                f"- **{art_label}**: not included in artifact profile. "
                f"Add '{art_key}' to the profile to enable this evidence source."
            )

    lines.append("")

    # ── Evidence intake (Track B1): unrecognized/pending files are gaps ──
    intake_md = _generate_intake_section(manifest)
    if intake_md:
        lines.append("")
        lines.append(intake_md)
        intake_bsp = _intake_blindspot_lines(manifest)
        if intake_bsp:
            lines.append("**Intake blind spots** (named, not boilerplate):\n")
            lines.extend(intake_bsp)
            lines.append("")

    # ── Profile-specific blind spot questions ─────────────────────────
    lines.append("## Evidence-Specific Blind Spots\n")

    # Which detection rules actually fired?  Rules that produced findings
    # mean the pipeline already assessed that question — flip from
    # UNVERIFIED to ASSESSED so the blind spot list doesn't contradict
    # the report body. `findings` loaded from disk never carry a `rule_id`
    # key (pipeline/emit_finding.py deliberately doesn't persist one on the
    # finding YAML — see `_finding_rule_ids`'s docstring); the only place
    # it survives past Phase 3 for a real case is
    # `manifest["detection"]["findings"]`. Using `_finding_rule_ids` (not a
    # bare `f.get("rule_id")`, which is always empty for real findings) is
    # what makes this override actually fire in production — A11-04's
    # exact contradiction (6 CONFIRMED pcap-dns-anomaly findings alongside
    # a static "DNS extraction pass needed") was this bug: the override
    # existed but its lookup key was never populated.
    fired_rules = set(_finding_rule_ids(findings, manifest).values())
    # ponytail: index-based mapping, add rule_id to tuple if ≥5 questions
    _ASSESSED_OVERRIDE: dict[str, dict[int, tuple[str, str]]] = {
        "pcap": {
            0: ("pcap-c2-protocol",
                "C2 protocol fingerprinting performed (see findings)"),
            1: ("pcap-dns-anomaly",
                "DNS queries extracted and analyzed for suspicious TLDs/DGA"),
            3: ("pcap-beacon",
                "Beacon timing analysis performed (see findings)"),
        },
    }

    # Gap-fill passes actually skipped this run (A11-08): named as a KNOWN
    # engine/tool limitation, never generic "not performed" boilerplate.
    gap_skips = _gap_fill_skips(manifest)

    profile_blind_spots_found = False
    for art in covered:
        if art in PROFILE_BLIND_SPOTS:
            profile_blind_spots_found = True
            lines.append(f"### {art.upper()} Analysis\n")
            overrides = _ASSESSED_OVERRIDE.get(art, {})
            gap_map = GAP_FILL_QUESTION_MAP.get(art, {})
            for i, (question, status, reason) in enumerate(PROFILE_BLIND_SPOTS[art]):
                ov = overrides.get(i)
                if ov and ov[0] in fired_rules:
                    status, reason = "ASSESSED", ov[1]
                else:
                    skip = next(
                        (s for s in gap_skips
                         if i in gap_map.get(s.get("extract_pass", ""), ())),
                        None,
                    )
                    if skip:
                        skip_tool = skip.get("tool", "?")
                        skip_pass = skip.get("extract_pass", "?")
                        skip_reason = skip.get("reason", "")
                        status = "KNOWN LIMITATION (this run)"
                        reason = (
                            f"`{skip_pass}` extraction pass did not run "
                            f"this run — {skip_tool} unavailable"
                            + (f" ({skip_reason})" if skip_reason else "")
                            + "; not a scope decision — rerun with the "
                              "tool available to assess this."
                        )
                lines.append(f"- **Q:** {question}\n")
                lines.append(f"  **Status:** {status} — {reason}\n")
            lines.append("")
    if not profile_blind_spots_found:
        lines.append("*No evidence-type-specific blind spot questions applicable.*\n")
    lines.append("")

    # Anti-forensics assessment
    lines.append("## Anti-Forensics Assessment\n")

    has_mft = any("mft" in c for c in covered)
    has_logfile = any("evtx" in c or "logfile" in c for c in covered)
    has_memory = any("memory" in c for c in covered)

    if has_mft:
        lines.append("- Timestomping: can be assessed via MFT timestamp anomalies")
    else:
        lines.append("- Timestomping: not assessed (no MFT data in profile)")

    if has_logfile:
        lines.append("- Log clearing: can be assessed via Security log gap analysis")
    else:
        lines.append("- Log clearing: not assessed (no Security log gap analysis)")

    if has_memory:
        lines.append("- Process hiding: can be assessed via cross-view detection (pslist vs psscan)")
    else:
        lines.append("- Process hiding: not assessed (no memory dump in profile)")

    lines.append(
        "- File deletion: not assessed (no MFT/USN journal to detect wiped entries)"
    )

    return "\n".join(lines) + "\n"
