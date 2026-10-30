"""
emit_finding.py — create a Spectre finding from a tool_runner handle.

Phase 3 hardened: evidence_refs[0].execution_id points directly to the
TOOL_EXEC row's entry_sha256, NOT to a finding_create row.

Usage:
    from emit_finding import emit_from_handle
    finding = emit_from_handle(
        handle=tool_runner.run_tool(...),
        case_dir="/path/to/case",
        anchor=detection_anchor,
        fk_yaml_path="/path/to/fk_yaml.yaml",
        mitre_map_path="/path/to/mitre-map.yaml",
    )
"""

import hashlib
import os
import yaml
from pathlib import Path
from datetime import datetime, timezone

from spectre.pipeline.audit import append as audit_append


# Source-count confidence formula
SOURCE_TO_STATUS = {
    0: ("DROPPED", 0.0),
    1: ("INFERRED", 0.50),
    2: ("CONFIRMED", 0.75),
    3: ("CONFIRMED", 1.00),
}


def _case_id_prefix(case_dir: Path) -> str:
    """Extract numeric case-id prefix from directory name.

    '004-new-mem' → '004'
    '017-cmdlog-test' → '017'
    Falls back to '000' if unparseable.
    """
    try:
        return case_dir.name.split('-')[0]
    except (AttributeError, IndexError):
        return '000'


def _finding_filename(case_dir: Path, finding_number: int) -> str:
    """Build finding filename: F-004-001.yaml"""
    return f"F-{_case_id_prefix(case_dir)}-{finding_number:03d}"


def _finding_id(case_dir: Path, finding_number: int) -> str:
    """Build finding ID: F-004-001"""
    return f"F-{_case_id_prefix(case_dir)}-{finding_number:03d}"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_yaml(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _get_allowed_mitre(mitre_map: dict, rule_id: str) -> list[str]:
    rules = mitre_map.get("rules", {})
    return rules.get(rule_id, {}).get("allowed", [])


def _has_map_entry(mitre_map: dict, rule_id: str) -> bool:
    return rule_id in mitre_map.get("rules", {})


def emit_from_handle(
    handle: dict,
    case_dir: str,
    finding_number: int,
    fk_yaml_path: str,
    mitre_map_path: str,
    rule_id: str,
    title: str,
    iocs: dict | None = None,
    event_time: str = None,  # Actual evidence timestamp (from NormEvent.timestamp)
    canary_status: str = "FULL",
    corroboration_note: str = "",
    source_record_id: str = "",      # A1-M1: record/offset within the raw_extract file
    source_file: str = "",           # A1-M1: evidence file this finding traces back to
    rule_origin: str = "deterministic",
    analyst_excluded: str | None = None,
    analyst_priority: str | None = None,
    sources: int | None = None,
    corroboration_labels: list[str] | None = None,
    extra_evidence_refs: list[dict] | None = None,
    confidence: float | None = None,       # Rule-level confidence (preserved when set)
    mitre: list[str] | None = None,         # Rule-level MITRE (preserved when set)
    host_ip: str | None = None,             # Monitored machine (NormEvent.host); "" if unknown
    occurrence_count: int | None = None,    # how many anchors collapsed here
    first_seen: str | None = None,          # earliest member timestamp
    last_seen: str | None = None,           # latest member timestamp
    ts_caveat: str = "",             # WS9: verbatim NormEvent.data["ts_caveat"] set by a
                                      # normalizer (lnk/prefetch FILETIME overflow, logfile
                                      # syslog year/tz ambiguity) — never authored here, only
                                      # relayed into forensic_caveats so it isn't dropped.
    ts_parse_error: bool = False,    # WS9: NormEvent.data["ts_parse_error"] — the source
                                      # record's timestamp field failed to parse (distinct
                                      # from a legitimately-absent timestamp).
    process_refs: list[dict] | None = None,  # W5-3: {pid, image, host, start_time}
                                      # read off the group's NormEvents by
                                      # correlation.process — a correlation
                                      # key only (never an IOC / MITRE).
) -> dict:
    """
    Create a finding from a tool_runner handle.

    Args:
        handle: tool_runner.run_tool() return value (has execution_id = tool_exec sha256)
        case_dir: Path to case directory
        finding_number: Auto-incrementing number (e.g., 1, 2, 3)
        fk_yaml_path: Path to FK YAML for caveats
        mitre_map_path: Path to MITRE map YAML
        rule_id: Detection rule ID (for MITRE lookup)
        title: Finding title
        iocs: Dict of IOCs {sha256: [...], ip: [...], domain: [...], filepath: [...], registry_key: [...]}
        canary_status: "FULL" | "DEGRADED" — from canary.py

    Returns:
        Finding dict matching the Spectre finding schema.
    """
    case_dir = Path(case_dir)
    findings_dir = case_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    # Load FK YAML for caveats
    fk = _load_yaml(fk_yaml_path)
    caveats = list(fk.get("does_NOT_prove", []))
    # Directed findings carry an extra caveat: a match confirms the requested
    # pattern is present, not that it is significant.
    if rule_origin == "user_directed":
        caveats.append(
            "Produced by analyst direction, not a baseline rule; confirms the "
            "requested pattern is present, not its significance — corroborate "
            "before treating as CONFIRMED.")

    # WS9: a normalizer-produced per-record timestamp caveat (FILETIME
    # overflow in lnk/prefetch, syslog year/timezone ambiguity in logfile)
    # is relayed verbatim — never invented here — and deduped against
    # whatever FK/rule_origin caveats already made the list.
    if ts_caveat and ts_caveat not in caveats:
        caveats.append(ts_caveat)

    # Load MITRE map
    mitre_map = _load_yaml(mitre_map_path)
    allowed_mitre = _get_allowed_mitre(mitre_map, rule_id)

    # ── evidence_refs: point to TOOL_EXEC row, NOT finding_create ──
    # handle["execution_id"] IS the tool_exec audit row entry_sha256
    tool_exec_id = handle.get("execution_id", "")
    evidence_refs = [{"execution_id": tool_exec_id, "source": "tool_exec"}]
    # Corroborating sources (e.g. a second engine that detected the same claim)
    # each contribute their own tool_exec row to the chain of custody.
    seen_ids = {tool_exec_id}
    for ref in (extra_evidence_refs or []):
        eid = ref.get("execution_id", "")
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            evidence_refs.append({"execution_id": eid, "source": "tool_exec"})

    # Source count: caller (correlation layer) may pass a count derived from how
    # many distinct sources asserted the same claim. Otherwise fall back to the
    # single-source default (data present → 1).
    has_data = handle.get("line_count", 0) > 0 or handle.get("size_bytes", 0) > 0
    if sources is None:
        sources = 1 if has_data else 0

    # Status & confidence — rule-level confidence VALUES are preserved when
    # provided by the detection rule (the rule's own domain judgment about
    # signal strength). STATUS, however, is always gated by genuine source
    # corroboration (WS2/A4-02 fix): `Anchor.confidence` defaults to 0.5
    # (core/base.py — never None), so every real per-rule anchor took this
    # branch and CONFIRMED vs INFERRED was effectively decided by a
    # hardcoded rule-author threshold (mostly 0.6), NOT by whether the claim
    # was independently corroborated. That let a SINGLE-source finding carry
    # the report's "CONFIRMED (multi-source)" badge. CONFIRMED now requires
    # sources >= 2 (WS3's honest per-claim source count from
    # correlation.corroborate()) regardless of the rule's own confidence
    # number; a single source is always INFERRED (or DROPPED at 0 sources),
    # never CONFIRMED, no matter how confident the rule's predicate was in
    # its own signal.
    if confidence is not None:
        # Rule explicitly set confidence (e.g. 0.7 for outbound C2, 0.4 for
        # inbound scanning). Preserve the rule's domain judgment as the
        # numeric score; the CONFIRMED/INFERRED label is corroboration-gated.
        if sources <= 0:
            status = "DROPPED"
        elif sources >= 2:
            status = "CONFIRMED"
        else:
            status = "INFERRED"
    else:
        capped = min(sources or 1, 3)
        status, confidence = SOURCE_TO_STATUS.get(capped, ("INFERRED", 0.50))

    # MITRE — the map regains authority here: when the rule has a map entry,
    # the rule-emitted techniques are INTERSECTED with that entry's allowed
    # list. Any technique the rule asserted but the map doesn't recognize is
    # dropped — loudly, as a forensic_caveat, never silently. An empty
    # intersection falls back to allowed[0] (today's behavior).
    #
    # A rule_id with NO map entry at all has zero reviewer-approved
    # authority behind whatever it self-declares (A5 Finding 1): Sigma
    # import sets rule_id = slug(title) and reads `mitre` straight from the
    # imported rule's own `tags:` field, and Direction directives use
    # per-case dir-NNN IDs — both, BY CONSTRUCTION, can never appear in
    # mitre-map.yaml. The old "legacy passthrough" branch let either one
    # stamp any technique ID it wanted on a finding regardless of what was
    # actually detected (PoC: a benign notepad.exe match self-declaring
    # T1003.006 / DCSync reached mitre_attack unfiltered end-to-end). No
    # map entry now means the techniques are QUARANTINED to the map's
    # fallback (UNMAPPED) — never asserted — with a loud caveat naming
    # exactly what was dropped and why.
    # Always normalize to a string for downstream consumers (report, grouping).
    has_map_entry = _has_map_entry(mitre_map, rule_id)
    fallback_mitre = mitre_map.get("fallback", "UNMAPPED")
    if mitre:
        if has_map_entry:
            kept = [t for t in mitre if t in allowed_mitre]
            dropped = [t for t in mitre if t not in allowed_mitre]
            for tid in dropped:
                caveats.append(
                    f"MITRE {tid} emitted by rule but not in mitre-map "
                    f"allowed list — dropped"
                )
            if kept:
                mitre_attack = ", ".join(kept)
            else:
                mitre_attack = allowed_mitre[0] if allowed_mitre else fallback_mitre
        else:
            # No map entry for this rule_id at all — quarantine, don't trust.
            caveats.append(
                f"Rule '{rule_id}' declared MITRE {', '.join(mitre)} but has "
                f"no mitre-map.yaml authority (no map entry for this "
                f"rule_id) — not asserted; techniques from rules without a "
                f"reviewed map entry are quarantined to {fallback_mitre}."
            )
            mitre_attack = fallback_mitre
    else:
        mitre_attack = allowed_mitre[0] if allowed_mitre else fallback_mitre

    # Build finding
    finding_id = _finding_id(case_dir, finding_number)
    finding = {
        "finding_id": finding_id,
        "status": status,
        "confidence": confidence,
        "corroboration": {
            "sources": sources,
            "tools": corroboration_labels or [],
            "artifacts": [
                corroboration_note if corroboration_note else
                f"Tool: {handle.get('tool', 'unknown')} — "
                f"output: {handle.get('path', '')} "
                f"({handle.get('line_count', 0)} lines)"
            ],
        },
        "cross_validated": sources >= 2,
        "title": title,
        "description": "",  # filled by explain layer
        "mitre_attack": mitre_attack,
        "evidence_refs": evidence_refs,
        "source_record_id": source_record_id,  # A1-M1: which record/offset in raw_extract
        "source_file": source_file,            # A1-M1: which evidence file it traces to
        "tool": f"{handle.get('tool', 'unknown')} {handle.get('tool_version', '')}",
        "exact_command": handle.get("exact_command", ""),
        "iocs": iocs or {
            "sha256": [],
            "ip": [],
            "domain": [],
            "filepath": [],
            "registry_key": [],
            "host": [],
            "account": [],
        },
        "forensic_caveats": caveats,
        "host_ip": host_ip or "",  # Monitored machine; always present, "" if unknown
        "canary_status": canary_status,  # Phase 3: FULL or DEGRADED
        "empty_data_status": handle.get("empty_data_status", "UNKNOWN"),  # Phase 3
        "rule_origin": rule_origin,  # "deterministic" | "user_directed"
        "event_time": event_time or "",  # Actual evidence time; empty if the
                                          # artifact carries none — NEVER
                                          # stamped with analysis run-time.
        "occurrence_count": occurrence_count if occurrence_count is not None else 1,
        "first_seen": first_seen if first_seen is not None else (event_time or ""),
        "last_seen": last_seen if last_seen is not None else (event_time or ""),
        "timestamp": _utcnow(),
    }
    # WS9: only stamped when True, mirroring how normalize.py itself only
    # sets NormEvent.data["ts_parse_error"] when a timestamp actually failed
    # to parse — its absence here means "not known to have failed", same as
    # its absence from a normalized record.
    if ts_parse_error:
        finding["ts_parse_error"] = True
    # W5-3: only stamped when present, so findings from evidence with no
    # process identity (pcap, registry, ...) are byte-identical to before.
    if process_refs:
        finding["process_refs"] = [dict(r) for r in process_refs]

    # Analyst-directed scoping (non-destructive — finding is retained, tagged).
    if analyst_excluded:
        finding["analyst_excluded"] = True
        finding["excluded_by"] = analyst_excluded
    if analyst_priority:
        finding["analyst_priority"] = "HIGH"
        finding["boosted_by"] = analyst_priority

    # ── Write finding YAML FIRST, so the audit row below can record its
    # REAL content hash instead of the old hardcoded "" (A1-H1: an empty
    # output_sha256 meant verify_full() never re-hashed finding YAMLs, so a
    # post-creation edit — status, confidence, MITRE ID, deleted caveats —
    # was invisible). Excluded findings are RETAINED (never deleted) in a
    # parallel subdir so a reviewer can always see what analyst direction
    # scoped out, and why. ──
    if analyst_excluded:
        out_dir = findings_dir / "excluded"
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = findings_dir
    finding_path = out_dir / f"{finding_id}.yaml"
    finding_yaml_bytes = yaml.dump(
        finding, default_flow_style=False, sort_keys=False, allow_unicode=True
    ).encode("utf-8")
    with open(finding_path, "wb") as f:
        f.write(finding_yaml_bytes)
    finding_sha256 = hashlib.sha256(finding_yaml_bytes).hexdigest()

    # ── Write finding_create audit row (provenance entry, NOT evidence_ref) ──
    audit_entry = {
        "actor": "deterministic-core",
        "action": "finding_create",
        "tool": "emit_finding.py",
        "tool_version": "2.0",
        "exact_command": f"emit_from_handle(handle.execution_id={tool_exec_id[:16]}...)",
        "params": {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "tool_exec_id": tool_exec_id,
            "sources": sources,
            "confidence": confidence,
            "status": status,
            "canary_status": canary_status,
        },
        "case_id": case_dir.name,
        "output_path": str(finding_path),
        "output_sha256": finding_sha256,
        "output_format": "yaml",
        "output_line_count": finding_yaml_bytes.decode("utf-8").count("\n"),
        "output_size_bytes": len(finding_yaml_bytes),
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "stderr": "",
        "finding_id": finding_id,
        "phase": 3,   # finding_create always Phase 3 (Detection)
        "phase_step": "S1-emit",
    }
    audit_append(str(case_dir), audit_entry)

    return finding


def get_next_finding_number(findings_dir: str) -> int:
    """Find the next available finding number (per-case, new format F-NNN-NNN.yaml).

    Also accepts old format F-SPECTRE-NNN.yaml for backward compatibility.
    """
    p = Path(findings_dir)
    if not p.exists():
        return 1
    # W4-5: excluded/ and superseded/ IDs are taken too — a re-run must
    # never reuse the ID of a retired finding.
    existing = (list(p.glob("F-*-*.yaml")) + list(p.glob("excluded/F-*-*.yaml"))
                + list(p.glob("superseded/F-*-*.yaml")))
    if not existing:
        return 1
    nums = []
    for f in existing:
        try:
            # Extract last segment: F-004-001 → 1, F-SPECTRE-037 → 37
            nums.append(int(f.stem.split("-")[-1]))
        except (ValueError, IndexError):
            pass
    return max(nums) + 1 if nums else 1


def supersede_prior_findings(case_dir: str, reason: str, run_id: str = "",
                             dry_run: bool = False) -> dict:
    """W4-5 (R2-18): retire every registered finding before a Phase-3
    re-run emits afresh, so the re-run does not duplicate them.

    Each active (findings/) or excluded (findings/excluded/) finding is moved,
    bytes unchanged, into findings/superseded/, after ONE chained
    ``finding_supersede`` row (step S3-supersede, carrying ``run_id``) that
    records its content hash at the new location. The row is honoured only
    inside this run's Phase-3 bracket (validators.supersede_brackets).

    All-or-nothing and fail-closed (``problems`` non-empty → nothing moved):
    - a registered finding whose bytes no longer match its recorded hash, or
      that has non-authority hash rows (never re-bless a tampered finding);
    - a registered finding whose file is missing from its bound location —
      moved or deleted by hand (W4 review LOW: refuse loudly, not skip).
    A row written whose move never landed (crash) is completed.
    Unregistered files are left in place for verify_full to flag.

    Returns {"superseded": [ids], "problems": [str]}.
    """
    from spectre.core.validators import finding_registry

    case = Path(case_dir)
    fdir = case / "findings"
    registry = finding_registry(case, include_open=True)
    todo, problems = [], []
    for fid, info in sorted(registry.items()):
        if not info.get("baseline"):
            continue
        loc = info.get("location") or ""
        if not loc:  # legacy registration row without a bound location
            cands = [p for p in (fdir / f"{fid}.yaml", fdir / "excluded" / f"{fid}.yaml")
                     if p.is_file()]
            if not cands:
                continue
            loc_path = cands[0]
        else:
            loc_path = fdir / loc
        if info.get("foreign_hash_rows"):
            problems.append(f"{fid}: non-authority rows carry a content hash")
            continue
        if info.get("superseded"):
            if loc_path.is_file():
                continue  # already retired
            old = fdir / (info.get("registered_location") or f"{fid}.yaml")
            if old.is_file() and not old.is_symlink():
                sha = hashlib.sha256(old.read_bytes()).hexdigest()
                if sha == info["baseline"]:
                    todo.append((old, loc_path, sha, True))  # interrupted move
                    continue
            problems.append(f"{fid}: retired to findings/{loc} but that file is "
                            f"missing (moved or deleted by hand)")
            continue
        if not loc_path.is_file() or loc_path.is_symlink():
            problems.append(f"{fid}: registered at findings/{loc or fid + '.yaml'} "
                            f"but the file is missing there (moved or deleted by hand)")
            continue
        sha = hashlib.sha256(loc_path.read_bytes()).hexdigest()
        if sha != info["baseline"]:
            problems.append(f"{fid}: content hash {sha[:12]}… does not match "
                            f"the recorded {info['baseline'][:12]}… (possible tamper)")
            continue
        todo.append((loc_path, fdir / "superseded" / loc_path.name, sha, False))
    if problems or dry_run:
        return {"superseded": [], "problems": problems}

    done = []
    for src, dest, sha, interrupted in todo:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            return {"superseded": done,
                    "problems": [f"{src.stem}: findings/superseded/{dest.name} already exists"]}
        if not interrupted:
            # Audit row BEFORE the file moves (methodology order); a crash
            # between the two is completed by the next call (interrupted).
            audit_append(str(case), {
                "actor": "deterministic-core",
                "action": "finding_supersede",
                "tool": "emit_finding.supersede_prior_findings",
                "tool_version": "1.1",
                "exact_command": "supersede_prior_findings() — Phase 3 re-run",
                "params": {"finding_id": src.stem, "reason": reason,
                           "run_id": run_id,
                           "from": src.parent.name if src.parent != fdir else "findings"},
                "case_id": case.name,
                "output_path": str(dest),
                "output_sha256": sha,
                "result": "success",
                "exit_code": 0,
                "duration_ms": 0,
                "finding_id": src.stem,
                "phase": 3,
                "phase_step": "S3-supersede",
            })
        os.replace(src, dest)
        done.append(src.stem)
    return {"superseded": done, "problems": []}
