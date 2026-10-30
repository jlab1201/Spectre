"""
emit_finding.py — create a finding from a detection anchor.

Steps:
  1. Write the finding_create (registration) audit row; evidence_refs cite
     the caller's source_execution_id (the extraction's tool_exec row)
  2. Source count (1 = EVTX-Security-4688 in spike)
  3. Status/confidence from source-count formula
  4. MITRE from anchor.candidate_mitre ∩ mitre-map
  5. Caveats from evtx_4688.yaml → does_NOT_prove (verbatim)
  6. Build Finding (full schema)
  7. Write F-{case_id}-NNN.yaml
  8. Append finding_status audit row
"""

import hashlib
import os
import yaml
from pathlib import Path
from datetime import datetime, timezone

from spectre.pipeline.audit import append as audit_append
from spectre.core.detect import Anchor


def _case_id_prefix(case_dir: Path) -> str:
    """Extract numeric case-id prefix from directory name.

    '004-new-mem' → '004'
    Falls back to '000' if unparseable.
    """
    try:
        return case_dir.name.split('-')[0]
    except (AttributeError, IndexError):
        return '000'


def _finding_filename(case_dir: Path, finding_counter: int) -> str:
    """Build finding filename: F-004-001.yaml"""
    return f"F-{_case_id_prefix(case_dir)}-{finding_counter:03d}"


def _finding_id_str(case_dir: Path, finding_counter: int) -> str:
    """Build finding ID: F-004-001"""
    return f"F-{_case_id_prefix(case_dir)}-{finding_counter:03d}"

# Source-count confidence formula (v6 plan)
SOURCE_TO_STATUS = {
    0: ("DROPPED", 0.0),
    1: ("INFERRED", 0.50),
    2: ("CONFIRMED", 0.75),
    3: ("CONFIRMED", 1.00),
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_yaml(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _load_mitre_map(mitre_path: str) -> dict:
    return _load_yaml(mitre_path)


def _get_allowed_mitre(mitre_map: dict, rule_id: str) -> list[str]:
    rules = mitre_map.get("rules", {})
    return rules.get(rule_id, {}).get("allowed", [])


def _source_count(records: list) -> int:
    """Count distinct artifact types. In the spike, always 1."""
    return 1  # single source


def emit(anchor: Anchor, case_dir: str, finding_counter: int,
         fk_yaml_path: str, mitre_map_path: str,
         case_id: str | None = None,
         source_execution_id: str = "") -> dict:
    """
    Create a finding from a detection anchor, write it to disk,
    and return the Finding dict.

    Args:
        case_id: Case identifier (e.g. "004-phase6-test"). If None,
                 derived from Path(case_dir).name.
        source_execution_id: entry_sha256 of the tool_exec row that produced
                 the anchor's data. It is the finding's evidence_ref; empty
                 means the source is unknown, and Phase 4 treats the ref
                 as unresolved.
    """
    case_dir = Path(case_dir)
    findings_dir = case_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    # Derive case_id from directory name if not explicitly provided
    if case_id is None:
        case_id = case_dir.name

    # Load FK YAML for caveats
    fk = _load_yaml(fk_yaml_path)
    caveats = fk.get("does_NOT_prove", [])

    # Load mitre map
    mitre_map = _load_mitre_map(mitre_map_path)
    allowed_mitre = _get_allowed_mitre(mitre_map, anchor.rule_id)

    # --- Step 1: Audit row for detection input ---
    entry = {
        "actor": "deterministic-core",
        "action": "finding_create",
        "tool": "spectre-core",
        "tool_version": "0.1",
        "exact_command": f"emit_finding.py emit(anchor, case_dir='{case_dir}', fk='{os.path.basename(fk_yaml_path)}') — Python function call, no CLI",
        "params": {"rule_id": anchor.rule_id, "record_number": anchor.record_number},
        "case_id": case_id,
        "output_path": str(findings_dir / f"{_finding_filename(case_dir, finding_counter)}.yaml"),
        "output_sha256": "",
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "finding_id": _finding_id_str(case_dir, finding_counter),
        "phase": 3,   # finding_create always Phase 3 (Detection)
        "phase_step": "S1-emit",
    }
    audit_append(str(case_dir), entry)

    # --- Step 2: Source count ---
    sources = _source_count([anchor])

    # --- Step 3: Status & confidence ---
    if sources > 3:
        sources = 3  # cap at max sources for the formula
    status, confidence = SOURCE_TO_STATUS.get(sources, ("INFERRED", 0.50))

    # --- Step 4: MITRE ---
    mitre = anchor.candidate_mitre[0] if anchor.candidate_mitre else "UNMAPPED"
    if mitre not in allowed_mitre:
        mitre = mitre_map.get("fallback", "UNMAPPED")

    # --- Step 5: Caveats (from FK YAML, verbatim) ---
    # discipline_reminder is separate — loaded at explain time

    # --- Step 6: Build Finding ---
    finding_id = _finding_id_str(case_dir, finding_counter)
    finding = {
        "finding_id": finding_id,
        "event_time": anchor.event.timestamp,  # Actual evidence time (from tcpdump/output)
        "timestamp": _utcnow(),  # Pipeline execution time (provenance)
        "status": status,
        "confidence": confidence,
        "corroboration": {
            "sources": sources,
            "artifacts": [
                f"EVTX 4688: {anchor.event.new_process_basename} (rec {anchor.record_number}), "
                f"parent {anchor.event.parent_basename}, dll {anchor.dll_path}"
            ],
        },
        "title": f"{anchor.rule_id} — rundll32 loading DLL from Temp (parent: {anchor.event.parent_basename})",
        "description": "",  # filled by explain.py
        "mitre_attack": mitre,
        "evidence_refs": [
            {"execution_id": source_execution_id, "source": "tool_exec"}
        ],
        "tool": "spectre-core 0.1",
        "exact_command": f"emit_finding.py emit(anchor, rule={anchor.rule_id!r}, dll={anchor.dll_path!r}) — module call, no CLI",
        "iocs": {
            "filepath": [anchor.dll_path] if anchor.dll_path else [],
            "sha256": [],
            "ip": [],
            "domain": [],
            "registry_key": [],
        },
        "forensic_caveats": caveats,
    }

    # --- Step 7: Write finding YAML ---
    finding_path = findings_dir / f"{finding_id}.yaml"
    with open(finding_path, "w") as f:
        yaml.dump(finding, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # The finding_create row above (Step 1) is written BEFORE this file
    # exists — and can't carry the file's hash anyway, since the finding's
    # own evidence_refs cites that row's entry_sha256 (see module
    # docstring: recording the file's hash there would be circular). This
    # finding_status row runs strictly after the file is on disk, so it can
    # (and does) carry the real content hash (A1-H1) — verify_full()'s
    # finding_integrity check takes the latest hash-bearing row per finding.
    try:
        finding_sha256 = hashlib.sha256(finding_path.read_bytes()).hexdigest()
    except OSError:
        finding_sha256 = ""

    # --- Step 8: finding_status audit row ---
    status_entry = {
        "actor": "deterministic-core",
        "action": "finding_status",
        "tool": "spectre-core",
        "tool_version": "0.1",
        "exact_command": "emit_finding.py emit() — finding_status audit row (module call, no CLI)",
        "params": {"finding_id": finding_id, "status": status, "confidence": confidence},
        "case_id": case_id,
        "output_path": str(finding_path),
        "output_sha256": finding_sha256,
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "finding_id": finding_id,
        "phase": 3,   # finding_status always Phase 3 (Detection)
        "phase_step": "S2-status",
    }
    audit_append(str(case_dir), status_entry)

    return finding


def get_next_finding_number(findings_dir: str) -> int:
    """Find the next available finding number by scanning existing files."""
    p = Path(findings_dir)
    if not p.exists():
        return 1
    # W4-5: retired (superseded/) and excluded IDs are never reused.
    existing = (list(p.glob("F-*-*.yaml")) + list(p.glob("excluded/F-*-*.yaml"))
                + list(p.glob("superseded/F-*-*.yaml")))
    if not existing:
        return 1
    nums = []
    for f in existing:
        try:
            nums.append(int(f.stem.split("-")[-1]))
        except (ValueError, IndexError):
            pass
    return max(nums) + 1 if nums else 1
