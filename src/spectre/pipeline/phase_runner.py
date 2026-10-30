#!/usr/bin/env python3
"""
phase_runner.py — Single-phase runner for the Spectre 7-phase pipeline.

Runs one phase at a time against a case directory, checking quality gates
before proceeding. Useful for mentor review between phases.

Usage:
    phase_runner.py --case ~/cases/004-phase6-test --phase 0   # setup (re-runs canary+manifest)
    phase_runner.py --case ~/cases/004-phase6-test --phase 1   # direction (synthesize directives)
    phase_runner.py --case ~/cases/004-phase6-test --phase 2   # extraction
    phase_runner.py --case ~/cases/004-phase6-test --phase 3   # detection + hypothesis
    phase_runner.py --case ~/cases/004-phase6-test --phase 4   # correlation + verification
    phase_runner.py --case ~/cases/004-phase6-test --phase 5   # adversarial review
    phase_runner.py --case ~/cases/004-phase6-test --phase 6   # synthesis + report

Phase 0 is handled by case_setup.py — this script invokes it.
Phases 1-6 are implemented here.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Paths ──────────────────────────────────────────────────────────
from spectre.config import (
    KNOWLEDGE_DIR, FK_WINDOWS_DIR, FK_DIRS,
    MITRE_MAP_PATH, RAW_DIR,
)
from spectre.pipeline import console
from spectre.pipeline.fk_routing import artifact_fk_files
SCRIPTS_DIR = Path(__file__).parent  # kept for local script references
FK_DIR = FK_WINDOWS_DIR
# Fixtures moved from spike/ to tests/fixtures/ in the spectre-forensic repo
from spectre.config import _PACKAGE_ROOT
FIXTURE_DIR = _PACKAGE_ROOT.parent.parent / "tests" / "fixtures"
FIXTURE_PATH = FIXTURE_DIR / "case-000.events.json"
TRUTH_PATH = FIXTURE_DIR / "case-000-truth.yaml"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _derived_skip_note(status: str | None, artifact_type: str | None) -> str:
    """Human-readable reason a carved artifact was not extracted.

    One renderer, so no call site invents wording for a status it does not
    know. The previous inline else-branch labelled EVERY non-pending status
    "not claimed by any module", which is false for anything but a genuine
    no-claim — an unknown status now names itself instead.
    """
    if status == "EXTRACTOR_PENDING":
        return (f"recognized as {artifact_type} but required tool "
                f"is unavailable")
    if status in (None, "", "UNRECOGNIZED"):
        return "no analyzer module claimed this carved file"
    return f"not extracted (status {status})"


def _disclosed_coverage_gaps(manifest: dict) -> list[dict]:
    """The coverage disclosures the report carries, as a compact receipt.

    Wrapped rather than called inline so a failure to compute it degrades to an
    EMPTY receipt instead of taking down the Phase 6 report write. That
    direction is deliberate and it is the safe one: an empty receipt makes
    verify_full()'s coverage_disclosure check FAIL closed whenever the chain
    holds gaps, so the visible outcome of a bug here is a loud verification
    failure, never a case that quietly verifies as fully disclosed.
    """
    try:
        from spectre.pipeline.coverage import disclosed_from_manifest
        return disclosed_from_manifest(manifest)
    except Exception as e:  # pragma: no cover - defensive
        print(f"  ⚠ coverage disclosure receipt not computed: {e}",
              file=sys.stderr)
        return []


def _load_manifest(case_dir: str) -> dict:
    """Load case manifest.yaml."""
    mp = Path(case_dir) / "manifest.yaml"
    if not mp.exists():
        print(json.dumps({"error": f"No manifest at {mp}", "success": False}))
        sys.exit(1)
    with open(mp) as f:
        return yaml.safe_load(f)


def _save_manifest(manifest: dict, case_dir: str):
    """Save updated manifest."""
    mp = Path(case_dir) / "manifest.yaml"
    with open(mp, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)


def _phase_gate_passed(manifest: dict, phase: int) -> bool:
    """Check if the gate for a given phase passed."""
    gate_key = f"gate_{phase}"
    gate = manifest.get(gate_key, {})
    return gate.get("passed", False)


def gate_6_passed(gate: dict) -> bool:
    """Assemble Gate 6 from the signals the gate record already carries.

    Integrity failures fail closed (missing report, unexported IOCs, empty
    blindspots, a verdict contradicting the deterministic class, or an LLM
    that ran and produced nothing). Availability failures degrade: when the
    LLM was unavailable, the deterministic baseline report still passes.

    `verdict_class_consistent` fails CLOSED on absence: a gate record that
    never recorded the signal has not been checked, and "not checked" is not
    "passed". Note the key being present and True is a weaker claim than it
    looks on the deferred host path — see the known-gap note in the plan.
    """
    structural = (
        bool(gate.get("report_exists"))
        and bool(gate.get("iocs_exported"))
        and bool(gate.get("blindspots_populated"))
    )
    if not structural:
        return False
    if not gate.get("verdict_class_consistent", False):
        return False
    if gate.get("llm_used") and not gate.get("narrative_complete"):
        return False
    # R1-G3/F13: computed now (was hardcoded True). A record without the
    # key predates the computation and is not treated as a failure.
    if gate.get("mitre_map_complete") is False:
        return False
    return True


def _mitre_map_complete(findings: list[dict], mitre_map: dict,
                        case_dir=None) -> tuple[bool, list[str]]:
    """Every finding's MITRE IDs must lie inside its own rule's mitre-map
    allowed set (validators.allowed_mitre_for_finding — the rule comes
    from the finding_create row when case_dir is given). UNMAPPED/empty is
    always complete. Returns (ok, offending finding IDs)."""
    from spectre.core.validators import (
        UNMAPPED, allowed_mitre_for_finding, parse_mitre_ids)
    bad = []
    for f in findings:
        emitted = [t for t in parse_mitre_ids(f.get("mitre_attack")) if t != UNMAPPED]
        if not emitted:
            continue
        allowed = {a.upper() for a in allowed_mitre_for_finding(f, mitre_map, case_dir)}
        if any(t.upper() not in allowed for t in emitted):
            bad.append(str(f.get("finding_id", "?")))
    return (not bad), bad


def invalidate_later_gates(manifest: dict, phase: int,
                           include_self: bool = False) -> list[int]:
    """W4-3 (R1-F6): re-running phase k makes every later phase's output
    stale (a Phase-5 re-run after Phase 6 left the report describing a
    review it never saw). Mark gates k+1..7 not passed so a resume re-runs
    them. Phase 0 is a pure gate check and invalidates nothing. Returns the
    gate numbers invalidated."""
    if phase <= 0:
        return []
    now = _utcnow()
    hit = []
    for j in range(phase if include_self else phase + 1, 8):
        gate = manifest.get(f"gate_{j}")
        if isinstance(gate, dict) and gate.get("passed"):
            manifest[f"gate_{j}"] = {"passed": False,
                                     "invalidated_by_phase": phase,
                                     "invalidated_at": now}
            hit.append(j)
    if hit:
        manifest.setdefault("gates_invalidated", []).append(
            {"by_phase": phase, "gates": hit, "at": now})
    return hit


def _phase3_open_bracket(case_dir: str) -> dict:
    """Chain a `phase3_run_start` row (W4 review MED-1/LOW). Any earlier run
    that started but never completed (a crash mid re-run) is recorded in
    `closes`, so this run's completion row closes its supersede batch."""
    import uuid
    from spectre.core.validators import RUN_START, RUN_COMPLETE, _key, _read_audit_rows
    from spectre.pipeline.audit import append as audit_append
    rows = _read_audit_rows(case_dir)
    started = [str((r.get("params") or {}).get("run_id") or "")
               for r in rows if _key(r) == RUN_START]
    done = set()
    for r in rows:
        if _key(r) == RUN_COMPLETE:
            p = r.get("params") or {}
            done.add(str(p.get("run_id") or ""))
            done.update(str(c) for c in (p.get("closes") or []))
    run = {"run_id": uuid.uuid4().hex,
           "closes": [r for r in dict.fromkeys(started) if r and r not in done]}
    audit_append(case_dir, {
        "actor": RUN_START[0], "action": RUN_START[1], "phase_step": RUN_START[2],
        "tool": "phase_runner._run_phase_3_live", "tool_version": "1.0",
        "exact_command": "Phase 3 run start (supersede bracket)",
        "params": dict(run), "case_id": Path(case_dir).name,
        "result": "success", "exit_code": 0, "duration_ms": 0, "phase": 3})
    return run


def _phase3_close_bracket(case_dir: str, run: dict, emitted: int) -> None:
    from spectre.core.validators import RUN_COMPLETE
    from spectre.pipeline.audit import append as audit_append
    audit_append(case_dir, {
        "actor": RUN_COMPLETE[0], "action": RUN_COMPLETE[1],
        "phase_step": RUN_COMPLETE[2],
        "tool": "phase_runner._run_phase_3_live", "tool_version": "1.0",
        "exact_command": "Phase 3 run complete (supersede bracket)",
        "params": {**run, "findings_emitted": emitted},
        "case_id": Path(case_dir).name,
        "result": "success", "exit_code": 0, "duration_ms": 0, "phase": 3})


def unfinished_phase3_reruns(case_dir: str) -> list[str]:
    """Problems that make any report unsafe: a supersede batch whose
    Phase-3 re-run never completed, or a supersede row outside any
    bracket (W4 review MED-1/LOW)."""
    from spectre.core.validators import _read_audit_rows, supersede_brackets
    rows = _read_audit_rows(case_dir)
    br = supersede_brackets(rows)
    out = []
    for i in sorted(br["open"]):
        out.append(f"{rows[i].get('finding_id')}: superseded by Phase-3 run "
                   f"{(rows[i].get('params') or {}).get('run_id')} which never completed")
    for i in sorted(br["unbracketed"]):
        out.append(f"{rows[i].get('finding_id')}: finding_supersede row outside any "
                   f"Phase-3 run bracket")
    return out


def _mark_empty_extraction(outcome: dict, handles: list[dict], events: list,
                           evidence: Path) -> None:
    """W4 review MED-3: a run that "succeeded" but parsed ZERO records from
    NON-EMPTY evidence (a corrupt EVTX → evtxexport exit 0 "No records to
    export"; a header-only pcap) examined nothing. Mark the artifact EMPTY
    (empty_data UNVERIFIED) and its successful handles EMPTY, so absence
    signals, the verdict and the blindspot rows never read it as clean."""
    if outcome["status"] not in ("SUCCESS", "PARTIAL") or events:
        return
    try:
        size = Path(evidence).stat().st_size
    except OSError:
        size = 0
    if size <= 0:
        return
    outcome["status"] = "EMPTY"
    outcome["empty_data"] = "UNVERIFIED"
    from spectre.pipeline.tool_runner import handle_succeeded
    for h in handles:
        if handle_succeeded(h):
            h["empty_data_status"] = "EMPTY"


def _plugins_examined(handles: list[dict]) -> tuple[list[str], list[str]]:
    """(examined, failed) artifact types from the slim Phase-2 handles.

    An artifact type is examined when at least one run producing it did
    not FAIL (W4-1, R1-F2); failed lists types with no successful run."""
    ok: set[str] = set()
    bad: set[str] = set()
    for h in handles:
        art = h.get("artifact_type")
        if not art:
            continue
        if h.get("empty_data_status") in ("FAILED", "EMPTY"):
            bad.add(art)
        else:
            ok.add(art)
    return sorted(ok), sorted(bad - ok)


def _fk_caveat_types(findings: list[dict]) -> list[str]:
    """Artifact types whose FK caveats belong in blindspots.md. No findings
    → none (R1-G10: finding_artifact_types' "evtx" default must not put
    evtx 4688 caveats into a memory-only case)."""
    from spectre.core.validators import finding_artifact_types
    if not findings:
        return []
    return finding_artifact_types(findings)


def missing_preceding_phases(manifest: dict, target: int) -> list:
    """Phases before `target` whose gate hasn't passed yet.

    Lets `--phase N` auto-run only the preceding phases that haven't already
    completed (true resume), never the target itself.
    """
    return [p for p in range(0, target) if not _phase_gate_passed(manifest, p)]


def run_phase_0(case_dir: str, manifest: dict) -> dict:
    """Phase 0: Case Setup — re-run canary and verify case state.

    A8-F1: this used to only READ the stored manifest["canary_status"]
    string despite the docstring's "re-run canary" claim — so a canary
    that was FULL at case creation but went DEAD before a later --phase N
    resume (tools uninstalled, wrong venv, disk full, corrupted symbol
    cache...) was never re-checked. canary.run_canary() is now actually
    called on every Phase-0 pass, including resume, and a fresh DEAD result
    fails this gate closed — matching the hard-stop case_setup.py's
    setup_case() already applies at creation (run_canary() itself
    sys.exit(3)s on a real DEAD; the explicit check below exists so a
    caller that stubs run_canary() to RETURN "DEAD" rather than exit —
    e.g. a test — still gets a fail-closed result). A DEGRADED canary still
    proceeds (matches creation-time behavior), and the freshly re-checked
    status is always persisted, not left as the stale creation-time value.
    """
    # Header printed by runner.py (or case_setup.py when invoked standalone).
    # This function is a gate-check pass — no redundant banner.

    manifest_path = Path(case_dir) / "manifest.yaml"
    if not manifest_path.exists():
        return {"error": "No manifest — run case_setup.py first", "success": False}

    # Verify directory structure
    for subdir in ["evidence", RAW_DIR, "findings", "reports"]:
        (Path(case_dir) / subdir).mkdir(parents=True, exist_ok=True)

    # Re-run canary (not just read the stale stored status) — see docstring.
    from spectre.pipeline import canary as canary_mod
    canary_result = canary_mod.run_canary(case_dir=case_dir)
    canary_status = canary_result.get("status", "UNKNOWN")
    manifest["canary_status"] = canary_status

    print(f"  Canary: {canary_status} (re-checked)", file=sys.stderr)
    print(f"  FK YAMLs: {manifest.get('artifacts', [])}", file=sys.stderr)
    print(f"  Evidence refs: {len(manifest.get('evidence', []))}", file=sys.stderr)

    # A8-F4/F5: previously `gate0 = manifest.get("gate_0", {})` built a
    # DISCONNECTED local dict when the key was absent, then indexed back
    # into manifest["gate_0"]["passed"] — a KeyError on any manifest
    # missing gate_0 (hand-edited/legacy). setdefault() ties the local
    # reference to the same dict that ends up in the manifest.
    manifest.setdefault("gate_0", {})

    if canary_status == "DEAD":
        print("FATAL: Session canary DEAD (re-checked at Phase 0) — "
              "core tools unavailable", file=sys.stderr)
        manifest["gate_0"]["passed"] = False
        manifest["gate_0"]["checked_at"] = _utcnow()
        _save_manifest(manifest, case_dir)
        return {
            "phase": 0, "gate_passed": False, "canary_status": "DEAD",
            "success": False, "error": "Session canary DEAD",
        }

    # R1-G3/F13: the old `len(evidence) >= 0` term was always true. Gate 0
    # now runs the check docs/phase-0-spec.md §Gate 0 requires:
    # audit.verify_chain() == ok.
    from spectre.pipeline.audit import verify_chain
    chain_ok, chain_reason = verify_chain(case_dir)
    if not chain_ok:
        print(f"  Gate 0: audit chain INVALID — {chain_reason}", file=sys.stderr)
    gate0_passed = bool(
        canary_status in ("FULL", "DEGRADED")
        and chain_ok
        and len(manifest.get("artifacts", [])) > 0
    )

    manifest["gate_0"]["audit_chain_valid"] = chain_ok
    manifest["gate_0"]["passed"] = gate0_passed
    manifest["gate_0"]["checked_at"] = _utcnow()
    _save_manifest(manifest, case_dir)

    return {
        "phase": 0,
        "gate_passed": gate0_passed,
        "canary_status": canary_status,
        "success": gate0_passed,
    }


def run_phase_1(case_dir: str, manifest: dict, skip_ai: bool = False) -> dict:
    """Phase 1: Direction — synthesize analyst-directed detection directives.

    Reads manifest["direction"] (the investigator's natural-language tasking).
    Empty direction is a clean pass-through. Otherwise the text is parsed into
    validated directive specs (deterministic-first; LLM only for fuzzy phrasing,
    skipped under --skip-ai), written to raw_extract/directives.json, and the
    synthesis is recorded in the audit chain (and execution.log, tagged [P1])
    BEFORE Phase 3 so every directed finding is reproducible. Directives are
    applied additively in Phase 3.
    """
    # Phase header printed by runner.py wrapper.
    from spectre.pipeline import direction as direction_mod
    from spectre import llm

    llm_preflight = llm.preflight()
    manifest["llm"] = llm_preflight
    if llm_preflight["status"] == "dead":
        print(
            f"  ⚠ LLM provider {llm_preflight['provider']} is DEAD — "
            "narrative seams will be inert; report will be a deterministic "
            f"baseline. {llm_preflight['detail']}",
            file=sys.stderr,
        )

    text = (manifest.get("direction") or "").strip()
    output_dir = Path(case_dir) / RAW_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    directives_path = output_dir / "directives.json"

    if not text:
        print("  No analyst direction provided — pass-through.", file=sys.stderr)
        directives_path.write_text("[]")
        # W3-1 (R2-16): the pass-through file is chained too, so a directive
        # planted into it later cannot pass as "Phase 1 wrote this".
        from spectre.pipeline.custody import record_derived_artifact
        record_derived_artifact(
            case_dir, directives_path, phase=1,
            phase_step="S1-synthesize-directives",
            tool="direction.py", action="directives_synthesized",
            params={"source_direction": "", "directive_count": 0,
                    "directive_ids": [], "warnings": []},
            output_line_count=0)
        manifest["directives"] = {"count": 0, "warnings": [], "source": ""}
        manifest["gate_1"] = {"directives_synthesized": 0, "passed": True,
                              "checked_at": _utcnow()}
        _save_manifest(manifest, case_dir)
        return {"phase": 1, "gate_passed": True, "directives": 0, "success": True,
                "llm": llm_preflight}

    result = direction_mod.synthesize(text, skip_ai=skip_ai)
    specs = result["directives"]
    warnings = result["warnings"]
    directives_path.write_text(json.dumps(specs, indent=2))

    llm_deferred = result.get("deferred", False)
    llm_used = result.get("llm_used", False)

    for w in warnings:
        print(f"  WARN: {w}", file=sys.stderr)
    print(f"  Synthesized {len(specs)} directive(s) from direction "
          f"(focus={manifest.get('focus', False)}).", file=sys.stderr)
    if llm_deferred:
        print("  Gate 1 DEGRADED: LLM unavailable — direction text not parsed into directives", file=sys.stderr)

    # Audit the synthesis BEFORE detection so directed findings are reproducible.
    # phase=1 routes this row into execution.log as [P1:S1-synthesize-directives].
    from spectre.pipeline.custody import case_relative, sha256_file
    try:
        from spectre.pipeline.audit import append as audit_append
        audit_append(case_dir, {
            "actor": "deterministic-core",
            "action": "directives_synthesized",
            "tool": "direction.py",
            "tool_version": "1.0",
            "exact_command": f"direction.synthesize(skip_ai={skip_ai})",
            "params": {
                "source_direction": text,
                "directive_count": len(specs),
                "directive_ids": [s["directive_id"] for s in specs],
                "warnings": warnings,
            },
            "case_id": Path(case_dir).name,
            # W3-1 (R2-16): bind the bytes Phase 3 will load (directives.load
            # re-hashes against this row and refuses a mismatch). Recorded
            # case-relative (W3-7) so a relocated case still verifies.
            "output_path": case_relative(case_dir, directives_path),
            "output_sha256": sha256_file(directives_path),
            "output_format": "json",
            "output_line_count": len(specs),
            "output_size_bytes": directives_path.stat().st_size,
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "stderr": "",
            "phase": 1,
            "phase_step": "S1-synthesize-directives",
        })
    except Exception as e:  # noqa: BLE001 — audit best-effort, never block the phase
        print(f"  (audit append skipped: {e})", file=sys.stderr)

    manifest["directives"] = {
        "count": len(specs),
        "warnings": warnings,
        "source": text,
        "specs": specs,
    }
    manifest["gate_1"] = {
        "directives_synthesized": len(specs),
        "warnings": len(warnings),
        "llm_used": llm_used,
        "passed": len(specs) > 0 or not text,
        "degraded_reason": "LLM unavailable — direction text not parsed into directives"
            if (llm_deferred and text and not specs) else None,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    return {
        "phase": 1,
        "gate_passed": True,
        "directives": len(specs),
        "warnings": warnings,
        "success": True,
        "llm": llm_preflight,
    }


_MODULES_DIR = KNOWLEDGE_DIR.parent.parent / "modules"  # src/spectre/modules
_FK_DIRS = FK_DIRS

# Map an EVENT-level artifact_type (what a rule emits, and therefore what a
# finding carries) to the FK YAML that supplies its caveats.
#
# DERIVED from each module's module.yaml (pipeline/fk_routing.py). It used to be
# a hand-written ~25-entry table, and the two comment blocks that stood here
# recorded the same defect being patched twice: an artifact type missing from
# the table fell through to _DEFAULT_FK = "evtx_4688.yaml", which is not a
# neutral default — it pastes Windows 4688 "corroborate with
# Prefetch/Amcache/MFT" caveats onto findings with no 4688 event at all. That
# shipped for the pcap types (case 268-001's two T1105 marquee findings, both
# anchored on pcap_flow) and again for registry_hive/prefetch/lnk/disk (A4-01).
# Both times the fix was to add keys, never to remove the reason keys go
# missing. `memory_psscan` was still missing when this was replaced, and the
# derived map picks it up.
#
# Resolution now: the owning module's fk_by_artifact entry, else its single
# fk_yamls entry, else nothing — and tests/test_fk_routing.py fails on that
# "nothing" rather than letting an artifact type inherit another evidence
# type's caveats.
ARTIFACT_FK = artifact_fk_files()
# Retained for findings whose corroboration names no artifact type this build
# knows (e.g. a hand-written finding, or evidence from a module that failed to
# load). Every artifact type any loaded rule can emit is in ARTIFACT_FK above,
# so reaching this is now the exception it was always meant to be.
_DEFAULT_FK = "evtx_4688.yaml"


def _fk_for_finding(finding: dict) -> str:
    """FK YAML name for a finding, derived from its corroborating tools
    ("tcpdump/pcap_conn" → pcap.yaml). Falls back to the evtx default."""
    tools = (finding.get("corroboration") or {}).get("tools") or []
    for t in tools:
        art = str(t).rsplit("/", 1)[-1]
        if art in ARTIFACT_FK:
            return ARTIFACT_FK[art]
    return _DEFAULT_FK


def _find_fk(fk_name: str) -> str:
    """Locate an FK YAML across windows + network artifact dirs."""
    for d in _FK_DIRS:
        p = d / fk_name
        if p.exists():
            return str(p)
    return str(_FK_DIRS[0] / fk_name)


def _modules():
    """Import and return the analyzer-module registry {name: AnalyzerModule}."""
    from spectre.modules import registry
    return registry.discover()


def _detect_monitored_ip(conn_text: str) -> str:
    """Identify the monitored host from a tcpdump connections summary.

    The monitored host (the machine under analysis) is the endpoint that
    communicates with the MOST DISTINCT peers — an infected client reaching
    out to dozens of C2 servers, or a web server contacted by hundreds of
    scanners. Counting distinct peers (not raw packets) is robust where a
    single large transfer would otherwise dominate a packet-count vote: a
    staging server the victim downloads 1.5 MB from still has only ONE peer
    (the victim), so it is never mistaken for the monitored host. Works
    whether the monitored host is a private client or a public server.

    Ties break toward a private/RFC1918 address, then total packet count.
    Returns "" when no parseable connections are present.
    """
    from collections import defaultdict, Counter

    peers: dict[str, set] = defaultdict(set)
    packets: Counter = Counter()
    for line in conn_text.splitlines():
        parts = line.split()
        # tcpdump brief format: <ts...> IP <src.port> > <dst.port>: ...
        for i, tok in enumerate(parts):
            if tok.upper().startswith("IP") and i + 3 < len(parts) \
                    and parts[i + 2] == ">":
                src = parts[i + 1].rsplit(".", 1)[0]
                dst = parts[i + 3].rstrip(":").rsplit(".", 1)[0]
                if src and dst and src != dst:
                    peers[src].add(dst)
                    peers[dst].add(src)
                    packets[src] += 1
                    packets[dst] += 1
                break
    if not peers:
        return ""
    return max(
        peers,
        key=lambda ip: (len(peers[ip]), _is_rfc1918(ip), packets[ip]),
    )


def _detect_monitored_ip_zeek(conn_text: str) -> str:
    """Identify the monitored host from a Zeek conn.log (JSON-lines).

    Same distinct-peer-count algorithm and tiebreak as _detect_monitored_ip
    (see its docstring), just reading Zeek's structured id.orig_h/id.resp_h
    fields instead of tcpdump's brief-text grammar. Needed because the Zeek
    engine has no "connections" (tcpdump) pass for _detect_monitored_ip to
    find (A10 Finding 2): without this, normalize_zeek_flows() never
    receives a monitored_ip and silently emits zero pcap_flow events, which
    permanently disables the pcap-large-transfer / pcap-staging-download
    rules under Zeek even though the identical capture fires them via the
    manual engine. Returns "" when no parseable conn.log rows are present.
    """
    from collections import defaultdict, Counter
    import json as _json

    peers: dict[str, set] = defaultdict(set)
    packets: Counter = Counter()
    for line in conn_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = _json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        src = d.get("id.orig_h", "")
        dst = d.get("id.resp_h", "")
        if not src or not dst or src == dst:
            continue
        peers[src].add(dst)
        peers[dst].add(src)
        pkt_total = 0
        try:
            pkt_total = int(d.get("orig_pkts") or 0) + int(d.get("resp_pkts") or 0)
        except (TypeError, ValueError):
            pkt_total = 0
        packets[src] += pkt_total or 1
        packets[dst] += pkt_total or 1
    if not peers:
        return ""
    return max(
        peers,
        key=lambda ip: (len(peers[ip]), _is_rfc1918(ip), packets[ip]),
    )


def _conn_distinct_counts(conn_text: str) -> tuple[int, int]:
    """Count distinct source IPs and distinct destination ports from a
    tcpdump connections summary. Deterministic capture-scale metadata —
    a count of what was captured, never a judgment that any counted value
    is malicious. Same line grammar as _detect_monitored_ip. Returns
    (0, 0) when nothing parses."""
    src_ips: set[str] = set()
    dst_ports: set[str] = set()
    for line in conn_text.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok.upper().startswith("IP") and i + 3 < len(parts) \
                    and parts[i + 2] == ">":
                src = parts[i + 1].rsplit(".", 1)[0]
                dst_tok = parts[i + 3].rstrip(":")
                port = dst_tok.rsplit(".", 1)[1] if "." in dst_tok else ""
                if src:
                    src_ips.add(src)
                if port:
                    dst_ports.add(port)
                break
    return (len(src_ips), len(dst_ports))


def _persist_capture_scale(manifest: dict, conn_text: str, monitored_ip: str) -> None:
    """Consolidate deterministic capture-scale metadata into the manifest.

    Copies packet/byte/duration counts already recorded per-evidence at
    intake, adds distinct src-IP / dst-port counts from the connections
    extract, and records the monitored host. All descriptive metadata —
    never a finding. Best-effort: a parse failure leaves the manifest
    unchanged rather than crashing Phase 2.

    Called once per evidence file in the Phase 2 evidence loop. MERGES into
    any capture_scale already recorded rather than rebuilding it from
    scratch — in a multi-evidence case (e.g. memory + pcap) the iteration
    whose conn_text is empty (a non-pcap file) must never wipe out the
    distinct_src_ips / distinct_dst_ports a prior pcap iteration recorded.
    """
    try:
        src_n, port_n = _conn_distinct_counts(conn_text)
        scale: dict = dict(manifest.get("capture_scale") or {})
        for meta in (manifest.get("evidence_metadata") or {}).values():
            if not isinstance(meta, dict):
                continue
            for k in ("total_packets", "file_size_bytes", "capture_duration_seconds"):
                if meta.get(k) and k not in scale:
                    scale[k] = meta[k]
        if src_n:
            scale["distinct_src_ips"] = src_n
        if port_n:
            scale["distinct_dst_ports"] = port_n
        if scale:
            manifest["capture_scale"] = scale
        if monitored_ip:
            manifest["monitored_ip"] = monitored_ip
    except Exception:
        pass


def _is_rfc1918(ip: str) -> bool:
    """True for private-range IPv4 addresses (RFC 1918) — used only as a
    monitored-host tiebreak, never as a filter."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def run_phase_2(case_dir: str, manifest: dict) -> dict:
    """Phase 2: Extraction dispatcher.

    Live path: route each recognized evidence file to its analyzer module
    (real tool via run_tool), normalize, and persist events + handles for
    Phase 3. Fixture path (profile 'fixture-test') is kept for regression.
    """
    if manifest.get("artifact_profile") == "fixture-test":
        return _run_phase_2_fixture(case_dir, manifest)
    return _run_phase_2_live(case_dir, manifest)


def _run_phase_2_live(case_dir: str, manifest: dict) -> dict:
    """Dispatch registered evidence to analyzer modules. No fixtures."""
    import dataclasses

    # Phase header printed by runner.py wrapper.
    from spectre.pipeline.tool_runner import (
        extraction_outcome, handle_succeeded, is_auxiliary)

    triage = manifest.get("triage", {})
    modules = _modules()
    extraction_results = {}
    all_handles = []
    all_events = []  # serialized NormEvents

    if not triage:
        print("  No triage records — was evidence registered & recognized?",
              file=sys.stderr)

    # Review MED (W3-2 follow-up): manifest["triage"] is a mutable file. Only
    # a path that resolves to a CHAINED evidence_register copy inside this
    # case (a regular file, not a symlink) is ever extracted; anything else
    # is refused and the refusal is chained.
    from spectre.pipeline import custody as _custody
    _registered = _custody.registered_evidence_paths(case_dir)
    for ev_path, rec in triage.items():
        status = rec.get("status")
        mod_name = rec.get("module")
        name = os.path.basename(ev_path)
        _local = _custody.try_resolve(case_dir, ev_path)
        if _local is None or str(_local) not in _registered \
                or _custody.link_problem(case_dir, _local):
            reason = ("not a chained evidence_register copy in this case"
                      if _local is None or str(_local) not in _registered
                      else _custody.link_problem(case_dir, _local))
            extraction_results[ev_path] = {"skipped": "UNREGISTERED", "note": reason}
            console.note(f"REFUSED: {name} — {reason}")
            _custody.note_tamper(case_dir, "unregistered_evidence_refused", 2,
                                 [f"{ev_path}: {reason}"],
                                 "phase_runner._run_phase_2_live")
            continue
        if status == "RECOGNIZED" and mod_name in modules:
            module = modules[mod_name]
            console.detail(f"{name} -> {mod_name}.extract()")
            try:
                # W3-7 (R1-F10): a relocated case extracts ITS OWN evidence
                # copy, never the path recorded at the original location.
                handles = module.extract(case_dir, str(_local))
            except Exception as e:
                extraction_results[ev_path] = {"error": f"extract failed: {e}"}
                console.note(f"ERROR: {e}")
                continue
            # Detect the monitored host IP from connections data so
            # direction labels (outbound/inbound) work for public-IP hosts.
            # First try the tcpdump "connections" pass (manual engine);
            # if absent, fall back to the Zeek engine's own zeek_conn
            # handle (A10 Finding 2 — without this fallback, monitored_ip
            # never resolves under Zeek, normalize_zeek_flows() silently
            # emits zero pcap_flow events, and the pcap-large-transfer /
            # pcap-staging-download rules never fire even though the
            # manual engine fires them on the identical capture).
            monitored_ip = ""
            conn_text = ""
            for h in handles:
                if h.get("extract_pass") == "connections":
                    conn_path = h.get("path")
                    if conn_path and Path(conn_path).exists():
                        try:
                            conn_text = Path(conn_path).read_text(errors="replace")
                            monitored_ip = _detect_monitored_ip(conn_text)
                        except Exception:
                            pass
                    break
            if not monitored_ip:
                for h in handles:
                    if h.get("extract_pass") == "zeek_conn":
                        conn_path = h.get("path")
                        if conn_path and Path(conn_path).exists():
                            try:
                                zeek_conn_text = Path(conn_path).read_text(errors="replace")
                                monitored_ip = _detect_monitored_ip_zeek(zeek_conn_text)
                            except Exception:
                                pass
                        break
            if monitored_ip:
                for h in handles:
                    h["monitored_ip"] = monitored_ip
            _persist_capture_scale(manifest, conn_text, monitored_ip)
            file_events = []
            for h in handles:
                all_handles.append(h)
                try:
                    evs = module.normalize(h)
                    # Provenance: stamp the producing tool/engine so the
                    # correlation layer can count distinct sources per claim,
                    # and the exact handle's execution_id so Phase 3 can
                    # recover the exact tool/exact_command that produced
                    # each event — not just any handle sharing evidence_path
                    # and tool (e.g. pcap runs 4 tcpdump passes over the
                    # same file; only execution_id disambiguates them).
                    src_tool = h.get("engine") or h.get("tool", "")
                    src_exec_id = h.get("execution_id", "")
                    for ev in evs:
                        if not ev.source_tool:
                            ev.source_tool = src_tool
                        if not ev.source_execution_id:
                            ev.source_execution_id = src_exec_id
                    file_events.extend(evs)
                except Exception as e:
                    console.note(f"normalize ERROR: {e}")
            for ev in file_events:
                all_events.append(dataclasses.asdict(ev))
            # W4-1 (R1-F2): judged over ALL handles, and a failed tool run
            # is never data. An artifact whose every run failed is
            # EXTRACTION_FAILED — not examined, whatever bytes it wrote.
            outcome = extraction_outcome(handles)
            _mark_empty_extraction(outcome, handles, file_events, _local)
            result = {
                "module": mod_name,
                "artifact_type": rec.get("artifact_type"),
                "handles": len(handles),
                "handles_ok": outcome["handles_ok"],
                "handles_failed": outcome["handles_failed"],
                "extraction_status": outcome["status"],
                "events": len(file_events),
                "empty_data": outcome["empty_data"],
                "output_paths": [h.get("path") for h in handles],
            }
            if outcome["status"] == "EXTRACTION_FAILED":
                errs = sorted({str(h.get("stderr") or "").strip().splitlines()[-1][:200]
                               for h in handles
                               if str(h.get("stderr") or "").strip()})
                result["error"] = (
                    f"EXTRACTION_FAILED: no parsing tool run succeeded "
                    f"({outcome['handles_failed']} of {len(handles)} run(s) failed)"
                    + (f" ({errs[0]})" if errs else ""))
                console.note(f"EXTRACTION_FAILED: {name} — {result['error']}")
            elif outcome["status"] == "EMPTY":
                console.note(f"EMPTY: {name} — the tool(s) ran but parsed zero "
                             f"records from non-empty evidence; nothing was examined")
            elif outcome["status"] == "PARTIAL":
                console.note(f"PARTIAL: {name} — {outcome['handles_failed']} of "
                             f"{len(handles)} tool run(s) failed")
            channel_stats = next((h["channel_stats"] for h in handles
                                   if "channel_stats" in h), None)
            if channel_stats:
                result["channel_stats"] = channel_stats
            # Honest record of any optional pass a module skipped rather
            # than crashed on (A10 Finding 3 — e.g. the Zeek engine's
            # tcpdump HTTP-payload/checksum gap-fill when tcpdump is
            # unavailable). Zeek's own handles above still count normally;
            # this only names what was NOT verified, so the manifest (and
            # anything reading extraction.results) records the gap instead
            # of it disappearing silently.
            gap_skips = [h for h in handles
                         if h.get("result") == "skipped_tool_unavailable"]
            if gap_skips:
                result["gap_fill_skipped"] = [
                    {"extract_pass": h.get("extract_pass", ""),
                     "artifact_type": h.get("artifact_type", ""),
                     "tool": h.get("tool", ""),
                     "reason": h.get("skip_reason", "")}
                    for h in gap_skips
                ]
                for gs in result["gap_fill_skipped"]:
                    console.note(
                        f"BLINDSPOT: {gs['artifact_type']} ({gs['extract_pass']}) "
                        f"not verified — {gs['reason']}"
                    )
            extraction_results[ev_path] = result
            console.detail(f"{len(file_events)} normalized event(s)")
        elif status == "EXTRACTOR_PENDING":
            extraction_results[ev_path] = {
                "skipped": "EXTRACTOR_PENDING",
                "tool": rec.get("tool"),
                "note": f"recognized as {rec.get('artifact_type')} but "
                        f"required tool is unavailable",
            }
        else:
            extraction_results[ev_path] = {
                "skipped": status or "UNRECOGNIZED",
                "note": "no analyzer module claimed this file",
            }

    # ── Derived evidence: register + re-triage carved artifacts ──────
    # Disk (and future) extraction may carve nested artifacts (EVTX, hives,
    # prefetch, ...) out of an image. Each carved file becomes its own
    # evidence: hashed, locked read-only, audited, re-triaged through the
    # module registry, and (if claimed) extracted/normalized exactly like
    # primary evidence. Depth is bounded to one level: any `derived_files`
    # produced while processing a derived file are ignored — we never
    # re-carve out of a carve.
    derived_manifest: dict = {}
    derived_queue = []
    for h in all_handles:
        for d in h.get("derived_files", []):
            derived_queue.append(d)
    if derived_queue:
        from spectre.pipeline.recognize import triage_one
        from spectre.pipeline.audit import append as audit_append
        import hashlib

        # parent_sha256, when known, from the registered evidence list.
        parent_sha_by_path = {
            e.get("evidence_path"): e.get("sha256")
            for e in manifest.get("evidence", []) if isinstance(e, dict)
        }

        for d in derived_queue:
            dpath = d.get("path", "")
            if d.get("carve_result") != "success" or not dpath or not Path(dpath).exists():
                key = dpath or d.get("in_image_path", "?")
                extraction_results[key] = {
                    "skipped": "carve_failed",
                    "note": d.get("stderr", ""),
                    "derived_from": d.get("parent_evidence", ""),
                }
                continue

            sha = hashlib.sha256(Path(dpath).read_bytes()).hexdigest()
            os.chmod(dpath, 0o444)
            audit_append(case_dir, {
                "actor": "phase_runner",
                "action": "derived_evidence_register",
                "tool": "phase_runner.py",
                "tool_version": "1.0",
                "exact_command": f"derive {d.get('in_image_path', '')}",
                "params": {
                    "parent_evidence": d.get("parent_evidence", ""),
                    "in_image_path": d.get("in_image_path", ""),
                    "inode": d.get("inode", ""),
                    "parent_sha256": parent_sha_by_path.get(d.get("parent_evidence", ""), ""),
                },
                "case_id": Path(case_dir).name,
                # W3-7: case-relative, re-hashed at every phase entry.
                "output_path": _custody.case_relative(case_dir, dpath),
                "output_sha256": sha,
                "result": "success",
                "exit_code": 0,
                "duration_ms": 0,
                "phase": 2,
                "phase_step": "S2-derive",
            })

            try:
                rec = triage_one(dpath)
                derived_manifest[dpath] = {
                    "derived_from": d.get("parent_evidence", ""),
                    "in_image_path": d.get("in_image_path", ""),
                    "sha256": sha,
                    "status": rec.get("status"),
                    "module": rec.get("module"),
                    "artifact_type": rec.get("artifact_type"),
                }

                mod_name = rec.get("module")
                if rec.get("status") == "RECOGNIZED" and mod_name in modules:
                    module = modules[mod_name]
                    try:
                        dhandles = module.extract(case_dir, dpath)
                    except Exception as e:
                        extraction_results[dpath] = {
                            "error": f"extract failed: {e}",
                            "derived_from": d.get("parent_evidence", ""),
                        }
                        continue
                    devents = []
                    for dh in dhandles:
                        dh.pop("derived_files", None)  # depth bound: never re-carve
                        all_handles.append(dh)
                        try:
                            evs = module.normalize(dh)
                            src_tool = dh.get("engine") or dh.get("tool", "")
                            src_exec_id = dh.get("execution_id", "")
                            for ev in evs:
                                if not ev.source_tool:
                                    ev.source_tool = src_tool
                                if not ev.source_execution_id:
                                    ev.source_execution_id = src_exec_id
                            devents.extend(evs)
                        except Exception as e:
                            console.note(f"derived normalize ERROR: {e}")
                    for ev in devents:
                        all_events.append(dataclasses.asdict(ev))
                    doutcome = extraction_outcome(dhandles)
                    _mark_empty_extraction(doutcome, dhandles, devents, Path(dpath))
                    extraction_results[dpath] = {
                        "module": mod_name,
                        "artifact_type": rec.get("artifact_type"),
                        "handles": len(dhandles),
                        "handles_ok": doutcome["handles_ok"],
                        "handles_failed": doutcome["handles_failed"],
                        "extraction_status": doutcome["status"],
                        "empty_data": doutcome["empty_data"],
                        "events": len(devents),
                        "derived_from": d.get("parent_evidence", ""),
                        "output_paths": [x.get("path") for x in dhandles],
                    }
                    if dhandles and "channel_stats" in dhandles[0]:
                        extraction_results[dpath]["channel_stats"] = dhandles[0]["channel_stats"]
                else:
                    note = _derived_skip_note(rec.get("status"),
                                              rec.get("artifact_type"))
                    extraction_results[dpath] = {
                        "skipped": rec.get("status") or "UNRECOGNIZED",
                        "derived_from": d.get("parent_evidence", ""),
                        "note": note,
                    }
            except Exception as e:
                # One pathological carved file (e.g. a recognizer sniff that
                # raises on a malformed carve) must not abort the whole
                # derived-evidence pass — record and move on.
                extraction_results[dpath] = {
                    "error": f"derived processing failed: {e}",
                    "derived_from": d.get("parent_evidence", ""),
                }
                continue

    if derived_manifest:
        manifest["derived_evidence"] = derived_manifest

    # Persist normalized events + handles for Phase 3 (modular detection).
    output_dir = Path(case_dir) / RAW_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "normalized_events.json").write_text(json.dumps(all_events))
    # Keep only the handle fields Phase 3 / emit_from_handle needs.
    slim_handles = [{
        "execution_id": h.get("execution_id", ""),
        "path": h.get("path", ""),
        "evidence_path": h.get("evidence_path", ""),
        "tool": h.get("tool", "unknown"),
        "engine": h.get("engine", ""),
        "tool_version": h.get("tool_version", ""),
        "exact_command": h.get("exact_command", ""),
        "line_count": h.get("line_count", 0),
        "size_bytes": h.get("size_bytes", 0),
        "empty_data_status": h.get("empty_data_status", "UNKNOWN"),
        # Which plugin/pass produced this handle (e.g. "memory_netscan") —
        # carried through even when the pass produced zero events, so Phase 3
        # can record which artifacts were actually EXAMINED (manifest
        # detection.plugins_run) as distinct from which produced findings.
        # D4: grounds cross-artifact absence signals ("no outbound
        # connections") in "we looked" rather than "we never checked".
        "artifact_type": h.get("artifact_type", ""),
    } for h in all_handles]
    (output_dir / "_handles.json").write_text(json.dumps(slim_handles))
    # W3-1 (R2-04): chain both files' sha256 so Phase 3 (and verify_full) can
    # prove the events it detects on are the ones Phase 2 produced.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(case_dir)

    manifest["extraction"] = {
        "mode": "live",
        "files_processed": len(extraction_results),
        "results": extraction_results,
        "total_events": len(all_events),
    }
    # W4-1 (R1-F2): only a SUCCESSFUL tool run counts toward Gate 2. Zero
    # events from a run that succeeded is a valid (UNVERIFIED) outcome; a
    # run that errored is not extraction. Every artifact failed → FAIL;
    # some failed → pass DEGRADED, naming them.
    handles_ok = sum(1 for h in all_handles
                     if handle_succeeded(h) and not is_auxiliary(h))
    extraction_failed = sorted(
        p for p, r in extraction_results.items()
        if isinstance(r, dict) and r.get("extraction_status") == "EXTRACTION_FAILED")
    extraction_empty = sorted(
        p for p, r in extraction_results.items()
        if isinstance(r, dict) and r.get("extraction_status") == "EMPTY")
    gate2_passed = handles_ok > 0
    manifest["gate_2"] = {
        "all_attempted": len(extraction_results) > 0,
        "handles_generated": len(all_handles),
        "handles_ok": handles_ok,
        "extraction_failed": extraction_failed,
        "extraction_empty": extraction_empty,
        "degraded": bool(gate2_passed and (extraction_failed or extraction_empty)),
        "passed": gate2_passed,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    # Chain the Phase-2 coverage gaps (skipped carves, EXTRACTION_FAILED
    # artifacts) the same way the fixture path does, so a failed
    # extraction is a chained fact the report must disclose (Check 9).
    try:
        from spectre.pipeline.coverage import append_gap_rows
        append_gap_rows(case_dir, str(manifest.get("case_id", "")),
                        phase=2, phase_step="S9-coverage", manifest=manifest)
    except Exception as e:
        print(f"  ⚠ coverage_gap rows not written: {e}", file=sys.stderr)

    result = {
        "phase": 2,
        "gate_passed": gate2_passed,
        "handles": len(all_handles),
        "handles_ok": handles_ok,
        "events": len(all_events),
        "results": extraction_results,
        "success": gate2_passed,
    }
    if all_handles and not gate2_passed:
        failures = [f"{os.path.basename(p)}: {extraction_results[p].get('error', 'EXTRACTION_FAILED')}"
                    for p in extraction_failed]
        result["error"] = (
            f"extraction failed for {len(extraction_failed)}/"
            f"{len(extraction_results) or 1} evidence file(s) — every tool run "
            f"errored, nothing was examined: " + "; ".join(failures[:5]))
    if not all_handles:
        # A10 Finding 3 tail: this dict never carried a top-level "error",
        # so a failed Phase 2 printed the literal string
        # `runner.py`'s `FAILED: {result.get('error', 'unknown')}` — no
        # tool name, no file name, nothing an operator running without -v
        # could act on. Summarize the per-evidence-file failures recorded
        # above into one diagnostic line instead.
        n_total = len(extraction_results) or 1
        failures = [
            f"{os.path.basename(p)}: {r['error']}"
            for p, r in extraction_results.items()
            if isinstance(r, dict) and "error" in r
        ]
        # A required tool being unavailable (recognize.py's EXTRACTOR_PENDING
        # gate — never even reaches module.extract(), so no "error" entry
        # exists for it) is the other common all-zero-handles cause. Name it
        # too, or the summary falls back to a generic, unhelpful message for
        # what is actually the most common degraded-canary case.
        pending = [
            f"{os.path.basename(p)}: EXTRACTOR_PENDING"
            + (f" (requires `{r.get('tool')}`)" if r.get("tool") else "")
            for p, r in extraction_results.items()
            if isinstance(r, dict) and r.get("skipped") == "EXTRACTOR_PENDING"
        ]
        detail = failures + pending
        if detail:
            result["error"] = (
                f"{len(detail)}/{n_total} evidence files failed extraction: "
                + "; ".join(detail)
            )
        else:
            result["error"] = (
                f"0/{n_total} evidence files produced extraction handles "
                "(no matching analyzer module or no recognized evidence)"
            )
    return result


def _run_phase_2_fixture(case_dir: str, manifest: dict) -> dict:
    """Phase 2 (FIXTURE regression path only — profile 'fixture-test').

    Loads case-000.events.json and writes it through tool_runner as an
    evtx_dump extraction. NEVER runs on the live path.
    """
    # Phase header printed by runner.py wrapper.

    from spectre.pipeline.tool_runner import run_tool, empty_data_protocol, size_gate

    artifacts = manifest.get("artifacts", [])
    extraction_results = {}
    all_handles = []

    for artifact in artifacts:
        console.detail(f"Processing artifact: {artifact}")

        if artifact == "evtx_4688" and FIXTURE_PATH.exists():
            # Load fixture and write directly (JSON fixture, not real EVTX)
            try:
                fixture_data = json.loads(FIXTURE_PATH.read_text())
            except Exception as e:
                extraction_results[artifact] = {"error": str(e)}
                continue

            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = str(Path(case_dir) / RAW_DIR /
                             f"{ts}_evtx_dump.json")

            # Write fixture data directly to output (skip evtx_dump.py)
            with open(output_path, "w") as f:
                json.dump(fixture_data, f)

            # Re-run fixture extraction — previous attempt may have
            # overwritten with empty XML. Clean up that file if it exists.
            old_xml = Path(case_dir) / RAW_DIR / "20260627_105611_evtx_dump.json"
            if old_xml.exists() and old_xml.stat().st_size < 500:
                old_xml.unlink()

            # Create tool handle via run_tool for audit trail
            handle = run_tool(
                case_dir=case_dir,
                tool_name="evtx_dump_fixture",
                tool_version="0.1",
                command=["cat", str(FIXTURE_PATH)],
                params={
                    "fixture_path": str(FIXTURE_PATH),
                    "record_count": len(fixture_data),
                    "phase": "extraction",
                    "note": "JSON fixture loaded directly (no real EVTX)"
                },
                output_path=output_path,
                timeout=30,
                output_format="json",
            )

            all_handles.append(handle)

            extraction_results[artifact] = {
                "execution_id": handle.get("execution_id", "")[:16] + "...",
                "line_count": handle.get("line_count", 0),
                "empty_data": empty_data_protocol(handle),
                "size_safe": size_gate(handle),
                "output_path": output_path,
            }
            console.detail(f"execution_id: {handle.get('execution_id', '?')[:16]}...")
        else:
            extraction_results[artifact] = {
                "skipped": "No extraction handler for fixture mode",
                "note": "Non-EVTX artifacts need real evidence",
            }

    # Update manifest
    manifest["extraction"] = {
        "artifacts_processed": len(extraction_results),
        "results": extraction_results,
    }
    manifest["gate_2"] = {
        "all_attempted": len(extraction_results) > 0,
        "handles_generated": len(all_handles),
        "passed": len(all_handles) > 0,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    # Chain the coverage gaps Phase 2 now knows about. Phase 0's rows only saw
    # primary-evidence triage; carved artifacts are re-triaged HERE, long after,
    # and their status lands in extraction results rather than manifest
    # ["triage"] — so without this a disk image that carved 200 unextractable
    # EVTX files left no chained trace of the gap at all. Aggregated by
    # (status, artifact_type, parent), so that image yields one row, not 200.
    try:
        from spectre.pipeline.coverage import append_gap_rows
        append_gap_rows(case_dir, str(manifest.get("case_id", "")),
                        phase=2, phase_step="S9-coverage", manifest=manifest)
    except Exception as e:
        print(f"  ⚠ coverage_gap rows not written: {e}", file=sys.stderr)

    return {
        "phase": 2,
        "gate_passed": len(all_handles) > 0,
        "handles": len(all_handles),
        "results": extraction_results,
        "success": len(all_handles) > 0,
    }


def _severity_breakdown(rules: list) -> dict:
    """Count snapshot rules per severity. An unset severity (None/absent) is
    bucketed as "unrated" — never folded into an unassessed "medium"."""
    out: dict[str, int] = {}
    for r in rules:
        sev = r.get("severity") or "unrated"
        out[sev] = out.get(sev, 0) + 1
    return out


def build_ruleset_snapshot(
    rule_catalog: list[dict],
    rule_hits: dict[str, int],
    source_hashes: dict[str, str],
    focus: bool,
    rule_statuses: dict[str, dict] | None = None,
) -> dict:
    """Build the ruleset.yaml dict."""
    rules = []
    fired_count = 0
    for card in rule_catalog:
        hits = rule_hits.get(card["rule_id"], 0)
        if rule_statuses and card["rule_id"] in rule_statuses:
            status_info = rule_statuses[card["rule_id"]]
            status = status_info.get("status", "NOT_EVALUATED")
            reason = status_info.get("reason", "")
            fired = False
        else:
            fired = hits > 0
            status = "FIRED" if fired else "NOT_FIRED"
            reason = ""
        if fired:
            fired_count += 1
        entry = {
            "rule_id": card["rule_id"],
            "module": card["module"],
            "artifact_type": card["artifact_type"],
            "description": card.get("description", ""),
            "candidate_mitre": card.get("candidate_mitre", []),
            "rule_origin": card.get("rule_origin", "deterministic"),
            "uuid": card.get("uuid", ""),
            # str|null contract: an unset severity stays None (UNRATED at
            # display), never coerced to an unassessed "medium".
            "severity": card.get("severity"),
            "rule_format": card.get("rule_format", "python"),
            "tags": card.get("tags", []),
            "references": card.get("references", []),
            "false_positives": card.get("false_positives", []),
            "fired": fired,
            "hits": hits,
            "status": status,
        }
        if reason:
            entry["not_evaluated_reason"] = reason
        rules.append(entry)

    not_evaluated = sum(
        1 for r in rules if r.get("status") == "NOT_EVALUATED"
    ) if rule_statuses else 0

    return {
        "generated_phase": 3,
        "focus_mode": focus,
        "rules_evaluated": len(rules),
        "rules_fired": fired_count,
        "rules_not_evaluated": not_evaluated,
        "source_hashes": dict(source_hashes),
        "rules": rules,
    }


def run_phase_3(case_dir: str, manifest: dict) -> dict:
    """Phase 3: Detection dispatcher.

    Live path runs modular rule packs over the NormEvents produced in
    Phase 2 and emits findings via emit_from_handle. Fixture path kept
    for regression.
    """
    if manifest.get("artifact_profile") == "fixture-test":
        return _run_phase_3_fixture(case_dir, manifest)
    return _run_phase_3_live(case_dir, manifest)


def _run_phase_3_live(case_dir: str, manifest: dict) -> dict:
    """Run every module's rule pack over normalized events; emit findings."""
    # Phase header printed by runner.py wrapper.

    modules = _modules()  # also ensures modules/ is importable for `base`
    from spectre.core.base import NormEvent, check_rule_fields
    from spectre.pipeline.emit_finding import emit_from_handle, get_next_finding_number
    from spectre.pipeline import directives as directives_mod
    from spectre.pipeline.correlation import corroborate

    output_dir = Path(case_dir) / RAW_DIR
    events_path = output_dir / "normalized_events.json"
    handles_path = output_dir / "_handles.json"
    if not events_path.exists():
        return {"error": "No normalized_events.json — run Phase 2 first",
                "success": False}

    # W3-1 (R2-04, R2-16): re-verify every derived input against its chained
    # hash row BEFORE consuming it. A forged or unrecorded file fails closed —
    # detection over it would fabricate a deterministic fact.
    # The bytes are read ONCE, hashed, and those same bytes are parsed.
    from spectre.pipeline import custody
    try:
        _rows = custody.read_audit_rows(case_dir)
        _events_bytes = custody.read_verified(case_dir, events_path, rows=_rows)
        _handles_bytes = (custody.read_verified(case_dir, handles_path, rows=_rows)
                          if handles_path.exists() else b"[]")
    except custody.CustodyError as e:
        custody.note_tamper(case_dir, "derived_artifact_tampered", 3, [str(e)],
                            "phase_runner._run_phase_3_live")
        return {"error": f"derived artifact integrity check failed: {e}",
                "success": False}

    # W4-5 (R2-18): a re-run retires the prior run's findings (chained
    # finding_supersede rows, files moved to findings/superseded/) instead
    # of emitting a second copy of each. W4 review: check first (fail
    # closed on a tampered, moved or deleted prior finding), open a
    # Phase-3 bracket, and retire only AFTER detection has succeeded.
    from spectre.pipeline.emit_finding import supersede_prior_findings
    _pre = supersede_prior_findings(case_dir, reason="phase 3 re-run", dry_run=True)
    if _pre["problems"]:
        custody.note_tamper(case_dir, "finding_tampered", 3, _pre["problems"],
                            "phase_runner._run_phase_3_live")
        return {"error": "prior findings failed their custody check — refusing "
                         "to re-run detection over them (possible tamper): "
                         + "; ".join(_pre["problems"][:5]),
                "success": False}
    _run_id = _phase3_open_bracket(case_dir)

    raw_events = json.loads(_events_bytes)
    events = [NormEvent(**d) for d in raw_events]
    handles = json.loads(_handles_bytes)
    # Index handles by the evidence file they came from.
    handle_by_evidence = {h.get("evidence_path", ""): h for h in handles}
    # And by (evidence file, producing tool/engine) so each corroborating
    # source can cite its own tool_exec row in the finding's evidence_refs.
    handle_by_tool = {
        (h.get("evidence_path", ""), h.get("engine") or h.get("tool", "")): h
        for h in handles
    }
    # And by execution_id — the ONLY unambiguous handle lookup when one
    # evidence file goes through multiple extract passes with the SAME tool
    # (e.g. pcap's tcpdump connections/dns/http/timing passes). Both dicts
    # above collapse to "last handle wins" for that case; this one doesn't.
    handle_by_execution_id = {
        h.get("execution_id", ""): h for h in handles if h.get("execution_id")
    }
    print(f"  Loaded {len(events)} normalized event(s), {len(handles)} handle(s)",
          file=sys.stderr)

    # ── Enrichment (optional per-module hook, before detection) ────────
    # A module may compute cross-event facts (e.g. "has a hidden-process
    # peer", "this flow answers a beaconing DNS query") and stamp them
    # into event.data so rules stay pure single-event predicates. Called
    # once per module over the FULL event list. Modules that omit the
    # hook (enrich=None, the default — all pre-Task-2 modules) are
    # skipped without error. Enrichment must never add/remove events;
    # that is a bug in the deterministic core, so it raises loudly rather
    # than being silently tolerated.
    n_before = len(events)
    for mod_name, module in modules.items():
        if module.enrich is None:
            continue
        module.enrich(events)
        assert len(events) == n_before, (
            f"enrich must not add/remove events (module={mod_name}, "
            f"before={n_before}, after={len(events)})"
        )

    # Load analyst-directed directives (Phase 1 output). --focus runs ONLY
    # directives, skipping the baseline rule packs (tunnel-vision triage).
    try:
        compiled = directives_mod.load(case_dir)
    except custody.CustodyError as e:
        custody.note_tamper(case_dir, "derived_artifact_tampered", 3, [str(e)],
                            "phase_runner._run_phase_3_live")
        return {"error": f"derived artifact integrity check failed: {e}",
                "success": False}
    focus = bool(manifest.get("focus", False))
    if compiled:
        print(f"  Loaded {len(compiled)} directive(s); focus={focus}",
              file=sys.stderr)

    # Gather rule packs grouped by artifact_type across all modules. While
    # grouping, also record — for ruleset.yaml — the identity card of every
    # rule that is actually EVALUABLE against this case's evidence. A rule is
    # evaluable iff at least one event of its artifact_type is present; the
    # detect loop below only ever calls a rule whose artifact_type matches a
    # real event, so a rule with no matching evidence is never executed.
    # Listing such rules as fired:false would falsely imply "we checked",
    # so the catalog (and its source hashes) covers only evaluable rules.
    event_types = {e.artifact_type for e in events}
    rules_by_type: dict[str, list] = {}
    rule_catalog: list[dict] = []
    module_src: dict[str, str] = {}  # module name -> its rules.py path
    if not focus:
        import inspect
        for mod_name, module in modules.items():
            for rule in module.rules:
                rules_by_type.setdefault(rule.artifact_type, []).append(rule)
                if rule.artifact_type not in event_types:
                    continue  # no matching evidence -> never evaluated
                md = rule.metadata
                rule_catalog.append({
                    "rule_id": rule.rule_id,
                    "module": mod_name,
                    "artifact_type": rule.artifact_type,
                    "description": rule.description,
                    "candidate_mitre": list(rule.mitre),
                    "uuid": md.uuid if md else "",
                    "severity": md.severity if md else None,
                    "rule_format": md.rule_format if md else "python",
                    "tags": list(md.tags) if md else [],
                    "references": list(md.references) if md else [],
                    "false_positives": list(md.false_positives) if md else [],
                })
                if mod_name not in module_src:
                    src = inspect.getsourcefile(rule.predicate)
                    if src:
                        module_src[mod_name] = src

    # ── Field-presence check ──────────────────────────────────────────
    # Before detection, check every rule's required_fields against the
    # actual data fields present in normalized events. Rules whose required
    # fields are absent are NOT_EVALUATED — honest about data starvation.
    rule_statuses: dict[str, dict] = {}
    if not focus:
        for mod_name, module in modules.items():
            for rule in module.rules:
                ok, missing = check_rule_fields(rule, events)
                if not ok:
                    rule_statuses[rule.rule_id] = {
                        "status": "NOT_EVALUATED",
                        "reason": f"Required fields missing from normalize output: {missing}",
                    }
    if rule_statuses:
        print(f"  Field check: {len(rule_statuses)} rule(s) NOT_EVALUATED "
              f"(required fields absent from normalized data)",
              file=sys.stderr)
        for rid, info in rule_statuses.items():
            console.detail(f"  NOT_EVALUATED: {rid} — {info['reason']}")

    # Detect: deterministic baseline first. Count per-rule hits so ruleset.yaml
    # can record which rules fired (and how often) vs. stayed silent.
    anchors = []
    rule_hits: dict[str, int] = {}
    for e in events:
        for rule in rules_by_type.get(e.artifact_type, []):
            if rule.rule_id in rule_statuses:
                continue  # NOT_EVALUATED — required fields missing
            try:
                a = rule.predicate(e)
            except Exception as ex:
                console.detail(f"rule {rule.rule_id} error: {ex}")
                continue
            if a:
                anchors.append(a)
                rule_hits[rule.rule_id] = rule_hits.get(rule.rule_id, 0) + 1

    # Then analyst-directed include/boost anchors (additive). Track which
    # anchors are directed so findings can be tagged rule_origin: user_directed.
    directed_anchors = directives_mod.collect_include_anchors(events, compiled)
    directed_ids = {id(a) for a in directed_anchors}
    anchors += directed_anchors

    # Collapse duplicate hits of the same claim into one finding each, but COUNT
    # the distinct sources behind each claim instead of discarding the extras —
    # when two engines (e.g. volatility3 + memprocfs) detect the same thing,
    # the finding is corroborated (CONFIRMED) rather than single-source.
    groups = corroborate(anchors)
    from spectre.pipeline.correlation.process import process_refs_for_events
    if len(groups) != len(anchors):
        print(f"  Corroborated {len(anchors)} anchor(s) -> {len(groups)} claim(s)",
              file=sys.stderr)
    cross = sum(1 for g in groups if g.cross_validated)
    if cross:
        print(f"  {cross} claim(s) cross-validated by 2+ sources", file=sys.stderr)
    print(f"  Detection: {len(groups)} finding(s) from {len(anchors)} anchor(s)",
          file=sys.stderr)

    # Detection succeeded — only now retire the prior run's findings.
    _sup = supersede_prior_findings(case_dir, reason="phase 3 re-run",
                                    run_id=_run_id["run_id"])
    if _sup["problems"]:
        custody.note_tamper(case_dir, "finding_tampered", 3, _sup["problems"],
                            "phase_runner._run_phase_3_live")
        return {"error": "prior findings failed their custody check: "
                         + "; ".join(_sup["problems"][:5]), "success": False}
    if _sup["superseded"]:
        console.note(f"Re-run: {len(_sup['superseded'])} prior finding(s) "
                     f"superseded -> findings/superseded/")

    canary_status = manifest.get("canary_status", "FULL")
    findings_summary = []

    if groups:
        finding_num = get_next_finding_number(str(Path(case_dir) / "findings"))
        for g in groups:
            a = g.representative
            fk_name = ARTIFACT_FK.get(a.artifact_type, _DEFAULT_FK)
            fk_path = _find_fk(fk_name)
            # Find the handle that produced this event (provenance link).
            # Prefer the exact handle by execution_id — a single evidence
            # file can go through multiple extract passes with the SAME
            # tool (e.g. pcap: tcpdump for conn/dns/http/timing) or
            # different tools (tshark for the smb2-pipe pass), all sharing
            # one evidence_path. handle_by_tool and handle_by_evidence both
            # collapse same-tool multi-pass handles to "last one wins",
            # which would stamp EVERY finding from that file with the last
            # pass's tool/command, corrupting the audit trail for the other
            # passes. handle_by_execution_id is unambiguous; the other two
            # dicts remain as fallbacks for events with no execution_id
            # (e.g. hand-built NormEvents in tests/fixtures).
            handle = handle_by_execution_id.get(a.event.source_execution_id)
            if handle is None:
                handle = handle_by_tool.get((a.event.source_file, a.event.source_tool))
            if handle is None:
                handle = handle_by_evidence.get(a.event.source_file)
            # No handle identified: cite nothing rather than an arbitrary
            # handle's tool_exec row. The empty id fails Phase 4's
            # evidence_ref gate.
            if handle is None:
                handle = {"execution_id": "", "line_count": 1, "size_bytes": 1}
            # One evidence_ref per corroborating source (its own tool_exec row).
            extra_refs = []
            for m in g.members:
                mh = (handle_by_execution_id.get(m.event.source_execution_id)
                      or handle_by_tool.get((m.event.source_file, m.event.source_tool)))
                if mh and mh.get("execution_id"):
                    extra_refs.append({"execution_id": mh["execution_id"]})
            origin = "user_directed" if id(a) in directed_ids else "deterministic"
            # Non-destructive analyst scoping: exclude tags + retains; boost
            # raises priority. Both evaluated against the triggering event.
            excluded_by = directives_mod.excluded_by(a.event, compiled)
            boosted_by = directives_mod.boosted_by(a.event, compiled)
            # WS9: relay a per-record timestamp caveat already produced by
            # the normalizer (lnk/prefetch FILETIME overflow, logfile
            # syslog ambiguity) — never authored here, only read off the
            # underlying NormEvent.data so it isn't silently dropped before
            # it reaches the finding.
            ts_caveat = str(a.event.data.get("ts_caveat") or "")
            ts_parse_error = bool(a.event.data.get("ts_parse_error"))
            finding = emit_from_handle(
                handle=handle,
                case_dir=case_dir,
                finding_number=finding_num,
                fk_yaml_path=fk_path,
                mitre_map_path=str(MITRE_MAP_PATH),
                rule_id=a.rule_id,
                title=a.title,
                iocs=a.iocs,
                event_time=a.event.timestamp,  # Evidence time from NormEvent
                canary_status=canary_status,
                corroboration_note=a.summary,
                source_record_id=str(a.event.record_id or ""),
                source_file=str(a.event.source_file or ""),
                rule_origin=origin,
                analyst_excluded=excluded_by,
                analyst_priority=boosted_by,
                sources=g.sources,
                corroboration_labels=g.source_labels,
                extra_evidence_refs=extra_refs,
                confidence=a.confidence,
                mitre=a.mitre,
                host_ip=a.event.host or "",
                occurrence_count=g.occurrence_count,
                first_seen=g.first_seen,
                last_seen=g.last_seen,
                ts_caveat=ts_caveat,
                ts_parse_error=ts_parse_error,
                process_refs=process_refs_for_events(m.event for m in g.members),
            )
            findings_summary.append({
                "finding_id": finding["finding_id"],
                "status": finding["status"],
                "confidence": finding["confidence"],
                "mitre_attack": finding.get("mitre_attack", "UNMAPPED"),
                "rule_id": a.rule_id,
                "rule_origin": origin,
                "analyst_excluded": bool(excluded_by),
            })
            tag = f" origin={origin}"
            if excluded_by:
                tag += f" EXCLUDED({excluded_by})"
            if boosted_by:
                tag += f" BOOST({boosted_by})"
            console.detail(f"{finding['finding_id']} {a.rule_id} "
                  f"status={finding['status']} mitre={finding.get('mitre_attack')}{tag}")
            finding_num += 1

    # Directive accounting: flag any directive that matched no events (targets
    # fields absent from the evidence given) as not-applicable rather than
    # silently doing nothing.
    directive_report = []
    for d in compiled:
        hits = sum(1 for e in events if d.matches(e))
        directive_report.append({
            "directive_id": d.directive_id,
            "type": d.type,
            "polarity": d.polarity,
            "matches": hits,
            "applicable": hits > 0,
        })
        # Directives ride in the unified ruleset.yaml catalog tagged
        # user_directed, so "what we looked for" lives in one place. A
        # directive's hit count is the events it matched (exclude/boost
        # directives act on findings without producing anchors, so events
        # matched is the honest signal of whether it did anything). Not
        # artifact-bound, so artifact_type is "*". Carried even under --focus.
        _dmitre = (d.spec.get("params", {}) or {}).get("mitre", [])
        rule_catalog.append({
            "rule_id": d.directive_id,
            "module": "directive",
            "artifact_type": "*",
            "description": f"analyst {d.polarity} directive ({d.type})",
            "candidate_mitre": _dmitre if isinstance(_dmitre, list) else [],
            "rule_origin": "user_directed",
        })
        rule_hits[d.directive_id] = hits

    # Record the rule pack in force — the full catalog of everything evaluated
    # (deterministic rules AND analyst directives, fired AND silent), with a
    # content hash of each contributing module's rules.py for reproducibility.
    # Mirrors fk_context.yaml's copied-into-the-case provenance, and is audited
    # so the tamper-evident chain covers it. source_hashes covers deterministic
    # modules only; directive provenance lives in directives.json + the audit.
    import hashlib
    from spectre.pipeline.shell_log import log_command

    source_hashes: dict[str, str] = {}
    _hash_by_file: dict[str, str] = {}  # dedup: hash each rules.py once
    for mod_name, src in module_src.items():
        if src not in _hash_by_file:
            try:
                _hash_by_file[src] = hashlib.sha256(
                    Path(src).read_bytes()).hexdigest()
            except OSError:
                continue
        source_hashes[mod_name] = _hash_by_file[src]

    snapshot = build_ruleset_snapshot(
        rule_catalog, rule_hits, source_hashes, focus,
        rule_statuses=rule_statuses)
    ruleset_path = Path(case_dir) / "ruleset.yaml"
    with open(ruleset_path, "w") as f:
        yaml.dump(snapshot, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)
    log_command(
        case_dir=str(case_dir), tool="ruleset-snapshot",
        command="build_ruleset_snapshot(rule_catalog, rule_hits, source_hashes, focus)",
        phase=3, phase_step="S3-ruleset", exit_code=0,
        extra=f"rules={snapshot['rules_evaluated']} fired={snapshot['rules_fired']}",
    )
    print(f"  Ruleset: {snapshot['rules_evaluated']} rule(s) evaluated, "
          f"{snapshot['rules_fired']} fired -> {ruleset_path.name}",
          file=sys.stderr)

    # Severity/tag breakdown of the rules evaluated — a quick coverage read for
    # the reviewer ("we ran 3 high, 5 medium, ..."). Computed from the snapshot
    # so it stays consistent with ruleset.yaml.
    severity_breakdown = _severity_breakdown(snapshot["rules"])
    tag_breakdown: dict[str, int] = {}
    for _r in snapshot["rules"]:
        for _t in _r.get("tags", []):
            tag_breakdown[_t] = tag_breakdown.get(_t, 0) + 1

    # Which plugins/passes were actually EXAMINED this case, regardless of
    # whether they produced any events or findings — from the extraction
    # handles, not from event artifact_types (a plugin that ran and found
    # zero events, e.g. netscan seeing no connections, still counts as
    # examined). This is the ground truth Phase 6's cross-artifact absence
    # signals (D4) key off: a "no outbound connections" claim is only
    # honest when memory_netscan is in this list.
    # W4-1 (R1-F2): a plugin whose run FAILED was not examined — listing it
    # here would ground a false negative ("no outbound connections") on a
    # tool error. Failed plugins are recorded separately.
    plugins_run, plugins_failed = _plugins_examined(handles)

    manifest["detection"] = {
        "anchors_count": len(anchors),
        "findings": findings_summary,
        "rules_evaluated": snapshot["rules_evaluated"],
        "rules_fired": snapshot["rules_fired"],
        "rules_not_evaluated": snapshot.get("rules_not_evaluated", 0),
        "rules_not_evaluated_reasons": [
            {"rule_id": rid, "reason": info["reason"]}
            for rid, info in rule_statuses.items()
        ],
        "severity_breakdown": severity_breakdown,
        "tag_breakdown": tag_breakdown,
        "focus_mode": focus,
        "directed_anchors": len(directed_anchors),
        "directives": directive_report,
        "ruleset_path": "ruleset.yaml",
        "plugins_run": plugins_run,
        "plugins_failed": plugins_failed,
    }
    # R1-G3/F13: Gate 3 was hardcoded True. Zero detections is still a
    # valid, honest outcome; what it checks now is the SKILL.md Gate 3
    # list's mechanical part — verify_chain passes, and every finding this
    # run emitted is on disk.
    from spectre.pipeline.audit import verify_chain
    chain_ok, chain_reason = verify_chain(case_dir)
    _fdir = Path(case_dir) / "findings"
    missing_files = [
        f["finding_id"] for f in findings_summary
        if isinstance(f, dict) and f.get("finding_id")
        and not (_fdir / f"{f['finding_id']}.yaml").exists()
        and not (_fdir / "excluded" / f"{f['finding_id']}.yaml").exists()
    ]
    gate3_passed = bool(chain_ok and not missing_files)
    if gate3_passed:
        _phase3_close_bracket(case_dir, _run_id, len(findings_summary))
    manifest["gate_3"] = {
        "detections": len(anchors),
        "no_detections_raised": "explicit" if len(anchors) == 0 else "n/a",
        "findings_emitted": len(findings_summary),
        "audit_chain_valid": chain_ok,
        "findings_missing_on_disk": missing_files,
        "passed": gate3_passed,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)
    out = {
        "phase": 3,
        "gate_passed": gate3_passed,
        "detections": len(anchors),
        "findings": findings_summary,
        "success": gate3_passed,
    }
    if not gate3_passed:
        out["error"] = ("Gate 3 failed: "
                        + (f"audit chain invalid ({chain_reason})" if not chain_ok
                           else f"emitted finding(s) missing on disk: {missing_files[:5]}"))
    return out


def _run_phase_3_fixture(case_dir: str, manifest: dict) -> dict:
    """Phase 3 (FIXTURE regression path only — profile 'fixture-test')."""
    # Phase header printed by runner.py wrapper.

    from spectre.core.normalize import normalize
    from spectre.core.detect import detect
    from spectre.core.emit_finding import emit, get_next_finding_number

    # Find the extraction output
    output_dir = Path(case_dir) / RAW_DIR
    evtx_files = sorted(output_dir.glob("*_evtx_dump.json"))
    if not evtx_files:
        return {"error": "No evtx_dump output found — run Phase 2 first",
                "success": False}

    # Load extraction output
    records = json.loads(evtx_files[-1].read_text())
    print(f"  Loaded {len(records)} records from {evtx_files[-1].name}", file=sys.stderr)

    # Normalize
    events = normalize(records, str(FIXTURE_PATH))
    print(f"  Normalized: {len(events)} events", file=sys.stderr)

    # Detect
    anchors = detect(events)
    print(f"  Detection: {len(anchors)} anchor(s)", file=sys.stderr)

    # ── Ruleset snapshot (TB-port T4) ─────────────────────────────────
    # The fixture detect path also emits ruleset.yaml so a fixture case
    # exposes the same per-rule severity contract (rule_id + severity
    # str|null) the live path does. The legacy fixture rule carries no
    # RuleMetadata, so its severity snapshots as null (UNRATED), never an
    # unassessed "medium".
    from spectre.core.detect import RULE_ID as _FIXTURE_RULE_ID
    from spectre.pipeline.shell_log import log_command
    fixture_catalog = [{
        "rule_id": _FIXTURE_RULE_ID,
        "module": "evtx",
        "artifact_type": "evtx_4688",
        "description": "rundll32.exe spawned from a temp/writable path "
                       "(fixture rule)",
        "candidate_mitre": ["T1218.011"],
    }]
    snapshot = build_ruleset_snapshot(
        fixture_catalog, {_FIXTURE_RULE_ID: len(anchors)},
        source_hashes={}, focus=False)
    ruleset_path = Path(case_dir) / "ruleset.yaml"
    with open(ruleset_path, "w") as f:
        yaml.dump(snapshot, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)
    log_command(
        case_dir=str(case_dir), tool="ruleset-snapshot",
        command="build_ruleset_snapshot(fixture_catalog, ...)",
        phase=3, phase_step="S3-ruleset", exit_code=0,
        extra=f"rules={snapshot['rules_evaluated']} "
              f"fired={snapshot['rules_fired']}",
    )

    if not anchors:
        print("  No detections raised", file=sys.stderr)
        manifest["gate_3"] = {
            "detections": 0,
            "anchors": [],
            "no_detections_raised": "explicit",
            "passed": True,  # Explicit "no detections" is valid
            "checked_at": _utcnow(),
        }
        _save_manifest(manifest, case_dir)
        return {"phase": 3, "gate_passed": True, "detections": 0, "success": True}

    # Emit findings for each anchor
    fk_yaml_path = str(FK_DIR / "evtx_4688.yaml")
    finding_num = get_next_finding_number(str(Path(case_dir) / "findings"))
    findings = []
    case_name = Path(case_dir).name  # e.g. "004-phase6-test"

    # The findings cite the tool_exec row Phase 2 wrote for this extraction
    # output; empty (unresolved in Phase 4) if no such row exists.
    from spectre.core.validators import _read_audit_rows, EVIDENCE_REF_SOURCE
    source_execution_id = ""
    for row in _read_audit_rows(case_dir):
        if ((row.get("actor"), row.get("action")) == EVIDENCE_REF_SOURCE
                and Path(str(row.get("output_path") or "")).name == evtx_files[-1].name):
            source_execution_id = row.get("entry_sha256", "")

    for anchor in anchors:
        console.detail(f"rec={anchor.record_number} rule={anchor.rule_id} "
              f"dll={anchor.dll_path}")

        finding = emit(anchor, case_dir, finding_num,
                       fk_yaml_path, str(MITRE_MAP_PATH),
                       case_id=case_name,
                       source_execution_id=source_execution_id)
        findings.append(finding)
        finding_num += 1

    # Write findings summary
    findings_summary = []
    for f in findings:
        summary = {
            "finding_id": f["finding_id"],
            "status": f["status"],
            "confidence": f["confidence"],
            "mitre_attack": f.get("mitre_attack", "UNMAPPED"),
            "rule_id": anchors[0].rule_id if anchors else "unknown",
        }
        findings_summary.append(summary)
        console.detail(f"{f['finding_id']} status={f['status']} "
              f"confidence={f['confidence']} mitre={f.get('mitre_attack', '?')}")

    # Check anti-forensics (basic checks)
    anti_forensics = {
        "timestomping": "not checked (fixture mode)",
        "log_clearing": "not checked (fixture mode)",
        "prefetch_anomaly": "not checked (fixture mode)",
    }

    # Update manifest
    manifest["detection"] = {
        "anchors_count": len(anchors),
        "findings": findings_summary,
        "anti_forensics": anti_forensics,
    }
    manifest["gate_3"] = {
        "detections": len(anchors),
        "no_detections_raised": "explicit" if len(anchors) == 0 else "n/a",
        "findings_emitted": len(findings),
        "anti_forensics_checked": True,
        "passed": True,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    return {
        "phase": 3,
        "gate_passed": True,
        "detections": len(anchors),
        "findings": findings_summary,
        "success": True,
    }


def run_phase_4(case_dir: str, manifest: dict) -> dict:
    """Phase 4: Correlation + Verification.

    Runs verify_chain, then requires each finding to have evidence_refs
    whose every execution_id resolves to a chained deterministic-core
    tool_exec row in this case's audit.jsonl (none resolve if the chain
    fails). A finding failing either check gets a failed correlation entry,
    is left out of clustering, and fails gate_4; an unresolved one also gets
    an `evidence_ref_unresolved` audit row.
    """
    # Phase header printed by runner.py wrapper.

    from spectre.pipeline.audit import verify_chain
    from spectre.pipeline.correlation import purge_dropped_findings

    # WS3 built purge_dropped_findings() (0-source / DROPPED-status finding
    # YAMLs) but never wired it into the live pipeline -- emit_finding.py
    # writes a finding for every anchor regardless of status, and no other
    # code path ever unlinked one, contradicting the "0 sources -> DROPPED
    # (auto-purged)" claim in skills/correlation-engine/SKILL.md /
    # skills/report-generator/SKILL.md. Phase 4 already globs findings/ next
    # -- purge first so the correlation pass (and everything downstream:
    # Phase 6's report, iocs.csv, ...) never sees a DROPPED finding at all.
    purge_dropped_findings(case_dir)

    findings_dir = Path(case_dir) / "findings"
    finding_files = sorted(findings_dir.glob("F-*-*.yaml"))

    if not finding_files:
        print("  No findings to correlate", file=sys.stderr)
        # A8-F3: this branch used to hardcode verify_chain=True/passed=True
        # WITHOUT ever calling verify_chain() — a case with zero findings
        # that stops at --phase 6 (a fully supported, documented
        # invocation) never got its audit chain examined at all. Actually
        # call it, same as the non-zero-findings path below.
        ok, reason = verify_chain(case_dir)
        print(f"  Audit chain: {'VALID' if ok else 'INVALID'} ({reason})", file=sys.stderr)
        manifest["gate_4"] = {
            "findings_correlated": 0,
            "verify_chain": ok,
            "verify_chain_reason": reason,
            "passed": ok,
            "checked_at": _utcnow(),
        }
        _save_manifest(manifest, case_dir)
        return {"phase": 4, "gate_passed": ok, "findings_correlated": 0, "success": ok}

    from spectre.core.validators import (
        _read_audit_rows, resolvable_execution_ids, unresolved_evidence_refs,
    )
    from spectre.pipeline.audit import append as audit_append

    # Verify the chain BEFORE resolving refs against it: a ref may only be
    # resolved by a row of a chain that verifies. A broken or missing
    # audit.jsonl leaves the resolvable set empty, so every ref fails closed.
    ok, reason = verify_chain(case_dir)
    resolvable = resolvable_execution_ids(_read_audit_rows(case_dir)) if ok else set()

    correlation_results = []
    loaded_findings = []
    for fp in finding_files:
        finding = yaml.safe_load(fp.read_text())
        fid = finding.get("finding_id", "?")

        # Validate: every finding must have evidence_refs
        ev_refs = finding.get("evidence_refs", [])
        if not ev_refs:
            correlation_results.append({
                "finding_id": fid,
                "error": "DROPPED: 0 source findings",
                "passed": False,
            })
            continue

        # Every evidence_ref must cite a chained deterministic-core tool_exec
        # row in this case's audit.jsonl. Handled like the empty-refs case
        # above, plus one chained row naming the finding and the ids.
        unresolved = unresolved_evidence_refs(finding, resolvable)
        if unresolved:
            correlation_results.append({
                "finding_id": fid,
                "error": "UNRESOLVED evidence_refs: " + ", ".join(unresolved),
                "unresolved_execution_ids": unresolved,
                "passed": False,
            })
            console.note(f"{fid}: unresolved evidence_refs {unresolved}")
            # Only a verified chain is extended; a broken or missing one
            # already fails the gate via verify_chain.
            if ok:
                audit_append(case_dir, {
                    "actor": "deterministic-core",
                    "action": "evidence_ref_unresolved",
                    "tool": "spectre-core",
                    "tool_version": "0.1",
                    "exact_command": "validators.unresolved_evidence_refs() "
                                     "— deterministic, no CLI",
                    "params": {"unresolved_execution_ids": unresolved},
                    "case_id": Path(case_dir).name,
                    "finding_id": fid,
                    "output_path": "",
                    "output_sha256": "",
                    "result": "failure",
                    "exit_code": 0,
                    "duration_ms": 0,
                    "token_usage": {"prompt": 0, "completion": 0},
                    "phase": 4,
                    "phase_step": "S4-evidence-refs",
                })
            continue

        # Source count (from corroboration)
        sources = finding.get("corroboration", {}).get("sources", 1)
        status = finding.get("status", "?")
        confidence = finding.get("confidence", "?")

        correlation_results.append({
            "finding_id": fid,
            "sources": sources,
            "status": status,
            "confidence": confidence,
            "evidence_refs": len(ev_refs),
            "source_count_ok": sources >= 1,
            "passed": sources >= 1,
        })
        loaded_findings.append(finding)
        console.detail(f"{fid}: sources={sources} status={status} confidence={confidence}")

    print(f"  Audit chain: {'VALID' if ok else 'INVALID'} ({reason})", file=sys.stderr)

    # WS8 (A7 Finding 2 — HIGH): the cross-case index write used to happen
    # HERE, at Phase 4 — three phases before adversarial review, synthesis,
    # or examiner approval, into a store SHARED across every case. It has
    # been moved to Phase 7 (`runner.verify_and_close()`), after which
    # `cross_case_index.update_index()` itself only pulls CONFIRMED
    # (+approved) findings (`_finding_is_indexable()`), so a finding that's
    # still INFERRED, or later REJECTED, never reaches the shared store.
    # Do not re-add an index write here — see cross_case_index.py's module
    # docstring.

    # Cross-artifact clustering (Spec B). Manifest-only — findings untouched.
    from spectre.pipeline.correlation.clustering import cluster_findings
    subject_ips = {str(manifest.get("monitored_ip") or "")}
    subject_ips |= {str(f.get("host_ip") or "") for f in loaded_findings}
    subject_ips.discard("")
    clusters = cluster_findings(loaded_findings, subject_ips)
    manifest["correlation_clusters"] = clusters
    audit_append(case_dir, {
        "actor": "deterministic-core",
        "action": "note",
        "tool": "correlation-clustering",
        "tool_version": "0.1",
        "exact_command": "correlation.clustering.cluster_findings() — deterministic, no CLI",
        "params": {"ioc_overlap": len(clusters["ioc_overlap"]),
                   "temporal": len(clusters["temporal"])},
        "case_id": Path(case_dir).name,
        "output_path": "",
        "output_sha256": "",
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "token_usage": {"prompt": 0, "completion": 0},
        "phase": 4,
        "phase_step": "S4-cluster",
    })

    # Update manifest
    manifest["correlation"] = correlation_results
    manifest["gate_4"] = {
        "findings_correlated": len(correlation_results),
        "all_have_sources": all(r.get("passed", False) for r in correlation_results),
        "verify_chain": ok,
        # WS8 (A7 Finding 2): the cross-case index write moved to Phase 7
        # (post-approval) — it no longer happens here, so this must not
        # claim it did. See gate_7.cross_case_updated for the real flag.
        "cross_case_updated": False,
        "passed": ok and all(r.get("passed", False) for r in correlation_results),
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    return {
        "phase": 4,
        "gate_passed": ok,
        "correlation": correlation_results,
        "verify_chain": ok,
        "success": ok,
    }


def _run_substantive_adversarial(case_dir: str, all_findings: list[dict],
                                  manifest: dict,
                                  provider_name: str | None = None) -> dict:
    """Mechanism B (WS7e) — case-level devil's-advocate review.

    Wires the previously-dead `build_adversarial_context()`
    (subagent_templates.py) into a real provider call, branching by provider
    exactly like report_synthesize.synthesize_report() does for the report
    narrative. This is a SEPARATE mechanism from the per-finding
    `explain(adversarial=True)` grounding probe run by the caller — that one
    is a red-team self-test of Validator #5; this one is the substantive
    "challenge the narrative" review (counter-hypotheses, evidence/citation
    gaps, alternative timeline) that the methodology (skills/methodology) describes.

    Advisory only, always: the returned dict is stored under
    `manifest["gate_5"]["adversarial_review"]` and NEVER reaches
    `explain._finalize()` or a F-*.yaml file — no code path here mutates a
    finding's confidence or status.

    Returns a dict with at least: status ("ran"|"deferred-to-host"|"not-run"),
    counter_hypotheses, counter_hypotheses_count, evidence_gaps,
    citation_gaps, alternative_timeline, violations, llm_used, api_error.
    In the "deferred-to-host" case it also carries `request` (system/user/
    schema bundle) + `ingest` — the caller finalizes via
    `explain.ingest_host_adversarial()`.
    """
    from spectre.core.explain import ADVERSARIAL_SCHEMA, _validate_adversarial
    from spectre.pipeline.subagent_templates import build_adversarial_context
    from spectre.llm import get_provider

    empty: dict[str, Any] = {
        "status": "not-run",
        "counter_hypotheses": [],
        "counter_hypotheses_count": 0,
        "evidence_gaps": [],
        "citation_gaps": [],
        "alternative_timeline": [],
        "violations": [],
        "llm_used": False,
        "api_error": None,
        "provider": None,
    }
    if not all_findings:
        return dict(empty)

    # Case-scoped MITRE set (R2-01): the union of each finding's OWN
    # per-rule set (its rule's mitre-map `allowed` ∩ what emit kept) —
    # never every rule's list. Same helper as the report seam.
    from spectre.core.validators import case_allowed_mitre, load_mitre_map
    allowed_mitre: list[str] = case_allowed_mitre(
        all_findings, load_mitre_map(), case_dir)

    ctx = build_adversarial_context(
        all_findings,
        evidence_manifest={"evidence": manifest.get("evidence", [])},
        artifact_profile=manifest.get("artifact_profile"),
    )
    system_prompt = (
        "You are a forensic adversarial reviewer — the devil's advocate. "
        "You may only critique EXISTING findings by their finding_id; you may "
        "NOT invent findings, MITRE ATT&CK IDs, or network/host IOCs not "
        "already present in the case data. Output valid JSON only, matching "
        "the required schema."
    )
    user_prompt = (
        ctx["context"]
        + "\n\nOutput valid JSON matching this schema: "
        + json.dumps(ADVERSARIAL_SCHEMA)
    )

    provider = get_provider(provider_name)
    resp = provider.complete(system_prompt, user_prompt, max_tokens=2048,
                             schema=ADVERSARIAL_SCHEMA)

    if resp.deferred:
        result = dict(empty)
        result["status"] = "deferred-to-host"
        result["api_error"] = ("host mode — substantive adversarial review "
                               "deferred to orchestrating agent")
        result["request"] = resp.request
        result["ingest"] = {"case_dir": case_dir, "allowed_mitre": allowed_mitre}
        return result

    if resp.parsed is None:
        result = dict(empty)
        result["status"] = "not-run"
        result["api_error"] = (resp.error
                               or "deterministic-only — no narrative provider configured")
        result["provider"] = provider.name
        return result

    cleaned, violations = _validate_adversarial(resp.parsed, all_findings, allowed_mitre)
    return {
        "status": "ran",
        "counter_hypotheses": cleaned.get("counter_hypotheses", []),
        "counter_hypotheses_count": len(cleaned.get("counter_hypotheses", [])),
        "evidence_gaps": cleaned.get("evidence_gaps", []),
        "citation_gaps": cleaned.get("citation_gaps", []),
        "alternative_timeline": cleaned.get("alternative_timeline", []),
        "violations": violations,
        "llm_used": True,
        "api_error": None,
        "provider": provider.name,
    }


def run_phase_5(case_dir: str, manifest: dict, skip_ai: bool = False) -> dict:
    """Phase 5: Adversarial Review — two independent mechanisms.

    Mechanism A ("grounding_probe"): the pre-existing per-finding
    `explain(adversarial=True)` red-team probe of Validator #5. Its SUCCESS
    criterion is that the injected, fabricated C2 claim gets stripped — it
    is an integrity self-test, not a forensic review, and is named
    accordingly everywhere outside explain.py.

    Mechanism B ("substantive_review", `_run_substantive_adversarial`
    above): a real case-level devil's-advocate pass — counter-hypotheses,
    evidence gaps, citation gaps, alternative timeline. Advisory only;
    never blocks the gate and never mutates a finding.

    Gate outcome (`manifest["gate_5"]["status"]`):
      FAIL     — the grounding probe's poison SURVIVED into a probe
                 output description (Validator #5 broken), or a normal
                 explain pass was persist-refused (tamper signal). Blocks
                 Phase 6 (`success=False`).
      DEGRADED — an honest "couldn't run" state (host-deferred / null
                 not-run) for either mechanism, or the substantive review
                 surfaced evidence/citation gaps. Never blocks
                 (`success=True`).
      PASS     — both mechanisms ran clean, or there were no findings.

    W4-3 (R1-F6): under --skip-ai both mechanisms run through the `null`
    provider (deterministic "not-run" path) — gate_5 is still written and
    records `skip_ai`, so the report discloses that no review happened.
    """
    provider_name = "null" if skip_ai else None
    # Phase header printed by runner.py wrapper.

    from spectre.core.explain import explain, ADVERSARIAL_POISON_IP
    from spectre.pipeline.audit import append as audit_append

    findings_dir = Path(case_dir) / "findings"
    finding_files = sorted(findings_dir.glob("F-*-*.yaml"))
    case_name = Path(case_dir).name

    if not finding_files:
        print("  No findings to review", file=sys.stderr)
        manifest["gate_5"] = {
            "adversarial_reviewed": 0,
            "passed": True,
            "status": "PASS",
            "grounding_probe": "not-run",
            "substantive_review": "not-run",
            "counter_hypotheses_count": 0,
            "skip_ai": bool(skip_ai),
            "degraded_reason": None,
            "adversarial_review": None,
            "checked_at": _utcnow(),
        }
        _save_manifest(manifest, case_dir)
        return {"phase": 5, "gate_passed": True, "reviewed": 0, "success": True}

    grounding_results = []
    loaded_findings = []
    any_deferred = False
    any_null = False
    poison_survived = False
    persist_refused_any = False

    for fp in finding_files:
        finding_path = str(fp)
        # FK YAML routed per finding — evtx caveats on a pcap finding is the
        # exact antipattern the gap reports flag.
        try:
            finding_data = yaml.safe_load(fp.read_text()) or {}
        except yaml.YAMLError:
            finding_data = {}
        loaded_findings.append(finding_data)
        fk_yaml_path = _find_fk(_fk_for_finding(finding_data))

        # Pass 1 — normal explanation: validated output IS persisted into the
        # finding (description + verbatim FK caveats).
        norm = explain(finding_path, fk_yaml_path,
                       str(MITRE_MAP_PATH), case_dir, adversarial=False,
                       case_id=case_name, phase=5, provider_name=provider_name)

        # Pass 2 — grounding probe (Mechanism A): red-team test of the
        # validators. NEVER persisted (explain defaults persist=False when
        # adversarial).
        probe = explain(finding_path, fk_yaml_path,
                        str(MITRE_MAP_PATH), case_dir, adversarial=True,
                        case_id=case_name, phase=5, provider_name=provider_name)

        fid = probe.get("finding_id", norm.get("finding_id", "?"))
        stripped = probe.get("adversarial_stripped", False)
        violations = len(probe.get("violations", []))
        probe_deferred = probe.get("deferred", False) or norm.get("deferred", False)
        probe_output = probe.get("output") or {}
        probe_desc = probe_output.get("description", "") if isinstance(probe_output, dict) else ""
        # A "null"/errored provider is NOT the same as "deferred" — explain()
        # returns no "deferred" key at all for that branch (see explain.py's
        # `resp.parsed is None` path), so `any_deferred` alone silently
        # treats a dead/null provider as if the probe passed. Detect it
        # explicitly instead of relying on `deferred` staying falsy.
        probe_null = (
            probe.get("output") is None
            and not probe.get("deferred", False)
            and bool(probe.get("api_error"))
        )
        if probe_deferred:
            any_deferred = True
        if probe_null:
            any_null = True
        if ADVERSARIAL_POISON_IP in probe_desc:
            poison_survived = True
        if norm.get("persist_refused", False):
            persist_refused_any = True

        grounding_results.append({
            "finding_id": fid,
            "adversarial_stripped": stripped,
            "violations": violations,
            "deferred": probe_deferred,
        })
        console.detail(f"{fid}: stripped={stripped} violations={violations}"
              + (" DEFERRED" if probe_deferred else "")
              + (" NULL" if probe_null else ""))

        # Closes audit.py's phase_coverage check (Check 4), which expects an
        # action="adversarial_review" row per finding_id — nothing wrote one
        # before this. The mechanism is distinguished via phase_step, not
        # the action name (phase_coverage keys off `action` alone).
        audit_append(case_dir, {
            "actor": "deterministic-core",
            "action": "adversarial_review",
            "tool": "phase5-grounding-probe",
            "tool_version": "0.1",
            "exact_command": "phase_runner.run_phase_5() — grounding probe "
                              "(Validator #5 integrity self-test), no CLI",
            "params": {"finding_id": fid, "stripped": stripped,
                       "deferred": probe_deferred, "null": probe_null},
            "case_id": case_name,
            "output_path": "",
            "output_sha256": "",
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "token_usage": {"prompt": 0, "completion": 0},
            "finding_id": fid,
            "phase": 5,
            "phase_step": "S5-grounding-probe",
        })

    # Mechanism B — substantive, case-level review (advisory only).
    substantive = _run_substantive_adversarial(case_dir, loaded_findings, manifest,
                                               provider_name=provider_name)
    substantive_status = substantive["status"]
    counter_hypotheses_count = substantive["counter_hypotheses_count"]
    evidence_gaps = substantive.get("evidence_gaps", [])
    citation_gaps = substantive.get("citation_gaps", [])

    if substantive_status == "ran":
        for ch in substantive.get("counter_hypotheses", []):
            ch_fid = ch.get("finding_id")
            if not ch_fid:
                continue
            audit_append(case_dir, {
                "actor": "deterministic-core",
                "action": "adversarial_review",
                "tool": "phase5-substantive-review",
                "tool_version": "0.1",
                "exact_command": "phase_runner._run_substantive_adversarial() — "
                                  "case-level devil's-advocate pass, no CLI",
                "params": {"finding_id": ch_fid},
                "case_id": case_name,
                "output_path": "",
                "output_sha256": "",
                "result": "success",
                "exit_code": 0,
                "duration_ms": 0,
                "token_usage": {"prompt": 0, "completion": 0},
                "finding_id": ch_fid,
                "phase": 5,
                "phase_step": "S5-substantive-review",
            })

    # Grounding-probe aggregate status label (Mechanism A).
    if any_deferred:
        grounding_probe_status = "deferred-to-host"
    elif any_null:
        grounding_probe_status = "not-run"
    elif poison_survived:
        grounding_probe_status = "broken"
    else:
        grounding_probe_status = "ran"

    # ── Gate outcome ──
    degraded_reason = None
    if poison_survived or persist_refused_any:
        status = "FAIL"
        passed = False
        success = False
        reasons = []
        if poison_survived:
            reasons.append(
                "grounding probe: adversarial C2 poison survived into probe "
                "output description — Validator #5 broken"
            )
        if persist_refused_any:
            reasons.append(
                "persist_refused on a normal explain pass — on-disk finding "
                "no longer matched the last recorded hash (possible tamper)"
            )
        degraded_reason = "; ".join(reasons)
    else:
        passed = True
        success = True
        reasons = []
        if grounding_probe_status in ("deferred-to-host", "not-run"):
            reasons.append(f"grounding probe {grounding_probe_status}")
        if substantive_status in ("deferred-to-host", "not-run"):
            extra = " — deterministic-only, no narrative provider configured" \
                if substantive_status == "not-run" else ""
            reasons.append(f"substantive adversarial review {substantive_status}{extra}")
        if substantive_status == "ran" and (evidence_gaps or citation_gaps):
            reasons.append(
                f"substantive review surfaced {len(evidence_gaps)} evidence "
                f"gap(s), {len(citation_gaps)} citation gap(s)"
            )
        if skip_ai:
            reasons.insert(0, "adversarial review skipped by --skip-ai "
                              "(null provider, deterministic path only)")
        if reasons:
            status = "DEGRADED"
            degraded_reason = "; ".join(reasons)
        else:
            status = "PASS"

    # Renamed from "adversarial_review" (Mechanism A's old, misleading name)
    # — the per-finding list here is the grounding-probe self-test result,
    # not a forensic review. Mechanism B's result lives under
    # gate_5["adversarial_review"] instead.
    manifest["grounding_probe"] = grounding_results
    manifest["gate_5"] = {
        "adversarial_reviewed": len(grounding_results),
        "all_reviewed": True,
        "llm_deferred": any_deferred,
        "grounding_probe": grounding_probe_status,
        "substantive_review": substantive_status,
        "counter_hypotheses_count": counter_hypotheses_count,
        "skip_ai": bool(skip_ai),
        "status": status,
        "passed": passed,
        "degraded_reason": degraded_reason,
        "adversarial_review": substantive,
        "checked_at": _utcnow(),
    }
    _save_manifest(manifest, case_dir)

    return {
        "phase": 5,
        "gate_passed": passed,
        "grounding_probe": grounding_results,
        "adversarial_review": substantive,
        "success": success,
    }


def _load_system_profile(case_dir: str) -> dict:
    """Read raw_extract/normalized_events.json for the memory_systeminfo
    profile signal (Task 7) and return its OS build / hostname / system
    time as plain metadata for the report.

    memory_systeminfo has no rule in rules.py — see
    modules/memory/normalize.py._normalize_systeminfo — so it can never
    emit a finding (the inviolable rule: only the deterministic detection
    core produces findings). This helper feeds the report's System Profile
    section only, never a finding/MITRE data path.

    Returns {} when normalized_events.json is missing/unparsable, no
    memory_systeminfo event is present, or the event carries no usable
    field.
    """
    from spectre.pipeline.custody import CustodyError, read_verified

    events_path = Path(case_dir) / RAW_DIR / "normalized_events.json"
    if not events_path.exists():
        return {}
    try:
        # Review LOW-2: only the Phase-2 bytes the chain vouches for.
        events = json.loads(read_verified(case_dir, events_path) or b"[]")
    except CustodyError as e:
        console.note(f"system profile skipped: {e}")
        return {}
    except json.JSONDecodeError:
        return {}
    if not isinstance(events, list):
        return {}
    for ev in events:
        if not isinstance(ev, dict) or ev.get("artifact_type") != "memory_systeminfo":
            continue
        data = ev.get("data") or {}
        profile = {
            "hostname": data.get("hostname", ""),
            "os_build": data.get("os_build", ""),
            "system_time": data.get("system_time", ""),
        }
        return profile if any(profile.values()) else {}
    return {}


def run_phase_6(case_dir: str, manifest: dict, skip_ai: bool = False) -> dict:
    """Phase 6: Synthesis + Report Generation.

    Uses LLM synthesis (report_synthesize.py) to produce a narrative
    forensic report with guardrails. Falls back to deterministic template
    on --skip-ai or LLM failure.
    """
    from spectre.pipeline.report_synthesize import (
        synthesize_report,
        _merge_report_md,
        _generate_blindspots_md,
        _generate_iocs_csv,
        _load_fk_caveats,
        _dashboard_metrics_sha256,
        deterministic_baseline_banner,
    )
    from spectre.pipeline.audit import append as audit_append
    from spectre.config import MITRE_MAP_PATH, FK_DIRS

    # W4 review MED-1: never build a report over a half-finished Phase-3
    # re-run (prior findings retired, new ones not all emitted) — that is
    # exactly how a false "No indicators of compromise" verdict was made.
    _unfinished = unfinished_phase3_reruns(case_dir)
    if _unfinished:
        return {"phase": 6, "success": False, "gate_passed": False,
                "error": "a Phase 3 re-run did not complete — re-run Phase 3 "
                         "before generating a report: " + "; ".join(_unfinished[:3])}

    findings_dir = Path(case_dir) / "findings"
    finding_files = sorted(findings_dir.glob("F-*-*.yaml"))
    reports_dir = Path(case_dir) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for fp in finding_files:
        all_findings.append(yaml.safe_load(fp.read_text()))

    # System Profile (Task 7 data path): a metadata signal only — never a
    # finding. Wired into the manifest BEFORE _merge_report_md so the
    # report's System Profile section (rendered only when this is present)
    # has it, and it persists to manifest.yaml alongside the rest of the
    # report metadata.
    manifest["system_profile"] = _load_system_profile(case_dir)

    case_id = manifest.get("case_id", "?")
    case_name = manifest.get("case_name", "?")
    # Audit rows record case_id = Path(case_dir).name (e.g. "002-name")
    # everywhere else in the pipeline; this bare form is only for display
    # (case_label below). Using the bare form in an audit row's case_id
    # field made verify_full()'s case_id check spuriously fail on every
    # case that ever reaches Phase 6 (A8-F2 bonus) — standardize on the
    # directory-name form for anything written to audit.jsonl.
    audit_case_id = Path(case_dir).name

    # ── LLM Synthesis (or skip) ──
    synth_start = int(time.time() * 1000)
    synth_result = synthesize_report(
        all_findings, manifest, case_dir, skip_ai=skip_ai
    )

    # host (the default) defers narrative synthesis to the orchestrating
    # agent; with no such agent behind a standalone `spectre` run, there is
    # no implicit fallback to a direct API provider — that used to happen
    # silently whenever a DEEPSEEK_API_KEY was discoverable in the
    # environment or ~/.spectre.env, which is real, undisclosed network
    # egress with case data (R2-06/W1-1). The deterministic template is used
    # instead, and the console note says so plainly; API narrative synthesis
    # now requires explicitly setting SPECTRE_LLM_PROVIDER=<deepseek|
    # anthropic|openai|local>.
    if synth_result.get("deferred") and not skip_ai:
        console.note(
            "narrative synthesis: host provider deferred (no orchestrating "
            "agent) — using deterministic template. To use a direct API "
            "provider instead, set SPECTRE_LLM_PROVIDER=<deepseek|anthropic|"
            "openai|local> explicitly."
        )
    synth_elapsed = int(time.time() * 1000) - synth_start

    llm_used = synth_result.get("llm_used", False)
    violations = synth_result.get("violations", [])

    # Deterministic baseline: there ARE findings, but the AI narrative seam
    # was dead/deferred with no fallback (and --skip-ai wasn't the reason).
    # This is the case gate_6.degraded_reason already flags below.
    is_baseline = bool(all_findings) and not llm_used and not skip_ai

    # ── MITRE map for merge and blindspots ──
    mitre_map = {}
    if MITRE_MAP_PATH.exists():
        mitre_map = yaml.safe_load(MITRE_MAP_PATH.read_text()) or {}

    # ── FK caveats for blindspots ──
    artifact_types = _fk_caveat_types(all_findings)
    fk_caveats_map = _load_fk_caveats(artifact_types, FK_DIRS)

    # ── report.md ──
    report_path = reports_dir / "report.md"
    report_md = _merge_report_md(
        synth_result if llm_used else None,
        all_findings,
        manifest,
        case_dir,
        violations,
        mitre_map,
    )
    if is_baseline:
        report_md = deterministic_baseline_banner() + "\n" + report_md
    report_path.write_text(report_md)
    report_size = report_path.stat().st_size
    console.note(f"report.md: {report_size} bytes")

    # Audit: report write
    report_sha256 = hashlib.sha256(report_md.encode()).hexdigest()
    from spectre.pipeline.custody import case_relative
    _rel_report = case_relative(case_dir, report_path)  # W3-7: portable row
    audit_append(case_dir, {
        "actor": "spectre-lead",
        "action": "note",
        "tool": "report_synthesize._merge_report_md",
        "tool_version": "0.1",
        "exact_command": "report_synthesize._merge_report_md() — deterministic markdown merge",
        "params": {
            "findings_count": len(all_findings),
            "llm_used": llm_used,
            "skip_ai": skip_ai,
            # The disclosure receipt. verify_full()'s coverage_disclosure check
            # asserts every chained coverage_gap row appears here at no smaller
            # a count, and report_integrity already binds THIS row's hash to
            # the report bytes on disk — so regenerating the report with a
            # disclosure dropped fails closed, and a fresh S3 row cannot
            # launder it. Derived from the same coverage.gaps_from_manifest()
            # the Blind Spots section renders, so the receipt cannot claim a
            # disclosure the reader will not find.
            "disclosed_coverage_gaps": _disclosed_coverage_gaps(manifest),
            # TB-port A6: binds the persisted dashboard metrics (the mutable
            # manifest copy the PDF/DOCX dashboards render from) to the
            # chain; verify_full re-hashes it (advisory).
            "dashboard_metrics_sha256": _dashboard_metrics_sha256(
                (manifest.get("report") or {}).get("dashboard_metrics") or {}),
        },
        "case_id": audit_case_id,
        "output_path": _rel_report,
        "output_sha256": report_sha256,
        "result": "success",
        "exit_code": 0,
        "duration_ms": synth_elapsed,
        "token_usage": synth_result.get("token_usage", {}),
        "phase": 6,
        "phase_step": "S3-merge-report",
    })

    # ── report.pdf ──
    # Set the ai_narrative marker BEFORE render_pdf: render_pdf receives
    # `manifest` and _build_cover_html() reads manifest["report"]["ai_narrative"]
    # to decide whether to render the "DETERMINISTIC BASELINE" cover badge.
    # The manifest["report"] dict is updated in place further below (after
    # blindspots.md is written), so this key and dashboard_metrics survive.
    manifest.setdefault("report", {})["ai_narrative"] = llm_used

    from spectre.pipeline.report_pdf import render_pdf
    pdf_path_obj = reports_dir / "report.pdf"
    case_label = f"{case_id}-{case_name}"
    pdf_path, pdf_reason = render_pdf(
        str(report_path), str(pdf_path_obj),
        title=f"Spectre Forensic Report — {case_label}",
        manifest=manifest, findings=all_findings)
    if pdf_path:
        console.note(f"report.pdf: {pdf_path_obj.stat().st_size} bytes")
    else:
        msg = pdf_reason or "report.pdf: skipped (unknown reason)"
        console.note(msg)
        print(f"  ⚠ {msg}", file=sys.stderr)

    # ── report.docx ──
    # The primary deliverable: the examiner edits and signs this during the
    # Phase 7 review, which a PDF cannot support. Same contract as render_pdf
    # (never raises; degrades to None + reason without the 'report' extra), and
    # the same report.md input — report.md stays the single source of truth.
    from spectre.pipeline.report_docx import render_docx
    docx_path_obj = reports_dir / "report.docx"
    docx_path, docx_reason = render_docx(
        str(report_path), str(docx_path_obj),
        title=f"Spectre Forensic Report — {case_label}",
        manifest=manifest, findings=all_findings)
    if docx_path:
        console.note(f"report.docx: {docx_path_obj.stat().st_size} bytes")
    else:
        msg = docx_reason or "report.docx: skipped (unknown reason)"
        console.note(msg)
        print(f"  ⚠ {msg}", file=sys.stderr)

    # ── iocs.csv ──
    iocs_path = reports_dir / "iocs.csv"
    _generate_iocs_csv(all_findings, str(iocs_path))
    print(f"  iocs.csv: {iocs_path.stat().st_size} bytes", file=sys.stderr)

    # ── blindspots.md (case-specific) ──
    bsp_path = reports_dir / "blindspots.md"
    blindspots_md = _generate_blindspots_md(
        all_findings, manifest, mitre_map, fk_caveats_map, case_dir
    )
    if is_baseline:
        blindspots_md += (
            "\n## AI Narrative\n\n"
            "- **AI narrative unavailable — this report is a deterministic "
            "baseline.** The AI synthesis seam was unavailable, deferred, "
            "or failed with no fallback for this run; all findings, MITRE "
            "mappings, and caveats above are complete and deterministic, "
            "but no analyst narrative was written around them.\n"
        )
    bsp_path.write_text(blindspots_md)
    print(f"  blindspots.md: {bsp_path.stat().st_size} bytes", file=sys.stderr)

    # ── Update manifest ──
    # In-place update, never a reassignment: _merge_report_md persisted
    # manifest["report"]["dashboard_metrics"] (TB-port T6), and a wholesale
    # reassignment here silently dropped it before _save_manifest.
    manifest.setdefault("report", {}).update({
        "report_md": str(report_path),
        "report_pdf": pdf_path,
        "report_docx": docx_path,
        "iocs_csv": str(iocs_path),
        "blindspots_md": str(bsp_path),
        "ai_narrative": llm_used,
        "generated_at": _utcnow(),
    })

    # ── Audit: deterministic-baseline note (extends the chain; never
    # mutates prior entries) ──
    if is_baseline:
        audit_append(case_dir, {
            "actor": "spectre-lead",
            "action": "report-baseline",
            "tool": "report_synthesize.deterministic_baseline_banner",
            "tool_version": "0.1",
            "exact_command": "report_synthesize.deterministic_baseline_banner() "
                              "— AI narrative unavailable, report is a deterministic baseline",
            "params": {
                "findings_count": len(all_findings),
                "llm_used": llm_used,
                "skip_ai": skip_ai,
                # Repeated deliberately: verify_full()'s report_integrity and
                # coverage_disclosure checks both read the LATEST
                # S3-merge-report row, which on a baseline run is this one. A
                # receipt on only the first row would leave the baseline path
                # looking like an undisclosed case.
                "disclosed_coverage_gaps": _disclosed_coverage_gaps(manifest),
                "dashboard_metrics_sha256": _dashboard_metrics_sha256(
                    (manifest.get("report") or {}).get("dashboard_metrics") or {}),
            },
            "case_id": audit_case_id,
            "output_path": _rel_report,
            "output_sha256": report_sha256,
            "result": "success",
            "exit_code": 0,
            "duration_ms": 0,
            "phase": 6,
            "phase_step": "S3-merge-report",
        })
    _mitre_ok, _mitre_bad = _mitre_map_complete(all_findings, mitre_map, case_dir)
    manifest["gate_6"] = {
        "report_exists": report_path.exists(),
        "narrative_complete": bool(synth_result.get("executive_summary")),
        "executive_summary_written": bool(synth_result.get("executive_summary")),
        "mitre_map_complete": _mitre_ok,
        "mitre_out_of_map": _mitre_bad,
        "blindspots_populated": bsp_path.stat().st_size > 100,
        "iocs_exported": iocs_path.exists(),
        "explain_violations": len(violations),
        "llm_used": llm_used,
        "verdict_class_consistent": not any(
            "verdict contradicts deterministic class" in v
            for v in synth_result.get("violations", [])
        ),
        "api_error": synth_result.get("api_error"),
        "degraded_reason": "LLM unavailable — report uses deterministic template (no AI narrative)"
            if is_baseline else None,
        "checked_at": _utcnow(),
    }
    gate6_passed = gate_6_passed(manifest["gate_6"])
    manifest["gate_6"]["passed"] = gate6_passed
    _save_manifest(manifest, case_dir)

    return {
        "phase": 6,
        "gate_passed": gate6_passed,
        "report_path": str(report_path),
        "iocs_path": str(iocs_path),
        "blindspots_path": str(bsp_path),
        "llm_used": llm_used,
        "violations": len(violations),
        "success": gate6_passed,
    }


# ── Phase dispatcher ──────────────────────────────────────────────

PHASES = {
    0: run_phase_0,
    1: run_phase_1,
    2: run_phase_2,
    3: run_phase_3,
    4: run_phase_4,
    5: run_phase_5,
    6: run_phase_6,
}


def main():
    parser = argparse.ArgumentParser(
        description="Spectre Phase Runner — run one phase of the 7-phase pipeline"
    )
    parser.add_argument("--case", required=True,
                        help="Case directory (e.g. ~/cases/004-phase6-test)")
    parser.add_argument("--phase", type=int, required=True, choices=range(0, 7),
                        help="Phase to run (0-6)")
    parser.add_argument("--force", action="store_true",
                        help="Run even if previous gate failed")
    parser.add_argument("--skip-ai", action="store_true",
                        help="Deterministic only — skip LLM use (e.g. Phase 1 "
                             "fuzzy-direction expansion, Phase 6 report synthesis).")

    args = parser.parse_args()
    case_dir = os.path.expanduser(args.case)
    phase = args.phase

    if not os.path.isdir(case_dir):
        print(json.dumps({"error": f"Case directory not found: {case_dir}",
                          "success": False}))
        sys.exit(1)

    # Load manifest
    manifest = _load_manifest(case_dir)

    # Gate check: require previous phase gate to pass
    if phase > 0 and not args.force:
        prev_gate = f"gate_{phase - 1}"
        prev = manifest.get(prev_gate, {})
        if not prev.get("passed", False):
            print(json.dumps({
                "error": f"Gate {phase-1} not passed. Run Phase {phase-1} first "
                         f"or use --force.",
                f"gate_{phase-1}": prev,
                "success": False,
            }))
            sys.exit(1)

    # Run phase — W4 review MED-1: gates k..7 are invalid from the moment
    # phase k starts (a crash must not leave them reading "passed").
    if invalidate_later_gates(manifest, phase, include_self=True):
        _save_manifest(manifest, case_dir)
    fn = PHASES[phase]
    try:
        result = fn(case_dir, manifest, args.skip_ai) if phase in (1, 5, 6) \
            else fn(case_dir, manifest)
        print(json.dumps(result, default=str))
    except Exception as e:
        import traceback
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "success": False,
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()
