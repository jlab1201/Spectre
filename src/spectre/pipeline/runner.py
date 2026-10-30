#!/usr/bin/env python3
"""
run.py — Single-command entry point for Spectre forensic pipeline.

Drop evidence, run one command, get findings + report.
Also supports per-phase execution for debugging.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ── Paths ──
from spectre.config import CASES_DIR

from spectre.pipeline.phase_runner import (
    run_phase_0, run_phase_1, run_phase_2,
    run_phase_3, run_phase_4, run_phase_5, run_phase_6,
    _load_manifest, _save_manifest, missing_preceding_phases,
    invalidate_later_gates,
)
from spectre.pipeline.case_setup import (
    PROFILES, evidence_sha_set, find_resumable_cases,
)
from spectre.pipeline import console
from spectre.pipeline.console import phase_banner

# Human-readable phase names (0-indexed, matching --phase / gate_N).
PHASE_NAMES = {
    0: "Case Setup", 1: "Direction", 2: "Raw Events Extraction",
    3: "Detection + Hypothesis", 4: "Correlation + Verification",
    5: "Adversarial Review", 6: "Synthesis + Report", 7: "Verification",
}

# ── Phase descriptions ──
PHASE_HELP = {
    0: "Case setup: canary, evidence registration, FK YAMLs, manifest",
    1: "Direction: synthesize analyst tasking into directed detection rules",
    2: "Raw events extraction: run forensic tools, normalize to typed events + audit rows",
    3: "Detection + hypothesis: normalize → detect → emit findings",
    4: "Correlation + verification: cross-artifact, corroboration scoring",
    5: "Adversarial review: subagent challenges primary narrative",
    6: "Synthesis + report: narrative, MITRE map, blind spots, IOC export",
    7: "Verification: audit chain, cross-case index, summary",
}


def list_profiles():
    """Print available artifact profiles with definitions."""
    print("\nArtifact Profiles (use with --profile):\n")
    for name, cfg in PROFILES.items():
        print(f"  {name}")
        print(f"      {cfg['description']}")
        print(f"      Artifacts: {', '.join(cfg['artifacts'])}")
        print()
    sys.exit(0)


def run_phase(case_dir: str, phase: int, skip_ai: bool = False) -> bool:
    """Run a single phase and return True if it passed."""
    manifest = _load_manifest(case_dir)

    phases = {
        0: ("Phase 0: Case Setup", run_phase_0),
        1: ("Phase 1: Direction", run_phase_1),
        2: ("Phase 2: Raw Events Extraction", run_phase_2),
        3: ("Phase 3: Detection + Hypothesis", run_phase_3),
        4: ("Phase 4: Correlation + Verification", run_phase_4),
        5: ("Phase 5: Adversarial Review", run_phase_5),
        6: ("Phase 6: Synthesis + Report", run_phase_6),
    }
    name, fn = phases[phase]

    # W4-3 (R1-F6): --skip-ai no longer skips Phase 5. It runs through the
    # null provider's deterministic path, writes gate_5, and the report
    # discloses that no adversarial review was performed.

    phase_banner(name, case_dir=case_dir, phase=phase)

    # W3-2 (R1-F8, R2-15): every phase entry re-hashes the registered
    # evidence against its chained evidence_register row (never the mutable
    # manifest) and re-runs evidence_guard on it. A swapped or edited copy
    # stops the pipeline here, before any phase output is built from it.
    if phase > 0 and not _evidence_intact(case_dir, phase):
        return False

    # W4-3 (R1-F6) + W4 review MED-1: invalidate gates k..7 at phase START,
    # not on success. A phase that crashes (Ctrl-C, OOM, timeout) half-way
    # must never leave its own and later gates reading "passed" over
    # output it has already started to replace.
    stale = invalidate_later_gates(manifest, phase, include_self=True)
    if stale:
        _save_manifest(manifest, case_dir)
        print(f"  Invalidated gate(s) {', '.join(map(str, stale))} "
              f"(re-earned as phases re-run)", file=sys.stderr)

    try:
        if phase in (1, 5, 6):
            result = fn(case_dir, manifest, skip_ai)
        else:
            result = fn(case_dir, manifest)
    except Exception as e:
        import traceback
        print(f"\n  FAILED: {e}", file=sys.stderr)
        if not skip_ai:
            traceback.print_exc(file=sys.stderr)
        return False

    if not result.get("success", False):
        print(f"\n  FAILED: {result.get('error', 'unknown')}", file=sys.stderr)
        return False

    print("  OK", file=sys.stderr)
    return True


def _evidence_intact(case_dir: str, phase: int) -> bool:
    """Re-hash registered evidence; print + chain an evidence_tampered row
    and return False on any mismatch (see custody.enforce_evidence)."""
    from spectre.pipeline.custody import enforce_evidence

    problems = enforce_evidence(case_dir, phase)
    if problems:
        print(f"\n  FATAL: evidence integrity check failed at Phase {phase} "
              f"entry — pipeline stopped:", file=sys.stderr)
        for pr in problems[:10]:
            print(f"    - {pr}", file=sys.stderr)
        return False
    return True


def run_phases_range(case_dir: str, start: int, end: int, skip_ai: bool) -> bool:
    """Run phases from start to end inclusive. Returns True if all pass."""
    for phase in range(start, end + 1):
        if not run_phase(case_dir, phase, skip_ai):
            return False
    return True


def _resume_canary_recheck(case_dir: str) -> dict:
    """MUST-FIX 1 (post-review, closes A8-F1 for real): force a fresh
    canary check before any phase > 0 runs, independent of
    missing_preceding_phases().

    run_phase_0() re-checking canary (see its docstring) is correct WHEN
    REACHED, but it is dead code on the resume path: once gate_0.passed is
    True (set once, at case creation), Phase 0 is dropped from
    missing_preceding_phases()'s list forever, so `spectre --case ...
    --phase N` (N > 0) never invokes run_phase_0 again and never
    re-checks canary. Empirically: a case built to Phase 2, resumed with
    `--phase 6`, auto-ran only phases 3, 4, 5 — canary was never touched,
    so a canary that went DEAD between sessions (tools uninstalled, wrong
    venv, disk full, corrupted symbol cache...) was invisible.

    Called unconditionally for every phase > 0 dispatch — fresh-case and
    resumed-case runs alike, deliberately not trying to distinguish the
    two (simpler, harder to regress). DEAD stops the pipeline here, before
    ANY phase or report runs (exit 3, matching case-creation's hard stop
    and run_phase_0's own DEAD branch). FULL/DEGRADED proceed and the
    freshly re-checked status is persisted either way.
    """
    from spectre.pipeline import canary as canary_mod

    manifest = _load_manifest(case_dir)
    result = canary_mod.run_canary(case_dir=case_dir)
    status = result.get("status", "UNKNOWN")
    print(f"  Canary (resume re-check): {status}", file=sys.stderr)

    manifest["canary_status"] = status

    # W3-2 (R1-F8): resume re-hashes all registered evidence (the
    # skills/methodology promise). Mismatch → evidence_tampered row, exit 4.
    if not _evidence_intact(case_dir, 0):
        sys.exit(4)

    if status == "DEAD":
        print(f"\nFATAL: Session canary DEAD (re-checked on resume) — "
              f"core tools unavailable: {result.get('failed_tools', [])}",
              file=sys.stderr)
        manifest.setdefault("gate_0", {})
        manifest["gate_0"]["passed"] = False
        _save_manifest(manifest, case_dir)
        sys.exit(3)

    _save_manifest(manifest, case_dir)
    return manifest


def verify_and_close(case_dir: str, manifest: dict) -> bool:
    """Phase 7: audit chain + comprehensive integrity + cross-case index + summary.

    A8-F2: verify_full() -- the only function that re-hashes evidence
    against the manifest, cross-checks manifest evidence against the
    chained evidence_register row, re-hashes finding YAMLs and report.md,
    and checks the narrative-grounding drift signal -- existed, was
    correct, and was never called anywhere in the pipeline. verify_chain()
    (SHA-256 chain-linkage only) stayed the sole Phase-7 check, so e.g.
    hand-editing manifest.yaml's evidence sha256 sailed through Phase 7
    printing "Audit: VALID". Both checks now gate the phase; verify_chain()
    is kept (not replaced -- verify_full() calls it too, but keeping it
    explicit here preserves the existing "Audit chain: VALID/INVALID" line
    downstream code and prints already depend on).

    verify_full()'s phase_coverage check is advisory for an in-progress
    case (no S3-merge-report row yet). R1-F12: on a COMPLETED case a
    coverage gap (a finding with no adversarial_review row, or created
    after the last report) is a real inconsistency and fails verify_full's
    "ok", and therefore this gate.
    """
    from spectre.pipeline.audit import verify_chain, verify_full, append as audit_append
    from spectre.pipeline.cross_case_index import update_index, retract_case

    case_name = Path(case_dir).name
    findings_dir = Path(case_dir) / "findings"
    finding_files = sorted(findings_dir.glob("F-*-*.yaml"))

    phase_banner("Phase 7: Verification", case_dir=case_dir, phase=7)

    ok, reason = verify_chain(case_dir)
    print(f"  Audit chain: {'VALID' if ok else 'INVALID'} ({reason})", file=sys.stderr)

    full_report = verify_full(case_dir)
    full_ok = full_report.get("ok", False)
    full_checks = {k: v.get("passed", False) for k, v in full_report.get("checks", {}).items()}
    if full_ok:
        print("  Full integrity check: VALID", file=sys.stderr)
    else:
        failed = [name for name, passed in full_checks.items() if not passed]
        print(f"  Full integrity check: FAILED ({', '.join(failed)})", file=sys.stderr)

    overall_ok = ok and full_ok

    # Isolate the cross-case index to the ACTIVE cases-dir (the case's own
    # parent), never the import-time CASES_DIR global — otherwise a run under
    # a custom --cases-dir would still write into the default global store
    # (WS8: cross-case containment, isolation goal). Case dirs always live at
    # {cases_dir}/{case_name}, so the parent IS the active cases-dir.
    #
    # W1-2: only feed a case into the shared cross-case index when Phase 7's
    # integrity result is fully OK (verify_chain AND verify_full both pass).
    # A tampered or otherwise-failing case must never contribute its
    # findings/IOCs into a store every other case's narrative context reads
    # from — indexing it first and finding out about the tamper later would
    # already be too late for whatever already read it.
    cross_case_updated = False
    if overall_ok:
        try:
            update_index(str(Path(case_dir).parent), case_name)
            print("  Cross-case index: updated", file=sys.stderr)
            cross_case_updated = True
        except Exception as e:
            print(f"  Cross-case index: skipped ({e})", file=sys.stderr)
    else:
        print(
            "  Cross-case index: NOT updated (Phase 7 integrity check "
            f"failed — audit_chain_valid={ok}, verify_full_ok={full_ok})",
            file=sys.stderr,
        )
        # W1-2 nits 1+2: the skip must land on the custody record itself,
        # not only stderr, and any rows a PRIOR OK Phase-7 run of this same
        # case already wrote into the shared cross-case index must be
        # retracted -- a later tamper/failure (e.g. resume-and-tamper)
        # must not leave stale rows from a once-clean run still feeding
        # every other case's narrative context. Both are best-effort and
        # must never override the real Phase-7 result already computed
        # above as `overall_ok`.
        try:
            audit_append(case_dir, {
                "actor": "deterministic-core",
                "action": "cross_case_index_skipped",
                "tool": "runner.verify_and_close",
                "tool_version": "1.0",
                "exact_command": "runner.verify_and_close() — Phase 7 "
                                  "integrity check failed",
                "params": {
                    "reason": "phase-7-integrity-failed",
                    "audit_chain_valid": ok,
                    "verify_full_ok": full_ok,
                },
                "case_id": case_name,
                "output_path": "",
                "output_sha256": "",
                "output_format": "text",
                "output_line_count": 0,
                "output_size_bytes": 0,
                "result": "skipped",
                "exit_code": 0,
                "duration_ms": 0,
                "stderr": "",
                "finding_id": None,
                "phase": 7,
                "phase_step": "S-cross-case-index-skip",
            })
        except Exception as e:
            print(f"  (audit row for cross-case-index skip failed: {e})",
                  file=sys.stderr)

        try:
            retracted = retract_case(str(Path(case_dir).parent), case_name)
            print(
                f"  Cross-case index: retracted {retracted.get('removed', 0)} "
                "stale entries from a prior OK run",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"  Cross-case index: retract skipped ({e})", file=sys.stderr)

    # W3-6: Gate 7's approval item, advisory — verification runs BEFORE the
    # examiner signs off (`spectre approve`), so pending decisions are
    # reported, not failed.
    from spectre.pipeline.approval import pending_approvals
    pending = pending_approvals(case_dir)
    if pending:
        print(f"  Approval: {len(pending)} finding(s) awaiting examiner decision "
              f"(spectre approve --case {case_dir} --finding F-… "
              f"--examiner NAME --decision APPROVED|REJECTED|SUPERSEDED "
              f"--rationale TEXT)", file=sys.stderr)

    manifest["gate_7"] = {
        "approval_pending": len(pending),
        "audit_chain_valid": ok,
        "verify_full_ok": full_ok,
        "verify_full_checks": full_checks,
        "cross_case_updated": cross_case_updated,
        "findings_count": len(finding_files),
        "passed": overall_ok,
    }
    _save_manifest(manifest, case_dir)
    return overall_ok


def print_summary(case_dir: str, ok: bool):
    """Print final summary with finding details."""
    findings_dir = Path(case_dir) / "findings"
    finding_files = sorted(findings_dir.glob("F-*-*.yaml"))
    report_path = Path(case_dir) / "reports" / "report.md"

    print(f"\n{'='*60}", file=sys.stderr)
    print("  PIPELINE COMPLETE", file=sys.stderr)
    print(f"  Case: {case_dir}", file=sys.stderr)
    print(f"  Audit: {'VALID' if ok else 'INVALID'}", file=sys.stderr)
    print(f"  Findings: {len(finding_files)}", file=sys.stderr)

    for fp in finding_files:
        import yaml
        f = yaml.safe_load(fp.read_text())
        print(f"    {f['finding_id']}: {f['status']} ({f['confidence']}) "
              f"— {f.get('mitre_attack', '?')}", file=sys.stderr)
        title = f.get('title', '')
        if title:
            print(f"      {title}", file=sys.stderr)

    if report_path.exists():
        print(f"  Report: {report_path}", file=sys.stderr)

    print(f"{'='*60}\n", file=sys.stderr)


EPILOG = """
Examples:
  # Full pipeline with test fixture (no evidence needed)
  %(prog)s --name "test-run" --profile fixture-test

  # Full pipeline with real evidence
  %(prog)s --name "intrusion-case" --profile quick-triage \\
      --evidence /cases/memory.raw /cases/security.evtx

  # Steer the investigation with analyst direction (Phase 1)
  %(prog)s --name "intrusion-case" --evidence /cases/security.evtx \\
      --direction "executable spawned by powershell.exe; exclude 10.0.0.5"

  # Run only Phase 0 (case setup)
  %(prog)s --name "new-case" --profile full-windows --phase 0

  # Run through Phase 3 — auto-runs phases 0-2 first if not done yet
  %(prog)s --name "intrusion-case" --evidence /cases/security.evtx --phase 3

  # Resume the matching case at Phase 5 without prompting (runs missing 4 first)
  %(prog)s --name "intrusion-case" --evidence /cases/security.evtx \\
      --phase 5 --resume

  # Resume an explicit case directory
  %(prog)s --case ~/cases/005-test --phase 3

  # Skip AI calls (phases 5-6) for fast deterministic-only testing
  %(prog)s --name "quick-test" --skip-ai

  # List available artifact profiles
  %(prog)s --list-profiles
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spectre",
        description="Spectre Forensic Pipeline — one command, end to end.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Mode selection ──
    parser.add_argument(
        "--list-profiles", action="store_true",
        help="List available artifact profiles and exit",
    )

    group = parser.add_argument_group("case definition")
    group.add_argument(
        "--name", default=None,
        help="Case name (e.g. 'suspected-intrusion'). Required for new cases.",
    )
    group.add_argument(
        "--case", default=None,
        help="Existing case directory (e.g. ~/cases/005-test). "
             "Use this to resume a run or run a single phase.",
    )
    group.add_argument(
        "--profile", default=None,
        help="Artifact profile. See --list-profiles for options. "
             "Default: 'auto' (recognize dropped evidence) when --evidence "
             "is given, else 'fixture-test'.",
    )
    group.add_argument(
        "--evidence", nargs="*", default=[],
        help="Evidence file paths (space-separated). Read-only, chmod 444 on copy.",
    )
    group.add_argument(
        "--direction", "--message", dest="direction", default="",
        help="Investigator tasking, e.g. \"look for ip 192.158.12.1\", "
             "\"executable spawned by powershell.exe\", or "
             "\"exclude events involving 192.168.12.1\". Synthesized into "
             "directed detection rules in Phase 1 (Direction).",
    )
    group.add_argument(
        "--focus", action="store_true",
        help="Run ONLY analyst-directed directives in Phase 3 (skip the baseline "
             "rule packs). Fast tunnel-vision triage; use with --direction.",
    )

    ctrl = parser.add_argument_group("execution control")
    ctrl.add_argument(
        "--phase", type=int, choices=range(0, 8), default=None,
        help="Run UP TO this phase (0-7): any preceding phases that haven't "
             "completed yet are auto-run first, then phase N is (re)run. "
             "With --name, a prior case built from the same name + evidence is "
             "offered for resume (see --resume/--new-case); --case targets one "
             "explicitly. 0=setup 1=direct 2=extract 3=detect 4=correlate "
             "5=adversarial 6=report 7=verify.",
    )
    ctrl.add_argument(
        "--from-phase", type=int, choices=range(1, 8), default=None,
        help="Run phases FROM this number through the end. "
             "Requires an existing case (--case). "
             "Useful for resuming after a fix.",
    )
    ctrl.add_argument(
        "--resume", action="store_true",
        help="With --phase + --name: if a case with the same name and "
             "evidence exists, continue it (run missing preceding phases) "
             "without prompting.",
    )
    ctrl.add_argument(
        "--new-case", action="store_true",
        help="With --phase + --name: always create a fresh case even if a "
             "matching one exists (don't prompt to resume).",
    )
    ctrl.add_argument(
        "--skip-ai", action="store_true",
        help="Skip LLM-dependent Phase 5 (adversarial review). "
             "Phase 6 (report) still runs with deterministic template. "
             "Faster, zero API cost, good for tool-chain testing.",
    )
    ctrl.add_argument(
        "--force", action="store_true",
        help="Skip gate checks from previous phase.",
    )

    misc = parser.add_argument_group("paths")
    misc.add_argument(
        "--cases-dir", default=str(CASES_DIR),
        help=f"Cases directory (default: {CASES_DIR})",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase stdout verbosity. Default shows phase banners + "
             "summaries only; -v adds step titles, -vv per-item progress, "
             "-vvv debug detail. Step/phase titles are always recorded in "
             "execution.log regardless of this flag.",
    )

    return parser


def _describe_case_progress(match: dict) -> str:
    """One-line progress summary for a resumable case."""
    if match["completed"]:
        return "completed (full pipeline through Phase 7: Verification)"
    last = match["last_phase"]
    if last < 0:
        return "no phases completed yet"
    return f"last reached Phase {last}: {PHASE_NAMES.get(last, '?')}"


def resolve_resume_choice(matches: list, resume: bool, new_case: bool,
                          interactive: bool, matched_on_evidence: bool) -> str | None:
    """Decide whether to continue an existing case or create a new one.

    Returns the case_dir to resume, or None to create a fresh case.
    `--new-case` always wins; `--resume` continues the newest match;
    otherwise prompt when interactive, else default to continuing the newest
    match (the same-name+evidence intent) with a printed notice.
    """
    newest = matches[0]
    scope = "name and evidence" if matched_on_evidence else "name"
    print(f"\n  An existing case matches this {scope}:", file=sys.stderr)
    for m in matches:
        print(f"    {Path(m['case_dir']).name}  —  "
              f"{_describe_case_progress(m)}", file=sys.stderr)
        print(f"      {m['case_dir']}", file=sys.stderr)

    if new_case:
        print("  --new-case: creating a fresh case.", file=sys.stderr)
        return None
    if resume:
        print(f"  --resume: continuing {Path(newest['case_dir']).name}.",
              file=sys.stderr)
        return newest["case_dir"]
    if not interactive:
        print("  Non-interactive: continuing the newest matching case "
              "(use --new-case to force a fresh one).", file=sys.stderr)
        return newest["case_dir"]

    prompt = (f"\n  Continue '{Path(newest['case_dir']).name}' [C] "
              f"or create a new case [n]? ")
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        answer = ""
    if answer in ("n", "new", "no"):
        return None
    return newest["case_dir"]


def main():
    # W3-6 (R1-F3): `spectre approve ...` — the in-process Phase 7 approval
    # writer (see spectre.pipeline.approval). Dispatched before the phase
    # parser so the existing flag-style CLI is unchanged.
    if len(sys.argv) > 1 and sys.argv[1] == "approve":
        from spectre.pipeline.approval import main as approve_main
        sys.exit(approve_main(sys.argv[2:]))

    parser = build_parser()
    args = parser.parse_args()

    # Apply stdout verbosity for the whole run (execution.log is unaffected).
    console.set_verbosity(args.verbose)

    # ── Special actions ──
    if args.list_profiles:
        list_profiles()

    # ── Argument rules ──
    if args.case and args.phase is None and args.from_phase is None:
        parser.error("--case needs --phase or --from-phase")
    if args.from_phase is not None and not args.case:
        parser.error("--from-phase requires --case")

    # ── Resolve default profile ──
    # Drop real files with no --profile → auto-recognize. No evidence and no
    # profile → fixture-test (regression demo) for backward compatibility.
    if args.profile is None:
        args.profile = "auto" if args.evidence else "fixture-test"

    # ── Resolve case directory ──
    case_dir = None

    if args.case:
        # Existing case
        case_dir = os.path.expanduser(args.case)
        if not os.path.isdir(case_dir):
            print(f"ERROR: Case directory not found: {case_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"  Using existing case: {case_dir}", file=sys.stderr)
    else:
        # New case: requires --name
        if not args.name:
            parser.error("--name is required for new cases. "
                         "Use --case for existing cases.")

    # ── Determine execution mode ──
    # Single phase mode: resolve the case (resume a matching one or create a
    # new one), then auto-run any missing preceding phases before phase N.
    if args.phase is not None:
        # Resolve the case directory when one wasn't given explicitly.
        if case_dir is None:
            ev_shas = evidence_sha_set(args.evidence)
            matches = find_resumable_cases(args.cases_dir, args.name, ev_shas)
            chosen = None
            if matches:
                chosen = resolve_resume_choice(
                    matches, resume=args.resume, new_case=args.new_case,
                    interactive=sys.stdin.isatty(),
                    matched_on_evidence=bool(ev_shas),
                )
            if chosen is not None:
                case_dir = chosen
                print(f"  Continuing case: {case_dir}", file=sys.stderr)
            else:
                # Create a fresh case (Phase 0 setup runs here).
                from spectre.pipeline.case_setup import setup_case
                result = setup_case(
                    name=args.name, profile=args.profile,
                    evidence_paths=args.evidence, cases_dir=args.cases_dir,
                    direction=args.direction, focus=args.focus,
                )
                case_dir = result["case_dir"]
                if not result.get("success"):
                    print("FATAL: Case setup failed", file=sys.stderr)
                    sys.exit(1)
                print(f"  Case created: {case_dir}", file=sys.stderr)

        # Phase 0 (setup/gate check): nothing precedes it.
        if args.phase == 0:
            ok = run_phase(case_dir, 0, args.skip_ai)
            sys.exit(0 if ok else 1)

        # MUST-FIX 1: force a fresh canary check before any phase > 0 runs
        # — independent of missing_preceding_phases(), which drops Phase 0
        # (and therefore its canary re-check) forever once gate_0 passes
        # once. See _resume_canary_recheck()'s docstring.
        manifest = _resume_canary_recheck(case_dir)

        # Auto-run preceding phases whose gate hasn't passed yet, in order,
        # then (re)run the requested phase N. Phase 0 is always a gate check.
        missing = missing_preceding_phases(manifest, args.phase)
        if missing:
            labels = ", ".join(f"{p} ({PHASE_NAMES.get(p, '?')})" for p in missing)
            print(f"  Auto-running missing preceding phase(s): {labels}",
                  file=sys.stderr)
        # W4-3 (R1-F6): recompute after every phase — re-running phase k
        # invalidates gates > k, so a later phase that looked complete
        # (e.g. Phase 6 after a missing Phase 5) must run again. Each
        # phase is attempted at most once per invocation (--force safety).
        attempted: set[int] = set()
        while True:
            pending = [p for p in missing_preceding_phases(
                _load_manifest(case_dir), args.phase) if p not in attempted]
            if not pending:
                break
            p = pending[0]
            attempted.add(p)
            if not run_phase(case_dir, p, args.skip_ai):
                if args.force:
                    # A8-F5: --force was parsed but never read — a
                    # documented no-op that gave an examiner stuck on a
                    # failed gate false confidence that it would help.
                    # Wired to match its own help text ("Skip gate checks
                    # from previous phase") and phase_runner.py's separate
                    # --force, which implements the same "run even if
                    # previous gate failed" semantic.
                    print(f"\n  --force: preceding Phase {p} "
                          f"({PHASE_NAMES.get(p, '?')}) failed — "
                          f"continuing anyway.", file=sys.stderr)
                    continue
                print(f"\nFATAL: preceding Phase {p} "
                      f"({PHASE_NAMES.get(p, '?')}) failed.", file=sys.stderr)
                sys.exit(1)

        if args.phase == 7:
            manifest = _load_manifest(case_dir)
            ok = verify_and_close(case_dir, manifest)
            print_summary(case_dir, ok)
            sys.exit(0 if ok else 1)

        ok = run_phase(case_dir, args.phase, args.skip_ai)
        sys.exit(0 if ok else 1)

    # ── Range mode (--from-phase) ──
    if args.from_phase is not None:
        # MUST-FIX 1: same resume-bypass class as --phase mode — --from-phase
        # is documented for "resuming after a fix" and its choices are
        # always >= 1, so Phase 0 (and its canary re-check) never runs on
        # this path either without this call.
        _resume_canary_recheck(case_dir)

        ok = run_phases_range(case_dir, args.from_phase, 6, args.skip_ai)
        if ok:
            manifest = _load_manifest(case_dir)
            ok = verify_and_close(case_dir, manifest)
        print_summary(case_dir, ok)
        sys.exit(0 if ok else 1)

    # ── Full pipeline (default) ──
    print("=" * 60, file=sys.stderr)
    print("  SPECTRE FORENSIC PIPELINE", file=sys.stderr)
    print(f"  Case: {args.name}", file=sys.stderr)
    print(f"  Profile: {args.profile}", file=sys.stderr)
    if args.evidence:
        print(f"  Evidence: {len(args.evidence)} file(s)", file=sys.stderr)
    if args.skip_ai:
        print("  AI: SKIPPED (--skip-ai)", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Phase 0
    from spectre.pipeline.case_setup import setup_case
    result = setup_case(
        name=args.name, profile=args.profile,
        evidence_paths=args.evidence, cases_dir=args.cases_dir,
        direction=args.direction, focus=args.focus,
    )
    if not result.get("success"):
        print(f"\nFATAL: Case setup failed — {result.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)

    case_dir = result["case_dir"]
    case_id = result["case_id"]
    canary = result["canary_status"]

    print(f"\n  Case ID: {case_id}", file=sys.stderr)
    print(f"  Directory: {case_dir}", file=sys.stderr)

    if canary == "DEAD":
        print("\nFATAL: Session canary DEAD — core tools unavailable", file=sys.stderr)
        sys.exit(3)

    # Gate 0
    manifest = _load_manifest(case_dir)
    gate0 = run_phase_0(case_dir, manifest)
    if not gate0.get("success"):
        print("\nFATAL: Gate 0 failed — pipeline stopped", file=sys.stderr)
        sys.exit(1)

    # Phases 1-6
    if not run_phases_range(case_dir, 1, 6, args.skip_ai):
        print("\nFATAL: Pipeline failed. Check output above.", file=sys.stderr)
        sys.exit(1)

    # Phase 7
    manifest = _load_manifest(case_dir)
    ok = verify_and_close(case_dir, manifest)

    # ── Write execution.log summary footer ──
    try:
        from spectre.pipeline.shell_log import write_summary
        write_summary(case_dir)
    except Exception:
        pass

    # Summary
    print_summary(case_dir, ok)

    print(json.dumps({
        "case_id": case_id,
        "case_dir": case_dir,
        "canary": canary,
        "audit_valid": ok,
        "findings": len(sorted(Path(case_dir).glob("findings/F-*-*.yaml"))),
        "success": ok,
    }))

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
