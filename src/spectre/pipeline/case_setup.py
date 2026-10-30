#!/usr/bin/env python3
"""
case_setup.py — Phase 0 orchestrator for Spectre forensic pipeline.

Creates a case directory, runs session canary, registers evidence,
writes manifest.yaml, and loads FK YAML context.

Usage:
    python3 case_setup.py --name "training-run" --profile quick-triage [--evidence <path>...]

Returns (printed to stdout as JSON):
    {"case_dir": "...", "case_id": "NNN", "canary_status": "FULL|DEGRADED|DEAD",
     "manifest_path": "...", "evidence_refs": [...], "fk_yamls_loaded": [...]}
"""

import argparse
import json
import os
import sys
import subprocess
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────
from spectre.config import (
    CASES_DIR, FK_DIRS, RAW_DIR,
)
from spectre.pipeline import console
from spectre.pipeline.console import phase_banner
from spectre.pipeline.shell_log import log_command

# Map a recognized artifact_type to the FK YAML(s) that carry its caveats.
# Used by the "auto" profile so a recognized evidence type still loads KB
# context even though it was never named in a static profile.
# Values can be a single FK name (str) or a list of FK names for container types.
#
# DERIVED from each module's module.yaml `fk_yamls` (pipeline/fk_routing.py) —
# it used to be a hand-written 8-entry dict that exactly covered the 8 modules,
# so a 9th module needed an edit here, and without one `ARTIFACT_FK.get(at, at)`
# resolved silently to a nonexistent FK name. Same shape as before: a bare
# string for a single FK, a list for a container type like a memory image.
from spectre.pipeline.fk_routing import module_fk_sets

ARTIFACT_FK = module_fk_sets()

# ── Artifact profiles ──────────────────────────────────────────────
PROFILES = {
    "auto": {
        "artifacts": [],  # derived at runtime from file recognition
        "description": "Auto: artifacts derived from dropped-file recognition",
    },
    "quick-triage": {
        "artifacts": [
            "evtx_4688", "prefetch", "amcache", "registry_run",
            "mft", "lnk", "shimcache", "srum",
        ],
        "description": "Full quick-triage: EVTX 4688 + file system + registry + SRUM",
    },
    "memory-only": {
        "artifacts": ["memory_pslist", "memory_netscan", "memory_cmdline"],
        "description": "Memory dump only: process list, network, command lines",
    },
    "disk-light": {
        "artifacts": ["mft", "lnk", "prefetch", "amcache", "registry_run"],
        "description": "Disk image light: file system + registry",
    },
    "evtx-focused": {
        "artifacts": ["evtx_4688"],
        "description": "EVTX only: Security 4688 process creation",
    },
    "full-windows": {
        "artifacts": [
            "evtx_4688", "prefetch", "amcache", "registry_run",
            "mft", "lnk", "shimcache", "srum",
        ],
        "description": "Full Windows: all available artifacts (60 indicators)",
    },
    "fixture-test": {
        "artifacts": ["evtx_4688"],
        "description": "Minimal profile for case-000.events.json fixture",
    },
    "network-only": {
        "artifacts": ["pcap", "firewall", "ids"],
        "description": "Network traffic only: PCAP capture + firewall logs + IDS alerts",
    },
    "pcap-focused": {
        "artifacts": ["pcap"],
        "description": "PCAP only: packet capture deep-dive analysis",
    },
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def evidence_sha_set(evidence_paths: list) -> frozenset:
    """SHA-256 of each provided evidence SOURCE file, as a set.

    Used to decide whether a prior case was built from the same evidence.
    Missing/unreadable paths are skipped so a stray argument never blocks a
    match; the empty set means "no evidence provided" (caller matches on name
    alone).
    """
    shas = set()
    for ep in evidence_paths or []:
        p = Path(os.path.expanduser(ep))
        if p.is_file():
            try:
                shas.add(_sha256_file(str(p)))
            except Exception:
                pass
    return frozenset(shas)


def _manifest_sha_set(manifest: dict) -> frozenset:
    """Evidence SHA-256 set recorded in a case manifest."""
    return frozenset(
        ref.get("sha256", "")
        for ref in manifest.get("evidence", [])
        if ref.get("sha256")
    )


def phase_status(manifest: dict) -> tuple:
    """(last_phase_reached, completed) for a case manifest.

    last_phase_reached = highest N in 0..7 whose gate_N passed (-1 if none).
    completed          = gate_7 passed (full pipeline incl. verification).
    """
    last = -1
    for n in range(0, 8):
        if manifest.get(f"gate_{n}", {}).get("passed", False):
            last = n
    completed = manifest.get("gate_7", {}).get("passed", False)
    return last, completed


def find_resumable_cases(cases_dir: str, name: str,
                         ev_shas: frozenset) -> list:
    """Existing cases matching name (+ evidence sha set), newest first.

    Match rule: manifest case_name == name AND, when evidence was provided
    (ev_shas non-empty), the manifest's evidence sha set equals ev_shas.
    With no evidence provided, match on name alone.

    Returns dicts: {case_dir, case_id, manifest, last_phase, completed},
    sorted by case_id descending (newest first).
    """
    import yaml
    base = Path(os.path.expanduser(cases_dir))
    out = []
    if not base.is_dir():
        return out
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        mp = d / "manifest.yaml"
        if not mp.exists():
            continue
        try:
            manifest = yaml.safe_load(mp.read_text()) or {}
        except Exception:
            continue
        if manifest.get("case_name") != name:
            continue
        if ev_shas and _manifest_sha_set(manifest) != ev_shas:
            continue
        last_phase, completed = phase_status(manifest)
        out.append({
            "case_dir": str(d),
            "case_id": str(manifest.get("case_id", d.name)),
            "manifest": manifest,
            "last_phase": last_phase,
            "completed": completed,
        })
    out.sort(key=lambda c: c["case_id"], reverse=True)
    return out


def _read_counter(cases_dir: str | Path) -> int:
    """Read and increment .case-counter under `cases_dir`, creating it if absent.

    `cases_dir` is the EFFECTIVE cases directory setup_case() resolved for
    this run (a caller's explicit --cases-dir, or the config.CASES_DIR
    default) — never the module-level CASES_DIR global directly. Before this
    fix, this function ignored whatever cases_dir setup_case() had already
    resolved and always read/wrote the counter under the import-time global,
    so a run under a custom --cases-dir would silently consume/advance the
    counter in the real default store (and could hand out a case_id already
    taken there, or vice versa). Same class of bug WS8 fixed for the
    cross-case index at runner.verify_and_close()'s call site — follow that
    pattern: derive the path from the real, active directory.

    The mkdir is not defensive tidying — without it the FIRST `spectre --phase
    0` on a fresh install died with a raw FileNotFoundError, because nothing
    creates the cases directory before this write. Invisible in any checkout
    where the directory already exists.

    A corrupt counter recovers from the case directories on disk rather than
    resetting to 1, which would hand a new case a case_id that already exists —
    two cases sharing an id is a chain-of-custody problem, not a cosmetic one.

    W1 fix: the directory rescan used to run ONLY when the counter file was
    missing or unreadable. A present-and-well-formed but STALE counter (a
    store copied from an older snapshot, a case dir created by another
    process/tool without going through this counter, or two cases-dirs
    merged together) still silently reused a case_id that already existed
    on disk — the exact same-id chain-of-custody problem the corrupt-
    counter path already guards against. The counter must never go
    backwards relative to what's actually on disk: always take
    max(counter_from_file, highest existing case dir number).
    """
    cases_dir = Path(os.path.expanduser(str(cases_dir)))
    cases_dir.mkdir(parents=True, exist_ok=True)
    counter_path = cases_dir / ".case-counter"
    n = 0
    if counter_path.exists():
        try:
            n = int(counter_path.read_text().strip())
        except (ValueError, OSError):
            n = 0
    highest_existing = 0
    for child in cases_dir.iterdir():
        if child.is_dir() and child.name[:3].isdigit():
            highest_existing = max(highest_existing, int(child.name[:3]))
    n = max(n, highest_existing)
    new_n = n + 1
    counter_path.write_text(f"{new_n:03d}\n")
    return new_n


def _run_canary(case_dir: str) -> dict:
    """Run session canary and return structured result."""
    from spectre.pipeline.canary import run_canary
    result = run_canary(case_dir=case_dir)
    return result


def _expand_evidence_paths(paths: list[str]) -> tuple[list[str], list[dict]]:
    """Expand --evidence arguments: files pass through, directories are
    walked recursively. Nothing is silently dropped — every skipped entry
    is returned as a record so it lands in the manifest and the report.

    Skips (with reason): missing paths, symlinks (never followed — evidence
    must be the real bytes), empty files, non-regular files.
    Deterministic: results sorted by path.
    """
    files: list[str] = []
    skipped: list[dict] = []

    def consider(p: Path) -> None:
        if p.is_symlink():
            skipped.append({"path": str(p), "reason": "symlink (not followed)"})
            return
        if not p.exists():
            skipped.append({"path": str(p), "reason": "does not exist"})
            return
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_dir() and not child.is_symlink():
                    continue
                consider(child)
            return
        if not p.is_file():
            skipped.append({"path": str(p), "reason": "not a regular file"})
            return
        if p.stat().st_size == 0:
            skipped.append({"path": str(p), "reason": "empty file (0 bytes)"})
            return
        files.append(str(p))

    for raw in paths:
        consider(Path(raw))
    return sorted(set(files)), skipped


def _register_evidence(evidence_path: str, case_dir: str) -> dict:
    """Auto-stage evidence into the case directory, then lock + verify it.

    The dropped source may live on writable, read-only, or fuse-mounted
    media we cannot chmod (e.g. VMware shared folders). Rather than require
    the SOURCE to already be read-only, we make the case's own copy the
    protected artifact:

      1. hash the source at ingest (chain of custody starts here),
      2. copy it into <case>/evidence/,
      3. chmod 444 the copy,
      4. guard the copy and verify its hash matches the source.

    Returns: {"ok", "reason", "sha256", "evidence_path", "evidence_relpath",
    "original_path"}
    """
    src = Path(evidence_path)
    if not src.exists():
        return {"ok": False, "reason": f"source does not exist: {src}",
                "sha256": "", "evidence_path": str(src)}
    if not src.is_file():
        return {"ok": False, "reason": f"source is not a regular file: {src}",
                "sha256": "", "evidence_path": str(src)}

    # Step 1: hash the source at ingest (O_RDONLY; no write-bit needed).
    try:
        src_sha = _sha256_file(str(src))
    except Exception as e:
        return {"ok": False, "reason": f"cannot read source: {e}",
                "sha256": "", "evidence_path": str(src)}
    source_writable = os.access(src, os.W_OK)

    # Step 2: auto-stage — copy the source into the case evidence dir.
    # Basename collisions are content-addressed, NEVER overwritten: a second
    # "Security.evtx" from another host becomes Security__<sha8>.evtx.
    # An identical re-submission (same sha256) reuses the staged copy.
    evidence_dir = Path(case_dir) / "evidence"
    dst = evidence_dir / src.name
    # W3-2: evidence/ is locked 0555 after registration; adding evidence to
    # an existing case re-opens it only for the duration of this staging.
    relock = _unlock_evidence_dir(evidence_dir)
    try:
        return _stage_and_register(src, dst, evidence_dir, src_sha,
                                   source_writable, evidence_path, case_dir)
    finally:
        if relock:
            lock_evidence_dir(case_dir)


def _unlock_evidence_dir(evidence_dir: Path) -> bool:
    """Make a locked evidence/ writable again; True if it was locked."""
    try:
        mode = evidence_dir.stat().st_mode & 0o777
    except OSError:
        return False
    if mode & 0o200:
        return False
    os.chmod(evidence_dir, mode | 0o700)
    return True


def lock_evidence_dir(case_dir: str) -> None:
    """W3-2 (R2-15): chmod 0555 the case's evidence/ directory.

    A 444 file does not stop ``mv``/``rm`` in a writable parent, which let a
    substituted file be swapped in before Phase 2 and restored before Phase 7.
    With evidence/ 0555 that swap needs an explicit chmod first (raises the
    bar only — the same OS user can still chmod; phase-entry re-hashing is
    the detective control). ``evidence/derived/`` is created first and stays
    writable: Phase 2 carving writes there."""
    evidence_dir = Path(case_dir) / "evidence"
    if not evidence_dir.is_dir():
        return
    try:
        (evidence_dir / "derived").mkdir(exist_ok=True)
        os.chmod(evidence_dir, 0o555)
    except OSError:
        pass


def _stage_and_register(src: Path, dst: Path, evidence_dir: Path, src_sha: str,
                        source_writable: bool, evidence_path: str,
                        case_dir: str) -> dict:
    """Steps 2-5 of _register_evidence (split out so the evidence/ unlock
    above always relocks, whatever path returns)."""
    from spectre.pipeline.evidence_guard import guard
    from spectre.pipeline.custody import case_relative
    import shutil

    duplicate = False
    # Review LOW-3: a symlink planted in evidence/ is never an evidence copy
    # (it would let content change without touching the 0555 directory).
    for cand in (dst, evidence_dir / f"{src.stem}__{src_sha[:8]}{src.suffix}"):
        if cand.is_symlink():
            return {"ok": False,
                    "reason": f"refusing symlink in evidence/: {cand.name}",
                    "sha256": src_sha, "evidence_path": str(src)}
    if dst.exists():
        if _sha256_file(str(dst)) == src_sha:
            duplicate = True
        else:
            dst = evidence_dir / f"{src.stem}__{src_sha[:8]}{src.suffix}"
            if dst.exists() and _sha256_file(str(dst)) == src_sha:
                duplicate = True
    if not duplicate:
        try:
            shutil.copy2(src, dst)
        except Exception as e:
            return {"ok": False, "reason": f"staging copy failed: {e}",
                    "sha256": src_sha, "evidence_path": str(src)}

    # Step 3: lock the copy read-only — this is now the protected artifact.
    try:
        os.chmod(dst, 0o444)
    except OSError as e:
        return {"ok": False, "reason": f"could not lock staged copy: {e}",
                "sha256": src_sha, "evidence_path": str(dst)}

    # Step 4: guard the copy and verify integrity against the ingest hash.
    ok, reason, dst_sha = guard(str(dst), case_dir=case_dir,
                                skip_parent_check=True)
    if not ok:
        return {"ok": False, "reason": f"staged-copy guard failed: {reason}",
                "sha256": dst_sha, "evidence_path": str(dst)}
    if dst_sha != src_sha:
        return {"ok": False,
                "reason": "hash mismatch after staging (copy != source)",
                "sha256": src_sha, "evidence_path": str(dst)}

    # Step 5: audit the registration.
    from spectre.pipeline.audit import append as audit_append
    entry = {
        "actor": "case_setup",
        "action": "evidence_register",
        "tool": "case_setup.py",
        "tool_version": "1.1.0",
        "exact_command": f"case_setup.py --evidence {evidence_path}",
        "params": {
            "original_path": str(src),
            # W3-7 (R1-F10): case-relative, so a handed-off/archived case
            # directory verifies its OWN evidence copy wherever it now lives.
            "copy_path": case_relative(case_dir, dst),
            "auto_staged": True,
            "source_writable_at_ingest": source_writable,
            "duplicate_reuse": duplicate,
        },
        "case_id": Path(case_dir).name,
        "output_path": case_relative(case_dir, dst),
        "output_sha256": src_sha,
        "result": "success",
        "exit_code": 0,
        "duration_ms": 0,
        "phase": 0,
        "phase_step": "S2-register",
    }
    audit_append(case_dir, entry)

    return {
        "ok": True,
        "reason": ("duplicate of already-staged evidence (same sha256)"
                   if duplicate else "Evidence auto-staged + registered"),
        "sha256": src_sha,
        "evidence_path": str(dst),
        "evidence_relpath": case_relative(case_dir, dst),
        "original_path": str(src),
    }


def _load_fk_yaml(artifact_name: str) -> dict:
    """Load FK YAML for an artifact if it exists."""
    for fk_dir in FK_DIRS:
        yaml_path = fk_dir / f"{artifact_name}.yaml"
        if yaml_path.exists():
            import yaml
            with open(yaml_path) as f:
                return yaml.safe_load(f) or {}
    return {}


def _run_episodic_recall(evidence_refs: list) -> dict:
    """Cross-case recall: has THIS evidence been seen in a prior case?

    At Phase 0 the case has no findings yet, so recall is seeded from the
    identifiers available now — the evidence SHA-256 and its original file
    path — and matched against the cross-case IOC index.

    Returns {ioc_type: [match, ...]} for any cross-case hits, or {} if none.
    """
    from spectre.pipeline.cross_case_index import search_index

    recalls: dict = {}
    for ref in evidence_refs:
        sha = ref.get("sha256", "")
        if sha:
            matches = search_index(ioc_type="sha256", value=sha)
            if matches:
                recalls.setdefault("sha256", []).extend(matches)
        orig = ref.get("original_path", "")
        if orig:
            matches = search_index(ioc_type="filepath", value=orig)
            if matches:
                recalls.setdefault("filepath", []).extend(matches)
    return recalls


def _extract_evidence_metadata(case_dir: str, triage_records: dict) -> dict:
    """Extract structural metadata from registered evidence files.

    Phase 0 preparation — answers "WHAT is this evidence?" before extraction.
    Runs lightweight, deterministic tools that complete in <10s per file.

    Returns dict keyed by evidence_path, suitable for manifest["evidence_metadata"].
    """

    metadata = {}

    for ev_path, rec in triage_records.items():
        module = rec.get("module", "")
        artifact_type = rec.get("artifact_type", "")
        entry = {"type": artifact_type, "module": module}
        evidence_file = rec.get("path", ev_path)

        # ── File-level metadata (common to all evidence types) ──
        try:
            from pathlib import Path
            ep = Path(evidence_file)
            if ep.exists() and ep.is_file():
                st = ep.stat()
                entry["sha256"] = _sha256_file(str(ep))
                entry["file_size_bytes"] = st.st_size
                entry["file_created"] = datetime.fromtimestamp(st.st_ctime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                entry["file_modified"] = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass  # file metadata is non-fatal

        try:
            # ── Memory images: volatility windows.info.Info ──
            if module == "memory" or artifact_type == "memory_image":
                entry.update(_extract_memory_metadata(evidence_file, case_dir))

            # ── EVTX: first/last event timestamp ──
            elif module == "evtx" or artifact_type in ("evtx", "process_creation"):
                entry.update(_extract_evtx_metadata(evidence_file, case_dir))

            # ── PCAP: capinfos ──
            elif module == "network" or artifact_type in ("pcap", "pcap_conn"):
                entry.update(_extract_pcap_metadata(evidence_file, case_dir))

        except Exception as e:
            entry["_error"] = str(e)

        metadata[ev_path] = entry

    return metadata


def _extract_memory_metadata(path: str, case_dir: str | None = None) -> dict:
    """Run vol windows.info.Info and parse OS/arch details."""
    import time
    from spectre.config import VOL_SYMBOLS_DIR

    result = {"os": "", "architecture": "", "build": "",
              "capture_time": "", "kernel_base": ""}

    try:
        vol_cmd = [
            "vol", "-q", "-r", "json",
            "-s", str(VOL_SYMBOLS_DIR),
            "-f", path,
            "windows.info.Info",
        ]
        _start = time.time()
        proc = subprocess.run(
            vol_cmd, capture_output=True, text=True, timeout=60,
        )
        if case_dir:
            log_command(
                case_dir=case_dir, tool="vol:windows.info.Info",
                command=" ".join(vol_cmd), exit_code=proc.returncode,
                duration_ms=int((time.time() - _start) * 1000),
                stderr=proc.stderr, stdout=proc.stdout,
                phase=0, phase_step="S4-metadata-vol:windows.info.Info",
            )
        if proc.returncode != 0:
            result["_error"] = f"vol exit {proc.returncode}: {proc.stderr[:200]}"
            return result

        import json
        data = json.loads(proc.stdout)
        # windows.info.Info uses Variable/Value format, not dict keys
        if isinstance(data, list):
            info = {}
            for item in data:
                var = item.get("Variable", "")
                val = item.get("Value", "")
                info[var] = val

            result["os"] = info.get("NTBuildLab", "") or \
                           f"Windows {info.get('NtMajorVersion', '')}.{info.get('NtMinorVersion', '')}"
            result["architecture"] = "x64" if info.get("Is64Bit", "") == "True" else "x86"
            result["build"] = f"{info.get('NtMajorVersion', '')}.{info.get('NtMinorVersion', '')}"
            result["capture_time"] = info.get("SystemTime", "")
            result["kernel_base"] = info.get("Kernel Base", "")
            result["system_root"] = info.get("NtSystemRoot", "")
            result["num_processors"] = info.get("KeNumberProcessors", "")
            result["machine_type"] = info.get("MachineType", "")
            result["symbols"] = info.get("Symbols", "")
    except subprocess.TimeoutExpired:
        result["_error"] = "vol windows.info.Info timed out after 60s"
    except Exception as e:
        result["_error"] = str(e)

    return result


def _extract_evtx_metadata(path: str, case_dir: str | None = None) -> dict:
    """Extract a real event count from an EVTX file via libevtx `evtxinfo`.

    `evtxinfo` reads the EVTX file header and reports the exact record count
    cheaply (no full enumeration), matching the `evtxexport` toolchain Phase 2
    uses. total_events is left as None (never fabricated) if the tool fails;
    the authoritative count still comes from Phase 2 extraction.
    """
    import re
    import time

    result = {"time_range_start": "", "time_range_end": "",
              "total_events": None, "hostname": "", "providers": []}

    try:
        info_cmd = ["evtxinfo", path]
        _start = time.time()
        proc = subprocess.run(
            info_cmd, capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            m = re.search(r"Number of records\s*:\s*(\d+)", proc.stdout)
            if m:
                result["total_events"] = int(m.group(1))
        if result["total_events"] is None:
            result["_note"] = "exact event count deferred to Phase 2 extraction"
        if case_dir:
            log_command(
                case_dir=case_dir, tool="evtxinfo",
                command=" ".join(info_cmd), exit_code=proc.returncode,
                duration_ms=int((time.time() - _start) * 1000),
                stderr=proc.stderr, stdout=proc.stdout,
                phase=0, phase_step="S4-metadata-evtxinfo",
                extra=f"events={result['total_events']}",
            )
    except Exception as e:
        result["_error"] = str(e)

    return result


def _extract_pcap_metadata(path: str, case_dir: str | None = None) -> dict:
    """Extract capture metadata via capinfos."""
    result = {"capture_duration_seconds": 0, "total_packets": 0,
              "data_rate_mbps": 0.0, "link_type": ""}

    try:
        import subprocess
        import time
        capinfos_cmd = ["capinfos", "-M", path]
        _start = time.time()
        proc = subprocess.run(
            capinfos_cmd, capture_output=True, text=True, timeout=30,
        )
        if case_dir:
            log_command(
                case_dir=case_dir, tool="capinfos",
                command=" ".join(capinfos_cmd), exit_code=proc.returncode,
                duration_ms=int((time.time() - _start) * 1000),
                stderr=proc.stderr, stdout=proc.stdout,
                phase=0, phase_step="S4-metadata-capinfos",
            )
        if proc.returncode != 0:
            result["_error"] = f"capinfos exit {proc.returncode}"
            return result

        for line in proc.stdout.split("\n"):
            line = line.strip()
            if "Number of packets:" in line:
                try:
                    result["total_packets"] = int(line.split(":")[-1].strip())
                except ValueError:
                    pass
            elif "Capture duration:" in line:
                dur = line.split(":")[-1].strip().split()[0]
                try:
                    result["capture_duration_seconds"] = float(dur)
                except ValueError:
                    pass
            elif "Data rate:" in line:
                rate = line.split(":")[-1].strip().split()[0]
                try:
                    result["data_rate_mbps"] = float(rate) / 1000
                except ValueError:
                    pass
    except Exception as e:
        result["_error"] = str(e)

    return result


def _build_manifest(case_id: int, case_name: str, profile_name: str,
                    evidence_refs: list, canary_status: str,
                    fk_yamls: dict, auto_extend: bool = False) -> dict:
    """Build manifest.yaml content."""
    return {
        "case_id": f"{case_id:03d}",
        "case_name": case_name,
        "created": _utcnow(),
        "artifact_profile": profile_name,
        "artifact_profile_desc": PROFILES.get(profile_name, {}).get("description", ""),
        "auto_extend": auto_extend,
        "canary_status": canary_status,
        "evidence": evidence_refs,
        "artifacts": list(fk_yamls.keys()),
        "phase": 0,
        "gate_0": {
            "canary_known": True,
            "canary_status": canary_status,
            "evidence_registered": len(evidence_refs),
            "manifest_exists": True,
            "fk_yamls_loaded": len(fk_yamls),
            "passed": bool(
                canary_status in ("FULL", "DEGRADED")
                # Pass when we have KB context (static profiles / fixture) OR
                # when real evidence was registered (auto/live path may have
                # recognized types without a matching FK YAML yet).
                and (len(fk_yamls) > 0 or len(evidence_refs) > 0)
            ),
        },
    }


def setup_case(name: str, profile: str,
               evidence_paths: list | None = None,
               cases_dir: str | None = None,
               auto_extend: bool = False,
               direction: str = "",
               focus: bool = False) -> dict:
    """Main entry point: run Phase 0 case setup.

    Args:
        name: Case display name (e.g. "training-run")
        profile: Artifact profile name (see PROFILES dict)
        evidence_paths: Optional list of evidence file paths
        cases_dir: Optional custom cases directory (default config.CASES_DIR, ~/spectre-cases/)
        auto_extend: If True, use profile artifacts as minimum scope
                     and add any additional artifacts found by the recognizer.
                     Only meaningful for non-"auto" profiles.
        direction: Investigator tasking text. Stored on the manifest and
                   synthesized into directed detection rules in Phase 1.
        focus: When True, Phase 3 runs only analyst-directed directives.

    Returns:
        Dict with case metadata
    """
    if cases_dir is None:
        cases_dir = str(CASES_DIR)
    # W1 fix: normalize ONCE, here, so the case_dir this function builds
    # below (`Path(cases_dir) / f"{case_id:03d}-{name}"`) and the counter
    # directory `_read_counter()` reads/writes under (which already
    # expanduser()s internally) always agree. Before this fix, a literal
    # "~"-prefixed --cases-dir made the two diverge: the counter lived
    # under the expanded real path while the case dir was created under a
    # literal "~" directory relative to cwd.
    cases_dir = os.path.expanduser(cases_dir)

    evidence_paths = evidence_paths or []

    # Validate profile
    if profile not in PROFILES:
        profiles = ", ".join(PROFILES.keys())
        print(json.dumps({
            "error": f"Unknown profile '{profile}'. Available: {profiles}",
            "success": False,
        }))
        sys.exit(1)

    # Step 1: Auto-increment case counter (under the EFFECTIVE cases_dir
    # resolved above, never the module-level CASES_DIR global — see
    # _read_counter()'s docstring).
    case_id = _read_counter(cases_dir)
    case_dir = Path(cases_dir) / f"{case_id:03d}-{name}"

    # Create case directory structure first so execution.log can be written
    # (the phase banner records its title there).
    for subdir in ["evidence", RAW_DIR, "findings", "reports"]:
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)

    phase_banner("Phase 0: Case Setup", case_dir=str(case_dir), phase=0)
    print(f"Case ID: {case_id:03d}", file=sys.stderr)
    print(f"Case Name: {name}", file=sys.stderr)
    print(f"Case Dir: {case_dir}", file=sys.stderr)
    print(f"Profile: {profile}", file=sys.stderr)

    # Step 1: Run session canary
    console.step("Session canary", case_dir=str(case_dir), phase=0, step_id="S1")
    canary_result = _run_canary(str(case_dir))
    canary_status = canary_result.get("status", "UNKNOWN")
    c_passed = canary_result.get("passed")
    c_failed = canary_result.get("failed")
    console.detail(f"Status: {canary_status} (passed={c_passed}, "
                   f"failed={c_failed})")
    unavailable = sorted(
        n for n, r in (canary_result.get("modules") or {}).items()
        if not r.get("available"))
    for mod_name in unavailable:
        console.detail(f"  module unavailable: {mod_name} — "
                       f"{canary_result['modules'][mod_name].get('detail', '')}")
    # tool/command name the Python probe, not the bash script it replaced.
    # Naming a script that no longer exists would put a false exact_command in
    # the transcript, and a reviewer who tried to reproduce it would find
    # nothing there.
    log_command(
        case_dir=str(case_dir), tool="canary.py",
        command="spectre-canary", phase=0, phase_step="S1-canary",
        exit_code=0 if canary_status != "DEAD" else 1,
        extra=f"status={canary_status} passed={c_passed} failed={c_failed}"
              + (f" unavailable_modules={','.join(unavailable)}"
                 if unavailable else ""),
    )

    if canary_status == "DEAD":
        print(json.dumps({
            "error": "Session canary DEAD — pipeline stopped",
            "case_dir": str(case_dir),
            "case_id": f"{case_id:03d}",
            "canary_status": "DEAD",
            "success": False,
        }))
        sys.exit(3)

    # Step 4: Register evidence (if provided)
    evidence_paths, intake_skipped = _expand_evidence_paths(evidence_paths)
    for skip in intake_skipped:
        console.detail(f"intake skip: {skip['path']} — {skip['reason']}")

    evidence_refs = []
    for ep in evidence_paths:
        console.step(f"Registering evidence: {ep}", case_dir=str(case_dir),
                     phase=0, step_id="S2")
        reg = _register_evidence(ep, str(case_dir))
        if reg["ok"]:
            evidence_refs.append(reg)
            console.detail(f"OK — SHA-256: {reg['sha256'][:16]}...")
        else:
            console.detail(f"FAILED: {reg['reason']}")
    # W3-2 (R2-15): lock evidence/ 0555 once staging is done (evidence/derived
    # stays writable for Phase 2 carving). See lock_evidence_dir().
    lock_evidence_dir(str(case_dir))

    # Step 3: Recognize/triage registered evidence → route to modules.
    triage_records = {}
    effective_artifacts = list(PROFILES[profile]["artifacts"])
    if evidence_refs:
        console.step("Recognizing evidence", case_dir=str(case_dir),
                     phase=0, step_id="S3")
        from spectre.pipeline.recognize import triage_one
        for ref in evidence_refs:
            rec = triage_one(ref["evidence_path"])
            triage_records[ref["evidence_path"]] = rec
            summary = (f"{os.path.basename(ref['evidence_path'])} -> "
                       f"{rec['module'] or '—'}/{rec['artifact_type'] or '—'} "
                       f"[{rec['status']}]")
            console.detail(summary)
            log_command(
                case_dir=str(case_dir), tool="recognize",
                command=f"recognize.triage_one {os.path.basename(ref['evidence_path'])}",
                phase=0, phase_step="S3-recognize", exit_code=0, extra=summary,
            )
        if profile == "auto":
            # Derive the artifact set from what we recognized.
            derived = []
            for rec in triage_records.values():
                at = rec.get("artifact_type")
                if at and rec.get("status") in ("RECOGNIZED", "EXTRACTOR_PENDING") \
                        and at not in derived:
                    derived.append(at)
            # FK YAMLs are keyed by artifact name; map recognized types to them.
            effective_artifacts = []
            for at in derived:
                mapped = ARTIFACT_FK.get(at, at)
                if isinstance(mapped, list):
                    effective_artifacts.extend(mapped)
                else:
                    effective_artifacts.append(mapped)
        elif auto_extend:
            # Use profile artifacts as minimum, add recognized extras
            extra = []
            for rec in triage_records.values():
                at = rec.get("artifact_type")
                if at and rec.get("status") in ("RECOGNIZED", "EXTRACTOR_PENDING") \
                        and at not in effective_artifacts:
                    mapped = ARTIFACT_FK.get(at, at)
                    if isinstance(mapped, list):
                        for m in mapped:
                            if m not in effective_artifacts:
                                extra.append(m)
                    elif mapped not in effective_artifacts:
                        extra.append(mapped)
            if extra:
                console.detail(f"auto-extend: adding {extra}")
            effective_artifacts.extend(extra)
    elif profile == "auto":
        console.note("[!] 'auto' profile requires --evidence; none provided.")

    # Step 4: Extract evidence metadata (OS, arch, time range, hostname)
    console.step("Extracting evidence metadata", case_dir=str(case_dir),
                 phase=0, step_id="S4")
    evidence_metadata = {}
    if triage_records:
        evidence_metadata = _extract_evidence_metadata(str(case_dir), triage_records)
        for ev_path, meta in evidence_metadata.items():
            os_info = meta.get("os", "") or meta.get("build", "") or ""
            arch = meta.get("architecture", "")
            err = meta.get("_error", "")
            tag = f"{os_info} {arch}".strip() if (os_info or arch) else \
                  f"events={meta.get('total_events', '?')}" if meta.get('total_events') else ""
            if err:
                tag = f"ERROR: {err[:80]}"
            console.detail(f"{os.path.basename(ev_path)}: "
                           f"{tag or meta.get('type', '?')}")

    # Step 5: Load FK YAMLs for the effective artifact list
    console.step("Loading FK YAMLs", case_dir=str(case_dir),
                 phase=0, step_id="S5")
    fk_yamls = {}
    fk_missing = []
    for artifact in effective_artifacts:
        fk = _load_fk_yaml(artifact)
        if fk:
            fk_yamls[artifact] = fk
            console.detail(f"{artifact}.yaml ({fk.get('artifact', '?')})")
        else:
            fk_missing.append(artifact)
            console.detail(f"{artifact}.yaml — NOT FOUND")
    log_command(
        case_dir=str(case_dir), tool="fk-load",
        command=f"load_fk_yaml {effective_artifacts}",
        phase=0, phase_step="S5-fk-load", exit_code=0,
        extra=f"loaded={len(fk_yamls)} missing={len(fk_missing)}",
    )

    # Step 6: Cross-case episodic recall
    console.step("Cross-case episodic recall", case_dir=str(case_dir),
                 phase=0, step_id="S6")
    try:
        recalls = _run_episodic_recall(evidence_refs)
        recall_count = sum(len(v) if isinstance(v, list) else 0 for v in recalls.values())
        console.detail(f"{recall_count} cross-case matches")
        log_command(
            case_dir=str(case_dir), tool="episodic-recall",
            command="cross_case_index.search_index (evidence sha256 / filepath)",
            phase=0, phase_step="S6-recall", exit_code=0,
            extra=f"{recall_count} cross-case matches",
        )
    except Exception as e:
        recalls = {}
        console.detail(f"Skipped: {e}")
        log_command(
            case_dir=str(case_dir), tool="episodic-recall",
            command="cross_case_index.search_index (evidence sha256 / filepath)",
            phase=0, phase_step="S6-recall", exit_code=1, stderr=str(e),
        )

    # Step 8: Build and write manifest
    manifest = _build_manifest(case_id, name, profile, evidence_refs,
                                canary_status, fk_yamls, auto_extend)
    manifest["triage"] = triage_records
    manifest["intake_skipped"] = intake_skipped
    manifest["evidence_metadata"] = evidence_metadata
    # Investigator direction (Phase 1 input) — the cross-phase carrier is the
    # manifest, so persist it here at case creation.
    manifest["direction"] = direction or ""
    manifest["focus"] = bool(focus)
    manifest_path = case_dir / "manifest.yaml"
    import yaml
    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)

    # Step 9: Write FK YAML context and evidence metadata files
    context_path = case_dir / "fk_context.yaml"
    with open(context_path, "w") as f:
        yaml.dump(fk_yamls, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)

    # evidence_metadata is carried on the manifest (manifest["evidence_metadata"]);
    # no separate evidence_metadata.yaml file — it was a verbatim duplicate.

    console.detail(f"Manifest: {manifest_path}")
    console.detail(f"FK Context: {context_path}")

    # Step 10: put the environment and the coverage gaps INSIDE the audit
    # chain. Both were previously manifest-only — and the manifest is a mutable
    # file with no hash behind it, written by log_command, which never touches
    # audit.jsonl. A reviewer asking "what could this examination see, and what
    # did it never open?" was relying on a field anyone could edit.
    # Ordered after the manifest write so the gaps are derived from exactly the
    # triage that was persisted.
    audit_case_id = f"{case_id:03d}"
    try:
        from spectre.pipeline.environment import append_environment_row
        snap = append_environment_row(str(case_dir), audit_case_id)
        if snap["module_import_failures"]:
            console.detail(f"  module import failures: "
                           f"{sorted(snap['module_import_failures'])}")
        if snap["unevaluated_rule_packs"]:
            console.detail(f"  unevaluated rule packs: "
                           f"{snap['unevaluated_rule_packs']}")
    except Exception as e:
        # Never fail case creation over the record of the environment; the
        # Phase-7 coverage check reports the absence rather than hiding it.
        print(f"  ⚠ environment row not written: {e}", file=sys.stderr)

    try:
        from spectre.pipeline.coverage import append_gap_rows
        gaps = append_gap_rows(str(case_dir), audit_case_id, phase=0,
                               phase_step="S8-coverage", manifest=manifest)
        for gap in gaps:
            console.detail(f"  coverage gap: {gap['count']}× "
                           f"{gap['status']} {gap['artifact_type']} "
                           f"(from {gap['parent']})")
    except Exception as e:
        print(f"  ⚠ coverage_gap rows not written: {e}", file=sys.stderr)

    # Return structured result
    result = {
        "case_dir": str(case_dir),
        "case_id": f"{case_id:03d}",
        "case_name": name,
        "canary_status": canary_status,
        "manifest_path": str(manifest_path),
        "evidence_refs": evidence_refs,
        "fk_yamls_loaded": list(fk_yamls.keys()),
        "artifact_profile": profile,
        "success": manifest["gate_0"]["passed"],
    }

    print(json.dumps(result))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Phase 0: Spectre case setup orchestrator"
    )
    parser.add_argument("--name", required=True, help="Case display name")
    parser.add_argument("--profile", required=True, help="Artifact profile name")
    parser.add_argument("--evidence", nargs="*", default=[],
                        help="Evidence file or directory paths (directories walked recursively; symlinks never followed — recorded as skips)")
    parser.add_argument("--cases-dir", default=None,
                        help="Custom cases directory (default: $SPECTRE_CASES_DIR or ~/spectre-cases/)")
    parser.add_argument("--auto-extend", action="store_true",
                        help="Use profile artifacts as minimum scope, add recognized extras")
    parser.add_argument("--direction", "--message", dest="direction", default="",
                        help="Investigator tasking text (Phase 1 Direction input)")
    parser.add_argument("--focus", action="store_true",
                        help="Phase 3 runs only analyst-directed directives")

    args = parser.parse_args()
    setup_case(
        name=args.name,
        profile=args.profile,
        evidence_paths=args.evidence or [],
        cases_dir=args.cases_dir,
        auto_extend=args.auto_extend,
        direction=args.direction,
        focus=args.focus,
    )


if __name__ == "__main__":
    main()
