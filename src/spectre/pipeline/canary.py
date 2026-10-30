"""
canary.py — environment health, derived from the analyzer modules themselves.

Reports one of three statuses:

  FULL      every check passed
  DEGRADED  something is missing, but at least one module can still extract
  DEAD      core infrastructure is broken, or NO module can extract at all
            → the pipeline hard-stops (sys.exit(3))

Four tiers of check:

  1. core infrastructure — the interpreter, pyyaml, libmagic, and module
     discovery itself. A failure here is DEAD: without libmagic every
     extensionless artifact triages UNRECOGNIZED and the report calls its
     contents unverified, which is a false statement about the evidence, not a
     degraded analysis.
  2. per-module required tools — from each module's `module.yaml`, resolved
     through `_resolve_tool`.
  3. per-module python dependencies — `importlib.util.find_spec`.
  4. optional tools and project extras — DEGRADED at worst, never DEAD.

Three things this replaced, all of them defects (see
the module-selection design spec §3.3, §3.6):

  - It used to shell out to `scripts/session-canary.sh`, resolved four parents
    up from this file. `scripts/` is not in the wheel, so on any non-editable
    install the script was absent, the canary returned DEAD, and runner.py
    turned that into exit 3. Spectre would not run outside a source checkout.
  - The DEAD rule was `vol_failed and other_failures >= 3` over a hardcoded
    tool list, so a pcap-only examiner hit DEAD and could not start.
  - That list had drifted from the modules in both directions: evtxexport,
    fls and rip.pl were declared by modules and checked by nothing, while
    bulk_extractor, evtx_dump.py, strings, sha256sum, yara(py) and
    log2timeline.py were checked though no module declares them and no code
    path runs them.

The inventory is now derived, and tests/test_pipeline/test_canary_module_derived
.py fails if it drifts again in either direction.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # noqa: F401 — kept importable; the canary itself runs no
                   # subprocess, and a test asserts no bash is spawned.
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from spectre import config
from spectre.modules import manifest as module_manifest
from spectre.modules import registry
from spectre.pipeline.audit import append as audit_append

# ── Tier 1: core infrastructure. Any failure here is DEAD. ───────────────
# name -> human label. The name must be a substring of the label; the
# inventory-sync test uses these names to prove every check traces to
# something declared.
CORE_CHECKS = {
    "python": "python >= 3.11",
    "pyyaml": "pyyaml (knowledge YAML)",
    "libmagic": "libmagic — live magic.from_file probe",
    "modules": "modules discovered",
}

# ── Tier 4b: project-level optional extras. Keys MUST be extras that
# pyproject.toml actually declares — pinned by test_project_extras_tier
# _matches_pyproject, so this last hardcoded list cannot rot into ghosts.
PROJECT_EXTRAS = {
    "report": ("report extra — PDF/DOCX rendering",
               ("weasyprint", "markdown", "bs4")),
}

MIN_PYTHON = (3, 11)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── tool resolution ──────────────────────────────────────────────────────

def _resolve_zeek_bin() -> str | None:
    path = config._resolve_zeek()
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


def _resolve_memprocfs() -> str | None:
    path = config.MEMPROCFS_BIN
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


# Tools config owns non-PATH resolution for. Asking PATH about these would
# report them missing on a correctly-configured host — Zeek's default install
# is /opt/zeek/bin and MemProcFS's is /opt/memprocfs, neither on PATH. The
# canary must ask config the same question the extractors ask it.
_SPECIAL_RESOLVERS = {
    "zeek": _resolve_zeek_bin,
    "memprocfs": _resolve_memprocfs,
}


def _resolve_tool(name: str) -> str | None:
    resolver = _SPECIAL_RESOLVERS.get(name)
    if resolver is not None:
        return resolver()
    return shutil.which(name)


def _have_python_dep(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ── Tier 1 probes ────────────────────────────────────────────────────────

def _probe_python() -> tuple[bool, str]:
    v = sys.version_info
    ok = (v.major, v.minor) >= MIN_PYTHON
    return ok, f"{v.major}.{v.minor}.{v.micro}"


def _probe_pyyaml() -> tuple[bool, str]:
    try:
        import yaml
        return True, getattr(yaml, "__version__", "present")
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _probe_libmagic() -> tuple[bool, str]:
    """Import python-magic AND actually characterise a file.

    Risk R2: the pure-python wrapper imports cleanly with libmagic.so absent,
    so an import check would pass on a host where every magic description
    comes back empty — which is exactly the silent failure in §3.4.
    """
    try:
        import magic
    except Exception as e:
        return False, f"python-magic not importable: {type(e).__name__}: {e}"
    try:
        with tempfile.NamedTemporaryFile(suffix=".probe", delete=False) as fh:
            fh.write(b"regf" + b"\x00" * 508)
            probe_path = fh.name
        try:
            desc = magic.from_file(probe_path)
        finally:
            os.unlink(probe_path)
    except Exception as e:
        return False, f"libmagic probe failed: {type(e).__name__}: {e}"
    if not desc:
        return False, "libmagic returned an empty description (libmagic.so?)"
    return True, desc


def _probe_modules() -> tuple[bool, str]:
    _, errors = registry.discover_with_errors()
    manifests, manifest_errors = module_manifest.load_manifests()
    if not manifests:
        return False, "no analyzer modules found"
    loadable = len(manifests) - len(errors)
    detail = f"{loadable}/{len(manifests)} loadable"
    if errors:
        detail += "; failed to import: " + ", ".join(
            f"{k} ({v})" for k, v in sorted(errors.items()))
    if manifest_errors:
        detail += "; bad manifest: " + ", ".join(
            f"{k} ({v})" for k, v in sorted(manifest_errors.items()))
    # A module that fails to import is a per-module loss, reported in the
    # modules table — not a core failure. Core only fails when there is no
    # module inventory at all to reason about.
    return True, detail


# Check name -> the module-level probe that answers it. Held as a NAME, not a
# function object, so the lookup below goes through module globals and a test
# monkeypatching e.g. _probe_libmagic is actually honoured.
_CORE_PROBES = {
    "python": "_probe_python",
    "pyyaml": "_probe_pyyaml",
    "libmagic": "_probe_libmagic",
    "modules": "_probe_modules",
}


def _core_rows() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for name, label in CORE_CHECKS.items():
        probe = globals()[_CORE_PROBES[name]]
        try:
            ok, detail = probe()
        except Exception as e:  # a probe must never take the canary down
            ok, detail = False, f"{type(e).__name__}: {e}"
        rows[name] = {"label": label, "ok": bool(ok), "detail": str(detail)}
    return rows


# ── Tiers 2 & 3: per-module ──────────────────────────────────────────────

def _module_rows() -> dict[str, dict]:
    """Per-module availability, keyed by module directory name.

    Joins three sources: the YAML manifest (readable even for a module that
    did not import), registry.discover_with_errors() (what actually loaded,
    and why not), and the module's own availability() hook when it has one.

    The hook is authoritative when present. That is the point of it: pcap's
    declared `required_tools=["tcpdump"]` would report the module unavailable
    on a Zeek-only host, where it extracts pcaps completely.
    """
    manifests, manifest_errors = module_manifest.load_manifests()
    discovered, load_errors = registry.discover_with_errors()

    rows: dict[str, dict] = {}
    for dir_name, man in sorted(manifests.items()):
        tools = {t: _resolve_tool(t) is not None for t in man.tools}
        optional = {t: _resolve_tool(t) is not None for t in man.optional_tools}
        deps = {d: _have_python_dep(d) for d in man.python_deps}
        opt_deps = {d: _have_python_dep(d)
                    for d in man.python_deps_optional}

        row = {
            "available": True, "degraded": False, "detail": "", "missing": "",
            "tools": tools, "optional_tools": optional,
            "python_deps": deps, "python_deps_optional": opt_deps,
            "summary": man.summary,
        }

        if dir_name in load_errors:
            row.update(available=False, missing="",
                       detail=f"module failed to load — {load_errors[dir_name]}")
            rows[dir_name] = row
            continue

        analyzer = discovered.get(man.name)
        if analyzer is None:
            row.update(available=False,
                       detail="module did not load and reported no reason")
            rows[dir_name] = row
            continue

        hook = getattr(analyzer, "availability", None)
        has_hook = hook is not None
        if has_hook:
            try:
                av = hook()
            except Exception as e:
                row.update(available=False,
                           detail=f"availability probe raised "
                                  f"{type(e).__name__}: {e}")
                rows[dir_name] = row
                continue
            row.update(available=bool(av.available), degraded=bool(av.degraded),
                       detail=av.detail, missing=av.missing)
        else:
            missing_required = [t for t, ok in tools.items() if not ok]
            if missing_required and not man.tool_optional:
                row.update(available=False, missing=missing_required[0],
                           detail=f"required tool(s) not found: "
                                  f"{', '.join(missing_required)}")

        missing_deps = [d for d, ok in deps.items() if not ok]
        if missing_deps and row["available"]:
            row.update(available=False, missing=missing_deps[0],
                       detail=f"python dependency not importable: "
                              f"{', '.join(missing_deps)}")

        if row["available"]:
            # A module with a hook already reasons about its own optional
            # tooling (pcap's names the passes it lost), so adding the generic
            # note would say the same thing twice in the same sentence. Only
            # the hookless modules need it written for them.
            lost = [d for d, ok in opt_deps.items() if not ok]
            if not has_hook:
                lost = [t for t, ok in optional.items() if not ok] + lost
            if lost:
                row["degraded"] = True
                extra = f"reduced capability without: {', '.join(lost)}"
                row["detail"] = f"{row['detail']}; {extra}".lstrip("; ")

        rows[dir_name] = row

    for dir_name, reason in sorted(manifest_errors.items()):
        rows[dir_name] = {
            "available": False, "degraded": False, "missing": "",
            "detail": f"unreadable module.yaml — {reason}",
            "tools": {}, "optional_tools": {}, "python_deps": {},
            "python_deps_optional": {}, "summary": "",
        }
    return rows


# ── Tier 4b: project extras ──────────────────────────────────────────────

def _extras_rows() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for extra, (label, imports) in PROJECT_EXTRAS.items():
        missing = [m for m in imports if not _have_python_dep(m)]
        rows[extra] = {
            "label": label, "ok": not missing,
            "detail": "present" if not missing
                      else f"not installed: {', '.join(missing)}",
        }
    return rows


# ── the probe ────────────────────────────────────────────────────────────

def probe_environment() -> dict:
    """Inspect the host and return the canary result. Never exits.

    Split out from run_canary() so the status rule is testable without
    catching SystemExit, and so a caller that only wants to *report* the
    environment (Phase 7 verification, the S0-environment audit row) does not
    risk terminating the process.
    """
    core = _core_rows()
    modules = _module_rows()
    extras = _extras_rows()

    all_tools: dict[str, bool] = {}
    failed_tools: list[str] = []

    def record(label: str, ok: bool) -> None:
        all_tools[label] = ok
        if not ok:
            failed_tools.append(label)

    for row in core.values():
        record(row["label"], row["ok"])

    for name, row in modules.items():
        for tool, ok in row.get("tools", {}).items():
            record(f"{tool} [{name}]", ok)
        for tool, ok in row.get("optional_tools", {}).items():
            record(f"{tool} [{name}, optional]", ok)
        for dep, ok in row.get("python_deps", {}).items():
            record(f"{dep} [{name}]", ok)
        for dep, ok in row.get("python_deps_optional", {}).items():
            record(f"{dep} [{name}, optional]", ok)

    for row in extras.values():
        record(row["label"], row["ok"])

    passed = sum(1 for ok in all_tools.values() if ok)
    failed = len(all_tools) - passed

    core_failed = [n for n, r in core.items() if not r["ok"]]
    usable = [n for n, r in modules.items() if r["available"]]

    if core_failed:
        status = "DEAD"
    elif not usable:
        status = "DEAD"
    elif failed or any(r["degraded"] for r in modules.values()):
        status = "DEGRADED"
    else:
        status = "FULL"

    return {
        "status": status,
        "passed": passed,
        "failed": failed,
        "failed_tools": failed_tools,
        "all_tools": all_tools,
        "timestamp": _utcnow(),
        "raw_output": _render(status, core, modules, extras, passed, failed),
        # Additive keys. Existing consumers read status/passed/failed/
        # failed_tools/all_tools and are unaffected.
        "core": core,
        "modules": modules,
        "extras": extras,
        "usable_modules": sorted(usable),
    }


def _render(status, core, modules, extras, passed, failed) -> str:
    out = ["=== Spectre Environment Canary ===",
           f"Checked: {_utcnow()}", ""]
    out.append("[1] Core infrastructure (failure here is DEAD)")
    for row in core.values():
        mark = "PASS" if row["ok"] else "FAIL"
        out.append(f"  {row['label']:<34} {mark}  {row['detail']}")

    out.append("")
    out.append("[2] Analyzer modules")
    for name, row in modules.items():
        if not row["available"]:
            state = "UNAVAILABLE"
        elif row["degraded"]:
            state = "DEGRADED"
        else:
            state = "OK"
        line = f"  {name:<16} {state:<12}"
        if row["detail"]:
            line += f" {row['detail']}"
        out.append(line)
        for bucket, suffix in (("tools", ""), ("optional_tools", " (optional)"),
                               ("python_deps", ""),
                               ("python_deps_optional", " (optional)")):
            for tool, ok in row.get(bucket, {}).items():
                out.append(f"      {tool}{suffix}: "
                           f"{'found' if ok else 'NOT FOUND'}")

    out.append("")
    out.append("[3] Project extras (never DEAD)")
    for row in extras.values():
        mark = "PASS" if row["ok"] else "FAIL"
        out.append(f"  {row['label']:<34} {mark}  {row['detail']}")

    out += ["", f"=== {passed} passed, {failed} failed — {status} ==="]
    if status == "DEGRADED":
        out.append("DEGRADED: reduced coverage. Every gap above is disclosed "
                   "in the report's Forensic Blind Spots section.")
    if status == "DEAD":
        out.append("DEAD: core infrastructure broken, or no analyzer module "
                   "can extract on this host.")
    return "\n".join(out)


# ── the pipeline entry point ─────────────────────────────────────────────

def run_canary(canary_script: str | None = None,
               case_dir: str | None = None, **_ignored) -> dict:
    """Probe the environment, audit a non-FULL result, exit 3 on DEAD.

    Args:
        canary_script: accepted and ignored. Kept because case_setup, runner
            and phase_runner all call this by keyword and every canary test in
            the suite stubs it as `lambda **kw`; the parameter outlives the
            shell script it used to name. Passing a path no longer makes the
            canary shell out — and, critically, a path that does not exist is
            no longer fatal (that was the §3.3 P0).
        case_dir: when given, a DEGRADED or DEAD result gets an audit row.

    Raises SystemExit(3) if DEAD.
    """
    result = probe_environment()
    status = result["status"]

    if case_dir and status in ("DEGRADED", "DEAD"):
        audit_append(case_dir, {
            "actor": "deterministic-core",
            "action": "canary_result",
            "tool": "canary.py",
            "tool_version": "2.0",
            "exact_command": f"canary.py probe --case {case_dir}",
            "params": {"usable_modules": result["usable_modules"],
                       "unavailable_modules": sorted(
                           n for n, r in result["modules"].items()
                           if not r["available"])},
            "case_id": Path(case_dir).name,
            "output_path": "",
            "output_sha256": "",
            "output_format": "json",
            "output_line_count": 0,
            "output_size_bytes": 0,
            "result": status,
            "exit_code": 0 if status == "DEGRADED" else 3,
            "duration_ms": 0,
            "stderr": json.dumps(result["failed_tools"]),
            "finding_id": None,
        })

    if status == "DEAD":
        print(f"FATAL: environment canary DEAD — {result['failed']} check(s) "
              f"failed: {result['failed_tools']}", file=sys.stderr)
        print(result["raw_output"], file=sys.stderr)
        sys.exit(3)

    return result


# ── CLI ──
def main():
    """Entry point for the spectre-canary console script."""
    import argparse

    parser = argparse.ArgumentParser(description="Spectre environment canary")
    parser.add_argument("--script", default=None,
                        help="(deprecated, ignored) the canary no longer "
                             "shells out to a bash script")
    parser.add_argument("--case", default=None, help="Case directory for audit")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print the full per-check transcript")
    args = parser.parse_args()

    result = run_canary(canary_script=args.script, case_dir=args.case)

    if args.json:
        out = {k: v for k, v in result.items() if k != "raw_output"}
        print(json.dumps(out, indent=2, default=str))
    elif args.verbose:
        print(result["raw_output"])
    else:
        print(f"Status: {result['status']}")
        print(f"Passed: {result['passed']}, Failed: {result['failed']}")
        for name, row in result["modules"].items():
            state = ("UNAVAILABLE" if not row["available"]
                     else "DEGRADED" if row["degraded"] else "OK")
            suffix = f" — {row['detail']}" if row["detail"] else ""
            print(f"  {name:<16} {state}{suffix}")
        if result["failed_tools"]:
            print(f"Failed checks: {', '.join(result['failed_tools'])}")

    sys.exit(0 if result["status"] != "DEAD" else 3)


if __name__ == "__main__":
    main()
