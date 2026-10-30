"""
environment.py — the analysis environment, recorded inside the audit chain.

Spec: the module-selection design spec §3.7, §5.5.

`canary_status` lived only in the manifest, written by `log_command`, which
touches `execution.log` and never `audit.jsonl` (shell_log.py:164). An unchained
mutable field is not a record of what the examination could see — and "which
modules were available when this case ran" is the question a reviewer asks first
when a report says nothing was found.

So Phase 0 appends an `S0-environment` row through `audit.append()`. This is
also the honest replacement for the install-time module-selection feature that
was cut (§2): scoping an examination is worth recording, and a chained per-case
row is strictly better than an unchained per-user dotfile — it records what was
actually available for THIS case, not what someone once chose.

**Deliberate omission: external tool versions.** The spec asked for "resolved
tool paths + versions". Paths, distribution versions and module availability are
all here, but binary `--version` output is not: running `vol --version` from
this module would put tool execution outside `tool_runner.py`, which owns all
tool exec and its auditing. That discipline is worth more than the field. Every
tool Spectre actually RUNS records its own `tool_version` on its own audit row
at the moment of use, which is the more defensible record anyway — it describes
the binary that touched the evidence, not one that happened to be on PATH at
Phase 0.
"""

from __future__ import annotations

import platform
import sys
from importlib import metadata

from spectre import config
from spectre.modules import manifest as module_manifest
from spectre.modules import registry

# Distributions worth pinning in the record. Absence is recorded, not fatal.
_TRACKED_DISTRIBUTIONS = (
    "spectre-forensic", "pyyaml", "python-magic", "volatility3",
)


def _distribution_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _TRACKED_DISTRIBUTIONS:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = "not installed"
        except Exception as e:  # pragma: no cover - defensive
            out[name] = f"unknown ({type(e).__name__})"
    return out


def _resolved_tool_paths(rows: dict) -> dict[str, str]:
    """Where each declared tool resolved, per module, at Phase 0."""
    from spectre.pipeline.canary import _resolve_tool

    out: dict[str, str] = {}
    manifests, _ = module_manifest.load_manifests()
    for man in manifests.values():
        for tool in list(man.tools) + list(man.optional_tools):
            if tool not in out:
                out[tool] = _resolve_tool(tool) or "NOT FOUND"
    return out


def _unevaluated_rule_packs(discovered: dict, load_errors: dict) -> list[str]:
    """Modules whose rule pack will not be evaluated this case.

    A module that failed to import contributes no recognizers AND no rules, so
    its whole detection surface is silently absent. registry only warns to
    stderr (§3.9), which reaches no audit row and no report line.
    """
    manifests, _ = module_manifest.load_manifests()
    out = []
    for dir_name, man in sorted(manifests.items()):
        if dir_name in load_errors or man.name not in discovered:
            out.append(man.name)
            continue
        if not discovered[man.name].rules:
            out.append(f"{man.name} (loaded, but declares no rules)")
    return out


def environment_snapshot() -> dict:
    """Everything about this host that bounds what the examination could see.

    Pure: no writes, no tool execution. Safe to call from a verifier or a
    report as well as from Phase 0.
    """
    discovered, load_errors = registry.discover_with_errors()
    manifests, manifest_errors = module_manifest.load_manifests()

    # A directory that ships a manifest but produced no module is capability
    # that shipped and did not arrive — distinct from one that never shipped.
    expected = set(manifests)
    absent = sorted(d for d in expected
                    if d not in load_errors and manifests[d].name not in discovered)

    from spectre.pipeline.canary import probe_environment
    probe = probe_environment()

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "distributions": _distribution_versions(),
        "canary_status": probe["status"],
        "modules_discovered": sorted(discovered),
        "modules_usable": probe["usable_modules"],
        "modules_unavailable": {
            name: row.get("detail", "")
            for name, row in probe["modules"].items()
            if not row.get("available")
        },
        "module_import_failures": dict(sorted(load_errors.items())),
        "module_manifest_failures": dict(sorted(manifest_errors.items())),
        "modules_expected_but_absent": absent,
        "unevaluated_rule_packs": _unevaluated_rule_packs(discovered, load_errors),
        "resolved_tool_paths": _resolved_tool_paths(probe["modules"]),
        "failed_checks": probe["failed_tools"],
        "config": {
            "cases_dir": str(config.CASES_DIR),
            "pcap_engine": config.PCAP_ENGINE,
            "memory_engine": config.MEMORY_ENGINE or "both",
            "llm_provider": config.LLM_PROVIDER,
        },
    }


def append_environment_row(case_dir: str, case_id: str) -> dict:
    """Append the chained `S0-environment` row. Returns the snapshot."""
    from spectre.pipeline.audit import append as audit_append

    snap = environment_snapshot()
    audit_append(case_dir, {
        "actor": "deterministic-core",
        "action": "environment_snapshot",
        "tool": "environment.environment_snapshot",
        "tool_version": "1.0",
        "exact_command": "environment.environment_snapshot()",
        "params": snap,
        "case_id": case_id,
        "output_path": "",
        "output_sha256": "",
        "output_format": "json",
        "output_line_count": 0,
        "output_size_bytes": 0,
        "result": snap["canary_status"],
        "exit_code": 0,
        "duration_ms": 0,
        "stderr": "",
        "finding_id": None,
        "phase": 0,
        "phase_step": "S0-environment",
    })
    return snap
