"""memory/extract.py — volatility3 plugins over a memory image.

Runs a small set of triage plugins through run_tool with the JSON
renderer. Each plugin produces its own handle tagged with the plugin
name so normalize() can map rows to the right artifact_type.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool, resolve_tool_version
from spectre.config import VOL_SYMBOLS_DIR, RAW_DIR

TOOL = "vol"
TOOL_VERSION = "volatility3"
# W4-6: `vol --version` exits 2 (usage), so the old probe always fell back to
# the literal "volatility3". frameworkinfo prints "Volatility 3 Framework X.Y.Z".
_VERSION_PROBE = ("-q", "frameworkinfo.FrameworkInfo")


def _pkg_version() -> str:
    """volatility3 package metadata version, or "" when not importable."""
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("volatility3")
        except PackageNotFoundError:
            return ""
    except Exception:  # never block extraction on provenance lookup
        return ""


def vol_version() -> str:
    """The REAL volatility3 version for the audit trail (W4-6).

    Probes the installed `vol` binary once per process (resolve_tool_version is
    lru-cached). Degrades to package metadata (labelled as such, since the
    binary may run a different interpreter), then to an explicit
    "version unresolved" — never a bare tool name posing as a version.
    """
    pkg = _pkg_version()
    fallback = (f"volatility3 {pkg} (package metadata)" if pkg
                else "volatility3 (version unresolved)")
    return resolve_tool_version(TOOL, _VERSION_PROBE, fallback)

# volatility3 auto-downloads kernel symbols and must WRITE them somewhere.
# Its package dir (/opt/volatility3/.../symbols) is not user-writable, so we
# point it at a writable cache. Created on first use.
SYMBOLS_DIR = VOL_SYMBOLS_DIR

# plugin -> artifact_type produced
PLUGINS = {
    "windows.pslist.PsList": "memory_pslist",
    "windows.netscan.NetScan": "memory_netscan",
    "windows.cmdline.CmdLine": "memory_cmdline",
    "windows.envars.Envars": "memory_envar",
    "windows.filescan.FileScan": "memory_filescan",
    # Code injection (SANS step 4): private, committed, executable memory with
    # no backing file — reflective PE injection or shellcode/unpacked code.
    "windows.malfind.Malfind": "memory_malfind",
    # Track D: windows.info IS added here (reverses the earlier Track C
    # decision). Phase 0 Step 5 already runs windows.info for evidence
    # metadata, but that pass never reaches Phase 2/3 — this pass makes the
    # OS build / host profile available as a normalized memory_systeminfo
    # event (see normalize.py) so the report can surface it. It is a
    # PROFILE SIGNAL, not a finding: no rule in rules.py consumes
    # memory_systeminfo, so it can never emit a MITRE finding.
    "windows.info.Info": "memory_systeminfo",
    # windows.handles is deliberately excluded — slow; a future opt-in.
    "windows.psscan.PsScan": "memory_psscan",
    "windows.svcscan.SvcScan": "memory_svcscan",
    "windows.dlllist.DllList": "memory_dlllist",
    "windows.modules.Modules": "memory_modules",
    "windows.registry.hivelist.HiveList": "memory_hivelist",
}

# Autostart registry keys to enumerate for persistence (SANS step 5). printkey
# searches every hive for the given key path, so both the SOFTWARE-hive form
# (Microsoft\...) and the NTUSER form (Software\Microsoft\...) are listed.
AUTOSTART_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon",
]

_CARVE_SCRIPT = Path(__file__).resolve().parent.parent.parent / "pipeline" / "carve_urls.py"


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    SYMBOLS_DIR.mkdir(parents=True, exist_ok=True)
    sym = str(SYMBOLS_DIR)
    handles: list[dict] = []
    for plugin, artifact in PLUGINS.items():
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        short = plugin.split(".")[1]
        output_path = str(Path(case_dir) / RAW_DIR
                          / f"{ts}_{TOOL}_{artifact}.json")
        command = [TOOL, "-q", "-r", "json", "-s", sym,
                   "-f", str(evidence_path), plugin]
        handle = run_tool(
            case_dir=case_dir,
            tool_name=f"{TOOL}:{plugin}",
            tool_version=vol_version(),
            command=command,
            params={"artifact_type": artifact, "plugin": plugin,
                    "evidence_path": str(evidence_path), "phase": "extraction"},
            output_path=output_path,
            timeout=900,
            output_format="json",
        )
        handle["evidence_path"] = str(evidence_path)
        handle["artifact_type"] = artifact
        handle["plugin"] = plugin
        handle["tool"] = f"{TOOL}:{short}"
        handle["tool_version"] = vol_version()
        handle["exact_command"] = " ".join(command)
        handles.append(handle)

    # URL carve (strings-style sweep) — surfaces paste/file-share/cloud links.
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    url_out = str(Path(case_dir) / RAW_DIR / f"{ts}_{TOOL}_memory_url.json")
    url_cmd = [sys.executable, str(_CARVE_SCRIPT), str(evidence_path)]
    uh = run_tool(
        case_dir=case_dir, tool_name="carve_urls", tool_version="1.0",
        command=url_cmd, params={"artifact_type": "memory_url",
                                 "evidence_path": str(evidence_path),
                                 "phase": "extraction"},
        output_path=url_out, timeout=900, output_format="json",
    )
    uh["evidence_path"] = str(evidence_path)
    uh["artifact_type"] = "memory_url"
    uh["tool"] = "carve_urls"
    # Raw-byte sweep: never counts toward extraction success (Gate 2).
    uh["auxiliary"] = True
    uh["tool_version"] = "1.0"
    uh["exact_command"] = " ".join(url_cmd)
    handles.append(uh)

    # Registry autostart enumeration (persistence). printkey takes one --key per
    # invocation, so each autostart key produces its own memory_regkey handle.
    for key in AUTOSTART_KEYS:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe = key.replace("\\", "_").replace(" ", "")
        rk_out = str(Path(case_dir) / RAW_DIR
                     / f"{ts}_{TOOL}_memory_regkey_{safe}.json")
        rk_cmd = [TOOL, "-q", "-r", "json", "-s", sym,
                  "-f", str(evidence_path),
                  "windows.registry.printkey.PrintKey", "--key", key]
        rh = run_tool(
            case_dir=case_dir,
            tool_name=f"{TOOL}:printkey",
            tool_version=vol_version(),
            command=rk_cmd,
            params={"artifact_type": "memory_regkey", "registry_key": key,
                    "evidence_path": str(evidence_path), "phase": "extraction"},
            output_path=rk_out,
            timeout=900,
            output_format="json",
        )
        rh["evidence_path"] = str(evidence_path)
        rh["artifact_type"] = "memory_regkey"
        rh["plugin"] = "windows.registry.printkey.PrintKey"
        rh["tool"] = f"{TOOL}:printkey"
        rh["tool_version"] = vol_version()
        rh["exact_command"] = " ".join(rk_cmd)
        handles.append(rh)

    return handles
