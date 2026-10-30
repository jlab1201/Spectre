"""
registry.py — discover and load analyzer modules.

Each evidence-type module lives in `modules/<name>/__init__.py` and
exposes a module-level `MODULE = AnalyzerModule(...)`. The registry
imports them and validates shape.

Discovery is filesystem-driven: dropping a new module directory makes
it available with no edits here — satisfying "add capabilities bit by
bit". The pipeline requires only ONE module to function.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from spectre.core.base import AnalyzerModule

MODULES_DIR = Path(__file__).resolve().parent

# Directories under modules/ that are not analyzer modules.
_SKIP = {"__pycache__", "tests"}


def discover_with_errors() -> tuple[dict[str, AnalyzerModule], dict[str, str]]:
    """discover(), plus the import errors it would otherwise only print.

    A module that fails to import is a silent loss of analysis capability:
    its evidence types stop being recognized, its rules stop being
    evaluated, and the stderr warning below reaches no audit row and no
    report line. Callers that must DISCLOSE reduced coverage need the
    errors, not just the survivors — see report_synthesize's Forensic Blind
    Spots section.

    Returns ({module_name: AnalyzerModule}, {module_dir_name: reason}).
    Note the two dicts are keyed differently: successes by the module's
    declared `name`, failures by its directory name, because a module that
    did not load has no declared name to key on.
    """
    found: dict[str, AnalyzerModule] = {}
    errors: dict[str, str] = {}
    for child in sorted(MODULES_DIR.iterdir()):
        if not child.is_dir() or child.name in _SKIP or child.name.startswith("."):
            continue
        if not (child / "__init__.py").exists():
            continue
        try:
            mod = importlib.import_module(f"spectre.modules.{child.name}")
            # ponytail: reload picks up indicator YAML changes without restart
            mod = importlib.reload(mod)
        except Exception as e:
            print(f"[registry] WARNING: failed to import module '{child.name}': {e}",
                  file=sys.stderr)
            errors[child.name] = f"{type(e).__name__}: {e}"
            continue
        analyzer = getattr(mod, "MODULE", None)
        # Also check for module-specific export names (e.g., MEMORY_MODULE, EVTX_MODULE)
        if not isinstance(analyzer, AnalyzerModule):
            # Try the *_MODULE naming convention
            for attr_name in dir(mod):
                if attr_name.endswith("_MODULE") and isinstance(getattr(mod, attr_name), AnalyzerModule):
                    analyzer = getattr(mod, attr_name)
                    break
        if not isinstance(analyzer, AnalyzerModule):
            print(f"[registry] WARNING: '{child.name}' has no MODULE: AnalyzerModule",
                  file=sys.stderr)
            errors[child.name] = "no MODULE: AnalyzerModule"
            continue
        found[analyzer.name] = analyzer
    return found, errors


def discover() -> dict[str, AnalyzerModule]:
    """Import every analyzer module package and return {name: AnalyzerModule}.

    Signature deliberately unchanged — recognize.py and test_mitre_map.py both
    depend on the plain dict. Use discover_with_errors() when the caller has
    to disclose what failed to load.
    """
    modules, _ = discover_with_errors()
    return modules


if __name__ == "__main__":
    mods = discover()
    print(f"Discovered {len(mods)} analyzer module(s):")
    for name, m in mods.items():
        tools = ", ".join(m.required_tools) or "—"
        print(f"  {name:10s} artifact={m.artifact_type:14s} tools=[{tools}] "
              f"rules={len(m.rules)} recognizers={len(m.recognizers)}")
