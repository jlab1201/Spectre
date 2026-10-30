"""rule_discovery.py — filesystem discovery of detection rules (Phase 2).

A contributor adds a rule by dropping a file into a module's `rules/`
directory and opening a PR — there is no central `RULES` list to edit. This
mirrors `modules/registry.py`, which discovers whole modules the same way.

`collect_rules(rules_dir)` imports every rule file under `rules_dir` and
gathers the `Rule` objects each defines:

  * Python files (`*.py`, not `_`-prefixed) export either a `RULES` list or
    one or more module-level `Rule` instances.
  * Sigma files (`*.yml`/`*.yaml`) are compiled via `core.sigma_import`
    (added in Phase 3); until then they are skipped honestly.

The function is pure-ish (I/O only at load): it imports files but mutates no
global state, and is unit-tested against a temp directory. A malformed
drop-in is skipped with a warning rather than taking down discovery — a bad
contribution must never silence the rules that load fine.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid as _uuid
from pathlib import Path

from spectre.core.base import Rule

_SIGMA_SUFFIXES = {".yml", ".yaml"}


def _load_python_rules(path: Path) -> list[Rule]:
    """Import a single .py rule file and return the Rule objects it defines.

    Prefers an exported ``RULES`` list; otherwise gathers every module-level
    ``Rule`` instance. Uses a unique synthetic module name so dropping two
    files with the same basename in different modules never collides.
    """
    mod_name = f"_spectre_dropin_{_uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        return []
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(mod_name, None)

    exported = getattr(module, "RULES", None)
    if isinstance(exported, (list, tuple)):
        return [r for r in exported if isinstance(r, Rule)]
    # No RULES list — gather any module-level Rule instances.
    return [v for v in vars(module).values() if isinstance(v, Rule)]


def _load_sigma_rules(path: Path) -> list[Rule]:
    """Compile a Sigma file into Rule objects.

    Wired in Phase 3 (``core.sigma_import``). If the importer is not present
    yet, the file is skipped honestly rather than guessed at.
    """
    try:
        from spectre.core.sigma_import import compile_sigma
    except ImportError:
        return []
    rule = compile_sigma(path.read_text())
    return [rule] if rule is not None else []


def collect_rules(rules_dir) -> list[Rule]:
    """Gather all Rule objects defined under ``rules_dir``.

    Returns [] when the directory does not exist, so a module can fall back to
    its legacy ``from .rules import RULES`` path. Files are loaded in filename
    order for a stable, reproducible catalog. ``_``-prefixed files (helpers,
    ``_template.py``, ``__init__.py``) are skipped.
    """
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        return []

    collected: list[Rule] = []
    for path in sorted(rules_dir.iterdir()):
        if not path.is_file() or path.name.startswith("_"):
            continue
        try:
            if path.suffix == ".py":
                collected.extend(_load_python_rules(path))
            elif path.suffix in _SIGMA_SUFFIXES:
                collected.extend(_load_sigma_rules(path))
        except Exception as e:  # a bad drop-in must not break the rest
            print(f"[rule_discovery] WARNING: skipping '{path.name}': {e}",
                  file=sys.stderr)
            continue
    return collected


def module_rules(module_dir, legacy_rules) -> list[Rule]:
    """The rule pack for a module: its legacy ``rules.py`` rules plus any
    community drop-ins under ``<module_dir>/rules/``.

    Both coexist — a module need not migrate its existing rules.py to accept
    drop-ins. When no ``rules/`` directory exists, this returns the legacy
    list unchanged, so behavior is identical until someone drops a file in.
    """
    return list(legacy_rules) + collect_rules(Path(module_dir) / "rules")
