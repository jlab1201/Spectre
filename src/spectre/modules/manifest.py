"""
manifest.py — read each module's `module.yaml` WITHOUT importing the module.

The distinction from `registry.discover()` is the whole point. `discover()`
imports every module package, so a module whose dependency is broken
disappears from its result entirely — and the only trace was a stderr warning
(§3.9). The canary needs to describe a module it cannot load: "pcap needs
tcpdump or zeek, and it failed to import because <reason>" is a usable
environment report; silence is not.

So this loader touches only YAML. It never imports `spectre.modules.<name>`,
and tests/test_module_manifest.py asserts that in a subprocess.

Fields that restate an AnalyzerModule field (`name`, `artifact`, `tools`) are
pinned against the dataclass by the same test file, so the two views cannot
drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

MODULES_DIR = Path(__file__).resolve().parent

MANIFEST_NAME = "module.yaml"

# Directories under modules/ that are not analyzer modules.
_SKIP = {"__pycache__", "tests"}


@dataclass(frozen=True)
class ModuleManifest:
    """One module's declared identity and host requirements."""
    name: str
    artifact: str
    summary: str = ""
    # Tools without which the module cannot extract — unless tool_optional,
    # which means the module ships an availability() hook that knows better
    # (pcap: required_tools=["tcpdump"] but extraction is Zeek-primary).
    tools: tuple[str, ...] = ()
    tool_optional: bool = False
    # Tools whose absence costs capability, never the module (DEGRADED only).
    optional_tools: tuple[str, ...] = ()
    # Importable distributions, checked with importlib.util.find_spec.
    python_deps: tuple[str, ...] = ()
    python_deps_optional: tuple[str, ...] = ()
    # Forensic-knowledge YAML names (no extension) this module's evidence needs.
    # Replaces the two hand-maintained ARTIFACT_FK dicts that a 9th module used
    # to have to edit — see pipeline/fk_routing.py.
    fk_yamls: tuple[str, ...] = ()
    # Only for modules whose rules span MORE THAN ONE FK YAML (today: memory).
    # Everything else resolves from the single fk_yamls entry, so a 1:1 module
    # states its FK once and never repeats itself per artifact type.
    fk_by_artifact: dict = field(default_factory=dict)
    dir_name: str = ""
    all_tools: tuple[str, ...] = field(default=(), compare=False)


_REQUIRED_KEYS = ("name", "artifact")


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def parse_manifest(text: str, dir_name: str) -> ModuleManifest:
    """Parse one manifest. Raises ValueError on a shape the canary cannot use.

    Deliberately strict about the two identity keys: a manifest that cannot
    say which module it describes is worse than no manifest, because it would
    silently join the inventory under the wrong name.
    """
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"{MANIFEST_NAME} is not a YAML mapping")
    missing = [k for k in _REQUIRED_KEYS if not str(data.get(k, "")).strip()]
    if missing:
        raise ValueError(f"{MANIFEST_NAME} missing required key(s): {missing}")
    tools = _as_tuple(data.get("tools"))
    optional_tools = _as_tuple(data.get("optional_tools"))
    by_artifact = data.get("fk_by_artifact") or {}
    if not isinstance(by_artifact, dict):
        raise ValueError("fk_by_artifact must be a mapping of "
                         "artifact_type -> FK YAML name")
    return ModuleManifest(
        name=str(data["name"]).strip(),
        artifact=str(data["artifact"]).strip(),
        summary=str(data.get("summary") or "").strip(),
        tools=tools,
        tool_optional=bool(data.get("tool_optional", False)),
        optional_tools=optional_tools,
        python_deps=_as_tuple(data.get("python_deps")),
        python_deps_optional=_as_tuple(data.get("python_deps_optional")),
        fk_yamls=_as_tuple(data.get("fk_yamls")),
        fk_by_artifact={str(k): str(v) for k, v in by_artifact.items()},
        dir_name=dir_name,
        all_tools=tools + optional_tools,
    )


def load_manifests() -> tuple[dict[str, ModuleManifest], dict[str, str]]:
    """Read every module.yaml under modules/.

    Returns ({dir_name: ModuleManifest}, {dir_name: reason}). Keyed by
    DIRECTORY name, matching how registry.discover_with_errors() keys its
    failures, so the canary can join the two views for a module that has a
    manifest but did not import.

    A directory with no manifest is an error, not a silent omission: it means
    the canary has no way to know what that module needs, and stage S-D's whole
    purpose is that the inventory stops drifting away from the modules.
    """
    found: dict[str, ModuleManifest] = {}
    errors: dict[str, str] = {}
    for child in sorted(MODULES_DIR.iterdir()):
        if (not child.is_dir() or child.name in _SKIP
                or child.name.startswith((".", "__"))):
            continue
        if not (child / "__init__.py").exists():
            continue
        path = child / MANIFEST_NAME
        if not path.exists():
            errors[child.name] = f"no {MANIFEST_NAME}"
            continue
        try:
            found[child.name] = parse_manifest(
                path.read_text(encoding="utf-8"), child.name)
        except Exception as e:
            errors[child.name] = f"{type(e).__name__}: {e}"
    return found, errors
