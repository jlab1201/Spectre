"""Knowledge base loader for FK YAML, MITRE map, and shared indicator lists."""

import yaml
from spectre.config import MITRE_MAP_PATH, FK_DIRS, INDICATORS_DIR

# Parsed indicator-group YAML, cached per group so repeated rule evaluations
# don't re-read disk. Keyed by group name (the YAML file stem).
_INDICATOR_CACHE: dict[str, dict] = {}


def _load_indicator_group(group: str) -> dict:
    if group not in _INDICATOR_CACHE:
        path = INDICATORS_DIR / f"{group}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Indicator group not found: {group} ({path})")
        _INDICATOR_CACHE[group] = yaml.safe_load(path.read_text()) or {}
    return _INDICATOR_CACHE[group]


def load_indicator_list(group: str, key: str) -> list[str]:
    """Return the value list for an indicator key, e.g. ('processes','lolbins').

    Each YAML entry is `{description: ..., values: [...]}`; this returns a copy
    of `values`. Callers wrap in set()/tuple() as their rule logic requires.
    """
    data = _load_indicator_group(group)
    if key not in data:
        raise KeyError(f"Indicator '{key}' not in group '{group}'")
    return list(data[key]["values"])


def load_indicator_map(group: str, key: str) -> dict:
    """Return the mapping for a dict-style indicator, e.g. expected parents.

    Each such YAML entry is `{description: ..., mapping: {k: v, ...}}`.
    """
    data = _load_indicator_group(group)
    if key not in data:
        raise KeyError(f"Indicator '{key}' not in group '{group}'")
    return dict(data[key]["mapping"])


def load_fk_yaml(artifact_name: str) -> dict:
    """Load FK YAML for a named artifact (e.g. 'evtx_4688', 'prefetch')."""
    for fk_dir in FK_DIRS:
        yaml_path = fk_dir / f"{artifact_name}.yaml"
        if yaml_path.exists():
            return yaml.safe_load(yaml_path.read_text())
    raise FileNotFoundError(f"FK YAML not found for artifact: {artifact_name}")

def load_mitre_map() -> dict:
    """Load MITRE ATT&CK technique map."""
    return yaml.safe_load(MITRE_MAP_PATH.read_text())

def list_artifacts() -> list[str]:
    """List all available artifact names."""
    names = []
    for fk_dir in FK_DIRS:
        for yp in fk_dir.glob("*.yaml"):
            names.append(yp.stem)
    return sorted(names)

__all__ = ["load_fk_yaml", "load_mitre_map", "list_artifacts",
           "load_indicator_list", "load_indicator_map"]
