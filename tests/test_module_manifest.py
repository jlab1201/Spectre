"""Every analyzer module declares itself in a YAML manifest, drift-checked.

Spec: the module-selection design spec §5.4.

`module.yaml` exists for exactly one consumer: the canary. Its point is to be
readable WITHOUT importing the module, so a module whose dependency is broken
can still be described ("pcap needs tcpdump or zeek") instead of vanishing
from the inventory entirely — the §3.9 silent-loss problem.

Two sources of truth is a drift hazard, so the overlapping fields are pinned
against the AnalyzerModule dataclass here. Anything the dataclass already
carries (name, artifact_type, required_tools) must agree exactly; the manifest
adds only what the runtime dataclass has no use for.
"""

import subprocess
import sys

import pytest

from spectre.modules import manifest as mf
from spectre.modules import registry

MODULE_DIRS = sorted(
    c.name for c in registry.MODULES_DIR.iterdir()
    if c.is_dir() and not c.name.startswith((".", "__"))
    and (c / "__init__.py").exists()
)


def test_every_module_dir_has_a_manifest():
    missing = [d for d in MODULE_DIRS
               if not (registry.MODULES_DIR / d / "module.yaml").exists()]
    assert not missing, f"no module.yaml in: {missing}"


def test_loader_finds_every_manifest_with_no_errors():
    manifests, errors = mf.load_manifests()
    assert errors == {}, errors
    assert sorted(manifests) == MODULE_DIRS


@pytest.mark.parametrize("dir_name", MODULE_DIRS)
def test_manifest_agrees_with_the_dataclass(dir_name):
    """The drift detector. module.yaml restating a dataclass field is only
    safe while the two cannot disagree."""
    manifests, _ = mf.load_manifests()
    man = manifests[dir_name]
    modules = registry.discover()
    assert man.name in modules, (
        f"{dir_name}/module.yaml declares name={man.name!r}, which "
        f"registry.discover() does not know: {sorted(modules)}"
    )
    mod = modules[man.name]
    assert man.artifact == mod.artifact_type, (
        f"{dir_name}: manifest artifact={man.artifact!r} != "
        f"MODULE.artifact_type={mod.artifact_type!r}"
    )
    assert list(man.tools) == list(mod.required_tools), (
        f"{dir_name}: manifest tools={list(man.tools)} != "
        f"MODULE.required_tools={list(mod.required_tools)}"
    )
    assert man.summary.strip(), f"{dir_name}: empty summary"


def test_manifest_directory_name_matches_declared_name():
    """registry.discover() keys by declared name but reports load failures by
    directory name (see discover_with_errors' docstring). The canary joins
    those two views, so the keys have to line up."""
    manifests, _ = mf.load_manifests()
    mismatched = {d: m.name for d, m in manifests.items() if d != m.name}
    assert not mismatched, mismatched


def test_loading_manifests_imports_no_analyzer_module():
    """The whole reason the manifest is YAML. If loading it imported the
    module, a module with a broken dependency would take its own description
    down with it and the canary would have nothing to report."""
    code = (
        "import sys\n"
        "from spectre.modules import manifest\n"
        "manifests, errors = manifest.load_manifests()\n"
        "assert len(manifests) >= 8, manifests\n"
        "leaked = [m for m in sys.modules if m.startswith('spectre.modules.')\n"
        "          and m != 'spectre.modules.manifest']\n"
        "assert not leaked, leaked\n"
    )
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_declared_tools_are_bare_names_not_paths():
    """The canary resolves these with shutil.which; an absolute path would
    silently always-fail, and a path is a host assumption besides."""
    manifests, _ = mf.load_manifests()
    for man in manifests.values():
        for tool in list(man.tools) + list(man.optional_tools):
            assert "/" not in tool, f"{man.name}: {tool!r} looks like a path"
