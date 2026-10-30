"""Declared dependencies must match what the code actually needs.

Spec: the module-selection design spec §3.4, §3.5.

Two failure modes, opposite directions, both live at HEAD before stage S-B:

  1. `python-magic` is UNDECLARED but load-bearing. With it absent,
     `recognize._magic_desc` returns "" and `Recognizer.match` loses its
     magic dimension entirely — so an extensionless `regf` hive (SYSTEM,
     SAM, NTUSER.DAT: the standard acquisition form) scores 0.00 and the
     report says "no analyzer module claimed it — contents UNVERIFIED".
     That statement is false: the module is installed. §3.4.

  2. `python-evtx` and `yara-python` are DECLARED but dead — zero consumers
     anywhere in src or tests. evtx extraction shells out to `evtxexport`
     (modules/evtx/extract.py), matching its declared required_tools. §3.5.

The hive test below is the one that matters forensically; the pyproject
assertions exist so a future dependency edit cannot silently re-open it.
"""

import tomllib
from pathlib import Path

from spectre import config
from spectre.pipeline import recognize

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# regf hive header + enough padding for libmagic to characterise it.
_REGF = b"regf" + b"\x00" * 508


def _core_deps() -> list[str]:
    with open(_PYPROJECT, "rb") as f:
        return tomllib.load(f)["project"]["dependencies"]


def _dep_names(deps: list[str]) -> set[str]:
    out = set()
    for spec in deps:
        name = spec.split(";")[0]
        for sep in (">=", "<=", "==", "!=", "~=", ">", "<", "["):
            name = name.split(sep)[0]
        out.add(name.strip().lower().replace("_", "-"))
    return out


def test_python_magic_is_a_declared_dependency():
    assert "python-magic" in _dep_names(_core_deps()), (
        "python-magic is imported by recognize.py and its absence silently "
        "breaks recognition of every extensionless artifact (§3.4)"
    )


def test_dead_dependencies_are_not_declared():
    names = _dep_names(_core_deps())
    dead = {"python-evtx", "yara-python"} & names
    assert not dead, (
        f"{sorted(dead)} have zero consumers in src or tests (§3.5); evtx "
        f"extraction uses the evtxexport binary, not python-evtx"
    )


def test_magic_is_importable_and_libmagic_is_present(tmp_path):
    """Declaring the wheel does not guarantee libmagic.so — risk R2.

    The wrapper imports fine with the native library absent, so probe it
    for real rather than asserting on the import alone.
    """
    assert recognize._HAVE_MAGIC, "python-magic did not import"
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(_REGF)
    desc = recognize._magic_desc(hive)
    assert desc, "libmagic returned no description — libmagic.so missing?"
    assert "registry" in desc.lower(), desc


def test_extensionless_registry_hive_is_claimed(tmp_path):
    """§3.4's measured failure, as a behavioural assertion.

    registry_hive's extensions are only {.dat,.hiv,.hive}, so a bare
    `SYSTEM` can only be claimed through the magic dimension. Asserting on
    the CLAIM (module/artifact_type), not on RECOGNIZED, because the status
    also depends on whether rip.pl is installed on the test host —
    EXTRACTOR_PENDING is an honest answer, UNRECOGNIZED is a false one.
    """
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(_REGF)
    rec = recognize.triage_one(str(hive))
    assert rec["module"] == "registry_hive", rec
    assert rec["artifact_type"] == "registry_run", rec
    assert rec["status"] in ("RECOGNIZED", "EXTRACTOR_PENDING"), rec
    assert rec["confidence"] > 0.0, rec


def test_config_exposes_no_dead_tool_paths():
    """EVTX_DUMP / YARA_PATH had zero consumers outside config.py; a stale
    tool path invites a future caller to shell out to a tool no module
    declares. CANARY_SCRIPT and REGISTER_SCRIPT are dead for a second
    reason — both point into scripts/, which is not in the wheel (§3.3)."""
    for dead in ("EVTX_DUMP", "YARA_PATH", "CANARY_SCRIPT", "REGISTER_SCRIPT"):
        assert not hasattr(config, dead), f"config.{dead} still exists"


def test_modules_package_does_not_eagerly_import_modules():
    """`spectre/modules/__init__.py` listed 4 of 8 modules in a hand-written
    MODULE_REGISTRY nothing referenced, and imported them eagerly — so
    `import spectre.modules.lnk` dragged in memory, evtx, disk and pcap.
    That is what made the import-weight guard in
    test_recognizer_import_weight.py report all 8 modules for one module's
    fault. Discovery is registry.discover()'s job and always was."""
    import subprocess
    import sys

    import spectre.modules as pkg
    assert not hasattr(pkg, "MODULE_REGISTRY")

    code = (
        "import spectre.modules.lnk, sys\n"
        "leaked = [m for m in ('memory', 'evtx', 'disk', 'pcap')\n"
        "          if f'spectre.modules.{m}' in sys.modules]\n"
        "assert not leaked, leaked\n"
    )
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
