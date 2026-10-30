"""End-to-end: build the wheel, install it, run a case out of site-packages.

Spec: the module-selection design spec §6 item 1 —
"Clean-venv wheel install: spectre-canary runs, Phase 0 completes, AND an
extensionless regf hive triages RECOGNIZED (catches §3.3 and §3.4 together)."

Opt-in, because it builds a wheel and creates a venv (tens of seconds, and the
build backend may need fetching):

    SPECTRE_TEST_WHEEL=1 pytest tests/test_packaging_wheel.py -v -m integration

Honest limit: the venv is created with --system-site-packages and the wheel is
installed --no-deps, so this does NOT verify that the declared dependencies
resolve from an index. It verifies the thing that was actually broken — file
LAYOUT. Every §3.3-class defect was a path that exists in a source checkout and
not in a wheel, and a --no-deps install into a fresh venv reproduces that
exactly: the package runs from site-packages, `scripts/` is gone, and package
data either shipped or it did not.

The cheap always-on guards for the same failure class are in
test_packaging_install.py.
"""

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parent.parent
_REGF = b"regf" + b"\x00" * 508

_ENABLED = os.environ.get("SPECTRE_TEST_WHEEL", "") not in ("", "0", "false")
_skip = pytest.mark.skipif(
    not _ENABLED, reason="set SPECTRE_TEST_WHEEL=1 to build and install a wheel")


@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    out = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out),
         str(_REPO)],
        capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    wheels = list(out.glob("spectre_forensic-*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


@pytest.fixture(scope="module")
def installed(wheel, tmp_path_factory):
    """A venv with the wheel installed, plus the python and console scripts."""
    venv = tmp_path_factory.mktemp("venv") / "v"
    proc = subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    pip = venv / "bin" / "pip"
    proc = subprocess.run([str(pip), "install", "--no-deps", str(wheel)],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return venv


def _run(venv, *args, env=None, timeout=300):
    full = dict(os.environ)
    # journald anchoring is best-effort and noisy under test; the audit chain
    # itself is unaffected.
    full["SPECTRE_AUDIT_JOURNAL_ANCHOR"] = "0"
    full.update(env or {})
    return subprocess.run([str(venv / "bin" / args[0]), *args[1:]],
                          capture_output=True, text=True, timeout=timeout,
                          env=full)


# ── wheel contents ───────────────────────────────────────────────────────

@_skip
def test_wheel_ships_every_module_manifest(wheel):
    names = zipfile.ZipFile(wheel).namelist()
    manifests = sorted(n for n in names if n.endswith("/module.yaml"))
    module_dirs = sorted(
        c.name for c in (_REPO / "src" / "spectre" / "modules").iterdir()
        if c.is_dir() and not c.name.startswith((".", "__"))
        and (c / "__init__.py").exists())
    assert len(manifests) == len(module_dirs), (manifests, module_dirs)


@_skip
def test_wheel_ships_the_knowledge_base(wheel):
    names = zipfile.ZipFile(wheel).namelist()
    fk = [n for n in names if "/knowledge/" in n and n.endswith((".yaml", ".yml"))]
    assert len(fk) > 20, f"only {len(fk)} knowledge YAML files shipped"
    assert any(n.endswith("mitre-map.yaml") for n in names)


@_skip
def test_wheel_contains_no_scripts_directory(wheel):
    """The premise of the §3.3 P0: `scripts/` never shipped. Nothing may depend
    on it — this asserts the absence so the next reader does not have to
    rediscover it the hard way."""
    names = zipfile.ZipFile(wheel).namelist()
    assert not [n for n in names if "scripts/" in n]


# ── the installed package ────────────────────────────────────────────────

@_skip
def test_package_runs_from_site_packages(installed):
    proc = _run(installed, "python", "-c",
                "import spectre, pathlib; "
                "print(pathlib.Path(spectre.__file__).parent)")
    assert proc.returncode == 0, proc.stderr
    where = proc.stdout.strip()
    assert "site-packages" in where, where
    assert str(_REPO) not in where, "resolved back to the source checkout"


@_skip
def test_canary_is_not_dead_on_a_non_editable_install(installed):
    """The P0 itself. Before S-D this exited 3 with
    failed_tools=['canary_script_missing'] on every install."""
    proc = _run(installed, "spectre-canary")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DEAD" not in proc.stdout
    assert "canary_script_missing" not in proc.stdout


@_skip
def test_extensionless_hive_is_recognized_from_the_wheel(installed, tmp_path):
    """§3.4 and §3.3 together: the module must ship, its manifest must ship,
    and libmagic must work — otherwise a bare SYSTEM hive triages UNRECOGNIZED
    and the report calls its contents unverified."""
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(_REGF)
    proc = _run(installed, "python", "-c",
                "import json,sys;from spectre.pipeline.recognize import "
                f"triage_one;print(json.dumps(triage_one({str(hive)!r})))")
    assert proc.returncode == 0, proc.stderr
    import json
    rec = json.loads(proc.stdout)
    assert rec["module"] == "registry_hive", rec
    assert rec["status"] in ("RECOGNIZED", "EXTRACTOR_PENDING"), rec
    assert rec["confidence"] > 0.0, rec


@_skip
def test_phase_0_completes_from_the_wheel(installed, tmp_path):
    """Including on a CASES_DIR that does not exist yet — the fresh-install
    FileNotFoundError this test found."""
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(_REGF)
    cases = tmp_path / "never-existed" / "cases"
    assert not cases.exists()
    proc = _run(installed, "spectre", "--name", "WHEELTEST", "--profile",
                "auto", "--phase", "0", "--evidence", str(hive),
                env={"SPECTRE_CASES_DIR": str(cases)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    case_dirs = [d for d in cases.iterdir() if d.is_dir()]
    assert len(case_dirs) == 1, case_dirs
    case = case_dirs[0]
    for expected in ("manifest.yaml", "audit.jsonl", "execution.log",
                     "fk_context.yaml", "evidence"):
        assert (case / expected).exists(), f"{expected} missing from {case}"
    # The knowledge base has to have shipped for FK context to resolve at all.
    assert "registry_run" in (case / "fk_context.yaml").read_text()
    shutil.rmtree(cases, ignore_errors=True)
