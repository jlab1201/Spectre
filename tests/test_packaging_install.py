"""Spectre must run from a real install, not just a source checkout.

Spec: the module-selection design spec §3.3.

Two first-run defects lived here, both invisible under `pip install -e .` in a
long-lived checkout:

  1. canary.py resolved `scripts/session-canary.sh` four parents up from
     itself. `scripts/` is not in the wheel, so on a non-editable install the
     file was absent, the canary returned DEAD, and runner.py turned that into
     exit 3 — every phase, every case. Fixed by stage S-D, which deleted the
     script; guarded here by asserting nothing resolves a runtime path through
     the repo root.

  2. `_read_counter()` wrote `.case-counter` into CASES_DIR without creating
     the directory, so the FIRST `spectre --phase 0` on any fresh install died
     with a raw FileNotFoundError traceback. Found by the clean-venv wheel run
     the spec asked for; it only ever worked because ~/spectre-cases already
     existed.

The heavyweight end-to-end (build wheel, install into a venv, run a case) is
in test_packaging_wheel.py behind an env flag. These are the cheap always-on
guards for the same failure class.
"""

from pathlib import Path

import pytest

from spectre.pipeline import case_setup

_SRC = Path(__file__).resolve().parent.parent / "src" / "spectre"


def test_first_run_creates_the_cases_dir(tmp_path, monkeypatch):
    """A fresh install has no ~/spectre-cases. Creating it is Spectre's job."""
    cases = tmp_path / "never-existed" / "spectre-cases"
    monkeypatch.setattr(case_setup, "CASES_DIR", cases)
    assert not cases.exists()
    assert case_setup._read_counter(str(cases)) == 1
    assert (cases / ".case-counter").read_text().strip() == "001"
    assert case_setup._read_counter(str(cases)) == 2


def test_counter_survives_a_corrupt_value(tmp_path, monkeypatch):
    """An unparseable counter must not crash the run. Recovering by scanning
    the existing case dirs keeps a NEW case from colliding with an old one —
    resetting to 1 would try to reuse a case_id that is already on disk."""
    cases = tmp_path / "spectre-cases"
    cases.mkdir()
    (cases / ".case-counter").write_text("not-a-number\n")
    (cases / "007-earlier-case").mkdir()
    monkeypatch.setattr(case_setup, "CASES_DIR", cases)
    assert case_setup._read_counter(str(cases)) == 8


def test_no_runtime_path_resolves_through_the_repo_root():
    """`_PROJECT_ROOT` is the repo root — one level above the installed
    package, which in a wheel install is site-packages. Anything resolved
    through it exists only in a source checkout, which is how defect 1
    happened. config.py may compute it; nothing may build a runtime path from
    it."""
    config_src = (_SRC / "config.py").read_text(encoding="utf-8")
    offenders = [
        line.strip() for line in config_src.splitlines()
        if "_PROJECT_ROOT" in line
        and not line.lstrip().startswith("#")
        and "_PROJECT_ROOT =" not in line
    ]
    assert not offenders, (
        "runtime path resolved through the repo root — absent in a wheel:\n"
        + "\n".join(offenders)
    )

    others = []
    for path in sorted(_SRC.rglob("*.py")):
        if path.name == "config.py":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "_PROJECT_ROOT" in line and not line.lstrip().startswith("#"):
                others.append(f"{path.relative_to(_SRC)}:{n}: {line.strip()}")
    assert not others, "\n".join(others)


@pytest.mark.parametrize("dead", ["CANARY_SCRIPT", "REGISTER_SCRIPT"])
def test_script_constants_are_gone(dead):
    from spectre import config
    assert not hasattr(config, dead), (
        f"config.{dead} pointed into scripts/, which is not in the wheel"
    )
