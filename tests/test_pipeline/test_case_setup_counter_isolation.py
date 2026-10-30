"""W1-3: `_read_counter()` (case_setup.py ~192-219) hardcoded the
module-level `CASES_DIR` global (bound from spectre.config at import time)
instead of the effective `cases_dir` a caller passed to `setup_case()` via
`--cases-dir`. WS8 fixed the identical class of bug for the cross-case
index at the runner.verify_and_close() call site (see
tests/test_pipeline/test_cross_case_containment.py) by deriving the path
from the real, active directory rather than the import-time global. This
file follows the same pattern for the Phase 0 case counter: a run under a
custom --cases-dir must read/write its `.case-counter` under THAT
directory, and must never touch the global default CASES_DIR store.

HARD SAFETY CONSTRAINT: every test here monkeypatches case_setup.CASES_DIR
to a decoy tmp_path before calling setup_case() with an explicit, different
tmp cases_dir -- so a regression back to the global would be caught by the
decoy-untouched assertion, and this suite never touches the real
~/spectre-cases store.
"""
from pathlib import Path

import pytest

from spectre.pipeline import case_setup


@pytest.fixture(autouse=True)
def _guard_real_cases_store():
    real_counter = Path.home() / "spectre-cases" / ".case-counter"
    before = real_counter.stat().st_mtime if real_counter.exists() else None
    yield
    after = real_counter.stat().st_mtime if real_counter.exists() else None
    assert before == after, (
        "a test in this file touched the REAL ~/spectre-cases/.case-counter"
    )


def test_setup_case_writes_counter_under_effective_cases_dir_not_global(tmp_path, monkeypatch):
    decoy_global = tmp_path / "DECOY-GLOBAL-should-never-be-touched"
    real_cases_dir = tmp_path / "actual-cases-dir"
    monkeypatch.setattr(case_setup, "CASES_DIR", decoy_global)

    result = case_setup.setup_case(
        name="counter-isolation-test", profile="quick-triage",
        cases_dir=str(real_cases_dir),
    )

    assert (real_cases_dir / ".case-counter").exists(), (
        "the counter must live under the effective --cases-dir, not the "
        "import-time config.CASES_DIR global"
    )
    assert not decoy_global.exists(), (
        "setup_case() must never read or create anything under the "
        "module-level CASES_DIR global when an explicit cases_dir is given"
    )
    assert result["case_id"] == "001"


def test_setup_case_second_run_increments_counter_under_effective_cases_dir(tmp_path, monkeypatch):
    decoy_global = tmp_path / "DECOY-GLOBAL-should-never-be-touched"
    real_cases_dir = tmp_path / "actual-cases-dir"
    monkeypatch.setattr(case_setup, "CASES_DIR", decoy_global)

    first = case_setup.setup_case(
        name="counter-isolation-a", profile="quick-triage",
        cases_dir=str(real_cases_dir),
    )
    second = case_setup.setup_case(
        name="counter-isolation-b", profile="quick-triage",
        cases_dir=str(real_cases_dir),
    )

    assert first["case_id"] == "001"
    assert second["case_id"] == "002"
    assert not decoy_global.exists()


def test_read_counter_takes_explicit_cases_dir_argument(tmp_path):
    """Unit-level check of _read_counter() itself: it must accept and act
    strictly on an explicit cases_dir, creating the directory and counter
    file there."""
    target = tmp_path / "explicit-cases-dir"
    n = case_setup._read_counter(str(target))
    assert n == 1
    assert (target / ".case-counter").exists()
    assert (target / ".case-counter").read_text().strip() == "001"

    n2 = case_setup._read_counter(str(target))
    assert n2 == 2


# ── W1 required fix 2a: cases_dir with a literal "~" must expanduser ────

def test_setup_case_expands_tilde_cases_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    decoy_global = tmp_path / "DECOY-GLOBAL-should-never-be-touched"
    monkeypatch.setattr(case_setup, "CASES_DIR", decoy_global)

    result = case_setup.setup_case(
        name="tilde-case", profile="quick-triage",
        cases_dir="~/actual-cases-dir",
    )

    real_cases_dir = tmp_path / "actual-cases-dir"
    assert (real_cases_dir / ".case-counter").exists(), (
        "a literal '~'-prefixed cases_dir must be expanded to the same "
        "real directory the counter is written under"
    )
    # The case dir itself must be created under the EXPANDED path, not a
    # literal "~" directory relative to cwd.
    assert Path(result["case_dir"]).is_absolute()
    assert Path(result["case_dir"]).parent == real_cases_dir
    assert not decoy_global.exists()


# ── W1 required fix 2b: counter never goes backwards relative to disk ──

def test_read_counter_never_goes_backwards_relative_to_existing_case_dirs(tmp_path):
    """A present, well-formed, but STALE counter (e.g. a store copied from
    an older snapshot, or a case dir created without going through this
    counter) must not hand out a case_id that already exists on disk."""
    target = tmp_path / "cases-dir"
    target.mkdir()
    # Case dirs "005-x" and "007-y" exist on disk already...
    (target / "005-existing-a").mkdir()
    (target / "007-existing-b").mkdir()
    # ...but the counter file itself says only "002" (stale/behind).
    (target / ".case-counter").write_text("002\n")

    n = case_setup._read_counter(str(target))

    assert n == 8, (
        "counter must take max(counter_from_file, highest existing case "
        "dir number) + 1, never reuse an id (007) that's already on disk"
    )
    assert (target / ".case-counter").read_text().strip() == "008"


def test_read_counter_uses_counter_file_when_it_is_already_ahead(tmp_path):
    """The reverse direction must still work: a counter ahead of every
    existing case dir is respected as-is (not reset down to disk state)."""
    target = tmp_path / "cases-dir"
    target.mkdir()
    (target / "001-existing").mkdir()
    (target / ".case-counter").write_text("050\n")

    n = case_setup._read_counter(str(target))

    assert n == 51
