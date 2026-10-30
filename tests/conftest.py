import tempfile
import shutil
from pathlib import Path
import pytest


@pytest.fixture
def temp_case_dir():
    """Temporary case directory — cleaned up after test."""
    d = tempfile.mkdtemp(prefix="spectre-test-")
    for sub in ["evidence", "raw_extract", "findings", "reports"]:
        Path(d, sub).mkdir(parents=True, exist_ok=True)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def isolate_filesystem(monkeypatch, tmp_path):
    """Prevent tests from touching real ~/spectre-cases/ or ~/.cache/spectre/."""
    monkeypatch.setenv("SPECTRE_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("SPECTRE_CACHE_DIR", str(tmp_path / "cache"))


@pytest.fixture(autouse=True)
def isolate_audit_external_anchors(monkeypatch):
    """WS1c (spectre.pipeline.audit): the audit-chain external anchors are
    real, best-effort integrations -- systemd-journal checkpointing on every
    append(), and an opt-in HMAC keyed from the environment -- and some
    hosts running this suite genuinely have a working journald. Left at
    their defaults, every test that calls audit.append() would shell out to
    systemd-cat for real, and a later verify_full() would read back a REAL,
    test-suite-wide journal that many unrelated fixtures populate with
    colliding case_id/seq combinations (fixtures across the suite often
    reuse generic case names like "case-a") -- pure test-isolation noise,
    unrelated to whatever an individual test is actually checking. Default
    both features off/absent for the whole suite; the tests that
    specifically exercise them
    (tests/test_pipeline/test_audit_journal_anchor.py and
    tests/test_pipeline/test_audit_hmac_anchor.py) opt back in per-test via
    their own monkeypatch calls, which run after this fixture and win."""
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "0")
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("SPECTRE_AUDIT_HMAC_KEYFILE", raising=False)


@pytest.fixture
def sample_evtx():
    return Path(__file__).parent / "test_evtx" / "sample.evtx"


@pytest.fixture
def sample_events():
    return Path(__file__).parent / "fixtures" / "case-000.events.json"
