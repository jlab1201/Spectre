"""W4-1 / R1-F2 e2e: random bytes must never yield a clean bill.

R1 repro: 200 KB of /dev/urandom was classified as a memory image, every vol
run errored, and the report said "No indicators of compromise were detected".
Runs the real pipeline (setup_case → runner.run_phase) with the null
provider. No network, no real vol: the second test puts a failing `vol` on
PATH so the tool-failure path is exercised deterministically.
"""
import os
from pathlib import Path

import pytest
import yaml

from spectre import config
from spectre.pipeline import runner
from spectre.pipeline.case_setup import setup_case

CLEAN = "No indicators of compromise were detected"


def _run(tmp_path, evidence: Path) -> tuple[Path, list[bool]]:
    result = setup_case(name="urandom", profile="auto",
                        evidence_paths=[str(evidence)],
                        cases_dir=str(tmp_path / "cases"))
    assert result.get("success"), result
    case_dir = Path(result["case_dir"])
    outcomes = []
    for p in range(0, 7):
        ok = runner.run_phase(str(case_dir), p, skip_ai=False)
        outcomes.append(ok)
        if not ok:
            break
    return case_dir, outcomes


def _assert_not_clean(case_dir: Path):
    for md in (case_dir / "reports").glob("*.md"):
        text = md.read_text()
        assert CLEAN not in text, md
        assert "malicious processes? | INVESTIGATED" not in text, md


@pytest.fixture
def _null_provider(monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")


def test_pure_urandom_is_not_recognized_and_never_clean(tmp_path, _null_provider):
    ev = tmp_path / "random.bin"
    ev.write_bytes(os.urandom(200 * 1024))
    case_dir, outcomes = _run(tmp_path, ev)

    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    rec = next(iter(manifest["triage"].values()))
    assert rec.get("module") != "memory", rec
    # Stops at Gate 0 (no analyzer claimed anything) or Gate 2 — never later.
    assert outcomes[-1] is False and len(outcomes) <= 3, outcomes
    assert not manifest.get("gate_2", {}).get("passed")
    _assert_not_clean(case_dir)


def test_memory_claim_with_failing_vol_is_extraction_failed(
        tmp_path, monkeypatch, _null_provider):
    # A structured-looking blob (one zero page) that the recognizer claims,
    # and a `vol` that errors on every plugin — the F2 failure shape.
    ev = tmp_path / "suspect.bin"
    ev.write_bytes(b"\x00" * 4096 + os.urandom(200 * 1024))
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    vol = fake_bin / "vol"
    vol.write_text("#!/bin/sh\necho 'Volatility 3 Framework 2.28.0'\n"
                   "echo 'Unsatisfied requirement plugins.X.kernel.layer_name: "
                   "Windows kernel translation layer' >&2\nexit 1\n")
    vol.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(config, "MEMORY_ENGINE", "vol")

    case_dir, outcomes = _run(tmp_path, ev)
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    rec = next(iter(manifest["triage"].values()))
    assert rec.get("module") == "memory", rec

    res = next(iter(manifest["extraction"]["results"].values()))
    assert res["extraction_status"] == "EXTRACTION_FAILED"
    assert res["empty_data"] == "FAILED"
    assert manifest["gate_2"]["passed"] is False
    assert outcomes[2] is False
    _assert_not_clean(case_dir)
