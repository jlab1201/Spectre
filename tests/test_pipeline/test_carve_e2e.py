"""Track B2 e2e: disk image -> carve -> derived evidence -> module analysis."""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.fixtures.build_carve_image import build, MKFS, DEBUGFS

pytestmark = pytest.mark.skipif(
    not (Path(MKFS).exists() and Path(DEBUGFS).exists()
         and shutil.which("fls") and shutil.which("icat")),
    reason="needs e2fsprogs + sleuthkit")


def test_disk_image_carve_to_findings_pipeline(tmp_path):
    img = build(tmp_path)
    # sanity: fls actually sees our files (fail fast with a clear message)
    body = subprocess.run(["fls", "-r", "-m", "/", str(img)],
                          capture_output=True, text=True)
    assert "Security.evtx" in body.stdout, f"fixture broken: {body.stderr}"

    # _read_counter() creates its own parent dir under the effective
    # cases_dir kwarg passed to setup_case() below (W1-3); this pre-create
    # is now just belt-and-suspenders.
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    from spectre.pipeline.case_setup import setup_case
    result = setup_case(name="carve-e2e", profile="auto",
                        evidence_paths=[str(img)],
                        cases_dir=str(cases_dir))
    case_dir = Path(result["case_dir"])

    # Phase 2 — mirror how tests/test_pipeline/test_derived_evidence.py
    # drives phase 2: load the manifest Phase 0 persisted and call the
    # real live-extraction entry point directly.
    from spectre.pipeline import phase_runner
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())
    phase_runner._run_phase_2_live(str(case_dir), manifest)

    derived = manifest.get("derived_evidence", {})
    assert derived, "no derived evidence carved"
    names = {Path(k).name for k in derived}
    assert any(n.endswith("Security.evtx") for n in names), (
        f"no carved Security.evtx among {names}; "
        f"body:\n{body.stdout}"
    )
    assert any(n.endswith(".pf") for n in names), (
        f"no carved .pf among {names}; body:\n{body.stdout}"
    )
    # the carved prefetch was re-triaged to the prefetch module
    pf = next(v for k, v in derived.items() if k.endswith(".pf"))
    assert pf["module"] == "prefetch"
    assert pf["derived_from"].endswith("host.dd")
    assert pf["sha256"]
    # audit chain carries the derivation
    audit = (case_dir / "audit.jsonl").read_text()
    assert "derived_evidence_register" in audit
