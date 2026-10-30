"""Opt-in golden change-detector: full pipeline run against the XLoader
sample pcap, compared against a committed STABLE snapshot.

This is a change-DETECTOR, not a correctness oracle: the golden JSON below
was generated from a real run on 2026-08-04 and captures TODAY's behavior,
warts included (e.g. it is silent on whether 50 pcap-c2-protocol findings
is the "right" number -- only that it doesn't move without someone looking
at the diff). Its job is to make later workstreams' regressions VISIBLE,
not to certify current output as correct.

Deliberately excluded from the snapshot: free text (finding titles,
descriptions, exact_command paths -- these are expected to change under
WS5's determinism fix and other in-flight workstreams) and timestamps.
Included: sorted rule_ids, per-rule finding counts, the MITRE technique
set, and status counts -- structural facts that should only change when
detection logic actually changes.

Kept OUT of the default `pytest` run via the `integration` marker (see
[tool.pytest.ini_options] markers in pyproject.toml) plus three independent
skip gates, so normal `pytest -q` stays fast, network-free, and
tool-free:
  - RUN_GOLDEN env var must be set (opt-in)
  - Zeek must be present (SPECTRE_ZEEK_PATH, PATH, or /opt/zeek/bin/zeek)
  - the XLoader sample pcap must be present under ~/spectre-cases/samples/

Run it explicitly with:
    RUN_GOLDEN=1 pytest tests/test_pipeline/test_golden_xloader.py -v -m integration

Regenerating the golden fixture (only after an intentional, reviewed change
to pcap detection/correlation -- never to silence a failure you haven't
looked at):
    RUN_GOLDEN=1 UPDATE_GOLDEN=1 pytest \\
        tests/test_pipeline/test_golden_xloader.py -v -m integration
This overwrites tests/fixtures/golden/xloader_summary.json with the current
run's summary instead of asserting against it. Review the diff like any
other change to committed behavior before merging it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLE_PCAP = Path.home() / "spectre-cases" / "samples" / "2026-01-15-XLoader-infection.pcap"
GOLDEN_PATH = REPO_ROOT / "tests" / "fixtures" / "golden" / "xloader_summary.json"


def _zeek_path() -> str | None:
    """Mirror spectre.config._resolve_zeek()'s search order without
    importing config at collection time (keep this test file import-light
    so a missing Zeek install can't break collection of the rest of the
    suite)."""
    env = os.environ.get("SPECTRE_ZEEK_PATH")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    import shutil
    found = shutil.which("zeek")
    if found:
        return found
    for cand in ("/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


_SKIP_REASON = None
if not os.environ.get("RUN_GOLDEN"):
    _SKIP_REASON = "opt-in only -- set RUN_GOLDEN=1 to run this golden change-detector"
elif not _zeek_path():
    _SKIP_REASON = "Zeek binary not found (checked SPECTRE_ZEEK_PATH, PATH, /opt/zeek/bin/zeek)"
elif not SAMPLE_PCAP.is_file():
    _SKIP_REASON = f"sample pcap not found: {SAMPLE_PCAP}"


def _build_summary(case_dir: Path) -> dict:
    """Build the STABLE (non-volatile) snapshot for a completed case dir:
    sorted rule_ids, per-rule finding counts, mitre-technique set, status
    counts. No free text, no timestamps, no paths."""
    audit_rows = [
        json.loads(line)
        for line in (case_dir / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    rule_id_by_finding = {
        row["params"]["finding_id"]: row["params"]["rule_id"]
        for row in audit_rows
        if row.get("action") == "finding_create"
    }

    finding_files = sorted((case_dir / "findings").glob("F-*.yaml"))
    findings = [yaml.safe_load(p.read_text()) for p in finding_files]

    rule_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    mitre_set: set[str] = set()

    for f in findings:
        rule_id = rule_id_by_finding.get(f["finding_id"], "UNKNOWN")
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        status_counts[f["status"]] = status_counts.get(f["status"], 0) + 1
        for technique in str(f.get("mitre_attack", "")).split(","):
            technique = technique.strip()
            if technique:
                mitre_set.add(technique)

    return {
        "total_findings": len(findings),
        "rule_counts": dict(sorted(rule_counts.items())),
        "mitre_techniques": sorted(mitre_set),
        "status_counts": dict(sorted(status_counts.items())),
    }


def _run_pipeline(cases_dir: Path) -> Path:
    """Run phases 0-4 (through Correlation + Verification) over the XLoader
    sample pcap into a fresh case under cases_dir. Stops before Phase 5
    (adversarial review) and Phase 6 (report), which require an LLM --
    --skip-ai skips Phase 5; we simply don't ask for Phase 6."""
    result = subprocess.run(
        [
            sys.executable, "-m", "spectre.pipeline.runner",
            "--name", "xloader-golden",
            "--profile", "auto",
            "--evidence", str(SAMPLE_PCAP),
            "--phase", "4",
            "--skip-ai",
            "--new-case",
            "--cases-dir", str(cases_dir),
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "SPECTRE_CASES_DIR": str(cases_dir)},
        capture_output=True,
        text=True,
        timeout=580,
    )
    assert result.returncode == 0, (
        f"spectre pipeline run failed (rc={result.returncode}):\n"
        f"--- stdout ---\n{result.stdout[-4000:]}\n"
        f"--- stderr ---\n{result.stderr[-4000:]}"
    )

    case_dirs = [d for d in cases_dir.iterdir() if d.is_dir() and d.name != "index.md"]
    assert len(case_dirs) == 1, f"expected exactly one case dir, found: {case_dirs}"
    return case_dirs[0]


@pytest.mark.integration
@pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
def test_xloader_pipeline_matches_golden_summary(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    case_dir = _run_pipeline(cases_dir)
    summary = _build_summary(case_dir)

    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"UPDATE_GOLDEN=1 -- wrote {GOLDEN_PATH}, not asserting")

    golden = json.loads(GOLDEN_PATH.read_text())
    assert summary == golden, (
        "pcap pipeline output diverged from the committed golden snapshot.\n"
        "If this divergence is an intentional, reviewed change to "
        "detection/correlation, regenerate with:\n"
        "  RUN_GOLDEN=1 UPDATE_GOLDEN=1 pytest "
        "tests/test_pipeline/test_golden_xloader.py -v -m integration\n"
        f"golden:  {json.dumps(golden, sort_keys=True)}\n"
        f"current: {json.dumps(summary, sort_keys=True)}"
    )
