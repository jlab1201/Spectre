"""case000_core.py — shared helper for the case-000 deterministic-core oracle.

NOT a test module (no test_* functions; pytest's default collection pattern
`test_*.py` / `*_test.py` skips this file). test_e2e.py and test_verify.py
both import `build_case000_case()` so there is exactly one code path that
builds the case-000 finding — the truth fixture
(tests/fixtures/case-000-truth.yaml) stays the single source of truth for
both the e2e pin and the verify oracle.

Deterministic core only: normalize -> detect -> emit. No LLM/explain step —
that seam is gated behind an API key and out of scope for this pin (see
Host neutrality (see README Architecture): explain() is one of the two in-process AI
seams, not part of the deterministic core).
"""

import json
from pathlib import Path

import yaml

from spectre.config import FK_WINDOWS_DIR, MITRE_MAP_PATH
from spectre.core.detect import detect
from spectre.core.emit_finding import emit, get_next_finding_number
from spectre.core.normalize import normalize
from spectre.pipeline.audit import append, verify_chain

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
EVENTS_FIXTURE = FIXTURES_DIR / "case-000.events.json"
TRUTH_FIXTURE = FIXTURES_DIR / "case-000-truth.yaml"

FK_YAML = str(FK_WINDOWS_DIR / "evtx_4688.yaml")
MITRE_MAP = str(MITRE_MAP_PATH)


def load_truth() -> dict:
    """Load tests/fixtures/case-000-truth.yaml — the single source of truth."""
    return yaml.safe_load(TRUTH_FIXTURE.read_text())


def make_case_dir(base_dir) -> Path:
    """Create a fresh case directory (evidence/raw_extract/findings/reports)
    under *base_dir* (a tmp_path or tmp_path_factory mktemp result), named
    like a real case ('000-...') so finding_id derivation (case_dir.name
    split on '-') behaves the way it does in production."""
    case_dir = Path(base_dir) / "000-case000-oracle"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir


def build_case000_case(case_dir) -> dict:
    """Run normalize -> detect -> emit over the case-000 fixture events into
    *case_dir* (must already exist, e.g. via make_case_dir()).

    Returns:
        {
          "events": list[NormEvent],
          "anchors": list[Anchor],
          "findings": list[dict],   # emit() return values, in anchor order
          "case_dir": Path,
        }
    """
    case_dir = Path(case_dir)
    records = json.loads(EVENTS_FIXTURE.read_text())
    events = normalize(records, str(EVENTS_FIXTURE))
    anchors = detect(events)

    # The extraction's tool_exec row, as Phase 2 writes it; the findings
    # cite it as their evidence_ref.
    source_execution_id = append(str(case_dir), {
        "actor": "deterministic-core", "action": "tool_exec",
        "tool": "evtx_dump_fixture", "tool_version": "0.1",
        "exact_command": f"cat {EVENTS_FIXTURE}", "params": {},
        "case_id": case_dir.name, "output_path": str(EVENTS_FIXTURE),
        "output_sha256": "", "result": "success", "exit_code": 0,
        "duration_ms": 0, "finding_id": None, "phase": 2,
        "phase_step": "S1-extract-evtx_dump_fixture",
    })

    findings = []
    for anchor in anchors:
        num = get_next_finding_number(str(case_dir / "findings"))
        finding = emit(anchor, str(case_dir), num, FK_YAML, MITRE_MAP,
                       source_execution_id=source_execution_id)
        findings.append(finding)

    return {
        "events": events,
        "anchors": anchors,
        "findings": findings,
        "case_dir": case_dir,
    }


__all__ = [
    "load_truth",
    "make_case_dir",
    "build_case000_case",
    "verify_chain",
    "FIXTURES_DIR",
    "EVENTS_FIXTURE",
    "TRUTH_FIXTURE",
    "FK_YAML",
    "MITRE_MAP",
]
