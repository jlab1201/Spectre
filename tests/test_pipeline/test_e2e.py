"""End-to-end oracle for the deterministic core: normalize -> detect -> emit.

Pinned against tests/fixtures/case-000-truth.yaml (loaded, not hardcoded, so
the fixture stays the single source of truth). Exercises ONLY the
deterministic core (core/normalize.py, core/detect.py, core/emit_finding.py)
-- no LLM/explain step, so this test has zero network dependency and runs
the same way in CI as it does locally, regardless of SPECTRE_LLM_PROVIDER.

Previously this file was a `__main__` script (no test_* functions, exercised
tool_runner + explain() + a hand-rolled report.md writer, and depended on a
DeepSeek API key) and collected ZERO pytest items. It has been rewritten as
real pytest, scoped to the deterministic core the deterministic-core/AI-explainer
rule (README Architecture): the AI layer only explains findings the deterministic
core already produced, so pinning the deterministic core's behavior is the
safety net that has to exist before any output-changing fix lands.
"""

from spectre.pipeline.audit import verify_chain

from tests.test_pipeline.case000_core import (
    build_case000_case,
    load_truth,
    make_case_dir,
)


def test_deterministic_core_e2e_matches_case000_truth(tmp_path):
    truth = load_truth()
    case_dir = make_case_dir(tmp_path)

    result = build_case000_case(case_dir)
    anchors = result["anchors"]
    findings = result["findings"]

    # --- must_not_flag_records: none of the benign/negative records fired ---
    flagged_records = {a.record_number for a in anchors}
    must_not = set(truth["must_not_flag_records"])
    bad = flagged_records & must_not
    assert not bad, f"rule flagged a must-not-flag record: {sorted(bad)}"

    # --- exactly expected_finding_count findings ---
    assert len(anchors) == truth["expected_finding_count"]
    assert len(findings) == truth["expected_finding_count"]

    expected = truth["expected_findings"][0]
    finding = findings[0]

    # --- status / confidence / mitre pinned to the truth fixture ---
    assert finding["status"] == expected["expected_status"]
    assert finding["confidence"] == expected["expected_confidence"]
    assert finding["mitre_attack"] == expected["expected_mitre"]

    # --- dll_path present in iocs.filepath ---
    assert expected["dll_path"] in finding["iocs"]["filepath"]

    # --- parent present in the title (case-insensitive) ---
    assert expected["parent"].lower() in finding["title"].lower()

    # --- source record is the one the truth fixture names ---
    assert anchors[0].record_number == expected["source_record"]

    # --- audit chain must verify after emit()'s writes ---
    ok, reason = verify_chain(str(case_dir))
    assert ok, f"verify_chain failed after emit(): {reason}"
