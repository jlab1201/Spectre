import json
import yaml
from spectre.pipeline import audit
from spectre.pipeline.report_synthesize import _finalize_report


def _seed_case(tmp_path, ai_narrative, with_validate_row):
    case = tmp_path
    (case / "manifest.yaml").write_text(yaml.safe_dump({"report": {"ai_narrative": ai_narrative}}))
    rows = []
    if with_validate_row:
        rows.append({"phase_step": "S2-validate-report", "action": "note"})
    (case / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(case)


def test_llm_run_without_validation_row_is_flagged(tmp_path):
    case = _seed_case(tmp_path, ai_narrative=True, with_validate_row=False)
    check = audit._narrative_grounding_check(case)
    assert check["passed"] is False


def test_llm_run_with_validation_row_passes(tmp_path):
    case = _seed_case(tmp_path, ai_narrative=True, with_validate_row=True)
    assert audit._narrative_grounding_check(case)["passed"] is True


def test_baseline_run_is_not_flagged(tmp_path):
    case = _seed_case(tmp_path, ai_narrative=False, with_validate_row=False)
    assert audit._narrative_grounding_check(case)["passed"] is True


def test_clean_validated_run_is_not_flagged(tmp_path):
    """Integration test — this is the gap that let the CRITICAL ship: the
    3 unit tests above hand-seed audit.jsonl, so they never exercised the
    real `_finalize_report` write path. `_finalize_report` writes an
    S2-validate-report row ONLY inside `for v in violations:` (per-violation
    detail rows) — a CLEAN run with zero violations (the intended success
    case for a well-behaved API-provider narrative) used to write NO
    S2-validate-report row at all, so `_narrative_grounding_check` would flag
    every clean run as if the validator had been bypassed. Drives a real
    `_finalize_report` call with a well-formed narrative that produces zero
    violations, then asserts the drift check still passes.
    """
    case_dir = tmp_path
    (case_dir / "manifest.yaml").write_text(
        yaml.safe_dump({"report": {"ai_narrative": True}})
    )

    findings = [
        {
            "finding_id": "F-TEST-001",
            "status": "CONFIRMED",  # vclass "confirmed" — Validator 11 doesn't
                                    # constrain verdict language for this class
            "confidence": 1.0,
            "mitre_attack": "UNMAPPED",
            "iocs": {},
        }
    ]
    parsed = {
        "executive_summary": "Analysis of F-TEST-001 is complete.",
        "threat_narrative": "The evidence for F-TEST-001 supports a confirmed assessment.",
        "verdict": "The evidence confirms activity related to F-TEST-001.",
        "findings_narrative": [
            {"finding_id": "F-TEST-001", "narrative": "F-TEST-001 activity was observed on the host."}
        ],
        "timeline_narrative": "F-TEST-001 occurred during the observed window.",
        "methodology_narrative": "Standard deterministic analysis was applied to F-TEST-001.",
    }

    result = _finalize_report(
        parsed, findings, {}, [],
        case_dir, "test-case", "anthropic", "test-model",
        {"prompt": 0, "completion": 0}, 0,
    )
    # Sanity check: this narrative really is clean — zero violations. If this
    # ever fails, the test needs a new narrative, not a loosened assertion.
    assert result["violations"] == []

    check = audit._narrative_grounding_check(str(case_dir))
    assert check["passed"] is True

    full = audit.verify_full(str(case_dir))
    assert full["checks"]["narrative_grounding"]["passed"] is True
