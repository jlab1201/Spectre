"""verify.py — pass/fail oracle for the case-000 deterministic-core spike.

Rewritten as real pytest. The previous version was script-style code that
referenced undefined names (`base`, `sys`), globbed a stale finding-name
format (`F-SPECTRE-*.yaml` -- current format is `F-{case_id}-{NNN}.yaml`,
see core/emit_finding.py `_finding_filename`), and collected ZERO pytest
items.

Checks pinned here (from the original module docstring, scoped to what the
deterministic core alone can prove -- the adversarial-review check and the
report.md check in the old docstring both require the LLM explain() seam
and are out of scope for this oracle):
  1. finding count == expected_finding_count
  2. no finding maps to must_not_flag_records
  3. status / confidence / mitre match the oracle
  4. evidence_refs[0].execution_id resolves to a real audit row
  5. audit.verify_chain() == True
  6. dll_path and parent match the oracle
  + a tamper sub-test: byte-flip a middle audit row -> verify_chain() must
    flip to False. This pins the chain check WS1 will extend.
"""

import json

import pytest

from tests.test_pipeline.case000_core import (
    build_case000_case,
    load_truth,
    make_case_dir,
    verify_chain,
)


@pytest.fixture(scope="module")
def case000(tmp_path_factory):
    """Build the case-000 finding once and share it across the checks below
    -- these are independent assertions over the same deterministic build,
    not independent builds."""
    base_dir = tmp_path_factory.mktemp("case000-verify")
    case_dir = make_case_dir(base_dir)
    result = build_case000_case(case_dir)
    result["truth"] = load_truth()
    return result


def _audit_rows(case_dir) -> list[dict]:
    audit_path = case_dir / "audit.jsonl"
    rows = []
    with open(audit_path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ── Check 1: finding count ──────────────────────────────────────────────
def test_check1_finding_count(case000):
    truth = case000["truth"]
    assert len(case000["findings"]) == truth["expected_finding_count"]


# ── Check 2: no must_not_flag_records were flagged ──────────────────────
def test_check2_must_not_flag_records(case000):
    truth = case000["truth"]
    must_not = set(truth["must_not_flag_records"])
    flagged = {a.record_number for a in case000["anchors"]}
    bad = flagged & must_not
    assert not bad, f"must-not-flag record(s) flagged: {sorted(bad)}"


# ── Check 3: status / confidence / mitre match the oracle ───────────────
def test_check3_status_confidence_mitre(case000):
    truth = case000["truth"]
    expected = truth["expected_findings"][0]
    finding = case000["findings"][0]

    assert finding["status"] == expected["expected_status"]
    assert finding["confidence"] == expected["expected_confidence"]
    assert finding["mitre_attack"] == expected["expected_mitre"]


# ── Check 4: evidence_refs execution_id resolves to a real audit row ────
def test_check4_evidence_refs_resolve_to_audit_row(case000):
    finding = case000["findings"][0]
    refs = finding.get("evidence_refs", [])
    assert refs, "finding has no evidence_refs"

    execution_id = refs[0]["execution_id"]
    rows = _audit_rows(case000["case_dir"])
    matches = [r for r in rows if r.get("entry_sha256") == execution_id]
    assert matches, f"execution_id {execution_id[:16]}... does not resolve to any audit row"
    assert matches[0]["action"] == "tool_exec"


# ── Check 5: audit.verify_chain() == True ────────────────────────────────
def test_check5_verify_chain_true(case000):
    ok, reason = verify_chain(str(case000["case_dir"]))
    assert ok, f"verify_chain() failed: {reason}"


# ── Check 6: dll_path and parent match the oracle ────────────────────────
def test_check6_dll_path_and_parent(case000):
    truth = case000["truth"]
    expected = truth["expected_findings"][0]
    finding = case000["findings"][0]

    assert expected["dll_path"] in finding["iocs"]["filepath"]
    assert expected["parent"].lower() in finding["title"].lower()


# ── Tamper sub-test: byte-flip a middle row -> verify_chain() flips False ─
def test_tamper_breaks_verify_chain(case000, tmp_path):
    case_dir = case000["case_dir"]
    src_audit = case_dir / "audit.jsonl"
    lines = src_audit.read_text().splitlines()
    assert len(lines) >= 2, "need at least 2 audit rows to tamper a middle one"

    # Sanity: the untouched chain verifies before we mutate a copy of it.
    ok_before, _ = verify_chain(str(case_dir))
    assert ok_before is True

    mid = len(lines) // 2
    row = json.loads(lines[mid])
    row["exact_command"] = "TAMPERED_BY_test_tamper_breaks_verify_chain"
    lines[mid] = json.dumps(row)

    tampered_dir = tmp_path / "tampered-copy"
    tampered_dir.mkdir()
    (tampered_dir / "audit.jsonl").write_text("\n".join(lines) + "\n")

    ok_after, reason = verify_chain(str(tampered_dir))
    assert ok_after is False, "verify_chain() did not detect the tampered row"
    assert reason  # a reason string must accompany the failure
