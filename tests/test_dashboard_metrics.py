"""TB-port T5: synthetic-validation tests for the deterministic dashboard metric helper
(spec §6, §9) and the PDF dashboard renderer (spec §5).

The fixture spans critical→low severities, BOTH CONFIRMED and INFERRED
statuses, and ≥6 distinct tactics/rules — the spec-mandated shape so the
dashboard is exercised on real data, not a collapsed 1-finding smoke case.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from spectre.pipeline.report_synthesize import (
    _dashboard_metrics,
    _persist_dashboard_metrics,
    _merge_report_md,
    _load_mitre_tactics,
)

# ── Technique IDs chosen to map to distinct ATT&CK tactics (verified against
# mitre_techniques.yaml) so tactic_coverage / kill_chain are non-trivial. ──
_T_RECON = "T1595.001"       # Reconnaissance         (rank 0)
_T_INITIAL = "T1190"         # Initial Access         (rank 2)
_T_EXEC = "T1047"            # Execution              (rank 3)
_T_PERSIST = "T1133"         # Persistence            (rank 4)
_T_CRED = "T1003.001"        # Credential Access      (rank 7)
_T_DISCOVERY = "T1046"       # Discovery              (rank 8)
_T_C2 = "T1071.001"          # Command and Control    (rank 11)
_T_EXFIL = "T1041"           # Exfiltration           (rank 12)


def _findings() -> list[dict]:
    """8 hand-built findings: critical/high/medium/low/unrated severities,
    both statuses, 8 distinct rules mapping to 8 distinct tactics."""
    return [
        {"finding_id": "F-900-001", "title": "Public-facing exploit — initial access",
         "status": "CONFIRMED", "confidence": 0.95, "mitre_attack": _T_INITIAL,
         "event_time": "2026-01-01T10:00:00Z"},
        {"finding_id": "F-900-002", "title": "HTTP C2 beacon to external host",
         "status": "CONFIRMED", "confidence": 0.90, "mitre_attack": _T_C2,
         "event_time": "2026-01-01T12:00:00Z"},
        {"finding_id": "F-900-003", "title": "Large outbound transfer (possible exfil)",
         "status": "INFERRED", "confidence": 0.55, "mitre_attack": _T_EXFIL,
         "event_time": "2026-01-01T13:00:00Z"},
        {"finding_id": "F-900-004", "title": "WMI process execution",
         "status": "CONFIRMED", "confidence": 0.70, "mitre_attack": _T_EXEC,
         "event_time": "2026-01-01T11:00:00Z"},
        {"finding_id": "F-900-005", "title": "External remote-service persistence",
         "status": "INFERRED", "confidence": 0.40, "mitre_attack": _T_PERSIST,
         "event_time": "2026-01-01T14:00:00Z"},
        {"finding_id": "F-900-006", "title": "Active scanning against the host",
         "status": "INFERRED", "confidence": 0.30, "mitre_attack": _T_RECON,
         "event_time": "2026-01-01T09:00:00Z"},
        {"finding_id": "F-900-007", "title": "LSASS credential access",
         "status": "CONFIRMED", "confidence": 0.65, "mitre_attack": _T_CRED,
         "event_time": "2026-01-01T10:30:00Z"},
        {"finding_id": "F-900-008", "title": "Network service discovery",
         "status": "INFERRED", "confidence": 0.50, "mitre_attack": _T_DISCOVERY,
         "event_time": "2026-01-01T10:15:00Z"},
    ]


# finding_id → rule_id (the provenance _finding_rule_ids recovers from the
# manifest's detection block, as a real case does).
_RULE_BY_FINDING = {
    "F-900-001": "r-critical",
    "F-900-002": "r-high",
    "F-900-003": "r-high2",
    "F-900-004": "r-medium",
    "F-900-005": "r-medium2",
    "F-900-006": "r-low",
    "F-900-007": "r-unrated",     # severity: null in the snapshot → UNRATED
    "F-900-008": "r-missing",     # absent from the snapshot        → UNRATED
}

# rule_id → severity, matching the §7.2 ruleset.yaml contract (str | null).
_RULESET_SEVERITY = {
    "r-critical": "critical",
    "r-high": "high",
    "r-high2": "high",
    "r-medium": "medium",
    "r-medium2": "medium",
    "r-low": "low",
    "r-unrated": None,            # explicit null — "author set no level"
    # r-missing deliberately absent.
}


def _manifest() -> dict:
    return {
        "case_id": "900",
        "case_name": "synthetic",
        "artifact_profile": "fixture-test",
        "canary_status": "FULL",
        "evidence": [
            {"evidence_path": "/ev/capture.pcap", "sha256": "a" * 64},
            {"evidence_path": "/ev/memory.raw", "sha256": "b" * 64},
        ],
        "detection": {
            "findings": [
                {"finding_id": fid, "rule_id": rid,
                 "status": next(f["status"] for f in _findings() if f["finding_id"] == fid)}
                for fid, rid in _RULE_BY_FINDING.items()
            ],
        },
    }


def _write_ruleset(case_dir: Path) -> None:
    """Write the case-local ruleset.yaml snapshot matching build_ruleset_snapshot's
    shape: a top-level `rules:` list, each entry with rule_id + severity."""
    rules = [{"rule_id": rid, "severity": sev} for rid, sev in _RULESET_SEVERITY.items()]
    (case_dir / "ruleset.yaml").write_text(yaml.safe_dump({"rules": rules}))


@pytest.fixture()
def case_dir(tmp_path) -> Path:
    _write_ruleset(tmp_path)
    (tmp_path / "reports").mkdir()
    return tmp_path


# ══════════════════════════════════════════════════════════════════════
# Metric fidelity
# ══════════════════════════════════════════════════════════════════════
def test_severity_split_sums_to_totals(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    k = m["kpis"]
    rows = m["severity_counts"]
    assert sum(r["total"] for r in rows) == k["findings_total"] == 8
    assert sum(r["confirmed"] for r in rows) == k["confirmed"]
    assert sum(r["inferred"] for r in rows) == k["inferred"]
    # every row: confirmed + inferred == total (only two statuses in play)
    for r in rows:
        assert r["confirmed"] + r["inferred"] == r["total"]


def test_kpi_status_counts(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    k = m["kpis"]
    assert k["confirmed"] == 4    # 001,002,004,007
    assert k["inferred"] == 4     # 003,005,006,008
    assert k["evidence_items"] == 2


def test_mitre_techniques_equals_distinct_ids(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    distinct = {f["mitre_attack"] for f in _findings()}
    assert m["kpis"]["mitre_techniques"] == len(distinct) == 8


def test_tactic_coverage_counts_match(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    cov = {t["tactic"]: t["technique_count"] for t in m["tactic_coverage"]}
    tactics_map = _load_mitre_tactics()
    # every finding's technique maps to exactly one tactic here → 8 tactics, count 1
    expected = {}
    for f in _findings():
        expected[tactics_map[f["mitre_attack"]]] = expected.get(
            tactics_map[f["mitre_attack"]], 0) + 1
    assert cov == expected
    assert len(cov) >= 6
    # tactic_coverage is ordered by ATT&CK kill-chain rank
    ranks = [t["rank"] for t in m["tactic_coverage"]]
    assert ranks == sorted(ranks)


def test_kill_chain_first_seen_is_min_event_time(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    tactics_map = _load_mitre_tactics()
    # expected min event_time per tactic
    expected: dict[str, str] = {}
    for f in _findings():
        tac = tactics_map[f["mitre_attack"]]
        ev = f["event_time"]
        if tac not in expected or ev < expected[tac]:
            expected[tac] = ev
    got = {n["tactic"]: n["first_seen"] for n in m["kill_chain"]}
    assert got == expected
    # Reconnaissance's finding (09:00) is the earliest overall
    assert got["Reconnaissance"] == "2026-01-01T09:00:00Z"


def test_threat_headline_highest_severity_then_confidence(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    # F-900-001 is the only CRITICAL → wins regardless of others' confidence
    # A1: the headline title is qualified by status/corroboration.
    assert m["headline"]["title"] == "Public-facing exploit — initial access"
    assert m["threat_headline"].endswith(": Public-facing exploit — initial access")
    assert m["headline"]["severity"] == "CRITICAL"
    assert m["top_severity"] == "CRITICAL"


def test_threat_headline_confidence_tiebreak(case_dir):
    # Two HIGH findings, no critical → the higher-confidence one wins.
    findings = [
        {"finding_id": "F-1-001", "title": "high but less sure",
         "status": "INFERRED", "confidence": 0.50, "mitre_attack": _T_C2},
        {"finding_id": "F-1-002", "title": "high and more sure",
         "status": "CONFIRMED", "confidence": 0.95, "mitre_attack": _T_EXFIL},
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1-001", "rule_id": "r-high"},
        {"finding_id": "F-1-002", "rule_id": "r-high2"},
    ]}}
    m = _dashboard_metrics(findings, manifest, str(case_dir))
    assert m["top_severity"] == "HIGH"
    assert m["headline"]["title"] == "high and more sure"


# ══════════════════════════════════════════════════════════════════════
# Severity resolution (spec §6, §9)
# ══════════════════════════════════════════════════════════════════════
def test_ruleset_value_wins(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    by_sev = {r["severity"]: r for r in m["severity_counts"]}
    assert by_sev["CRITICAL"]["total"] == 1
    assert by_sev["HIGH"]["total"] == 2
    assert by_sev["MEDIUM"]["total"] == 2
    assert by_sev["LOW"]["total"] == 1
    # r-unrated (null) + r-missing (absent) → UNRATED
    assert by_sev["UNRATED"]["total"] == 2


def test_null_absent_unresolved_all_map_to_unrated(case_dir):
    findings = [
        {"finding_id": "F-2-001", "title": "null severity", "status": "CONFIRMED",
         "confidence": 0.9, "mitre_attack": _T_C2},          # r-unrated → null
        {"finding_id": "F-2-002", "title": "rule not in snapshot", "status": "INFERRED",
         "confidence": 0.9, "mitre_attack": _T_EXFIL},        # r-missing → absent
        {"finding_id": "F-2-003", "title": "no rule_id at all", "status": "INFERRED",
         "confidence": 0.9, "mitre_attack": _T_EXEC},         # unresolved rule
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-2-001", "rule_id": "r-unrated"},
        {"finding_id": "F-2-002", "rule_id": "r-missing"},
        # F-2-003 has no rule_id record at all
    ]}}
    m = _dashboard_metrics(findings, manifest, str(case_dir))
    assert [r["severity"] for r in m["severity_counts"]] == ["UNRATED"]
    assert m["severity_counts"][0]["total"] == 3
    assert m["top_severity"] == "UNRATED"


def test_missing_ruleset_file_everything_unrated(tmp_path):
    # No ruleset.yaml written → snapshot absent → all UNRATED.
    m = _dashboard_metrics(_findings(), _manifest(), str(tmp_path))
    assert [r["severity"] for r in m["severity_counts"]] == ["UNRATED"]
    assert m["severity_counts"][0]["total"] == 8


def test_confidence_never_used_for_severity(case_dir):
    # A high-confidence finding with a null-severity rule stays UNRATED;
    # a low-confidence finding with a critical rule stays CRITICAL.
    findings = [
        {"finding_id": "F-3-001", "title": "sure but unrated", "status": "CONFIRMED",
         "confidence": 0.99, "mitre_attack": _T_C2},          # r-unrated (null)
        {"finding_id": "F-3-002", "title": "unsure but critical", "status": "INFERRED",
         "confidence": 0.01, "mitre_attack": _T_INITIAL},     # r-critical
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-3-001", "rule_id": "r-unrated"},
        {"finding_id": "F-3-002", "rule_id": "r-critical"},
    ]}}
    m = _dashboard_metrics(findings, manifest, str(case_dir))
    by_sev = {r["severity"]: r for r in m["severity_counts"]}
    assert "CRITICAL" in by_sev and by_sev["CRITICAL"]["total"] == 1
    assert "UNRATED" in by_sev and by_sev["UNRATED"]["total"] == 1
    # confidence 0.99 did NOT upgrade the unrated finding
    assert "HIGH" not in by_sev


# ══════════════════════════════════════════════════════════════════════
# Persistence — one computation, both consumers read it (spec §6)
# ══════════════════════════════════════════════════════════════════════
def test_persist_writes_manifest(case_dir):
    manifest = _manifest()
    metrics = _persist_dashboard_metrics(_findings(), manifest, str(case_dir))
    assert manifest["report"]["dashboard_metrics"] is metrics
    # persisted dict equals a fresh computation
    assert manifest["report"]["dashboard_metrics"] == _dashboard_metrics(
        _findings(), _manifest(), str(case_dir))


def test_merge_report_md_persists_and_prose_reads_it(case_dir):
    manifest = _manifest()
    report_md = _merge_report_md(None, _findings(), manifest, str(case_dir), [], {})
    metrics = manifest["report"]["dashboard_metrics"]
    assert metrics["kpis"]["findings_total"] == 8
    # The prose states counts sourced from the SAME persisted dict.
    assert "**8 indicators**" in report_md
    # confirmed count (4) appears in the CONFIRMED-status sentence
    assert f"{metrics['kpis']['confirmed']} observation(s) have CONFIRMED status" in report_md


# ══════════════════════════════════════════════════════════════════════
# PDF render (spec §5, §9)
# ══════════════════════════════════════════════════════════════════════
def _report_md(case_dir: Path) -> Path:
    manifest = _manifest()
    md = _merge_report_md(None, _findings(), manifest, str(case_dir), [], {})
    p = case_dir / "reports" / "report.md"
    p.write_text(md)
    return p




# ══════════════════════════════════════════════════════════════════════
# Honesty amendments (TB-PORT A1/A3/A4/A6) — the current design's
# guarantees win over the TB version.
# ══════════════════════════════════════════════════════════════════════
import hashlib  # noqa: E402
import json  # noqa: E402

from spectre.pipeline.report_synthesize import (  # noqa: E402
    _confidence_label,
    _coverage_counts,
    _dashboard_metrics_sha256,
    _finding_rule_ids,
    _overall_confidence_banner,
    verdict_class,
)


def _leads_only():
    return [dict(f, status="INFERRED") for f in _findings()]


def test_a1_metrics_carry_verdict_class(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    assert m["verdict_class"] == verdict_class(_findings(), _manifest()) == "mixed"


def test_a1_leads_only_headline_is_qualified(case_dir):
    fs = _leads_only()
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    assert m["verdict_class"] == "leads_only"
    h = m["headline"]
    assert h["finding_id"] == "F-900-001"
    assert h["status"] == "INFERRED"
    assert h["corroboration"] == "single-source"
    assert h["qualifier"].startswith("Lead (INFERRED, single-source)")
    # the plain title is never presented bare on a leads-only case
    assert m["threat_headline"].startswith("Lead (INFERRED, single-source): ")
    assert m["threat_headline"].endswith("Public-facing exploit — initial access")


def test_a1_confirmed_lead_still_states_status(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    h = m["headline"]
    assert h["status"] == "CONFIRMED"
    # corroboration axis comes from _is_cross_validated, never from status
    assert h["corroboration"] == "single-source"
    assert "CONFIRMED" in m["threat_headline"]


def test_a1_corroboration_axis_uses_cross_validated(case_dir):
    fs = _findings()
    fs[0]["cross_validated"] = True
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    assert m["headline"]["corroboration"] == "multi-source corroborated"
    assert m["kpis"]["corroborated"] == 1


def test_a1_context_findings_never_headline(case_dir):
    fs = [
        {"finding_id": "F-4-001", "title": "Host identity: WS01",
         "status": "CONFIRMED", "confidence": 0.99, "mitre_attack": "UNMAPPED",
         "rule_id": "pcap-host-identity"},
        {"finding_id": "F-4-002", "title": "real detection",
         "status": "INFERRED", "confidence": 0.5, "mitre_attack": _T_C2},
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-4-001", "rule_id": "pcap-host-identity"},
        {"finding_id": "F-4-002", "rule_id": "r-unrated"},
    ]}}
    m = _dashboard_metrics(fs, manifest, str(case_dir))
    assert m["headline"]["finding_id"] == "F-4-002"


def test_w4b_confidence_labels_reuse_existing_predicates(case_dir):
    fs, man = _findings(), _manifest()
    m = _dashboard_metrics(fs, man, str(case_dir))
    rids = _finding_rule_ids(fs, man)
    assert m["confidence_label"] == _confidence_label(fs, rids)
    assert m["confidence_banner"] == _overall_confidence_banner(fs, rids)


def _extraction(*states):
    res = {}
    for i, st in enumerate(states):
        rec = {"module": "evtx", "extraction_status": st, "events": 0 if st in (
            "EMPTY", "EXTRACTION_FAILED") else 10}
        res[f"/ev/item{i}"] = rec
    return {"results": res}


def test_a3_no_coverage_state(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("EMPTY", "EXTRACTION_FAILED")
    m = _dashboard_metrics([], man, str(case_dir))
    assert m["verdict_class"] == "no_coverage"
    cov = m["coverage"]
    assert (cov["examined"], cov["total"]) == _coverage_counts(man) == (0, 2)
    assert cov["state"] == "no_coverage"
    assert cov["empty"] == 1 and cov["failed"] == 1
    assert "No evidence was examined" in cov["sentence"]


def test_a3_partial_and_full_coverage_states(case_dir):
    man = _manifest()
    man["extraction"] = _extraction("SUCCESS", "EMPTY")
    m = _dashboard_metrics(_findings(), man, str(case_dir))
    assert m["coverage"]["state"] == "partial"
    assert (m["coverage"]["examined"], m["coverage"]["total"]) == (1, 2)
    man["extraction"] = _extraction("SUCCESS", "PARTIAL")
    m = _dashboard_metrics(_findings(), man, str(case_dir))
    assert m["coverage"]["state"] == "full"


def test_a3_nothing_registered_is_not_called_full(case_dir):
    m = _dashboard_metrics([], _manifest(), str(case_dir))
    assert m["coverage"]["state"] == "not_recorded"
    assert m["verdict_class"] == "none"


def test_a4_first_seen_is_utc_normalised(case_dir):
    fs = [{"finding_id": "F-5-001", "title": "t", "status": "INFERRED",
           "confidence": 0.5, "mitre_attack": _T_C2,
           "event_time": "2026-01-01T12:00:00+02:00"},
          {"finding_id": "F-5-002", "title": "t2", "status": "INFERRED",
           "confidence": 0.5, "mitre_attack": _T_C2,
           "event_time": "2026-01-01T11:00:00Z"}]
    m = _dashboard_metrics(fs, {}, str(case_dir))
    (node,) = m["kill_chain"]
    # 12:00+02:00 == 10:00Z is the earlier of the two
    assert node["first_seen"] == "2026-01-01T10:00:00Z"
    assert m["kill_chain_basis"] == "attck_order"


def test_a6_provenance_and_sha256(case_dir):
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    assert m["provenance"].startswith("Deterministic")
    assert "no AI input" in m["provenance"]
    expect = hashlib.sha256(
        json.dumps(m, sort_keys=True).encode("utf-8")).hexdigest()
    assert _dashboard_metrics_sha256(m) == expect


def test_metrics_are_yaml_round_trippable(case_dir):
    """The manifest is YAML; the hash must survive a save/load cycle."""
    m = _dashboard_metrics(_findings(), _manifest(), str(case_dir))
    back = yaml.safe_load(yaml.safe_dump(m))
    assert back == m
    assert _dashboard_metrics_sha256(back) == _dashboard_metrics_sha256(m)


def test_mitre_map_intro_points_at_detailed_findings(case_dir):
    md = _merge_report_md(None, _findings(), _manifest(), str(case_dir), [], {})
    i = md.index("## 2. MITRE ATT&CK Map")
    assert md.index("### Detailed Findings") < i
    assert "_Techniques are mapped to findings by ID" in md[i:i + 300]


def test_inferred_single_source_and_finding_severity(case_dir):
    fs = _findings()
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    assert m["kpis"]["inferred_single_source"] == m["kpis"]["inferred"] == 4
    assert m["finding_severity"]["F-900-001"] == "CRITICAL"
    assert m["finding_severity"]["F-900-008"] == "UNRATED"
    fs[2]["cross_validated"] = True   # INFERRED yet corroborated
    m = _dashboard_metrics(fs, _manifest(), str(case_dir))
    assert m["kpis"]["inferred_single_source"] == 3
