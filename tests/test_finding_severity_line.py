"""TB-port T9: a deterministic per-finding **Severity:** line in Detailed
Findings (rule-assessed, or UNRATED — never derived from confidence), and
severity-then-confidence ordering within the CONFIRMED-first grouping."""
from __future__ import annotations

import pytest
import yaml

from spectre.pipeline.report_synthesize import (
    _append_finding_evidence_block,
    _merge_report_md,
)
from tests.test_dashboard_metrics import (
    _findings,
    _manifest,
    _write_ruleset,
)


@pytest.fixture()
def case_dir(tmp_path):
    _write_ruleset(tmp_path)
    (tmp_path / "reports").mkdir()
    return tmp_path


def _detailed(md: str) -> str:
    i = md.index("### Detailed Findings")
    return md[i:md.index("## 2. MITRE ATT&CK Map")]


def test_severity_line_rule_assessed_and_unrated(case_dir):
    md = _merge_report_md(None, _findings(), _manifest(), str(case_dir), [], {})
    d = _detailed(md)
    assert "**Severity:** CRITICAL (rule-assessed)" in d
    assert "**Severity:** UNRATED (detection rule sets no severity level)" in d


def test_severity_line_absent_without_resolved_severity():
    lines: list[str] = []
    _append_finding_evidence_block(lines, _findings()[0], {})
    assert not any(ln.startswith("**Severity:**") for ln in lines)


def test_severity_line_follows_status_line():
    lines: list[str] = []
    _append_finding_evidence_block(lines, _findings()[0], {}, severity="HIGH")
    i = next(n for n, ln in enumerate(lines) if ln.startswith("**Status:**"))
    assert lines[i + 1] == "**Severity:** HIGH (rule-assessed)"


def _rules(case_dir, mapping):
    (case_dir / "ruleset.yaml").write_text(yaml.safe_dump(
        {"rules": [{"rule_id": r, "severity": s} for r, s in mapping.items()]}))


def test_group_representative_is_most_severe(case_dir):
    fs = [
        {"finding_id": f"F-1-00{i}", "title": f"Beacon: host{i}", "status": "INFERRED",
         "confidence": c, "mitre_attack": "T1071.001",
         "event_time": f"2026-01-01T1{i}:00:00Z"}
        for i, c in ((1, 0.9), (2, 0.4), (3, 0.5))
    ]
    man = {"detection": {"findings": [
        {"finding_id": "F-1-001", "rule_id": "r-low"},
        {"finding_id": "F-1-002", "rule_id": "r-crit"},
        {"finding_id": "F-1-003", "rule_id": "r-high"},
    ]}}
    _rules(case_dir, {"r-low": "low", "r-crit": "critical", "r-high": "high"})
    d = _detailed(_merge_report_md(None, fs, man, str(case_dir), [], {}))
    # the CRITICAL finding represents the group even though its confidence
    # is the lowest — severity and confidence are separate axes.
    assert "**Representative finding — F-1-002:**" in d
    assert d.index("F-1-003") < d.index("F-1-001", d.index("Additional findings"))


def test_groups_confirmed_first_then_severity(case_dir):
    fs = [
        {"finding_id": "F-2-001", "title": "Low thing", "status": "INFERRED",
         "confidence": 0.9, "mitre_attack": "T1046"},
        {"finding_id": "F-2-002", "title": "Critical thing", "status": "INFERRED",
         "confidence": 0.3, "mitre_attack": "T1190"},
        {"finding_id": "F-2-003", "title": "Confirmed low", "status": "CONFIRMED",
         "confidence": 0.7, "mitre_attack": "T1047"},
    ]
    man = {"detection": {"findings": [
        {"finding_id": "F-2-001", "rule_id": "r-low"},
        {"finding_id": "F-2-002", "rule_id": "r-crit"},
        {"finding_id": "F-2-003", "rule_id": "r-low"},
    ]}}
    _rules(case_dir, {"r-low": "low", "r-crit": "critical"})
    d = _detailed(_merge_report_md(None, fs, man, str(case_dir), [], {}))
    assert d.index("#### F-2-003") < d.index("#### F-2-002") < d.index("#### F-2-001")
