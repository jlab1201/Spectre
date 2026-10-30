"""Host-delegated report synthesis round-trip and guardrails.

In host mode synthesize_report() defers to the orchestrating agent; the
agent's JSON must come back through ingest_host_report(), which runs the
SAME validators. An agent cannot introduce a fabricated IOC, an out-of-set
MITRE ID, or a verdict contradicting the deterministic class.
"""
from pathlib import Path

from spectre.pipeline.report_synthesize import (
    synthesize_report, ingest_host_report, _merge_report_md, _finalize_report,
)

MANIFEST = {"case_id": "000-host", "artifact_profile": "windows"}


def _findings():
    return [{
        "finding_id": "F-000-001",
        "title": "rundll32 from temp path",
        "status": "INFERRED",
        "confidence": 0.5,
        "mitre_attack": "UNMAPPED",
        "iocs": {"filepath": ["C:\\Temp\\eo.dll"]},
    }]


def test_host_mode_returns_ingestable_bundle(temp_case_dir):
    result = synthesize_report(_findings(), MANIFEST, temp_case_dir,
                               provider_name="host")
    assert result["deferred"] is True
    assert "request" in result
    # Must carry what ingest needs to finalize later — the gap this task closes.
    assert result["ingest"]["case_dir"] == temp_case_dir


def test_ingest_rejects_out_of_set_mitre(temp_case_dir):
    host_json = {
        "executive_summary": "Summary.",
        "threat_narrative": "This behavior matches MITRE technique T9999.001.",
        "verdict": "These are investigative leads.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    result = ingest_host_report(temp_case_dir, host_json)
    assert "T9999.001" not in result["threat_narrative"]
    assert "UNMAPPED" in result["threat_narrative"]
    assert any("invented MITRE technique IDs" in v for v in result["violations"])


def test_ingest_strips_fabricated_ioc(temp_case_dir):
    host_json = {
        "executive_summary": "One observation recorded.",
        "threat_narrative": "The host contacted 203.0.113.99 repeatedly.",
        "verdict": "These are investigative leads.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    result = ingest_host_report(temp_case_dir, host_json)
    assert "203.0.113.99" not in result["threat_narrative"]
    assert any("fabricated IOC" in v for v in result["violations"])


def test_ingest_rejects_contradicting_verdict(temp_case_dir):
    host_json = {
        "executive_summary": "Summary.",
        "threat_narrative": "",
        "verdict": "The attacker compromised this host.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    result = ingest_host_report(temp_case_dir, host_json)
    assert result["verdict"] == ""
    assert any("verdict contradicts deterministic class" in v
               for v in result["violations"])


def test_ingest_reports_host_provenance(temp_case_dir):
    host_json = {
        "executive_summary": "Summary.", "threat_narrative": "",
        "verdict": "Investigative leads only.", "findings_narrative": [],
        "timeline_narrative": "", "methodology_narrative": "",
    }
    result = ingest_host_report(temp_case_dir, host_json)
    assert result["llm_used"] is True
    assert result["api_error"] is None
    # WS7a sub-task 3: ingest_host_report ran through _finalize_report /
    # _validate_report, so this result must self-report as validated.
    assert result["provider"] == "host"
    assert result["validated"] is True


# ── WS7a sub-task 3 (A2-1): report.md must disclose narrative provenance ──
# _merge_report_md's `llm_output` is exactly the dict synthesize_report()/
# ingest_host_report() return, so these tests exercise the real return
# shapes rather than hand-built provenance dicts wherever possible.

def test_report_provenance_deterministic_baseline():
    md = _merge_report_md(None, _findings(), MANIFEST, "/tmp/x", [], {})
    assert "**Narrative Provenance:**" in md
    assert "Deterministic baseline" in md
    assert "no AI narrative" in md


def test_report_provenance_host_validated(temp_case_dir):
    host_json = {
        "executive_summary": "Summary.", "threat_narrative": "",
        "verdict": "Investigative leads only.", "findings_narrative": [],
        "timeline_narrative": "", "methodology_narrative": "",
    }
    llm_output = ingest_host_report(temp_case_dir, host_json)
    md = _merge_report_md(llm_output, _findings(), MANIFEST, temp_case_dir, [], {})
    assert "**Narrative Provenance:**" in md
    assert "host-authored" in md
    assert "validated by in-process guardrails" in md
    assert "NOT validated" not in md


def test_report_provenance_direct_api_validated(temp_case_dir):
    llm_output = _finalize_report(
        {
            "executive_summary": "Summary.", "threat_narrative": "",
            "verdict": "Investigative leads only.", "findings_narrative": [],
            "timeline_narrative": "", "methodology_narrative": "",
        },
        _findings(), {}, ["UNMAPPED"], Path(temp_case_dir), "000-host",
        "anthropic", "claude-x", {"prompt": 0, "completion": 0}, 0,
    )
    md = _merge_report_md(llm_output, _findings(), MANIFEST, temp_case_dir, [], {})
    assert "**Narrative Provenance:**" in md
    assert "provider=anthropic" in md
    assert "validated by in-process guardrails" in md
    assert "host-authored" not in md


def test_report_provenance_unvalidated_host_prose_warns():
    # A non-compliant caller that skips ingest_host_report()/ingest_host_output()
    # entirely and hand-builds an llm_output-shaped dict must NOT render as
    # validated — this is the exact A2-1 scenario the disclosure exists for.
    forged = {
        "executive_summary": "Everything is fine.",
        "threat_narrative": "", "verdict": "", "findings_narrative": [],
        "timeline_narrative": "", "methodology_narrative": "",
    }
    md = _merge_report_md(forged, _findings(), MANIFEST, "/tmp/x", [], {})
    assert "**Narrative Provenance:**" in md
    assert "NOT validated in-process" in md
