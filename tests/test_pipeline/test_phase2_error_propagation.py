"""A10 Finding 3 tail: Phase 2's returned dict never carried a top-level
"error" key when extraction produced zero handles, so runner.py's
`FAILED: {result.get('error', 'unknown')}` printed the literal string
"unknown" -- no tool name, no evidence file, nothing actionable.

_run_phase_2_live must now populate a descriptive "error" whenever
len(all_handles) == 0, summarizing which evidence file(s) failed and why.
"""

from tests.test_pipeline.custody_helpers import chain_triage
from spectre.pipeline import phase_runner
from spectre.core.base import AnalyzerModule


def _make_failing_module(exc_text: str):
    def extract(case_dir, evidence_path):
        raise FileNotFoundError(exc_text)

    return AnalyzerModule(
        name="pcap", artifact_type="pcap_conn", required_tools=[],
        recognizers=[], extract=extract, normalize=lambda h: [], rules=[],
    )


def test_phase2_error_populated_when_all_extraction_fails(tmp_path, monkeypatch):
    case_dir = tmp_path / "004-forced-fail"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    module = _make_failing_module("[Errno 2] No such file or directory: 'tcpdump'")
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": module})

    manifest = {
        "case_id": "004", "case_name": "forcedfail", "artifact_profile": "auto",
        "canary_status": "DEGRADED", "direction": "", "focus": False,
        "evidence": [], "artifacts": ["pcap_conn"],
        "triage": {
            "evidence/case.pcap": {
                "status": "RECOGNIZED", "module": "pcap",
                "artifact_type": "pcap_conn",
            }
        },
    }

    chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
    result = phase_runner._run_phase_2_live(str(case_dir), manifest)

    assert result["success"] is False
    assert result["handles"] == 0
    assert "error" in result, "runner.py falls back to the literal string 'unknown' without this"
    assert result["error"] != "unknown"
    assert "case.pcap" in result["error"]
    assert "tcpdump" in result["error"]
    assert "1/1" in result["error"]


def test_phase2_error_names_extractor_pending_reason(tmp_path, monkeypatch):
    """Real-world degraded scenario (discovered while verifying A10 Finding
    3 end-to-end): PCAP_MODULE.required_tools=["tcpdump"] means recognize.py
    marks evidence EXTRACTOR_PENDING -- never even calling module.extract()
    -- whenever tcpdump is absent, regardless of Zeek's availability. That
    path never populates an "error" entry in extraction_results (it's a
    "skipped" entry), so it must still produce an honest, non-'unknown'
    top-level error naming what happened -- not just the generic
    no-evidence-recognized fallback."""
    case_dir = tmp_path / "006-pending"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(phase_runner, "_modules", lambda: {})  # pcap not in modules dict either way

    manifest = {
        "case_id": "006", "case_name": "pending", "artifact_profile": "auto",
        "canary_status": "DEGRADED", "direction": "", "focus": False,
        "evidence": [], "artifacts": ["pcap_conn"],
        "triage": {
            "evidence/case.pcap": {
                "status": "EXTRACTOR_PENDING", "module": "pcap",
                "artifact_type": "pcap_conn", "tool": "tcpdump",
            }
        },
    }

    chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
    result = phase_runner._run_phase_2_live(str(case_dir), manifest)

    assert result["success"] is False
    assert "error" in result
    assert result["error"] != "unknown"
    assert "case.pcap" in result["error"]
    assert "tcpdump" in result["error"]


def test_phase2_error_absent_on_success(tmp_path, monkeypatch):
    """Sanity: a normal successful run must not gain a spurious 'error' key."""
    case_dir = tmp_path / "005-ok"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    conn_path = case_dir / "raw_extract" / "conn.txt"
    conn_path.write_text("2026-01-01 00:00:00.1 IP 10.0.0.5.1 > 9.9.9.9.80: tcp 0\n")

    def extract(case_dir_arg, evidence_path):
        return [{
            "evidence_path": evidence_path, "path": str(conn_path),
            "artifact_type": "pcap_conn", "extract_pass": "connections",
            "tool": "tcpdump", "tool_version": "tcpdump",
            "line_count": 1, "size_bytes": conn_path.stat().st_size,
            "empty_data_status": "DATA_PRESENT",
        }]

    module = AnalyzerModule(
        name="pcap", artifact_type="pcap_conn", required_tools=[],
        recognizers=[], extract=extract, normalize=lambda h: [], rules=[],
    )
    monkeypatch.setattr(phase_runner, "_modules", lambda: {"pcap": module})

    manifest = {
        "case_id": "005", "case_name": "ok", "artifact_profile": "auto",
        "canary_status": "FULL", "direction": "", "focus": False,
        "evidence": [], "artifacts": ["pcap_conn"],
        "triage": {
            "evidence/case.pcap": {
                "status": "RECOGNIZED", "module": "pcap",
                "artifact_type": "pcap_conn",
            }
        },
    }

    chain_triage(case_dir, manifest)  # W3: Phase 2 extracts registered evidence only
    result = phase_runner._run_phase_2_live(str(case_dir), manifest)
    assert result["success"] is True
    assert "error" not in result
