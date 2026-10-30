"""
test_explain_host.py — host-delegated explanation round-trip and guardrails.

In host mode explain() defers to the orchestrating agent; the agent's JSON is
fed back through ingest_host_output(), which runs the SAME validators. These
tests prove the guardrails hold regardless of who produced the text — an agent
cannot introduce a finding, an out-of-set MITRE ID, or a fabricated caveat.
"""
import os

import yaml

from spectre.core import explain as explain_mod
from spectre.config import FK_WINDOWS_DIR, MITRE_MAP_PATH

FK_YAML = str(FK_WINDOWS_DIR / "evtx_4688.yaml")
MITRE_MAP = str(MITRE_MAP_PATH)


def _write_finding(case_dir, finding_id="F-000-001"):
    finding = {
        "finding_id": finding_id,
        "title": "rundll32 launched from a temp path",
        "status": "REVIEW",
        "confidence": 0.5,
        "mitre_attack": "T1218.011",
        "iocs": {"filepath": ["C:\\Temp\\eo.dll"]},
        "evidence_refs": [{"execution_id": "exec-1"}],
    }
    path = f"{case_dir}/findings/{finding_id}.yaml"
    with open(path, "w") as f:
        yaml.dump(finding, f, sort_keys=False)
    # Deterministic registration row — persist requires it (W2-A round 2).
    import hashlib
    from spectre.pipeline.audit import append as audit_append
    audit_append(case_dir, {
        "actor": "deterministic-core", "action": "finding_create",
        "phase_step": "S1-emit", "phase": 3, "finding_id": finding_id,
        "params": {"finding_id": finding_id, "rule_id": "rundll32-from-temp"},
        "output_path": path,
        "output_sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
    })
    return path


def test_explain_host_mode_returns_deferred_bundle(temp_case_dir):
    finding_path = _write_finding(temp_case_dir)
    result = explain_mod.explain(
        finding_path, FK_YAML, MITRE_MAP, temp_case_dir, provider_name="host"
    )
    assert result["deferred"] is True
    assert result["output"] is None
    assert result["request"]["schema"] == explain_mod.EXPLAIN_SCHEMA
    assert "system" in result["request"] and "user" in result["request"]
    # Carries everything ingest needs to finalize later.
    assert result["ingest"]["finding_path"] == finding_path


def test_ingest_host_output_runs_validators_and_persists_finding(temp_case_dir):
    finding_path = _write_finding(temp_case_dir)
    host_json = {
        "description": "Finding F-000-001 records rundll32 launched from a temp path.",
        "mitre_attack": "T1218.011",
        "caveats": [
            "Process creation (4688) proves the process was launched, not that the DLL is still on disk.",
        ],
        "next_evidence": ["Prefetch for rundll32.exe"],
    }
    result = explain_mod.ingest_host_output(
        finding_path, FK_YAML, MITRE_MAP, temp_case_dir, host_json
    )
    assert result["api_error"] is None
    assert result["output"]["mitre_attack"] == "T1218.011"
    # Finding YAML persisted with the validated description/MITRE.
    with open(finding_path) as f:
        persisted = yaml.safe_load(f)
    assert persisted["description"] == host_json["description"]
    assert persisted["mitre_attack"] == "T1218.011"
    # ingest_host_output no longer writes a single-finding reports/report.md
    # stub — that used to clobber the Phase-6 multi-finding report on every
    # persist. `_merge_report_md` (Phase 6) is the sole report.md writer.
    assert not os.path.exists(f"{temp_case_dir}/reports/report.md")


def test_ingest_rejects_out_of_set_mitre(temp_case_dir):
    finding_path = _write_finding(temp_case_dir)
    host_json = {
        "description": "Finding F-000-001 is benign.",
        "mitre_attack": "T9999",  # not in the allowed set
        "caveats": [],
        "next_evidence": [],
    }
    result = explain_mod.ingest_host_output(
        finding_path, FK_YAML, MITRE_MAP, temp_case_dir, host_json
    )
    # W2-1: an out-of-set ID never widens the attribution, and is never
    # forced to UNMAPPED either — the deterministic value is kept.
    assert result["output"]["mitre_attack"] == "T1218.011"
    assert any("not in allowed set" in v for v in result["violations"])


def test_ingest_strips_unsupported_c2_claim(temp_case_dir):
    finding_path = _write_finding(temp_case_dir)
    host_json = {
        "description": (
            "Finding F-000-001 records rundll32 from a temp path. "
            "The host was beaconing to a C2 server over the network."
        ),
        "mitre_attack": "T1218.011",
        "caveats": [],
        "next_evidence": [],
    }
    result = explain_mod.ingest_host_output(
        finding_path, FK_YAML, MITRE_MAP, temp_case_dir, host_json
    )
    assert "C2" not in result["output"]["description"]
    assert any("stripped unsupported claim" in v for v in result["violations"])


def test_null_provider_surfaces_api_error(temp_case_dir):
    finding_path = _write_finding(temp_case_dir)
    result = explain_mod.explain(
        finding_path, FK_YAML, MITRE_MAP, temp_case_dir, provider_name="null"
    )
    assert result["output"] is None
    assert result["api_error"]
