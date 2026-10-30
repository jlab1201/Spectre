"""WS7e — real Phase-5 adversarial review.

Pins the split between the two Phase-5 mechanisms:

  A. grounding_probe  — the pre-existing per-finding explain(adversarial=True)
     red-team self-test of Validator #5 (explain.py's C2-poison strip).
  B. substantive_review — the new case-level devil's-advocate pass
     (build_adversarial_context() -> ADVERSARIAL_SCHEMA -> _validate_adversarial),
     wired via phase_runner._run_substantive_adversarial.

Before this change, run_phase_5() hardcoded success=True/gate_passed=True/
manifest["gate_5"]["passed"]=True unconditionally, and the "counter_hypotheses"
metric it read didn't exist on EXPLAIN_SCHEMA's output — it was structurally
always 0. These tests pin the fix: a real FAIL path, a real DEGRADED (honest,
non-blocking) path, and a real counter-hypotheses count.
"""
import json
from pathlib import Path

import yaml

from spectre.core import explain as explain_mod
from spectre.pipeline import phase_runner
import spectre.llm as llm_mod
from spectre.llm import LLMResponse, NullProvider


# ── Fixtures / helpers ──────────────────────────────────────────────

def _finding(finding_id="F-100-001", **overrides):
    f = {
        "finding_id": finding_id,
        "status": "CONFIRMED",
        "confidence": 0.75,
        "title": "rundll32-from-temp: rundll32 loading DLL from Temp",
        "mitre_attack": "T1218.011",
        "description": "",
        "corroboration": {"sources": 2, "tools": ["evtx/evtx_4688"], "artifacts": []},
        "iocs": {"filepath": ["C:\\Windows\\Temp\\evil.dll"], "ip": [], "domain": []},
        "forensic_caveats": [],
        "evidence_refs": [{"execution_id": "exec-1"}],
    }
    f.update(overrides)
    return f


def _write_finding(case_dir: Path, finding_id="F-100-001", **overrides) -> Path:
    finding = _finding(finding_id, **overrides)
    path = case_dir / "findings" / f"{finding_id}.yaml"
    path.write_text(yaml.dump(finding, sort_keys=False))
    return path


def _case_dir(tmp_path, name="100-phase5") -> Path:
    case_dir = tmp_path / name
    (case_dir / "findings").mkdir(parents=True)
    return case_dir


def _manifest(case_id="100"):
    return {"case_id": case_id, "case_name": "phase5-test", "evidence": []}


def _clean_stub_explain(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                        adversarial=False, case_id=None, phase=5, **kw):
    """A fully-clean explain() double: no poison, no persist_refused, no
    deferral — a straightforward API-provider pass on both passes."""
    fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
    fid = fdata.get("finding_id", "?")
    return {
        "finding_id": fid,
        "output": {"description": f"{fid} — clean explanation (adversarial={adversarial})."},
        "violations": [],
        "token_usage": {"prompt": 10, "completion": 10},
        "api_error": None,
        "adversarial_stripped": False,
        "persist_refused": False,
    }


# ── Test 1 — grounding-probe break FAILS the gate ──────────────────

def test_gate_5_can_fail_on_grounding_break(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir)
    manifest = _manifest()

    def _poison_survives(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                         adversarial=False, case_id=None, phase=5, **kw):
        fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
        fid = fdata.get("finding_id", "?")
        if adversarial:
            # Simulates Validator #5 failing to strip the injected C2 poison.
            desc = (f"{fid} — outbound C2 beacon to "
                    f"{explain_mod.ADVERSARIAL_POISON_IP}:{explain_mod.ADVERSARIAL_POISON_PORT} observed.")
        else:
            desc = f"{fid} — clean normal explanation."
        return {
            "finding_id": fid,
            "output": {"description": desc},
            "violations": [],
            "token_usage": {"prompt": 1, "completion": 1},
            "api_error": None,
            "adversarial_stripped": False,
            "persist_refused": False,
        }

    monkeypatch.setattr(explain_mod, "explain", _poison_survives)

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    assert result["success"] is False
    assert manifest["gate_5"]["status"] == "FAIL"
    assert manifest["gate_5"]["passed"] is False
    assert "poison" in manifest["gate_5"]["degraded_reason"].lower() \
        or "validator" in manifest["gate_5"]["degraded_reason"].lower()


# ── Test 2 — persist_refused (tamper signal) FAILS the gate ────────

def test_gate_5_fails_on_persist_refused(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir)
    manifest = _manifest()

    def _persist_refused(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                         adversarial=False, case_id=None, phase=5, **kw):
        fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
        fid = fdata.get("finding_id", "?")
        out = {
            "finding_id": fid,
            "output": {"description": f"{fid} — clean explanation."},
            "violations": [],
            "token_usage": {"prompt": 1, "completion": 1},
            "api_error": None,
            "adversarial_stripped": False,
            "persist_refused": False,
        }
        if not adversarial:
            out["persist_refused"] = True
        return out

    monkeypatch.setattr(explain_mod, "explain", _persist_refused)

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    assert manifest["gate_5"]["status"] == "FAIL"
    assert result["success"] is False


# ── Test 3 — real counter-hypotheses metric for an API provider ────

def test_counter_hypotheses_metric_real_for_api_provider(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir, "F-100-001")
    _write_finding(case_dir, "F-100-002")
    manifest = _manifest()

    monkeypatch.setattr(explain_mod, "explain", _clean_stub_explain)

    class _StubAPIProvider:
        name = "stub-api"

        def complete(self, system, user, *, max_tokens=2048, temperature=0.0, schema=None):
            return LLMResponse(parsed={
                "counter_hypotheses": [
                    {"finding_id": "F-100-001",
                     "alternative": "Could be legitimate administrative activity."},
                    {"finding_id": "F-100-002",
                     "alternative": "Could be a benign scheduled task, not malicious."},
                ],
                "evidence_gaps": [],
                "citation_gaps": [],
                "alternative_timeline": [],
            })

    monkeypatch.setattr(llm_mod, "get_provider", lambda name=None: _StubAPIProvider())

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    assert manifest["gate_5"]["counter_hypotheses_count"] == 2
    assert manifest["gate_5"]["substantive_review"] == "ran"
    assert result["success"] is True


# ── Test 4 — host provider: honest deferred state, never blocks ────

def test_host_provider_honest_deferred(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir)
    manifest = _manifest()

    def _deferred_explain(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                          adversarial=False, case_id=None, phase=5, **kw):
        fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
        fid = fdata.get("finding_id", "?")
        return {
            "finding_id": fid,
            "output": None,
            "deferred": True,
            "request": {"system": "s", "user": "u", "schema": explain_mod.EXPLAIN_SCHEMA},
            "ingest": {},
            "violations": [],
            "token_usage": {"prompt": 0, "completion": 0},
            "api_error": None,
            "adversarial_stripped": False,
        }

    monkeypatch.setattr(explain_mod, "explain", _deferred_explain)
    # get_provider not monkeypatched -> real spectre.llm.get_provider(None),
    # default SPECTRE_LLM_PROVIDER="host" -> HostProvider, always deferred,
    # makes no network call.

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    gate = manifest["gate_5"]
    assert gate["status"] == "DEGRADED"
    assert gate["substantive_review"] == "deferred-to-host"
    assert gate["grounding_probe"] == "deferred-to-host"
    assert gate["passed"] is True
    assert result["success"] is True


# ── Test 5 — null provider: honest not-run state, never blocks ─────

def test_null_provider_honest_not_run(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir)
    manifest = _manifest()

    def _null_explain(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                      adversarial=False, case_id=None, phase=5, **kw):
        fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
        fid = fdata.get("finding_id", "?")
        # Matches explain()'s real `resp.parsed is None` branch shape: no
        # "deferred" key at all (see explain.py) — this is the exact shape
        # that used to make `any_deferred` silently stay False for null.
        return {
            "finding_id": fid,
            "output": None,
            "violations": [],
            "token_usage": {"prompt": 0, "completion": 0},
            "api_error": "no output from LLM provider",
            "adversarial_stripped": False,
        }

    monkeypatch.setattr(explain_mod, "explain", _null_explain)
    monkeypatch.setattr(llm_mod, "get_provider", lambda name=None: NullProvider())

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    gate = manifest["gate_5"]
    assert gate["status"] == "DEGRADED"
    assert gate["substantive_review"] == "not-run"
    assert "deterministic-only" in gate["degraded_reason"]
    assert gate["passed"] is True
    assert result["success"] is True


# ── Test 6 — _validate_adversarial can't smuggle a finding/technique/IOC ──

def test_adversarial_cannot_smuggle_finding(tmp_path):
    case_dir = _case_dir(tmp_path)
    finding_path = _write_finding(case_dir, "F-100-001")
    before = finding_path.read_text()

    all_findings = [_finding("F-100-001")]
    allowed_mitre = ["T1218.011"]  # T1055 deliberately NOT in this set

    output = {
        "counter_hypotheses": [
            {"finding_id": "F-999-999",
             "alternative": "An unrelated, entirely benign explanation."},
        ],
        "evidence_gaps": [
            "Technique T1055 process injection was never investigated.",
        ],
        "citation_gaps": [
            "Traffic to 203.0.113.99 was never explained in any finding.",
        ],
        "alternative_timeline": [],
    }

    cleaned, violations = explain_mod._validate_adversarial(
        output, all_findings, allowed_mitre
    )

    # Unknown finding_id counter-hypothesis dropped entirely.
    assert cleaned["counter_hypotheses"] == []
    assert any("F-999-999" in v for v in violations)

    # Unauthorized MITRE token redacted in place, not left verbatim.
    assert not any("T1055" in item for item in cleaned["evidence_gaps"])
    assert any("MITRE-REDACTED" in item for item in cleaned["evidence_gaps"])
    assert any("T1055" in v for v in violations)

    # Bare, ungrounded C2 IP stripped (whole entry dropped).
    assert not any("203.0.113.99" in item for item in cleaned["citation_gaps"])
    assert any("203.0.113.99" in v for v in violations)

    # Structural: no F-*.yaml on disk was touched.
    assert finding_path.read_text() == before
    assert sorted((case_dir / "findings").glob("F-*.yaml")) == [finding_path]


def test_adversarial_annotates_unverified_software_without_deleting(tmp_path):
    """Ungrounded EXECUTABLE-shaped literals are a different posture from
    ungrounded IP/domain literals: they are the substance of a legitimate
    counter-hypothesis (benign software the deterministic layer never
    observed), so they are annotated, not deleted."""
    all_findings = [_finding("F-100-001")]
    output = {
        "counter_hypotheses": [
            {"finding_id": "F-100-001",
             "alternative": "This could be svchost.exe performing routine Windows Update activity."},
        ],
        "evidence_gaps": [],
        "citation_gaps": [],
        "alternative_timeline": [],
    }
    cleaned, violations = explain_mod._validate_adversarial(output, all_findings, ["T1218.011"])
    assert len(cleaned["counter_hypotheses"]) == 1
    alt = cleaned["counter_hypotheses"][0]["alternative"]
    assert "svchost.exe" in alt
    assert "unverified" in alt.lower()
    assert any("unverified" in v.lower() for v in violations)


def test_adversarial_strips_dotcom_c2_domain(tmp_path):
    """Regression: `.com` is the most common TLD, not a software extension.
    An ungrounded `.com` C2 domain must be treated as a NETWORK literal and
    the whole item dropped — never annotated-and-kept like a benign
    executable name. Also guards the tiebreak: a `.exe` and a `.com` together
    in one item must still drop (network literal wins)."""
    all_findings = [_finding("F-100-001")]
    output = {
        "counter_hypotheses": [
            {"finding_id": "F-100-001",
             "alternative": "Traffic actually went to attacker-c2.com for exfil."},
            {"finding_id": "F-100-001",
             "alternative": "This could be svchost.exe talking to evil-c2.example.com."},
        ],
        "evidence_gaps": [],
        "citation_gaps": ["Unexplained beacon to badhost.com every 60s."],
        "alternative_timeline": [],
    }
    cleaned, violations = explain_mod._validate_adversarial(output, all_findings, ["T1218.011"])

    # Both counter-hypotheses carried an ungrounded .com domain -> both dropped.
    assert cleaned["counter_hypotheses"] == []
    assert not any("attacker-c2.com" in c.get("alternative", "")
                   for c in cleaned["counter_hypotheses"])
    assert not any("evil-c2.example.com" in c.get("alternative", "")
                   for c in cleaned["counter_hypotheses"])
    # The .com in the citation gap is stripped too.
    assert not any("badhost.com" in item for item in cleaned["citation_gaps"])
    # And the leak is recorded in the violation audit trail.
    assert any("attacker-c2.com" in v for v in violations)


# ── Test 7 — a correctly-neutralized probe must NOT fail the gate ──

def test_grounding_probe_pass_neutralized(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir)
    manifest = _manifest()

    def _neutralized_explain(finding_path, fk_yaml_path, mitre_map_path, case_dir,
                             adversarial=False, case_id=None, phase=5, **kw):
        fdata = yaml.safe_load(Path(finding_path).read_text()) or {}
        fid = fdata.get("finding_id", "?")
        violations = []
        if adversarial:
            violations = [
                f"stripped ungrounded claim (literals not in finding: "
                f"['{explain_mod.ADVERSARIAL_POISON_IP}']): outbound C2 beacon..."
            ]
        return {
            "finding_id": fid,
            "output": {"description": f"{fid} — clean explanation (poison stripped)."},
            "violations": violations,
            "token_usage": {"prompt": 5, "completion": 5},
            "api_error": None,
            "adversarial_stripped": adversarial,
            "persist_refused": False,
        }

    monkeypatch.setattr(explain_mod, "explain", _neutralized_explain)

    result = phase_runner.run_phase_5(str(case_dir), manifest)

    assert manifest["gate_5"]["status"] != "FAIL"
    assert result["success"] is True


# ── Test 8 — an adversarial_review audit row exists per finding ────

def test_adversarial_review_audit_row_written(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path)
    _write_finding(case_dir, "F-100-001")
    _write_finding(case_dir, "F-100-002")
    manifest = _manifest()

    monkeypatch.setattr(explain_mod, "explain", _clean_stub_explain)

    phase_runner.run_phase_5(str(case_dir), manifest)

    audit_path = case_dir / "audit.jsonl"
    assert audit_path.exists()
    rows = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    reviewed_ids = {r["finding_id"] for r in rows if r.get("action") == "adversarial_review"}
    assert reviewed_ids == {"F-100-001", "F-100-002"}
