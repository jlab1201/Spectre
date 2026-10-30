"""W1-1 (R2-06/R2-11/R2-12): host mode (SPECTRE_LLM_PROVIDER=host, the
default) must NEVER implicitly fall back to a direct API provider just
because a key (e.g. DEEPSEEK_API_KEY) happens to be discoverable in the
environment or ~/.spectre.env.

Before this fix:
  - pipeline/phase_runner.py's run_phase_6() silently retried narrative
    synthesis against DeepSeek whenever host mode deferred and a key was
    present — an undisclosed network call with case finding data, no
    opt-in, observed live in R2-06's review.
  - pipeline/direction.py's _call_llm() did the same for Phase 1 direction
    parsing via the (now-removed) llm.first_direct_provider() helper.

Both call sites now defer to the deterministic path unconditionally under
host mode: Phase 6 falls back to the deterministic report template, Phase 1
leaves the fragment unparsed (surfaced as a warning). API use requires
explicitly setting SPECTRE_LLM_PROVIDER=<deepseek|anthropic|openai|local>.

Each test below monkeypatches urllib.request.urlopen to raise, so ANY
direct-provider HTTP call (from any of the OpenAI-style providers or the
Anthropic provider, which all funnel through llm._post_json -> urlopen)
fails the test loudly instead of silently succeeding against a live
endpoint (there must be no such call at all under provider=host).

W1-1 nit 2 additionally hardens this file two ways:
  - socket.socket.connect / socket.create_connection are ALSO patched to
    raise. The urlopen patch is complete for every current transport (no
    requests/http.client/httpx anywhere in src — see W1-REVIEW.md), but a
    future transport (e.g. an SDK) that opens its own socket would bypass
    a urlopen-only patch silently. Patching at the socket layer too closes
    that regression class BEFORE it can happen.
  - Phase-5 adversarial review (`phase_runner.run_phase_5`) and a direct
    `explain.explain()` call are now exercised too, under host mode with a
    key present — previously only Phase 1 and Phase 6 were covered here.
"""
import socket

import pytest
import yaml

from spectre import llm
from spectre.pipeline import direction


def _boom_urlopen(*a, **k):
    raise AssertionError(
        "host mode must never make a direct-provider HTTP call, even when "
        "an API key is discoverable in the environment"
    )


def _boom_socket(*a, **k):
    raise AssertionError(
        "host mode must never open a raw socket, even when an API key is "
        "discoverable in the environment — this would bypass a "
        "urlopen-only patch if a future transport stopped using urllib"
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(llm.urllib.request, "urlopen", _boom_urlopen)
    monkeypatch.setattr(socket.socket, "connect", _boom_socket)
    monkeypatch.setattr(socket, "create_connection", _boom_socket)


@pytest.fixture(autouse=True)
def _host_provider_with_key_present(monkeypatch):
    """The exact condition that used to trigger the silent fallback:
    provider=host (default) AND a direct-provider key present."""
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "host")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-should-never-be-used")


def test_phase1_direction_parsing_makes_no_api_call(monkeypatch):
    res = direction.synthesize("do something clever about the thing", skip_ai=False)
    # Deterministic-first preserved: nothing invented, fragment surfaced as
    # a warning rather than silently expanded by an API call.
    assert res["directives"] == [], res
    assert res["warnings"]
    assert res["llm_used"] is False
    assert res["deferred"] is True


def test_phase6_synthesis_makes_no_api_call_and_uses_deterministic_template(tmp_path):
    from spectre.pipeline.phase_runner import run_phase_6

    case_dir = tmp_path / "997-no-egress"
    findings_dir = case_dir / "findings"
    findings_dir.mkdir(parents=True)
    fid = "F-997-001"
    (findings_dir / f"{fid}.yaml").write_text(yaml.safe_dump({
        "finding_id": fid,
        "status": "INFERRED",
        "confidence": 0.5,
        "title": "test finding",
        "mitre_attack": "UNMAPPED",
        "iocs": {},
    }))

    manifest = {
        "case_id": "997",
        "case_name": "no-egress",
        "artifact_profile": "pcap-focused",
        "canary_status": "FULL",
        "evidence": [],
    }

    result = run_phase_6(str(case_dir), manifest, skip_ai=False)

    # No API call happened (the autouse fixture would have raised); the
    # deterministic baseline path was used instead.
    assert result["llm_used"] is False
    report_path = case_dir / "reports" / "report.md"
    assert report_path.exists()


def test_first_direct_provider_helper_no_longer_exists():
    """The implicit-fallback discovery helper itself was removed, not just
    its call sites — nothing should be able to silently reintroduce the
    fallback by importing it back in."""
    assert not hasattr(llm, "first_direct_provider")


# ── W1-1 nit 2: explain() and Phase-5 adversarial review, under host mode
# with a key present, must also make no network call at all ────────────

def _seed_fk_and_mitre(tmp_path):
    fk = tmp_path / "fk.yaml"
    fk.write_text(yaml.safe_dump({"does_NOT_prove": ["placeholder caveat"]}))
    mitre = tmp_path / "mitre.yaml"
    mitre.write_text(yaml.safe_dump({"rules": {}, "fallback": "UNMAPPED"}))
    return str(fk), str(mitre)


def test_explain_makes_no_api_call_under_host_with_key_present(tmp_path):
    from spectre.core.explain import explain
    from spectre.pipeline.audit import append as audit_append

    case_dir = tmp_path / "998-no-egress-explain"
    (case_dir / "findings").mkdir(parents=True)
    finding_id = "F-998-001"
    finding_path = case_dir / "findings" / f"{finding_id}.yaml"
    finding = {
        "finding_id": finding_id, "status": "INFERRED", "confidence": 0.5,
        "mitre_attack": "UNMAPPED", "forensic_caveats": [],
        "title": "test finding", "corroboration": {"sources": 1, "tools": []},
        "evidence_refs": [{"execution_id": "exec-1"}],
    }
    finding_path.write_text(yaml.safe_dump(finding))
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(finding_path), "output_sha256": "",
        "result": "success", "finding_id": finding_id, "phase": 3,
    })
    fk_path, mitre_path = _seed_fk_and_mitre(tmp_path)

    result = explain(str(finding_path), fk_path, mitre_path, str(case_dir))

    # No network call happened (the autouse fixture would have raised);
    # host mode returns a deferred request bundle for the orchestrating
    # agent to fill instead.
    assert result["deferred"] is True
    assert result["output"] is None


def test_phase5_adversarial_review_makes_no_api_call_under_host_with_key_present(tmp_path):
    from spectre.pipeline.phase_runner import run_phase_5

    case_dir = tmp_path / "998-no-egress-phase5"
    (case_dir / "findings").mkdir(parents=True)
    finding_id = "F-998-001"
    finding_path = case_dir / "findings" / f"{finding_id}.yaml"
    finding_path.write_text(yaml.safe_dump({
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
    }))

    manifest = {"case_id": "998", "case_name": "no-egress-phase5", "evidence": []}

    result = run_phase_5(str(case_dir), manifest)

    # No network call happened (the autouse fixture would have raised);
    # the real explain()/get_provider() seam ran end to end and honestly
    # reported the host-deferred state rather than silently falling back.
    assert result["success"] is True
    assert manifest["gate_5"]["status"] == "DEGRADED"
    assert manifest["gate_5"]["substantive_review"] == "deferred-to-host"
    assert manifest["gate_5"]["grounding_probe"] == "deferred-to-host"
