"""W2-A adversarial re-review (2026-09-30) — B1..B9 as end-to-end tests.

Every PoC string from W2A-REREVIEW.md is driven through the PUBLIC seams a
host agent can reach (ingest_host_report / ingest_host_output /
ingest_host_adversarial / explain) against a case whose findings are
registered exactly as pipeline/emit_finding.py registers them.
"""
from __future__ import annotations

import hashlib
import shutil

import pytest
import yaml

from spectre.core import grounding

F1 = {
    "finding_id": "F-900-001", "title": "pcap-beacon — periodic HTTP to good.example.com",
    "status": "INFERRED", "confidence": 0.5, "rule_id": "pcap-beacon",
    "mitre_attack": "T1071.001",
    "corroboration": {"sources": 1, "tools": ["zeek/pcap"],
                      "artifacts": ["10.0.0.5 -> 198.51.100.7 good.example.com [outbound]"]},
    "iocs": {"ip": ["198.51.100.7"], "domain": ["good.example.com"]},
    "evidence_refs": [{"execution_id": "x"}], "description": "",
    "forensic_caveats": [],
}
F2 = {
    "finding_id": "F-900-002", "title": "pcap-c2-protocol",
    "status": "INFERRED", "confidence": 0.5, "rule_id": "pcap-c2-protocol",
    "mitre_attack": "T1071.001, T1573.001",
    "corroboration": {"sources": 1, "tools": ["zeek/ssl"], "artifacts": ["tls ja3"]},
    "iocs": {"ip": ["198.51.100.8"], "domain": []},
    "evidence_refs": [{"execution_id": "y"}], "description": "",
    "forensic_caveats": [],
}
F3_EXCL = dict(F1, finding_id="F-900-003",
               iocs={"ip": ["203.0.113.66"], "domain": ["excluded.example"]},
               analyst_excluded=True, excluded_by="analyst directive")


@pytest.fixture(autouse=True)
def _no_journal(monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "0")
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "host")


def _register(case, f, excluded=False):
    from spectre.pipeline.audit import append as audit_append
    d = case / "findings" / ("excluded" if excluded else "")
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{f['finding_id']}.yaml"
    b = yaml.dump(f, default_flow_style=False, sort_keys=False, allow_unicode=True).encode()
    p.write_bytes(b)
    audit_append(str(case), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "tool_version": "2.0",
        "exact_command": "emit_from_handle(test)",
        "params": {"finding_id": f["finding_id"], "rule_id": f["rule_id"]},
        "case_id": case.name, "output_path": str(p),
        "output_sha256": hashlib.sha256(b).hexdigest(), "result": "success",
        "exit_code": 0, "duration_ms": 0, "finding_id": f["finding_id"],
        "phase": 3, "phase_step": "S1-emit"})
    return p


@pytest.fixture
def make_case(tmp_path):
    from spectre.pipeline.audit import append as audit_append

    def _mk(findings=(F1, F2), excluded=(), name="900-rr"):
        case = tmp_path / name
        if case.exists():
            shutil.rmtree(case)
        for s in ("evidence", "raw_extract", "findings", "reports"):
            (case / s).mkdir(parents=True, exist_ok=True)
        (case / "manifest.yaml").write_text(
            yaml.dump({"case_id": name, "artifact_profile": "pcap"}))
        audit_append(str(case), {"actor": "deterministic-core", "action": "case_init",
                                 "phase": 0, "phase_step": "S0", "case_id": name})
        for f in findings:
            _register(case, dict(f))
        for f in excluded:
            _register(case, dict(f), excluded=True)
        return case
    return _mk


def _narr(**kw):
    base = {"executive_summary": "Summary of F-900-001.", "threat_narrative": "",
            "verdict": "These are investigative leads.", "findings_narrative": [],
            "timeline_narrative": "", "methodology_narrative": ""}
    base.update(kw)
    return base


def _report(case, **kw):
    from spectre.pipeline.report_synthesize import ingest_host_report
    return ingest_host_report(str(case), _narr(**kw))


def _host_explain(case, fid, desc, mitre="T1071.001", caveats=None):
    from spectre.core import explain as ex
    fp = case / "findings" / f"{fid}.yaml"
    r = ex.ingest_host_output(str(fp), case_dir=str(case),
                              host_json={"description": desc, "mitre_attack": mitre,
                                         "caveats": caveats or []})
    return r, yaml.safe_load(fp.read_text())


# ── canonicalize(): the ONE shared normalizer ───────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("Т1003.006", "T1003.006"),          # Cyrillic TE
    ("Τ1003.006", "T1003.006"),          # Greek TAU
    ("ᴛ1003.006", "T1003.006"),          # small-cap t (case-insensitive downstream)
    ("does nоt prove", "does not prove"),  # Cyrillic o
    ("F‐900‐777", "F-900-777"),          # U+2010
    ("F‑900‑777", "F-900-777"),          # U+2011
    ("F－900－777", "F-900-777"),         # fullwidth
    ("185·220·101·42", "185.220.101.42"),
    ("185‧220‧101‧42", "185.220.101.42"),
    ("185 . 220 . 101 . 42", "185.220.101.42"),
    ("185. 220. 101. 42", "185.220.101.42"),
    ("evil-c2 . com", "evil-c2.com"),
    ("evil-c2.cоm", "evil-c2.com"),
    ("185.220.101­.42", "185.220.101.42"),
])
def test_canonicalize_folds_evasions(raw, expected):
    assert grounding.canonicalize(raw).upper() == expected.upper()


def test_canonicalize_leaves_ordinary_prose_alone():
    s = "The host beaconed. Then it stopped. Version 2 shipped."
    assert grounding.canonicalize(s) == s


# ── B1: report V2 MITRE token evasions ─────────────────────────────────

B1_TOKENS = ["Т1003.006", "Τ1003.006", "ᴛ1003.006", "_T1003.006_", "ATT&CK_T1003.006",
             "MITRE:T1003.006", "T  1003.006", "T  1003.006", "T\n1003.006",
             "T-1003.006", "T‐1003.006", "T—1003.006", "**T**1003.006", "T1003．006",
             "t1003.006", "T１００３.００６"]


@pytest.mark.parametrize("tok", B1_TOKENS)
def test_b1_report_mitre_evasions_fail_closed(make_case, tok):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 is consistent with {tok} (DCSync).")
    assert "1003" not in r["threat_narrative"]
    # Round 4+: a non-Latin T is now caught first by the character whitelist.
    assert any("invented MITRE" in v or "disallowed character" in v for v in r["violations"])


def test_b1_allowed_subtechnique_never_rewritten(make_case):
    c = make_case()
    r = _report(c, threat_narrative="F-900-001 is T1071 and T1071.001; F-900-002 adds T1573.001.")
    t = r["threat_narrative"]
    assert "T1071.001" in t and "T1573.001" in t
    assert "UNMAPPED and" in t


def test_b1_ordinary_words_not_flagged(make_case):
    c = make_case()
    txt = ("F-900-001 was seen at 10 past the hour; the setting 1000 and the "
           "last 2024 events were reviewed, including T1071.001 activity.")
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt
    assert not any("MITRE" in v for v in r["violations"])


# ── B2: spaced-dot IP split across sentences ───────────────────────────

@pytest.mark.parametrize("ioc", ["185 . 220 . 101 . 42", "185. 220. 101. 42"])
def test_b2_report_spaced_dot_ip_stripped(make_case, ioc):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 contacted {ioc} repeatedly.")
    assert "220" not in r["threat_narrative"]
    fn = _report(c, findings_narrative=[{"finding_id": "F-900-001",
                                         "narrative": f"F-900-001 contacted {ioc} repeatedly."}])
    assert "220" not in str(fn["findings_narrative"])


def test_b2_explain_spaced_dot_ip_not_persisted(make_case):
    c = make_case()
    _, f = _host_explain(c, "F-900-001",
                         "F-900-001 beacons to C2 185 . 220 . 101 . 42 every 60s.")
    assert "220" not in f["description"]


# ── B3: homoglyph / separator IOC evasions ─────────────────────────────

@pytest.mark.parametrize("ioc", ["evil-c2.cоm", "pаypal-update.com", "185·220·101·42",
                                 "185‧220‧101‧42", "evil-c2 . com"])
# "evil-c2. com" (whitespace AFTER the dot only) is no longer fused (R3-4:
# that join fused real sentence boundaries) — a documented residual.
def test_b3_report_ioc_evasions_stripped(make_case, ioc):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 contacted {ioc} repeatedly.")
    assert "repeatedly" not in r["threat_narrative"]
    fn = _report(c, findings_narrative=[{"finding_id": "F-900-001",
                                         "narrative": f"F-900-001 contacted {ioc} repeatedly."}])
    assert "repeatedly" not in str(fn["findings_narrative"])


def test_b3_explain_homoglyph_domain_not_persisted(make_case):
    c = make_case()
    _, f = _host_explain(c, "F-900-001", "F-900-001 beacons to C2 at evil-c2.cоm every 60s.")
    assert "evil" not in f["description"]


def test_b3_grounded_ioc_still_survives(make_case):
    c = make_case()
    txt = "F-900-001 contacted 198.51.100.7 and good.example.com repeatedly."
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt


# ── B4: Unicode-dash invented finding IDs ──────────────────────────────

@pytest.mark.parametrize("fid", ["F－900－777", "F‑900‑777", "F‐900‐777", "F—900—777"])
def test_b4_invented_fid_explain(make_case, fid):
    c = make_case()
    r, f = _host_explain(c, "F-900-001", f"F-900-001 and {fid} show the same beacon cadence.")
    assert "777" not in f["description"]
    # Round 5: U+2010/U+2011 are outside the character whitelist, so the
    # sentence is dropped by the policy before the ID check sees it.
    assert any("invented finding IDs" in v or "disallowed character" in v
               for v in r["violations"])


@pytest.mark.parametrize("fid", ["F－900－777", "F‑900‑777", "F‐900‐777"])
def test_b4_invented_fid_report(make_case, fid):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 and {fid} show the same cadence.")
    assert "777" not in r["threat_narrative"]


# ── B5: explain description MITRE + caveat/certainty checks ────────────

def test_b5_description_invented_mitre_and_certainty_stripped(make_case):
    c = make_case()
    r, f = _host_explain(
        c, "F-900-001",
        "F-900-001 is OS Credential Dumping: DCSync (T1003.006). "
        "F-900-001 is conclusive proof of domain compromise and needs no corroboration. "
        "F-900-001 shows periodic HTTP to good.example.com.")
    d = f["description"]
    assert "1003" not in d
    assert "conclusive" not in d
    assert "periodic HTTP" in d
    assert any("MITRE" in v for v in r["violations"])


@pytest.mark.parametrize("tok", ["_T1003.006_", "Т1003.006", "T 1003.006", "T-1003.006"])
def test_b5_description_mitre_evasions(make_case, tok):
    c = make_case()
    _, f = _host_explain(c, "F-900-001", f"F-900-001 matches {tok}.")
    assert "1003" not in f["description"]


def test_b5_description_allowed_mitre_kept(make_case):
    c = make_case()
    _, f = _host_explain(c, "F-900-001", "F-900-001 matches T1071.001 web protocols.")
    assert "T1071.001" in f["description"]


def test_b5_description_fabricated_caveat_stripped(make_case):
    c = make_case()
    _, f = _host_explain(c, "F-900-001",
                         "F-900-001 shows periodic HTTP. F-900-001 does nоt prove the attacker left.")
    assert "attacker" not in f["description"]
    assert "periodic HTTP" in f["description"]


# ── B6: public explain() ignores caller FK / map paths ─────────────────

def test_b6_explain_api_ignores_caller_fk(make_case, tmp_path, monkeypatch):
    from spectre import llm
    from spectre.config import MITRE_MAP_PATH
    from spectre.core import explain as ex

    evil = "Analyst verified this host was fully compromised by APT29."
    evil_fk = tmp_path / "evil_fk.yaml"
    evil_fk.write_text(yaml.dump({"does_NOT_prove": [evil]}))
    evil_map = tmp_path / "evil_map.yaml"
    evil_map.write_text(yaml.dump({"rules": {"pcap-beacon": {"allowed": ["T1486"]}}}))

    def fake_complete(self, system, user, max_tokens=0, schema=None):
        return llm.LLMResponse(parsed={"description": "F-900-001 periodic HTTP.",
                                       "mitre_attack": "T1486", "caveats": [evil]},
                               usage={}, model="stub")
    monkeypatch.setattr(llm.LocalProvider, "complete", fake_complete)
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    r = ex.explain(str(fp), str(evil_fk), str(evil_map), str(c), provider_name="local")
    f = yaml.safe_load(fp.read_text())
    assert evil not in (f.get("forensic_caveats") or [])
    assert f["mitre_attack"] == "T1071.001"
    assert "T1486" not in str(f)
    assert r["violations"]
    _ = MITRE_MAP_PATH


# ── B7: homoglyph inside the caveat signal phrase ──────────────────────

def test_b7_report_caveat_homoglyph_stripped(make_case):
    c = make_case()
    r = _report(c, threat_narrative="F-900-001 beacon does nоt prove lateral movement.")
    assert "lateral" not in r["threat_narrative"]


def test_b7_verbatim_fk_caveat_still_kept(make_case):
    from spectre.core.validators import guardrail_context, load_verified_findings
    c = make_case()
    fnd, _ = load_verified_findings(c)
    _, fkmap = guardrail_context(fnd, case_dir=c)
    cavs = [x for v in fkmap.values() for x in v]
    if not cavs:
        pytest.skip("no FK caveats routed for pcap")
    cv = cavs[0].strip().rstrip(".") + "."
    r = _report(c, threat_narrative=cv)
    assert r["threat_narrative"].strip() == cv


# ── B8: excluded finding copied back into findings/ ────────────────────

def test_b8_excluded_copy_not_trusted(make_case):
    from spectre.core.validators import FindingIntegrityError, load_verified_findings
    from spectre.pipeline.audit import verify_full
    c = make_case(excluded=(F3_EXCL,))
    shutil.copy(c / "findings" / "excluded" / "F-900-003.yaml",
                c / "findings" / "F-900-003.yaml")
    try:
        fnd, _ = load_verified_findings(c)
        assert "F-900-003" not in [x["finding_id"] for x in fnd]
    except FindingIntegrityError:
        pass
    try:
        r = _report(c, threat_narrative="F-900-003 contacted 203.0.113.66.")
        assert "203.0.113.66" not in r["threat_narrative"]
    except FindingIntegrityError:
        pass
    vf = verify_full(str(c))
    assert vf["checks"]["finding_integrity"]["passed"] is False


def test_b8_excluded_in_place_is_not_a_violation(make_case):
    from spectre.core.validators import load_verified_findings
    from spectre.pipeline.audit import verify_full
    c = make_case(excluded=(F3_EXCL,))
    fnd, _ = load_verified_findings(c)
    assert "F-900-003" not in [x["finding_id"] for x in fnd]
    vf = verify_full(str(c))
    assert vf["checks"]["finding_integrity"]["passed"] is True, vf["checks"]["finding_integrity"]


def test_b8_explain_refuses_persist_at_relocated_path(make_case):
    c = make_case(excluded=(F3_EXCL,))
    shutil.copy(c / "findings" / "excluded" / "F-900-003.yaml",
                c / "findings" / "F-900-003.yaml")
    r, _ = _host_explain(c, "F-900-003", "F-900-003 shows periodic HTTP.")
    assert r["persist_refused"] is True


# ── B9: Phase-5 adversarial redaction ──────────────────────────────────

@pytest.mark.parametrize("tok", ["_T1003.006_", "T 1003.006", "Т1003.006", "T  1003.006",
                                 "T-1003.006", "ᴛ1003.006"])
def test_b9_adversarial_mitre_evasions_redacted(make_case, tok):
    from spectre.core import explain as ex
    c = make_case()
    r = ex.ingest_host_adversarial([], [], {
        "counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
        "evidence_gaps": [f"F-900-001 may instead be {tok} DCSync."]}, str(c))
    assert "1003" not in str(r["evidence_gaps"])


def test_b9_adversarial_allowed_subtechnique_kept(make_case):
    from spectre.core import explain as ex
    c = make_case()
    r = ex.ingest_host_adversarial([], [], {
        "counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
        "evidence_gaps": ["F-900-001 T1071.001 could be benign polling."]}, str(c))
    assert "T1071.001" in r["evidence_gaps"][0]
