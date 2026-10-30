"""W2-1 / W2-2 (R2-01, R2-02, R2-03, R2-17): per-rule MITRE allowlist at every
AI seam, and host-ingest entry points that take their validator inputs from
config / disk only — never from the caller.

Principle under test: the deterministic layer owns MITRE. The model may
narrow within the finding's own emitted set and never widen it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from spectre.config import FK_NETWORK_DIR, MITRE_MAP_PATH
from spectre.core import explain as explain_mod
from spectre.core import validators
from spectre.pipeline.emit_finding import emit_from_handle

MITRE_MAP = yaml.safe_load(MITRE_MAP_PATH.read_text())
RULES = MITRE_MAP["rules"]
PCAP_FK = str(FK_NETWORK_DIR / "pcap.yaml")


@pytest.fixture(autouse=True)
def _no_journal(monkeypatch):
    monkeypatch.setenv("SPECTRE_AUDIT_JOURNAL_ANCHOR", "0")


@pytest.fixture
def case_dir(tmp_path):
    d = tmp_path / "882-w2a"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (d / sub).mkdir(parents=True)
    return d


def _emit(case_dir: Path, n: int, rule_id: str, mitre: list[str] | None,
          iocs: dict | None = None, tools=("zeek/pcap_conn",)) -> dict:
    handle = {"execution_id": f"exec-{n}", "tool": "zeek", "tool_version": "8",
              "path": "raw", "line_count": 1, "size_bytes": 10,
              "exact_command": "zeek -r x"}
    return emit_from_handle(
        handle=handle, case_dir=str(case_dir), finding_number=n,
        fk_yaml_path=PCAP_FK, mitre_map_path=str(MITRE_MAP_PATH),
        rule_id=rule_id, title=f"{rule_id} finding",
        iocs=iocs or {"ip": ["10.0.0.5"], "domain": []},
        mitre=mitre, corroboration_labels=list(tools),
    )


def _fpath(case_dir: Path, finding: dict) -> str:
    return str(case_dir / "findings" / f"{finding['finding_id']}.yaml")


def _host_json(fid: str, mitre: str, caveats=None) -> dict:
    return {"description": f"Finding {fid} records the flagged connection.",
            "mitre_attack": mitre, "caveats": caveats or [],
            "next_evidence": []}


# ── helper: allowed_mitre_for_finding ────────────────────────────────────

def test_allowed_is_rule_allowed_intersect_emitted(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    assert validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir) == ["T1071.001"]


def test_allowed_uses_emitted_subset_of_multi_technique_rule(case_dir):
    f = _emit(case_dir, 1, "pcap-c2-protocol", ["T1573.001"])
    # T1071.001 is in the rule's list but the deterministic finding never
    # asserted it — the model may not widen to it.
    assert validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir) == ["T1573.001"]


def test_no_map_entry_rule_only_unmapped(case_dir):
    for n, rid in enumerate(("sigma-some-imported-rule", "dir-001"), start=1):
        f = _emit(case_dir, n, rid, ["T1059"])
        assert f["mitre_attack"] == "UNMAPPED"
        assert validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir) == []


def test_legacy_finding_rule_id_from_audit(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    assert "rule_id" not in f  # resolved via the chained finding_create row
    assert validators.rule_id_for_finding(f, case_dir) == "pcap-beacon"


def test_no_rule_id_resolvable_gives_empty(case_dir):
    f = {"finding_id": "F-882-050", "mitre_attack": "T1071.001"}
    assert validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir) == []


def test_parse_mitre_ids_handles_lists_and_case():
    assert validators.parse_mitre_ids("T1071.001, t1573.001") == ["T1071.001", "T1573.001"]
    assert validators.parse_mitre_ids("UNMAPPED") == ["UNMAPPED"]
    assert validators.parse_mitre_ids("") == []
    assert validators.parse_mitre_ids(None) == []


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_rejects_foreign_ids_accepts_own(rule_id):
    own = RULES[rule_id].get("allowed", [])
    finding = {"finding_id": "F-1-001", "rule_id": rule_id,
               "mitre_attack": ", ".join(own) if own else "UNMAPPED"}
    allowed = validators.allowed_mitre_for_finding(finding, MITRE_MAP)
    assert set(allowed) == set(own)
    foreign = sorted({t for r in RULES.values() for t in r.get("allowed", [])} - set(own))
    # Echoing the finding's own value is accepted without a violation.
    cleaned, v = explain_mod._validate_output(
        _host_json("F-1-001", finding["mitre_attack"]), finding, [], allowed, "F-1-001")
    assert cleaned["mitre_attack"] == finding["mitre_attack"]
    assert not any("mitre_attack" in x for x in v)
    for tid in foreign[:10]:
        cleaned, v = explain_mod._validate_output(
            _host_json("F-1-001", tid), finding, [], allowed, "F-1-001")
        assert cleaned["mitre_attack"] == finding["mitre_attack"]
        assert any(tid in x for x in v)


# ── explain seam (host path) — R2-01 PoC ─────────────────────────────────

@pytest.mark.parametrize("bad", ["T1573.001", "T1003.006", "t1003.006"])
def test_host_ingest_rejects_out_of_rule_mitre_and_keeps_deterministic(case_dir, bad):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    res = explain_mod.ingest_host_output(
        _fpath(case_dir, f), PCAP_FK, str(MITRE_MAP_PATH), str(case_dir),
        _host_json(f["finding_id"], bad))
    assert any("not in allowed set" in v for v in res["violations"])
    assert res["output"]["mitre_attack"] == "T1071.001"
    persisted = yaml.safe_load(Path(_fpath(case_dir, f)).read_text())
    assert persisted["mitre_attack"] == "T1071.001"


def test_explain_multi_technique_preserved(case_dir):
    f = _emit(case_dir, 1, "pcap-c2-protocol", ["T1071.001", "T1573.001"])
    assert f["mitre_attack"] == "T1071.001, T1573.001"
    # Review round 2: the model can never narrow either — the deterministic
    # list is always persisted; echo variants (case, order) are not invented.
    for echoed in ("T1071.001, T1573.001", "t1573.001, T1071.001", "T1573.001"):
        allowed = validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir)
        cleaned, v = explain_mod._validate_output(
            _host_json(f["finding_id"], echoed), f, [], allowed, f["finding_id"])
        assert cleaned["mitre_attack"] == "T1071.001, T1573.001", (echoed, v)
        assert not any("allowed set" in x for x in v)


def test_model_cannot_erase_deterministic_mitre_to_unmapped(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    allowed = validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir)
    cleaned, v = explain_mod._validate_output(
        _host_json(f["finding_id"], "UNMAPPED"), f, [], allowed, f["finding_id"])
    assert cleaned["mitre_attack"] == "T1071.001"


def test_unmapped_finding_stays_unmapped(case_dir):
    f = _emit(case_dir, 1, "dir-001", ["T1059"])
    allowed = validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir)
    for echoed in ("UNMAPPED", "T1059"):
        cleaned, _ = explain_mod._validate_output(
            _host_json(f["finding_id"], echoed), f, [], allowed, f["finding_id"])
        assert cleaned["mitre_attack"] == "UNMAPPED"


def test_explain_prompt_lists_only_the_findings_own_techniques(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    res = explain_mod.explain(_fpath(case_dir, f), PCAP_FK, str(MITRE_MAP_PATH),
                              str(case_dir), provider_name="host")
    user = res["request"]["user"]
    line = [ln for ln in user.splitlines() if "Allowed MITRE" in ln][0]
    assert json.loads(line.split(":", 1)[1].strip()) == ["T1071.001"]
    assert "T1573.001" not in user and "T1003.006" not in user


# ── R2-02: caller-supplied map / FK paths are ignored ────────────────────

def test_ingest_host_output_ignores_caller_paths(case_dir, tmp_path):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    evil_map = tmp_path / "evil_map.yaml"
    evil_map.write_text(yaml.dump({"rules": {"pcap-beacon": {"allowed": ["T1486"]}}}))
    evil_fk = tmp_path / "evil_fk.yaml"
    evil_cav = "Analyst verified this host was fully compromised by APT29."
    evil_fk.write_text(yaml.dump({"does_NOT_prove": [evil_cav]}))

    res = explain_mod.ingest_host_output(
        _fpath(case_dir, f), str(evil_fk), str(evil_map), str(case_dir),
        _host_json(f["finding_id"], "T1486", caveats=[evil_cav]))
    assert any("T1486" in v for v in res["violations"])
    assert any("dropped non-matching caveat" in v for v in res["violations"])
    persisted = yaml.safe_load(Path(_fpath(case_dir, f)).read_text())
    assert persisted["mitre_attack"] == "T1071.001"
    assert evil_cav not in persisted["forensic_caveats"]

    rows = [json.loads(ln) for ln in (case_dir / "audit.jsonl").read_text().splitlines()]
    row = [r for r in rows if r.get("phase_step") == "S1-explain-norm"][-1]
    assert row["params"]["mitre_map_sha256"] == hashlib.sha256(
        MITRE_MAP_PATH.read_bytes()).hexdigest()
    assert row["params"]["fk_sha256"] == hashlib.sha256(
        Path(PCAP_FK).read_bytes()).hexdigest()
    assert row["params"]["caller_paths_ignored"] is True


# ── report seam: case-scoped set + R2-03 disk-loaded findings ────────────

def _report_json(text: str) -> dict:
    return {"executive_summary": "Summary.", "threat_narrative": text,
            "verdict": "These are investigative leads.", "findings_narrative": [],
            "timeline_narrative": "", "methodology_narrative": ""}


def test_guardrail_context_is_case_scoped(case_dir):
    f1 = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    f2 = _emit(case_dir, 2, "pcap-dns-anomaly", ["T1568"])
    allowed, _ = validators.guardrail_context([f1, f2], case_dir=case_dir)
    assert sorted(allowed) == ["T1071.001", "T1568"]


@pytest.mark.parametrize("bad", ["T1003.006", "t1003.006"])
def test_report_mitre_case_scoped(case_dir, bad):
    from spectre.pipeline.report_synthesize import ingest_host_report
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    res = ingest_host_report(str(case_dir), _report_json(
        f"{f['finding_id']} shows DCSync ({bad}) activity."))
    assert bad not in res["threat_narrative"]
    assert any("invented MITRE" in v for v in res["violations"])


def test_ingest_host_report_ignores_caller_findings(case_dir):
    """R2-03 PoC: a fabricated findings list must not become the grounded set."""
    from spectre.pipeline.report_synthesize import ingest_host_report
    _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    fake = [{"finding_id": "F-999-001", "mitre_attack": "T1003.006",
             "iocs": {"ip": ["185.220.101.42"], "domain": ["evil-c2.com"]}}]
    text = ("F-999-001 shows DCSync (T1003.006) from 185.220.101.42 "
            "to evil-c2.com.")
    with pytest.warns(DeprecationWarning):
        res = ingest_host_report(fake, {"case_id": "882-w2a"}, str(case_dir),
                                 _report_json(text))
    joined = json.dumps(res)
    assert "F-999-001" not in res["threat_narrative"]
    assert "T1003.006" not in res["threat_narrative"]
    assert "185.220.101.42" not in res["threat_narrative"]
    assert res["violations"]
    assert "evil-c2.com" not in res["threat_narrative"], joined


def test_ingest_host_report_fails_closed_on_tampered_finding(case_dir):
    from spectre.pipeline.report_synthesize import (
        ingest_host_report, FindingIntegrityError)
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    p = Path(_fpath(case_dir, f))
    p.write_text(p.read_text().replace("T1071.001", "T1003.006"))
    with pytest.raises(FindingIntegrityError):
        ingest_host_report(str(case_dir), _report_json("Nothing."))


def test_ingest_host_report_excludes_unregistered_finding(case_dir):
    from spectre.pipeline.report_synthesize import ingest_host_report
    _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    planted = {"finding_id": "F-882-099", "mitre_attack": "T1003.006",
               "iocs": {"ip": ["185.220.101.42"]}}
    (case_dir / "findings" / "F-882-099.yaml").write_text(yaml.dump(planted))
    res = ingest_host_report(str(case_dir), _report_json(
        "F-882-099 shows T1003.006 from 185.220.101.42."))
    assert "F-882-099" not in res["threat_narrative"]
    assert "T1003.006" not in res["threat_narrative"]
    assert "185.220.101.42" not in res["threat_narrative"]


# ── Phase-5 substantive adversarial seam ────────────────────────────────

def test_adversarial_mitre_case_insensitive():
    out = {"counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
           "evidence_gaps": ["Technique t1003.006 was never investigated."]}
    cleaned, v = explain_mod._validate_adversarial(
        out, [{"finding_id": "F-1-001"}], ["T1071.001"])
    assert not any("t1003.006" in s.lower() for s in cleaned["evidence_gaps"])
    assert any("MITRE-REDACTED" in s for s in cleaned["evidence_gaps"])


def test_phase5_substantive_uses_case_scoped_set(case_dir):
    from spectre.pipeline.phase_runner import _run_substantive_adversarial
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    res = _run_substantive_adversarial(str(case_dir), [f], {"evidence": []},
                                       provider_name="host")
    assert res["status"] == "deferred-to-host"
    assert res["ingest"]["allowed_mitre"] == ["T1071.001"]


def test_ingest_host_adversarial_ignores_caller_allowed(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    out = {"counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
           "evidence_gaps": ["Technique T1003.006 was never investigated."]}
    res = explain_mod.ingest_host_adversarial(
        [f], ["T1003.006"], out, str(case_dir))
    assert not any("T1003.006" in s for s in res["evidence_gaps"])


# ════ Review round 2 (W2A-REVIEW.md) ════════════════════════════════════

def _plant(case_dir: Path, fid="F-882-099", rule_id="prefetch-suspicious-execution",
           mitre="T1003.001") -> Path:
    forged = {"finding_id": fid, "rule_id": rule_id, "mitre_attack": mitre,
              "title": "forged", "forensic_caveats": [],
              "iocs": {"ip": ["185.220.101.42"], "domain": ["evil-c2.com"]},
              "corroboration": {"tools": ["zeek/pcap_conn"]}}
    fp = case_dir / "findings" / f"{fid}.yaml"
    fp.write_text(yaml.dump(forged))
    return fp


def test_forged_finding_not_laundered_via_ingest_host_output(case_dir):
    """Review PoC C: a planted F-*.yaml must not become 'registered' by
    running it through ingest_host_output."""
    from spectre.pipeline import audit
    from spectre.pipeline.report_synthesize import ingest_host_report
    _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    fp = _plant(case_dir)
    before = fp.read_bytes()
    res = explain_mod.ingest_host_output(
        str(fp), None, None, str(case_dir),
        {"description": "F-882-099 records it.", "mitre_attack": "T1003.001",
         "caveats": [], "next_evidence": []})
    assert res["persist_refused"] is True
    assert fp.read_bytes() == before
    fs, unreg = validators.load_verified_findings(case_dir)
    assert "F-882-099" in unreg
    assert "F-882-099" not in [f["finding_id"] for f in fs]
    r = ingest_host_report(str(case_dir), _report_json(
        "F-882-099 shows T1003.001 from 185.220.101.42 to evil-c2.com."))
    for bad in ("F-882-099", "T1003.001", "185.220.101.42", "evil-c2.com"):
        assert bad not in r["threat_narrative"]
    vf = audit.verify_full(str(case_dir))
    assert vf["checks"]["finding_integrity"]["passed"] is False


def test_generic_row_cannot_bless_an_edit(case_dir):
    """R2-13: only emit/explain authority rows are hash baselines."""
    from spectre.pipeline import audit
    from spectre.pipeline.audit import append as audit_append
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    p = Path(_fpath(case_dir, f))
    p.write_text(p.read_text().replace("INFERRED", "CONFIRMED"))
    audit_append(str(case_dir), {
        "actor": "anyone", "action": "note", "tool": "x", "phase": 3,
        "phase_step": "whatever", "finding_id": f["finding_id"],
        "output_path": str(p),
        "output_sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    with pytest.raises(validators.FindingIntegrityError):
        validators.load_verified_findings(case_dir)
    vf = audit.verify_full(str(case_dir))
    assert vf["checks"]["finding_integrity"]["passed"] is False


def test_rule_id_only_from_audit_when_case_dir_known(case_dir):
    fp = _plant(case_dir)
    f = yaml.safe_load(fp.read_text())
    assert validators.rule_id_for_finding(f, case_dir) is None
    assert validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir) == []


@pytest.mark.parametrize("variant", [
    "T１００３.００６", "Ｔ１００３.００６", "T1003​.006", "T1003­.006",
    "T 1003.006", "T1003．006"])
def test_report_fullwidth_and_hidden_char_mitre_stripped(case_dir, variant):
    import unicodedata
    from spectre.pipeline.report_synthesize import ingest_host_report
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    r = ingest_host_report(str(case_dir), _report_json(
        f"{f['finding_id']} shows DCSync ({variant})."))
    norm = unicodedata.normalize("NFKC", r["threat_narrative"])
    norm = "".join(c for c in norm if unicodedata.category(c) != "Cf")
    assert "1003" not in norm
    assert any("MITRE" in v for v in r["violations"])


def test_report_parent_id_strip_does_not_corrupt_subtechnique(case_dir):
    from spectre.pipeline.report_synthesize import ingest_host_report
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    r = ingest_host_report(str(case_dir), _report_json(
        f"{f['finding_id']} beacon T1071.001; parent T1071."))
    assert "T1071.001" in r["threat_narrative"]
    assert "UNMAPPED.001" not in r["threat_narrative"]


def test_adversarial_uses_disk_findings_only(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    fake = [f, {"finding_id": "F-882-777", "rule_id": "pcap-c2-protocol",
                "mitre_attack": "T1573.001", "iocs": {"ip": ["185.220.101.42"]}}]
    out = {"counter_hypotheses": [{"finding_id": "F-882-777",
                                   "alternative": "Traffic to 185.220.101.42 is C2."}],
           "citation_gaps": [], "alternative_timeline": [], "evidence_gaps": []}
    res = explain_mod.ingest_host_adversarial(fake, [], out, str(case_dir))
    assert res["counter_hypotheses"] == []


def test_adversarial_empty_disk_trusts_nothing(tmp_path):
    d = tmp_path / "883-empty"
    (d / "findings").mkdir(parents=True)
    fake = [{"finding_id": "F-883-777", "rule_id": "lsass-dump",
             "mitre_attack": "T1003.001", "iocs": {"ip": ["185.220.101.42"]}}]
    out = {"counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
           "evidence_gaps": ["DCSync T1003.001 was never examined."]}
    res = explain_mod.ingest_host_adversarial(fake, ["T1003.001"], out, str(d))
    assert not any("T1003.001" in s for s in res["evidence_gaps"])


def test_ingest_host_report_legacy_mixed_call(case_dir):
    from spectre.pipeline.report_synthesize import ingest_host_report
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    with pytest.warns(DeprecationWarning):
        r = ingest_host_report([{"finding_id": "F-9-9"}], {}, case_dir=str(case_dir),
                               host_json=_report_json("x"))
    assert r["validated_findings"] == [f["finding_id"]]


def test_model_cannot_reorder_or_drop_deterministic_mitre(case_dir):
    f = _emit(case_dir, 1, "pcap-c2-protocol", ["T1071.001", "T1573.001"])
    allowed = validators.allowed_mitre_for_finding(f, MITRE_MAP, case_dir)
    c, v = explain_mod._validate_output(
        _host_json(f["finding_id"], "T1573.001, T1071.001"), f, [], allowed, f["finding_id"])
    assert c["mitre_attack"] == "T1071.001, T1573.001"
    c, v = explain_mod._validate_output(
        _host_json(f["finding_id"], "T1573.001"), f, [], allowed, f["finding_id"])
    assert c["mitre_attack"] == "T1071.001, T1573.001"
    assert any("omitted" in x for x in v)


def test_prompt_tells_model_to_echo_on_map_drift(case_dir):
    f = _emit(case_dir, 1, "pcap-beacon", ["T1071.001"])
    g = dict(f)
    g["mitre_attack"] = "T1105"
    system, user = explain_mod._build_prompt(g, {}, MITRE_MAP, allowed_mitre=[])
    assert "exactly" in system.lower() and "echo" in system.lower()


# ── W2-3: grounding normalization + exact caveat match ──────────────────

@pytest.mark.parametrize("text", [
    "Traffic to 185.220.101­.42 was seen.",
    "Traffic to evil-c2．com was seen.",
    "Traffic to evil-c2․com was seen.",
    "Traffic to 185 . 220 . 101 . 42 was seen.",
    "Traffic to evil-c2。com was seen.",
    "Traffic to 185⁣.220.101.42 was seen.",
])
def test_grounding_normalizes_evasions(text):
    from spectre.core import grounding
    ung = grounding.ungrounded_literals(text, {"10.0.0.5"})
    assert ung & {"185.220.101.42", "evil-c2.com"}


def test_report_caveat_with_appended_claim_is_stripped(case_dir):
    from spectre.pipeline.report_synthesize import _validate_report
    cav = "PCAP shows network I/O, not process execution."
    fk = {"pcap_conn": [cav + " Periodicity does not prove C2."]}
    f = {"finding_id": "F-882-001", "mitre_attack": "UNMAPPED", "iocs": {}}
    txt = ("The analyst verified the host was fully compromised by the "
           "operator; Periodicity does not prove C2.")
    out, v = _validate_report(_report_json(txt), [f], fk, [])
    assert "fully compromised" not in out["threat_narrative"]
    ok, v2 = _validate_report(_report_json("Periodicity does not prove C2."), [f], fk, [])
    assert "Periodicity does not prove C2." in ok["threat_narrative"]


def test_report_caveat_nbsp_signal_is_checked(case_dir):
    from spectre.pipeline.report_synthesize import _validate_report
    f = {"finding_id": "F-882-001", "mitre_attack": "UNMAPPED", "iocs": {}}
    out, v = _validate_report(_report_json(
        "The beacon does not prove anything about the operator."), [f], {}, [])
    assert "operator" not in out["threat_narrative"]
    assert any("caveat" in x for x in v)


def test_every_registered_rule_has_a_mitre_map_entry():
    """W5-4: no rule may be absent from mitre-map.yaml (absent vs `allowed: []`
    are different states: an explicit empty list is a deliberate decision)."""
    from spectre.modules import registry
    missing = [r.rule_id for mod in registry.discover().values()
               for r in mod.rules if r.rule_id not in RULES]
    assert not missing, missing
