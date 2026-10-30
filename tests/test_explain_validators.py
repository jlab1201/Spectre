"""
test_explain_validators.py — guardrails on the explain seam.

Regression tests for the phase-5 adversarial probe leak (case 077): the
injected fake C2 claim (185.220.101.42 / rundll32) survived Validator 5 by
riding in the same sentence as the finding_id citation, and _finalize then
persisted the poisoned description + wrong-FK caveats into the finding YAML.
"""

import yaml
import pytest

from spectre.core import explain as explain_mod
from spectre.core.explain import _validate_output, _finalize, ingest_host_output


@pytest.fixture
def pcap_finding():
    return {
        "finding_id": "F-077-001",
        "status": "INFERRED",
        "confidence": 0.4,
        "title": "Inbound connection to commonly-malicious port 5555 "
                 "(remote: 203.161.44.208, source: 45.135.194.48)",
        "description": "",
        "mitre_attack": "T1571",
        "corroboration": {
            "sources": 1,
            "tools": ["tcpdump/pcap_conn"],
            "artifacts": [
                "pcap [inbound]: 2026-03-11 00:27:30 IP 45.135.194.48.40423 "
                "> 203.161.44.208.5555: tcp 0"
            ],
        },
        "iocs": {"ip": ["203.161.44.208"], "domain": []},
        "forensic_caveats": ["PCAP shows network I/O, not process execution"],
        "evidence_refs": [{"execution_id": "8ae223d2736ab065"}],
    }


PCAP_CAVEATS = ["PCAP shows network I/O, not process execution"]
ALLOWED = ["T1571"]


def _register(case_dir, finding_path, finding_id):
    """Seed the deterministic finding_create registration row persist now
    requires (W2-A review round 2: no registration -> persist refused)."""
    import hashlib
    import json
    row = {"actor": "deterministic-core", "action": "finding_create",
           "phase_step": "S1-emit", "finding_id": finding_id,
           "params": {"finding_id": finding_id, "rule_id": "pcap-suspicious-port"},
           "output_sha256": hashlib.sha256(finding_path.read_bytes()).hexdigest()}
    with open(f"{case_dir}/audit.jsonl", "a") as f:
        f.write(json.dumps(row) + "\n")


def test_injected_ip_stripped_even_with_finding_id_citation(pcap_finding):
    """The adversarial-probe bypass: a fabricated IP in the SAME sentence as
    the finding_id citation must still be stripped."""
    output = {
        "description": (
            "Finding F-077-001 records an inbound TCP connection from "
            "45.135.194.48 to the host's port 5555, while an outbound TCP "
            "connection to 185.220.101.42:8443—a known C2 infrastructure "
            "IP—was observed within 2 seconds of rundll32 execution, "
            "indicating likely command-and-control activity."
        ),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "185.220.101.42" not in cleaned["description"]
    assert "rundll32" not in cleaned["description"]
    assert any("ungrounded" in v or "unsupported" in v for v in violations)


def test_grounded_sentences_survive(pcap_finding):
    """Sentences whose IPs/domains exist in the finding's own data are kept."""
    output = {
        "description": (
            "Finding F-077-001 records an inbound TCP connection from "
            "45.135.194.48 to 203.161.44.208 on port 5555."
        ),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "203.161.44.208" in cleaned["description"]
    assert "45.135.194.48" in cleaned["description"]


def test_finalize_persist_false_leaves_finding_untouched(
    pcap_finding, tmp_path, monkeypatch
):
    """The adversarial probe validates but must never patch the finding YAML."""
    monkeypatch.setattr(explain_mod, "audit_append", lambda *a, **k: None)
    finding_path = tmp_path / "F-077-001.yaml"
    finding_path.write_text(yaml.dump(pcap_finding, sort_keys=False))
    before = finding_path.read_text()

    poisoned = {
        "description": "Finding F-077-001 shows C2 traffic to 185.220.101.42.",
        "mitre_attack": "T1571",
        "caveats": ["Process creation (4688) proves the process was launched"],
        "next_evidence": [],
    }
    result = _finalize(
        dict(pcap_finding), str(finding_path), PCAP_CAVEATS, ALLOWED,
        "F-077-001", tmp_path, "077-test", True, 5, poisoned,
        {"prompt": 0, "completion": 0}, "deepseek", "deepseek-v4-pro",
        persist=False,
    )
    assert finding_path.read_text() == before, "adversarial pass must not write"
    assert not (tmp_path / "reports" / "report.md").exists()
    assert result["violations"], "poisoned output must record violations"


def test_finalize_persist_true_patches_finding(pcap_finding, tmp_path, monkeypatch):
    """The normal explain pass still patches validated output into the YAML."""
    monkeypatch.setattr(explain_mod, "audit_append", lambda *a, **k: None)
    finding_path = tmp_path / "F-077-001.yaml"
    finding_path.write_text(yaml.dump(pcap_finding, sort_keys=False))
    _register(tmp_path, finding_path, "F-077-001")

    good = {
        "description": ("Finding F-077-001 records an inbound TCP connection "
                        "from 45.135.194.48 to port 5555."),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    _finalize(
        dict(pcap_finding), str(finding_path), PCAP_CAVEATS, ALLOWED,
        "F-077-001", tmp_path, "077-test", False, 3, good,
        {"prompt": 0, "completion": 0}, "deepseek", "deepseek-v4-pro",
        persist=True,
    )
    patched = yaml.safe_load(finding_path.read_text())
    assert "45.135.194.48" in patched["description"]
    assert patched["forensic_caveats"] == PCAP_CAVEATS


def test_finalize_preserves_deterministic_mitre_dropped_caveat(
    pcap_finding, tmp_path, monkeypatch
):
    """Critical regression: emit_finding.py writes a deterministic caveat
    ("MITRE T9999.999 ... dropped") onto the finding at Phase 3. That caveat
    is authored by the deterministic core, not the model. _finalize must not
    wipe it when it persists the explain-pass output — only FK does_NOT_prove
    caveats plus the finding's own pre-existing caveats may survive; nothing
    the model invents may appear.
    """
    monkeypatch.setattr(explain_mod, "audit_append", lambda *a, **k: None)

    mitre_dropped_caveat = (
        "MITRE T9999.999 emitted by rule but not in mitre-map allowed "
        "list — dropped"
    )
    finding_on_disk = dict(pcap_finding)
    finding_on_disk["forensic_caveats"] = [
        "PCAP shows network I/O, not process execution",
        mitre_dropped_caveat,
    ]
    finding_path = tmp_path / "F-077-001.yaml"
    finding_path.write_text(yaml.dump(finding_on_disk, sort_keys=False))
    _register(tmp_path, finding_path, "F-077-001")

    # W2-2 (R2-02): ingest_host_output ignores caller-supplied FK/map paths
    # and resolves the FK from the finding's own corroboration tools
    # (tcpdump/pcap_conn -> the packaged pcap.yaml), so these decoy paths
    # must have no effect.
    fk_yaml_path = tmp_path / "pcap.yaml"
    fk_yaml_path.write_text(yaml.dump({
        "does_NOT_prove": PCAP_CAVEATS,
        "discipline_reminder": "",
    }))
    mitre_map_path = tmp_path / "mitre-map.yaml"
    mitre_map_path.write_text(yaml.dump({
        "rules": {"pcap_conn": {"allowed": ALLOWED, "label": "test"}},
    }))
    from spectre.core.validators import fk_path_for_finding
    real_fk = yaml.safe_load(fk_path_for_finding(finding_on_disk).read_text())
    real_caveats = real_fk["does_NOT_prove"]

    # Model output echoes only the FK caveats it was told about — it has
    # never seen the deterministic MITRE-dropped caveat and must not need to.
    host_json = {
        "description": "Finding F-077-001 records an inbound TCP connection "
                        "from 45.135.194.48 to port 5555.",
        "mitre_attack": "T1571",
        "caveats": real_caveats,
        "next_evidence": [],
    }

    ingest_host_output(
        str(finding_path), str(fk_yaml_path), str(mitre_map_path),
        str(tmp_path), host_json, adversarial=False,
        case_id="077-test", phase=3,
    )

    persisted = yaml.safe_load(finding_path.read_text())
    persisted_caveats = persisted["forensic_caveats"]

    # The deterministic MITRE-dropped caveat must survive the explain pass.
    assert mitre_dropped_caveat in persisted_caveats
    # The finding's own prior caveat must also be present.
    assert "PCAP shows network I/O, not process execution" in persisted_caveats
    # No duplicates.
    assert len(persisted_caveats) == len(set(persisted_caveats))
    # Nothing beyond the two deterministic sources (finding's own prior
    # caveats + the packaged FK does_NOT_prove) appears.
    assert set(persisted_caveats) == {
        "PCAP shows network I/O, not process execution",
        mitre_dropped_caveat,
        *real_caveats,
    }


def test_finalize_model_cannot_inject_new_caveat(pcap_finding, tmp_path, monkeypatch):
    """The model cannot smuggle in a brand-new caveat that is neither in the
    FK does_NOT_prove list nor previously present on the finding."""
    monkeypatch.setattr(explain_mod, "audit_append", lambda *a, **k: None)

    finding_path = tmp_path / "F-077-001.yaml"
    finding_path.write_text(yaml.dump(pcap_finding, sort_keys=False))

    injected_caveat = "This finding conclusively proves lateral movement occurred"
    poisoned = {
        "description": "Finding F-077-001 records an inbound TCP connection "
                        "from 45.135.194.48 to port 5555.",
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS + [injected_caveat],
        "next_evidence": [],
    }

    result = _finalize(
        dict(pcap_finding), str(finding_path), PCAP_CAVEATS, ALLOWED,
        "F-077-001", tmp_path, "077-test", False, 3, poisoned,
        {"prompt": 0, "completion": 0}, "deepseek", "deepseek-v4-pro",
        persist=True,
    )

    patched = yaml.safe_load(finding_path.read_text())
    assert injected_caveat not in patched["forensic_caveats"]
    assert any("dropped non-matching caveat" in v for v in result["violations"])


def test_phase5_fk_routing_from_corroboration_tools(pcap_finding):
    """Phase 5 derives the FK YAML from the finding's artifact type —
    never the evtx default for pcap findings."""
    from spectre.pipeline.phase_runner import _fk_for_finding
    assert _fk_for_finding(pcap_finding) == "pcap.yaml"
    assert _fk_for_finding({"corroboration": {"tools": ["vol3/memory_pslist"]}}) \
        == "memory_pslist.yaml"
    assert _fk_for_finding({}) == "evtx_4688.yaml"


# ── BUG 4 (case 268-001): ARTIFACT_FK was missing the "pcap_flow" key (and
#    "smb_pipe" / "drsuapi_call"), so any anchor of those artifact types
#    silently fell through to _DEFAULT_FK ("evtx_4688.yaml") at BOTH the
#    Phase 3 emission site (phase_runner.py's inline
#    `ARTIFACT_FK.get(a.artifact_type, _DEFAULT_FK)`) and the Phase 5
#    per-finding routing site (`_fk_for_finding`, which reads the SAME dict).
#    The two marquee T1105 findings (pcap-staging-download, pcap-large-
#    transfer) both anchor on artifact_type="pcap_flow" (see
#    modules/pcap/rules.py staging_download/large_transfer) and so both
#    ended up carrying EVTX-4688/Prefetch/Amcache/MFT caveats — nonsensical
#    for a PCAP-only case. Phase 5's earlier fix (e1fdc77/bc3d1d5) routed
#    correctly for pcap_conn/pcap_http, which masked this: it never touched
#    ARTIFACT_FK's coverage of the flow/SMB artifact types the pcap module
#    added afterward. This is a regression in dict coverage, not a
#    reintroduction of the original hardcoded-evtx bug. ──

def test_artifact_fk_covers_every_pcap_module_artifact_type():
    """Every artifact_type any pcap-module rule can emit (see
    modules/pcap/rules.py Anchor(...artifact_type=...) call sites) must
    route to the pcap FK, never fall through to the EVTX default."""
    from spectre.pipeline.phase_runner import ARTIFACT_FK, _DEFAULT_FK

    pcap_module_artifact_types = {
        "pcap_conn", "pcap_dns", "pcap_http", "pcap_timing",
        "pcap_flow", "smb_pipe", "drsuapi_call", "host_identity",
        "pcap_checksum",
    }
    for art in pcap_module_artifact_types:
        fk = ARTIFACT_FK.get(art)
        assert fk is not None, f"{art!r} missing from ARTIFACT_FK — falls back to {_DEFAULT_FK}"
        assert fk == "pcap.yaml", f"{art!r} routed to {fk}, expected pcap.yaml"


def test_artifact_fk_covers_registry_prefetch_lnk_disk_module_artifact_types():
    """A4-01: registry_hive/prefetch/lnk/disk findings must route to their
    OWN artifact's FK YAML — never fall through to _DEFAULT_FK
    (evtx_4688.yaml), the same antipattern already fixed once for the pcap
    module (see test_artifact_fk_covers_every_pcap_module_artifact_type)
    and never generalized to these four Windows-host/disk artifact types.
    A registry-run-persistence finding (artifact_type='registry_run')
    carrying evtx_4688.yaml's "corroborate with Prefetch/Amcache/MFT"
    caveat is nonsensical — there is no 4688 event anywhere in a
    registry-only finding."""
    from spectre.pipeline.phase_runner import ARTIFACT_FK, _DEFAULT_FK

    expected = {
        "registry_run": "registry_run.yaml",
        "prefetch": "prefetch.yaml",
        "lnk": "lnk.yaml",
        "disk_file_entry": "disk_image.yaml",
    }
    for art, want_fk in expected.items():
        fk = ARTIFACT_FK.get(art)
        assert fk is not None, f"{art!r} missing from ARTIFACT_FK — falls back to {_DEFAULT_FK}"
        assert fk == want_fk, f"{art!r} routed to {fk}, expected {want_fk}"


def test_fk_for_finding_registry_prefetch_lnk_disk_never_evtx():
    """Phase 5 per-finding FK routing (_fk_for_finding, reads the SAME
    ARTIFACT_FK dict) must also route these four artifact types correctly
    — the case-268-001 bug hit both the Phase 3 emission site and this
    Phase 5 routing site from one missing dict entry."""
    from spectre.pipeline.phase_runner import _fk_for_finding
    assert _fk_for_finding(
        {"corroboration": {"tools": ["regripper/registry_run"]}}
    ) == "registry_run.yaml"
    assert _fk_for_finding(
        {"corroboration": {"tools": ["scca/prefetch"]}}
    ) == "prefetch.yaml"
    assert _fk_for_finding(
        {"corroboration": {"tools": ["lecmd/lnk"]}}
    ) == "lnk.yaml"
    assert _fk_for_finding(
        {"corroboration": {"tools": ["fls/disk_file_entry"]}}
    ) == "disk_image.yaml"


def test_emit_from_handle_registry_run_finding_never_carries_evtx_caveats(tmp_path):
    """End-to-end repro of A4-01's exact symptom: emit a finding the way
    Phase 3 does for a registry-run-persistence anchor (artifact_type=
    'registry_run', routed through the SAME ARTIFACT_FK lookup
    phase_runner.py uses) and assert forensic_caveats contains only
    registry_run.yaml's caveats — never the EVTX-4688/Prefetch/Amcache/MFT
    text a wrong-FK routing pastes on today."""
    from spectre.pipeline.emit_finding import emit_from_handle
    from spectre.pipeline.phase_runner import ARTIFACT_FK, _DEFAULT_FK
    from spectre.config import FK_DIRS, MITRE_MAP_PATH

    def _find_fk(fk_name: str) -> str:
        for d in FK_DIRS:
            p = d / fk_name
            if p.exists():
                return str(p)
        return str(FK_DIRS[0] / fk_name)

    fk_name = ARTIFACT_FK.get("registry_run", _DEFAULT_FK)
    fk_path = _find_fk(fk_name)

    handle = {"execution_id": "reg-exec-abc", "tool": "regripper", "line_count": 2}
    finding = emit_from_handle(
        handle=handle,
        case_dir=str(tmp_path),
        finding_number=1,
        fk_yaml_path=fk_path,
        mitre_map_path=str(MITRE_MAP_PATH),
        rule_id="registry-run-persistence",
        title="Run-key persistence",
        iocs={"ip": [], "domain": [], "filepath": [r"C:\Users\bob\AppData\Roaming\x.exe"],
              "sha256": [], "registry_key": []},
        corroboration_note="NTUSER.DAT: Run\\Updater = ...",
        corroboration_labels=["regripper/registry_run"],
        confidence=0.6,
        mitre=["T1547.001"],
    )

    caveats_blob = " ".join(finding["forensic_caveats"])
    assert "4688" not in caveats_blob
    assert "Prefetch/Amcache/MFT" not in caveats_blob
    assert finding["forensic_caveats"], "registry_run.yaml must still supply real caveats"
    assert any("still present at the referenced path" in c for c in finding["forensic_caveats"])


def test_fk_for_finding_pcap_flow_never_evtx():
    """A finding whose sole corroborating tool is 'tcpdump/pcap_flow' (the
    exact shape of F-268-001/F-268-002's corroboration.tools) must route to
    pcap.yaml — this is the literal repro of the case-268-001 bug."""
    from spectre.pipeline.phase_runner import _fk_for_finding
    assert _fk_for_finding(
        {"corroboration": {"tools": ["tcpdump/pcap_flow"]}}
    ) == "pcap.yaml"


def test_emit_from_handle_pcap_flow_finding_never_carries_evtx_caveats(tmp_path):
    """End-to-end repro of the exact case-268-001 symptom: emit a finding
    the way Phase 3 does for a pcap-staging-download / pcap-large-transfer
    anchor (artifact_type='pcap_flow', routed through the SAME ARTIFACT_FK
    lookup phase_runner.py uses) and assert forensic_caveats contains only
    pcap caveats — never the EVTX-4688/Prefetch/Amcache/MFT text."""
    from spectre.pipeline.emit_finding import emit_from_handle
    from spectre.pipeline.phase_runner import ARTIFACT_FK, _DEFAULT_FK
    from spectre.config import FK_DIRS, MITRE_MAP_PATH

    def _find_fk(fk_name: str) -> str:
        for d in FK_DIRS:
            p = d / fk_name
            if p.exists():
                return str(p)
        return str(FK_DIRS[0] / fk_name)

    fk_name = ARTIFACT_FK.get("pcap_flow", _DEFAULT_FK)
    fk_path = _find_fk(fk_name)

    handle = {"execution_id": "deadbeef", "tool": "tcpdump", "line_count": 10}
    finding = emit_from_handle(
        handle=handle,
        case_dir=str(tmp_path),
        finding_number=1,
        fk_yaml_path=fk_path,
        mitre_map_path=str(MITRE_MAP_PATH),
        rule_id="pcap-large-transfer",
        title="Large network transfer",
        iocs={"ip": ["23.205.110.9"], "domain": [], "filepath": [], "sha256": [], "registry_key": []},
        corroboration_note="pcap flow: 9147076 bytes total",
        corroboration_labels=["tcpdump/pcap_flow"],
        confidence=0.45,
        mitre=["T1105"],
        host_ip="10.1.13.175",
    )

    caveats_blob = " ".join(finding["forensic_caveats"])
    assert "4688" not in caveats_blob
    assert "Prefetch/Amcache/MFT" not in caveats_blob
    assert finding["forensic_caveats"], "pcap.yaml must still supply real pcap caveats"


def test_v5_strips_ungrounded_user_agent(pcap_finding):
    # A fabricated UA in the model description (absent from the finding) is
    # stripped by Validator 5 now that grounding covers UA tokens.
    out = dict(pcap_finding)
    out["description"] = (
        "Traffic to F-077-001 used User-Agent Mozilla/4.0 (compatible; MSIE 7.0)."
    )
    cleaned, violations = _validate_output(
        out, pcap_finding, ["PCAP shows network I/O, not process execution"],
        ["T1571"], "F-077-001")
    assert "MSIE" not in cleaned["description"]
    assert any("ungrounded" in v.lower() or "unsupported" in v.lower()
               for v in violations)


def test_v5_keeps_grounded_ip_sentence(pcap_finding):
    # The finding's own IP (203.161.44.208) is grounded — a sentence citing it
    # plus the finding_id survives.
    out = dict(pcap_finding)
    out["description"] = "F-077-001 records inbound traffic to 203.161.44.208."
    cleaned, _ = _validate_output(
        out, pcap_finding, ["PCAP shows network I/O, not process execution"],
        ["T1571"], "F-077-001")
    assert "203.161.44.208" in cleaned["description"]


# ── WS7a sub-task 1 (A3 finding #1): finding_id citation must not exempt
# defanged/obfuscated IOC-shaped literals from grounding. Before the
# grounding.py normalization fix, a fabricated IP formatted with [.]
# defanging or a zero-width space evaded the token regex entirely, so
# ungrounded_literals() returned an empty set and the finding_id-citation
# branch kept the sentence with ZERO violations logged (CONFIRMED-BY-
# EXECUTION in the A3 review). The ungrounded-literal check already runs
# BEFORE the citation check in _validate_output — these regressions pin
# that a defanged/obfuscated fabrication is actually caught by it now.
def test_defanged_fabricated_ip_stripped_even_with_finding_id_citation(pcap_finding):
    output = {
        "description": (
            "F-077-001 — outbound beacon observed to 185[.]220[.]101[.]42 "
            "(C2 infrastructure), confirming active command and control."
        ),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "185" not in cleaned["description"]
    assert any("ungrounded" in v for v in violations)


def test_zero_width_fabricated_ip_stripped_even_with_finding_id_citation(pcap_finding):
    output = {
        "description": (
            "F-077-001 — outbound beacon observed to 185.220.101​.42 "
            "(C2 infrastructure), confirming active command and control."
        ),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "185" not in cleaned["description"]
    assert any("ungrounded" in v for v in violations)


def test_defanged_fabricated_domain_stripped_even_with_finding_id_citation(pcap_finding):
    output = {
        "description": (
            "F-077-001 confirms exfiltration of staged data to "
            "evil-c2(dot)example[.]net as the drop site."
        ),
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "evil-c2.example.net" not in cleaned["description"]
    assert "example.net" not in cleaned["description"]
    assert any("ungrounded" in v for v in violations)


def test_defanged_grounded_ip_survives_with_finding_id_citation(pcap_finding):
    # The finding's own IP (203.161.44.208), cited in defanged form, must NOT
    # be treated as fabricated — normalization applies identically to the
    # grounded set and the candidate sentence.
    output = {
        "description": "F-077-001 records inbound traffic to 203[.]161[.]44[.]208.",
        "mitre_attack": "T1571",
        "caveats": PCAP_CAVEATS,
        "next_evidence": [],
    }
    cleaned, violations = _validate_output(
        output, pcap_finding, PCAP_CAVEATS, ALLOWED, "F-077-001"
    )
    assert "203[.]161[.]44[.]208" in cleaned["description"]
    assert not any("ungrounded" in v for v in violations)
