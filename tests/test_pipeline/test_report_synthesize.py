"""
test_report_synthesize.py — tests for the Phase 6 report synthesis module.

Covers:
  1. skip_ai path returns empty LLM output
  2. synthesize_report never raises on error
  3. _validate_report strips invented finding IDs
  4. _validate_report strips invented MITRE IDs
  5. _validate_report preserves verbatim caveats
  6. _merge_report_md produces valid markdown with 6 sections
  7. _merge_report_md includes all findings
  8. _generate_blindspots_md is case-specific (not hardcoded)
"""

import json
import re

import pytest

from spectre.pipeline.report_synthesize import (
    synthesize_report,
    _validate_report,
    _merge_report_md,
    _generate_blindspots_md,
    _generate_iocs_csv,
    _build_system_prompt,
    _build_user_prompt,
    _absence_signals,
    _parse_finding_ts,
    _finding_scale_phrase,
    _rollup_scale_lines,
    _load_mitre_tactics,
    _resolve_tactic,
    _cap_finding_ids,
    _MITRE_CELL_ID_CAP,
    _recovered_credential_values,
    _dedupe_domains,
    _tld_histogram,
    _key_findings_digest,
    _KEY_FINDINGS_TOP_N,
    _deterministic_threat_chain,
    _phase5_disposition_line,
)


# ── Test fixtures ────────────────────────────────────────────────────
@pytest.fixture
def sample_findings():
    """Two sample findings matching the fixture-test case shape."""
    return [
        {
            "finding_id": "F-004-001",
            "title": "rundll32-from-temp",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1218.011",
            "description": "A rundll32.exe process loaded a DLL from C:\\Windows\\Temp.",
            "forensic_caveats": [
                "Process creation (4688) proves the process was launched, not that the DLL is still on disk.",
                "A single 4688 is one source; corroborate with Prefetch/Amcache/MFT.",
            ],
            "iocs": {"filepath": ["C:\\Windows\\Temp\\evil.dll"]},
            "event_time": "2026-06-27T14:30:00Z",
            "evidence_refs": [
                {"execution_id": "abc123def456", "artifact_type": "evtx_4688"}
            ],
        },
        {
            "finding_id": "F-004-002",
            "title": "powershell-encoded",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1059.001",
            "description": "PowerShell executed an encoded command.",
            "forensic_caveats": [
                "Encoded command does not prove malicious intent.",
            ],
            "iocs": {"commandline": ["powershell.exe -enc SQBFAFgA..."]},
            "event_time": "2026-06-27T14:31:00Z",
            "evidence_refs": [
                {"execution_id": "def456ghi789", "artifact_type": "evtx_4688"}
            ],
        },
    ]


@pytest.fixture
def sample_manifest():
    """Sample manifest matching the fixture-test case."""
    return {
        "case_id": "004",
        "case_name": "test",
        "artifact_profile": "fixture-test",
        "canary_status": "FULL",
        "artifacts": ["evtx_4688"],
        "gate_0": {
            "fk_yamls_loaded": ["evtx_4688.yaml"],
            "passed": True,
        },
        "detection": {
            "rules_evaluated": 8,
            "rules_fired": 1,
            "severity_breakdown": {"medium": 1},
        },
        "directives": [{"action": "extract_evtx"}],
    }


@pytest.fixture
def sample_mitre_map():
    """Minimal MITRE map for testing."""
    return {
        "rules": {
            "rundll32-from-temp": {
                "allowed": ["T1218.011"],
                "label": "System Binary Proxy Execution: Rundll32",
            },
            "powershell-encoded": {
                "allowed": ["T1059.001"],
                "label": "Command and Scripting Interpreter: PowerShell (encoded)",
            },
        }
    }


@pytest.fixture
def sample_fk_caveats():
    """Sample FK caveats per artifact type."""
    return {
        "evtx_4688": [
            "Process creation (4688) proves the process was launched, not that the DLL is still on disk.",
            "A single 4688 is one source; corroborate with Prefetch/Amcache/MFT.",
        ]
    }


# ── Test 1: skip_ai returns empty LLM output ─────────────────────────
def test_synthesize_skips_with_skip_ai(sample_findings, sample_manifest, tmp_path):
    """With skip_ai=True, synthesize_report returns empty template data."""
    result = synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=True
    )
    assert result["llm_used"] is False
    assert result["executive_summary"] == ""
    assert result["findings_narrative"] == []
    assert result["api_error"] is None


def test_synthesize_skips_with_empty_findings(sample_manifest, tmp_path):
    """With no findings, return empty template immediately."""
    result = synthesize_report(
        [], sample_manifest, str(tmp_path), skip_ai=False
    )
    assert result["llm_used"] is False


# ── Test 2: synthesize_report never raises ──────────────────────────
def test_synthesize_never_raises(sample_findings, sample_manifest, tmp_path):
    """synthesize_report should never raise an exception — it returns (output, reason)."""
    # With host provider (default), it returns deferred, not error
    result = synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=False
    )
    # Result should always be a dict with expected keys
    assert isinstance(result, dict)
    assert "executive_summary" in result
    assert "llm_used" in result
    # Host mode defers — that's expected, not an error
    if result.get("deferred"):
        assert result.get("api_error", "").startswith("host mode")


# ── Test 3: _validate_report strips invented finding IDs ─────────────
def test_validate_strips_invented_finding_ids(sample_findings, sample_fk_caveats):
    """Validator removes invented F-NNN-NNN references from output."""
    output = {
        "executive_summary": "Found F-004-001 and F-999-001 evidence.",
        "findings_narrative": [
            {"finding_id": "F-004-001",
             "narrative": "Finding F-004-001 is related to F-888-001."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    allowed_mitre = ["T1218.011", "T1059.001"]
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, allowed_mitre
    )
    # F-999-001 and F-888-001 should be caught
    assert len(violations) > 0
    assert any("invented finding IDs" in v for v in violations)


# ── Test 4: _validate_report strips invented MITRE IDs ───────────────
def test_validate_strips_invented_mitre(sample_findings, sample_fk_caveats):
    """Validator replaces invented MITRE IDs with UNMAPPED."""
    output = {
        "executive_summary": "This used T1218.011 and T1566.001 techniques.",
        "findings_narrative": [
            {"finding_id": "F-004-001",
             "narrative": "F-004-001 leverages T1218.011."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    allowed_mitre = ["T1218.011", "T1059.001"]
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, allowed_mitre
    )
    assert any("invented MITRE" in v for v in violations)
    # T1566.001 should be replaced with UNMAPPED
    all_text = json.dumps(cleaned)
    assert "T1566.001" not in all_text


# ── Regression: dict/list-valued narrative fields must not crash the
# validator (a live DeepSeek run intermittently returned `verdict` as a
# structured object → re.search(..., dict) TypeError → whole synthesis
# silently degraded to the deterministic baseline). Narrative keys must be
# coerced to strings so validation AND downstream markdown join stay safe.
def test_validate_coerces_nonstring_narrative_fields(sample_findings, sample_fk_caveats):
    output = {
        # DeepSeek returned an object instead of a string here:
        "verdict": {"determination": "suspicious", "confidence": "LOW"},
        "executive_summary": ["para one", "para two"],  # or a list
        "findings_narrative": [
            {"finding_id": "F-004-001", "narrative": "F-004-001 detail."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    # Must not raise; must return string-typed narrative fields.
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, ["T1218.011"]
    )
    assert isinstance(cleaned["verdict"], str)
    assert isinstance(cleaned["executive_summary"], str)
    # Content is preserved (not silently dropped).
    assert "suspicious" in cleaned["verdict"]
    assert "para one" in cleaned["executive_summary"]
    # And the merged report must render without a join TypeError.
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(cleaned, sample_findings, {"case_id": "004"},
                          "/tmp/x", violations, {"rules": {}})
    assert isinstance(md, str)


# ── Test 5: _validate_report preserves verbatim caveats ──────────────
# (Caveat validation is currently soft — this tests that the Empty Data
# Protocol validator works, which is relevant for caveats implicitly.)

def test_validate_empty_data_protocol(sample_findings, sample_fk_caveats):
    """Validator replaces 'clean'/'no malware' with UNVERIFIED."""
    output = {
        "executive_summary": "The system appears clean with no malware found.",
        "findings_narrative": [
            {"finding_id": "F-004-001",
             "narrative": "F-004-001: nothing suspicious detected."},
        ],
        "timeline_narrative": "The timeline shows clean activity.",
        "methodology_narrative": "Analysis was clean and found no malware.",
    }
    allowed_mitre = ["T1218.011", "T1059.001"]
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, allowed_mitre
    )
    assert len(violations) > 0
    assert any("UNVERIFIED" in v or "clean" in v.lower() for v in violations)


# ── Test 6: _merge_report_md produces valid markdown with all sections (now 7 + appendix)
def test_merge_produces_valid_markdown(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Output markdown has all 7 required sections plus appendix."""
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    # Check for all section headers
    assert "## Executive Summary" in md
    assert "## 1. Threat Narrative" in md
    assert "## 2. MITRE ATT&CK Map" in md
    assert "## 3. Timeline" in md
    assert "## 4. Forensic Blind Spots" in md
    assert "## 5. IOC Export" in md
    assert "## 6. Methodology" in md
    assert "## Appendix" in md or "Finding Index" in md


# ── Test 7: _merge_report_md includes all findings ──────────────────
def test_merge_includes_all_findings(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """No finding is dropped from the report."""
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "F-004-001" in md
    assert "F-004-002" in md
    assert "rundll32-from-temp" in md
    assert "powershell-encoded" in md


# ── Test 8: _generate_blindspots_md is case-specific ────────────────
def test_blindspots_derived_from_profile(
    sample_findings, sample_manifest, sample_mitre_map, sample_fk_caveats, tmp_path
):
    """blindspots.md is derived from artifact profile coverage, not hardcoded."""
    md = _generate_blindspots_md(
        sample_findings, sample_manifest, sample_mitre_map,
        sample_fk_caveats, str(tmp_path)
    )
    # Should NOT contain the old hardcoded strings
    # (prefetch, amcache coverage gaps should be mentioned because profile
    # only has evtx_4688 — but they derive from FULL_ARTIFACT_SET, not hardcoded)
    assert "prefetch" in md.lower() or "Prefetch" in md

    # With a different profile, output changes
    manifest_full = dict(sample_manifest)
    manifest_full["artifacts"] = ["evtx_4688", "prefetch", "amcache", "mft", "pcap", "memory"]

    md_full = _generate_blindspots_md(
        sample_findings, manifest_full, sample_mitre_map,
        sample_fk_caveats, str(tmp_path)
    )
    # More coverage = fewer coverage gaps mentioned
    assert md_full != md  # Output differs based on profile


# ── Test: _generate_iocs_csv produces valid CSV ──────────────────────
def test_generate_iocs_csv(sample_findings, tmp_path):
    """IOC CSV has correct headers and includes finding data."""
    csv_path = tmp_path / "iocs.csv"
    _generate_iocs_csv(sample_findings, str(csv_path))
    content = csv_path.read_text()
    lines = content.strip().split("\n")
    assert lines[0] == "finding_id,ioc_type,value,confidence,role"
    assert len(lines) > 1  # At least one data row
    assert "C:\\Windows\\Temp\\evil.dll" in content


def test_generate_iocs_csv_role_victim_vs_remote(tmp_path):
    """The IOC that equals the finding's host_ip is labeled 'victim'; every
    other ip IOC (and every non-ip IOC) is 'remote'. Deterministic equality,
    no inference."""
    findings = [
        {
            "finding_id": "F-004-001",
            "confidence": 0.7,
            "host_ip": "10.0.0.5",
            "iocs": {"ip": ["45.77.12.9", "10.0.0.5"], "domain": ["evil.example.com"]},
        },
    ]
    csv_path = tmp_path / "iocs.csv"
    _generate_iocs_csv(findings, str(csv_path))
    rows = csv_path.read_text().strip().split("\n")[1:]
    by_value = {r.split(",")[2]: r.split(",")[-1] for r in rows}
    assert by_value["45.77.12.9"] == "remote"
    assert by_value["10.0.0.5"] == "victim"
    assert by_value["evil.example.com"] == "remote"


def test_generate_iocs_csv_role_remote_when_no_host_ip(tmp_path):
    """When a finding carries no host_ip (non-pcap artifact), every ip IOC
    is labeled remote — there's no victim address to compare against."""
    findings = [
        {
            "finding_id": "F-004-002",
            "confidence": 0.5,
            "iocs": {"ip": ["1.2.3.4"]},
        },
    ]
    csv_path = tmp_path / "iocs.csv"
    _generate_iocs_csv(findings, str(csv_path))
    rows = csv_path.read_text().strip().split("\n")[1:]
    assert rows[0].split(",")[-1] == "remote"


# ── Test: _build_system_prompt contains guardrail rules ──────────────
def test_system_prompt_has_guardrails():
    """System prompt includes all guardrail rules."""
    prompt = _build_system_prompt()
    assert "do NOT create them" in prompt
    assert "finding_id" in prompt
    assert "MITRE ATT&CK" in prompt
    assert "VERBATIM" in prompt
    assert "confidence" in prompt
    assert "UNVERIFIED" in prompt
    assert "DRAFT" in prompt


# ── Test: _build_user_prompt includes all findings ───────────────────
def test_user_prompt_includes_all_findings(sample_findings, sample_manifest, sample_mitre_map):
    """User prompt contains data for all findings."""
    prompt = _build_user_prompt(
        sample_findings, sample_manifest, sample_mitre_map,
        {"evtx_4688": ["caveat 1"]},
        sample_manifest.get("detection", {}),
        "fixture-test",
    )
    assert "F-004-001" in prompt
    assert "F-004-002" in prompt
    assert "T1218.011" in prompt
    assert "T1059.001" in prompt
    assert "fixture-test" in prompt


# ── Test: _validate_report catches confidence mentions ───────────────
def test_validate_strips_confidence_mentions(sample_findings, sample_fk_caveats):
    """Validator removes confidence score mentions from narrative sections."""
    output = {
        "executive_summary": "The confidence of 0.95 is high.",
        "findings_narrative": [
            {"finding_id": "F-004-001",
             "narrative": "F-004-001 with confidence 0.95."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "Confidence: 0.8 for this method.",
    }
    allowed_mitre = ["T1218.011", "T1059.001"]
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, allowed_mitre
    )
    assert len(violations) > 0
    assert any("confidence" in v for v in violations)


# ── New tests: deduplication, grouping, prose exec summary, appendix (Task 3) ──

def test_merge_deduplicates_iocs_in_summary_table(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Duplicate IOC values appear ONCE in the deduped Key Indicators table."""
    dup = dict(sample_findings[0])
    dup["finding_id"] = "F-004-003"
    findings = [sample_findings[0], sample_findings[1], dup]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    # Extract the "### Key Indicators" table section (to the next ## or end)
    key_start = md.find("### Key Indicators")
    assert key_start >= 0, "Key Indicators section missing"
    # Find the next section boundary: either "## " or end of doc
    next_boundary = md.find("\n## ", key_start + 20)
    if next_boundary < 0:
        next_boundary = len(md)
    key_section = md[key_start:next_boundary]
    # evil.dll should appear once in the deduped IOC summary
    count = key_section.count("evil.dll")
    assert count == 1, f"evil.dll appeared {count} times in Key Indicators, expected once"


def test_merge_groups_when_many_findings(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """When 30+ findings exist, output is GROUPED not individually enumerated."""
    many = []
    for i in range(35):
        f = dict(sample_findings[0])
        f["finding_id"] = f"F-004-{i+1:03d}"
        many.append(f)
    md = _merge_report_md(None, many, sample_manifest, str(tmp_path), [], sample_mitre_map)
    # Should not contain 35 individual finding headers
    h3_count = md.count("### F-004-")
    assert h3_count < 10, f"Expected <10 finding headers, got {h3_count}"


def test_merge_produces_prose_exec_summary_without_llm(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Without LLM, executive summary is prose (not just bullet counts)."""
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    # Should contain narrative sentences, not just bullet lists
    assert "investigation" in md.lower() or "identified" in md.lower()


def test_report_has_appendix(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Report includes an appendix with the full finding index."""
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "## Appendix" in md or "Finding Index" in md
    assert "F-004-001" in md  # finding IDs appear in index


# ── Merge cleanups: MITRE label dedupe, confidence range, caveat dedupe ──

@pytest.fixture
def composite_mitre_map():
    """Two TIDs sharing one label — the case 073 duplicate-header shape."""
    return {
        "rules": {
            "exploit-probe": {
                "allowed": ["T1595.002", "T1190"],
                "label": "Vulnerability Scanning / Exploit Public-Facing Application",
            },
        }
    }


def _make_finding(fid, mitre, title, conf=0.60, caveats=None,
                   event_time="2026-07-01T15:22:21Z", tool=""):
    finding = {
        "finding_id": fid,
        "title": title,
        "status": "CONFIRMED",
        "confidence": conf,
        "mitre_attack": mitre,
        "description": "desc",
        "forensic_caveats": caveats or [],
        "iocs": {"ip": ["203.0.113.7"]},
        "event_time": event_time,
        "evidence_refs": [{"execution_id": "abc123def456", "artifact_type": "pcap_http"}],
    }
    if tool:
        finding["tool"] = tool
    return finding


def test_composite_mitre_label_not_duplicated(
    sample_manifest, composite_mitre_map, tmp_path
):
    """A composite 'T1595.002, T1190' resolves each TID to its OWN canonical
    technique name — not the rule's shared composite label duplicated across
    both. (The rule's composite label in this fixture — 'Vulnerability
    Scanning / Exploit Public-Facing Application' — must NOT appear verbatim;
    that was the bug: a rule's whole-rule label assigned to every TID.)"""
    findings = [
        _make_finding(f"F-004-{i:03d}", "T1595.002, T1190", "exploit probe: IoT")
        for i in range(1, 4)
    ]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], composite_mitre_map)
    rule_composite_label = "Vulnerability Scanning / Exploit Public-Facing Application"
    assert rule_composite_label not in md, (
        "rule-level composite label leaked into per-technique rendering"
    )
    # Each TID's own canonical name appears, joined — not a shared blob.
    assert "Active Scanning: Vulnerability Scanning" in md
    assert "Exploit Public-Facing Application" in md
    header_lines = [ln for ln in md.splitlines() if ln.startswith("#### ")
                    and "Active Scanning: Vulnerability Scanning" in ln]
    assert header_lines, "expected a group header carrying the per-technique labels"
    for ln in header_lines:
        assert ln.count("Active Scanning: Vulnerability Scanning") == 1
        assert ln.count("Exploit Public-Facing Application") == 1


def test_mitre_label_is_per_technique_not_rule_composite(
    sample_manifest, tmp_path
):
    """RED (gold-loop audit): a finding mapped to T1552.001 alone must render
    the canonical technique name for T1552.001 — NOT the composite label of
    whatever rule happens to list T1552.001 in its 'allowed' (e.g.
    pcap-exploit-probe's 4-technique blob). Uses the REAL mitre-map.yaml
    (loaded via synthesize_report's own loader) so this catches the actual
    production bug, not just a crafted fixture."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH

    real_mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    f = _make_finding("F-004-001", "T1552.001", "credential probe: env var")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], real_mitre_map)

    # The finding's evidence block carries "MITRE: T1552.001 — <label>".
    mitre_lines = [ln for ln in md.splitlines() if ln.startswith("**Status:**")]
    assert mitre_lines, "expected a Status/MITRE line in the evidence block"
    mitre_line = mitre_lines[0]
    assert "Unsecured Credentials: Credentials In Files" in mitre_line
    assert "Vulnerability Scanning" not in mitre_line
    assert " / " not in mitre_line.split("—", 1)[-1]


def test_mitre_techniques_yaml_covers_every_mapped_tid():
    """Completeness guard: every tid referenced by any mitre-map.yaml rule's
    'allowed' list must have a canonical entry in mitre_techniques.yaml, so
    future rule/tid additions can't silently regress to a missing label
    (which would fall back to the bare tid string, never a composite)."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH, MITRE_TECHNIQUES_PATH

    mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    mapped_tids = {
        tid
        for rule_data in mitre_map.get("rules", {}).values()
        for tid in rule_data.get("allowed", [])
    }
    techniques = _yaml.safe_load(MITRE_TECHNIQUES_PATH.read_text()).get("techniques", {})
    missing = mapped_tids - set(techniques.keys())
    assert not missing, f"tids missing from mitre_techniques.yaml: {sorted(missing)}"


# ── BUG 5: MITRE map "Detection Rule" column must use each finding's OWN
#    rule_id, never a technique-level guess (multiple rules can share one
#    MITRE technique, e.g. T1071.001 is "allowed" by both pcap-suspicious-port
#    AND pcap-c2-protocol in the real mitre-map.yaml; T1105 by both
#    pcap-staging-download AND pcap-large-transfer). Case 268-001's report
#    mislabeled every pcap-c2-protocol finding as pcap-suspicious-port and
#    the ~9MB pcap-large-transfer marquee finding as pcap-staging-download —
#    both are the YAML-declaration-order "first rule wins" artifact of the
#    old technique_to_rule lookup. ──

def test_mitre_map_rule_column_uses_finding_rule_id_not_technique_guess(
    sample_manifest, tmp_path
):
    """RED (gold-loop audit, case 268-001): a T1071.001 finding whose own
    rule_id is pcap-c2-protocol must render 'pcap-c2-protocol' in the
    Detection Rule column — never 'pcap-suspicious-port', even though
    mitre-map.yaml lists pcap-suspicious-port first for that technique."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH

    real_mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    f = _make_finding("F-268-009", "T1071.001", "C2 protocol fingerprint")
    f["rule_id"] = "pcap-c2-protocol"
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], real_mitre_map)

    mitre_table_lines = [ln for ln in md.splitlines() if ln.startswith("| T1071.001")]
    assert mitre_table_lines, "expected a MITRE map row for T1071.001"
    row = mitre_table_lines[0]
    assert "pcap-c2-protocol" in row
    assert "pcap-suspicious-port" not in row


def test_mitre_map_rule_column_from_manifest_detection_findings(
    sample_manifest, tmp_path
):
    """Real finding YAMLs on disk carry no rule_id field at all — Phase 3's
    per-finding rule_id lives in manifest['detection']['findings'] (written
    by phase_runner's findings_summary). The MITRE map builder must recover
    rule attribution from there when the finding dict itself lacks rule_id,
    and must NOT collapse two distinct rules sharing one MITRE technique
    (T1105 == pcap-staging-download for F-268-001, pcap-large-transfer for
    F-268-002) onto a single guessed rule."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH

    real_mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    f1 = _make_finding("F-268-001", "T1105", "catbox.moe staging download")
    f2 = _make_finding("F-268-002", "T1105", "9MB secondary transfer")
    manifest = dict(sample_manifest)
    manifest["detection"] = {
        "findings": [
            {"finding_id": "F-268-001", "rule_id": "pcap-staging-download"},
            {"finding_id": "F-268-002", "rule_id": "pcap-large-transfer"},
        ]
    }
    md = _merge_report_md(None, [f1, f2], manifest, str(tmp_path), [], real_mitre_map)

    mitre_table_lines = [ln for ln in md.splitlines() if ln.startswith("| T1105")]
    assert mitre_table_lines, "expected a MITRE map row for T1105"
    row = mitre_table_lines[0]
    assert "pcap-staging-download" in row
    assert "pcap-large-transfer" in row, (
        "F-268-002's real rule (pcap-large-transfer) must appear — it must "
        "not be silently collapsed onto F-268-001's rule"
    )


def test_mitre_map_rule_column_falls_back_without_rule_data(
    sample_manifest, tmp_path
):
    """No rule_id on the finding AND no manifest['detection']['findings']
    entry (e.g. a hand-built test fixture with no provenance) — the column
    must still render something (the old technique-level guess), not crash
    or go blank."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH

    real_mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    f = _make_finding("F-004-001", "T1071.001", "C2 protocol fingerprint")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], real_mitre_map)
    mitre_table_lines = [ln for ln in md.splitlines() if ln.startswith("| T1071.001")]
    assert mitre_table_lines
    assert mitre_table_lines[0].strip().endswith("|")  # well-formed row, rule column populated


def test_degenerate_confidence_range_collapses(
    sample_manifest, composite_mitre_map, tmp_path
):
    """All-equal confidences render 'Confidence: 0.60', never '0.60–0.60'."""
    findings = [
        _make_finding(f"F-004-{i:03d}", "T1595.002", "exploit probe: IoT", conf=0.60)
        for i in range(1, 4)
    ]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], composite_mitre_map)
    assert "0.60–0.60" not in md
    assert "Confidence: 0.60" in md


def test_identical_caveat_blocks_rendered_once(
    sample_manifest, composite_mitre_map, tmp_path
):
    """Verbatim-identical caveat lists appear once in the Threat Narrative;
    later findings reference the first occurrence instead of repeating."""
    caveats = [
        "Intent — a connection to a known-bad IP could be drive-by, compromise, or misconfiguration",
        "PCAP shows network I/O, not process execution or file writes",
    ]
    # Two distinct groups (different mitre/category), same caveat list
    findings = (
        [_make_finding(f"F-004-{i:03d}", "T1595.002", "exploit probe: IoT", caveats=caveats)
         for i in range(1, 4)]
        + [_make_finding(f"F-004-{i:03d}", "T1190", "credential probe: env", caveats=caveats)
           for i in range(4, 7)]
    )
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], composite_mitre_map)
    narrative_start = md.find("## 1. Threat Narrative")
    narrative_end = md.find("## 2.")
    narrative = md[narrative_start:narrative_end]
    count = narrative.count(caveats[0])
    assert count == 1, f"identical caveat block rendered {count} times in narrative, expected 1"
    # The second group must point back rather than stay silent
    assert "same caveats as" in narrative.lower() or "see F-004-001" in narrative


# ── Threat Narrative timestamp honesty ────────────────────────────────
# _append_finding_evidence_block used to read finding["timestamps"] (plural)
# — a key that is NEVER written by emit_finding.py (findings carry
# "event_time" and "timestamp" only) — so it always fell back to
# _utcnow(), fabricating a run-time "Timestamp:" line on every finding.

def test_evidence_block_no_run_time_stamp_when_event_time_empty(
    sample_manifest, composite_mitre_map, tmp_path
):
    """A finding whose artifact carries no evidence time (event_time="")
    must render NO fabricated run-time 'Timestamp:' line."""
    f = _make_finding("F-004-001", "T1595.002", "exploit probe: IoT", event_time="")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], composite_mitre_map)
    narrative_start = md.find("## 1. Threat Narrative")
    narrative_end = md.find("## 2.")
    narrative = md[narrative_start:narrative_end]
    # No ISO-8601 run-time-shaped timestamp anywhere in the evidence block
    assert not re.search(r"\*\*Timestamp:\*\*\s*\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", narrative)


def test_evidence_block_shows_real_event_time_when_set(
    sample_manifest, composite_mitre_map, tmp_path
):
    """A finding with a real evidence event_time renders that exact value —
    never the analysis run's wall-clock time."""
    f = _make_finding("F-004-001", "T1595.002", "exploit probe: IoT",
                       event_time="2026-06-27T14:30:00Z")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], composite_mitre_map)
    assert "**Timestamp:** 2026-06-27T14:30:00Z" in md


# ── Per-finding engine/tool attribution (A10 Finding 2, MED transparency
# gap) — emit_finding.py already writes finding["tool"] (e.g.
# "zeek:http.log zeek-8.0.9" vs "tcpdump tcpdump") and audit.jsonl already
# carries it, but report.md never surfaced which engine produced which
# observation. An analyst/court reading only the report could not tell.

def test_evidence_block_surfaces_producing_engine_zeek(
    sample_manifest, composite_mitre_map, tmp_path
):
    f = _make_finding("F-004-001", "T1595.002", "exploit probe: IoT",
                       tool="zeek:http.log zeek-8.0.9")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], composite_mitre_map)
    assert "zeek:http.log zeek-8.0.9" in md
    assert "**Source:**" in md


def test_evidence_block_surfaces_producing_engine_tcpdump(
    sample_manifest, composite_mitre_map, tmp_path
):
    f = _make_finding("F-004-001", "T1595.002", "exploit probe: IoT",
                       tool="tcpdump tcpdump")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], composite_mitre_map)
    assert "**Source:** tcpdump tcpdump" in md


def test_evidence_block_no_source_line_when_tool_unknown(
    sample_manifest, composite_mitre_map, tmp_path
):
    """A finding built without a tool field (legacy fixture / synthesized
    test data) must not render a fabricated/empty '**Source:**' line."""
    f = _make_finding("F-004-001", "T1595.002", "exploit probe: IoT")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], composite_mitre_map)
    assert "**Source:**" not in md


# ── Validator updates: verdict, qualitative confidence, negatives, IOC dumps ──

def test_validate_flags_missing_verdict(sample_findings, sample_fk_caveats):
    """LLM output without a verdict section is a violation."""
    output = {
        "executive_summary": "Summary citing F-004-001.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, ["T1218.011"]
    )
    assert any("verdict" in v.lower() for v in violations)


def test_validate_allows_qualitative_attribution_confidence(
    sample_findings, sample_fk_caveats
):
    """'Attribution confidence: LOW' is analyst language, not a score — kept."""
    output = {
        "executive_summary": "Opportunistic scanning per F-004-001. Attribution confidence: LOW.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "Attribution confidence: LOW. Opportunistic, non-targeted activity.",
    }
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, ["T1218.011"]
    )
    assert "Attribution confidence: LOW" in cleaned["executive_summary"]
    assert not any("confidence mentioned in executive_summary" in v for v in violations)


def test_validate_still_strips_numeric_confidence(sample_findings, sample_fk_caveats):
    """Numeric confidence claims are still removed from narratives."""
    output = {
        "executive_summary": "The confidence of 0.95 is high for F-004-001.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "Confidence: 0.8 for this method.",
        "verdict": "v",
    }
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, ["T1218.011"]
    )
    assert any("confidence" in v.lower() for v in violations)
    assert "0.95" not in cleaned["executive_summary"]


def test_validate_allows_grounded_negative_statement(sample_findings, sample_fk_caveats):
    """Evidence-grounded negatives ('no evidence of X was observed') pass untouched;
    'clean'/'no malware found' are still replaced."""
    negative = ("No evidence of successful compromise was observed in the "
                "examined traffic (F-004-001).")
    output = {
        "executive_summary": negative,
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "The system appears clean.",
        "verdict": "v",
    }
    cleaned, violations = _validate_report(
        output, sample_findings, sample_fk_caveats, ["T1218.011"]
    )
    assert cleaned["executive_summary"] == negative
    assert "clean" not in cleaned["methodology_narrative"]
    assert "UNVERIFIED" in cleaned["methodology_narrative"]


def test_validate_flags_ioc_dump_in_exec_summary(sample_fk_caveats):
    """Executive summaries that dump many raw IOC literals get flagged."""
    findings = []
    ips = []
    for i in range(8):
        ip = f"203.0.113.{i+1}"
        ips.append(ip)
        findings.append({
            "finding_id": f"F-004-{i+1:03d}",
            "title": "t", "status": "INFERRED", "confidence": 0.5,
            "mitre_attack": "T1218.011", "iocs": {"ip": [ip]},
        })
    output = {
        "executive_summary": "Suspicious IPs include " + ", ".join(ips) + " per F-004-001.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "v",
    }
    cleaned, violations = _validate_report(
        output, findings, sample_fk_caveats, ["T1218.011"]
    )
    assert any("ioc" in v.lower() and "executive" in v.lower() for v in violations)


def test_merge_renders_llm_verdict(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """When the LLM output carries a verdict, §7 renders it above the
    deterministic recommendation."""
    llm_output = {
        "executive_summary": "Summary.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "Opportunistic scanning; attribution confidence LOW (F-004-001).",
    }
    md = _merge_report_md(
        llm_output, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert "Opportunistic scanning; attribution confidence LOW" in verdict_section
    assert "**Recommendation:**" in verdict_section


# ── Prompt upgrades: richer payload, direction summary, verdict ask ──

@pytest.fixture
def pcap_findings():
    """Findings shaped like real pcap case output (corroboration + event_time)."""
    return [
        {
            "finding_id": "F-073-001",
            "title": "Inbound connection to commonly-malicious port 5555",
            "status": "INFERRED",
            "confidence": 0.4,
            "mitre_attack": "T1571",
            "description": "",
            "event_time": "2026-03-11 00:27:30.155745",
            "corroboration": {
                "sources": 1,
                "tools": ["tcpdump/pcap_conn"],
                "artifacts": [
                    "pcap [inbound]: 2026-03-11 00:27:30 IP 45.135.194.48.40423 > 203.161.44.208.5555: tcp 0"
                ],
            },
            "iocs": {"ip": ["203.161.44.208"]},
            "forensic_caveats": ["PCAP shows network I/O, not process execution"],
            "evidence_refs": [{"execution_id": "c5c46cc9acb0559e"}],
        },
        {
            "finding_id": "F-073-002",
            "title": "Exploit probe against public-facing app",
            "status": "CONFIRMED",
            "confidence": 0.8,
            "mitre_attack": "T1190",
            "description": "",
            "event_time": "2026-03-12 08:00:00.000000",
            "corroboration": {
                "sources": 2,
                "tools": ["tcpdump/pcap_http", "tshark/pcap_http"],
                "artifacts": [
                    "pcap [inbound]: GET /config/getuser?index=0 HTTP/1.1"
                ],
            },
            "iocs": {"ip": ["185.248.138.248"]},
            "forensic_caveats": ["PCAP shows network I/O, not process execution"],
            "evidence_refs": [{"execution_id": "524d5b6e39b4d13f"}],
        },
    ]


def test_user_prompt_carries_rich_finding_payload(
    pcap_findings, sample_manifest, sample_mitre_map
):
    """Prompt includes event_time, corroboration source count, and an
    evidence excerpt — not just title/desc."""
    prompt = _build_user_prompt(
        pcap_findings, sample_manifest, sample_mitre_map, {}, {}, "pcap"
    )
    assert "2026-03-11 00:27:30" in prompt          # event_time
    assert "SOURCES=2" in prompt                    # corroboration count
    assert "45.135.194.48" in prompt                # evidence excerpt content
    assert "203.161.44.208" in prompt               # IOC


def test_user_prompt_has_direction_summary(
    pcap_findings, sample_manifest, sample_mitre_map
):
    """Deterministic traffic-direction aggregate appears in the prompt."""
    prompt = _build_user_prompt(
        pcap_findings, sample_manifest, sample_mitre_map, {}, {}, "pcap"
    )
    assert "inbound: 2" in prompt.lower()
    assert "outbound: 0" in prompt.lower()


def test_user_prompt_names_monitored_host(
    pcap_findings, sample_manifest, sample_mitre_map
):
    """The prompt states which IP is the monitored host (dest of inbound
    evidence), so the narrative can't call the server its own attacker (C1)."""
    prompt = _build_user_prompt(
        pcap_findings, sample_manifest, sample_mitre_map, {}, {}, "pcap"
    )
    assert "monitored host" in prompt.lower()
    # 203.161.44.208 is the destination of the inbound artifact
    mh_line = [ln for ln in prompt.splitlines() if "monitored host" in ln.lower()]
    assert mh_line and "203.161.44.208" in mh_line[0]


def test_user_prompt_asks_for_verdict_and_attribution(
    pcap_findings, sample_manifest, sample_mitre_map
):
    """Instructions require a verdict with qualitative attribution confidence
    and forbid raw IOC dumps in the executive summary."""
    prompt = _build_user_prompt(
        pcap_findings, sample_manifest, sample_mitre_map, {}, {}, "pcap"
    )
    assert "verdict" in prompt.lower()
    assert "attribution confidence" in prompt.lower()
    assert "LOW" in prompt and "HIGH" in prompt
    # IOC-dump prohibition
    assert "IOC table" in prompt


def test_system_prompt_mentions_verdict_rules():
    """System prompt covers verdict + qualitative confidence + grounded negatives."""
    prompt = _build_system_prompt()
    assert "verdict" in prompt.lower()
    assert "attribution" in prompt.lower()
    assert "no evidence of" in prompt.lower()


def test_artifact_types_from_corroboration_tools(pcap_findings):
    """Artifact types come from corroboration.tools — real findings have no
    'artifact_type' on evidence_refs, so evtx must NOT be the default for pcap."""
    from spectre.pipeline.report_synthesize import _get_finding_artifact_types
    types = _get_finding_artifact_types(pcap_findings)
    assert "pcap_conn" in types or "pcap_http" in types
    assert "evtx" not in types


def test_fk_caveats_for_pcap_never_load_evtx(pcap_findings):
    """The FK caveat map for pcap findings must not contain 4688 caveats."""
    from spectre.pipeline.report_synthesize import (
        _get_finding_artifact_types, _load_fk_caveats,
    )
    from spectre.config import FK_DIRS
    types = _get_finding_artifact_types(pcap_findings)
    fk_map = _load_fk_caveats(types, FK_DIRS)
    blob = " ".join(c for cavs in fk_map.values() for c in cavs)
    assert "4688" not in blob
    assert "Prefetch/Amcache/MFT" not in blob


# ── Timeline: dated findings sort chronologically, undated findings are
#    called out explicitly instead of masquerading as run-time events ──

@pytest.fixture
def mixed_dated_undated_findings():
    """Two dated findings (out of order) plus one undated finding — the
    shape of real memory-module output (netscan/cmdline/malfind carry no
    evidence timestamp)."""
    return [
        {
            "finding_id": "F-004-002",
            "title": "later dated event",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1059.001",
            "event_time": "2026-03-12 08:00:00.000000",
        },
        {
            "finding_id": "F-004-001",
            "title": "earlier dated event",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1218.011",
            "event_time": "2026-03-11 00:27:30.155745",
        },
        {
            "finding_id": "F-004-003",
            "title": "undated memory finding",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1055",
            "event_time": "",
        },
    ]


def test_timeline_dated_chronological_and_undated_block(
    mixed_dated_undated_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Fallback timeline (no LLM narrative): dated rows appear in
    chronological order; the undated finding is listed under an explicit
    'Undated findings' block, never given a fabricated timestamp."""
    md = _merge_report_md(
        None, mixed_dated_undated_findings, sample_manifest, str(tmp_path),
        [], sample_mitre_map,
    )

    timeline = md.split("## 3. Timeline")[1].split("## 4.")[0]

    earlier_pos = timeline.index("earlier dated event")
    later_pos = timeline.index("later dated event")
    assert earlier_pos < later_pos

    assert "**Undated findings**" in timeline
    dated_block, undated_block = timeline.split("**Undated findings**", 1)

    # Undated finding does not appear in the dated table.
    assert "F-004-003" not in dated_block

    assert "F-004-003" in undated_block
    assert "undated memory finding" in undated_block

    # The undated finding's own line must not contain a timestamp-shaped
    # string (no invented date sneaks in).
    undated_line = [
        ln for ln in undated_block.splitlines() if "F-004-003" in ln
    ][0]
    assert not re.search(r"\d{4}-\d{2}-\d{2}", undated_line)


def test_user_prompt_marks_missing_event_time_explicitly(
    sample_manifest, sample_mitre_map
):
    """The LLM prompt's per-finding TIME field sends an explicit
    '(no evidence timestamp)' marker for undated findings, so the model
    can't be tempted to invent a date."""
    findings = [
        {
            "finding_id": "F-004-001",
            "title": "undated memory finding",
            "status": "INFERRED",
            "confidence": 0.5,
            "mitre_attack": "T1055",
            "event_time": "",
        },
    ]
    prompt = _build_user_prompt(
        findings, sample_manifest, sample_mitre_map, {}, {}, "memory"
    )
    assert "(no evidence timestamp)" in prompt
    assert "TIME=(no evidence timestamp)" in prompt


def test_synthesis_retries_transient_failure(
    sample_findings, sample_manifest, tmp_path, monkeypatch
):
    """A transient parse/API failure is retried once before falling back —
    DeepSeek intermittently returns malformed JSON (case 002)."""
    from spectre.pipeline import report_synthesize as rs
    from spectre.llm import LLMResponse

    calls = {"n": 0}

    class FlakyProvider:
        name = "deepseek"
        def complete(self, *a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return LLMResponse(parsed=None, error="malformed JSON", model="x")
            return LLMResponse(
                parsed={
                    "executive_summary": "Summary of F-004-001.",
                    "findings_narrative": [], "timeline_narrative": "",
                    "methodology_narrative": "", "verdict": "v (F-004-001).",
                },
                finish_reason="stop", model="x",
                usage={"prompt_tokens": 10, "completion_tokens": 20},
            )

    monkeypatch.setattr(rs, "get_provider", lambda *a, **k: FlakyProvider())
    result = rs.synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=False
    )
    assert calls["n"] == 2, "should retry once on transient failure"
    assert result["llm_used"] is True
    assert result["executive_summary"]


def test_truncated_response_falls_back_cleanly(
    sample_findings, sample_manifest, tmp_path, monkeypatch
):
    """finish_reason=length (truncated JSON) must not half-merge — treat as
    API error so phase 6 falls back to the deterministic template visibly."""
    from spectre.pipeline import report_synthesize as rs
    from spectre.llm import LLMResponse

    class TruncatingProvider:
        name = "fake"
        def complete(self, *a, **k):
            return LLMResponse(
                parsed={"case_id": "079", "findings_narrative": []},  # keys lost to truncation
                finish_reason="length",
                raw="{...", model="fake",
            )

    monkeypatch.setattr(rs, "get_provider", lambda *a, **k: TruncatingProvider())
    result = rs.synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=False
    )
    assert result["llm_used"] is False
    assert "truncat" in (result["api_error"] or "").lower()
    assert result["executive_summary"] == ""


def test_truncated_anthropic_stop_reason_also_caught(
    sample_findings, sample_manifest, tmp_path, monkeypatch
):
    """Anthropic's raw stop_reason is "max_tokens"; the guard must fire for it
    too, not only for the OpenAI-style "length"."""
    from spectre.pipeline import report_synthesize as rs
    from spectre.llm import LLMResponse

    class TruncatingProvider:
        name = "fake"
        def complete(self, *a, **k):
            return LLMResponse(
                parsed={"case_id": "079", "findings_narrative": []},
                finish_reason="max_tokens", raw="{...", model="fake",
            )

    monkeypatch.setattr(rs, "get_provider", lambda *a, **k: TruncatingProvider())
    result = rs.synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=False
    )
    assert result["llm_used"] is False
    assert "truncat" in (result["api_error"] or "").lower()


def test_refusal_is_not_resent(
    sample_findings, sample_manifest, tmp_path, monkeypatch
):
    """A refusal is deterministic for the same request/model: no blind retry,
    and the refusal is what the caller sees as api_error."""
    from spectre.pipeline import report_synthesize as rs
    from spectre.llm import LLMResponse
    calls = {"n": 0}

    class RefusingProvider:
        name = "fake"
        def complete(self, *a, **k):
            calls["n"] += 1
            return LLMResponse(finish_reason="refusal", model="fake",
                               error="model refusal (category: cyber)")

    monkeypatch.setattr(rs, "get_provider", lambda *a, **k: RefusingProvider())
    result = rs.synthesize_report(
        sample_findings, sample_manifest, str(tmp_path), skip_ai=False
    )
    assert calls["n"] == 1
    assert result["llm_used"] is False
    assert "refusal" in (result["api_error"] or "")


# ── Track B1: evidence intake visibility ─────────────────────────────

def _intake_manifest():
    return {
        "case_id": "099",
        "triage": {
            "/case/evidence/traffic.pcap": {
                "status": "RECOGNIZED", "module": "pcap",
                "artifact_type": "pcap_conn", "confidence": 0.95},
            "/case/evidence/mystery.xyz": {
                "status": "UNRECOGNIZED", "module": None,
                "artifact_type": None, "confidence": 0.0},
            "/case/evidence/image.e01": {
                "status": "EXTRACTOR_PENDING", "module": "disk",
                "artifact_type": "disk_image", "tool": "libewf"},
        },
        "intake_skipped": [
            {"path": "/dump/empty.log", "reason": "empty file (0 bytes)"},
        ],
        "extraction": {"results": {
            "/case/evidence/traffic.pcap": {"events": 42, "module": "pcap"},
            "/case/evidence/mystery.xyz": {"skipped": "UNRECOGNIZED",
                                           "note": "no analyzer module claimed this file"},
        }},
    }


def test_intake_section_lists_every_file_and_outcome():
    from spectre.pipeline.report_synthesize import _generate_intake_section
    md = _generate_intake_section(_intake_manifest())
    assert "## Evidence Intake" in md
    assert "traffic.pcap" in md and "RECOGNIZED" in md and "42" in md
    assert "mystery.xyz" in md and "UNRECOGNIZED" in md
    assert "image.e01" in md and "EXTRACTOR_PENDING" in md and "libewf" in md
    assert "empty.log" in md and "empty file (0 bytes)" in md


def test_intake_section_empty_for_legacy_manifest():
    from spectre.pipeline.report_synthesize import _generate_intake_section
    assert _generate_intake_section({"case_id": "001"}) == ""


def test_intake_section_renders_channel_stats():
    from spectre.pipeline.report_synthesize import _generate_intake_section
    m = _intake_manifest()
    m["triage"]["/case/evidence/System.evtx"] = {
        "status": "RECOGNIZED", "module": "evtx",
        "artifact_type": "process_creation", "confidence": 0.95}
    m["extraction"]["results"]["/case/evidence/System.evtx"] = {
        "events": 0, "module": "evtx",
        "channel_stats": {"System": {"seen": 120, "parsed": 0, "supported": False}}}
    md = _generate_intake_section(m)
    assert "System: 0/120" in md and "channel not supported" in md


def test_intake_section_supported_channel_with_zero_matches_is_not_mislabeled():
    from spectre.pipeline.report_synthesize import _generate_intake_section
    m = _intake_manifest()
    m["triage"]["/case/evidence/Security.evtx"] = {
        "status": "RECOGNIZED", "module": "evtx",
        "artifact_type": "process_creation", "confidence": 0.95}
    m["extraction"]["results"]["/case/evidence/Security.evtx"] = {
        "events": 0, "module": "evtx",
        "channel_stats": {"Security": {"seen": 50, "parsed": 0, "supported": True}}}
    md = _generate_intake_section(m)
    assert "Security: 0/50" in md
    assert "no process-creation events" in md
    lines = [ln for ln in md.splitlines() if "Security: 0/50" in ln]
    assert lines and "channel not supported" not in lines[0]


def test_intake_section_renders_derived_evidence():
    from spectre.pipeline.report_synthesize import _generate_intake_section
    m = _intake_manifest()
    m["derived_evidence"] = {
        "/case/evidence/derived/img/Windows_..._Security.evtx": {
            "derived_from": "/case/evidence/image.dd",
            "in_image_path": "/Windows/System32/winevt/Logs/Security.evtx",
            "sha256": "ab" * 32, "status": "RECOGNIZED",
            "module": "evtx", "artifact_type": "process_creation"},
    }
    m["extraction"]["results"]["/case/evidence/derived/img/Windows_..._Security.evtx"] = {
        "events": 7, "module": "evtx", "derived_from": "/case/evidence/image.dd"}
    md = _generate_intake_section(m)
    assert "Derived evidence" in md
    assert "Security.evtx" in md and "image.dd" in md and "7 events" in md


def test_blindspots_flags_unrecognized_and_pending_evidence():
    from spectre.pipeline.report_synthesize import _generate_blindspots_md
    md = _generate_blindspots_md([], _intake_manifest(), {}, {}, "/tmp/nocase")
    assert "mystery.xyz" in md, "unrecognized evidence must be a stated blind spot"
    assert "image.e01" in md


# ── Report-honesty regression: "corroborated by multiple detection methods" ──
# Gold-loop audit found the report claiming N findings were "corroborated by
# multiple detection methods" where N == count of CONFIRMED-status findings.
# Real finding YAMLs show CONFIRMED can be reached via rule-level confidence
# (>=0.6) with corroboration.sources == 1 and cross_validated: false — i.e.
# CONFIRMED status does NOT imply multi-source corroboration. The report must
# key "corroborated by multiple methods" to the real cross_validated signal.

def _false_corroboration_claims(text: str) -> list[tuple[str, str]]:
    """Return (count, sentence) for every sentence that *asserts* (does not
    deny) a nonzero count of findings are corroborated by multiple detection
    methods. Sentence-scoped and negation-aware so honest statements like
    "none are corroborated by multiple ... methods" are NOT flagged."""
    hits = []
    for sent in re.split(r"(?<=[.!?])\s+", text):
        if not re.search(r"\bcorroborated\b", sent, re.IGNORECASE):
            continue
        if not re.search(r"\bmultiple\b", sent, re.IGNORECASE):
            continue
        if re.search(r"\bnone\b|\bnot\b|\bn['’]t\b|\bno\b", sent, re.IGNORECASE):
            continue
        m = re.search(r"\d+", sent)
        if m and m.group(0) != "0":
            hits.append((m.group(0), sent.strip()))
    return hits


def _confirmed_single_source_findings(n=3):
    """CONFIRMED-status findings that are genuinely single-source — matches
    real gold-run shape (rule-level confidence sets CONFIRMED even though
    only one detection tool ever fired; cross_validated stays false)."""
    out = []
    for i in range(n):
        out.append({
            "finding_id": f"F-212-{i+1:03d}",
            "title": f"Inbound connection to commonly-malicious port ({i})",
            "status": "CONFIRMED",
            "confidence": 0.8,
            "mitre_attack": "T1571",
            "description": "",
            "event_time": "2026-03-11 00:27:30.155745",
            "corroboration": {
                "sources": 1,
                "tools": ["tcpdump/pcap_conn"],
                "artifacts": ["pcap [inbound]: 203.161.44.208.5555: tcp 0"],
            },
            "cross_validated": False,
            "iocs": {"ip": ["203.161.44.208"]},
            "forensic_caveats": ["PCAP shows network I/O, not process execution"],
            "evidence_refs": [{"execution_id": f"exec{i}"}],
        })
    return out


def test_confirmed_status_without_cross_validation_makes_no_multi_method_claim(
    sample_manifest, sample_mitre_map, tmp_path
):
    """All findings CONFIRMED, but cross_validated False / sources == 1 for
    every one: the report must NOT claim any nonzero count of findings are
    'corroborated by multiple detection methods' — that is the false
    statement the gold-loop audit caught. It must instead state the honest
    single-method limitation."""
    findings = _confirmed_single_source_findings(3)
    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    bad = _false_corroboration_claims(md)
    assert not bad, (
        f"report falsely claims multi-method corroboration: {bad}"
    )
    assert re.search(r"single[- ]?(?:detection )?(?:method|source)", md, re.IGNORECASE), (
        "report should honestly state findings rest on a single detection "
        "method each when nothing is cross-validated"
    )


def test_corroborated_count_reflects_only_cross_validated_findings(
    sample_manifest, sample_mitre_map, tmp_path
):
    """3 findings are CONFIRMED, but only 1 is genuinely cross-validated
    (2+ independent sources). Any 'corroborated by multiple methods' claim
    in the report must cite 1, never 3 (the CONFIRMED-status count)."""
    findings = _confirmed_single_source_findings(3)
    findings[0]["cross_validated"] = True
    findings[0]["corroboration"]["sources"] = 2
    findings[0]["corroboration"]["tools"] = ["tcpdump/pcap_conn", "tshark/pcap_conn"]

    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    matches = _false_corroboration_claims(md)
    assert matches, "expected at least one honest corroboration claim in the report"
    assert all(count == "1" for count, _ in matches), (
        f"corroboration claim must cite the cross_validated count (1), "
        f"not the CONFIRMED-status count (3): {matches}"
    )


def test_grouped_narrative_no_false_corroboration_claim(
    sample_manifest, sample_mitre_map, tmp_path
):
    """35 CONFIRMED, single-source findings grouped together (report groups
    when there are many findings of the same technique) must not claim
    'corroborated by multiple sources' — every one is single-source."""
    findings = _confirmed_single_source_findings(35)
    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    assert not re.search(r"corroborated by multiple sources", md, re.IGNORECASE)


def test_methodology_correlation_note_matches_real_corroboration(
    sample_manifest, sample_mitre_map, tmp_path
):
    """The Methodology section's 'Cross-Artifact Correlation' note must not
    claim single-source CONFIRMED findings were corroborated across multiple
    detection methods."""
    findings = _confirmed_single_source_findings(3)
    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    methodology_section = md[md.find("## 6. Methodology"):md.find("## 7. Verdict")]
    assert not _false_corroboration_claims(methodology_section)


def test_verdict_no_false_corroboration_claim_when_single_source(
    sample_manifest, sample_mitre_map, tmp_path
):
    """Verdict section (§7): CONFIRMED-but-single-source findings must not be
    described as 'corroborated by multiple detection methods'."""
    findings = _confirmed_single_source_findings(3)
    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert not _false_corroboration_claims(verdict_section)


# ── Task 3 (D4): cross-artifact absence signals — verdict tempering ──────
# Gold case 004 is a benign CTF memory image with only a single-source lead
# (a masquerade-ish finding); the synthesizer must not frame that as a
# compromise. _absence_signals feeds grounded negatives ("no outbound
# connections", "no persistence findings", ...) into both the LLM prompt and
# the deterministic verdict, gated strictly on manifest["detection"]
# ["plugins_run"] (see phase_runner.py — written from extraction handles).

def _benign_memory_manifest():
    return {
        "case_id": "004", "case_name": "ctf", "artifact_profile": "memory",
        "canary_status": "FULL",
        "artifacts": ["memory"],
        "gate_0": {"fk_yamls_loaded": [], "passed": True},
        "detection": {
            "rules_evaluated": 5, "rules_fired": 1,
            "plugins_run": ["memory_netscan", "memory_malfind", "memory_pslist"],
        },
    }


def _masquerade_lead():
    return [{
        "finding_id": "F-004-001",
        "title": "process-name-masquerade",
        "status": "INFERRED",
        "confidence": 0.4,
        "mitre_attack": "T1036.005",
        "description": "A process name closely resembles a legitimate Windows binary.",
        "corroboration": {"sources": 1, "tools": ["vol:pslist"], "artifacts": []},
        "iocs": {},
        "forensic_caveats": [],
        "evidence_refs": [{"execution_id": "exec1", "artifact_type": "memory_pslist"}],
    }]


def test_user_prompt_includes_absence_signals_section(sample_mitre_map):
    """The prompt carries a dedicated, clearly-labeled absence-signals block
    so the model can ground benign language in it rather than inventing a
    compromise narrative to fill the silence."""
    manifest = _benign_memory_manifest()
    findings = _masquerade_lead()
    prompt = _build_user_prompt(
        findings, manifest, sample_mitre_map, {}, manifest["detection"], "memory"
    )
    assert "Cross-Artifact Absence Signals" in prompt
    assert "no outbound" in prompt.lower()


def test_user_prompt_absence_section_empty_when_nothing_examined(sample_mitre_map):
    """No detection.plugins_run recorded -> the prompt must not fabricate a
    negative; it states there's insufficient coverage to ground one."""
    manifest = {"case_id": "004", "case_name": "ctf",
                "artifact_profile": "memory", "canary_status": "FULL",
                "detection": {}}
    prompt = _build_user_prompt(
        [], manifest, sample_mitre_map, {}, manifest["detection"], "memory"
    )
    assert "Cross-Artifact Absence Signals" in prompt
    assert "no outbound" not in prompt.lower()


def test_deterministic_verdict_tempered_by_absence_signals_when_benign(
    sample_mitre_map, tmp_path
):
    """The gold-004 shape: no CONFIRMED (high-confidence) finding, a single
    INFERRED lead, and plugins that ran and saw nothing malicious. The
    deterministic verdict branch must weigh that in rather than defaulting
    to compromise-shaped silence."""
    manifest = _benign_memory_manifest()
    findings = _masquerade_lead()
    md = _merge_report_md(
        None, findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert "no outbound" in verdict_section.lower()
    assert "persistence" in verdict_section.lower()


def test_deterministic_verdict_not_tempered_when_confirmed_finding_dominates(
    sample_mitre_map, tmp_path
):
    """A CONFIRMED malicious finding must stand on its own — absence signals
    for OTHER categories must not soften a verdict a high-confidence finding
    already establishes as malicious."""
    manifest = _benign_memory_manifest()
    findings = _confirmed_single_source_findings(1)  # CONFIRMED, T1571
    md = _merge_report_md(
        None, findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert "no outbound" not in verdict_section.lower()
    assert "malicious activity" in verdict_section.lower()


def test_absence_signals_respects_real_manifest_key(sample_mitre_map):
    """Sanity: the deterministic key the whole feature hangs off
    (detection.plugins_run) is what phase_runner.py actually writes (see
    _run_phase_3_live), not an assumed/invented key."""
    manifest = _benign_memory_manifest()
    sigs = _absence_signals(_masquerade_lead(), manifest)
    assert sigs, "expected grounded negatives for a benign memory case with plugins_run set"


# ── Track D Task 4 (D3): per-finding narrative subsections ───────────────

def test_threat_narrative_renders_per_finding_subsections_citing_finding_id(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """When findings_narrative is a list of {finding_id, narrative}, the
    Detailed Findings block renders ONE subsection per finding — headed by
    and citing its own finding_id — not one undifferentiated blob. The
    Appendix Finding Index already exists elsewhere; this is the
    per-finding narrative, not a duplicate of it."""
    llm_output = {
        "executive_summary": "Summary.",
        "threat_narrative": "Causal chain (F-004-001).",
        "findings_narrative": [
            {"finding_id": "F-004-001",
             "narrative": "F-004-001 shows a rundll32 execution from Temp."},
            {"finding_id": "F-004-002",
             "narrative": "F-004-002 shows an encoded PowerShell command."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "",
    }
    md = _merge_report_md(
        llm_output, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    narrative_start = md.find("## 1. Threat Narrative")
    narrative_end = md.find("## 2.")
    narrative = md[narrative_start:narrative_end]
    assert "#### F-004-001" in narrative
    assert "#### F-004-002" in narrative
    assert "F-004-001 shows a rundll32 execution from Temp." in narrative
    assert "F-004-002 shows an encoded PowerShell command." in narrative


# ── Track D Task 4 (D3): System Profile section ───────────────────────────

def test_system_profile_section_rendered_when_present(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """manifest['system_profile'] (Task 7 data path: memory_systeminfo) must
    render as a plain metadata section — never as a finding, never
    MITRE-mapped."""
    manifest = dict(sample_manifest)
    manifest["system_profile"] = {
        "hostname": "WIN-VICTIM01",
        "os_build": "19041.1.amd64fre.vb_release.191206-1406",
        "system_time": "2026-03-11T00:12:03Z",
    }
    md = _merge_report_md(
        None, sample_findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "## System Profile" in md
    assert "WIN-VICTIM01" in md
    assert "19041.1.amd64fre.vb_release.191206-1406" in md

    profile_start = md.find("## System Profile")
    rest = md[profile_start + len("## System Profile"):]
    next_heading = re.search(r"\n#{2,3} ", rest)
    profile_block = rest[:next_heading.start()] if next_heading else rest
    # The section may disclaim "no MITRE mapping" in prose, but must never
    # carry an actual technique ID or a finding_id — i.e. never read as a
    # finding/MITRE data path.
    assert not re.search(r"T\d{4}(?:\.\d{3})?", profile_block), (
        "system profile must never carry a MITRE technique ID"
    )
    assert "F-004-001" not in profile_block, "system profile must never read as a finding"


def test_system_profile_section_absent_when_not_present(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """No system_profile on the manifest -> no section at all (not even an
    empty one) — a memory_systeminfo-less case must not show the header."""
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "## System Profile" not in md


def test_system_profile_section_absent_when_empty_dict(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """An empty system_profile dict (e.g. windows.info ran but yielded no
    usable fields) must not render an empty section."""
    manifest = dict(sample_manifest)
    manifest["system_profile"] = {}
    md = _merge_report_md(
        None, sample_findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "## System Profile" not in md


# ── Track D Task 4 (D3): intake-fed, case-specific blind spots ───────────

def test_merge_forensic_blindspots_names_unrecognized_and_pending_files(
    sample_findings, sample_mitre_map, tmp_path
):
    """The IN-REPORT '## 4. Forensic Blind Spots' section (not just the
    separate blindspots.md) must name specific unrecognized/pending intake
    files by name, not generic boilerplate."""
    manifest = _intake_manifest()
    md = _merge_report_md(
        None, sample_findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    section_start = md.find("## 4. Forensic Blind Spots")
    section_end = md.find("## 5.")
    section = md[section_start:section_end]
    assert "mystery.xyz" in section
    assert "image.e01" in section


def test_carve_cap_hits_detected(tmp_path):
    """_carve_cap_hits flags a parent image whose carved-derived-evidence
    count reached the disk module's carve cap (200) — the pipeline
    truncated coverage and additional artifacts may exist uncarved."""
    from spectre.pipeline.report_synthesize import _carve_cap_hits

    manifest = {
        "derived_evidence": {
            f"/case/evidence/derived/img/{i}_evt.evtx": {
                "derived_from": "/case/evidence/image.dd", "status": "RECOGNIZED",
            }
            for i in range(200)
        }
    }
    hits = _carve_cap_hits(manifest)
    assert hits == ["/case/evidence/image.dd"]


def test_carve_cap_hits_empty_below_cap(tmp_path):
    from spectre.pipeline.report_synthesize import _carve_cap_hits

    manifest = {
        "derived_evidence": {
            f"/case/evidence/derived/img/{i}_evt.evtx": {
                "derived_from": "/case/evidence/image.dd", "status": "RECOGNIZED",
            }
            for i in range(5)
        }
    }
    assert _carve_cap_hits(manifest) == []


def test_blindspots_md_names_carve_cap_hit(tmp_path):
    """blindspots.md surfaces a named carve-cap hit, not boilerplate."""
    manifest = _intake_manifest()
    manifest["derived_evidence"] = {
        f"/case/evidence/derived/img/{i}_evt.evtx": {
            "derived_from": "/case/evidence/image.dd", "status": "RECOGNIZED",
        }
        for i in range(200)
    }
    md = _generate_blindspots_md([], manifest, {}, {}, "/tmp/nocase")
    assert "image.dd" in md
    assert "carve cap" in md.lower()


# ── WS7d: blindspots.md must be state-aware, not static boilerplate ──────
# (A11-04 self-contradiction, A11-08 engine-parity mislabeling, and the
# CONFIRMED->INFERRED framing gap — see report_synthesize.py's
# `_generate_blindspots_md`, `_finding_rule_ids`, `_gap_fill_skips`, and
# `_is_single_evidence_source_case`.)

def _pcap_blindspot_manifest(**overrides):
    manifest = {
        "case_id": "073", "case_name": "traffic", "artifact_profile": "pcap",
        "artifacts": ["pcap"],
        "gate_0": {"fk_yamls_loaded": []},
    }
    manifest.update(overrides)
    return manifest


def _dns_question_snippet(md: str) -> str:
    idx = md.index("Were DNS queries captured and analyzed for suspicious TLDs?")
    end = md.find("- **Q:**", idx + 1)
    return md[idx: end if end != -1 else idx + 300]


def test_blindspots_dns_assessed_when_dns_anomaly_rule_fired_via_manifest():
    """A11-04: real finding YAMLs never carry a top-level `rule_id` key (only
    manifest['detection']['findings'] does — see _finding_rule_ids). The DNS
    blind-spot question must be derived through that helper, not a bare
    f.get('rule_id'), or 6 CONFIRMED pcap-dns-anomaly findings coexist with a
    literal 'DNS extraction pass needed' claim in the same report package."""
    findings = [
        {"finding_id": f"F-073-{i:03d}", "status": "CONFIRMED", "confidence": 0.6,
         "mitre_attack": "T1568.002", "corroboration": {"sources": 2}}
        for i in range(1, 7)
    ]
    manifest = _pcap_blindspot_manifest(detection={"findings": [
        {"finding_id": f"F-073-{i:03d}", "rule_id": "pcap-dns-anomaly"}
        for i in range(1, 7)
    ]})
    md = _generate_blindspots_md(findings, manifest, {}, {}, "/tmp/nocase")
    snippet = _dns_question_snippet(md)
    assert "UNVERIFIED" not in snippet
    assert "ASSESSED" in snippet


def test_blindspots_dns_assessed_when_rule_id_on_finding_directly():
    """Simpler fixture shape (rule_id set directly on the finding dict, as
    other tests in this file already do) must also flip DNS to ASSESSED."""
    findings = [
        {"finding_id": "F-073-001", "rule_id": "pcap-dns-anomaly",
         "status": "CONFIRMED", "confidence": 0.6, "mitre_attack": "T1568.002",
         "corroboration": {"sources": 2}},
    ]
    manifest = _pcap_blindspot_manifest()
    md = _generate_blindspots_md(findings, manifest, {}, {}, "/tmp/nocase")
    snippet = _dns_question_snippet(md)
    assert "UNVERIFIED" not in snippet
    assert "ASSESSED" in snippet


def test_blindspots_dns_still_unverified_when_no_dns_rule_fired():
    """Negative control: when no DNS-TLD rule actually fired, the UNVERIFIED
    template text remains legitimate — it must not be flipped unconditionally."""
    findings = [
        {"finding_id": "F-073-001", "rule_id": "pcap-c2-protocol",
         "status": "CONFIRMED", "confidence": 0.6, "mitre_attack": "T1071.001",
         "corroboration": {"sources": 2}},
    ]
    manifest = _pcap_blindspot_manifest()
    md = _generate_blindspots_md(findings, manifest, {}, {}, "/tmp/nocase")
    snippet = _dns_question_snippet(md)
    assert "UNVERIFIED" in snippet
    assert "ASSESSED" not in snippet


def test_blindspots_gap_fill_skip_named_as_known_limitation():
    """A11-08: when Phase 2 records a gap-fill pass as skipped because its
    tool was unavailable this run (manifest['extraction']['results'][*]
    ['gap_fill_skipped']), the matching blind-spot question must name it as
    a KNOWN engine/tool limitation of THIS run — not generic 'not performed'
    boilerplate indistinguishable from an ordinary scope decision."""
    manifest = _pcap_blindspot_manifest(extraction={"results": {
        "evidence/case.pcap": {
            "gap_fill_skipped": [
                {"extract_pass": "timing", "artifact_type": "pcap_timing",
                 "tool": "bash",
                 "reason": "bash unavailable/failed: [Errno 2] No such "
                           "file or directory: 'bash'"},
            ]
        }
    }})
    md = _generate_blindspots_md([], manifest, {}, {}, "/tmp/nocase")
    idx = md.index("Are there beacon patterns (regular intervals) from any monitored IP?")
    snippet = md[idx: idx + 400]
    assert "UNVERIFIED" not in snippet
    assert "not performed" not in snippet
    assert "KNOWN LIMITATION" in snippet
    assert "timing" in snippet
    assert "bash" in snippet


def test_blindspots_gap_fill_skip_does_not_leak_to_unrelated_question():
    """A skip recorded for one capability (http) must not bleed into an
    unrelated question's status (e.g. DNS, which has its own template
    text and was never in scope of the http gap-fill pass)."""
    manifest = _pcap_blindspot_manifest(extraction={"results": {
        "evidence/case.pcap": {
            "gap_fill_skipped": [
                {"extract_pass": "http", "artifact_type": "pcap_http",
                 "tool": "tcpdump", "reason": "tcpdump unavailable/failed"},
            ]
        }
    }})
    md = _generate_blindspots_md([], manifest, {}, {}, "/tmp/nocase")
    dns_snippet = _dns_question_snippet(md)
    assert "KNOWN LIMITATION" not in dns_snippet
    assert "UNVERIFIED" in dns_snippet

    http_idx = md.index(
        "Was HTTP payload on port 443 plaintext (HTTP) or encrypted (TLS)?"
    )
    http_snippet = md[http_idx: http_idx + 300]
    assert "KNOWN LIMITATION" in http_snippet
    assert "tcpdump" in http_snippet


def test_blindspots_single_source_framing_present_when_all_inferred():
    """CONFIRMED->INFERRED framing gap: when every finding in the case never
    reached multi-source corroboration (WS2/WS3: CONFIRMED requires
    corroboration.sources >= 2), blindspots.md must explain that INFERRED
    here means high-confidence single-source detection, not a weak result."""
    findings = [
        {"finding_id": "F-073-001", "status": "INFERRED", "confidence": 0.5,
         "corroboration": {"sources": 1}},
        {"finding_id": "F-073-002", "status": "INFERRED", "confidence": 0.85,
         "corroboration": {"sources": 1}},
    ]
    manifest = _pcap_blindspot_manifest()
    md = _generate_blindspots_md(findings, manifest, {}, {}, "/tmp/nocase")
    assert "Confidence Framing" in md
    assert "high-confidence single-source" in md
    assert "INFERRED" in md
    assert "CONFIRMED" in md


def test_blindspots_single_source_framing_absent_when_multi_source():
    """Negative control: a genuinely multi-source case (a finding with
    corroboration.sources >= 2) must NOT get the single-source caveat —
    it would misrepresent a corroborated case as single-source."""
    findings = [
        {"finding_id": "F-073-001", "status": "CONFIRMED", "confidence": 0.85,
         "corroboration": {"sources": 2}},
        {"finding_id": "F-073-002", "status": "INFERRED", "confidence": 0.5,
         "corroboration": {"sources": 1}},
    ]
    manifest = _pcap_blindspot_manifest()
    md = _generate_blindspots_md(findings, manifest, {}, {}, "/tmp/nocase")
    assert "Confidence Framing" not in md
    assert "high-confidence single-source" not in md


def test_blindspots_single_source_framing_absent_when_no_findings():
    """No findings at all -> nothing to caveat; the section must not appear
    for an empty-findings case (e.g. intake-only blindspots.md calls)."""
    manifest = _pcap_blindspot_manifest()
    md = _generate_blindspots_md([], manifest, {}, {}, "/tmp/nocase")
    assert "Confidence Framing" not in md


def test_gap_fill_skips_deduplicates_and_sorts_deterministically():
    from spectre.pipeline.report_synthesize import _gap_fill_skips
    manifest = {"extraction": {"results": {
        "a.pcap": {"gap_fill_skipped": [
            {"extract_pass": "timing", "tool": "bash", "reason": "r1"},
            {"extract_pass": "http", "tool": "tcpdump", "reason": "r2"},
        ]},
        "b.pcap": {"gap_fill_skipped": [
            {"extract_pass": "timing", "tool": "bash", "reason": "r1-dup"},
        ]},
    }}}
    skips = _gap_fill_skips(manifest)
    assert len(skips) == 2
    passes = [s["extract_pass"] for s in skips]
    assert passes == sorted(passes)


def test_is_single_evidence_source_case_true_when_sources_never_exceed_one():
    from spectre.pipeline.report_synthesize import _is_single_evidence_source_case
    findings = [{"corroboration": {"sources": 1}}, {"corroboration": {"sources": 1}}]
    assert _is_single_evidence_source_case(findings) is True


def test_is_single_evidence_source_case_false_when_any_finding_multi_source():
    from spectre.pipeline.report_synthesize import _is_single_evidence_source_case
    findings = [{"corroboration": {"sources": 1}}, {"corroboration": {"sources": 2}}]
    assert _is_single_evidence_source_case(findings) is False


def test_is_single_evidence_source_case_false_when_empty():
    from spectre.pipeline.report_synthesize import _is_single_evidence_source_case
    assert _is_single_evidence_source_case([]) is False


# ── Task 9 fold-in: MITRE composite-label rendering regression guard ─────

def test_composite_mitre_label_drsuapi_rule_renders_clean_technique_name(
    sample_manifest, tmp_path
):
    """The smb-drsuapi-opnum rule's mitre-map.yaml label is a composite
    ('OS Credential Dumping: DCSync / Account Discovery: Domain Account —
    DRSUAPI opnum granularity ...'). A finding mapped to a single technique
    from that rule (T1087.002, the DsCrackNames opnum) must render ONLY its
    own canonical technique name — never the rule's composite blob, and
    never a sibling technique's name (DCSync) bleeding in from the shared
    rule-level label."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH

    real_mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    f = _make_finding(
        "F-004-001", "T1087.002",
        "DRSUAPI DsCrackNames (opnum 12) — AD principal name resolution "
        "(SharpHound/BloodHound hallmark)",
    )
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], real_mitre_map)

    mitre_lines = [ln for ln in md.splitlines() if ln.startswith("**Status:**")]
    assert mitre_lines, "expected a Status/MITRE line in the evidence block"
    mitre_line = mitre_lines[0]
    assert "Account Discovery: Domain Account" in mitre_line
    assert "DCSync" not in mitre_line, "sibling technique's label leaked via the rule's composite"
    assert " / " not in mitre_line.split("—", 1)[-1], "rule-level composite separator leaked"


# ── Track E3 Task 2: Capture Scale aggregates in Executive Summary ───────

def test_human_bytes():
    from spectre.pipeline.report_synthesize import _human_bytes
    assert _human_bytes(52696108) == "50.3 MB"
    assert _human_bytes(1024) == "1.0 KB"
    assert _human_bytes(5_000_000_000) == "4.7 GB"
    assert _human_bytes(500) == "500 B"


def test_human_duration():
    from spectre.pipeline.report_synthesize import _human_duration
    assert _human_duration(604766.33) == "~7.0 days"
    assert _human_duration(7200) == "~2.0 hours"
    assert _human_duration(90) == "~1.5 minutes"


def test_capture_scale_block_rendered(sample_findings, sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = {
        "case_id": "003", "case_name": "scans", "artifact_profile": "auto",
        "capture_scale": {
            "total_packets": 313954, "file_size_bytes": 52696108,
            "capture_duration_seconds": 604766.33,
            "distinct_src_ips": 12330, "distinct_dst_ports": 31773,
        },
    }
    md = _merge_report_md(None, sample_findings, manifest, str(tmp_path), [], sample_mitre_map)
    assert "### Capture Scale" in md
    assert "313,954" in md
    assert "50.3 MB" in md
    assert "~7.0 days" in md
    assert "12,330" in md
    assert "31,773" in md
    # Inviolable rule: capture-scale block carries no MITRE technique id
    scale_section = md.split("### Capture Scale", 1)[1].split("\n\n", 1)[0]
    import re
    assert not re.search(r"T\d{4}", scale_section)


def test_capture_scale_block_omitted_when_absent(sample_findings, sample_manifest,
                                                 sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "### Capture Scale" not in md   # sample_manifest has no capture_scale


def test_overall_confidence_tiers():
    from spectre.pipeline.report_synthesize import _overall_confidence
    assert _overall_confidence([]) == "LOW"
    assert _overall_confidence([{"status": "INFERRED", "confidence": 0.5}]) == "LOW"
    assert _overall_confidence([{"status": "CONFIRMED", "confidence": 0.8}]) == "MEDIUM"
    assert _overall_confidence([
        {"status": "CONFIRMED", "confidence": 0.8, "cross_validated": True}
    ]) == "HIGH"


def test_confidence_banner_and_table(sample_findings, sample_manifest,
                                     sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "**Overall Confidence:**" in md          # banner in header
    assert "### Confidence Assessment" in md          # per-claim table


# ── Track E3 Task 4: role-segmented IOC export (§5) ──────────────────
def test_segment_iocs_roles_by_rule_id():
    from spectre.pipeline.report_synthesize import _segment_iocs
    findings = [
        {"finding_id": "F-1", "rule_id": "pcap-exposed-service", "confidence": 0.9,
         "iocs": {"ip": ["9.9.9.9"]}},
        {"finding_id": "F-2", "rule_id": "pcap-c2-protocol", "confidence": 0.8,
         "iocs": {"ip": ["5.5.5.5"]}},
        {"finding_id": "F-3", "rule_id": "pcap-suspicious-port", "confidence": 0.4,
         "iocs": {"ip": ["1.2.3.4"]}},
        {"finding_id": "F-4", "rule_id": "pcap-host-identity", "confidence": 0.7,
         "iocs": {"host": ["DESKTOP-X"], "account": ["bob@X"]}},
        {"finding_id": "F-5", "rule_id": "some-unknown-rule", "confidence": 0.3,
         "iocs": {"ip": ["7.7.7.7"]}},
    ]
    seg = _segment_iocs(findings, {"monitored_ip": "10.0.0.1"})
    assert ("ip", "9.9.9.9", "F-1", 0.9) in seg["Exposed Services"]
    assert ("ip", "5.5.5.5", "F-2", 0.8) in seg["Malware C2 & Payload Hosts"]
    assert ("ip", "1.2.3.4", "F-3", 0.4) in seg["Scanner Infrastructure"]
    assert ("host", "DESKTOP-X", "F-4", 0.7) in seg["Host & Account Identity"]
    assert ("ip", "7.7.7.7", "F-5", 0.3) in seg["Other"]          # unknown rule -> Other


def test_segment_iocs_monitored_host_wins():
    from spectre.pipeline.report_synthesize import _segment_iocs
    findings = [{"finding_id": "F-1", "rule_id": "pcap-c2-protocol",
                 "confidence": 0.8, "iocs": {"ip": ["10.0.0.1"]}}]
    seg = _segment_iocs(findings, {"monitored_ip": "10.0.0.1"})
    assert ("ip", "10.0.0.1", "F-1", 0.8) in seg["Monitored Host"]
    assert seg["Malware C2 & Payload Hosts"] == []


def test_segmented_ioc_export_rendered(sample_manifest, sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [{"finding_id": "F-1", "rule_id": "pcap-exposed-service",
                 "status": "CONFIRMED", "confidence": 0.9, "mitre_attack": "T1133",
                 "iocs": {"ip": ["9.9.9.9"]}, "evidence_refs": []}]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "## 5. IOC Export" in md
    assert "### Exposed Services" in md
    assert "9.9.9.9" in md
    assert "| Claim | Findings | Confidence | Basis |" in md


def test_recommended_actions_exposed_service():
    from spectre.pipeline.report_synthesize import _recommended_actions
    findings = [{"finding_id": "F-1", "rule_id": "pcap-exposed-service",
                 "confidence": 0.9, "iocs": {"ip": ["9.9.9.9"]}}]
    immediate, followup = _recommended_actions(findings, {})
    assert any("Firewall or authenticate" in a and "9.9.9.9" in a for a in immediate)
    # baseline follow-up always present
    assert any("Correlate with endpoint telemetry" in a for a in followup)


def test_recommended_actions_c2_and_identity():
    from spectre.pipeline.report_synthesize import _recommended_actions
    findings = [
        {"finding_id": "F-1", "rule_id": "pcap-c2-protocol", "confidence": 0.8,
         "iocs": {"ip": ["5.5.5.5"]}},
        # W4-4: only an identity bound to the monitored host (host_ip set by
        # the normalizer on an ip/mac match) is contained.
        {"finding_id": "F-2", "rule_id": "pcap-host-identity", "confidence": 0.7,
         "host_ip": "10.0.0.5",
         "iocs": {"host": ["DESKTOP-X"], "account": ["bob@X"]}},
    ]
    immediate, _ = _recommended_actions(findings, {"monitored_ip": "10.0.0.5"})
    assert any("Block the identified C2/payload hosts" in a and "5.5.5.5" in a for a in immediate)
    assert any("DESKTOP-X" in a and "bob@X" in a for a in immediate)


def test_recommended_actions_baseline_only_when_nothing_fires():
    from spectre.pipeline.report_synthesize import _recommended_actions
    findings = [{"finding_id": "F-1", "rule_id": "some-benign-rule",
                 "confidence": 0.3, "iocs": {"ip": ["1.1.1.1"]}}]
    immediate, followup = _recommended_actions(findings, {})
    assert immediate == []
    assert followup == ["Correlate with endpoint telemetry, memory, and disk "
                        "evidence before final determination."]


def test_recommended_actions_section_rendered(sample_manifest, sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [{"finding_id": "F-1", "rule_id": "pcap-exposed-service",
                 "status": "CONFIRMED", "confidence": 0.9, "mitre_attack": "T1133",
                 "iocs": {"ip": ["9.9.9.9"]}, "evidence_refs": []}]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "## Recommended Actions" in md
    assert "**Immediate:**" in md
    assert "1. Firewall or authenticate" in md


# ── Track E3 Task 6: case-specific blind spots (§4) ──────────────────
def test_blindspot_dcsync_not_observed(sample_manifest, sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [{"finding_id": "F-1", "rule_id": "pcap-host-identity",
                 "status": "CONFIRMED", "confidence": 0.7, "mitre_attack": "T1087.002",
                 "iocs": {"account": ["bob@X"]}, "evidence_refs": [
                     {"execution_id": "x", "artifact_type": "pcap_conn"}]}]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "Was DCSync (credential replication) attempted?" in md
    assert "NOT OBSERVED" in md


def test_blindspot_dcsync_suppressed_when_dcsync_present(sample_manifest,
                                                         sample_mitre_map, tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [
        {"finding_id": "F-1", "mitre_attack": "T1087.002", "confidence": 0.7,
         "iocs": {}, "evidence_refs": []},
        {"finding_id": "F-2", "mitre_attack": "T1003.006", "confidence": 0.8,
         "iocs": {}, "evidence_refs": []},
    ]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "Was DCSync (credential replication) attempted?" not in md


def test_blindspot_dcsync_fires_on_composite_mitre_string(sample_manifest,
                                                           sample_mitre_map, tmp_path):
    """A finding's mitre_attack field is a comma-joined composite string in the
    real world (e.g. samr/netlogon pipe rules mapping to multiple techniques).
    The DCSync blind-spot check must split on commas, not substring/equality
    match the whole field, to correctly detect T1087.002 among siblings."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [{"finding_id": "F-1", "rule_id": "pcap-ad-recon-pipe",
                 "status": "CONFIRMED", "confidence": 0.7,
                 "mitre_attack": "T1087.002, T1021.002",
                 "iocs": {}, "evidence_refs": []}]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "Was DCSync (credential replication) attempted?" in md
    assert "NOT OBSERVED" in md


def test_blindspot_dcsync_suppressed_on_composite_mitre_string(sample_manifest,
                                                                sample_mitre_map, tmp_path):
    """Suppression must also honor the comma-split: T1003.006 present as part
    of a composite mitre_attack string should suppress the row."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    findings = [{"finding_id": "F-1", "rule_id": "pcap-ad-recon-pipe",
                 "status": "CONFIRMED", "confidence": 0.8,
                 "mitre_attack": "T1003.006, T1087.002",
                 "iocs": {}, "evidence_refs": []}]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "Was DCSync (credential replication) attempted?" not in md


def test_blindspot_single_evidence_source(sample_manifest, sample_mitre_map, tmp_path):
    """Family is derived from manifest['artifacts'], the authoritative
    artifact-profile list — not from finding evidence_refs."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = dict(sample_manifest)
    manifest["artifacts"] = ["pcap"]
    findings = [{"finding_id": "F-1", "mitre_attack": "T1133", "confidence": 0.9,
                 "iocs": {"ip": ["9.9.9.9"]},
                 "evidence_refs": [{"execution_id": "x", "artifact_type": "pcap_conn"}]}]
    md = _merge_report_md(None, findings, manifest, str(tmp_path), [], sample_mitre_map)
    assert "Single evidence source (pcap)" in md


def test_blindspot_single_evidence_source_memory_only(sample_manifest, sample_mitre_map,
                                                        tmp_path):
    """A memory-only case must not render the pcap-flavored wording ('no ...
    memory data to corroborate network observations' is self-contradictory
    when the sole source IS memory). The Why cell must be source-agnostic."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = dict(sample_manifest)
    manifest["artifacts"] = ["memory"]
    findings = [{"finding_id": "F-1", "mitre_attack": "T1055", "confidence": 0.8,
                 "iocs": {},
                 "evidence_refs": [{"execution_id": "x",
                                    "artifact_type": "memory_pslist"}]}]
    md = _merge_report_md(None, findings, manifest, str(tmp_path), [], sample_mitre_map)
    assert "Single evidence source (memory)" in md
    assert "to corroborate network observations" not in md


def test_blindspot_single_evidence_source_no_artifact_type_on_refs(
    sample_manifest, sample_mitre_map, tmp_path
):
    """Regression test: real finding YAMLs' evidence_refs carry only
    execution_id/source — no artifact_type key. The single-evidence-source
    row must still fire, driven by manifest['artifacts'], not evidence_refs.
    This is the exact shape that exposed the Track E3 bug (row never fired
    on real cases because evidence_refs-derived _e3_arts was always empty)."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = dict(sample_manifest)
    manifest["artifacts"] = ["pcap"]
    findings = [{"finding_id": "F-1", "mitre_attack": "T1133", "confidence": 0.9,
                 "iocs": {"ip": ["9.9.9.9"]},
                 "evidence_refs": [{"execution_id": "x", "source": "tshark"}]}]
    md = _merge_report_md(None, findings, manifest, str(tmp_path), [], sample_mitre_map)
    assert "Single evidence source (pcap)" in md


def test_blindspot_suppressed_multi_evidence_from_manifest(
    sample_manifest, sample_mitre_map, tmp_path
):
    """When manifest['artifacts'] spans more than one evidence-type family,
    the single-evidence-source row must not fire — even if every individual
    finding's evidence_refs happen to point at only one artifact type."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = dict(sample_manifest)
    manifest["artifacts"] = ["pcap", "memory"]
    findings = [{"finding_id": "F-1", "mitre_attack": "T1133", "confidence": 0.9,
                 "iocs": {"ip": ["9.9.9.9"]},
                 "evidence_refs": [{"execution_id": "x", "source": "tshark"}]}]
    md = _merge_report_md(None, findings, manifest, str(tmp_path), [], sample_mitre_map)
    assert "Corroboration across evidence types" not in md


# ── Track H: Host-Based IOCs table + Campaign Tags table ─────────────
# Both tables must be built ONLY from corroboration.artifacts text that
# findings already carry — no lookups outside the finding, nothing invented.
# See the track-H case001 report-tables design spec.

def _campaign_finding(fid, artifact_text, mitre="T1071.001"):
    return {
        "finding_id": fid,
        "title": artifact_text,
        "status": "CONFIRMED",
        "confidence": 0.85,
        "mitre_attack": mitre,
        "corroboration": {"sources": 1, "tools": ["tcpdump/pcap_http"],
                           "artifacts": [artifact_text]},
        "iocs": {"ip": ["1.2.3.4"], "domain": [], "filepath": []},
    }


@pytest.fixture
def case268_shaped_findings():
    """Findings shaped like the real F-268-* fixtures: corroboration.artifacts
    carries 'User-Agent matches: ...', 'Campaign tag KEY=VALUE (family)', and
    'C2 parameter KEY=VALUE' fragments exactly as the pcap rule pack writes
    them. Covers all 9 tag keys actually present in case 268, plus the T1-0
    encrypted-payload parameter (which must NOT be treated as a campaign tag)."""
    return [
        _campaign_finding(
            "F-268-009",
            "pcap C2: User-Agent matches: (KHTML like Gecko), Campaign tag "
            "z8=MN12STGOG (XLoader / FormBook), C2 parameter T1-0=abc123==",
        ),
        _campaign_finding(
            "F-268-025",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "mk1=dT41, C2 parameter T1-0=def456==",
        ),
        _campaign_finding(
            "F-268-029",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "6V=FVySw7A, C2 parameter T1-0=ghi789==",
        ),
        _campaign_finding(
            "F-268-030",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "SV=3F6cwjCi7Ycm",
        ),
        _campaign_finding(
            "F-268-031",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "reFq=-ech08rf",
        ),
        _campaign_finding(
            "F-268-032",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "TW=8upS2zljiuP",
        ),
        _campaign_finding(
            "F-268-033",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "UGZ=QKzs5KRhGBka-bql",
        ),
        _campaign_finding(
            "F-268-034",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "fHR=Ozho",
        ),
        _campaign_finding(
            "F-268-035",
            "pcap C2: User-Agent matches: (KHTML like Gecko), C2 parameter "
            "ma8kQ=snqv6lu",
        ),
    ]


def test_build_campaign_tags_table_surfaces_all_present_tags(case268_shaped_findings):
    """Every distinct campaign-tag key present in the findings' artifacts
    surfaces as a row — including the 8 tags that were never namedropped in
    prose before Track H (only z8 was)."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    rows = _build_campaign_tags_table(case268_shaped_findings)
    tags = {tag for tag, _, _ in rows}
    assert tags == {"z8", "mk1", "6V", "SV", "reFq", "TW", "UGZ", "fHR", "ma8kQ"}
    by_tag = {tag: value for tag, value, _ in rows}
    assert by_tag["z8"] == "MN12STGOG"
    assert by_tag["mk1"] == "dT41"
    assert by_tag["6V"] == "FVySw7A"


def test_build_campaign_tags_table_excludes_t1_0_payload_param(case268_shaped_findings):
    """T1-0 is the encrypted base64 C2 payload parameter, not a rotating
    campaign/config tag — it must never appear as a row in this table even
    though it matches the same 'C2 parameter KEY=VALUE' artifact shape."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    rows = _build_campaign_tags_table(case268_shaped_findings)
    tags = {tag for tag, _, _ in rows}
    assert "T1-0" not in tags


def test_build_campaign_tags_table_z8_interpretation_from_finding_text(case268_shaped_findings):
    """The z8 interpretation is the malware-family name already written into
    the finding by the deterministic rule pack (grounded) — not a fabricated
    label."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    rows = _build_campaign_tags_table(case268_shaped_findings)
    by_tag = {tag: interp for tag, _, interp in rows}
    assert "XLoader / FormBook" in by_tag["z8"]


def test_build_campaign_tags_table_other_tags_no_invented_role(case268_shaped_findings):
    """Tags with no family mapping in the finding text get a neutral,
    non-fabricated interpretation — never a specific semantic guess
    ('hardware ID', 'configuration version', etc.) that isn't grounded in
    any finding field."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    rows = _build_campaign_tags_table(case268_shaped_findings)
    by_tag = {tag: interp for tag, _, interp in rows}
    for tag in ("mk1", "6V", "SV", "reFq", "TW", "UGZ", "fHR", "ma8kQ"):
        interp = by_tag[tag].lower()
        assert "hardware" not in interp
        assert "affiliate" not in interp
        assert "configuration version" not in interp


def test_build_campaign_tags_table_not_hardcoded_to_case_268(case268_shaped_findings):
    """The helper is a generic text parser, not a case-268-specific lookup:
    tags absent from case 268 (wxv, 7p) surface when a fixture actually
    contains them, proving nothing is hardcoded to the 9-tag set."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    findings = case268_shaped_findings + [
        _campaign_finding("F-268-999", "pcap C2: C2 parameter wxv=YWiL12505XDZ, "
                                       "C2 parameter 7p=QbbknGsGi"),
    ]
    rows = _build_campaign_tags_table(findings)
    tags = {tag for tag, _, _ in rows}
    assert "wxv" in tags
    assert "7p" in tags


def test_build_campaign_tags_table_empty_when_no_campaign_artifacts():
    """No fabricated rows when no finding ever matched a campaign parameter."""
    from spectre.pipeline.report_synthesize import _build_campaign_tags_table
    findings = [{"finding_id": "F-1", "corroboration": {"artifacts": ["pcap flow: some other text"]}}]
    assert _build_campaign_tags_table(findings) == []


def test_build_host_iocs_table_surfaces_only_grounded_ua_fragment(case268_shaped_findings):
    """The only Host-Based IOC fact any case-268 finding actually carries is
    the UA *signature fragment* the pcap rule pack matched against its known
    C2 User-Agent indicator list — never a full UA string, OS version, URI
    regex, or filename (none of those exist in any finding's iocs/artifacts)."""
    from spectre.pipeline.report_synthesize import _build_host_iocs_table
    rows = _build_host_iocs_table(case268_shaped_findings)
    assert len(rows) == 1
    fact_type, value, note = rows[0]
    assert value == "(KHTML like Gecko)"
    # Must NOT be a reconstructed full UA string (the fabrication root-caused
    # in 001-gap-v4.md's root-cause note #1).
    assert "Mozilla" not in value
    assert "Windows NT" not in value


def test_build_host_iocs_table_no_os_filename_or_uri_rows_without_source(case268_shaped_findings):
    """No OS-version, downloaded-filename, or URI-pattern row is invented —
    those facts have no deterministic source in any case-268 finding."""
    from spectre.pipeline.report_synthesize import _build_host_iocs_table
    rows = _build_host_iocs_table(case268_shaped_findings)
    types = [t.lower() for t, _, _ in rows]
    assert not any("os" == t or "os version" in t for t in types)
    assert not any("filename" in t or "downloaded" in t for t in types)
    assert not any("uri" in t or "regex" in t for t in types)


def test_build_host_iocs_table_empty_when_no_ua_match():
    """No fabricated row when no finding ever matched a C2 User-Agent."""
    from spectre.pipeline.report_synthesize import _build_host_iocs_table
    findings = [{"finding_id": "F-1", "corroboration": {"artifacts": ["pcap flow: benign"]}}]
    assert _build_host_iocs_table(findings) == []


# ── Track L: full UA + OS rows (gold gap G2) ───────────────────────────────

_L_FULL_UA = (
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
    "(KHTML like Gecko) Chrome/35.0.1916.114 Safari/537.36"
)


def test_build_host_iocs_table_renders_full_ua_and_os_rows():
    """When a finding carries the Track L full-UA + OS markers, the table
    surfaces the full header and derived OS as real rows — and drops the
    apologetic 'signature fragment / not captured' row (now false)."""
    from spectre.pipeline.report_synthesize import _build_host_iocs_table
    findings = [
        _campaign_finding(
            "F-268-009",
            "pcap C2: User-Agent matches: (KHTML like Gecko) "
            f"| host User-Agent (full): {_L_FULL_UA} "
            "| host OS (from UA): Windows 7 / Server 2008 R2 (NT 6.1) "
            "[WOW64 — 32-bit process on 64-bit Windows]",
        ),
    ]
    rows = _build_host_iocs_table(findings)
    types = [t for t, _, _ in rows]
    values = {t: v for t, v, _ in rows}
    assert "Host User-Agent (full header)" in types
    assert values["Host User-Agent (full header)"] == _L_FULL_UA
    assert "Host OS (derived from User-Agent)" in types
    assert "Windows 7" in values["Host OS (derived from User-Agent)"]
    # The apologetic fragment row is gone once the full header is present.
    assert not any("fragment" in t.lower() for t in types)
    assert not any("not captured" in note.lower() for _, _, note in rows)


def test_build_host_iocs_table_keeps_fragment_row_without_full_ua():
    """Back-compat: a finding with only the old fragment marker (no full-UA
    marker) still yields the fragment row exactly as before."""
    from spectre.pipeline.report_synthesize import _build_host_iocs_table
    findings = [
        _campaign_finding("F-1", "pcap C2: User-Agent matches: (KHTML like Gecko)"),
    ]
    rows = _build_host_iocs_table(findings)
    assert len(rows) == 1
    fact_type, value, note = rows[0]
    assert value == "(KHTML like Gecko)"
    assert "fragment" in fact_type.lower()


def test_merge_report_renders_campaign_tags_and_host_iocs_tables(
    case268_shaped_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """The rendered report's IOC Export section carries both new subsections,
    with all 9 campaign tags visible to an examiner reading the markdown."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(
        None, case268_shaped_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "### Host-Based IOCs" in md
    assert "### Campaign Tags" in md
    assert "(KHTML like Gecko)" in md
    for tag in ("z8", "mk1", "6V", "SV", "reFq", "TW", "UGZ", "fHR", "ma8kQ"):
        assert f"| {tag} " in md
    # The encrypted payload parameter must never surface as a campaign tag row.
    assert "| T1-0 " not in md


def test_merge_report_omits_new_tables_when_no_campaign_or_ua_data(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Non-pcap findings (no campaign/UA artifact text at all) render neither
    new subsection — nothing is fabricated to fill an empty table."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    assert "### Host-Based IOCs" not in md
    assert "### Campaign Tags" not in md
# ── Track G: per-finding narrative depth + causal threat narrative ────
# Gap: gold (case 001) has a causal attack-chain Threat Narrative and a
# Detailed Findings section (Evidence/Assessment/Confidence per finding).
# Spectre had neither; findings_narrative rendered flat under §1. These
# deepen the model prose — so every deepened field MUST still pass the
# same grounding validators (the inviolable rule).

def _grounded_pcap_findings():
    """Two findings whose IOCs are the ONLY grounded literals — anything else
    IOC-shaped in model prose is fabricated and must be stripped."""
    return [
        {
            "finding_id": "F-268-001",
            "title": "Staging download from files.catbox.moe",
            "status": "CONFIRMED",
            "confidence": 0.70,
            "mitre_attack": "T1105",
            "event_time": "2026-01-15T22:19:45Z",
            "iocs": {"ip": ["108.181.20.35"], "domain": ["files.catbox.moe"]},
            "forensic_caveats": ["TLS-encrypted payload — cannot confirm file hash from PCAP."],
            "evidence_refs": [{"execution_id": "abc123def456", "artifact_type": "pcap_http"}],
        },
        {
            "finding_id": "F-268-002",
            "title": "Large secondary transfer",
            "status": "INFERRED",
            "confidence": 0.45,
            "mitre_attack": "T1105",
            "event_time": "2026-01-15T22:45:08Z",
            "iocs": {"ip": ["23.205.110.9"]},
            "forensic_caveats": ["TLS-encrypted payload — cannot confirm file hash from PCAP."],
            "evidence_refs": [{"execution_id": "def456ghi789", "artifact_type": "pcap_http"}],
        },
    ]


def test_schema_requires_threat_narrative():
    """REPORT_SCHEMA must declare threat_narrative as a required string field."""
    from spectre.pipeline.report_synthesize import REPORT_SCHEMA
    assert "threat_narrative" in REPORT_SCHEMA["properties"]
    assert REPORT_SCHEMA["properties"]["threat_narrative"]["type"] == "string"
    assert "threat_narrative" in REPORT_SCHEMA["required"]


def test_user_prompt_asks_for_causal_threat_narrative(
    pcap_findings, sample_manifest, sample_mitre_map
):
    """The prompt must ask for a causal attack chain with timestamps and F-ID
    cross-refs (gold parity), distinct from the timeline listing."""
    prompt = _build_user_prompt(
        pcap_findings, sample_manifest, sample_mitre_map, {}, {}, "pcap"
    )
    assert "threat_narrative" in prompt
    low = prompt.lower()
    assert "causal" in low or "attack chain" in low
    # must instruct timestamps + finding_id cross-refs in the chain
    assert "timestamp" in low
    assert "finding_id" in low


def test_merge_renders_threat_narrative_and_detailed_findings(
    sample_manifest, sample_mitre_map, tmp_path
):
    """LLM threat_narrative renders under §1; findings_narrative renders as a
    Detailed Findings block with an Assessment label per finding, wrapped by
    the deterministic evidence/confidence block."""
    findings = _grounded_pcap_findings()
    llm_output = {
        "executive_summary": "XLoader staging then C2 (F-268-001).",
        "threat_narrative": (
            "At 2026-01-15T22:19:45Z the host downloaded a staging payload "
            "(F-268-001); this led directly to the secondary transfer at "
            "2026-01-15T22:45:08Z (F-268-002)."
        ),
        "findings_narrative": [
            {"finding_id": "F-268-001",
             "narrative": "F-268-001 is the initial staging download and the "
                          "root of the intrusion chain."},
            {"finding_id": "F-268-002",
             "narrative": "F-268-002 is the follow-on bulk transfer consistent "
                          "with exfiltration or stage retrieval."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "Malicious (F-268-001).",
    }
    md = _merge_report_md(
        llm_output, findings, sample_manifest, str(tmp_path), [], sample_mitre_map
    )
    section1 = md[md.find("## 1. Threat Narrative"):md.find("## 2.")]
    # Causal chain prose rendered
    assert "led directly to the secondary transfer" in section1
    # Detailed Findings block present, with per-finding Assessment prose
    assert "Detailed Findings" in section1
    assert "**Assessment:**" in section1
    assert "root of the intrusion chain" in section1
    # Deterministic Evidence/Confidence still rendered alongside the assessment
    assert "**Status:**" in section1
    assert "**Confidence:**" in section1


def test_threat_narrative_ungrounded_ioc_is_stripped(
    sample_fk_caveats
):
    """THE load-bearing grounding test: a fabricated IOC (User-Agent + IP not
    in any finding) placed in the NEW threat_narrative field must be stripped
    by _validate_report and logged as a violation — the deepened prose stays
    authoritative-validated, exactly as case 001's invented MSIE UA should
    have been caught."""
    findings = _grounded_pcap_findings()
    fabricated_ua = ("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; "
                     "Trident/4.0)")
    output = {
        "executive_summary": "Summary (F-268-001).",
        "threat_narrative": (
            "The host at 108.181.20.35 downloaded a payload (F-268-001). "
            f"The C2 traffic used {fabricated_ua} to beacon to 9.9.9.9 "
            "(F-268-002)."
        ),
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "v (F-268-001).",
    }
    cleaned, violations = _validate_report(
        output, findings, sample_fk_caveats, ["T1105"]
    )
    # The fabricated-UA/IP sentence is gone; the grounded first sentence stays.
    tn = cleaned["threat_narrative"]
    assert "MSIE 7.0" not in tn
    assert "Trident" not in tn
    assert "9.9.9.9" not in tn
    assert "108.181.20.35" in tn  # grounded literal survives
    assert any("threat_narrative" in v for v in violations)


def test_detailed_findings_assessment_ungrounded_ioc_is_stripped(
    sample_manifest, sample_mitre_map, sample_fk_caveats, tmp_path
):
    """The deepened per-finding Assessment prose is still grounded: an
    ungrounded IP in a findings_narrative item is stripped before it can be
    rendered into the Detailed Findings block."""
    findings = _grounded_pcap_findings()
    output = {
        "executive_summary": "Summary (F-268-001).",
        "threat_narrative": "Chain summary (F-268-001).",
        "findings_narrative": [
            {"finding_id": "F-268-001",
             "narrative": "F-268-001 staging download. It also contacted "
                          "203.0.113.250 which is not in any finding."},
        ],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "v (F-268-001).",
    }
    cleaned, violations = _validate_report(
        output, findings, sample_fk_caveats, ["T1105"]
    )
    narr = cleaned["findings_narrative"][0]["narrative"]
    assert "203.0.113.250" not in narr
    # And the rendered report never shows the fabricated IP either.
    md = _merge_report_md(
        cleaned, findings, sample_manifest, str(tmp_path), violations, sample_mitre_map
    )
    assert "203.0.113.250" not in md


def test_threat_narrative_coerced_and_confidence_stripped(sample_fk_caveats):
    """threat_narrative gets the same non-string coercion and numeric-confidence
    stripping as the other narrative fields."""
    findings = _grounded_pcap_findings()
    output = {
        "executive_summary": "S (F-268-001).",
        # non-string (a live model occasionally returns a list/dict)
        "threat_narrative": ["Step one (F-268-001).",
                             "Confidence of 0.91 in step two (F-268-002)."],
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "v (F-268-001).",
    }
    cleaned, violations = _validate_report(
        output, findings, sample_fk_caveats, ["T1105"]
    )
    assert isinstance(cleaned["threat_narrative"], str)
    assert "Step one" in cleaned["threat_narrative"]
    # numeric confidence claim removed
    assert "0.91" not in cleaned["threat_narrative"]


# ── Track K: monitored-host naming (gold gap G1) ──────────────────────
def test_segment_iocs_seeds_monitored_host_from_manifest():
    """The monitored host lives in each finding's host_ip, never in iocs, so it
    never matches a finding IOC value. When monitored_ip is known but the
    Monitored Host segment would otherwise be empty, seed it from the manifest
    so the subject host is surfaced in the IOC export (fixes E3 Component 3)."""
    from spectre.pipeline.report_synthesize import _segment_iocs
    findings = [
        {"finding_id": "F-1", "rule_id": "pcap-c2-protocol", "confidence": 0.9,
         "host_ip": "10.1.13.175", "iocs": {"ip": ["5.5.5.5"]}},
    ]
    seg = _segment_iocs(findings, {"monitored_ip": "10.1.13.175"})
    assert ("ip", "10.1.13.175", "(subject host)", 0.0) in seg["Monitored Host"]
    # the C2 IOC is still routed to its own segment
    assert ("ip", "5.5.5.5", "F-1", 0.9) in seg["Malware C2 & Payload Hosts"]


def test_segment_iocs_no_seed_when_monitored_absent():
    """Non-pcap cases (no monitored_ip) get no synthetic Monitored Host row."""
    from spectre.pipeline.report_synthesize import _segment_iocs
    findings = [{"finding_id": "F-1", "rule_id": "pcap-c2-protocol",
                 "confidence": 0.9, "iocs": {"ip": ["5.5.5.5"]}}]
    seg = _segment_iocs(findings, {})            # no monitored_ip
    assert seg["Monitored Host"] == []


def test_segment_iocs_no_double_seed_when_finding_matches():
    """If a finding IOC already equals monitored_ip, the segment is populated
    from that finding — do NOT also seed a synthetic row."""
    from spectre.pipeline.report_synthesize import _segment_iocs
    findings = [{"finding_id": "F-1", "rule_id": "pcap-c2-protocol",
                 "confidence": 0.8, "iocs": {"ip": ["10.0.0.1"]}}]
    seg = _segment_iocs(findings, {"monitored_ip": "10.0.0.1"})
    assert seg["Monitored Host"] == [("ip", "10.0.0.1", "F-1", 0.8)]


def test_subject_host_line_rendered(sample_findings, sample_mitre_map, tmp_path):
    """A **Subject Host:** line names the monitored host in the Exec Summary."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    manifest = {"case_id": "001", "case_name": "xloader",
                "artifact_profile": "auto", "monitored_ip": "10.1.13.175"}
    md = _merge_report_md(None, sample_findings, manifest, str(tmp_path), [],
                          sample_mitre_map)
    assert "**Subject Host:** 10.1.13.175" in md
    # It sits up top (Exec Summary), before the numbered detail sections.
    assert md.index("Subject Host") < md.index("## 1. Threat Narrative")


def test_subject_host_line_omitted_when_absent(sample_findings, sample_manifest,
                                               sample_mitre_map, tmp_path):
    """Non-pcap cases render no Subject Host line (sample_manifest lacks it)."""
    from spectre.pipeline.report_synthesize import _merge_report_md
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path),
                          [], sample_mitre_map)
    assert "Subject Host" not in md


def test_build_user_prompt_includes_subject_host(sample_findings, sample_mitre_map):
    """The synthesis prompt tells the model the monitored host by IP so the
    narrative can refer to it as the subject host."""
    from spectre.pipeline.report_synthesize import _build_user_prompt
    manifest = {"case_id": "001", "case_name": "xloader",
                "artifact_profile": "auto", "monitored_ip": "10.1.13.175"}
    prompt = _build_user_prompt(sample_findings, manifest, sample_mitre_map,
                                {}, {}, "auto")
    assert "10.1.13.175" in prompt
    assert "Subject Host" in prompt


def test_build_user_prompt_omits_subject_host_when_absent(
        sample_findings, sample_manifest, sample_mitre_map):
    from spectre.pipeline.report_synthesize import _build_user_prompt
    prompt = _build_user_prompt(sample_findings, sample_manifest, sample_mitre_map,
                                {}, {}, "fixture-test")
    # The instruction clause always mentions "Subject Host" (guarded by
    # "If a Subject Host is listed…"); what must be absent is the populated
    # Case-Metadata data line when no monitored host is known.
    assert "- Subject Host (monitored):" not in prompt


def test_monitored_ip_grounded_but_fabricated_ip_stripped(sample_fk_caveats):
    """Load-bearing: feeding monitored_ip to the prompt must not loosen
    grounding. monitored_ip == host_ip (a grounded finding field) so the model
    may name it; a DIFFERENT, fabricated IP is still stripped by Validator 10."""
    from spectre.pipeline.report_synthesize import _validate_report
    findings = [{
        "finding_id": "F-1", "status": "CONFIRMED", "confidence": 0.85,
        "host_ip": "10.1.13.175",
        "iocs": {"ip": ["5.5.5.5"]},
        "description": "C2 beacon.",
    }]
    output = {
        "executive_summary": "The subject host 10.1.13.175 beaconed to C2. "
                             "It also contacted 203.0.113.99 covertly.",
        "findings_narrative": [],
        "timeline_narrative": "", "methodology_narrative": "", "verdict": "",
    }
    cleaned, violations = _validate_report(
        output, findings, sample_fk_caveats, ["T1071.001"])
    # grounded via host_ip -> the sentence naming it survives
    assert "10.1.13.175" in cleaned["executive_summary"]
    # fabricated IP -> its sentence is stripped and a violation recorded
    assert "203.0.113.99" not in cleaned["executive_summary"]
    assert any("203.0.113.99" in v for v in violations)


# ── Fix wave 1 (Finding 3): absence_sentence must reach a surviving model
# verdict, not just the deterministic template branches ──────────────────

def test_surviving_model_verdict_gets_absence_sentence_appended(
    sample_mitre_map, tmp_path
):
    """The gold-004 shape (benign memory, single INFERRED lead, plugins ran
    and saw nothing malicious) but with a model verdict that does NOT
    contradict the leads-only class — it must survive Validator 11's guard
    and still get the deterministic grounded-negative sentence appended,
    exactly like the template branches below it already do."""
    manifest = _benign_memory_manifest()
    findings = _masquerade_lead()
    llm_output = {
        "verdict": "These observations are investigative leads requiring "
                   "corroboration.",
    }
    md = _merge_report_md(
        llm_output, findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert "investigative leads requiring corroboration" in verdict_section
    assert "Cross-artifact analysis found:" in verdict_section


# ── Fix wave 1 (Finding 4): end-to-end propagation of a blanked verdict ───

def test_blanked_verdict_falls_through_to_deterministic_template(
    sample_mitre_map, tmp_path
):
    """Pins that _merge_report_md itself renders the deterministic
    '**No corroborated findings.**' template when llm_output["verdict"] is
    empty — the exact state Validator 11 leaves behind on a leads-only/none
    class. This test calls _merge_report_md directly with a hand-built
    llm_output dict; it does not exercise synthesize_report or
    _validate_report, so it pins the merge-site fallback rendering in
    isolation, not end-to-end propagation through the full pipeline."""
    manifest = _benign_memory_manifest()
    findings = _masquerade_lead()  # leads-only: single INFERRED finding
    llm_output = {"verdict": ""}  # what Validator 11 leaves behind
    md = _merge_report_md(
        llm_output, findings, manifest, str(tmp_path), [], sample_mitre_map
    )
    verdict_section = md[md.find("## 7. Verdict"):]
    assert "**No corroborated findings.**" in verdict_section


# ── Spec C / C1: scale + quantification rendering ────────────────────
# (imports consolidated into the top-of-file import block)


def test_parse_finding_ts_handles_zulu_and_bad_input():
    dt = _parse_finding_ts("2026-06-27T14:30:00Z")
    assert dt is not None and dt.year == 2026 and dt.minute == 30
    assert _parse_finding_ts("") is None
    assert _parse_finding_ts("not-a-timestamp") is None
    assert _parse_finding_ts(None) is None


def test_finding_scale_phrase_with_count_and_span():
    f = {
        "occurrence_count": 264,
        "first_seen": "2026-06-27T14:00:00Z",
        "last_seen": "2026-06-27T15:19:00Z",
    }
    phrase = _finding_scale_phrase(f)
    assert phrase.startswith("264 observations from 2026-06-27T14:00:00Z "
                             "to 2026-06-27T15:19:00Z")
    # 79-minute span: _human_duration rolls to hours above 60 min (~1.3 hours).
    assert "over ~1.3 hours" in phrase


def test_finding_scale_phrase_mixed_tz_aware_and_naive_does_not_crash():
    # Regression: one offset-bearing ('Z') + one naive timestamp must not raise
    # TypeError at the span subtraction (both normalised to UTC-naive). 14:00Z
    # to 15:00 naive -> a ~1.0 hour span, rendered, not crashed.
    f = {"occurrence_count": 5, "first_seen": "2026-06-27T14:00:00Z",
         "last_seen": "2026-06-27T15:00:00"}
    phrase = _finding_scale_phrase(f)
    assert phrase.startswith("5 observations from 2026-06-27T14:00:00Z to 2026-06-27T15:00:00")
    assert "over ~1.0 hours" in phrase


def test_rollup_mixed_tz_aware_and_naive_does_not_crash():
    # Same regression at the roll-up's max(lasts)/min(firsts) span arithmetic.
    findings = [
        {"finding_id": "F-1", "occurrence_count": 200,
         "first_seen": "2026-06-27T14:00:00Z", "last_seen": "2026-06-27T15:00:00Z"},
        {"finding_id": "F-2", "occurrence_count": 64,
         "first_seen": "2026-06-27T14:30:00", "last_seen": "2026-06-27T15:19:00"},
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1", "rule_id": "pcap-beacon"},
        {"finding_id": "F-2", "rule_id": "pcap-beacon"},
    ]}}
    body = "\n".join(_rollup_scale_lines(findings, manifest))  # must not raise
    assert "264 observations" in body and "over" in body


def test_finding_scale_phrase_omits_span_when_timestamps_absent():
    f = {"occurrence_count": 42}
    assert _finding_scale_phrase(f) == "42 observations"


def test_finding_scale_phrase_omits_span_when_timestamps_unparseable():
    f = {"occurrence_count": 42, "first_seen": "early", "last_seen": "late"}
    phrase = _finding_scale_phrase(f)
    assert phrase == "42 observations from early to late"  # count + literal range, NO span
    assert "over" not in phrase


def test_finding_scale_phrase_empty_when_count_le_one():
    assert _finding_scale_phrase({"occurrence_count": 1}) == ""
    assert _finding_scale_phrase({}) == ""  # default 1


def test_scale_phrase_renders_in_evidence_block(sample_manifest, sample_mitre_map, tmp_path):
    f = _make_finding("F-532-001", "T1071.001", "HTTP beacon to C2")
    f["occurrence_count"] = 264
    f["first_seen"] = "2026-06-27T14:00:00Z"
    f["last_seen"] = "2026-06-27T15:19:00Z"
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "**Scale:** 264 observations from" in md


def test_rollup_sums_occurrence_counts_per_rule_group():
    findings = [
        {"finding_id": "F-1", "occurrence_count": 200,
         "first_seen": "2026-06-27T14:00:00Z", "last_seen": "2026-06-27T15:00:00Z"},
        {"finding_id": "F-2", "occurrence_count": 64,
         "first_seen": "2026-06-27T14:30:00Z", "last_seen": "2026-06-27T15:19:00Z"},
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1", "rule_id": "pcap-beacon"},
        {"finding_id": "F-2", "rule_id": "pcap-beacon"},
    ]}}
    lines = _rollup_scale_lines(findings, manifest)
    body = "\n".join(lines)
    assert "### Activity Volume" in body
    assert "264 observations" in body          # 200 + 64
    assert "pcap-beacon" in body
    assert "over ~1" in body and "hours" in body  # 14:00 -> 15:19 span


def test_rollup_omits_span_when_no_member_has_real_timestamps():
    findings = [
        {"finding_id": "F-1", "occurrence_count": 10},
        {"finding_id": "F-2", "occurrence_count": 5},
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1", "rule_id": "pcap-beacon"},
        {"finding_id": "F-2", "rule_id": "pcap-beacon"},
    ]}}
    lines = _rollup_scale_lines(findings, manifest)
    body = "\n".join(lines)
    assert "15 observations" in body
    assert "over" not in body  # no member carried parseable timestamps


def test_rollup_empty_when_no_real_scale():
    # Every member defaults to occurrence_count 1 -> total == member count -> nothing to roll up.
    findings = [{"finding_id": "F-1"}, {"finding_id": "F-2"}]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1", "rule_id": "pcap-beacon"},
        {"finding_id": "F-2", "rule_id": "pcap-beacon"},
    ]}}
    assert _rollup_scale_lines(findings, manifest) == []


def test_c1_no_invention_counts_only_from_findings():
    # Roll-up total must equal the exact sum of real occurrence_count values — never inflated.
    findings = [
        {"finding_id": "F-1", "occurrence_count": 7},
        {"finding_id": "F-2"},  # contributes its default of 1
    ]
    manifest = {"detection": {"findings": [
        {"finding_id": "F-1", "rule_id": "pcap-beacon"},
        {"finding_id": "F-2", "rule_id": "pcap-beacon"},
    ]}}
    body = "\n".join(_rollup_scale_lines(findings, manifest))
    assert "8 observations" in body  # 7 + 1, not 8+ anything fabricated


# ── Spec C / C2: tactic column + table hygiene ───────────────────────
# (imports consolidated into the top-of-file import block)


def test_mitre_tactics_yaml_covers_every_mapped_tid():
    """Completeness guard (mirrors the techniques-map guard): every tid in any
    mitre-map.yaml rule's 'allowed' list must have a tactics: entry, so a new
    rule/tid can't silently render tactic '—' by omission."""
    import yaml as _yaml
    from spectre.config import MITRE_MAP_PATH, MITRE_TECHNIQUES_PATH

    mitre_map = _yaml.safe_load(MITRE_MAP_PATH.read_text())
    mapped_tids = {
        tid
        for rule_data in mitre_map.get("rules", {}).values()
        for tid in rule_data.get("allowed", [])
    }
    tactics = _yaml.safe_load(MITRE_TECHNIQUES_PATH.read_text()).get("tactics", {})
    missing = mapped_tids - set(tactics.keys())
    assert not missing, f"tids missing from mitre_techniques.yaml tactics: {sorted(missing)}"


def test_load_mitre_tactics_returns_map():
    tactics = _load_mitre_tactics()
    assert tactics.get("T1071.001") == "Command and Control"
    assert tactics.get("T1595.002") == "Reconnaissance"


def test_resolve_tactic_composite_and_missing():
    tactics = {"T1071.001": "Command and Control", "T1105": "Command and Control",
               "T1046": "Discovery"}
    assert _resolve_tactic("T1071.001", tactics) == "Command and Control"
    assert _resolve_tactic("T1071.001, T1046", tactics) == "Command and Control, Discovery"
    assert _resolve_tactic("T9999", tactics) == "—"          # unknown tid -> em dash, no crash
    assert _resolve_tactic("UNMAPPED", tactics) == "—"
    assert _resolve_tactic("", tactics) == "—"


def test_cap_finding_ids():
    ids = [f"F-{i:03d}" for i in range(1, 36)]  # 35 ids
    out = _cap_finding_ids(ids, _MITRE_CELL_ID_CAP)
    assert out.startswith("F-001, F-002")
    assert "(+27 more)" in out                              # 35 - 8
    assert out.count("F-0") == _MITRE_CELL_ID_CAP           # only K ids listed
    assert _cap_finding_ids(["F-001"], _MITRE_CELL_ID_CAP) == "F-001"  # under cap: no suffix


def test_section2_has_tactic_column(sample_manifest, sample_mitre_map, tmp_path):
    f = _make_finding("F-004-001", "T1071.001", "HTTP beacon")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec2 = md[md.find("## 2."):md.find("## 3.")]
    assert "| Technique ID | Technique Name | Tactic | Finding IDs | Detection Rule |" in sec2
    row = [ln for ln in sec2.splitlines() if ln.startswith("| T1071.001")][0]
    assert "Command and Control" in row


def test_section2_unmapped_tid_renders_em_dash(sample_manifest, sample_mitre_map, tmp_path):
    # A finding whose technique has no tactics: entry must render '—', never crash.
    f = _make_finding("F-004-001", "T9999", "synthetic unknown technique")
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec2 = md[md.find("## 2."):md.find("## 3.")]
    row = [ln for ln in sec2.splitlines() if ln.startswith("| T9999")][0]
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[2] == "—"  # Tactic column


def test_section2_caps_large_finding_cell(sample_manifest, sample_mitre_map, tmp_path):
    findings = [_make_finding(f"F-004-{i:03d}", "T1071.001", "beacon") for i in range(1, 36)]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec2 = md[md.find("## 2."):md.find("## 3.")]
    row = [ln for ln in sec2.splitlines() if ln.startswith("| T1071.001")][0]
    assert "(+27 more)" in row
    assert row.count("F-004-0") == _MITRE_CELL_ID_CAP


def test_section2_no_invention_only_input_techniques_and_tactics(
    sample_manifest, sample_mitre_map, tmp_path
):
    """Spec Testing #5 archetype: a report built from findings whose only
    techniques are T1071.001 / T1105 shows ONLY those techniques and their
    tactics in §2 — the tactic map introduces no extra technique or tactic."""
    findings = [
        _make_finding("F-004-001", "T1071.001", "web C2"),
        _make_finding("F-004-002", "T1105", "tool transfer"),
    ]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec2 = md[md.find("## 2."):md.find("## 3.")]
    tid_rows = [ln for ln in sec2.splitlines()
                if ln.startswith("| T") and "Technique ID" not in ln]
    assert {r.split("|")[1].strip() for r in tid_rows} == {"T1071.001", "T1105"}
    # No tactic other than the two techniques' own tactic (both Command and Control) appears.
    assert "Reconnaissance" not in sec2
    assert "Exfiltration" not in sec2
    assert "Discovery" not in sec2


# ── Spec C / C3: artifact + field completeness ───────────────────────
# (imports consolidated into the top-of-file import block)


def test_recovered_credential_values_allowlisted_only():
    f = {"corroboration": {"artifacts": [
        "Archive password recovered: easypeasyvirus",
        "internal note: do not distribute widely",   # NOT allowlisted -> ignored
    ]}}
    assert _recovered_credential_values(f) == ["easypeasyvirus"]


def test_recovered_credential_values_dedupes_and_handles_empty():
    f = {"corroboration": {"artifacts": [
        "RAR password: hunter2", "ZIP password: hunter2",
    ]}}
    assert _recovered_credential_values(f) == ["hunter2"]
    assert _recovered_credential_values({}) == []
    assert _recovered_credential_values({"corroboration": {"artifacts": []}}) == []


def test_credential_renders_in_evidence_block(sample_manifest, sample_mitre_map, tmp_path):
    f = _make_finding("F-004-001", "T1560", "RAR archive staged")
    f["corroboration"] = {"artifacts": ["Archive password recovered: easypeasyvirus"]}
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "Recovered Credentials" in md
    assert "easypeasyvirus" in md


def test_non_allowlisted_blob_not_dumped(sample_manifest, sample_mitre_map, tmp_path):
    f = _make_finding("F-004-001", "T1560", "RAR archive staged")
    f["corroboration"] = {"artifacts": ["raw memory blob: 4f8a2c...deadbeef unvetted"]}
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    assert "deadbeef" not in md  # un-marked blob is never surfaced


def test_recovered_credential_value_does_not_over_capture_across_newline():
    # The capture group is newline-bounded: a marker match must not drag adjacent
    # (possibly sensitive) text on the next line into the surfaced value.
    f = {"corroboration": {"artifacts": [
        "Archive password recovered: hunter2\nInternal note: do-not-share",
    ]}}
    assert _recovered_credential_values(f) == ["hunter2"]


def test_dedupe_domains_case_insensitive():
    findings = [
        {"iocs": {"domain": ["Evil.RU", "evil.ru", "bad.TK"]}},
        {"iocs": {"domain": ["BAD.tk", "good.com"]}},
    ]
    assert _dedupe_domains(findings) == ["evil.ru", "bad.tk", "good.com"]


def test_tld_histogram_counts():
    hist = _tld_histogram(["evil.ru", "bad.ru", "x.tk", "plainhost"])
    # sorted by -count then tld asc; at count 1, "(none)" ('(' < 't') precedes "tk".
    assert hist == [("ru", 2), ("(none)", 1), ("tk", 1)]


def test_section5_renders_domain_list_and_histogram(sample_manifest, sample_mitre_map, tmp_path):
    f = _make_finding("F-004-001", "T1071.004", "DNS anomaly")
    f["iocs"] = {"domain": ["Evil.ru", "evil.RU", "bad.tk"]}
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec5 = md[md.find("## 5."):md.find("## 6.")]
    assert "Domain Indicators (deduplicated)" in sec5
    assert "`evil.ru`" in sec5 and "`bad.tk`" in sec5
    assert sec5.count("`evil.ru`") == 1        # mixed-case dup collapsed
    assert "| .ru | 1 |" in sec5 and "| .tk | 1 |" in sec5


def test_c3_no_invention_only_input_domains(sample_manifest, sample_mitre_map, tmp_path):
    """No-invention: the deduped domain list contains exactly the input domains
    (case-normalized), nothing added by the histogram arithmetic."""
    f = _make_finding("F-004-001", "T1071.004", "DNS anomaly")
    f["iocs"] = {"domain": ["a.ru", "b.tk"]}
    md = _merge_report_md(None, [f], sample_manifest, str(tmp_path), [], sample_mitre_map)
    sec5 = md[md.find("## 5."):md.find("## 6.")]
    dom_block = sec5[sec5.find("Domain Indicators"):]
    listed = {ln.strip("- `") for ln in dom_block.splitlines() if ln.startswith("- `")}
    assert listed == {"a.ru", "b.tk"}


# ── Spec C / C4: Key Findings BLUF digest ────────────────────────────
# (imports consolidated into the top-of-file import block)


def test_key_findings_digest_orders_by_confidence_then_id():
    findings = [
        {"finding_id": "F-3", "title": "c", "status": "INFERRED", "confidence": 0.40},
        {"finding_id": "F-1", "title": "a", "status": "CONFIRMED", "confidence": 0.90},
        {"finding_id": "F-2", "title": "b", "status": "CONFIRMED", "confidence": 0.90},
    ]
    lines = _key_findings_digest(findings)
    body = "\n".join(lines)
    assert "### Key Findings" in body
    # 0.90 findings first; tie broken by finding_id -> F-1 before F-2; then F-3.
    assert body.index("**a**") < body.index("**b**") < body.index("**c**")
    assert "**a** — CONFIRMED, confidence 0.90" in body


def test_key_findings_digest_includes_observation_count_when_present():
    findings = [{"finding_id": "F-1", "title": "beacon", "status": "CONFIRMED",
                 "confidence": 0.8, "occurrence_count": 264}]
    body = "\n".join(_key_findings_digest(findings))
    assert "**beacon** — CONFIRMED, confidence 0.80, 264 observations" in body


def test_key_findings_digest_caps_at_top_n():
    findings = [{"finding_id": f"F-{i:02d}", "title": f"t{i}", "status": "INFERRED",
                 "confidence": 0.5} for i in range(10)]
    lines = _key_findings_digest(findings)
    bullets = [ln for ln in lines if ln.startswith("- **")]
    assert len(bullets) == _KEY_FINDINGS_TOP_N


def test_key_findings_digest_empty_findings_no_header():
    assert _key_findings_digest([]) == []


def test_key_findings_digest_stable_across_reruns():
    findings = [
        {"finding_id": "F-2", "title": "b", "status": "CONFIRMED", "confidence": 0.7},
        {"finding_id": "F-1", "title": "a", "status": "CONFIRMED", "confidence": 0.7},
    ]
    assert _key_findings_digest(findings) == _key_findings_digest(findings)
    # deterministic tie-break: F-1 (title a) precedes F-2 (title b)
    body = "\n".join(_key_findings_digest(findings))
    assert body.index("**a**") < body.index("**b**")


def test_key_findings_renders_in_report(sample_findings, sample_manifest, sample_mitre_map, tmp_path):
    md = _merge_report_md(None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    exec_block = md[md.find("## Executive Summary"):md.find("## 1.")]
    assert "### Key Findings" in exec_block
    # BLUF: Key Findings appears before any Activity Volume / Capture Scale sub-blocks.
    kf = exec_block.find("### Key Findings")
    cs = exec_block.find("### Capture Scale")
    assert kf != -1 and (cs == -1 or kf < cs)


def test_c4_no_invention_titles_from_findings_only(sample_manifest, sample_mitre_map, tmp_path):
    """No-invention: every digest bullet's title comes from an input finding."""
    findings = [_make_finding("F-004-001", "T1071.001", "web C2 beacon")]
    md = _merge_report_md(None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map)
    exec_block = md[md.find("## Executive Summary"):md.find("## 1.")]
    kf_block = exec_block[exec_block.find("### Key Findings"):]
    assert "web C2 beacon" in kf_block
    # no title text that isn't one of the input findings' titles
    for ln in kf_block.splitlines():
        if ln.startswith("- **"):
            assert "web C2 beacon" in ln


# ── WS4 (A6 Finding 2): timeline/threat-chain must sort by parsed datetime,
# never by raw string. Mixed lexical shapes across artifact types (space-
# separated pcap-fallback, 'Z'-suffixed EVTX, '+00:00'-suffixed LNK/registry,
# and a bare unparseable epoch integer) must NOT invert chronology, and the
# unparseable value must fall into the honest "undated" bucket rather than
# being sorted by accident of string shape. ──

def _a6_mixed_format_findings():
    """The exact repro shapes of the fused-token grounding bypass."""
    return [
        {
            "finding_id": "F-004-002", "title": "pcap fallback event (actually LATEST)",
            "status": "INFERRED", "confidence": 0.5, "mitre_attack": "T1071.001",
            "event_time": "2024-08-01 23:00:00",
        },
        {
            "finding_id": "F-004-001", "title": "evtx early event (actually EARLIEST)",
            "status": "INFERRED", "confidence": 0.5, "mitre_attack": "T1059.001",
            "event_time": "2024-08-01T05:00:00Z",
        },
        {
            "finding_id": "F-004-003", "title": "lnk noon event (actually MIDDLE)",
            "status": "INFERRED", "confidence": 0.5, "mitre_attack": "T1204.002",
            "event_time": "2024-08-01T12:00:00+00:00",
        },
        {
            "finding_id": "F-004-004", "title": "disk bare epoch event (unparseable)",
            "status": "INFERRED", "confidence": 0.5, "mitre_attack": "T1105",
            "event_time": "1735689600",
        },
    ]


def test_deterministic_threat_chain_sorts_by_parsed_datetime_not_string():
    """_deterministic_threat_chain must anchor on the true earliest/latest
    PARSEABLE finding, not the string-sorted first/last. Ground truth:
    F-004-001 (05:00) is earliest, F-004-002 (23:00) is latest, among the
    3 ISO-parseable findings; the bare-epoch finding is excluded from the
    dated count (honest 'undated' bucket), never sorted by string accident."""
    findings = _a6_mixed_format_findings()
    chain = _deterministic_threat_chain(findings)
    text = " ".join(chain)
    assert "from F-004-001" in text, (
        f"expected chain to anchor on the true-earliest finding F-004-001, got: {text}"
    )
    assert "to F-004-002" in text, (
        f"expected chain to anchor on the true-latest finding F-004-002, got: {text}"
    )
    # The bare-epoch finding is unparseable -> excluded from the dated
    # sequence (3 dated observations: F-004-001, F-004-002, F-004-003).
    assert "3 dated observation" in text


def test_timeline_table_sorts_mixed_iso_shapes_chronologically(
    sample_manifest, sample_mitre_map, tmp_path
):
    """Fallback Timeline table (§3, no LLM narrative): rows must render in
    true chronological order across incompatible event_time lexical shapes,
    and the unparseable bare-epoch finding must land in the 'Undated
    findings' block rather than being string-sorted into the dated table."""
    findings = _a6_mixed_format_findings()
    md = _merge_report_md(
        None, findings, sample_manifest, str(tmp_path), [], sample_mitre_map,
    )
    timeline = md.split("## 3. Timeline")[1].split("## 4.")[0]

    early_pos = timeline.index("evtx early event")
    mid_pos = timeline.index("lnk noon event")
    late_pos = timeline.index("pcap fallback event")
    assert early_pos < mid_pos < late_pos, (
        "timeline must be in true chronological order, not string-sorted"
    )

    assert "**Undated findings**" in timeline
    dated_block, undated_block = timeline.split("**Undated findings**", 1)
    assert "disk bare epoch event" not in dated_block
    assert "disk bare epoch event" in undated_block
    assert "F-004-004" in undated_block


def test_report_header_declares_utc_timestamp_basis(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """WS4 sub-task 6: the rendered report header must explicitly state the
    timezone basis of evidence timestamps (only true now that findings 1-5
    make it so) — a courtroom-facing report must never leave this implicit."""
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map,
    )
    header = md.split("---", 1)[0]
    assert "UTC" in header
    assert re.search(r"timestamps?.{0,40}UTC|UTC.{0,40}timestamps?", header, re.IGNORECASE), (
        f"expected an explicit UTC timestamp-basis statement in the report header, got: {header}"
    )


# ── WS9: timestamp caveats reach report.md; Phase-5 disposition surfaced ──

_TS_OVERFLOW_CAVEAT = (
    "write_time FILETIME value does not fit in a representable timestamp "
    "(overflow/out-of-range) — this field is unparseable, not legitimately "
    "absent; treat the record as having a corrupted or hostile timestamp."
)


def test_ts_caveat_renders_in_report_md(
    sample_manifest, sample_mitre_map, tmp_path
):
    """A finding whose forensic_caveats carries a ts_caveat (WS9, relayed by
    emit_from_handle from the normalizer) shows that exact text in the
    rendered report.md Detailed Findings section."""
    finding = _make_finding(
        "F-004-001", "T1204.002", "lnk-suspicious-target",
        caveats=[_TS_OVERFLOW_CAVEAT],
    )
    md = _merge_report_md(
        None, [finding], sample_manifest, str(tmp_path), [], sample_mitre_map,
    )
    assert _TS_OVERFLOW_CAVEAT in md


def test_blindspots_ts_parse_error_produces_unparseable_timestamps_line(
    sample_manifest, sample_mitre_map, sample_fk_caveats, tmp_path
):
    """A finding carrying ts_parse_error=True (WS9) produces a dedicated
    'Unparseable Timestamps' blindspots line naming its finding_id."""
    finding = _make_finding(
        "F-004-001", "T1204.002", "lnk-suspicious-target",
        caveats=[_TS_OVERFLOW_CAVEAT],
    )
    finding["ts_parse_error"] = True

    md = _generate_blindspots_md(
        [finding], sample_manifest, sample_mitre_map, sample_fk_caveats, str(tmp_path)
    )

    assert "## Unparseable Timestamps" in md
    assert "F-004-001" in md.split("## Unparseable Timestamps", 1)[1]


def test_blindspots_no_ts_parse_error_no_unparseable_timestamps_line(
    sample_findings, sample_manifest, sample_mitre_map, sample_fk_caveats, tmp_path
):
    """Negative: findings with no ts_parse_error flag (the ordinary case —
    sample_findings carries none) must NOT produce the 'Unparseable
    Timestamps' section at all."""
    md = _generate_blindspots_md(
        sample_findings, sample_manifest, sample_mitre_map, sample_fk_caveats, str(tmp_path)
    )
    assert "## Unparseable Timestamps" not in md


def test_phase5_disposition_line_ran_reports_count():
    manifest = {"gate_5": {"substantive_review": "ran",
                            "counter_hypotheses_count": 3}}
    line = _phase5_disposition_line(manifest)
    assert "ran" in line
    assert "3 counter-hypotheses" in line


def test_phase5_disposition_line_ran_singular_count():
    manifest = {"gate_5": {"substantive_review": "ran",
                            "counter_hypotheses_count": 1}}
    line = _phase5_disposition_line(manifest)
    assert "1 counter-hypothesis" in line


def test_phase5_disposition_line_deferred_to_host():
    manifest = {"gate_5": {"substantive_review": "deferred-to-host",
                            "counter_hypotheses_count": 0}}
    line = _phase5_disposition_line(manifest)
    assert "deferred to the orchestrating agent" in line


def test_phase5_disposition_line_not_run():
    manifest = {"gate_5": {"substantive_review": "not-run",
                            "counter_hypotheses_count": 0}}
    line = _phase5_disposition_line(manifest)
    assert "No substantive Phase 5 adversarial review was performed" in line


def test_phase5_disposition_line_absent_gate5_is_empty():
    """Negative: a manifest with no gate_5 key at all (Phase 5 never ran in
    this context) must produce NO disposition line — never a false
    'not-run' claim fabricated from an absent key."""
    assert _phase5_disposition_line({}) == ""
    assert _phase5_disposition_line({"gate_5": {}}) == ""


def test_merge_report_md_renders_phase5_disposition(
    sample_findings, sample_mitre_map, tmp_path
):
    """The Phase 5 disposition line actually reaches the rendered report.md
    when the manifest carries a real gate_5.substantive_review state."""
    manifest = {
        "case_id": "004", "case_name": "test", "artifact_profile": "fixture-test",
        "canary_status": "FULL", "artifacts": ["evtx_4688"],
        "gate_0": {"fk_yamls_loaded": ["evtx_4688.yaml"], "passed": True},
        "gate_5": {"substantive_review": "deferred-to-host",
                   "counter_hypotheses_count": 0},
    }
    md = _merge_report_md(
        None, sample_findings, manifest, str(tmp_path), [], sample_mitre_map,
    )
    assert "deferred to the orchestrating agent" in md


def test_merge_report_md_no_false_not_run_line_without_gate5(
    sample_findings, sample_manifest, sample_mitre_map, tmp_path
):
    """Negative: sample_manifest (a clean multi-source-shaped case fixture)
    carries no gate_5 key at all — the rendered report must not claim
    'No substantive Phase 5 adversarial review was performed' or any other
    Phase-5 disposition text that was never actually recorded."""
    md = _merge_report_md(
        None, sample_findings, sample_manifest, str(tmp_path), [], sample_mitre_map,
    )
    assert "substantive Phase 5 adversarial review" not in md


def test_user_prompt_states_output_shape(sample_findings, sample_manifest,
                                         sample_mitre_map):
    """The prompt names every REPORT_SCHEMA field and the findings_narrative
    item shape (API providers never see the schema itself) — audit F10."""
    from spectre.pipeline.report_synthesize import REPORT_SCHEMA
    prompt = _build_user_prompt(
        sample_findings, sample_manifest, sample_mitre_map,
        {"evtx_4688": ["caveat 1"]}, sample_manifest.get("detection", {}),
        "fixture-test",
    )
    tail = prompt[prompt.rindex("Output only valid JSON"):]
    for key in REPORT_SCHEMA["properties"]:
        assert key in tail
    assert '{"finding_id": "...", "narrative": "..."}' in tail
