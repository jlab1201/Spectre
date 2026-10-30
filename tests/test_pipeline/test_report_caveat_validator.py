from spectre.pipeline.report_synthesize import _validate_report, _STANDARD_SCOPING_CAVEATS

FK = {"pcap_flow": ["A completed TCP handshake does not prove data was exfiltrated."]}
FINDINGS = [{"finding_id": "F-001-001", "corroboration": {"tools": ["tcpdump/pcap_flow"]}}]


def _validate(section_text):
    out = {"executive_summary": section_text, "threat_narrative": "", "verdict": "x",
           "timeline_narrative": "", "methodology_narrative": "", "findings_narrative": []}
    return _validate_report(out, FINDINGS, FK, [])


def test_fk_caveat_verbatim_passes():
    _, violations = _validate("A completed TCP handshake does not prove data was exfiltrated.")
    assert not any("caveat" in v.lower() for v in violations)


def test_paraphrased_fk_caveat_fails_closed():
    # Paraphrase — not verbatim — must be flagged.
    _, violations = _validate("The finished handshake does not prove that any data left the host.")
    assert any("caveat" in v.lower() for v in violations)


def test_fabricated_caveat_without_ioc_fails_closed():
    # Invented limitation resembling no FK caveat — the dangerous case.
    _, violations = _validate("The beaconing interval does not prove the objective of the intrusion.")
    assert any("caveat" in v.lower() for v in violations)


def test_template_standard_scoping_passes():
    # Our own deterministic template caveat must never self-flag.
    text = _STANDARD_SCOPING_CAVEATS[0]
    _, violations = _validate(text)
    assert not any("caveat" in v.lower() for v in violations)


def test_non_caveat_prose_is_untouched():
    _, violations = _validate("The host contacted 10.0.0.5 over TCP 443 at 14:03 UTC.")
    assert not any("caveat" in v.lower() for v in violations)
