"""Track E1 — the synthesis layer must ground free-form narrative literals
against finding data, closing the case-001 fabricated-User-Agent hole."""
from spectre.pipeline.report_synthesize import _validate_report

# Real UA present in the deterministic finding (case 001 ground truth).
_REAL_UA = ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
            "(KHTML like Gecko) Chrome/35.0.1916.114 Safari/537.36")
# The fabricated UA the LLM invented at synthesis time (case 001).
_FAKE_UA = ("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; "
            "SLCC1; .NET CLR 2.0.50727)")


def _findings():
    return [{
        "finding_id": "F-268-002",
        "title": "C2 HTTP beacon to 45.131.214.85",
        "iocs": {"ip": ["45.131.214.85"], "user_agent": [_REAL_UA]},
        "corroboration": {"artifacts": [f"http UA {_REAL_UA}"]},
        "mitre_attack": "T1071.001",
    }]


def _base_output():
    return {
        "executive_summary": "",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
        "verdict": "",
    }


def test_fabricated_ua_stripped_from_exec_summary():
    out = _base_output()
    out["executive_summary"] = (
        f"The C2 channel used User-Agent {_FAKE_UA}. "
        "This indicates an automated implant.")
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "MSIE 7.0" not in cleaned["executive_summary"]
    assert "Trident" not in cleaned["executive_summary"]
    assert any("fabricated" in v.lower() for v in violations)


def test_grounded_ua_survives():
    out = _base_output()
    out["executive_summary"] = f"The implant used User-Agent {_REAL_UA} throughout."
    cleaned, _ = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "Chrome/35.0.1916.114" in cleaned["executive_summary"]


def test_fabricated_ip_stripped_from_verdict():
    out = _base_output()
    out["verdict"] = ("Attribution is LOW. The beacon reached 45.131.214.85. "
                      "A second channel to 8.8.4.4 was also observed.")
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "8.8.4.4" not in cleaned["verdict"]
    assert "45.131.214.85" in cleaned["verdict"]  # grounded — survives
    assert any("fabricated" in v.lower() for v in violations)


def test_fabricated_domain_stripped_from_timeline():
    out = _base_output()
    out["timeline_narrative"] = "At T+45s the host resolved evil-c2.example.net."
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "evil-c2.example.net" not in cleaned["timeline_narrative"]
    assert any("fabricated" in v.lower() for v in violations)


def test_plain_prose_untouched():
    out = _base_output()
    out["methodology_narrative"] = (
        "Network flows were reconstructed and correlated by source host.")
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert cleaned["methodology_narrative"] == out["methodology_narrative"]
    assert not any("fabricated" in v.lower() for v in violations)


def test_fabricated_ua_stripped_from_findings_narrative():
    # The case-001 fabrication must not survive by riding in findings_narrative
    # (even while citing the finding_id, which Validator 7 would wave through).
    out = _base_output()
    out["findings_narrative"] = [{
        "finding_id": "F-268-002",
        "narrative": (f"Finding F-268-002 shows the implant used {_FAKE_UA}. "
                      "It beaconed repeatedly."),
    }]
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    narr = cleaned["findings_narrative"][0]["narrative"]
    assert "MSIE 7.0" not in narr
    assert "Trident" not in narr
    assert any("fabricated" in v.lower() for v in violations)


def test_clean_paragraph_breaks_preserved():
    # M1: a clean section with only grounded content keeps its \n\n formatting.
    out = _base_output()
    out["executive_summary"] = (
        "The host contacted 45.131.214.85 over HTTP.\n\n"
        "This is consistent with a NetSupport RAT beacon.")
    cleaned, _ = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "\n\n" in cleaned["executive_summary"]


def test_defanged_fabricated_ip_stripped_from_threat_narrative():
    # WS7a sub-task 1/2 (A3 finding #1): a fabricated C2 IP formatted with
    # [.] defanging, cited alongside a real finding_id, previously survived
    # Validator 10 with zero violations because the token regex didn't
    # recognize the defanged form as an IOC at all.
    out = _base_output()
    out["threat_narrative"] = (
        "As documented in F-268-002, the attacker established command-and-"
        "control to 185[.]220[.]101[.]42 and exfiltrated sensitive data "
        "over the following days."
    )
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "185" not in cleaned["threat_narrative"]
    assert any("fabricated" in v.lower() for v in violations)


def test_zero_width_fabricated_ip_stripped_from_threat_narrative():
    out = _base_output()
    poisoned = "185.220.101​.42"  # zero-width space inside the address
    out["threat_narrative"] = (
        f"As documented in F-268-002, the attacker beaconed to {poisoned} "
        "as its command-and-control channel."
    )
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "185" not in cleaned["threat_narrative"]
    assert any("fabricated" in v.lower() for v in violations)


def test_defanged_grounded_ip_survives_in_verdict():
    # A legitimately-defanged mention of the finding's REAL IP must not be
    # treated as fabricated.
    out = _base_output()
    out["verdict"] = "Attribution is LOW. The beacon reached 45[.]131[.]214[.]85 repeatedly."
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "45[.]131[.]214[.]85" in cleaned["verdict"]
    assert not any("fabricated" in v.lower() for v in violations)


def test_case_001_regression_full_fake_ua():
    # The exact case-001 defect: fabricated MSIE UA in the exec summary while
    # the only real UA in findings is the Chrome/35 string.
    out = _base_output()
    out["executive_summary"] = (
        f"Command-and-control traffic used the User-Agent '{_FAKE_UA}', "
        "implying a Windows NT 6.0 victim.")
    cleaned, violations = _validate_report(out, _findings(), {}, ["T1071.001"])
    assert "MSIE" not in cleaned["executive_summary"]
    assert "6.0" not in cleaned["executive_summary"]  # wrong-OS claim rode the fake UA sentence
    assert any("fabricated" in v.lower() for v in violations)
