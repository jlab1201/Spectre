"""Coverage honesty — a report must never assert a negative about evidence
nothing examined.

Spec: the module-selection design spec §5.1 (S-A).

The load-bearing case is the MODEL-AUTHORED verdict branch: under the default
SPECTRE_LLM_PROVIDER=host there is no _validate_report seam at all, so the
disclosure has to be composed deterministically into every branch rather than
enforced by a validator afterwards.
"""

from spectre.pipeline.report_synthesize import _coverage_counts, _coverage_sentence


def _manifest(results):
    return {"extraction": {"results": results}}


def test_coverage_counts_all_examined():
    m = _manifest({"/e/a.pcap": {"events": 10}, "/e/b.evtx": {"events": 3}})
    assert _coverage_counts(m) == (2, 2)


def test_coverage_counts_skipped_is_not_examined():
    m = _manifest({
        "/e/a.pcap": {"events": 10},
        "/e/b.evtx": {"skipped": "EXTRACTOR_PENDING", "tool": "evtxexport"},
    })
    assert _coverage_counts(m) == (1, 2)


def test_coverage_counts_error_is_not_examined():
    m = _manifest({"/e/a.pcap": {"error": "tool crashed"}})
    assert _coverage_counts(m) == (0, 1)


def test_coverage_sentence_empty_when_fully_examined():
    m = _manifest({"/e/a.pcap": {"events": 10}})
    assert _coverage_sentence(m) == ""


def test_coverage_sentence_empty_when_no_evidence_at_all():
    assert _coverage_sentence(_manifest({})) == ""


def test_coverage_sentence_partial_names_the_counts():
    m = _manifest({
        "/e/a.pcap": {"events": 10},
        "/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"},
        "/e/c.raw": {"skipped": "UNRECOGNIZED"},
    })
    s = _coverage_sentence(m)
    assert "2 of 3" in s
    assert "not examined" in s
    assert "Forensic Blind Spots" in s


def test_coverage_sentence_zero_examined_is_explicit():
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    s = _coverage_sentence(m)
    assert "No evidence was examined" in s
    assert "establishes nothing" in s


# ── Verdict-branch coverage disclosure ────────────────────────────────
# The model-authored branch is the important one: under the default
# SPECTRE_LLM_PROVIDER=host its prose reaches disk with no validator in the
# path, so the disclosure must be composed in deterministically.

def test_deterministic_no_findings_branch_discloses_zero_coverage():
    from spectre.pipeline.report_synthesize import _generate_verdict_section
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    md = "\n".join(_generate_verdict_section([], m, llm_output=None))
    assert "No evidence was examined" in md
    assert "establishes nothing" in md


def test_model_authored_branch_also_discloses_zero_coverage():
    from spectre.pipeline.report_synthesize import _generate_verdict_section
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    llm = {"verdict": "**No indicators of compromise were detected.**"}
    md = "\n".join(_generate_verdict_section([], m, llm_output=llm))
    assert "No evidence was examined" in md, \
        "model-authored verdict escaped coverage disclosure"


def test_partial_coverage_disclosed_even_with_confirmed_findings():
    """A confirmed finding does not excuse silence about unexamined evidence."""
    from spectre.pipeline.report_synthesize import _generate_verdict_section
    m = _manifest({
        "/e/a.pcap": {"events": 12},
        "/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"},
    })
    findings = [{"status": "CONFIRMED", "confidence": 0.9,
                 "mitre_attack": "T1059", "finding_id": "F-001-001"}]
    md = "\n".join(_generate_verdict_section(findings, m, llm_output=None))
    assert "1 of 2" in md
    assert "not examined" in md


def test_fully_examined_case_gets_no_coverage_sentence():
    from spectre.pipeline.report_synthesize import _generate_verdict_section
    m = _manifest({"/e/a.pcap": {"events": 12}})
    md = "\n".join(_generate_verdict_section([], m, llm_output=None))
    assert "not examined" not in md
    assert "No evidence was examined" not in md


# ── Validator 6: absence-assertion phrases ────────────────────────────
# Defence in depth behind the deterministic disclosure above: this seam only
# runs for an in-process API provider, never under the default host provider.

def _validate(output):
    from spectre.pipeline.report_synthesize import _validate_report
    return _validate_report(output, [], {}, [])


def test_validator6_rejects_no_indicators_phrase():
    cleaned, violations = _validate({
        "verdict": "No indicators of compromise were detected."})
    assert any("forbidden phrase" in v for v in violations)
    assert "UNVERIFIED" in cleaned["verdict"]


def test_validator6_rejects_no_evidence_of_compromise():
    cleaned, violations = _validate({
        "threat_narrative": "There is no evidence of compromise on this host."})
    assert any("forbidden phrase" in v for v in violations)


def test_validator6_still_rejects_clean():
    cleaned, violations = _validate({"verdict": "The host is clean."})
    assert any("forbidden phrase" in v for v in violations)


# ── Validator 11: no_coverage verdict class ───────────────────────────

def test_verdict_class_no_coverage():
    from spectre.pipeline.report_synthesize import verdict_class
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    assert verdict_class([], m) == "no_coverage"


def test_verdict_class_none_when_examined_and_empty():
    from spectre.pipeline.report_synthesize import verdict_class
    m = _manifest({"/e/a.pcap": {"events": 5}})
    assert verdict_class([], m) == "none"


def test_verdict_class_no_coverage_outranks_confirmed():
    """Nothing examined means no verdict is supportable, findings or not."""
    from spectre.pipeline.report_synthesize import verdict_class
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    assert verdict_class([{"status": "CONFIRMED"}], m) == "no_coverage"


def test_verdict_class_back_compat_without_manifest():
    from spectre.pipeline.report_synthesize import verdict_class
    assert verdict_class([]) == "none"


def test_absence_verdict_contradicts_no_coverage():
    from spectre.pipeline.report_synthesize import _verdict_contradicts_class
    assert _verdict_contradicts_class(
        "No indicators of compromise were detected.", "no_coverage") is True


def test_absence_verdict_allowed_when_coverage_exists():
    from spectre.pipeline.report_synthesize import _verdict_contradicts_class
    assert _verdict_contradicts_class(
        "No indicators of compromise were detected.", "none") is False


def test_validator11_blanks_absence_verdict_under_no_coverage():
    from spectre.pipeline.report_synthesize import _validate_report
    m = _manifest({"/e/b.evtx": {"skipped": "EXTRACTOR_PENDING"}})
    cleaned, violations = _validate_report(
        {"verdict": "The host shows no indicators of compromise."},
        [], {}, [], m,
    )
    assert cleaned["verdict"] == "" or "UNVERIFIED" in cleaned["verdict"]
    assert violations


# ── Blind Spots: derived/carved evidence ──────────────────────────────
# Derived evidence is re-triaged in Phase 2, long after Phase 0, and its
# status lands in extraction results rather than manifest["triage"] — so
# reading triage alone silently omitted every carved artifact we could not
# analyze. Pre-existing defect for EXTRACTOR_PENDING, not new to this work.

def test_blindspots_disclose_derived_pending():
    from spectre.pipeline.report_synthesize import _intake_blindspot_lines
    manifest = {
        "triage": {},
        "extraction": {"results": {
            "/case/derived/Security.evtx": {
                "skipped": "EXTRACTOR_PENDING",
                "derived_from": "/evidence/disk.dd",
                "tool": "evtxexport",
            },
        }},
    }
    lines = "\n".join(_intake_blindspot_lines(manifest))
    assert "Security.evtx" in lines
    assert "disk.dd" in lines
    assert "UNVERIFIED" in lines
    assert "evtxexport" in lines


def test_blindspots_ignore_examined_derived():
    from spectre.pipeline.report_synthesize import _intake_blindspot_lines
    manifest = {
        "triage": {},
        "extraction": {"results": {
            "/case/derived/Security.evtx": {
                "events": 40, "derived_from": "/evidence/disk.dd",
            },
        }},
    }
    assert _intake_blindspot_lines(manifest) == []


def test_blindspots_ignore_top_level_skips_here():
    """Top-level evidence has no derived_from; it is already covered by the
    triage-driven lines, and must not be double-reported."""
    from spectre.pipeline.report_synthesize import _intake_blindspot_lines
    manifest = {
        "triage": {},
        "extraction": {"results": {
            "/evidence/a.evtx": {"skipped": "EXTRACTOR_PENDING"},
        }},
    }
    assert _intake_blindspot_lines(manifest) == []


# ── Phase 2: derived-evidence skip note ───────────────────────────────
# The else-branch wrote "not claimed by any module" for ANY status other than
# EXTRACTOR_PENDING, which is false for anything but a genuine no-claim.

def test_derived_note_names_the_tool_when_pending():
    from spectre.pipeline.phase_runner import _derived_skip_note
    note = _derived_skip_note("EXTRACTOR_PENDING", "process_creation")
    assert "tool" in note
    assert "process_creation" in note


def test_derived_note_no_claim_reads_as_no_claim():
    from spectre.pipeline.phase_runner import _derived_skip_note
    assert "no analyzer module claimed" in _derived_skip_note("UNRECOGNIZED", None)
    assert "no analyzer module claimed" in _derived_skip_note(None, None)


def test_derived_note_unknown_status_names_itself():
    from spectre.pipeline.phase_runner import _derived_skip_note
    note = _derived_skip_note("MISSING", None)
    assert "MISSING" in note
    assert "no analyzer module claimed" not in note
