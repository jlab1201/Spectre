"""Verdict classification — the deterministic layer owns the verdict class.

The model may articulate the verdict; it may not change which class the
evidence falls into. These tests pin the four classes.
"""
import pytest

from spectre.pipeline.report_synthesize import (
    verdict_class, _verdict_contradicts_class, _validate_report,
)


def _f(status, confidence=0.5):
    return {"status": status, "confidence": confidence, "mitre_attack": "UNMAPPED"}


def test_no_findings_is_none():
    assert verdict_class([]) == "none"


def test_only_inferred_is_leads_only():
    assert verdict_class([_f("INFERRED"), _f("INFERRED")]) == "leads_only"


def test_only_confirmed_is_confirmed():
    assert verdict_class([_f("CONFIRMED"), _f("CONFIRMED")]) == "confirmed"


def test_confirmed_plus_inferred_is_mixed():
    assert verdict_class([_f("CONFIRMED"), _f("INFERRED")]) == "mixed"


def test_review_status_alone_is_leads_only():
    # REVIEW is neither CONFIRMED nor INFERRED; findings exist but none confirmed.
    assert verdict_class([_f("REVIEW")]) == "leads_only"


def test_compromise_language_contradicts_leads_only():
    assert _verdict_contradicts_class(
        "The host was compromised by the attacker.", "leads_only") is True


def test_hedged_language_survives_leads_only():
    assert _verdict_contradicts_class(
        "These observations are investigative leads requiring corroboration.",
        "leads_only") is False


def test_compromise_language_fine_when_confirmed():
    assert _verdict_contradicts_class(
        "The host was compromised by the attacker.", "confirmed") is False


def test_validator_blanks_contradicting_verdict():
    findings = [_f("INFERRED")]
    out = {
        "executive_summary": "Summary.",
        "threat_narrative": "",
        "verdict": "The attacker compromised this host and exfiltrated data.",
        "findings_narrative": [],
        "timeline_narrative": "",
        "methodology_narrative": "",
    }
    cleaned, violations = _validate_report(out, findings, {}, [])
    assert cleaned["verdict"] == ""
    assert any("verdict contradicts deterministic class" in v for v in violations)


# ── Fix wave 1: sentence-level negation guard, pinned per-string ──────────
# These are the review's verified examples (see task-2-report.md, "Fix wave
# 1"). Each string is pinned individually so a future regex edit that
# regresses even one gets caught precisely, not just "some fired".

MUST_FIRE = [
    "The host was compromised by the attacker.",
    "This host is compromised.",
    "The system was breached and a backdoor installed.",
    "We conclude the machine was successfully compromised by an external party.",
    "The threat actor established persistence via the Run key.",
    "The attacker exfiltrated the archive.",
]

MUST_NOT_FIRE = [
    "These observations are investigative leads requiring corroboration.",
    "No evidence indicates the host was compromised.",
    "There is no indication that data was exfiltrated.",
    "The attacker hypothesis is not supported by the current evidence.",
    "No artifact places the adversary on this host.",
    "This activity is consistent with the attacker's known tooling.",
]

# ── Fix wave 3: plain negation must not fire ──────────────────────────────
# Every MUST_NOT_FIRE string above is a cue-FIRST shape ("No evidence
# indicates…"), so the cue-order rule was only ever exercised in one
# direction. Plain negation is the opposite: the assertive pattern's adverb
# slot swallows the "not"/"never", putting the cue INSIDE the match span.
# Against the old `cue.start() > m.start()` boundary these all fired — and a
# blanked verdict logs a violation, which clears
# gate_6.verdict_class_consistent and fails Gate 6 on a correctly-written
# benign report. Pinned individually; the boundary is now m.end().
PLAIN_NEGATION_MUST_NOT_FIRE = [
    "The host was not compromised.",
    "The host is not compromised.",
    "The system was not breached.",
    "Data was never exfiltrated.",
    "Nothing was exfiltrated.",
    # This one was already correct before wave 3 ("has been" is not swallowed
    # by the adverb slot the same way) — pinned to lock the inconsistency out.
    "The host has not been compromised.",
]


@pytest.mark.parametrize("text", PLAIN_NEGATION_MUST_NOT_FIRE)
def test_plain_negation_survives_leads_only(text):
    assert _verdict_contradicts_class(text, "leads_only") is False


@pytest.mark.parametrize("text", PLAIN_NEGATION_MUST_NOT_FIRE)
def test_plain_negation_survives_none_class(text):
    # "none" is the class a benign zero-finding case lands in — precisely
    # where this phrasing appears, and where the false fire failed Gate 6.
    assert _verdict_contradicts_class(text, "none") is False


@pytest.mark.parametrize("text", MUST_FIRE)
def test_assertive_compromise_fires_on_leads_only(text):
    assert _verdict_contradicts_class(text, "leads_only") is True


@pytest.mark.parametrize("text", MUST_NOT_FIRE)
def test_negated_or_hedged_prose_survives_leads_only(text):
    assert _verdict_contradicts_class(text, "leads_only") is False


@pytest.mark.parametrize("text", MUST_FIRE[:2])
def test_assertive_compromise_never_fires_when_confirmed_or_mixed(text):
    # The vclass early-return covers this — pin at least two so a future
    # change to the early-return itself gets caught here, not just by
    # inference from the "none"/"leads_only" tests.
    assert _verdict_contradicts_class(text, "confirmed") is False
    assert _verdict_contradicts_class(text, "mixed") is False


def test_assertive_compromise_fires_on_none_class():
    # There was previously no "none"-class coverage at all.
    assert _verdict_contradicts_class(MUST_FIRE[0], "none") is True


# ── Fix wave 2: cue must precede the assertive match ──────────────────────
# Round-2 review: a negation/hedge cue anywhere in the sentence used to
# exempt it, including a cue appearing AFTER the assertive claim that scopes
# something else entirely. This is the canonical shape of LLM verdict prose
# ("X was compromised, although we couldn't determine Y") — these three must
# now fire even though each contains a hedge word.

NEGATION_ORDER_MUST_FIRE = [
    "The host was compromised, although we could not determine the initial "
    "access vector.",
    "The host was compromised; we cannot determine the initial vector.",
    "The machine was compromised and the attacker installed a backdoor, but "
    "we did not recover the payload.",
]


@pytest.mark.parametrize("text", NEGATION_ORDER_MUST_FIRE)
def test_assertive_fires_when_cue_follows_the_claim(text):
    assert _verdict_contradicts_class(text, "leads_only") is True


def test_all_twelve_wave1_pinned_strings_still_correct():
    # Explicit regression pin: the reviewer verified both wave-2 fixes
    # (cue-order + newline splitting) preserve every wave-1 pinned string.
    for text in MUST_FIRE:
        assert _verdict_contradicts_class(text, "leads_only") is True
    for text in MUST_NOT_FIRE:
        assert _verdict_contradicts_class(text, "leads_only") is False


# ── Fix wave 2: sentence splitter must also split on newlines ─────────────
# `(?<=[.!?])\s+` alone collapses unpunctuated/bulleted text into one blob,
# so a single cue anywhere in it exempts everything — including a bulleted
# verdict, a common LLM output shape. This block had zero coverage before
# wave 2: every previously-pinned string was a single punctuated sentence.

def test_bulleted_verdict_with_no_terminal_punctuation_fires():
    text = "- No malware was found\n- The attacker exfiltrated the archive"
    assert _verdict_contradicts_class(text, "leads_only") is True


def test_multiline_early_cue_does_not_exempt_a_later_asserting_line():
    text = (
        "No indicators were found on the host.\n"
        "The attacker compromised the domain controller."
    )
    assert _verdict_contradicts_class(text, "leads_only") is True


def test_multi_sentence_string_one_negated_one_asserting_fires():
    text = ("No compromise was confirmed by the initial review. "
            "The attacker exfiltrated the archive.")
    assert _verdict_contradicts_class(text, "leads_only") is True


def test_unpunctuated_single_sentence_that_asserts_still_fires():
    text = "The attacker compromised the domain controller"
    assert _verdict_contradicts_class(text, "leads_only") is True


# ── Fix wave 2: phrasing gaps enumerated by the reviewer ──────────────────
# Each of these slipped past on leads_only before wave 2 broadened the
# vocabulary. Scope is deliberately limited to exactly these six phrasings
# plus the twelve already pinned above — not exhaustive coverage.

PHRASING_GAP_MUST_FIRE = [
    "The adversary maintained access for weeks.",
    "The attacker gained access to the domain controller.",
    "The intruder escalated privileges to SYSTEM.",
    "Data was stolen from this host.",
    "This is a confirmed breach.",
    "Ransomware was deployed across the estate by the threat actor.",
]


@pytest.mark.parametrize("text", PHRASING_GAP_MUST_FIRE)
def test_phrasing_gap_fires_on_leads_only(text):
    assert _verdict_contradicts_class(text, "leads_only") is True


def test_all_eighteen_previously_pinned_strings_still_correct():
    # Wave-3 regression pin. The m.start() → m.end() boundary change is the
    # kind of edit that can silently flip an unrelated pinned string, so all
    # 18 pre-wave-3 strings (6 MUST_FIRE + 6 MUST_NOT_FIRE + 6 phrasing-gap)
    # are re-asserted in one place, alongside the 3 cue-order cases.
    for text in MUST_FIRE + PHRASING_GAP_MUST_FIRE + NEGATION_ORDER_MUST_FIRE:
        assert _verdict_contradicts_class(text, "leads_only") is True, text
    for text in MUST_NOT_FIRE:
        assert _verdict_contradicts_class(text, "leads_only") is False, text
