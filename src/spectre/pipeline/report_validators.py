"""report_validators.py — the report-narrative validation seam (security seam).

`_validate_report()` and its 11 validators (V1–V11) check the model-written
report narrative for invented findings, out-of-case MITRE IDs, paraphrased or
fabricated caveats (V5), forbidden absence/"clean" claims, verdict/verdict-class
contradictions and ungrounded prose. The deterministic-core/AI-explainer rule (README Architecture) names
this seam as `report_synthesize._validate_report()`: that path stays valid —
report_synthesize re-exports it and `_finalize_report` calls it from there.
Split out of report_synthesize.py with no behaviour change.
"""

from __future__ import annotations

import re

from spectre.core import grounding
from spectre.core.validators import mitre_in_allowed
from spectre.pipeline.report_sections.verdict import verdict_class


# ── Validation ────────────────────────────────────────────────────────
def _coerce_narrative_str(v) -> str:
    """Flatten a narrative field to text. The LLM contract is a string, but a
    live model occasionally returns a dict/list; recurse so nested content is
    preserved as readable prose rather than crashing validation/rendering."""
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    if isinstance(v, list):
        return "\n\n".join(_coerce_narrative_str(x) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        return " ".join(_coerce_narrative_str(x) for x in v.values() if x not in (None, ""))
    return str(v)


# Assertive compromise language that is only admissible once the deterministic
# layer has CONFIRMED something.
#
# Sentence-level negation guard. A single monolithic alternation trying to
# bake negation windows directly into one pattern both under-matches ordinary
# assertive phrasing (present tense "is compromised", bare "the threat actor
# established persistence") and over-matches negated or hedged prose that
# merely *mentions* the actor ("the attacker hypothesis is not supported",
# "no artifact places the adversary on this host"). Splitting verdict text
# into sentences and asking, per sentence, "does it assert compromise, and if
# so does a negation/hedge cue precede that assertion" is both more robust
# and far easier to test and extend than encoding negation distance into a
# single regex.
#
# Ordering matters: a negation/hedge cue only exempts a sentence when it
# starts before the END of the assertive match. A cue occurring anywhere in
# the sentence — regardless of order — used to exempt it, which let the
# canonical shape of LLM verdict prose defeat the guard: "The host was
# compromised, although we could not determine the initial access vector."
# has its hedge ("could not") scope the access-vector clause, not the
# compromise claim, so the sentence must still fire. "No evidence indicates
# the host was compromised" is the opposite shape — the cue precedes the
# claim and rightly exempts it.
#
# The boundary is m.end(), NOT m.start(). Plain negation puts the cue INSIDE
# the assertive span: the pattern's adverb slot ("(?:\w+\s+){0,2}") swallows
# the "not"/"never" in "The host was not compromised", so the match begins at
# "was" and the cue lands after m.start() but before m.end(). Comparing
# against m.start() therefore fired on ordinary benign phrasing — and a
# blanked verdict logs a violation, which clears
# gate_6.verdict_class_consistent and fails Gate 6 on a correctly-written
# zero-finding report. Comparing against m.end() exempts the cue-inside-span
# case while still firing on the trailing-caveat case above, where the cue
# falls beyond the assertive span entirely.
#
# Known limitation: this is a vocabulary-based guard, not a parser. It does
# not reason about conditional or interrogative scope, so a conditional
# ("if the host was compromised, we would expect prefetch entries") or a
# question still reads as an assertive claim and over-fires. That is an
# accepted, disclosed gap rather than something this guard chases further —
# over-firing just blanks the verdict and falls back to the deterministic
# template, which is the safe direction for a validator that may only ever
# blank the model's text, never rewrite or synthesize replacement content.
# The vocabulary below is scoped to the pinned test cases; it is not an
# attempt at exhaustive coverage of assertive English.
_ASSERTIVE_COMPROMISE_RE = re.compile(
    r"\b(?:is|are|was|were|has\s+been|have\s+been)\s+(?:\w+\s+){0,2}"
    r"(?:compromised|breached|exfiltrated|stolen)\b"
    r"|\bconfirmed\s+breach\b"
    r"|\b(?:the\s+)?(?:attacker|adversary|threat\s+actor|intruder)(?:'s)?\b"
    r"[^.!?]{0,40}?\b(?:compromised|breached|exfiltrated|established\s+persistence"
    r"|installed\s+(?:a\s+)?backdoor|deployed|maintained\s+access|gained\s+access"
    r"|escalated\s+privileges)\b"
    r"|\b(?:compromised|breached|exfiltrated|deployed|installed\s+(?:a\s+)?backdoor)\b"
    r"[^.!?]{0,40}?\bby\s+(?:the\s+)?(?:attacker|adversary|threat\s+actor|intruder)\b",
    re.IGNORECASE,
)


# Negation/hedge cues that exempt a sentence even when it matches the
# assertive pattern above — hedged or negated analyst prose ("no evidence the
# host was compromised", "the attacker hypothesis is not supported") must
# survive; only the bare assertive claim must not.
_NEGATION_HEDGE_RE = re.compile(
    r"\bno\b|\bnot\b|\bnever\b|\bwithout\b|\bunconfirmed\b|\bunsupported\b"
    r"|\binsufficient\b|\babsence\s+of\b|\bhypothesis\b|\bconsistent\s+with\b"
    r"|\bsuggest(?:s|ed|ing)?\b|\bmay\s+have\b|\bmight\s+have\b|\bpossibly\b"
    r"|\balleged(?:ly)?\b|\bpotential(?:ly)?\b|\bcould\s+have\b"
    r"|\bdoes\s+not\b|\bdid\s+not\b|\bdo\s+not\b|\bcannot\b|\bcan't\b|\bdoesn't\b"
    # "Nothing was exfiltrated." carries no other cue — without this the
    # sentence has no negation token at all and fires as an assertion.
    r"|\bnothing\b",
    re.IGNORECASE,
)


# Sentence boundary: split after ./!/? followed by whitespace, OR on a run of
# newlines. The newline split matters because LLM verdict prose is sometimes
# bulleted or otherwise line-broken with no terminal punctuation at all
# ("- No malware was found\n- The attacker exfiltrated the archive") —
# splitting on punctuation alone would leave that as one blob, letting a cue
# on one line exempt an unrelated assertive claim on another line.
# Deliberately simple otherwise — the verdict is analyst/model prose, not a
# document needing abbreviation-aware sentence tokenization.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


# Caveat-signal phrasings mirror the FK does_NOT_prove vocabulary: an
# evidentiary "does not prove / is not evidence of" claim. Deliberately NARROW
# — ordinary analytic hedges ("we cannot determine the objective") use other
# words and are not scrutinized, keeping the false-positive surface small.
# Shared with the explain description check (B5); matched on
# grounding.canonicalize() text so a homoglyph inside the phrase still
# triggers (B7).
_CAVEAT_SIGNAL_RE = grounding.CAVEAT_SIGNAL_RE


def _normalize_narrative_obj(obj):
    """NFKC + strip Cf (invisible) chars in every string of the
    model output (R2-07): fullwidth digits, soft hyphens, zero-width and
    other invisible format chars are removed BEFORE any validator matches,
    so what the validators see is what a reader sees."""
    if isinstance(obj, str):
        return grounding.normalize_unicode(obj)
    if isinstance(obj, list):
        return [_normalize_narrative_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _normalize_narrative_obj(v) for k, v in obj.items()}
    return obj


# MITRE technique token: the shared tolerant matcher (B1), run on
# grounding.canonicalize() text — homoglyph T, `_T1003.006_`, "T  1003",
# "T\n1003", "T-1003" all match; the sub-technique is consumed greedily so
# an invented parent "T1071" can never rewrite an allowed "T1071.001".
_REPORT_MITRE_RE = grounding.MITRE_TOKEN_RE


def _map_str(obj, fn):
    """Apply `fn` to every string value in a JSON-shaped object."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_map_str(v, fn) for v in obj]
    if isinstance(obj, dict):
        return {k: _map_str(v, fn) for k, v in obj.items()}
    return obj


# The deterministic template's OWN caveat-shaped sentences. This is the
# allowlist seed for Validator 5 — a self-owned, finite set our code emits.
# Referenced by the template emitter AND Validator 5, so the two can never
# drift. Any caveat-shaped sentence (per _CAVEAT_SIGNAL_RE) matching neither
# an FK caveat nor one of these is treated as model-invented -> violation.
# Scoped to the signal vocabulary: a limitation sentence that doesn't match
# _CAVEAT_SIGNAL_RE at all never reaches this check.
_STANDARD_SCOPING_CAVEATS = (
    "All observations are based on automated forensic analysis and require "
    "examiner validation. Confidence scores reflect detection method reliability, "
    "not certainty of compromise. Absence of evidence is not evidence of absence.",
)


def _verdict_contradicts_class(text: str, vclass: str) -> bool:
    """True when verdict prose asserts compromise the evidence class disallows.

    Only "none" and "leads_only" constrain the language — once a finding is
    CONFIRMED, assertive phrasing is the analyst's call to make.

    Evaluated sentence-by-sentence (splitting on sentence punctuation AND
    newlines — see _SENTENCE_SPLIT_RE — so bulleted or unpunctuated verdict
    text can't collapse into one blob that a single cue exempts wholesale): a
    sentence fires when it contains an assertive-compromise construction
    (_ASSERTIVE_COMPROMISE_RE) and the earliest negation/hedge cue
    (_NEGATION_HEDGE_RE), if any, starts at or after the END of that
    construction — plain negation ("was not compromised") puts the cue inside
    the matched span, so m.end() is the boundary, not m.start(). See
    _ASSERTIVE_COMPROMISE_RE's comment for the ordering rationale and the
    disclosed vocabulary-coverage limitation.
    """
    # "no_coverage" constrains BOTH directions. When nothing was examined, an
    # absence claim is as unsupportable as a compromise claim — and absence is
    # the likelier failure, since an empty finding set reads as "clean".
    if vclass == "no_coverage" and re.search(
            _FORBIDDEN_ABSENCE_RE, text or "", re.IGNORECASE):
        return True
    if vclass not in ("none", "leads_only", "no_coverage"):
        return False
    for sentence in _SENTENCE_SPLIT_RE.split(text or ""):
        m = _ASSERTIVE_COMPROMISE_RE.search(sentence)
        if not m:
            continue
        cue = _NEGATION_HEDGE_RE.search(sentence)
        if cue is None or cue.start() >= m.end():
            return True
    return False


# Phrases that assert absence of compromise. Forbidden in model narrative:
# the deterministic layer owns absence claims (_absence_signals for grounded
# negatives, _coverage_sentence for what was never examined), and a model has
# no basis for one. "no indicators of compromise" is the phrase the
# deterministic template itself used to emit over unexamined evidence — see
# _generate_verdict_section.
_FORBIDDEN_ABSENCE_RE = (
    r"\b(clean"
    r"|no malware found"
    r"|nothing suspicious"
    r"|no indicators? of compromise"
    r"|no evidence of (?:malicious|compromise)"
    r"|no signs? of compromise)\b"
)


def _validate_report(
    output: dict,
    findings: list[dict],
    fk_caveats_map: dict[str, list[str]],
    allowed_mitre: list[str],
    manifest: dict | None = None,
) -> tuple[dict, list[str]]:
    """
    Validate LLM report output against all guardrails.
    Returns (cleaned_output, violations).
    """
    violations = []
    cleaned = dict(output)  # shallow copy

    # Narrative fields must be strings. A live LLM (DeepSeek) intermittently
    # returns one of these as a dict/list; without coercion re.search() below
    # and the downstream markdown join both raise TypeError and the whole
    # synthesis silently degrades to the deterministic baseline. Flatten any
    # non-string narrative value to text (content preserved, never dropped).
    for _nk in ("executive_summary", "threat_narrative", "verdict",
                "timeline_narrative", "methodology_narrative"):
        if _nk in cleaned and not isinstance(cleaned[_nk], str):
            cleaned[_nk] = _coerce_narrative_str(cleaned[_nk])

    cleaned = _normalize_narrative_obj(cleaned)
    finding_ids = {f.get("finding_id", "") for f in findings}

    # ── Validator 0: fail-closed character WHITELIST (W2-A round 5) ──
    # A sentence holding any character outside grounding's whitelist
    # (printable ASCII, whitespace, Latin-1/Extended-A letters, a short
    # typographic list) is dropped, unless that whole token occurs
    # verbatim in the deterministic finding data / FK caveats (a real
    # IDN/homograph IOC).
    _corpus = grounding.build_corpus(
        *findings, [c for cs in (fk_caveats_map or {}).values() for c in (cs or [])],
        list(_STANDARD_SCOPING_CAVEATS))

    def _policy_fix(text: str) -> str:
        def _judge(s):
            bad = grounding.policy_violations(s.orig, _corpus)
            if not bad:
                return None
            violations.append(
                f"stripped sentence: {grounding.POLICY_REASON} {bad[:3]}: {s.orig[:120]}")
            return ""
        return grounding.edit_sentences(text, _judge)[0]

    cleaned = _map_str(cleaned, _policy_fix)

    # Every validator below DECIDES on grounding.canonicalize() text (W2-A
    # re-review B1-B9: NFKC, Cf/combining stripped, Cyrillic/Greek/small-cap
    # lookalikes folded, every dash/dot variant folded, spaced separators
    # fused). A string is rewritten into canonical form only when a
    # validator actually replaces or strips something in it.

    # ── Validator 1: No invented finding IDs ──
    # ── Validator 2: No invented MITRE IDs ──
    # Both judge the WHOLE field on canonical text (a token spanning a
    # sentence boundary is still seen) and replace the invented token alone,
    # in the ORIGINAL text. Each whole MITRE token (incl. sub-technique) is
    # judged on its own, so an invented parent never corrupts an allowed
    # sub-technique. Both run AGAIN after the last sentence-dropping
    # validator (LOW-2): a later drop can join "tagged T." + "1003 events".
    new_ids: list[str] = []
    invented_mitre: list[str] = []

    def _fid_fix(text: str) -> str:
        out, hit = grounding.redact_candidates(
            text, grounding.finding_id_candidates,
            lambda tok: None if tok in finding_ids or tok == "F-000-000" else "F-000-000")
        new_ids.extend(hit)
        return out

    def _mitre_fix(text: str) -> str:
        out, hit = grounding.redact_candidates(
            text, grounding.mitre_candidates,
            lambda tok: "UNMAPPED" if mitre_in_allowed([tok.upper()], allowed_mitre) else None)
        invented_mitre.extend(t.upper() for t in hit)
        return out

    def _id_checks(obj):
        n_ids, n_mitre = len(new_ids), len(invented_mitre)
        obj = _map_str(_map_str(obj, _fid_fix), _mitre_fix)
        if len(new_ids) > n_ids:
            violations.append(f"invented finding IDs: {new_ids[n_ids:]}")
        if len(invented_mitre) > n_mitre:
            violations.append(f"invented MITRE technique IDs: {invented_mitre[n_mitre:]}")
        return obj

    cleaned = _id_checks(cleaned)

    # ── Validator 3: No NUMERIC confidence scores in narrative ──
    # Qualitative analyst language ("attribution confidence: LOW") is allowed;
    # numeric score claims ("confidence of 0.95") are stripped — scores are
    # computed deterministically and live in the tables, not the prose.
    narrative_keys = [
        "executive_summary",
        "threat_narrative",
        "timeline_narrative",
        "methodology_narrative",
        "verdict",
    ]
    for key in narrative_keys:
        text = cleaned.get(key, "")
        if not text:
            continue
        if not re.search(r"\bconfidence\b", grounding.canonicalize(text), re.IGNORECASE):
            continue

        def _conf(s):
            # Digits from finding/MITRE citations don't make a score claim
            digits_only = re.sub(r"F-\d+-\d+|T\d{4}(?:\.\d{3})?", "", s.canon)
            if (re.search(r"\bconfidence\b", s.canon, re.IGNORECASE)
                    and re.search(r"\d", digits_only)):
                return ""
            return None
        new_text, removed_any = grounding.edit_sentences(text, _conf)
        if removed_any:
            violations.append(f"confidence mentioned in {key} — removed")
            cleaned[key] = new_text

    # ── Validator 4: Findings narrative must cite finding_id ──
    fn = cleaned.get("findings_narrative", [])
    for item in fn:
        # ponytail: LLM may return strings instead of {finding_id, narrative}
        if not isinstance(item, dict):
            continue
        fid = item.get("finding_id", "")
        narrative = item.get("narrative", "")
        if fid and fid not in narrative:
            violations.append(
                f"finding {fid} narrative does not cite its own finding_id"
            )

    # ── Validator 5: Caveats fail-closed (within the signal vocabulary) ──
    # A caveat-shaped sentence — one matching _CAVEAT_SIGNAL_RE — in the
    # narrative must reproduce an FK does_NOT_prove caveat VERBATIM, or match
    # a known template scoping sentence. Anything else is a model-invented
    # caveat -> violation, and the sentence is stripped. Fail-closed WITHIN
    # that vocabulary: a fabrication or paraphrase using the recognized
    # limitation phrasing resembles no allowed caveat and is therefore
    # caught (a similarity check would wave it through). A limitation phrased
    # OUTSIDE that vocabulary (e.g. "does not indicate compromise", "is not
    # conclusive", "cannot rule out") never triggers _CAVEAT_SIGNAL_RE and is
    # not scrutinized here — see _CAVEAT_SIGNAL_RE's comment for why the
    # trigger is deliberately narrow.
    all_fk_caveats = set()
    for caveats in fk_caveats_map.values():
        all_fk_caveats.update(c.strip() for c in (caveats or []) if isinstance(c, str))

    # Allowlist at SENTENCE granularity: the check runs per-sentence, but FK
    # caveats and the template scoping constant may be multi-sentence. Split so
    # one narrative sentence can match one allowed caveat sentence verbatim.
    def _caveat_sentences(text: str) -> list[str]:
        return grounding.split_sentences(grounding.canonicalize(text))
    # EXACT sentence match (R2-07): a verbatim FK caveat with a fabricated
    # claim appended in the same sentence is NOT the caveat. Comparison is
    # on canonical, whitespace-collapsed text, ignoring only terminal
    # punctuation (FK caveats are often unpunctuated fragments).
    _caveat_key = grounding.caveat_key

    allowed_caveats: set[str] = set()
    for _c in all_fk_caveats:
        allowed_caveats.update(_caveat_key(x) for x in _caveat_sentences(_c))
        allowed_caveats.add(_caveat_key(_c))
    for _c in _STANDARD_SCOPING_CAVEATS:
        allowed_caveats.update(_caveat_key(x) for x in _caveat_sentences(_c))
    allowed_caveats.discard("")

    def _caveat_check(text: str, label: str) -> str:
        def _judge(s):
            if _CAVEAT_SIGNAL_RE.search(s.canon) and _caveat_key(s.canon) not in allowed_caveats:
                violations.append(
                    f"stripped fabricated/paraphrased caveat in {label} "
                    f"(matches no FK caveat verbatim): {s.orig[:120]}"
                )
                return ""
            return None
        return grounding.edit_sentences(text, _judge)[0]

    for _sec in ("executive_summary", "threat_narrative", "timeline_narrative",
                 "methodology_narrative", "verdict"):
        _t = cleaned.get(_sec, "")
        if _t:
            cleaned[_sec] = _caveat_check(_t, _sec)
    for _item in cleaned.get("findings_narrative", []):
        if isinstance(_item, dict) and _item.get("narrative"):
            _item["narrative"] = _caveat_check(
                _item["narrative"], f"findings_narrative[{_item.get('finding_id', '?')}]")

    # ── Validator 6: Empty Data Protocol — no absence assertions ──
    def _absence(s):
        repl = [(m.start(), m.end(), "UNVERIFIED")
                for m in re.finditer(_FORBIDDEN_ABSENCE_RE, s.canon, re.IGNORECASE)]
        return s.replace(repl) if repl else None

    for key in narrative_keys:
        text = cleaned.get(key, "") or ""
        if not isinstance(text, str):
            continue
        new_text, hit = grounding.edit_sentences(text, _absence)
        if hit:
            violations.append(
                f"'{key}' contains forbidden phrase (clean/no malware) — replaced with UNVERIFIED"
            )
            cleaned[key] = new_text

    # ── Validator 7: Check per-finding narratives for invented facts ──
    # Strip sentences in findings_narrative that make factual claims
    # without citing the finding_id
    for item in fn:
        # ponytail: LLM may return strings — skip
        if not isinstance(item, dict):
            continue
        fid = item.get("finding_id", "")
        narrative = item.get("narrative", "")
        if not narrative:
            continue
        sentences = re.split(r"(?<=[.!?])\s+", narrative)
        kept = []
        for sent in sentences:
            sent = sent.strip()
            if not sent:
                continue
            if fid in sent:
                kept.append(sent)
                continue
            # Check for factual claims: IP addresses, domains, file paths, new timestamps
            has_claim = any(
                [
                    re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", sent),
                    re.search(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b", sent),
                    # File path patterns
                    re.search(r"[A-Za-z]:\\", sent),
                ]
            )
            if has_claim and fid not in sent:
                violations.append(
                    f"stripped unsupported claim in {fid}: '{sent[:100]}...'"
                )
                continue
            kept.append(sent)
        item["narrative"] = " ".join(kept)

    # ── Validator 8: Verdict must be present ──
    if not str(cleaned.get("verdict", "") or "").strip():
        violations.append(
            "verdict missing from LLM output — deterministic verdict used"
        )

    # ── Validator 9: No raw IOC dumps in the executive summary ──
    # The IOC table carries the literals; the summary names the threat.
    ioc_values = set()
    for f in findings:
        for values in (f.get("iocs") or {}).values():
            for v in (values if isinstance(values, list) else [values]):
                if v and len(str(v)) > 3:
                    ioc_values.add(str(v))
    exec_text = cleaned.get("executive_summary", "")
    ioc_hits = sum(1 for v in ioc_values if v in exec_text)
    if ioc_hits > 5:
        violations.append(
            f"executive_summary contains {ioc_hits} raw IOC literals (max 5) — "
            f"reference the IOC table instead"
        )

    # ── Validator 10: Ground free-form narrative literals (Track E1) ──
    # The per-finding explainer grounds description literals; the synthesis
    # narrative had no equivalent check, so a fabricated IOC (case 001's
    # invented MSIE User-Agent) sailed through. Build the grounded set from
    # ALL findings' non-narrative data and strip any sentence carrying an
    # IOC-shaped token absent from it. Covers every model-written free-form
    # field, including findings_narrative — a fabricated UA must not survive
    # merely by being written one section over. Never adds anything; only
    # removes ungrounded model prose (inviolable rule).
    grounded: set[str] = set()
    for f in findings:
        grounded |= grounding.grounded_tokens(f, skip_keys=("description",))

    def _ground_narrative(text: str, label: str) -> str:
        # Drop whole sentences containing an ungrounded IOC token. Only rejoin
        # (which flattens paragraph breaks) when something was actually
        # dropped — a clean section keeps its original formatting verbatim.
        # B2: ground the WHOLE field first and split only canonical text —
        # splitting raw text cut "185 . 220 . 101 . 42" into IOC-free
        # fragments. If the whole field is clean, nothing to do.
        if not grounding.ungrounded_literals(text, grounded):
            return text
        def _judge(s):
            ungrounded = grounding.ungrounded_literals(s.canon, grounded)
            if ungrounded:
                violations.append(
                    f"stripped fabricated IOC in {label} "
                    f"(not in any finding): {sorted(ungrounded)}: {s.orig[:120]}"
                )
                return ""
            return None
        out = grounding.edit_sentences(text, _judge)[0]
        residual = grounding.ungrounded_literals(out, grounded)
        if residual:
            # Fail closed: the field is ungrounded as a whole but no single
            # sentence carries the literal.
            violations.append(
                f"stripped whole {label}: ungrounded literal(s) {sorted(residual)} "
                f"survive sentence-level checks")
            return ""
        return out

    for section in ("executive_summary", "threat_narrative",
                    "timeline_narrative", "methodology_narrative", "verdict"):
        text = cleaned.get(section, "")
        if text:
            cleaned[section] = _ground_narrative(text, section)

    for item in cleaned.get("findings_narrative", []):
        if not isinstance(item, dict):
            continue
        narr = item.get("narrative", "")
        if narr:
            item["narrative"] = _ground_narrative(
                narr, f"findings_narrative[{item.get('finding_id', '?')}]")

    # ── Validator 11: Verdict must not contradict the deterministic class ──
    # The deterministic layer owns WHICH verdict the evidence supports; the
    # model owns only its articulation. Blanking here makes _merge_report_md
    # fall through to the deterministic template — never blocks the report.
    vclass = verdict_class(findings, manifest)
    if _verdict_contradicts_class(
            grounding.canonicalize(cleaned.get("verdict", "") or ""), vclass):
        violations.append(
            f"verdict contradicts deterministic class '{vclass}': "
            f"{cleaned.get('verdict', '')[:120]} — falling back to template"
        )
        cleaned["verdict"] = ""

    # ── Validators 1 + 2 again, LAST (LOW-2): sentence drops above (V3, V5,
    # V6, V7, V10) join the surviving sentences, which can form a new
    # finding-ID or MITRE token across the old boundary.
    cleaned = _id_checks(cleaned)

    return cleaned, violations
