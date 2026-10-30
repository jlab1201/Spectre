"""W2-A review round 4 (2026-09-30) — R4-1..R4-5 + LOW items as end-to-end tests.

Design under test (round 5 of the fix):
  * WHITELISTED charset: after NFKC every character of validated prose must
    be printable ASCII, normalized whitespace, a Latin-1 / Latin Extended-A
    letter, or one of a small list of typographic characters (bullet only
    when not between two alphanumerics). Anything else — every combining
    mark, symbol, enclosed/regional letter, braille blank, unusual dot —
    drops the sentence ("disallowed character in validated text"), unless
    the WHOLE token occurs verbatim in the case's deterministic data;
  * MITRE candidates accept quote / bracket separators (T'1003, T(1003));
  * finding-ID and MITRE checks run on the whole field and again LAST, so a
    later sentence drop cannot join "T." + "1003" into a technique;
  * ingest_host_output reads the finding ONCE, hashes and parses the same
    bytes, and persists atomically after re-checking the on-disk hash.
"""
from __future__ import annotations

import hashlib
import json

import pytest
import yaml

from spectre.core import grounding
from tests.test_core import test_w2a_rereview as _rr
from tests.test_core.test_w2a_rereview import F1, F2, _host_explain, _report

make_case = _rr.make_case
_no_journal = _rr._no_journal

REASON = "disallowed character in validated text"


def _adv(case, item):
    from spectre.core import explain as ex
    return ex.ingest_host_adversarial([], [], {
        "counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
        "evidence_gaps": [item]}, str(case))


def _three(make_case, text):
    """(report threat_narrative, persisted explain description, adversarial gaps)."""
    c = make_case()
    rep = _report(c, threat_narrative=text)["threat_narrative"]
    _, f = _host_explain(c, "F-900-001", text)
    c2 = make_case(name="900-rr-adv")
    adv = _adv(c2, text)["evidence_gaps"]
    return rep, (f.get("description") or ""), " ".join(adv)


# ── R4-1: MITRE via non-letter T / exotic separators ───────────────────

R4_MITRE = ["⊤1003", "⟙1003", "\U0001f1831003", "\U0001f1f91003", "T⠀1003",
            "T'1003", "T(1003)", "T1003"]


@pytest.mark.parametrize("tok", R4_MITRE)
def test_r4_1_mitre_symbol_forms_fail_closed_all_seams(make_case, tok):
    rep, desc, adv = _three(make_case, f"F-900-001 is consistent with {tok} OS Credential Dumping.")
    assert "1003" not in rep, rep
    assert "1003" not in desc, desc
    assert "1003" not in adv, adv


@pytest.mark.parametrize("txt,expected", [
    ("T'1003", ["T1003"]), ("T(1003)", ["T1003"]), ("T[1003]", ["T1003"]),
    ("T\"1003\"", ["T1003"]), ("T’1003", ["T1003"]),
    ("at T+1200 s", []), ("in 2024", []), ("/t 3600", []),
])
def test_r4_1_mitre_candidate_separators_unit(txt, expected):
    assert grounding.mitre_tokens(txt) == expected


# ── R4-2: IOC dot lookalikes ───────────────────────────────────────────

R4_SEPS = ["•", "܂", "۔", "⸰", "˙", "꘎"]


@pytest.mark.parametrize("sep", R4_SEPS)
def test_r4_2_ipv4_dot_lookalikes_fail_closed_all_seams(make_case, sep):
    ip = sep.join(["185", "220", "101", "42"])
    for out in _three(make_case, f"F-900-001 beacons to {ip} every 60 seconds."):
        assert "220" not in out, out


@pytest.mark.parametrize("sep", R4_SEPS)
def test_r4_2_domain_dot_lookalikes_fail_closed_all_seams(make_case, sep):
    for out in _three(make_case, f"F-900-001 beacons to evil-c2{sep}com every 60 seconds."):
        assert "evil-c2" not in out, out


# ── R4-4: combining marks (strike-through) ─────────────────────────────

def _strike(w):
    return "".join(ch + "̶" for ch in w)


def test_r4_4_struck_negation_in_verdict_dropped(make_case):
    c = make_case()
    r = _report(c, verdict=f"The host was {_strike('not')} compromised.")
    assert "̶" not in r["verdict"]
    assert any(REASON in v for v in r["violations"])


def test_r4_4_struck_scoping_caveat_dropped(make_case):
    c = make_case()
    t = f"Absence of evidence is {_strike('not')} evidence of absence."
    r = _report(c, threat_narrative="F-900-001 shows periodic HTTP. " + t)
    assert r["threat_narrative"] == "F-900-001 shows periodic HTTP."


def test_r4_4_combining_marks_all_seams(make_case):
    for out in _three(make_case, f"F-900-001 does {_strike('not')} show exfiltration."):
        assert "̶" not in out and "exfiltration" not in out, out


def test_r4_4_precomposed_latin_still_allowed(make_case):
    c = make_case()
    txt = "F-900-001 involves the account of José Ñúñez."
    assert _report(c, threat_narrative=txt)["threat_narrative"] == txt


# ── Whitelist unit behaviour ───────────────────────────────────────────

@pytest.mark.parametrize("txt", [
    "F-900-001 round trip was ~150 µs on the LAN leg.",
    "F-900-001 jitter σ = 1.1 s and Δt ≈ 60 s.",
    "F-900-001 beacons every ≈60 s (jitter ≤ 1.1 s) — see the “Beacons” table.",
    "F-900-001 → T1071.001; the session’s 3 × 20 °C ± 2 figures ≥ 1 © vendor.",
    "• F-900-001 shows periodic HTTP… as noted – twice.",
])
def test_whitelist_typographic_prose_round_trips(make_case, txt):
    c = make_case()
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt, r["violations"]


@pytest.mark.parametrize("ch", ["⊤", "⠀", "̶", "܂", "۔", "⸰", "꘎", "Ꭲ", "ᴛ",
                                " ", "·", "ễ", "Ω", "\x00"])
def test_whitelist_rejects(ch):
    assert grounding.foreign_words(f"see x{ch}y here") != []


def test_whitelist_bullet_between_alnum_rejected():
    assert grounding.foreign_words("185•220") != []
    assert grounding.foreign_words("• item one") == []
    assert grounding.foreign_words("a • b") == []


# ── LOW-1: verbatim exemption is whole-token only ──────────────────────

def _host_case(make_case, host):
    f = dict(F1, corroboration={"sources": 1, "tools": ["zeek/conn"],
                                "artifacts": [f"10.0.0.5 -> 198.51.100.7 host {host} [outbound]"]})
    return make_case(findings=(f, F2))


def test_low1_substring_of_case_token_not_exempt(make_case):
    c = _host_case(make_case, "Ꭲest-srv")
    txt = "F-900-001 is consistent with Ꭲ 1003 OS Credential Dumping."
    r = _report(c, threat_narrative=txt)
    assert "1003" not in r["threat_narrative"]
    _, f = _host_explain(c, "F-900-001", txt)
    assert "1003" not in (f.get("description") or "")


def test_low1_whole_case_token_still_exempt(make_case):
    c = _host_case(make_case, "Ꭲest-srv")
    txt = "F-900-001 reached the host Ꭲest-srv repeatedly."
    assert _report(c, threat_narrative=txt)["threat_narrative"] == txt


# ── LOW-2: ID / MITRE checks run again after the last sentence drop ────

def test_low2_join_after_caveat_drop_rechecked(make_case):
    c = make_case()
    txt = ("F-900-001 was tagged T. The beacon does not prove lateral movement. "
           "1003 events followed.")
    t = _report(c, threat_narrative=txt)["threat_narrative"]
    assert "1003" not in t, t


def test_low2_cross_sentence_mitre_in_original_caught(make_case):
    rep, desc, adv = _three(make_case, "F-900-001 was tagged T. 1003 events followed.")
    for out in (rep, desc, adv):
        assert "1003" not in out, out


def test_low2_cross_sentence_finding_id_rechecked(make_case):
    c = make_case()
    txt = ("F-900-001 see Appendix F. The beacon does not prove lateral movement. "
           "900. 777 rows followed.")
    t = _report(c, threat_narrative=txt)["threat_narrative"]
    assert "777" not in t, t


# ── R4-5: TOCTOU in ingest_host_output ─────────────────────────────────

def _tampered_bytes():
    t = dict(F1, status="CONFIRMED", confidence=0.99, mitre_attack="T1003.006",
             iocs={"ip": ["198.51.100.7", "185.220.101.42"], "domain": ["good.example.com"]})
    return yaml.dump(t, sort_keys=False).encode()


def _audit_rows(case):
    return [json.loads(x) for x in (case / "audit.jsonl").read_text().splitlines() if x.strip()]


def test_r4_5_tamper_then_restore_during_validation_not_laundered(make_case, monkeypatch):
    """Read tampered bytes; the attacker restores the originals mid-flight."""
    from spectre.core import explain as ex
    from spectre.core.validators import load_verified_findings
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    orig = fp.read_bytes()
    fp.write_bytes(_tampered_bytes())
    real = ex._validate_output

    def swap(*a, **k):
        fp.write_bytes(orig)          # restore between read and persist
        return real(*a, **k)

    monkeypatch.setattr(ex, "_validate_output", swap)
    r = ex.ingest_host_output(str(fp), case_dir=str(c),
                              host_json={"description": "F-900-001 shows periodic HTTP.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert r["persist_refused"] is True
    after = yaml.safe_load(fp.read_text())
    assert after["status"] == "INFERRED" and after["mitre_attack"] == "T1071.001"
    assert fp.read_bytes() == orig
    load_verified_findings(c)   # untouched original still verifies


def test_r4_5_swap_between_read_and_persist_aborts(make_case, monkeypatch):
    """Read verified bytes; the attacker swaps in a tamper before the write."""
    from spectre.core import explain as ex
    from spectre.core.validators import FindingIntegrityError, load_verified_findings
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    tampered = _tampered_bytes()
    real = ex._validate_output

    def swap(*a, **k):
        fp.write_bytes(tampered)
        return real(*a, **k)

    monkeypatch.setattr(ex, "_validate_output", swap)
    with pytest.raises(FindingIntegrityError):
        ex.ingest_host_output(str(fp), case_dir=str(c),
                              host_json={"description": "F-900-001 shows periodic HTTP.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert fp.read_bytes() == tampered            # not overwritten / blessed
    assert not any(r.get("phase_step") == "S1-explain-norm" and r.get("output_sha256")
                   for r in _audit_rows(c))
    with pytest.raises(FindingIntegrityError):
        load_verified_findings(c)
    assert not list(fp.parent.glob("*.tmp")) and not list(fp.parent.glob(".*tmp*"))


def test_r4_5_parse_and_hash_same_bytes(make_case, monkeypatch):
    """The finding dict validated is parsed from the bytes that were hashed:
    the file is opened for reading exactly once before the persist re-check."""
    from pathlib import Path

    from spectre.core import explain as ex
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    reads = []
    real_rb = Path.read_bytes

    def rb(self):
        if self.resolve() == fp.resolve():
            reads.append(1)
        return real_rb(self)

    monkeypatch.setattr(Path, "read_bytes", rb)
    import builtins
    real_open = builtins.open

    def op(file, mode="r", *a, **k):
        if "r" in mode and str(file) == str(fp):
            reads.append("open")
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", op)
    import os
    real_replace = os.replace

    def rep(a, b):
        reads.append("replace")
        return real_replace(a, b)

    monkeypatch.setattr(os, "replace", rep)
    r = ex.ingest_host_output(str(fp), case_dir=str(c),
                              host_json={"description": "F-900-001 shows periodic HTTP.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert r["persist_refused"] is False
    # one read to parse+hash, one re-check right before os.replace
    # (the audit transcript reads the written file afterwards — not a check)
    assert reads[:reads.index("replace")] == [1, 1], reads


def test_r4_5_successful_persist_is_atomic_and_hash_recorded(make_case):
    from spectre.core import explain as ex
    from spectre.core.validators import load_verified_findings
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    r = ex.ingest_host_output(str(fp), case_dir=str(c),
                              host_json={"description": "F-900-001 shows periodic HTTP.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert r["persist_refused"] is False
    assert sorted(p.name for p in fp.parent.iterdir()) == ["F-900-001.yaml", "F-900-002.yaml"]
    sha = hashlib.sha256(fp.read_bytes()).hexdigest()
    assert any(x.get("output_sha256") == sha for x in _audit_rows(c))
    load_verified_findings(c)


# ── fp_corpus regression (no strips above HEAD) ────────────────────────

def _sents(t):
    import re
    return [s for s in re.split(r"(?<=[.!?])\s+", t) if s.strip()]


def test_fp_corpus_explain_no_new_strips():
    from spectre.core import explain as ex
    from tests.test_core import _fp_corpus_data as d
    lost = 0
    total = 0
    for tag, dd in (("main", d.D), ("unicode", d.DX)):
        for fid, desc in dd.items():
            f = next(x for x in d.F if x["finding_id"] == fid)
            allowed = [t.strip() for t in f["mitre_attack"].split(",")]
            out, _ = ex._validate_output({"description": desc, "mitre_attack": f["mitre_attack"],
                                          "caveats": d.FK[fid]}, f, d.FK[fid], allowed, fid)
            o = out.get("description", "")
            miss = [s for s in _sents(desc) if s not in o]
            total += len(_sents(desc))
            lost += len(miss)
            if tag == "unicode":
                assert not miss, (fid, miss)
    assert total == 44
    assert lost <= 12, lost          # HEAD baseline: 12/44 (pre-existing V5 heuristic)


def test_fp_corpus_report_sections_unchanged():
    from spectre.pipeline import report_synthesize as rs
    from tests.test_core import _fp_corpus_data as d
    rep = json.loads(json.dumps(d.REPORT))
    allowed = sorted({t.strip() for f in d.F for t in f["mitre_attack"].split(",")})
    out, viol = rs._validate_report(rep, d.F, {f["artifact"]: d.FK[f["finding_id"]] for f in d.F},
                                    allowed, {"artifact_profile": "auto"})
    for k in ("executive_summary", "threat_narrative", "timeline_narrative",
              "methodology_narrative", "verdict"):
        assert out[k] == d.REPORT[k], (k, viol)
    lost = sum(1 for a, b in zip(d.REPORT["findings_narrative"], out["findings_narrative"])
               for s in _sents(a["narrative"]) if s not in b.get("narrative", ""))
    assert lost <= 3, lost           # HEAD baseline: 3 (V7)
    assert not any(REASON in v for v in viol), viol


# ── LOW-4: whole-field redaction stays linear ──────────────────────────

@pytest.mark.parametrize("blob,fn", [("T1003 " * 166_000, "mitre_candidates"),
                                     ("F-1-2 " * 166_000, "finding_id_candidates")])
def test_low4_whole_field_redaction_1mb_linear(blob, fn):
    import time
    t0 = time.perf_counter()
    out, hit = grounding.redact_candidates(blob, getattr(grounding, fn), lambda tok: "X")
    assert len(hit) == 166_000 and "1003" not in out and "F-1-2" not in out
    assert time.perf_counter() - t0 < 5.0


def test_whitelist_allows_unicode_hyphens_but_ids_still_fold():
    # LLMs routinely emit U+2010/U+2011; they must not drop the sentence,
    # and canonicalize() must still fold them so dashed IDs are caught.
    assert grounding.policy_violations("a non‑blocking read") == []
    assert grounding.policy_violations("self‐signed cert") == []
    assert grounding.mitre_tokens("T‑1003") == ["T1003"]
    assert grounding.finding_ids("F‑900‑777") == ["F-900-777"]
