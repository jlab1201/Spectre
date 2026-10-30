"""W2-A review round 3 (2026-09-30) — R3-1..R3-5 + LOW items as end-to-end tests.

Design under test (round 4 of the fix):
  * fail-closed character policy — a letter/digit outside Basic Latin +
    Latin-1 + Latin Extended-A (after NFKC) in validated text drops the
    sentence, unless it sits inside a string that appears verbatim in the
    case's deterministic finding data (a real IDN/homograph IOC);
  * output keeps the ORIGINAL characters or drops the sentence — folded
    (canonical) text is never written back;
  * MITRE candidate shapes (letter-for-digit, any separator, bare
    sub-technique shape), with years/ports/PIDs NOT candidates;
  * whitespace-agnostic spaced-dot / defang folding, idempotent canonicalize;
  * no "word. tld" sentence-boundary fusion (R3-4 false positives).
"""
from __future__ import annotations

import os
import random
import shutil
import time

import pytest

from spectre.core import grounding
from tests.test_core import test_w2a_rereview as _rr
from tests.test_core.test_w2a_rereview import F1, F2, _host_explain, _report

# Shared fixtures (re-bound, not imported, so pytest collects them here).
make_case = _rr.make_case
_no_journal = _rr._no_journal


def _adv(case, item):
    from spectre.core import explain as ex
    return ex.ingest_host_adversarial([], [], {
        "counter_hypotheses": [], "citation_gaps": [], "alternative_timeline": [],
        "evidence_gaps": [item]}, str(case))


# ── R3-1: MITRE token shapes ───────────────────────────────────────────

R3_MITRE = ["Ꭲ1003.006", "ꓔ1003.006", "Ⲧ1003.006", "Tl003.006", "T1OO3.OO6",
            "T:1003.006", "T.1003.006", "/T 1003.006", "/T-1003.006",
            "T1003.006", "1003.006", "Ŧ1003.006", "T1ØØ3.ØØ6", "T: 1003",
            "technique 1003", "T-1003"]


@pytest.mark.parametrize("tok", R3_MITRE)
def test_r3_1_report_mitre_shapes_fail_closed(make_case, tok):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 is consistent with {tok} (DCSync).")
    assert "003" not in r["threat_narrative"], r["threat_narrative"]
    assert r["violations"]


@pytest.mark.parametrize("tok", R3_MITRE)
def test_r3_1_explain_mitre_shapes_not_persisted(make_case, tok):
    c = make_case()
    _, f = _host_explain(c, "F-900-001", f"F-900-001 is consistent with {tok} (DCSync).")
    assert "003" not in (f.get("description") or "")


@pytest.mark.parametrize("tok", R3_MITRE)
def test_r3_1_adversarial_mitre_shapes_redacted(make_case, tok):
    c = make_case()
    r = _adv(c, f"F-900-001 may instead be {tok} DCSync.")
    assert "003" not in str(r["evidence_gaps"])


@pytest.mark.parametrize("txt", [
    "F-900-001 activity peaked in 2024 across the capture.",
    "F-900-001 used port 1003 for the session.",
    "F-900-001 was spawned by PID 1003 on the host.",
    "F-900-001 ran shutdown /t 3600 once.",
    "F-900-001 shows T1071.001 web protocol use.",
])
def test_r3_1_years_ports_pids_not_candidates(make_case, txt):
    c = make_case()
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt
    assert not any("MITRE" in v for v in r["violations"])


@pytest.mark.parametrize("txt,expected", [
    ("in 2024", []), ("port 1003", []), ("PID 1003", []),
    ("T1003.006", ["T1003.006"]), ("Tl003.006", ["T1003.006"]),
    ("T:1003", ["T1003"]), ("x 1003.006 y", ["T1003.006"]),
    ("T1071 and T1071.001", ["T1071", "T1071.001"]),
])
def test_r3_1_mitre_tokens_unit(txt, expected):
    assert grounding.mitre_tokens(txt) == expected


# ── R3-2 / R3-3: whitespace + defang vocabulary ────────────────────────

R3_IOCS = ["185[[.]]220[[.]]101[[.]]42", "185{.}220{.}101{.}42", "185.\n220.\n101.\n42",
           "185\n.220\n.101\n.42", "185. 220. 101. 42",
           "185.\r\n220.\r\n101.\r\n42", "185. 220. 101. 42",
           "185 dot 220 dot 101 dot 42", "185 (dot) 220 (dot) 101 (dot) 42",
           "185[dot]220[dot]101[dot]42", "185 [ . ] 220 [ . ] 101 [ . ] 42",
           "evil-c2 [ . ] com", "evil-c2 . com", "evil-c2{.}com", "evil-c2 [[.]] com",
           "evil-c2 (dot) com", "evil-c2 dot com"]


@pytest.mark.parametrize("ioc", R3_IOCS)
def test_r3_2_report_ioc_forms_stripped(make_case, ioc):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 contacted {ioc} repeatedly.")
    t = r["threat_narrative"]
    assert "185" not in t and "evil" not in t, repr(t)


@pytest.mark.parametrize("ioc", R3_IOCS)
def test_r3_2_explain_ioc_forms_not_persisted(make_case, ioc):
    c = make_case()
    _, f = _host_explain(c, "F-900-001", f"F-900-001 contacted {ioc} repeatedly.")
    d = f.get("description") or ""
    assert "185" not in d and "evil" not in d, repr(d)


@pytest.mark.parametrize("raw,expected", [
    ("185[[.]]220[[.]]101[[.]]42", "185.220.101.42"),
    ("185{.}220{.}101{.}42", "185.220.101.42"),
    ("185.\n220.\n101.\n42", "185.220.101.42"),
    ("185\n.220\n.101\n.42", "185.220.101.42"),
    ("185 dot 220 dot 101 dot 42", "185.220.101.42"),
    ("evil-c2 [ . ] com", "evil-c2.com"),
    ("evil[[.]]com", "evil.com"),
])
def test_r3_3_canonicalize_single_pass(raw, expected):
    assert grounding.canonicalize(raw) == expected


_ALPHABET = list("T1003.006 F-9[](){}<>dot\n\r\t  ​­·．。‐—-hxxp:/_*`~evilcom") + [
    "[.]", "[[.]]", "(dot)", "[dot]", " dot ", "{.}", "[ . ]", "Т", "ο", "ᴛ", "Ꭲ", "ꓔ"]


def test_r3_3_canonicalize_idempotent_property():
    rng = random.Random(1234)
    for _ in range(3000):
        s = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 30)))
        c1 = grounding.canonicalize(s)
        assert grounding.canonicalize(c1) == c1, (s, c1)


# ── R3-4: no sentence-boundary TLD fusion (false positives) ────────────

R3_FP = [
    "F-900-001 beacons were observed. Local administrator logons are out of scope for this capture.",
    "F-900-001 shows periodic HTTP. Live response was not performed.",
    "F-900-001 shows periodic HTTP. Top talkers are listed in the IOC table.",
    "F-900-001 shows periodic HTTP to good.example.com. Online services were contacted.",
    "F-900-001 is mapped to T1071.001. Local timestamps are UTC.",
    "F-900-001 involves 198.51.100.7. Top talkers are listed in the IOC table.",
    "F-900-001 uses the .NET runtime and web protocols.",
]


@pytest.mark.parametrize("txt", R3_FP)
def test_r3_4_report_legit_prose_round_trips(make_case, txt):
    c = make_case()
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt, r["violations"]


@pytest.mark.parametrize("txt", [
    "F-900-001 beacons were observed. Local administrator logons for F-900-001 are out of scope.",
    "F-900-001 shows periodic HTTP. Live response for F-900-001 was not performed.",
    "F-900-001 shows periodic HTTP to good.example.com. Online services in F-900-001 were contacted.",
    "F-900-001 is mapped to T1071.001. Local timestamps for F-900-001 are UTC.",
])
def test_r3_4_explain_legit_prose_round_trips(make_case, txt):
    c = make_case()
    r, f = _host_explain(c, "F-900-001", txt)
    assert f["description"] == txt, r["violations"]


# Realistic XLoader case (review e2e_host.py prose) — every sentence cited
# and grounded, so NOTHING may be stripped.
XL = [
    {"finding_id": "F-001-001", "rule_id": "pcap-staging-download", "mitre_attack": "T1105",
     "title": "Large download from file-sharing/staging host files.catbox.moe "
              "(108.181.20.35, 1.4 MB)",
     "iocs": {"ip": ["108.181.20.35"], "domain": ["files.catbox.moe"]}},
    {"finding_id": "F-001-002", "rule_id": "pcap-beacon", "mitre_attack": "T1071.001",
     "title": "C2 Beacon detected: 66.235.200.146 — 18 beacons at 3s intervals (MAD=0.0s)",
     "iocs": {"ip": ["66.235.200.146"], "domain": []}},
    {"finding_id": "F-001-003", "rule_id": "pcap-dns-anomaly", "mitre_attack": "T1568",
     "title": "DNS anomaly: suspicious TLD: .top — www.qmrcumg.top",
     "iocs": {"ip": [], "domain": ["www.qmrcumg.top"]}},
    {"finding_id": "F-001-004", "rule_id": "pcap-large-transfer", "mitre_attack": "T1105",
     "title": "Large network transfer (large ingress transfer): 6375 bytes out / 8172723 bytes in",
     "iocs": {"ip": ["108.181.20.35"], "domain": []}},
]


def _xl_findings():
    out = []
    for x in XL:
        f = dict(F1)
        f.update(x)
        f["corroboration"] = {"sources": 1, "tools": ["zeek:conn.log"],
                              "artifacts": [x["title"]]}
        out.append(f)
    return out


def test_r3_4_xloader_realistic_prose_nothing_stripped(make_case):
    from spectre.core.validators import load_verified_findings
    from spectre.pipeline.report_synthesize import ingest_host_report
    c = make_case(findings=_xl_findings(), name="001-xl")
    for x in XL:
        fid = x["finding_id"]
        parts = [f"{fid} records {x['title'].split(' — ')[0]} activity."]
        if x["iocs"]["ip"]:
            parts.append(f"{fid} involves {x['iocs']['ip'][0]}.")
        if x["iocs"]["domain"]:
            parts.append(f"{fid} references {x['iocs']['domain'][0]}.")
        parts.append(f"{fid} is mapped to {x['mitre_attack']}.")
        parts.append(f"Local analysis of endpoint artifacts for {fid} was not performed.")
        desc = " ".join(parts)
        r, f = _host_explain(c, fid, desc, mitre=x["mitre_attack"])
        assert f["description"] == desc, (fid, r["violations"])
    fnd, _ = load_verified_findings(c)
    f0 = fnd[0]
    narr = {
        "executive_summary": f"The capture shows repeated outbound activity. "
                             f"{f0['finding_id']} is the strongest lead.",
        "threat_narrative": f"{f0['finding_id']} shows periodic traffic to 108.181.20.35. "
                            "Top talkers are summarised in the IOC table. "
                            "Live response was not performed.",
        "verdict": "These are investigative leads that need examiner validation.",
        "findings_narrative": [{"finding_id": f["finding_id"],
                                "narrative": f"{f['finding_id']} is {f['title']}."}
                               for f in fnd],
        "timeline_narrative": "Activity clusters in the first hour of the capture.",
        "methodology_narrative": "Zeek logs were parsed and deterministic rules evaluated. "
                                 "Local timestamps are UTC.",
    }
    rep = ingest_host_report(str(c), narr)
    for k in ("executive_summary", "threat_narrative", "verdict",
              "timeline_narrative", "methodology_narrative"):
        assert rep[k] == narr[k], (k, rep[k], rep["violations"])
    for a, b in zip(narr["findings_narrative"], rep["findings_narrative"]):
        assert a["narrative"] == b["narrative"], rep["violations"]
    assert not any("stripped" in v for v in rep["violations"]), rep["violations"]


# ── R3-5: caveat signal evasions ───────────────────────────────────────

@pytest.mark.parametrize("sig", ["does nⲟt prove", "does-not-prove", "does_not_prove",
                                 "does not prove"])
def test_r3_5_report_caveat_signal_evasions(make_case, sig):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 beacon {sig} lateral movement.")
    assert "lateral" not in r["threat_narrative"]


# ── Character policy + L1: originals kept, never folded ────────────────

def test_policy_non_latin_letter_sentence_dropped_with_reason(make_case):
    c = make_case()
    r = _report(c, threat_narrative="F-900-001 shows periodic HTTP. F-900-001 is Ꭲ-class activity.")
    assert r["threat_narrative"] == "F-900-001 shows periodic HTTP."
    assert any("disallowed character in validated text" in v for v in r["violations"])


def _idn_case(make_case, idn):
    f = dict(F1, iocs={"ip": ["198.51.100.7"], "domain": [idn]},
             corroboration={"sources": 1, "tools": ["zeek/dns"], "artifacts": [f"dns {idn}"]})
    return make_case(findings=(f, F2))


def test_policy_real_idn_ioc_survives_verbatim(make_case):
    idn = "pаypal-update.com"   # Cyrillic а: a REAL homograph IOC in the data
    c = _idn_case(make_case, idn)
    txt = f"F-900-001 resolved {idn} repeatedly."
    r = _report(c, threat_narrative=txt)
    assert r["threat_narrative"] == txt          # Cyrillic kept, not folded
    _, fy = _host_explain(c, "F-900-001", txt)
    assert fy["description"] == txt


def test_l1_rewrite_never_folds_other_sentences(make_case):
    idn = "pаypal-update.com"
    c = _idn_case(make_case, idn)
    r = _report(c, threat_narrative=f"F-900-001 resolved {idn}. F-900-001 is T1486 — ransomware.")
    t = r["threat_narrative"]
    assert idn in t                   # original Cyrillic preserved
    assert "paypal-update.com" not in t
    assert "1486" not in t


def test_l1_typography_preserved_next_to_a_rewrite(make_case):
    c = make_case()
    txt = "F-900-001 shows periodic HTTP — cadence noted. F-900-001 is T1486."
    r = _report(c, threat_narrative=txt)
    assert "HTTP — cadence" in r["threat_narrative"]
    assert "1486" not in r["threat_narrative"]


# ── L5: finding-ID forms ───────────────────────────────────────────────

@pytest.mark.parametrize("fid", ["f-900-777", "ꓝ-900-777", "F.900.777", "F-900-777"])
def test_l5_invented_fid_forms(make_case, fid):
    c = make_case()
    r = _report(c, threat_narrative=f"F-900-001 and {fid} show the same cadence.")
    assert "777" not in r["threat_narrative"]
    _, f = _host_explain(c, "F-900-001", f"F-900-001 and {fid} show the same cadence.")
    assert "777" not in (f.get("description") or "")


# ── L3: non-string caveats must not crash ──────────────────────────────

@pytest.mark.parametrize("cav", ["abc", [{"x": 1}], [1], [None, "x"], {"a": "b"}])
def test_l3_non_string_caveats_do_not_crash(make_case, cav):
    from spectre.core import explain as ex
    c = make_case()
    fp = c / "findings" / "F-900-001.yaml"
    r = ex.ingest_host_output(str(fp), case_dir=str(c),
                              host_json={"description": "F-900-001 beacons.",
                                         "mitre_attack": "T1071.001", "caveats": cav})
    assert isinstance(r["output"]["caveats"], list)
    assert all(isinstance(x, str) for x in r["output"]["caveats"])


# ── L2: B8 location binding compares the resolved path ─────────────────

def test_l2_persist_to_copy_outside_case_refused(make_case, tmp_path):
    from spectre.core import explain as ex
    from spectre.core.validators import load_verified_findings
    c = make_case()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shutil.copy(c / "findings" / "F-900-001.yaml", outside / "F-900-001.yaml")
    r = ex.ingest_host_output(str(outside / "F-900-001.yaml"), case_dir=str(c),
                              host_json={"description": "F-900-001 beacons.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert r["persist_refused"] is True
    load_verified_findings(c)   # real finding untouched → no integrity error


def test_l2_symlink_into_case_refused(make_case, tmp_path):
    from spectre.core import explain as ex
    c = make_case()
    outside = tmp_path / "elsewhere2"
    outside.mkdir()
    real = c / "findings" / "F-900-001.yaml"
    shutil.copy(real, outside / "F-900-001.yaml")
    real.unlink()
    os.symlink(outside / "F-900-001.yaml", real)
    r = ex.ingest_host_output(str(real), case_dir=str(c),
                              host_json={"description": "F-900-001 beacons.",
                                         "mitre_attack": "T1071.001", "caveats": []})
    assert r["persist_refused"] is True


# ── L4: ReDoS / performance ────────────────────────────────────────────

@pytest.mark.parametrize("blob", ["1." * 500_000, "a-" * 500_000, "a." * 500_000,
                                  "T" + " " * 1_000_000 + "x", ("F" + "_" * 50 + "-") * 20_000,
                                  "185 . " * 170_000, "x [.] " * 170_000])
def test_l4_extract_iocs_1mb_under_1s(blob):
    t0 = time.perf_counter()
    grounding.extract_iocs(blob)
    assert time.perf_counter() - t0 < 1.0


def test_l4_domain_extraction_unchanged():
    toks = grounding.extract_iocs("see evil.com. and a.b.example.org, then x_y.evil.net")
    assert {"evil.com", "a.b.example.org"} <= toks
    assert any(t.endswith("evil.net") for t in toks)
    assert "evil.com" in grounding.extract_iocs("see _evil.com_ in italics")
    assert "files.catbox.moe" in grounding.extract_iocs("host files.catbox.moe (108.181.20.35)")
