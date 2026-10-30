"""R4-3 (W2A-REVIEW4): ASCII digit lookalikes inside IOCs.

`l85.220.101.42` (l for 1), `185.22O.1O1.42` (O for 0) and a sha256 with an
`O` did not parse as IOCs, so nothing was grounded or stripped, yet a reader
reads them as one. They are now IOC candidates in their ORIGINAL spelling:
grounded only when that exact spelling occurs in deterministic data, so a
lookalike of a grounded IOC is stripped too. Output is never rewritten.
"""
from __future__ import annotations

import pytest

from spectre.core import grounding
from tests.test_core import test_w2a_rereview as _rr
from tests.test_core.test_w2a_round4 import _three

make_case = _rr.make_case
_no_journal = _rr._no_journal

SHA = "9f2b5c3a7d1e4f60a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5"
SHA_O = SHA.replace("60a8", "6Oa8")
MD5_L = "5d41402abc4b2a76b9719d911O17c592"
SHA1_I = "a94a8fe5ccb19ba61c4c0873d391e987982fbbdI"

POSITIVE = [
    ("l85.220.101.42", "l85.220.101.42"),
    ("185.22O.1O1.42", "185.22O.1O1.42"),
    ("I85.220.101.42", "I85.220.101.42"),
    ("185.220.1|1.42", "185.220.1|1.42"),
    ("l98.51.100.7", "l98.51.100.7"),          # lookalike of F1's GROUNDED ip
    (SHA_O, SHA_O),
    (MD5_L, MD5_L),
    (SHA1_I, SHA1_I),
    ("evil-c2.c0m", "evil-c2.c0m"),
]


@pytest.mark.parametrize("txt,tok", POSITIVE)
def test_lookalike_is_ioc_candidate_in_original_spelling(txt, tok):
    toks = grounding.extract_iocs(f"Beacon to {txt}, every 60 seconds.")
    assert tok in toks, toks


@pytest.mark.parametrize("txt,_tok", POSITIVE)
def test_lookalike_of_grounded_ioc_is_not_grounded(txt, _tok):
    # Folded form IS grounded; only a verbatim occurrence grounds it.
    grounded = grounding.grounded_tokens({"iocs": ["185.220.101.42", "198.51.100.7",
                                                   SHA, SHA.replace("6Oa8", "60a8"),
                                                   "evil-c2.com"]})
    assert grounding.ungrounded_literals(f"Beacon to {txt}.", grounded)


def test_lookalike_grounded_verbatim_survives():
    grounded = grounding.grounded_tokens({"artifacts": ["dst l85.220.101.42 seen", SHA_O]})
    assert not grounding.ungrounded_literals(f"Beacon to l85.220.101.42 and {SHA_O}.",
                                             grounded)


@pytest.mark.parametrize("txt", [
    "lOO", "The lOO marker was set.", "v1.O", "Upgraded to v2.1.O last week.",
    "Il.lO", "IOI.IO.IO.II", "| 10.0.0.1 | 10.0.0.2 |", "|10.0.0.1|10.0.0.2|",
    "I/O wait was high.", "OLE stream", "x86.64", "song.mp3", "COM1.LOG",
    "Table I.O.U.", "999.l.l.l", "lOOO.10.10.10", "300.2O.1.1",
    "deadbeefIOIOdeadbeefIOIOdeadbeef",            # 32 chars, < 2 real digits
    "SELECT lOO FROM t", "The ratio was 1.0.", "build 10.0.19041.l",
    "see report.l0g", "host web01.corp", "node srv.n1", "api.v1",
])
def test_no_false_positive(txt):
    """R4-3 must add no token the pre-existing regexes did not produce."""
    assert grounding.extract_iocs(txt) - _plain(txt) == set(), grounding.extract_iocs(txt)


def test_short_dotted_quad_with_substitution_is_a_documented_conservative_strip():
    # One substitution + >=2 real digits IS an IPv4 lookalike by construction.
    assert grounding.extract_iocs("Section 3.1.2.l of the guide.") == {"3.1.2.l"}


def _plain(txt):
    """IOC tokens the pre-R4-3 regexes already produced."""
    t = grounding.canonicalize(txt)
    out = set()
    for rx in grounding._CASE_SENSITIVE:
        out |= set(rx.findall(t))
    for rx in grounding._CASE_FOLD:
        out |= {m.lower() for m in rx.findall(t)}
    return out


@pytest.mark.parametrize("txt", ["l85.220.101.42", "185.22O.1O1.42", "l98.51.100.7",
                                 SHA_O, "evil-c2.c0m"])
def test_lookalike_fail_closed_all_seams(make_case, txt):
    for out in _three(make_case, f"F-900-001 beacons to {txt} every 60 seconds."):
        assert txt not in out, out
