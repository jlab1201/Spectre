"""Determinism tripwire for the pcap rule pack (WS5 target).

Confirmed bug (WS5, now fixed): `src/spectre/modules/pcap/rules.py` built
several indicator lookups as `frozenset(load_indicator_list(...))`
(module-level, ~lines 27-33 and ~684: _SUSPICIOUS_PORTS,
_EXPOSED_SERVICE_PORTS, _C2_USER_AGENTS, _CAMPAIGN_PARAM_KEYS,
_C2_SERVER_HEADERS, _SUSPICIOUS_TLDS) and iterated them with plain
`for x in frozenset_obj:` (c2_protocol() at ~lines 522/540/579;
dns_anomaly() at ~line 718). Python randomizes str hashing per-process
(PYTHONHASHSEED), so frozenset iteration order for the SAME set of strings
differs across process runs. When more than one indicator matches the same
event (e.g. a User-Agent containing two known RAT substrings, or a domain
matching two suspicious-TLD entries), the match order leaked into
`Anchor.title` via `'; '.join(triggers)` (c2_protocol ~line 630,
dns_anomaly ~line 738) -- so the same evidence could produce a
differently-worded finding title on different runs, purely from hash-seed
noise, with zero change in the underlying evidence.

WS5 fixed this by iterating `sorted(...)` at every site whose match order
reaches output text, while keeping the frozensets themselves for O(1)
membership tests elsewhere.

This test drives the REAL rule functions (spectre.modules.pcap.rules.
c2_protocol and dns_anomaly) — not a reimplementation — from two child
processes with different PYTHONHASHSEED values, over the same synthetic
NormEvent, and asserts the two titles are byte-identical. Two paths are
covered: c2_protocol() exercises _C2_USER_AGENTS (and, by the same fix,
_C2_SERVER_HEADERS / _CAMPAIGN_PARAM_KEYS use the identical sorted()
pattern), and dns_anomaly() exercises _SUSPICIOUS_TLDS. The dns_anomaly
case monkeypatches _SUSPICIOUS_TLDS with nested-suffix entries (e.g.
"xyz" / "top.xyz" / "shop.top.xyz") so a single domain matches more than
one entry — the real production indicator list has no TLD that is itself
a suffix of another TLD, so a real domain can never match more than one
entry and would not exercise the ordering bug at all.
"""

import subprocess
import sys

# A User-Agent containing FOUR known c2_user_agents substrings (see
# knowledge/indicators/network.yaml -> c2_user_agents.values). Using four
# distinct matches (rather than two) makes the seed-0-vs-seed-1 comparison
# robust -- empirically confirmed to differ for this pair; a two-substring
# UA can coincidentally agree between some seed pairs even though the
# underlying iteration order is still hash-randomized.
_CHILD_SCRIPT = r"""
import sys
from spectre.core.base import NormEvent
from spectre.modules.pcap.rules import c2_protocol

e = NormEvent(
    artifact_type="pcap_http",
    timestamp="2026-01-01T00:00:00Z",
    source_file="determinism-tripwire.pcap",
    record_id="1",
    host="10.0.0.5",
    data={
        "direction": "outbound",
        "dst_port": "8080",
        "dst_ip": "203.0.113.9",
        "src_ip": "10.0.0.5",
        "raw": "",
        "ascii_payload": "",
        "http_user_agent": (
            "NetSupport Manager NetSupport Gateway Cobalt Strike Metasploit"
        ),
        "http_server": "",
        "http_request_path": "",
        "http_host": "",
    },
)
anchor = c2_protocol(e)
sys.stdout.write(anchor.title if anchor is not None else "NO_ANCHOR")
"""


# dns_anomaly() path: _SUSPICIOUS_TLDS is monkeypatched with nested-suffix
# entries so ONE domain matches FOUR entries at once (the real production
# list has no TLD that is a suffix of another TLD, so a real domain can
# only ever match one entry -- see module docstring above). The nested
# suffixes ("xyz", "top.xyz", "shop.top.xyz", "biz.shop.top.xyz") all end
# the domain "evil.biz.shop.top.xyz" simultaneously, exercising the exact
# same hash-randomized-join hazard that c2_protocol's User-Agent loop hits.
_DNS_CHILD_SCRIPT = r"""
import sys
from spectre.core.base import NormEvent
import spectre.modules.pcap.rules as rules

rules._SUSPICIOUS_TLDS = frozenset({
    "xyz", "top.xyz", "shop.top.xyz", "biz.shop.top.xyz",
})

e = NormEvent(
    artifact_type="pcap_dns",
    timestamp="2026-01-01T00:00:00Z",
    source_file="determinism-tripwire.pcap",
    record_id="1",
    host="10.0.0.5",
    data={"dns_query": "evil.biz.shop.top.xyz"},
)
anchor = rules.dns_anomaly(e)
sys.stdout.write(anchor.title if anchor is not None else "NO_ANCHOR")
"""


def _run_with_hashseed(seed: str, script: str = _CHILD_SCRIPT) -> str:
    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**__import__("os").environ, "PYTHONHASHSEED": seed},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"child process (PYTHONHASHSEED={seed}) failed: {result.stderr}"
    )
    return result.stdout


def test_c2_protocol_title_is_hashseed_independent():
    title_seed0 = _run_with_hashseed("0")
    title_seed1 = _run_with_hashseed("1")

    assert title_seed0 != "NO_ANCHOR", "rule did not fire -- fixture drifted"
    assert title_seed1 != "NO_ANCHOR", "rule did not fire -- fixture drifted"

    assert title_seed0 == title_seed1, (
        "finding title changed across PYTHONHASHSEED values for identical "
        "evidence -- frozenset iteration order is leaking into output text:\n"
        f"  seed=0: {title_seed0!r}\n"
        f"  seed=1: {title_seed1!r}"
    )


def test_dns_anomaly_title_is_hashseed_independent():
    title_seed0 = _run_with_hashseed("0", _DNS_CHILD_SCRIPT)
    title_seed1 = _run_with_hashseed("1", _DNS_CHILD_SCRIPT)

    assert title_seed0 != "NO_ANCHOR", "rule did not fire -- fixture drifted"
    assert title_seed1 != "NO_ANCHOR", "rule did not fire -- fixture drifted"

    assert title_seed0 == title_seed1, (
        "finding title changed across PYTHONHASHSEED values for identical "
        "evidence -- _SUSPICIOUS_TLDS iteration order is leaking into "
        "output text:\n"
        f"  seed=0: {title_seed0!r}\n"
        f"  seed=1: {title_seed1!r}"
    )


# ── memory/rules.py: _looks_like_system (R3-01) ──
#
# `_SYSTEM_NAMES` is a frozenset built from an indicator list. The
# edit-distance scan in `_looks_like_system()` used to be a bare
# `for sysname in _SYSTEM_NAMES: if _damerau1(...): return sysname` --
# first-hash-order-match. When a masqueraded name is edit-distance-1 from
# more than one real system name, the returned name (and therefore the
# "is a look-alike of X.exe" text in masquerade_system_process()'s title)
# depended on PYTHONHASHSEED, not on the evidence. Fixed by scanning
# `sorted(_SYSTEM_NAMES)`. _SYSTEM_NAMES is monkeypatched here with three
# 5-letter names that are all simultaneously edit-distance-1 from one
# probe name, so the ambiguity is guaranteed regardless of the production
# indicator list's actual contents.
_MEMORY_CHILD_SCRIPT = r"""
import sys
import spectre.modules.memory.rules as rules

rules._SYSTEM_NAMES = frozenset({"alpha", "alphb", "alphc"})

result = rules._looks_like_system("alphx")
sys.stdout.write(result if result is not None else "NO_MATCH")
"""


def test_looks_like_system_is_hashseed_independent():
    result_seed0 = _run_with_hashseed("0", _MEMORY_CHILD_SCRIPT)
    result_seed1 = _run_with_hashseed("1", _MEMORY_CHILD_SCRIPT)

    assert result_seed0 != "NO_MATCH", "rule did not fire -- fixture drifted"
    assert result_seed1 != "NO_MATCH", "rule did not fire -- fixture drifted"

    assert result_seed0 == result_seed1, (
        "_looks_like_system() picked a different masqueraded-as name across "
        "PYTHONHASHSEED values for identical evidence -- _SYSTEM_NAMES "
        "iteration order is leaking into the returned name:\n"
        f"  seed=0: {result_seed0!r}\n"
        f"  seed=1: {result_seed1!r}"
    )


# ── logfile/rules.py: suspicious_token (R3-02) ──
#
# `_BAD_TOKENS` is a frozenset (offensive-tool + LOLBin indicator lists).
# The scan used to be `for token in _BAD_TOKENS: if token in blob: return
# ...` -- first-hash-order-match, dropping every other indicator present
# in the same record and letting the chosen token (which feeds both the
# title and the dedup_key) vary with PYTHONHASHSEED. Fixed by reporting
# ALL matched tokens, sorted, in one finding. _BAD_TOKENS is monkeypatched
# with three tokens that all appear in one synthetic record so the test
# does not depend on the production indicator lists' contents or order.
_LOGFILE_CHILD_SCRIPT = r"""
import sys
from spectre.core.base import NormEvent
import spectre.modules.logfile.rules as rules

rules._BAD_TOKENS = frozenset({"mimikatz", "psexec", "certutil"})

e = NormEvent(
    "logfile_record", "2026-01-01T00:00:00Z", "auth.log", "1",
    data={"message": "certutil dropped psexec then ran mimikatz on host"},
)
anchor = rules.suspicious_token(e)
sys.stdout.write(anchor.title + "|" + anchor.dedup_key if anchor else "NO_ANCHOR")
"""


def test_suspicious_token_output_is_hashseed_independent():
    out_seed0 = _run_with_hashseed("0", _LOGFILE_CHILD_SCRIPT)
    out_seed1 = _run_with_hashseed("1", _LOGFILE_CHILD_SCRIPT)

    assert out_seed0 != "NO_ANCHOR", "rule did not fire -- fixture drifted"
    assert out_seed1 != "NO_ANCHOR", "rule did not fire -- fixture drifted"

    assert out_seed0 == out_seed1, (
        "suspicious_token() title/dedup_key changed across PYTHONHASHSEED "
        "values for identical evidence -- _BAD_TOKENS iteration order is "
        "leaking into output text:\n"
        f"  seed=0: {out_seed0!r}\n"
        f"  seed=1: {out_seed1!r}"
    )

    # All three matched tokens must be present and in sorted order -- the
    # forensically-better fix reports every matched indicator, not just
    # the first hash-order hit.
    assert "'certutil'" in out_seed0
    assert "'mimikatz'" in out_seed0
    assert "'psexec'" in out_seed0
    assert out_seed0.index("'certutil'") < out_seed0.index("'mimikatz'") \
        < out_seed0.index("'psexec'")


# ── pipeline/spectre_memory.py: _engines_used (sweep finding, same class) ──
#
# `"engines_used": list(set(h.get("engine", "?") for h in handles))` built a
# set from three+ distinct engine-name strings and converted it straight to
# a list -- no sort. Found during the R3-01/R3-02 sweep of every
# `for x in <set>`/`list(set(...))` site whose result reaches output. Fixed
# by extracting `_engines_used()` and sorting.
_SPECTRE_MEMORY_CHILD_SCRIPT = r"""
import sys
from spectre.pipeline.spectre_memory import _engines_used

handles = [
    {"engine": "volatility3"},
    {"engine": "memprocfs"},
    {"engine": "zzz-third-engine"},
]
sys.stdout.write(",".join(_engines_used(handles)))
"""


def test_engines_used_is_hashseed_independent():
    out_seed0 = _run_with_hashseed("0", _SPECTRE_MEMORY_CHILD_SCRIPT)
    out_seed1 = _run_with_hashseed("1", _SPECTRE_MEMORY_CHILD_SCRIPT)

    assert out_seed0 == "memprocfs,volatility3,zzz-third-engine"
    assert out_seed0 == out_seed1, (
        "engines_used ordering changed across PYTHONHASHSEED values for "
        "identical handles:\n"
        f"  seed=0: {out_seed0!r}\n"
        f"  seed=1: {out_seed1!r}"
    )
