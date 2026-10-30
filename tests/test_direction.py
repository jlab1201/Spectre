"""
test_direction.py — Phase 1 (Direction) parser / synthesizer tests.

direction.py turns a natural-language investigator tasking into validated,
JSON-serializable *directive specs*. Deterministic-first: literal IOCs,
lineage, temporal and concept directives are parsed with no LLM. The LLM is
only a seam for truly fuzzy phrasing; under --skip-ai unparsed fragments
become recorded warnings, never silent guesses.
"""

import sys

from spectre.pipeline import direction


# ── parse: IOC ──────────────────────────────────────────────────────
def test_parse_ip_ioc_include():
    specs, unparsed = direction.parse_deterministic("look for ip 192.158.12.1")
    assert len(specs) == 1, specs
    s = specs[0]
    assert s["type"] == "ioc_match"
    assert s["params"]["ioc_type"] == "ip"
    assert s["params"]["value"] == "192.158.12.1"
    assert s["polarity"] == "include"
    assert s["origin"] == "deterministic"


def test_parse_negation_sets_exclude_polarity():
    specs, _ = direction.parse_deterministic("exclude events involving 192.168.12.1")
    assert len(specs) == 1, specs
    assert specs[0]["params"]["value"] == "192.168.12.1"
    assert specs[0]["polarity"] == "exclude"


def test_parse_sha256_ioc():
    h = "a" * 64
    specs, _ = direction.parse_deterministic(f"hunt for hash {h}")
    assert any(s["params"].get("ioc_type") == "sha256" and s["params"]["value"] == h
               for s in specs), specs


def test_exe_is_not_parsed_as_domain():
    # 'powershell.exe' must never be misread as a domain IOC.
    specs, _ = direction.parse_deterministic("executable spawned by powershell.exe")
    assert not any(s["params"].get("ioc_type") == "domain" for s in specs), specs


# ── parse: lineage ──────────────────────────────────────────────────
def test_parse_lineage_spawned_by():
    specs, _ = direction.parse_deterministic("executable spawned by powershell.exe")
    lin = [s for s in specs if s["type"] == "lineage"]
    assert len(lin) == 1, specs
    assert lin[0]["params"]["parent"] == "powershell.exe"
    assert lin[0]["polarity"] == "include"


# ── parse: temporal ─────────────────────────────────────────────────
def test_parse_temporal_standalone():
    specs, _ = direction.parse_deterministic("show anything between 02:00 and 04:00")
    temp = [s for s in specs if s["type"] == "temporal"]
    assert len(temp) == 1, specs
    assert temp[0]["params"]["start"] == "02:00"
    assert temp[0]["params"]["end"] == "04:00"


def test_temporal_attaches_as_modifier_when_combined():
    # "spawned by X between T1 and T2" -> ONE lineage directive whose
    # modifiers carry the time window (not two separate directives).
    specs, _ = direction.parse_deterministic(
        "executable spawned by powershell.exe between 02:00 and 04:00")
    lin = [s for s in specs if s["type"] == "lineage"]
    assert len(lin) == 1, specs
    assert lin[0]["modifiers"]["time_window"]["start"] == "02:00"
    assert lin[0]["modifiers"]["time_window"]["end"] == "04:00"
    assert not [s for s in specs if s["type"] == "temporal"], specs


# ── parse: concept (curated map, no LLM) ────────────────────────────
def test_parse_concept_expands_to_directives():
    specs, unparsed = direction.parse_deterministic("look for suspicious executables")
    assert specs, "concept should expand to >=1 directive"
    assert all(s["origin"] == "concept_map" for s in specs), specs
    assert all(s["type"] in ("field_match", "lineage", "ioc_match") for s in specs)
    assert not unparsed, unparsed


# ── parse: mixed polarity per clause ────────────────────────────────
def test_mixed_polarity_split_per_clause():
    # One sentence, two intents: hunt the lineage, scope out the IP.
    specs, _ = direction.parse_deterministic(
        "look for executable spawned by powershell.exe and exclude 192.168.12.1")
    lin = [s for s in specs if s["type"] == "lineage"]
    ioc = [s for s in specs if s["type"] == "ioc_match"]
    assert len(lin) == 1 and lin[0]["polarity"] == "include", specs
    assert len(ioc) == 1 and ioc[0]["polarity"] == "exclude", specs


def test_and_split_does_not_break_temporal_range():
    # "between 02:00 and 04:00" must stay one temporal window, not split on 'and'.
    specs, _ = direction.parse_deterministic(
        "executable spawned by powershell.exe between 02:00 and 04:00")
    lin = [s for s in specs if s["type"] == "lineage"]
    assert len(lin) == 1, specs
    assert lin[0]["modifiers"]["time_window"]["start"] == "02:00"
    assert lin[0]["modifiers"]["time_window"]["end"] == "04:00"


# ── parse: junk ─────────────────────────────────────────────────────
def test_parse_junk_is_unparsed_not_invented():
    specs, unparsed = direction.parse_deterministic("please have a nice day")
    assert specs == [], specs
    assert unparsed, "non-matching text must be surfaced as unparsed"


# ── validate ────────────────────────────────────────────────────────
def test_validate_accepts_good_ioc():
    spec = {"type": "ioc_match", "polarity": "include",
            "params": {"ioc_type": "ip", "value": "1.2.3.4"}}
    assert direction.validate(spec) is True


def test_validate_rejects_bad_type():
    spec = {"type": "nonsense", "polarity": "include", "params": {}}
    assert direction.validate(spec) is False


def test_validate_rejects_empty_ioc_value():
    spec = {"type": "ioc_match", "polarity": "include",
            "params": {"ioc_type": "ip", "value": ""}}
    assert direction.validate(spec) is False


def test_validate_rejects_bad_polarity():
    spec = {"type": "ioc_match", "polarity": "destroy",
            "params": {"ioc_type": "ip", "value": "1.2.3.4"}}
    assert direction.validate(spec) is False


# ── synthesize ──────────────────────────────────────────────────────
def test_synthesize_assigns_ids_and_keeps_source():
    res = direction.synthesize("look for ip 192.158.12.1", skip_ai=True)
    ds = res["directives"]
    assert len(ds) == 1
    assert ds[0]["directive_id"].startswith("dir-")
    assert ds[0]["source_direction"] == "look for ip 192.158.12.1"


def test_synthesize_empty_direction_is_clean():
    res = direction.synthesize("", skip_ai=True)
    assert res["directives"] == []
    assert res["warnings"] == []


def test_synthesize_skip_ai_warns_on_unparsed_not_guesses():
    res = direction.synthesize("do something clever about the thing", skip_ai=True)
    assert res["directives"] == [], res["directives"]
    assert res["warnings"], "skip-ai must surface unparsed direction as a warning"


# ── W1-1: host-mode NEVER implicitly falls back to a direct API provider ──
# (R2-06): removed entirely. A DEEPSEEK_API_KEY (or any other direct-provider
# key) being discoverable in the environment or ~/.spectre.env must not
# change host-mode behavior at all — the fragment stays unparsed either way,
# and no HTTP call is ever made from this seam under the host provider.
def test_synthesize_host_defers_even_with_key_present_no_egress(monkeypatch):
    """A DEEPSEEK_API_KEY being present must NOT drive parsing, and must
    NOT result in any network call — the exact undisclosed-egress behavior
    R2-06 flagged (a real run posted case findings to DeepSeek with no
    opt-in). urlopen raising proves the seam is never reached."""
    from spectre import llm

    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "host")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")

    def _boom(*a, **k):
        raise AssertionError(
            "host mode must never call a direct provider's API, even when "
            "a key is discoverable in the environment"
        )

    monkeypatch.setattr(llm.urllib.request, "urlopen", _boom)

    res = direction.synthesize("do something clever about the thing", skip_ai=False)
    assert res["directives"] == [], res
    assert res["warnings"]
    assert res["llm_used"] is False
    assert not hasattr(llm, "first_direct_provider")


def test_synthesize_host_defers_no_key_stays_unparsed(monkeypatch):
    """No direct key discoverable → deferred, fragment surfaced as a warning
    (deterministic-first preserved; nothing invented)."""
    from spectre import llm

    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "host")
    for k in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SPECTRE_ENV_FILE", "/nonexistent/path/.env")

    def _boom(*a, **k):  # a network call here would be a bug
        raise AssertionError("must not call an API when no key is discoverable")

    monkeypatch.setattr(llm.urllib.request, "urlopen", _boom)

    res = direction.synthesize("do something clever about the thing", skip_ai=False)
    assert res["directives"] == []
    assert res["warnings"]


# ── R2-05(a): LLM-produced directive values bound to the fragment ────
# directives.py's to_anchor() copies a directive's *value* straight into
# the finding's iocs (R2-05(c) makes it record the observed value instead,
# but that only helps once a directive actually matches an event). The
# earlier line of defense belongs here: an LLM asked to expand a fuzzy
# fragment must never be allowed to introduce a literal IOC/param value that
# was not in the analyst's own text — R2's PoC showed `validate()` alone
# accepts exactly that ("look at the tor stuff" -> a concrete IP).
class _FakeIOCProvider:
    """Returns one canned ioc_match spec, whatever the fragment. Used to
    prove the caller — not the provider — is responsible for grounding."""

    def __init__(self, ioc_type="ip", value="185.220.101.4"):
        self.ioc_type = ioc_type
        self.value = value

    def complete(self, system, user, *, max_tokens=512, temperature=0.0, schema=None):
        from spectre import llm as llm_mod
        return llm_mod.LLMResponse(parsed={"specs": [
            {"type": "ioc_match", "polarity": "include",
             "params": {"ioc_type": self.ioc_type, "value": self.value}},
        ]})


def test_call_llm_drops_ioc_value_absent_from_fragment(monkeypatch):
    monkeypatch.setattr(direction, "get_provider", lambda: _FakeIOCProvider())
    specs, deferred, dropped = direction._call_llm("look at the tor stuff")
    assert specs is None
    assert deferred is False
    assert dropped and "ungrounded" in dropped[0]


def test_call_llm_keeps_ioc_value_present_in_fragment(monkeypatch):
    monkeypatch.setattr(direction, "get_provider", lambda: _FakeIOCProvider())
    specs, deferred, dropped = direction._call_llm(
        "connections to 185.220.101.4 look suspicious")
    assert deferred is False
    assert dropped == []
    assert specs and specs[0]["params"]["value"] == "185.220.101.4"


def test_call_llm_grounding_is_defang_aware(monkeypatch):
    monkeypatch.setattr(
        direction, "get_provider",
        lambda: _FakeIOCProvider(ioc_type="domain", value="evil-c2.com"))
    specs, deferred, dropped = direction._call_llm("beaconing to evil-c2[.]com observed")
    assert dropped == []
    assert specs and specs[0]["params"]["value"] == "evil-c2.com"


def test_call_llm_grounding_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(
        direction, "get_provider",
        lambda: _FakeIOCProvider(ioc_type="domain", value="Evil-C2.com"))
    specs, deferred, dropped = direction._call_llm("traffic to EVIL-C2.COM noted")
    assert dropped == []
    assert specs


# ── Orchestrator follow-up: temporal/scope are not IOC-shaped ─────────
# directives.py's to_anchor() never writes temporal start/end or scope
# artifact_types/hosts/files into a finding's `iocs` (only ioc_match does),
# so verbatim-grounding those values over-drops legitimate analyst intent
# an LLM correctly interpreted ("since last Tuesday" -> a concrete ISO
# date that never appears literally). These are validated for
# well-formedness instead; the interpretation is still surfaced as a
# warning so an analyst can catch a misreading.
class _FakeTemporalProvider:
    def __init__(self, start, end):
        self.start, self.end = start, end

    def complete(self, system, user, *, max_tokens=512, temperature=0.0, schema=None):
        from spectre import llm as llm_mod
        return llm_mod.LLMResponse(parsed={"specs": [
            {"type": "temporal", "polarity": "include",
             "params": {"start": self.start, "end": self.end}},
        ]})


def test_call_llm_keeps_temporal_with_no_verbatim_match(monkeypatch):
    # "since last Tuesday" never appears as "2026-09-23T00:00:00" in the
    # fragment — verbatim grounding would have wrongly dropped this.
    monkeypatch.setattr(
        direction, "get_provider",
        lambda: _FakeTemporalProvider("2026-09-23T00:00:00", "2026-09-30T00:00:00"))
    specs, deferred, notes = direction._call_llm("activity since last Tuesday")
    assert deferred is False
    assert specs and specs[0]["type"] == "temporal"
    assert specs[0]["params"]["start"] == "2026-09-23T00:00:00"
    assert any("LLM-interpreted temporal window" in n and "since last Tuesday" in n
               for n in notes), notes


def test_call_llm_keeps_temporal_hhmm_range(monkeypatch):
    monkeypatch.setattr(direction, "get_provider",
                         lambda: _FakeTemporalProvider("02:00", "04:00"))
    specs, deferred, notes = direction._call_llm("activity overnight")
    assert specs and specs[0]["params"]["start"] == "02:00"
    assert specs[0]["params"]["end"] == "04:00"


def test_call_llm_drops_temporal_with_start_after_end(monkeypatch):
    monkeypatch.setattr(direction, "get_provider",
                         lambda: _FakeTemporalProvider("04:00", "02:00"))
    specs, deferred, notes = direction._call_llm("activity late at night")
    assert specs is None
    assert any("dropped invalid LLM temporal directive" in n for n in notes)


def test_call_llm_drops_temporal_with_unparseable_bound(monkeypatch):
    monkeypatch.setattr(direction, "get_provider",
                         lambda: _FakeTemporalProvider("whenever", "later"))
    specs, deferred, notes = direction._call_llm("activity whenever")
    assert specs is None
    assert any("dropped invalid LLM temporal directive" in n for n in notes)


def test_synthesize_keeps_llm_temporal_from_fuzzy_fragment(monkeypatch):
    """End to end: a fragment the deterministic parser cannot handle,
    resolved by the LLM into a concrete (non-verbatim) date range, must
    survive into the directive set — this is the over-drop the
    orchestrator flagged."""
    monkeypatch.setattr(
        direction, "get_provider",
        lambda: _FakeTemporalProvider("2026-09-23T00:00:00", "2026-09-30T00:00:00"))
    res = direction.synthesize("activity since last Tuesday", skip_ai=False)
    assert len(res["directives"]) == 1
    assert res["directives"][0]["type"] == "temporal"
    assert res["llm_used"] is True
    assert any("LLM-interpreted temporal window" in w for w in res["warnings"])


class _FakeScopeProvider:
    def __init__(self, artifact_types=None, hosts=None, files=None):
        self.artifact_types = artifact_types or []
        self.hosts = hosts or []
        self.files = files or []

    def complete(self, system, user, *, max_tokens=512, temperature=0.0, schema=None):
        from spectre import llm as llm_mod
        return llm_mod.LLMResponse(parsed={"specs": [
            {"type": "scope", "polarity": "include",
             "params": {"artifact_types": self.artifact_types,
                        "hosts": self.hosts, "files": self.files}},
        ]})


def test_call_llm_keeps_scope_with_well_formed_but_unquoted_hosts(monkeypatch):
    # "the workstation" never appears as "WKSTN-07" in the fragment —
    # scope values never reach a finding field, so shape is enough.
    monkeypatch.setattr(direction, "get_provider",
                         lambda: _FakeScopeProvider(hosts=["WKSTN-07"]))
    specs, deferred, notes = direction._call_llm("only the workstation")
    assert specs and specs[0]["params"]["hosts"] == ["WKSTN-07"]


def test_call_llm_drops_scope_with_malformed_host(monkeypatch):
    monkeypatch.setattr(direction, "get_provider",
                         lambda: _FakeScopeProvider(hosts=["not a host\x00"]))
    specs, deferred, notes = direction._call_llm("only that host")
    assert specs is None
    assert any("dropped malformed LLM scope directive" in n for n in notes)


def test_synthesize_drops_ungrounded_llm_ioc_end_to_end(monkeypatch):
    """R2-05 PoC, end to end through synthesize(): a fragment the
    deterministic parser cannot handle at all, fed to an LLM that invents
    an IOC never present in the analyst's text, must not become a
    directive — and the drop must be recorded as a warning (which
    phase_runner already persists into the manifest/audit trail)."""
    monkeypatch.setattr(direction, "get_provider", lambda: _FakeIOCProvider())
    res = direction.synthesize("look at the tor stuff", skip_ai=False)
    assert res["directives"] == []
    assert res["llm_used"] is False
    assert any("ungrounded" in w for w in res["warnings"]), res["warnings"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


# ── W2-B review L1: grounding is token-bounded, not raw substring ─────
def test_call_llm_grounding_rejects_ip_prefix_of_longer_ip(monkeypatch):
    monkeypatch.setattr(direction, "get_provider", lambda: _FakeIOCProvider())
    specs, deferred, dropped = direction._call_llm("traffic to 185.220.101.42 only")
    assert specs is None
    assert dropped and "ungrounded" in dropped[0]


def test_call_llm_grounding_rejects_domain_inside_longer_label(monkeypatch):
    monkeypatch.setattr(
        direction, "get_provider",
        lambda: _FakeIOCProvider(ioc_type="domain", value="evil.com"))
    specs, _, dropped = direction._call_llm("beacons to notevil.com seen")
    assert specs is None and dropped


def test_call_llm_grounding_token_bounded_defanged_with_punctuation(monkeypatch):
    monkeypatch.setattr(direction, "get_provider", lambda: _FakeIOCProvider())
    specs, _, dropped = direction._call_llm("check (185.220.101[.]4), then report.")
    assert dropped == []
    assert specs


# ── Prompt states the contract validate() enforces (audit F9) ────────
def test_call_llm_system_prompt_states_full_contract(monkeypatch):
    from spectre.llm import LLMResponse
    seen = {}

    class _Cap:
        def complete(self, system, user, **k):
            seen["system"] = system
            return LLMResponse(parsed={"specs": []})

    monkeypatch.setattr(direction, "get_provider", lambda: _Cap())
    direction._call_llm("look at the tor stuff")
    sys_prompt = seen["system"]
    for name in (direction.DIRECTIVE_TYPES | direction.POLARITIES
                 | direction.IOC_TYPES):
        assert name in sys_prompt
    assert "Do not invent IOCs" in sys_prompt
