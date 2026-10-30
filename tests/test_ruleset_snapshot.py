"""
test_ruleset_snapshot.py — the pure ruleset-snapshot builder (Phase 3).

`build_ruleset_snapshot` records the deterministic rule pack in force for a
case: every rule that was *evaluated* (fired or silent), its identity card,
hit count, and a content hash of each module's rules.py. It is pure (no I/O)
so the dict is asserted directly from synthetic inputs.
"""

from spectre.pipeline.phase_runner import build_ruleset_snapshot


def _catalog():
    return [
        {
            "rule_id": "mem_injection_temp_dll",
            "module": "memory",
            "artifact_type": "memory_pslist",
            "description": "DLL loaded from a temp/writable path",
            "candidate_mitre": ["T1055.001"],
        },
        {
            "rule_id": "evtx_4688_lolbin",
            "module": "evtx",
            "artifact_type": "evtx_4688",
            "description": "LOLBin spawned via 4688",
            "candidate_mitre": ["T1059"],
        },
    ]


def test_fired_flips_on_hit_count():
    snap = build_ruleset_snapshot(
        rule_catalog=_catalog(),
        rule_hits={"mem_injection_temp_dll": 2},
        source_hashes={"memory": "ab12", "evtx": "cd34"},
        focus=False,
    )
    by_id = {r["rule_id"]: r for r in snap["rules"]}
    assert by_id["mem_injection_temp_dll"]["fired"] is True
    assert by_id["mem_injection_temp_dll"]["hits"] == 2
    assert by_id["evtx_4688_lolbin"]["fired"] is False
    assert by_id["evtx_4688_lolbin"]["hits"] == 0


def test_totals_and_metadata():
    snap = build_ruleset_snapshot(
        rule_catalog=_catalog(),
        rule_hits={"mem_injection_temp_dll": 2},
        source_hashes={"memory": "ab12", "evtx": "cd34"},
        focus=False,
    )
    assert snap["generated_phase"] == 3
    assert snap["focus_mode"] is False
    assert snap["rules_evaluated"] == 2
    assert snap["rules_fired"] == 1
    assert snap["source_hashes"] == {"memory": "ab12", "evtx": "cd34"}


def test_each_rule_carries_identity_card():
    snap = build_ruleset_snapshot(
        rule_catalog=_catalog(),
        rule_hits={},
        source_hashes={},
        focus=False,
    )
    r = next(r for r in snap["rules"] if r["rule_id"] == "mem_injection_temp_dll")
    assert r["module"] == "memory"
    assert r["artifact_type"] == "memory_pslist"
    assert r["description"] == "DLL loaded from a temp/writable path"
    assert r["candidate_mitre"] == ["T1055.001"]
    assert r["rule_origin"] == "deterministic"


def test_rule_origin_is_honored_per_card():
    # Analyst-directed directives ride in the same catalog tagged
    # user_directed; deterministic rules default to "deterministic".
    catalog = _catalog() + [{
        "rule_id": "dir-001",
        "module": "directive",
        "artifact_type": "*",
        "description": "analyst include directive (ioc_match)",
        "candidate_mitre": [],
        "rule_origin": "user_directed",
    }]
    snap = build_ruleset_snapshot(
        rule_catalog=catalog,
        rule_hits={"dir-001": 5},
        source_hashes={},
        focus=False,
    )
    by_id = {r["rule_id"]: r for r in snap["rules"]}
    assert by_id["dir-001"]["rule_origin"] == "user_directed"
    assert by_id["dir-001"]["fired"] is True
    assert by_id["dir-001"]["hits"] == 5
    assert by_id["mem_injection_temp_dll"]["rule_origin"] == "deterministic"


def test_card_carries_defensibility_metadata():
    # A deterministic card with a full RuleMetadata-derived dict surfaces
    # severity/tags/refs/false_positives/uuid/rule_format in the snapshot.
    catalog = [{
        "rule_id": "evtx_4688_lolbin",
        "module": "evtx",
        "artifact_type": "evtx_4688",
        "description": "LOLBin spawned via 4688",
        "candidate_mitre": ["T1059"],
        "uuid": "abc-123",
        "severity": "high",
        "rule_format": "sigma",
        "tags": ["attack.execution"],
        "references": ["https://example/ref"],
        "false_positives": ["admin scripts"],
    }]
    snap = build_ruleset_snapshot(
        rule_catalog=catalog, rule_hits={}, source_hashes={}, focus=False)
    r = snap["rules"][0]
    assert r["uuid"] == "abc-123"
    assert r["severity"] == "high"
    assert r["rule_format"] == "sigma"
    assert r["tags"] == ["attack.execution"]
    assert r["references"] == ["https://example/ref"]
    assert r["false_positives"] == ["admin scripts"]


def test_metadata_fields_default_safely_when_absent():
    # Legacy/directive cards that omit the defensibility fields still produce
    # a valid, fully-keyed entry.
    snap = build_ruleset_snapshot(
        rule_catalog=_catalog(), rule_hits={}, source_hashes={}, focus=False)
    r = snap["rules"][0]
    assert r["uuid"] == ""
    assert r["severity"] is None  # unset stays null, never coerced to medium
    assert r["rule_format"] == "python"
    assert r["tags"] == []
    assert r["references"] == []
    assert r["false_positives"] == []


def test_focus_mode_is_a_recorded_flag_not_an_emptier():
    # Under --focus the caller skips deterministic packs, so it passes only
    # directive cards. The builder must record focus_mode and list whatever it
    # is given — it must NOT drop directives just because focus is on.
    directive_only = [{
        "rule_id": "dir-001",
        "module": "directive",
        "artifact_type": "*",
        "description": "analyst include directive",
        "candidate_mitre": [],
        "rule_origin": "user_directed",
    }]
    snap = build_ruleset_snapshot(
        rule_catalog=directive_only,
        rule_hits={"dir-001": 3},
        source_hashes={},
        focus=True,
    )
    assert snap["focus_mode"] is True
    assert snap["rules_evaluated"] == 1
    assert snap["rules_fired"] == 1
    assert snap["rules"][0]["rule_id"] == "dir-001"


def test_empty_catalog_is_zeroed():
    # focus with no directives at all -> honest "nothing was checked".
    snap = build_ruleset_snapshot(
        rule_catalog=[], rule_hits={}, source_hashes={}, focus=True)
    assert snap["focus_mode"] is True
    assert snap["rules_evaluated"] == 0
    assert snap["rules_fired"] == 0
    assert snap["rules"] == []


def test_severity_breakdown_buckets_unset_as_unrated():
    """TB-port T4: a rule with severity None is counted as "unrated", never
    folded into "medium" (and never raises on a None dict key sort)."""
    from spectre.pipeline.phase_runner import _severity_breakdown
    rules = [{"severity": "high"}, {"severity": None}, {"severity": None},
             {"severity": "medium"}, {}]
    assert _severity_breakdown(rules) == {"high": 1, "unrated": 3, "medium": 1}
