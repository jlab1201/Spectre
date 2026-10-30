"""emit_from_handle honors missing evidence timestamps as empty, not run-time.

Locks the fix for timeline_uses_run_not_evidence_ts: findings from artifacts
that carry no evidence timestamp (memory netscan/cmdline/malfind/etc.) must
NOT be stamped with the analysis run's wall-clock time via `_utcnow()` —
event_time stays empty ("") so the report layer can render them as
explicitly undated instead of masquerading as dated events.
"""

import yaml

from spectre.pipeline.emit_finding import emit_from_handle


def _yaml(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data))
    return str(p)


def _case(tmp_path):
    (tmp_path / "findings").mkdir()
    return str(tmp_path)


def test_explicit_empty_event_time_stays_empty(tmp_path):
    """A caller-supplied event_time="" (artifact carries no evidence time)
    must be written verbatim — not replaced with the current wall-clock
    time."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "vol-exec-aaa", "tool": "volatility3",
              "line_count": 5, "path": "/x/netscan.json"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-NET-01", title="unexpected listening port",
        event_time="",
    )

    assert finding["event_time"] == ""

    written = yaml.safe_load(
        (tmp_path / "findings" / f"{finding['finding_id']}.yaml").read_text()
    )
    assert written["event_time"] == ""
    # analysis "timestamp" field is a separate, correctly-named concept and
    # is allowed to be wall-clock time.
    assert written["timestamp"] != ""


def test_default_event_time_stays_empty_not_wall_clock(tmp_path):
    """Callers that omit event_time entirely (e.g. memory netscan/cmdline/
    malfind rules — artifact type carries no event time at all) get an
    empty event_time, not a value stamped with the analysis run time."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "vol-exec-bbb", "tool": "volatility3",
              "line_count": 3, "path": "/x/cmdline.json"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-CMD-01", title="suspicious command line",
    )

    assert finding["event_time"] == ""


def test_host_ip_persisted_when_provided(tmp_path):
    """emit_from_handle writes host_ip (the monitored machine) onto the
    finding — the field the correlation/report layers need to tell victim
    IOCs apart from remote/attacker IOCs."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "pcap-exec-ccc", "tool": "tcpdump",
              "line_count": 1, "path": "/x/conn.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="pcap-suspicious-port", title="outbound C2",
        host_ip="10.0.0.5",
    )

    assert finding["host_ip"] == "10.0.0.5"
    written = yaml.safe_load(
        (tmp_path / "findings" / f"{finding['finding_id']}.yaml").read_text()
    )
    assert written["host_ip"] == "10.0.0.5"


def test_mitre_intersection_drops_unmapped_tid_with_caveat(tmp_path):
    """The map regains authority at emit time: a rule-emitted technique not
    present in the map's allowed list for that rule_id is dropped from
    mitre_attack and recorded as a loud forensic_caveat — never silently
    swallowed."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {
        "rules": {"pcap-suspicious-port": {"allowed": ["T1571"], "label": "x"}},
        "fallback": "UNMAPPED",
    })
    handle = {"execution_id": "pcap-exec-eee", "tool": "tcpdump",
              "line_count": 1, "path": "/x/conn.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="pcap-suspicious-port", title="outbound C2",
        mitre=["T1571", "T9999.999"],
    )

    assert finding["mitre_attack"] == "T1571"
    assert any(
        "T9999.999" in c and "dropped" in c
        for c in finding["forensic_caveats"]
    )


def test_mitre_intersection_empty_falls_back_to_allowed_first(tmp_path):
    """When the rule's emitted techniques share nothing with the map's
    allowed list, fall back to allowed[0] (today's pre-gate behavior) —
    the finding must still carry a concrete technique, not UNMAPPED."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {
        "rules": {"pcap-suspicious-port": {"allowed": ["T1571"], "label": "x"}},
        "fallback": "UNMAPPED",
    })
    handle = {"execution_id": "pcap-exec-fff", "tool": "tcpdump",
              "line_count": 1, "path": "/x/conn.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="pcap-suspicious-port", title="weird traffic",
        mitre=["T9999.999"],
    )

    assert finding["mitre_attack"] == "T1571"
    assert any("T9999.999" in c and "dropped" in c for c in finding["forensic_caveats"])


def test_mitre_no_map_entry_quarantines_to_unmapped_with_caveat(tmp_path):
    """A5-F1 fix: a rule_id with NO mitre-map entry at all has no
    reviewer-approved authority behind whatever MITRE IDs it self-declares
    — Sigma-imported rules (rule_id=slug(title)) and Direction directives
    (dir-NNN) can never have a map entry by construction, so passing their
    self-declared techniques through unchecked let a benign notepad.exe
    match ride in labeled T1003.006 (DCSync) end-to-end (A5 PoC). The
    no-map-entry branch must now quarantine to the map's fallback
    (UNMAPPED) instead of asserting the unverified technique, and must
    leave a loud caveat naming what was dropped and why."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "pcap-exec-ggg", "tool": "tcpdump",
              "line_count": 1, "path": "/x/conn.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="some-unmapped-rule", title="unmapped rule hit",
        mitre=["T1071.001", "T1090.004"],
    )

    assert finding["mitre_attack"] == "UNMAPPED"
    assert any(
        "some-unmapped-rule" in c and "no mitre-map" in c.lower()
        and "T1071.001" in c and "T1090.004" in c
        for c in finding["forensic_caveats"]
    ), finding["forensic_caveats"]


def test_mitre_notepad_dcsync_poc_no_longer_passes_through(tmp_path):
    """A5 Finding 1's exact repro: a Sigma-imported rule_id (slug of the
    rule title, which by construction never appears in mitre-map.yaml)
    self-declares T1003.006 (DCSync) on what is, forensically, nothing
    more than a benign notepad.exe launch. Must no longer reach the
    finding as an asserted technique."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "sigma-exec-001", "tool": "evtx",
              "line_count": 1, "path": "/x/4688.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="notepad-exe-launch",  # slug(title) — never in mitre-map.yaml
        title="notepad.exe launched",
        mitre=["T1003.006"],  # self-declared by the imported rule's tags
    )

    assert finding["mitre_attack"] != "T1003.006"
    assert finding["mitre_attack"] == "UNMAPPED"


def test_host_ip_defaults_to_empty_string_when_unknown(tmp_path):
    """When the caller doesn't know the monitored host (e.g. non-pcap
    artifacts), host_ip is always present but empty — never omitted."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "vol-exec-ddd", "tool": "volatility3",
              "line_count": 1, "path": "/x/netscan.json"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-NET-01", title="unexpected listening port",
    )

    assert finding["host_ip"] == ""


def test_emit_from_handle_writes_occurrence_and_span(tmp_path):
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "abc", "tool": "tshark", "tool_version": "4.2",
              "exact_command": "tshark ...", "line_count": 124, "path": "x.txt"}
    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="smb-drsuapi-opnum", title="DsCrackNames",
        event_time="t-first", occurrence_count=124,
        first_seen="t-first", last_seen="t-last",
    )
    assert finding["occurrence_count"] == 124
    assert finding["first_seen"] == "t-first"
    assert finding["last_seen"] == "t-last"


def test_rule_confidence_single_source_is_inferred_not_confirmed(tmp_path):
    """A4-02 fix: a rule-supplied confidence (e.g. registry-run-persistence's
    hardcoded 0.6) must NOT by itself produce a CONFIRMED status. Anchor.
    confidence defaults to 0.5 (never None), so every real per-rule anchor
    took the "rule explicitly set confidence" branch — the SOURCE_TO_STATUS
    corroboration formula was unreachable in practice. CONFIRMED must
    require genuine multi-source corroboration (sources >= 2); a
    single-source, high-confidence rule hit is INFERRED."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "reg-exec-001", "tool": "regripper",
              "line_count": 1, "path": "/x/run.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="registry-run-persistence", title="Run-key persistence",
        confidence=0.85,  # deliberately high rule-domain confidence
        sources=1,
    )

    assert finding["status"] == "INFERRED"
    assert finding["confidence"] == 0.85  # numeric judgment preserved
    assert finding["cross_validated"] is False


def test_rule_confidence_two_sources_is_confirmed(tmp_path):
    """The genuine multi-source counterpart: when the correlation layer
    reports sources >= 2 for the same claim, a rule-supplied confidence
    finding IS allowed to read CONFIRMED."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "reg-exec-002", "tool": "regripper",
              "line_count": 1, "path": "/x/run.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="registry-run-persistence", title="Run-key persistence",
        confidence=0.6,
        sources=2,
        corroboration_labels=["regripper/registry_run", "amcache/registry_run"],
    )

    assert finding["status"] == "CONFIRMED"
    assert finding["confidence"] == 0.6
    assert finding["cross_validated"] is True


def test_rule_confidence_value_decoupled_from_status_gate(tmp_path):
    """Status is now gated purely by genuine source corroboration, not by
    the rule's self-reported confidence number — a LOW rule confidence
    (0.3) with 2 real sources still reads CONFIRMED (the evidentiary bar
    is corroboration count); the numeric confidence itself is preserved
    unchanged as the rule's own domain judgment, decoupled from status."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "reg-exec-003", "tool": "regripper",
              "line_count": 1, "path": "/x/run.txt"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="uac-autoelevate-binary", title="possible UAC bypass",
        confidence=0.3,
        sources=2,
    )

    assert finding["status"] == "CONFIRMED"
    assert finding["confidence"] == 0.3


def test_emit_from_handle_span_defaults_to_event_time(tmp_path):
    fk = _yaml(tmp_path, "fk2.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre2.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "abc", "tool": "t", "line_count": 1, "path": "x"}
    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=2,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="r", title="t", event_time="t0",
    )
    assert finding["occurrence_count"] == 1
    assert finding["first_seen"] == "t0"
    assert finding["last_seen"] == "t0"


# ── WS9: per-record timestamp caveats reach forensic_caveats/ts_parse_error ──

_TS_OVERFLOW_CAVEAT = (
    "write_time FILETIME value does not fit in a representable timestamp "
    "(overflow/out-of-range) — this field is unparseable, not legitimately "
    "absent; treat the record as having a corrupted or hostile timestamp."
)


def test_ts_caveat_appended_to_forensic_caveats(tmp_path):
    """A finding whose source record carried a ts_caveat (WS9 — set by
    lnk/prefetch/logfile normalize.py) gets that EXACT string appended to
    forensic_caveats — relayed verbatim, never rephrased or invented."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": ["baseline caveat"]})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "lnk-exec-001", "tool": "lnk-parser",
              "line_count": 1, "path": "/x/target.lnk"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="lnk-suspicious-target", title="suspicious lnk target",
        ts_caveat=_TS_OVERFLOW_CAVEAT,
    )

    assert _TS_OVERFLOW_CAVEAT in finding["forensic_caveats"]
    # FK caveats are preserved alongside it, not replaced.
    assert "baseline caveat" in finding["forensic_caveats"]


def test_ts_caveat_deduped_not_double_appended(tmp_path):
    """If the exact ts_caveat string is somehow already present (e.g. an FK
    YAML happens to already list it), it must not be duplicated."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": [_TS_OVERFLOW_CAVEAT]})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "lnk-exec-002", "tool": "lnk-parser",
              "line_count": 1, "path": "/x/target.lnk"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="lnk-suspicious-target", title="suspicious lnk target",
        ts_caveat=_TS_OVERFLOW_CAVEAT,
    )

    assert finding["forensic_caveats"].count(_TS_OVERFLOW_CAVEAT) == 1


def test_ts_parse_error_stamped_on_finding(tmp_path):
    """ts_parse_error=True is written onto the finding (and persisted to
    the YAML on disk) so the report layer can build a blind-spots line."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "pf-exec-001", "tool": "prefetch-parser",
              "line_count": 1, "path": "/x/BAD.EXE-1.pf"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="prefetch-rare-run", title="rare prefetch execution",
        ts_caveat=_TS_OVERFLOW_CAVEAT, ts_parse_error=True,
    )

    assert finding["ts_parse_error"] is True
    written = yaml.safe_load(
        (tmp_path / "findings" / f"{finding['finding_id']}.yaml").read_text()
    )
    assert written["ts_parse_error"] is True


def test_no_ts_caveat_means_no_spurious_caveat_or_flag(tmp_path):
    """Negative: a finding with no ts_caveat/ts_parse_error (the default,
    every non-lnk/prefetch/logfile artifact) gets no timestamp caveat text
    and no ts_parse_error key at all — never fabricated."""
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": ["ordinary caveat"]})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "evtx-exec-001", "tool": "evtx-parser",
              "line_count": 1, "path": "/x/security.evtx"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="rundll32-from-temp", title="rundll32 from temp",
    )

    assert finding["forensic_caveats"] == ["ordinary caveat"]
    assert "ts_parse_error" not in finding
    written = yaml.safe_load(
        (tmp_path / "findings" / f"{finding['finding_id']}.yaml").read_text()
    )
    assert "ts_parse_error" not in written
