"""WS9 — per-record timestamp caveats reach the finding, via phase_runner.

Deterministic normalizers (lnk/normalize.py, prefetch/normalize.py,
logfile/normalize.py) already stamp NormEvent.data["ts_caveat"] (and, for
FILETIME overflow, data["ts_parse_error"]) when a record's timestamp field
fails to parse. This pins the actual wiring at the Phase 3 emit call site in
phase_runner.py: the anchor's underlying event data must be read and passed
into emit_from_handle so the caveat isn't silently dropped before it ever
reaches forensic_caveats.

Follows the fake-module pattern established in test_enrich_hook.py so this
exercises the real `_run_phase_3_live` call site rather than re-testing
emit_from_handle's own logic (covered directly in test_emit_finding.py).
"""

import json
from pathlib import Path

import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.pipeline import phase_runner


_TS_OVERFLOW_CAVEAT = (
    "write_time FILETIME value does not fit in a representable timestamp "
    "(overflow/out-of-range) — this field is unparseable, not legitimately "
    "absent; treat the record as having a corrupted or hostile timestamp."
)


def _event(record_id, data, artifact_type="fake_ts_artifact",
           ts="2026-07-09T03:00:00Z", source="evidence/fake.lnk"):
    return {"artifact_type": artifact_type, "timestamp": ts,
            "source_file": source, "record_id": record_id, "host": "WS01",
            "data": data}


def _make_case(tmp, events):
    case_dir = Path(tmp) / "001-tscaveat"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))

    handle = {"execution_id": "", "line_count": 5, "size_bytes": 100,
              "tool": "faketool", "tool_version": "0.1", "exact_command": "faketool ...",
              "empty_data_status": "DATA_PRESENT", "evidence_path": "evidence/fake.lnk",
              "path": "raw_extract/x.json"}
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps([handle]))
    # W3-1: chain the hashes exactly as Phase 2 does, or Phase 3 refuses them.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))

    manifest = {"case_id": "001", "case_name": "tscaveat",
                "artifact_profile": "auto", "canary_status": "FULL",
                "direction": "", "focus": False,
                "evidence": [], "artifacts": ["fake_ts_artifact"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _findings(case_dir):
    fdir = Path(case_dir) / "findings"
    return {f.stem: yaml.safe_load(f.read_text()) for f in fdir.glob("F-*-*.yaml")}


def _rule_fires_on_flag(event):
    if event.data.get("flag"):
        return Anchor(
            rule_id="fake-ts-rule",
            artifact_type="fake_ts_artifact",
            event=event,
            title="Flagged record observed",
            mitre=[],
            confidence=0.9,
            dedup_key=event.record_id,
        )
    return None


def _make_module():
    rule = Rule(
        rule_id="fake-ts-rule",
        artifact_type="fake_ts_artifact",
        predicate=_rule_fires_on_flag,
        mitre=[],
        description="fires on data['flag']",
        metadata=RuleMetadata(uuid="fake-ts-uuid", severity="low"),
    )
    return AnalyzerModule(
        name="fake_ts_mod",
        artifact_type="fake_ts_artifact",
        required_tools=[],
        recognizers=[],
        extract=lambda case_dir, evidence_path: [],
        normalize=lambda handle: [],
        rules=[rule],
    )


def test_ts_caveat_threads_from_event_to_finding(monkeypatch, tmp_path):
    """A NormEvent whose data carries ts_caveat/ts_parse_error (exactly how
    lnk/prefetch normalize.py stamps a FILETIME overflow) must produce a
    finding whose forensic_caveats contains that exact string and whose
    ts_parse_error flag is True — the plumbing must not drop it."""
    events = [_event("A", {"flag": True, "ts_caveat": _TS_OVERFLOW_CAVEAT,
                            "ts_parse_error": True})]
    case_dir, manifest = _make_case(tmp_path, events)

    modules = {"fake_ts_mod": _make_module()}
    monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

    phase_runner._run_phase_3_live(case_dir, manifest)

    findings = _findings(case_dir)
    assert len(findings) == 1, findings
    finding = next(iter(findings.values()))
    assert _TS_OVERFLOW_CAVEAT in finding["forensic_caveats"]
    assert finding["ts_parse_error"] is True


def test_no_ts_caveat_on_event_means_no_spurious_caveat(monkeypatch, tmp_path):
    """Negative: an event with no ts_caveat/ts_parse_error in its data must
    not gain either on the resulting finding — nothing invented."""
    events = [_event("A", {"flag": True})]
    case_dir, manifest = _make_case(tmp_path, events)

    modules = {"fake_ts_mod": _make_module()}
    monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

    phase_runner._run_phase_3_live(case_dir, manifest)

    findings = _findings(case_dir)
    assert len(findings) == 1, findings
    finding = next(iter(findings.values()))
    assert _TS_OVERFLOW_CAVEAT not in finding["forensic_caveats"]
    assert "ts_parse_error" not in finding
