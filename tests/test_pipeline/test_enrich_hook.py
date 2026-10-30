"""
test_enrich_hook.py — Phase 3 optional per-module `enrich` hook.

The deterministic core lets a module compute cross-event facts (e.g. "this
process has a hidden-process peer", "this flow answers a beaconing DNS
query") before rules run, so rules stay pure single-event predicates. The
hook is optional (`AnalyzerModule.enrich: Optional[Callable] = None`,
default None) so all pre-existing modules stay valid without changes.

Contract exercised here:
  - a module with `enrich` set has it called once with the FULL event list
    before detection; it mutates event.data in place.
  - rules see the enriched data (a rule can require the enriched field).
  - a module with `enrich=None` (the default / all pre-Task-2 modules) is
    skipped without error.
  - enrich must never add or remove events — the pipeline asserts the
    length is unchanged and raises (loud, not a warning) if it isn't.
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from spectre.core.base import AnalyzerModule, Anchor, Rule, RuleMetadata
from spectre.pipeline import phase_runner


def _event(record_id, data, artifact_type="fake_artifact",
           ts="2026-07-09T03:00:00Z", source="evidence/fake.bin"):
    return {"artifact_type": artifact_type, "timestamp": ts,
            "source_file": source, "record_id": record_id, "host": "WS01",
            "data": data}


def _make_case(tmp, events):
    case_dir = Path(tmp) / "001-enrichtest"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))

    handle = {"execution_id": "", "line_count": 5, "size_bytes": 100,
              "tool": "faketool", "tool_version": "0.1", "exact_command": "faketool ...",
              "empty_data_status": "DATA_PRESENT", "evidence_path": "evidence/fake.bin",
              "path": "raw_extract/x.json"}
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps([handle]))
    # W3-1: chain the hashes exactly as Phase 2 does, or Phase 3 refuses them.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))

    manifest = {"case_id": "001", "case_name": "enrichtest",
                "artifact_profile": "auto", "canary_status": "FULL",
                "direction": "", "focus": False,
                "evidence": [], "artifacts": ["fake_artifact"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _findings(case_dir):
    fdir = Path(case_dir) / "findings"
    return {f.stem: yaml.safe_load(f.read_text()) for f in fdir.glob("F-*-*.yaml")}


def _stamps_enriched(events):
    """A well-behaved enrich: mutates data in place, never touches length."""
    for e in events:
        if e.artifact_type == "fake_artifact":
            e.data["enriched"] = True


def _rule_requires_enriched(event):
    if event.data.get("enriched"):
        return Anchor(
            rule_id="fake-enriched-rule",
            artifact_type="fake_artifact",
            event=event,
            title="Enriched fact observed",
            mitre=[],
            confidence=0.9,
            # Distinct per event so the two hits don't collapse into one
            # corroborated finding — each event is its own claim here.
            dedup_key=event.record_id,
        )
    return None


def _make_module(enrich=None, rule_predicate=_rule_requires_enriched, name="fakemod"):
    rule = Rule(
        rule_id="fake-enriched-rule",
        artifact_type="fake_artifact",
        predicate=rule_predicate,
        mitre=[],
        description="fires only if enrich stamped the event",
        metadata=RuleMetadata(uuid="fake-uuid", severity="low"),
    )
    return AnalyzerModule(
        name=name,
        artifact_type="fake_artifact",
        required_tools=[],
        recognizers=[],
        extract=lambda case_dir, evidence_path: [],
        normalize=lambda handle: [],
        rules=[rule],
        enrich=enrich,
    )


def test_enrich_hook_defaults_to_none_and_is_skipped():
    """All pre-Task-2 modules omit `enrich`; the dataclass must default it
    to None so they stay valid, and Phase 3 must not error calling them."""
    mod = _make_module(enrich=None)
    assert mod.enrich is None


def test_rules_see_data_stamped_by_enrich(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        events = [_event("A", {}), _event("B", {})]
        case_dir, manifest = _make_case(tmp, events)

        modules = {"fakemod": _make_module(enrich=_stamps_enriched)}
        monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

        phase_runner._run_phase_3_live(case_dir, manifest)

        findings = _findings(case_dir)
        assert len(findings) == 2, findings
        assert all(f["title"] == "Enriched fact observed" for f in findings.values())


def test_module_with_enrich_none_is_skipped_without_error(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        events = [_event("A", {}), _event("B", {})]
        case_dir, manifest = _make_case(tmp, events)

        # enrich=None -> rule never fires (no stamped field), but no crash.
        modules = {"fakemod": _make_module(enrich=None)}
        monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

        result = phase_runner._run_phase_3_live(case_dir, manifest)

        findings = _findings(case_dir)
        assert not findings, findings
        assert result is not None


def test_enrich_that_adds_an_event_raises(monkeypatch):
    def _adds_event(events):
        events.append(events[0])

    with tempfile.TemporaryDirectory() as tmp:
        events = [_event("A", {}), _event("B", {})]
        case_dir, manifest = _make_case(tmp, events)

        modules = {"fakemod": _make_module(enrich=_adds_event)}
        monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

        with pytest.raises(AssertionError, match="enrich must not add/remove events"):
            phase_runner._run_phase_3_live(case_dir, manifest)


def test_enrich_that_removes_an_event_raises(monkeypatch):
    def _removes_event(events):
        events.pop()

    with tempfile.TemporaryDirectory() as tmp:
        events = [_event("A", {}), _event("B", {})]
        case_dir, manifest = _make_case(tmp, events)

        modules = {"fakemod": _make_module(enrich=_removes_event)}
        monkeypatch.setattr(phase_runner, "_modules", lambda: modules)

        with pytest.raises(AssertionError, match="enrich must not add/remove events"):
            phase_runner._run_phase_3_live(case_dir, manifest)
