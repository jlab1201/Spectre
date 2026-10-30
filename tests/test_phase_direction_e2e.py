"""
test_phase_direction_e2e.py — end-to-end Phase 1 (Direction) + Phase 3
integration on a synthetic case. Deterministic (skip_ai), no external tools:
we hand-build normalized_events.json / _handles.json and drive the real
run_phase_1 + _run_phase_3_live + emit_finding + directives code paths.

Covers the plan's verification scenarios:
  - positive directed finding is additive to the baseline
  - exclusion is non-destructive (retained under findings/excluded/)
  - --focus runs directives only
  - empty direction passes through unchanged
  - the audit chain stays VALID
"""

import json
import sys
import tempfile
from pathlib import Path

import yaml  # noqa: E402
from spectre.pipeline import phase_runner  # noqa: E402
from spectre.pipeline.audit import verify_chain  # noqa: E402


def _event(record_id, data, artifact_type="process_creation",
           ts="2026-06-28T03:00:00Z", source="evidence/security.evtx"):
    return {"artifact_type": artifact_type, "timestamp": ts,
            "source_file": source, "record_id": record_id, "host": "WS01",
            "data": data}


def _make_case(tmp, direction="", focus=False, events=None):
    case_dir = Path(tmp) / "001-directiontest"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    events = events if events is not None else [
        # A: child of powershell -> directed lineage fires; no baseline rule.
        _event("A", {"parent_basename": "powershell.exe",
                     "image_basename": "whoami.exe",
                     "command_line": "whoami /all",
                     "command_line_lower": "whoami /all",
                     "event_id": 1}),
        # B: rundll32 from temp -> baseline rule fires (additive control).
        _event("B", {"parent_basename": "explorer.exe",
                     "image_basename": "rundll32.exe",
                     "command_line": "rundll32.exe C:\\Windows\\Temp\\evil.dll,Run",
                     "command_line_lower": "rundll32.exe c:\\windows\\temp\\evil.dll,run",
                     "event_id": 1}),
    ]
    (case_dir / "raw_extract" / "normalized_events.json").write_text(json.dumps(events))

    handle = {"execution_id": "", "line_count": 5, "size_bytes": 100,
              "tool": "evtxexport", "tool_version": "0.27", "exact_command": "evtxexport ...",
              "empty_data_status": "DATA_PRESENT", "evidence_path": "evidence/security.evtx",
              "path": "raw_extract/x.json"}
    (case_dir / "raw_extract" / "_handles.json").write_text(json.dumps([handle]))
    # W3-1: chain the hashes exactly as Phase 2 does, or Phase 3 refuses them.
    from spectre.pipeline.custody import record_derived_artifacts
    record_derived_artifacts(str(case_dir))

    manifest = {"case_id": "001", "case_name": "directiontest",
                "artifact_profile": "auto", "canary_status": "FULL",
                "direction": direction, "focus": focus,
                "evidence": [], "artifacts": ["evtx_4688"], "triage": {}}
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def _findings(case_dir):
    fdir = Path(case_dir) / "findings"
    top = {f.stem: yaml.safe_load(f.read_text()) for f in fdir.glob("F-*-*.yaml")}
    edir = fdir / "excluded"
    excl = {f.stem: yaml.safe_load(f.read_text())
            for f in edir.glob("F-*-*.yaml")} if edir.exists() else {}
    return top, excl


def test_directed_finding_is_additive_to_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest = _make_case(
            tmp, direction="look for executable spawned by powershell.exe")
        phase_runner.run_phase_1(case_dir, manifest, skip_ai=True)
        manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
        phase_runner._run_phase_3_live(case_dir, manifest)

        top, _ = _findings(case_dir)
        origins = {f["title"]: f["rule_origin"] for f in top.values()}
        assert any(o == "user_directed" for o in origins.values()), origins
        assert any(o == "deterministic" for o in origins.values()), origins
        # The directed finding carries the extra analyst caveat.
        directed = [f for f in top.values() if f["rule_origin"] == "user_directed"][0]
        assert any("analyst direction" in c for c in directed["forensic_caveats"])


def test_exclusion_is_non_destructive():
    with tempfile.TemporaryDirectory() as tmp:
        # Baseline rundll32-from-temp event whose data also carries the excluded IP.
        ev = _event("B", {"parent_basename": "explorer.exe",
                          "image_basename": "rundll32.exe",
                          "command_line": "rundll32.exe C:\\Windows\\Temp\\evil.dll 192.158.12.1",
                          "command_line_lower": "rundll32.exe c:\\windows\\temp\\evil.dll 192.158.12.1",
                          "event_id": 1})
        case_dir, manifest = _make_case(
            tmp, direction="exclude events involving 192.158.12.1", events=[ev])
        phase_runner.run_phase_1(case_dir, manifest, skip_ai=True)
        manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
        phase_runner._run_phase_3_live(case_dir, manifest)

        top, excl = _findings(case_dir)
        assert excl, "excluded finding must be retained under findings/excluded/"
        assert not top, f"excluded finding must not remain in primary view: {list(top)}"
        ef = next(iter(excl.values()))
        assert ef["analyst_excluded"] is True
        assert ef["excluded_by"].startswith("dir-")


def test_focus_runs_directives_only():
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest = _make_case(
            tmp, direction="look for executable spawned by powershell.exe", focus=True)
        phase_runner.run_phase_1(case_dir, manifest, skip_ai=True)
        manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
        phase_runner._run_phase_3_live(case_dir, manifest)

        top, _ = _findings(case_dir)
        assert top, "focus mode should still emit the directed finding"
        assert all(f["rule_origin"] == "user_directed" for f in top.values()), \
            {f["title"]: f["rule_origin"] for f in top.values()}


def test_empty_direction_passes_through_with_baseline_only():
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest = _make_case(tmp, direction="")
        phase_runner.run_phase_1(case_dir, manifest, skip_ai=True)
        manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
        assert json.loads((Path(case_dir) / "raw_extract" / "directives.json").read_text()) == []
        phase_runner._run_phase_3_live(case_dir, manifest)
        top, _ = _findings(case_dir)
        assert top, "baseline detection still runs"
        assert all(f["rule_origin"] == "deterministic" for f in top.values())


def test_audit_chain_valid_after_direction_and_detection():
    with tempfile.TemporaryDirectory() as tmp:
        case_dir, manifest = _make_case(
            tmp, direction="look for executable spawned by powershell.exe")
        phase_runner.run_phase_1(case_dir, manifest, skip_ai=True)
        manifest = yaml.safe_load((Path(case_dir) / "manifest.yaml").read_text())
        phase_runner._run_phase_3_live(case_dir, manifest)
        ok, reason = verify_chain(case_dir)
        assert ok, f"audit chain invalid: {reason}"
        # the synthesis was recorded before detection
        rows = [json.loads(l) for l in
                (Path(case_dir) / "audit.jsonl").read_text().splitlines() if l.strip()]
        assert any(r.get("action") == "directives_synthesized" for r in rows), \
            [r.get("action") for r in rows]


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
            import traceback
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
