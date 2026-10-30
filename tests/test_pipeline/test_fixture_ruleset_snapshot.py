"""§7.2 — the fixture / --skip-ai detect path must also emit ruleset.yaml.

Agent B's severity resolver and the synthetic validation case depend on every
detect path producing a ruleset.yaml with a per-rule `severity` (str|null).
Before this fix `_run_phase_3_fixture` emitted findings but no ruleset snapshot,
so a fixture case had UNRATED severity everywhere and the resolver was never
exercised. This drives the fixture Phase 2 + 3 path and asserts the snapshot
lands with the schema contract (`rule_id` + `severity` present per rule; a rule
with no explicit severity snapshots as null, not "medium").
"""
import yaml
from pathlib import Path

from spectre.pipeline import phase_runner


def _fixture_case(tmp_path):
    case_dir = tmp_path / "001-fixtureruleset"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "001", "case_name": "fixtureruleset",
        "artifact_profile": "fixture-test", "canary_status": "FULL",
        "artifacts": ["evtx_4688"], "evidence": [], "triage": {},
    }
    (case_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    return str(case_dir), manifest


def test_fixture_phase3_writes_ruleset_yaml(tmp_path):
    case_dir, manifest = _fixture_case(tmp_path)
    phase_runner._run_phase_2_fixture(case_dir, manifest)
    phase_runner._run_phase_3_fixture(case_dir, manifest)

    ruleset_path = Path(case_dir) / "ruleset.yaml"
    assert ruleset_path.exists(), "fixture detect path must write ruleset.yaml"

    snap = yaml.safe_load(ruleset_path.read_text())
    assert snap["generated_phase"] == 3
    assert snap["rules"], "ruleset must list the fixture rule(s)"
    for entry in snap["rules"]:
        # Contract Agent B reads: rule_id + severity (str|null) per rule.
        assert "rule_id" in entry
        assert "severity" in entry
        assert entry["severity"] is None or isinstance(entry["severity"], str)


def test_fixture_rule_without_metadata_is_null_severity(tmp_path):
    case_dir, manifest = _fixture_case(tmp_path)
    phase_runner._run_phase_2_fixture(case_dir, manifest)
    phase_runner._run_phase_3_fixture(case_dir, manifest)

    snap = yaml.safe_load((Path(case_dir) / "ruleset.yaml").read_text())
    by_id = {r["rule_id"]: r for r in snap["rules"]}
    # The legacy fixture rule carries no RuleMetadata -> severity is null,
    # NOT coerced to "medium".
    assert "rundll32-from-temp" in by_id
    assert by_id["rundll32-from-temp"]["severity"] is None
