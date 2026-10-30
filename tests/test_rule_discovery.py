"""test_rule_discovery.py — filesystem rule discovery (Phase 2).

`collect_rules(rules_dir)` lets a contributor add a detection rule by dropping
a file into a module's `rules/` directory — mirroring how `registry.py`
discovers whole modules. It gathers `Rule` objects from each Python file
(either an exported `RULES` list or module-level `Rule` instances), skips
`_`-prefixed helpers/templates, and returns [] for a missing directory so the
caller can fall back to the legacy `from .rules import RULES` path.
"""

import textwrap
from pathlib import Path

from spectre.core.rule_discovery import collect_rules


def _write(p: Path, body: str) -> None:
    p.write_text(textwrap.dedent(body))


def test_missing_dir_returns_empty(tmp_path):
    assert collect_rules(tmp_path / "nope") == []


def test_collects_rules_list_export(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "my_rule.py", """
        from spectre.core.base import Rule
        def pred(e):
            return None
        RULES = [Rule("dropped-1", "process_creation", pred, ["T1059"], "dropped")]
    """)
    rules = collect_rules(rules_dir)
    assert [r.rule_id for r in rules] == ["dropped-1"]
    assert rules[0].artifact_type == "process_creation"


def test_collects_module_level_rule_objects(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "loose.py", """
        from spectre.core.base import Rule
        def pred(e):
            return None
        SOME_RULE = Rule("dropped-loose", "memory_pslist", pred, [], "loose rule")
    """)
    rules = collect_rules(rules_dir)
    assert [r.rule_id for r in rules] == ["dropped-loose"]


def test_skips_underscore_prefixed_files(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "_template.py", """
        from spectre.core.base import Rule
        def pred(e):
            return None
        RULES = [Rule("template-should-not-load", "x", pred, [], "tpl")]
    """)
    _write(rules_dir / "__init__.py", "")
    assert collect_rules(rules_dir) == []


def test_multiple_files_are_all_collected_sorted(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "b_rule.py", """
        from spectre.core.base import Rule
        RULES = [Rule("b", "t", lambda e: None, [], "b")]
    """)
    _write(rules_dir / "a_rule.py", """
        from spectre.core.base import Rule
        RULES = [Rule("a", "t", lambda e: None, [], "a")]
    """)
    ids = [r.rule_id for r in collect_rules(rules_dir)]
    # deterministic order (by filename) so catalogs are stable across runs
    assert ids == ["a", "b"]


def test_module_rules_unions_legacy_with_dropins(tmp_path):
    from spectre.core.base import Rule
    from spectre.core.rule_discovery import module_rules

    legacy = [Rule("legacy-1", "t", lambda e: None, [], "legacy")]
    # no rules/ dir yet -> behavior unchanged (legacy only)
    assert [r.rule_id for r in module_rules(tmp_path, legacy)] == ["legacy-1"]

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "extra.py", """
        from spectre.core.base import Rule
        RULES = [Rule("dropin-1", "t", lambda e: None, [], "dropin")]
    """)
    ids = [r.rule_id for r in module_rules(tmp_path, legacy)]
    assert ids == ["legacy-1", "dropin-1"]


def test_sigma_yaml_is_routed_through_compiler(tmp_path):
    # A dropped-in Sigma .yml is compiled into a native Rule by collect_rules.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "lolbin.yml", """
        title: Regsvr32 LOLBin
        id: 22222222-3333-4444-5555-666666666666
        level: high
        logsource:
            category: process_creation
        detection:
            selection:
                Image|endswith: '\\\\regsvr32.exe'
            condition: selection
    """)
    rules = collect_rules(rules_dir)
    assert len(rules) == 1
    assert rules[0].metadata.rule_format == "sigma"
    assert rules[0].metadata.severity == "high"


def test_out_of_subset_sigma_is_skipped_not_crashed(tmp_path):
    # An unsupported Sigma rule must be skipped (honest failure), never
    # miscompiled, and must not break discovery of the good rules beside it.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "unsupported.yml", """
        title: DNS rule (unsupported logsource)
        logsource:
            category: dns_query
        detection:
            selection:
                QueryName|contains: 'evil'
            condition: selection
    """)
    _write(rules_dir / "good.py", """
        from spectre.core.base import Rule
        RULES = [Rule("good", "process_creation", lambda e: None, [], "good")]
    """)
    ids = [r.rule_id for r in collect_rules(rules_dir)]
    assert ids == ["good"]


def test_bad_rule_file_does_not_crash_discovery(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir / "broken.py", "this is not valid python ::::")
    _write(rules_dir / "good.py", """
        from spectre.core.base import Rule
        RULES = [Rule("good", "t", lambda e: None, [], "good")]
    """)
    # a broken drop-in is skipped with a warning, the good one still loads
    ids = [r.rule_id for r in collect_rules(rules_dir)]
    assert ids == ["good"]
