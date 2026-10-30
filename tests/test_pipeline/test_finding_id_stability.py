"""Finding-ID / dedup-key text-independence pin.

WS5 is going to reorder free-text in finding titles (fixing the
frozenset-iteration-order bug pinned by test_determinism.py). That reorder
must NOT change finding IDs or correlation dedup grouping -- otherwise WS5
would silently split/merge findings across runs, or renumber them, purely
from cosmetic text changes.

Result of this investigation (see report): finding_id is POSITIONAL, not
title-derived, in both emit paths:

  - core/emit_finding.py `emit()`: `_finding_id_str(case_dir, finding_counter)`
    = f"F-{case_dir.name.split('-')[0]}-{finding_counter:03d}" -- reads
    only the case directory name and an integer counter. Title is built
    internally from anchor.rule_id + anchor.event.parent_basename and is
    never read back into the ID.

  - pipeline/emit_finding.py `emit_from_handle()`: same shape,
    `_finding_id(case_dir, finding_number)` -- `title` is an explicit
    caller-supplied parameter that never feeds the ID.

  - get_next_finding_number() scans FILENAMES on disk (`F-*-*.yaml` glob +
    trailing integer), never file contents, so it is unaffected by title
    text.

Separately, correlation grouping (spectre/pipeline/correlation/__init__.py
`corroborate()`) keys claims on `(rule_id, dedup_key or title)`. Every rule
in modules/pcap/rules.py sets dedup_key explicitly (confirmed by
inspection), so today's title-noise (test_determinism.py) does NOT bleed
into which findings get collapsed together -- but this pin exists so a
future rule that forgets to set dedup_key doesn't accidentally start
depending on title-text stability.

No HIGH finding here: finding_id does NOT depend on title text.
"""


import yaml

from spectre.core.base import Anchor as BaseAnchor
from spectre.core.base import NormEvent as BaseNormEvent
from spectre.pipeline.correlation import corroborate
from spectre.pipeline.emit_finding import emit_from_handle, get_next_finding_number


def _fk_yaml(tmp_path):
    p = tmp_path / "fk.yaml"
    p.write_text(yaml.safe_dump({"does_NOT_prove": ["placeholder caveat"]}))
    return str(p)


def _mitre_map(tmp_path):
    p = tmp_path / "mitre.yaml"
    p.write_text(yaml.safe_dump({"rules": {}, "fallback": "UNMAPPED"}))
    return str(p)


def _handle(exec_id: str) -> dict:
    return {
        "execution_id": exec_id,
        "tool": "test-tool",
        "tool_version": "0.1",
        "line_count": 1,
        "path": "/x/y.json",
        "exact_command": "test-tool --fixture",
    }


def test_finding_id_is_positional_not_title_derived(tmp_path):
    """Same case_dir-name prefix + same finding_number -> same finding_id,
    even when the title text is completely different."""
    fk = _fk_yaml(tmp_path)
    mitre = _mitre_map(tmp_path)

    case_dir_a = tmp_path / "099-case-a"
    case_dir_b = tmp_path / "099-case-b"
    (case_dir_a / "findings").mkdir(parents=True)
    (case_dir_b / "findings").mkdir(parents=True)

    finding_a = emit_from_handle(
        handle=_handle("exec-aaa"),
        case_dir=str(case_dir_a),
        finding_number=1,
        fk_yaml_path=fk,
        mitre_map_path=mitre,
        rule_id="pcap-c2-protocol",
        title="C2 protocol fingerprint: User-Agent matches: Cobalt Strike; "
              "User-Agent matches: Metasploit (203.0.113.9)",
    )
    finding_b = emit_from_handle(
        handle=_handle("exec-bbb"),
        case_dir=str(case_dir_b),
        finding_number=1,
        fk_yaml_path=fk,
        mitre_map_path=mitre,
        rule_id="pcap-c2-protocol",
        title="C2 protocol fingerprint: User-Agent matches: Metasploit; "
              "User-Agent matches: Cobalt Strike (203.0.113.9)",
    )

    assert finding_a["title"] != finding_b["title"], (
        "test setup error: titles must differ to prove independence"
    )
    assert finding_a["finding_id"] == finding_b["finding_id"] == "F-099-001", (
        "finding_id depends on title text -- this would make WS5's title "
        "reorder dangerous (HIGH finding)"
    )


def test_get_next_finding_number_ignores_finding_content(tmp_path):
    """get_next_finding_number scans filenames, not YAML content -- so
    title text (or any other field) inside existing findings can never
    perturb the next counter value."""
    case_dir = tmp_path / "042-numbering"
    findings_dir = case_dir / "findings"
    findings_dir.mkdir(parents=True)

    assert get_next_finding_number(str(findings_dir)) == 1

    (findings_dir / "F-042-001.yaml").write_text(
        yaml.safe_dump({"title": "anything, arbitrary free text \x00 unicode 漢字"})
    )
    assert get_next_finding_number(str(findings_dir)) == 2


def _base_event(record_id: str) -> BaseNormEvent:
    return BaseNormEvent(
        artifact_type="pcap_http",
        timestamp="2026-01-01T00:00:00Z",
        source_file="test.pcap",
        record_id=record_id,
        host="10.0.0.5",
        data={},
    )


def test_dedup_key_not_title_drives_correlation_grouping():
    """corroborate() groups on (rule_id, dedup_key or title). When a rule
    sets dedup_key explicitly (as every pcap/rules.py rule does today,
    including pcap-c2-protocol: dedup_key=ip), two anchors with the SAME
    dedup_key but DIFFERENT title text (simulating WS5's reorder) must
    still collapse into ONE corroborated group."""
    anchor_1 = BaseAnchor(
        rule_id="pcap-c2-protocol",
        artifact_type="pcap_http",
        event=_base_event("1"),
        title="C2 protocol fingerprint: User-Agent matches: Cobalt Strike; "
              "User-Agent matches: Metasploit (203.0.113.9)",
        dedup_key="203.0.113.9",
    )
    anchor_2 = BaseAnchor(
        rule_id="pcap-c2-protocol",
        artifact_type="pcap_http",
        event=_base_event("2"),
        title="C2 protocol fingerprint: User-Agent matches: Metasploit; "
              "User-Agent matches: Cobalt Strike (203.0.113.9)",
        dedup_key="203.0.113.9",
    )

    groups = corroborate([anchor_1, anchor_2])

    assert len(groups) == 1, (
        "anchors sharing a rule_id + dedup_key were NOT collapsed despite "
        "differing only in title text -- correlation grouping is title-"
        "sensitive, which WS5's reorder would silently perturb"
    )
    assert len(groups[0].members) == 2
