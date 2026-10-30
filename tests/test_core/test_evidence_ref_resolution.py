"""Pure predicates behind the Phase 4 evidence_ref gate: a finding's every
evidence_ref execution_id must be the entry_sha256 of a deterministic-core
tool_exec row in the case's audit.jsonl."""
from spectre.core.validators import (
    resolvable_execution_ids, unresolved_evidence_refs,
)

ROWS = [
    {"actor": "deterministic-core", "action": "tool_exec", "entry_sha256": "a" * 64},
    {"actor": "deterministic-core", "action": "finding_create", "entry_sha256": "b" * 64},
    {"actor": "host-agent", "action": "tool_exec", "entry_sha256": "c" * 64},
    {"actor": "deterministic-core", "action": "derived_artifact", "entry_sha256": "d" * 64},
    {"actor": "deterministic-core", "action": "tool_exec"},
]


def test_only_deterministic_tool_exec_rows_resolve():
    assert resolvable_execution_ids(ROWS) == {"a" * 64}


def test_all_refs_resolved():
    f = {"evidence_refs": [{"execution_id": "a" * 64, "source": "tool_exec"}]}
    assert unresolved_evidence_refs(f, {"a" * 64}) == []


def test_unknown_and_non_tool_exec_ids_are_unresolved():
    f = {"evidence_refs": [{"execution_id": "a" * 64}, {"execution_id": "b" * 64},
                           {"execution_id": "mpfs-2026"}]}
    assert unresolved_evidence_refs(f, resolvable_execution_ids(ROWS)) == [
        "b" * 64, "mpfs-2026"]


def test_missing_or_empty_execution_id_is_unresolved():
    f = {"evidence_refs": [{"source": "tool_exec"}, {"execution_id": ""},
                           {"execution_id": None}]}
    assert unresolved_evidence_refs(f, {"a" * 64}) == ["<missing>"] * 3


def test_unparseable_refs_are_unresolved():
    assert unresolved_evidence_refs({"evidence_refs": ["a" * 64]}, {"a" * 64}) == ["<unparseable>"]
    assert unresolved_evidence_refs({"evidence_refs": {"execution_id": "a" * 64}},
                                    {"a" * 64}) == ["<unparseable>"]
    assert unresolved_evidence_refs({"evidence_refs": [{"execution_id": 7}]},
                                    {"a" * 64}) == ["<missing>"]


def test_empty_resolvable_set_fails_closed():
    f = {"evidence_refs": [{"execution_id": "a" * 64}]}
    assert unresolved_evidence_refs(f, set()) == ["a" * 64]
