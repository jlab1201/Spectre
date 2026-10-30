"""WS8 — cross-case containment (A7 Finding 2, HIGH, "the key risk item").

`.remediation/findings/A7.md` Finding 2: `cross_case_index.py`'s `index.md`
is a single Markdown store SHARED across every case in a cases-dir. Before
this workstream it was (a) written at Phase 4 (correlation), three phases
before adversarial review, synthesis, or examiner approval, (b) status/
approval-blind — CONFIRMED/INFERRED/DROPPED findings were all indexed
alike, (c) had no retraction path when a finding was later REJECTED or a
case abandoned, and (d) fed loose `mitre_attack` cross-case "matches" —
near-guaranteed to be unrelated cases in a large store (SKILL.md's own
audit found T1071.001 alone in ~1,681 rows across ~270 real cases) —
straight into narrative-writing subagent context with no advisory label.

This file covers: the write moved to Phase 7 and gated on status/approval
(`cross_case_index._finding_is_indexable()`), retraction (`retract_case`),
purge/rebuild (`rebuild_index`), the specificity filter and mandatory
advisory labelling at `subagent_templates._format_cross_case_matches()`,
and `cross_case_index.py`'s own cases-dir parameterization (every public
function takes `cases_dir` as an explicit argument and acts strictly on
it, never on the module's import-time-bound default).

cases-dir isolation is now fixed end to end: `runner.verify_and_close()`
(the actual Phase 7 call site) passes `Path(case_dir).parent` — the case's
real parent cases-dir — to `update_index()`, not the module-level
`runner.CASES_DIR` global, so a real run under a custom `--cases-dir` writes
its index there and never silently targets the default global store. Tests
that exercise `runner.verify_and_close()` below build `case_dir` under a
tmp cases-dir, so they cover the real fix; the historical
`monkeypatch.setattr(runner, "CASES_DIR", ...)` some helpers still set (per
tests/test_pipeline/test_phase7_verify_full_wiring.py convention) is now
redundant but harmless — that global is no longer read by verify_and_close.

HARD SAFETY CONSTRAINT: every test below passes an explicit tmp_path-
derived `cases_dir` to every cross_case_index function, and every test
that calls `runner.verify_and_close()` monkeypatches `runner.CASES_DIR`
to a tmp_path first — never the real `~/spectre-cases` (it holds ~270
real cases). `_guard_real_cases_store` below is a read-only (stat-only)
empirical check that nothing in this file ever wrote to it.
"""
from pathlib import Path

import pytest
import yaml

from spectre.pipeline import cross_case_index as cci
from spectre.pipeline import phase_runner
from spectre.pipeline import runner
from spectre.pipeline.audit import append as audit_append
from spectre.pipeline.subagent_templates import (
    CROSS_CASE_ADVISORY_LABEL,
    _format_cross_case_matches,
    build_deep_dive_context,
)


# ── Safety guard ─────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _guard_real_cases_store():
    """Every test in this file passes an explicit tmp_path cases_dir to
    every cross_case_index call (and monkeypatches runner.CASES_DIR
    before calling verify_and_close()), so this should be a pure no-op —
    it just empirically confirms (read-only stat, never a write) that the
    REAL ~/spectre-cases/index.md is untouched by anything in this
    module."""
    real_index = Path.home() / "spectre-cases" / "index.md"
    before = real_index.stat().st_mtime if real_index.exists() else None
    yield
    after = real_index.stat().st_mtime if real_index.exists() else None
    assert before == after, (
        "a test in this file touched the REAL ~/spectre-cases/index.md — "
        "this must never happen"
    )


# ── Helpers ──────────────────────────────────────────────────────────

def _init_case(cases_dir: Path, case_name: str) -> Path:
    case_dir = cases_dir / case_name
    for sub in ("findings", "reports", "evidence"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir


def _write_finding(case_dir: Path, finding_id: str, *, status: str,
                    iocs: dict | None = None, mitre: str = "T1071.001",
                    approval: str | None = None) -> Path:
    data = {
        "finding_id": finding_id,
        "status": status,
        "confidence": 0.75 if status == "CONFIRMED" else 0.5,
        "title": f"{finding_id} test finding",
        "mitre_attack": mitre,
        "evidence_refs": [{"execution_id": "abc123"}],
        "corroboration": {"sources": 2 if status == "CONFIRMED" else 1},
        "iocs": iocs or {},
        "timestamp": "2026-08-01T00:00:00",
    }
    if approval is not None:
        data["approval"] = approval
    fp = case_dir / "findings" / f"{finding_id}.yaml"
    fp.write_text(yaml.safe_dump(data))
    # W1-2: verify_and_close() now gates the cross-case index write on
    # verify_full()'s "ok" (audit_disk + finding_integrity among the checks
    # that flip it). A finding_create row (output_sha256 left empty, same
    # "legacy, skipped" stance the checks themselves document) is enough to
    # satisfy both without pinning these tests to a real content hash.
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "finding_create",
        "tool": "emit_finding.py", "case_id": case_dir.name,
        "output_path": str(fp), "output_sha256": "", "result": "success",
        "finding_id": finding_id, "phase": 3, "phase_step": "S1-emit",
    })
    return fp


def _verify_and_close_isolated(case_dir: Path, cases_dir: Path, manifest: dict,
                                monkeypatch) -> bool:
    """runner.verify_and_close() derives its cases-dir from
    Path(case_dir).parent (WS8 isolation fix), so building case_dir under the
    tmp cases_dir already isolates the index write. The runner.CASES_DIR
    monkeypatch is kept as belt-and-suspenders (and to match the convention
    in tests/test_pipeline/test_phase7_verify_full_wiring.py) but is no longer
    load-bearing — that global is not read by verify_and_close anymore."""
    monkeypatch.setattr(runner, "CASES_DIR", cases_dir)
    return runner.verify_and_close(str(case_dir), manifest)


# ── 1. Index write moved from Phase 4 to Phase 7, status/approval-gated ──

def test_phase4_does_not_write_cross_case_index(tmp_path):
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase4-test")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["a" * 64]})
    # run_phase_4 needs a valid audit.jsonl for verify_chain() to pass.
    audit_append(str(case_dir), {
        "actor": "deterministic-core", "action": "note", "tool": "x",
        "case_id": case_dir.name, "output_path": "", "output_sha256": "",
        "result": "success", "phase": 0, "phase_step": "row",
    })

    manifest = {"case_id": "001"}
    result = phase_runner.run_phase_4(str(case_dir), manifest)
    assert result["success"] is True, result

    assert not (cases_dir / "index.md").exists(), (
        "Phase 4 must never write the cross-case index — that write moved "
        "to Phase 7 (post-approval); A7 Finding 2"
    )
    assert manifest["gate_4"]["cross_case_updated"] is False


def test_phase7_indexes_confirmed_finding(tmp_path, monkeypatch):
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase7-confirmed")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["b" * 64]})
    manifest = {"case_id": "001"}

    _verify_and_close_isolated(case_dir, cases_dir, manifest, monkeypatch)

    index_path = cases_dir / "index.md"
    assert index_path.exists(), "Phase 7 must write the cross-case index"
    text = index_path.read_text()
    assert "b" * 64 in text
    assert manifest["gate_7"]["cross_case_updated"] is True


def test_phase7_excludes_inferred_finding(tmp_path, monkeypatch):
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase7-inferred")
    _write_finding(case_dir, "F-001-001", status="INFERRED",
                    iocs={"sha256": ["c" * 64]})
    manifest = {"case_id": "001"}

    _verify_and_close_isolated(case_dir, cases_dir, manifest, monkeypatch)

    text = (cases_dir / "index.md").read_text()
    assert "c" * 64 not in text, "INFERRED findings must never be indexed"


def test_phase7_excludes_dropped_finding(tmp_path, monkeypatch):
    """Bypasses Phase 4's purge_dropped_findings() deliberately -- this
    proves the index-side exclusion in _finding_is_indexable() holds on
    its own, independent of whatever purge already ran upstream."""
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase7-dropped")
    _write_finding(case_dir, "F-001-001", status="DROPPED",
                    iocs={"sha256": ["d" * 64]})
    manifest = {"case_id": "001"}

    _verify_and_close_isolated(case_dir, cases_dir, manifest, monkeypatch)

    text = (cases_dir / "index.md").read_text()
    assert "d" * 64 not in text, "DROPPED findings must never be indexed"


def test_phase7_excludes_confirmed_but_explicitly_rejected_finding(tmp_path, monkeypatch):
    """CONFIRMED status alone is not enough once a finding YAML already
    carries the SKILL.md-documented `approval:` field with a non-APPROVED
    value — _finding_is_indexable() respects that existing signal."""
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase7-rejected")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["e" * 64]}, approval="REJECTED")
    manifest = {"case_id": "001"}

    _verify_and_close_isolated(case_dir, cases_dir, manifest, monkeypatch)

    text = (cases_dir / "index.md").read_text()
    assert "e" * 64 not in text, (
        "a CONFIRMED finding explicitly marked approval: REJECTED must "
        "not be indexed"
    )


def test_phase7_indexes_confirmed_explicitly_approved_finding(tmp_path, monkeypatch):
    cases_dir = tmp_path / "cases"
    case_dir = _init_case(cases_dir, "001-phase7-approved")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["1" * 64]}, approval="APPROVED")
    manifest = {"case_id": "001"}

    _verify_and_close_isolated(case_dir, cases_dir, manifest, monkeypatch)

    text = (cases_dir / "index.md").read_text()
    assert "1" * 64 in text


# ── 2. Retraction ────────────────────────────────────────────────────

def test_retract_case_removes_only_target_case(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    case_a = _init_case(cases_dir, "001-case-a")
    _write_finding(case_a, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["a" * 64]})
    case_b = _init_case(cases_dir, "002-case-b")
    _write_finding(case_b, "F-002-001", status="CONFIRMED",
                    iocs={"sha256": ["b" * 64]})

    cci.update_index(str(cases_dir), "001-case-a")
    cci.update_index(str(cases_dir), "002-case-b")

    text_before = (cases_dir / "index.md").read_text()
    assert "a" * 64 in text_before and "b" * 64 in text_before

    result = cci.retract_case(str(cases_dir), "001-case-a")
    assert result["case"] == "001-case-a"
    assert result["removed"] >= 1

    text_after = (cases_dir / "index.md").read_text()
    assert "a" * 64 not in text_after, "retracted case's rows must be gone"
    assert "b" * 64 in text_after, "other case's rows must be untouched"


def test_retract_case_noop_when_index_missing(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    result = cci.retract_case(str(cases_dir), "nonexistent-case")
    assert result == {"removed": 0, "case": "nonexistent-case"}


def test_retract_case_noop_when_case_never_indexed(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    case_a = _init_case(cases_dir, "001-case-a")
    _write_finding(case_a, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["a" * 64]})
    cci.update_index(str(cases_dir), "001-case-a")

    result = cci.retract_case(str(cases_dir), "099-never-indexed")
    assert result["removed"] == 0
    assert "a" * 64 in (cases_dir / "index.md").read_text()


# ── 3. Purge / rebuild ───────────────────────────────────────────────

def test_rebuild_index_purges_stale_and_disqualified_entries(tmp_path):
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()

    # Simulate a polluted index.md (as pre-WS8 code, or a hand edit, could
    # have produced): a stale entry for a case that no longer exists on
    # disk at all.
    stale_index = cases_dir / "index.md"
    stale_index.write_text(
        "# Cross-Case Artifact Index\n\n"
        "## SHA-256 Hashes\n\n"
        "| Hash | Case | Finding | Date |\n"
        "|------|------|---------|------|\n"
        "| " + ("f" * 64) + " | 999-phantom-case | F-999-001 | 2026-01-01 |\n\n"
    )

    # A real, on-disk CONFIRMED finding — must survive the rebuild.
    case_dir = _init_case(cases_dir, "001-real-case")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["a" * 64]})

    # A real, on-disk INFERRED finding — must NOT appear post-rebuild.
    case_dir2 = _init_case(cases_dir, "002-inferred-case")
    _write_finding(case_dir2, "F-002-001", status="INFERRED",
                    iocs={"sha256": ["b" * 64]})

    index_path = cci.rebuild_index(str(cases_dir))
    text = Path(index_path).read_text()

    assert "a" * 64 in text, "real CONFIRMED finding must survive rebuild"
    assert "999-phantom-case" not in text, "stale pre-existing entry must be purged"
    assert "f" * 64 not in text
    assert "b" * 64 not in text, "INFERRED finding must not be (re)indexed"


def test_rebuild_index_scoped_to_given_cases_dir_only(tmp_path):
    cases_dir = tmp_path / "synthetic-cases"
    cases_dir.mkdir()
    case_dir = _init_case(cases_dir, "001-synthetic")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["9" * 64]})

    index_path = cci.rebuild_index(str(cases_dir))
    assert Path(index_path) == cases_dir / "index.md"
    assert "9" * 64 in Path(index_path).read_text()


# ── 4 & 5. Specificity filter + mandatory advisory labelling ─────────

def test_format_cross_case_matches_drops_mitre_technique_matches():
    matches = [
        {"ioc_type": "mitre_attack", "value": "T1071.001", "case": "099-unrelated",
         "finding_id": "F-099-001", "date": "2026-01-01"},
    ]
    rendered = _format_cross_case_matches(matches)
    assert "T1071.001" not in rendered
    assert rendered == "(No prior cross-case matches)"


def test_format_cross_case_matches_renders_only_high_specificity_types():
    matches = [
        {"ioc_type": "sha256", "value": "a" * 64, "case": "002-x",
         "finding_id": "F-002-001", "date": "2026-01-01"},
        {"ioc_type": "domain", "value": "evil.example.com", "case": "003-y",
         "finding_id": "F-003-001", "date": "2026-01-02"},
        {"ioc_type": "ip", "value": "10.9.9.9", "case": "004-z",
         "finding_id": "F-004-001", "date": "2026-01-03"},
        {"ioc_type": "mitre_attack", "value": "T1071.001", "case": "099-unrelated",
         "finding_id": "F-099-001", "date": "2026-01-01"},
        {"ioc_type": "filepath", "value": "C:\\Windows\\System32\\svchost.exe",
         "case": "088-benign", "finding_id": "F-088-001", "date": "2026-01-01"},
        {"ioc_type": "registry_key", "value": "HKLM\\...\\Run",
         "case": "077-benign", "finding_id": "F-077-001", "date": "2026-01-01"},
    ]
    rendered = _format_cross_case_matches(matches)

    assert "a" * 64 in rendered
    assert "evil.example.com" in rendered
    assert "10.9.9.9" in rendered

    assert "T1071.001" not in rendered
    assert "099-unrelated" not in rendered
    assert "svchost.exe" not in rendered
    assert "Run" not in rendered or "HKLM" not in rendered  # registry match dropped


def test_format_cross_case_matches_drops_malformed_entries():
    """A match missing/lacking a recognized ioc_type, or a bare string,
    must be dropped, not rendered raw -- we can't verify its specificity."""
    rendered = _format_cross_case_matches(["a raw string match", {"case": "x"}])
    assert rendered == "(No prior cross-case matches)"


def test_format_cross_case_matches_always_carries_advisory_label():
    matches = [
        {"ioc_type": "sha256", "value": "c" * 64, "case": "005-a",
         "finding_id": "F-005-001", "date": "2026-01-01"},
    ]
    rendered = _format_cross_case_matches(matches)
    assert CROSS_CASE_ADVISORY_LABEL in rendered

    # Present on the per-entry line itself, not just the header — must
    # survive truncation/excerpting of any single line.
    entry_lines = [l for l in rendered.splitlines() if "c" * 64 in l]
    assert entry_lines
    assert all(CROSS_CASE_ADVISORY_LABEL in l for l in entry_lines)


def test_format_cross_case_matches_empty_when_no_specific_matches_no_label():
    """No advisory label needed when there's no content to label."""
    rendered = _format_cross_case_matches([])
    assert rendered == "(No prior cross-case matches)"
    assert CROSS_CASE_ADVISORY_LABEL not in rendered


def test_build_deep_dive_context_host_path_never_surfaces_mitre_matches_unlabelled():
    """The deep-dive subagent context is exactly what reaches the
    orchestrating (host) agent — the path that has
    no in-process validator seam. The filter must hold here too."""
    finding = {
        "finding_id": "F-001-001", "status": "CONFIRMED", "confidence": 0.75,
        "title": "test finding", "mitre_attack": "T1071.001",
    }
    ctx = build_deep_dive_context(
        finding=finding,
        cross_case_matches=[
            {"ioc_type": "mitre_attack", "value": "T1071.001", "case": "099-unrelated",
             "finding_id": "F-099-001", "date": "2026-01-01"},
            {"ioc_type": "sha256", "value": "d" * 64, "case": "006-b",
             "finding_id": "F-006-001", "date": "2026-01-01"},
        ],
    )
    context = ctx["context"]
    assert "099-unrelated" not in context, (
        "a loose mitre_attack cross-case match must never reach the "
        "narrative-writing subagent's context"
    )
    assert "d" * 64 in context
    assert CROSS_CASE_ADVISORY_LABEL in context, (
        "the rendered cross-case match must carry the advisory/different-"
        "matter label inside the subagent context itself"
    )


# ── 6. DROPPED exclusion ───────────────────────────────────────────────

def test_extract_iocs_excludes_dropped_status_directly():
    """Unit-level check of the filter itself, independent of any phase
    plumbing or upstream purge."""
    findings = [
        {"_case": "001-x", "finding_id": "F-001-001", "status": "DROPPED",
         "iocs": {"sha256": ["a" * 64]}, "corroboration": {"sources": 0}},
        {"_case": "001-x", "finding_id": "F-001-002", "status": "CONFIRMED",
         "iocs": {"sha256": ["b" * 64]}, "corroboration": {"sources": 2}},
    ]
    iocs = cci._extract_iocs(findings)
    values = [v for v, *_ in iocs.get("sha256", [])]
    assert "a" * 64 not in values
    assert "b" * 64 in values


# ── 7. cross_case_index.py's own cases-dir isolation ──────────────────

def test_cross_case_index_never_falls_back_to_its_module_default_global(tmp_path, monkeypatch):
    """cross_case_index.py's DEFAULT_CASES_DIR / INDEX_PATH module
    constants are bound once at import time from spectre.config.CASES_DIR
    (the REAL, shared store). Every public write function
    (update_index/retract_case/rebuild_index) must act strictly on the
    explicit `cases_dir` argument it's given and never silently fall back
    to those globals -- point them at a bogus sentinel path that must
    NEVER receive a write."""
    bogus_global = tmp_path / "SHOULD-NEVER-BE-WRITTEN-TO"
    monkeypatch.setattr(cci, "DEFAULT_CASES_DIR", str(bogus_global))
    monkeypatch.setattr(cci, "INDEX_PATH", str(bogus_global / "index.md"))

    real_cases_dir = tmp_path / "actual-cases-dir"
    case_dir = _init_case(real_cases_dir, "001-isolation-test")
    _write_finding(case_dir, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["f" * 64]})

    cci.update_index(str(real_cases_dir), "001-isolation-test")
    assert (real_cases_dir / "index.md").exists()
    assert not bogus_global.exists(), (
        "update_index() must act strictly on the explicit cases_dir "
        "argument, never the module-level default global"
    )

    cci.rebuild_index(str(real_cases_dir))
    assert not bogus_global.exists(), (
        "rebuild_index() must act strictly on the explicit cases_dir "
        "argument, never the module-level default global"
    )

    cci.retract_case(str(real_cases_dir), "001-isolation-test")
    assert not bogus_global.exists(), (
        "retract_case() must act strictly on the explicit cases_dir "
        "argument, never the module-level default global"
    )


def test_update_index_and_rebuild_index_use_only_the_given_cases_dir(tmp_path):
    """Two independent tmp cases-dirs never see each other's writes —
    each call is scoped strictly to the `cases_dir` argument passed."""
    cases_dir_1 = tmp_path / "cases-1"
    cases_dir_2 = tmp_path / "cases-2"
    case_1 = _init_case(cases_dir_1, "001-one")
    _write_finding(case_1, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["1" * 64]})
    case_2 = _init_case(cases_dir_2, "001-two")
    _write_finding(case_2, "F-001-001", status="CONFIRMED",
                    iocs={"sha256": ["2" * 64]})

    cci.update_index(str(cases_dir_1), "001-one")
    cci.update_index(str(cases_dir_2), "001-two")

    text_1 = (cases_dir_1 / "index.md").read_text()
    text_2 = (cases_dir_2 / "index.md").read_text()

    assert "1" * 64 in text_1 and "2" * 64 not in text_1
    assert "2" * 64 in text_2 and "1" * 64 not in text_2
