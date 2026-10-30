"""Tests for case-resume + auto-run-preceding-phases logic (issue 2).

Covers the pure, deterministic helpers that decide:
  - whether an existing case matches (name + evidence sha set),
  - how far that case got (last phase / completed),
  - which preceding phases still need to run for a --phase target.
"""
import yaml
from pathlib import Path

from spectre.pipeline.case_setup import (
    evidence_sha_set, find_resumable_cases, phase_status, _sha256_file,
)
from spectre.pipeline.phase_runner import missing_preceding_phases


def _write_case(cases_dir: Path, case_id: str, name: str,
                ev_shas, gates_passed) -> Path:
    """Create a minimal case dir with a manifest for matching tests."""
    d = cases_dir / f"{case_id}-{name}"
    d.mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": case_id,
        "case_name": name,
        "evidence": [{"sha256": s} for s in ev_shas],
    }
    for n in range(0, 8):
        manifest[f"gate_{n}"] = {"passed": n in gates_passed}
    (d / "manifest.yaml").write_text(yaml.dump(manifest))
    return d


def test_evidence_sha_set_hashes_each_file(tmp_path):
    f1 = tmp_path / "a.bin"
    f1.write_bytes(b"hello")
    f2 = tmp_path / "b.bin"
    f2.write_bytes(b"world")
    shas = evidence_sha_set([str(f1), str(f2)])
    assert shas == frozenset({_sha256_file(str(f1)), _sha256_file(str(f2))})


def test_evidence_sha_set_skips_missing(tmp_path):
    f1 = tmp_path / "a.bin"
    f1.write_bytes(b"hello")
    shas = evidence_sha_set([str(f1), str(tmp_path / "nope.bin")])
    assert shas == frozenset({_sha256_file(str(f1))})


def test_phase_status_reports_last_and_completed():
    m = {f"gate_{n}": {"passed": n <= 4} for n in range(0, 8)}
    assert phase_status(m) == (4, False)


def test_phase_status_completed_when_gate7_passed():
    m = {f"gate_{n}": {"passed": True} for n in range(0, 8)}
    assert phase_status(m) == (7, True)


def test_phase_status_none_completed():
    m = {f"gate_{n}": {"passed": False} for n in range(0, 8)}
    assert phase_status(m) == (-1, False)


def test_find_resumable_matches_name_and_evidence(tmp_path):
    cases = tmp_path / "cases"
    _write_case(cases, "001", "alpha", {"aaa", "bbb"}, {0, 1, 2})
    _write_case(cases, "002", "beta", {"aaa", "bbb"}, {0})
    matches = find_resumable_cases(str(cases), "alpha", frozenset({"aaa", "bbb"}))
    assert [m["case_id"] for m in matches] == ["001"]
    assert matches[0]["last_phase"] == 2


def test_find_resumable_rejects_mismatched_evidence(tmp_path):
    cases = tmp_path / "cases"
    _write_case(cases, "001", "alpha", {"aaa"}, {0})
    matches = find_resumable_cases(str(cases), "alpha", frozenset({"xxx"}))
    assert matches == []


def test_find_resumable_newest_first(tmp_path):
    cases = tmp_path / "cases"
    _write_case(cases, "001", "alpha", {"aaa"}, {0})
    _write_case(cases, "003", "alpha", {"aaa"}, {0, 1})
    _write_case(cases, "002", "alpha", {"aaa"}, {0})
    matches = find_resumable_cases(str(cases), "alpha", frozenset({"aaa"}))
    assert [m["case_id"] for m in matches] == ["003", "002", "001"]


def test_find_resumable_name_only_when_no_evidence(tmp_path):
    cases = tmp_path / "cases"
    _write_case(cases, "001", "alpha", {"aaa"}, {0})
    matches = find_resumable_cases(str(cases), "alpha", frozenset())
    assert [m["case_id"] for m in matches] == ["001"]


def test_find_resumable_empty_when_dir_missing(tmp_path):
    assert find_resumable_cases(str(tmp_path / "nope"), "alpha", frozenset()) == []


def test_missing_preceding_only_unpassed():
    m = {f"gate_{n}": {"passed": n in (0, 1)} for n in range(0, 8)}
    assert missing_preceding_phases(m, 5) == [2, 3, 4]


def test_missing_preceding_none_when_all_passed():
    m = {f"gate_{n}": {"passed": True} for n in range(0, 8)}
    assert missing_preceding_phases(m, 5) == []


def test_missing_preceding_excludes_target_itself():
    m = {f"gate_{n}": {"passed": False} for n in range(0, 8)}
    assert missing_preceding_phases(m, 3) == [0, 1, 2]
