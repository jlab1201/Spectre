"""Residual A (documented, NOT closed by WS1a — see audit.py's
_update_chain_anchor()/verify_full() docstrings): the tail-truncation
anchor sidecar (audit_chain_anchor.json) lives in the same case directory
as audit.jsonl, so deleting it alongside a truncated chain makes the tail
check fail OPEN (silently skipped). This test pins the loud-warning
behavior WS1a DOES add — a missing anchor on a chain that has rows must
show up as a visible, advisory (non-failing) signal in verify_full()'s
output, not silent benignity. WS1b closes the actual gap with an external
anchor.
"""
from spectre.pipeline.audit import append, verify_full


def _append_n(case_dir, n):
    for i in range(n):
        append(str(case_dir), {
            "actor": "deterministic-core", "action": "note", "tool": "x",
            "case_id": case_dir.name, "output_path": "",
            "output_sha256": "", "result": "success",
            "phase": 0, "phase_step": f"row-{i}",
        })


def test_missing_anchor_on_chain_with_rows_is_a_loud_advisory_warning(tmp_path):
    case_dir = tmp_path / "case-anchor-missing"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    (case_dir / "audit_chain_anchor.json").unlink()

    report = verify_full(str(case_dir))
    assert report["checks"]["chain_anchor"]["passed"] is False
    # Advisory only — must NOT fail the whole report on its own (an
    # untampered, merely anchor-less chain is not proof of tampering).
    assert report["checks"]["chain"]["passed"] is True
    assert report["ok"] is True, (
        "chain_anchor is advisory and must not fail report['ok'] by itself"
    )


def test_present_anchor_is_silent(tmp_path):
    case_dir = tmp_path / "case-anchor-present"
    case_dir.mkdir()
    _append_n(case_dir, 3)

    report = verify_full(str(case_dir))
    assert report["checks"]["chain_anchor"]["passed"] is True


def test_no_rows_at_all_does_not_warn(tmp_path):
    case_dir = tmp_path / "case-empty"
    case_dir.mkdir()
    report = verify_full(str(case_dir))
    assert report["checks"]["chain_anchor"]["passed"] is True
