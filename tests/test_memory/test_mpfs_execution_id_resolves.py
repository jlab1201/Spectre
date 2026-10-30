"""A MemProcFS handle's execution_id must be the entry_sha256 of the
tool_exec row written for it, so a finding citing that handle resolves to a
chained audit row (Phase 4 evidence_ref gate)."""
import json

from spectre.modules.memory import _audit_mpfs_handles


def _rows(case_dir):
    return [json.loads(l) for l in (case_dir / "audit.jsonl").read_text().splitlines() if l.strip()]


def test_mpfs_handle_execution_id_is_its_tool_exec_row(tmp_path):
    out = tmp_path / "raw_extract" / "pslist.json"
    out.parent.mkdir()
    out.write_text("[]")
    handles = [
        {"path": str(out), "output_sha256": "", "tool": "memprocfs",
         "execution_id": "mpfs-20260101000000000000", "line_count": 0},
        {"path": str(out), "output_sha256": "", "tool": "memprocfs",
         "execution_id": "mpfs-20260101000000000000", "line_count": 0},
    ]
    _audit_mpfs_handles(str(tmp_path), handles)

    rows = {r["entry_sha256"]: r for r in _rows(tmp_path)}
    ids = [h["execution_id"] for h in handles]
    assert len(set(ids)) == 2, "each handle gets its own row id"
    for eid in ids:
        assert eid in rows
        assert rows[eid]["action"] == "tool_exec"
        assert rows[eid]["actor"] == "deterministic-core"


def test_subprocess_handle_carries_no_placeholder_id(tmp_path):
    """The subprocess has no audit row to cite; its handle must carry an
    empty id (unresolved, fail closed) until the parent audits it."""
    import time
    from spectre.modules.memory.extract_memprocfs import _make_handle
    out = tmp_path / "x.json"
    out.write_text("[]")
    h = _make_handle(str(out), "/ev/mem.raw", "memory_pslist", 0, "cmd", time.time())
    assert h["execution_id"] == ""
