"""Carve pass: body-file pattern matching + icat dispatch."""
from pathlib import Path

import spectre.modules.disk.carve as carve_mod
from spectre.modules.disk.carve import _match_targets, carve_targets

_BODY = "\n".join([
    "0|/Windows/System32/winevt/Logs/Security.evtx|12-128-1|r/rrwxrwxrwx|0|0|4096|1|2|3|4",
    "0|/Windows/System32/config/SYSTEM|13-128-1|r/rrwxrwxrwx|0|0|8192|1|2|3|4",
    "0|/Users/bob/NTUSER.DAT|14-128-1|r/rrwxrwxrwx|0|0|1024|1|2|3|4",
    "0|/Windows/Prefetch/CALC.EXE-12345678.pf|15-128-1|r/rrwxrwxrwx|0|0|512|1|2|3|4",
    "0|/Users/bob/Desktop/evil.lnk|16-128-1|r/rrwxrwxrwx|0|0|256|1|2|3|4",
    "0|/$MFT|17-128-1|r/rrwxrwxrwx|0|0|65536|1|2|3|4",
    "0|/Users/bob/Documents/notes.txt|18-128-1|r/rrwxrwxrwx|0|0|100|1|2|3|4",
    "0|/Windows/System32/kernel32.dll|19-128-1|r/rrwxrwxrwx|0|0|999|1|2|3|4",
])


def test_match_targets_selects_forensic_artifacts_only():
    hits = _match_targets(_BODY.splitlines())
    names = {h["in_image_path"] for h in hits}
    assert "/Windows/System32/winevt/Logs/Security.evtx" in names
    assert "/Windows/System32/config/SYSTEM" in names
    assert "/Users/bob/NTUSER.DAT" in names
    assert "/Windows/Prefetch/CALC.EXE-12345678.pf" in names
    assert "/Users/bob/Desktop/evil.lnk" in names
    assert "/$MFT" in names
    assert "/Users/bob/Documents/notes.txt" not in names
    assert "/Windows/System32/kernel32.dll" not in names


def test_match_respects_carve_cap(monkeypatch):
    monkeypatch.setattr(carve_mod, "_CARVE_CAP", 2)
    hits = _match_targets(_BODY.splitlines())
    assert len(hits) == 2


def test_carve_targets_runs_icat_per_hit(tmp_path, monkeypatch):
    calls = []

    def fake_run_tool(**kw):
        calls.append(kw)
        Path(kw["output_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(kw["output_path"]).write_bytes(b"CARVED")
        return {"path": kw["output_path"], "result": "success",
                "exit_code": 0, "stderr": "", "size_bytes": 6,
                "output_sha256": "x", "line_count": 0}

    monkeypatch.setattr(carve_mod, "run_tool", fake_run_tool)
    body = tmp_path / "body.txt"
    body.write_text(_BODY)
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    recs = carve_targets(str(case), str(tmp_path / "image.dd"), str(body))
    assert len(recs) == 6
    assert all(r["carve_result"] == "success" for r in recs)
    # icat invoked with image + bare inode number
    cmd = calls[0]["command"]
    assert cmd[0].endswith("icat") and cmd[-2].endswith("image.dd")
    assert cmd[-1] == "12"
    assert calls[0]["output_format"] == "binary"
    # carved under evidence/derived/<parent_stem>/, sanitized name
    assert "/evidence/derived/image/" in recs[0]["path"]
    assert recs[0]["path"].endswith("Windows_System32_winevt_Logs_Security.evtx")


def test_carve_icat_failure_is_recorded_not_raised(tmp_path, monkeypatch):
    def failing_run_tool(**kw):
        # icat still leaves behind an empty output file even on failure.
        Path(kw["output_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(kw["output_path"]).write_bytes(b"")
        return {"path": kw["output_path"], "result": "error", "exit_code": 1,
                "stderr": "icat: invalid inode", "size_bytes": 0,
                "output_sha256": "", "line_count": 0}
    monkeypatch.setattr(carve_mod, "run_tool", failing_run_tool)
    body = tmp_path / "body.txt"
    body.write_text(_BODY.splitlines()[0])
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    recs = carve_targets(str(case), str(tmp_path / "image.dd"), str(body))
    assert recs[0]["carve_result"] == "error"
    assert "invalid inode" in recs[0]["stderr"]
    # empty failed-carve stub is unlinked, not left behind writable/unregistered
    assert not Path(recs[0]["path"]).exists()


def test_carve_failure_with_partial_output_is_locked_not_deleted(tmp_path, monkeypatch):
    def failing_run_tool(**kw):
        # icat wrote SOME bytes before erroring out — may hold forensic value.
        Path(kw["output_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(kw["output_path"]).write_bytes(b"PARTIAL")
        return {"path": kw["output_path"], "result": "error", "exit_code": 1,
                "stderr": "icat: read error mid-file", "size_bytes": 7,
                "output_sha256": "", "line_count": 0}
    monkeypatch.setattr(carve_mod, "run_tool", failing_run_tool)
    body = tmp_path / "body.txt"
    body.write_text(_BODY.splitlines()[0])
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    recs = carve_targets(str(case), str(tmp_path / "image.dd"), str(body))
    assert recs[0]["carve_result"] == "error"
    out_path = Path(recs[0]["path"])
    assert out_path.exists()
    assert out_path.read_bytes() == b"PARTIAL"
    # non-empty partial output is preserved but locked read-only
    assert not (out_path.stat().st_mode & 0o200)


def test_duplicate_in_image_paths_do_not_collide(tmp_path, monkeypatch):
    # fls emits the same path twice (deleted + live entry, different
    # inodes) — both must carve to distinct files, never overwrite.
    body_lines = [
        "0|/Windows/System32/winevt/Logs/Security.evtx|100-128-1|r|0|0|10|1|2|3|4",
        "0|/Windows/System32/winevt/Logs/Security.evtx|205-128-3|r|0|0|20|1|2|3|4",
    ]
    calls = []

    def fake_run_tool(**kw):
        calls.append(kw["output_path"])
        Path(kw["output_path"]).parent.mkdir(parents=True, exist_ok=True)
        Path(kw["output_path"]).write_bytes(b"X")
        return {"path": kw["output_path"], "result": "success",
                "exit_code": 0, "stderr": "", "size_bytes": 1,
                "output_sha256": "x", "line_count": 0}

    monkeypatch.setattr(carve_mod, "run_tool", fake_run_tool)
    body = tmp_path / "body.txt"
    body.write_text("\n".join(body_lines))
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    recs = carve_targets(str(case), str(tmp_path / "image.dd"), str(body))
    assert len(recs) == 2
    assert recs[0]["path"] != recs[1]["path"]
    assert len(set(calls)) == 2


def test_body_line_with_pipe_in_name_is_rejected():
    line = "0|/Users/x/ntuser.dat|/home/x/evil|r/rrwxrwxrwx|0|0|10|1|2|3|4|5"
    assert _match_targets([line]) == []


def test_pipe_in_name_with_valid_fields_keeps_numeric_inode():
    line = "0|/Users/x|a/NTUSER.DAT|14-128-1|r/rrwxrwxrwx|0|0|10|1|2|3|4"
    hits = _match_targets([line])
    assert hits and hits[0]["inode"] == "14"


def test_carve_output_stays_under_derived(tmp_path, monkeypatch):
    paths = []

    def fake_run_tool(**kw):
        paths.append(Path(kw["output_path"]))
        return {"result": "error", "stderr": ""}

    monkeypatch.setattr(carve_mod, "run_tool", fake_run_tool)
    body = tmp_path / "body.txt"
    body.write_text(_BODY)
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    carve_targets(str(case), str(tmp_path / "image.dd"), str(body))
    out_dir = (case / "evidence" / "derived" / "image").resolve()
    assert paths
    for p in paths:
        p.resolve().relative_to(out_dir)
