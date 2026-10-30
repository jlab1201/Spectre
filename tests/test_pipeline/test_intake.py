"""Track B1: evidence intake — directory expansion."""
import os
from pathlib import Path

from spectre.pipeline.case_setup import _expand_evidence_paths, _register_evidence


def _mk(tmp_path, rel, content=b"x"):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def test_expand_plain_files_pass_through(tmp_path):
    a = _mk(tmp_path, "a.pcap")
    files, skipped = _expand_evidence_paths([str(a)])
    assert files == [str(a)]
    assert skipped == []


def test_expand_walks_directories_recursively(tmp_path):
    _mk(tmp_path, "dump/a.pcap")
    _mk(tmp_path, "dump/host1/Security.evtx")
    files, skipped = _expand_evidence_paths([str(tmp_path / "dump")])
    names = sorted(Path(f).name for f in files)
    assert names == ["Security.evtx", "a.pcap"]
    assert skipped == []


def test_expand_skips_empty_files_with_reason(tmp_path):
    _mk(tmp_path, "dump/real.evtx")
    _mk(tmp_path, "dump/empty.log", content=b"")
    files, skipped = _expand_evidence_paths([str(tmp_path / "dump")])
    assert [Path(f).name for f in files] == ["real.evtx"]
    assert len(skipped) == 1
    assert skipped[0]["reason"] == "empty file (0 bytes)"
    assert skipped[0]["path"].endswith("empty.log")


def test_expand_skips_symlinks_with_reason(tmp_path):
    real = _mk(tmp_path, "outside.bin")
    d = tmp_path / "dump"
    d.mkdir()
    (d / "link.bin").symlink_to(real)
    files, skipped = _expand_evidence_paths([str(d)])
    assert files == []
    assert skipped[0]["reason"] == "symlink (not followed)"


def test_expand_missing_path_is_skip_record_not_crash(tmp_path):
    files, skipped = _expand_evidence_paths([str(tmp_path / "nope")])
    assert files == []
    assert skipped[0]["reason"] == "does not exist"


def test_expand_is_deterministic_sorted(tmp_path):
    _mk(tmp_path, "dump/b.bin", b"b")
    _mk(tmp_path, "dump/a.bin", b"a")
    files, _ = _expand_evidence_paths([str(tmp_path / "dump")])
    assert [Path(f).name for f in files] == ["a.bin", "b.bin"]


def test_expand_deduplicates_overlapping_args(tmp_path):
    _mk(tmp_path, "dump/sub/a.bin")
    files, skipped = _expand_evidence_paths(
        [str(tmp_path / "dump"), str(tmp_path / "dump" / "sub"),
         str(tmp_path / "dump" / "sub" / "a.bin")])
    assert files == [str(tmp_path / "dump" / "sub" / "a.bin")]
    assert skipped == []


def test_expand_records_symlinked_subdirectory(tmp_path):
    # A symlinked subdir inside a walked dir must be RECORDED as a skip,
    # not silently dropped (rglob lists but does not descend into it).
    _mk(tmp_path, "outside/real.bin")
    d = tmp_path / "dump"
    d.mkdir()
    _mk(tmp_path, "dump/normal.bin")
    (d / "linked_dir").symlink_to(tmp_path / "outside")
    files, skipped = _expand_evidence_paths([str(d)])
    assert [Path(f).name for f in files] == ["normal.bin"]
    assert any(s["reason"] == "symlink (not followed)"
               and s["path"].endswith("linked_dir") for s in skipped)


def _case(tmp_path):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    return str(case)


def test_register_collision_suffixes_not_overwrites(tmp_path):
    case = _case(tmp_path)
    a = _mk(tmp_path, "host1/Security.evtx", b"AAAA")
    b = _mk(tmp_path, "host2/Security.evtx", b"BBBB")
    ra = _register_evidence(str(a), case)
    rb = _register_evidence(str(b), case)
    assert ra["ok"] and rb["ok"]
    staged = sorted(os.listdir(os.path.join(case, "evidence")))
    assert len(staged) == 2, f"collision overwrote evidence: {staged}"
    assert ra["evidence_path"] != rb["evidence_path"]
    # first keeps its natural name; second is content-addressed
    assert Path(ra["evidence_path"]).name == "Security.evtx"
    assert Path(rb["evidence_path"]).name.startswith("Security__")


def test_register_identical_resubmission_reuses_copy(tmp_path):
    case = _case(tmp_path)
    a = _mk(tmp_path, "host1/Security.evtx", b"AAAA")
    r1 = _register_evidence(str(a), case)
    r2 = _register_evidence(str(a), case)
    assert r1["ok"] and r2["ok"]
    assert r2["evidence_path"] == r1["evidence_path"]
    assert "duplicate" in r2["reason"]
    staged = os.listdir(os.path.join(case, "evidence"))
    assert len(staged) == 1


# ── Track B1: E01/libewf capability probe ────────────────────────────
# The probe moved out of recognize.py into the disk module's availability()
# hook (spec §5.4) — recognize.py was not its only caller, and the canary was
# getting the naive `shutil.which(required_tools)` answer instead. The
# behaviour asserted here is unchanged; only the monkeypatch target moved.

def test_e01_without_libewf_is_extractor_pending(tmp_path, monkeypatch):
    import spectre.pipeline.recognize as recognize
    from spectre.modules.disk import availability as disk_av
    monkeypatch.setattr(disk_av, "_EWF_SUPPORT", None)
    monkeypatch.setattr(disk_av, "probe_ewf_support", lambda: False)
    p = tmp_path / "image.e01"
    p.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
    rec = recognize.triage_one(str(p))
    assert rec["module"] == "disk"
    assert rec["status"] == "EXTRACTOR_PENDING"
    assert rec["tool"] == "libewf"


def test_e01_with_libewf_stays_recognized(tmp_path, monkeypatch):
    import spectre.pipeline.recognize as recognize
    from spectre.modules.disk import availability as disk_av
    monkeypatch.setattr(disk_av, "_EWF_SUPPORT", None)
    monkeypatch.setattr(disk_av, "probe_ewf_support", lambda: True)
    p = tmp_path / "image.e01"
    p.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
    rec = recognize.triage_one(str(p))
    assert rec["module"] == "disk"
    assert rec["status"] == "RECOGNIZED"


# ── Track B1: disk_image FK YAML ──────────────────────────────────────

def test_disk_image_fk_yaml_loads():
    from spectre.pipeline.case_setup import ARTIFACT_FK, _load_fk_yaml
    assert "disk_image" in ARTIFACT_FK
    fk = _load_fk_yaml("disk_image")
    assert fk, "disk_image.yaml must exist and load"
    # Sibling FK YAMLs (pcap, evtx_4688, logfile) carry their caveats under
    # `does_NOT_prove` — explain.py / emit_finding.py / report_synthesize.py
    # all read that key verbatim. disk_image must follow the same contract.
    caveats = fk.get("does_NOT_prove")
    assert caveats, "disk FK must carry caveats (does_NOT_prove)"
    assert len(caveats) >= 4, "brief requires >=4 honest caveats"
