"""Derived evidence: registration, re-triage, depth bound."""
import os
import stat

import yaml

from tests.test_pipeline.custody_helpers import chain_triage
from spectre.core.base import AnalyzerModule, NormEvent, Recognizer
from spectre.pipeline.phase_runner import _run_phase_2_live

_EVTX_HDR = b"ElfFile\x00" + b"\x00" * 100


def _make_case(tmp_path):
    """Minimal case dir: evidence/, raw_extract/ + a seeded audit.jsonl."""
    case = tmp_path / "case"
    for sub in ("evidence", "raw_extract", "findings", "reports"):
        (case / sub).mkdir(parents=True)
    (case / "audit.jsonl").write_text("")
    return case


def _staged_image(case):
    img = case / "evidence" / "image.dd"
    img.write_bytes(b"\x00" * 512)
    return img


def _disk_recognizer():
    return Recognizer(module_name="disk", artifact_type="disk_image",
                       extensions={".dd"})


def _evtx_recognizer():
    return Recognizer(module_name="evtx", artifact_type="evtx_process_creation",
                       extensions={".evtx"})


def _fake_disk_module(derived_files):
    def extract(case_dir, ev_path):
        return [{"path": ev_path, "tool": "fls", "engine": "fls",
                  "line_count": 0, "size_bytes": 512,
                  "derived_files": derived_files}]

    def normalize(handle):
        return []

    return AnalyzerModule(
        name="disk", artifact_type="disk_image", required_tools=[],
        recognizers=[_disk_recognizer()], extract=extract, normalize=normalize,
    )


def _fake_evtx_module(extra_derived_files=None):
    def extract(case_dir, ev_path):
        handle = {"path": ev_path, "tool": "fake_evtx", "engine": "fake_evtx"}
        if extra_derived_files is not None:
            handle["derived_files"] = extra_derived_files
        return [handle]

    def normalize(handle):
        return [NormEvent(artifact_type="evtx_process_creation",
                           timestamp="2026-01-01T00:00:00Z",
                           source_file=handle["path"], record_id="1",
                           data={})]

    return AnalyzerModule(
        name="evtx", artifact_type="evtx_process_creation", required_tools=[],
        recognizers=[_evtx_recognizer()], extract=extract, normalize=normalize,
    )


def test_derived_evidence_registered_retriaged_and_analyzed(tmp_path, monkeypatch):
    case = _make_case(tmp_path)
    staged_image = _staged_image(case)

    carved = case / "evidence" / "derived" / "img" / "Security.evtx"
    carved.parent.mkdir(parents=True)
    carved.write_bytes(_EVTX_HDR)

    derived_files = [{
        "path": str(carved),
        "in_image_path": "/Windows/System32/winevt/Logs/Security.evtx",
        "inode": "12", "size": carved.stat().st_size,
        "parent_evidence": str(staged_image),
        "carve_result": "success", "stderr": "",
    }]

    modules = {"disk": _fake_disk_module(derived_files), "evtx": _fake_evtx_module()}
    monkeypatch.setattr("spectre.modules.registry.discover", lambda: modules)

    manifest = {
        "evidence": [{"evidence_path": str(staged_image), "sha256": "a" * 64}],
        "triage": {str(staged_image): {"status": "RECOGNIZED", "module": "disk",
                                        "artifact_type": "disk_image"}},
    }

    chain_triage(case, manifest)  # W3: Phase 2 extracts registered evidence only
    result = _run_phase_2_live(str(case), manifest)

    # carved file is read-only
    assert not (os.stat(carved).st_mode & stat.S_IWUSR)

    # derived evidence in manifest with parent linkage
    de = manifest["derived_evidence"]
    assert de[str(carved)]["derived_from"].endswith("image.dd")
    assert de[str(carved)]["sha256"]

    # re-triaged and analyzed by the evtx module
    assert result["results"][str(carved)]["derived_from"]
    assert result["results"][str(carved)]["module"] == "evtx"
    assert result["results"][str(carved)]["events"] == 1

    # events merged into the same stream Phase 3 reads
    normalized = (case / "raw_extract" / "normalized_events.json").read_text()
    assert "evtx_process_creation" in normalized

    # audit row exists
    audit_text = (case / "audit.jsonl").read_text()
    assert "derived_evidence_register" in audit_text

    # manifest.yaml on disk carries derived_evidence
    saved = yaml.safe_load((case / "manifest.yaml").read_text())
    assert str(carved) in saved["derived_evidence"]


def test_derived_of_derived_not_carved(tmp_path, monkeypatch):
    case = _make_case(tmp_path)
    staged_image = _staged_image(case)

    carved = case / "evidence" / "derived" / "img" / "Security.evtx"
    carved.parent.mkdir(parents=True)
    carved.write_bytes(_EVTX_HDR)

    nested = case / "evidence" / "derived" / "img" / "nested.evtx"
    nested.write_bytes(_EVTX_HDR)

    derived_files = [{
        "path": str(carved),
        "in_image_path": "/Windows/System32/winevt/Logs/Security.evtx",
        "inode": "12", "size": carved.stat().st_size,
        "parent_evidence": str(staged_image),
        "carve_result": "success", "stderr": "",
    }]
    # the re-triaged evtx module ALSO claims to have carved something —
    # this must be ignored (depth bound: only primary evidence is carved).
    nested_derived_files = [{
        "path": str(nested),
        "in_image_path": "/Windows/System32/winevt/Logs/nested.evtx",
        "inode": "13", "size": nested.stat().st_size,
        "parent_evidence": str(carved),
        "carve_result": "success", "stderr": "",
    }]

    modules = {"disk": _fake_disk_module(derived_files),
               "evtx": _fake_evtx_module(extra_derived_files=nested_derived_files)}
    monkeypatch.setattr("spectre.modules.registry.discover", lambda: modules)

    manifest = {
        "evidence": [{"evidence_path": str(staged_image), "sha256": "a" * 64}],
        "triage": {str(staged_image): {"status": "RECOGNIZED", "module": "disk",
                                        "artifact_type": "disk_image"}},
    }

    chain_triage(case, manifest)  # W3: Phase 2 extracts registered evidence only
    _run_phase_2_live(str(case), manifest)

    assert len(manifest["derived_evidence"]) == 1
    assert str(nested) not in manifest["derived_evidence"]
    # nested was never chmod'd/registered
    assert os.stat(nested).st_mode & stat.S_IWUSR


def test_derived_evidence_extractor_pending_labeled_honestly(tmp_path, monkeypatch):
    """A derived file recognized but whose module's tool is unavailable
    (EXTRACTOR_PENDING) must be labeled with the specific reason, not the
    generic 'not claimed by any module' note (that's for UNRECOGNIZED)."""
    case = _make_case(tmp_path)
    staged_image = _staged_image(case)

    carved = case / "evidence" / "derived" / "img" / "Security.evtx"
    carved.parent.mkdir(parents=True)
    carved.write_bytes(_EVTX_HDR)

    derived_files = [{
        "path": str(carved),
        "in_image_path": "/Windows/System32/winevt/Logs/Security.evtx",
        "inode": "12", "size": carved.stat().st_size,
        "parent_evidence": str(staged_image),
        "carve_result": "success", "stderr": "",
    }]

    evtx_module = _fake_evtx_module()
    # simulate the evtx module's required tool being unavailable so
    # recognize.triage_one marks the re-triaged carve EXTRACTOR_PENDING.
    evtx_module = AnalyzerModule(
        name=evtx_module.name, artifact_type=evtx_module.artifact_type,
        required_tools=["definitely_nonexistent_tool_xyz"],
        recognizers=evtx_module.recognizers, extract=evtx_module.extract,
        normalize=evtx_module.normalize,
    )

    modules = {"disk": _fake_disk_module(derived_files), "evtx": evtx_module}
    monkeypatch.setattr("spectre.modules.registry.discover", lambda: modules)

    manifest = {
        "evidence": [{"evidence_path": str(staged_image), "sha256": "a" * 64}],
        "triage": {str(staged_image): {"status": "RECOGNIZED", "module": "disk",
                                        "artifact_type": "disk_image"}},
    }

    chain_triage(case, manifest)  # W3: Phase 2 extracts registered evidence only
    result = _run_phase_2_live(str(case), manifest)

    entry = result["results"][str(carved)]
    assert entry["skipped"] == "EXTRACTOR_PENDING"
    assert entry["note"] == "recognized as evtx_process_creation but required tool is unavailable"


def test_failed_carves_are_skipped_but_recorded(tmp_path, monkeypatch):
    case = _make_case(tmp_path)
    staged_image = _staged_image(case)

    missing = case / "evidence" / "derived" / "img" / "gone.evtx"

    derived_files = [{
        "path": str(missing),
        "in_image_path": "/Windows/System32/winevt/Logs/gone.evtx",
        "inode": "99", "size": 0,
        "parent_evidence": str(staged_image),
        "carve_result": "error", "stderr": "icat: inode not found",
    }]

    modules = {"disk": _fake_disk_module(derived_files), "evtx": _fake_evtx_module()}
    monkeypatch.setattr("spectre.modules.registry.discover", lambda: modules)

    manifest = {
        "evidence": [{"evidence_path": str(staged_image), "sha256": "a" * 64}],
        "triage": {str(staged_image): {"status": "RECOGNIZED", "module": "disk",
                                        "artifact_type": "disk_image"}},
    }

    chain_triage(case, manifest)  # W3: Phase 2 extracts registered evidence only
    result = _run_phase_2_live(str(case), manifest)

    assert "carve_failed" in str(result["results"])
    # no registration happened for a failed carve
    assert manifest.get("derived_evidence", {}) == {}


def test_pathological_derived_file_does_not_abort_pass(tmp_path, monkeypatch):
    """One carved file raising during triage/analysis must not abort the
    whole derived-evidence pass — later derived files still get processed."""
    case = _make_case(tmp_path)
    staged_image = _staged_image(case)

    carved1 = case / "evidence" / "derived" / "img" / "bad.evtx"
    carved1.parent.mkdir(parents=True)
    carved1.write_bytes(_EVTX_HDR)

    carved2 = case / "evidence" / "derived" / "img" / "Security.evtx"
    carved2.write_bytes(_EVTX_HDR)

    derived_files = [
        {
            "path": str(carved1),
            "in_image_path": "/Windows/System32/winevt/Logs/bad.evtx",
            "inode": "20", "size": carved1.stat().st_size,
            "parent_evidence": str(staged_image),
            "carve_result": "success", "stderr": "",
        },
        {
            "path": str(carved2),
            "in_image_path": "/Windows/System32/winevt/Logs/Security.evtx",
            "inode": "12", "size": carved2.stat().st_size,
            "parent_evidence": str(staged_image),
            "carve_result": "success", "stderr": "",
        },
    ]

    modules = {"disk": _fake_disk_module(derived_files), "evtx": _fake_evtx_module()}
    monkeypatch.setattr("spectre.modules.registry.discover", lambda: modules)

    import spectre.pipeline.recognize as recognize_mod
    real_triage_one = recognize_mod.triage_one

    def flaky_triage_one(path):
        if str(path) == str(carved1):
            raise ValueError("pathological carved file — sniff exploded")
        return real_triage_one(path)

    monkeypatch.setattr(recognize_mod, "triage_one", flaky_triage_one)

    manifest = {
        "evidence": [{"evidence_path": str(staged_image), "sha256": "a" * 64}],
        "triage": {str(staged_image): {"status": "RECOGNIZED", "module": "disk",
                                        "artifact_type": "disk_image"}},
    }

    chain_triage(case, manifest)  # W3: Phase 2 extracts registered evidence only
    result = _run_phase_2_live(str(case), manifest)

    # pathological file: error recorded, not raised
    entry1 = result["results"][str(carved1)]
    assert "error" in entry1
    assert entry1["derived_from"] == str(staged_image)

    # second derived file still processed normally despite the first raising
    entry2 = result["results"][str(carved2)]
    assert entry2["module"] == "evtx"
    assert entry2["events"] == 1

    # registration (hash/chmod/audit) still happened for the pathological file
    assert not (os.stat(carved1).st_mode & stat.S_IWUSR)
