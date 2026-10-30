"""WS1 — regression tests for the four defects that made the MemProcFS
integration nominal rather than real.

Every test here failed before the corresponding fix. They are grouped by
defect, not by module, because each defect spans a seam:

  1. spectre-memory imported the volatility-only extractor, so the CLI
     raised TypeError on every invocation regardless of --engine.
  2. MemProcFS writes the registry value under the key "Value"; normalize
     read only "Data", so every MemProcFS autostart artifact was extracted,
     hashed, audited -- and then silently discarded at the rule layer.
  3. Handles shipped output_sha256 = "" and were hashed later in the PARENT
     process, after the producing subprocess had already exited.
  4. Rule summaries hardcoded "vol ..." regardless of the engine that
     actually produced the event, so a MemProcFS-sourced finding contradicted
     its own corroboration.tools list.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time

import pytest

import spectre.modules.memory.rules as memrules
from spectre.core.base import NormEvent
# NOTE: `spectre.modules.memory.normalize` is shadowed by the function the
# package re-exports under the same name, so import the function directly.
from spectre.modules.memory.normalize import normalize


# ── Defect 1: the spectre-memory CLI could never run ──────────────────────

def test_cli_calls_the_dispatcher_not_the_vol_only_extractor(tmp_path, monkeypatch):
    """spectre_memory.main() must reach the package-level extract(), which
    accepts `engine`. The vol-only extract() takes (case_dir, evidence_path)
    and raised TypeError for every --engine value, including the default.
    """
    import spectre.modules.memory as memmod
    from spectre.pipeline import spectre_memory

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    evidence = tmp_path / "dump.raw"
    evidence.write_bytes(b"\x00" * 64)

    seen: dict = {}

    def _fake_extract(cd, ev, engine="both"):
        seen["case_dir"], seen["evidence"], seen["engine"] = cd, ev, engine
        return []

    monkeypatch.setattr(memmod, "extract", _fake_extract)
    monkeypatch.setattr(sys, "argv", [
        "spectre-memory", "--case", str(case_dir),
        "--evidence", str(evidence), "--engine", "memprocfs",
        "--json", "--no-audit",
    ])

    with pytest.raises(SystemExit) as exc:  # main() exits on completion
        spectre_memory.main()

    assert exc.value.code == 0
    assert seen["engine"] == "memprocfs", (
        "the CLI did not forward --engine to the dispatcher")


# ── Defect 2: MemProcFS registry values were discarded ────────────────────

def _regkey_handle(tmp_path, rows) -> dict:
    p = tmp_path / "regkey.json"
    p.write_text(json.dumps(rows))
    return {"artifact_type": "memory_regkey", "path": str(p),
            "evidence_path": "/ev/dump.raw"}


@pytest.mark.parametrize("row,engine", [
    # volatility3 printkey shape
    ({"Key": r"\SystemRoot\System32\Config\SOFTWARE\Microsoft\Windows"
             r"\CurrentVersion\Run",
      "Name": "Updater", "Type": "REG_SZ",
      "Data": r"C:\Users\jaffa\AppData\evil.exe"}, "volatility3"),
    # MemProcFS FUSE shape -- note the key is "Value", not "Data"
    ({"Key": "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
      "Name": "Updater", "Type": "REG_SZ",
      "Value": r"C:\Users\jaffa\AppData\evil.exe"}, "memprocfs"),
])
def test_registry_value_survives_normalize_from_either_engine(
        tmp_path, row, engine):
    events = normalize(_regkey_handle(tmp_path, [row]))
    assert len(events) == 1
    assert events[0].data["value_data"] == r"C:\Users\jaffa\AppData\evil.exe", (
        f"{engine}: the autostart value was dropped during normalize")


def test_registry_persistence_rule_fires_on_a_memprocfs_row(tmp_path):
    """The rule early-returns on empty value_data, so defect 2 meant no
    MemProcFS autostart artifact could ever produce a finding."""
    row = {"Key": "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
           "Name": "Updater", "Type": "REG_SZ",
           "Value": r"C:\Users\jaffa\AppData\evil.exe"}
    event = normalize(_regkey_handle(tmp_path, [row]))[0]
    event.source_tool = "memprocfs"

    anchor = memrules.registry_persistence(event)

    assert anchor is not None, "memprocfs autostart row produced no anchor"
    assert anchor.rule_id == "memory-registry-persistence"


# ── Defect 3: handles were unhashed by their producer ─────────────────────

def test_make_handle_hashes_its_own_output(tmp_path):
    """The producing process must record the digest of what it just wrote.
    Hashing in the parent afterwards is a TOCTOU gap in the custody chain.
    """
    from spectre.modules.memory import extract_memprocfs as mpfs

    payload = [{"PID": 4, "ImageFileName": "System"}]
    out = tmp_path / "20260101_000000_mpfs_memory_pslist.json"
    body = json.dumps(payload, indent=2)
    out.write_text(body)

    handle = mpfs._make_handle(
        output_path=str(out), evidence_path="/ev/dump.raw",
        artifact_type="memory_pslist", row_count=len(payload),
        cmd_desc="memprocfs FUSE sys/proc", start_time=time.time())

    assert handle["output_sha256"] == hashlib.sha256(
        body.encode()).hexdigest()


# ── Defect 4: summaries misattributed the producing engine ────────────────

def _pslist_event(source_tool: str) -> NormEvent:
    return NormEvent(
        artifact_type="memory_pslist", timestamp="2019-08-19T14:40:07+00:00",
        source_file="/ev/dump.raw", record_id="0", source_tool=source_tool,
        data={"pid": 1944, "ppid": 608, "image": "scvhost.exe",
              "image_basename": "scvhost.exe", "parent_image": "svchost.exe",
              "instance_count": 1, "create_time": "2019-08-19T14:40:07+00:00",
              "exit_time": ""},
    )


def test_summary_names_the_engine_that_actually_produced_the_event():
    vol = memrules.masquerade_system_process(_pslist_event("volatility3"))
    mpfs = memrules.masquerade_system_process(_pslist_event("memprocfs"))

    assert vol is not None and mpfs is not None
    assert "volatility3" in vol.summary
    assert "memprocfs" in mpfs.summary
    assert "memprocfs" not in vol.summary
    assert not mpfs.summary.startswith("vol "), (
        "a memprocfs-sourced finding still claims volatility provenance")
