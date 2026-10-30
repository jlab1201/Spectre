"""WS4 sub-task 5 (A6 Finding 5) — disk/extract.py's `fls` invocation must
pass -z UTC. FAT/exFAT on-disk timestamps are local wall-clock with no
embedded offset; without -z, TSK's epoch conversion for those filesystems
depends on the analysis host's ambient timezone (NTFS is unaffected since
its on-disk FILETIME fields are already true UTC, but the flag is harmless
there — same defect class as A6 Finding 1, applied to disk evidence).
"""
import importlib

# importlib, not `import ... as`: the package re-exports the extract FUNCTION
# under the same name, shadowing the submodule.
disk_extract = importlib.import_module("spectre.modules.disk.extract")
extract = disk_extract.extract


def test_fls_command_includes_utc_timezone_flag(tmp_path, monkeypatch):
    # Only the command extract() BUILDS is under test, so stub the runner:
    # the assertion must not depend on Sleuth Kit being installed on the host.
    monkeypatch.setattr(disk_extract, "run_tool",
                        lambda **kw: {"result": "error", "exit_code": 1})
    case = tmp_path / "case"
    case.mkdir()
    ev = tmp_path / "disk.dd"
    ev.write_bytes(b"\x00" * 1024)

    handles = extract(str(case), str(ev))
    fls_handles = [h for h in handles if h.get("tool") == "fls"]
    assert len(fls_handles) == 1
    command = fls_handles[0]["exact_command"]
    assert "-z" in command.split()
    zone = command.split()[command.split().index("-z") + 1]
    assert zone == "UTC"
