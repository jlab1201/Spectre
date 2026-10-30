"""test_extract_filenames.py — raw extraction filenames follow
{ts}_{engine}_{artifact}[_{slug}] under raw_extract/.

Engine tag is symmetric and leads the name; the doubled artifact segment
(`pslist_memory_pslist`) is gone; a slug is kept only for multi-output plugins
(printkey). run_tool is stubbed so no real tool runs — we only assert the
output_path each extractor hands to run_tool.
"""

import importlib
import re
from pathlib import Path



def _capture(monkeypatch, module):
    """Stub the module's run_tool to record output_path; return a stub handle."""
    paths: list[str] = []

    def stub(*args, **kwargs):
        paths.append(kwargs["output_path"])
        return {"output_path": kwargs["output_path"]}

    monkeypatch.setattr(module, "run_tool", stub)
    return paths


def _mod(dotted):
    # import_module (not `from pkg import extract`) so we get the *module*, not
    # the extract() function the package __init__ re-exports under that name.
    return importlib.import_module(dotted)


def test_vol_filenames_symmetric_no_doubling(monkeypatch, tmp_path):
    vol = _mod("spectre.modules.memory.extract")
    monkeypatch.setattr(vol, "SYMBOLS_DIR", tmp_path / "sym")
    paths = _capture(monkeypatch, vol)

    vol.extract(str(tmp_path), "/evidence/mem.raw")
    names = [Path(p).name for p in paths]
    assert names

    assert all(re.match(r"^\d{8}_\d{6}_vol_", n) for n in names), names
    assert not any("pslist_memory_pslist" in n for n in names), names
    assert any(re.fullmatch(r"\d{8}_\d{6}_vol_memory_pslist\.json", n)
               for n in names), names
    assert any(re.fullmatch(r"\d{8}_\d{6}_vol_memory_url\.json", n)
               for n in names), names

    regkeys = [n for n in names if "regkey" in n]
    assert regkeys, names
    assert all(n.count("regkey") == 1 for n in regkeys), regkeys
    assert all(re.fullmatch(r"\d{8}_\d{6}_vol_memory_regkey_.+\.json", n)
               for n in regkeys), regkeys


def test_disk_filenames_engine_first(monkeypatch, tmp_path):
    disk = _mod("spectre.modules.disk.extract")
    paths = _capture(monkeypatch, disk)

    disk.extract(str(tmp_path), "/evidence/disk001.img")
    names = sorted(Path(p).name for p in paths)

    assert any(re.fullmatch(r"\d{8}_\d{6}_mmls_disk001\.txt", n) for n in names), names
    assert any(re.fullmatch(r"\d{8}_\d{6}_fls_disk001\.txt", n) for n in names), names
    assert all(Path(p).parent.name == "raw_extract" for p in paths), paths


def test_evtx_filename_engine_first(monkeypatch, tmp_path):
    evtx = _mod("spectre.modules.evtx.extract")
    paths = _capture(monkeypatch, evtx)

    evtx.extract(str(tmp_path), "/evidence/security.evtx")
    name = Path(paths[0]).name

    assert re.fullmatch(r"\d{8}_\d{6}_evtx_security\.xml", name), name
    assert Path(paths[0]).parent.name == "raw_extract"


def test_pcap_filename_engine_first(monkeypatch, tmp_path):
    pcap = _mod("spectre.modules.pcap.extract")
    # This asserts the tcpdump/tshark (manual/fallback) filename convention,
    # so pin the manual engine — otherwise, with Zeek installed, extract()
    # takes the Zeek-primary path and the first pass is no longer connections.
    monkeypatch.setattr(pcap, "PCAP_ENGINE", "manual")
    paths = _capture(monkeypatch, pcap)

    pcap.extract(str(tmp_path), "/evidence/capture.pcap")
    name = Path(paths[0]).name

    assert re.fullmatch(r"\d{8}_\d{6}_tcpdump_conn_capture\.txt", name), name
    assert Path(paths[0]).parent.name == "raw_extract"


def test_pcap_checksum_pass_filename_and_command(monkeypatch, tmp_path):
    pcap = _mod("spectre.modules.pcap.extract")
    monkeypatch.setattr(pcap, "PCAP_ENGINE", "manual")
    paths = _capture(monkeypatch, pcap)

    pcap.extract(str(tmp_path), "/evidence/capture.pcap")
    names = [Path(p).name for p in paths]

    assert any(re.fullmatch(r"\d{8}_\d{6}_tcpdump_checksum_capture\.txt", n)
               for n in names), names


def test_memory_carve_urls_handle_is_flagged_auxiliary(monkeypatch, tmp_path):
    vol = _mod("spectre.modules.memory.extract")
    monkeypatch.setattr(vol, "SYMBOLS_DIR", tmp_path / "sym")
    monkeypatch.setattr(vol, "run_tool", lambda *a, **k: {"output_path": k["output_path"]})
    handles = vol.extract(str(tmp_path), "/evidence/mem.raw")
    carve = [h for h in handles if h.get("tool") == "carve_urls"]
    assert len(carve) == 1 and carve[0]["auxiliary"] is True
    assert not any(h.get("auxiliary") for h in handles if h.get("tool") != "carve_urls")
