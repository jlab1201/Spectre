"""WS1b-prov: resolve_tool_version records the REAL installed tool version
(A1-H4) and degrades gracefully — never a garbage 'version', never a crash."""

import subprocess
import types


from spectre.pipeline import tool_runner
from spectre.pipeline.tool_runner import resolve_tool_version


def _fake_run(stdout="", stderr=""):
    def _run(cmd, capture_output=True, text=True, timeout=None):
        return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)
    return _run


def setup_function(_):
    resolve_tool_version.cache_clear()


def teardown_function(_):
    resolve_tool_version.cache_clear()


def test_records_real_dotted_version(monkeypatch):
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/tcpdump")
    monkeypatch.setattr(tool_runner.subprocess, "run",
                        _fake_run(stdout="tcpdump version 4.99.4\nlibpcap version 1.10.4\n"))
    assert resolve_tool_version("tcpdump", "--version", "tcpdump") == "tcpdump version 4.99.4"


def test_missing_binary_falls_back(monkeypatch):
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: None)
    assert resolve_tool_version("nope", "--version", "fallback-name") == "fallback-name"


def test_probe_crash_falls_back(monkeypatch):
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/x")

    def _boom(*a, **k):
        raise OSError("boom")

    monkeypatch.setattr(tool_runner.subprocess, "run", _boom)
    assert resolve_tool_version("x", "--version", "x-fallback") == "x-fallback"


def test_usage_header_without_version_is_rejected(monkeypatch):
    # A tool with an unexpected version flag prints a usage header (no dotted
    # version) — we must NOT record that as the version; fall back instead.
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/x")
    monkeypatch.setattr(tool_runner.subprocess, "run",
                        _fake_run(stderr="usage: x [options] file\n"))
    assert resolve_tool_version("x", "--bad", "x-fallback") == "x-fallback"


def test_timeout_falls_back(monkeypatch):
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/x")

    def _to(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=15)

    monkeypatch.setattr(tool_runner.subprocess, "run", _to)
    assert resolve_tool_version("x", "--version", "x-fallback") == "x-fallback"


# --- W4-6: volatility3 `vol --version` exits 2 (usage) → literal "volatility3"
# was recorded. The probe may be a multi-arg command, and the memory module
# must record the real framework version (or degrade honestly).

def test_multi_arg_probe_is_supported(monkeypatch):
    seen = {}

    def _run(cmd, capture_output=True, text=True, timeout=None):
        seen["cmd"] = cmd
        return types.SimpleNamespace(stdout="Volatility 3 Framework 2.28.0\n\nData\n",
                                     stderr="", returncode=0)

    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/vol")
    monkeypatch.setattr(tool_runner.subprocess, "run", _run)
    got = resolve_tool_version("vol", ("-q", "frameworkinfo.FrameworkInfo"), "volatility3")
    assert got == "Volatility 3 Framework 2.28.0"
    assert seen["cmd"] == ["/usr/bin/vol", "-q", "frameworkinfo.FrameworkInfo"]


def test_memory_module_records_real_vol_version(monkeypatch):
    import importlib
    mem_extract = importlib.import_module("spectre.modules.memory.extract")
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: "/usr/bin/vol")
    monkeypatch.setattr(tool_runner.subprocess, "run",
                        _fake_run(stdout="Volatility 3 Framework 2.28.0\n"))
    v = mem_extract.vol_version()
    assert v == "Volatility 3 Framework 2.28.0"
    assert any(c.isdigit() for c in v)


def test_memory_module_vol_absent_degrades_to_package_metadata(monkeypatch):
    import importlib
    mem_extract = importlib.import_module("spectre.modules.memory.extract")
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: None)
    monkeypatch.setattr(mem_extract, "_pkg_version", lambda: "2.28.0")
    assert mem_extract.vol_version() == "volatility3 2.28.0 (package metadata)"


def test_memory_module_vol_fully_unavailable_is_honest(monkeypatch):
    import importlib
    mem_extract = importlib.import_module("spectre.modules.memory.extract")
    monkeypatch.setattr(tool_runner.shutil, "which", lambda b: None)
    monkeypatch.setattr(mem_extract, "_pkg_version", lambda: "")
    assert mem_extract.vol_version() == "volatility3 (version unresolved)"
