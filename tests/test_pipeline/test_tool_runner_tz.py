"""WS4 sub-task 2 (A6 Finding 1) — run_tool must pin every subprocess it
launches to TZ=UTC, regardless of the analyst's ambient shell timezone.
Without this, tcpdump/tshark (and any other tool whose output embeds a
local-clock rendering) silently leak the analysis-workstation's timezone
into evidence timestamps — a courtroom-facing forensic report must never
depend on where the analyst happened to be sitting.

This is the CUTOVER: only NEW runs are affected; no existing case output
is rewritten.
"""
import sys

from spectre.pipeline.tool_runner import run_tool


def _case(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    return str(case)


def test_run_tool_pins_child_tz_to_utc_regardless_of_ambient_tz(tmp_path, monkeypatch):
    """The subprocess must see TZ=UTC even when the analyst's shell has TZ
    set to something else entirely (America/New_York here)."""
    monkeypatch.setenv("TZ", "America/New_York")
    out = str(tmp_path / "out.txt")
    handle = run_tool(
        case_dir=_case(tmp_path), tool_name="python", tool_version="3",
        command=[sys.executable, "-c", "import os; print(os.environ.get('TZ'))"],
        params={"artifact_type": "test", "phase": "extraction"},
        output_path=out,
    )
    assert handle["result"] == "success"
    from pathlib import Path
    assert Path(out).read_text().strip() == "UTC"


def test_run_tool_preserves_other_ambient_env_vars(tmp_path, monkeypatch):
    """Pinning TZ must not blow away the rest of the child's environment —
    only TZ is overridden, everything else (PATH, and whatever else the
    analyst's shell carries) still reaches the child unchanged."""
    monkeypatch.setenv("TZ", "America/New_York")
    monkeypatch.setenv("SPECTRE_TEST_MARKER", "hello-from-parent")
    out = str(tmp_path / "out.txt")
    handle = run_tool(
        case_dir=_case(tmp_path), tool_name="python", tool_version="3",
        command=[sys.executable, "-c",
                 "import os; print(os.environ.get('SPECTRE_TEST_MARKER'))"],
        params={"artifact_type": "test", "phase": "extraction"},
        output_path=out,
    )
    assert handle["result"] == "success"
    from pathlib import Path
    assert Path(out).read_text().strip() == "hello-from-parent"
