"""Runner entry modes: --case/--from-phase argument rules and Gate 0 in full mode."""
import pytest

from spectre.pipeline import runner


def _boom(*a, **kw):
    raise AssertionError("must not be called")


def test_case_without_phase_errors(tmp_path, monkeypatch):
    from spectre.pipeline import case_setup
    monkeypatch.setattr(case_setup, "setup_case", _boom)
    monkeypatch.setattr("sys.argv", ["spectre", "--case", str(tmp_path)])
    with pytest.raises(SystemExit) as e:
        runner.main()
    assert e.value.code == 2


def test_from_phase_without_case_errors(monkeypatch):
    from spectre.pipeline import case_setup
    monkeypatch.setattr(case_setup, "setup_case", _boom)
    monkeypatch.setattr("sys.argv", ["spectre", "--name", "x", "--from-phase", "3"])
    with pytest.raises(SystemExit) as e:
        runner.main()
    assert e.value.code == 2


def test_full_pipeline_stops_when_gate0_fails(tmp_path, monkeypatch):
    from spectre.pipeline import case_setup
    monkeypatch.setattr(case_setup, "setup_case", lambda **kw: {
        "success": True, "case_dir": str(tmp_path), "case_id": "001",
        "canary_status": "FULL"})
    monkeypatch.setattr(runner, "_load_manifest", lambda d: {})
    monkeypatch.setattr(runner, "run_phase_0", lambda d, m: {"success": False})
    monkeypatch.setattr(runner, "run_phases_range", _boom)
    monkeypatch.setattr("sys.argv", ["spectre", "--name", "x"])
    with pytest.raises(SystemExit) as e:
        runner.main()
    assert e.value.code == 1
