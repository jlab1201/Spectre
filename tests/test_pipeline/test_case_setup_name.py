from pathlib import Path

import yaml

from spectre.pipeline import case_setup


def test_case_name_survives_unavailable_modules(monkeypatch, tmp_path):
    monkeypatch.setattr(
        case_setup, "_run_canary",
        lambda case_dir: {"status": "DEGRADED", "passed": 1, "failed": 1,
                          "modules": {"pcap": {"available": False,
                                               "detail": "x"}}})
    result = case_setup.setup_case(
        name="my-case", profile="fixture-test", cases_dir=tmp_path)
    case_dir = Path(result["case_dir"])
    assert case_dir.name.endswith("-my-case")
    assert result["case_name"] == "my-case"
    manifest = yaml.safe_load(Path(result["manifest_path"]).read_text())
    assert manifest["case_name"] == "my-case"
