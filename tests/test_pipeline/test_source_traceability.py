"""WS1b-prov (A1-M1): a finding carries structured source_record_id/source_file
so it can be traced back to a specific record in a specific raw_extract file,
regardless of whether the rule author mentioned it in the free-text summary."""

import tempfile
import os

import yaml

from spectre.pipeline.emit_finding import emit_from_handle
from spectre.config import FK_WINDOWS_DIR, MITRE_MAP_PATH


def _case():
    d = tempfile.mkdtemp(prefix="spectre-trace-")
    for sub in ("findings", "raw_extract", "reports", "evidence"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return d


def test_finding_carries_structured_record_id_and_source_file():
    case_dir = _case()
    handle = {"execution_id": "", "tool": "evtxexport", "tool_version": "x",
              "path": "raw_extract/x.xml", "line_count": 1, "exact_command": ""}
    finding = emit_from_handle(
        handle=handle,
        case_dir=case_dir,
        finding_number=1,
        fk_yaml_path=str(FK_WINDOWS_DIR / "evtx_4688.yaml"),
        mitre_map_path=str(MITRE_MAP_PATH),
        rule_id="rundll32-from-temp",
        title="Executable staged in a temp directory",
        iocs={"filepath": ["C:\\Windows\\Temp\\evil.dll"]},
        source_record_id="5093",
        source_file="Security.evtx",
        sources=1,
    )
    # Present on the returned dict...
    assert finding["source_record_id"] == "5093"
    assert finding["source_file"] == "Security.evtx"
    # ...and persisted to the finding YAML on disk (structured, not free-text).
    path = os.path.join(case_dir, "findings", f"{finding['finding_id']}.yaml")
    on_disk = yaml.safe_load(open(path))
    assert on_disk["source_record_id"] == "5093"
    assert on_disk["source_file"] == "Security.evtx"


def test_traceability_defaults_are_empty_not_missing():
    case_dir = _case()
    handle = {"execution_id": "", "tool": "t", "tool_version": "x",
              "path": "raw_extract/x", "line_count": 1, "exact_command": ""}
    finding = emit_from_handle(
        handle=handle, case_dir=case_dir, finding_number=1,
        fk_yaml_path=str(FK_WINDOWS_DIR / "evtx_4688.yaml"),
        mitre_map_path=str(MITRE_MAP_PATH),
        rule_id="rundll32-from-temp", title="t", sources=1,
    )
    # The keys always exist (uniform schema), defaulting to "".
    assert finding["source_record_id"] == ""
    assert finding["source_file"] == ""
