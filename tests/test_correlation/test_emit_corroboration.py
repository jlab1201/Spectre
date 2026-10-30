"""emit_from_handle honors a caller-supplied corroboration result.

Locks the seam between the correlation layer and finding emission: when two
sources asserted the same claim, the written finding must read CONFIRMED, carry
the source labels, flag cross_validated, and cite BOTH tool_exec rows.
"""

import yaml

from spectre.pipeline.emit_finding import emit_from_handle


def _yaml(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data))
    return str(p)


def _case(tmp_path):
    (tmp_path / "findings").mkdir()
    return str(tmp_path)


def test_two_sources_emit_confirmed_cross_validated_finding(tmp_path):
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": ["not a smoking gun"]})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "vol-exec-aaa", "tool": "volatility3",
              "line_count": 5, "path": "/x/pslist.json"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-MASQ-01", title="rundll32 masquerade",
        sources=2,
        corroboration_labels=["memprocfs/memory_pslist",
                              "volatility3/memory_pslist"],
        extra_evidence_refs=[{"execution_id": "mpfs-exec-bbb"}],
    )

    assert finding["status"] == "CONFIRMED"
    assert finding["confidence"] == 0.75
    assert finding["cross_validated"] is True
    assert finding["corroboration"]["sources"] == 2
    assert finding["corroboration"]["tools"] == ["memprocfs/memory_pslist",
                                                 "volatility3/memory_pslist"]
    eids = {r["execution_id"] for r in finding["evidence_refs"]}
    assert eids == {"vol-exec-aaa", "mpfs-exec-bbb"}


def test_single_source_stays_inferred(tmp_path):
    fk = _yaml(tmp_path, "fk.yaml", {"does_NOT_prove": []})
    mitre = _yaml(tmp_path, "mitre.yaml", {"rules": {}, "fallback": "UNMAPPED"})
    handle = {"execution_id": "vol-exec-aaa", "tool": "volatility3",
              "line_count": 5, "path": "/x/pslist.json"}

    finding = emit_from_handle(
        handle=handle, case_dir=_case(tmp_path), finding_number=1,
        fk_yaml_path=fk, mitre_map_path=mitre,
        rule_id="MEM-MASQ-01", title="rundll32 masquerade",
        sources=1, corroboration_labels=["volatility3/memory_pslist"],
    )

    assert finding["status"] == "INFERRED"
    assert finding["confidence"] == 0.50
    assert finding["cross_validated"] is False
    assert len(finding["evidence_refs"]) == 1
