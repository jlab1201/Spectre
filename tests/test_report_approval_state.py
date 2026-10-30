"""The report classification derives from the findings' ACTUAL examiner
approval state (approval.py / `spectre approve`), not from gate_7 alone: a
PDF/DOCX re-rendered after Phase 7 must not say APPROVED while findings still
await an examiner decision. Consistent across report_synthesize, report_pdf
and report_docx."""
from __future__ import annotations


import pytest
import yaml

from spectre.pipeline.report_synthesize import (
    approval_state,
    classification_for,
    load_approval_state,
    classification_status_line,
)
from spectre.pipeline.report_pdf import (
    _build_cover_html,
    _build_doc_control,
    _classification,
)


def _fs(*decisions):
    return [{"finding_id": f"F-1-00{i}", **({"approval": d} if d else {})}
            for i, d in enumerate(decisions, 1)]


def test_approval_state_counts_decisions():
    st = approval_state(_fs("APPROVED", None, "REJECTED", "bogus"))
    assert (st["decided"], st["total"], st["all_decided"]) == (2, 4, False)
    assert st["pending"] == ["F-1-002", "F-1-004"]
    assert approval_state(_fs("APPROVED", "SUPERSEDED"))["all_decided"] is True


def test_load_approval_state_reads_active_findings_only(tmp_path):
    fd = tmp_path / "findings"
    (fd / "excluded").mkdir(parents=True)
    (fd / "F-1-001.yaml").write_text(yaml.safe_dump({"finding_id": "F-1-001",
                                                      "approval": "APPROVED"}))
    (fd / "F-1-002.yaml").write_text(yaml.safe_dump({"finding_id": "F-1-002"}))
    (fd / "excluded" / "F-1-003.yaml").write_text(yaml.safe_dump({"finding_id": "F-1-003"}))
    st = load_approval_state(str(tmp_path))
    assert (st["decided"], st["total"]) == (1, 2)
    assert load_approval_state(str(tmp_path / "nope")) is None


@pytest.mark.parametrize("gate7, decisions, want", [
    (True, ("APPROVED", None), "DRAFT"),          # the bug: gate_7 but pending
    (True, ("APPROVED", "REJECTED"), "APPROVED"),
    (False, ("APPROVED", "APPROVED"), "DRAFT"),   # Phase 7 verification not passed
])
def test_classification_for(gate7, decisions, want):
    man = {"gate_7": {"passed": gate7}}
    assert classification_for(man, approval_state(_fs(*decisions))) == want


def test_unknown_approval_state_is_draft():
    assert classification_for({"gate_7": {"passed": True}}, None) == "DRAFT"
    assert _classification({"gate_7": {"passed": True}}) == "DRAFT"


def test_status_line_carries_counts():
    st = approval_state(_fs("APPROVED", None, None))
    assert classification_status_line("DRAFT", st) == \
        "Pending Examiner Approval (1 of 3 decided)"
    done = approval_state(_fs("APPROVED"))
    assert classification_status_line("APPROVED", done) == \
        "Examiner Approved (Phase 7) — 1 of 1 decided"
    assert classification_status_line("DRAFT", None) == "Pending Examiner Approval"


def _man(decisions):
    return {"case_id": "1", "case_name": "t", "gate_7": {"passed": True},
            "_approval_state": approval_state(_fs(*decisions))}


def test_pdf_cover_and_doc_control_pending_after_phase7():
    man = _man(("APPROVED", None, None))
    cover, ctrl = _build_cover_html(man, None), _build_doc_control(man)
    for html in (cover, ctrl):
        assert "APPROVED" not in html.replace("(1 of 3 decided)", "")
        assert "Pending Examiner Approval (1 of 3 decided)" in html


def test_pdf_cover_approved_when_all_decided():
    man = _man(("APPROVED", "REJECTED"))
    assert "Examiner Approved (Phase 7) — 2 of 2 decided" in _build_cover_html(man, None)


def _case_with_report(tmp_path, decisions):
    case = tmp_path / "001-t"
    (case / "findings").mkdir(parents=True)
    (case / "reports").mkdir()
    for f in _fs(*decisions):
        (case / "findings" / f"{f['finding_id']}.yaml").write_text(yaml.safe_dump(f))
    md = case / "reports" / "report.md"
    md.write_text("# Spectre Forensic Investigation Report\n\n## Executive Summary\n\ntext\n")
    return case, md


def test_render_pdf_rerender_after_phase7_is_draft(tmp_path):
    pytest.importorskip("weasyprint")
    from spectre.pipeline.report_pdf import render_pdf
    case, md = _case_with_report(tmp_path, ("APPROVED", None))
    man = {"case_id": "001", "case_name": "t", "gate_7": {"passed": True}}
    out, reason = render_pdf(str(md), str(case / "reports" / "r.pdf"), manifest=man)
    assert out, reason
    import subprocess
    txt = subprocess.run(["pdftotext", out, "-"], capture_output=True, text=True).stdout
    assert "Pending Examiner Approval (1 of 2 decided)" in txt
    assert "Examiner Approved" not in txt
    assert "_approval_state" not in man   # the caller's manifest is not mutated


def test_render_docx_rerender_after_phase7_is_draft(tmp_path):
    docx = pytest.importorskip("docx")
    from spectre.pipeline.report_docx import render_docx
    case, md = _case_with_report(tmp_path, ("APPROVED", None))
    man = {"case_id": "001", "case_name": "t", "gate_7": {"passed": True}}
    out, reason = render_docx(str(md), str(case / "reports" / "r.docx"), manifest=man)
    assert out, reason
    d = docx.Document(out)
    text = "\n".join(p.text for p in d.paragraphs)
    for t in d.tables:
        text += "\n".join(c.text for r in t.rows for c in r.cells)
    for sec in d.sections:
        text += "\n".join(p.text for p in sec.footer.paragraphs)
    assert "1 of 2 decided" in text
    assert "APPROVED" not in text.replace("DRAFT", "")
    # all decided → APPROVED
    case2, md2 = _case_with_report(tmp_path / "b", ("APPROVED", "APPROVED"))
    out2, _ = render_docx(str(md2), str(case2 / "reports" / "r.docx"), manifest=dict(man))
    d2 = docx.Document(out2)
    assert any("APPROVED" in p.text for p in d2.paragraphs) or any(
        "APPROVED" in c.text for t in d2.tables for r in t.rows for c in r.cells)


def test_report_md_classification_line_states_counts(tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    man = {"case_id": "1", "case_name": "t"}
    md = _merge_report_md(None, _fs(None, None), man, str(tmp_path), [], {})
    # report.md is hash-bound at Phase 6, so the line is explicitly a
    # generation-time snapshot; the rendered cover/doc-control carry the
    # live state (a later `spectre approve` changes those, not this).
    assert ("**Classification:** DRAFT — pending examiner review (as of report "
            "generation: 0 of 2 findings decided)") in md
