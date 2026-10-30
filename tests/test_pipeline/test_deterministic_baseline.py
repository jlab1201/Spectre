from spectre.pipeline.report_synthesize import deterministic_baseline_banner
from spectre.pipeline.report_pdf import _build_cover_html


def test_banner_is_loud_and_unmissable():
    b = deterministic_baseline_banner()
    assert "DETERMINISTIC BASELINE" in b
    assert "NO AI NARRATIVE" in b
    # markdown callout / heading so it renders prominently
    assert b.strip().startswith(("#", ">"))


def test_cover_shows_baseline_badge_when_ai_narrative_false():
    manifest = {"case_id": "001", "case_name": "x",
                "report": {"ai_narrative": False}}
    html = _build_cover_html(manifest)
    assert "DETERMINISTIC BASELINE" in html


def test_cover_has_no_baseline_badge_when_ai_used():
    manifest = {"case_id": "001", "case_name": "x",
                "report": {"ai_narrative": True}}
    html = _build_cover_html(manifest)
    assert "DETERMINISTIC BASELINE" not in html
