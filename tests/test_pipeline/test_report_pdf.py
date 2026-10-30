"""Tests for optional Markdown→PDF report rendering (issue 9)."""

import pytest

from spectre.pipeline.report_pdf import render_pdf

_SAMPLE_MD = """# Spectre Forensic Report

## Executive Summary

- **Findings:** 1

## 1. Narrative

### F-001-001: Suspicious process

Some validated description.

## 2. MITRE ATT&CK Map

| Finding | Technique |
|---------|-----------|
| F-001-001 | T1059 |
"""


def _deps_available() -> bool:
    try:
        import markdown  # noqa: F401
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def test_render_pdf_never_raises(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(_SAMPLE_MD)
    pdf = tmp_path / "report.pdf"
    # Must return a tuple and never raise, regardless of dependency state.
    result = render_pdf(str(md), str(pdf))
    assert isinstance(result, tuple) and len(result) == 2


def test_render_pdf_skips_gracefully_without_deps(tmp_path):
    if _deps_available():
        pytest.skip("optional report deps are installed; skip-path not exercised")
    md = tmp_path / "report.md"
    md.write_text(_SAMPLE_MD)
    pdf = tmp_path / "report.pdf"
    path, reason = render_pdf(str(md), str(pdf))
    assert path is None
    assert reason and "report" in reason
    assert not pdf.exists()


def test_render_pdf_produces_valid_pdf_when_deps_present(tmp_path):
    if not _deps_available():
        pytest.skip("optional report extra not installed")
    md = tmp_path / "report.md"
    md.write_text(_SAMPLE_MD)
    pdf = tmp_path / "report.pdf"
    path, reason = render_pdf(str(md), str(pdf))
    assert path == str(pdf), reason
    assert pdf.exists()
    assert pdf.read_bytes().startswith(b"%PDF")


# ── Manifest-driven metadata + layout regression (report.md real shape) ──

_REAL_SHAPE_MD = """# Forensic Investigation Report

**Case Reference:** 073-smbtest
**Date:** 2026-07-02T00:00:00Z
**Evidence Examined:** Network Packet Capture (PCAP) (1 file(s))
**Classification:** DRAFT — pending examiner review

---

## Executive Summary

Analysis identified opportunistic scanning against the monitored host
(F-073-001). Attribution confidence: LOW.

### Key Indicators

| Type | Value | Findings | Ref Count |
|------|-------|----------|-----------|
| ip | `203.161.44.208` | F-073-001 | 1 |
| domain | `3416337616.round2026-03-09.odns.m.dnsmeasure.top` | F-073-002 | 1 |

## 1. Threat Narrative

All findings are INFERRED (single-source detection). Confidence: 0.60.

### F-073-001: Inbound scan

**Status:** CONFIRMED | **Confidence:** 0.60 | **MITRE:** T1595.002
**Timestamp:** 2026-03-11T00:30:00Z

**Forensic Caveats:**
- PCAP shows network I/O, not process execution or file writes

## 2. MITRE ATT&CK Map

| Technique ID | Technique Name | Finding IDs | Detection Rule |
|-------------|----------------|-------------|----------------|
| T1595.002 | Vulnerability Scanning | F-073-001 | pcap-exploit-probe |

## 3. Timeline

| Timestamp | Event | Finding |
|-----------|-------|---------|
| 2026-03-11 | Inbound scan | F-073-001 |

## 4. Forensic Blind Spots

| Question | Status | Why |
|----------|--------|-----|
| Was data exfiltrated? | UNVERIFIED | Full traffic content not inspected |

## 5. IOC Export

See iocs.csv.

## 6. Methodology

Automated pipeline, pcap profile, canary FULL.

---

## 7. Verdict

Opportunistic scanning; no evidence of successful compromise observed in
the examined traffic (F-073-001). Attribution confidence: LOW.

---

## Appendix: Finding Index

| Finding ID | Status | Confidence | MITRE | Title |
|------------|--------|------------|-------|-------|
| F-073-001 | CONFIRMED | 0.60 | T1595.002 | Inbound scan |
"""


@pytest.fixture
def pdf_manifest():
    return {
        "case_id": "073",
        "case_name": "smbtest",
        "artifact_profile": "pcap-focused",
        "canary_status": "FULL",
        "evidence": [{
            "sha256": "f30ab49b4c7417b23523ffc085b884de7449e12aba1c799e822fa3152f24be91",
            "evidence_path": "/cases/evidence/seven-days.pcap",
        }],
        "detection": {"findings": [
            {"finding_id": "F-073-001", "status": "CONFIRMED"},
        ]},
    }


def _render_and_read(tmp_path, manifest):
    fitz = pytest.importorskip("fitz")  # pymupdf — reader for assertions
    md = tmp_path / "report.md"
    md.write_text(_REAL_SHAPE_MD)
    out = tmp_path / "report.pdf"
    pdf_path, reason = render_pdf(str(md), str(out), manifest=manifest)
    assert pdf_path is not None, f"render failed: {reason}"
    return fitz.open(str(out))


def test_render_pdf_with_manifest_metadata(tmp_path, pdf_manifest):
    """Manifest-driven metadata: no '?-?' placeholders anywhere."""
    if not _deps_available():
        pytest.skip("optional report extra not installed")
    doc = _render_and_read(tmp_path, pdf_manifest)
    assert doc.page_count >= 3
    all_text = "\n".join(page.get_text() for page in doc)
    assert "?-?" not in all_text
    assert "073-smbtest" in all_text
    assert "pcap-focused" in all_text


def test_render_pdf_cover_carries_evidence(tmp_path, pdf_manifest):
    """Cover/doc-control shows evidence file and SHA-256 from the manifest."""
    if not _deps_available():
        pytest.skip("optional report extra not installed")
    doc = _render_and_read(tmp_path, pdf_manifest)
    first_pages = "\n".join(doc[i].get_text() for i in range(min(2, doc.page_count)))
    assert "seven-days.pcap" in first_pages
    assert "f30ab49b" in first_pages  # sha256 prefix


def test_render_pdf_fallback_regex_matches_real_header(tmp_path):
    """Without a manifest, the real report.md header format is parsed."""
    if not _deps_available():
        pytest.skip("optional report extra not installed")
    doc = _render_and_read(tmp_path, None)
    all_text = "\n".join(page.get_text() for page in doc)
    assert "?-?" not in all_text
    assert "073-smbtest" in all_text


def test_render_pdf_has_toc(tmp_path, pdf_manifest):
    """A contents block lists the numbered sections."""
    if not _deps_available():
        pytest.skip("optional report extra not installed")
    doc = _render_and_read(tmp_path, pdf_manifest)
    all_text = "\n".join(page.get_text() for page in doc)
    assert "Contents" in all_text
    assert "Threat Narrative" in all_text
    assert "Verdict" in all_text
