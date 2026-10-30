"""W4-2 / R1-F5: confidence framing splits two deterministic axes.

Corroboration (single- vs multi-source) and detection strength (from rule
confidence: >=0.8 strong, 0.6-0.8 moderate, <0.6 weak). A 0.90 single-source
finding must NOT read "LOW", and nothing may imply multi-source corroboration
that does not exist.
"""

import re

from spectre.pipeline.report_synthesize import (
    _confidence_label,
    _detection_strength,
    _merge_report_md,
    _overall_confidence_banner,
)


def _f(fid, title, conf, mitre="T1071", **kw):
    d = {"finding_id": fid, "title": title, "confidence": conf,
         "mitre_attack": mitre, "status": "INFERRED", "iocs": {},
         "caveats": [], "description": "d"}
    d.update(kw)
    return d


def test_detection_strength_thresholds():
    assert _detection_strength(0.90) == "strong"
    assert _detection_strength(0.80) == "strong"
    assert _detection_strength(0.79) == "moderate"
    assert _detection_strength(0.60) == "moderate"
    assert _detection_strength(0.59) == "weak"
    assert _detection_strength(None) == "weak"


def test_label_strong_single_source():
    assert _confidence_label([_f("F-1", "x", 0.9)]) == "Strong single-source indicator"


def test_label_multi_source_only_from_corroborated_findings():
    # The strong finding is single-source; the corroborated one is weak.
    # The multi-source claim must be graded by the corroborated finding only.
    fs = [_f("F-1", "x", 0.9), _f("F-2", "x", 0.5, cross_validated=True)]
    assert _confidence_label(fs) == "Weak multi-source indicator"


def test_banner_single_source_high_confidence_is_not_low():
    fs = [_f("F-1", "a", 0.9), _f("F-2", "b", 0.85), _f("F-3", "c", 0.4)]
    b = _overall_confidence_banner(fs)
    assert "LOW" not in b
    assert b.startswith("Strong single-source indicator")
    assert "0 of 3" in b
    assert "multi-source" not in b


def test_banner_multi_source():
    fs = [_f("F-1", "a", 0.9, cross_validated=True), _f("F-2", "b", 0.5)]
    b = _overall_confidence_banner(fs)
    assert b.startswith("Strong multi-source indicator")
    assert "1 of 2" in b


def test_banner_no_findings():
    assert _overall_confidence_banner([]) == "No findings"


def _table(md):
    sec = md.split("### Confidence Assessment", 1)[1].lstrip("\n")
    return [ln for ln in sec.split("\n\n", 1)[0].splitlines() if ln.startswith("| ")]


def test_table_rows_carry_ids_and_collapse_duplicate_titles(tmp_path):
    fs = [_f(f"F-9-00{i}", "AD recon via SMB named pipe: \\lsarpc", 0.7,
             mitre=m) for i, m in enumerate(["T1087", "T1069", "T1482"], 1)]
    fs.append(_f("F-9-010", "NetSupport UA C2 fingerprint", 0.85))
    md = _merge_report_md(None, fs, {"case_id": "9", "case_name": "t"},
                          str(tmp_path), [], {})
    rows = _table(md)[1:]  # skip header (separator has no "| " prefix)
    recon = [r for r in rows if "AD recon via SMB named pipe" in r]
    assert len(recon) == 1
    for fid in ("F-9-001", "F-9-002", "F-9-003"):
        assert fid in recon[0]
    assert "Moderate single-source indicator" in recon[0]
    ns = [r for r in rows if "NetSupport" in r]
    assert len(ns) == 1 and "F-9-010" in ns[0]
    assert "Strong single-source indicator" in ns[0]
    assert not any(re.search(r"\|\s*LOW\s*\|", r) for r in rows)
    assert "multi-source" not in "\n".join(rows)
    banner = [ln for ln in md.splitlines() if ln.startswith("**Overall Confidence:**")]
    assert banner and "Strong single-source indicator" in banner[0]
