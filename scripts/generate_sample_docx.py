#!/usr/bin/env python3
"""Generate a sample.docx from a full-coverage fixture report.md, for
manual visual review of the Hairline DOCX template (Phase 1 of the
DOCX report renderer plan). Run with the 'report' extra installed:

    pip install -e ".[report]"
    python scripts/generate_sample_docx.py

Output: sample.docx in the current directory.
"""
from spectre.pipeline.report_docx import render_docx

_SAMPLE_MD = """# Forensic Investigation Report

**Case Reference:** 073-smbtest
**Date:** 2026-07-02T00:00:00Z
**Evidence Examined:** Network Packet Capture (PCAP) (1 file(s))
**Classification:** DRAFT — pending examiner review

---

## Executive Summary

Analysis identified opportunistic scanning against the monitored host
(F-073-001), corroborated by two independent detection methods.
Attribution confidence: LOW.

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

### F-073-002: Suspicious DNS beacon

**Status:** INFERRED | **Confidence:** 0.45 | **MITRE:** T1071.004
**Timestamp:** 2026-03-11T00:31:00Z

**Forensic Caveats:**
- Single-source detection; no corroborating memory or endpoint evidence

## 2. MITRE ATT&CK Map

| Technique ID | Technique Name | Finding IDs | Detection Rule |
|-------------|----------------|-------------|----------------|
| T1595.002 | Vulnerability Scanning | F-073-001 | pcap-exploit-probe |
| T1071.004 | Application Layer Protocol: DNS | F-073-002 | pcap-dns-anomaly |

## 3. Timeline

| Timestamp | Event | Finding |
|-----------|-------|---------|
| 2026-03-11 | Inbound scan | F-073-001 |
| 2026-03-11 | Suspicious DNS beacon | F-073-002 |

## 4. Forensic Blind Spots

| Question | Status | Why |
|----------|--------|-----|
| Was data exfiltrated? | UNVERIFIED | Full traffic content not inspected |
| Are there additional malicious processes? | UNVERIFIED | No memory dump available |

## 5. IOC Export

| Type | Value | Finding ID | Confidence |
|------|-------|------------|------------|
| ip | 203.161.44.208 | F-073-001 | 0.60 |
| domain | 3416337616.round2026-03-09.odns.m.dnsmeasure.top | F-073-002 | 0.45 |

## 6. Methodology

- **Network Traffic Analysis:** Packet capture was inspected for
  connections to known-malicious ports, statistical beacon patterns, and
  DNS anomalies.

**Evidence Sources:** pcap.

*All observations are based on automated forensic analysis and require
examiner validation.*
"""

_SAMPLE_MANIFEST = {
    "case_id": "073",
    "case_name": "smbtest",
    "artifact_profile": "pcap-focused",
    "canary_status": "FULL",
    "evidence": [{
        "evidence_path": "/cases/evidence/seven-days.pcap",
        "sha256": "f30ab49b4c7417b23523ffc085b884de7449e12aba1c799e822fa3152f24be91",
    }],
    "gate_7": {"passed": False},
}

if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(_SAMPLE_MD)
        md_path = f.name

    path, reason = render_docx(
        md_path, "sample.docx",
        title="Spectre Forensic Report — 073-smbtest",
        manifest=_SAMPLE_MANIFEST,
    )
    if path:
        print(f"Wrote {path} — open it in Word to review the Hairline template.")
    else:
        print(f"Failed: {reason}")
