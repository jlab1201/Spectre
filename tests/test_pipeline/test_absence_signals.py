"""
test_absence_signals.py — Task 3 (D4): cross-artifact absence signals.

_absence_signals(findings, manifest) produces grounded negatives ("no
outbound connections observed") ONLY when the relevant plugin/artifact was
actually examined (manifest["detection"]["plugins_run"] — written by Phase 3
from the extraction handles; see phase_runner.py's `plugins_run` block).
Absence-of-examination must never read as a grounded negative, and a
positive finding for a category must suppress that category's signal.
"""

from spectre.pipeline.report_synthesize import _absence_signals


def _f(**kw):
    base = {"finding_id": "F-1", "status": "INFERRED", "mitre_attack": "UNMAPPED"}
    base.update(kw)
    return base


def test_benign_memory_emits_no_outbound_no_persistence_no_injection():
    # A benign memory image: plugins ran, nothing malicious fired.
    manifest = {"artifact_profile": "memory",
                "detection": {"plugins_run": ["memory_netscan", "memory_malfind",
                                              "memory_pslist"]}}
    findings = [_f(mitre_attack="T1036.005")]  # only a masquerade-ish lead
    sigs = _absence_signals(findings, manifest)
    joined = " ".join(sigs).lower()
    assert "no outbound" in joined
    assert "no code-injection" in joined or "malfind" in joined
    assert "persistence" in joined


def test_absence_signal_not_emitted_when_plugin_not_run():
    # netscan was NOT run -> we cannot claim "no outbound connections".
    manifest = {"artifact_profile": "memory",
                "detection": {"plugins_run": ["memory_pslist"]}}
    sigs = _absence_signals([_f()], manifest)
    assert not any("outbound" in s.lower() for s in sigs)


def test_malicious_finding_suppresses_that_absence_signal():
    manifest = {"artifact_profile": "memory",
                "detection": {"plugins_run": ["memory_malfind"]}}
    findings = [_f(mitre_attack="T1055.001", artifact_type="memory_malfind")]
    sigs = _absence_signals(findings, manifest)
    assert not any("injection" in s.lower() for s in sigs)


def test_no_plugins_run_emits_nothing():
    """No detection.plugins_run at all (older manifests / no key written)
    -> no signals, never inferred from silence."""
    manifest = {"artifact_profile": "memory", "detection": {}}
    assert _absence_signals([_f()], manifest) == []


def test_empty_manifest_emits_nothing():
    assert _absence_signals([_f()], {}) == []
