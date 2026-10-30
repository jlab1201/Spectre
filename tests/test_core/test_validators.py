from spectre.core import validators


def test_finding_artifact_types_reads_corroboration_tools():
    findings = [{"corroboration": {"tools": ["tcpdump/pcap_conn"]}}]
    assert validators.finding_artifact_types(findings) == ["pcap_conn"]


def test_finding_artifact_types_defaults_to_evtx_when_empty():
    assert validators.finding_artifact_types([{}]) == ["evtx"]


def test_guardrail_context_returns_allowed_and_caveats_map():
    allowed, caveats = validators.guardrail_context([{"corroboration": {"tools": ["x/pcap_flow"]}}])
    assert isinstance(allowed, list)
    assert isinstance(caveats, dict)


def test_no_audit_report_synthesize_import_cycle():
    # core.validators must be importable without dragging in pipeline.audit,
    # and audit must be able to import it. This is the cycle-break contract.
    import importlib
    import spectre.core.validators as v
    import spectre.pipeline.audit as a
    assert importlib.import_module("spectre.core.validators") is v
    assert hasattr(a, "verify_full")


def test_mitre_in_allowed_returns_only_invented():
    from spectre.core import validators
    assert validators.mitre_in_allowed(["T1071", "T9999", "UNMAPPED"], ["T1071"]) == ["T9999"]
