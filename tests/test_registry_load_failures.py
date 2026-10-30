"""A module that fails to import is a silent loss of analysis capability.

registry.discover() catches every import error, prints to stderr, and
continues. That warning reaches no audit row, no manifest field, and no
report line — so a case run against a broken module looks complete.

Spec: the module-selection design spec §3.9.
"""

import shutil
import sys
import textwrap

from spectre.modules import registry


def _write_broken_module(name: str, body: str):
    d = registry.MODULES_DIR / name
    d.mkdir(exist_ok=True)
    (d / "__init__.py").write_text(textwrap.dedent(body))
    return d


def _cleanup(d, name: str):
    # rmtree, not unlink-each: importing the module leaves a __pycache__ dir.
    shutil.rmtree(d, ignore_errors=True)
    sys.modules.pop(f"spectre.modules.{name}", None)


def test_discover_with_errors_reports_import_failure():
    name = "zzz_broken_import_test"
    d = _write_broken_module(name, """
        raise ImportError("deliberate test failure")
    """)
    try:
        modules, errors = registry.discover_with_errors()
        assert name in errors
        assert "deliberate test failure" in errors[name]
        assert len(modules) >= 8, "a broken module must not lose the others"
        assert "pcap" in modules
    finally:
        _cleanup(d, name)


def test_discover_with_errors_reports_bad_shape():
    name = "zzz_broken_shape_test"
    d = _write_broken_module(name, """
        # imports fine, but exposes no AnalyzerModule
        NOT_A_MODULE = 42
    """)
    try:
        modules, errors = registry.discover_with_errors()
        assert name in errors
        assert "AnalyzerModule" in errors[name]
        assert len(modules) >= 8
    finally:
        _cleanup(d, name)


def test_healthy_tree_reports_no_errors():
    modules, errors = registry.discover_with_errors()
    assert errors == {}, f"unexpected module load errors: {errors}"
    assert len(modules) == 8


def test_discover_signature_unchanged():
    """discover() must keep returning a plain dict — test_mitre_map.py and
    recognize.py both depend on it."""
    mods = registry.discover()
    assert isinstance(mods, dict)
    assert "pcap" in mods


def test_blindspots_disclose_module_load_failure():
    """The stderr warning must also reach the report."""
    from spectre.pipeline.report_synthesize import _intake_blindspot_lines
    name = "zzz_broken_report_test"
    d = _write_broken_module(name, """
        raise ImportError("boom")
    """)
    try:
        lines = "\n".join(_intake_blindspot_lines({"triage": {}}))
        assert "failed to load" in lines
        assert name in lines
        assert "NOT analyzed" in lines
    finally:
        _cleanup(d, name)


def test_blindspots_silent_when_all_modules_load():
    from spectre.pipeline.report_synthesize import _intake_blindspot_lines
    assert _intake_blindspot_lines({"triage": {}}) == []
