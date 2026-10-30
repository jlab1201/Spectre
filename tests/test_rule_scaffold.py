"""test_rule_scaffold.py — AI rule/FK scaffolder (Phase 4).

`scaffold(doc_path)` turns a threat-report document into *reviewable drafts*:
an FK YAML entry, a candidate rule, and should-fire/should-not-fire test stubs,
all written to a staging area and **never** registered into a module. The AI
fills the blank page; a human plus the tests are the gate. Drafts are
guilty-until-tested, consistent with explain.py's validator philosophy.

These tests run the deterministic/null LLM path (no network), asserting the
scaffolder still emits well-formed drafts seeded from the document and that it
registers nothing live.
"""

import compileall
import importlib

import yaml

from spectre.core.sigma_import import compile_sigma
from spectre.llm import LLMResponse
from spectre.pipeline import rule_scaffold


def _doc(tmp_path):
    p = tmp_path / "threat_report.md"
    p.write_text(
        "# Acme RAT\n\n"
        "Acme RAT launches rundll32.exe to load a DLL from %TEMP%.\n\n"
        "## False positives\n"
        "- legitimate installers staging a DLL in temp\n"
    )
    return p


def test_scaffold_creates_staging_with_drafts(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    staging = rule_scaffold.scaffold(_doc(tmp_path), staging_root=tmp_path / "staging")
    assert staging.is_dir()
    assert (staging / "README.md").exists()
    assert list((staging / "fk").glob("*.yaml"))
    assert list((staging / "rules").glob("*"))
    assert list((staging / "tests").glob("test_*.py"))


def test_fk_draft_is_valid_yaml_with_required_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    staging = rule_scaffold.scaffold(_doc(tmp_path), staging_root=tmp_path / "staging")
    fk_file = next((staging / "fk").glob("*.yaml"))
    fk = yaml.safe_load(fk_file.read_text())
    for key in ("artifact", "artifact_id", "proves", "does_NOT_prove",
                "corroborate_with"):
        assert key in fk


def test_rule_and_test_drafts_are_well_formed(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    staging = rule_scaffold.scaffold(_doc(tmp_path), staging_root=tmp_path / "staging")
    # every drafted .py compiles; any drafted .yml compiles as Sigma
    assert compileall.compile_dir(str(staging), quiet=1)
    for yml in (staging / "rules").glob("*.yml"):
        compile_sigma(yml.read_text())  # raises if malformed


def test_provenance_records_source_document(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    doc = _doc(tmp_path)
    staging = rule_scaffold.scaffold(doc, staging_root=tmp_path / "staging")
    rule_text = "\n".join(p.read_text() for p in (staging / "rules").iterdir())
    # the source document is recorded as provenance in the drafted rule
    assert doc.name in rule_text


def test_registers_nothing_live(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    from spectre.modules import registry
    before = {n: len(m.rules) for n, m in registry.discover().items()}
    rule_scaffold.scaffold(_doc(tmp_path), staging_root=tmp_path / "staging")
    after = {n: len(m.rules) for n, m in registry.discover().items()}
    assert before == after
    # nothing was written under the modules package
    modules_dir = importlib.import_module("spectre.modules").__path__[0]
    assert str(tmp_path) not in modules_dir  # sanity: staging is outside modules


def test_uses_llm_content_when_available(tmp_path, monkeypatch):
    # When the provider returns parsed content, the scaffolder uses it.
    drafted = {
        "artifact_type": "process_creation",
        "rule_style": "python",
        "fk_entries": [{
            "artifact": "Custom Artifact From LLM",
            "artifact_id": "Custom-LLM",
            "proves": ["something"],
            "does_NOT_prove": ["intent"],
            "corroborate_with": ["other evidence"],
        }],
        "python_rule": {
            "rule_id": "llm-drafted-rule",
            "title": "LLM drafted rule",
            "severity": "high",
            "mitre": ["T1218.011"],
            "description": "drafted by the model",
        },
        "false_positives": ["benign case from model"],
    }

    class FakeProvider:
        name = "fake"

        def complete(self, system, user, **kw):
            return LLMResponse(parsed=drafted)

    staging = rule_scaffold.scaffold(
        _doc(tmp_path), staging_root=tmp_path / "staging",
        provider=FakeProvider())
    fk = yaml.safe_load(next((staging / "fk").glob("*.yaml")).read_text())
    assert fk["artifact_id"] == "Custom-LLM"
    rule_text = "\n".join(p.read_text() for p in (staging / "rules").iterdir())
    assert "llm-drafted-rule" in rule_text


def test_deterministic_seed_leaves_severity_unrated(tmp_path, monkeypatch):
    """TB-port T4: the null-provider seed must not assert a severity the
    source document never gave — the draft rule carries severity=None."""
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    staging = rule_scaffold.scaffold(_doc(tmp_path),
                                     staging_root=tmp_path / "staging")
    rule_text = "\n".join(p.read_text() for p in (staging / "rules").iterdir())
    assert "severity=None" in rule_text
    assert "severity='medium'" not in rule_text


def test_hostile_rule_id_and_filename_cannot_inject_code(tmp_path):
    import ast

    hostile_id = 'x"""\nimport os\nos.system("id")\n"""'

    class _Stub:
        name = "stub"

        def complete(self, system, user, **kw):
            return LLMResponse(
                parsed={
                    "rule_style": "python",
                    "python_rule": {"rule_id": hostile_id},
                    "rationale": hostile_id,
                })

    try:
        doc = tmp_path / "evil'''#.md"
        doc.write_text("# Evil\n\nrundll32.exe\n")
    except OSError:
        doc = tmp_path / "evil'''_.md"
        doc.write_text("# Evil\n\nrundll32.exe\n")
    staging = rule_scaffold.scaffold(doc, staging_root=tmp_path / "staging",
                                     provider=_Stub())
    pys = list(staging.rglob("*.py"))
    assert len(pys) >= 2
    for py in pys:
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name != "os" for a in node.names), py
            if isinstance(node, ast.ImportFrom):
                assert node.module != "os", py
            if isinstance(node, ast.Name):
                assert node.id != "os", py
        for node in tree.body:
            assert isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom,
                                     ast.Assign, ast.FunctionDef)), py
            if isinstance(node, ast.Expr):
                assert isinstance(node.value, ast.Constant), py


def _assert_safe_python(staging):
    import ast

    pys = list(staging.rglob("*.py"))
    assert len(pys) >= 2
    for py in pys:
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name != "os" for a in node.names), py
            if isinstance(node, ast.ImportFrom):
                assert node.module != "os", py
            if isinstance(node, ast.Name):
                assert node.id != "os", py
        for node in tree.body:
            assert isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom,
                                     ast.Assign, ast.FunctionDef)), py
            if isinstance(node, ast.Expr):
                assert isinstance(node.value, ast.Constant), py


def test_hostile_document_filename_with_newline_cannot_inject_code(tmp_path):
    class _Stub:
        name = "stub"

        def complete(self, system, user, **kw):
            return LLMResponse(parsed={"rule_style": "python", "python_rule": {}})

    doc = tmp_path / 'x"""\nimport os\n#.md'
    doc.write_text("# Evil\n\nrundll32.exe\n")
    staging = rule_scaffold.scaffold(doc, staging_root=tmp_path / "staging",
                                     provider=_Stub())
    _assert_safe_python(staging)


def test_non_string_rule_id_is_tolerated(tmp_path):
    class _Stub:
        name = "stub"

        def complete(self, system, user, **kw):
            return LLMResponse(parsed={
                "rule_style": "python", "python_rule": {"rule_id": 123}})

    staging = rule_scaffold.scaffold(_doc(tmp_path), staging_root=tmp_path / "staging",
                                     provider=_Stub())
    _assert_safe_python(staging)
