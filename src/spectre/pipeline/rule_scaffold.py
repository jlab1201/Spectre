"""rule_scaffold.py — AI rule/FK scaffolder (Phase 4).

"Bring a document, get a draft PR." `scaffold(doc_path)` turns a threat-report
or analysis document into *reviewable drafts*:

  * an FK YAML entry for the artifact(s) the document describes,
  * a candidate rule (a Sigma rule for log-style detections, or a Python
    predicate **stub** for algorithmic ones), and
  * should-fire / should-not-fire test stubs.

Everything is written to a **staging** directory and **nothing** is registered
into a module. The AI fills the blank page; a human plus the tests are the gate.
Rule drafts are guilty-until-tested — the scaffolder never embeds model logic as
an executable predicate; it emits a compilable stub with the model's rationale
in the docstring, so a human must implement and test it before it can fire. FK
drafts are lower-risk descriptive context. This is consistent with explain.py:
the AI is never the authority on a finding.

Host-neutral: the draft content comes from the LLM seam (`spectre.llm`); under
the `null`/`host` providers (no API output) the scaffolder still emits
well-formed drafts seeded deterministically from the document.
"""

from __future__ import annotations

import json
import keyword
import re
from pathlib import Path

import yaml

from spectre.llm import get_provider

_DEFAULT_STAGING = Path("staging/rule_drafts")

_SYSTEM = (
    "You are a detection-engineering assistant for a forensic pipeline whose #1 "
    "rule is: the deterministic core produces findings as FACTS; the AI only "
    "drafts candidates for human review. Draft ONLY what the document supports. "
    "Never assert a MITRE technique you cannot justify from the document; if "
    "unsure, use an empty list. Respond with a single JSON object, no prose."
)

# The JSON contract we ask the model for (also handed to host-mode agents).
_SCHEMA = {
    "type": "object",
    "properties": {
        "artifact_type": {"type": "string"},
        "rule_style": {"enum": ["sigma", "python"]},
        "fk_entries": {"type": "array"},
        "sigma_rule": {"type": "string"},
        "python_rule": {"type": "object"},
        "false_positives": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "draft"


def _doc_title(doc_text: str, fallback: str) -> str:
    for line in doc_text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip() or fallback
        if line:
            return line[:80]
    return fallback


def _doc_false_positives(doc_text: str) -> list[str]:
    """Best-effort pull of a 'false positives' bullet list from the document."""
    out: list[str] = []
    in_section = False
    for line in doc_text.splitlines():
        stripped = line.strip()
        if re.search(r"false[\s_-]*positive", stripped, re.IGNORECASE):
            in_section = True
            continue
        if in_section:
            if stripped.startswith(("-", "*")):
                out.append(stripped.lstrip("-* ").strip())
            elif stripped.startswith("#") or not stripped:
                if out:  # blank/heading ends the list once we have items
                    break
    return out


def _seed_draft(doc_text: str, doc_name: str) -> dict:
    """Deterministic, document-seeded draft used as defaults (and as the whole
    draft when the LLM produces no output)."""
    title = _doc_title(doc_text, fallback=doc_name)
    slug = _slug(title)
    fps = _doc_false_positives(doc_text)
    artifact_type = "process_creation"
    return {
        "artifact_type": artifact_type,
        "rule_style": "python",
        "false_positives": fps,
        "rationale": (
            "TODO: implement and justify this detection from the source document. "
            "Drafted automatically; not yet reviewed."),
        "fk_entries": [{
            "artifact": f"Artifact described in {doc_name}: {title}",
            "artifact_id": slug[:40],
            "source": "TODO: evidence source this artifact comes from",
            "parser": "TODO: tool/plugin that produces it",
            "proves": ["TODO: what this artifact deterministically proves"],
            "does_NOT_prove": [
                "TODO: the inferences this artifact does NOT support"],
            "corroborate_with": ["TODO: corroborating artifacts"],
            "discipline_reminder": (
                "Draft FK from a document — verify every claim against real "
                "evidence before relying on it."),
            "confidence_weight": 0.5,
        }],
        "python_rule": {
            "rule_id": f"{slug[:40]}-draft",
            "title": title,
            # The source document assessed no level: leave it UNRATED (None)
            # for the human reviewer to set, never an implied "medium".
            "severity": None,
            "mitre": [],
            "description": f"DRAFT detection scaffolded from {doc_name}",
        },
    }


def _merge(seed: dict, parsed: dict | None) -> dict:
    """Overlay LLM-parsed content onto the document-seeded defaults."""
    if not parsed:
        return seed
    draft = dict(seed)
    for key in ("artifact_type", "rule_style", "rationale"):
        if parsed.get(key):
            draft[key] = parsed[key]
    if isinstance(parsed.get("false_positives"), list):
        draft["false_positives"] = parsed["false_positives"]
    if isinstance(parsed.get("fk_entries"), list) and parsed["fk_entries"]:
        draft["fk_entries"] = parsed["fk_entries"]
    if isinstance(parsed.get("python_rule"), dict):
        draft["python_rule"] = {**seed["python_rule"], **parsed["python_rule"]}
    if parsed.get("sigma_rule"):
        draft["sigma_rule"] = parsed["sigma_rule"]
    return draft


# ── Rendering ───────────────────────────────────────────────────────
def _render_fk(entry: dict, doc_name: str) -> str:
    entry = dict(entry)
    entry.setdefault("drafted_from", doc_name)  # provenance
    return yaml.safe_dump(entry, sort_keys=False, allow_unicode=True)


def _render_python_rule(rule: dict, false_positives: list[str],
                        doc_path: Path, artifact_type: str) -> str:
    rid = rule.get("rule_id", "draft-rule")
    title = rule.get("title", "Draft rule")
    severity = rule.get("severity")
    mitre = rule.get("mitre", []) or []
    description = rule.get("description", "")
    rationale = rule.get("rationale", "")
    # Docstring/comment positions: slug only (repr could still close a docstring).
    doc_label = _slug(doc_path.name)
    return f'''"""DRAFT rule scaffolded from {doc_label} — NOT REGISTERED.

Guilty-until-tested: the predicate below is a STUB that matches nothing. A human
must implement it from the source document and add passing tests before this
rule may move into a module. The deterministic core asserts facts; this draft
asserts nothing until you make it.

Model rationale: {json.dumps(rationale)}
"""

from __future__ import annotations

from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata

ARTIFACT = {artifact_type!r}


def predicate(e: NormEvent) -> Optional[Anchor]:
    # TODO: implement the detection described in {doc_label}.
    # Read fields off e.data; return an Anchor on a match, else None.
    return None


RULES = [
    Rule(
        rule_id={rid!r},
        artifact_type=ARTIFACT,
        predicate=predicate,
        mitre={mitre!r},
        description={description!r},
        metadata=RuleMetadata(
            uuid="",  # TODO: generate with `python -c "import uuid;print(uuid.uuid4())"`
            name={title!r},
            author="scaffold-draft",
            severity={severity!r},
            rule_format="python",
            rule_source="staging (draft) — move into modules/<m>/rules/ after review",
            references=[{str(doc_path)!r}],  # provenance: the source document
            false_positives={false_positives!r},
        ),
    ),
]
'''


def _render_test(rule: dict, artifact_type: str) -> str:
    rid = rule.get("rule_id", "draft-rule")
    rid_label = _slug(str(rid))
    mod = rid_label.replace("-", "_")
    if not mod.isidentifier() or keyword.iskeyword(mod):
        mod = f"rule_{mod}"
    return f'''"""DRAFT tests for {rid_label} — fill in real should-fire / should-not-fire cases."""

from spectre.core.base import NormEvent

# After you move the rule into a module, fix this import to its real location.
from {mod} import predicate  # noqa: F401 — placeholder import path


def test_fires_on_match():
    e = NormEvent({artifact_type!r}, "t", "f", "1", data={{}})
    # TODO: populate data with a malicious sample so this asserts is not None
    assert predicate(e) is None  # CHANGE ME once implemented


def test_silent_on_benign():
    e = NormEvent({artifact_type!r}, "t", "f", "2", data={{}})
    assert predicate(e) is None
'''


def _render_readme(doc_path: Path, draft: dict, provider_name: str) -> str:
    return (
        f"# Rule/FK drafts scaffolded from `{doc_path.name}`\n\n"
        f"- **Source document:** `{doc_path}`\n"
        f"- **LLM provider:** `{provider_name}`\n"
        f"- **Rule style:** `{draft.get('rule_style')}`\n\n"
        "## These are DRAFTS — nothing here is registered or active.\n\n"
        "Human-gated workflow:\n\n"
        "1. Review every draft against the source document and real evidence.\n"
        "2. Implement the rule predicate (or finish the Sigma rule).\n"
        "3. Make the should-fire / should-not-fire tests real and pass them.\n"
        "4. Move the FK YAML into `src/spectre/knowledge/artifacts/<area>/` and the\n"
        "   rule into `src/spectre/modules/<module>/rules/`.\n"
        "5. Run `pytest` and `spectre-canary`, then open a PR.\n\n"
        "The AI is never the authority on a finding — a human and the tests are "
        "the gate, consistent with `explain.py`.\n"
    )


def scaffold(doc_path, staging_root=None, provider=None) -> Path:
    """Draft FK + rule + test stubs from a document into a staging dir.

    Returns the staging directory. Registers nothing live; writes nothing into
    any module. Uses the host-neutral LLM seam — under `null`/`host` providers
    it falls back to deterministic, document-seeded drafts.
    """
    doc_path = Path(doc_path)
    doc_text = doc_path.read_text(errors="replace")

    provider = provider or get_provider()
    user = (
        "Draft FK + a detection rule + test stubs for the artifact/behavior in "
        "this document. Return JSON matching the schema.\n\nDOCUMENT:\n"
        + doc_text[:8000]
    )
    try:
        resp = provider.complete(_SYSTEM, user, max_tokens=2048,
                                 temperature=0.0, schema=_SCHEMA)
        parsed = resp.parsed if resp else None
    except Exception:
        parsed = None  # any provider/transport failure -> deterministic draft

    draft = _merge(_seed_draft(doc_text, doc_path.name), parsed)

    staging = Path(staging_root or _DEFAULT_STAGING) / doc_path.stem
    (staging / "fk").mkdir(parents=True, exist_ok=True)
    (staging / "rules").mkdir(parents=True, exist_ok=True)
    (staging / "tests").mkdir(parents=True, exist_ok=True)

    # FK drafts
    for i, entry in enumerate(draft.get("fk_entries") or []):
        if not isinstance(entry, dict):
            continue
        name = _slug(str(entry.get("artifact_id") or entry.get("artifact") or f"fk-{i}"))
        (staging / "fk" / f"{name}.yaml").write_text(_render_fk(entry, doc_path.name))

    # Rule draft: Sigma (validated) or a Python stub.
    artifact_type = draft.get("artifact_type", "process_creation")
    py_rule = dict(draft.get("python_rule") or {})
    py_rule.setdefault("rationale", draft.get("rationale", ""))
    rule_slug = _slug(str(py_rule.get("rule_id", "draft-rule")))

    wrote_sigma = False
    if draft.get("rule_style") == "sigma" and draft.get("sigma_rule"):
        from spectre.core.sigma_import import SigmaUnsupportedError, compile_sigma
        sigma_text = draft["sigma_rule"]
        try:
            compile_sigma(sigma_text)  # only write Sigma that actually compiles
            (staging / "rules" / f"{rule_slug}.yml").write_text(sigma_text)
            wrote_sigma = True
        except SigmaUnsupportedError:
            wrote_sigma = False  # fall through to a Python stub
    if not wrote_sigma:
        (staging / "rules" / f"{rule_slug}.py").write_text(
            _render_python_rule(py_rule, draft.get("false_positives") or [],
                                doc_path, artifact_type))

    # Test stub + README
    (staging / "tests" / f"test_{rule_slug.replace('-', '_')}.py").write_text(
        _render_test(py_rule, artifact_type))
    (staging / "README.md").write_text(
        _render_readme(doc_path, draft, getattr(provider, "name", "unknown")))

    return staging


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="spectre-scaffold",
        description="Draft FK + rule + tests from a document into staging "
                    "(drafts only; nothing is registered).")
    ap.add_argument("doc", help="path to the source document")
    ap.add_argument("--staging-root", default=None,
                    help=f"staging base dir (default: {_DEFAULT_STAGING})")
    args = ap.parse_args(argv)
    out = scaffold(args.doc, staging_root=args.staging_root)
    print(f"Drafts written to: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
