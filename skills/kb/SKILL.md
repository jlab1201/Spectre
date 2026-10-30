---
name: kb
description: "Spectre forensic knowledge base — PDF ingestion, chunking, FTS5 indexing, FK YAML authoring, and MITRE map maintenance."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, knowledge-base, fk-yaml, mitre, fts5]
metadata:
  hermes:
    tags: [forensic, spectre, knowledge-base, fk-yaml, mitre, fts5]
---

# Spectre Knowledge Base

Maintain the Spectre knowledge base: author forensic-knowledge (FK) YAML per artifact, maintain the MITRE ATT&CK map, and (optionally) ingest reference PDFs into a searchable FTS5 index. Everything lives in the repo under `src/spectre/` and resolves through `spectre.config`.

## When to use

- Adding or updating FK YAML for a forensic artifact
- Expanding the detection-rule to MITRE-technique map
- Ingesting reference PDFs (SANS posters) into the optional FTS5 index

## Where things live

| Thing | Path (`spectre.config` name) |
|---|---|
| FK YAML | `src/spectre/knowledge/artifacts/{windows,network,logs,disk}/*.yaml` (`KNOWLEDGE_DIR`, `FK_DIRS`) |
| Rule to technique map | `src/spectre/knowledge/mitre-map.yaml` (`MITRE_MAP_PATH`) |
| Technique id to name | `src/spectre/knowledge/mitre_techniques.yaml` (`MITRE_TECHNIQUES_PATH`) |
| Shared indicator lists / playbooks | `src/spectre/knowledge/indicators/`, `playbooks/` |
| Reference PDFs in, FTS5 index out | `~/.cache/spectre/` (`CACHE_DIR`; `INDEX_DB` = `index.db`), a runtime artifact, not source |

Counts are not recorded here (they drift); get them with `find src/spectre/knowledge/artifacts -name '*.yaml' | wc -l` and `python -c "import yaml;print(len(yaml.safe_load(open('src/spectre/knowledge/mitre-map.yaml'))['rules']))"`.

## 1. Author FK YAML

One file per artifact, in the subdirectory matching its evidence type. Template (taken from `artifacts/windows/prefetch.yaml`):

```yaml
artifact: "Human-readable artifact name"
artifact_id: "Short-ID"           # e.g. "Prefetch", "Amcache"
source: "path or hive location"
parser: "tool name(s)"
proves:
  - "What this artifact definitively establishes"
does_NOT_prove:
  - "What this artifact CANNOT establish (becomes finding caveats, verbatim)"
corroborate_with: ["Other", "Artifacts"]
discipline_reminder: |
  Analyst context for the explain prompt. NOT a caveat.
confidence_weight: 0.00   # documented but INACTIVE (confidence uses source count only)
```

Required fields: artifact, artifact_id, source, parser, proves, does_NOT_prove, corroborate_with, discipline_reminder, confidence_weight. Caveats in findings come from `does_NOT_prove` only, verbatim; the AI layer may not add any.

**YAML quoting for Windows paths:** in double quotes a backslash starts an escape, so use `"C:\\Windows\\Prefetch\\*.pf"` (doubled) or single quotes (`'C:\Windows\Prefetch\*.pf'`).

Validate after editing (run from the repo root):

```bash
python - <<'PY'
import yaml
from spectre.config import KNOWLEDGE_DIR
for f in sorted(KNOWLEDGE_DIR.rglob("*.yaml")):
    d = yaml.safe_load(f.read_text())
    for k in ("proves", "does_NOT_prove", "corroborate_with"):
        assert d.get(k), f"{f.name}: missing {k}"
print("ok")
PY
```

To draft FK + rule + tests from a source document (drafts only, nothing registered): `spectre-scaffold DOC [--staging-root DIR]` (default `staging/rule_drafts`). Rule authoring is covered in `docs/contributing-rules.md`.

## 2. Maintain the MITRE map

`mitre-map.yaml` maps detection rule ids to the ATT&CK technique ids a finding from that rule may carry. The model can never pick a technique outside the finding's own rule entry (enforced in `src/spectre/core/validators.py`).

```yaml
rules:
  rule-id:
    allowed: ["Txxxx.yyy"]
    label: "Human-readable technique name"
fallback: "UNMAPPED"
```

- Add the entry when you add the rule. Every `allowed` id must also exist in `mitre_techniques.yaml` (enforced by `tests/test_pipeline/test_report_synthesize.py`).
- Every key must be a real rule id from `python -m spectre.modules.registry` or be listed in `_LEGACY_MAP_KEYS` in `tests/test_mitre_map.py`, which also checks that a rule only emits techniques inside its `allowed` set.
- Verify: `pytest -q tests/test_mitre_map.py`.

## 3. Optional: reference PDF index

Two module-level scripts, no CLI flags. Neither is wired into the deterministic pipeline; the FTS5 index is only mentioned to subagents as reference material (`pipeline/subagent_templates.py`).

```bash
pip install pymupdf        # not a declared dependency; `import fitz` fails without it
python -m spectre.pipeline.extract_posters   # runs on import
python -m spectre.pipeline.build_index
```

- `extract_posters` looks for fixed PDF names (Hunt-Evil.pdf, Windows-Forensics-Poster.pdf, SIFT-Cheatsheet.pdf, ...) in `CACHE_DIR` (`~/.cache/spectre/`) and writes `<name>.md` into `KNOWLEDGE_DIR` (the FK `artifacts/` directory inside the package). Delete or do not commit those `.md` files.
- `build_index` reads `*.md` from `KNOWLEDGE_DIR`, chunks by heuristic headings, and rebuilds `INDEX_DB` (deleting any existing one) with an FTS5 table `poster_fts` and a plain `chunks` table. With no `.md` files it prints an error and changes nothing.
- SANS posters are dense 2-column layouts; text extraction is noisy. Adequate for keyword search, not a clean document.
- **FTS5 pitfall:** do not use external-content tables (`content='chunks'`); SQLite did not create the triggers and MATCH returned 0 hits silently. The script uses a standalone FTS5 table plus a separate `chunks` table for `LIKE` exact-match IOC search (FTS5 MATCH handles punctuation-heavy tokens poorly). Details in `references/fts5-pitfall.md`.

## Key constraints

- No LLM tokens in any KB authoring step; pure Python and YAML.
- `discipline_reminder` is analyst context, never a caveat.
- `confidence_weight` is documented but inactive.
- Knowledge describes artifacts, not tools.
- Run `pytest` before claiming a KB change is done.
