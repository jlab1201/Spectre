---
name: knowledge-retriever
description: "Query the Spectre forensic knowledge base — FTS5 exact-match search, FK YAML loading, MITRE technique lookup, IOC cross-reference against case index."
version: 1.0.0
author: Spectre
license: MIT
tags: [forensic, spectre, knowledge-base, retrieval, fts5, mitre]
metadata:
  hermes:
    tags: [forensic, spectre, knowledge-base, retrieval, fts5, mitre]
---

# Forensic Knowledge Retriever

Query the Spectre knowledge base during investigations. Three retrieval modes: exact-match IOC search (LIKE on chunks), full-text conceptual search (FTS5 MATCH), and FK YAML / MITRE injection for interpretation.

## When to use

- Before deep-dive: "What does this artifact mean?"
- During detection: "Is this hash/IP/path known-bad?"
- During correlation: "What MITRE technique matches this behavior?"
- During explanation: "What caveats apply to this artifact?"

## KB Architecture

Resolved through `spectre.config` (no hardcoded paths):

1. **chunks table (LIKE)** — exact-match for IOCs (hashes, IPs, registry keys, filenames, paths), in `config.INDEX_DB` (optional; see `skills/kb/SKILL.md`)
2. **poster_fts (FTS5 MATCH)** — full-text search over ingested reference material, same DB
3. **FK YAML** — `config.FK_DIRS`; per-artifact proves/does_NOT_prove/corroborate_with
4. **mitre-map.yaml** — `config.MITRE_MAP_PATH`; rule → allowed MITRE technique IDs
5. **index.md** — `config.CASES_DIR / "index.md"`; cross-case artifact index (hashes, IPs, registry keys)

## Steps

### 1. Exact-match IOC search (LIKE on chunks)

For hashes, IPs, paths, registry keys — use LIKE against the chunks table:

```python
import sqlite3
from spectre.config import INDEX_DB
conn = sqlite3.connect(INDEX_DB)

# Search for a hash
cursor = conn.execute(
    "SELECT poster_name, section_title, chunk_text FROM chunks WHERE chunk_text LIKE ?",
    (f"%{ioc_hash}%",)
)
results = cursor.fetchall()
```

**Pitfall:** Backslashes in registry paths need careful escaping. Use `%CurrentVersion%Run%` instead of `%HKLM\\Software\\...%`.

### 2. Full-text search (FTS5 MATCH on poster_fts)

For conceptual queries like "process injection techniques":

```python
cursor = conn.execute(
    "SELECT poster_name, section_title, snippet(poster_fts, 2, '<b>', '</b>', '...', 40) "
    "FROM poster_fts WHERE poster_fts MATCH ?",
    (query,)
)
```

FTS5 uses unicode61 tokenizer. Punctuation-heavy tokens (hashes, paths) do NOT match well in FTS5 — use LIKE instead.

### 3. FK YAML loading

```python
import yaml
from spectre.config import FK_DIRS

def load_fk_yaml(artifact_id: str) -> dict:
    """Load FK YAML by artifact_id (e.g. 'EVTX-Security-4688', 'Prefetch')."""
    for yaml_file in (f for d in FK_DIRS for f in d.rglob("*.yaml")):
        data = yaml.safe_load(yaml_file.read_text())
        if data.get("artifact_id") == artifact_id:
            return {
                "artifact_id": data["artifact_id"],
                "artifact_name": data["artifact"],
                "proves": data["proves"],
                "does_NOT_prove": data["does_NOT_prove"],
                "corroborate_with": data["corroborate_with"],
                "discipline_reminder": data["discipline_reminder"],
                "confidence_weight": data.get("confidence_weight", 0.50),
            }
    return None
```

List the available `artifact_id` values with `grep -rh '^artifact_id:' src/spectre/knowledge/artifacts`.

### 4. MITRE technique lookup

```python
from spectre.config import MITRE_MAP_PATH

def lookup_mitre(rule_id: str) -> list[str]:
    """Return allowed MITRE technique IDs for a detection rule."""
    mitre_map = yaml.safe_load(MITRE_MAP_PATH.read_text())
    return mitre_map.get("rules", {}).get(rule_id, {}).get("allowed", [])

# Fallback if no match
mitre_ids = lookup_mitre("rundll32-from-temp")
if not mitre_ids:
    mitre_ids = ["UNMAPPED"]
```

Fallback is "UNMAPPED".

### 5. IOC cross-reference against case index

```python
def cross_ref_ioc(ioc_value: str, ioc_type: str) -> list[dict]:
    """Search the cross-case index.md for prior appearances of an IOC."""
    from pathlib import Path
    from spectre.config import CASES_DIR
    index_path = Path(CASES_DIR) / "index.md"
    if not index_path.exists():
        return []
    # Parse markdown table, search for ioc_value in appropriate section
    ...
```

**IMPORTANT:** IOC cross-reference is ADVISORY ONLY. Prior case appearance does NOT automatically adjust confidence. It only informs the analyst that this artifact has been seen before.

## Output handle

```json
{
  "query": "rundll32.exe",
  "query_type": "ioc_exact",
  "results": [
    {
      "poster_name": "Hunt-Evil",
      "section_title": "SYSTEM",
      "snippet": "...ShimCache records existence of malicious service executable...",
      "source": "fts5_chunks"
    }
  ],
  "fk_envelope": {
    "artifact_id": "EVTX-Security-4688",
    "proves": ["A process was created..."],
    "does_NOT_prove": ["The DLL is still on disk..."],
    "corroborate_with": ["Prefetch", "Amcache", "MFT", "ShimCache"]
  },
  "mitre_candidates": ["T1218.011"],
  "cross_case_matches": 0,
  "execution_id": "abc123..."
}
```

## Pitfalls

- **FTS5 MATCH does NOT handle punctuation-heavy tokens.** Use LIKE on chunks table for hashes, IPs, and paths.
- **SQLite LIKE is case-insensitive for ASCII only.** Non-ASCII letters match case-sensitively.
- **FK YAML caveats are verbatim.** Never paraphrase `does_NOT_prove` entries — inject them exactly as written.
- **discipline_reminder is NOT a caveat.** It goes to the explain prompt, not into findings.
- **IOC cross-reference is advisory only.** Never say "this hash was seen in case 002 therefore confidence increases."
- **MITRE lookup must respect allowed set.** The LLM may ONLY choose from allowed technique IDs. Free-typing is blocked.
- **Event ID 4688 search returns 0 hits in KB** (graphical poster element). Use FK YAML directly for 4688 interpretation.
