# Contributing detection rules

Spectre is **host-neutral** and built for blue-team **community contributors**.
You can add a detection rule without touching the framework or any central list:
drop a file into a module's `rules/` directory and open a PR.

> **The one inviolable rule.** The deterministic core produces findings as
> *facts*; the AI only *explains* them. A rule may assert a MITRE technique only
> if it can justify it — otherwise leave `mitre=[]`. Nothing downstream invents
> findings, technique IDs, or caveats your predicate did not produce.

There are two ways to write a rule, plus an AI assist to draft one for you.

## 1. Native Python rule (most powerful)

Best for algorithmic detections (fuzzy name matching, canonicalization, header
checks) and anything that needs real logic. Rules are pure functions and are
directly unit-testable.

1. Copy the template:

   ```
   cp src/spectre/modules/evtx/rules/_template.py \
      src/spectre/modules/<module>/rules/my_rule.py
   ```

   The `_`-prefix is why the template itself is ignored by discovery — your copy
   must **not** start with an underscore. Create the `rules/` directory if it
   does not exist yet.

2. Write a pure `predicate(event) -> Optional[Anchor]` (no I/O — read fields off
   `event.data`).

3. Fill in the `RuleMetadata` defensibility card: `severity`, `references`,
   known `false_positives`, and `tags`. Generate your own `uuid`
   (`python -c "import uuid; print(uuid.uuid4())"`).

4. Export the rule(s): either a module-level `RULES = [...]` list or one or more
   module-level `Rule` objects. `collect_rules()` discovers both.

5. Add tests (see below) and open a PR. There is **no central list to edit** —
   discovery finds your file automatically.

### How discovery works

`core/rule_discovery.py::module_rules()` returns each module's legacy
`rules.py` rules **plus** any drop-ins under `modules/<module>/rules/`. The two
coexist — a module never has to migrate its existing `rules.py` to accept
drop-ins. Files are loaded in filename order for a stable, reproducible catalog.
A malformed drop-in is skipped with a warning; it can never silence the rules
that load fine.

## 2. Sigma rule (the community on-ramp)

For log-style evidence (process-creation / EVTX), you can drop a community
**Sigma** `.yml` file straight into `modules/evtx/rules/`. Spectre compiles it
into the same native `Rule` object — one engine runs everything. See the Sigma
support and supported-subset notes in `core/sigma_import.py`. Anything outside
the supported subset is **rejected with a clear error**, never best-guessed, so
a Sigma rule can't silently miscompile into a wrong finding.

## 3. AI scaffolder — bring a document, get draft drafts

Have a threat report or analysis write-up but a blank page for the rule? The
scaffolder drafts the starting point for you:

```
spectre-scaffold path/to/threat_report.md
# or: python -m spectre.pipeline.rule_scaffold path/to/threat_report.md
```

It writes to a **staging** directory (default `staging/rule_drafts/<doc>/`):

- `fk/<artifact>.yaml` — a forensic-knowledge entry for the artifact the doc
  describes (proves / does-NOT-prove / corroborate-with skeleton).
- `rules/<slug>.py` (or `.yml` for Sigma) — a candidate rule. The Python draft
  is a **compilable stub that matches nothing** — guilty-until-tested. The
  model's rationale rides in the docstring; you implement the predicate.
- `tests/test_<slug>.py` — should-fire / should-not-fire stubs to fill in.
- `README.md` — the human-gated checklist below.

**Nothing is registered or active.** The scaffolder writes nothing into any
module and never makes the AI the authority on a finding — a human plus the
tests are the gate, consistent with `explain.py`. Provenance is baked in: each
drafted rule records the source document in its `metadata.references`, and known
false positives are seeded from the document's caveats.

The scaffolder uses Spectre's host-neutral LLM seam (`SPECTRE_LLM_PROVIDER`).
With `null`/`host` (no direct API output) it still emits well-formed drafts
seeded deterministically from the document.

### Human-gated workflow

1. Review every draft against the source document **and real evidence**.
2. Implement the rule predicate (or finish the Sigma rule).
3. Make the should-fire / should-not-fire tests real and pass them.
4. Move the FK YAML into `src/spectre/knowledge/artifacts/<area>/` and the rule
   into `src/spectre/modules/<module>/rules/`.
5. Run `pytest` and `spectre-canary`, then open a PR.

## Writing tests (required)

Every rule needs at least a should-fire and a should-not-fire test against a
single synthetic `NormEvent`:

```python
from spectre.core.base import NormEvent
from spectre.modules.evtx.rules.my_rule import example_predicate

def test_fires_on_match():
    e = NormEvent("process_creation", "t", "f", "1",
                  data={"image_basename": "example.exe"})
    assert example_predicate(e) is not None

def test_silent_on_benign():
    e = NormEvent("process_creation", "t", "f", "2",
                  data={"image_basename": "explorer.exe"})
    assert example_predicate(e) is None
```

Run `pytest` and `spectre-canary` before opening the PR.

## What lands in the case record

Every evaluated rule (fired or silent) is recorded in the per-case
`ruleset.yaml` with its identity card — `uuid`, `severity`, `rule_format`,
`tags`, `references`, and `false_positives` — so a reviewer can judge coverage
and defensibility. The report surfaces a severity/tag breakdown.
