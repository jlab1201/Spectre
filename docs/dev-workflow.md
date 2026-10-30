# Development Workflow — Graphify-Driven Design

Maintainers may keep a local knowledge graph of the codebase in `graphify-out/` (not tracked in
the repository; generate it with `graphify`). If it exists, use it as a design aid. If it does
not, the rules below still apply using plain code search.

## Before designing a change

If `graphify-out/` exists, treat "how does X work / what touches Y" as a **graphify query first**, then read code.

1. Open `graphify-out/GRAPH_REPORT.md`. Find the **community** that owns the area you're
   touching (e.g. "Finding Emission & Recognizers", "Pipeline Orchestrator", "Detection & AI
   Explainer").
2. Check the **God Nodes** list — these are the core abstractions with the most edges
   (`setup_case()`, `emit()`, `explain()`, `CompiledDirective`, `normalize_text()`, …).
   If your change touches one, expect ripple effects; trace its edges before editing.
3. Scan **Surprising Connections** and **Hyperedges** for cross-cutting relationships you might
   not have in your head (e.g. the deterministic core flow `normalize→detect→emit→explain`, the
   shared `tool_runner`/`tool_exec` audit group).
4. For deeper questions, run a graphify query against the graph rather than guessing.

## Use the gaps the graph already found

The report's **Knowledge Gaps** (isolated/weakly-connected nodes) and **Suggested Questions**
(high-betweenness bridges, INFERRED edges to verify) are a ready-made to-do list for
documentation and missing wiring. Before adding new components, check whether you're about to
worsen an existing gap or can close one.

## After a structural change

- If you keep a local graph, regenerate it (`/graphify`) so it reflects reality. Graph drift is
  the same failure mode `docs/phase-0-spec.md` guards against for the Phase 0 spec.
- Confirm no new **import cycles** and that intended new hubs appear (e.g. after adding
  `spectre.llm`, it should show up as a connected node, not isolated).

## Record non-obvious decisions

When a design choice isn't recoverable from the code or git history (a trade-off, a constraint,
a "why not the obvious thing"), save it to memory so the next session — yours or another agent's —
doesn't re-litigate it.

## Discipline that doesn't change

Graphify is the *navigation* layer. The engineering rules still apply: TDD (write the failing
test first), preserve the chain-of-custody and explain-layer guardrails (the validators in `src/spectre/core/explain.py` and `src/spectre/pipeline/report_validators.py` stay authoritative), and
run `pytest` + `spectre-canary` before claiming work complete.
