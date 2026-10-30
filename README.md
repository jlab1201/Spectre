# Spectre Forensic

Deterministic forensic analysis pipeline for AI agents.

## Architecture

Two-layer design: **Deterministic Core** + **AI Explainer**.

- **Core**: Extracts, normalizes, detects, and emits findings deterministically — no AI involved
- **Explainer**: Guard-railed AI that explains findings without inventing new ones


Spectre has two layers. The deterministic core (`core/` and `modules/`) involves no AI: each
evidence-type module recognizes, extracts and normalizes artifacts, then a rule pack emits
findings as facts. The optional AI layer only *explains* those findings; its output is checked
by validators and can never introduce a finding, MITRE technique or caveat the core did not
produce. Work runs through seven phases (case setup, direction, extraction, detection,
correlation, adversarial review, synthesis/report plus examiner approval) with quality gates in
between, and every action lands in a SHA-256-chained audit trail. See `docs/phase-0-spec.md`
for the Phase 0 / Gate 0 spec and `CONTRIBUTING.md` for how to contribute.

## Quick Start

```bash
pip install -e ".[dev]"
spectre --help
spectre-memory --help
spectre-canary                       # environment health: FULL / DEGRADED / DEAD
```

Run a case (cases live in `~/spectre-cases/`, override with `SPECTRE_CASES_DIR` or `--cases-dir`):

```bash
spectre --list-profiles
spectre --name my-case --profile auto --evidence /path/to/Security.evtx   # all phases 0-7
spectre --name my-case --profile auto --phase 0 --evidence /path/to/x     # Phase 0 only
spectre --case ~/spectre-cases/001-my-case --phase 7                      # run up to a phase
```

Phase 7 is an examiner sign-off. Record decisions with `spectre approve`; it writes a chained audit row before editing the finding:

```bash
spectre approve --case ~/spectre-cases/001-my-case --finding F-001-001 \
    --examiner "Your Name" --decision APPROVED --rationale "why"
# --decision APPROVED | REJECTED | SUPERSEDED (SUPERSEDED needs --superseded-by F-...)
# --finding may be repeated
```

Evidence is copied into the case and made read-only (`chmod 444`, with `evidence/` locked to `0555`). To delete a case you must first unlock it, otherwise `rm -rf` fails:

```bash
chmod -R u+w ~/spectre-cases/001-my-case/evidence && rm -rf ~/spectre-cases/001-my-case
```

Only do this to a case the examiner has cleared for deletion. Environment variables are documented in the docstring of `src/spectre/config.py`; see `docs/dev-workflow.md` for the development workflow.

## Project Structure

```
src/spectre/
├── core/        — base classes, normalize, detect, emit, explain
├── modules/     — analyzer modules per evidence type (memory, evtx, disk, pcap)
├── pipeline/    — orchestration (runner, phases, audit, canary)
└── knowledge/   — FK YAML data files + MITRE map
```

## License

AGPL-3.0. See `LICENSE`.
