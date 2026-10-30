# Contributing

Thanks for helping improve Spectre.

- Read `docs/contributing-rules.md` for the rules a change must follow.
- Read `docs/dev-workflow.md` for the design and development workflow.
- Write the test first. Run the suite with `pytest` and lint with `ruff check src tests`
  before opening a pull request.
- Install for development with `pip install -e ".[dev]"`; `spectre-canary` reports
  environment health.
- Do not weaken the chain-of-custody, audit or validator guarantees; the deterministic
  core produces findings and the AI layer only explains them.
- Report security issues privately; see `SECURITY.md`.
