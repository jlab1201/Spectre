"""
console.py — shared terminal presentation helpers for the Spectre pipeline.

Kept dependency-free at import time (no top-level pipeline imports) so any
module — including case_setup and runner — can import it without
circular-import risk. shell_log is imported lazily inside functions.

Verbosity model (set once from the CLI via set_verbosity):

    0  (default)  phase banners, final summaries, warnings/errors only
    1  (-v)       + step titles  (the [P0:S1]-style markers, all phases)
    2  (-vv)      + per-item progress detail
    3  (-vvv)     + debug detail

Step/phase titles are ALSO written to execution.log regardless of the stdout
verbosity level, so the persistent transcript keeps the same structure the
console shows when a case_dir is supplied.
"""

import sys

_BANNER_WIDTH = 60

# Process-wide stdout verbosity. Set once from the CLI; read by the gated
# emitters below. Defaults to 0 (minimal) so library/test use stays quiet.
_VERBOSITY = 0


def set_verbosity(level: int) -> None:
    """Set the process-wide stdout verbosity (clamped to 0-3)."""
    global _VERBOSITY
    _VERBOSITY = max(0, min(3, int(level)))


def get_verbosity() -> int:
    return _VERBOSITY


def phase_banner(name: str, *, case_dir: str | None = None,
                 phase: int | None = None) -> None:
    """Print a phase banner in the standard box-drawing style to stderr.

    Always shown (level 0). When case_dir + phase are given, the title is also
    recorded in execution.log. Used by every phase so Phase 0 and Phases 1-7
    look identical:

        ────────────────────────────────────────────────────────────
          Phase 1: Direction
        ────────────────────────────────────────────────────────────
    """
    rule = "─" * _BANNER_WIDTH
    print(f"\n{rule}", file=sys.stderr)
    print(f"  {name}", file=sys.stderr)
    print(rule, file=sys.stderr)
    if case_dir is not None and phase is not None:
        _log_step(case_dir, phase, name, step_id="")


def step(title: str, *, case_dir: str | None = None, phase: int = 0,
         step_id: str = "") -> None:
    """A step title within a phase. Shown at verbosity >= 1.

    Always recorded in execution.log when case_dir is supplied (independent of
    the stdout verbosity level). `step_id` like "S1" produces a "[P0:S1]" tag.
    """
    if case_dir is not None:
        _log_step(case_dir, phase, title, step_id=step_id)
    if _VERBOSITY >= 1:
        tag = f"[P{phase}:{step_id}] " if step_id else ""
        print(f"\n  {tag}{title}", file=sys.stderr)


def detail(msg: str) -> None:
    """Per-item progress detail. Shown at verbosity >= 2."""
    if _VERBOSITY >= 2:
        print(f"    {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    """Low-level debug detail. Shown at verbosity >= 3."""
    if _VERBOSITY >= 3:
        print(f"    [debug] {msg}", file=sys.stderr)


def note(msg: str) -> None:
    """Always-shown informational line (summaries, results, warnings)."""
    print(f"  {msg}", file=sys.stderr)


def _log_step(case_dir: str, phase: int, title: str, step_id: str) -> None:
    """Persist a step/phase title to execution.log (best-effort, lazy import)."""
    try:
        from spectre.pipeline.shell_log import log_step
        log_step(case_dir, phase, title, step_id=step_id)
    except Exception:
        pass
