"""
shell_log.py — Universal command + output logger for the Spectre pipeline.

Every command executed by the pipeline — whether through tool_runner,
a direct subprocess, grep/jq/awk filter, or any future tool — should
call log_command() so it appears in execution.log.

The log is a complete transcript: phase+step identifier, command line,
exit code, timing, stderr on failure, AND the command's stdout output
(truncated at a configurable limit with a pointer to the full output file).
This makes execution.log the authoritative record — grep it to trace
every tool invocation and its result without opening individual
output files.

Usage:
    from shell_log import log_command, write_summary

    # After running a command:
    log_command(
        case_dir="/tmp/example-case",
        tool="grep",
        command="grep -i 'mimikatz' raw_extract/pslist.json",
        exit_code=0,
        duration_ms=45,
        stdout="  PID 1234  mimikatz.exe\n  PID 5678  mimikatz.exe\n",
        stdout_path="raw_extract/pslist_mimikatz.txt",
        extra="2 matches",
        phase=2,
        phase_step="S4-grep-mimikatz",
    )

    # At pipeline end:
    write_summary(case_dir)
"""

import os
import re
import threading
from datetime import datetime, timezone

_LOCK = threading.Lock()
_SEQ_COUNTERS: dict[str, int] = {}
_HEADER_WRITTEN: set[str] = set()

# An execution.log entry header line begins with a "YYYY-MM-DD HH:MM:SS"
# timestamp (see _utcnow_full). Used to count existing entries on resume so a
# fresh process continues numbering instead of restarting at 1.
_ENTRY_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ")

# ── Output truncation ──
MAX_STDOUT_LINES = 200
MAX_STDOUT_CHARS = 20_000


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow_full() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _count_existing_entries(log_path: str) -> int:
    """Count entry header lines already in an execution.log (for seq seeding)."""
    try:
        with open(log_path, "r") as f:
            return sum(1 for line in f if _ENTRY_LINE_RE.match(line))
    except OSError:
        return 0


def _ensure_initialized(case_dir: str, log_path: str) -> None:
    """Initialize per-process state for a case, honouring existing on-disk log.

    Runs once per process per case_dir (guarded by _HEADER_WRITTEN). Writes the
    header ONLY when execution.log is absent or empty, so resuming a stopped run
    in a fresh process appends instead of truncating. Seeds the sequence counter
    from any entries already in the log. Caller must hold _LOCK.
    """
    if case_dir in _HEADER_WRITTEN:
        return
    _HEADER_WRITTEN.add(case_dir)

    existing = _count_existing_entries(log_path)
    _SEQ_COUNTERS[case_dir] = existing + 1

    # Only write the header for a brand-new (absent/empty) log.
    if existing == 0 and (not os.path.exists(log_path)
                          or os.path.getsize(log_path) == 0):
        case_name = os.path.basename(case_dir)
        header = (
            f"{'='*78}\n"
            f"Spectre Execution Log — Phase-by-Phase Transcript\n"
            f"Case: {case_name}\n"
            f"Started: {_utcnow()}\n"
            f"Each entry: YYYY-MM-DD HH:MM:SS [PX:SY] [step] command → result; "
            f"stdout follows (truncated at {MAX_STDOUT_LINES} lines / {MAX_STDOUT_CHARS} chars)\n"
            f"Full output files under raw_extract/ — see stdout_path references\n"
            f"{'='*78}\n\n"
        )
        with open(log_path, "w") as f:
            f.write(header)


def _truncate_stdout(stdout: str, stdout_path: str = "") -> str:
    """Truncate stdout to safe limits. Returns the rendered block or ''."""
    if not stdout:
        return ""

    lines = stdout.split("\n")
    truncated_lines = False
    truncated_chars = False

    if len(lines) > MAX_STDOUT_LINES:
        lines = lines[:MAX_STDOUT_LINES]
        truncated_lines = True

    truncated = "\n".join(lines)
    if len(truncated) > MAX_STDOUT_CHARS:
        truncated = truncated[:MAX_STDOUT_CHARS]
        truncated_chars = True

    if not truncated.strip():
        return ""

    # Build the output block
    block = "  ── stdout"
    if stdout_path:
        block += f" (full output: {stdout_path})"
    block += " ──\n"

    # Indent each line of output
    for line in truncated.split("\n"):
        block += f"  │ {line}\n"

    if truncated_lines:
        block += f"  │ ... (truncated at {MAX_STDOUT_LINES} lines)"
        if stdout_path:
            block += f", see {stdout_path}"
        block += "\n"
    elif truncated_chars:
        block += f"  │ ... (truncated at {MAX_STDOUT_CHARS} chars)"
        if stdout_path:
            block += f", see {stdout_path}"
        block += "\n"

    block += "  ── end stdout ──\n"
    return block


def log_command(
    case_dir: str,
    tool: str,
    command: str,
    exit_code: int = 0,
    duration_ms: int = 0,
    stderr: str = "",
    extra: str = "",
    stdout: str = "",
    stdout_path: str = "",
    phase: int = 0,
    phase_step: str = "",
) -> int:
    """Log a command + its output to execution.log. Returns the assigned sequence number.

    Thread-safe. Auto-creates the log with a header on first call.
    Full command lines and truncated stdout are written without further shortening.

    Args:
        case_dir: Absolute path to case directory
        tool: Short tool name (e.g. 'vol:pslist', 'grep', 'jq', 'memprocfs')
        command: Full command line as executed
        exit_code: Process exit code (0 = success)
        duration_ms: Wall-clock duration in milliseconds
        stderr: Stderr output (shown only on failure or if non-empty)
        extra: Optional extra info (row counts, output paths, etc.)
        stdout: The command's stdout output (truncated internally if needed)
        stdout_path: Path to the full output file (for reference)
        phase: Pipeline phase number (0-7)
        phase_step: Short step identifier (e.g. 'S2-pslist', 'S3-anchors')
    """
    log_path = os.path.join(case_dir, "execution.log")

    with _LOCK:
        # Write header (only for a fresh log) + seed seq counter from any
        # existing on-disk log, so resuming in a new process appends.
        _ensure_initialized(case_dir, log_path)

        seq = _SEQ_COUNTERS[case_dir]
        _SEQ_COUNTERS[case_dir] = seq + 1

        # Build log line
        ts = _utcnow_full()
        status = "PASS" if exit_code == 0 else f"FAIL({exit_code})"
        dur = f"{duration_ms}ms" if duration_ms else ""

        # Phase+step tags: "[P2:S3] [recognize]" — split "S3-recognize" on the
        # first '-' into step id and step name. "[P0]" alone if no step.
        if phase_step:
            step_id, _, step_name = phase_step.partition("-")
            phase_tag = f"[P{phase}:{step_id}]"
            name_tag = f"[{step_name}]" if step_name else ""
        else:
            phase_tag = f"[P{phase}]"
            name_tag = ""

        # Result = status [duration] [| extra]
        result = status
        if dur:
            result += f" {dur}"
        if extra:
            result += f" | {extra}"

        # Single header line: timestamp [P#:S#] [step] command → result
        parts = [ts, phase_tag]
        if name_tag:
            parts.append(name_tag)
        if command:
            parts.append(command)
        parts.append(f"→ {result}")
        line = " ".join(parts) + "\n"

        # Show stderr on failure OR if explicitly provided
        if exit_code != 0 and stderr:
            stderr_clean = stderr.strip()[:500]
            if stderr_clean:
                line += f"  stderr: {stderr_clean}\n"

        # ── Include stdout output inline ──
        stdout_block = _truncate_stdout(stdout, stdout_path)
        if stdout_block:
            line += stdout_block

        line += "\n"

        with open(log_path, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    return seq


def log_step(case_dir: str, phase: int, title: str, step_id: str = "") -> None:
    """Append a phase/step title marker to execution.log.

    Written regardless of stdout verbosity so the persistent transcript carries
    the same structure the console shows. Marker lines are divider-style (no
    leading timestamp) so they are not counted as command entries by the
    sequence seeder or the failure scan in write_summary().

        ── [P2:S1] Raw Events Extraction ──
    """
    log_path = os.path.join(case_dir, "execution.log")
    tag = f"[P{phase}:{step_id}]" if step_id else f"[P{phase}]"
    line = f"── {tag} {title} ──\n"
    with _LOCK:
        _ensure_initialized(case_dir, log_path)
        with open(log_path, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())


def write_summary(case_dir: str, total_commands: int | None = None,
                  total_failures: int | None = None) -> None:
    """Write a summary footer to execution.log. Call at pipeline end.

    Args:
        case_dir: Case directory
        total_commands: Total commands executed (auto-counted if None)
        total_failures: Total failed commands (auto-counted if None)
    """
    log_path = os.path.join(case_dir, "execution.log")
    if not os.path.exists(log_path):
        return

    # Count from the log if not provided
    if total_commands is None:
        total_commands = _SEQ_COUNTERS.get(case_dir, 1) - 1
    if total_failures is None:
        total_failures = 0
        try:
            with open(log_path, "r") as f:
                for line in f:
                    # Entry header lines carry the result after a "→"; a failed
                    # command renders "→ FAIL(...)". "→" never appears in the
                    # "│"-prefixed stdout block, so this only counts real failures.
                    if "→ FAIL" in line:
                        total_failures += 1
        except Exception:
            pass

    footer = (
        f"{'─'*78}\n"
        f"Pipeline complete: {_utcnow()}\n"
        f"Commands executed: {total_commands}\n"
        f"Failures: {total_failures}\n"
        f"{'─'*78}\n"
    )

    with _LOCK:
        with open(log_path, "a") as f:
            f.write(footer)
            f.flush()
            os.fsync(f.fileno())
