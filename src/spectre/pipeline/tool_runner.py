"""
tool_runner.py — shared execution layer for all forensic tool skills.

Every forensic tool invocation routes through this module:
  1. Build command from typed parameters
  2. Execute via subprocess (with timeout, capture stdout/stderr)
  3. Measure output (wc -l, file size)
  4. Validate output format (JSON probe for JSON tools)
  5. Write audit row via audit.py
  6. Return typed handle: {path, line_count, size_bytes, fk_envelope, execution_id}

This is the architectural enforcement point — no raw terminal access for the lead agent.
All tool calls are audited and parameter-typed.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from datetime import datetime, timezone

from spectre.pipeline.audit import append as audit_append
from spectre.pipeline.denylist import check as denylist_check, block_and_audit


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@lru_cache(maxsize=None)
def resolve_tool_version(binary: str, version_arg: str = "--version",
                         fallback: str = "") -> str:
    """Resolve a tool's REAL version string for the audit trail (A1-H4).

    Chain of custody: a result is only reproducible if the audit row records
    WHICH version of the tool produced it. Every module used to hardcode a
    tool *name* ("volatility3", "tcpdump") or a stale guess here — this probes
    the actually-installed binary instead.

    Graceful by design — returns ``fallback or binary`` when the binary is
    absent or the probe fails; never raises, never blocks extraction. Cached
    per (binary, arg) for the process, mirroring pcap/zeek.py's _zeek_version.
    """
    path = shutil.which(binary)
    if not path:
        return fallback or binary
    try:
        # version_arg may be a tuple for multi-arg probes (W4-6: volatility3's
        # `vol --version` exits 2; `vol -q frameworkinfo.FrameworkInfo` works).
        args = list(version_arg) if isinstance(version_arg, tuple) else [version_arg]
        out = subprocess.run([path, *args], capture_output=True,
                             text=True, timeout=15)
        lines = ((out.stdout or "") + "\n" + (out.stderr or "")).splitlines()
        # Only accept a line carrying a dotted version number (e.g.
        # "tcpdump version 4.99.4", "Volatility 3 Framework 2.5.0",
        # "Rip v.3.0"). This deliberately rejects usage/help headers so a
        # tool with an unexpected version flag falls back to `fallback`
        # rather than recording a garbage "version". Never raises.
        for line in lines:
            if re.search(r"\d+\.\d+", line):
                return line.strip()[:200]
    except (OSError, subprocess.SubprocessError):
        pass
    return fallback or binary


def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_json(path: str) -> bool:
    """
    Probe whether a file is valid JSON (first 10 lines).
    NOTE: This handles JSONL (one JSON object per line) correctly.
    A pretty-printed JSON array >10 lines will falsely report is_json=False
    because the probe only sees the opening '[' and not enough content
    to parse as a complete JSON value. Low priority — all current tool
    outputs are JSONL or small JSON. If a tool produces pretty-printed
    JSON arrays, raise the probe to 100 lines or parse the first line
    and check for leading '['.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Read first 10 lines and try to parse as JSON
            head = "".join(f.readline() for _ in range(10))
            # Try JSON array
            json.loads(head)
            return True
    except json.JSONDecodeError:
        pass
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Try JSONL (first line)
            first_line = f.readline().strip()
            if first_line:
                json.loads(first_line)
                return True
    except json.JSONDecodeError:
        pass
    return False


def run_tool(
    case_dir: str,
    tool_name: str,
    tool_version: str,
    command: list[str],
    params: dict,
    output_path: str,
    timeout: int = 300,
    fk_envelope: dict | None = None,
    output_format: str = "text",
) -> dict:
    """
    Execute a forensic tool with typed parameters.

    Args:
        case_dir: Path to case directory (for audit trail)
        tool_name: Tool name (e.g. "volatility3", "evtx_dump")
        tool_version: Tool version string
        command: Full command as list of strings
        params: Typed parameters dict for audit row
        output_path: Where to write tool output
        timeout: Max execution time in seconds
        fk_envelope: FK YAML dict to attach (optional)
        output_format: "json", "csv", "text", or "binary"

    Returns typed handle:
        {
            "path": str,
            "line_count": int,
            "size_bytes": int,
            "output_sha256": str,
            "is_json": bool,
            "fk_envelope": dict | None,
            "execution_id": str,
            "exit_code": int,
            "duration_ms": int,
            "result": "success" | "error",
            "stderr": str,
        }
    """
    # ── Denylist check (HARD gate — Phase 3) ──
    allowed, deny_reason = denylist_check(command, case_dir=case_dir)
    if not allowed:
        # Write audit row and refuse execution
        block_and_audit(command, case_dir, deny_reason)
        raise PermissionError(f"Command blocked by denylist: {deny_reason}")

    start = time.time()

    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Determine text mode based on output format
    text_mode = output_format != "binary"

    # Execute — pin the child's TZ to UTC. Without this, any tool whose
    # output renders a local-clock timestamp (tcpdump/tshark -tttt,
    # tshark's frame.time, etc.) silently inherits the analyst's ambient
    # shell TZ, so the SAME evidence prints a different wall-clock time
    # depending on who runs the extraction and where (A6 Finding 1). This
    # is a cutover: it affects only NEW tool_exec runs going forward, not
    # any output already on disk in an existing case.
    child_env = {**os.environ, "TZ": "UTC"}
    # Stream stdout straight to output_path (bounded memory). Text output is
    # newline-normalized in place afterwards so the bytes match the former
    # subprocess text=True path (universal newlines).
    timed_out = False
    stderr_raw = b""
    exit_code = -1
    created_here = not os.path.exists(output_path)
    try:
        with open(output_path, "wb") as out_f:
            try:
                result = subprocess.run(
                    command,
                    stdout=out_f,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    env=child_env,
                )
                exit_code = result.returncode
                stderr_raw = result.stderr or b""
            except subprocess.TimeoutExpired:
                timed_out = True
    except Exception:
        # Launch failure (missing/unexecutable tool): never leave an empty
        # stub behind (matters for carve outputs in evidence/derived/). Only
        # remove a file this call created.
        if created_here:
            try:
                os.unlink(output_path)
            except OSError:
                pass
        raise
    if text_mode:
        _normalize_newlines_inplace(output_path)

    duration_ms = int((time.time() - start) * 1000)
    if timed_out:
        return _build_handle(
            case_dir, tool_name, tool_version, command, params,
            output_path, fk_envelope, output_format,
            exit_code=-1, duration_ms=duration_ms,
            result="error", stderr=f"Timeout after {timeout}s",
        )

    stderr = stderr_raw.decode("utf-8", errors="replace")[:2000]
    return _build_handle(
        case_dir, tool_name, tool_version, command, params,
        output_path, fk_envelope, output_format,
        exit_code=exit_code, duration_ms=duration_ms,
        result="success" if exit_code == 0 else "error",
        stderr=stderr,
    )


def _normalize_newlines_inplace(path: str, chunk_size: int = 1 << 20) -> None:
    """Rewrite CRLF and lone CR as LF, in bounded chunks (temp file + replace).

    A trailing CR is carried across chunk boundaries so a CRLF split between
    chunks is still collapsed. Skips the rewrite when nothing changes.
    """
    import tempfile

    orig_mode = os.stat(path).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(path)),
        prefix=f".{os.path.basename(path)}.", suffix=".nl-tmp",
    )
    changed = False
    try:
        with open(path, "rb") as src, os.fdopen(fd, "wb") as dst:
            carry = b""
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                data = carry + chunk
                if data.endswith(b"\r"):
                    carry, data = b"\r", data[:-1]
                else:
                    carry = b""
                if b"\r" in data:
                    changed = True
                    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                dst.write(data)
            if carry:
                changed = True
                dst.write(b"\n")
        if changed:
            os.chmod(tmp, orig_mode)
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _build_handle(
    case_dir, tool_name, tool_version, command, params,
    output_path, fk_envelope, output_format,
    exit_code, duration_ms, result, stderr,
) -> dict:
    """Build the typed handle and write audit row."""
    # Measure output
    path = Path(output_path)
    if path.exists():
        # For binary format, line_count is 0 and skip JSON validation
        if output_format == "binary":
            line_count = 0
            is_json = False
        else:
            with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                line_count = sum(1 for _ in f)
            is_json = _validate_json(output_path) if output_format == "json" else False
        size_bytes = path.stat().st_size
        output_sha256 = _sha256_file(output_path)
    else:
        line_count = 0
        size_bytes = 0
        output_sha256 = ""
        is_json = False

    # Write audit row
    exact_command = " ".join(command)
    audit_entry = {
        "actor": "deterministic-core",
        "action": "tool_exec",
        "tool": tool_name,
        "tool_version": tool_version,
        "exact_command": exact_command,
        "params": params,
        "case_id": Path(case_dir).name,
        "output_path": str(output_path),
        "output_sha256": output_sha256,
        "output_format": output_format,
        "output_line_count": line_count,
        "output_size_bytes": size_bytes,
        "result": result,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stderr": stderr[:500],
        "finding_id": None,
        "phase": 2,   # tool_exec always Phase 2 (Extraction)
        "phase_step": f"S1-extract-{tool_name}",
    }
    execution_id = audit_append(case_dir, audit_entry)

    # Build handle
    handle = {
        "path": str(output_path),
        "line_count": line_count,
        "size_bytes": size_bytes,
        "output_sha256": output_sha256,
        "is_json": is_json,
        "fk_envelope": fk_envelope,
        "execution_id": execution_id,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "result": result,
        "stderr": stderr,
    }

    # ── Auto-apply Empty Data Protocol (Phase 3 hardening) ──
    handle["empty_data_status"] = empty_data_protocol(handle)

    return handle


def passthrough_handle(
    case_dir: str,
    tool_name: str,
    tool_version: str,
    evidence_path: str,
    params: dict,
    output_format: str = "text",
) -> dict:
    """Build a typed handle that references the evidence file IN PLACE.

    For evidence that is already in a parseable text form (CSV, unix .log),
    there is no external tool to run and copying a multi-GB file would defeat
    the purpose of streaming. This records a `tool_exec` audit row (so chain of
    custody is preserved) and returns a handle whose `path` is the evidence
    file itself. Normalizers stream from that path; nothing is duplicated.
    """
    path = Path(evidence_path)
    start = time.time()
    if path.exists():
        with open(evidence_path, "r", errors="replace") as f:
            line_count = sum(1 for _ in f)
        size_bytes = path.stat().st_size
        output_sha256 = _sha256_file(evidence_path)
    else:
        line_count = 0
        size_bytes = 0
        output_sha256 = ""

    exact_command = f"passthrough:{tool_name} {evidence_path}"
    audit_entry = {
        "actor": "deterministic-core",
        "action": "tool_exec",
        "tool": tool_name,
        "tool_version": tool_version,
        "exact_command": exact_command,
        "params": params,
        "case_id": Path(case_dir).name,
        "output_path": str(evidence_path),
        "output_sha256": output_sha256,
        "output_format": output_format,
        "output_line_count": line_count,
        "output_size_bytes": size_bytes,
        "result": "success" if path.exists() else "error",
        "exit_code": 0 if path.exists() else -1,
        "duration_ms": int((time.time() - start) * 1000),
        "stderr": "" if path.exists() else "evidence file not found",
        "finding_id": None,
        "phase": 2,
        "phase_step": f"S1-extract-{tool_name}",
    }
    execution_id = audit_append(case_dir, audit_entry)

    handle = {
        "path": str(evidence_path),
        "line_count": line_count,
        "size_bytes": size_bytes,
        "output_sha256": output_sha256,
        "is_json": False,
        "fk_envelope": None,
        "execution_id": execution_id,
        "exit_code": 0 if path.exists() else -1,
        "duration_ms": 0,
        "result": "success" if path.exists() else "error",
        "stderr": "",
    }
    handle["empty_data_status"] = empty_data_protocol(handle)
    return handle


def empty_data_protocol(handle: dict) -> str:
    """
    Apply Empty Data Protocol (from engram-mcp / VeriSIFT):
    If tool returns no output, return "UNVERIFIED" marker.
    Never say "clean" — absence of evidence is not evidence of absence.

    W4-1 (R1-F2): a tool that FAILED (non-zero exit, or result
    error/failure) is "FAILED" whatever it wrote — error text is not data.
    A pass skipped because its tool was unavailable is "UNVERIFIED".
    """
    if handle_failed(handle):
        return "FAILED"
    if str(handle.get("result", "")).startswith("skipped"):
        return "UNVERIFIED"
    if handle.get("line_count", 0) == 0 and handle.get("size_bytes", 0) == 0:
        return "UNVERIFIED"
    return "DATA_PRESENT"


_FAILED_RESULTS = {"error", "failure", "failed"}


def handle_failed(handle: dict) -> bool:
    """True when the tool run behind `handle` did not succeed: result
    error/failure, or a non-zero exit on a handle that was not deliberately
    skipped. A legacy handle carrying neither field is not a failure."""
    result = str(handle.get("result", "") or "")
    if result.startswith("skipped"):
        return False
    if result in _FAILED_RESULTS:
        return True
    exit_code = handle.get("exit_code")
    return exit_code not in (None, 0)


# Passes that sweep raw bytes without parsing the artifact (a strings-style
# URL carve succeeds on ANY input). They never make an artifact "examined"
# on their own: 17 failed vol plugins + 1 successful carve is a FAILED
# memory extraction, not a partial one. Modules mark such handles with
# handle["auxiliary"] = True (authoritative). This tool-name set is only a
# back-compat fallback for handles recorded before the flag existed.
AUXILIARY_TOOLS = frozenset({"carve_urls"})


def is_auxiliary(handle: dict) -> bool:
    return bool(handle.get("auxiliary")) or str(handle.get("tool", "")) in AUXILIARY_TOOLS


def handle_skipped(handle: dict) -> bool:
    """A pass that never ran (tool unavailable) — neither failed nor
    succeeded; it must never count as a successful extraction."""
    return str(handle.get("result", "") or "").startswith("skipped")


def handle_succeeded(handle: dict) -> bool:
    return not handle_failed(handle) and not handle_skipped(handle)


def extraction_outcome(handles: list[dict]) -> dict:
    """Per-artifact extraction outcome over ALL handles (never handles[0]).

    status (judged on the primary, non-auxiliary runs):
    SUCCESS (every run succeeded), PARTIAL (some failed),
    EXTRACTION_FAILED (no primary run succeeded, or nothing ran).
    empty_data: DATA_PRESENT if any successful run produced output,
    UNVERIFIED if the successful runs were all empty (or nothing ran),
    FAILED if extraction failed.
    """
    statuses = [h.get("empty_data_status") or empty_data_protocol(h) for h in handles]
    failed = sum(1 for h in handles if handle_failed(h))
    primary = [h for h in handles if not is_auxiliary(h)] or list(handles)
    # W4 review LOW: a skipped-tool marker is not a successful run.
    primary_ok = sum(1 for h in primary if handle_succeeded(h))
    ok = sum(1 for h in handles if handle_succeeded(h))
    if not handles:
        status, empty = "EXTRACTION_FAILED", "UNVERIFIED"
    elif primary_ok == 0:
        status, empty = "EXTRACTION_FAILED", "FAILED"
    else:
        status = "SUCCESS" if failed == 0 else "PARTIAL"
        empty = ("DATA_PRESENT" if any(
            s == "DATA_PRESENT" for h, s in zip(handles, statuses)
            if handle_succeeded(h)) else "UNVERIFIED")
    return {"status": status, "empty_data": empty,
            "handles_ok": ok, "handles_failed": failed,
            "primary_ok": primary_ok}


def size_gate(handle: dict, max_lines: int = 500, max_bytes: int = 50000) -> bool:
    """
    Check if output exceeds context-safe thresholds.
    Returns True if output is safe to read directly, False if needs filtering.
    """
    return handle["line_count"] <= max_lines and handle["size_bytes"] <= max_bytes
