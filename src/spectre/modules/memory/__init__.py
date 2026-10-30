"""memory — memory image analyzer module (volatility3 + MemProcFS).

Supports dual-mode extraction:
  --engine vol        volatility3 only (fast, well-tested)
  --engine memprocfs  MemProcFS only (subprocess sandbox — survives crashes)
  --engine both       both engines (the default) — two engines over one image
                      is what lets matching claims corroborate

The choice resolves in `_resolve_engine`: an explicit argument, then
`SPECTRE_MEMORY_ENGINE`, then `both`.

MemProcFS runs in a subprocess because its native .so libraries (leechcore,
vmm) can SIGSEGV on non-Windows or malformed dumps. A subprocess crash is
caught and logged as a failure handle without taking down the pipeline. The
memprocfs daemon itself is a *grandchild* of that subprocess, which is why
teardown goes through the process group — see `_terminate_process_group`.
"""

import time
from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .enrich import enrich_events
from .extract import extract as extract_vol
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under memory/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)


def _terminate_process_group(proc, grace: float = 15.0) -> None:
    """Tear down the extraction subprocess *and* the memprocfs daemon below it.

    `memprocfs` is a grandchild: our Python child `Popen`s it and keeps the FUSE
    mount open for the life of the read. `subprocess.run(timeout=...)` kills
    only the direct child, so on timeout the daemon survived — still mounted,
    still backed by the read-only evidence file, outliving the case.

    So SIGTERM the child *alone* first: `extract_memprocfs` installs a handler
    (`_install_sigterm_unmount`) that lets `extract()`'s `finally` run, which
    unmounts properly and reaps the daemon. Then SIGKILL the whole session as a
    backstop for anything that ignored it.

    The group kill is skipped when the child shares our session — that means
    `start_new_session=True` did not take effect, and `killpg` would signal the
    pipeline itself.
    """
    import os
    import signal

    # Read the group id BEFORE anything can reap the child: once it is reaped,
    # `getpgid` fails and the surviving daemon becomes unreachable — which is
    # exactly the leak this function exists to close.
    try:
        pgid = os.getpgid(proc.pid)
        own_pgid = os.getpgid(0)
    except OSError:
        pgid = own_pgid = None

    try:
        proc.terminate()
    except OSError:
        pass

    deadline = time.time() + grace
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.1)

    if pgid is not None and pgid != own_pgid:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
    else:
        try:
            proc.kill()
        except OSError:
            pass

    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _run_mpfs_subprocess(case_dir: str, evidence_path: str) -> list[dict]:
    """Run MemProcFS extraction in a subprocess to survive SIGSEGV."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    from spectre import config

    # ── Shell logger (for execution.log) ──
    try:
        from spectre.pipeline.shell_log import log_command as _shell_log
    except ImportError:
        def _shell_log(*args, **kwargs):
            pass

    mpfs_script = Path(__file__).resolve().parent / "extract_memprocfs.py"
    if not mpfs_script.exists():
        return [_failure_handle(evidence_path, "extract_memprocfs.py not found")]

    mpfs_cmd = [sys.executable, str(mpfs_script),
                "--case-dir", case_dir, "--evidence", str(evidence_path)]
    timeout = config.MEMPROCFS_TIMEOUT
    start = time.time()

    try:
        # start_new_session so the memprocfs grandchild lands in a session we
        # can tear down as a unit -- see _terminate_process_group.
        proc = subprocess.Popen(mpfs_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        _shell_log(case_dir=case_dir, tool="memprocfs",
                   command=" ".join(mpfs_cmd),
                   exit_code=-1, duration_ms=duration_ms,
                   stderr=str(e),
                   stdout="", stdout_path="",
                   phase=2, phase_step="S1-extract-memprocfs")
        return [_failure_handle(evidence_path, f"MemProcFS subprocess error: {e}")]

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        # Measured, not assumed: this row goes into audit.jsonl, and the wait
        # can end short of the ceiling.
        duration_ms = int((time.time() - start) * 1000)
        _shell_log(case_dir=case_dir, tool="memprocfs",
                   command=" ".join(mpfs_cmd),
                   exit_code=-1, duration_ms=duration_ms,
                   stderr=f"Timeout after {timeout}s",
                   stdout="", stdout_path="",
                   phase=2, phase_step="S1-extract-memprocfs")
        return [_failure_handle(
            evidence_path,
            f"MemProcFS subprocess timed out ({timeout}s) — mount torn down")]
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        _shell_log(case_dir=case_dir, tool="memprocfs",
                   command=" ".join(mpfs_cmd),
                   exit_code=-1, duration_ms=duration_ms,
                   stderr=str(e),
                   stdout="", stdout_path="",
                   phase=2, phase_step="S1-extract-memprocfs")
        return [_failure_handle(evidence_path, f"MemProcFS subprocess error: {e}")]

    returncode = proc.returncode
    stdout = stdout or ""
    stderr = stderr or ""
    duration_ms = int((time.time() - start) * 1000)

    def _log_mpfs_failure(msg: str) -> None:
        _shell_log(case_dir=case_dir, tool="memprocfs",
                   command=" ".join(mpfs_cmd),
                   exit_code=returncode, duration_ms=duration_ms,
                   stderr=msg, stdout="", stdout_path="",
                   phase=2, phase_step="S1-extract-memprocfs")

    if returncode < 0:
        sig = -returncode
        sig_names = {11: "SIGSEGV", 6: "SIGABRT", 4: "SIGILL", 8: "SIGFPE"}
        sig_name = sig_names.get(sig, f"signal {sig}")
        _log_mpfs_failure(f"crashed ({sig_name}): {stderr[:300]}")
        return [_failure_handle(
            evidence_path,
            f"MemProcFS crashed ({sig_name}) — dump may not be a valid Windows memory image. "
            f"stderr: {stderr[:200]}"
        )]

    if returncode != 0:
        _log_mpfs_failure(stderr[:500])
        return [_failure_handle(
            evidence_path,
            f"MemProcFS exit {returncode}: {stderr[:500]}"
        )]

    try:
        handles = json.loads(stdout)
        for h in handles:
            h["engine"] = "memprocfs"
        # Chain-of-custody: one audit.jsonl row per artifact (like vol via
        # tool_runner). audit.append() also emits the execution.log line, so
        # each memprocfs artifact shows up tagged [P2:S1-extract-memprocfs].
        _audit_mpfs_handles(case_dir, handles)
        return handles
    except json.JSONDecodeError:
        _log_mpfs_failure(f"non-JSON output: {stdout[:300]}")
        return [_failure_handle(
            evidence_path,
            f"MemProcFS produced non-JSON output: {stdout[:300]}"
        )]


def _failure_handle(evidence_path: str, error: str) -> dict:
    """Produce a failure handle matching the extraction handle schema."""
    return {
        "path": "",
        "line_count": 0,
        "size_bytes": 0,
        "output_sha256": "",
        "is_json": False,
        "fk_envelope": None,
        "execution_id": "",
        "exit_code": 1,
        "duration_ms": 0,
        "result": "failure",
        "stderr": error,
        "evidence_path": str(evidence_path),
        "artifact_type": "memory_pslist",
        "plugin": "memprocfs",
        "tool": "memprocfs",
        "tool_version": "5.17.8",
        "engine": "memprocfs",
        "exact_command": "memprocfs subprocess",
        "params": {"engine": "memprocfs", "phase": "extraction",
                   "evidence_path": str(evidence_path)},
    }


def _audit_mpfs_handles(case_dir: str, handles: list[dict]) -> None:
    """Write one tamper-evident audit.jsonl row per memprocfs artifact handle.

    Mirrors what tool_runner does for volatility outputs so memprocfs artifacts
    join the SHA-256 chain of custody instead of living only in execution.log.
    """
    import hashlib
    from pathlib import Path
    try:
        from spectre.pipeline.audit import append as audit_append
    except ImportError:
        return

    for h in handles:
        out_path = h.get("path", "")
        sha = h.get("output_sha256", "")
        if out_path and not sha:
            try:
                with open(out_path, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                sha = ""
        entry = {
            "actor": "deterministic-core",
            "action": "tool_exec",
            "tool": h.get("tool", "memprocfs"),
            "tool_version": h.get("tool_version", ""),
            "exact_command": h.get("exact_command", "memprocfs FUSE"),
            "params": h.get("params", {}),
            "case_id": Path(case_dir).name,
            "output_path": out_path,
            "output_sha256": sha,
            "output_format": "json",
            "output_line_count": h.get("line_count", 0),
            "output_size_bytes": h.get("size_bytes", 0),
            "result": h.get("result", "success"),
            "exit_code": h.get("exit_code", 0),
            "duration_ms": h.get("duration_ms", 0),
            "stderr": h.get("stderr", ""),
            "finding_id": None,
            "phase": 2,
            "phase_step": "S1-extract-memprocfs",
        }
        # The handle cites its own tool_exec row, the same as run_tool's
        # handles, so findings built from it resolve in Phase 4.
        h["execution_id"] = audit_append(case_dir, entry)


_ENGINES = ("vol", "memprocfs", "both")


def _resolve_engine(engine: str | None) -> str:
    """Settle the engine choice: explicit argument, then env knob, then both.

    Read here rather than threaded through `phase_runner` so every caller
    honours `SPECTRE_MEMORY_ENGINE` through one seam, and an explicit argument
    (the `spectre-memory --engine` flag) still wins over the environment.

    An unrecognized value falls back to `both` and says so on stderr. The
    previous behaviour was worse than an error: each engine was gated on
    `engine in (...)`, so a typo ran neither and produced an empty extraction
    that is indistinguishable from an image with nothing in it.
    """
    import sys

    from spectre import config

    if engine is None:
        engine = config.MEMORY_ENGINE or "both"
    resolved = str(engine).strip().lower()
    if resolved not in _ENGINES:
        print(f"[memory] unrecognized engine {engine!r} — expected one of "
              f"{', '.join(_ENGINES)}; running both", file=sys.stderr)
        return "both"
    return resolved


def extract(case_dir: str, evidence_path: str,
            engine: str | None = None) -> list[dict]:
    """Run memory extraction with the specified engine(s).

    `engine=None` defers to `SPECTRE_MEMORY_ENGINE`, then to `both`.
    """
    engine = _resolve_engine(engine)
    handles: list[dict] = []

    if engine in ("vol", "both"):
        vol_handles = extract_vol(case_dir, evidence_path)
        for h in vol_handles:
            h["engine"] = "volatility3"
        handles.extend(vol_handles)

    if engine in ("memprocfs", "both"):
        mpfs_handles = _run_mpfs_subprocess(case_dir, evidence_path)
        handles.extend(mpfs_handles)

    return handles


MEMORY_MODULE = AnalyzerModule(
    name="memory",
    artifact_type="memory_image",
    required_tools=["vol"],
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    enrich=enrich_events,
    description="Memory image (.raw/.mem/.vmem/.lime) — triage via volatility3 + optional MemProcFS.",
)
