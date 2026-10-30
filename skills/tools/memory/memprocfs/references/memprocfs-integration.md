# MemProcFS Integration — Key Patterns and Reproduction

## SIGSEGV Reproduction

The native `.so` libraries (leechcore.so, vmm.so) in MemProcFS v5.17.8 crash on certain memory dumps.

**Test case**: `Challenge.raw` — a CTF memory dump (1.5 GB, SHA-256: `80366d7ec64a5529c95c2f523f4281a5f11efbad33ecb19f73525470c1407b23`). `file(1)` identifies it as "Windows Event Trace Log" but volatility3 parses it successfully (745 processes, 1264 netscan rows).

**Crash signature**:
```
subprocess exit code: -11 (SIGSEGV)
```

A Python `try/except` around `memprocfs.Vmm()` cannot catch this — SIGSEGV kills the process.

**Fix pattern** (from `memory/__init__.py`):
```python
proc = subprocess.Popen(
    [sys.executable, "extract_memprocfs.py",
     "--case-dir", case_dir, "--evidence", evidence_path],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    start_new_session=True,          # see "Teardown" below
)
try:
    stdout, stderr = proc.communicate(timeout=config.MEMPROCFS_TIMEOUT)
except subprocess.TimeoutExpired:
    _terminate_process_group(proc)
    ...
if proc.returncode < 0:
    sig = -proc.returncode
    sig_names = {11: "SIGSEGV", 6: "SIGABRT", 4: "SIGILL", 8: "SIGFPE"}
    return [_failure_handle(evidence_path,
                            f"crashed ({sig_names.get(sig, sig)})")]
return json.loads(stdout)
```

## Teardown: the daemon is a grandchild

`subprocess.run(..., timeout=N)` is **not** sufficient here, and the difference
is a chain-of-custody one. `memprocfs` is a grandchild: the Python child
`Popen`s it and holds the FUSE mount open for the life of the read. `run()`
kills only the direct child, so on timeout the daemon survives — measured on
Challenge.raw with a 1 s ceiling:

```
/opt/memprocfs/memprocfs -device .../Challenge.raw -mount /tmp/mpfs_zsznxdlr
/dev/fuse on /tmp/mpfs_zsznxdlr type fuse (rw,nosuid,nodev,...)
```

A writable FUSE view of read-only evidence, outliving the case, recorded
nowhere. The fix is three parts:

1. `start_new_session=True` so the daemon lands in a session we can address.
2. SIGTERM the child *alone* first — `extract_memprocfs._install_sigterm_unmount`
   turns that into a `SystemExit` so `extract()`'s `finally` runs `_unmount_dump`.
   Python's default SIGTERM action skips `finally` entirely.
3. `os.killpg(..., SIGKILL)` as the backstop, skipped when the child shares our
   own group (which would signal the pipeline itself).

Read the group id *before* anything reaps the child: once reaped, `getpgid`
fails and the surviving daemon is unreachable.

## Timeout and engine selection

`SPECTRE_MEMPROCFS_TIMEOUT` (default 600 s) bounds the whole pass. The audit
row reports **measured** elapsed time on the timeout path, not the ceiling.

`SPECTRE_MEMORY_ENGINE` selects `vol` | `memprocfs` | `both`; unset means
`both`, and an explicit `--engine` argument overrides it:

```python
def extract(case_dir, evidence_path, engine=None):   # None -> env -> "both"
```

An unrecognized value falls back to `both` with a stderr warning — never to
"run neither engine", which would produce an empty extraction indistinguishable
from an image with nothing in it.

## Command Logging Integration

MemProcFS subprocess calls are logged to commands.log via `shell_log.log_command()`:

```python
from spectre.pipeline.shell_log import log_command as _shell_log

_shell_log(
    case_dir=case_dir,
    tool="memprocfs",
    command=" ".join(mpfs_cmd),
    exit_code=exit_code,
    duration_ms=duration_ms,
    stderr=stderr,
    extra=extra,
)
```

All tool invocations (volatility3, MemProcFS, carve_urls, emit_finding) also appear automatically because `audit.py` delegates to `shell_log.log_command()` on every `append()` call.

## Canary Check Quirk

The memprocfs binary uses `-version` (single dash, not `--version`), prints the version correctly, but exits with code 1. Canary check pattern:

```bash
[ -x /opt/memprocfs/memprocfs ] && echo OK
```

Do NOT check the binary's exit code — `-version` prints correctly and exits 1.

This is what `spectre-canary` does, resolving the path through
`config.MEMPROCFS_BIN` rather than PATH (`/opt/memprocfs` is not on PATH). It
does **not** check the Python API import: Spectre drives the FUSE binary, so a
failing `import memprocfs` is not a degraded pipeline and reporting it as one
would be a false alarm.

## Where the pieces live

| File | Purpose |
|---|---|
| `src/spectre/pipeline/shell_log.py` | Universal command logger — call `log_command()` from anywhere |
| `src/spectre/modules/memory/extract_memprocfs.py` | CLI entry point for subprocess-sandboxed MemProcFS extraction |
| `src/spectre/modules/memory/__init__.py` | Dual-engine dispatch with subprocess sandbox |
| `spectre-memory` (console script, `spectre.pipeline.spectre_memory:main`) | Unified CLI: `--engine vol|memprocfs|both` |
| `spectre-canary` (console script, `spectre.pipeline.canary`) | MemProcFS binary resolution + executability check |
