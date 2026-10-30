"""
memory/extract_memprocfs.py — MemProcFS-based extraction for memory images.

Uses the MemProcFS FUSE mount (filesystem metaphor) to extract forensic
artifacts from memory dumps. Outputs JSON matching volatility3 schema so
the normalize() and rules pipeline works without changes.

Why FUSE instead of Python API:
  The native leechcore.so/vmm.so libraries can SIGSEGV on some dumps when
  accessed via the Python API (Vmm() init). The FUSE binary handles the
  same dumps without issue. This module mounts the dump, reads forensic data
  from the virtual filesystem, then unmounts.

Requirements:
  - MemProcFS binary at /opt/memprocfs/memprocfs
  - FUSE kernel module loaded (modprobe fuse)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from spectre.config import MEMPROCFS_BIN, RAW_DIR

TOOL = "memprocfs"
TOOL_VERSION = "5.17.8"

# The artifact types this engine actually produces. Declared here so the FK
# YAMLs' `parser:` provenance lines can be checked against the code instead of
# against a reader's memory — see tests/test_memory/test_fk_parser_truth.py,
# which caught memory_filescan.yaml claiming a MemProcFS surface that does not
# exist. Asserted against the emitting code below by
# test_emitted_artifact_types_matches_what_extract_from_mount_writes, so adding
# a pass without updating this set fails rather than silently under-declaring.
EMITTED_ARTIFACT_TYPES = frozenset({
    "memory_pslist",
    "memory_netscan",
    "memory_cmdline",
    "memory_envar",
    "memory_malfind",
    "memory_svcscan",
    "memory_regkey",
    "memory_modules",
})

# ── Parsing helpers ──


# A process-tree glyph run: one or more dashes followed by whitespace, at the
# very start of a line. Only proc.txt indents; proc-time.txt is flat.
_TREE_GLYPHS = re.compile(r"^-+\s+")
# MemProcFS renders timestamps as "YYYY-MM-DD HH:MM:SS UTC" and a process that
# is still running as "***" in the Exit Time column.
_MPFS_TS = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")
# Flag tokens sitting between Parent and User, e.g. "32", "U", "U*", "32  U*".
_FLAG_PREFIX = re.compile(r"^(?:\d+\s+)?(?:[U*]+\s+)?")


def _parse_proc_txt(text: str) -> list[dict]:
    r"""Parse a MemProcFS process listing into rows.

    Handles BOTH `sys/proc/proc-time.txt` (flat -- the preferred source, it
    also carries Exit Time and the full image path) and `sys/proc/proc.txt`
    (process-TREE indented).

    Deliberately NOT fixed-offset. proc.txt indents each row by its depth in
    the process tree, so slicing at constant columns silently corrupted the
    output three ways: tree glyphs were baked into the image name, the PID
    field slid out of its window at depth 4 (dropping those processes
    entirely), and PPID fell back to 0. Instead: strip the glyph run, take
    the first three whitespace-delimited tokens as name/pid/ppid, and anchor
    the timestamps by pattern. That survives both layouts and column drift.

    User is recovered from the span between PPID and the first timestamp,
    minus any flag tokens, so values containing a space ("NETWORK SERVICE")
    stay intact.
    """
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        # Header and its dashed rule.
        if line.lstrip().startswith("---") and "-" * 10 in line:
            continue
        if "Process" in line and "Pid" in line and "Parent" in line:
            continue

        body = _TREE_GLYPHS.sub("", line.lstrip())
        parts = body.split(None, 3)
        if len(parts) < 3 or not parts[1].isdigit() or not parts[2].isdigit():
            continue

        name, pid_str, ppid_str = parts[0], parts[1], parts[2]
        rest = parts[3] if len(parts) > 3 else ""

        stamps = list(_MPFS_TS.finditer(rest))
        create_time = stamps[0].group(0) if stamps else ""
        # Second timestamp is Exit Time; "***" means the process is live.
        # This MUST normalize to "" -- enrich.py treats a non-empty exit_time
        # as "legitimately terminated" and would suppress hidden-process hits.
        exit_time = stamps[1].group(0) if len(stamps) > 1 else ""

        user = rest[:stamps[0].start()] if stamps else rest
        user = _FLAG_PREFIX.sub("", user.strip()).strip()

        row = {
            "PID": int(pid_str),
            "PPID": int(ppid_str),
            "ImageFileName": name,
            "CreateTime": create_time,
            "ExitTime": exit_time,
        }
        if user:
            row["User"] = user
        # proc-time.txt's trailing "Process Full Name" column, when present.
        if stamps:
            tail = rest[stamps[-1].end():].replace("***", "").strip()
            if tail:
                row["FullName"] = tail
        rows.append(row)
    return rows


# A VAD row from pid/<n>/memmap/vad.txt. Anchored on the 16-16 hex range,
# because the Type column between Commit and FLAGS is frequently blank and
# the Description that follows FLAGS may contain spaces.
_VAD_ROW = re.compile(
    r"^\s*([0-9a-f]+)\s+(\d+)\s+([0-9a-f]+)\s+"      # index, PID, object addr
    r"([0-9a-f]+)\s+([0-9a-f]+)\s+(\d+)\s+"          # pages, commit, mem-commit
    r"([0-9a-f]{16})-([0-9a-f]{16})\s*(.*)$",        # range, then Type/FLAGS/Desc
    re.IGNORECASE)

# The FLAGS token: exactly six chars, positions 2/3/4 carry r/w/x. Type values
# (Heap, Pf, File, Stack) are capitalised and descriptions are longer or
# start with a backslash, so neither can be mistaken for it.
_VAD_FLAGS = re.compile(r"^[p-][a-z-][r-][w-][x-][c-]$")


def _parse_vad_txt(text: str) -> list[dict]:
    r"""Parse pid/<n>/memmap/vad.txt into VAD rows.

    Column layout, confirmed against the live mount:

        #    PID   Object Address  Pages  Commit  ?  Range Start-End  Type  FLAGS  Description
        0071 1944  fffffa8003208a40     1       1  1  0000000003ce0000-0000000003ce0fff       p-rwx-

    Two things here are easy to get wrong and both are load-bearing:

    * **Pages and Commit are hexadecimal, without a 0x prefix.** Row 0005 of
      explorer.exe spans 0x60000-0x15ffff -- 0x100 pages -- and prints "100".
      Reading that as decimal understates the region by 156 pages.
    * **The Type column is often blank.** Splitting on whitespace and taking a
      fixed index therefore slides FLAGS into Type on every private region,
      which is exactly the set of regions this parser exists to find. So the
      row is anchored on the fixed-width range instead, and the tail is split
      by locating the six-character FLAGS token.

    The sixth numeric column is undocumented (it tracks with MemCommit) and is
    kept verbatim as `mem_commit` rather than interpreted.
    """
    rows = []
    for line in text.splitlines():
        m = _VAD_ROW.match(line)
        if not m:
            continue
        tail = m.group(9).rstrip()
        parts = tail.split()
        flag_idx = next((i for i, p in enumerate(parts) if _VAD_FLAGS.match(p)), None)
        if flag_idx is None:
            continue
        flags = parts[flag_idx]
        vtype = " ".join(parts[:flag_idx])
        desc = tail.split(flags, 1)[1].strip() if flags in tail else ""
        rows.append({
            "index": m.group(1).lower(),
            "pid": int(m.group(2)),
            "object_address": m.group(3).lower(),
            "pages": int(m.group(4), 16),
            "commit": int(m.group(5), 16),
            "mem_commit": int(m.group(6)),
            "start": int(m.group(7), 16),
            "end": int(m.group(8), 16),
            "type": vtype,
            "flags": flags,
            "description": desc,
        })
    return rows


def _vad_protection(flags: str) -> str:
    """Render a VAD flag string in the PAGE_* vocabulary the rule already reads.

    This is a re-rendering of an observation, not a judgement: the flag string
    IS what MemProcFS observed of the PTE protection, and positions 2/3/4/5 map
    onto read/write/execute/copy-on-write one-for-one. Nothing is inferred and
    nothing is added.
    """
    r, w, x, c = (flags[2] == "r", flags[3] == "w",
                  flags[4] == "x", flags[5] == "c")
    if x:
        if c:
            return "PAGE_EXECUTE_WRITECOPY"
        if w:
            return "PAGE_EXECUTE_READWRITE"
        return "PAGE_EXECUTE_READ" if r else "PAGE_EXECUTE"
    if c:
        return "PAGE_WRITECOPY"
    if w:
        return "PAGE_READWRITE"
    return "PAGE_READONLY" if r else "PAGE_NOACCESS"


def _is_injection_candidate(row: dict) -> bool:
    """malfind's criterion, expressed over a VAD row: private, executable,
    committed, and not backed by a file.

    The committed test is the one that carries the weight. On Challenge.raw
    21 regions across 53 processes are private+executable, but 17 of them are
    the WOW64 thunks at 0x77410000/0x77510000 -- present identically in 11
    unrelated processes, all with Commit == 0, and reported by volatility3 in
    none of them. The 4 with a non-zero Commit are exactly volatility3's 4
    malfind rows, at byte-identical addresses.
    """
    flags = row.get("flags", "")
    if len(flags) != 6:
        return False
    if flags[0] != "p" or flags[4] != "x":
        return False
    if row.get("commit", 0) <= 0:
        return False
    # MemProcFS labels a region "Heap"/"Stack" from its own enumeration; only
    # "File" states a file backing, and only that disqualifies the region.
    return row.get("type", "") != "File"


def _read_region_head(mount: str, pid: int, start: int,
                      description: str, nbytes: int = 16) -> tuple[str, bool]:
    """Read the first bytes of a VAD region from pid/<n>/vmemd/.

    Returns (hexdump, was_read). `was_read` exists so a caller can tell "this
    region does not begin with a PE header" from "we never managed to look":
    reporting the second as the first would turn an unmade observation into a
    stated fact.

    MemProcFS appends the region description to the vmemd filename, e.g.
    `0x0000000001bd0000-HEAP-06 [NtSegment].vvmem`, so the description has to
    be part of the lookup.
    """
    vmemd = os.path.join(mount, "pid", str(pid), "vmemd")
    stem = f"0x{start:016x}"
    candidates = [f"{stem}.vvmem"]
    if description:
        candidates.insert(0, f"{stem}-{description}.vvmem")
    for cand in candidates:
        try:
            with open(os.path.join(vmemd, cand), "rb") as f:
                data = f.read(nbytes)
        except (FileNotFoundError, OSError):
            continue
        return (" ".join(f"{b:02x}" for b in data), True)
    return ("", False)


def _collect_vad_regions(mount: str, pid: int, process: str) -> list[dict]:
    """Injected-code candidates for one process, shaped like a malfind row.

    Field names mirror volatility3's windows.malfind output so normalize.py
    needs no MemProcFS-specific branch -- the two engines arrive at the same
    NormEvent shape and therefore at the same dedup_key.
    """
    vad_path = os.path.join(mount, "pid", str(pid), "memmap", "vad.txt")
    try:
        with open(vad_path, "r") as f:
            vad_rows = _parse_vad_txt(f.read())
    except (FileNotFoundError, OSError):
        return []

    out = []
    for r in vad_rows:
        if not _is_injection_candidate(r):
            continue
        hexdump, was_read = _read_region_head(
            mount, pid, r["start"], r["description"])
        out.append({
            "PID": pid,
            "Process": process,
            "Address": f"0x{r['start']:016x}",
            "End VPN": r["end"],
            "Protection": _vad_protection(r["flags"]),
            "PrivateMemory": 1,
            "CommitCharge": r["commit"],
            "Hexdump": hexdump,
            "RegionBytesRead": was_read,
            "VadFlags": r["flags"],
            "VadType": r["type"],
            "Description": r["description"],
        })
    return out


# "SERVICE_AUTO_START (0x2)" -> constant name and numeric value, both kept.
_SVC_ENUM = re.compile(r"^(.*?)\s*\(0x([0-9a-f]+)\)\s*$", re.IGNORECASE)


def _parse_svcinfo(text: str) -> dict:
    r"""Parse one sys/services/by-name/<svc>/svcinfo.txt into a service row.

    Read per service rather than from the single `sys/services/services.txt`
    table, which is fixed-width and truncates: a display name that fills its
    64-column field runs into the next column with only one space between
    them, so no whitespace rule separates them. svcinfo.txt is unambiguous
    key/value and, usefully, already speaks volatility3's vocabulary
    (`SERVICE_AUTO_START`, `SERVICE_WIN32_SHARE_PROCESS`).

    `Path:` -- not `Image Path:` -- carries the binary. Image Path is empty
    for all 393 services on the reference image, so a parser that reads it
    returns no binaries at all.

    Field names mirror volatility3's windows.svcscan output. The enum values
    are split into their constant name and numeric value, both retained;
    nothing is discarded and nothing is rewritten.
    """
    fields = {}
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if not sep:
            continue
        fields[key.strip()] = val.strip()

    name = fields.get("Service Name", "")
    if not name:
        return {}

    def _enum(key: str) -> tuple[str, str]:
        m = _SVC_ENUM.match(fields.get(key, ""))
        return (m.group(1), f"0x{m.group(2)}") if m else (fields.get(key, ""), "")

    start, start_value = _enum("Start Type")
    state, _ = _enum("Service State")
    svc_type, _ = _enum("Service Type")
    try:
        pid = int(fields.get("Process ID (PID)", "") or 0)
    except ValueError:
        pid = 0

    return {
        "Name": name,
        "Display": fields.get("Display Name", ""),
        "Binary": fields.get("Path", ""),
        "State": state,
        "Start": start,
        "StartValue": start_value,
        "Type": svc_type,
        "PID": pid,
        "Offset": fields.get("Record Address", ""),
        "User": fields.get("User Account", ""),
    }


def _collect_services(mount: str) -> list[dict]:
    """Every service under sys/services/by-name/, one row each."""
    base = os.path.join(mount, "sys", "services", "by-name")
    try:
        entries = sorted(os.listdir(base))
    except (FileNotFoundError, OSError):
        return []
    rows = []
    for entry in entries:
        try:
            with open(os.path.join(base, entry, "svcinfo.txt"), "r") as f:
                row = _parse_svcinfo(f.read())
        except (FileNotFoundError, OSError, NotADirectoryError):
            continue
        if row:
            rows.append(row)
    return rows


def _parse_env_txt(text: str, pid: int, process: str) -> list[dict]:
    r"""Parse pid/<n>/win-environment.txt into environment-variable rows.

    One NAME=VALUE per line. Two details matter:

    * Split on the FIRST separator only -- an env value may contain '=', and
      splitting on every one truncates exactly the recovered secret the rule
      exists to surface.
    * Windows stores per-drive working directories in variables whose name
      literally begins with '=' (`=C:`, and the block-leading `=::`), so the
      search for the separator starts at index 1.

    Field names mirror volatility3's windows.envars output so normalize.py
    needs no MemProcFS-specific branch.
    """
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        sep = line.find("=", 1)
        if sep < 0:
            continue
        rows.append({
            "PID": pid,
            "Process": process,
            "Variable": line[:sep],
            "Value": line[sep + 1:],
        })
    return rows


def _parse_netstat_v(text: str) -> list[dict]:
    r"""Parse sys/net/netstat-v.txt into network connection rows.

    Format:
       #    PID Proto  State        Src                           Dst                          Process              Time                     Object Address    Process Path
    -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
    0000      0 TCPv4  SYN_SENT     ***:0                         ***                                                              ***  fffffa8001498cf0
    0012   2080 TCPv4  ESTABLISHED  10.0.2.15:49232               172.217.160.131:80             firefox.exe         2019-08-19 14:42:39 UTC fffffa8002cfa810    C:\Program Files...
    """
    rows = []
    lines = text.splitlines()

    i = 0
    for j, line in enumerate(lines):
        if "PID Proto" in line:
            i = j + 2
            break

    for line in lines[i:]:
        if not line.strip():
            continue
        # Columns: idx(hex) PID Proto State Src Dst Process Time ObjAddr Path
        # Src includes *** or addr:port, Dst same
        m = re.match(
            r'^([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+'
            r'(.+?)\s{2,}(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+)\s+'
            r'([0-9a-fA-F]+)\s+(.*)',
            line)
        if not m:
            # Try simpler: idx PID Proto State Src Dst Process (rest may be
            # empty). The separator before Process is `\s*`, not `\s+`: a row
            # that ends at Dst -- a listening socket or a dead SYN_SENT entry
            # with no owning process -- has nothing after it, and requiring a
            # separator dropped exactly the rows this fallback exists to catch.
            m = re.match(
                r'^([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)',
                line)
            if not m:
                continue
            pid = int(m.group(2))
            proto = m.group(3)
            state = m.group(4)
            src = m.group(5)
            dst = m.group(6)
            owner = m.group(7).strip() if m.group(7).strip() != "***" else ""
            local_addr, local_port = _split_addr_port(src)
            foreign_addr, foreign_port = _split_addr_port(dst)
            rows.append({
                "Proto": proto, "LocalAddr": local_addr, "LocalPort": local_port,
                "ForeignAddr": foreign_addr, "ForeignPort": foreign_port,
                "State": state, "Owner": owner, "PID": pid, "CreateTime": "",
            })
            continue

        pid = int(m.group(2))
        proto = m.group(3)
        state = m.group(4)
        src = m.group(5)
        dst = m.group(6)
        owner = m.group(7).strip()
        create_time = m.group(8)

        local_addr, local_port = _split_addr_port(src)
        foreign_addr, foreign_port = _split_addr_port(dst)

        rows.append({
            "Proto": proto,
            "LocalAddr": local_addr, "LocalPort": local_port,
            "ForeignAddr": foreign_addr, "ForeignPort": foreign_port,
            "State": state, "Owner": owner, "PID": pid,
            "CreateTime": create_time,
        })
    return rows


def _split_addr_port(addr_spec: str) -> tuple[str, str]:
    """Split '10.0.2.15:49232' or '[::]:445' into (addr, port)."""
    if addr_spec in ("***", "***:0"):
        return ("*", "0")
    m = re.match(r'^\[(.+)\]:(\d+)$', addr_spec)
    if m:
        return (m.group(1), m.group(2))
    if ":" in addr_spec:
        parts = addr_spec.rsplit(":", 1)
        return (parts[0], parts[1])
    return (addr_spec, "0")


def _read_pid_info(mount: str, pid: int) -> dict:
    """Read per-process info from the FUSE mount."""
    pid_dir = os.path.join(mount, "pid", str(pid))
    info = {}
    for fname, key in [
        ("name.txt", "name"),
        ("ppid.txt", "ppid"),
        ("win-cmdline.txt", "cmdline"),
        ("time-create.txt", "create_time"),
    ]:
        fpath = os.path.join(pid_dir, fname)
        try:
            with open(fpath, "r") as f:
                info[key] = f.read().strip()
        except (FileNotFoundError, OSError):
            info[key] = ""
    return info


def _read_registry_values(mount: str, reg_path: str) -> list[dict]:
    """Read registry values from a key directory.

    MemProcFS FUSE stores each registry value as an individual file.
    Value files are named <Name>.txt and contain:
      <address>
      <type>
      <value data>
    Excludes (_Key_) and (_Key_).txt (directory metadata).
    """
    full_dir = os.path.join(mount, "registry", reg_path)
    rows = []
    try:
        entries = os.listdir(full_dir)
    except (FileNotFoundError, OSError):
        return rows

    for entry in entries:
        if entry.startswith("(_Key_)") or not entry.endswith(".txt"):
            continue
        name = entry[:-4]  # strip .txt
        fpath = os.path.join(full_dir, entry)
        try:
            with open(fpath, "r") as f:
                content = f.read().strip()
        except (FileNotFoundError, OSError):
            continue

        # Parse: address, type, value
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        reg_type = lines[1] if len(lines) >= 2 else ""
        reg_value = lines[2] if len(lines) >= 3 else ""

        rows.append({
            "Name": name,
            "Type": reg_type,
            "Value": reg_value,
            "Key": reg_path,
        })
    return rows


# ── Mount management ──


def _mount_dump(evidence_path: str) -> tuple[str | None, subprocess.Popen | None]:
    """Mount a memory dump via memprocfs FUSE.

    Returns (mount_point, process) tuple. The process runs in background
    and must be terminated + waited on after unmounting.
    Returns (None, None) on failure.
    """
    mount_point = tempfile.mkdtemp(prefix="mpfs_")
    cmd = [MEMPROCFS_BIN, "-device", evidence_path, "-mount", mount_point]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            os.rmdir(mount_point)
        except OSError:
            pass
        return None, None

    # Wait for mount to become ready (poll for sys/ directory)
    deadline = time.time() + 30
    while time.time() < deadline:
        if os.path.isdir(os.path.join(mount_point, "sys")):
            return mount_point, proc
        if proc.poll() is not None:
            break
        time.sleep(0.5)

    # Mount failed -- clean up through the same path as a normal teardown.
    # FUSE may well be mounted even though `sys/` never appeared, and a bare
    # rmdir here would strand it exactly as the success path used to.
    _unmount_dump(mount_point, proc)
    return None, None


def _install_sigterm_unmount() -> None:
    """Make SIGTERM unwind this process instead of killing it in place.

    Python's default SIGTERM action terminates without running `finally`, so a
    parent that times out and signals us politely would still leave
    `extract()`'s `_unmount_dump` unrun — the FUSE mount and its daemon outlive
    us, holding a view of read-only evidence. Raising `SystemExit` from the
    handler gives that `finally` its chance; the parent's group SIGKILL is the
    backstop if it takes too long (see `memory.__init__._terminate_process_group`).

    Only meaningful in the main thread of the extraction subprocess; installing
    it elsewhere raises ValueError, which is not worth failing an extraction
    over because the parent's backstop still applies.
    """
    def _handler(signum, frame):
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        pass


def _is_mounted(path: str) -> bool:
    """Whether the kernel still has `path` mounted.

    `os.path.ismount` lstat()s the path, and a stale FUSE mount answers
    ENOTCONN — so it reports "not mounted" for precisely the case that must be
    detected. Ask /proc/self/mounts, which does not touch the dead endpoint.
    """
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as f:
            entries = f.read().splitlines()
    except OSError:
        return False
    target = path.rstrip("/") or "/"
    for line in entries:
        parts = line.split()
        if len(parts) >= 2 and parts[1].replace("\\040", " ") == target:
            return True
    return False


def _fusermount(mount_point: str, flag: str) -> bool:
    try:
        r = subprocess.run(["fusermount", flag, mount_point],
                           capture_output=True, timeout=10)
    except Exception:
        return False
    return r.returncode == 0 and not _is_mounted(mount_point)


def _unmount_dump(mount_point: str, proc: subprocess.Popen | None = None) -> bool:
    """Unmount a memprocfs FUSE mount, reap the daemon, remove the mount dir.

    Returns True if the mount point was actually released.

    The exit code of `fusermount -u` used to be discarded, and the daemon was
    killed regardless. A busy mount — an unflushed handle, a read still in
    flight — therefore became a *permanently stale* one: the process holding it
    was gone, and nothing tried again. Observed on a real 2 GB dump, on the
    ordinary success path, leaving `/dev/fuse on /tmp/mpfs_… type fuse (rw,…)`
    in /proc/self/mounts with the path answering ENOTCONN.

    So: try while the daemon lives, reap it, then retry — the daemon is usually
    what made the mount busy — then escalate to a lazy unmount. A mount that
    survives all of that is announced rather than swallowed; a FUSE view of the
    evidence still live on the host is not something to leave for the examiner
    to discover.
    """
    released = _fusermount(mount_point, "-u")

    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

    if not released:
        for flag in ("-u", "-uz"):
            time.sleep(0.5)
            if _fusermount(mount_point, flag):
                released = True
                break

    if not released and _is_mounted(mount_point):
        print(f"[memprocfs] WARNING: could not release FUSE mount "
              f"{mount_point} — a view of the evidence is still mounted on "
              f"this host; clean it up with: fusermount -uz {mount_point}",
              file=sys.stderr)
        return False

    time.sleep(0.5)
    try:
        os.rmdir(mount_point)
    except OSError:
        pass
    return True


# ── Extraction ──


def extract(case_dir: str, evidence_path: str) -> list[dict]:
    """Run MemProcFS extraction on a memory image via FUSE mount.

    Mounts the dump as a virtual filesystem, delegates to
    extract_from_mount(), then unmounts. The split exists so the reading half
    -- which is nearly all the logic -- is testable against a directory tree
    on disk, with no FUSE and no 1.5 GB dump.
    """
    evidence = str(evidence_path)

    mount, proc = _mount_dump(evidence)
    if mount is None:
        return [_failure_handle(evidence, "FUSE mount failed — "
                                "check that memprocfs binary is executable and FUSE is loaded")]
    try:
        return extract_from_mount(case_dir, evidence, mount)
    finally:
        _unmount_dump(mount, proc)


def extract_from_mount(case_dir: str, evidence_path: str,
                       mount: str) -> list[dict]:
    """Read every artifact from an already-mounted MemProcFS tree.

    `mount` is just a directory path, so this works equally against a live
    FUSE mount and a fixture tree.

    Every artifact is written even when its source is absent from the mount:
    a zero-row artifact with `result: success` records that we looked and
    found nothing, which is a different fact from never having looked, and
    only the first belongs in the audit trail as a successful read.
    """
    evidence = str(evidence_path)
    out_dir = Path(case_dir) / RAW_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    handles: list[dict] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    start = time.time()

    try:
        # ── PsList ──
        # proc-time.txt FIRST: it is flat (no process-tree indentation) and
        # carries Exit Time plus the full image path. proc.txt is the same
        # process set rendered as a tree and is kept only as a fallback for
        # builds that do not publish proc-time.txt.
        pslist_rows: list[dict] = []
        proc_source = ""
        for candidate in ("proc-time.txt", "proc.txt"):
            proc_fpath = os.path.join(mount, "sys", "proc", candidate)
            try:
                with open(proc_fpath, "r") as f:
                    pslist_rows = _parse_proc_txt(f.read())
            except (FileNotFoundError, OSError):
                continue
            if pslist_rows:
                proc_source = candidate
                break

        out_path = str(out_dir / f"{ts}_mpfs_memory_pslist.json")
        Path(out_path).write_text(json.dumps(pslist_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_pslist", len(pslist_rows),
            f"memprocfs FUSE {proc_source or 'proc-time.txt'} -> "
            f"{len(pslist_rows)} processes", start,
        ))

        # ── NetScan ──
        net_fpath = os.path.join(mount, "sys", "net", "netstat-v.txt")
        try:
            with open(net_fpath, "r") as f:
                netscan_rows = _parse_netstat_v(f.read())
        except (FileNotFoundError, OSError):
            netscan_rows = []

        out_path = str(out_dir / f"{ts}_mpfs_memory_netscan.json")
        Path(out_path).write_text(json.dumps(netscan_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_netscan", len(netscan_rows),
            f"memprocfs FUSE netstat-v.txt -> {len(netscan_rows)} conns", start,
        ))

        # ── Per-process pass: cmdline, environment, injected code ──
        # One walk of pid/, not three. Every read here crosses the FUSE
        # boundary, and _read_pid_info alone is four opens per process.
        #
        # Injected code deserves a word: MemProcFS has no malfind plugin, but
        # it publishes the underlying observation -- the VAD map -- per
        # process. Transcribing that is what makes memory_malfind a
        # dual-engine artifact type; importing forensic/findevil.csv would
        # not, because FindEvil states a verdict and carries neither a
        # protection nor a byte preview, so a rule could only "confirm" it by
        # asserting facts nobody observed.
        cmdline_rows: list[dict] = []
        envar_rows: list[dict] = []
        malfind_rows: list[dict] = []
        pid_base = os.path.join(mount, "pid")
        try:
            pid_dirs = sorted(os.listdir(pid_base))
        except (FileNotFoundError, OSError):
            pid_dirs = []

        for pid_dir in pid_dirs:
            try:
                pid = int(pid_dir)
            except ValueError:
                continue
            info = _read_pid_info(mount, pid)
            name = info.get("name", "")
            cmdline_rows.append({
                "PID": pid,
                "Process": name,
                "Args": info.get("cmdline", ""),
            })
            env_path = os.path.join(pid_base, pid_dir, "win-environment.txt")
            try:
                with open(env_path, "r") as f:
                    envar_rows.extend(
                        _parse_env_txt(f.read(), pid, name.strip()))
            except (FileNotFoundError, OSError):
                pass
            malfind_rows.extend(_collect_vad_regions(mount, pid, name.strip()))

        out_path = str(out_dir / f"{ts}_mpfs_memory_cmdline.json")
        Path(out_path).write_text(json.dumps(cmdline_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_cmdline", len(cmdline_rows),
            f"memprocfs FUSE pid/*/win-cmdline.txt -> {len(cmdline_rows)} cmdlines", start,
        ))

        out_path = str(out_dir / f"{ts}_mpfs_memory_envar.json")
        Path(out_path).write_text(json.dumps(envar_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_envar", len(envar_rows),
            f"memprocfs FUSE pid/*/win-environment.txt -> {len(envar_rows)} vars", start,
        ))

        out_path = str(out_dir / f"{ts}_mpfs_memory_malfind.json")
        Path(out_path).write_text(json.dumps(malfind_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_malfind", len(malfind_rows),
            f"memprocfs FUSE pid/*/memmap/vad.txt (private+committed+exec, "
            f"unbacked) -> {len(malfind_rows)} regions", start,
        ))

        # ── Services ──
        # volatility3 has extracted memory_svcscan since this module was
        # written and nothing consumed it. Services are half of the
        # AutoStart+Services pair that accounts for most real persistence, so
        # this arrives alongside memory-service-persistence, with a second
        # engine for the artifact type from the outset.
        service_rows = _collect_services(mount)
        out_path = str(out_dir / f"{ts}_mpfs_memory_svcscan.json")
        Path(out_path).write_text(json.dumps(service_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_svcscan", len(service_rows),
            f"memprocfs FUSE sys/services/by-name/*/svcinfo.txt -> "
            f"{len(service_rows)} services", start,
        ))

        # ── Registry ──
        for reg_path, label in [
            ("HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run", "run"),
            ("HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce", "runonce"),
            ("HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon", "winlogon"),
        ]:
            reg_rows = _read_registry_values(mount, reg_path)
            slug = label.replace("/", "_")
            out_path = str(out_dir / f"{ts}_mpfs_memory_regkey_{slug}.json")
            Path(out_path).write_text(json.dumps(reg_rows, indent=2))
            handles.append(_make_handle(
                out_path, evidence, "memory_regkey", len(reg_rows),
                f"memprocfs FUSE registry/{reg_path} -> {len(reg_rows)} values", start,
            ))

        # ── Loaded Modules (per-PID modules directory) ──
        modules_rows = []
        try:
            for pid_dir in os.listdir(pid_base):
                modules_dir = os.path.join(pid_base, pid_dir, "modules")
                if not os.path.isdir(modules_dir):
                    continue
                try:
                    for fname in os.listdir(modules_dir):
                        if fname.startswith("(_") or not fname.endswith(".txt"):
                            continue
                        mod_path = os.path.join(modules_dir, fname)
                        try:
                            with open(mod_path, "r") as f:
                                mod_data = f.read().strip()
                        except OSError:
                            mod_data = ""
                        modules_rows.append({
                            "PID": pid_dir,
                            "Name": fname[:-4],
                            "Path": mod_data.split("\n")[-1] if mod_data else "",
                        })
                except OSError:
                    pass
        except OSError:
            pass

        out_path = str(out_dir / f"{ts}_mpfs_memory_modules.json")
        Path(out_path).write_text(json.dumps(modules_rows, indent=2))
        handles.append(_make_handle(
            out_path, evidence, "memory_modules", len(modules_rows),
            f"memprocfs FUSE pid/*/modules -> {len(modules_rows)} DLLs", start,
        ))

    except Exception as e:
        handles.append(_failure_handle(evidence, f"Extraction error: {e}"))

    return handles


# ── Handle builders ──


def _make_handle(output_path: str, evidence_path: str,
                 artifact_type: str, row_count: int,
                 cmd_desc: str, start_time: float) -> dict:
    """Build a handle dict matching the volatility3 extract output format.

    The digest is computed HERE, in the process that just wrote the file.
    Hashing it later in the parent (as _audit_mpfs_handles used to do on its
    own) leaves a TOCTOU window: the audit row would attest to the file as it
    existed after this subprocess exited, not to what this subprocess wrote.
    """
    elapsed = int((time.time() - start_time) * 1000)
    try:
        size = Path(output_path).stat().st_size
    except OSError:
        size = 0
    try:
        sha256 = hashlib.sha256(Path(output_path).read_bytes()).hexdigest()
    except OSError:
        sha256 = ""
    return {
        "path": output_path,
        "line_count": row_count,
        "size_bytes": size,
        "output_sha256": sha256,
        "is_json": True,
        "fk_envelope": None,
        # No audit row exists in this subprocess; the parent's
        # _audit_mpfs_handles() sets this to the tool_exec row's entry_sha256.
        # Empty until then, so an unaudited handle never resolves.
        "execution_id": "",
        "exit_code": 0,
        "duration_ms": elapsed,
        "result": "success",
        "stderr": "",
        "evidence_path": str(evidence_path),
        "artifact_type": artifact_type,
        "plugin": f"memprocfs:fuse:{artifact_type}",
        "tool": "memprocfs",
        "tool_version": TOOL_VERSION,
        "exact_command": cmd_desc,
        "params": {
            "artifact_type": artifact_type,
            "evidence_path": str(evidence_path),
            "phase": "extraction",
            "engine": "memprocfs",
        },
    }


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
        "plugin": "memprocfs:fuse",
        "tool": "memprocfs",
        "tool_version": TOOL_VERSION,
        "exact_command": "memprocfs FUSE mount",
        "params": {
            "artifact_type": "memory_pslist",
            "phase": "extraction",
            "evidence_path": str(evidence_path),
            "engine": "memprocfs",
        },
    }


# ── CLI entry point ──
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="MemProcFS FUSE extraction for Spectre memory module")
    parser.add_argument("--case-dir", required=True, help="Case directory")
    parser.add_argument("--evidence", required=True, help="Memory dump path")
    args = parser.parse_args()

    # A timeout in the parent arrives here as SIGTERM; unwind so the mount is
    # torn down on the way out rather than left behind.
    _install_sigterm_unmount()

    handles = extract(args.case_dir, args.evidence)
    print(json.dumps(handles, indent=2))
    sys.exit(0 if all(h.get("result") == "success" for h in handles) else 1)
