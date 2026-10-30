r"""MemProcFS process environments as a second source for memory_envar.

`memory_envar` was one of the four volatility3-only artifact types keeping 38
of 40 findings at a single source. MemProcFS publishes the same block per
process at `pid/<n>/win-environment.txt`, one NAME=VALUE per line.

`memory-secret-env-var` already keys on `{var.lower()}={val}`, which is
engine-neutral, so no identity work is needed here -- the artifact simply had
to exist.

The fixture is the live `pid/1944/win-environment.txt` from Challenge.raw,
copied byte-for-byte.
"""

from __future__ import annotations

import json
from pathlib import Path

from spectre.modules.memory.extract_memprocfs import _parse_env_txt
from spectre.modules.memory.normalize import normalize
from spectre.pipeline.correlation import corroborate
import spectre.modules.memory.rules as memrules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "memprocfs"
ENV_1944 = (FIXTURES / "win-environment_1944.txt").read_text()


def test_every_line_becomes_a_variable():
    rows = _parse_env_txt(ENV_1944, pid=1944, process="explorer.exe")
    assert len(rows) == 39
    assert all(r["PID"] == 1944 and r["Process"] == "explorer.exe" for r in rows)


def test_the_planted_credential_is_recovered():
    rows = {r["Variable"]: r["Value"]
            for r in _parse_env_txt(ENV_1944, pid=1944, process="explorer.exe")}
    assert rows["RAR password"] == "easypeasyvirus"


def test_values_containing_an_equals_sign_are_not_truncated():
    """Split on the FIRST separator only. `windows_tracing_logfile` is a path,
    but any env value may legitimately contain '='; splitting on all of them
    silently truncates the recovered secret."""
    rows = {r["Variable"]: r["Value"]
            for r in _parse_env_txt("FOO=a=b=c\n", pid=1, process="p.exe")}
    assert rows["FOO"] == "a=b=c"


def test_windows_drive_variables_whose_name_starts_with_equals_survive():
    r"""Windows stores per-drive cwd in variables literally named `=C:`, and
    the block begins with `=::=::\`. Splitting on index 0 would produce an
    empty name and swallow the rest as the value."""
    rows = _parse_env_txt("=::=::\\\n=C:=C:\\Users\\Jaffa\n", pid=1, process="p.exe")
    assert [(r["Variable"], r["Value"]) for r in rows] == [
        ("=::", "::\\"), ("=C:", "C:\\Users\\Jaffa")]


def test_blank_and_separatorless_lines_are_skipped():
    rows = _parse_env_txt("A=1\n\n   \nNOSEPARATOR\nB=2\n", pid=1, process="p.exe")
    assert [r["Variable"] for r in rows] == ["A", "B"]


def test_the_rule_fires_on_normalized_memprocfs_rows(tmp_path):
    rows = _parse_env_txt(ENV_1944, pid=1944, process="explorer.exe")
    p = tmp_path / "mpfs_envar.json"
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": "memory_envar", "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    anchors = [a for a in (memrules.secret_env_var(e) for e in evs) if a]
    assert len(anchors) == 1
    assert anchors[0].dedup_key == "rar password=easypeasyvirus"


# Real volatility3 rows from
# ~/spectre-cases/842-901-mpfs-ws5/raw_extract/*_vol_memory_envar.json.
VOL_ROWS = [
    {"Block": "0x61de0", "PID": 1944, "Process": "explorer.exe",
     "Variable": "RAR password", "Value": "easypeasyvirus"},
    {"Block": "0x231dc0", "PID": 1812, "Process": "taskhost.exe",
     "Variable": "RAR password", "Value": "easypeasyvirus"},
]


def _events(tmp_path, rows, source_tool, name):
    p = tmp_path / name
    p.write_text(json.dumps(rows))
    evs = normalize({"artifact_type": "memory_envar", "path": str(p),
                     "evidence_path": "/ev/dump.raw"})
    for e in evs:
        e.source_tool = source_tool
    return evs


def test_the_same_credential_from_both_engines_is_one_two_source_claim(tmp_path):
    vol = _events(tmp_path, VOL_ROWS, "volatility3", "vol.json")
    mpfs = _events(tmp_path,
                   _parse_env_txt(ENV_1944, pid=1944, process="explorer.exe"),
                   "memprocfs", "mpfs.json")

    anchors = [a for a in (memrules.secret_env_var(e) for e in vol + mpfs) if a]
    groups = corroborate(anchors)
    assert len(groups) == 1, "one credential, however many processes inherited it"
    assert groups[0].sources == 2
    assert sorted(groups[0].source_labels) == ["memprocfs/memory_envar",
                                               "volatility3/memory_envar"]
