"""The analysis environment is a chained fact, not a mutable manifest field.

Spec: the module-selection design spec §3.7, §5.5.

`canary_status` was written by log_command, which writes execution.log and
never audit.jsonl (shell_log.py:164). "Which modules were available when this
case ran" is the first question a reviewer asks of a report that found nothing,
and the answer lived in a file anyone could edit.

This is also the honest replacement for the install-time module-selection
feature that was cut (§2): a chained per-case row records what was actually
available for THIS case, where an unchained per-user dotfile records only what
someone once chose.
"""

import json
from pathlib import Path

from spectre.pipeline import audit, environment


def _case(tmp_path) -> str:
    d = tmp_path / "001-ENV"
    (d / "findings").mkdir(parents=True)
    return str(d)


def test_snapshot_records_what_bounds_the_examination():
    snap = environment.environment_snapshot()
    for key in ("python", "platform", "distributions", "canary_status",
                "modules_discovered", "modules_usable", "modules_unavailable",
                "module_import_failures", "modules_expected_but_absent",
                "unevaluated_rule_packs", "resolved_tool_paths", "config"):
        assert key in snap, f"missing {key}"
    assert len(snap["modules_discovered"]) == 8, snap["modules_discovered"]
    assert snap["canary_status"] in ("FULL", "DEGRADED", "DEAD")
    assert snap["distributions"]["spectre-forensic"], snap["distributions"]


def test_snapshot_is_pure():
    """Safe to call from a verifier or a report, not just from Phase 0. In
    particular it runs no external tool: probing `vol --version` here would put
    tool execution outside tool_runner.py, which owns all tool exec and its
    auditing."""
    import subprocess
    calls = []
    real = subprocess.run
    try:
        subprocess.run = lambda *a, **kw: (calls.append(a), real(*a, **kw))[1]
        environment.environment_snapshot()
    finally:
        subprocess.run = real
    versiony = [a for a in calls
                if any("--version" in str(x) for x in (a[0] if a else []))]
    assert not versiony, versiony


def test_declared_tools_all_appear_with_a_resolution():
    from spectre.modules import manifest as mf
    snap = environment.environment_snapshot()
    manifests, _ = mf.load_manifests()
    declared = {t for m in manifests.values()
                for t in list(m.tools) + list(m.optional_tools)}
    assert declared <= set(snap["resolved_tool_paths"]), (
        declared - set(snap["resolved_tool_paths"]))


def test_import_failure_reaches_the_row(tmp_path, monkeypatch):
    """registry.discover_with_errors() catches import errors and only warns to
    stderr (§3.9). Warnings reach no reviewer."""
    monkeypatch.setattr(environment.registry, "discover_with_errors",
                        lambda: ({}, {"pcap": "ImportError: boom"}))
    snap = environment.environment_snapshot()
    assert snap["module_import_failures"] == {"pcap": "ImportError: boom"}
    # A module that failed to import contributes no rules either — its whole
    # detection surface is absent, which is the part that changes conclusions.
    assert "pcap" in snap["unevaluated_rule_packs"]


def test_absent_module_is_distinguished_from_a_failed_one(tmp_path, monkeypatch):
    """A directory that ships a manifest but produces no module is capability
    that shipped and did not arrive — a different fault from one that raised."""
    monkeypatch.setattr(environment.registry, "discover_with_errors",
                        lambda: ({}, {}))
    snap = environment.environment_snapshot()
    assert snap["module_import_failures"] == {}
    assert len(snap["modules_expected_but_absent"]) == 8


def test_row_is_chained_and_verifies(tmp_path):
    case = _case(tmp_path)
    snap = environment.append_environment_row(case, "001")
    entries = [json.loads(ln) for ln in
               (Path(case) / "audit.jsonl").read_text().splitlines() if ln.strip()]
    rows = [e for e in entries if e["phase_step"] == "S0-environment"]
    assert len(rows) == 1
    assert rows[0]["action"] == "environment_snapshot"
    assert rows[0]["params"]["modules_discovered"] == snap["modules_discovered"]
    assert rows[0]["result"] == snap["canary_status"]
    ok, reason = audit.verify_chain(case)
    assert ok, reason


def test_row_survives_json_round_trip(tmp_path):
    """audit.append() serialises params to JSON. A snapshot carrying anything
    unserialisable would break the chain write, not just this row."""
    case = _case(tmp_path)
    environment.append_environment_row(case, "001")
    raw = (Path(case) / "audit.jsonl").read_text()
    row = json.loads(raw.splitlines()[0])
    assert json.loads(json.dumps(row["params"])) == row["params"]
