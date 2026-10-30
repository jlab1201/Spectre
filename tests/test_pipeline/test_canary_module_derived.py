"""The canary reports per-module availability and stops lying about DEAD.

Spec: the module-selection design spec §3.3, §3.6,
§5.4. Testing items 7, 8, 9.

Three defects this pins:

  P0 (§3.3) — the old canary shelled out to `scripts/session-canary.sh`,
  resolved four parents up from `canary.py`. `scripts/` is not in the wheel, so
  on any non-editable install the file was absent, the canary returned
  status=DEAD / failed_tools=['canary_script_missing'], and runner.py turned
  that into sys.exit(3). Spectre could not run outside a source checkout.

  §3.6 — the DEAD rule was `vol_failed and other_failures >= 3` over a static
  tool list. A pcap-only examiner failed vol, plaso, mmls, yara(py),
  evtx_dump, bulk_extractor and memprocfs -> DEAD -> exit 3. The stated use
  case could not start. Five of those checks referenced tools no module
  declares and no code path runs.

  §3.6 again — the naive fix is also wrong. pcap's required_tools=['tcpdump']
  is, by its own docstring, the WRONG signal: a Zeek-only host extracts pcaps
  fine. A shutil.which sweep over required_tools would report pcap
  UNAVAILABLE on exactly the host this branch was built for. Hence the
  availability hook.
"""

import shutil
import tomllib
from pathlib import Path

import pytest

from spectre import config
from spectre.modules import manifest as mf
from spectre.pipeline import canary as canary_mod

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _only(present: set[str]):
    """A shutil.which that resolves only the named tools."""
    return lambda t: f"/usr/bin/{t}" if t in present else None


def _executable(tmp_path, name: str) -> Path:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    return p


# ── shape and back-compat ────────────────────────────────────────────────

def test_probe_returns_the_documented_shape():
    r = canary_mod.probe_environment()
    for key in ("status", "passed", "failed", "failed_tools", "all_tools",
                "timestamp", "raw_output", "modules", "core"):
        assert key in r, f"missing key {key!r}"
    assert r["status"] in ("FULL", "DEGRADED", "DEAD")
    assert isinstance(r["all_tools"], dict)
    assert isinstance(r["failed_tools"], list)
    assert isinstance(r["modules"], dict)


def test_probe_reports_every_discovered_module():
    r = canary_mod.probe_environment()
    manifests, _ = mf.load_manifests()
    assert sorted(r["modules"]) == sorted(manifests)
    for name, entry in r["modules"].items():
        assert set(entry) >= {"available", "degraded", "detail", "missing"}


def test_run_canary_still_accepts_the_old_keywords():
    """case_setup, runner and phase_runner all call run_canary(case_dir=...),
    and every canary test in the suite stubs it as `lambda **kw`. The
    canary_script keyword outlives the script it named."""
    r = canary_mod.run_canary(canary_script=None, case_dir=None)
    assert r["status"] in ("FULL", "DEGRADED")


def test_a_bogus_script_path_no_longer_kills_the_run():
    """The P0 regression, stated as behaviour: there is no script to be
    missing. A path that does not exist must be ignored, not fatal."""
    r = canary_mod.run_canary(canary_script="/nonexistent/session-canary.sh")
    assert r["status"] != "DEAD"
    assert "canary_script_missing" not in r["failed_tools"]


def test_no_bash_script_is_executed(monkeypatch):
    """Record every subprocess and assert none of them is a shell script.

    Not "no subprocess at all": disk's availability hook legitimately runs
    `fls -i list` to probe for libewf. And not a raising stub either — disk's
    probe catches Exception, so an exploding stub would be swallowed and this
    test would pass without proving anything.
    """
    calls = []
    real = canary_mod.subprocess.run

    def record(cmd, *a, **kw):
        calls.append(cmd)
        return real(cmd, *a, **kw)

    monkeypatch.setattr(canary_mod.subprocess, "run", record)
    canary_mod.probe_environment()
    for cmd in calls:
        flat = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        assert "bash" not in flat and ".sh" not in flat, flat


# ── the DEAD rule (item 7) ───────────────────────────────────────────────

def test_pcap_only_host_is_degraded_not_dead(monkeypatch):
    """§3.6's stated use case. vol, fls, mmls, evtxexport, rip.pl all absent;
    tcpdump present. Seven-plus failures, but pcap works, so the examination
    can proceed."""
    monkeypatch.setattr(shutil, "which", _only({"tcpdump"}))
    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    r = canary_mod.probe_environment()
    assert r["status"] == "DEGRADED", r["raw_output"]
    assert r["failed"] > 0
    assert r["modules"]["pcap"]["available"] is True
    assert r["modules"]["memory"]["available"] is False
    assert r["modules"]["memory"]["missing"] == "vol"


def test_dead_only_when_no_module_can_run(monkeypatch):
    """Every tool gone. The pass-through modules (logfile, lnk, prefetch)
    declare no tools, so they stay available and this is still DEGRADED —
    which is correct: those modules genuinely still work."""
    monkeypatch.setattr(shutil, "which", _only(set()))
    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "zeek")
    r = canary_mod.probe_environment()
    assert r["status"] == "DEGRADED", r["raw_output"]
    assert r["modules"]["logfile"]["available"] is True

    # ...but with no module at all available, there is nothing to examine.
    monkeypatch.setattr(canary_mod, "_module_rows",
                        lambda: {"pcap": {"available": False, "degraded": False,
                                          "detail": "stubbed", "missing": "tcpdump"}})
    r = canary_mod.probe_environment()
    assert r["status"] == "DEAD", r["raw_output"]


def test_core_infrastructure_failure_is_dead(monkeypatch):
    """libmagic is core: without it every extensionless artifact triages
    UNRECOGNIZED and the report calls its contents unverified (§3.4). A run
    that cannot recognise evidence is not a degraded run."""
    monkeypatch.setattr(canary_mod, "_probe_libmagic",
                        lambda: (False, "libmagic.so not found"))
    r = canary_mod.probe_environment()
    assert r["status"] == "DEAD", r["raw_output"]
    assert any("magic" in t for t in r["failed_tools"]), r["failed_tools"]


def test_module_load_failure_is_reported_not_swallowed(monkeypatch):
    monkeypatch.setattr(canary_mod.registry, "discover_with_errors",
                        lambda: ({}, {"pcap": "ImportError: boom"}))
    r = canary_mod.probe_environment()
    assert r["modules"]["pcap"]["available"] is False
    assert "boom" in r["modules"]["pcap"]["detail"]
    assert "boom" in r["raw_output"]


# ── the availability hook (item 8) ───────────────────────────────────────

def test_zeek_only_host_reports_pcap_available(tmp_path, monkeypatch):
    """§3.6's trap. No tcpdump at all, Zeek resolvable off PATH at
    /opt/zeek/bin — the host this branch exists for."""
    fake_zeek = _executable(tmp_path, "zeek")
    monkeypatch.setattr(shutil, "which", _only(set()))
    monkeypatch.setattr(config, "PCAP_ENGINE", "auto")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: str(fake_zeek))
    r = canary_mod.probe_environment()
    assert r["modules"]["pcap"]["available"] is True, r["modules"]["pcap"]
    assert r["status"] != "DEAD"


def test_manual_engine_still_requires_tcpdump(tmp_path, monkeypatch):
    fake_zeek = _executable(tmp_path, "zeek")
    monkeypatch.setattr(shutil, "which", _only(set()))
    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: str(fake_zeek))
    r = canary_mod.probe_environment()
    assert r["modules"]["pcap"]["available"] is False
    assert r["modules"]["pcap"]["missing"] == "tcpdump"


def test_optional_tool_absence_degrades_but_does_not_disable(monkeypatch):
    """pcap declares zeek and tshark as optional_tools: their absence costs
    extraction passes, not the module."""
    monkeypatch.setattr(shutil, "which", _only({"tcpdump"}))
    monkeypatch.setattr(config, "PCAP_ENGINE", "manual")
    monkeypatch.setattr(config, "_resolve_zeek", lambda: "zeek")
    r = canary_mod.probe_environment()
    entry = r["modules"]["pcap"]
    assert entry["available"] is True
    assert entry["degraded"] is True
    assert "zeek" in entry["detail"] or "tshark" in entry["detail"]


# ── inventory sync (item 9) ──────────────────────────────────────────────

def test_every_declared_tool_is_checked():
    """§3.6: evtxexport, fls and rip.pl were declared by modules and checked
    by nothing."""
    r = canary_mod.probe_environment()
    checked = set(r["all_tools"])
    manifests, _ = mf.load_manifests()
    declared = {t for m in manifests.values()
                for t in list(m.tools) + list(m.optional_tools)}
    unchecked = {t for t in declared
                 if not any(t in label for label in checked)}
    assert not unchecked, f"declared by a module but never checked: {unchecked}"


def test_no_check_references_an_undeclared_tool():
    """The other half of §3.6: bulk_extractor, evtx_dump.py, strings,
    sha256sum, yara(py) and log2timeline.py were all checked while no module
    declared them and no code path ran them. Every binary check must now trace
    to a module manifest or to a declared project extra."""
    r = canary_mod.probe_environment()
    manifests, _ = mf.load_manifests()
    declared = {t for m in manifests.values()
                for t in list(m.tools) + list(m.optional_tools)}
    declared |= {d for m in manifests.values()
                 for d in list(m.python_deps) + list(m.python_deps_optional)}
    declared |= set(canary_mod.CORE_CHECKS)
    declared |= set(canary_mod.PROJECT_EXTRAS)
    orphans = [label for label in r["all_tools"]
               if not any(d in label for d in declared)]
    assert not orphans, f"checked but declared by nobody: {orphans}"


def test_project_extras_tier_matches_pyproject():
    """PROJECT_EXTRAS is the one hardcoded list left; pin it to the extras
    pyproject actually declares so it cannot drift into ghosts again."""
    with open(_PYPROJECT, "rb") as f:
        extras = tomllib.load(f)["project"]["optional-dependencies"]
    for name in canary_mod.PROJECT_EXTRAS:
        assert name in extras, (
            f"canary checks a '{name}' extra that pyproject does not declare"
        )


def test_deleted_ghost_checks_are_gone():
    r = canary_mod.probe_environment()
    labels = " ".join(r["all_tools"]).lower()
    for ghost in ("bulk_extractor", "evtx_dump", "strings", "sha256sum",
                  "yara", "log2timeline"):
        assert ghost not in labels, f"{ghost} check survived (§3.6 ghost)"


# ── DEAD still hard-stops ────────────────────────────────────────────────

def test_run_canary_exits_3_on_dead(monkeypatch, tmp_path):
    monkeypatch.setattr(canary_mod, "_probe_libmagic",
                        lambda: (False, "libmagic.so not found"))
    with pytest.raises(SystemExit) as exc:
        canary_mod.run_canary()
    assert exc.value.code == 3
