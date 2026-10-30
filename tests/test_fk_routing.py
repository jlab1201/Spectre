"""Knowledge routing is derived from the modules — no central edit.

Spec: the module-selection design spec §3.8, §5.7
(decision D7). Testing item 12.

Discovery was already filesystem-driven, so "drop a directory in, no edits
needed" was half true. Knowledge routing was the other half, and it needed TWO
hand-maintained tables:

  - case_setup.ARTIFACT_FK — 8 entries, exactly covering the 8 modules, keyed by
    the module-level artifact_type. A 9th module without an edit here made
    `ARTIFACT_FK.get(at, at)` resolve to a nonexistent FK name.
  - phase_runner.ARTIFACT_FK — ~25 entries keyed by the event-level artifact_type
    a rule emits. A missing key fell through to _DEFAULT_FK = "evtx_4688.yaml",
    which is NOT a neutral default: it pastes Windows 4688 "corroborate with
    Prefetch/Amcache/MFT" caveats onto findings with no 4688 event.

That second one shipped twice — the pcap types (case 268-001) and then
registry_hive/prefetch/lnk/disk (A4-01) — and both times the fix was to add
keys, never to remove the reason keys go missing. `memory_psscan` was still
unmapped when this test was written.
"""

import pytest

from spectre.config import FK_DIRS
from spectre.modules import registry
from spectre.pipeline import fk_routing
from spectre.pipeline.case_setup import ARTIFACT_FK as SETUP_FK
from spectre.pipeline.phase_runner import ARTIFACT_FK as FINDING_FK

MODULES = registry.discover()


def _fk_on_disk() -> set[str]:
    return {f.name for d in FK_DIRS if d.exists()
            for f in d.iterdir() if f.suffix in (".yaml", ".yml")}


# ── item 12: every artifact type resolves to an FK file that exists ───────

def test_no_artifact_type_is_left_unrouted():
    """The whole point. An unrouted type is one that inherits some other
    evidence type's caveats."""
    assert fk_routing.missing_fk_routes() == {}


@pytest.mark.parametrize("name", sorted(MODULES))
def test_every_rule_artifact_type_routes_to_a_file_on_disk(name):
    on_disk = _fk_on_disk()
    analyzer = MODULES[name]
    for rule in analyzer.rules:
        fk = FINDING_FK.get(rule.artifact_type)
        assert fk is not None, (
            f"{name}: rule {rule.rule_id} emits {rule.artifact_type!r}, which "
            f"has no FK route — it would fall through to evtx_4688.yaml"
        )
        assert fk in on_disk, f"{name}: {rule.artifact_type} -> {fk} not on disk"


@pytest.mark.parametrize("name", sorted(MODULES))
def test_every_module_artifact_type_loads_real_fk_files(name):
    on_disk = {f.rsplit(".", 1)[0] for f in _fk_on_disk()}
    analyzer = MODULES[name]
    entry = SETUP_FK.get(analyzer.artifact_type)
    assert entry is not None, (
        f"{name}: artifact_type {analyzer.artifact_type!r} has no FK set, so "
        f"Phase 0's auto profile would load no knowledge for it"
    )
    names = [entry] if isinstance(entry, str) else list(entry)
    assert names
    for fk in names:
        assert fk in on_disk, f"{name}: FK {fk!r} is not on disk"


def test_memory_psscan_is_routed():
    """The live instance of the defect at the time this landed: memory_psscan
    is emitted by a memory rule and was absent from the hand-written table, so
    a psscan finding carried Windows 4688 caveats."""
    assert FINDING_FK.get("memory_psscan") == "memory_psscan.yaml"


def test_each_memory_artifact_keeps_its_own_caveats():
    """A memory_netscan finding carrying memory_pslist's caveats would cite the
    wrong volatility plugin. memory is the only multi-FK module, so it is the
    only place this can go wrong."""
    memory = MODULES["memory"]
    routes = {r.artifact_type: FINDING_FK.get(r.artifact_type)
              for r in memory.rules}
    for art, fk in routes.items():
        assert fk == f"{art}.yaml", f"{art} routed to {fk}"
    assert len(set(routes.values())) == len(routes), routes


def test_no_pcap_artifact_type_routes_to_windows_knowledge():
    """Case 268-001, as a standing assertion. Every pcap artifact type must
    land on pcap.yaml, never on evtx_4688.yaml."""
    for rule in MODULES["pcap"].rules:
        assert FINDING_FK.get(rule.artifact_type) == "pcap.yaml", rule.artifact_type


# ── the derived tables reproduce the shape their callers expect ───────────

def test_setup_map_keeps_the_str_or_list_shape():
    """`_load_fk_yaml` and the auto profile branch on this: a bare string for a
    single FK, a list for a container type.

    Uses `prefetch` (still single-FK) rather than `process_creation` as the
    single-FK example: evtx grew a second multi-FK-module shape alongside
    memory once its rules spanned six distinct artifact types (log-cleared,
    service-install, scriptblock, two logon aggregates, process_creation),
    each needing its own caveats — see modules/evtx/module.yaml."""
    assert isinstance(SETUP_FK["prefetch"], str)
    assert isinstance(SETUP_FK["process_creation"], list)
    assert len(SETUP_FK["process_creation"]) == 6
    assert isinstance(SETUP_FK["memory_image"], list)
    assert len(SETUP_FK["memory_image"]) == 13


def test_finding_map_values_carry_the_yaml_suffix():
    assert all(v.endswith(".yaml") for v in FINDING_FK.values()), FINDING_FK


def test_both_maps_agree_where_they_overlap():
    """Two independent tables could disagree, and nothing checked. Derivation
    from one manifest makes disagreement impossible — this pins it."""
    for art, setup_entry in SETUP_FK.items():
        if not isinstance(setup_entry, str):
            continue  # multi-FK container type; no single finding-level route
        finding_entry = FINDING_FK.get(art)
        if finding_entry is None:
            continue  # recognizer-only type no rule emits
        assert finding_entry == f"{setup_entry}.yaml", (
            f"{art}: Phase 0 loads {setup_entry}, findings get {finding_entry}")


# ── a new module needs no edit anywhere ──────────────────────────────────

def test_a_new_module_routes_with_no_central_edit(tmp_path, monkeypatch):
    """D7, stated as behaviour: drop a manifest in, get routing.

    Uses the manifest loader directly, since a full fake module would need a
    working extract/normalize pair — the claim under test is about knowledge
    routing, not about discovery, which registry.py already made drop-in.
    """
    from spectre.modules import manifest as mf
    man = mf.parse_manifest(
        "name: ninth\n"
        "artifact: ninth_artifact\n"
        "summary: a ninth module\n"
        "tools: []\n"
        "fk_yamls: [prefetch]\n",
        "ninth")
    assert man.fk_yamls == ("prefetch",)
    monkeypatch.setattr(mf, "load_manifests", lambda: ({"ninth": man}, {}))
    assert fk_routing.module_fk_sets() == {"ninth_artifact": "prefetch"}
