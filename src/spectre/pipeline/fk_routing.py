"""
fk_routing.py — artifact_type → forensic-knowledge YAML, derived from modules.

Spec: the module-selection design spec §3.8, §5.7
(decision D7). This is what makes "drop a directory in, no edits needed"
actually true: discovery was already filesystem-driven (registry.py), but
*knowledge* routing was not.

There were TWO hand-maintained tables, not one:

  - `case_setup.ARTIFACT_FK` — 8 entries keyed by the module-level
    artifact_type a recognizer claims, values without a `.yaml` suffix. Decides
    which FK context Phase 0 loads for recognized evidence.
  - `phase_runner.ARTIFACT_FK` — ~25 entries keyed by the EVENT-level
    artifact_type a rule emits, values with `.yaml`. Decides which caveats a
    finding carries.

A 9th module needed both edited, and nothing stopped them disagreeing. Worse,
`phase_runner`'s missing keys fell through to `_DEFAULT_FK = "evtx_4688.yaml"`,
which is not a neutral default — it pastes Windows 4688 "corroborate with
Prefetch/Amcache/MFT" caveats onto findings that have no 4688 event at all.
That shipped twice: once for the pcap types (case 268-001's two T1105 marquee
findings) and once for registry_hive/prefetch/lnk/disk (A4-01). Both were fixed
by adding keys, never by removing the reason keys go missing. `memory_psscan`
was still missing when this module was written.

Resolution, in order:

  1. the owning module's `fk_by_artifact[artifact_type]`, if it declares one;
  2. its single `fk_yamls` entry, when the module has exactly one — which is
     every module except memory, so a 1:1 module states its FK once and never
     repeats itself per artifact type;
  3. nothing. A multi-FK module with an unlisted artifact type gets no mapping,
     and tests/test_fk_routing.py fails loudly rather than letting it inherit
     another evidence type's caveats.

Read from `module.yaml`, so a module whose dependency is broken still routes its
knowledge — FK YAML is package data with zero tool cost, and its caveats are
exactly what explains to a reader what the missing module cost them.
"""

from __future__ import annotations

from spectre.config import FK_DIRS
from spectre.modules import manifest as module_manifest


def _owning_manifests() -> list:
    manifests, _ = module_manifest.load_manifests()
    return [manifests[k] for k in sorted(manifests)]


def module_fk_sets() -> dict[str, str | list[str]]:
    """{module-level artifact_type: FK name or list of names}.

    Replaces `case_setup.ARTIFACT_FK`. Keeps that dict's shape exactly — a bare
    string when the module needs one FK YAML, a list when it needs several — so
    `_load_fk_yaml` and the `auto` profile are untouched.
    """
    out: dict[str, str | list[str]] = {}
    for man in _owning_manifests():
        if not man.fk_yamls:
            continue
        out[man.artifact] = (man.fk_yamls[0] if len(man.fk_yamls) == 1
                             else list(man.fk_yamls))
    return out


def artifact_fk_files() -> dict[str, str]:
    """{event-level artifact_type: "<name>.yaml"}.

    Replaces `phase_runner.ARTIFACT_FK`. Covers every artifact_type any
    discovered module's rules emit, plus every module-level artifact_type, so
    the `_DEFAULT_FK` fallback stops being load-bearing.

    Imports the modules (unlike module_fk_sets) because only the loaded Rule
    objects know which artifact types the rules actually emit. A module that
    fails to import contributes nothing here — correctly: its rules will not run
    either, and the S0-environment row records the loss.
    """
    from spectre.modules import registry

    manifests, _ = module_manifest.load_manifests()
    by_name = {m.name: m for m in manifests.values()}
    out: dict[str, str] = {}

    for name, analyzer in sorted(registry.discover().items()):
        man = by_name.get(name)
        if man is None or not man.fk_yamls:
            continue
        fallback = man.fk_yamls[0] if len(man.fk_yamls) == 1 else ""
        for art in _artifact_types(analyzer):
            fk = man.fk_by_artifact.get(art) or fallback
            if fk:
                out[art] = f"{fk}.yaml"
    return out


def _rule_artifact_types(analyzer) -> set[str]:
    """Artifact types a FINDING can carry — that is, what rules emit.

    The distinction matters. `memory_image` is a RECOGNIZER artifact type: it
    names the evidence a module claims, and Phase 0 routes it to the module's
    whole FK set (13 YAMLs for memory). No rule emits it, so no finding is ever
    labelled with it, so demanding a single-FK route for it would be demanding
    an answer to a question nobody asks.
    """
    return {r.artifact_type for r in analyzer.rules}


def _artifact_types(analyzer) -> set[str]:
    arts = {analyzer.artifact_type}
    arts.update(r.artifact_type for r in analyzer.recognizers)
    arts.update(_rule_artifact_types(analyzer))
    return arts


def missing_fk_routes() -> dict[str, str]:
    """{artifact_type: why it does not route} — the drift detector's input.

    Two failure modes, both of which used to end in evtx_4688.yaml:
      - a multi-FK module emitting an artifact type absent from
        `fk_by_artifact` (this is how memory_psscan went unmapped);
      - a route naming an FK YAML that is not on disk.
    """
    from spectre.modules import registry

    manifests, _ = module_manifest.load_manifests()
    by_name = {m.name: m for m in manifests.values()}
    on_disk = {f.stem for d in FK_DIRS if d.exists()
               for f in d.iterdir() if f.suffix in (".yaml", ".yml")}
    problems: dict[str, str] = {}

    for name, analyzer in sorted(registry.discover().items()):
        man = by_name.get(name)
        if man is None:
            problems[name] = "module has no module.yaml"
            continue
        if not man.fk_yamls:
            problems[name] = "module.yaml declares no fk_yamls"
            continue
        for fk in man.fk_yamls:
            if fk not in on_disk:
                problems[f"{name}:{fk}"] = (
                    f"fk_yamls names {fk}.yaml, which is not in "
                    f"{[str(d.name) for d in FK_DIRS]}")
        fallback = man.fk_yamls[0] if len(man.fk_yamls) == 1 else ""
        # Rule artifact types only: those are the ones a finding carries, and
        # therefore the ones that would inherit the wrong caveats. See
        # _rule_artifact_types.
        for art in sorted(_rule_artifact_types(analyzer)):
            fk = man.fk_by_artifact.get(art) or fallback
            if not fk:
                problems[art] = (
                    f"{name} owns >1 FK YAML and does not map {art!r} in "
                    f"fk_by_artifact — it would inherit another evidence "
                    f"type's caveats")
            elif fk not in on_disk:
                problems[art] = f"routes to {fk}.yaml, which is not on disk"
    return problems
