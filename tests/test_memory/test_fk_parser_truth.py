"""An FK YAML's `parser:` line is a provenance claim, and several were false.

The `parser:` field names the tool and plugin that produced the artifact a
finding rests on. It travels into the report, so it is read as a statement
about how this evidence was obtained — not as a note about what the tool is
capable of. Four of the memory FK YAMLs named a MemProcFS surface that the
extractor has never called:

  - `memory_filescan.yaml` — "MemProcFS VFS /files". No filescan pass exists.
    MemProcFS has no comparable file-object surface at all: `handles.txt` is a
    table of *open handles*, a different population from volatility3's
    FILE_OBJECT scan of physical memory.
  - `memory_pslist.yaml` — "MemProcFS Vmm.process_list()"
  - `memory_netscan.yaml` — "MemProcFS vmm.maps.net()"
  - `memory_envar.yaml`   — "MemProcFS /process/<pid>/env"

The last three name the *Python API*, which `extract_memprocfs`'s own module
docstring explains it deliberately does not use (the native `vmm.so` can
SIGSEGV on some dumps). Those three artifact types are genuinely dual-engine,
so the claim of coverage was true while the cited surface was wrong — which is
the more insidious kind of error, because the number of engines checks out.

Two guards, both derived rather than hand-maintained:

  1. If an FK YAML names MemProcFS, `extract_memprocfs` must actually emit
     that artifact type. Coverage the code lacks is worse than an omission:
     an omission understates, a false `parser:` line overstates to a reader who
     cannot see the code.
  2. No FK YAML may cite the MemProcFS Python API, because the implementation
     is FUSE. If the engine is ever ported, this test fails and the docs get
     revisited in the same commit.

Both read `EMITTED_ARTIFACT_TYPES` from the extractor and the artifact_type →
FK mapping from `fk_routing`, so neither can drift into agreement with a stale
list.
"""

from __future__ import annotations

import yaml

import pytest

from spectre.config import FK_DIRS
from spectre.modules.memory.extract_memprocfs import EMITTED_ARTIFACT_TYPES
from spectre.pipeline import fk_routing

# Call forms that only exist in the Python API. `vmm.so` is the native library
# behind it; the FUSE binary is a separate entry point.
_PYTHON_API_MARKERS = (
    "vmm.", "Vmm(", "Vmm.", "vmmpyc", "memprocfs.Vmm", "process_list()",
    "maps.net()",
)


def _fk_files_naming_memprocfs() -> list[tuple[str, str]]:
    """[(fk filename, parser text)] for every FK YAML that names MemProcFS."""
    out = []
    for d in FK_DIRS:
        if not d.exists():
            continue
        for f in sorted(d.iterdir()):
            if f.suffix not in (".yaml", ".yml"):
                continue
            doc = yaml.safe_load(f.read_text()) or {}
            parser = doc.get("parser", "")
            text = " ".join(parser) if isinstance(parser, list) else str(parser)
            if "memprocfs" in text.lower():
                out.append((f.name, text))
    return out


def _artifact_types_for(fk_name: str) -> set[str]:
    return {at for at, fk in fk_routing.artifact_fk_files().items()
            if fk == fk_name}


def test_the_extractor_declares_what_it_emits():
    """The constant is the derivation point for both guards below, so it must
    itself be non-trivial and name only real artifact types."""
    assert EMITTED_ARTIFACT_TYPES
    assert all(at.startswith("memory_") for at in EMITTED_ARTIFACT_TYPES)


def test_at_least_one_fk_yaml_names_memprocfs():
    """Guard the guard: if the search finds nothing, the two tests below pass
    vacuously and stop protecting anything."""
    assert _fk_files_naming_memprocfs()


@pytest.mark.parametrize(
    "fk_name,parser_text",
    _fk_files_naming_memprocfs(),
    ids=lambda v: v if v.endswith((".yaml", ".yml")) else "",
)
def test_fk_yaml_naming_memprocfs_is_actually_produced_by_it(fk_name, parser_text):
    types = _artifact_types_for(fk_name)
    assert types, (
        f"{fk_name} names MemProcFS but no artifact_type routes to it — "
        f"the claim cannot even be checked"
    )
    assert types & EMITTED_ARTIFACT_TYPES, (
        f"{fk_name} `parser:` claims MemProcFS produces {sorted(types)}, but "
        f"extract_memprocfs emits only {sorted(EMITTED_ARTIFACT_TYPES)}. "
        f"A finding on this artifact would carry a provenance line naming a "
        f"tool that never ran."
    )


@pytest.mark.parametrize(
    "fk_name,parser_text",
    _fk_files_naming_memprocfs(),
    ids=lambda v: v if v.endswith((".yaml", ".yml")) else "",
)
def test_fk_yaml_does_not_cite_the_memprocfs_python_api(fk_name, parser_text):
    hits = [m for m in _PYTHON_API_MARKERS if m in parser_text]
    assert not hits, (
        f"{fk_name} `parser:` cites the MemProcFS Python API ({hits}), but "
        f"extract_memprocfs uses the FUSE mount by design — see its module "
        f"docstring. Cite the mount path that was actually read."
    )
