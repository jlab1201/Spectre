"""registry_hive — Windows registry hive analyzer module (RegRipper).

Handles the raw hive files themselves (SYSTEM, SAM, SOFTWARE, SECURITY,
NTUSER.DAT, and any *.dat/*.hiv/*.hive derivative) — recognized by the
`regf` magic signature so extensionless hives carved off a disk image are
still claimed. Extraction shells out to RegRipper's `-a` (run-all-plugins)
mode; normalize() narrowly parses its Run/RunOnce autostart output into
`registry_run` NormEvents (see FK YAML
`knowledge/artifacts/windows/registry_run.yaml`) — the artifact_type the
quick-triage/full-windows/disk-light profiles already request. W5-2 adds
parsers for the `services`, `appcompatcache`/`shimcache` and `amcache`
plugin sections (`registry_service`, `shimcache`, `amcache` NormEvents).

Module dir is named `registry_hive`, NOT `registry`, so it never shadows
`spectre.modules.registry` (the discovery module itself).
"""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under registry_hive/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

REGISTRY_HIVE_MODULE = AnalyzerModule(
    name="registry_hive",
    artifact_type="registry_run",
    required_tools=["rip.pl"],
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    description="Windows registry hive (SYSTEM/SAM/SOFTWARE/SECURITY/NTUSER.DAT) "
                "— Run/RunOnce, Services, ShimCache and Amcache via RegRipper.",
)
