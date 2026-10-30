"""evtx — Windows Event Log analyzer module (reference implementation).

Real extraction via evtxexport (libevtx). Normalizes Sysmon EID 1 and
Security 4688 into a unified process_creation schema, then applies a
source-agnostic detection rule pack.
"""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under evtx/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

EVTX_MODULE = AnalyzerModule(
    name="evtx",
    artifact_type="process_creation",
    required_tools=["evtxexport"],
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    description="Windows Event Log (.evtx) — process creation analysis via evtxexport.",
)
