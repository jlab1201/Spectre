"""logfile — generic CSV / unix .log analyzer module (streaming, no external tool).

Reads large line-oriented evidence in constant memory via core.streaming, with
a configurable cap (config.LOGFILE_MAX_EVENTS) that surfaces — never silently
drops — any un-analyzed remainder.
"""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under logfile/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

LOGFILE_MODULE = AnalyzerModule(
    name="logfile",
    artifact_type="logfile_record",
    required_tools=[],  # pass-through: no external tool needed
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    description="Generic CSV / unix .log evidence — memory-bounded streaming "
                "normalization with honest large-file partitioning.",
)
