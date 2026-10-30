"""disk — disk image analyzer module (Sleuth Kit-based)."""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

# Aliased: a bare `availability` here would shadow the .availability SUBMODULE
# in this package's namespace, so `from spectre.modules.disk import
# availability` would hand back the function and a caller reaching for the
# module (a test monkeypatching the EWF probe cache, say) would get a
# confusing AttributeError.
from .availability import availability as _availability
from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under disk/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

DISK_MODULE = AnalyzerModule(
    name="disk",
    artifact_type="disk_image",
    required_tools=["fls", "mmls"],
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    availability=_availability,
    description="Disk image (.dd/.raw/.E01) — filesystem timeline via Sleuth Kit.",
)
