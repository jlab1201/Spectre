"""prefetch — Windows Prefetch (.pf) analyzer module (stdlib parser).

Handles both on-disk shapes of a .pf file: the uncompressed layout (SCCA
magic, versions 17/23/26/30) parsed narrowly for exe name / last-run /
run-count, and the Windows 10 default MAM-compressed layout, whose content
is never decompressed or guessed at — normalize() emits one honest
"compressed, unparsed" event per file instead (see FK YAML
`knowledge/artifacts/windows/prefetch.yaml`).

No external tool is required: extraction is a pass-through read of the
evidence file in place, mirroring `modules/logfile/extract.py`.
"""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under prefetch/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

PREFETCH_MODULE = AnalyzerModule(
    name="prefetch",
    artifact_type="prefetch",
    required_tools=[],  # pass-through: stdlib binary parser, no external tool
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    description="Windows Prefetch (.pf) — stdlib parser for uncompressed "
                "records (v17/23/26/30); Win10 MAM-compressed content is "
                "reported as unparsed, never guessed.",
)
