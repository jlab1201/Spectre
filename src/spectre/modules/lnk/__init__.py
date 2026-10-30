"""lnk — Windows shortcut (.lnk) analyzer module (stdlib parser).

Parses the fixed 76-byte MS-SHLLINK ShellLinkHeader and, when present, the
LinkInfo block, narrowly for target path / drive type / network-link flag
/ file size / write time (see `knowledge/artifacts/windows/lnk.yaml`).
Nothing else in the file is interpreted; malformed or truncated records
emit nothing rather than a partial guess.

No external tool is required: extraction is a pass-through read of the
evidence file in place, mirroring `modules/prefetch/extract.py`.
"""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

from .extract import extract
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under lnk/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

LNK_MODULE = AnalyzerModule(
    name="lnk",
    artifact_type="lnk",
    required_tools=[],  # pass-through: stdlib binary parser, no external tool
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    description="Windows shortcut (.lnk) — stdlib parser for the "
                "ShellLinkHeader + LinkInfo block: target path, drive "
                "type, network-link flag.",
)
