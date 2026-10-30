"""pcap — packet capture analyzer module.

Primary engine is Zeek (structured JSON logs); the tcpdump/tshark passes
are the automatic fallback (when Zeek is absent) and the verification path.
Engine selected by config.PCAP_ENGINE (auto | zeek | manual). tcpdump is
the only hard requirement — Zeek and tshark are optional (their absence
degrades to the passes that remain available), so required_tools stays
minimal and canary treats them as DEGRADED, never DEAD."""

from pathlib import Path

from spectre.core.base import AnalyzerModule
from spectre.core.rule_discovery import module_rules

# Aliased so it does not shadow the .availability submodule — see the same
# note in modules/disk/__init__.py.
from .availability import availability as _availability
from .enrich import enrich_events
from .extract import extract, verify  # noqa: F401  (public re-export)
from .normalize import normalize
from .recognizer import RECOGNIZERS
from .rules import RULES as _LEGACY_RULES

# Legacy rules.py rules plus any community drop-ins under pcap/rules/.
RULES = module_rules(Path(__file__).parent, _LEGACY_RULES)

PCAP_MODULE = AnalyzerModule(
    name="pcap",
    artifact_type="pcap_conn",
    required_tools=["tcpdump"],
    recognizers=RECOGNIZERS,
    extract=extract,
    normalize=normalize,
    rules=RULES,
    enrich=enrich_events,
    availability=_availability,
    description="Network capture (.pcap/.pcapng) — Zeek-primary extraction "
                "(structured logs) with tcpdump/tshark fallback + verification.",
)
