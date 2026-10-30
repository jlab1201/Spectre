"""disk/rules.py — starter detection pack for disk file_entry events.

Starter rule: executable content staged in a temp directory — a common
artifact of malware drop/staging. Grow with timeline anomalies, deleted
file recovery flags, and known-bad path heuristics.
"""

from __future__ import annotations

from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list

_TEMP_MARKERS = tuple(load_indicator_list("paths", "disk_temp_markers"))
_EXE_EXTS = tuple(load_indicator_list("paths", "executable_extensions"))


def executable_in_temp(e: NormEvent) -> Optional[Anchor]:
    p = str(e.data.get("path", "")).lower()
    if any(m in p for m in _TEMP_MARKERS) and p.endswith(_EXE_EXTS):
        iocs = {"filepath": [e.data.get("path", "")], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        return Anchor(
            rule_id="disk-executable-in-temp",
            artifact_type="disk_file_entry",
            event=e,
            title=f"Executable staged in a temp directory: {e.data.get('path')}",
            mitre=["T1105"],
            confidence=0.4,
            iocs=iocs,
            summary=f"fls: {e.data.get('path')} ({e.data.get('size')} bytes)",
        )
    return None


RULES: list[Rule] = [
    Rule("disk-executable-in-temp", "disk_file_entry", executable_in_temp,
         ["T1105"], "executable content staged in a temp directory",
         metadata=RuleMetadata(
             uuid="2bd10c13-ea54-40d4-ae66-31005494b168",
             name="Executable staged in a temp directory",
             author="spectre-core", date="2026-06-28", version="1.0",
             severity="low", rule_format="python",
             rule_source="modules/disk/rules.py",
             references=["https://attack.mitre.org/techniques/T1105/"],
             tags=["attack.command_and_control", "attack.t1105"],
             false_positives=["installers/updaters that stage binaries in %TEMP%"])),
]
