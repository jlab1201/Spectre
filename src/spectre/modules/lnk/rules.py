"""lnk/rules.py — suspicious shortcut target (removable / network / temp-exe).

A parsed LNK record proves a shortcut *points at* a path, not that the
target was ever run — most .lnk files are entirely mundane (Recent Items
created by opening a document). The signal here is narrow and limited to
what the LinkInfo block actually asserts: the target lives on a removable
drive (T1091, Replication Through Removable Media), the target is reached
over a network path (T1021.002, Remote Services: SMB/Windows Admin
Shares), or the target is an executable-class file sitting in a Temp
directory (T1204.002, User Execution: Malicious File).
"""

from __future__ import annotations

import re
from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata

ARTIFACT = "lnk"

_DRIVE_REMOVABLE = 2

_TEMP_EXE_RE = re.compile(
    r"\\(temp|appdata\\local\\temp)\\.*\.(exe|dll|scr|bat|ps1|vbs|js)$",
    re.IGNORECASE)


def lnk_suspicious_target(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != ARTIFACT:
        return None

    target_path = str(e.data.get("target_path") or "")
    drive_type = e.data.get("drive_type")
    network_link = bool(e.data.get("network_link"))

    mitre: list[str] = []
    reasons: list[str] = []

    if drive_type == _DRIVE_REMOVABLE:
        mitre.append("T1091")
        reasons.append("target on removable drive")
    if network_link:
        mitre.append("T1021.002")
        reasons.append("target reached over network path")
    if target_path and _TEMP_EXE_RE.search(target_path):
        mitre.append("T1204.002")
        reasons.append("executable-class target in a Temp directory")

    if not mitre:
        return None

    source_lnk = str(e.data.get("source_lnk") or "")
    reason = "; ".join(reasons)

    return Anchor(
        rule_id="lnk-suspicious-target",
        artifact_type=ARTIFACT,
        event=e,
        title=f"LNK: suspicious target '{target_path}' — {reason}",
        mitre=mitre,
        confidence=0.6,
        iocs={"filepath": [target_path] if target_path else [], "ip": [],
              "domain": [], "sha256": [], "registry_key": []},
        summary=f"{source_lnk or target_path}: {reason}",
        dedup_key=f"{target_path.lower()}",
    )


RULES = [
    Rule(
        rule_id="lnk-suspicious-target",
        artifact_type=ARTIFACT,
        predicate=lnk_suspicious_target,
        mitre=["T1091", "T1021.002", "T1204.002"],
        description="LNK target sits on removable media, is reached over "
                    "a network path, or is an executable in a Temp "
                    "directory.",
        metadata=RuleMetadata(
            uuid="7c2e9a4d-1f6b-4e3c-9a8d-5b0e6c1f2a7e",
            name="LNK suspicious target",
            author="spectre-core", date="2026-07-10", version="1.0",
            severity="medium", rule_format="python",
            rule_source="modules/lnk/rules.py",
            tags=["spectre.execution", "spectre.lateral-movement"],
            required_fields=["target_path", "drive_type", "network_link"],
            false_positives=[
                "Removable-media shortcuts are routine for USB-based file "
                "transfer workflows; network shortcuts are routine for "
                "mapped drives / file shares in an enterprise environment."],
        ),
    ),
]
