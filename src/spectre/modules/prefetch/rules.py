"""prefetch/rules.py — masquerading / known-offensive-tool execution.

A prefetch record proves an executable *ran*, not that it was malicious —
most .pf files are entirely mundane. The signal here is narrow: the
executable name itself is either a double-extension masquerade (an
"INVOICE.PDF.EXE"-style name designed to look like a document at a glance)
or matches a small, well-known set of offensive-security / credential-theft
tool binaries (T1204.002, User Execution: Malicious File).

Honesty contract: this rule NEVER judges a MAM-compressed record. Compressed
events carry `run_count=None` because their content was never parsed — the
`exe_name` on those events came from the filename, not verified content —
so the predicate refuses to fire whenever `run_count is None`, regardless of
what the (filename-derived) exe_name looks like.
"""

from __future__ import annotations

import re
from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata

ARTIFACT = "prefetch"

_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|jpg|png|txt)\.exe$", re.IGNORECASE)

_OFFENSIVE_TOOLS = {
    "mimikatz.exe", "psexec.exe", "psexesvc.exe", "procdump.exe",
    "lazagne.exe", "sharphound.exe", "rubeus.exe", "nc.exe", "ncat.exe",
}

# A4-03 fix: T1204.002 (User Execution: Malicious File) describes a user
# being socially engineered into running a file DISGUISED as something
# benign — exactly right for the double-extension masquerade branch, but
# wrong for a tool running under its own overt name (the opposite of a
# masquerade). Each known offensive tool maps to the technique its own
# execution actually evidences; none of these reuse T1204.002.
_OFFENSIVE_TOOL_MITRE = {
    "mimikatz.exe": "T1003.001",   # OS Credential Dumping: LSASS Memory
    "procdump.exe": "T1003.001",   # commonly used to dump lsass.exe
    "lazagne.exe": "T1555",        # Credentials from Password Stores
    "psexec.exe": "T1569.002",     # System Services: Service Execution
    "psexesvc.exe": "T1569.002",   # the PsExec service component itself
    "sharphound.exe": "T1087.002", # Account Discovery: Domain Account (AD/BloodHound recon)
    "rubeus.exe": "T1558.003",     # Steal or Forge Kerberos Tickets: Kerberoasting
    "nc.exe": "T1105",             # Ingress Tool Transfer / remote-access utility
    "ncat.exe": "T1105",
}
# Union of every technique this rule can emit — kept as the rule's static
# mitre-map.yaml-checked declaration (test_mitre_map.py asserts Rule.mitre
# is a subset of the map's allowed list for this rule_id).
_ALL_PREFETCH_MITRE = ["T1204.002"] + sorted(set(_OFFENSIVE_TOOL_MITRE.values()))


def prefetch_suspicious_execution(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != ARTIFACT:
        return None
    # Never judge unparsed (MAM-compressed) content — its exe_name came
    # from the filename, not verified execution evidence.
    if e.data.get("run_count") is None:
        return None

    exe_name = str(e.data.get("exe_name") or "")
    if not exe_name:
        return None

    is_masquerade = bool(_DOUBLE_EXT_RE.search(exe_name))
    exe_lower = exe_name.lower()
    is_known_tool = exe_lower in _OFFENSIVE_TOOLS
    if not (is_masquerade or is_known_tool):
        return None

    if is_masquerade:
        reason = "double-extension masquerade"
        mitre = ["T1204.002"]
    else:
        reason = "known offensive-security tool"
        mitre = [_OFFENSIVE_TOOL_MITRE[exe_lower]]
    source_pf = str(e.data.get("source_pf") or "")

    return Anchor(
        rule_id="prefetch-suspicious-execution",
        artifact_type=ARTIFACT,
        event=e,
        title=f"Prefetch: '{exe_name}' executed — {reason}",
        mitre=mitre,
        confidence=0.6,
        iocs={"filepath": [exe_name], "ip": [], "domain": [],
              "sha256": [], "registry_key": []},
        summary=f"{source_pf or exe_name}: run_count={e.data.get('run_count')}",
        dedup_key=f"{exe_name.lower()}",
    )


RULES = [
    Rule(
        rule_id="prefetch-suspicious-execution",
        artifact_type=ARTIFACT,
        predicate=prefetch_suspicious_execution,
        mitre=_ALL_PREFETCH_MITRE,
        description="Prefetch record shows execution of a double-extension "
                    "masquerade name or a known offensive-security tool.",
        metadata=RuleMetadata(
            uuid="4b8f1e2a-6c3d-4a9f-8e1b-7d5a2c9f0e63",
            name="Prefetch masquerade / known-tool execution",
            author="spectre-core", date="2026-07-10", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/prefetch/rules.py",
            tags=["spectre.execution"],
            required_fields=["exe_name", "run_count"],
            false_positives=[
                "Legitimate binary that happens to carry a double extension "
                "in its filename (rare but possible for installer wrappers)."],
        ),
    ),
]
