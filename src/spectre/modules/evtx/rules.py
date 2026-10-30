"""
evtx/rules.py — detection rule pack for process_creation events.

Each Rule has a pure predicate(NormEvent) -> Optional[Anchor]. Rules are
source-agnostic: they read the unified process_creation schema, so they
fire on both Sysmon EventID 1 and Security 4688 logs. Adding a rule is
local to this file; it never touches the framework or other modules.

This is the starter pack. Extend it incrementally — each rule is unit
testable against a single synthetic NormEvent.
"""

from __future__ import annotations

import re
from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list

_SRC = "modules/evtx/rules.py"


def _mitre_refs(*ids: str) -> list[str]:
    """MITRE ATT&CK technique URLs for the given technique IDs (e.g.
    T1218.011 -> .../techniques/T1218/011/)."""
    out = []
    for tid in ids:
        out.append(
            "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/")
    return out

ARTIFACT = "process_creation"
_TEMP_MARKERS = tuple(load_indicator_list("paths", "evtx_temp_markers"))
_LOLBINS = frozenset(load_indicator_list("processes", "lolbins"))
_SHELLS = frozenset(load_indicator_list("processes", "command_shells"))
_OFFICE = frozenset(load_indicator_list("processes", "office_apps"))
_UAC_AUTOELEVATE = frozenset(load_indicator_list("processes", "uac_autoelevate"))


def _anchor(rule_id, e, title, mitre, confidence, iocs) -> Anchor:
    return Anchor(
        rule_id=rule_id,
        artifact_type=ARTIFACT,
        event=e,
        title=title,
        mitre=mitre,
        confidence=confidence,
        iocs=iocs,
        summary=(f"EVTX EID {e.data.get('event_id')}: "
                 f"{e.data.get('image_basename')} (rec {e.record_id}), "
                 f"parent {e.data.get('parent_basename')}, "
                 f"cmd={e.data.get('command_line')}"),
    )


def _dll_in_cmd(cmd: str) -> str:
    m = re.search(r'([A-Za-z]:\\[^,"\s]*\.dll)', cmd, re.IGNORECASE)
    if m:
        return m.group(1)
    for tok in cmd.split():
        if tok.lower().endswith(".dll"):
            return tok.strip('"\'')
    return ""


# ── Rules ───────────────────────────────────────────────────────────
def rundll32_from_temp(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    if d.get("image_basename") != "rundll32.exe":
        return None
    cl = d.get("command_line_lower", "")
    if ".dll" in cl and any(m in cl for m in _TEMP_MARKERS):
        dll = _dll_in_cmd(d.get("command_line", ""))
        iocs = {"filepath": [dll] if dll else [], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        return _anchor("rundll32-from-temp", e,
                       f"rundll32 loading DLL from Temp (parent: {d.get('parent_basename')})",
                       ["T1218.011"], 0.5, iocs)
    return None


def lolbin_from_temp(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    if d.get("image_basename") not in _LOLBINS:
        return None
    cl = d.get("command_line_lower", "")
    if any(m in cl for m in _TEMP_MARKERS):
        iocs = {"filepath": [d.get("image", "")], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        return _anchor("lolbin-from-temp", e,
                       f"LOLBin {d.get('image_basename')} executing from a temp path",
                       ["T1218"], 0.5, iocs)
    return None


# A4-05 fix: command_shells mixes genuine command/script interpreters
# (cmd.exe, powershell.exe, pwsh.exe, wscript.exe, cscript.exe) with two
# binaries that are NOT command/script interpreters — mshta.exe (System
# Binary Proxy Execution: Mshta, T1218.005 — already used for
# mshta-execution elsewhere in mitre-map.yaml) and bitsadmin.exe (a BITS
# transfer utility, T1197 — BITS Jobs). Per-child overrides keep the
# genuine shells on T1059; anything not listed here falls back to T1059.
_SHELL_MITRE_OVERRIDES = {
    "mshta.exe": "T1218.005",
    "bitsadmin.exe": "T1197",
}


def office_spawns_shell(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    child = d.get("image_basename")
    if d.get("parent_basename") in _OFFICE and child in _SHELLS:
        iocs = {"filepath": [d.get("image", "")], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        mitre = [_SHELL_MITRE_OVERRIDES.get(child, "T1059")]
        return _anchor("office-spawns-shell", e,
                       f"Office app {d.get('parent_basename')} spawned {child}",
                       mitre, 0.6, iocs)
    return None


def encoded_powershell(e: NormEvent) -> Optional[Anchor]:
    d = e.data
    if d.get("image_basename") not in ("powershell.exe", "pwsh.exe"):
        return None
    cl = d.get("command_line_lower", "")
    if re.search(r"(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{16,})", cl):
        iocs = {"filepath": [], "ip": [], "domain": [], "sha256": [],
                "registry_key": []}
        return _anchor("encoded-powershell", e,
                       "PowerShell launched with an encoded command",
                       ["T1059.001"], 0.6, iocs)
    return None


EMPTY_IOCS = {"filepath": [], "ip": [], "domain": [], "sha256": [], "registry_key": []}


def log_cleared(e: NormEvent) -> Optional[Anchor]:
    """1102 (Security audit log cleared) / 104 (System: any log cleared).

    A log-clearing event is a strong, discrete anti-forensics signal on its
    own — no threshold or co-occurring indicator is needed. See
    evtx_1102.yaml for the audit-policy caveat (a cleared log destroys
    evidence of what came before it; it does not by itself prove WHY).
    """
    if e.artifact_type != "evtx_log_cleared":
        return None
    d = e.data
    # Never fall back to the record's own channel: a 104 lives in System but
    # reports the channel that was cleared in UserData.
    channel = d.get("cleared_channel") or "unknown"
    subject = d.get("subject_user", "")
    who = f" by {subject}" if subject else ""
    return Anchor(
        rule_id="evtx-log-cleared",
        artifact_type="evtx_log_cleared",
        event=e,
        title=f"{channel} event log cleared{who}",
        mitre=["T1070.001"],
        confidence=0.8,
        iocs=dict(EMPTY_IOCS),
        summary=(f"EVTX EID {d.get('event_id')}: {channel} log cleared "
                 f"(rec {e.record_id})" + (f", subject {subject}" if subject else "")),
        dedup_key=(f"{e.host}:{d.get('channel')}:{d.get('event_id')}:"
                   f"{e.record_id}:{e.timestamp}"),
    )


# 7045 ImagePath suspicion markers. Deliberately narrow: a plain service
# install with a benign ImagePath (the overwhelming majority) matches none of
# these and is NOT flagged at all — see docstring of suspicious_service_install.
_SERVICE_SUSPICIOUS_BINARIES = _LOLBINS | _SHELLS
_SERVICE_ENCODED_RE = re.compile(r"(-enc\b|-encodedcommand|frombase64string|-e\s+[a-z0-9+/=]{16,})")
_PSEXEC_SERVICE_MARKER = "psexesvc"


def suspicious_service_install(e: NormEvent) -> Optional[Anchor]:
    """7045 (a new service was installed) — flagged only when the ImagePath
    or ServiceName carries a concrete suspicion marker: staged from a temp
    path, hosted by a command/script interpreter or LOLBin, invoking
    %COMSPEC%, carrying an encoded/base64 command, or named like a
    PsExec-dropped service (PSEXESVC). A plain legitimate service install
    (e.g. an MSI-installed Windows service pointing at its own Program Files
    binary) matches none of these and is intentionally NOT reported — even
    as a low-confidence lead — because "a service was installed" alone is
    true of essentially every software install and would be pure noise.
    """
    if e.artifact_type != "evtx_service_install":
        return None
    d = e.data
    image_lower = d.get("image_path_lower", "")
    if not image_lower:
        return None
    service_name = d.get("service_name", "")
    service_name_lower = d.get("service_name_lower", "")

    reasons = []
    if any(m in image_lower for m in _TEMP_MARKERS):
        reasons.append("binary staged in a temp path")
    if any(b in image_lower for b in _SERVICE_SUSPICIOUS_BINARIES):
        reasons.append("service hosted by a command/script interpreter or LOLBin")
    if "%comspec%" in image_lower:
        reasons.append("ImagePath invokes %COMSPEC%")
    if _SERVICE_ENCODED_RE.search(image_lower):
        reasons.append("encoded/base64 command")
    is_psexec = (_PSEXEC_SERVICE_MARKER in service_name_lower
                 or _PSEXEC_SERVICE_MARKER in image_lower)
    if is_psexec:
        reasons.append("PsExec-style remote service name")

    if not reasons:
        return None

    mitre = ["T1543.003"]
    if is_psexec:
        mitre.append("T1569.002")

    iocs = dict(EMPTY_IOCS)
    if d.get("image_path"):
        iocs["filepath"] = [d["image_path"]]

    return Anchor(
        rule_id="evtx-suspicious-service-install",
        artifact_type="evtx_service_install",
        event=e,
        title=(f"Suspicious service installed: {service_name or '(unnamed)'} "
               f"({'; '.join(reasons)})"),
        mitre=mitre,
        confidence=0.7 if is_psexec else 0.6,
        iocs=iocs,
        summary=(f"EVTX EID 7045: service {service_name!r} ImagePath="
                 f"{d.get('image_path')!r} (rec {e.record_id}): {'; '.join(reasons)}"),
        dedup_key=f"{e.host}:{service_name_lower}:{image_lower}",
    )


# 4104 (PowerShell ScriptBlock logging) suspicion markers.
_SCRIPTBLOCK_ENCODED_RE = re.compile(r"(-enc\b|-encodedcommand|-e\s+[a-z0-9+/=]{16,})")
_SB_FROMBASE64 = "frombase64string"
_SB_EXPRESSION_RE = re.compile(r"(?<![\w-])iex\b|invoke-expression")
_SB_EXEC_RE = re.compile(
    r"(?<![\w-])iex\b|invoke-expression|\[scriptblock\]::create|"
    r"reflection\.assembly\]?::load|\[system\.reflection\.assembly\]::load")
_SB_DOWNLOAD_MARKERS = ("downloadstring", "downloadfile", "downloaddata",
                         "net.webclient", "net.webrequest", "invoke-webrequest")
_SB_AMSI_MARKERS = ("amsiutils", "amsiinitfailed", "amsiscanbuffer", "amsi bypass")
_SB_MIMIKATZ_MARKER = "invoke-mimikatz"


def scriptblock_suspicious(e: NormEvent) -> Optional[Anchor]:
    """4104 (PowerShell ScriptBlock logging) — content-based indicators:
    an encoded/base64 command (T1027), an IEX/Invoke-Expression download
    cradle (T1105, only when BOTH the expression and a download call are
    present — an IEX with no remote fetch is not a cradle), an AMSI-bypass
    string (T1562.001), or an Invoke-Mimikatz reference (T1003.001).
    Base technique is always T1059.001 (PowerShell is being used to execute
    something); the others are added only when their specific pattern actually shows.
    """
    if e.artifact_type != "evtx_scriptblock":
        return None
    d = e.data
    text = d.get("script_block_text_lower", "")
    if not text:
        return None

    reasons: list[str] = []
    mitre = {"T1059.001"}

    # FromBase64String alone is routine in legitimate module code: it counts
    # only alongside an execution primitive or an -EncodedCommand context.
    if _SCRIPTBLOCK_ENCODED_RE.search(text) or (
            _SB_FROMBASE64 in text and _SB_EXEC_RE.search(text)):
        reasons.append("encoded/base64 command")
        mitre.add("T1027")

    has_expression = bool(_SB_EXPRESSION_RE.search(text))
    has_download = any(m in text for m in _SB_DOWNLOAD_MARKERS)
    if has_expression and has_download:
        reasons.append("download cradle (IEX/Invoke-Expression + remote download)")
        mitre.add("T1105")

    # AMSI bypass (T1562.001) and Invoke-Mimikatz (T1003.001). The latter
    # records that the script REFERENCED Mimikatz, not that credentials were
    # dumped (see FK evtx_4104.yaml does_NOT_prove).
    if any(m in text for m in _SB_AMSI_MARKERS):
        reasons.append("AMSI-bypass string")
        mitre.add("T1562.001")

    if _SB_MIMIKATZ_MARKER in text:
        reasons.append("Invoke-Mimikatz reference")
        mitre.add("T1003.001")

    if not reasons:
        return None

    return Anchor(
        rule_id="evtx-scriptblock-suspicious",
        artifact_type="evtx_scriptblock",
        event=e,
        title=f"Suspicious PowerShell scriptblock ({'; '.join(reasons)})",
        mitre=sorted(mitre),
        confidence=0.6,
        iocs=dict(EMPTY_IOCS),
        summary=(f"EVTX EID 4104: scriptblock {d.get('script_block_id')} "
                 f"(rec {e.record_id}): {'; '.join(reasons)}"),
        dedup_key=f"{e.host}:{d.get('script_block_id') or e.record_id}",
    )


def bruteforce_logon(e: NormEvent) -> Optional[Anchor]:
    """Aggregate of 4625 (logon failure) events, one per source IP whose
    densest window already met the brute-force threshold — see
    normalize.py's _aggregate_failed_logons for the windowing itself; this
    rule only reports what the aggregate already found. T1110.
    """
    if e.artifact_type != "evtx_4625_aggregate":
        return None
    d = e.data
    ip = d.get("source_ip", "")
    accounts = d.get("target_accounts", [])
    acct_str = f", targeted accounts: {', '.join(accounts)}" if accounts else ""
    iocs = dict(EMPTY_IOCS)
    if ip:
        iocs["ip"] = [ip]
    return Anchor(
        rule_id="evtx-bruteforce-logon",
        artifact_type="evtx_4625_aggregate",
        event=e,
        title=(f"Possible brute force: {d.get('count')} failed logons from "
               f"{ip} within {d.get('window_minutes')} min"),
        mitre=["T1110"],
        confidence=0.6,
        iocs=iocs,
        summary=(f"EVTX EID 4625 aggregate: {d.get('count')} failures from "
                 f"{ip} between {d.get('first_seen')} and {d.get('last_seen')}"
                 f"{acct_str}"),
        dedup_key=f"{e.host}:{ip}",
    )


def rdp_remote_logon(e: NormEvent) -> Optional[Anchor]:
    """Aggregate of 4624 (logon success) events with LogonType 10 (RDP) from
    a non-local source IP, grouped by (source IP, account) — see
    normalize.py's _aggregate_rdp_logons. Deliberately low confidence: RDP
    from a remote address is routine for legitimate remote administration;
    this is an honest lead for the analyst to corroborate (jump-box
    allowlist, VPN range, ticket), not an accusation. T1021.001. Scope note:
    a 4624 logon type 3 (network) fan-out-to-many-hosts lateral-movement
    detection is deliberately NOT implemented here — a single-host EVTX log
    cannot see "many hosts", so that pattern needs cross-host correlation
    this module does not have data for.
    """
    if e.artifact_type != "evtx_4624_rdp_aggregate":
        return None
    d = e.data
    ip = d.get("source_ip", "")
    account = d.get("account", "")
    iocs = dict(EMPTY_IOCS)
    if ip:
        iocs["ip"] = [ip]
    return Anchor(
        rule_id="evtx-rdp-remote-logon",
        artifact_type="evtx_4624_rdp_aggregate",
        event=e,
        title=(f"RDP logon from {ip}" + (f" as {account}" if account else "")
               + f" ({d.get('count')}x)"),
        mitre=["T1021.001"],
        confidence=0.4,
        iocs=iocs,
        summary=(f"EVTX EID 4624 aggregate: LogonType 10 (RDP) from {ip} as "
                 f"{account or '(unknown account)'}, {d.get('count')}x between "
                 f"{d.get('first_seen')} and {d.get('last_seen')}"),
        dedup_key=f"{e.host}:{ip}:{account}",
    )


def uac_autoelevate(e: NormEvent) -> Optional[Anchor]:
    """Known auto-elevating Windows binaries are a hallmark of UAC-bypass
    chains (fodhelper, eventvwr, sdclt, ...). T1548.002."""
    d = e.data
    if d.get("image_basename") in _UAC_AUTOELEVATE:
        iocs = {"filepath": [d.get("image", "")], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        return _anchor("uac-autoelevate-binary", e,
                       f"Auto-elevating binary {d.get('image_basename')} executed "
                       f"(possible UAC bypass, parent {d.get('parent_basename')})",
                       ["T1548.002"], 0.5, iocs)
    return None


RULES: list[Rule] = [
    Rule(
        "rundll32-from-temp", ARTIFACT, rundll32_from_temp, ["T1218.011"],
        "rundll32 loading a DLL from a temp directory",
        metadata=RuleMetadata(
            uuid="eae9ef6a-7563-4744-a53c-5d2992e8a572",
            name="rundll32 loading a DLL from Temp",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1218.011"),
            tags=["attack.defense_evasion", "attack.t1218.011"],
            false_positives=["installers/updaters that stage a DLL in %TEMP%"],
            required_fields=["image_basename", "command_line_lower", "command_line", "parent_basename"],
        ),
    ),
    Rule(
        "lolbin-from-temp", ARTIFACT, lolbin_from_temp, ["T1218"],
        "a living-off-the-land binary executing from a temp path",
        metadata=RuleMetadata(
            uuid="d71015ff-9a8c-4ec6-b8d3-8fc17e0b9334",
            name="LOLBin executing from a temp path",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_source=_SRC,
            references=_mitre_refs("T1218"),
            tags=["attack.defense_evasion", "attack.t1218"],
            false_positives=["software running portable tools from a temp dir"],
            required_fields=["image_basename", "command_line_lower", "image"],
        ),
    ),
    Rule(
        "office-spawns-shell", ARTIFACT, office_spawns_shell,
        ["T1059", "T1218.005", "T1197"],
        "an Office application spawning a command shell",
        metadata=RuleMetadata(
            uuid="101a8fbb-473a-4551-87b2-2ab3bf746cb2",
            name="Office application spawning a command shell",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1059"),
            tags=["attack.execution", "attack.t1059"],
            false_positives=["Office add-ins/macros that legitimately shell out"],
            required_fields=["parent_basename", "image_basename", "image"],
        ),
    ),
    Rule(
        "encoded-powershell", ARTIFACT, encoded_powershell, ["T1059.001"],
        "PowerShell with an encoded command",
        metadata=RuleMetadata(
            uuid="271954bd-d69f-49d1-9fe9-2bc4395afa3d",
            name="PowerShell launched with an encoded command",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1059.001"),
            tags=["attack.execution", "attack.t1059.001"],
            false_positives=["management tooling that base64-encodes commands"],
            required_fields=["image_basename", "command_line_lower"],
        ),
    ),
    Rule(
        "evtx-log-cleared", "evtx_log_cleared", log_cleared, ["T1070.001"],
        "the Security audit log or a System-channel log was cleared",
        metadata=RuleMetadata(
            uuid="1c6a7c3b-6e33-4b2c-9a3e-6b3f6a9d3b1a",
            name="Event log cleared",
            author="spectre-core", date="2026-09-29", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1070.001"),
            tags=["attack.defense_evasion", "attack.t1070.001"],
            false_positives=["scheduled log rotation/maintenance by admin tooling"],
            required_fields=["event_id", "cleared_channel", "subject_user"],
        ),
    ),
    Rule(
        "evtx-suspicious-service-install", "evtx_service_install",
        suspicious_service_install, ["T1543.003", "T1569.002"],
        "a service was installed with a suspicious ImagePath or name",
        metadata=RuleMetadata(
            uuid="2d7b8d4c-7f44-4c3d-8b4f-7c4a7b0e4c2b",
            name="Suspicious service install",
            author="spectre-core", date="2026-09-29", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1543.003", "T1569.002"),
            tags=["attack.persistence", "attack.t1543.003", "attack.t1569.002"],
            false_positives=["legitimate admin/deployment tooling that installs "
                              "a service via a scripted ImagePath"],
            required_fields=["service_name", "image_path_lower", "image_path"],
        ),
    ),
    Rule(
        "evtx-scriptblock-suspicious", "evtx_scriptblock", scriptblock_suspicious,
        ["T1059.001", "T1027", "T1105"],
        "a PowerShell scriptblock carries an encoding/download-cradle/AMSI-bypass pattern",
        metadata=RuleMetadata(
            uuid="3e8c9e5d-8055-4d4e-9c5a-8d5b8c1f5d3c",
            name="Suspicious PowerShell scriptblock",
            author="spectre-core", date="2026-09-29", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1059.001", "T1027", "T1105"),
            tags=["attack.execution", "attack.t1059.001", "attack.defense_evasion",
                  "attack.t1027"],
            false_positives=["legitimate deployment scripts that base64-encode "
                              "arguments or download from an internal repo"],
            required_fields=["script_block_text_lower", "script_block_id"],
        ),
    ),
    Rule(
        "evtx-bruteforce-logon", "evtx_4625_aggregate", bruteforce_logon, ["T1110"],
        "many logon failures from one source within a short window",
        metadata=RuleMetadata(
            uuid="4f9d0f6e-9166-4e5f-ad6b-9e6c9d2f6e4d",
            name="Possible brute-force logon",
            author="spectre-core", date="2026-09-29", version="1.0",
            severity="medium", rule_source=_SRC,
            references=_mitre_refs("T1110"),
            tags=["attack.credential_access", "attack.t1110"],
            false_positives=["a misconfigured service account retrying with a "
                              "stale password; a shared workstation/jump host"],
            required_fields=["source_ip", "count", "window_minutes"],
        ),
    ),
    Rule(
        "evtx-rdp-remote-logon", "evtx_4624_rdp_aggregate", rdp_remote_logon,
        ["T1021.001"],
        "an RDP (LogonType 10) logon from a non-local source address",
        metadata=RuleMetadata(
            uuid="5a0e1a7f-a277-4f60-be7c-af7dae3f7f5e",
            name="RDP logon from a remote address",
            author="spectre-core", date="2026-09-29", version="1.0",
            severity="low", rule_source=_SRC,
            references=_mitre_refs("T1021.001"),
            tags=["attack.lateral_movement", "attack.t1021.001"],
            false_positives=["legitimate remote administration/helpdesk RDP; "
                              "a VPN or jump-box range"],
            required_fields=["source_ip", "account", "count"],
        ),
    ),
    Rule(
        "uac-autoelevate-binary", ARTIFACT, uac_autoelevate, ["T1548.002"],
        "execution of a known auto-elevating binary (UAC bypass)",
        metadata=RuleMetadata(
            uuid="4ba2f36f-b72f-4546-bb85-59576fede295",
            name="Auto-elevating binary executed (possible UAC bypass)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_source=_SRC,
            references=_mitre_refs("T1548.002"),
            tags=["attack.privilege_escalation", "attack.t1548.002"],
            false_positives=["normal admin use of fodhelper/eventvwr/sdclt"],
            required_fields=["image_basename", "image", "parent_basename"],
        ),
    ),
]
