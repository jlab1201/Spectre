"""registry_hive/rules.py — Run/RunOnce autostart persistence detection,
plus (W5-2) Services, ShimCache and Amcache rules further down.

A Run/RunOnce value is not inherently suspicious — most are legitimate
vendor updaters under Program Files. The signal here is location or launch
mechanism: a command line that runs out of a user-writable directory (Temp,
AppData, ProgramData, the public profile) or that goes through a
script/LOLBin interpreter (powershell, wscript/cscript, mshta, rundll32,
regsvr32, cmd /c, an encoded PowerShell command) — both are classic
autostart-persistence tradecraft (MITRE T1547.001).

Cache rules (W5-2 + follow-ups): `shimcache-suspicious-path` /
`amcache-suspicious-path` demote — never drop — a hit whose path is an
installer's own extraction folder holding a known installer filename
(`markers.installer_extraction_context`); `shimcache-anti-forensics` flags a
ShimCache row named like a known wiper/cleaner or timestomp tool.

Deliberately NOT implemented (mitre-map stubs removed, not faked):
  - `amcache-unknown-hash`: "unknown" needs a hash-reputation or known-good
    source (VirusTotal, NSRL, a vendor allowlist). Spectre runs offline and
    ships none, so every Amcache SHA1 would be "unknown" — a rule firing on
    presence, which this pack refuses to do.
  - `shimcache-unknown-binary`: same problem with no hash at all — ShimCache
    carries only a path and an mtime, so "unknown" could only mean "not on a
    name allowlist", which proves nothing and is trivially defeated by
    naming. Re-add either only once a real offline known-good set (e.g. an
    NSRL RDS import) is wired in as evidence-independent knowledge.
"""

from __future__ import annotations

from typing import Optional

from spectre.core import markers
from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list

ARTIFACT = "registry_run"

# A4-04 fix: a narrow allowlist of stock, vendor-recommended AppData
# install paths for common consumer software (OneDrive/Discord/Dropbox/
# Spotify/Slack/Zoom). A user-writable-dir match alone under one of these
# is downgraded to a low, non-CONFIRMED-eligible confidence — never
# silently suppressed (still emitted, with an explanatory note) — and the
# allowlist is bypassed entirely whenever a LOLBIN/script-host token is
# ALSO present in the same value (a strong co-occurring malicious signal).
_BENIGN_APPDATA_VENDORS = tuple(
    load_indicator_list("processes", "benign_appdata_vendors")
)
_ALLOWLIST_DOWNGRADED_CONFIDENCE = 0.3

# User-writable directories a legitimate installer wouldn't normally launch
# a persisted autostart binary from.
_USER_WRITABLE_DIRS = (
    "\\temp\\", "\\appdata\\", "%temp%", "\\programdata\\", "\\users\\public\\",
)

# Script hosts / LOLBins commonly abused to launch persistence payloads.
_LOLBIN_TOKENS = (
    "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    "cmd /c", "-enc",
)


def run_key_persistence(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != ARTIFACT:
        return None
    value_data = str(e.data.get("value_data") or "")
    if not value_data:
        return None
    blob = value_data.lower()

    dir_reason = next((d for d in _USER_WRITABLE_DIRS if d in blob), None)
    lolbin_reason = next((t for t in _LOLBIN_TOKENS if t in blob), None)
    reason = dir_reason or lolbin_reason
    if reason is None:
        return None

    value_name = str(e.data.get("value_name") or "")
    key = str(e.data.get("key") or "")
    hive = str(e.data.get("hive") or "")

    confidence = 0.6
    title = (f"Run-key persistence: '{value_name}' launches from a "
             f"suspicious location or interpreter ({hive})")
    summary = f"{hive}: {key}\\{value_name} = {value_data}"

    # Narrow allowlist: a user-writable-dir match with NO co-occurring
    # LOLBIN/script-host token, whose value data matches a known-benign
    # consumer-software vendor path, is downgraded rather than silently
    # dropped — a strong co-occurring signal (lolbin_reason) always
    # overrides the allowlist.
    vendor_match = next((v for v in _BENIGN_APPDATA_VENDORS if v in blob), None)
    if vendor_match and lolbin_reason is None:
        confidence = _ALLOWLIST_DOWNGRADED_CONFIDENCE
        note = (f"[allowlist-downgraded: matches known-benign consumer "
                f"software vendor path '{vendor_match}' — likely a "
                f"legitimate self-registered updater; verify signature/"
                f"install path before treating as malicious]")
        title += f" {note}"
        summary += f" {note}"

    return Anchor(
        rule_id="registry-run-persistence",
        artifact_type=ARTIFACT,
        event=e,
        title=title,
        mitre=["T1547.001"],
        confidence=confidence,
        iocs={"filepath": [value_data], "ip": [], "domain": [],
              "sha256": [], "registry_key": [key]},
        summary=summary,
        dedup_key=f"{hive}:{key}:{value_name}",
    )


# ── W5-2: Services / ShimCache / AmCache ──────────────────────────────────
#
# Every rule below fires on a CONCRETE marker (core/markers.py) and never on
# plain presence: a service existing, a ShimCache row, or an Amcache row is
# true of every program on every machine. ShimCache and Amcache rows are
# presence evidence, not execution evidence (see the FK YAML caveats), so
# their titles say "recorded", never "executed", and their confidence stays
# below the 0.6 bar a genuine single-source signal carries.

_SVC_ARTIFACT = "registry_service"
_SHIM_ARTIFACT = "shimcache"
_AMC_ARTIFACT = "amcache"

_PRESENCE_CONFIDENCE = 0.4     # temp/public-path presence in a cache
_INSTALLER_DEMOTED_CONFIDENCE = 0.2  # temp hit inside an installer's own extraction dir
_ANTI_FORENSIC_CONFIDENCE = 0.4      # wiper/timestomp tool NAME in ShimCache
_TOOL_CONFIDENCE = 0.5         # known offensive tool name in a cache
_MASQUERADE_CONFIDENCE = 0.5   # system-process name outside its home dir


def _iocs(filepath: str = "", registry_key: str = "") -> dict:
    iocs = {"filepath": [], "ip": [], "domain": [], "sha256": [],
            "registry_key": [], "host": [], "account": []}
    if filepath:
        iocs["filepath"] = [filepath]
    if registry_key:
        iocs["registry_key"] = [registry_key]
    return iocs


def service_persistence(e: NormEvent) -> Optional[Anchor]:
    """A Services-key entry whose ImagePath (or RegRipper 4.0's
    FailureCommand) carries a concrete marker: a temp/public-profile binary,
    a command/script interpreter or LOLBin as the launcher, %COMSPEC%, an
    encoded command, or a PSEXESVC-style name. A service with a normal
    System32 / Program Files ImagePath is not flagged."""
    if e.artifact_type != _SVC_ARTIFACT:
        return None
    d = e.data
    name = str(d.get("service_name") or "")
    name_lower = name.lower()
    image = str(d.get("image_path") or "")
    image_lower = image.lower()
    failure = str(d.get("failure_command") or "")

    reasons = [f"ImagePath {r}" for r in markers.launcher_markers(image_lower)]
    reasons += [f"FailureCommand {r}"
                for r in markers.launcher_markers(failure.lower())]
    is_psexec = (markers.PSEXEC_SERVICE_MARKER in name_lower
                 or markers.PSEXEC_SERVICE_MARKER in image_lower)
    if is_psexec:
        reasons.append("PsExec-style remote service name")
    if not reasons:
        return None

    mitre = ["T1543.003"] + (["T1569.002"] if is_psexec else [])
    key = str(d.get("key") or "")
    hive = str(d.get("hive") or "")
    svc_key = f"{key}\\{name}" if key else name
    summary = (f"{hive}: {svc_key} ImagePath={image!r} Start={d.get('start_type', '')!r}"
               + (f" FailureCommand={failure!r}" if failure else "")
               + f": {'; '.join(reasons)}")
    return Anchor(
        rule_id="registry-services",
        artifact_type=_SVC_ARTIFACT,
        event=e,
        title=(f"Suspicious service configuration: {name or '(unnamed)'} "
               f"({'; '.join(reasons)})"),
        mitre=mitre,
        confidence=0.7 if is_psexec else 0.6,
        iocs=_iocs(image or failure, svc_key),
        summary=summary,
        dedup_key=f"{hive}:{key.lower()}:{name_lower}:{image_lower}",
    )


def _cache_path_anchor(e: NormEvent, rule_id: str, label: str,
                       extra: str) -> Optional[Anchor]:
    d = e.data
    path = str(d.get("path") or "")
    path_lower = str(d.get("path_lower") or path.lower())
    base = str(d.get("basename_lower") or markers.basename(path_lower))
    if not path:
        return None
    stage = markers.staging_marker(path_lower)
    tool = markers.offensive_tool(base)
    if stage is None and tool is None:
        return None
    reasons = []
    if stage:
        reasons.append(f"in a temp/public-profile directory ('{stage}')")
    if tool:
        reasons.append(f"known offensive-tool name ('{tool}')")
    hive = str(d.get("hive") or "")
    title = f"{label} records {base} {' and '.join(reasons)}"
    summary = f"{hive}: {label} entry {path}{extra}"
    confidence = _TOOL_CONFIDENCE if tool else _PRESENCE_CONFIDENCE
    # Installer noise: a known installer filename inside that installer's
    # own extraction folder is demoted, not dropped — the pattern can be
    # mimicked, so the row stays visible with an explicit note. An
    # offensive-tool name is never demoted.
    installer = (markers.installer_extraction_context(path_lower)
                 if tool is None else None)
    if installer:
        confidence = _INSTALLER_DEMOTED_CONFIDENCE
        note = (f"[installer-context-demoted: {installer} — consistent with an "
                f"installer unpacking itself to temp; verify the file's "
                f"signature/hash before dismissing]")
        title += f" {note}"
        summary += f" {note}"
    return Anchor(
        rule_id=rule_id,
        artifact_type=e.artifact_type,
        event=e,
        title=title,
        mitre=["T1105"],
        confidence=confidence,
        iocs=_iocs(path),
        summary=summary,
        # The same file is often recorded twice (8.3 short and long profile
        # path); basename + recorded timestamp identifies it.
        dedup_key=f"{base}|{d.get('file_mtime') or e.timestamp}",
    )


def _cache_masquerade_anchor(e: NormEvent, rule_id: str, label: str,
                             extra: str) -> Optional[Anchor]:
    d = e.data
    path = str(d.get("path") or "")
    name = markers.masquerades_as_system_process(path.lower())
    if not name:
        return None
    hive = str(d.get("hive") or "")
    return Anchor(
        rule_id=rule_id,
        artifact_type=e.artifact_type,
        event=e,
        title=(f"{label} records a Windows system-process name ({name}) "
               f"outside its legitimate directory"),
        mitre=["T1036.005"],
        confidence=_MASQUERADE_CONFIDENCE,
        iocs=_iocs(path),
        summary=f"{hive}: {label} entry {path}{extra}",
        dedup_key=path.lower(),
    )


def _shim_extra(e: NormEvent) -> str:
    d = e.data
    out = f" (file last-modified {d.get('file_mtime') or 'n/a'}"
    if d.get("executed_flag") is True:
        out += ", Win7-era InsertFlag set"
    return out + ")"


def _amc_extra(e: NormEvent) -> str:
    d = e.data
    out = f" (entry LastWrite {e.timestamp or 'n/a'}"
    if d.get("sha1"):
        out += f", SHA1 {d['sha1']}"
    return out + ")"


def shimcache_suspicious_path(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != _SHIM_ARTIFACT:
        return None
    return _cache_path_anchor(e, "shimcache-suspicious-path", "ShimCache",
                              _shim_extra(e))


def shimcache_masquerade(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != _SHIM_ARTIFACT:
        return None
    return _cache_masquerade_anchor(e, "shimcache-masquerade", "ShimCache",
                                    _shim_extra(e))


def shimcache_anti_forensics(e: NormEvent) -> Optional[Anchor]:
    """A ShimCache row whose basename is a known wiper/cleaner (T1070.004)
    or timestomp tool (T1070.006). Name-only and presence-only: it says the
    tool's file was on the system, not that it ran or what it touched; a
    renamed tool escapes it and CCleaner/SDelete are often installed
    legitimately."""
    if e.artifact_type != _SHIM_ARTIFACT:
        return None
    d = e.data
    path = str(d.get("path") or "")
    if not path:
        return None
    base = str(d.get("basename_lower") or markers.basename(path.lower()))
    hit = markers.anti_forensic_tool(base)
    if hit is None:
        return None
    kind, indicator = hit
    if kind == "timestomp":
        mitre, what = ["T1070.006"], "timestamp-manipulation (timestomp) tool"
    else:
        mitre, what = ["T1070.004"], "secure-delete / trace-cleaner tool"
    hive = str(d.get("hive") or "")
    return Anchor(
        rule_id="shimcache-anti-forensics",
        artifact_type=_SHIM_ARTIFACT,
        event=e,
        title=(f"ShimCache records {base}, a known {what} name "
               f"('{indicator}')"),
        mitre=mitre,
        confidence=_ANTI_FORENSIC_CONFIDENCE,
        iocs=_iocs(path),
        summary=(f"{hive}: ShimCache entry {path}{_shim_extra(e)} — name match "
                 f"only: the file was present; whether it ran, and against "
                 f"what, needs Prefetch/EVTX/MFT corroboration"),
        dedup_key=f"{base}|{d.get('file_mtime') or e.timestamp}",
    )


def amcache_suspicious_path(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != _AMC_ARTIFACT:
        return None
    return _cache_path_anchor(e, "amcache-suspicious-path", "Amcache",
                              _amc_extra(e))


def amcache_masquerade(e: NormEvent) -> Optional[Anchor]:
    if e.artifact_type != _AMC_ARTIFACT:
        return None
    return _cache_masquerade_anchor(e, "amcache-mismatch", "Amcache",
                                    _amc_extra(e))


def _meta(uuid: str, name: str, severity: str, fields: list[str],
          fps: list[str], tag: str) -> RuleMetadata:
    return RuleMetadata(
        uuid=uuid, name=name, author="spectre-core", date="2026-09-30",
        version="1.0", severity=severity, rule_format="python",
        rule_source="modules/registry_hive/rules.py", tags=[tag],
        required_fields=fields, false_positives=fps)


_CACHE_PATH_FPS = [
    "Installers and updaters routinely unpack into %TEMP% / C:\\Windows\\Temp "
    "(vcredist, VMware Tools setup, browser updaters); a known installer name "
    "inside its own extraction folder is demoted (installer-context-demoted).",
    "Sysinternals PsExec/ProcDump used legitimately by administrators.",
]
_ANTI_FORENSIC_FPS = [
    "CCleaner, BleachBit and PrivaZer are common user-installed privacy tools.",
    "SDelete is a Sysinternals tool used legitimately for media sanitisation.",
    "Name-only match: an unrelated file can share the name, and a renamed "
    "tool is missed.",
]
_MASQ_FPS = ["Vendor or backup copies of a system binary kept outside System32."]

RULES = [
    Rule(
        rule_id="registry-run-persistence",
        artifact_type=ARTIFACT,
        predicate=run_key_persistence,
        mitre=["T1547.001"],
        description="Run/RunOnce autostart entry launches from a user-writable "
                    "directory or via a script/LOLBin interpreter.",
        metadata=RuleMetadata(
            uuid="7e2c9a3d-1f5b-4e8a-9c6d-2b4f8a1e6d70",
            name="Registry Run-key persistence (user-writable path or LOLBin)",
            author="spectre-core", date="2026-07-09", version="1.0",
            severity="high", rule_format="python",
            rule_source="modules/registry_hive/rules.py",
            tags=["spectre.persistence"],
            required_fields=["value_data"],
            false_positives=[
                "Legitimate updater/agent binaries installed under AppData "
                "(e.g. browser or cloud-sync updaters)."],
        ),
    ),
    Rule(
        rule_id="registry-services",
        artifact_type=_SVC_ARTIFACT,
        predicate=service_persistence,
        mitre=["T1543.003", "T1569.002"],
        description="Services-key ImagePath/FailureCommand launches from a "
                    "temp/public path, via a script host/LOLBin, %COMSPEC% or "
                    "an encoded command, or is a PSEXESVC-style service.",
        metadata=_meta("3c1f6d2a-9b8e-4f57-a0c4-5e2d7b9a1c31",
                       "Registry service with suspicious ImagePath", "high",
                       ["service_name", "image_path"],
                       ["Admin tooling that wraps a script in a service "
                        "(e.g. cmd.exe /c based monitoring agents)."],
                       "spectre.persistence"),
    ),
    Rule(
        rule_id="shimcache-suspicious-path",
        artifact_type=_SHIM_ARTIFACT,
        predicate=shimcache_suspicious_path,
        mitre=["T1105"],
        description="ShimCache records an executable in a temp/public-profile "
                    "directory or with a known offensive-tool name "
                    "(presence, not proof of execution).",
        metadata=_meta("8d4e2b7c-1a6f-4c39-b2e8-7f0a9c3d5e12",
                       "ShimCache entry in staging path / offensive tool name",
                       "medium", ["path"], _CACHE_PATH_FPS, "spectre.execution_trace"),
    ),
    Rule(
        rule_id="shimcache-masquerade",
        artifact_type=_SHIM_ARTIFACT,
        predicate=shimcache_masquerade,
        mitre=["T1036.005"],
        description="ShimCache records a Windows system-process name outside "
                    "System32/SysWOW64/WinSxS.",
        metadata=_meta("5a9c3e1d-7b2f-4d86-9e41-2c6b8f0d7a53",
                       "ShimCache system-process name outside its directory",
                       "medium", ["path"], _MASQ_FPS, "spectre.defense_evasion"),
    ),
    Rule(
        rule_id="shimcache-anti-forensics",
        artifact_type=_SHIM_ARTIFACT,
        predicate=shimcache_anti_forensics,
        mitre=["T1070.004", "T1070.006"],
        description="ShimCache records an executable named like a known "
                    "secure-delete/trace-cleaner or timestomp tool "
                    "(presence, not proof of execution).",
        metadata=_meta("9f3a6c2e-4b1d-4e85-a7c0-3d2e8b6f1a94",
                       "ShimCache entry named like an anti-forensic tool",
                       "medium", ["path"], _ANTI_FORENSIC_FPS,
                       "spectre.defense_evasion"),
    ),
    Rule(
        rule_id="amcache-suspicious-path",
        artifact_type=_AMC_ARTIFACT,
        predicate=amcache_suspicious_path,
        mitre=["T1105"],
        description="Amcache records an executable in a temp/public-profile "
                    "directory or with a known offensive-tool name "
                    "(presence, not proof of execution).",
        metadata=_meta("e2b7a4c9-3d1f-4a68-8c5e-9f1b0d2c6e74",
                       "Amcache entry in staging path / offensive tool name",
                       "medium", ["path"], _CACHE_PATH_FPS, "spectre.execution_trace"),
    ),
    Rule(
        rule_id="amcache-mismatch",
        artifact_type=_AMC_ARTIFACT,
        predicate=amcache_masquerade,
        mitre=["T1036.005"],
        description="Amcache records a Windows system-process name outside "
                    "System32/SysWOW64/WinSxS.",
        metadata=_meta("b6d1f8e3-2c4a-4e97-a3f0-1d8c5b7e9a26",
                       "Amcache system-process name outside its directory",
                       "medium", ["path"], _MASQ_FPS, "spectre.defense_evasion"),
    ),
]
