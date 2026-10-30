"""memory/rules.py — starter detection pack for memory artifacts.

Minimal starter: flag processes masquerading as system binaries running
from the wrong path is impossible without path data here, so we start
with a high-signal name check — known offensive tool process names in the
process list. Grow incrementally (malfind, hollowing, suspicious parents).
"""

from __future__ import annotations

import re
from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list, load_indicator_map

_SRC = "modules/memory/rules.py"


def _mitre_refs(*ids: str) -> list[str]:
    """MITRE ATT&CK technique URLs for the given technique IDs."""
    return ["https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"
            for t in ids]


def _prov(e: NormEvent, plugin: str) -> str:
    """Provenance prefix naming the engine that ACTUALLY produced the event.

    These summaries are written verbatim into the finding's corroboration
    block, so a hardcoded "vol ..." on a MemProcFS-sourced event produces an
    evidence document that contradicts its own corroboration.tools list.
    `source_tool` is stamped in Phase 2 from the extraction handle's engine
    ("volatility3" / "memprocfs"); rules never branch on it for detection --
    this is presentation only.
    """
    tool = getattr(e, "source_tool", "") or "unknown-engine"
    return f"{tool} {plugin}:"

_SUSPICIOUS_NAMES = frozenset(load_indicator_list("processes", "offensive_tools"))

# Archive utilities commonly used to stage data for exfiltration (T1560).
_ARCHIVE_TOOLS = frozenset(load_indicator_list("processes", "archive_tools"))
_ARCHIVE_PATH = re.compile(
    r'([A-Za-z]:\\[^"]*?\.(?:rar|zip|7z|tar|gz|cab|arj|ace))', re.IGNORECASE)


def suspicious_process(e: NormEvent) -> Optional[Anchor]:
    name = str(e.data.get("image_basename", "")).lower()
    if name in _SUSPICIOUS_NAMES:
        iocs = {"filepath": [e.data.get("image", "")], "ip": [], "domain": [],
                "sha256": [], "registry_key": []}
        return Anchor(
            rule_id="memory-suspicious-process",
            artifact_type="memory_pslist",
            event=e,
            title=f"Known offensive tool in process list: {name} (PID {e.data.get('pid')})",
            mitre=["T1059"],
            confidence=0.6,
            iocs=iocs,
            summary=f"{_prov(e, 'pslist')} {name} pid={e.data.get('pid')}",
        )
    return None


def archive_staging(e: NormEvent) -> Optional[Anchor]:
    """Archive utility seen in memory — classic exfil staging (T1560).

    Reads the command line (memory_cmdline) and, when the process is an
    archiver, records the archive path it operated on as the IOC.
    """
    proc = str(e.data.get("process", "")).lower()
    if proc not in _ARCHIVE_TOOLS:
        return None
    args = str(e.data.get("args", ""))
    m = _ARCHIVE_PATH.search(args)
    archive = m.group(1) if m else ""
    iocs = {"filepath": [archive] if archive else [], "ip": [], "domain": [],
            "sha256": [], "registry_key": []}
    return Anchor(
        rule_id="memory-archive-staging",
        artifact_type="memory_cmdline",
        event=e,
        title=f"Archive utility {proc} run against {archive or '(unknown archive)'} "
              f"— possible data staging for exfiltration",
        mitre=["T1560"],
        confidence=0.5,
        iocs=iocs,
        summary=f"{_prov(e, 'cmdline')} {proc} args={args[:120]}",
    )


# Environment-variable names that suggest a stored secret (T1552.001).
_SECRET_VAR = re.compile(
    r"(password|passwd|pwd|passphrase|secret|token|cred|apikey|api_key)",
    re.IGNORECASE)
# Standard Windows vars to never treat as secrets even if they match loosely.
_BENIGN_VARS = frozenset(load_indicator_list("processes", "benign_env_vars"))


def secret_env_var(e: NormEvent) -> Optional[Anchor]:
    """A user/process env var whose NAME implies a stored credential."""
    var = str(e.data.get("variable", ""))
    val = str(e.data.get("value", ""))
    if var.lower() in _BENIGN_VARS or not val:
        return None
    if _SECRET_VAR.search(var):
        return Anchor(
            rule_id="memory-secret-env-var",
            artifact_type="memory_envar",
            event=e,
            title=f"Credential in environment variable '{var}' "
                  f"(process {e.data.get('process')}, value recovered)",
            mitre=["T1552.001"],
            confidence=0.6,
            iocs={"filepath": [], "ip": [], "domain": [], "sha256": [],
                  "registry_key": []},
            summary=f"{_prov(e, 'envars')} {var}={val}",
            dedup_key=f"{var.lower()}={val}",
        )
    return None


_ARCHIVE_EXT = tuple(load_indicator_list("paths", "archive_extensions"))


def sensitive_file_on_disk(e: NormEvent) -> Optional[Anchor]:
    """An archive sitting in a user profile dir — candidate exfil staging."""
    p = str(e.data.get("path", "")).lower()
    if "\\users\\" in p and p.endswith(_ARCHIVE_EXT):
        return Anchor(
            rule_id="memory-sensitive-file",
            artifact_type="memory_filescan",
            event=e,
            title=f"Archive in a user profile directory: {e.data.get('path')}",
            mitre=["T1560"],
            confidence=0.4,
            iocs={"filepath": [e.data.get("path", "")], "ip": [], "domain": [],
                  "sha256": [], "registry_key": []},
            summary=f"{_prov(e, 'filescan')} {e.data.get('path')}",
            dedup_key=p,
        )
    return None


# High-signal paste / file-share hosts (deliberately NOT including
# drive/docs.google or dropbox — far too common in normal browsing).
_INTEREST_HOSTS = tuple(load_indicator_list("network", "paste_share_hosts"))


# Carving from RAM has no notion of URL boundaries, so two adjacent links
# in the same memory region are sometimes carved as one run-on string with
# no separator (e.g. ".../RSGSi1hkhttps://pastebin.com/..."). Detect a
# second embedded scheme after the first character and truncate there,
# keeping only the first (leftmost) URL.
_EMBEDDED_SCHEME = re.compile(r"https?://", re.IGNORECASE)
# A trailing bare scheme WORD glued to the end with no "://" — the carve
# grabbed the leading bytes of an adjacent second URL before truncating
# (case 004 F-272-009: ".../RSGSi1hkhttps"). Strip it so the corrupted carve
# canonicalizes to the clean URL instead of becoming its own finding + IOC.
_TRAILING_SCHEME = re.compile(r"(?<=[A-Za-z0-9])https?$", re.IGNORECASE)
# A valid dotted host: 2+ labels ending in an alphabetic TLD. Rejects
# single-label junk ("www", "cloud-assets-z") and scheme-glued run-ons that
# survive repair. Deliberately loose on the TLD length — this is a sanity
# gate, not a public-suffix validator.
_VALID_HOST = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def _repair_carved_url(url: str) -> str:
    if not url:
        return url
    m = _EMBEDDED_SCHEME.search(url, 1)
    if m:
        url = url[:m.start()]
    return _TRAILING_SCHEME.sub("", url)


def _clean_host(url: str) -> str:
    """Registrable host from a repaired carved URL, or '' if malformed.

    Rules re-derive the host from the REPAIRED url rather than trusting
    normalize()'s data['host'] (computed from the raw carve, which can carry
    trailing/scheme-glued junk).
    """
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return host if _VALID_HOST.match(host) else ""


def interesting_url(e: NormEvent) -> Optional[Anchor]:
    raw_url = str(e.data.get("url", ""))
    url = _repair_carved_url(raw_url)
    # Re-derive the host from the REPAIRED url and validate it — a corrupted
    # carve can carry scheme-glued/trailing junk in normalize()'s data['host'].
    path_host = _clean_host(url)
    if not path_host or not any(h in path_host for h in _INTEREST_HOSTS):
        return None
    # Carving from RAM grabs trailing/adjacent bytes, so the same link shows
    # up many ways. Canonicalize to host + first path resource token and
    # dedup on that, so e.g. pastebin.com/RSGSi1hk collapses to one finding.
    from urllib.parse import urlparse
    m = re.match(r"/([A-Za-z0-9_-]+)", urlparse(url).path if url else "")
    resource = m.group(1) if m else ""
    if not resource:
        # Bare host, no meaningful path (e.g. "https://pastebin.com/") is
        # low forensic value on its own — not worth a standalone finding.
        return None
    canonical = f"https://{path_host}/{resource}".rstrip("/")
    # NEUTRAL observation — a paste/file-share service was referenced in
    # memory. Deliberately NO attack technique: carving is a pure single-event
    # signal with no outbound-network corroboration, so an Exfiltration
    # (T1567.002) mapping would be unfounded (case 004 gold gap G2). The report
    # layer may interpret; the deterministic layer only surfaces the FACT.
    return Anchor(
        rule_id="memory-interesting-url",
        artifact_type="memory_url",
        event=e,
        title=f"Paste/file-share URL recovered from memory: {canonical}",
        mitre=[],
        confidence=0.4,
        iocs={"filepath": [], "ip": [], "domain": [path_host], "sha256": [],
              "registry_key": []},
        summary=f"carved url: {canonical} (raw: {raw_url[:80]})",
        dedup_key=canonical,
    )


def browsing_history_domain(e: NormEvent) -> Optional[Anchor]:
    """A domain the user actually navigated to, recovered from memory.

    Discriminator: the carved URL echoes its own host as the leading path
    segment (e.g. "http://bi0s.in/bi0s.in0,1") — a Firefox awesomebar / places
    autocomplete memory artifact that marks a browser history / bookmark entry,
    as opposed to a passively-referenced asset / CDN / telemetry / certificate
    URL (which never appears in that self-referential form). On a raw RAM carve
    this cleanly isolates the user's real browsing history from the hundreds of
    infrastructure domains a strings sweep also picks up.

    This is a FACT surfacing only: a neutral observation with NO attack
    technique and no "benign"/"CTF" conclusion. Surfacing the domain lets it
    reach the IOC export so the report layer can interpret it, grounded in the
    carved evidence (case 004 gold gap G1). NEVER asserts an interpretation.
    """
    raw_url = str(e.data.get("url", ""))
    url = _repair_carved_url(raw_url)
    host = _clean_host(url)
    if not host:
        return None
    from urllib.parse import urlparse
    seg = urlparse(url).path.lstrip("/").lower()
    if not seg.startswith(host):
        return None
    return Anchor(
        rule_id="memory-browsing-history-domain",
        artifact_type="memory_url",
        event=e,
        title=f"Browsing-history domain recovered from memory: {host}",
        mitre=[],
        confidence=0.4,
        iocs={"filepath": [], "ip": [], "domain": [host], "sha256": [],
              "registry_key": []},
        summary=f"carved browsing-history entry: {host} (raw: {raw_url[:80]})",
        dedup_key=host,
    )


# ── Established outbound connections (case 004 gold gap G3) ──────────────
# A loopback or unspecified foreign address is not an outbound connection.
_LOOPBACK_PREFIXES = ("127.", "::1")
_UNSPECIFIED_ADDRS = frozenset(("*", "0.0.0.0", "::", ""))


def _owner_proc(owner: str) -> str:
    """Process basename from a netscan owner field. volatility pads some rows
    with '*** ffff… \\Device\\…\\proc.exe' junk after the name — take the first
    whitespace token so padded and clean rows of the same process collapse."""
    return owner.strip().split()[0].lower() if owner and owner.strip() else ""


def established_connection(e: NormEvent) -> Optional[Anchor]:
    """An ESTABLISHED outbound connection recovered from netscan.

    Surfaces the FACT that a process held established connections to external
    hosts — the signal the report needs to judge network directionality.
    Without it the verdict wrongly reads "zero outbound … directionality
    cannot be determined" (case 004 gold gap G3), even though netscan captured
    dozens of Firefox → CDN browsing connections.

    NEUTRAL: no attack technique and no "benign browsing" conclusion — the
    report layer interprets. Aggregated per owning process (dedup_key = owner)
    so a browser's many connections collapse into ONE finding rather than
    inflating the report with a per-host finding each (gold gap G6).
    """
    if "ESTAB" not in str(e.data.get("state", "")).upper():
        return None
    foreign = str(e.data.get("foreign_addr", "")).strip()
    if foreign in _UNSPECIFIED_ADDRS or foreign.startswith(_LOOPBACK_PREFIXES):
        return None
    owner = _owner_proc(str(e.data.get("owner", "")))
    if not owner:
        return None
    fport = e.data.get("foreign_port", "")
    return Anchor(
        rule_id="memory-established-connection",
        artifact_type="memory_netscan",
        event=e,
        title=f"Established outbound network connections from {owner}",
        mitre=[],
        confidence=0.3,
        iocs={"filepath": [], "ip": [foreign], "domain": [], "sha256": [],
              "registry_key": []},
        summary=f"{_prov(e, 'netscan')} {owner} -> {foreign}:{fport} (ESTABLISHED)",
        dedup_key=owner,
    )


# ── Memory-acquisition artifacts (case 004 gold gap G4) ─────────────────
_ACQUISITION_TOOLS = tuple(load_indicator_list("processes",
                                               "memory_acquisition_tools"))
# Memory-image output extensions — a dump file on disk marks an acquisition.
_MEMORY_IMAGE_EXT = (".raw", ".mem", ".vmem", ".dmp", ".lime", ".aff4")


def acquisition_artifact(e: NormEvent) -> Optional[Anchor]:
    """A memory-acquisition tool or its dump output found on disk (filescan).

    The strongest "this image is a forensic/CTF acquisition capture, not a
    compromise" indicator (case 004 gold gap G4: DumpIt.exe + its
    VIRUS-PC-*.raw output on the Desktop). NEUTRAL: surfaces the FACT only —
    the acquisition read is the report layer's to draw, grounded here.
    """
    path = str(e.data.get("path", ""))
    base = str(e.data.get("basename", "")).lower() or path.rsplit("\\", 1)[-1].lower()
    if not path:
        return None
    is_tool = any(t in base for t in _ACQUISITION_TOOLS)
    is_image = base.endswith(_MEMORY_IMAGE_EXT)
    if not (is_tool or is_image):
        return None
    return Anchor(
        rule_id="memory-acquisition-artifact",
        artifact_type="memory_filescan",
        event=e,
        title=f"Memory-acquisition artifact on disk: {path}",
        mitre=[],
        confidence=0.3,
        iocs={"filepath": [path], "ip": [], "domain": [], "sha256": [],
              "registry_key": []},
        summary=f"{_prov(e, 'filescan')} {path}",
        dedup_key=base,
    )


# ── Generic anomaly detection (SANS 6-step) ──────────────────────────
# These encode "what makes a process/region suspicious" generically — no
# hashes or named-tool lists. They rely on normalize() having embedded
# `parent_image` and `instance_count` into each pslist event.

# Step 1: anomalous parent/child. Shell / script hosts spawned by a browser,
# Office app, or web server are a classic exploitation footprint
# (GrrCon: iexplore.exe->cmd.exe, w3wp.exe->cmd.exe).
_SHELL_HOSTS = frozenset(load_indicator_list("processes", "memory_shell_hosts"))
_SUSPECT_PARENTS = frozenset(load_indicator_list("processes", "suspect_parents"))


def anomalous_parent(e: NormEvent) -> Optional[Anchor]:
    name = str(e.data.get("image_basename", "")).lower()
    parent = str(e.data.get("parent_image", "")).lower()
    if name in _SHELL_HOSTS and parent in _SUSPECT_PARENTS:
        return Anchor(
            rule_id="memory-anomalous-parent",
            artifact_type="memory_pslist",
            event=e,
            title=f"Anomalous parent/child: {parent} spawned {name} "
                  f"(PID {e.data.get('pid')}) — possible exploitation/proxy execution",
            mitre=["T1059"],
            confidence=0.7,
            iocs={"filepath": [e.data.get("image", "")], "ip": [], "domain": [],
                  "sha256": [], "registry_key": []},
            summary=f"{_prov(e, 'pslist')} {parent} -> {name} pid={e.data.get('pid')}",
            dedup_key=f"{name}:{e.data.get('pid')}",
        )
    return None


# Step 1: system-process masquerade. Core Windows binaries have known parents,
# are singletons, and have canonical names. A wrong parent, an extra instance
# of a singleton, or a look-alike misspelling is high signal.
_EXPECTED_PARENT = load_indicator_map("processes", "expected_process_parents")
_SINGLETONS = frozenset(load_indicator_list("processes", "singleton_processes"))
_SYSTEM_NAMES = frozenset(load_indicator_list("processes", "system_process_names"))
# Common homoglyph substitutions used to disguise a system name.
_CONFUSE = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e"})


def _damerau1(a: str, b: str) -> bool:
    """True if a is within one edit (incl. adjacent transposition) of b."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    # adjacent transposition (e.g. scvhost vs svchost)
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1 \
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]:
            return True
        return len(diffs) == 1
    # one insertion/deletion
    short, long = (a, b) if la < lb else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long):
        if short[i] != long[j]:
            if skipped:
                return False
            skipped = True
            j += 1
        else:
            i += 1
            j += 1
    return True


def _looks_like_system(name_base: str) -> Optional[str]:
    """Return the system name this is masquerading as, or None."""
    if name_base in _SYSTEM_NAMES:
        return None
    deconfused = name_base.translate(_CONFUSE)
    if deconfused != name_base and deconfused in _SYSTEM_NAMES:
        return deconfused
    if len(name_base) >= 5:
        # _SYSTEM_NAMES is a frozenset: iteration order is hash-seed
        # dependent (PYTHONHASHSEED). Sort so that when a masqueraded name
        # is edit-distance-1 from more than one system name, the SAME
        # candidate is chosen on every run -- the returned name feeds the
        # finding title (and, transitively, reason/reason_class text) in
        # masquerade_system_process(). Lexicographic order is an arbitrary
        # but stable tie-break; there is no forensic reason to prefer one
        # matching system name over another edit-distance-1 match.
        for sysname in sorted(_SYSTEM_NAMES):
            if len(sysname) >= 5 and _damerau1(name_base, sysname):
                return sysname
    return None


def masquerade_system_process(e: NormEvent) -> Optional[Anchor]:
    name = str(e.data.get("image_basename", "")).lower()
    parent = str(e.data.get("parent_image", "")).lower()
    count = int(e.data.get("instance_count", 1) or 1)
    base = name[:-4] if name.endswith(".exe") else name

    # `reason` is prose for the analyst; `reason_class` is the identity. The
    # class is a CLOSED ENUM deliberately: the old key embedded reason[:20],
    # which carried instance_count -- an aggregate derived from how many
    # processes THIS engine happened to enumerate. Two engines with different
    # coverage then produced different keys, so the more they disagreed the
    # less they could corroborate. The count stays in the title as evidence.
    reason = ""
    reason_class = ""
    if name in _EXPECTED_PARENT and parent and parent != _EXPECTED_PARENT[name]:
        reason = (f"{name} has parent {parent}, expected "
                  f"{_EXPECTED_PARENT[name]}")
        reason_class = "wrong_parent"
    elif name in _SINGLETONS and count > 1:
        reason = f"{count} instances of singleton {name} (expected 1)"
        reason_class = "singleton_dup"
    else:
        impersonated = _looks_like_system(base)
        if impersonated:
            reason = f"{name} is a look-alike of {impersonated}.exe"
            reason_class = "lookalike"

    if not reason:
        return None
    return Anchor(
        rule_id="memory-masquerade-system-process",
        artifact_type="memory_pslist",
        event=e,
        title=f"System-process masquerade: {reason} (PID {e.data.get('pid')})",
        mitre=["T1036.005"],
        confidence=0.6,
        iocs={"filepath": [e.data.get("image", "")], "ip": [], "domain": [],
              "sha256": [], "registry_key": []},
        summary=f"{_prov(e, 'pslist')} {reason} pid={e.data.get('pid')}",
        dedup_key=f"{name}:{e.data.get('pid')}:{reason_class}",
    )


# Step 4: code injection. malfind only surfaces private, committed, executable
# memory that has no backing file — i.e. likely injected/unpacked code. A PE
# (MZ) header points to reflective DLL/PE injection; otherwise raw shellcode.
# ponytail: known JIT processes — malfind hits are false positives.
# explorer.exe/wmiprvse.exe intentionally excluded: they are common
# injection TARGETS, not JIT processes (closes memory_malfind_explorer_allowlisted).
_BENIGN_MALFIND = frozenset(load_indicator_list("memory", "benign_malfind_processes"))

# ponytail: known injection TARGET processes (Track D calibration, closes
# gold case 004 FP: memory_malfind_explorer_confirmed). explorer.exe and
# wmiprvse.exe are common hosts for reflective/process injection — they
# must stay OFF _BENIGN_MALFIND (a real attacker can and does inject into
# them), but a bare malfind hit with no corroborating signal (no suspicious
# parent chain, no unbacked RWX in a non-target process alongside it) is
# just as consistent with normal OS/WMI activity in these specific hosts.
# So the hit still fires — never dropped — but at reduced confidence, so it
# renders as an INFERRED single-source lead instead of a CONFIRMED
# injection on a benign image.
_INJECTION_TARGET_PROCS = frozenset(
    load_indicator_list("memory", "injection_target_processes"))
_INJECTION_TARGET_CONF = 0.35

def injected_code(e: NormEvent) -> Optional[Anchor]:
    # ponytail: skip known JIT/browser processes
    proc = str(e.data.get("process", "")).lower()
    if proc in _BENIGN_MALFIND:
        return None
    prot = str(e.data.get("protection", "")).upper()
    if "EXECUTE" not in prot:
        return None
    pe = bool(e.data.get("has_pe_header"))
    pid = e.data.get("pid")
    proc = e.data.get("process")
    addr = e.data.get("address")
    if pe:
        title = (f"Injected PE in {proc} (PID {pid}) at {addr} "
                 f"[{prot}] — reflective/process injection")
        conf = 0.7
    elif e.data.get("region_bytes_read", True):
        title = (f"Executable non-file-backed memory in {proc} (PID {pid}) "
                 f"at {addr} [{prot}] — shellcode/unpacked code")
        conf = 0.55
    else:
        # The region's contents were never read, so "no PE header" is an
        # absence of observation, not an observation of absence. Say what was
        # actually seen -- the protection and the lack of a file backing --
        # and nothing about what the bytes are.
        title = (f"Executable non-file-backed memory in {proc} (PID {pid}) "
                 f"at {addr} [{prot}] — region contents not read")
        conf = 0.5
    if str(proc).lower() in _INJECTION_TARGET_PROCS:
        # No corroborating signal available to this single-event rule
        # (cross-process/parent-chain corroboration is a correlation-layer
        # concern) — calibrate down rather than drop.
        conf = min(conf, _INJECTION_TARGET_CONF)
    return Anchor(
        rule_id="memory-injected-code",
        artifact_type="memory_malfind",
        event=e,
        title=title,
        mitre=["T1055.001"] if pe else ["T1027.002"],
        confidence=conf,
        iocs={"filepath": [], "ip": [], "domain": [], "sha256": [],
              "registry_key": []},
        summary=f"{_prov(e, 'malfind')} {proc} pid={pid} {addr} {prot}",
        dedup_key=f"{pid}:{e.data.get('address_canonical') or addr}",
    )


# Step 5: persistence. An autostart (Run/RunOnce/Winlogon) value that references
# an executable or script is a boot/logon persistence mechanism.
_PERSIST_REF = re.compile(
    r'([A-Za-z]:\\[^"]*?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|com))',
    re.IGNORECASE)


# ponytail: default Windows autostart values — not persistence
_BENIGN_AUTOSTART = frozenset({
    "shell", "userinit", "vmapplet", "autorestartshell", "background",
    "cachedlogonscount", "debugservercommand", "forceunlocklogon",
    "legalnoticecaption", "legalnoticetext", "passwordexpirywarning",
    "powerdownaftershutdown", "shutdownwithoutlogon", "winstationsdisabled",
    "disablecad", "scremoveoption", "shutdownflags", "autoadminlogon",
    "defaultusername", "reportbootok", "precreateknownfolders",
    # ponytail: known-benign vendor Run keys
    "vboxtray", "sidebar", "mctadmin",
})

def registry_persistence(e: NormEvent) -> Optional[Anchor]:
    data = str(e.data.get("value_data", "")).strip()
    if not data:
        return None
    key = str(e.data.get("key", ""))
    name = str(e.data.get("value_name", ""))
    # ponytail: skip default Windows autostart values
    if name.lower() in _BENIGN_AUTOSTART:
        return None
    m = _PERSIST_REF.search(data)
    ref = m.group(1) if m else data
    return Anchor(
        rule_id="memory-registry-persistence",
        artifact_type="memory_regkey",
        event=e,
        title=f"Autostart persistence: {key}\\{name} -> {ref}",
        mitre=["T1547.001"],
        confidence=0.55,
        iocs={"filepath": [ref] if m else [], "ip": [], "domain": [],
              "sha256": [], "registry_key": [f"{key}\\{name}"]},
        summary=f"{_prov(e, 'printkey')} {key}\\{name} = {data[:120]}",
        dedup_key=f"{e.data.get('key_canonical') or key}\\{name.lower()}",
    )


# Step 5 (continued): services. AutoStart locations and Services together
# account for the large majority of real-world persistence, and memory_svcscan
# has been extracted since this module was written with nothing consuming it.
#
# A service is persistence when it starts by itself at boot AND its binary is
# somewhere a service binary has no business being. Either half alone is
# noise: every Windows host has hundreds of auto-start services in System32,
# and a demand-start service in a temp directory does not survive a reboot.
_SERVICE_USER_WRITABLE = ("\\users\\", "\\temp\\", "\\appdata\\",
                          "\\programdata\\")
_LOLBIN_HOSTS = frozenset(load_indicator_list("processes", "lolbins"))
_SERVICE_IMAGE_EXT = re.compile(
    r"^(.*?\.(?:exe|sys|dll|bat|cmd|ps1|com|scr))(?:\s|$)", re.IGNORECASE)


def _service_image(binary: str) -> tuple[str, bool]:
    """Split a service ImagePath into (image, was_quoted).

    The unquoted case is genuinely ambiguous -- that ambiguity IS the
    unquoted-service-path weakness -- so the first token ending in an
    executable extension is taken as the image, which is how the service
    controller's own search resolves it.
    """
    b = binary.strip()
    if b.startswith('"'):
        end = b.find('"', 1)
        return (b[1:end] if end > 0 else b[1:]), True
    m = _SERVICE_IMAGE_EXT.match(b)
    if m:
        return m.group(1), False
    return (b.split()[0] if b.split() else ""), False


def service_persistence(e: NormEvent) -> Optional[Anchor]:
    """An auto-start service whose binary sits somewhere anomalous."""
    if e.data.get("start_canonical") != "auto":
        return None
    binary = str(e.data.get("binary", "")).strip()
    if not binary:
        return None
    image, quoted = _service_image(binary)
    if not image:
        return None
    low = image.lower()
    base = low.replace("/", "\\").rsplit("\\", 1)[-1]

    if any(marker in low for marker in _SERVICE_USER_WRITABLE):
        reason = "binary in a user-writable location"
    elif "\\" not in image and "/" not in image:
        # No directory component: resolved against the service controller's
        # working directory, so a planted binary earlier in the search order
        # wins.
        reason = "relative binary path (resolution hijack)"
    elif not quoted and " " in image:
        reason = "unquoted path containing a space"
    elif base in _LOLBIN_HOSTS:
        reason = f"service hosted by LOLBin {base}"
    else:
        return None

    service = str(e.data.get("service", ""))
    return Anchor(
        rule_id="memory-service-persistence",
        artifact_type="memory_svcscan",
        event=e,
        title=f"Auto-start service '{service}' — {reason}: {image}",
        mitre=["T1543.003"],
        # Deliberately modest. This is a shape, not a verdict; let
        # corroboration promote the ones a second engine also saw.
        confidence=0.5,
        iocs={"filepath": [image], "ip": [], "domain": [], "sha256": [],
              "registry_key": []},
        summary=f"{_prov(e, 'svcscan')} {service} start=auto binary={binary[:120]}",
        dedup_key=service.lower(),
    )


# Winlogon's Userinit must reference userinit.exe and nothing else. Anything
# appended after a comma runs at every interactive logon (T1547.004). The
# trailing comma in the stock value is Windows' own rendering, not an empty
# second entry -- treating it as one flags every healthy Windows host.
def winlogon_userinit_hijack(e: NormEvent) -> Optional[Anchor]:
    if str(e.data.get("value_name", "")).lower() != "userinit":
        return None
    key = str(e.data.get("key_canonical") or e.data.get("key", "")).lower()
    if "winlogon" not in key:
        return None
    raw = str(e.data.get("value_data", "")).strip()
    if not raw:
        # An absent value is a gap in what was recovered from the hive, not an
        # observation that Userinit was tampered with.
        return None
    entries = [p.strip().strip('"') for p in raw.split(",")]
    entries = [p for p in entries if p]
    if len(entries) == 1 and entries[0].replace("/", "\\").rsplit(
            "\\", 1)[-1].lower() == "userinit.exe":
        return None
    return Anchor(
        rule_id="memory-winlogon-userinit-hijack",
        artifact_type="memory_regkey",
        event=e,
        title=f"Winlogon Userinit hijack — logon shell chain is "
              f"{', '.join(entries) or '(empty)'}",
        mitre=["T1547.004"],
        confidence=0.75,
        iocs={"filepath": entries[1:] if len(entries) > 1 else entries,
              "ip": [], "domain": [], "sha256": [],
              "registry_key": [f"{key}\\userinit"]},
        summary=f"{_prov(e, 'printkey')} Userinit = {raw[:120]}",
        dedup_key=f"{e.data.get('key_canonical') or key}\\userinit",
    )


# Track C: hidden-process cross-check. `hidden_from_pslist` is stamped by
# enrich_events() (memory/enrich.py) BEFORE rules run — this predicate never
# computes the cross-reference itself, it only reads the stamped fact, so it
# stays a pure single-event predicate like every other rule here.
def hidden_process(e: NormEvent) -> Optional[Anchor]:
    if not e.data.get("hidden_from_pslist"):
        return None
    if e.data.get("exit_time"):
        # psscan pool-scanning also surfaces freed EPROCESS blocks from
        # TERMINATED processes — legitimately absent from pslist, not hidden.
        return None
    image = e.data.get("image") or e.data.get("image_basename", "")
    pid = e.data.get("pid")
    return Anchor(
        rule_id="memory-hidden-process",
        artifact_type="memory_psscan",
        event=e,
        title=(f"Hidden process: {image} (PID {pid}) seen in psscan but absent "
               f"from pslist, no exit time recorded (live, unlinked)"),
        mitre=["T1564.001"],
        confidence=0.7,
        iocs={"filepath": [e.data.get("image", "")], "ip": [], "domain": [],
              "sha256": [], "registry_key": []},
        summary=(f"{_prov(e, 'psscan')} psscan-only process absent from pslist (same image, "
                 f"same engine), no exit time recorded: {image} pid={pid}"),
        dedup_key=f"{str(image).lower()}:{pid}",
    )


RULES: list[Rule] = [
    Rule(
        "memory-suspicious-process", "memory_pslist", suspicious_process,
        ["T1059"], "a known offensive-tool process name in the process list",
        metadata=RuleMetadata(
            uuid="8be23dbf-b33a-45ad-8f9e-8b47adf4c675",
            name="Known offensive tool in the process list",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1059"),
            tags=["attack.execution", "attack.t1059"],
            false_positives=["sanctioned red-team/pentest tooling on the host"],
            required_fields=["image_basename", "image", "pid"],
        ),
    ),
    Rule(
        "memory-anomalous-parent", "memory_pslist", anomalous_parent,
        ["T1059"], "a shell/script host spawned by a browser/Office/web-server",
        metadata=RuleMetadata(
            uuid="6148d5b9-893f-4809-bb1f-2c799b2b1080",
            name="Anomalous parent/child (shell spawned by browser/Office/web server)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1059"),
            tags=["attack.execution", "attack.t1059"],
            false_positives=["help/diagnostic launchers that shell out by design"],
            required_fields=["image_basename", "parent_image", "pid", "image"],
        ),
    ),
    Rule(
        "memory-masquerade-system-process", "memory_pslist",
        masquerade_system_process, ["T1036.005"],
        "a system binary with the wrong parent, extra instance, or look-alike name",
        metadata=RuleMetadata(
            uuid="9d95bcd5-62fe-49e6-ab7f-cbc9f707509b",
            name="System-process masquerade (wrong parent / extra instance / look-alike)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1036.005"),
            tags=["attack.defense_evasion", "attack.t1036.005"],
            false_positives=["unusual but legitimate service host configurations"],
            required_fields=["image_basename", "parent_image", "instance_count", "pid", "image"],
        ),
    ),
    Rule(
        "memory-injected-code", "memory_malfind", injected_code,
        ["T1055.001"], "injected/unpacked executable memory (malfind)",
        metadata=RuleMetadata(
            uuid="9ef35683-ec2a-4286-886c-333707ae0a46",
            name="Injected/unpacked executable memory (malfind)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="high", rule_source=_SRC,
            references=_mitre_refs("T1055.001", "T1027.002"),
            tags=["attack.defense_evasion", "attack.t1055.001"],
            false_positives=["JIT compilers / packers in legitimate software"],
            required_fields=["protection", "has_pe_header", "pid", "process", "address"],
        ),
    ),
    Rule(
        "memory-registry-persistence", "memory_regkey", registry_persistence,
        ["T1547.001"], "an autostart registry value referencing an executable",
        metadata=RuleMetadata(
            uuid="e7815343-8b46-409a-bb61-b5f28ed3addb",
            name="Autostart registry persistence (Run/RunOnce/Winlogon)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_source=_SRC, references=_mitre_refs("T1547.001"),
            tags=["attack.persistence", "attack.t1547.001"],
            false_positives=["legitimate software registering an autostart entry"],
            required_fields=["value_data", "key", "value_name"],
        ),
    ),
    Rule(
        "memory-archive-staging", "memory_cmdline", archive_staging,
        ["T1560"], "an archive utility staging data (possible exfiltration)",
        metadata=RuleMetadata(
            uuid="ff8dc551-9c24-4e49-844c-e4690bb470b2",
            name="Archive utility staging data (possible exfiltration)",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_source=_SRC, references=_mitre_refs("T1560"),
            tags=["attack.collection", "attack.t1560"],
            false_positives=["routine backup/compression by an admin or user"],
            required_fields=["process", "args"],
        ),
    ),
    Rule(
        "memory-secret-env-var", "memory_envar", secret_env_var,
        ["T1552.001"], "a credential stored in an environment variable",
        metadata=RuleMetadata(
            uuid="54b18488-a22b-4980-bae5-40bc7b1f0262",
            name="Credential stored in an environment variable",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="medium", rule_source=_SRC, references=_mitre_refs("T1552.001"),
            tags=["attack.credential_access", "attack.t1552.001"],
            false_positives=["app config that names a var 'token'/'key' benignly"],
            required_fields=["variable", "value", "process"],
        ),
    ),
    Rule(
        "memory-sensitive-file", "memory_filescan", sensitive_file_on_disk,
        ["T1560"], "an archive in a user profile directory",
        metadata=RuleMetadata(
            uuid="0b71e083-5cc4-4b18-be37-f039f0387534",
            name="Archive in a user profile directory",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="low", rule_source=_SRC, references=_mitre_refs("T1560"),
            tags=["attack.collection", "attack.t1560"],
            false_positives=["user-downloaded archives kept in their profile"],
            required_fields=["path"],
        ),
    ),
    Rule(
        "memory-service-persistence", "memory_svcscan", service_persistence,
        ["T1543.003"], "an auto-start service whose binary sits somewhere anomalous",
        metadata=RuleMetadata(
            uuid="c1d2a7f4-6b93-4c2e-9a51-8f0d3b7e4a16",
            name="Auto-start service with an anomalous binary path",
            author="spectre-core", date="2026-08-07", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1543.003"),
            tags=["attack.persistence", "attack.t1543.003"],
            false_positives=[
                "third-party software installed under ProgramData or AppData",
                "a legacy vendor service registered with an unquoted path",
            ],
            required_fields=["service", "binary", "start_canonical"],
        ),
    ),
    Rule(
        "memory-winlogon-userinit-hijack", "memory_regkey",
        winlogon_userinit_hijack,
        ["T1547.004"], "Winlogon Userinit referencing anything but userinit.exe",
        metadata=RuleMetadata(
            uuid="a93f5e21-70c8-4d4b-b6ac-2e5719d8c033",
            name="Winlogon Userinit hijack",
            author="spectre-core", date="2026-08-07", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1547.004"),
            tags=["attack.persistence", "attack.t1547.004"],
            false_positives=[
                "a domain build that legitimately chains a logon helper",
            ],
            required_fields=["value_name", "value_data", "key"],
        ),
    ),
    Rule(
        "memory-hidden-process", "memory_psscan", hidden_process,
        ["T1564.001"],
        "a psscan-only process absent from the pslist baseline for the same evidence file/engine",
        metadata=RuleMetadata(
            uuid="f4d35e37-a79f-4fa3-83c6-eac520961dc1",
            name="Hidden process (psscan-only, absent from pslist)",
            author="spectre-core", date="2026-07-10", version="1.0",
            severity="high", rule_source=_SRC, references=_mitre_refs("T1564.001"),
            tags=["attack.defense_evasion", "attack.t1564.001"],
            false_positives=["process exited between the pslist and psscan snapshots"],
            required_fields=["hidden_from_pslist"],
        ),
    ),
    Rule(
        "memory-interesting-url", "memory_url", interesting_url,
        [], "a paste/file-share/cloud URL referenced in memory (neutral)",
        metadata=RuleMetadata(
            uuid="6488b3ac-ae11-4c35-90c4-82452aee30b0",
            name="Paste/file-share URL recovered from memory",
            author="spectre-core", date="2026-07-12", version="2.0",
            severity="informational", rule_source=_SRC, references=[],
            tags=["observation", "memory.browsing"],
            false_positives=["benign browsing of paste/file-share sites"],
            required_fields=["url"],
        ),
    ),
    Rule(
        "memory-browsing-history-domain", "memory_url", browsing_history_domain,
        [], "a domain the user navigated to, recovered from memory (neutral)",
        metadata=RuleMetadata(
            uuid="b0f3d2a1-7c4e-4a9b-9d21-2f6a3c8e15d4",
            name="Browsing-history domain recovered from memory",
            author="spectre-core", date="2026-07-12", version="1.0",
            severity="informational", rule_source=_SRC, references=[],
            tags=["observation", "memory.browsing"],
            false_positives=[
                "a self-referential host string carved from non-history memory"],
            required_fields=["url"],
        ),
    ),
    Rule(
        "memory-established-connection", "memory_netscan", established_connection,
        [], "an established outbound connection recovered from netscan (neutral)",
        metadata=RuleMetadata(
            uuid="d4c9e1a7-3b62-4e58-8a0f-6c1d92b4f703",
            name="Established outbound network connections (netscan)",
            author="spectre-core", date="2026-07-12", version="1.0",
            severity="informational", rule_source=_SRC, references=[],
            tags=["observation", "memory.network"],
            false_positives=[
                "ordinary application/browser network activity"],
            required_fields=["state", "foreign_addr", "owner"],
        ),
    ),
    Rule(
        "memory-acquisition-artifact", "memory_filescan", acquisition_artifact,
        [], "a memory-acquisition tool or dump output found on disk (neutral)",
        metadata=RuleMetadata(
            uuid="a17f5c02-9e84-4d31-b6a5-38e0c7419f2b",
            name="Memory-acquisition artifact on disk (filescan)",
            author="spectre-core", date="2026-07-12", version="1.0",
            severity="informational", rule_source=_SRC, references=[],
            tags=["observation", "memory.acquisition"],
            false_positives=[
                "a non-dump file matching a memory-image extension"],
            required_fields=["path", "basename"],
        ),
    ),
]
