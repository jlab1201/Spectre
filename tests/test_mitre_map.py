"""tests/test_mitre_map.py — mitre-map.yaml authority/consistency guard.

The map's per-rule `allowed` list is only meaningful if two things stay
true:

  1. Every module rule that HAS a map entry only ever emits techniques
     within that entry's `allowed` set (checked statically via each rule's
     declared `Rule.mitre`, and — for the pcap rules with condition-specific
     technique sets — via the exposed per-condition module constants too).
  2. Every key under `mitre-map.yaml: rules:` is either a real rule_id
     (discoverable via `spectre.modules.registry.discover()`) or has been
     explicitly acknowledged as a legacy/aspirational entry in
     `_LEGACY_MAP_KEYS` below. This starts empty by design — a future
     stray key must be deliberately added here, not silently tolerated.
"""

import yaml

from spectre.config import MITRE_MAP_PATH
from spectre.modules import registry
from spectre.modules.pcap import rules as pcap_rules


# Map keys that do not (yet) correspond to an implemented rule_id — future
# artifact types (Amcache, MFT, SRUM, ShimCache, ...) and Hunt-Evil-poster
# techniques staged ahead of their module implementation. Each entry here is
# a deliberate acknowledgment, not an oversight — new keys added later must
# either match a real rule_id or be added here explicitly.
_LEGACY_MAP_KEYS = {
    "rundll32-from-appdata",
    "regsvr32-from-temp",
    "mshta-execution",
    "powershell-download-cradle",
    "wmic-process-call",
    "schtasks-suspicious",
    "service-creation",
    "encoded-command",
    "prefetch-anomaly",
    "prefetch-low-run-count",
    "registry-persistence",
    "registry-runonce",
    "registry-winlogon-helper",
    "registry-appinit-dlls",
    "mft-timestomp",
    "mft-hidden-file",
    "mft-ads",
    "lnk-suspicious-path",
    "lnk-persistence-startup",
    "srum-anomalous-process",
    "srum-network-exfil",
    "abnormal-parent-child",
    "process-injection",
    "dll-side-loading",
    "dll-search-order",
    "token-manipulation",
    "kerberoasting",
    "pass-the-hash",
    "lsass-dump",
    "dns-tunneling",
    "lateral-movement-smb",
    "data-staging",
    "port-scan",
    "injected-thread",
    "hollowed-process",
    "unpacked-memory",
}

# Per-condition MITRE constants exposed by pcap/rules.py, keyed by the
# rule_id whose map entry they must stay a subset of.
_PCAP_CONDITION_CONSTANTS = {
    "pcap-suspicious-port": [
        pcap_rules._MITRE_PORT_OUTBOUND,
        pcap_rules._MITRE_PORT_OTHER,
    ],
    "pcap-exposed-service": [
        pcap_rules._MITRE_EXPOSED_SERVICE,
    ],
    "pcap-beacon": [
        pcap_rules._MITRE_BEACON_BASE,
    ],
    "pcap-c2-protocol": [
        pcap_rules._MITRE_C2_PLAINTEXT,
        pcap_rules._MITRE_C2_USER_AGENT,
        pcap_rules._MITRE_C2_SERVER_HEADER,
        pcap_rules._MITRE_C2_POLL,
        pcap_rules._MITRE_C2_CHECKIN_HOST,
        pcap_rules._MITRE_C2_CAMPAIGN,
    ],
    "pcap-dns-anomaly": [
        pcap_rules._MITRE_DNS_TLD,
        pcap_rules._MITRE_DNS_DGA,
        pcap_rules._MITRE_DNS_WPAD,
    ],
    "smb-drsuapi-opnum": [
        pcap_rules._MITRE_DRSUAPI_DCSYNC,
        pcap_rules._MITRE_DRSUAPI_NAMERES,
    ],
}


def _load_map() -> dict:
    with open(MITRE_MAP_PATH) as f:
        return yaml.safe_load(f)


def test_every_map_key_matches_a_real_rule_id_or_is_explicitly_legacy():
    mitre_map = _load_map()
    real_rule_ids = {
        rule.rule_id
        for analyzer in registry.discover().values()
        for rule in analyzer.rules
    }

    unrecognized = []
    for key in mitre_map.get("rules", {}):
        if key in real_rule_ids or key in _LEGACY_MAP_KEYS:
            continue
        unrecognized.append(key)

    assert not unrecognized, (
        f"mitre-map.yaml key(s) match no real rule_id and are not in "
        f"_LEGACY_MAP_KEYS: {unrecognized}"
    )


def test_legacy_map_keys_allowlist_has_no_stale_entries():
    """Every _LEGACY_MAP_KEYS entry must still be an actual map key (and
    must NOT coincidentally match a real rule_id — that would mean it
    should have been removed from the allowlist and treated as real)."""
    mitre_map = _load_map()
    map_keys = set(mitre_map.get("rules", {}))
    real_rule_ids = {
        rule.rule_id
        for analyzer in registry.discover().values()
        for rule in analyzer.rules
    }

    missing = _LEGACY_MAP_KEYS - map_keys
    assert not missing, f"_LEGACY_MAP_KEYS entries no longer present in the map: {missing}"

    now_real = _LEGACY_MAP_KEYS & real_rule_ids
    assert not now_real, (
        f"_LEGACY_MAP_KEYS entries now match a real rule_id — remove from "
        f"the allowlist: {now_real}"
    )


def test_every_rule_that_emits_a_technique_has_a_map_entry():
    """The missing direction, and the one D7 needs (spec §5.7).

    The two tests above police map-key → rule_id: no stray keys. Nothing
    policed rule → map, so a NEW module's rules could emit MITRE technique IDs
    with no map entry at all, and the map's `allowed` list — the whole authority
    it exists to provide — simply would not apply to them. Combined with
    filesystem-driven discovery, that means dropping a module directory in could
    silently widen the set of techniques Spectre attributes, with nothing
    constraining it.

    Scoped to rules that actually declare techniques. A rule with `mitre=[]`
    (logfile-suspicious-token, memory-browsing-history-domain,
    pcap-host-identity, pcap-evidence-tampered) attributes nothing, so there is
    nothing for the map to constrain and an entry would be noise.
    """
    mitre_map = _load_map()
    mapped = set(mitre_map.get("rules", {}))
    unmapped = []
    for name, analyzer in sorted(registry.discover().items()):
        for rule in analyzer.rules:
            if rule.mitre and rule.rule_id not in mapped:
                unmapped.append(f"{name}/{rule.rule_id} emits {rule.mitre}")
    assert not unmapped, (
        "rule(s) emit MITRE techniques with no mitre-map.yaml entry, so the "
        "map's `allowed` list does not constrain them:\n  "
        + "\n  ".join(unmapped)
    )


def test_every_rule_with_a_map_entry_declares_mitre_within_allowed():
    mitre_map = _load_map()
    rules_map = mitre_map.get("rules", {})

    violations = []
    for analyzer in registry.discover().values():
        for rule in analyzer.rules:
            entry = rules_map.get(rule.rule_id)
            if entry is None:
                continue  # no map entry — not this test's concern
            allowed = set(entry.get("allowed", []))
            declared = set(rule.mitre)
            if not declared <= allowed:
                violations.append(
                    f"{rule.rule_id}: Rule.mitre {sorted(declared)} not subset "
                    f"of allowed {sorted(allowed)}"
                )

    assert not violations, "\n".join(violations)


def test_pcap_per_condition_mitre_stays_within_map_allowed():
    """The pcap rules with condition-specific technique sets (beacon,
    c2-protocol, dns-anomaly, suspicious-port) must keep every condition's
    list a subset of the map's allowed set for that rule_id — this is what
    the emit-time intersection gate depends on to never drop a legitimately
    emitted technique."""
    mitre_map = _load_map()
    rules_map = mitre_map.get("rules", {})

    violations = []
    for rule_id, condition_lists in _PCAP_CONDITION_CONSTANTS.items():
        allowed = set(rules_map[rule_id]["allowed"])
        for condition_list in condition_lists:
            if not set(condition_list) <= allowed:
                violations.append(
                    f"{rule_id}: condition list {condition_list} not subset "
                    f"of allowed {sorted(allowed)}"
                )

    assert not violations, "\n".join(violations)
