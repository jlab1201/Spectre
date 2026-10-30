"""MITRE ATT&CK label/tactic resolution and the "2. MITRE ATT&CK Map" section."""

from __future__ import annotations

import yaml

from spectre.pipeline.report_sections.common import _finding_rule_ids


def _load_mitre_technique_labels() -> dict[str, str]:
    """Load the canonical tid -> ATT&CK technique-name map (mitre_techniques.yaml).

    This is the ONLY source of truth for per-technique report labels. A
    mitre-map.yaml rule's "label" field describes the whole RULE (often a
    slash-joined composite spanning multiple techniques, e.g. rule
    pcap-exploit-probe's "Vulnerability Scanning / Exploit Public-Facing
    Application / Brute Force / Credentials In Files"). Assigning that
    composite to every tid in the rule's allowed list — as the old code did —
    means a single technique like T1552.001 renders with the whole blob, and
    since tids are shared across rules, last-writer-wins garbles labels
    further. Callers needing a rule-level description should read
    mitre-map.yaml directly; callers needing a technique-level label must use
    this map. Missing tids are left for the caller to fall back to the tid
    string itself (never a rule's composite label).
    """
    from spectre.config import MITRE_TECHNIQUES_PATH

    if not MITRE_TECHNIQUES_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(MITRE_TECHNIQUES_PATH.read_text()) or {}
    except yaml.YAMLError:
        return {}
    techniques = data.get("techniques", {})
    return techniques if isinstance(techniques, dict) else {}


def _load_mitre_tactics() -> dict[str, str]:
    """Load the canonical tid -> ATT&CK tactic map (mitre_techniques.yaml
    'tactics:' block). Mirrors _load_mitre_technique_labels: same file, same
    safe-load-with-fallback shape. A tid absent here is the caller's cue to
    render tactic '—' (never a guessed tactic). This map groups techniques that
    already appear in findings under their standard tactic; it adds no technique
    and no mapping a rule did not already select.
    """
    from spectre.config import MITRE_TECHNIQUES_PATH

    if not MITRE_TECHNIQUES_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(MITRE_TECHNIQUES_PATH.read_text()) or {}
    except yaml.YAMLError:
        return {}
    tactics = data.get("tactics", {})
    return tactics if isinstance(tactics, dict) else {}


def _resolve_mitre_labels(mt_string: str, mitre_labels: dict) -> str:
    """Resolve a (possibly composite) MITRE TID string to a label string.
    Composite TIDs that share one label render it once (order-preserving)."""
    if not mt_string or mt_string == "UNMAPPED":
        return mt_string
    parts = [p.strip() for p in mt_string.split(",")]
    seen: list[str] = []
    for p in parts:
        label = mitre_labels.get(p, p)
        if label not in seen:
            seen.append(label)
    return ", ".join(seen)


# C2: §2 MITRE map table hygiene. Cap the Finding-IDs cell so a 35-id cell
# becomes scannable; the full list stays discoverable via the Appendix index.
_MITRE_CELL_ID_CAP = 8


# ATT&CK kill-chain tactic order — §2 rows are grouped by tactic in this order
# (gold's signature), tie-broken by tid. A tactic not in this list sorts last.
_TACTIC_ORDER = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
)


def _tactic_rank(tactic: str) -> int:
    try:
        return _TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(_TACTIC_ORDER)


def _resolve_tactic(mt_string: str, tactics_map: dict[str, str]) -> str:
    """Resolve a (possibly composite) MITRE TID string to its tactic(s). Each
    tid is looked up; tactics are de-duplicated in encounter order. A tid with
    no tactic entry contributes nothing; if NONE of the tids map, returns '—'
    (never crashes, never invents a tactic)."""
    if not mt_string or mt_string == "UNMAPPED":
        return "—"
    seen: list[str] = []
    for tid in (p.strip() for p in mt_string.split(",")):
        t = tactics_map.get(tid)
        if t and t not in seen:
            seen.append(t)
    return ", ".join(seen) if seen else "—"


def _cap_finding_ids(fids: list[str], cap: int) -> str:
    """Render finding IDs for a table cell, capping at `cap` ids + '(+M more)'."""
    if len(fids) <= cap:
        return ", ".join(fids)
    return f"{', '.join(fids[:cap])} (+{len(fids) - cap} more)"


def _section_mitre_map(
    findings: list[dict],
    manifest: dict,
    mitre_map: dict,
    mitre_labels: dict,
) -> list[str]:
    """2. MITRE ATT&CK Map."""
    lines = []

    # ponytail: composite "T1071.001, T1095" strings need per-TID resolution
    def _resolve_mitre(mt_string: str) -> str:
        return _resolve_mitre_labels(mt_string, mitre_labels)

    # ── 2. MITRE ATT&CK Map ──
    # Reference section: maps techniques to findings by ID; Detailed Findings
    # (section 1) owns each finding's narrative and evidence.
    lines.append("## 2. MITRE ATT&CK Map\n")
    lines.append(
        "_Techniques are mapped to findings by ID; the full narrative and "
        "evidence for each finding are in **Detailed Findings** above._\n"
    )
    lines.append("| Technique ID | Technique Name | Tactic | Finding IDs | Detection Rule |")
    lines.append("|-------------|----------------|--------|-------------|----------------|")

    mitre_to_findings: dict[str, list[str]] = {}
    for finding in findings:
        mt = finding.get("mitre_attack", "UNMAPPED")
        fid = finding.get("finding_id", "?")
        mitre_to_findings.setdefault(mt, []).append(fid)

    tactics_map = _load_mitre_tactics()

    # Fallback technique->rule guess, used ONLY when a finding's own rule_id
    # cannot be recovered (see _finding_rule_ids) — e.g. a hand-built test
    # fixture with no manifest['detection']['findings'] provenance. Never
    # used for real case findings: two rules can share one MITRE technique
    # (pcap-suspicious-port AND pcap-c2-protocol both allow T1071.001;
    # pcap-staging-download AND pcap-large-transfer both allow T1105) and
    # this dict can only name one of them per technique.
    technique_to_rule: dict[str, str] = {}
    for rule_name, rule_data in mitre_map.get("rules", {}).items():
        for tid in rule_data.get("allowed", []):
            technique_to_rule.setdefault(tid, rule_name)

    rule_ids_by_finding = _finding_rule_ids(findings, manifest)

    mitre_rows: list[tuple[int, str, str, str, list[str], str]] = []
    for mt, fids in mitre_to_findings.items():
        resolved = _resolve_mitre(mt)
        tactic = _resolve_tactic(mt, tactics_map)
        # Rule attribution: each finding's OWN originating rule_id, never a
        # technique-level guess. Findings in one technique group can come
        # from different rules — list every distinct rule that actually
        # fired, not the first rule mitre-map.yaml happens to declare.
        own_rules = sorted({
            rule_ids_by_finding[fid] for fid in fids if fid in rule_ids_by_finding
        })
        if own_rules:
            rule = ", ".join(own_rules)
        else:
            rule = technique_to_rule.get(mt, "")
            # composite key → resolve first TID's rule
            if not rule and "," in mt:
                rule = technique_to_rule.get(mt.split(",")[0].strip(), "unknown")
            elif not rule:
                rule = "unknown"
        name = resolved if (resolved and resolved != mt) else "(technique label not in map)"
        primary = tactic.split(",")[0].strip()
        mitre_rows.append((_tactic_rank(primary), mt, name, tactic, fids, rule))

    # Group by kill-chain tactic order, tie-broken by tid.
    mitre_rows.sort(key=lambda r: (r[0], r[1]))
    for _, mt, name, tactic, fids, rule in mitre_rows:
        fids_str = _cap_finding_ids(fids, _MITRE_CELL_ID_CAP)
        lines.append(f"| {mt} | {name} | {tactic} | {fids_str} | {rule} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    return lines
