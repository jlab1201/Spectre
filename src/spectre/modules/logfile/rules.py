"""logfile/rules.py — starter detection pack for generic log records.

Minimal by design: generic logs are heterogeneous, so the starter rule is a
high-signal token match — an offensive-tool or LOLBin name appearing anywhere
in a record. Indicator lists are shared (knowledge/indicators), so tuning them
benefits every module. Grow with format-specific rules (failed-auth bursts,
sudo abuse, web-shell URIs) incrementally.
"""

from __future__ import annotations

from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata
from spectre.knowledge import load_indicator_list

ARTIFACT = "logfile_record"

# Reuse the shared offensive-tool + LOLBin name lists.
_BAD_TOKENS = frozenset(
    load_indicator_list("processes", "offensive_tools")
    + load_indicator_list("processes", "lolbins"))


def _record_text(e: NormEvent) -> str:
    """Flatten a record's values to a single lowercased blob for matching."""
    return " ".join(str(v) for v in e.data.values() if v is not None).lower()


def suspicious_token(e: NormEvent) -> Optional[Anchor]:
    blob = _record_text(e)
    # _BAD_TOKENS is a frozenset; plain iteration order is hash-seed
    # dependent (PYTHONHASHSEED). Two defects follow from a bare
    # `for token in _BAD_TOKENS: ... return` first-match scan: (1) which
    # token is reported (and therefore the title/dedup_key text) varies
    # run-to-run on identical evidence, and (2) when a record legitimately
    # contains more than one indicator (e.g. both an offensive-tool name
    # and a LOLBin name), first-match silently drops the others from the
    # finding entirely -- an analyst never sees them. The forensically
    # better fix is to report ALL matched tokens on one finding, not to
    # keep first-match-wins with a stable tie-break: dropping a real,
    # independently-detected indicator loses evidence the deterministic
    # core actually observed. Sorting the matches (not just the scan
    # order) makes the title and dedup_key byte-identical across runs
    # for the same set of matches, regardless of hash seed.
    matched = sorted(token for token in _BAD_TOKENS if token in blob)
    if not matched:
        return None
    token_list = ", ".join(f"'{t}'" for t in matched)
    dedup_tokens = "+".join(matched)
    return Anchor(
        rule_id="logfile-suspicious-token",
        artifact_type=ARTIFACT,
        event=e,
        title=f"Suspicious tool/LOLBin {token_list} referenced in log "
              f"record {e.record_id} of {e.source_file}",
        mitre=[],  # deterministic core never invents technique IDs
        confidence=0.4,
        iocs={"filepath": [], "ip": [], "domain": [],
              "sha256": [], "registry_key": []},
        summary=f"logfile {e.source_file}:{e.record_id} contains {token_list}",
        dedup_key=f"{dedup_tokens}:{e.source_file}",
    )


RULES = [
    Rule(
        rule_id="logfile-suspicious-token",
        artifact_type=ARTIFACT,
        predicate=suspicious_token,
        mitre=[],
        description="Offensive-tool or LOLBin name referenced in a log record.",
        # No MITRE technique is asserted (the predicate emits mitre=[]), so the
        # card stays free of any technique tag/reference too — honest by default.
        metadata=RuleMetadata(
            uuid="a96b37f6-d300-472d-9a76-26a131c9cb74",
            name="Offensive-tool or LOLBin name referenced in a log record",
            author="spectre-core", date="2026-06-28", version="1.0",
            severity="low", rule_format="python",
            rule_source="modules/logfile/rules.py",
            tags=["spectre.token_match"],
            false_positives=[
                "logs that legitimately mention a tool/LOLBin name in text"]),
    ),
]
