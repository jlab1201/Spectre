"""_template.py — copy me to author a new drop-in detection rule.

HOW TO USE
  1. Copy this file to `modules/<module>/rules/<your_rule>.py`
     (the `_`-prefix is why THIS file is ignored by discovery — your copy
     must NOT start with an underscore).
  2. Write a pure `predicate(event) -> Optional[Anchor]` (no I/O).
  3. Fill in the RuleMetadata defensibility card (severity, references,
     known false positives, tags).
  4. Add a should-fire and a should-not-fire test under `tests/`.
  5. Open a PR. `collect_rules()` finds your file automatically — there is no
     central list to edit.

THE ONE INVIOLABLE RULE
  The deterministic core produces findings as FACTS. A rule may only assert a
  MITRE technique it can actually justify; if unsure, leave `mitre=[]`. The AI
  layer never adds findings/MITRE/caveats your predicate did not produce.
"""

from __future__ import annotations

from typing import Optional

from spectre.core.base import Anchor, NormEvent, Rule, RuleMetadata

# The normalized artifact_type this rule consumes. It MUST match the schema
# your module's normalize() produces (e.g. "process_creation", "memory_pslist").
ARTIFACT = "process_creation"


def example_predicate(e: NormEvent) -> Optional[Anchor]:
    """Return an Anchor when the event matches, else None.

    Read only fields from `e.data` (the normalized record). Keep it pure so it
    is trivially unit-testable against a single synthetic NormEvent.
    """
    d = e.data
    if d.get("image_basename") == "example.exe":
        return Anchor(
            rule_id="example-rule",
            artifact_type=ARTIFACT,
            event=e,
            title="Example rule fired on example.exe",
            mitre=["T1059"],        # only what you can defend; else []
            confidence=0.5,
            iocs={"filepath": [d.get("image", "")], "ip": [], "domain": [],
                  "sha256": [], "registry_key": []},
            summary=f"example: {d.get('image_basename')} (rec {e.record_id})",
        )
    return None


RULES: list[Rule] = [
    Rule(
        rule_id="example-rule",
        artifact_type=ARTIFACT,
        predicate=example_predicate,
        mitre=["T1059"],
        description="example: a placeholder rule showing the drop-in shape",
        metadata=RuleMetadata(
            uuid="00000000-0000-0000-0000-000000000000",   # generate your own
            name="Example drop-in rule",
            author="your-handle",
            date="2026-01-01",
            version="1.0",
            severity="medium",   # critical | high | medium | low | informational
            rule_format="python",
            rule_source="modules/evtx/rules/<your_rule>.py",
            references=["https://attack.mitre.org/techniques/T1059/"],
            tags=["attack.execution", "attack.t1059"],
            false_positives=["describe the benign cases that also match"],
        ),
    ),
]
