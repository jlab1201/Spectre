"""
detect.py — deterministic detection rules.

One rule in the spike: rundll32-from-temp.
Must flag record 5093 only. Must skip 5040 (System32 DLL, no Temp),
5001, 5002 (benign baseline).
"""

from dataclasses import dataclass, field
from spectre.core.normalize import NormEvent

RULE_ID = "rundll32-from-temp"
TEMP_MARKERS = ["\\temp\\", "\\appdata\\local\\temp\\"]


@dataclass
class Anchor:
    rule_id: str
    record_number: int
    event: NormEvent
    dll_path: str
    candidate_mitre: list[str] = field(default_factory=lambda: ["T1218.011"])


def _extract_dll_path(command_line: str) -> str:
    r"""Extract the DLL path from a rundll32 command line.
    Typical: rundll32.exe C:\Windows\Temp\evil.dll,Start
    Returns the .dll path or empty string."""
    import re
    # Match a path-like token containing .dll
    match = re.search(r'([A-Za-z]:\\[^,\s]*\.dll)', command_line, re.IGNORECASE)
    if match:
        return match.group(1)
    # Fallback: any token ending in .dll
    tokens = command_line.split()
    for tok in tokens:
        if tok.lower().endswith('.dll'):
            return tok.strip('"').strip("'")
    return ""


def detect(events: list[NormEvent]) -> list[Anchor]:
    """Run the rundll32-from-temp rule over normalized events."""
    anchors = []
    for e in events:
        if e.event_id != 4688:
            continue
        if e.new_process_basename != "rundll32.exe":
            continue
        cl = e.command_line_lower
        if (".dll" in cl) and any(m in cl for m in TEMP_MARKERS):
            dll_path = _extract_dll_path(e.command_line)
            anchors.append(Anchor(
                rule_id=RULE_ID,
                record_number=e.record_number,
                event=e,
                dll_path=dll_path,
                candidate_mitre=["T1218.011"],
            ))
    return anchors
