"""
normalize.py — source records → normalized events.

Pure transform. No detection. Writes nothing.

NormEvent shape:
  event_id, channel, timestamp, record_number, computer,
  new_process_name, new_process_basename (lower), new_process_id,
  parent_process_name, parent_basename (lower),
  command_line, command_line_lower, subject_user,
  source_artifact: "EVTX-Security-4688",
  source_file
"""

from dataclasses import dataclass


@dataclass
class NormEvent:
    event_id: int
    channel: str
    timestamp: str
    record_number: int
    computer: str
    new_process_name: str
    new_process_basename: str  # lowercased
    new_process_id: str
    parent_process_name: str
    parent_basename: str       # lowercased
    command_line: str
    command_line_lower: str
    subject_user: str
    source_artifact: str = "EVTX-Security-4688"
    source_file: str = ""


def _basename(path: str) -> str:
    """Extract and lowercase the basename from a Windows path.
    Uses both \\ and / as separators since pathlib only respects OS-native separators."""
    if not path:
        return ""
    # Normalize separators
    normalized = path.replace("\\", "/")
    return normalized.rsplit("/", 1)[-1].lower()


def normalize(records: list[dict], source_file: str = "") -> list[NormEvent]:
    """
    Convert raw source records (evtx_dump JSON shape) into NormEvent objects.
    """
    events = []
    for rec in records:
        ed = rec.get("EventData", {})
        new_proc = ed.get("NewProcessName", "")
        parent_proc = ed.get("ParentProcessName", "")
        cmdline = ed.get("CommandLine", "")

        events.append(NormEvent(
            event_id=rec.get("EventID", 0),
            channel=rec.get("Channel", ""),
            timestamp=rec.get("TimeCreated", ""),
            record_number=rec.get("RecordNumber", 0),
            computer=rec.get("Computer", ""),
            new_process_name=new_proc,
            new_process_basename=_basename(new_proc),
            new_process_id=ed.get("NewProcessId", ""),
            parent_process_name=parent_proc,
            parent_basename=_basename(parent_proc),
            command_line=cmdline,
            command_line_lower=cmdline.lower(),
            subject_user=ed.get("SubjectUserName", ""),
            source_artifact="EVTX-Security-4688",
            source_file=source_file,
        ))
    return events
