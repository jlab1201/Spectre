"""pcap/recognizer.py — claim packet captures (.pcap/.pcapng)."""

from __future__ import annotations

from pathlib import Path

from spectre.core.base import Recognizer

ARTIFACT = "pcap_conn"
# libpcap (0xa1b2c3d4 / 0xd4c3b2a1) and pcapng (0x0a0d0d0a) magic.
_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
           b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond pcap
           b"\x0a\x0d\x0d\x0a")  # pcapng


def _sniff(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) in _MAGICS
    except OSError:
        return False


RECOGNIZERS = [
    Recognizer(
        module_name="pcap",
        artifact_type=ARTIFACT,
        extensions={".pcap", ".pcapng", ".cap"},
        magic_patterns=["pcap capture file", "pcapng", "tcpdump capture"],
        sniff=_sniff,
        confidence=0.9,
    ),
]
