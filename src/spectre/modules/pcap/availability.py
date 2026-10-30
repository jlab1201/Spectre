"""pcap/availability.py — engine-aware host-capability probe.

Moved here from recognize.py, where it lived as `if analyzer.name == "pcap"`.
The module owns the question of whether it can run; recognize.py and the
canary both just ask.

The trap this exists to avoid: `required_tools=["tcpdump"]` is deliberately
minimal (it keeps the canary DEGRADED rather than DEAD) and is the WRONG
signal for availability, because extraction is Zeek-primary. A blind
shutil.which("tcpdump") reports pcap unavailable on a Zeek-only host, which
extracts pcaps completely.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from spectre import config
from spectre.core.base import ModuleAvailability


def zeek_resolvable() -> bool:
    """True when config's Zeek resolution names a real, executable file.

    Calls config._resolve_zeek() fresh rather than reading the cached
    config.ZEEK_PATH constant, so SPECTRE_ZEEK_PATH and PATH changes are seen
    at call time. That is not a stylistic preference — it is a scar: the
    import-time cache was wrong at triage time. Handles all of
    _resolve_zeek()'s outcomes uniformly, including an env override (which
    _resolve_zeek() itself trusts unchecked) and the unresolved bare-name
    fallback "zeek", which is never itself an existing file.
    """
    zeek_path = config._resolve_zeek()
    return os.path.isfile(zeek_path) and os.access(zeek_path, os.X_OK)


def availability(path: Path | None = None) -> ModuleAvailability:
    """Decide from the configured engine, not from the tool list.

      - "manual": the tcpdump/tshark passes are the only extraction path, so
        tcpdump is genuinely required.
      - "auto"/"zeek" (and any other value, matching extract.py's leniency):
        Zeek alone suffices, tcpdump is an accepted fallback. Report a problem
        only when NEITHER is present, and name whichever tool the active
        engine actually wanted.

    `path` is accepted and unused: pcap capability does not vary per file.
    """
    engine = config.PCAP_ENGINE
    tcpdump_ok = shutil.which("tcpdump") is not None
    zeek_ok = zeek_resolvable()
    tshark_ok = shutil.which("tshark") is not None

    if engine == "manual":
        if not tcpdump_ok:
            return ModuleAvailability(
                available=False, missing="tcpdump",
                detail="PCAP_ENGINE=manual and tcpdump is absent — the "
                       "manual engine has no other extraction path")
    elif not (zeek_ok or tcpdump_ok):
        return ModuleAvailability(
            available=False, missing="zeek",
            detail=f"PCAP_ENGINE={engine} and neither zeek nor tcpdump "
                   f"resolves — no extraction path available")

    # Available. Name what is missing anyway: a reader deserves to know the
    # capture was processed by fewer passes than a full host would run.
    lost = [t for t, ok in (("zeek", zeek_ok), ("tcpdump", tcpdump_ok),
                            ("tshark", tshark_ok)) if not ok]
    if lost:
        return ModuleAvailability(
            available=True, degraded=True,
            detail=f"extracting without {', '.join(lost)} — "
                   f"fewer passes than a fully-tooled host")
    return ModuleAvailability(available=True)
