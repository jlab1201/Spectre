"""disk/carve.py — carve well-known forensic artifacts out of a disk image.

Reads the fls body file already produced by extract(), matches nested
artifact paths (EVTX, registry hives, prefetch, LNK, $MFT), and icat's
each hit into <case>/evidence/derived/<image_stem>/. The pipeline
(phase_runner) registers each carved file as DERIVED EVIDENCE — hashed,
chmod 444, audit-chained — and re-triages it through the module registry.

Deliberately name-pattern-targeted, not exhaustive: carving every file
from an image would explode the case; _CARVE_CAP bounds the worst case
and a cap hit is reported so the analyst knows coverage was truncated.
"""

from __future__ import annotations

import re
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool
from spectre.config import ICAT_PATH

_CARVE_CAP = 200

_TARGET_PATTERNS = [
    re.compile(r"windows/system32/winevt/logs/[^/|]+\.evtx$", re.I),
    re.compile(r"windows/system32/config/(sam|system|software|security)$", re.I),
    re.compile(r"users/[^/]+/ntuser\.dat$", re.I),
    re.compile(r"windows/prefetch/[^/]+\.pf$", re.I),
    re.compile(r"users/[^/]+/.*\.lnk$", re.I),
    re.compile(r"^/?\$mft$", re.I),
]


_INODE_RE = re.compile(r"^\d+(-\d+-\d+)?$")


def _match_targets(body_lines: list[str]) -> list[dict]:
    hits: list[dict] = []
    for line in body_lines:
        # The 9 trailing fields are fixed; the name may itself contain "|".
        parts = line.rsplit("|", 9)
        if len(parts) != 10 or "|" not in parts[0]:
            continue
        name = parts[0].split("|", 1)[1]
        parts = [parts[0].split("|", 1)[0], name, *parts[1:]]
        if not _INODE_RE.match(parts[2]):
            continue
        norm = name.replace("\\", "/").lstrip("/").lower()
        if not any(p.search(norm) or p.search("/" + norm) for p in _TARGET_PATTERNS):
            continue
        hits.append({
            "in_image_path": name,
            "inode": parts[2].split("-")[0],
            "size": int(parts[6]) if parts[6].isdigit() else 0,
        })
        if len(hits) >= _CARVE_CAP:
            break
    return hits


def _sanitize(name: str) -> str:
    flat = name.replace("\\", "/").lstrip("/").replace("/", "_")
    return re.sub(r"[^A-Za-z0-9._$-]", "_", flat)[:200]


def carve_targets(case_dir: str, evidence_path: str, body_path: str) -> list[dict]:
    body = Path(body_path)
    if not body.exists():
        return []
    hits = _match_targets(body.read_text(errors="replace").splitlines())
    stem = Path(evidence_path).stem
    out_dir = Path(case_dir) / "evidence" / "derived" / stem
    records: list[dict] = []
    for hit in hits:
        out_path = out_dir / f"{hit['inode']}_{_sanitize(hit['in_image_path'])}"
        try:
            out_path.resolve().relative_to(out_dir.resolve())
        except ValueError:
            continue
        handle = run_tool(
            case_dir=case_dir, tool_name="icat", tool_version="sleuthkit",
            command=[ICAT_PATH, str(evidence_path), hit["inode"]],
            params={"artifact_type": "derived_carve",
                    "evidence_path": str(evidence_path),
                    "in_image_path": hit["in_image_path"],
                    "phase": "extraction"},
            output_path=str(out_path), timeout=600, output_format="binary",
        )
        carve_result = handle.get("result", "error")
        if carve_result != "success":
            _clean_failed_carve_output(out_path)
        records.append({
            "path": str(out_path),
            "in_image_path": hit["in_image_path"],
            "inode": hit["inode"],
            "size": hit["size"],
            "parent_evidence": str(evidence_path),
            "carve_result": carve_result,
            "stderr": handle.get("stderr", ""),
        })
    return records


def _clean_failed_carve_output(out_path: Path) -> None:
    """run_tool may still have written an output file for a failed carve.

    An empty stub has no forensic value and would otherwise sit writable
    and unregistered in evidence/derived/ — unlink it. A non-empty partial
    output may hold forensic value, so keep it but lock it read-only like
    any other registered evidence.
    """
    try:
        st = out_path.stat()
    except FileNotFoundError:
        return
    if st.st_size == 0:
        out_path.unlink()
    else:
        out_path.chmod(0o444)
