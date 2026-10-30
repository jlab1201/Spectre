"""Test helper (not a test module): register fixture evidence the way
case_setup does, so Phase 2's registered-only extraction (W3 review MED)
accepts it."""
import hashlib
from pathlib import Path

from spectre.pipeline.audit import append as audit_append
from spectre.pipeline.custody import case_relative, resolve_case_path


def chain_triage(case_dir, manifest: dict) -> None:
    """Chain an evidence_register row for every manifest['triage'] key,
    creating a placeholder file where the fixture never wrote one."""
    for key in (manifest.get("triage") or {}):
        p = resolve_case_path(str(case_dir), key)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"fixture evidence\n")
        p.chmod(0o444)
        audit_append(str(case_dir), {
            "actor": "case_setup", "action": "evidence_register",
            "tool": "case_setup.py", "case_id": Path(case_dir).name,
            "params": {"copy_path": case_relative(case_dir, p)},
            "output_path": case_relative(case_dir, p),
            "output_sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "result": "success", "phase": 0, "phase_step": "S2-register",
        })
