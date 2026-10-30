"""Deterministic guardrail context — single source of truth shared by the
per-finding explainer, the report synthesizer, and the Phase-5 substantive
adversarial review.

Lives in `core` (module-level imports are stdlib + yaml only; config,
emit_finding and fk_routing are imported lazily inside functions) so
`pipeline.audit` can import it without an
`audit -> report_synthesize -> audit` import cycle.

MITRE (W2-1, R2-01/R2-17): the deterministic layer owns technique
attribution. `allowed_mitre_for_finding()` is the ONE definition of what an
AI seam may say about a finding's MITRE: that finding's own rule's
mitre-map `allowed` list (via emit_finding's `_get_allowed_mitre` /
`_has_map_entry` — the same semantics emit used) INTERSECTED with what emit
actually kept on the finding. A model may narrow within that set; it may
never widen it. Case-level seams (report narrative, Phase-5 review) use the
union of that set over the case's own findings — never the whole map.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

UNMAPPED = "UNMAPPED"
_MITRE_SPLIT_RE = re.compile(r"[,;\s/|]+")


def finding_artifact_types(findings: list[dict]) -> list[str]:
    """Unique artifact types per finding, from corroboration.tools
    ("engine/artifact_type"); falls back to evidence_refs.artifact_type;
    defaults to ["evtx"]. (Moved verbatim from report_synthesize.)"""
    types = set()
    for finding in findings:
        for t in (finding.get("corroboration") or {}).get("tools") or []:
            art = str(t).rsplit("/", 1)[-1]
            if art:
                types.add(art)
        for ref in finding.get("evidence_refs", []):
            art = ref.get("artifact_type", "")
            if art:
                types.add(art)
    return sorted(types) if types else ["evtx"]


def load_fk_caveats(artifact_types: list[str], fk_dirs: list[Path]) -> dict[str, list[str]]:
    """Load does_NOT_prove caveats from FK YAML per artifact type.
    (Moved verbatim from report_synthesize.)"""
    caveats_map: dict[str, list[str]] = {}
    for art_type in artifact_types:
        art_lower = art_type.lower()
        for fk_dir in fk_dirs:
            matches = list(fk_dir.glob(f"*{art_lower}*.yaml"))
            if not matches:
                matches = list(fk_dir.glob(f"{art_lower}*.yaml"))
            for match in matches:
                try:
                    fk = yaml.safe_load(match.read_text())
                    caveats = fk.get("does_NOT_prove", [])
                    if caveats:
                        caveats_map.setdefault(art_type, []).extend(caveats)
                except Exception:
                    continue
    return caveats_map


def mitre_in_allowed(ids: list[str], allowed: list[str]) -> list[str]:
    """Return the MITRE IDs in `ids` that are NOT permitted (invented).
    Comparison is case-insensitive (`t1003.006` is T1003.006)."""
    allowed_up = {str(a).strip().upper() for a in allowed}
    return [m for m in ids
            if str(m).strip().upper() not in allowed_up
            and str(m).strip().upper() != UNMAPPED]


def parse_mitre_ids(value) -> list[str]:
    """Parse a finding/model `mitre_attack` value into canonical upper-case
    IDs, order-preserving and de-duplicated. emit_finding joins multiple
    kept techniques as "T1071.001, T1573.001" (R2-17), so this must accept a
    delimited list, not a single token. A list/tuple input is also accepted.
    """
    from spectre.core.grounding import canonicalize

    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        parts = [canonicalize(str(v)) for v in value]
    else:
        parts = _MITRE_SPLIT_RE.split(canonicalize(str(value)))
    out: list[str] = []
    for p in parts:
        tok = p.strip().upper()
        if tok and tok not in out:
            out.append(tok)
    return out


def load_mitre_map() -> dict:
    """The packaged mitre-map.yaml (config.MITRE_MAP_PATH). Never a
    caller-supplied path — see W2-2 / R2-02."""
    from spectre.config import MITRE_MAP_PATH

    if MITRE_MAP_PATH.exists():
        return yaml.safe_load(MITRE_MAP_PATH.read_text()) or {}
    return {}


def file_sha256(path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def _read_audit_rows(case_dir) -> list[dict]:
    if case_dir is None:
        return []
    ap = Path(case_dir) / "audit.jsonl"
    if not ap.exists():
        return []
    rows = []
    with open(ap) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# ── Finding registration + hash authority (review round 2, R2-13) ───────
# A finding EXISTS only if a deterministic emitter wrote its `finding_create`
# row. Its content-hash baseline may be advanced only by an allowlisted
# authority row chained AFTER that registration: emit itself, core emit's
# finding_status, or the explain pass that persisted a validated rewrite. Any
# other row carrying a finding hash (a host/agent `audit.append`) is not an
# authority — verify_full's finding_integrity treats it as a violation.
_REGISTRATION = ("deterministic-core", "finding_create", "S1-emit")
APPROVAL_AUTHORITY = ("examiner", "approval", "S7-approve")
# W4-5 (R2-18): a Phase-3 re-run retires each prior finding into
# findings/superseded/ — bytes unchanged, hash re-recorded, and the
# finding's bound location moved to superseded/<id>.yaml.
SUPERSEDE_AUTHORITY = ("deterministic-core", "finding_supersede", "S3-supersede")


# W4 review (MED-1/LOW): a supersede row is honoured ONLY inside a Phase-3
# re-run bracket — a `phase3_run_start` row with the same run_id BEFORE it,
# and a `phase3_run_complete` row AFTER it whose run_id is the same (or
# whose params.closes lists it: a crashed run's batch is closed by the next
# run that completes). An unbracketed row is a non-authority hash row; an
# opened-but-never-completed batch is an unfinished re-run. Same-user
# residual: a writer who forges all three rows is still believed.
RUN_START = ("deterministic-core", "phase3_run_start", "S3-run-start")
RUN_COMPLETE = ("deterministic-core", "phase3_run_complete", "S3-run-complete")


# ── Evidence-ref resolution (Phase 4 gate) ──────────────────────────────
# A finding's evidence_refs cite the extraction that produced its data: the
# entry_sha256 of the deterministic-core `tool_exec` row run_tool,
# passthrough_handle or the MemProcFS auditor wrote. No other row resolves a
# ref (a finding_create row is the finding's own registration, not evidence).
EVIDENCE_REF_SOURCE = ("deterministic-core", "tool_exec")
UNRESOLVED_MISSING = "<missing>"
UNRESOLVED_UNPARSEABLE = "<unparseable>"


def resolvable_execution_ids(rows: list[dict]) -> set[str]:
    """entry_sha256 of every row that an evidence_ref may cite."""
    return {
        r["entry_sha256"] for r in rows
        if isinstance(r, dict)
        and (r.get("actor"), r.get("action")) == EVIDENCE_REF_SOURCE
        and isinstance(r.get("entry_sha256"), str) and r["entry_sha256"]
    }


def unresolved_evidence_refs(finding: dict, resolvable: set[str]) -> list[str]:
    """The finding's evidence_ref execution_ids that are not in `resolvable`,
    in ref order. A ref with no string execution_id is `<missing>`; a ref (or
    evidence_refs value) of the wrong shape is `<unparseable>`. Pass an empty
    set when the audit trail can't be trusted: every ref is then unresolved."""
    refs = finding.get("evidence_refs")
    if not isinstance(refs, list):
        return [UNRESOLVED_UNPARSEABLE]
    out: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            out.append(UNRESOLVED_UNPARSEABLE)
            continue
        eid = ref.get("execution_id")
        if not isinstance(eid, str) or not eid:
            out.append(UNRESOLVED_MISSING)
        elif eid not in resolvable:
            out.append(eid)
    return out


def _key(row: dict) -> tuple:
    return (row.get("actor"), row.get("action"), row.get("phase_step"))


def is_finding_supersede(row: dict) -> bool:
    return _key(row) == SUPERSEDE_AUTHORITY


def _run_id(row: dict) -> str:
    return str((row.get("params") or {}).get("run_id") or "")


def supersede_brackets(rows: list[dict]) -> dict:
    """Classify every finding_supersede row by its Phase-3 bracket.

    Returns {"honored": {idx}, "open": {idx}, "unbracketed": {idx},
    "starts": {run_id: idx}, "completes": [(idx, run_id, closes)]}.
    """
    starts: dict[str, int] = {}
    completes: list[tuple[int, str, list]] = []
    closed_at: dict[str, int] = {}
    for i, r in enumerate(rows):
        k = _key(r)
        if k == RUN_START and _run_id(r):
            starts.setdefault(_run_id(r), i)
        elif k == RUN_COMPLETE and _run_id(r):
            rid = _run_id(r)
            closes = [str(c) for c in ((r.get("params") or {}).get("closes") or [])]
            completes.append((i, rid, closes))
            for c in [rid, *closes]:
                if c in starts and starts[c] < i:
                    closed_at.setdefault(c, i)
    out = {"honored": set(), "open": set(), "unbracketed": set(),
           "starts": starts, "completes": completes}
    for i, r in enumerate(rows):
        if not is_finding_supersede(r):
            continue
        rid = _run_id(r)
        if not rid or rid not in starts or starts[rid] > i:
            out["unbracketed"].add(i)
        elif closed_at.get(rid, -1) > i:
            out["honored"].add(i)
        else:
            out["open"].add(i)
    return out


def is_finding_registration(row: dict) -> bool:
    return (row.get("actor"), row.get("action"), row.get("phase_step")) == _REGISTRATION


def is_finding_hash_authority(row: dict) -> bool:
    key = (row.get("actor"), row.get("action"), row.get("phase_step"))
    if key == _REGISTRATION:
        return True
    if key == ("deterministic-core", "finding_status", "S2-status"):
        return True
    # W3-6 (R1-F3): the in-process Phase 7 approval writer
    # (spectre.pipeline.approval / `spectre approve`). Same same-user
    # residual as every other authority key — see the README Architecture section.
    if key == APPROVAL_AUTHORITY:
        return True
    # SUPERSEDE_AUTHORITY rows are NOT unconditional authorities: callers
    # honour them only via supersede_brackets() (W4 review LOW).
    if key == ("spectre-lead", "note", "S1-explain-norm") and \
            str(row.get("tool", "")).startswith("llm:"):
        return True
    return False


def _row_fid(row: dict) -> str | None:
    fid = row.get("finding_id") or (row.get("params") or {}).get("finding_id")
    return str(fid) if fid else None


def finding_location(path) -> str:
    """Where a finding file lives inside its case, independent of where the
    case dir itself sits: "F-x.yaml" (active) or "excluded/F-x.yaml"
    (analyst-excluded, emit_finding's parallel subdir). B8: a registration
    is bound to this location, so a copy of an excluded finding placed back
    in findings/ is not the registered finding."""
    p = Path(str(path))
    if p.parent.name in ("excluded", "superseded"):
        return f"{p.parent.name}/{p.name}"
    return p.name


def finding_path_matches(case_dir, path, location: str,
                         output_path: str = "") -> bool:
    """L2 (W2-A round 4): `path`, fully RESOLVED (symlinks followed), must
    be exactly <case_dir>/findings/<location>, or exactly the path the
    registration row recorded (`output_path`) — not merely share the file
    name. The expected paths resolve their directory only, never a final
    symlink, so a copy outside the case or a symlink out of it is not the
    registered finding. A legacy registration row with neither a location
    nor an output_path carries no location binding (declared residual)."""
    if not location and not output_path:
        return True
    try:
        rp = Path(str(path)).resolve()
        base = (Path(case_dir) / "findings").resolve()
        if output_path:
            op = Path(str(output_path))
            if rp == op.parent.resolve() / op.name:
                return True
    except (OSError, TypeError, ValueError):
        return False
    if location:
        return rp == base / location
    return False


def finding_registry(case_dir, include_open: bool = False) -> dict[str, dict]:
    """finding_id -> {"rule_id", "baseline", "foreign_hash_rows",
    "output_path", "location"} for every finding registered by a
    deterministic finding_create row. `baseline` is the latest authority-row
    hash at/after registration (None if none); `foreign_hash_rows` counts
    non-authority rows that carry a hash for it; `location` is
    finding_location() of the REGISTRATION row's output_path ("" for a
    legacy row without one) — only a later `finding_supersede` row that
    sits in a COMPLETED Phase-3 bracket moves it (to superseded/, W4-5)
    and sets "superseded". include_open=True also honours the rows of a
    not-yet-completed re-run (used by the re-run itself for recovery); an
    open row is otherwise neither honoured nor counted as foreign — the
    unfinished batch is reported by verify_full's supersede_batches."""
    rows = _read_audit_rows(case_dir)
    br = supersede_brackets(rows)
    trusted_sup = br["honored"] | (br["open"] if include_open else set())
    reg: dict[str, dict] = {}
    for i, row in enumerate(rows):
        fid = _row_fid(row)
        if not fid:
            continue
        if is_finding_registration(row):
            op = str(row.get("output_path") or "")
            loc = finding_location(op) if op else ""
            reg[fid] = {"rule_id": (row.get("params") or {}).get("rule_id"),
                        "baseline": row.get("output_sha256") or None,
                        "foreign_hash_rows": 0,
                        "output_path": op,
                        "location": loc,
                        "registered_location": loc,
                        "registered_at": i}
            continue
        if not row.get("output_sha256") or row.get("finding_id") != fid:
            continue
        if fid not in reg:
            continue  # hash rows before/without registration never count
        if is_finding_supersede(row):
            if i in trusted_sup and row.get("output_path"):
                op = str(row["output_path"])
                reg[fid]["baseline"] = row["output_sha256"]
                reg[fid]["output_path"] = op
                reg[fid]["location"] = finding_location(op)
                reg[fid]["superseded"] = True
            elif i not in br["open"]:
                reg[fid]["foreign_hash_rows"] += 1  # unbracketed = forged
            continue
        if is_finding_hash_authority(row):
            reg[fid]["baseline"] = row["output_sha256"]
        else:
            reg[fid]["foreign_hash_rows"] += 1
    return reg


def audit_rule_ids(case_dir) -> dict[str, str]:
    """finding_id -> rule_id from the deterministic `finding_create` rows."""
    return {fid: str(v["rule_id"]) for fid, v in finding_registry(case_dir).items()
            if v.get("rule_id")}


def rule_id_for_finding(finding: dict, case_dir=None) -> str | None:
    """The detection rule that produced `finding`. When `case_dir` is known
    the deterministic finding_create row is the ONLY source (a `rule_id`
    field in the YAML is attacker-writable). Without a case_dir (pure unit
    use) the finding's own `rule_id` field is used."""
    if case_dir is not None:
        fid = finding.get("finding_id")
        return audit_rule_ids(case_dir).get(str(fid)) if fid else None
    rid = finding.get("rule_id")
    return str(rid) if rid else None


def allowed_mitre_for_finding(finding: dict, mitre_map: dict, case_dir=None,
                              *, rule_id: str | None = None) -> list[str]:
    """Techniques an AI seam may attach to THIS finding.

    = (the finding's own rule's mitre-map `allowed` list)
      ∩ (what emit actually kept in the finding's `mitre_attack`)

    - No resolvable rule_id, or a rule with no map entry (Sigma slug,
      dir-NNN): [] — only UNMAPPED is valid, mirroring emit's quarantine.
    - Finding already UNMAPPED / empty: [].
    Returned in the map's canonical spelling, in the finding's order.
    """
    from spectre.pipeline.emit_finding import _get_allowed_mitre, _has_map_entry

    emitted = [t for t in parse_mitre_ids(finding.get("mitre_attack"))
               if t != UNMAPPED]
    if not emitted:
        return []
    if rule_id is None:
        rule_id = rule_id_for_finding(finding, case_dir)
    if not rule_id or not _has_map_entry(mitre_map, rule_id):
        return []
    canon = {str(a).strip().upper(): str(a).strip()
             for a in _get_allowed_mitre(mitre_map, rule_id)}
    return [canon[t] for t in emitted if t in canon]


def case_allowed_mitre(findings: list[dict], mitre_map: dict | None = None,
                       case_dir=None) -> list[str]:
    """Case-scoped set for case-level seams (report, Phase-5 review): the
    union of `allowed_mitre_for_finding` over the case's own findings."""
    if mitre_map is None:
        mitre_map = load_mitre_map()
    rids = audit_rule_ids(case_dir) if case_dir is not None else None
    out: set[str] = set()
    for f in findings:
        rid = (rids.get(str(f.get("finding_id"))) if rids is not None
               else f.get("rule_id"))
        out.update(allowed_mitre_for_finding(f, mitre_map, rule_id=rid or ""))
    return sorted(out)


def guardrail_context(findings: list[dict], case_dir=None) -> tuple[list[str], dict]:
    """Load the case-scoped MITRE allow-list and FK caveats map that gate
    report validation. Single source of truth for the direct-API and
    host-ingest paths. The MITRE set is the union of each finding's own
    per-rule allowed set — never the whole mitre-map (R2-01)."""
    from spectre.config import FK_DIRS

    allowed_mitre = case_allowed_mitre(findings, load_mitre_map(), case_dir)
    artifact_types = finding_artifact_types(findings)
    fk_caveats_map = load_fk_caveats(artifact_types, FK_DIRS)
    return allowed_mitre, fk_caveats_map


# ── FK resolution from config only (W2-2 / R2-02) ────────────────────────

_DEFAULT_FK = "evtx_4688.yaml"


def fk_path_for_finding(finding: dict) -> Path:
    """FK YAML for a finding, resolved ONLY within config.FK_DIRS via the
    module-derived routing table (pipeline.fk_routing) — the same routing
    phase_runner._fk_for_finding/_find_fk uses. Never a caller path."""
    from spectre.config import FK_DIRS
    from spectre.pipeline.fk_routing import artifact_fk_files

    routing = artifact_fk_files()
    name = _DEFAULT_FK
    for t in (finding.get("corroboration") or {}).get("tools") or []:
        art = str(t).rsplit("/", 1)[-1]
        if art in routing:
            name = routing[art]
            break
    for d in FK_DIRS:
        p = Path(d) / name
        if p.exists():
            return p
    return Path(FK_DIRS[0]) / name


# ── Disk-loaded, hash-verified findings (W2-2 / R2-03) ───────────────────

class FindingIntegrityError(RuntimeError):
    """A finding YAML on disk no longer matches its latest recorded
    content hash in audit.jsonl — refuse to validate against it."""


def load_verified_findings(case_dir) -> tuple[list[dict], list[str]]:
    """Load `case_dir/findings/F-*.yaml`, trusting only REGISTERED findings.

    A finding counts only if a deterministic `finding_create` row registered
    it (finding_registry). Its bytes must equal the latest hash-authority
    row at/after registration. Returns (findings, unregistered_ids):
    - no registration, or registered with no hash baseline → EXCLUDED and
      listed in unregistered_ids;
    - hash mismatch, or a non-authority row carrying a hash for it (an
      attempt to bless an edit) → FindingIntegrityError (fail closed);
    - a file whose location differs from its registration's (B8: an
      excluded finding copied back into findings/) → FindingIntegrityError;
    - an `analyst_excluded` finding is never trusted (excluded stays
      excluded) and is silently skipped.
    """
    case_dir = Path(case_dir)
    reg = finding_registry(case_dir)
    findings: list[dict] = []
    unregistered: list[str] = []
    fdir = case_dir / "findings"
    for fp in sorted(fdir.glob("F-*.yaml")) if fdir.exists() else []:
        fid = fp.stem
        info = reg.get(fid)
        if not info or not info.get("baseline"):
            unregistered.append(fid)
            continue
        if info["foreign_hash_rows"]:
            raise FindingIntegrityError(
                f"{fid}: {info['foreign_hash_rows']} non-authority audit row(s) "
                f"carry a content hash for this finding")
        if info.get("location") and info["location"] != finding_location(fp):
            raise FindingIntegrityError(
                f"{fid}: registered at findings/{info['location']} but found at "
                f"findings/{finding_location(fp)} — refusing a relocated finding")
        if not finding_path_matches(case_dir, fp, info.get("location") or "",
                                    info.get("output_path") or ""):
            raise FindingIntegrityError(
                f"{fid}: findings/{fp.name} resolves outside its registered "
                f"location — refusing a relocated finding")
        data = fp.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != info["baseline"]:
            raise FindingIntegrityError(
                f"{fid}: on-disk content {actual[:12]}… does not match the "
                f"recorded hash {info['baseline'][:12]}… — refusing to "
                f"validate against a tampered finding")
        f = yaml.safe_load(data) or {}
        if f.get("finding_id") != fid:
            raise FindingIntegrityError(
                f"{fid}: file name and finding_id disagree")
        if f.get("analyst_excluded"):
            continue
        findings.append(f)
    return findings, unregistered
