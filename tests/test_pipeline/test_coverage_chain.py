"""Coverage gaps are chained facts, and the report must disclose all of them.

Spec: the module-selection design spec §3.7, §5.5.
Testing items 10 and 11.

The defect: a **vacuous PASS**. `canary_status` and `gate_0.passed` were
written by `log_command`, which touches execution.log only and never
audit.jsonl (shell_log.py:164) — mutable manifest fields with no hash behind
them. And verify_full()'s twelve checks inspected no triage or coverage data at
all. So a report could be regenerated with its coverage disclosures quietly
dropped and still PASS every integrity check.

The binding is structural, never textual: Phase 6's S3-merge-report row carries
`params["disclosed_coverage_gaps"]`, report_integrity already ties that row's
hash to the bytes on disk, and check 9 asserts the receipt covers every chained
`coverage_gap` row. A prose grep would couple audit.py to report wording, where
the first reword either breaks verification or silently disarms it.
"""

import json
from pathlib import Path

from spectre.pipeline import audit, coverage
from spectre.pipeline.report_synthesize import _intake_blindspot_lines


def _case(tmp_path) -> str:
    d = tmp_path / "001-COV"
    (d / "findings").mkdir(parents=True)
    (d / "reports").mkdir(parents=True)
    return str(d)


def _row(**kw):
    base = {
        "actor": "deterministic-core", "action": "note", "tool": "t",
        "tool_version": "1", "exact_command": "x", "case_id": "001",
        "output_path": "", "output_sha256": "", "output_format": "json",
        "output_line_count": 0, "output_size_bytes": 0, "result": "success",
        "exit_code": 0, "duration_ms": 0, "stderr": "", "finding_id": None,
    }
    base.update(kw)
    return base


# ── the gap model ────────────────────────────────────────────────────────

def test_triage_statuses_become_gaps():
    manifest = {"triage": {
        "/e/a.bin": {"status": "UNRECOGNIZED", "artifact_type": None},
        "/e/b.evtx": {"status": "EXTRACTOR_PENDING",
                      "artifact_type": "process_creation",
                      "tool": "evtxexport"},
        "/e/gone.pf": {"status": "MISSING", "artifact_type": "prefetch"},
        "/e/ok.pcap": {"status": "RECOGNIZED", "artifact_type": "pcap_conn"},
    }}
    gaps = {g["key"]: g for g in coverage.gaps_from_manifest(manifest)}
    assert len(gaps) == 3, gaps
    assert "UNRECOGNIZED|unknown|primary" in gaps
    assert "EXTRACTOR_PENDING|process_creation|primary" in gaps
    assert "MISSING|prefetch|primary" in gaps
    assert gaps["EXTRACTOR_PENDING|process_creation|primary"]["tool"] == "evtxexport"


def test_extraction_errors_are_gaps_too():
    """_coverage_counts already treats an errored extraction as not examined.
    The gap model has to agree, or the count and the named list diverge."""
    manifest = {"extraction": {"results": {
        "/e/x.pcap": {"error": "tcpdump exited 2"},
        "/e/y.pcap": {"events": 12},
    }}}
    gaps = coverage.gaps_from_manifest(manifest)
    assert len(gaps) == 1
    assert gaps[0]["status"] == "EXTRACTION_ERROR"


def test_carved_files_aggregate_into_one_gap_per_category():
    """Item 11: 200 carved files produce aggregated rows, not 200.

    Each audit.append() also does a best-effort journald write, so 200 rows
    would be 200 external writes for one fact.
    """
    results = {
        f"/case/derived/evt{i}.evtx": {
            "skipped": "EXTRACTOR_PENDING",
            "artifact_type": "process_creation",
            "derived_from": "/case/evidence/disk.dd",
            "tool": "evtxexport",
        } for i in range(200)
    }
    gaps = coverage.gaps_from_manifest({"extraction": {"results": results}})
    assert len(gaps) == 1, [g["key"] for g in gaps]
    assert gaps[0]["count"] == 200
    assert gaps[0]["parent"] == "disk.dd"
    # ...and the row must not carry 200 filenames either.
    assert len(gaps[0]["items"]) <= 25


def test_two_parents_do_not_collapse_together():
    results = {
        "/d/a.evtx": {"skipped": "EXTRACTOR_PENDING", "derived_from": "/e/one.dd",
                      "artifact_type": "process_creation"},
        "/d/b.evtx": {"skipped": "EXTRACTOR_PENDING", "derived_from": "/e/two.dd",
                      "artifact_type": "process_creation"},
    }
    gaps = coverage.gaps_from_manifest({"extraction": {"results": results}})
    assert len(gaps) == 2, [g["key"] for g in gaps]


def test_gap_key_excludes_count():
    """Phase 2 can legitimately carve more artifacts after Phase 0 charged a
    gap. A count-bearing key would make honest growth look like a missing
    disclosure."""
    a = coverage.gap_key("UNRECOGNIZED", "unknown", "primary")
    b = coverage.gap_key("UNRECOGNIZED", "unknown", "primary")
    assert a == b
    assert "1" not in a and "×" not in a


# ── the rows ─────────────────────────────────────────────────────────────

def test_gap_rows_land_in_the_chain(tmp_path):
    case = _case(tmp_path)
    manifest = {"triage": {"/e/a.bin": {"status": "UNRECOGNIZED"}}}
    coverage.append_gap_rows(case, "001", phase=0, phase_step="S8-coverage",
                             manifest=manifest)
    entries = [json.loads(ln) for ln in
               (Path(case) / "audit.jsonl").read_text().splitlines() if ln.strip()]
    gap_rows = [e for e in entries if e["action"] == "coverage_gap"]
    assert len(gap_rows) == 1
    assert gap_rows[0]["params"]["key"] == "UNRECOGNIZED|unknown|primary"
    ok, reason = audit.verify_chain(case)
    assert ok, reason


def test_chained_gaps_takes_the_largest_count():
    """Phase 0 and Phase 2 both charge, and a resumed phase charges again. The
    report must cover the worst of what the chain says."""
    entries = [
        {"action": "coverage_gap", "params": {"key": "K", "count": 3}},
        {"action": "coverage_gap", "params": {"key": "K", "count": 12}},
        {"action": "coverage_gap", "params": {"key": "K", "count": 5}},
        {"action": "note", "params": {"key": "K", "count": 900}},
    ]
    assert coverage.chained_gaps(entries) == {"K": 12}


# ── verify_full check 9 ──────────────────────────────────────────────────

def _seed(case, gaps, receipt, *, with_s3=True):
    for key, count in gaps.items():
        audit.append(case, _row(action="coverage_gap", phase=0,
                                phase_step="S8-coverage",
                                params={"key": key, "count": count}))
    if with_s3:
        report = Path(case) / "reports" / "report.md"
        report.write_text("# report\n")
        import hashlib
        audit.append(case, _row(
            action="note", phase=6, phase_step="S3-merge-report",
            output_path=str(report),
            output_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
            params={} if receipt is None
                   else {"disclosed_coverage_gaps": receipt}))


def test_full_disclosure_passes(tmp_path):
    case = _case(tmp_path)
    _seed(case, {"A|x|primary": 2}, [{"key": "A|x|primary", "count": 2}])
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert check["passed"], check["detail"]


def test_a_dropped_disclosure_fails_closed(tmp_path):
    """Item 10, the vacuous-PASS regression. A fresh S3 row cannot launder it:
    the receipt itself is what check 9 reads."""
    case = _case(tmp_path)
    _seed(case, {"A|x|primary": 2, "B|y|disk.dd": 7}, [
        {"key": "A|x|primary", "count": 2},
    ])
    result = audit.verify_full(case)
    check = result["checks"]["coverage_disclosure"]
    assert not check["passed"], check["detail"]
    assert "B|y|disk.dd" in check["detail"]
    assert result["ok"] is False, "a dropped disclosure must flip overall ok"


def test_a_shrunken_count_fails_closed(tmp_path):
    """Disclosing "1 of 200 not examined" when the chain charged 200 is a lie
    the category key alone would not catch."""
    case = _case(tmp_path)
    _seed(case, {"A|x|disk.dd": 200}, [{"key": "A|x|disk.dd", "count": 1}])
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert not check["passed"], check["detail"]
    assert "×200" in check["detail"] and "×1" in check["detail"]


def test_a_grown_count_still_passes(tmp_path):
    """Phase 2 carving more than Phase 0 saw is honest growth, not a shortfall."""
    case = _case(tmp_path)
    _seed(case, {"A|x|disk.dd": 5}, [{"key": "A|x|disk.dd", "count": 40}])
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert check["passed"], check["detail"]


def test_a_missing_receipt_fails_closed(tmp_path):
    """A report writer that recorded no receipt is indistinguishable from one
    that dropped the disclosures, so it must fail the same way. The host-driven
    Phase 6 in skills/report-generator/SKILL.md must write the field."""
    case = _case(tmp_path)
    _seed(case, {"A|x|primary": 1}, None)
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert not check["passed"], check["detail"]
    assert "receipt" in check["detail"]


def test_no_gaps_abstains(tmp_path):
    case = _case(tmp_path)
    audit.append(case, _row(action="note"))
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert check["passed"]
    assert "no coverage_gap rows" in check["detail"]


def test_gaps_before_phase_6_abstains(tmp_path):
    """A case that has not reached Phase 6 has no report to have disclosed
    anything. Failing here would make every mid-case verify red."""
    case = _case(tmp_path)
    _seed(case, {"A|x|primary": 1}, None, with_s3=False)
    check = audit.verify_full(case)["checks"]["coverage_disclosure"]
    assert check["passed"], check["detail"]
    assert "has not reached Phase 6" in check["detail"]


# ── the receipt cannot claim an undisclosed gap ──────────────────────────

def test_every_gap_category_is_named_in_blind_spots():
    """The load-bearing tie between the chain and the reader.

    disclosed_from_manifest() and _intake_blindspot_lines() derive from the same
    manifest, so the receipt is only honest if the prose actually names every
    category the model produces. Before this stage, MISSING evidence and failed
    extractions were in the model (and in _coverage_counts) but rendered
    nowhere — the receipt would have claimed disclosures the reader could not
    find.
    """
    manifest = {
        "triage": {
            "/e/a.bin": {"status": "UNRECOGNIZED"},
            "/e/b.evtx": {"status": "EXTRACTOR_PENDING",
                          "artifact_type": "process_creation",
                          "tool": "evtxexport"},
            "/e/gone.pf": {"status": "MISSING", "artifact_type": "prefetch"},
        },
        "extraction": {"results": {
            "/d/c.evtx": {"skipped": "EXTRACTOR_PENDING",
                          "artifact_type": "process_creation",
                          "derived_from": "/e/disk.dd", "tool": "evtxexport"},
            "/e/d.pcap": {"error": "tcpdump exited 2"},
        }},
    }
    gaps = coverage.gaps_from_manifest(manifest)
    assert len(gaps) == 5, [g["key"] for g in gaps]
    rendered = "\n".join(_intake_blindspot_lines(manifest))
    for gap in gaps:
        for name in gap["items"]:
            assert name in rendered, (
                f"gap {gap['key']} charges {name}, which the Forensic Blind "
                f"Spots section never names:\n{rendered}"
            )


def test_receipt_is_compact():
    """It sits inside an audit row; it is a receipt, not a second manifest."""
    manifest = {"extraction": {"results": {
        f"/d/e{i}.evtx": {"skipped": "EXTRACTOR_PENDING",
                          "artifact_type": "process_creation",
                          "derived_from": "/e/disk.dd"} for i in range(500)
    }}}
    receipt = coverage.disclosed_from_manifest(manifest)
    assert receipt == [{"key": "EXTRACTOR_PENDING|process_creation|disk.dd",
                        "count": 500}]
