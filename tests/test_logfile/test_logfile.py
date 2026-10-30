"""Tests for the logfile module + core streaming helpers (issue 1).

Covers: constant-memory CSV/log streaming, NormEvent shape, the honest
large-file cap (truncation surfaced, not silently dropped), pass-through
extraction (no copy + audit row), recognizer claims, and the starter rule.
"""

from spectre.core import streaming
from spectre.core.base import NormEvent
from spectre.modules.logfile.normalize import normalize as lf_normalize
from spectre.modules.logfile.extract import extract as lf_extract_fn
from spectre.modules.logfile.recognizer import RECOGNIZERS
from spectre.modules.logfile.rules import suspicious_token


# ── core.streaming generators ──

def test_iter_csv_rows_yields_dicts(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("ts,user,action\n2026-01-01,alice,login\n2026-01-02,bob,logout\n")
    rows = list(streaming.iter_csv_rows(str(p)))
    assert [n for n, _ in rows] == [1, 2]
    assert rows[0][1]["user"] == "alice"


def test_iter_log_lines_skips_blanks(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("line one\n\n   \nline two\n")
    lines = list(streaming.iter_log_lines(str(p)))
    assert [l for _, l in lines] == ["line one", "line two"]


def test_count_remaining_drains():
    gen = iter(range(100))
    assert streaming.count_remaining(gen, max_count=10) == 10


# ── normalize ──

def _handle(path):
    return {"path": str(path), "evidence_path": str(path)}


def test_normalize_csv_picks_timestamp_column(tmp_path):
    p = tmp_path / "events.csv"
    p.write_text("timestamp,user,cmd\n2026-06-28T10:00:00,alice,whoami\n")
    events = lf_normalize(_handle(p))
    assert len(events) == 1
    assert events[0].timestamp == "2026-06-28T10:00:00"
    assert events[0].data["user"] == "alice"
    assert events[0].artifact_type == "logfile_record"


def test_normalize_syslog_parses_host_and_ts(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("Jun 28 16:18:20 web01 sshd[123]: Failed password for root\n")
    events = lf_normalize(_handle(p))
    assert events[0].host == "web01"
    assert events[0].timestamp == "Jun 28 16:18:20"
    assert "Failed password" in events[0].data["message"]


def test_normalize_syslog_flags_yearless_tzless_timestamp_caveat(tmp_path):
    """WS4 sub-task 7 (A6 Finding 7): a BSD-syslog timestamp carries no
    year and no timezone (conventionally local time on the *originating*
    host, which Spectre cannot determine). It also fails both
    report_synthesize._parse_finding_ts and clustering._parse_time, so it
    silently falls into the 'undated' bucket. The analyst must be told
    WHY — a caveat/note on the event, not silence."""
    p = tmp_path / "auth.log"
    p.write_text("Jun 28 16:18:20 web01 sshd[123]: Failed password for root\n")
    events = lf_normalize(_handle(p))
    assert events[0].data.get("ts_caveat"), (
        "syslog-shaped event must carry a timestamp ambiguity caveat"
    )
    caveat = events[0].data["ts_caveat"].lower()
    assert "year" in caveat
    assert "timezone" in caveat or "time zone" in caveat


def test_normalize_csv_timestamp_has_no_syslog_caveat(tmp_path):
    """A properly-dated CSV row (has a real year/date) must not carry the
    syslog ambiguity caveat — it's specific to the yearless/tz-less shape."""
    p = tmp_path / "events.csv"
    p.write_text("timestamp,user,cmd\n2026-06-28T10:00:00,alice,whoami\n")
    events = lf_normalize(_handle(p))
    assert "ts_caveat" not in events[0].data


def test_normalize_non_syslog_log_line_has_no_syslog_caveat(tmp_path):
    p = tmp_path / "plain.log"
    p.write_text("this is not syslog shaped at all\n")
    events = lf_normalize(_handle(p))
    assert "ts_caveat" not in events[0].data


def test_normalize_caps_and_surfaces_truncation(tmp_path, capsys):
    p = tmp_path / "big.log"
    p.write_text("".join(f"line {i}\n" for i in range(50)))
    events = lf_normalize(_handle(p), max_events=10)
    assert len(events) == 10  # capped
    err = capsys.readouterr().err
    assert "NOT analyzed" in err  # remainder surfaced, never silently dropped


def test_normalize_missing_file_returns_empty():
    assert lf_normalize({"path": "/no/such/file"}) == []


# ── extract (pass-through, no copy) ──

def test_extract_passthrough_points_at_evidence(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    ev = tmp_path / "evidence.csv"
    ev.write_text("a,b\n1,2\n")
    handles = lf_extract_fn(str(case), str(ev))
    assert len(handles) == 1
    h = handles[0]
    assert h["path"] == str(ev)  # in place, not copied into the case dir
    assert h["execution_id"]  # audit row written
    assert (case / "audit.jsonl").exists()


# ── recognizer ──

def test_recognizer_claims_csv(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n")
    score = RECOGNIZERS[0].match(p, "CSV text")
    assert score > 0.0


def test_recognizer_rejects_binary(tmp_path):
    p = tmp_path / "x.log"
    p.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert RECOGNIZERS[0].match(p, "data") == 0.0


# ── rule ──

def test_suspicious_token_fires_on_offensive_tool():
    e = NormEvent("logfile_record", "", "auth.log", "5",
                  data={"message": "user ran mimikatz.exe on host"})
    anchor = suspicious_token(e)
    assert anchor is not None
    assert anchor.rule_id == "logfile-suspicious-token"


def test_suspicious_token_silent_on_benign():
    e = NormEvent("logfile_record", "", "auth.log", "6",
                  data={"message": "user logged in normally"})
    assert suspicious_token(e) is None
