"""test_memory_rules.py — unit tests for the generic memory-forensics rules.

These encode the SANS 6-step "what makes a process/region suspicious" heuristics
(anomalous parent/child, system-process masquerade, injected code, registry
persistence) as pure predicates over synthetic NormEvents — no real memory image
needed. Each rule is a pure function (NormEvent -> Optional[Anchor]), so we build
events by hand and assert fire / no-fire.

Guard against the known fixture-replay pitfall: every test constructs FRESH
synthetic events, never a shared replayed fixture.
"""

import json
import sys
import tempfile

from spectre.core.base import NormEvent
from spectre.modules.memory.normalize import normalize
from spectre.modules.memory.rules import (
    anomalous_parent,
    masquerade_system_process,
    injected_code,
    registry_persistence,
    hidden_process,
    interesting_url,
    browsing_history_domain,
    established_connection,
    acquisition_artifact,
)


def _pslist(image, parent_image="", instance_count=1, pid=1000, ppid=900):
    return NormEvent(
        artifact_type="memory_pslist", timestamp="", source_file="mem.raw",
        record_id="0",
        data={
            "pid": pid, "ppid": ppid,
            "image_basename": image.lower(), "image": image,
            "parent_image": parent_image.lower(),
            "instance_count": instance_count,
        },
    )


# ── anomalous parent/child ───────────────────────────────────────────
def test_anomalous_parent_fires_browser_spawns_shell():
    # GrrCon signal: iexplore.exe -> cmd.exe
    a = anomalous_parent(_pslist("cmd.exe", parent_image="iexplore.exe"))
    assert a is not None
    assert a.rule_id == "memory-anomalous-parent"


def test_anomalous_parent_fires_webserver_spawns_shell():
    a = anomalous_parent(_pslist("cmd.exe", parent_image="w3wp.exe"))
    assert a is not None


def test_anomalous_parent_no_fire_normal_parent():
    # explorer.exe -> cmd.exe is normal user activity.
    assert anomalous_parent(_pslist("cmd.exe", parent_image="explorer.exe")) is None


# ── system-process masquerade ────────────────────────────────────────
def test_masquerade_wrong_parent_lsass():
    # lsass.exe must be a child of wininit.exe.
    a = masquerade_system_process(_pslist("lsass.exe", parent_image="cmd.exe"))
    assert a is not None
    assert a.rule_id == "memory-masquerade-system-process"


def test_masquerade_no_fire_legit_lsass():
    assert masquerade_system_process(
        _pslist("lsass.exe", parent_image="wininit.exe")) is None


def test_masquerade_extra_singleton_instance():
    # Two lsass.exe is a classic credential-theft masquerade.
    a = masquerade_system_process(
        _pslist("lsass.exe", parent_image="wininit.exe", instance_count=2))
    assert a is not None


def test_masquerade_lookalike_misspelling():
    # scvhost.exe (transposed) and svch0st.exe (zero) are look-alikes.
    assert masquerade_system_process(_pslist("scvhost.exe")) is not None
    assert masquerade_system_process(_pslist("svch0st.exe")) is not None


def test_masquerade_no_fire_unrelated_process():
    assert masquerade_system_process(
        _pslist("chrome.exe", parent_image="explorer.exe")) is None


# ── injected code (malfind) ──────────────────────────────────────────
def _malfind(protection="PAGE_EXECUTE_READWRITE", has_pe=True, pid=1337,
             process="notepad.exe"):
    return NormEvent(
        artifact_type="memory_malfind", timestamp="", source_file="mem.raw",
        record_id="0",
        data={"pid": pid, "process": process, "address": "0x5000000",
              "protection": protection, "has_pe_header": has_pe},
    )


def test_injected_code_fires_on_injected_pe():
    a = injected_code(_malfind(has_pe=True))
    assert a is not None
    assert a.rule_id == "memory-injected-code"


def test_injected_code_fires_on_shellcode():
    a = injected_code(_malfind(has_pe=False))
    assert a is not None


def test_injected_code_no_fire_without_exec_protection():
    assert injected_code(_malfind(protection="PAGE_READONLY", has_pe=False)) is None


def test_injected_code_no_fire_on_benign_jit_process():
    # ponytail FP guard: JIT/browser processes are skipped by design
    assert injected_code(_malfind(process="chrome.exe")) is None


def test_injected_code_fires_on_explorer():
    # explorer.exe is an injection TARGET, not a JIT process — the
    # allowlist was narrowed to remove it (Track C), closing
    # memory_malfind_explorer_allowlisted. It must keep firing (KNOWN-FN
    # guard: do not silently re-allowlist it), but Track D calibrates the
    # confidence down for injection-target processes with no corroborating
    # signal, so a bare malfind hit on a benign image (case 004) renders as
    # an INFERRED lead rather than a CONFIRMED injection.
    a = injected_code(_malfind(process="explorer.exe"))
    assert a is not None
    assert a.confidence <= 0.4


def test_injected_code_fires_on_wmiprvse():
    # wmiprvse.exe is also an injection TARGET, not a JIT process — removed
    # from the allowlist alongside explorer.exe. Same calibration applies.
    a = injected_code(_malfind(process="wmiprvse.exe"))
    assert a is not None
    assert a.confidence <= 0.4


def test_injected_code_confidence_unchanged_for_non_target_process():
    # A malfind hit on a process that is neither a known-JIT process nor a
    # known injection target keeps the normal (uncalibrated) confidence.
    pe = injected_code(_malfind(process="svc0x.exe", has_pe=True))
    assert pe is not None
    assert pe.confidence == 0.7
    shellcode = injected_code(_malfind(process="svc0x.exe", has_pe=False))
    assert shellcode is not None
    assert shellcode.confidence == 0.55


# ── registry persistence ─────────────────────────────────────────────
def _regkey(value_data, key=r"Software\Microsoft\Windows\CurrentVersion\Run",
            value_name="Updater"):
    return NormEvent(
        artifact_type="memory_regkey", timestamp="", source_file="mem.raw",
        record_id="0",
        data={"key": key, "value_name": value_name, "value_data": value_data},
    )


def test_registry_persistence_fires_on_exe_value():
    a = registry_persistence(_regkey(r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert a is not None
    assert a.rule_id == "memory-registry-persistence"


def test_registry_persistence_no_fire_on_empty_value():
    assert registry_persistence(_regkey("")) is None


# ── paste/file-share URL recovery (case 004 gold gap: dup + corrupted FPs) ──
def _url_event(url, host="pastebin.com"):
    return NormEvent(
        artifact_type="memory_url", timestamp="", source_file="mem.raw",
        record_id="0",
        data={"host": host, "url": url},
    )


def _emit_finding(anchor, tmp_path):
    """Emit a real finding via emit_from_handle against the REAL mitre-map,
    so tests prove what mitre_attack / iocs actually land in the report layer
    (the IOC CSV generator reads finding['iocs'] with no MITRE/confidence
    floor)."""
    from spectre.pipeline.emit_finding import emit_from_handle
    from spectre.config import MITRE_MAP_PATH

    fk = tmp_path / "fk.yaml"
    fk.write_text("does_NOT_prove: []\n")
    (tmp_path / "findings").mkdir(exist_ok=True)
    handle = {"execution_id": "vol-url-1", "tool": "carve_urls",
              "line_count": 1, "path": "/x/url.json"}
    return emit_from_handle(
        handle=handle, case_dir=str(tmp_path), finding_number=1,
        fk_yaml_path=str(fk), mitre_map_path=str(MITRE_MAP_PATH),
        rule_id=anchor.rule_id, title=anchor.title,
        iocs=anchor.iocs, mitre=anchor.mitre or None,
        confidence=anchor.confidence,
    )


def test_interesting_url_fires_on_valid_url_with_path():
    # A single legitimate, distinct carve with a real path must still fire —
    # this is a real pastebin URL on a real case, not an allowlist bypass.
    a = interesting_url(_url_event("https://pastebin.com/RSGSi1hk"))
    assert a is not None
    assert a.rule_id == "memory-interesting-url"
    assert "pastebin.com/RSGSi1hk" in a.title


def test_interesting_url_does_not_claim_exfiltration(tmp_path):
    # G2 gold gap: a paste/share URL carved from RAM, with NO outbound network
    # corroboration, must NOT be mapped to T1567.002 (Exfiltration to Cloud
    # Storage). It is a neutral observation — a paste service referenced in
    # memory — not an exfiltration TTP. The rule is a pure single-event
    # predicate with no access to netscan; an exfil mapping would need
    # outbound evidence this image does not have.
    a = interesting_url(_url_event("https://pastebin.com/RSGSi1hk"))
    assert a is not None
    assert a.mitre == []            # no attack technique asserted
    assert "T1567" not in " ".join(a.mitre)

    # And end-to-end through emit_from_handle against the REAL mitre-map:
    # mitre_attack must not be the exfil technique (the allowed[0] fallback
    # can't re-introduce it either).
    mitre_attack = _emit_finding(a, tmp_path)["mitre_attack"]
    assert "T1567.002" not in mitre_attack
    assert mitre_attack == "UNMAPPED"


def test_interesting_url_no_fire_on_bare_host():
    # Carved with no resource path — low forensic value, not worth a
    # standalone finding (case 004 F-272-008: "https://pastebin.com").
    assert interesting_url(_url_event("https://pastebin.com/")) is None
    assert interesting_url(_url_event("https://pastebin.com")) is None


def test_interesting_url_repairs_double_scheme_corruption():
    # A carved string ran two URLs together with no separator (case 004
    # F-272-009: ".../RSGSi1hkhttps://pastebin.com/RSGSi1hk..."). The rule
    # must repair (truncate at the second scheme) rather than emit the
    # corrupted string verbatim.
    corrupted = (
        "https://pastebin.com/RSGSi1hkhttps://pastebin.com/RSGSi1hk"
        "https://pastebin.com/R"
    )
    a = interesting_url(_url_event(corrupted))
    assert a is not None
    assert "https" not in a.title.split("pastebin.com/RSGSi1hk", 1)[1][:5]
    assert a.title == "Paste/file-share URL recovered from memory: https://pastebin.com/RSGSi1hk"


def test_interesting_url_repaired_corruption_dedups_with_clean_carving():
    # After repair, the corrupted carving must collapse into the SAME
    # dedup_key as a clean carving of the same underlying URL, so Phase 3's
    # one-finding-per-(rule_id, dedup_key) emits a single finding instead of
    # F-272-007 + F-272-009 as near-duplicates.
    clean = interesting_url(_url_event("https://pastebin.com/RSGSi1hk"))
    corrupted = interesting_url(_url_event(
        "https://pastebin.com/RSGSi1hkhttps://pastebin.com/RSGSi1hkhttps://pastebin.com/R"))
    assert clean is not None and corrupted is not None
    assert clean.dedup_key == corrupted.dedup_key


def test_interesting_url_distinct_resources_stay_separate():
    # Two genuinely different paste URLs must NOT collapse into one finding.
    a = interesting_url(_url_event("https://pastebin.com/RSGSi1hk"))
    b = interesting_url(_url_event("https://pastebin.com/AbCdEfGh"))
    assert a is not None and b is not None
    assert a.dedup_key != b.dedup_key


def test_interesting_url_no_fire_on_uninteresting_host():
    assert interesting_url(_url_event("https://example.com/foo", host="example.com")) is None


def test_interesting_url_guards_trailing_scheme_corruption():
    # G6/G2: F-272-009 corruption — a carved paste string with a trailing bare
    # scheme remnant (no "://"): ".../RSGSi1hkhttps". The rule must strip the
    # remnant and canonicalize to the clean URL rather than promote the
    # corrupted string to its own finding + IOC.
    a = interesting_url(_url_event(
        "https://pastebin.com/RSGSi1hkhttps", host="pastebin.com"))
    assert a is not None
    assert a.title == (
        "Paste/file-share URL recovered from memory: https://pastebin.com/RSGSi1hk")
    # dedups with the clean carve -> Phase 3 emits one finding, not two.
    clean = interesting_url(_url_event("https://pastebin.com/RSGSi1hk"))
    assert clean is not None
    assert a.dedup_key == clean.dedup_key


# ── browsing-history domain surfacing (case 004 gold gap G1) ─────────────
def _browse_event(url):
    # normalize() sets data['host'] from the RAW carve, so a corrupted carve
    # can carry a junk host; the rule must re-derive from the repaired URL.
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""
    return NormEvent(
        artifact_type="memory_url", timestamp="", source_file="mem.raw",
        record_id="0", data={"host": host, "url": url})


def test_browsing_domain_fires_on_firefox_frecency_artifact():
    # Firefox awesomebar/places autocomplete memory artifact: the host echoed
    # as the leading path segment marks a host the user actually navigated to.
    for url, host in [
        ("http://bi0s.in/bi0s.in0,1Amrita", "bi0s.in"),
        ("http://inctf.in/inctf.in0,1", "inctf.in"),
        ("http://amfoss.in/amfoss.in0,1India's", "amfoss.in"),
        ("http://volatilevirus.home.blog/volatilevirus.home.blog0,1",
         "volatilevirus.home.blog"),
    ]:
        a = browsing_history_domain(_browse_event(url))
        assert a is not None, url
        assert a.rule_id == "memory-browsing-history-domain"
        assert a.iocs["domain"] == [host]
        assert a.dedup_key == host


def test_browsing_domain_is_a_neutral_fact_not_an_attack(tmp_path):
    # THE INVIOLABLE RULE for this track: the deterministic layer surfaces the
    # domain as a FACT (observed browsing artifact). It asserts NO attack
    # technique and never concludes "benign"/"CTF" — that stays LLM narrative.
    a = browsing_history_domain(_browse_event("http://inctf.in/inctf.in0,1"))
    assert a is not None
    assert a.mitre == []
    # neutral title — no editorialized conclusion (benign/malicious/exfil/attack)
    assert a.title == "Browsing-history domain recovered from memory: inctf.in"
    low = a.title.lower()
    assert not any(w in low for w in ("benign", "malicious", "exfil", "attack"))
    # End-to-end: neutral (UNMAPPED, not in the attack chain) but the domain
    # DOES reach the finding's iocs -> the IOC CSV export.
    finding = _emit_finding(a, tmp_path)
    assert finding["mitre_attack"] == "UNMAPPED"
    assert "inctf.in" in finding["iocs"]["domain"]


def test_browsing_domain_no_fire_on_cdn_or_asset_noise():
    # Passively-referenced assets / certificate URLs never self-reference, so
    # the 300+ CDN/tracker/CA domains in a raw carve stay out of the report.
    assert browsing_history_domain(_browse_event(
        "https://www.gstatic.com/images/icons/material/system/2x/star.png")) is None
    assert browsing_history_domain(_browse_event(
        "http://crl.pki.goog/GTSGIAG3.crl0")) is None
    assert browsing_history_domain(_browse_event(
        "https://pastebin.com/RSGSi1hk")) is None  # path is a paste id, not the host


def test_browsing_domain_guards_malformed_host():
    # single-label junk and scheme-glued run-on hosts are not valid domains.
    assert browsing_history_domain(_browse_event("https://www")) is None
    assert browsing_history_domain(_browse_event("https://cloud-assets-z")) is None
    # scheme-glued: after repair the host resolves to a valid domain, and the
    # frecency echo still matches -> it may fire, but NEVER with a junk host.
    a = browsing_history_domain(_browse_event(
        "http://twitter.comhttps://twitter.com/twitter.com0,1"))
    if a is not None:
        assert a.iocs["domain"] == ["twitter.com"]


# ── established outbound connections (case 004 gold gap G3) ──────────────
def _netscan_event(foreign_addr, owner="firefox.exe", state="ESTABLISHED",
                   proto="TCPv4", local_addr="10.0.2.15", local_port=49232,
                   foreign_port=443):
    return NormEvent(
        artifact_type="memory_netscan", timestamp="", source_file="mem.raw",
        record_id="0",
        data={"proto": proto, "local_addr": local_addr, "local_port": local_port,
              "foreign_addr": foreign_addr, "foreign_port": foreign_port,
              "state": state, "owner": owner})


def test_established_connection_fires_on_external_outbound():
    # G3: netscan HAS established outbound browser connections — the "zero
    # outbound / directionality undetermined" verdict was factually wrong.
    a = established_connection(_netscan_event("172.217.160.131", foreign_port=80))
    assert a is not None
    assert a.rule_id == "memory-established-connection"
    assert a.iocs["ip"] == ["172.217.160.131"]
    assert "firefox.exe" in a.title


def test_established_connection_no_fire_on_loopback():
    # Loopback IPC (127.0.0.1 <-> 127.0.0.1) is not an outbound connection.
    assert established_connection(_netscan_event("127.0.0.1")) is None


def test_established_connection_no_fire_on_wildcard_or_unspecified():
    for fa in ("*", "0.0.0.0", "::", ""):
        assert established_connection(_netscan_event(fa)) is None


def test_established_connection_no_fire_on_non_established():
    for st in ("LISTENING", "CLOSED", "FIN_WAIT2", ""):
        assert established_connection(
            _netscan_event("172.217.160.131", state=st)) is None


def test_established_connection_aggregates_per_owner():
    # Key decision: dedup on the owning process so a browser's many established
    # connections collapse into ONE finding (occurrence_count conveys volume),
    # rather than inflating a benign 9-finding case with 21 CDN findings (G6).
    a = established_connection(_netscan_event("172.217.160.131"))
    b = established_connection(_netscan_event("216.58.197.67"))
    assert a is not None and b is not None
    assert a.dedup_key == b.dedup_key == "firefox.exe"


def test_established_connection_strips_padded_owner():
    # volatility pads the owner field on some rows with "*** ffff… \Device\…";
    # the rule must take the process basename only, so padded and clean rows of
    # the same process still share a dedup_key.
    padded = ("firefox.exe                              ***  fffffa800143a010  "
              "\\Device\\HarddiskVolume2\\...\\firefox.exe")
    a = established_connection(_netscan_event("172.217.160.131", owner=padded))
    assert a is not None
    assert a.dedup_key == "firefox.exe"


def test_established_connection_is_a_neutral_fact_not_an_attack(tmp_path):
    # Neutral observation: NO attack technique, no "benign browsing" conclusion
    # baked in — that interpretation is the report layer's job. The connection
    # (owner + foreign IP) still reaches the IOC export.
    a = established_connection(_netscan_event("172.217.160.131"))
    assert a is not None
    assert a.mitre == []
    low = a.title.lower()
    assert not any(w in low for w in ("benign", "malicious", "c2", "attack"))
    finding = _emit_finding(a, tmp_path)
    assert finding["mitre_attack"] == "UNMAPPED"
    assert "172.217.160.131" in finding["iocs"]["ip"]


# ── memory-acquisition artifacts (case 004 gold gap G4) ─────────────────
def _filescan_event(path):
    from os.path import basename
    return NormEvent(
        artifact_type="memory_filescan", timestamp="", source_file="mem.raw",
        record_id="0",
        data={"path": path, "basename": basename(path.replace("\\", "/")).lower()})


def test_acquisition_artifact_fires_on_dumpit_tool():
    # G4: DumpIt.exe on the Desktop is the strongest "acquisition capture, not
    # malware" indicator.
    a = acquisition_artifact(_filescan_event(r"\Users\Jaffa\Desktop\DumpIt.exe"))
    assert a is not None
    assert a.rule_id == "memory-acquisition-artifact"
    assert a.iocs["filepath"] == [r"\Users\Jaffa\Desktop\DumpIt.exe"]


def test_acquisition_artifact_fires_on_raw_dump_output():
    # The .raw dump output names the host + acquisition time (VIRUS-PC / 2019…).
    a = acquisition_artifact(
        _filescan_event(r"\Users\Jaffa\Desktop\VIRUS-PC-20190819-144155.raw"))
    assert a is not None
    assert "VIRUS-PC-20190819-144155.raw" in a.iocs["filepath"][0]


def test_acquisition_artifact_no_fire_on_ordinary_file():
    for p in (r"\Users\Jaffa\Desktop\flag.rar", r"\Windows\System32\ntdll.dll",
              r"\Users\Jaffa\Documents\notes.txt"):
        assert acquisition_artifact(_filescan_event(p)) is None


def test_acquisition_artifact_dedups_per_basename():
    # DumpIt.exe appears at multiple filescan offsets — collapse to one finding.
    a = acquisition_artifact(_filescan_event(r"\Users\Jaffa\Desktop\DumpIt.exe"))
    b = acquisition_artifact(_filescan_event(r"\Users\Jaffa\Desktop\DumpIt.exe"))
    assert a is not None and b is not None
    assert a.dedup_key == b.dedup_key


def test_acquisition_artifact_is_a_neutral_fact_not_an_attack(tmp_path):
    a = acquisition_artifact(_filescan_event(r"\Users\Jaffa\Desktop\DumpIt.exe"))
    assert a is not None
    assert a.mitre == []
    finding = _emit_finding(a, tmp_path)
    assert finding["mitre_attack"] == "UNMAPPED"
    assert r"\Users\Jaffa\Desktop\DumpIt.exe" in finding["iocs"]["filepath"]


# ── normalize enrichment ─────────────────────────────────────────────
def _write_handle(rows, artifact):
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False)
    json.dump(rows, tmp)
    tmp.close()
    return {"path": tmp.name, "artifact_type": artifact, "evidence_path": "mem.raw"}


def test_normalize_pslist_embeds_parent_and_count():
    rows = [
        {"PID": 900, "PPID": 4, "ImageFileName": "wininit.exe"},
        {"PID": 1000, "PPID": 900, "ImageFileName": "lsass.exe"},
        {"PID": 1001, "PPID": 900, "ImageFileName": "lsass.exe"},
    ]
    events = normalize(_write_handle(rows, "memory_pslist"))
    lsass = [e for e in events if e.data["image_basename"] == "lsass.exe"]
    assert len(lsass) == 2
    # parent of lsass (ppid 900) is wininit.exe
    assert lsass[0].data["parent_image"] == "wininit.exe"
    # two lsass instances counted
    assert lsass[0].data["instance_count"] == 2


def test_normalize_malfind_detects_pe_header():
    rows = [{"PID": 1337, "Process": "explorer.exe", "Start VPN": "0x5000000",
             "Protection": "PAGE_EXECUTE_READWRITE",
             "Hexdump": "0x5000000  4d 5a 90 00 03 00 00 00  MZ......"}]
    events = normalize(_write_handle(rows, "memory_malfind"))
    assert len(events) == 1
    assert events[0].data["has_pe_header"] is True
    assert "EXECUTE" in events[0].data["protection"]


def test_normalize_regkey_maps_value():
    rows = [{"Key": r"Software\Microsoft\Windows\CurrentVersion\Run",
             "Name": "Updater", "Data": r"C:\Temp\evil.exe", "Type": "REG_SZ"}]
    events = normalize(_write_handle(rows, "memory_regkey"))
    assert events[0].data["value_data"] == r"C:\Temp\evil.exe"
    assert events[0].data["value_name"] == "Updater"


# ── psscan (Track C: shares pslist row shape via _process_row) ────────
def test_normalize_psscan_shares_pslist_shape():
    rows = [
        {"PID": 1000, "PPID": 900, "ImageFileName": "lsass.exe",
         "CreateTime": "2026-07-01 12:00:00"},
    ]
    events = normalize(_write_handle(rows, "memory_psscan"))
    assert len(events) == 1
    e = events[0]
    assert e.data["pid"] == 1000
    assert e.data["ppid"] == 900
    assert e.data["image_basename"] == "lsass.exe"
    assert e.data["image"] == "lsass.exe"
    # Timestamps are canonicalized to ISO-8601 UTC at the normalize seam so
    # that vol ("...T14:40:07+00:00") and MemProcFS ("... 14:40:07 UTC")
    # describe one moment identically -- otherwise a corroborated group's
    # first_seen/last_seen depends on which engine's anchor is representative.
    assert e.data["create_time"] == "2026-07-01T12:00:00+00:00"
    # psscan event timestamp mirrors the row's CreateTime, like pslist.
    assert e.timestamp == "2026-07-01T12:00:00+00:00"


def test_normalize_psscan_captures_exit_time():
    rows = [
        {"PID": 1000, "PPID": 900, "ImageFileName": "lsass.exe",
         "CreateTime": "2026-07-01 12:00:00",
         "ExitTime": "2026-07-01 12:05:00"},
    ]
    events = normalize(_write_handle(rows, "memory_psscan"))
    assert events[0].data["exit_time"] == "2026-07-01T12:05:00+00:00"


def test_normalize_psscan_normalizes_na_exit_time_variants():
    # vol version differences render "still running" as N/A, -, or None.
    for placeholder in ("N/A", "-", "None"):
        rows = [{"PID": 1000, "PPID": 900, "ImageFileName": "lsass.exe",
                 "ExitTime": placeholder}]
        events = normalize(_write_handle(rows, "memory_psscan"))
        assert events[0].data["exit_time"] == "", placeholder


def test_normalize_psscan_parent_and_instance_enrichment():
    # psscan should get the same parent-image/instance-count enrichment as
    # pslist (via the shared _process_row helper), so masquerade/parent
    # rules can run against either artifact type unmodified.
    rows = [
        {"PID": 900, "PPID": 4, "ImageFileName": "wininit.exe", "CreateTime": ""},
        {"PID": 1000, "PPID": 900, "ImageFileName": "lsass.exe", "CreateTime": ""},
        {"PID": 1001, "PPID": 900, "ImageFileName": "lsass.exe", "CreateTime": ""},
    ]
    events = normalize(_write_handle(rows, "memory_psscan"))
    lsass = [e for e in events if e.data["image_basename"] == "lsass.exe"]
    assert len(lsass) == 2
    assert lsass[0].data["parent_image"] == "wininit.exe"
    assert lsass[0].data["instance_count"] == 2


# ── svcscan ─────────────────────────────────────────────────────────
def test_normalize_svcscan_maps_fields_and_lowercases_binary():
    rows = [{"Name": "WinDefend", "Display": "Windows Defender",
             "Binary": r"C:\Windows\System32\MsMpEng.EXE",
             "State": "SERVICE_RUNNING", "Start": "SERVICE_AUTO_START",
             "Pid": 2468}]
    events = normalize(_write_handle(rows, "memory_svcscan"))
    assert len(events) == 1
    d = events[0].data
    assert d["service"] == "WinDefend"
    assert d["display"] == "Windows Defender"
    assert d["binary"] == r"C:\Windows\System32\MsMpEng.EXE"
    assert d["binary_lower"] == r"c:\windows\system32\msmpeng.exe"
    assert d["state"] == "SERVICE_RUNNING"
    assert d["start"] == "SERVICE_AUTO_START"
    assert d["pid"] == 2468


# ── dlllist ─────────────────────────────────────────────────────────
def test_normalize_dlllist_maps_fields():
    rows = [{"Pid": 1337, "Process": "notepad.exe",
             "Path": r"C:\Windows\System32\ntdll.dll", "Base": "0x7ffabc0000"}]
    events = normalize(_write_handle(rows, "memory_dlllist"))
    assert len(events) == 1
    d = events[0].data
    assert d["pid"] == 1337
    assert d["process"] == "notepad.exe"
    assert d["dll_path"] == r"C:\Windows\System32\ntdll.dll"
    assert d["dll_base"] == "0x7ffabc0000"


# ── modules ─────────────────────────────────────────────────────────
def test_normalize_modules_maps_fields():
    rows = [{"Name": "ntoskrnl.exe", "Base": "0xfffff8000a000000",
             "Path": r"\SystemRoot\system32\ntoskrnl.exe"}]
    events = normalize(_write_handle(rows, "memory_modules"))
    assert len(events) == 1
    d = events[0].data
    assert d["module"] == "ntoskrnl.exe"
    assert d["path"] == r"\SystemRoot\system32\ntoskrnl.exe"
    assert d["base"] == "0xfffff8000a000000"


# ── hivelist ────────────────────────────────────────────────────────
def test_normalize_hivelist_maps_file_full_path():
    rows = [{"FileFullPath": r"\SystemRoot\System32\config\SOFTWARE"}]
    events = normalize(_write_handle(rows, "memory_hivelist"))
    assert len(events) == 1
    assert events[0].data["hive_path"] == r"\SystemRoot\System32\config\SOFTWARE"


def test_normalize_hivelist_falls_back_to_hive_key():
    rows = [{"Hive": r"\SystemRoot\System32\config\SYSTEM"}]
    events = normalize(_write_handle(rows, "memory_hivelist"))
    assert len(events) == 1
    assert events[0].data["hive_path"] == r"\SystemRoot\System32\config\SYSTEM"


# ── hidden-process (Track C: pslist vs psscan, stamped by enrich_events) ──
def _psscan_event(pid=666, image="evil.exe", hidden=None, exit_time=""):
    data = {"pid": pid, "image": image, "image_basename": image.lower(),
            "exit_time": exit_time}
    if hidden is not None:
        data["hidden_from_pslist"] = hidden
    return NormEvent(
        artifact_type="memory_psscan", timestamp="", source_file="mem.raw",
        record_id="0", data=data,
    )


def test_hidden_process_fires_when_stamped():
    a = hidden_process(_psscan_event(pid=666, image="evil.exe", hidden=True))
    assert a is not None
    assert a.rule_id == "memory-hidden-process"
    assert a.mitre == ["T1564.001"]
    assert "666" in a.title
    assert "evil.exe" in a.title
    # no exit_time recorded -- the evidence that distinguishes a truly
    # unlinked LIVE process from a pool-scan hit on a terminated one.
    assert "no exit time" in a.title.lower()


def test_hidden_process_silent_when_not_stamped():
    # enrich_events never ran (or found no baseline) -> field absent.
    assert hidden_process(_psscan_event(pid=1, hidden=None)) is None


def test_hidden_process_silent_when_explicitly_false():
    assert hidden_process(_psscan_event(pid=1, hidden=False)) is None


def test_hidden_process_no_fire_when_terminated():
    # psscan pool-scanning surfaces freed EPROCESS blocks belonging to
    # TERMINATED processes, which are legitimately absent from pslist.
    # ExitTime set means this is not evidence of hiding.
    assert hidden_process(_psscan_event(
        pid=666, image="evil.exe", hidden=True,
        exit_time="2026-01-01 10:00:00")) is None


def test_rows_tolerates_non_utf8(tmp_path):
    from spectre.modules.memory.normalize import _rows
    p = tmp_path / "rows.json"
    p.write_bytes(b'[{"a":"\xff"}]')
    assert len(_rows({"path": str(p)})) == 1


def test_rows_corrupt_json_is_not_silent(tmp_path, caplog):
    import logging
    from spectre.modules.memory.normalize import _rows
    p = tmp_path / "rows.json"
    p.write_text("{not json")
    with caplog.at_level(logging.WARNING):
        assert _rows({"path": str(p)}) == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert str(p) in warnings[0].getMessage()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
