"""Regression corpus from W2-A review round 4 (fp_corpus.py): realistic,
fully grounded analyst prose across memory / evtx / disk / pcap findings.
Used by test_w2a_round4.py to prove the character policy adds no strips
over HEAD (12/44 explain sentences, 0/5 report sections, 3 V7 strips)."""
# ruff: noqa: E501
from pathlib import Path

import yaml

import spectre

KN = Path(spectre.__file__).parent / "knowledge" / "artifacts"


def cav(p):
    return (yaml.safe_load((KN / p).read_text()) or {}).get("does_NOT_prove", []) or []


H1 = "9f2b5c3a7d1e4f60a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5"
H2 = "5d41402abc4b2a76b9719d911017c592"
F = [
 dict(finding_id="F-884-001", rule_id="mem-malfind", mitre_attack="T1055", artifact="memory_malfind",
      title="Injected PAGE_EXECUTE_READWRITE region in rundll32.exe (PID 4412)",
      iocs={"process": ["rundll32.exe"], "sha256": [H1]},
      corroboration={"tools": ["volatility3/windows.malfind"], "artifacts": [
          "PID 4412 rundll32.exe VAD 0x1f0000-0x21ffff PAGE_EXECUTE_READWRITE MZ header",
          "parent PID 3120 explorer.exe", "dumped region sha256 " + H1]}),
 dict(finding_id="F-884-002", rule_id="mem-netscan", mitre_attack="T1071.001", artifact="memory_netscan",
      title="rundll32.exe ESTABLISHED to 185.220.101.42:443",
      iocs={"ip": ["185.220.101.42"], "port": [443]},
      corroboration={"tools": ["volatility3/windows.netscan"], "artifacts": [
          "TCPv4 10.1.4.23:49812 -> 185.220.101.42:443 ESTABLISHED PID 4412 rundll32.exe"]}),
 dict(finding_id="F-884-003", rule_id="mem-cmdline", mitre_attack="T1059.001", artifact="memory_cmdline",
      title="Encoded PowerShell command line (PID 6620)",
      iocs={"process": ["powershell.exe"]},
      corroboration={"tools": ["volatility3/windows.cmdline"], "artifacts": [
          "PID 6620 powershell.exe -nop -w hidden -enc SQBFAFgA... parent PID 4412"]}),
 dict(finding_id="F-884-004", rule_id="evtx-4624-type10", mitre_attack="T1021.001", artifact="evtx_4624",
      title="RDP logon (4624 LogonType 10) for CORP\\svc_backup from 10.1.4.77",
      iocs={"ip": ["10.1.4.77"], "user": ["CORP\\svc_backup"]},
      corroboration={"tools": ["evtx/Security"], "artifacts": [
          "EventID 4624 LogonType 10 TargetUserName svc_backup IpAddress 10.1.4.77 2024-03-14T02:11:09Z WS-0231"]}),
 dict(finding_id="F-884-005", rule_id="evtx-7045", mitre_attack="T1543.003", artifact="evtx_7045",
      title="Service install (7045) 'WinSvcUpd' ImagePath C:\\Windows\\Temp\\svcupd.exe",
      iocs={"file": ["C:\\Windows\\Temp\\svcupd.exe"], "sha256": []},
      corroboration={"tools": ["evtx/System"], "artifacts": [
          "EventID 7045 ServiceName WinSvcUpd ImagePath C:\\Windows\\Temp\\svcupd.exe StartType auto 2024-03-14T02:14:51Z"]}),
 dict(finding_id="F-884-006", rule_id="evtx-1102", mitre_attack="T1070.001", artifact="evtx_1102",
      title="Security log cleared (1102) by CORP\\svc_backup",
      iocs={"user": ["CORP\\svc_backup"]},
      corroboration={"tools": ["evtx/Security"], "artifacts": ["EventID 1102 SubjectUserName svc_backup 2024-03-14T03:02:17Z"]}),
 dict(finding_id="F-884-007", rule_id="disk-run-key", mitre_attack="T1547.001", artifact="registry_run",
      title="Run key persistence HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
      iocs={"file": ["C:\\ProgramData\\Updater\\upd.dll"], "md5": [H2]},
      corroboration={"tools": ["regripper/run"], "artifacts": [
          "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Updater = rundll32.exe C:\\ProgramData\\Updater\\upd.dll,Start LastWrite 2024-03-14 02:16:03"]}),
 dict(finding_id="F-884-008", rule_id="disk-prefetch", mitre_attack="T1204.002", artifact="prefetch",
      title="Prefetch SVCUPD.EXE-3A1F2B4C.pf run count 3",
      iocs={"file": ["SVCUPD.EXE-3A1F2B4C.pf"]},
      corroboration={"tools": ["sccainfo"], "artifacts": ["SVCUPD.EXE-3A1F2B4C.pf RunCount 3 LastRun 2024-03-14 02:15:10 Windows 10 build 19045"]}),
 dict(finding_id="F-884-009", rule_id="disk-mft-timestomp", mitre_attack="T1070.006", artifact="mft",
      title="$SI < $FN created time on C:\\ProgramData\\Updater\\upd.dll",
      iocs={"file": ["C:\\ProgramData\\Updater\\upd.dll"]},
      corroboration={"tools": ["MFTECmd"], "artifacts": ["entry 88213 $SI created 2019-07-02 $FN created 2024-03-14 02:15:58"]}),
 dict(finding_id="F-884-010", rule_id="pcap-beacon", mitre_attack="T1071.001", artifact="pcap",
      title="Periodic HTTPS to cdn-update.example-cdn.net (185.220.101.42) every ~60 s",
      iocs={"ip": ["185.220.101.42"], "domain": ["cdn-update.example-cdn.net"]},
      corroboration={"tools": ["zeek/conn", "zeek/ssl"], "artifacts": [
          "10.1.4.23 -> 185.220.101.42:443 cdn-update.example-cdn.net 214 connections median interval 60.2 s MAD 1.1 s JA3 72a589da586844d7f0818ce684948eea"]}),
 dict(finding_id="F-884-011", rule_id="pcap-dns-tunnel", mitre_attack="T1071.004", artifact="pcap",
      title="High-entropy TXT queries to t.example-dns.org",
      iocs={"domain": ["t.example-dns.org"], "ip": ["10.1.4.23"]},
      corroboration={"tools": ["zeek/dns"], "artifacts": ["1,284 TXT queries from 10.1.4.23 to t.example-dns.org, mean label entropy 4.7 bits/char"]}),
 dict(finding_id="F-884-012", rule_id="pcap-exfil", mitre_attack="T1048", artifact="pcap",
      title="Large outbound upload 1.8 GB to 203.0.113.50:8443",
      iocs={"ip": ["203.0.113.50"], "port": [8443]},
      corroboration={"tools": ["zeek/conn"], "artifacts": ["10.1.4.23:50122 -> 203.0.113.50:8443 orig_bytes 1932735283 duration 2711.4 s"]}),
]
FK = {f["finding_id"]: cav(("network/" if f["artifact"] == "pcap" else "windows/") + f["artifact"] + ".yaml") for f in F}

D = {
 "F-884-001": "F-884-001 records a PAGE_EXECUTE_READWRITE VAD at 0x1f0000 inside rundll32.exe (PID 4412) that begins with an MZ header. The parent process is explorer.exe (PID 3120), which is the normal parent for an interactive user session. The dumped region hashes to 9f2b5c3a7d1e4f60a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5 — this hash should be checked against the internal malware repository. In F-884-001, the RWX protection combined with the PE header is the classic T1055 pattern.",
 "F-884-002": "F-884-002 shows rundll32.exe (PID 4412) holding an ESTABLISHED TCP session from 10.1.4.23:49812 to 185.220.101.42:443. A rundll32 process with an outbound TLS session is unusual on a workstation. F-884-002 is mapped to T1071.001 because the session uses port 443.",
 "F-884-003": "F-884-003 captures powershell.exe (PID 6620) launched with -nop -w hidden -enc, a hidden, encoded command line. Its parent is PID 4412, the same rundll32.exe flagged by the injection finding. Decoding the base64 blob would reveal the payload.",
 "F-884-004": "F-884-004 is an interactive RDP logon (event 4624, LogonType 10) for CORP\\svc_backup from 10.1.4.77 at 2024-03-14T02:11:09Z on WS-0231. Service accounts such as svc_backup rarely log on interactively. F-884-004 maps to T1021.001 (Remote Desktop Protocol).",
 "F-884-005": "F-884-005 records a 7045 service installation named WinSvcUpd with ImagePath C:\\Windows\\Temp\\svcupd.exe and StartType auto, about three minutes after the RDP logon. Services launched from C:\\Windows\\Temp are a common persistence pattern. F-884-005 corresponds to T1543.003.",
 "F-884-006": "F-884-006 shows the Security log was cleared (event 1102) by svc_backup at 2024-03-14T03:02:17Z. Log clearing ~50 minutes after the logon suggests anti-forensics. F-884-006 is mapped to T1070.001.",
 "F-884-007": "F-884-007 is a Run value named Updater under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run that launches rundll32.exe C:\\ProgramData\\Updater\\upd.dll,Start. The key's LastWrite time is 2024-03-14 02:16:03, which fits the intrusion window. The DLL's MD5 is 5d41402abc4b2a76b9719d911017c592. F-884-007 maps to T1547.001.",
 "F-884-008": "F-884-008 shows SVCUPD.EXE-3A1F2B4C.pf with a run count of 3 and a last run of 2024-03-14 02:15:10 on Windows 10 build 19045. Prefetch corroborates that the service binary executed at least once. F-884-008 is consistent with T1204.002.",
 "F-884-009": "F-884-009 flags MFT entry 88213 (C:\\ProgramData\\Updater\\upd.dll) whose $SI created time is 2019-07-02 while its $FN created time is 2024-03-14 02:15:58. A $SI timestamp older than $FN is a strong timestomping indicator. F-884-009 maps to T1070.006.",
 "F-884-010": "F-884-010 shows 214 HTTPS connections from 10.1.4.23 to cdn-update.example-cdn.net (185.220.101.42) with a median interval of 60.2 s and a MAD of 1.1 s. That regularity, with jitter under 2 %, is typical of an implant heartbeat. The JA3 hash is 72a589da586844d7f0818ce684948eea. F-884-010 is mapped to T1071.001.",
 "F-884-011": "F-884-011 records 1,284 TXT queries from 10.1.4.23 to t.example-dns.org with a mean label entropy of 4.7 bits/char. High-entropy TXT traffic to one domain is characteristic of DNS tunnelling. F-884-011 maps to T1071.004.",
 "F-884-012": "F-884-012 shows 10.1.4.23 uploading about 1.8 GB (1932735283 bytes) to 203.0.113.50:8443 over 2711.4 s. The upload started after the Run key was written. F-884-012 is consistent with T1048 exfiltration over an alternative protocol.",
}
# Extra-character descriptions (typographic Unicode an analyst/model routinely emits)
DX = {
 "F-884-010": "F-884-010 beacons every ≈60 s (jitter ≤ 1.1 s, i.e. under 2 %) — see the “Beacons” table. F-884-010 → T1071.001.",
 "F-884-002": "F-884-002: the session’s round-trip time was ~150 µs on the LAN leg, which is expected.",
 "F-884-004": "F-884-004 involves the account of José Ñúñez (CORP\\svc_backup); the RDP client name was “WS-0231”.",
}

REPORT = {
 "executive_summary": ("Spectre identified a likely intrusion on WS-0231 beginning 2024-03-14 at 02:11 UTC. "
    "An RDP logon (F-884-004) was followed by a service install (F-884-005), a Run key (F-884-007) and "
    "periodic HTTPS beaconing to 185.220.101.42 (F-884-010). The Security log was cleared at 03:02 (F-884-006)."),
 "threat_narrative": ("The operator logged on over RDP as CORP\\svc_backup from 10.1.4.77 (F-884-004, T1021.001). "
    "Three minutes later the WinSvcUpd service was installed from C:\\Windows\\Temp\\svcupd.exe (F-884-005, T1543.003), "
    "and prefetch shows it ran (F-884-008). A Run key launching C:\\ProgramData\\Updater\\upd.dll was created at 02:16 (F-884-007, T1547.001); "
    "the DLL's $SI time was backdated to 2019 (F-884-009, T1070.006).\n\n"
    "In memory, rundll32.exe (PID 4412) holds an RWX region with an MZ header (F-884-001, T1055) and an ESTABLISHED session to "
    "185.220.101.42:443 (F-884-002). Network data shows the same host beaconing every ~60 s to cdn-update.example-cdn.net "
    "(F-884-010, T1071.001), DNS TXT tunnelling to t.example-dns.org (F-884-011, T1071.004) and a 1.8 GB upload to "
    "203.0.113.50:8443 (F-884-012, T1048). The Security log was cleared at 03:02:17 (F-884-006, T1070.001)."),
 "timeline_narrative": ("02:11:09 RDP logon (F-884-004). 02:14:51 service install (F-884-005). 02:15:10 first svcupd.exe run (F-884-008). "
    "02:16:03 Run key written (F-884-007). 03:02:17 log cleared (F-884-006)."),
 "methodology_narrative": ("Memory was analysed with Volatility 3 (windows.malfind, windows.netscan, windows.cmdline). "
    "EVTX Security and System logs were parsed for events 4624, 7045 and 1102. The disk image was examined with RegRipper, "
    "sccainfo and MFTECmd. PCAP was processed with Zeek 8 (conn, ssl, dns). All timestamps are UTC."),
 "verdict": "Evidence supports an intrusion: an RDP logon, persistence, injected code and outbound C2/exfiltration are corroborated across memory, disk, EVTX and PCAP.",
 "findings_narrative": [{"finding_id": f["finding_id"], "narrative": D[f["finding_id"]]} for f in F],
}

