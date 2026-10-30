# PCAP Triage — tcpdump Patterns for Network Forensics

Phase 2 and Phase 3 run the pcap module automatically (`src/spectre/modules/pcap/`: Zeek
primary, tcpdump/tshark fallback, rules such as `pcap-beacon` and `pcap-dns-anomaly`). The
tcpdump patterns below are for manually verifying what it extracted and flagged, or for a
lightweight look when the module cannot run.

## Evidence Registration for PCAP

Register PCAPs through Phase 0 (`case_setup`); never hand-copy them into a
case's `evidence/` dir. Registration hashes the SOURCE at ingest, copies it
into `evidence/`, sets `chmod 444`, guards the copy (parent-dir check skipped,
since `evidence/` must be writable during the copy), refuses on a hash
mismatch, and writes chained `evidence_guard` / `evidence_register` audit rows.
`evidence/` is then locked `0555`.

### Standard registration (any source, including vmblock-fuse, NFS, CIFS, USB)
```bash
# 1. Record the source hash yourself (chain of custody)
sha256sum <source.pcap>

# 2. Optional pre-check. It FAILS on fuse/NFS/CIFS sources because the
#    mount's parent dir is writable; that is expected and not a blocker.
python3 -m spectre.pipeline.evidence_guard <source.pcap> --skip-audit

# 3. Register (Phase 0). case_setup does the copy, chmod 444 and post-copy guard.
spectre --name <case-name> --profile auto --phase 0 --evidence <source.pcap>
#    equivalent: python3 -m spectre.pipeline.case_setup --name <case-name> \
#                  --profile auto --evidence <source.pcap>

# 4. Confirm the sha256 from step 1 equals output_sha256 in the evidence_register row
grep evidence_register ~/spectre-cases/NNN-name/audit.jsonl
```

### Unstable mount (source may change or disappear mid-read)

Snapshot it first, then register the snapshot:

```bash
TMPDIR=$(mktemp -d)
cp <source.pcap> "$TMPDIR/traffic.pcap"
chmod 444 "$TMPDIR/traffic.pcap"
chmod 555 "$TMPDIR"                                  # prevents file replacement
sha256sum <source.pcap> "$TMPDIR/traffic.pcap"       # MUST match
spectre --name <case-name> --profile auto --phase 0 --evidence "$TMPDIR/traffic.pcap"
chmod 755 "$TMPDIR" && rm -rf "$TMPDIR"              # clean up after success
```

Record the original source path in the case notes: the audit trail will show
the temp path as `original_path`. The SHA-256 is verified at the source, the
temp copy and the case copy.

## Phase 2: Extraction Commands

### Capture metadata
```bash
capinfos evidence/capture.pcap
# Gives: packet count, duration, data rate, SHA256, first/last timestamps
```

### Quick overview (no payload)
```bash
tcpdump -nr evidence/capture.pcap -q | head -80
# -n = no DNS resolution, -r = read file, -q = quiet (summary)
```

### Top IP conversations (source)
```bash
tcpdump -nr evidence/capture.pcap -nn 'ip' | \
  awk '{print $3}' | sed 's/\.[0-9]*$//' | sort | uniq -c | sort -rn | head -20
```

### Top TCP destinations (by packet count)
```bash
tcpdump -nr evidence/capture.pcap -nn 'tcp' | \
  awk '{print $5}' | sed 's/\.[0-9]*$//' | sort | uniq -c | sort -rn | head -20
```

### All unique external destinations (excluding private IPs)
```bash
tcpdump -nr evidence/capture.pcap -nn 'ip' | \
  awk '{print $5}' | sed 's/\.[0-9]*$//' | grep -v '^10\.' | sort | uniq -c | sort -rn
```

### DNS queries extracted
```bash
tcpdump -nr evidence/capture.pcap -nn 'port 53' | \
  grep -oP 'A\?\s+\K\S+' | sort | uniq -c | sort -rn
```

### DNS responses with resolved IPs
```bash
tcpdump -nr evidence/capture.pcap -nn 'src port 53' | \
  grep -oP 'A\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn
```

### HTTP Host headers
```bash
tcpdump -nr evidence/capture.pcap -A 'tcp port 80' | \
  grep -i 'Host:' | sort | uniq -c | sort -rn
```

### All unique DNS domains queried
```bash
tcpdump -nr evidence/capture.pcap -nn 'port 53' | \
  grep -oP 'A\?\s+\K[^\s.]+(\.[^\s.]+)+' | sort -u
```

## Phase 3: Detection Patterns

### Beacon detection (identify regular-interval traffic)

1. **Identify candidate IPs**: Look for external destinations with unusual
   packet counts or ports (HTTP on 443 without TLS, non-standard ports).

2. **Check for regularity**:
   ```bash
   tcpdump -nr evidence/capture.pcap -nn 'host <suspicious_ip>' | head -30
   ```
   Look for: consistent timing gaps (e.g., every 60s), PUSH flags at regular
   intervals, similar packet lengths.

3. **Extract HTTP from port 443** (TLS avoidance):
   ```bash
   tcpdump -nr evidence/capture.pcap -A 'host <suspicious_ip> and tcp port 443' | \
     grep -i 'POST\|GET\|User-Agent\|Server:\|Host:'
   ```
   Plaintext HTTP on port 443 strongly indicates evasion. Legitimate HTTPS
   would show only binary (TLS handshake, encrypted records).

4. **Count beacons**:
   ```bash
   tcpdump -nr evidence/capture.pcap -A 'host <c2_ip>' | grep -c 'POST http'
   ```

### DNS anomaly detection

- **Suspicious domains**: Non-corporate domains, typosquatted names, .xyz/.tk/.ml TLDs
- **DNS → IP correlation**: Did a suspicious domain resolve to a suspicious IP?
  ```bash
  tcpdump -nr evidence/capture.pcap -nn 'port 53' | grep '<suspicious_domain>'
  ```
- **Short TTLs**: Indicates fast-flux or disposable infrastructure
- **WPAD queries**: `wpad.*` queries indicate the machine is looking for proxy
  auto-config — benign in corporate environments, but can be abused

### C2 protocol fingerprinting

Common RAT signatures visible in HTTP headers:
- `NetSupport Manager` → NetSupport RAT (legit tool, abused for C2)
- `Mozilla/4.0 (compatible; MSIE ...` on non-browser ports → potential Cobalt Strike
- Custom/non-standard User-Agent strings
- Server headers identifying beacon infrastructure (e.g., `NetSupport Gateway`)

### Eliding Phase 1 for network-only cases

Phase 1 is Direction (investigator tasking → directives); it needs no hash or IP database.
For PCAP-only triage:
- Check IOCs offline first: the cross-case index
  (`python3 -m spectre.pipeline.cross_case_index search --search-all --value <ioc>`)
  and the knowledge base (`src/spectre/knowledge/indicators/network.yaml`, the
  knowledge-retriever skill)
- Case IOCs never leave this box by default. An external reputation lookup
  (VirusTotal, AbuseIPDB, ...) needs the examiner's explicit approval for that
  specific value and service, every time; record in the case notes what was sent,
  to which service, when, and who approved it
- Document the skip reason in the case manifest
- FK YAMLs for network artifacts are at `src/spectre/knowledge/artifacts/network/` (pcap, firewall, ids). The domain caveats from pcap.yaml apply (e.g., "IP addresses can be spoofed, NAT'd, or belong to CDNs/proxies").

## Phase 3-4: Network Findings Come Only From the pcap Rule Pack

Network findings are produced by `spectre --phase 3`, which runs the pcap
module's rule pack (`src/spectre/modules/pcap/rules.py`: `pcap-beacon`,
`pcap-c2-protocol`, `pcap-dns-anomaly`, `pcap-exploit-probe`,
`pcap-staging-download`, `pcap-large-transfer`, `pcap-suspicious-port`, …) on the
Phase 2 normalized events. Never emit a network finding yourself: do not call
`emit_from_handle()` or any other `emit_finding` function, do not choose a rule_id,
title, IOCs or FK YAML, and do not write a finding YAML.

The tcpdump commands in this reference are verification aids only: use them to
check what a rule reported, and cite their output to the examiner.

If you see network activity no rule covers, report it to the examiner in the
session as an investigative lead (what you saw, the exact command that shows it,
the evidence file) — it is not a finding. You may propose a new rule for it
following the vertical-slice pattern in `skills/core/SKILL.md`; once that rule
lands, Phase 3 produces the finding deterministically.

### Beacon timing confirmation

To verify a `pcap-beacon` finding's interval:
```bash
# Extract timestamps from consecutive beacons
tcpdump -nr evidence/capture.pcap -nn 'host <c2_ip>' | \
  awk '{print $1}' | head -20
# Look for consistent gaps (e.g., 00:01:00 = 60s)
```

A perfectly regular interval (σ ≈ 0) strongly supports C2 beaconing over
interactive use or legitimate polling.

## Pitfalls

- **tshark may not be installed**: Wireshark GUI packages don't always include
  tshark. Check `which tshark` before assuming it's available. tcpdump handles
  most triage needs. editcap/mergecap/capinfos from wireshark-common are usually
  present.

- **`tcpdump -A` is ASCII-only**: Binary protocols (TLS, SMB, RPC) will show
  garbage. Use `tcpdump -X` for hex+ASCII when needed, but redirect to files
  (raw hex dumps can blow context).

- **Port 443 ≠ HTTPS**: Many RATs and C2 frameworks use HTTP over port 443 to
  evade egress filtering. Always inspect port 443 traffic for plaintext HTTP
  headers — TLS traffic starts with a ClientHello (0x16 0x03 ...), not "GET"
  or "POST".

- **DNS responses can be fragmented**: grep for the domain name in the full
  DNS output to capture both query and response. Some DNS servers return
  multiple IPs in a single response.

- **`Host: /` is a grep false-positive**: When extracting Host headers with
  `grep -i 'Host:'`, the regex matches request paths like `GET / HTTP/1.1`
  if the output contains "Host:" near "/". Always verify the top Host
  header results by inspecting raw packets before concluding pattern.

- **Large PCAPs (~300K+ packets) need batching**: A full ASCII dump of a
  300K-packet PCAP will saturate context. Use targeted filters (specific
  ports, IPs, or BPF expressions) instead of dumping all payloads. The
  extraction commands in this reference use awk/sort/uniq pipelining to
  produce compact summaries — never raw payload dumps into context.

## Phase 3 Addendum: Bulk Scanning Detection

These patterns identify internet-wide scanning and exploit probing against
exposed servers — distinct from targeted C2 activity.

### Port scan summary (SYN-per-destination-port)
```bash
tcpdump -nr evidence/capture.pcap -nn 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' | \
  awk '{print $5}' | sed 's/.*\.//' | sort -n | uniq -c | sort -rn | head -40
```
Reveals which services are being targeted. 80+ unique ports = mass scanning.
Ports like 27017 (MongoDB), 3306 (MySQL), 6379 (Redis), 2375 (Docker) indicate
the scanner is probing for exposed databases and infrastructure services.

### Unique scanner count and network distribution
```bash
# Total unique scanner IPs
tcpdump -nr evidence/capture.pcap -nn 'tcp[tcpflags] & (tcp-syn) != 0' | \
  awk '{print $3}' | sed 's/\.[0-9]*$//' | sort -u | wc -l

# Top /16 networks
tcpdump -nr evidence/capture.pcap -nn 'tcp[tcpflags] & (tcp-syn) != 0' | \
  awk '{print $3}' | sed 's/\.[0-9]*$//' | sed 's/\.[0-9]*$//' | \
  sort | uniq -c | sort -rn | head -20
```
12K+ unique IPs = internet-wide scanning. Dominant /16 networks (e.g., 85.217.x.x)
point to hosting providers running scan infrastructure.

### HTTP response code analysis (server-side perspective)
```bash
tcpdump -nr evidence/capture.pcap -A 'src host <server_ip> and tcp port 80' | \
  grep -oP 'HTTP/1\.[01] \d{3}' | sort | uniq -c | sort -rn
```
404s dominating = most exploit attempts fail. High 200 count compared to total
requests = successful content serving. 400/405 = malformed HTTP probes.

### Daily activity breakdown
```bash
tcpdump -nr evidence/capture.pcap -nn -tt 'ip' | \
  awk '{print int($1/86400)}' | sort -n | uniq -c
```
Flat daily counts (35K-58K) = consistent background radiation. Spikes on
specific days = targeted campaign. Steady decline = scanner losing interest.

### IoT exploit fingerprinting
Look for these request patterns in HTTP payloads:
- `GET /config/getuser?index=0` → Hikvision camera config disclosure (CVE-2017-7921)
- `POST /goform/websLogin` → Router/DVR admin login brute force
- `POST /goform/execute_script` → Router command injection
- `/cgi-bin/operator/servetest` → Device diagnostic abuse

Extract the specific exploit paths:
```bash
tcpdump -nr evidence/capture.pcap -A 'tcp port 80' | \
  grep -oP '^(GET|POST) \S+' | sort | uniq -c | sort -rn | head -30
```

### EICAR / security test probe detection on port 443
```bash
tcpdump -nr evidence/capture.pcap -A 'tcp port 443' | grep -i 'EICAR'
```
The EICAR test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
on port 443 indicates a Nessus or similar vulnerability scanner testing whether
the server/WAF detects AV test signatures. Often comes from source port 12345
and uses spoofed Host headers (e.g., `Host: www.baidu.com`). Server responding
with RST = port not accepting plaintext HTTP — harmless probe.
