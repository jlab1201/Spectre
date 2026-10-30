"""W4-4 / R1-F7 report side: RFC1918 and victim identities are internal/
victim in iocs.csv, never in block-list sections, and Recommended Actions
never tell anyone to isolate a bystander host."""

import csv

from spectre.pipeline.report_synthesize import (
    _generate_iocs_csv,
    _recommended_actions,
    _segment_iocs,
)

MON = "10.2.28.88"


def _findings():
    return [
        # victim identity (bound to the monitored host): Kerberos realm ...
        {"finding_id": "F-1", "rule_id": "pcap-host-identity", "confidence": 0.8,
         "host_ip": MON,
         "corroboration": {"artifacts": ["identity [kerberos]: host= account=brolf@EASYAS123.TECH"]},
         "iocs": {"ip": [MON], "domain": ["EASYAS123.TECH"],
                  "account": ["brolf@EASYAS123.TECH"]}},
        # ... corroborated by the victim's own DHCP client FQDN suffix
        {"finding_id": "F-5", "rule_id": "pcap-host-identity", "confidence": 0.8,
         "host_ip": MON,
         "corroboration": {"artifacts": ["identity [dhcp]: host=DESKTOP-TEYQ2NR"]},
         "iocs": {"ip": [MON], "domain": ["easyas123.tech", "mshome.net"],
                  "host": ["DESKTOP-TEYQ2NR"]}},
        # bystander DHCP DISCOVER — foreign MAC, positively not bound
        {"finding_id": "F-2", "rule_id": "pcap-host-identity", "confidence": 0.8,
         "host_ip": "",
         "corroboration": {"artifacts": ["identity [dhcp]: host=brads-MBP account= ip= "
                                         "— not bound to the monitored host (bystander device)"]},
         "iocs": {"host": ["brads-MBP"]}},
        # dns anomaly on the org's own WPAD names + a real C2 domain
        {"finding_id": "F-3", "rule_id": "pcap-dns-anomaly", "confidence": 0.6,
         "host_ip": MON,
         "iocs": {"domain": ["wpad.easyas123.tech", "wpad.mshome.net", "evil.example",
                             "wpad.evil.tld", "wpad.com", "printer.local"]}},
        # AD recon against the internal DC; C2 to a real remote
        {"finding_id": "F-6", "rule_id": "smb-ad-recon-pipe", "confidence": 0.85,
         "host_ip": MON, "iocs": {"ip": ["10.2.28.2"]}},
        {"finding_id": "F-4", "rule_id": "pcap-c2-protocol", "confidence": 0.85,
         "host_ip": MON, "iocs": {"ip": ["45.131.214.85"]}},
    ]


def _roles(tmp_path, findings):
    p = tmp_path / "iocs.csv"
    _generate_iocs_csv(findings, str(p))
    return {(r["ioc_type"], r["value"]): r["role"] for r in csv.DictReader(open(p))}


def test_iocs_csv_roles(tmp_path):
    r = _roles(tmp_path, _findings())
    assert r[("ip", MON)] == "victim"
    assert r[("host", "DESKTOP-TEYQ2NR")] == "victim"
    assert r[("account", "brolf@EASYAS123.TECH")] == "victim"
    assert r[("domain", "EASYAS123.TECH")] == "internal"
    assert r[("domain", "wpad.easyas123.tech")] == "internal"
    assert r[("domain", "printer.local")] == "internal"
    # WPAD hijack guard: wpad.X is internal only under the victim's domain.
    assert r[("domain", "wpad.mshome.net")] == "remote"   # domain never observed
    assert r[("domain", "wpad.evil.tld")] == "remote"
    assert r[("domain", "wpad.com")] == "remote"
    assert r[("ip", "10.2.28.2")] == "internal"
    assert r[("host", "brads-MBP")] == "internal"
    assert r[("ip", "45.131.214.85")] == "remote"
    assert r[("domain", "evil.example")] == "remote"


def test_segments_keep_internal_out_of_blocklists():
    seg = _segment_iocs(_findings(), {"monitored_ip": MON})
    blocklist = seg["Malware C2 & Payload Hosts"] + seg["Scanner Infrastructure"]
    vals = {row[1] for row in blocklist}
    assert "45.131.214.85" in vals and "evil.example" in vals
    assert {"wpad.evil.tld", "wpad.com"} <= vals          # hijack IOCs stay visible
    for bad in ("10.2.28.2", "wpad.easyas123.tech", "printer.local",
                "EASYAS123.TECH", MON):
        assert bad not in vals
    internal = {row[1] for row in seg["Internal Infrastructure"]}
    assert {"10.2.28.2", "wpad.easyas123.tech", "printer.local"} <= internal
    assert not {"wpad.evil.tld", "wpad.com", "wpad.mshome.net"} & internal


def test_recommended_actions_never_isolate_bystander():
    immediate, followup = _recommended_actions(_findings(), {"monitored_ip": MON})
    text = "\n".join(immediate)
    assert "DESKTOP-TEYQ2NR" in text and "brolf@EASYAS123.TECH" in text
    assert "brads-MBP" not in text
    assert "10.2.28.2" not in text           # internal DC is never "blocked"
    assert "45.131.214.85" in text
    assert any("brads-MBP" in a and "not attributed" in a for a in followup)


def test_domain_inventory_marks_internal_names(tmp_path):
    from spectre.pipeline.report_synthesize import _merge_report_md
    fs = [dict(f, status="INFERRED", mitre_attack="UNMAPPED", title=f["finding_id"],
               caveats=[], description="d") for f in _findings()]
    md = _merge_report_md(None, fs, {"case_id": "1", "case_name": "t", "monitored_ip": MON},
                          str(tmp_path), [], {})
    inv = md.split("### Domain Indicators (deduplicated)", 1)[1].split("**TLD", 1)[0]
    assert "`wpad.easyas123.tech` _(internal — not for block-listing)_" in inv
    assert "`evil.example`\n" in inv + "\n"
    assert "`evil.example` _(internal" not in inv
    assert "`wpad.evil.tld` _(internal" not in inv
