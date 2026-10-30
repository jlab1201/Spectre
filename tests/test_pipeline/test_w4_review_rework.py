"""W4 adversarial review (W4-REVIEW.md) — B-items as regression tests.

MED-2: an attacker's Kerberos realm must not make C2 domains internal.
LOW:   own-MAC no-IP DHCP is not a bystander; context findings don't drive
       the headline strength; a private-IP C2 stays in the C2 section.
"""

import csv

from spectre.modules.pcap import zeek_normalize as zn
from spectre.pipeline.report_synthesize import (
    _confidence_label,
    _generate_iocs_csv,
    _merge_report_md,
    _overall_confidence_banner,
    _recommended_actions,
    _segment_iocs,
)

MON = "10.2.28.88"


def _krb(fid, account, realm, host_ip=MON):
    return {"finding_id": fid, "rule_id": "pcap-host-identity", "confidence": 0.8,
            "host_ip": host_ip, "title": f"Host identity resolved: {account}",
            "corroboration": {"artifacts": [f"identity [kerberos]: host= account={account} ip={host_ip}"]},
            "iocs": {"ip": [host_ip] if host_ip else [], "domain": [realm],
                     "host": [], "account": [account]}}


def _dhcp(fid, host, domains, host_ip=MON):
    return {"finding_id": fid, "rule_id": "pcap-host-identity", "confidence": 0.8,
            "host_ip": host_ip, "title": f"Host identity resolved: {host}",
            "corroboration": {"artifacts": [f"identity [dhcp]: host={host} account= ip={host_ip}"]},
            "iocs": {"ip": [host_ip] if host_ip else [], "domain": list(domains),
                     "host": [host], "account": []}}


def _c2(fid, ips=(), domains=(), rid="pcap-dns-anomaly"):
    return {"finding_id": fid, "rule_id": rid, "confidence": 0.6, "host_ip": MON,
            "title": fid, "iocs": {"ip": list(ips), "domain": list(domains)}}


def _roles(tmp_path, findings):
    p = tmp_path / "iocs.csv"
    _generate_iocs_csv(findings, str(p))
    return {(r["ioc_type"], r["value"]): r["role"] for r in csv.DictReader(open(p))}


def _c2_vals(findings):
    seg = _segment_iocs(findings, {"monitored_ip": MON})
    return {r[1] for r in seg["Malware C2 & Payload Hosts"]}


# ── MED-2 PoCs ────────────────────────────────────────────────────────
def test_poc_bystander_realm_cannot_make_c2_internal(tmp_path):
    fs = [_krb("F-1", "eve@EVIL-C2.COM", "EVIL-C2.COM", host_ip=""),
          _c2("F-2", domains=["cdn.evil-c2.com"])]
    assert _roles(tmp_path, fs)[("domain", "cdn.evil-c2.com")] == "remote"
    assert "cdn.evil-c2.com" in _c2_vals(fs)


def test_poc_uncorroborated_victim_realm_cannot_make_c2_internal(tmp_path):
    # Even bound to the victim, a lone Kerberos realm is not enough.
    fs = [_krb("F-1", "bob@EVIL-C2.COM", "EVIL-C2.COM"),
          _c2("F-2", domains=["cdn.evil-c2.com"])]
    assert _roles(tmp_path, fs)[("domain", "cdn.evil-c2.com")] == "remote"
    assert "cdn.evil-c2.com" in _c2_vals(fs)


def test_poc_public_suffix_realm_rejected_even_if_corroborated(tmp_path):
    fs = [_krb("F-1", "bob@COM", "COM"), _dhcp("F-3", "PC", ["com"]),
          _krb("F-4", "bob@CO.UK", "CO.UK"), _dhcp("F-5", "PC2", ["co.uk"]),
          _c2("F-2", domains=["evil.com", "bad.co.uk"])]
    r = _roles(tmp_path, fs)
    assert r[("domain", "evil.com")] == "remote"
    assert r[("domain", "bad.co.uk")] == "remote"
    assert {"evil.com", "bad.co.uk"} <= _c2_vals(fs)


def test_corroborated_victim_realm_is_internal(tmp_path):
    fs = [_krb("F-1", "brolf@EASYAS123.TECH", "EASYAS123.TECH"),
          _dhcp("F-3", "DESKTOP-TEYQ2NR", ["easyas123.tech"]),
          _c2("F-2", domains=["wpad.easyas123.tech", "wpad.evil.tld"])]
    r = _roles(tmp_path, fs)
    assert r[("domain", "wpad.easyas123.tech")] == "internal"
    assert r[("domain", "wpad.evil.tld")] == "remote"
    assert "wpad.easyas123.tech" not in _c2_vals(fs)


def test_bystander_dhcp_domain_is_not_corroboration(tmp_path):
    fs = [_krb("F-1", "bob@EVIL-C2.COM", "EVIL-C2.COM"),
          _dhcp("F-3", "ATTACKER", ["evil-c2.com"], host_ip=""),
          _c2("F-2", domains=["cdn.evil-c2.com"])]
    assert _roles(tmp_path, fs)[("domain", "cdn.evil-c2.com")] == "remote"


def test_uncorroborated_realm_note_in_report(tmp_path):
    fs = [dict(f, status="INFERRED", mitre_attack="UNMAPPED", caveats=[], description="d")
          for f in (_krb("F-1", "bob@EVIL-C2.COM", "EVIL-C2.COM"),
                    _c2("F-2", domains=["cdn.evil-c2.com"]))]
    md = _merge_report_md(None, fs, {"case_id": "1", "case_name": "t", "monitored_ip": MON},
                          str(tmp_path), [], {})
    assert "EVIL-C2.COM" in md and "not corroborated" in md
    assert "`cdn.evil-c2.com` _(internal" not in md


# ── LOW: own-MAC DHCP with no IP, monitored IP absent from dhcp.log ──
def test_victim_own_mac_no_ip_is_not_called_bystander():
    text = ('{"ts":1.0,"mac":"00:19:d1:b2:4d:ad","host_name":"DESKTOP-TEYQ2NR",'
            '"msg_types":["DISCOVER"]}\n')
    ev = zn.normalize_zeek_dhcp(text, monitored_ip=MON)[0]
    assert ev.data["bound_to_monitored"] is None      # unattributed, not bystander
    from spectre.modules.pcap.rules import host_identity
    assert "bystander" not in host_identity(ev).summary


def test_unattributed_identity_not_told_do_not_treat_as_compromised():
    f = _dhcp("F-1", "DESKTOP-TEYQ2NR", [], host_ip="")
    f["corroboration"]["artifacts"] = ["identity [dhcp]: host=DESKTOP-TEYQ2NR account= ip="]
    immediate, followup = _recommended_actions([f], {"monitored_ip": MON})
    txt = "\n".join(immediate + followup)
    assert "isolate" not in txt
    assert "do not treat as compromised" not in txt
    assert any("DESKTOP-TEYQ2NR" in a and "unattributed" in a for a in followup)


# ── LOW: context findings don't drive headline strength ───────────────
def test_context_findings_do_not_drive_headline():
    fs = [_dhcp("F-1", "PC", []), _c2("F-2", domains=["x.example"])]
    fs[1]["confidence"] = 0.4
    b = _overall_confidence_banner(fs)
    assert b.startswith("Weak single-source indicator")
    assert "0.40" in b
    only_ctx = _overall_confidence_banner([_dhcp("F-1", "PC", [])])
    assert "Strong" not in only_ctx and "context" in only_ctx.lower()
    assert "Strong" not in _confidence_label([_dhcp("F-1", "PC", [])])


# ── LOW: private-IP C2 stays in the C2 section, annotated ─────────────
def test_private_ip_c2_stays_in_c2_section(tmp_path):
    fs = [_c2("F-1", ips=["10.9.9.9"], rid="pcap-beacon")]
    assert "10.9.9.9" in _c2_vals(fs)
    md = _merge_report_md(None, [dict(fs[0], status="INFERRED", mitre_attack="T1071",
                                      caveats=[], description="d")],
                          {"case_id": "1", "case_name": "t", "monitored_ip": MON},
                          str(tmp_path), [], {})
    c2 = md.split("### Malware C2 & Payload Hosts", 1)[1].split("###", 1)[0]
    assert "10.9.9.9" in c2 and "internal address" in c2


def test_private_ip_c2_gets_investigate_action_not_block():
    fs = [_c2("F-1", ips=["10.9.9.9", "45.1.2.3"], rid="pcap-beacon")]
    immediate, _ = _recommended_actions(fs, {"monitored_ip": MON})
    block = [a for a in immediate if a.startswith("Block")]
    assert block and "45.1.2.3" in block[0] and "10.9.9.9" not in block[0]
    assert any("10.9.9.9" in a and "internal" in a for a in immediate)


def test_context_row_basis_is_not_a_detection(tmp_path):
    fs = [dict(_dhcp("F-1", "PC", []), status="INFERRED", mitre_attack="UNMAPPED",
               caveats=[], description="d")]
    md = _merge_report_md(None, fs, {"case_id": "1", "case_name": "t", "monitored_ip": MON},
                          str(tmp_path), [], {})
    row = [ln for ln in md.splitlines() if ln.startswith("| Host identity resolved")][0]
    assert "Context only" in row and "detection confidence" not in row
