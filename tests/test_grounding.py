"""Unit tests for the shared IOC-grounding token definition (Track E1)."""
from spectre.core import grounding


def test_extract_ipv4():
    assert "45.131.214.85" in grounding.extract_iocs("beacon to 45.131.214.85 seen")


def test_extract_domain_lowercased():
    assert "vadusa.xyz" in grounding.extract_iocs("resolved VADUSA.xyz via DNS")


def test_extract_url_and_its_domain():
    toks = grounding.extract_iocs("fetched https://pastebin.com/RSGSi1hk now")
    assert "https://pastebin.com/rsgsi1hk" in toks
    assert "pastebin.com" in toks


def test_extract_hash_exact():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert h in grounding.extract_iocs(f"md5 {h} matched")


def test_extract_user_agent_tokens():
    toks = grounding.extract_iocs(
        "UA Mozilla/4.0 (compatible; MSIE 7.0; Trident/4.0)")
    assert "mozilla/4.0" in toks
    assert "msie 7.0" in toks
    assert "trident/4.0" in toks


def test_extract_ignores_bare_product_without_version():
    # "Chrome" with no version must not be treated as an IOC token
    assert grounding.extract_iocs("the user opened Chrome") == set()


def test_grounded_tokens_excludes_description():
    finding = {"iocs": {"ip": ["1.2.3.4"]}, "description": "9.9.9.9 fabricated"}
    g = grounding.grounded_tokens(finding, skip_keys=("description",))
    assert "1.2.3.4" in g
    assert "9.9.9.9" not in g


def test_ungrounded_literals():
    grounded = {"1.2.3.4"}
    assert grounding.ungrounded_literals("saw 1.2.3.4 and 5.6.7.8", grounded) == {"5.6.7.8"}


def test_ungrounded_literals_empty_when_all_grounded():
    grounded = {"1.2.3.4", "evil.com"}
    assert grounding.ungrounded_literals("1.2.3.4 evil.com", grounded) == set()


def test_plain_prose_has_no_tokens():
    assert grounding.extract_iocs("The attacker established persistence.") == set()


def test_ipv6_full_address_extracted_with_prefix():
    toks = grounding.extract_iocs("beacon to fe80::abcd on link")
    assert "fe80::abcd" in toks


def test_ipv6_prefix_distinguishes_addresses():
    # Two addresses sharing only a suffix must NOT cross-ground (the CRITICAL bug).
    grounded = grounding.grounded_tokens({"iocs": {"ipv6": ["fe80::abcd"]}})
    fabricated = "exfil to 1234::abcd observed"
    assert grounding.ungrounded_literals(fabricated, grounded) == {"1234::abcd"}


def test_ipv6_uncompressed_extracted():
    a = "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert a in grounding.extract_iocs(f"host {a} seen")


from spectre.core.grounding import extract_iocs, ungrounded_literals


def test_extracts_apt_designator():
    assert "apt29" in extract_iocs("Attributed to APT29 with low confidence.")


def test_extracts_named_malware_family():
    assert "emotet" in extract_iocs("The loader is consistent with Emotet.")


def test_ungrounded_actor_is_flagged():
    grounded = {"c:\\temp\\eo.dll"}
    out = ungrounded_literals("This activity is attributed to APT29.", grounded)
    assert "apt29" in out


def test_grounded_actor_survives():
    grounded = {"apt29"}
    assert ungrounded_literals("Attributed to APT29.", grounded) == set()


def test_ordinary_capitalized_prose_is_not_an_actor():
    # Sentence-initial capitals and common nouns must not be treated as IOCs.
    found = extract_iocs("The Host was rebooted. Windows Defender logged it.")
    assert found == set()


# ── WS7a sub-task 2: defanged / zero-width IOC evasion (A3 finding #1) ──

def test_bracket_defanged_ip_extracted():
    assert "1.2.3.4" in extract_iocs("beacon to 1[.]2[.]3[.]4 observed")


def test_paren_dot_defanged_domain_extracted():
    assert "evil.com" in extract_iocs("resolved evil(dot)com via DNS")


def test_bracket_dot_defanged_domain_extracted():
    assert "evil.com" in extract_iocs("resolved evil[dot]com via DNS")


def test_hxxp_defanged_url_extracted():
    toks = extract_iocs("fetched hxxps://evil[.]com/payload now")
    assert "https://evil.com/payload" in toks
    assert "evil.com" in toks


def test_zero_width_space_injected_ip_extracted():
    # Same obfuscation confirmed in the A3 repro: a ZWSP inside the address
    # defeats the literal-character regex without normalization.
    poisoned = "185.220.101​.42"
    assert "185.220.101.42" in extract_iocs(f"beacon to {poisoned} seen")


def test_fabricated_defanged_ip_is_ungrounded():
    grounded = {"1.2.3.4"}
    out = ungrounded_literals("saw 9[.]9[.]9[.]9 on the wire", grounded)
    assert "9.9.9.9" in out


def test_grounded_ip_written_defanged_is_not_a_false_positive():
    # A legitimately-defanged mention of a REAL, grounded IOC must survive —
    # normalization has to apply identically to both sides of the comparison.
    grounded = grounding.grounded_tokens({"iocs": {"ip": ["1.2.3.4"]}})
    assert grounding.ungrounded_literals("beacon to 1[.]2[.]3[.]4 observed", grounded) == set()


def test_plain_prose_with_brackets_is_not_falsely_defanged():
    # Ordinary bracketed prose (not a defang marker) must not be mangled into
    # a spurious IOC token.
    assert extract_iocs("See section [4.2] for details.") == set()
