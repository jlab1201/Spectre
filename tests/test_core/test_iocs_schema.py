from spectre.core.base import _empty_iocs


def test_empty_iocs_has_host_and_account():
    iocs = _empty_iocs()
    assert iocs["host"] == []
    assert iocs["account"] == []


def test_empty_iocs_keeps_existing_five_categories():
    iocs = _empty_iocs()
    for key in ("filepath", "ip", "domain", "sha256", "registry_key"):
        assert iocs[key] == []


def test_empty_iocs_returns_fresh_dict():
    a = _empty_iocs()
    a["ip"].append("1.2.3.4")
    b = _empty_iocs()
    assert b["ip"] == []
