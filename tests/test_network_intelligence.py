import pytest

from phishguard import network_intelligence as network


def test_validate_ipv4():
    assert str(network._validate_ip("8.8.8.8")) == "8.8.8.8"


def test_validate_ipv6():
    assert network._validate_ip("2001:4860:4860::8888").version == 6


@pytest.mark.parametrize("address", ["invalid", "example.com", ""])
def test_invalid_ip_rejected(address):
    with pytest.raises(ValueError):
        network.analyze_ip_network(address)


def test_ipv4_cymru_query_name():
    assert network._cymru_query_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"


def test_ipv6_cymru_query_name():
    result = network._cymru_query_name("2001:4860:4860::8888")
    assert result.endswith(".origin6.asn.cymru.com")
    assert result == "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"


def test_private_ip_skips_external_lookups(monkeypatch):
    def unexpected_lookup(address):
        raise AssertionError("Private IP must not trigger external lookups")

    monkeypatch.setattr(network, "_lookup_asn", unexpected_lookup)
    monkeypatch.setattr(network, "_lookup_reverse_dns", unexpected_lookup)

    result = network.analyze_ip_network("192.168.1.1")

    assert result["is_private"] is True
    assert result["asn"]["status"] == "not_applicable"
    assert result["reverse_dns"]["status"] == "not_applicable"


def test_public_ip_network_result(monkeypatch):
    monkeypatch.setattr(
        network,
        "_lookup_asn",
        lambda address: {
            "status": "found",
            "records": [{
                "asn": "15169",
                "network": "8.8.8.0/24",
                "country": "US",
                "registry": "arin",
                "allocation_date": "2000-03-30",
                "organization": "GOOGLE",
            }],
        },
    )
    monkeypatch.setattr(
        network,
        "_lookup_reverse_dns",
        lambda address: {"status": "found", "records": ["dns.google"]},
    )

    result = network.analyze_ip_network("8.8.8.8")

    assert result["asn"]["records"][0]["asn"] == "15169"
    assert result["asn"]["records"][0]["organization"] == "GOOGLE"
    assert result["reverse_dns"]["records"] == ["dns.google"]


def test_address_list_deduplicates_and_skips_invalid(monkeypatch):
    monkeypatch.setattr(
        network,
        "analyze_ip_network",
        lambda address: {"address": address},
    )

    result = network.analyze_network_addresses([
        "8.8.8.8",
        "8.8.8.8",
        "invalid",
        "1.1.1.1",
    ])

    assert result == [
        {"address": "8.8.8.8"},
        {"address": "1.1.1.1"},
    ]
