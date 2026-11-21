import pytest

from phishguard import domain_intelligence as intelligence


def test_domain_validation():
    assert intelligence._validate_domain("Example.COM.") == "example.com"


@pytest.mark.parametrize("domain", [
    "localhost",
    "127.0.0.1",
    "bad domain.com",
    "-invalid.com",
    "example..com",
])
def test_invalid_domains_rejected(domain):
    with pytest.raises(ValueError):
        intelligence._validate_domain(domain)


def test_ip_details():
    result = intelligence._ip_details(["8.8.8.8", "2001:4860:4860::8888"])

    assert result[0]["version"] == "IPv4"
    assert result[1]["version"] == "IPv6"
    assert all(item["is_global"] for item in result)


def test_private_ip_identified():
    result = intelligence._ip_details(["192.168.1.1"])

    assert result[0]["is_private"] is True
    assert result[0]["is_global"] is False


def test_hosting_indicators():
    result = intelligence._hosting_indicators([
        "ns1.cloudflare.com",
        "ns2.cloudflare.com",
        "ns1.vercel-dns.com",
    ])

    assert "Cloudflare" in result
    assert "Vercel" in result
    assert len(result) == 2


def test_domain_intelligence_result(monkeypatch):
    def fake_dns(domain, record_type):
        records = {
            "A": ["8.8.8.8"],
            "AAAA": [],
            "MX": [{"priority": 10, "host": "mail.example.com"}],
            "NS": ["ns1.cloudflare.com"],
            "TXT": ["v=spf1 include:example.com ~all"],
            "CAA": [],
        }
        return {
            "status": "found" if records[record_type] else "not_found",
            "records": records[record_type],
        }

    monkeypatch.setattr(intelligence, "_query_dns", fake_dns)
    monkeypatch.setattr(
        intelligence,
        "_lookup_rdap",
        lambda domain: {
            "status": "found",
            "registrar": "Example Registrar",
            "expiration_date": "2027-01-01T00:00:00Z",
            "nameservers": [],
        },
    )

    result = intelligence.analyze_domain_intelligence("example.com")

    assert result["domain"] == "example.com"
    assert result["ip_addresses"][0]["address"] == "8.8.8.8"
    assert result["email_security"]["spf"]["status"] == "found"
    assert result["registration"]["registrar"] == "Example Registrar"
    assert "Cloudflare" in result["hosting_indicators"]
