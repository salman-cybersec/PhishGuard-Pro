import pytest

from phishguard import subdomain_discovery as discovery


@pytest.mark.parametrize("domain", [
    "localhost",
    "bad domain.com",
    "-invalid.com",
    "example..com",
    "*.example.com",
])
def test_invalid_domains_rejected(domain):
    with pytest.raises(ValueError):
        discovery._validate_domain(domain)


def test_domain_normalization():
    assert discovery._validate_domain("Example.COM.") == "example.com"


def test_extracts_valid_subdomains_and_removes_duplicates():
    entries = [
        {"name_value": "www.example.com\n*.mail.example.com"},
        {"name_value": "www.example.com\nexample.com"},
        {"name_value": "evil-example.com\nnotexample.com"},
        {"name_value": "bad name.example.com"},
    ]

    result = discovery._extract_subdomains("example.com", entries)

    assert sorted(result) == ["mail.example.com", "www.example.com"]
    assert result["www.example.com"] == {"Certificate Transparency"}


def test_rejects_unrelated_and_invalid_entries():
    result = discovery._extract_subdomains(
        "example.com",
        [
            None,
            {"name_value": 123},
            {"name_value": "attacker.com\nfoo.example.org"},
        ],
    )
    assert result == {}


def test_discovery_result(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "_query_certificate_transparency",
        lambda domain: {
            "status": "found",
            "records": [{"name_value": "www.example.com\napi.example.com"}],
        },
    )
    monkeypatch.setattr(
        discovery,
        "_resolve_subdomain",
        lambda hostname: {
            "A": ["8.8.8.8"] if hostname.startswith("www") else [],
            "AAAA": [],
            "status": "resolved" if hostname.startswith("www") else "not_resolved",
        },
    )

    result = discovery.discover_subdomains("example.com")

    assert result["total_discovered"] == 2
    assert result["total_resolved"] == 1
    assert result["subdomains"][0]["hostname"] == "api.example.com"


def test_ct_failure_returns_unavailable(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "_query_certificate_transparency",
        lambda domain: {"status": "unavailable", "records": []},
    )

    result = discovery.discover_subdomains("example.com")

    assert result["source_status"] == "unavailable"
    assert result["subdomains"] == []


def test_discovery_respects_processing_limit_and_reports_truncation(monkeypatch):
    from phishguard import subdomain_discovery as discovery

    discovered = {
        f"host{i}.example.com": {"crt.sh"}
        for i in range(1, 5)
    }
    processed = []

    monkeypatch.setattr(
        discovery,
        "_query_certificate_transparency",
        lambda domain: {"status": "found", "records": []},
    )
    monkeypatch.setattr(
        discovery,
        "_extract_subdomains",
        lambda domain, records: discovered,
    )

    def fake_resolve(hostname):
        processed.append(hostname)
        return {"status": "resolved", "addresses": ["8.8.8.8"]}

    monkeypatch.setattr(discovery, "_resolve_subdomain", fake_resolve)

    result = discovery.discover_subdomains(
        "example.com",
        max_subdomains=2,
    )

    assert result["total_discovered"] == 4
    assert result["total_processed"] == 2
    assert result["total_resolved"] == 2
    assert result["total_unresolved"] == 0
    assert result["truncated"] is True
    assert processed == sorted(discovered)[:2]


def test_discovery_counts_unresolved_subdomains(monkeypatch):
    from phishguard import subdomain_discovery as discovery

    discovered = {
        "a.example.com": {"crt.sh"},
        "b.example.com": {"crt.sh"},
        "c.example.com": {"crt.sh"},
    }

    monkeypatch.setattr(
        discovery,
        "_query_certificate_transparency",
        lambda domain: {"status": "found", "records": []},
    )
    monkeypatch.setattr(
        discovery,
        "_extract_subdomains",
        lambda domain, records: discovered,
    )
    monkeypatch.setattr(
        discovery,
        "_resolve_subdomain",
        lambda hostname: {
            "status": "resolved" if hostname.startswith("a.") else "unresolved",
            "addresses": ["8.8.8.8"] if hostname.startswith("a.") else [],
        },
    )

    result = discovery.discover_subdomains(
        "example.com",
        max_subdomains=3,
    )

    assert result["total_processed"] == 3
    assert result["total_resolved"] == 1
    assert result["total_unresolved"] == 2
    assert result["truncated"] is False


@pytest.mark.parametrize("limit", [0, -1, 501, True, 50.0])
def test_discovery_rejects_invalid_processing_limits(limit):
    from phishguard import subdomain_discovery as discovery

    with pytest.raises(ValueError):
        discovery.discover_subdomains(
            "example.com",
            max_subdomains=limit,
        )
