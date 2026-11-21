import pytest

from phishguard import full_scan


@pytest.fixture
def base_result():
    return {
        "url": "https://example.com",
        "hostname": "example.com",
        "http_status": 200,
        "tls": {},
        "headers": {},
        "technologies": {},
        "cookie_security": {
            "cookies": [],
            "count": 0,
            "findings": [],
        },
        "findings": [],
    }


@pytest.fixture
def mock_scan_dependencies(monkeypatch, base_result):
    calls = {}

    monkeypatch.setattr(
        full_scan,
        "analyze_website",
        lambda url: dict(base_result),
    )
    monkeypatch.setattr(
        full_scan,
        "analyze_dns_security",
        lambda hostname: {"checks": [], "findings": []},
    )
    monkeypatch.setattr(
        full_scan,
        "calculate_security_score",
        lambda findings: {"score": 100, "grade": "A"},
    )

    def fake_discovery(hostname, max_subdomains):
        calls["hostname"] = hostname
        calls["max_subdomains"] = max_subdomains
        return {
            "domain": hostname,
            "source_status": "found",
            "max_subdomains": max_subdomains,
            "total_discovered": 12,
            "total_processed": 12,
            "total_resolved": 10,
            "total_unresolved": 2,
            "truncated": False,
            "subdomains": [],
            "source": "Test fixture",
        }

    monkeypatch.setattr(
        full_scan,
        "discover_subdomains",
        fake_discovery,
    )
    return calls


@pytest.mark.parametrize(
    ("mode", "expected_limit"),
    [
        ("fast", 50),
        ("extended", 200),
        ("thorough", 500),
    ],
)
def test_scan_modes_apply_expected_subdomain_limits(
    mode,
    expected_limit,
    mock_scan_dependencies,
):
    result = full_scan.analyze_full_website(
        "https://example.com",
        scan_mode=mode,
    )

    assert mock_scan_dependencies["hostname"] == "example.com"
    assert mock_scan_dependencies["max_subdomains"] == expected_limit
    assert result["scan_mode"] == mode
    assert result["subdomain_limit"] == expected_limit


def test_full_scan_includes_subdomain_statistics(mock_scan_dependencies):
    result = full_scan.analyze_full_website("https://example.com")

    subdomains = result["checks"]["subdomains"]

    assert result["scan_mode"] == "fast"
    assert subdomains["total_discovered"] == 12
    assert subdomains["total_processed"] == 12
    assert subdomains["total_resolved"] == 10
    assert subdomains["total_unresolved"] == 2
    assert subdomains["truncated"] is False


def test_invalid_scan_mode_is_rejected(monkeypatch):
    called = False

    def unexpected_call(url):
        nonlocal called
        called = True
        raise AssertionError("Website analysis should not run.")

    monkeypatch.setattr(full_scan, "analyze_website", unexpected_call)

    with pytest.raises(ValueError, match="scan_mode"):
        full_scan.analyze_full_website(
            "https://example.com",
            scan_mode="invalid",
        )

    assert called is False


def test_unavailable_subdomain_discovery_is_preserved(
    monkeypatch,
    base_result,
):
    monkeypatch.setattr(
        full_scan,
        "analyze_website",
        lambda url: dict(base_result),
    )
    monkeypatch.setattr(
        full_scan,
        "analyze_dns_security",
        lambda hostname: {"checks": [], "findings": []},
    )
    monkeypatch.setattr(
        full_scan,
        "calculate_security_score",
        lambda findings: {"score": 100, "grade": "A"},
    )
    monkeypatch.setattr(
        full_scan,
        "discover_subdomains",
        lambda hostname, max_subdomains: {
            "domain": hostname,
            "source_status": "unavailable",
            "max_subdomains": max_subdomains,
            "total_discovered": 0,
            "total_processed": 0,
            "total_resolved": 0,
            "total_unresolved": 0,
            "truncated": False,
            "subdomains": [],
            "source": "Certificate Transparency via crt.sh",
        },
    )

    result = full_scan.analyze_full_website("https://example.com")

    assert result["checks"]["subdomains"]["source_status"] == "unavailable"
    assert result["scan_mode"] == "fast"
