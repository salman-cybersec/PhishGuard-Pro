import pytest

from phishguard import security_analyzer as analyzer


def test_valid_https_url():
    parsed, hostname = analyzer.validate_target_url(
        "https://example.com"
    )
    assert hostname == "example.com"
    assert parsed.scheme == "https"


@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://127.0.0.1",
    "https://user:pass@example.com",
    "https://example.com:8443",
    "javascript:alert(1)",
])
def test_invalid_urls_rejected(url):
    with pytest.raises(ValueError):
        analyzer.validate_target_url(url)


def test_security_headers_detected():
    result = analyzer.analyze_security_headers({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    })

    assert "HSTS" in result["present"]
    assert "CSP" in result["present"]
    assert "X-Frame-Options" in result["missing"]


def test_all_security_headers_present():
    headers = {
        key: "test"
        for key in analyzer.SECURITY_HEADERS
    }

    result = analyzer.analyze_security_headers(headers)

    assert result["missing"] == []
    assert result["findings"] == []


def test_website_analysis_success(monkeypatch):
    monkeypatch.setattr(
        analyzer,
        "resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        analyzer,
        "inspect_tls",
        lambda hostname, addresses: {
            "valid": True,
            "version": "TLSv1.3",
            "expires_at": "2027-01-01T00:00:00+00:00",
            "days_remaining": 100,
        },
    )

    monkeypatch.setattr(
        analyzer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin",
                "Permissions-Policy": "camera=()",
            },
            "content": b"test",
            "connected_ip": "8.8.8.8",
        },
    )

    result = analyzer.analyze_website(
        "https://example.com"
    )

    assert result["hostname"] == "example.com"
    assert result["http_status"] == 200
    assert result["risk_level"] == "low"
    assert result["summary"]["total"] == 0


def test_redirect_is_not_followed(monkeypatch):
    monkeypatch.setattr(
        analyzer,
        "resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        analyzer,
        "inspect_tls",
        lambda hostname, addresses: {
            "valid": True,
            "version": "TLSv1.3",
            "expires_at": None,
            "days_remaining": None,
        },
    )

    monkeypatch.setattr(
        analyzer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 302,
            "headers": {"Location": "https://other.example"},
            "content": b"",
            "connected_ip": "8.8.8.8",
        },
    )

    with pytest.raises(RuntimeError, match="redirect"):
        analyzer.analyze_website("https://example.com")


def test_dns_failure_stops_analysis(monkeypatch):
    monkeypatch.setattr(
        analyzer,
        "resolve_public_addresses",
        lambda hostname: (_ for _ in ()).throw(
            ValueError("DNS failure")
        ),
    )

    with pytest.raises(ValueError, match="DNS failure"):
        analyzer.analyze_website("https://example.com")
