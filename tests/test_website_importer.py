import pytest

from phishguard import website_importer


def test_unauthorized_domain_rejected(monkeypatch):
    def reject_authorization(url):
        raise ValueError("Unauthorized domain")

    def unexpected_fetch(**kwargs):
        raise AssertionError(
            "Unauthorized website must not be fetched."
        )

    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        reject_authorization,
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        unexpected_fetch,
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )


def test_non_html_response_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "content": b'{"message": "test"}',
        },
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )


def test_redirect_response_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 302,
            "headers": {
                "Location": "https://another-site.com"
            },
            "content": b"",
        },
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )


def test_empty_html_response_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "content": b"",
        },
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )


def test_html_response_decoded(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html; charset=utf-8"
            },
            "content": "<h1>Authorized Lab</h1>".encode("utf-8"),
        },
    )

    result = website_importer.analyze_website(
        "https://example.com"
    )

    assert result == "<h1>Authorized Lab</h1>"


def test_invalid_charset_uses_utf8_fallback(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html; charset=invalid-encoding"
            },
            "content": b"<h1>Fallback</h1>",
        },
    )

    result = website_importer.analyze_website(
        "https://example.com"
    )

    assert result == "<h1>Fallback</h1>"


def test_fetch_uses_authorized_hostname_and_size_limit(monkeypatch):
    calls = []

    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    def fake_fetch(**kwargs):
        calls.append(kwargs)

        return {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "content": b"<h1>Safe</h1>",
        }

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        fake_fetch,
    )

    website_importer.analyze_website(
        "https://example.com"
    )

    assert calls[0]["expected_host"] == "example.com"
    assert calls[0]["max_bytes"] == website_importer.MAX_HTML_SIZE


def test_wrong_authorized_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "other.com"},
    )

    monkeypatch.setattr(
        website_importer,
        "fetch_https",
        lambda **kwargs: {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "content": b"<h1>Test</h1>",
        },
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )
