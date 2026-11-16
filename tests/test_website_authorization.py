
import pytest

from phishguard.website_authorization import (
    validate_website_authorization,
)


def test_authorized_domain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    result = validate_website_authorization(
        "https://example.com/login"
    )

    assert result["authorized"] is True
    assert result["hostname"] == "example.com"
    assert result["status"] == "approved"


def test_unapproved_domain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://another-site.com"
        )


def test_http_url_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "http://example.com"
        )


def test_url_with_credentials_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://user:password@example.com"
        )


def test_nonstandard_port_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com:8080"
        )


def test_missing_allowlist_rejected(monkeypatch):
    monkeypatch.delenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        raising=False,
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com"
        )
