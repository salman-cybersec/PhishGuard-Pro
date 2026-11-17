
import pytest

from phishguard.website_authorization import (
    validate_website_authorization,
)


def test_authorized_https_domain_is_accepted(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    result = validate_website_authorization(
        "https://example.com/training"
    )

    assert result["authorized"] is True
    assert result["hostname"] == "example.com"


def test_unapproved_domain_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization("https://unapproved.com")


def test_http_url_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization("http://example.com")


def test_url_with_credentials_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://user:password@example.com"
        )


def test_non_standard_port_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com:8443"
        )


def test_subdomain_requires_explicit_authorization(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://sub.example.com"
        )


def test_missing_domain_configuration_is_rejected(monkeypatch):
    monkeypatch.delenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match="No authorized website domains configured",
    ):
        validate_website_authorization("https://example.com")


def test_invalid_hostname_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com.evil.org"
        )
