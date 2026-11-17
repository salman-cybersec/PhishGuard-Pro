
import pytest

from phishguard.website_authorization import (
    get_allowed_domains,
    validate_website_authorization,
)


def test_authorizes_exact_domain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    result = validate_website_authorization(
        "https://example.com"
    )

    assert result["authorized"] is True
    assert result["hostname"] == "example.com"


def test_rejects_unauthorized_subdomain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://shop.example.com"
        )


def test_rejects_domain_suffix_bypass(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com.attacker.test"
        )


def test_normalizes_uppercase_domain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "EXAMPLE.COM",
    )

    result = validate_website_authorization(
        "https://example.com"
    )

    assert result["hostname"] == "example.com"


def test_normalizes_trailing_dot(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    result = validate_website_authorization(
        "https://example.com."
    )

    assert result["authorized"] is True


def test_rejects_empty_allowlist(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(
            "https://example.com"
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://user@example.com",
        "https://user:password@example.com",
        "https://example.com:8443",
        "https://example.com:444",
        "https://",
        "not-a-url",
        "",
        None,
        "https://example.com\\@attacker.test",
    ],
)
def test_rejects_unsafe_urls(monkeypatch, url):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com",
    )

    with pytest.raises(ValueError):
        validate_website_authorization(url)


def test_rejects_wildcard_allowlist(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "*.example.com",
    )

    with pytest.raises(ValueError):
        get_allowed_domains()


def test_rejects_invalid_domain_label(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "-example.com",
    )

    with pytest.raises(ValueError):
        get_allowed_domains()


def test_normalizes_idna_domain(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "xn--bcher-kva.example",
    )

    result = validate_website_authorization(
        "https://bücher.example"
    )

    assert result["hostname"] == "xn--bcher-kva.example"


def test_returns_all_configured_domains(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "example.com, shop.example.org",
    )

    result = get_allowed_domains()

    assert result == {
        "example.com",
        "shop.example.org",
    }
