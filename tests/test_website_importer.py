
import pytest

from phishguard import website_importer


def test_unauthorized_domain_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: (_ for _ in ()).throw(
            ValueError("Unauthorized domain")
        ),
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )


def test_private_address_rejected(monkeypatch):
    monkeypatch.setattr(
        website_importer,
        "validate_website_authorization",
        lambda url: {"hostname": "example.com"},
    )

    monkeypatch.setattr(
        website_importer.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("127.0.0.1", 443))
        ],
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
        "_validate_public_host",
        lambda hostname: None,
    )

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        website_importer.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
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
        "_validate_public_host",
        lambda hostname: None,
    )

    class FakeResponse:
        status_code = 302
        headers = {"Location": "https://another-site.com"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        website_importer.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(ValueError):
        website_importer.analyze_website(
            "https://example.com"
        )
