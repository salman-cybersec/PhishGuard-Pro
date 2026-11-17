
import pytest

from phishguard.website_manager import _resolve_asset_url


BASE_URL = "https://example.com/index.html"


def test_resolves_relative_asset_url():
    result = _resolve_asset_url(
        BASE_URL,
        "images/logo.png",
    )

    assert result == "https://example.com/images/logo.png"


def test_resolves_root_relative_asset_url():
    result = _resolve_asset_url(
        BASE_URL,
        "/images/logo.png",
    )

    assert result == "https://example.com/images/logo.png"


def test_resolves_same_host_https_url():
    result = _resolve_asset_url(
        BASE_URL,
        "https://example.com/style.css",
    )

    assert result == "https://example.com/style.css"


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "   ",
        None,
        "http://example.com/image.png",
        "https://example.com:8443/image.png",
        "https://user:password@example.com/image.png",
        "javascript:alert(1)",
        "data:image/png;base64,AAAA",
        "https://[invalid/image.png",
    ],
)
def test_rejects_invalid_asset_references(reference):
    with pytest.raises(ValueError):
        _resolve_asset_url(BASE_URL, reference)


def test_external_https_url_is_resolved_but_not_authorized():
    result = _resolve_asset_url(
        BASE_URL,
        "https://other-example.com/image.png",
    )

    assert result == "https://other-example.com/image.png"


def test_rejects_invalid_base_url():
    with pytest.raises(ValueError):
        _resolve_asset_url(
            "not-a-valid-url",
            "image.png",
        )
