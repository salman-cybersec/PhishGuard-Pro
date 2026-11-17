
from phishguard import website_assets


VALID_PNG = b"\x89PNG\r\n\x1a\n" + b"test-image-data"


def test_asset_download_success(monkeypatch, tmp_path):
    monkeypatch.setattr(
        website_assets,
        "ASSET_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        website_assets,
        "fetch_https",
        lambda *args, **kwargs: {
            "status_code": 200,
            "headers": {"Content-Type": "image/png"},
            "content": VALID_PNG,
            "connected_ip": "8.8.8.8",
        },
    )

    result = website_assets.download_asset(
        "https://example.com/logo.png",
        "example.com",
    )

    saved_file = tmp_path / result["filename"]

    assert result["status"] == "downloaded"
    assert result["size"] == len(VALID_PNG)
    assert result["sanitized"] is False
    assert saved_file.exists()
    assert saved_file.read_bytes() == VALID_PNG


def test_different_domain_asset_rejected():
    try:
        website_assets.download_asset(
            "https://other.com/logo.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("Different domain should be rejected")


def test_http_asset_rejected():
    try:
        website_assets.download_asset(
            "http://example.com/logo.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("HTTP asset should be rejected")


def test_asset_with_credentials_rejected():
    try:
        website_assets.download_asset(
            "https://user:pass@example.com/logo.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("Credential URL should be rejected")


def test_unsupported_content_type_rejected(monkeypatch):
    monkeypatch.setattr(
        website_assets,
        "fetch_https",
        lambda *args, **kwargs: {
            "status_code": 200,
            "headers": {
                "Content-Type": "application/javascript"
            },
            "content": b"alert(1)",
            "connected_ip": "8.8.8.8",
        },
    )

    try:
        website_assets.download_asset(
            "https://example.com/script.js",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("JavaScript assets should be rejected")


def test_unsuccessful_asset_response_rejected(monkeypatch):
    monkeypatch.setattr(
        website_assets,
        "fetch_https",
        lambda *args, **kwargs: {
            "status_code": 404,
            "headers": {"Content-Type": "image/png"},
            "content": b"",
            "connected_ip": "8.8.8.8",
        },
    )

    try:
        website_assets.download_asset(
            "https://example.com/missing.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("Unsuccessful response should be rejected")


def test_empty_asset_rejected(monkeypatch):
    monkeypatch.setattr(
        website_assets,
        "fetch_https",
        lambda *args, **kwargs: {
            "status_code": 200,
            "headers": {"Content-Type": "image/png"},
            "content": b"",
            "connected_ip": "8.8.8.8",
        },
    )

    try:
        website_assets.download_asset(
            "https://example.com/empty.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("Empty asset should be rejected")


def test_invalid_image_signature_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(
        website_assets,
        "ASSET_DIR",
        tmp_path,
    )

    monkeypatch.setattr(
        website_assets,
        "fetch_https",
        lambda *args, **kwargs: {
            "status_code": 200,
            "headers": {"Content-Type": "image/png"},
            "content": b"not-a-real-png",
            "connected_ip": "8.8.8.8",
        },
    )

    try:
        website_assets.download_asset(
            "https://example.com/fake.png",
            "example.com",
        )
    except ValueError:
        return

    raise AssertionError("Invalid image signature should be rejected")
