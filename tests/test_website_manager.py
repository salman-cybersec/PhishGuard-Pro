
from phishguard import website_manager


def test_website_asset_import(monkeypatch):
    html = """
    <html>
        <head>
            <link rel="stylesheet" href="/style.css">
        </head>
        <body>
            <img src="/images/logo.png">
        </body>
    </html>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    downloaded = []

    def fake_download(url, original_host):
        downloaded.append(url)

        return {
            "filename": "test-asset",
            "status": "downloaded",
        }

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        fake_download,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert result["status"] == "import_completed"
    assert result["assets_found"] == 2
    assert result["assets_imported"] == 2
    assert result["assets_skipped"] == 0

    assert "https://example.com/style.css" in downloaded
    assert "https://example.com/images/logo.png" in downloaded


def test_failed_asset_is_skipped(monkeypatch):
    html = """
    <html>
        <body>
            <img src="/broken.png">
        </body>
    </html>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    def fake_download(url, original_host):
        raise ValueError("Asset rejected")

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        fake_download,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert result["assets_found"] == 1
    assert result["assets_imported"] == 0
    assert result["assets_skipped"] == 1


def test_http_website_rejected():
    try:
        website_manager.import_website(
            "http://example.com"
        )
    except ValueError:
        return

    raise AssertionError("HTTP website should be rejected")

from phishguard import website_manager


def test_website_asset_import(monkeypatch):
    html = """
    <html>
        <head>
            <link rel="stylesheet" href="/style.css">
        </head>
        <body>
            <img src="/images/logo.png">
        </body>
    </html>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    downloaded = []

    def fake_download(url, original_host):
        downloaded.append(url)

        return {
            "filename": "test-asset",
            "status": "downloaded",
        }

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        fake_download,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert result["status"] == "import_completed"
    assert result["assets_found"] == 2
    assert result["assets_imported"] == 2
    assert result["assets_skipped"] == 0

    assert "https://example.com/style.css" in downloaded
    assert "https://example.com/images/logo.png" in downloaded


def test_failed_asset_is_skipped(monkeypatch):
    html = """
    <html>
        <body>
            <img src="/broken.png">
        </body>
    </html>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    def fake_download(url, original_host):
        raise ValueError("Asset rejected")

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        fake_download,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert result["assets_found"] == 1
    assert result["assets_imported"] == 0
    assert result["assets_skipped"] == 1


def test_http_website_rejected():
    try:
        website_manager.import_website(
            "http://example.com"
        )
    except ValueError:
        return

    raise AssertionError("HTTP website should be rejected")


def test_import_returns_sanitized_preview(monkeypatch):
    html = """
    <h1>Welcome</h1>
    <script>alert('unsafe')</script>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        lambda url, host: {},
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert "<h1>Welcome</h1>" in result["preview_html"]
    assert "<script" not in result["preview_html"].lower()
    assert "alert('unsafe')" not in result["preview_html"]


def test_import_preview_discloses_simulation(monkeypatch):
    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: "<h1>Test</h1>",
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert (
        "AUTHORIZED SECURITY AWARENESS SIMULATION"
        in result["preview_html"]
    )

    assert result["credentials_collected"] is False


def test_import_rejects_url_with_credentials():
    try:
        website_manager.import_website(
            "https://user:password@example.com"
        )
    except ValueError:
        return

    raise AssertionError("Credential-based URL should be rejected")
