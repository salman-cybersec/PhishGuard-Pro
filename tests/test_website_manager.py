
from pathlib import Path

import pytest

from phishguard import website_manager
from phishguard.website_preview import create_safe_preview


@pytest.fixture
def fake_preview_storage(monkeypatch, tmp_path):
    def save_preview(html):
        safe_html = create_safe_preview(html)
        output = tmp_path / "preview.html"
        output.write_text(safe_html, encoding="utf-8")

        return {
            "preview_id": "test-preview",
            "filename": "preview.html",
            "path": str(output),
            "size": output.stat().st_size,
            "status": "saved",
        }

    monkeypatch.setattr(
        website_manager,
        "save_safe_preview",
        save_preview,
    )


def test_website_asset_import(monkeypatch, fake_preview_storage):
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


def test_failed_asset_is_skipped(monkeypatch, fake_preview_storage):
    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: '<img src="/broken.png">',
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
    with pytest.raises(ValueError):
        website_manager.import_website(
            "http://example.com"
        )


def test_import_saves_sanitized_preview(
    monkeypatch,
    fake_preview_storage,
):
    html = """
    <h1>Welcome</h1>
    <script>alert('unsafe')</script>
    """

    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: html,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    saved_preview = Path(
        result["preview_path"]
    ).read_text(encoding="utf-8")

    assert "<h1>Welcome</h1>" in saved_preview
    assert "<script" not in saved_preview.lower()
    assert "alert('unsafe')" not in saved_preview


def test_import_preview_discloses_simulation(
    monkeypatch,
    fake_preview_storage,
):
    monkeypatch.setattr(
        website_manager,
        "analyze_website",
        lambda url: "<h1>Training</h1>",
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    saved_preview = Path(
        result["preview_path"]
    ).read_text(encoding="utf-8")

    assert (
        "AUTHORIZED SECURITY AWARENESS SIMULATION"
        in saved_preview
    )

    assert result["credentials_collected"] is False
    assert result["javascript_executed"] is False


def test_import_rejects_url_with_credentials():
    with pytest.raises(ValueError):
        website_manager.import_website(
            "https://user:password@example.com"
        )


def test_duplicate_assets_are_downloaded_once(
    monkeypatch,
    fake_preview_storage,
):
    html = """
    <html>
        <body>
            <img src="/logo.png">
            <img src="/logo.png">
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
        return {"filename": "logo.png"}

    monkeypatch.setattr(
        website_manager,
        "download_asset",
        fake_download,
    )

    result = website_manager.import_website(
        "https://example.com"
    )

    assert len(downloaded) == 1
    assert result["unique_assets_found"] == 1
    assert result["assets_imported"] == 1
