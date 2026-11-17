
import re

import pytest

from phishguard.website_preview import (
    create_safe_preview,
    save_safe_preview,
)


def test_preview_contains_simulation_disclosure():
    result = create_safe_preview("<h1>Training</h1>")

    assert (
        "AUTHORIZED SECURITY AWARENESS SIMULATION"
        in result
    )


def test_preview_removes_javascript():
    result = create_safe_preview(
        "<script>alert('unsafe')</script>"
    )

    assert "<script" not in result.lower()
    assert "alert('unsafe')" not in result


def test_preview_removes_forms():
    result = create_safe_preview(
        '<form action="https://example.com">'
        '<input name="password">'
        "</form>"
    )

    assert "<form" not in result.lower()
    assert "<input" not in result.lower()


def test_preview_escapes_html_text():
    result = create_safe_preview(
        "<p>Safe text</p>"
    )

    assert "<p>Safe text</p>" in result


def test_preview_rejects_non_string_html():
    with pytest.raises(ValueError):
        create_safe_preview(None)


def test_preview_rejects_oversized_html():
    html = "<p>" + ("A" * (2 * 1024 * 1024)) + "</p>"

    with pytest.raises(ValueError):
        create_safe_preview(html)


def test_preview_rejects_invalid_asset_mapping():
    with pytest.raises(ValueError):
        create_safe_preview(
            "<img src='/logo.png'>",
            asset_map="invalid",
        )


def test_preview_connects_valid_local_image():
    filename = "a" * 64 + ".png"

    result = create_safe_preview(
        '<img src="/logo.png">',
        asset_map={
            "/logo.png": f"/assets/{filename}"
        },
    )

    assert f'src="/assets/{filename}"' in result


def test_preview_rejects_external_image():
    result = create_safe_preview(
        '<img src="https://example.com/logo.png">'
    )

    assert "https://example.com/logo.png" not in result


def test_preview_rejects_invalid_local_image_path():
    result = create_safe_preview(
        '<img src="/logo.png">',
        asset_map={
            "/logo.png": "/assets/../../secret.png"
        },
    )

    assert "/assets/../../secret.png" not in result


def test_preview_connects_valid_css_file():
    filename = "a" * 64 + ".css"

    result = create_safe_preview(
        "<h1>Training</h1>",
        css_files=[filename],
    )

    assert (
        f'href="/assets/{filename}"'
        in result
    )


def test_preview_rejects_invalid_css_filename():
    result = create_safe_preview(
        "<h1>Training</h1>",
        css_files=["../../malicious.css"],
    )

    assert "../../malicious.css" not in result
    assert "malicious.css" not in result


def test_preview_rejects_non_list_css_files():
    with pytest.raises(ValueError):
        create_safe_preview(
            "<h1>Training</h1>",
            css_files="malicious.css",
        )


def test_preview_removes_duplicate_css_files():
    filename = "b" * 64 + ".css"

    result = create_safe_preview(
        "<h1>Training</h1>",
        css_files=[filename, filename],
    )

    assert result.count(
        f'href="/assets/{filename}"'
    ) == 1


def test_preview_content_is_inside_scoped_wrapper():
    result = create_safe_preview(
        "<h1>Training</h1>"
    )

    assert '<div class="phishguard-preview">' in result
    assert "</div>" in result


def test_preview_does_not_execute_imported_javascript():
    html = """
    <script>
        document.location = "https://example.com";
    </script>
    <h1>Training</h1>
    """

    result = create_safe_preview(html)

    assert "<script" not in result.lower()
    assert "document.location" not in result
    assert "<h1>Training</h1>" in result


def test_saved_preview_has_random_id(tmp_path, monkeypatch):
    from phishguard import website_preview

    monkeypatch.setattr(
        website_preview,
        "PREVIEW_DIR",
        tmp_path,
    )

    result = save_safe_preview(
        "<h1>Training</h1>"
    )

    assert re.fullmatch(
        r"[A-Za-z0-9_-]{24}",
        result["preview_id"],
    )

    assert result["status"] == "saved"
    assert (tmp_path / result["filename"]).is_file()
