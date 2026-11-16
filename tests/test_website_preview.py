
import pytest

from phishguard.website_preview import create_safe_preview


def test_preview_contains_awareness_notice():
    result = create_safe_preview("<h1>Test Website</h1>")

    assert "AUTHORIZED SECURITY AWARENESS SIMULATION" in result
    assert "No passwords or credentials" in result


def test_script_tag_is_removed():
    result = create_safe_preview(
        "<h1>Hello</h1><script>alert('test')</script>"
    )

    assert "<script" not in result.lower()
    assert "alert(" not in result
    assert "<h1>Hello</h1>" in result


def test_event_handlers_are_removed():
    result = create_safe_preview(
        '<div onclick="alert(1)">Hello</div>'
    )

    assert "onclick" not in result
    assert "alert(1)" not in result
    assert "Hello" in result


def test_forms_are_removed():
    result = create_safe_preview(
        '<form action="https://example.com">'
        '<input type="password">'
        '</form>'
    )

    assert "<form" not in result.lower()
    assert "<input" not in result.lower()


def test_external_images_are_removed():
    result = create_safe_preview(
        '<img src="https://example.com/image.png" alt="Test">'
    )

    assert "<img" not in result.lower()
    assert "https://example.com" not in result


def test_style_tags_are_removed():
    result = create_safe_preview(
        "<style>body { display:none; }</style><p>Visible</p>"
    )

    assert "<style" not in result.lower()
    assert "display:none" not in result
    assert "<p>Visible</p>" in result


def test_unsupported_tags_are_removed():
    result = create_safe_preview(
        "<iframe>Hidden</iframe><p>Visible</p>"
    )

    assert "<iframe" not in result.lower()
    assert "Visible" in result


def test_non_string_html_rejected():
    with pytest.raises(ValueError):
        create_safe_preview(123)


def test_html_size_limit():
    with pytest.raises(ValueError):
        create_safe_preview("A" * (2 * 1024 * 1024))
