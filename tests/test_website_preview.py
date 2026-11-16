
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

def test_javascript_links_are_removed():
    result = create_safe_preview(
        '<a href="javascript:alert(1)">Click</a>'
    )

    assert "javascript:" not in result
    assert "alert(1)" not in result
    assert "Click" in result


def test_data_attributes_are_removed():
    result = create_safe_preview(
        '<div data-secret="123" onclick="alert(1)">Safe text</div>'
    )

    assert "data-secret" not in result
    assert "onclick" not in result
    assert "123" not in result
    assert "Safe text" in result


def test_html_comments_are_not_rendered():
    result = create_safe_preview(
        "<!-- hidden comment --><p>Visible content</p>"
    )

    assert "hidden comment" not in result
    assert "Visible content" in result


def test_nested_script_content_is_removed():
    result = create_safe_preview(
        "<script><script>alert(1)</script>"
        "<p>Hidden content</p></script>"
        "<p>Visible content</p>"
    )

    assert "alert(1)" not in result
    assert "Hidden content" not in result
    assert "Visible content" in result


def test_external_links_are_not_preserved():
    result = create_safe_preview(
        '<a href="https://example.com">External link</a>'
    )

    assert "https://example.com" not in result
    assert "External link" in result


def test_html_size_limit():
    with pytest.raises(ValueError):
        create_safe_preview("A" * (2 * 1024 * 1024))
