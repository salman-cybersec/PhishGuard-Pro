
import pytest

from phishguard.css_sanitizer import (
    sanitize_css,
    scope_css,
)


def test_safe_css_is_preserved():
    css = """
    h1 {
        color: blue;
        font-size: 24px;
    }
    """

    result = sanitize_css(css)

    assert "color: blue" in result
    assert "font-size: 24px" in result


def test_import_rule_is_removed():
    css = """
    @import url("https://example.com/style.css");

    h1 {
        color: red;
    }
    """

    result = sanitize_css(css)

    assert "@import" not in result
    assert "color: red" in result


def test_external_url_is_removed():
    css = """
    .logo {
        background-color: red;
        background-image: url("https://example.com/image.png");
    }
    """

    result = sanitize_css(css)

    assert "background-image" not in result
    assert "background-color: red" in result


def test_expression_is_removed():
    css = """
    .box {
        color: expression(alert(1));
    }
    """

    result = sanitize_css(css)

    assert "expression" not in result


def test_unsupported_property_is_removed():
    css = """
    .box {
        color: red;
        position: fixed;
        z-index: 9999;
    }
    """

    result = sanitize_css(css)

    assert "color: red" in result
    assert "position" not in result
    assert "z-index" not in result


def test_important_declaration_is_removed():
    css = """
    .box {
        color: red !important;
    }
    """

    result = sanitize_css(css)

    assert "color" not in result


def test_at_font_face_is_removed():
    css = """
    @font-face {
        font-family: custom;
        src: url("https://example.com/font.woff");
    }
    """

    result = sanitize_css(css)

    assert "@font-face" not in result


def test_invalid_css_input():
    with pytest.raises(ValueError):
        sanitize_css(None)


def test_oversized_css_is_rejected():
    css = "a { color: red; }" * 100000

    with pytest.raises(ValueError):
        sanitize_css(css)


def test_empty_css():
    assert sanitize_css("") == ""


def test_css_selectors_are_scoped():
    css = """
    h1 {
        color: blue;
    }
    """

    result = scope_css(css)

    assert ".phishguard-preview h1" in result
    assert "color: blue" in result


def test_multiple_selectors_are_scoped():
    css = """
    h1, p {
        color: green;
    }
    """

    result = scope_css(css)

    assert ".phishguard-preview h1" in result
    assert ".phishguard-preview p" in result


def test_comma_inside_function_is_preserved():
    css = """
    :not(.first, .second) {
        color: red;
    }
    """

    result = scope_css(css)

    assert ":not(.first, .second)" in result


def test_root_selector_is_scoped():
    css = """
    body {
        color: black;
    }
    """

    result = scope_css(css)

    assert ".phishguard-preview {" in result


def test_invalid_scope_is_rejected():
    with pytest.raises(ValueError):
        scope_css(
            "h1 { color: red; }",
            scope="body; script",
        )


def test_scope_css_rejects_non_string():
    with pytest.raises(ValueError):
        scope_css(None)


def test_scoped_css_blocks_external_urls():
    css = """
    .box {
        background-image: url("https://example.com/a.png");
        color: blue;
    }
    """

    result = scope_css(css)

    assert "background-image" not in result
    assert "color: blue" in result


def test_scoped_css_removes_unsupported_at_rules():
    css = """
    @import "remote.css";

    .box {
        color: green;
    }
    """

    result = scope_css(css)

    assert "@import" not in result
    assert "color: green" in result
