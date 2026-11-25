
import pytest

from phishguard.css_sanitizer import sanitize_css, scope_css


def test_safe_css_is_preserved():
    css = """
    h1 {
        color: red;
        font-size: 24px;
        text-align: center;
    }
    """

    result = sanitize_css(css)

    assert "color: red" in result
    assert "font-size: 24px" in result
    assert "text-align: center" in result


def test_import_rule_is_removed():
    css = """
    @import url("https://evil.example/style.css");

    h1 {
        color: blue;
    }
    """

    result = sanitize_css(css)

    assert "@import" not in result
    assert "evil.example" not in result
    assert "color: blue" in result


def test_external_url_is_removed():
    css = """
    .logo {
        background-color: red;
        background-image: url("https://evil.example/image.png");
    }
    """

    result = sanitize_css(css)

    assert "evil.example" not in result
    assert "background-color: red" in result


def test_unsafe_css_functions_are_removed():
    css = """
    .box {
        color: expression(alert(1));
        background-color: red;
    }
    """

    result = sanitize_css(css)

    assert "expression" not in result
    assert "background-color: red" in result


def test_unsupported_properties_are_removed():
    css = """
    .box {
        behavior: url("unsafe.htc");
        color: green;
    }
    """

    result = sanitize_css(css)

    assert "behavior" not in result
    assert "color: green" in result


def test_important_declarations_are_removed():
    css = """
    .box {
        color: red !important;
        background-color: white;
    }
    """

    result = sanitize_css(css)

    assert "color: red" not in result
    assert "background-color: white" in result


def test_invalid_css_input_rejected():
    with pytest.raises(ValueError):
        sanitize_css(None)


def test_oversized_css_rejected():
    css = " " * 1_000_001

    with pytest.raises(ValueError):
        sanitize_css(css)


def test_empty_css_returns_empty_string():
    assert sanitize_css("") == ""


def test_at_font_face_is_removed():
    css = """
    @font-face {
        font-family: "UnsafeFont";
        src: url("https://evil.example/font.woff2");
    }

    p {
        color: black;
    }
    """

    result = sanitize_css(css)

    assert "@font-face" not in result
    assert "evil.example" not in result
    assert "color: black" in result



def test_scope_css_prefixes_global_selectors():
    result = scope_css(
        "body { color: red; } html { color: blue; }"
    )
    assert ".phishguard-preview { color: red;" in result
    assert ".phishguard-preview { color: blue;" in result


def test_scope_css_keeps_valid_scoped_selector():
    result = scope_css(
        ".phishguard-preview .title { color: red; }"
    )
    assert ".phishguard-preview .title" in result


def test_scope_css_does_not_accept_scope_name_prefix():
    result = scope_css(
        ".phishguard-preview-evil { color: red; }"
    )
    assert ".phishguard-preview .phishguard-preview-evil" in result
    assert not result.startswith(".phishguard-preview-evil {")


def test_scope_css_removes_unsafe_at_rules():
    result = scope_css(
        "@import url(https://evil.example/x.css); "
        ".title { color: green; }"
    )
    assert "@import" not in result
    assert "evil.example" not in result
    assert ".phishguard-preview .title" in result
