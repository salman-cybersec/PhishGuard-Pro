from phishguard.website_preview import create_safe_preview


def test_javascript_links_are_removed():
    result = create_safe_preview(
        '<a href="javascript:alert(1)">Click here</a>'
    )

    assert "javascript:" not in result
    assert "alert(1)" not in result
    assert "Click here" in result


def test_comments_are_not_rendered():
    result = create_safe_preview(
        "<p>Visible text</p><!-- hidden comment -->"
    )

    assert "Visible text" in result
    assert "hidden comment" not in result


def test_dangerous_attributes_are_removed():
    result = create_safe_preview(
        '<div id="safe" onmouseover="alert(1)" '
        'style="background:url(javascript:alert(1))">'
        "Content</div>"
    )

    assert 'id="safe"' in result
    assert "onmouseover" not in result
    assert "javascript:" not in result
    assert "Content" in result


def test_imported_links_are_not_clickable():
    result = create_safe_preview(
        '<a href="https://example.com">External link</a>'
    )

    assert "https://example.com" not in result
    assert "External link" in result


def test_text_is_html_escaped():
    result = create_safe_preview(
        "<p>Test & sample</p>"
    )

    assert "Test &amp; sample" in result
