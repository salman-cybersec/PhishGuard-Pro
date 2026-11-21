from phishguard.website_preview import create_safe_preview


def test_preview_removes_event_handler_attributes():
    result = create_safe_preview(
        '<div onclick="alert(1)" onmouseover="alert(2)">Safe</div>'
    )

    assert "onclick" not in result.lower()
    assert "onmouseover" not in result.lower()
    assert "Safe" in result


def test_preview_removes_iframe_content():
    result = create_safe_preview(
        '<iframe src="https://example.com">'
        "unsafe content"
        "</iframe>"
        "<p>Safe content</p>"
    )

    assert "<iframe" not in result.lower()
    assert "unsafe content" not in result
    assert "Safe content" in result


def test_preview_escapes_attribute_values():
    result = create_safe_preview(
        '<p title="&quot; onmouseover=&quot;alert(1)">Safe</p>'
    )

    assert 'onmouseover="alert(1)"' not in result
    assert "<p" in result


def test_preview_rejects_non_string_asset_mapping_values():
    result = create_safe_preview(
        '<img src="/logo.png">',
        asset_map={"/logo.png": 123},
    )

    assert "<img" in result
    assert "src=" not in result
