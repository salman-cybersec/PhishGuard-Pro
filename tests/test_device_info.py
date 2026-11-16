
import pytest

from phishguard.device_info import parse_device_info


def test_chrome_on_windows():
    result = parse_device_info(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    )

    assert result["browser_name"] == "Chrome"
    assert result["browser_version"] == "120.0.0.0"
    assert result["os_name"] == "Windows"
    assert result["device_type"] == "desktop"


def test_edge_browser():
    result = parse_device_info(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0"
    )

    assert result["browser_name"] == "Edge"
    assert result["browser_version"] == "120.0"


def test_android_mobile():
    result = parse_device_info(
        "Mozilla/5.0 (Linux; Android 13; Mobile)"
    )

    assert result["os_name"] == "Android"
    assert result["device_type"] == "mobile"


def test_ipad_tablet():
    result = parse_device_info(
        "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)"
    )

    assert result["os_name"] == "iOS"
    assert result["device_type"] == "tablet"


def test_unknown_user_agent():
    result = parse_device_info("")

    assert result["browser_name"] == "Unknown"
    assert result["os_name"] == "Unknown"
    assert result["device_type"] == "unknown"


def test_invalid_user_agent_type():
    with pytest.raises(ValueError):
        parse_device_info(123)


def test_user_agent_length_limit():
    with pytest.raises(ValueError):
        parse_device_info("A" * 501)
