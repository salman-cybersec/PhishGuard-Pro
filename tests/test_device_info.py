
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
    assert result["os_name"] == "Windows"


def test_firefox_browser():
    result = parse_device_info(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "Gecko/20100101 Firefox/121.0"
    )

    assert result["browser_name"] == "Firefox"
    assert result["browser_version"] == "121.0"


def test_safari_browser():
    result = parse_device_info(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "Version/17.0 Safari/605.1.15"
    )

    assert result["browser_name"] == "Safari"
    assert result["browser_version"] == "17.0"
    assert result["os_name"] == "macOS"


def test_opera_browser():
    result = parse_device_info(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "Chrome/120.0.0.0 OPR/106.0.0.0"
    )

    assert result["browser_name"] == "Opera"
    assert result["browser_version"] == "106.0.0.0"


def test_samsung_internet_browser():
    result = parse_device_info(
        "Mozilla/5.0 (Linux; Android 13) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 "
        "SamsungBrowser/23.0 Mobile Safari/537.36"
    )

    assert result["browser_name"] == "Samsung Internet"
    assert result["browser_version"] == "23.0"
    assert result["os_name"] == "Android"
    assert result["device_type"] == "mobile"


def test_android_mobile():
    result = parse_device_info(
        "Mozilla/5.0 (Linux; Android 13; Mobile)"
    )

    assert result["os_name"] == "Android"
    assert result["device_type"] == "mobile"


def test_android_tablet():
    result = parse_device_info(
        "Mozilla/5.0 (Linux; Android 13; Tablet)"
    )

    assert result["os_name"] == "Android"
    assert result["device_type"] == "tablet"


def test_iphone_device():
    result = parse_device_info(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
    )

    assert result["os_name"] == "iOS"
    assert result["device_type"] == "mobile"


def test_ipad_tablet():
    result = parse_device_info(
        "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)"
    )

    assert result["os_name"] == "iOS"
    assert result["device_type"] == "tablet"


def test_linux_desktop():
    result = parse_device_info(
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
    )

    assert result["os_name"] == "Linux"
    assert result["device_type"] == "desktop"


def test_unknown_user_agent():
    result = parse_device_info("")

    assert result["browser_name"] == "Unknown"
    assert result["browser_version"] is None
    assert result["os_name"] == "Unknown"
    assert result["device_type"] == "unknown"


def test_invalid_user_agent_type():
    with pytest.raises(ValueError):
        parse_device_info(123)


def test_user_agent_length_limit():
    with pytest.raises(ValueError):
        parse_device_info("A" * 501)
