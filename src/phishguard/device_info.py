
import re


def parse_device_info(user_agent: str) -> dict:
    if not isinstance(user_agent, str):
        raise ValueError("User-Agent must be text.")

    if len(user_agent) > 500:
        raise ValueError("User-Agent is too long.")

    browser_name = "Unknown"
    browser_version = None

    browser_patterns = [
        ("Edge", r"Edg/([\d.]+)"),
        ("Opera", r"OPR/([\d.]+)"),
        ("Chrome", r"Chrome/([\d.]+)"),
        ("Firefox", r"Firefox/([\d.]+)"),
        ("Safari", r"Version/([\d.]+).*Safari"),
    ]

    for name, pattern in browser_patterns:
        match = re.search(pattern, user_agent)

        if match:
            browser_name = name
            browser_version = match.group(1)
            break

    if "Windows" in user_agent:
        os_name = "Windows"
    elif "Android" in user_agent:
        os_name = "Android"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        os_name = "iOS"
    elif "Mac OS X" in user_agent:
        os_name = "macOS"
    elif "Linux" in user_agent:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if "iPad" in user_agent or "Tablet" in user_agent:
        device_type = "tablet"
    elif "Mobile" in user_agent or "iPhone" in user_agent:
        device_type = "mobile"
    elif user_agent:
        device_type = "desktop"
    else:
        device_type = "unknown"

    return {
        "browser_name": browser_name,
        "browser_version": browser_version,
        "os_name": os_name,
        "device_type": device_type,
    }
