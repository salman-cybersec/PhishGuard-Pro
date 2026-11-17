
import re


MAX_USER_AGENT_LENGTH = 500


def parse_device_info(user_agent: str) -> dict:
    if not isinstance(user_agent, str):
        raise ValueError("User-Agent must be text.")

    if len(user_agent) > MAX_USER_AGENT_LENGTH:
        raise ValueError("User-Agent is too long.")

    user_agent = user_agent.strip()

    if not user_agent:
        return {
            "browser_name": "Unknown",
            "browser_version": None,
            "os_name": "Unknown",
            "device_type": "unknown",
        }

    browser_name = "Unknown"
    browser_version = None

    browser_patterns = [
        ("Edge", r"EdgA?/([\d.]+)"),
        ("Opera", r"OPR/([\d.]+)"),
        ("Samsung Internet", r"SamsungBrowser/([\d.]+)"),
        ("Brave", r"Brave/([\d.]+)"),
        ("Firefox", r"Firefox/([\d.]+)"),
        ("Chrome", r"Chrome/([\d.]+)"),
        ("Safari", r"Version/([\d.]+).*Safari"),
    ]

    for name, pattern in browser_patterns:
        match = re.search(pattern, user_agent, re.IGNORECASE)

        if match:
            browser_name = name
            browser_version = match.group(1)
            break

    if "iPhone" in user_agent or "iPad" in user_agent:
        os_name = "iOS"
    elif "Android" in user_agent:
        os_name = "Android"
    elif "Windows" in user_agent:
        os_name = "Windows"
    elif "Mac OS X" in user_agent or "Macintosh" in user_agent:
        os_name = "macOS"
    elif "Linux" in user_agent:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if (
        "iPad" in user_agent
        or "Tablet" in user_agent
        or (
            "Android" in user_agent
            and "Mobile" not in user_agent
        )
    ):
        device_type = "tablet"

    elif (
        "Mobile" in user_agent
        or "iPhone" in user_agent
        or "Android" in user_agent
    ):
        device_type = "mobile"

    elif (
        "Windows" in user_agent
        or "Macintosh" in user_agent
        or "Linux" in user_agent
    ):
        device_type = "desktop"

    else:
        device_type = "unknown"

    return {
        "browser_name": browser_name,
        "browser_version": browser_version,
        "os_name": os_name,
        "device_type": device_type,
    }
