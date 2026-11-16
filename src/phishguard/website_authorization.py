import os
from urllib.parse import urlsplit


def get_allowed_domains() -> set:
    configured = os.getenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS", ""
    )

    return {
        domain.strip().lower()
        for domain in configured.split(",")
        if domain.strip()
    }


def validate_website_authorization(url: str) -> dict:
    try:
        parsed = urlsplit(url)

        if parsed.scheme != "https":
            raise ValueError("Only HTTPS websites are allowed.")

        if not parsed.hostname:
            raise ValueError("Website hostname is missing.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are blocked.")

        if parsed.port not in (None, 443):
            raise ValueError("Only the standard HTTPS port is allowed.")

        hostname = parsed.hostname.lower().rstrip(".")

        allowed_domains = get_allowed_domains()

        if not allowed_domains:
            raise ValueError("No authorized website domains configured.")

        if hostname not in allowed_domains:
            raise ValueError("Website is not in the authorized domain list.")

        return {
            "authorized": True,
            "hostname": hostname,
            "status": "approved",
        }

    except (ValueError, UnicodeError) as error:
        raise ValueError(str(error)) from error
