
import ipaddress
import os
import re
from urllib.parse import urlsplit


DOMAIN_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname:
        raise ValueError("Invalid hostname.")

    hostname = hostname.strip().rstrip(".")

    if not hostname or any(
        char in hostname
        for char in ("/", "\\", "@", ":", "*", " ")
    ):
        raise ValueError("Invalid hostname.")

    try:
        return ipaddress.ip_address(hostname).compressed.lower()
    except ValueError:
        pass

    try:
        normalized = hostname.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise ValueError("Invalid internationalized hostname.") from error

    if len(normalized) > 253:
        raise ValueError("Hostname is too long.")

    labels = normalized.split(".")

    if len(labels) < 2:
        raise ValueError("A fully qualified domain name is required.")

    if any(
        not DOMAIN_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise ValueError("Invalid domain name.")

    return normalized


def get_allowed_domains() -> set:
    configured = os.getenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "",
    )

    domains = set()

    for entry in configured.split(","):
        entry = entry.strip()

        if not entry:
            continue

        domains.add(_normalize_hostname(entry))

    return domains


def validate_website_authorization(url: str) -> dict:
    if not isinstance(url, str) or not url:
        raise ValueError("A valid website URL is required.")

    if any(ord(char) < 32 for char in url) or "\\" in url:
        raise ValueError("Website URL contains invalid characters.")

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS websites are allowed.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("Website hostname is missing.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are blocked.")

        if parsed.port not in (None, 443):
            raise ValueError("Only the standard HTTPS port is allowed.")

        hostname = _normalize_hostname(parsed.hostname)

        allowed_domains = get_allowed_domains()

        if not allowed_domains:
            raise ValueError(
                "No authorized website domains configured."
            )

        if hostname not in allowed_domains:
            raise ValueError(
                "Website is not in the authorized domain list."
            )

        return {
            "authorized": True,
            "hostname": hostname,
            "status": "approved",
        }

    except (ValueError, UnicodeError) as error:
        raise ValueError(str(error)) from error
