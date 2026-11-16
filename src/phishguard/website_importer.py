
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


MAX_PAGE_SIZE = 2_000_000
REQUEST_TIMEOUT = 10

ALLOWED_CONTENT_TYPES = {
    "text/html",
    "text/css",
}


def validate_website_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Website URL is required.")

    try:
        parsed = urlsplit(url.strip())

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("A valid HTTPS website URL is required.")

        if parsed.port not in (None, 443):
            raise ValueError("Only the standard HTTPS port is allowed.")

        hostname = parsed.hostname.encode("idna").decode("ascii").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("Localhost URLs cannot be imported.")

        addresses = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            raise ValueError("Website hostname could not be resolved.")

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise ValueError(
                    "Private, local, and reserved IP addresses are not allowed."
                )

        return url.strip()

    except (ValueError, UnicodeError, OSError) as error:
        raise ValueError("Website URL validation failed.") from error


def analyze_website(url: str) -> dict:
    validated_url = validate_website_url(url)

    try:
        response = requests.get(
            validated_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "PhishGuard-Pro-Authorized-Lab/0.1"
            },
        )

        with response:
            if response.status_code != 200:
                raise ValueError(
                    f"Website returned HTTP {response.status_code}."
                )

            content_type = (
                response.headers.get("Content-Type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )

            if content_type != "text/html":
                raise ValueError("Website did not return an HTML page.")

            content_length = response.headers.get("Content-Length")

            if content_length:
                try:
                    if int(content_length) > MAX_PAGE_SIZE:
                        raise ValueError("Website page is too large.")
                except ValueError as error:
                    raise ValueError(
                        "Invalid or oversized Content-Length."
                    ) from error

            body = bytearray()

            for chunk in response.iter_content(chunk_size=16384):
                body.extend(chunk)

                if len(body) > MAX_PAGE_SIZE:
                    raise ValueError("Website page exceeded the size limit.")

            html = bytes(body).decode(
                response.encoding or "utf-8",
                errors="replace",
            )

            return {
                "website": validated_url,
                "status_code": response.status_code,
                "content_type": content_type,
                "page_size": len(body),
                "html": html,
                "status": "analyzed",
            }

    except requests.RequestException as error:
        raise RuntimeError(
            "Unable to retrieve the authorized website."
        ) from error
