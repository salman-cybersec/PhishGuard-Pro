
import ipaddress
import socket
from urllib.parse import urlsplit

import requests

from phishguard.website_authorization import (
    validate_website_authorization,
)

MAX_HTML_SIZE = 2_000_000
REQUEST_TIMEOUT = 10


def _validate_public_host(hostname: str) -> None:
    try:
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
                raise ValueError("Private or local addresses are blocked.")

    except OSError as error:
        raise ValueError("Website hostname could not be resolved.") from error


def analyze_website(url: str) -> str:
    authorization = validate_website_authorization(url)
    parsed = urlsplit(url)

    _validate_public_host(authorization["hostname"])

    try:
        with requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "PhishGuard-Pro-Authorized-Lab/0.1"
            },
        ) as response:

            if response.status_code != 200:
                raise ValueError("Website returned an unsuccessful response.")

            content_type = response.headers.get(
                "Content-Type", ""
            ).split(";", 1)[0].strip().lower()

            if content_type != "text/html":
                raise ValueError("Target must return an HTML page.")

            content_length = response.headers.get("Content-Length")

            if content_length:
                try:
                    if int(content_length) > MAX_HTML_SIZE:
                        raise ValueError("Website HTML exceeds the size limit.")
                except ValueError as error:
                    raise ValueError("Invalid website content size.") from error

            content = bytearray()

            for chunk in response.iter_content(chunk_size=16384):
                content.extend(chunk)

                if len(content) > MAX_HTML_SIZE:
                    raise ValueError("Website HTML exceeds the size limit.")

            if not content:
                raise ValueError("Website returned an empty HTML page.")

            encoding = response.encoding or "utf-8"
            return content.decode(encoding, errors="replace")

    except requests.RequestException as error:
        raise RuntimeError("Unable to retrieve authorized website.") from error
