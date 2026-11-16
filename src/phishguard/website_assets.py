
import hashlib
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

from phishguard.config import DATA_DIR


ASSET_DIR = DATA_DIR / "website_assets"
MAX_ASSET_SIZE = 5_000_000
REQUEST_TIMEOUT = 10

ALLOWED_TYPES = {
    "text/css": ".css",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
}


def _validate_asset_url(url: str, original_host: str) -> str:
    try:
        parsed = urlsplit(url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.lower() != original_host.lower()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise ValueError("Asset must use the original HTTPS domain.")

        addresses = socket.getaddrinfo(
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            raise ValueError("Asset hostname could not be resolved.")

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise ValueError("Private or local asset addresses are blocked.")

        return url

    except (ValueError, OSError, UnicodeError) as error:
        raise ValueError("Invalid asset URL.") from error


def download_asset(
    asset_url: str,
    original_host: str,
) -> dict:

    validated_url = _validate_asset_url(
        asset_url,
        original_host,
    )

    try:
        with requests.get(
            validated_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "PhishGuard-Pro-Authorized-Lab/0.1"
            },
        ) as response:

            if response.status_code != 200:
                raise ValueError("Asset could not be retrieved.")

            content_type = (
                response.headers.get("Content-Type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )

            if content_type not in ALLOWED_TYPES:
                raise ValueError("Unsupported asset file type.")

            content_length = response.headers.get("Content-Length")

            if content_length:
                try:
                    if int(content_length) > MAX_ASSET_SIZE:
                        raise ValueError("Asset exceeds the size limit.")
                except ValueError as error:
                    raise ValueError("Invalid asset size.") from error

            content = bytearray()

            for chunk in response.iter_content(chunk_size=16384):
                content.extend(chunk)

                if len(content) > MAX_ASSET_SIZE:
                    raise ValueError("Asset exceeds the size limit.")

            if not content:
                raise ValueError("Asset is empty.")

            digest = hashlib.sha256(content).hexdigest()
            extension = ALLOWED_TYPES[content_type]

            ASSET_DIR.mkdir(parents=True, exist_ok=True)

            filename = f"{digest}{extension}"
            output_path = ASSET_DIR / filename

            output_path.write_bytes(content)

            return {
                "filename": filename,
                "path": str(output_path),
                "content_type": content_type,
                "size": len(content),
                "sha256": digest,
                "status": "downloaded",
            }

    except requests.RequestException as error:
        raise RuntimeError("Unable to download website asset.") from error
