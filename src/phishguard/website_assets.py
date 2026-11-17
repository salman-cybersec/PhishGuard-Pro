
import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from phishguard.config import DATA_DIR
from phishguard.safe_http import fetch_https
from phishguard.css_sanitizer import sanitize_css, scope_css


ASSET_DIR = DATA_DIR / "website_assets"
MAX_ASSET_SIZE = 5_000_000

ALLOWED_TYPES = {
    "text/css": ".css",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}

IMAGE_SIGNATURES = {
    ".png": lambda data: data.startswith(
        b"\x89PNG\r\n\x1a\n"
    ),
    ".jpg": lambda data: data.startswith(
        b"\xff\xd8\xff"
    ),
    ".webp": lambda data: (
        len(data) >= 12
        and data[0:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    ),
}


def _validate_asset_url(url, original_host):
    if not isinstance(url, str) or not isinstance(original_host, str):
        raise ValueError("Invalid asset URL or original host")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid asset URL") from exc

    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS assets are allowed")

    if not hostname or hostname.lower().rstrip(".") != original_host.lower().rstrip("."):
        raise ValueError("Asset host is not authorized")

    if parsed.username or parsed.password:
        raise ValueError("Asset URL credentials are not allowed")

    if port not in (None, 443):
        raise ValueError("Only HTTPS port 443 is allowed")

    if parsed.fragment:
        raise ValueError("Asset URL fragments are not allowed")

    return hostname.lower().rstrip(".")


def _validate_image_content(content, extension):
    validator = IMAGE_SIGNATURES.get(extension)

    if validator is None or not validator(content):
        raise ValueError("Image content does not match its file type")


def download_asset(url, original_host):
    hostname = _validate_asset_url(url, original_host)

    response = fetch_https(
        url,
        expected_host=hostname,
        max_bytes=MAX_ASSET_SIZE,
    )

    if response.status_code != 200:
        raise ValueError("Asset download failed")

    content_type = response.headers.get(
        "content-type", ""
    ).split(";", 1)[0].strip().lower()

    extension = ALLOWED_TYPES.get(content_type)

    if extension is None:
        raise ValueError("Asset content type is not allowed")

    content = response.content

    if not content:
        raise ValueError("Asset is empty")

    if len(content) > MAX_ASSET_SIZE:
        raise ValueError("Asset exceeds size limit")

    if extension == ".css":
        try:
            css_text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("CSS must use UTF-8 encoding") from exc

        sanitized = sanitize_css(css_text)
        safe_css = scope_css(sanitized)

        if not safe_css.strip():
            raise ValueError("CSS contains no safe rules")

        content = safe_css.encode("utf-8")

    else:
        _validate_image_content(content, extension)

    digest = hashlib.sha256(content).hexdigest()
    filename = f"{digest}{extension}"

    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    destination = ASSET_DIR / filename
    destination.write_bytes(content)

    return {
        "filename": filename,
        "status": "downloaded",
        "size": len(content),
        "sanitized": extension == ".css",
    }
