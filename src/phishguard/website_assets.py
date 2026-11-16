import hashlib

from pathlib import Path
from urllib.parse import urlsplit

from phishguard.config import DATA_DIR
from phishguard.safe_http import fetch_https


ASSET_DIR = DATA_DIR / "website_assets"

MAX_ASSET_SIZE = 5_000_000

ALLOWED_TYPES = {
    "text/css": ".css",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}


def _validate_asset_url(url: str, original_host: str) -> str:
    try:
        parsed = urlsplit(url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.lower().rstrip(".")
            != original_host.lower().rstrip(".")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise ValueError(
                "Asset must use the original HTTPS domain."
            )

        return url

    except (ValueError, UnicodeError) as error:
        raise ValueError("Invalid asset URL.") from error


def download_asset(
    asset_url: str,
    original_host: str,
) -> dict:

    validated_url = _validate_asset_url(
        asset_url,
        original_host,
    )

    response = fetch_https(
        url=validated_url,
        expected_host=original_host,
        max_bytes=MAX_ASSET_SIZE,
    )

    if response["status_code"] != 200:
        raise ValueError(
            "Asset could not be retrieved."
        )

    content_type = (
        response["headers"]
        .get("Content-Type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    if content_type not in ALLOWED_TYPES:
        raise ValueError(
            "Unsupported asset file type."
        )

    content = response["content"]

    if not content:
        raise ValueError("Asset is empty.")

    digest = hashlib.sha256(content).hexdigest()
    extension = ALLOWED_TYPES[content_type]

    ASSET_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

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
