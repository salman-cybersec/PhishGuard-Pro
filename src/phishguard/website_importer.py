import email.message

from urllib.parse import urlsplit

from phishguard.website_authorization import (
    validate_website_authorization,
)
from phishguard.safe_http import fetch_https


MAX_HTML_SIZE = 2_000_000


def analyze_website(url: str) -> str:
    authorization = validate_website_authorization(url)

    response = fetch_https(
        url=url,
        expected_host=authorization["hostname"],
        max_bytes=MAX_HTML_SIZE,
    )

    if response["status_code"] != 200:
        raise ValueError(
            "Website returned an unsuccessful response."
        )

    content_type = (
        response["headers"]
        .get("Content-Type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    if content_type != "text/html":
        raise ValueError(
            "Target must return an HTML page."
        )

    content = response["content"]

    if not content:
        raise ValueError(
            "Website returned an empty HTML page."
        )

    message = email.message.Message()
    message["Content-Type"] = response["headers"].get(
        "Content-Type", "text/html"
    )

    encoding = message.get_content_charset() or "utf-8"

    try:
        return content.decode(encoding, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")
