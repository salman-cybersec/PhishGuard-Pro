
import re
from urllib.parse import urlsplit, urlunsplit

from phishguard.database import get_connection


TRACKING_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,100}$")


def get_tracking_link(base_url: str, tracking_code: str) -> str:

    if not isinstance(base_url, str):
        raise ValueError("Base URL must be text.")

    if not isinstance(tracking_code, str):
        raise ValueError("Tracking code must be text.")

    if not TRACKING_CODE_PATTERN.fullmatch(tracking_code):
        raise ValueError("Invalid tracking code.")

    try:
        parsed_url = urlsplit(base_url)

        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError("Invalid base URL.")

        parsed_url.port

    except ValueError as error:
        raise ValueError("A valid authorized HTTP or HTTPS base URL is required.") from error

    if parsed_url.scheme == "http" and parsed_url.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        raise ValueError("HTTP is only allowed for localhost testing.")

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT tracking_code, status
            FROM campaigns
            WHERE tracking_code = ?
            """,
            (tracking_code,),
        ).fetchone()

    if campaign is None:
        raise ValueError("Campaign not found.")

    if campaign["status"] != "active":
        raise ValueError("Campaign is not active.")

    normalized_path = parsed_url.path.rstrip("/") + "/"

    return urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        normalized_path + f"training/{tracking_code}",
        "",
        "",
    ))
