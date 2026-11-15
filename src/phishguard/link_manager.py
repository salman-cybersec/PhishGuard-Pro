from urllib.parse import urljoin

from phishguard.database import get_connection


def get_tracking_link(base_url: str, tracking_code: str) -> str:
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("A valid HTTP or HTTPS base URL is required.")

    if not tracking_code or len(tracking_code) > 100:
        raise ValueError("Invalid tracking code.")

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

    base_url = base_url.rstrip("/") + "/"

    return urljoin(base_url, f"training/{tracking_code}")
