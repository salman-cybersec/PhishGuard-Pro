import secrets
import sqlite3

from phishguard.database import get_connection


def create_campaign(name: str) -> dict:
    name = name.strip()

    if not name or len(name) > 100:
        raise ValueError("Campaign name must be 1–100 characters.")

    tracking_code = secrets.token_urlsafe(12)

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO campaigns (name, tracking_code)
                VALUES (?, ?)
                """,
                (name, tracking_code),
            )

            campaign_id = cursor.lastrowid

        return {
            "id": campaign_id,
            "name": name,
            "tracking_code": tracking_code,
            "status": "draft",
        }

    except sqlite3.Error as error:
        raise RuntimeError("Unable to create campaign.") from error


def list_campaigns() -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, name, tracking_code, status, created_at
            FROM campaigns
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]
