
import secrets
import sqlite3

from phishguard.database import get_connection


MAX_CAMPAIGN_NAME_LENGTH = 100


def create_campaign(name: str) -> dict:
    if not isinstance(name, str):
        raise ValueError("Campaign name must be text.")

    name = name.strip()

    if not name or len(name) > MAX_CAMPAIGN_NAME_LENGTH:
        raise ValueError("Campaign name must be 1–100 characters.")

    if "\x00" in name:
        raise ValueError("Campaign name contains invalid characters.")

    tracking_code = secrets.token_urlsafe(24)

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

    except sqlite3.IntegrityError as error:
        raise ValueError(
            "Campaign could not be saved because of a database constraint."
        ) from error

    except sqlite3.Error as error:
        raise RuntimeError("Unable to create campaign.") from error


def list_campaigns() -> list[dict]:
    try:
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT id, name, tracking_code, status, created_at
                FROM campaigns
                ORDER BY id DESC
                """
            ).fetchall()

        return [dict(row) for row in rows]

    except sqlite3.Error as error:
        raise RuntimeError("Unable to retrieve campaigns.") from error
