from phishguard.config import ALLOWED_EVENT_TYPES
from phishguard.database import get_connection


def record_event(
    campaign_id: int,
    event_type: str,
    user_agent: str | None = None,
) -> dict:

    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Unsupported event type.")

    if user_agent and len(user_agent) > 500:
        raise ValueError("User agent is too long.")

    with get_connection() as connection:
        campaign = connection.execute(
            "SELECT id FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        cursor = connection.execute(
            """
            INSERT INTO events (campaign_id, event_type, user_agent)
            VALUES (?, ?, ?)
            """,
            (campaign_id, event_type, user_agent),
        )

        event_id = cursor.lastrowid

    return {
        "event_id": event_id,
        "campaign_id": campaign_id,
        "event_type": event_type,
        "status": "recorded",
    }
