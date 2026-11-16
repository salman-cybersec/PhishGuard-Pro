
from phishguard.config import ALLOWED_EVENT_TYPES
from phishguard.database import get_connection


MAX_USER_AGENT_LENGTH = 500


def record_event(
    campaign_id: int,
    event_type: str,
    user_agent: str | None = None,
) -> dict:

    if (
        not isinstance(campaign_id, int)
        or isinstance(campaign_id, bool)
        or campaign_id <= 0
    ):
        raise ValueError("Campaign ID must be a positive integer.")

    if not isinstance(event_type, str):
        raise ValueError("Event type must be text.")

    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Unsupported event type.")

    if user_agent is not None:
        if not isinstance(user_agent, str):
            raise ValueError("User agent must be text.")

        if len(user_agent) > MAX_USER_AGENT_LENGTH:
            raise ValueError("User agent is too long.")

        if "\x00" in user_agent:
            raise ValueError("User agent contains invalid characters.")

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, status
            FROM campaigns
            WHERE id = ?
            """,
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        if campaign["status"] != "active":
            raise ValueError("Events can only be recorded for active campaigns.")

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
