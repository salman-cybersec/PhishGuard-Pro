
from phishguard.config import ALLOWED_EVENT_TYPES
from phishguard.database import get_connection


MAX_USER_AGENT_LENGTH = 500


def record_event(
    campaign_id: int,
    event_type: str,
    user_agent: str | None = None,
    participant_id: int | None = None,
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

    if participant_id is not None:
        if (
            not isinstance(participant_id, int)
            or isinstance(participant_id, bool)
            or participant_id <= 0
        ):
            raise ValueError("Participant ID must be a positive integer.")

    if user_agent is not None:
        if not isinstance(user_agent, str):
            raise ValueError("User-Agent must be text.")

        if len(user_agent) > MAX_USER_AGENT_LENGTH:
            raise ValueError("User-Agent is too long.")

        if "\x00" in user_agent:
            raise ValueError("Invalid User-Agent.")

        if participant_id is None:
            raise ValueError(
                "Participant consent is required to store User-Agent."
            )

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
            raise ValueError("Campaign is not active.")

        stored_user_agent = None

        if participant_id is not None:

            participant = connection.execute(
                """
                SELECT
                    id,
                    campaign_id,
                    consent_device
                FROM participants
                WHERE id = ?
                """,
                (participant_id,),
            ).fetchone()

            if participant is None:
                raise ValueError("Participant not found.")

            if participant["campaign_id"] != campaign_id:
                raise ValueError(
                    "Participant does not belong to this campaign."
                )

            if user_agent is not None:
                if not participant["consent_device"]:
                    raise ValueError(
                        "Participant has not consented to device data collection."
                    )

                stored_user_agent = user_agent

        cursor = connection.execute(
            """
            INSERT INTO events (
                campaign_id,
                participant_id,
                event_type,
                user_agent
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                campaign_id,
                participant_id,
                event_type,
                stored_user_agent,
            ),
        )

        event_id = cursor.lastrowid

        event = connection.execute(
            """
            SELECT created_at
            FROM events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

    return {
        "event_id": event_id,
        "campaign_id": campaign_id,
        "participant_id": participant_id,
        "event_type": event_type,
        "created_at": event["created_at"],
        "status": "recorded",
    }
