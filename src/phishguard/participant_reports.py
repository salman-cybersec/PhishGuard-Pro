
from phishguard.database import get_connection


def get_participant_report(campaign_id: int) -> dict:
    if (
        not isinstance(campaign_id, int)
        or isinstance(campaign_id, bool)
        or campaign_id <= 0
    ):
        raise ValueError("Invalid campaign ID.")

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, name
            FROM campaigns
            WHERE id = ?
            """,
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        rows = connection.execute(
            """
            SELECT
                id,
                participant_name,
                submitted_at,
                consent_ip,
                ip_address,
                consent_device,
                user_agent,
                browser_name,
                browser_version,
                os_name,
                device_type,
                consent_activity
            FROM participants
            WHERE campaign_id = ?
            ORDER BY submitted_at DESC, id DESC
            """,
            (campaign_id,),
        ).fetchall()

        event_rows = connection.execute(
            """
            SELECT
                participant_id,
                event_type,
                created_at
            FROM events
            WHERE campaign_id = ?
              AND participant_id IS NOT NULL
            ORDER BY created_at ASC, id ASC
            """,
            (campaign_id,),
        ).fetchall()

    events_by_participant = {}

    for event in event_rows:
        participant_id = event["participant_id"]

        if participant_id not in events_by_participant:
            events_by_participant[participant_id] = []

        events_by_participant[participant_id].append({
            "event_type": event["event_type"],
            "created_at": event["created_at"],
        })

    participants = []

    for row in rows:
        consent_ip = bool(row["consent_ip"])
        consent_device = bool(row["consent_device"])
        consent_activity = bool(row["consent_activity"])

        participant_events = (
            events_by_participant.get(row["id"], [])
            if consent_activity
            else []
        )

        interaction_count = sum(
            1
            for event in participant_events
            if event["event_type"] == "form_interaction"
        )

        completion_count = sum(
            1
            for event in participant_events
            if event["event_type"] == "simulation_complete"
        )

        participants.append({
            "participant_name": row["participant_name"],
            "submitted_at": row["submitted_at"],

            "consent_ip": consent_ip,
            "ip_address": (
                row["ip_address"] if consent_ip else None
            ),

            "consent_device": consent_device,
            "user_agent": (
                row["user_agent"] if consent_device else None
            ),
            "browser_name": (
                row["browser_name"] if consent_device else None
            ),
            "browser_version": (
                row["browser_version"] if consent_device else None
            ),
            "os_name": (
                row["os_name"] if consent_device else None
            ),
            "device_type": (
                row["device_type"] if consent_device else None
            ),

            "consent_activity": consent_activity,
            "total_events": len(participant_events),
            "interaction_count": interaction_count,
            "completion_count": completion_count,
            "completed": completion_count > 0,
            "last_activity": (
                participant_events[-1]["created_at"]
                if participant_events
                else None
            ),
            "events": participant_events,
        })

    return {
        "campaign_id": campaign["id"],
        "campaign_name": campaign["name"],
        "total_participants": len(participants),
        "participants": participants,
    }
