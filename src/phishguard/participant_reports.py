
from phishguard.database import get_connection


def get_participant_report(campaign_id: int) -> dict:
    if not isinstance(campaign_id, int) or campaign_id <= 0:
        raise ValueError("Invalid campaign ID.")

    with get_connection() as connection:
        campaign = connection.execute(
            "SELECT id, name FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        rows = connection.execute(
            """
            SELECT
                participant_name,
                submitted_at,
                consent_ip,
                ip_address,
                consent_device,
                user_agent,
                browser_name,
                browser_version,
                os_name,
                device_type
            FROM participants
            WHERE campaign_id = ?
            ORDER BY submitted_at DESC, id DESC
            """,
            (campaign_id,),
        ).fetchall()

    participants = []

    for row in rows:
        participants.append({
            "participant_name": row["participant_name"],
            "submitted_at": row["submitted_at"],
            "consent_ip": bool(row["consent_ip"]),
            "ip_address": (
                row["ip_address"] if row["consent_ip"] else None
            ),
            "consent_device": bool(row["consent_device"]),
            "user_agent": (
                row["user_agent"] if row["consent_device"] else None
            ),
            "browser_name": (
                row["browser_name"] if row["consent_device"] else None
            ),
            "browser_version": (
                row["browser_version"] if row["consent_device"] else None
            ),
            "os_name": (
                row["os_name"] if row["consent_device"] else None
            ),
            "device_type": (
                row["device_type"] if row["consent_device"] else None
            ),
        })

    return {
        "campaign_id": campaign["id"],
        "campaign_name": campaign["name"],
        "total_participants": len(participants),
        "participants": participants,
    }
