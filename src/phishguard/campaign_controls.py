
from phishguard.database import get_connection


VALID_TRANSITIONS = {
    "draft": {"active"},
    "active": {"paused", "completed"},
    "paused": {"active", "completed"},
    "completed": set(),
}


def update_campaign_status(
    campaign_id: int,
    status: str,
) -> dict:

    if not isinstance(campaign_id, int) or isinstance(campaign_id, bool):
        raise ValueError("Campaign ID must be an integer.")

    if campaign_id <= 0:
        raise ValueError("Campaign ID must be positive.")

    if not isinstance(status, str) or status not in VALID_TRANSITIONS:
        raise ValueError("Invalid campaign status.")

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

        current_status = campaign["status"]

        if status not in VALID_TRANSITIONS[current_status]:
            raise ValueError(
                f"Cannot change campaign status from "
                f"'{current_status}' to '{status}'."
            )

        connection.execute(
            """
            UPDATE campaigns
            SET status = ?
            WHERE id = ?
            """,
            (status, campaign_id),
        )

    return {
        "campaign_id": campaign_id,
        "previous_status": current_status,
        "status": status,
        "updated": True,
    }
