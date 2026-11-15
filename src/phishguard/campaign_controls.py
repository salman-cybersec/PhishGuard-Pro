from phishguard.database import get_connection


VALID_STATUSES = {
    "draft",
    "active",
    "paused",
    "completed",
}


def update_campaign_status(
    campaign_id: int,
    status: str,
) -> dict:

    if status not in VALID_STATUSES:
        raise ValueError("Invalid campaign status.")

    with get_connection() as connection:
        campaign = connection.execute(
            "SELECT id FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

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
        "status": status,
        "updated": True,
    }
