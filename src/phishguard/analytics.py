from phishguard.database import get_connection


def get_campaign_analytics(campaign_id: int) -> dict:
    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, name, status, created_at
            FROM campaigns
            WHERE id = ?
            """,
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        events = connection.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN event_type = 'page_visit'
                    THEN 1 ELSE 0 END) AS page_visits,
                SUM(CASE WHEN event_type = 'simulation_complete'
                    THEN 1 ELSE 0 END) AS completions
            FROM events
            WHERE campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()

    total = events["total_events"] or 0
    visits = events["page_visits"] or 0
    completions = events["completions"] or 0

    completion_rate = (
        round((completions / visits) * 100, 2)
        if visits else 0
    )

    return {
        "campaign": dict(campaign),
        "total_events": total,
        "page_visits": visits,
        "completions": completions,
        "completion_rate": completion_rate,
    }
