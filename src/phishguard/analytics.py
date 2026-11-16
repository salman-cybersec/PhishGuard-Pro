
from phishguard.database import get_connection


def get_campaign_analytics(campaign_id: int) -> dict:

    if (
        not isinstance(campaign_id, int)
        or isinstance(campaign_id, bool)
        or campaign_id <= 0
    ):
        raise ValueError("Campaign ID must be a positive integer.")

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

                SUM(CASE WHEN event_type = 'training_page_view'
                    THEN 1 ELSE 0 END) AS training_page_views,

                SUM(CASE WHEN event_type = 'form_interaction'
                    THEN 1 ELSE 0 END) AS form_interactions,

                SUM(CASE WHEN event_type = 'simulation_complete'
                    THEN 1 ELSE 0 END) AS completions

            FROM events
            WHERE campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()

    total = events["total_events"] or 0
    visits = events["page_visits"] or 0
    training_views = events["training_page_views"] or 0
    interactions = events["form_interactions"] or 0
    completions = events["completions"] or 0

    completion_rate = (
        round((completions / visits) * 100, 2)
        if visits > 0 else 0.0
    )

    return {
        "campaign": dict(campaign),
        "total_events": total,
        "page_visits": visits,
        "training_page_views": training_views,
        "form_interactions": interactions,
        "completions": completions,
        "completion_rate": completion_rate,
    }
