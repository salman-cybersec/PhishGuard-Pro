
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

        participant_stats = connection.execute(
            """
            SELECT
                COUNT(*) AS total_participants,
                SUM(
                    CASE WHEN consent_activity = 1
                    THEN 1 ELSE 0 END
                ) AS activity_consent_participants
            FROM participants
            WHERE campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()

        event_stats = connection.execute(
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
                    THEN 1 ELSE 0 END) AS completions,

                COUNT(DISTINCT CASE
                    WHEN event_type = 'simulation_complete'
                    THEN participant_id
                END) AS completed_participants,

                MAX(created_at) AS last_activity

            FROM events
            WHERE campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()

    total_participants = participant_stats["total_participants"] or 0
    activity_consent = (
        participant_stats["activity_consent_participants"] or 0
    )

    total = event_stats["total_events"] or 0
    visits = event_stats["page_visits"] or 0
    training_views = event_stats["training_page_views"] or 0
    interactions = event_stats["form_interactions"] or 0
    completions = event_stats["completions"] or 0
    completed_participants = (
        event_stats["completed_participants"] or 0
    )

    completion_rate = (
        round(
            (completed_participants / activity_consent) * 100,
            2,
        )
        if activity_consent > 0
        else 0.0
    )

    return {
        "campaign": dict(campaign),
        "total_participants": total_participants,
        "activity_consent_participants": activity_consent,
        "total_events": total,
        "page_visits": visits,
        "training_page_views": training_views,
        "form_interactions": interactions,
        "completions": completions,
        "completed_participants": completed_participants,
        "completion_rate": completion_rate,
        "last_activity": event_stats["last_activity"],
    }
