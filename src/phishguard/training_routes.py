
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from phishguard.database import get_connection
from phishguard.training_page import render_training_page


router = APIRouter()


@router.get(
    "/training/{campaign_reference}",
    response_class=HTMLResponse,
)
def show_training_page(
    campaign_reference: str,
    service_id: str | None = Query(default=None),
    scenario_id: str | None = Query(default=None),
):
    if (
        not isinstance(campaign_reference, str)
        or not campaign_reference
        or len(campaign_reference) > 100
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid campaign reference.",
        )

    try:
        with get_connection() as connection:

            campaign = connection.execute(
                """
                SELECT id, name, tracking_code
                FROM campaigns
                WHERE tracking_code = ?
                  AND status = 'active'
                """,
                (campaign_reference,),
            ).fetchone()

            # Backward compatibility for existing numeric campaign links.
            if campaign is None and campaign_reference.isdecimal():
                campaign_id = int(campaign_reference)

                if campaign_id <= 0:
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid campaign ID.",
                    )

                campaign = connection.execute(
                    """
                    SELECT id, name, tracking_code
                    FROM campaigns
                    WHERE id = ?
                      AND status = 'active'
                    """,
                    (campaign_id,),
                ).fetchone()

        if campaign is None:
            raise HTTPException(
                status_code=404,
                detail="Active campaign not found.",
            )

        page = render_training_page(
            campaign_name=campaign["name"],
            campaign_id=campaign["id"],
            service_id=service_id,
            scenario_id=scenario_id,
        )

        return HTMLResponse(content=page)

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to load training page.",
        ) from error
