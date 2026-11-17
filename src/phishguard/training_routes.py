
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from phishguard.database import get_connection
from phishguard.training_page import render_training_page


router = APIRouter()


@router.get(
    "/training/{campaign_id}",
    response_class=HTMLResponse,
)
def show_training_page(
    campaign_id: int,
    service_id: str | None = Query(default=None),
    scenario_id: str | None = Query(default=None),
):
    if campaign_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="Invalid campaign ID.",
        )

    try:
        with get_connection() as connection:
            campaign = connection.execute(
                """
                SELECT id, name
                FROM campaigns
                WHERE id = ? AND status = 'active'
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
