from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from phishguard.config import APP_NAME, APP_VERSION
from phishguard.database import initialize_database
from phishguard.campaigns import create_campaign, list_campaigns
from phishguard.campaign_controls import update_campaign_status
from phishguard.analytics import get_campaign_analytics
from phishguard.tracking import record_event
from phishguard.security import validate_input
from phishguard.link_manager import get_tracking_link
from phishguard.reporting import export_campaign_report
from phishguard.qr_generator import generate_qr_code


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Authorized security awareness lab API.",
    lifespan=lifespan,
)


class CampaignRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class StatusRequest(BaseModel):
    status: str


class EventRequest(BaseModel):
    campaign_id: int = Field(gt=0)
    event_type: str
    user_agent: str | None = Field(default=None, max_length=500)


class InputRequest(BaseModel):
    value: str = Field(max_length=2000)


class LinkRequest(BaseModel):
    base_url: str
    tracking_code: str


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "application": APP_NAME,
        "version": APP_VERSION,
    }


@app.post("/api/campaigns")
def new_campaign(request: CampaignRequest):
    try:
        return create_campaign(request.name)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/api/campaigns")
def campaigns():
    return {"campaigns": list_campaigns()}


@app.patch("/api/campaigns/{campaign_id}/status")
def change_campaign_status(
    campaign_id: int,
    request: StatusRequest,
):
    try:
        return update_campaign_status(
            campaign_id,
            request.status,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/api/campaigns/{campaign_id}/analytics")
def campaign_analytics(campaign_id: int):
    try:
        return get_campaign_analytics(campaign_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post("/api/events")
def new_event(request: EventRequest):
    try:
        return record_event(
            request.campaign_id,
            request.event_type,
            request.user_agent,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/security/validate")
def security_validation(request: InputRequest):
    try:
        return validate_input(request.value)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/tracking-link")
def create_tracking_link(request: LinkRequest):
    try:
        link = get_tracking_link(
            request.base_url,
            request.tracking_code,
        )
        return {"tracking_link": link}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/campaigns/{campaign_id}/report")
def campaign_report(campaign_id: int):
    try:
        return export_campaign_report(campaign_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post("/api/campaigns/{campaign_id}/qr")
def campaign_qr(campaign_id: int):
    try:
        analytics = get_campaign_analytics(campaign_id)
        code = analytics["campaign"]["id"]

        return {
            "campaign_id": code,
            "message": "Campaign exists. Supply its authorized training URL to the QR generator.",
        }
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
