from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from phishguard.config import APP_NAME, APP_VERSION
from phishguard.database import initialize_database
from phishguard.campaigns import create_campaign, list_campaigns
from phishguard.analytics import get_campaign_analytics
from phishguard.tracking import record_event
from phishguard.security import validate_input


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


class EventRequest(BaseModel):
    campaign_id: int = Field(gt=0)
    event_type: str
    user_agent: str | None = Field(default=None, max_length=500)


class InputRequest(BaseModel):
    value: str = Field(max_length=2000)


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
