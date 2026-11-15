
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
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
from phishguard.auth import verify_api_key
from phishguard.audit import write_audit_log, AUDIT_FILE
from phishguard.rate_limit import enforce_rate_limit

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

@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    if request.url.path != "/health":
        enforce_rate_limit(request)

    response = await call_next(request)
    return response
    
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


@app.post("/api/campaigns", dependencies=[Depends(verify_api_key)])
def new_campaign(request: CampaignRequest):
    try:
        result = create_campaign(request.name)
        write_audit_log("campaign_created", {"campaign_name": request.name})
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/api/campaigns", dependencies=[Depends(verify_api_key)])
def campaigns():
    return {"campaigns": list_campaigns()}


@app.patch(
    "/api/campaigns/{campaign_id}/status",
    dependencies=[Depends(verify_api_key)],
)
def change_campaign_status(campaign_id: int, request: StatusRequest):
    try:
        result = update_campaign_status(campaign_id, request.status)
        write_audit_log(
            "campaign_status_changed",
            {"campaign_id": campaign_id, "status": request.status},
        )
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get(
    "/api/campaigns/{campaign_id}/analytics",
    dependencies=[Depends(verify_api_key)],
)
def campaign_analytics(campaign_id: int):
    try:
        return get_campaign_analytics(campaign_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post("/api/events", dependencies=[Depends(verify_api_key)])
def new_event(request: EventRequest):
    try:
        return record_event(
            request.campaign_id,
            request.event_type,
            request.user_agent,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post(
    "/api/security/validate",
    dependencies=[Depends(verify_api_key)],
)
def security_validation(request: InputRequest):
    try:
        result = validate_input(request.value)
        write_audit_log("security_validation", {"result": "completed"})
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/tracking-link", dependencies=[Depends(verify_api_key)])
def create_tracking_link(request: LinkRequest):
    try:
        link = get_tracking_link(
            request.base_url,
            request.tracking_code,
        )
        write_audit_log("tracking_link_created", {"status": "success"})
        return {"tracking_link": link}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post(
    "/api/campaigns/{campaign_id}/report",
    dependencies=[Depends(verify_api_key)],
)
def campaign_report(campaign_id: int):
    try:
        return export_campaign_report(campaign_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.post(
    "/api/campaigns/{campaign_id}/qr",
    dependencies=[Depends(verify_api_key)],
)
def campaign_qr(campaign_id: int):
    try:
        analytics = get_campaign_analytics(campaign_id)
        return {
            "campaign_id": analytics["campaign"]["id"],
            "message": "An authorized training URL is required for QR generation.",
        }
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))


@app.get("/api/audit-logs", dependencies=[Depends(verify_api_key)])
def get_audit_logs(limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500.",
        )

    if not AUDIT_FILE.exists():
        return {"logs": []}

    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        logs = [line for line in lines[-limit:] if line.strip()]
        return {"logs": logs}
    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Unable to read audit logs.",
        )

@app.get(
    "/api/audit-logs/verify",
    dependencies=[Depends(verify_api_key)],
)
def verify_audit_integrity():
    from phishguard.audit import verify_audit_log

    is_valid = verify_audit_log()

    return {
        "integrity": "valid" if is_valid else "tampered",
        "verified": is_valid,
    }
