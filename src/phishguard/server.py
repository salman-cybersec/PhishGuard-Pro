
import re
import hashlib
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel, Field

from phishguard.config import (
    APP_NAME,
    APP_VERSION,
    MAX_REQUEST_SIZE,
    DATA_DIR,
)
from phishguard.database import initialize_database
from phishguard.campaigns import create_campaign, list_campaigns
from phishguard.campaign_controls import update_campaign_status
from phishguard.analytics import get_campaign_analytics
from phishguard.tracking import record_event
from phishguard.security import validate_input
from phishguard.link_manager import get_tracking_link
from phishguard.reporting import export_campaign_report
from phishguard.auth import verify_api_key
from phishguard.audit import (
    write_audit_log,
    AUDIT_FILE,
    verify_audit_log,
)
from phishguard.rate_limit import enforce_rate_limit
from phishguard.request_limits import RequestSizeLimitMiddleware

from phishguard.training_submission import router as training_router
from phishguard.training_routes import router as training_page_router
from phishguard.training_activity import router as training_activity_router

from phishguard.participant_reports import get_participant_report
from phishguard.participant_export import export_participants_csv


PREVIEW_DIR = DATA_DIR / "website_previews"
ASSET_DIR = DATA_DIR / "website_assets"

PREVIEW_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{24}$"
)

ASSET_FILENAME_PATTERN = re.compile(
    r"^[a-f0-9]{64}\.(?:png|jpg|webp|css)$"
)

ASSET_CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".webp": "image/webp",
    ".css": "text/css",
}


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

app.include_router(training_router)
app.include_router(training_page_router)
app.include_router(training_activity_router)

app.add_middleware(
    RequestSizeLimitMiddleware,
    max_size=MAX_REQUEST_SIZE,
)


@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    if request.url.path != "/health":
        enforce_rate_limit(request)

    response = await call_next(request)
    return response


@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

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

        write_audit_log(
            "campaign_created",
            {"campaign_name": request.name},
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.get("/api/campaigns", dependencies=[Depends(verify_api_key)])
def campaigns():
    return {"campaigns": list_campaigns()}


@app.patch(
    "/api/campaigns/{campaign_id}/status",
    dependencies=[Depends(verify_api_key)],
)
def change_campaign_status(
    campaign_id: int,
    request: StatusRequest,
):
    try:
        result = update_campaign_status(
            campaign_id,
            request.status,
        )

        write_audit_log(
            "campaign_status_changed",
            {
                "campaign_id": campaign_id,
                "status": request.status,
            },
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.get(
    "/api/campaigns/{campaign_id}/analytics",
    dependencies=[Depends(verify_api_key)],
)
def campaign_analytics(campaign_id: int):
    try:
        return get_campaign_analytics(campaign_id)

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


@app.post("/api/events", dependencies=[Depends(verify_api_key)])
def new_event(request: EventRequest):
    try:
        return record_event(
            request.campaign_id,
            request.event_type,
            request.user_agent,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.post(
    "/api/security/validate",
    dependencies=[Depends(verify_api_key)],
)
def security_validation(request: InputRequest):
    try:
        result = validate_input(request.value)

        write_audit_log(
            "security_validation",
            {"result": "completed"},
        )

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.post("/api/tracking-link", dependencies=[Depends(verify_api_key)])
def create_tracking_link(request: LinkRequest):
    try:
        link = get_tracking_link(
            request.base_url,
            request.tracking_code,
        )

        write_audit_log(
            "tracking_link_created",
            {"status": "success"},
        )

        return {"tracking_link": link}

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.post(
    "/api/campaigns/{campaign_id}/report",
    dependencies=[Depends(verify_api_key)],
)
def campaign_report(campaign_id: int):
    try:
        return export_campaign_report(campaign_id)

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


@app.get(
    "/api/campaigns/{campaign_id}/participants",
    dependencies=[Depends(verify_api_key)],
)
def participant_report(campaign_id: int):
    try:
        return get_participant_report(campaign_id)

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


@app.get(
    "/api/campaigns/{campaign_id}/participants/export",
    dependencies=[Depends(verify_api_key)],
)
def export_participant_report(campaign_id: int):
    try:
        csv_data = export_participants_csv(campaign_id)

        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="participants_{campaign_id}.csv"'
                )
            },
        )

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


@app.post(
    "/api/campaigns/{campaign_id}/qr",
    dependencies=[Depends(verify_api_key)],
)
def campaign_qr(campaign_id: int):
    try:
        analytics = get_campaign_analytics(campaign_id)

        return {
            "campaign_id": analytics["campaign"]["id"],
            "message": (
                "An authorized training URL is required "
                "for QR generation."
            ),
        }

    except ValueError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


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
        lines = AUDIT_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

        logs = [
            line
            for line in lines[-limit:]
            if line.strip()
        ]

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
    is_valid = verify_audit_log()

    return {
        "integrity": "valid" if is_valid else "tampered",
        "verified": is_valid,
    }


@app.get("/preview/{preview_id}")
def serve_website_preview(preview_id: str):
    if not PREVIEW_ID_PATTERN.fullmatch(preview_id):
        raise HTTPException(
            status_code=404,
            detail="Preview not found.",
        )

    try:
        safe_directory = PREVIEW_DIR.resolve()
        preview_path = (
            safe_directory / f"{preview_id}.html"
        ).resolve()

        if preview_path.parent != safe_directory:
            raise HTTPException(
                status_code=404,
                detail="Preview not found.",
            )

        if not preview_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Preview not found.",
            )

        return FileResponse(
            path=preview_path,
            media_type="text/html",
            headers={
                "Content-Disposition": "inline",
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'none'; "
                    "img-src 'self'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "script-src 'none'; "
                    "connect-src 'none'; "
                    "font-src 'none'; "
                    "object-src 'none'; "
                    "frame-src 'none'; "
                    "base-uri 'none'; "
                    "form-action 'none'; "
                    "frame-ancestors 'none'; "
                    "sandbox allow-same-origin"
                ),
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

    except HTTPException:
        raise

    except OSError:
        raise HTTPException(
            status_code=404,
            detail="Preview not found.",
        )


@app.get("/assets/{filename}")
def serve_website_asset(filename: str):
    if not ASSET_FILENAME_PATTERN.fullmatch(filename):
        raise HTTPException(
            status_code=404,
            detail="Asset not found.",
        )

    extension = Path(filename).suffix.lower()
    content_type = ASSET_CONTENT_TYPES.get(extension)

    if not content_type:
        raise HTTPException(
            status_code=404,
            detail="Asset not found.",
        )

    try:
        safe_directory = ASSET_DIR.resolve()
        asset_path = (
            safe_directory / filename
        ).resolve()

        if asset_path.parent != safe_directory:
            raise HTTPException(
                status_code=404,
                detail="Asset not found.",
            )

        if not asset_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Asset not found.",
            )

        digest = hashlib.sha256(
            asset_path.read_bytes()
        ).hexdigest()

        expected_digest = filename.rsplit(".", 1)[0]

        if digest != expected_digest:
            raise HTTPException(
                status_code=404,
                detail="Asset integrity check failed.",
            )

        return FileResponse(
            path=asset_path,
            media_type=content_type,
            headers={
                "Content-Disposition": "inline",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'",
            },
        )

    except HTTPException:
        raise

    except OSError:
        raise HTTPException(
            status_code=404,
            detail="Asset not found.",
        )
