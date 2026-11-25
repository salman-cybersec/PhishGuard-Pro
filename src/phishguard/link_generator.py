import ipaddress
import re
import secrets

from phishguard.database import get_connection
from phishguard.website_authorization import validate_website_authorization


MAX_NAME_LENGTH = 100
MAX_URL_LENGTH = 2048
MAX_USER_AGENT_LENGTH = 500
TRACKING_ID_LENGTH = 32

DEVICE_TYPES = {"desktop", "mobile", "tablet", "unknown"}

SERVICE_SLUGS = {
    "facebook", "instagram", "tiktok", "snapchat", "paypal",
    "google", "microsoft", "netflix", "linkedin", "x", "amazon",
    "apple", "discord", "telegram", "steam", "spotify", "yahoo",
    "reddit", "pinterest", "twitch", "zoom", "dropbox", "github",
}


def _validate_service_slug(service_slug):
    if service_slug is None:
        return None
    if not isinstance(service_slug, str) or service_slug not in SERVICE_SLUGS:
        raise ValueError("Unsupported service workspace.")
    return service_slug


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Link name must be text.")

    name = name.strip()

    if (
        not name
        or len(name) > MAX_NAME_LENGTH
        or any(ord(char) < 32 for char in name)
    ):
        raise ValueError("Link name must contain 1 to 100 valid characters.")

    return name


def _validate_destination(url: str) -> str:
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        raise ValueError("Invalid destination URL.")

    try:
        authorization = validate_website_authorization(url.strip())
    except ValueError as error:
        raise ValueError(
            "Destination must use HTTPS and belong to an authorized domain."
        ) from error

    return url.strip()


def create_generated_link(name: str, destination_url: str, service_slug: str | None = None) -> dict:
    name = _validate_name(name)
    destination_url = _validate_destination(destination_url)
    service_slug = _validate_service_slug(service_slug)

    for _ in range(5):
        tracking_id = secrets.token_urlsafe(24)

        with get_connection() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO generated_links (
                        name,
                        tracking_id,
                        destination_url,
                        service_slug
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (name, tracking_id, destination_url, service_slug),
                )
            except Exception as error:
                if "UNIQUE constraint failed" in str(error):
                    continue
                raise

            link_id = cursor.lastrowid

        return {
            "id": link_id,
            "name": name,
            "tracking_id": tracking_id,
            "destination_url": destination_url,
            "service_slug": service_slug,
            "status": "active",
        }

    raise RuntimeError("Unable to generate a unique tracking ID.")



def create_generated_links(name: str, destination_url: str, count: int, service_slug: str | None = None) -> list[dict]:
    name = _validate_name(name)
    destination_url = _validate_destination(destination_url)
    service_slug = _validate_service_slug(service_slug)

    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 100:
        raise ValueError("Bulk count must be between 1 and 100.")

    if len(name) > 96:
        raise ValueError("Bulk link name must be 96 characters or fewer.")

    links = []

    with get_connection() as connection:
        for index in range(1, count + 1):
            link_name = f"{name}-{index:03d}"

            for _ in range(5):
                tracking_id = secrets.token_urlsafe(24)

                try:
                    cursor = connection.execute(
                        """
                        INSERT INTO generated_links (
                            name, tracking_id, destination_url, service_slug
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (link_name, tracking_id, destination_url, service_slug),
                    )
                except Exception as error:
                    if "UNIQUE constraint failed" in str(error):
                        continue
                    raise

                links.append({
                    "id": cursor.lastrowid,
                    "name": link_name,
                    "tracking_id": tracking_id,
                    "destination_url": destination_url,
                    "service_slug": service_slug,
                    "status": "active",
                })
                break
            else:
                raise RuntimeError(
                    "Unable to generate a unique tracking ID."
                )

    return links


def resolve_generated_link(tracking_id: str) -> dict:
    if (
        not isinstance(tracking_id, str)
        or len(tracking_id) != TRACKING_ID_LENGTH
        or not re.fullmatch(r"[A-Za-z0-9_-]+", tracking_id)
    ):
        raise ValueError("Invalid tracking ID.")

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, tracking_id, destination_url, service_slug, status
            FROM generated_links
            WHERE tracking_id = ?
            """,
            (tracking_id,),
        ).fetchone()

    if row is None or row["status"] != "active":
        raise ValueError("Tracking link not found or inactive.")

    return dict(row)



def set_generated_link_status(tracking_id: str, status: str) -> dict:
    if not isinstance(status, str) or status not in {"active", "paused"}:
        raise ValueError("Status must be active or paused.")

    if (
        not isinstance(tracking_id, str)
        or len(tracking_id) != TRACKING_ID_LENGTH
        or not re.fullmatch(r"[A-Za-z0-9_-]+", tracking_id)
    ):
        raise ValueError("Invalid tracking ID.")

    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE generated_links SET status = ? WHERE tracking_id = ?",
            (status, tracking_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("Tracking link not found.")

        row = connection.execute(
            "SELECT id, name, tracking_id, status FROM generated_links "
            "WHERE tracking_id = ?",
            (tracking_id,),
        ).fetchone()

    return dict(row)


def record_generated_link_event(
    tracking_id: str,
    source: str = "direct",
    consent_ip: bool = False,
    ip_address: str | None = None,
    country_code: str | None = None,
    consent_device: bool = False,
    user_agent: str | None = None,
    browser_name: str | None = None,
    os_name: str | None = None,
    device_type: str | None = None,
) -> dict:
    link = resolve_generated_link(tracking_id)

    if not isinstance(source, str) or source not in {"direct", "qr"}:
        raise ValueError("Source must be direct or qr.")

    if not isinstance(consent_ip, bool) or not isinstance(consent_device, bool):
        raise ValueError("Consent values must be boolean.")

    if not consent_ip and any(
        value is not None for value in (ip_address, country_code)
    ):
        raise ValueError("IP metadata requires explicit consent.")

    if consent_ip and ip_address is not None:
        if not isinstance(ip_address, str):
            raise ValueError("Invalid IP address.")

        try:
            parsed_ip = ipaddress.ip_address(ip_address)
        except ValueError as error:
            raise ValueError("Invalid IP address.") from error

        if not parsed_ip.is_global:
            raise ValueError("Only public IP addresses are accepted.")

        ip_address = parsed_ip.compressed

    if country_code is not None:
        if (
            not consent_ip
            or not isinstance(country_code, str)
            or not re.fullmatch(r"[A-Za-z]{2}", country_code)
        ):
            raise ValueError("Invalid country code or missing IP consent.")

        country_code = country_code.upper()

    if not consent_device and any(
        value is not None
        for value in (user_agent, browser_name, os_name, device_type)
    ):
        raise ValueError("Device metadata requires explicit consent.")

    if user_agent is not None:
        if (
            not isinstance(user_agent, str)
            or len(user_agent) > MAX_USER_AGENT_LENGTH
            or "\x00" in user_agent
        ):
            raise ValueError("Invalid User-Agent.")

    for value, field_name in (
        (browser_name, "Browser name"),
        (os_name, "OS name"),
    ):
        if value is not None and (
            not isinstance(value, str)
            or len(value) > 100
            or any(ord(char) < 32 for char in value)
        ):
            raise ValueError(f"Invalid {field_name}.")

    if device_type is not None and (
        not isinstance(device_type, str) or device_type not in DEVICE_TYPES
    ):
        raise ValueError("Invalid device type.")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO generated_link_events (
                generated_link_id,
                source,
                consent_ip,
                ip_address,
                country_code,
                consent_device,
                user_agent,
                browser_name,
                os_name,
                device_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link["id"],
                source,
                int(consent_ip),
                ip_address if consent_ip else None,
                country_code if consent_ip else None,
                int(consent_device),
                user_agent if consent_device else None,
                browser_name if consent_device else None,
                os_name if consent_device else None,
                device_type if consent_device else None,
            ),
        )

        event_id = cursor.lastrowid

        event = connection.execute(
            """
            SELECT created_at
            FROM generated_link_events
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()

    return {
        "event_id": event_id,
        "tracking_id": tracking_id,
        "source": source,
        "created_at": event["created_at"],
        "status": "recorded",
    }


def get_generated_link_stats(tracking_id: str) -> dict:
    link = resolve_generated_link(tracking_id)

    with get_connection() as connection:
        stats = connection.execute(
            """
            SELECT
                COUNT(*) AS total_clicks,
                SUM(CASE WHEN source = 'direct' THEN 1 ELSE 0 END)
                    AS direct_clicks,
                SUM(CASE WHEN source = 'qr' THEN 1 ELSE 0 END)
                    AS qr_clicks
            FROM generated_link_events
            WHERE generated_link_id = ?
            """,
            (link["id"],),
        ).fetchone()

    return {
        **link,
        "total_clicks": stats["total_clicks"] or 0,
        "direct_clicks": stats["direct_clicks"] or 0,
        "qr_clicks": stats["qr_clicks"] or 0,
    }


def get_generated_link_history(
    tracking_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    if (
        not isinstance(tracking_id, str)
        or len(tracking_id) != TRACKING_ID_LENGTH
        or not re.fullmatch(r"[A-Za-z0-9_-]+", tracking_id)
    ):
        raise ValueError("Invalid tracking ID.")

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= 200
    ):
        raise ValueError("Limit must be between 1 and 200.")

    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or offset < 0
    ):
        raise ValueError("Offset must be a non-negative integer.")

    with get_connection() as connection:
        link = connection.execute(
            "SELECT id FROM generated_links WHERE tracking_id = ?",
            (tracking_id,),
        ).fetchone()
        if link is None:
            raise ValueError("Tracking link not found.")

        rows = connection.execute(
            """
            SELECT
                id AS event_id,
                created_at,
                source,
                consent_ip,
                ip_address,
                country_code,
                consent_device,
                browser_name,
                os_name,
                device_type,
                user_agent
            FROM generated_link_events
            WHERE generated_link_id = ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (link["id"], limit, offset),
        ).fetchall()

        total = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM generated_link_events
            WHERE generated_link_id = ?
            """,
            (link["id"],),
        ).fetchone()["total"]

    return {
        "tracking_id": tracking_id,
        "total_events": total,
        "limit": limit,
        "offset": offset,
        "events": [dict(row) for row in rows],
    }



def get_generated_link_analytics(start_date: str, end_date: str) -> dict:
    from datetime import date

    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except (TypeError, ValueError) as error:
        raise ValueError("Dates must use YYYY-MM-DD format.") from error

    if start.isoformat() != start_date or end.isoformat() != end_date:
        raise ValueError("Dates must use YYYY-MM-DD format.")

    if start > end:
        raise ValueError("Start date cannot be after end date.")

    with get_connection() as connection:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                SUM(CASE WHEN source = 'direct' THEN 1 ELSE 0 END)
                    AS direct_events,
                SUM(CASE WHEN source = 'qr' THEN 1 ELSE 0 END)
                    AS qr_events
            FROM generated_link_events
            WHERE date(created_at) BETWEEN ? AND ?
            """,
            (start_date, end_date),
        ).fetchone()

        daily_rows = connection.execute(
            """
            SELECT
                date(created_at) AS event_date,
                COUNT(*) AS total_events,
                SUM(CASE WHEN source = 'direct' THEN 1 ELSE 0 END)
                    AS direct_events,
                SUM(CASE WHEN source = 'qr' THEN 1 ELSE 0 END)
                    AS qr_events
            FROM generated_link_events
            WHERE date(created_at) BETWEEN ? AND ?
            GROUP BY date(created_at)
            ORDER BY event_date
            """,
            (start_date, end_date),
        ).fetchall()

    return {
        "start_date": start_date,
        "end_date": end_date,
        "total_events": totals["total_events"] or 0,
        "direct_events": totals["direct_events"] or 0,
        "qr_events": totals["qr_events"] or 0,
        "daily": [dict(row) for row in daily_rows],
    }
