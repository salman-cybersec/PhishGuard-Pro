
import ipaddress
import secrets

from phishguard.database import get_connection


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("Participant name must be text.")

    name = name.strip()

    if not name or len(name) > 100:
        raise ValueError("Name must contain 1–100 characters.")

    if any(ord(char) < 32 for char in name):
        raise ValueError("Name contains invalid characters.")

    return name


def _validate_ip(ip_address: str | None) -> str | None:
    if ip_address is None:
        return None

    if not isinstance(ip_address, str):
        raise ValueError("IP address must be text.")

    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError as error:
        raise ValueError("Invalid IP address.") from error

    if not parsed.is_global:
        raise ValueError("Only public IP addresses can be recorded.")

    return str(parsed)


def register_participant(
    campaign_id: int,
    participant_name: str,
    consent_ip: bool = False,
    ip_address: str | None = None,
    consent_device: bool = False,
    user_agent: str | None = None,
) -> dict:

    if (
        not isinstance(campaign_id, int)
        or isinstance(campaign_id, bool)
        or campaign_id <= 0
    ):
        raise ValueError("Invalid campaign ID.")

    if not isinstance(consent_ip, bool):
        raise ValueError("IP consent must be true or false.")

    if not isinstance(consent_device, bool):
        raise ValueError("Device consent must be true or false.")

    name = _validate_name(participant_name)

    if consent_ip:
        ip_address = _validate_ip(ip_address)
    else:
        ip_address = None

    if consent_device:
        if not isinstance(user_agent, str) or not user_agent.strip():
            raise ValueError("Device information requires a User-Agent.")

        if len(user_agent) > 500:
            raise ValueError("User-Agent is too long.")

        if any(ord(char) < 32 and char != "\t" for char in user_agent):
            raise ValueError("Invalid User-Agent.")

        user_agent = user_agent.strip()
    else:
        user_agent = None

    participant_token = secrets.token_urlsafe(24)

    with get_connection() as connection:
        campaign = connection.execute(
            """
            SELECT id, status
            FROM campaigns
            WHERE id = ?
            """,
            (campaign_id,),
        ).fetchone()

        if campaign is None:
            raise ValueError("Campaign not found.")

        if campaign["status"] != "active":
            raise ValueError("Campaign is not active.")

        connection.execute(
            """
            INSERT INTO participants (
                campaign_id,
                participant_token,
                participant_name,
                consent_ip,
                ip_address,
                consent_device,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                participant_token,
                name,
                int(consent_ip),
                ip_address,
                int(consent_device),
                user_agent,
            ),
        )

    return {
        "participant_id": participant_token,
        "campaign_id": campaign_id,
        "participant_name": name,
        "ip_recorded": bool(consent_ip and ip_address),
        "device_information_recorded": bool(consent_device),
        "password_stored": False,
        "status": "registered",
    }
