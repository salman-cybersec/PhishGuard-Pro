"""Safe terminal output for consent-based training activity events."""

import logging
import re


LOGGER = logging.getLogger("phishguard.monitor")


def _safe_label(value: str | None) -> str | None:
    if not value:
        return None

    # Keep untrusted participant/browser strings on a single log line.
    cleaned = re.sub(r"[\r\n\t]+", " ", str(value)).strip()
    return cleaned[:120] or None


def log_training_event(
    *,
    event_type: str,
    campaign_id: int,
    participant_name: str | None = None,
    ip_address: str | None = None,
    browser_name: str | None = None,
    os_name: str | None = None,
    device_type: str | None = None,
) -> None:
    """Log only submitted identity and telemetry fields covered by consent."""
    details = [f"campaign_id={campaign_id}"]

    safe_name = _safe_label(participant_name)
    if safe_name:
        details.append(f"participant={safe_name!r}")

    if ip_address:
        details.append(f"ip={_safe_label(ip_address)}")

    device = " / ".join(
        value for value in (
            _safe_label(browser_name),
            _safe_label(os_name),
            _safe_label(device_type),
        )
        if value
    )
    if device:
        details.append(f"device={device!r}")

    LOGGER.info("TRAINING EVENT | %s | %s", event_type, " | ".join(details))
