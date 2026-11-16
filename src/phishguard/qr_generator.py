
from urllib.parse import urlsplit

import qrcode

from phishguard.config import REPORT_DIR


def generate_qr_code(
    tracking_url: str,
    output_name: str,
) -> str:

    if not isinstance(tracking_url, str):
        raise ValueError("Tracking URL must be text.")

    if not isinstance(output_name, str):
        raise ValueError("Output name must be text.")

    if not output_name or not output_name.isascii() or not output_name.isalnum():
        raise ValueError(
            "Output name must contain only English letters and numbers."
        )

    try:
        parsed_url = urlsplit(tracking_url)

        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
        ):
            raise ValueError("A valid HTTP or HTTPS URL is required.")

        parsed_url.port

    except ValueError as error:
        raise ValueError("Invalid tracking URL.") from error

    output_dir = REPORT_DIR / "qr_codes"

    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / f"{output_name}.png"

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )

        qr.add_data(tracking_url)
        qr.make(fit=True)

        image = qr.make_image(
            fill_color="black",
            back_color="white",
        )

        image.save(output_path)

    except OSError as error:
        raise RuntimeError("Unable to generate QR code.") from error

    return str(output_path)
