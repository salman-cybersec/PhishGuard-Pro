import qrcode

from pathlib import Path


def generate_qr_code(
    tracking_url: str,
    output_name: str,
) -> str:

    if not tracking_url.startswith(("http://", "https://")):
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    if not output_name.isalnum():
        raise ValueError("Output name must contain letters or numbers only.")

    output_dir = Path("reports/qr_codes")
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

    return str(output_path)
