
import pytest

from phishguard.website_assets import _validate_image_content


def test_accepts_png_signature():
    content = b"\x89PNG\r\n\x1a\n" + b"image-data"

    _validate_image_content(content, ".png")


def test_accepts_jpeg_signature():
    content = b"\xff\xd8\xff" + b"image-data"

    _validate_image_content(content, ".jpg")


def test_accepts_webp_signature():
    content = (
        b"RIFF"
        + b"\x00\x00\x00\x00"
        + b"WEBP"
        + b"image-data"
    )

    _validate_image_content(content, ".webp")


@pytest.mark.parametrize(
    "extension,content",
    [
        (".png", b"not-a-png"),
        (".jpg", b"not-a-jpeg"),
        (".webp", b"not-a-webp"),
        (".png", b""),
        (".jpg", b"\xff"),
        (".webp", b"RIFF"),
    ],
)
def test_rejects_invalid_image_signature(extension, content):
    with pytest.raises(ValueError):
        _validate_image_content(content, extension)


def test_rejects_unknown_extension():
    with pytest.raises(ValueError):
        _validate_image_content(b"some-data", ".gif")
