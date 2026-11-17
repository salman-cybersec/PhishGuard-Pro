
import pytest

from phishguard import config


def test_build_preview_url_with_valid_id(monkeypatch):
    monkeypatch.setattr(
        config,
        "LOCAL_PREVIEW_BASE_URL",
        "http://127.0.0.1:3399",
    )

    preview_id = "A" * 24

    result = config.build_preview_url(preview_id)

    assert result == (
        "http://127.0.0.1:3399/preview/"
        + preview_id
    )


@pytest.mark.parametrize(
    "preview_id",
    [
        "",
        "short",
        "A" * 23,
        "A" * 25,
        "../" + "A" * 21,
        "A" * 23 + "/",
        "A" * 23 + "!",
        None,
        123,
    ],
)
def test_build_preview_url_rejects_invalid_id(preview_id):
    with pytest.raises(ValueError):
        config.build_preview_url(preview_id)


def test_build_preview_url_uses_configured_port(monkeypatch):
    monkeypatch.setattr(
        config,
        "LOCAL_PREVIEW_BASE_URL",
        "http://127.0.0.1:8080",
    )

    result = config.build_preview_url("B" * 24)

    assert result.startswith("http://127.0.0.1:8080/")
