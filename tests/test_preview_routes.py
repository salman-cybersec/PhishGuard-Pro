
import hashlib

from fastapi.testclient import TestClient

from phishguard import server


def test_preview_route_serves_html(tmp_path, monkeypatch):
    preview_id = "a" * 24
    preview_file = tmp_path / f"{preview_id}.html"
    preview_file.write_text(
        "<html><body>Authorized training preview</body></html>",
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "PREVIEW_DIR", tmp_path)

    client = TestClient(server.app)
    response = client.get(f"/preview/{preview_id}")

    assert response.status_code == 200
    assert "Authorized training preview" in response.text
    assert "text/html" in response.headers["content-type"]
    assert "script-src 'none'" in response.headers.get(
        "content-security-policy", ""
    )


def test_preview_route_rejects_invalid_id():
    client = TestClient(server.app)

    response = client.get("/preview/invalid-id")

    assert response.status_code == 404


def test_preview_route_rejects_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "PREVIEW_DIR", tmp_path)

    client = TestClient(server.app)
    response = client.get(f"/preview/{'b' * 24}")

    assert response.status_code == 404


def test_asset_route_serves_valid_png(tmp_path, monkeypatch):
    content = b"\x89PNG\r\n\x1a\n" + b"test-image-data"
    digest = hashlib.sha256(content).hexdigest()
    filename = f"{digest}.png"

    (tmp_path / filename).write_bytes(content)
    monkeypatch.setattr(server, "ASSET_DIR", tmp_path)

    client = TestClient(server.app)
    response = client.get(f"/assets/{filename}")

    assert response.status_code == 200
    assert response.content == content
    assert "image/png" in response.headers["content-type"]


def test_asset_route_serves_valid_css(tmp_path, monkeypatch):
    content = b".phishguard-preview { color: black; }"
    digest = hashlib.sha256(content).hexdigest()
    filename = f"{digest}.css"

    (tmp_path / filename).write_bytes(content)
    monkeypatch.setattr(server, "ASSET_DIR", tmp_path)

    client = TestClient(server.app)
    response = client.get(f"/assets/{filename}")

    assert response.status_code == 200
    assert response.content == content
    assert "text/css" in response.headers["content-type"]


def test_asset_route_rejects_hash_mismatch(tmp_path, monkeypatch):
    expected_content = b"expected content"
    actual_content = b"different content"

    digest = hashlib.sha256(expected_content).hexdigest()
    filename = f"{digest}.png"

    (tmp_path / filename).write_bytes(actual_content)
    monkeypatch.setattr(server, "ASSET_DIR", tmp_path)

    client = TestClient(server.app)
    response = client.get(f"/assets/{filename}")

    assert response.status_code == 404


def test_asset_route_rejects_invalid_filename():
    client = TestClient(server.app)

    response = client.get("/assets/../../secret.png")

    assert response.status_code == 404


def test_asset_route_rejects_unsupported_extension():
    client = TestClient(server.app)

    response = client.get(
        f"/assets/{'c' * 64}.html"
    )

    assert response.status_code == 404
