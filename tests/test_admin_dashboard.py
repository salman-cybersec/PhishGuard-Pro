
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.admin_dashboard import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def admin_password(monkeypatch):
    password = "Test-Only-Admin-Password-2026!"
    monkeypatch.setenv("PHISHGUARD_ADMIN_PASSWORD", password)
    return password


def test_admin_login_page_is_available(client):
    response = client.get("/admin/login")

    assert response.status_code == 200
    assert "password" in response.text.lower()


def test_dashboard_requires_login(client):
    response = client.get("/admin/dashboard")

    assert response.status_code == 401


def test_invalid_admin_password_is_rejected(
    client,
    admin_password,
):
    response = client.post(
        "/admin/login",
        data={"password": "Incorrect-Password"},
    )

    assert response.status_code in (401, 403)


def test_valid_admin_login_creates_session(
    client,
    admin_password,
):
    response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert response.status_code in (302, 303)
    assert response.headers["location"].endswith(
        "/admin/dashboard"
    )
    assert "phishguard_admin_session" in response.cookies


def test_logout_clears_admin_session(
    client,
    admin_password,
):
    login_response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert login_response.status_code in (302, 303)

    logout_response = client.post("/admin/logout")

    assert logout_response.status_code in (302, 303, 200)

    dashboard_response = client.get("/admin/dashboard")

    assert dashboard_response.status_code == 401


def test_admin_login_cookie_is_secure_over_https(admin_password):
    app = FastAPI()
    app.include_router(router)
    client = TestClient(
        app,
        base_url="https://testserver",
        follow_redirects=False,
    )

    response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert response.status_code == 303

    cookie = response.headers["set-cookie"].lower()

    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=1800" in cookie
    assert "path=/admin" in cookie

    client.close()


def test_admin_login_cookie_is_not_secure_over_local_http(admin_password):
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app, follow_redirects=False)

    response = client.post(
        "/admin/login",
        data={"password": admin_password},
    )

    assert response.status_code == 303

    cookie = response.headers["set-cookie"].lower()

    assert "httponly" in cookie
    assert "secure" not in cookie
    assert "samesite=strict" in cookie
    assert "max-age=1800" in cookie
    assert "path=/admin" in cookie

    client.close()


@pytest.mark.parametrize(
    ("tool", "result_field", "marker"),
    [
        ("tls", "tls", "mock-tls-result"),
        ("headers", "headers", "mock-headers-result"),
        ("cookies", "cookie_security", "mock-cookies-result"),
        ("technology", "technologies", "mock-technology-result"),
    ],
)
def test_individual_security_tools_use_website_analyzer_only(
    monkeypatch,
    tool,
    result_field,
    marker,
):
    import phishguard.admin_dashboard as dashboard

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[dashboard.verify_admin_session] = lambda: {}

    client = TestClient(app)

    mock_result = {
        "url": "https://example.com",
        "hostname": "example.com",
        "tls": {},
        "headers": {},
        "cookie_security": {},
        "technologies": {},
    }
    mock_result[result_field] = {"result": marker}

    def mock_analyze_website(url):
        assert url == "https://example.com"
        return mock_result

    def unexpected_full_scan(*args, **kwargs):
        raise AssertionError("Individual tool must not trigger Full Scan.")

    monkeypatch.setattr(
        dashboard,
        "analyze_website",
        mock_analyze_website,
    )
    monkeypatch.setattr(
        dashboard,
        "analyze_full_website",
        unexpected_full_scan,
    )

    response = client.post(
        "/admin/security-tools/run",
        data={
            "url": "https://example.com",
            "tool": tool,
            "authorized": "yes",
        },
    )

    assert response.status_code == 200
    assert marker in response.text

    client.close()
