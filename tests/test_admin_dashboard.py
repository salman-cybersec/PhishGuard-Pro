
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from phishguard.admin_dashboard import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, follow_redirects=False, headers={"Origin": "http://testserver"})


@pytest.fixture
def admin_password(monkeypatch):
    password = "Test-Only-Admin-Password-2026!"
    monkeypatch.setenv("PHISHGUARD_ADMIN_PASSWORD", password)
    return password


def test_admin_login_page_is_available(client):
    response = client.get("/admin/login")

    assert response.status_code == 200
    assert "password" in response.text.lower()


def test_admin_post_rejects_cross_origin(client, admin_password):
    response = client.post(
        "/admin/login",
        headers={"Origin": "https://attacker.example"},
        data={"password": admin_password},
    )
    assert response.status_code == 403


def test_admin_post_rejects_missing_origin_and_referer(client, admin_password):
    response = client.post(
        "/admin/login",
        headers={"Origin": "", "Referer": ""},
        data={"password": admin_password},
    )
    assert response.status_code == 403


def test_admin_post_accepts_same_origin_referer(client, admin_password):
    response = client.post(
        "/admin/login",
        headers={"Origin": "", "Referer": "http://testserver/admin/login"},
        data={"password": admin_password},
    )
    assert response.status_code in (302, 303)


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
        headers={"Origin": "https://testserver"},
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
    client = TestClient(app, follow_redirects=False, headers={"Origin": "http://testserver"})

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

    client = TestClient(app, headers={"Origin": "http://testserver"})

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


@pytest.fixture
def link_generator_client(monkeypatch, tmp_path):
    import phishguard.admin_dashboard as dashboard
    import phishguard.database as database

    monkeypatch.setattr(database, "DATABASE_BACKEND", "sqlite")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "dashboard-test.db")

    database.initialize_database()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[dashboard.verify_admin_session] = lambda: {}

    with TestClient(app, follow_redirects=False, headers={"Origin": "http://testserver"}) as test_client:
        yield test_client


def test_link_generator_dashboard_requires_login(client):
    response = client.get("/admin/link-generator")

    assert response.status_code == 401


def test_link_generator_dashboard_loads_for_admin(link_generator_client):
    response = link_generator_client.get("/admin/link-generator")

    assert response.status_code == 200
    assert "Link Generator" in response.text
    assert "Create a tracking link" in response.text
    assert "Generated links" in response.text
    assert "Total Links" in response.text
    assert "Active Links" in response.text
    assert "Paused Links" in response.text
    assert "Total Events" in response.text
    assert "Direct Events" in response.text
    assert "QR Events" in response.text
    assert "<strong>0</strong>" in response.text


def test_link_generator_create_route_creates_link(
    link_generator_client,
    monkeypatch,
):
    import phishguard.admin_dashboard as dashboard

    created = {}

    def mock_create(name, destination_url):
        created["name"] = name
        created["destination_url"] = destination_url

    monkeypatch.setattr(dashboard, "create_generated_link", mock_create)

    response = link_generator_client.post(
        "/admin/link-generator/create",
        data={
            "name": "Authorized Test",
            "destination_url": "https://owned.example.com/page",
            "authorized": "yes",
        },
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/link-generator"
    assert created["name"] == "Authorized Test"
    assert created["destination_url"] == "https://owned.example.com/page"


def test_link_generator_create_requires_authorization(
    link_generator_client,
    monkeypatch,
):
    import phishguard.admin_dashboard as dashboard

    def unexpected_create(*args, **kwargs):
        raise AssertionError("Link creation must not run without authorization.")

    monkeypatch.setattr(dashboard, "create_generated_link", unexpected_create)

    response = link_generator_client.post(
        "/admin/link-generator/create",
        data={
            "name": "Unauthorized Test",
            "destination_url": "https://owned.example.com/page",
            "authorized": "no",
        },
    )

    assert response.status_code == 400
    assert "Authorization confirmation is required" in response.text


def test_link_generator_rejects_invalid_destination(
    link_generator_client,
    monkeypatch,
):
    import phishguard.admin_dashboard as dashboard

    def reject_destination(name, destination_url):
        raise ValueError("Destination is not authorized.")

    monkeypatch.setattr(
        dashboard,
        "create_generated_link",
        reject_destination,
    )

    response = link_generator_client.post(
        "/admin/link-generator/create",
        data={
            "name": "Invalid Destination",
            "destination_url": "https://untrusted.example/page",
            "authorized": "yes",
        },
    )

    assert response.status_code == 400
    assert "Destination is not authorized" in response.text


def test_generated_link_history_displays_events_and_pagination(
    link_generator_client,
    monkeypatch,
):
    import phishguard.admin_dashboard as dashboard

    captured = {}

    def mock_history(tracking_id, limit=50, offset=0):
        captured.update(tracking_id=tracking_id, limit=limit, offset=offset)
        return {
            "tracking_id": tracking_id,
            "total_events": 120,
            "limit": limit,
            "offset": offset,
            "events": [{
                "event_id": 1,
                "created_at": "2026-11-22 10:00:00",
                "source": "direct",
                "consent_ip": 0,
                "ip_address": None,
                "country_code": None,
                "consent_device": 0,
                "browser_name": None,
                "os_name": None,
                "device_type": None,
                "user_agent": None,
            }],
        }

    monkeypatch.setattr(dashboard, "get_generated_link_history", mock_history)

    response = link_generator_client.get(
        "/admin/link-generator/" + "A" * 32 + "/history?offset=50"
    )

    assert response.status_code == 200
    assert "Generated Link History" in response.text
    assert "Not collected" in response.text
    assert "?offset=0" in response.text
    assert "?offset=100" in response.text
    assert captured == {
        "tracking_id": "A" * 32,
        "limit": 50,
        "offset": 50,
    }


def test_generated_link_history_rejects_unknown_tracking_id(
    link_generator_client,
    monkeypatch,
):
    import phishguard.admin_dashboard as dashboard

    def missing_history(*args, **kwargs):
        raise ValueError("Tracking link not found.")

    monkeypatch.setattr(
        dashboard,
        "get_generated_link_history",
        missing_history,
    )

    response = link_generator_client.get(
        "/admin/link-generator/" + "B" * 32 + "/history"
    )

    assert response.status_code == 404
    assert "Tracking link not found" in response.text


def test_generated_link_analytics_requires_login(client):
    response = client.get("/admin/link-generator/analytics")
    assert response.status_code == 401


def test_generated_link_analytics_displays_report(link_generator_client):
    response = link_generator_client.get(
        "/admin/link-generator/analytics",
        params={"start_date": "2026-11-20", "end_date": "2026-11-22"},
    )

    assert response.status_code == 200
    assert "Generated Link Analytics" in response.text
    assert "Total Events" in response.text
    assert "Direct Events" in response.text
    assert "QR Events" in response.text
    assert "Daily Breakdown" in response.text


def test_generated_link_analytics_rejects_invalid_date(link_generator_client):
    response = link_generator_client.get(
        "/admin/link-generator/analytics",
        params={"start_date": "invalid", "end_date": "2026-11-22"},
    )
    assert response.status_code == 400


def test_web_importer_dashboard_requires_login(client):
    response = client.get("/admin/web-importer")
    assert response.status_code == 401


def test_web_importer_post_requires_login(client):
    response = client.post(
        "/admin/web-importer/import",
        data={
            "url": "https://authorized.example",
            "authorized": "yes",
        },
    )
    assert response.status_code == 401


def test_web_importer_rejects_unapproved_domain(
    client, admin_password, monkeypatch
):
    import phishguard.admin_dashboard as dashboard

    login = client.post(
        "/admin/login",
        data={"password": admin_password},
    )
    assert login.status_code in (302, 303)

    def reject_url(url):
        raise ValueError("Domain is not on the authorization allowlist.")

    def unexpected_import(url):
        raise AssertionError("Import must not run for an unapproved domain.")

    monkeypatch.setattr(
        dashboard, "validate_website_authorization", reject_url
    )
    monkeypatch.setattr(dashboard, "import_website", unexpected_import)

    response = client.post(
        "/admin/web-importer/import",
        data={
            "url": "https://unauthorized.example",
            "authorized": "yes",
        },
    )

    assert response.status_code == 400
    assert "allowlist" in response.text.lower()


def test_web_importer_success_shows_sanitized_preview(
    client, admin_password, monkeypatch
):
    import phishguard.admin_dashboard as dashboard

    login = client.post(
        "/admin/login",
        data={"password": admin_password},
    )
    assert login.status_code in (302, 303)

    monkeypatch.setattr(
        dashboard,
        "validate_website_authorization",
        lambda url: {
            "authorized": True,
            "hostname": "authorized.example",
            "status": "approved",
        },
    )
    monkeypatch.setattr(
        dashboard,
        "import_website",
        lambda url: {
            "website": url,
            "preview_id": "a" * 24,
            "preview_type": "sanitized_static_html",
            "assets_found": 5,
            "assets_imported": 3,
            "assets_skipped": 2,
            "status": "import_completed",
        },
    )
    monkeypatch.setattr(
        dashboard,
        "build_preview_url",
        lambda preview_id: f"/preview/{preview_id}",
    )

    response = client.post(
        "/admin/web-importer/import",
        data={
            "url": "https://authorized.example",
            "authorized": "yes",
        },
    )

    assert response.status_code == 200
    assert "Website Import Completed" in response.text
    assert "/preview/" + ("a" * 24) in response.text
    assert "Assets imported: 3" in response.text
    assert "JavaScript executed: No" in response.text
    assert "Credentials collected: No" in response.text



@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("internal connection detail"),
        OSError("internal storage detail"),
    ],
)
def test_web_importer_handles_operational_failures_safely(
    client, admin_password, monkeypatch, failure
):
    import phishguard.admin_dashboard as dashboard

    login = client.post(
        "/admin/login",
        data={"password": admin_password},
    )
    assert login.status_code in (302, 303)

    monkeypatch.setattr(
        dashboard,
        "validate_website_authorization",
        lambda url: {"authorized": True},
    )

    def fail_import(url):
        raise failure

    monkeypatch.setattr(dashboard, "import_website", fail_import)

    response = client.post(
        "/admin/web-importer/import",
        data={
            "url": "https://authorized.example",
            "authorized": "yes",
        },
    )

    assert response.status_code == 502
    assert "network or storage error" in response.text.lower()
    assert "internal connection detail" not in response.text
    assert "internal storage detail" not in response.text


def test_all_phishing_service_pages_load():
    import phishguard.admin_dashboard as dashboard

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[dashboard.verify_admin_session] = lambda: {}

    with TestClient(app) as test_client:
        listing = test_client.get("/admin/phishing-links")
        assert listing.status_code == 200

        for slug, service_name in dashboard._RED_TEAM_SERVICES:
            response = test_client.get(f"/admin/phishing-links/{slug}")
            assert response.status_code == 200, (
                f"{service_name} ({slug}) returned {response.status_code}: "
                f"{response.text[:300]}"
            )
            assert f"{service_name} Security Review Workspace" in response.text

        invalid = test_client.get("/admin/phishing-links/invalid-service")
        assert invalid.status_code == 404


def test_phishing_service_page_requires_admin_login(client):
    response = client.get("/admin/phishing-links/facebook")
    assert response.status_code == 401


def test_facebook_workspace_has_service_specific_local_modules():
    import phishguard.admin_dashboard as dashboard

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[dashboard.verify_admin_session] = lambda: {}

    with TestClient(app) as test_client:
        response = test_client.get("/admin/phishing-links/facebook")

    assert response.status_code == 200

    for module in (
        "Facebook Page Access Review",
        "Meta Business Portfolio Audit",
        "Account Recovery Readiness",
        "Impersonation & Brand Protection",
        "Public Profile Security Review",
    ):
        assert module in response.text

    assert "facebook.com/security/" in response.text
    assert "No network request or data storage occurred." in response.text
    assert 'type="password"' not in response.text
    assert "name=" + '"otp"' not in response.text
    assert "fetch(" not in response.text


def test_service_workspaces_have_complete_service_specific_content():
    import phishguard.admin_dashboard as dashboard
    from phishguard.service_workspaces import SERVICE_WORKSPACES

    expected = {
        slug for slug, _ in dashboard._RED_TEAM_SERVICES
    }
    assert set(SERVICE_WORKSPACES) == expected

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[dashboard.verify_admin_session] = lambda: {}

    with TestClient(app) as test_client:
        for slug, config in SERVICE_WORKSPACES.items():
            assert len(config["modules"]) == 3, slug
            assert len({title for title, _ in config["modules"]}) == 3, slug
            assert all(len(checks) == 3 for _, checks in config["modules"]), slug

            response = test_client.get(f"/admin/phishing-links/{slug}")
            assert response.status_code == 200, slug
            assert "Local Assessment Simulator" in response.text
            assert "Official " in response.text
            assert config["url"] in response.text

            if slug != "facebook":
                for title, _ in config["modules"]:
                    assert title in response.text, f"{slug}: missing {title}"

            assert 'type="password"' not in response.text
            assert "fetch(" not in response.text


def test_admin_login_accepts_null_origin_with_same_origin_referer(client, admin_password):
    response = client.post(
        "/admin/login",
        headers={
            "Origin": "null",
            "Referer": "http://testserver/admin/login",
        },
        data={"password": admin_password},
    )
    assert response.status_code == 303


def test_admin_login_rejects_null_origin_with_cross_origin_referer(client, admin_password):
    response = client.post(
        "/admin/login",
        headers={
            "Origin": "null",
            "Referer": "https://attacker.example/admin/login",
        },
        data={"password": admin_password},
    )
    assert response.status_code == 403
