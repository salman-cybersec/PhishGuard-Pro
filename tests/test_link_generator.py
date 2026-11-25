import pytest

import phishguard.link_generator as generator
import phishguard.database as database


@pytest.fixture
def setup_database(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_BACKEND", "sqlite")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test.db",
    )
    monkeypatch.setattr(
        generator,
        "validate_website_authorization",
        lambda url: {
            "authorized": True,
            "hostname": "owned.example.com",
            "status": "approved",
        },
    )
    monkeypatch.setenv(
        "PHISHGUARD_ALLOWED_WEBSITE_DOMAINS",
        "owned.example.com",
    )
    database.initialize_database()


def test_create_generated_link(setup_database):
    link = generator.create_generated_link(
        "My Test Link",
        "https://owned.example.com/page",
    )

    assert link["name"] == "My Test Link"
    assert len(link["tracking_id"]) == 32
    assert link["status"] == "active"


def test_tracking_ids_are_unique(setup_database):
    first = generator.create_generated_link(
        "First",
        "https://owned.example.com/first",
    )
    second = generator.create_generated_link(
        "Second",
        "https://owned.example.com/second",
    )

    assert first["tracking_id"] != second["tracking_id"]


def test_invalid_destination_is_rejected(setup_database, monkeypatch):
    def reject_url(url):
        raise ValueError("Unauthorized domain.")

    monkeypatch.setattr(
        generator,
        "validate_website_authorization",
        reject_url,
    )

    with pytest.raises(ValueError):
        generator.create_generated_link(
            "Invalid",
            "https://untrusted.example/page",
        )


def test_event_without_consent_stores_no_metadata(setup_database):
    link = generator.create_generated_link(
        "Consent Test",
        "https://owned.example.com/page",
    )

    generator.record_generated_link_event(
        link["tracking_id"],
        source="direct",
    )

    with database.get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM generated_link_events
            WHERE generated_link_id = ?
            """,
            (link["id"],),
        ).fetchone()

    assert row["consent_ip"] == 0
    assert row["ip_address"] is None
    assert row["country_code"] is None
    assert row["consent_device"] == 0
    assert row["user_agent"] is None


def test_metadata_without_consent_is_rejected(setup_database):
    link = generator.create_generated_link(
        "Privacy Test",
        "https://owned.example.com/page",
    )

    with pytest.raises(ValueError, match="explicit consent"):
        generator.record_generated_link_event(
            link["tracking_id"],
            ip_address="8.8.8.8",
        )


def test_qr_and_direct_click_statistics(setup_database):
    link = generator.create_generated_link(
        "Statistics Test",
        "https://owned.example.com/page",
    )

    generator.record_generated_link_event(
        link["tracking_id"],
        source="direct",
    )
    generator.record_generated_link_event(
        link["tracking_id"],
        source="qr",
    )
    generator.record_generated_link_event(
        link["tracking_id"],
        source="qr",
    )

    stats = generator.get_generated_link_stats(
        link["tracking_id"]
    )

    assert stats["total_clicks"] == 3
    assert stats["direct_clicks"] == 1
    assert stats["qr_clicks"] == 2


def test_paused_link_cannot_record_events(setup_database):
    link = generator.create_generated_link(
        "Paused Test",
        "https://owned.example.com/page",
    )

    with database.get_connection() as connection:
        connection.execute(
            "UPDATE generated_links SET status = 'paused' WHERE id = ?",
            (link["id"],),
        )

    with pytest.raises(ValueError, match="inactive"):
        generator.record_generated_link_event(
            link["tracking_id"]
        )


def test_generated_link_history_returns_newest_first(setup_database):
    link = generator.create_generated_link(
        "History Test",
        "https://owned.example.com/page",
    )

    first = generator.record_generated_link_event(
        link["tracking_id"],
        source="direct",
    )
    second = generator.record_generated_link_event(
        link["tracking_id"],
        source="qr",
    )

    history = generator.get_generated_link_history(link["tracking_id"])

    assert history["total_events"] == 2
    assert len(history["events"]) == 2
    assert history["events"][0]["event_id"] == second["event_id"]
    assert history["events"][1]["event_id"] == first["event_id"]


def test_generated_link_history_respects_pagination(setup_database):
    link = generator.create_generated_link(
        "Pagination Test",
        "https://owned.example.com/page",
    )

    for _ in range(3):
        generator.record_generated_link_event(link["tracking_id"])

    first_page = generator.get_generated_link_history(
        link["tracking_id"],
        limit=2,
        offset=0,
    )
    second_page = generator.get_generated_link_history(
        link["tracking_id"],
        limit=2,
        offset=2,
    )

    assert first_page["total_events"] == 3
    assert len(first_page["events"]) == 2
    assert len(second_page["events"]) == 1



def test_paused_generated_link_history_remains_accessible(setup_database):
    link = generator.create_generated_link(
        "Paused History Test",
        "https://owned.example.com/page",
    )
    generator.record_generated_link_event(
        link["tracking_id"],
        source="direct",
    )
    generator.set_generated_link_status(link["tracking_id"], "paused")

    history = generator.get_generated_link_history(link["tracking_id"])

    assert history["total_events"] == 1
    assert history["events"][0]["source"] == "direct"


def test_history_rejects_unknown_tracking_id(setup_database):
    with pytest.raises(ValueError, match="not found"):
        generator.get_generated_link_history("A" * 32)


def test_history_does_not_expose_unconsented_metadata(setup_database):
    link = generator.create_generated_link(
        "Privacy History Test",
        "https://owned.example.com/page",
    )

    generator.record_generated_link_event(link["tracking_id"])

    history = generator.get_generated_link_history(link["tracking_id"])
    event = history["events"][0]

    assert event["ip_address"] is None
    assert event["country_code"] is None
    assert event["user_agent"] is None
    assert event["browser_name"] is None
    assert event["os_name"] is None
    assert event["device_type"] is None


@pytest.mark.parametrize(
    ("limit", "offset"),
    [
        (0, 0),
        (201, 0),
        (True, 0),
        (50, -1),
        (50, True),
    ],
)
def test_history_rejects_invalid_pagination(setup_database, limit, offset):
    link = generator.create_generated_link(
        "Invalid Pagination Test",
        "https://owned.example.com/page",
    )

    with pytest.raises(ValueError):
        generator.get_generated_link_history(
            link["tracking_id"],
            limit=limit,
            offset=offset,
        )


def test_pause_and_resume_generated_link(setup_database):
    link = generator.create_generated_link(
        "Pause Resume Test",
        "https://owned.example.com/page",
    )

    paused = generator.set_generated_link_status(
        link["tracking_id"], "paused"
    )
    assert paused["status"] == "paused"

    with pytest.raises(ValueError, match="inactive"):
        generator.resolve_generated_link(link["tracking_id"])

    resumed = generator.set_generated_link_status(
        link["tracking_id"], "active"
    )
    assert resumed["status"] == "active"

    resolved = generator.resolve_generated_link(link["tracking_id"])
    assert resolved["tracking_id"] == link["tracking_id"]


def test_status_update_rejects_invalid_status(setup_database):
    link = generator.create_generated_link(
        "Invalid Status Test",
        "https://owned.example.com/page",
    )

    with pytest.raises(ValueError, match="Status must"):
        generator.set_generated_link_status(
            link["tracking_id"], "deleted"
        )


def test_status_update_rejects_unknown_tracking_id(setup_database):
    with pytest.raises(ValueError, match="not found"):
        generator.set_generated_link_status(
            "A" * 32, "paused"
        )


def test_bulk_generation_creates_unique_links(setup_database):
    links = generator.create_generated_links(
        "Bulk Test",
        "https://owned.example.com/page",
        5,
    )

    assert len(links) == 5
    assert len({link["tracking_id"] for link in links}) == 5
    assert [link["name"] for link in links] == [
        f"Bulk Test-{i:03d}" for i in range(1, 6)
    ]


@pytest.mark.parametrize("count", [0, 101, -1, True, 1.5])
def test_bulk_generation_rejects_invalid_count(setup_database, count):
    with pytest.raises(ValueError, match="Bulk count"):
        generator.create_generated_links(
            "Bulk Test",
            "https://owned.example.com/page",
            count,
        )


def test_bulk_generation_rejects_long_name_before_creation(setup_database):
    with pytest.raises(ValueError, match="96 characters"):
        generator.create_generated_links(
            "N" * 97,
            "https://owned.example.com/page",
            2,
        )

    with database.get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM generated_links"
        ).fetchone()[0]

    assert total == 0


def test_date_range_analytics_returns_daily_source_totals(setup_database):
    link = generator.create_generated_link(
        "Analytics Test", "https://owned.example.com/page"
    )

    for source in ("direct", "direct", "qr"):
        event = generator.record_generated_link_event(
            link["tracking_id"], source=source
        )
        with database.get_connection() as connection:
            connection.execute(
                "UPDATE generated_link_events SET created_at = ? WHERE id = ?",
                ("2026-11-20 10:00:00", event["event_id"]),
            )

    result = generator.get_generated_link_analytics(
        "2026-11-20", "2026-11-21"
    )

    assert result["total_events"] == 3
    assert result["direct_events"] == 2
    assert result["qr_events"] == 1
    assert result["daily"][0]["event_date"] == "2026-11-20"


@pytest.mark.parametrize(
    "start,end",
    [
        ("invalid", "2026-11-21"),
        ("2026-11-22", "2026-11-21"),
    ],
)
def test_date_range_analytics_rejects_invalid_ranges(setup_database, start, end):
    with pytest.raises(ValueError):
        generator.get_generated_link_analytics(start, end)


@pytest.mark.parametrize("status", [["paused"], {"status": "paused"}, None])
def test_status_update_rejects_non_string_status(setup_database, status):
    link = generator.create_generated_link(
        "Invalid Type Status", "https://owned.example.com/page"
    )

    with pytest.raises(ValueError, match="Status must"):
        generator.set_generated_link_status(link["tracking_id"], status)


@pytest.mark.parametrize("source", [["direct"], {"source": "qr"}, None])
def test_event_rejects_non_string_source(setup_database, source):
    link = generator.create_generated_link(
        "Invalid Type Source", "https://owned.example.com/page"
    )

    with pytest.raises(ValueError, match="Source must"):
        generator.record_generated_link_event(
            link["tracking_id"], source=source
        )


@pytest.mark.parametrize("device_type", [["desktop"], {"type": "desktop"}])
def test_event_rejects_non_string_device_type(setup_database, device_type):
    link = generator.create_generated_link(
        "Invalid Device Type", "https://owned.example.com/page"
    )

    with pytest.raises(ValueError, match="device type"):
        generator.record_generated_link_event(
            link["tracking_id"],
            consent_device=True,
            device_type=device_type,
        )


def test_bulk_generation_rolls_back_all_links_on_failure(
    setup_database, monkeypatch
):
    existing = generator.create_generated_link(
        "Existing Bulk Link", "https://owned.example.com/page"
    )

    generated_ids = iter(["B" * 32] + [existing["tracking_id"]] * 5)
    monkeypatch.setattr(
        generator.secrets,
        "token_urlsafe",
        lambda _: next(generated_ids),
    )

    with pytest.raises(RuntimeError, match="unique tracking ID"):
        generator.create_generated_links(
            "Atomic Bulk", "https://owned.example.com/page", 2
        )

    with database.get_connection() as connection:
        rows = connection.execute(
            "SELECT name FROM generated_links ORDER BY id"
        ).fetchall()

    assert [row["name"] for row in rows] == ["Existing Bulk Link"]


@pytest.mark.parametrize(
    "ip_address",
    [134744072, b"\\x08\\x08\\x08\\x08", ["8.8.8.8"], {"ip": "8.8.8.8"}],
)
def test_event_rejects_non_string_ip_address(setup_database, ip_address):
    link = generator.create_generated_link(
        "Invalid IP Type", "https://owned.example.com/page"
    )

    with pytest.raises(ValueError, match="Invalid IP address"):
        generator.record_generated_link_event(
            link["tracking_id"],
            consent_ip=True,
            ip_address=ip_address,
        )
