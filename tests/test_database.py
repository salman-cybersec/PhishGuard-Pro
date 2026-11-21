
import sqlite3

import phishguard.database as database


def configure_test_database(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_BACKEND", "sqlite")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_phishguard.db",
    )


def test_initialize_database_creates_required_tables(
    monkeypatch,
    tmp_path,
):
    configure_test_database(monkeypatch, tmp_path)

    database.initialize_database()

    with database.get_connection() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

    assert {"campaigns", "participants", "events"}.issubset(tables)


def test_database_integrity_is_valid(
    monkeypatch,
    tmp_path,
):
    configure_test_database(monkeypatch, tmp_path)

    database.initialize_database()

    assert database.verify_database_integrity() is True


def test_database_version_is_five(
    monkeypatch,
    tmp_path,
):
    configure_test_database(monkeypatch, tmp_path)

    database.initialize_database()

    assert database.get_database_version() == 5


def test_initialize_database_adds_missing_columns(
    monkeypatch,
    tmp_path,
):
    configure_test_database(monkeypatch, tmp_path)

    database.DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database.DATABASE_PATH)

    try:
        connection.executescript(
            """
            CREATE TABLE campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tracking_code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL
            );

            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    database.initialize_database()

    with database.get_connection() as connection:
        participant_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(participants)"
            ).fetchall()
        }

        event_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(events)"
            ).fetchall()
        }

    assert "consent_activity" in participant_columns
    assert "participant_id" in event_columns
