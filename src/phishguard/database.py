
import sqlite3
from contextlib import contextmanager

from phishguard.config import (
    DATA_DIR,
    DATABASE_BACKEND,
)

DATABASE_PATH = DATA_DIR / "phishguard.db"
DATABASE_TIMEOUT = 10
DATABASE_VERSION = 3


@contextmanager
def get_connection():
    if DATABASE_BACKEND == "postgresql":
        from phishguard.db_backend import get_database_connection

        with get_database_connection() as connection:
            yield connection

        return

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=DATABASE_TIMEOUT,
    )

    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")

        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def _get_columns(connection, table_name):
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {row["name"] for row in rows}


def _add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition,
):
    if column_name not in _get_columns(connection, table_name):
        connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN "
            f"{column_name} {column_definition}"
        )


def initialize_database():
    if DATABASE_BACKEND == "postgresql":
        from phishguard.db_backend import get_database_connection
        from phishguard.schema import initialize_schema

        with get_database_connection() as connection:
            initialize_schema(connection)

        return

    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode=WAL")

        connection.executescript("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 100),
                tracking_code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'draft'
                    CHECK(status IN (
                        'draft', 'active', 'paused', 'completed'
                    )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                participant_token TEXT NOT NULL
                    CHECK(length(participant_token) BETWEEN 20 AND 100),
                participant_name TEXT NOT NULL
                    CHECK(length(participant_name) BETWEEN 1 AND 100),
                submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                consent_ip INTEGER NOT NULL DEFAULT 0
                    CHECK(consent_ip IN (0,1)),
                ip_address TEXT
                    CHECK(ip_address IS NULL OR length(ip_address)<=45),
                consent_device INTEGER NOT NULL DEFAULT 0
                    CHECK(consent_device IN (0,1)),
                user_agent TEXT
                    CHECK(user_agent IS NULL OR length(user_agent)<=500),
                browser_name TEXT,
                browser_version TEXT,
                os_name TEXT,
                device_type TEXT,
                consent_activity INTEGER NOT NULL DEFAULT 0
                    CHECK(consent_activity IN (0,1)),
                FOREIGN KEY(campaign_id)
                    REFERENCES campaigns(id) ON DELETE CASCADE,
                UNIQUE(campaign_id, participant_token),
                CHECK(consent_ip=1 OR ip_address IS NULL),
                CHECK(
                    consent_device=1 OR (
                        user_agent IS NULL
                        AND browser_name IS NULL
                        AND browser_version IS NULL
                        AND os_name IS NULL
                        AND device_type IS NULL
                    )
                )
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL CHECK(event_type IN (
                    'page_visit',
                    'training_page_view',
                    'form_interaction',
                    'simulation_complete'
                )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                participant_id INTEGER,
                FOREIGN KEY(campaign_id)
                    REFERENCES campaigns(id) ON DELETE CASCADE,
                FOREIGN KEY(participant_id)
                    REFERENCES participants(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_participants_campaign
            ON participants(campaign_id);

            CREATE INDEX IF NOT EXISTS idx_events_campaign_created
            ON events(campaign_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_events_participant
            ON events(participant_id);
        """)

        _add_column_if_missing(
            connection,
            "events",
            "participant_id",
            "INTEGER REFERENCES participants(id) ON DELETE SET NULL",
        )

        _add_column_if_missing(
            connection,
            "participants",
            "consent_activity",
            "INTEGER NOT NULL DEFAULT 0 CHECK(consent_activity IN (0,1))",
        )

        connection.execute(
            "PRAGMA user_version=3"
        )


def verify_database_integrity():
    if DATABASE_BACKEND == "postgresql":
        from phishguard.db_backend import get_database_connection

        with get_database_connection() as connection:
            connection.execute("SELECT 1").fetchone()

        return True

    with get_connection() as connection:
        result = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()

        return bool(result and result[0] == "ok")


def get_database_version():
    if DATABASE_BACKEND == "postgresql":
        from phishguard.db_backend import get_database_connection

        with get_database_connection() as connection:
            row = connection.execute(
                "SELECT version FROM schema_version "
                "ORDER BY version DESC LIMIT 1"
            ).fetchone()

            return row["version"] if row else 0

    with get_connection() as connection:
        row = connection.execute(
            "PRAGMA user_version"
        ).fetchone()

        return row[0]


if __name__ == "__main__":
    initialize_database()
