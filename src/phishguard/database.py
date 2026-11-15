
import sqlite3

from phishguard.config import DATA_DIR


DATABASE_PATH = DATA_DIR / "phishguard.db"
DATABASE_TIMEOUT = 10


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=DATABASE_TIMEOUT,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")

    return connection


def initialize_database():
    with get_connection() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 100),
                tracking_code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'draft'
                    CHECK(status IN (
                        'draft',
                        'active',
                        'paused',
                        'completed'
                    )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL
                    CHECK(event_type IN (
                        'page_visit',
                        'training_page_view',
                        'form_interaction',
                        'simulation_complete'
                    )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
                    CHECK(user_agent IS NULL OR length(user_agent) <= 500),
                FOREIGN KEY (campaign_id)
                    REFERENCES campaigns(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_campaign
            ON events(campaign_id);

            CREATE INDEX IF NOT EXISTS idx_events_created
            ON events(created_at);
        """)


def verify_database_integrity():
    with get_connection() as connection:
        result = connection.execute(
            "PRAGMA integrity_check"
        ).fetchone()

        return result[0] == "ok"


if __name__ == "__main__":
    initialize_database()
    print("Database initialized.")

    if verify_database_integrity():
        print("Database integrity verified.")
    else:
        print("Database integrity check failed.")
