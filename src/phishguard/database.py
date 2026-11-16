
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
    connection.execute("PRAGMA synchronous = FULL")

    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")

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

            CREATE TABLE IF NOT EXISTS participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                campaign_id INTEGER NOT NULL,

                participant_token TEXT NOT NULL
                    CHECK(length(participant_token) BETWEEN 20 AND 100),

                participant_name TEXT NOT NULL
                    CHECK(length(participant_name) BETWEEN 1 AND 100),

                submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                consent_ip INTEGER NOT NULL DEFAULT 0
                    CHECK(consent_ip IN (0, 1)),

                ip_address TEXT
                    CHECK(ip_address IS NULL OR length(ip_address) <= 45),

                consent_device INTEGER NOT NULL DEFAULT 0
                    CHECK(consent_device IN (0, 1)),

                user_agent TEXT
                    CHECK(user_agent IS NULL OR length(user_agent) <= 500),

                browser_name TEXT
                    CHECK(browser_name IS NULL OR length(browser_name) <= 100),

                browser_version TEXT
                    CHECK(browser_version IS NULL OR length(browser_version) <= 50),

                os_name TEXT
                    CHECK(os_name IS NULL OR length(os_name) <= 100),

                device_type TEXT
                    CHECK(device_type IS NULL OR device_type IN (
                        'desktop',
                        'mobile',
                        'tablet',
                        'unknown'
                    )),

                FOREIGN KEY (campaign_id)
                    REFERENCES campaigns(id)
                    ON DELETE CASCADE,

                UNIQUE (campaign_id, participant_token),

                CHECK (
                    consent_ip = 1 OR ip_address IS NULL
                ),

                CHECK (
                    consent_device = 1 OR (
                        user_agent IS NULL
                        AND browser_name IS NULL
                        AND browser_version IS NULL
                        AND os_name IS NULL
                        AND device_type IS NULL
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS idx_events_campaign
            ON events(campaign_id);

            CREATE INDEX IF NOT EXISTS idx_events_created
            ON events(created_at);

            CREATE INDEX IF NOT EXISTS idx_participants_campaign
            ON participants(campaign_id);

            CREATE INDEX IF NOT EXISTS idx_participants_token
            ON participants(participant_token);
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
