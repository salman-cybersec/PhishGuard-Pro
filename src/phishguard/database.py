import sqlite3

from phishguard.config import DATA_DIR


DATABASE_PATH = DATA_DIR / "phishguard.db"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    with get_connection() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tracking_code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                FOREIGN KEY (campaign_id)
                    REFERENCES campaigns(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_campaign
            ON events(campaign_id);

            CREATE INDEX IF NOT EXISTS idx_events_created
            ON events(created_at);
        """)


if __name__ == "__main__":
    initialize_database()
    print("PhishGuard Pro database initialized.")
