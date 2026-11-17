
import os
from contextlib import contextmanager

from phishguard.config import (
    DATABASE_BACKEND,
    DATABASE_URL,
)


_pool = None


def _get_postgres_pool():
    global _pool

    if DATABASE_BACKEND != "postgresql":
        raise RuntimeError(
            "PostgreSQL backend is not enabled."
        )

    if _pool is None:
        from psycopg_pool import ConnectionPool

        _pool = ConnectionPool(
            conninfo=DATABASE_URL,
            min_size=1,
            max_size=int(
                os.getenv("PHISHGUARD_DB_POOL_SIZE", "10")
            ),
            timeout=10,
            open=True,
        )

    return _pool


@contextmanager
def get_database_connection():
    if DATABASE_BACKEND == "postgresql":
        pool = _get_postgres_pool()

        with pool.connection() as connection:
            yield connection

    else:
        import sqlite3

        from phishguard.database import DATABASE_PATH

        connection = sqlite3.connect(
            DATABASE_PATH,
            timeout=10,
        )

        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")

            yield connection
            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()


def close_database_pool():
    global _pool

    if _pool is not None:
        _pool.close()
        _pool = None
