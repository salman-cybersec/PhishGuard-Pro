
import importlib

import pytest

import phishguard.config as config


def test_sqlite_is_the_default_backend(monkeypatch):
    monkeypatch.delenv(
        "PHISHGUARD_DATABASE_BACKEND",
        raising=False,
    )
    monkeypatch.delenv(
        "PHISHGUARD_DATABASE_URL",
        raising=False,
    )

    reloaded = importlib.reload(config)

    assert reloaded.DATABASE_BACKEND == "sqlite"


def test_sqlite_backend_is_accepted(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_DATABASE_BACKEND",
        "sqlite",
    )

    reloaded = importlib.reload(config)

    assert reloaded.DATABASE_BACKEND == "sqlite"


def test_postgresql_backend_is_blocked(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_DATABASE_BACKEND",
        "postgresql",
    )
    monkeypatch.setenv(
        "PHISHGUARD_DATABASE_URL",
        "postgresql://test:test@localhost/test",
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL is temporarily disabled",
    ):
        importlib.reload(config)


def test_invalid_database_backend_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_DATABASE_BACKEND",
        "mysql",
    )

    with pytest.raises(
        ValueError,
        match="must be sqlite",
    ):
        importlib.reload(config)
