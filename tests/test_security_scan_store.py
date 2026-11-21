import json
import sqlite3

import pytest

from phishguard.security_scan_store import save_security_scan


@pytest.fixture
def scan_database(tmp_path, monkeypatch):
    import phishguard.database as database

    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", db_path)
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)

    connection = sqlite3.connect(db_path)
    connection.execute("""
        CREATE TABLE security_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            security_score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            html_report_path TEXT,
            json_report_path TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.commit()
    connection.close()

    return db_path


def sample_result():
    return {
        "hostname": "example.com",
        "url": "https://example.com/",
        "risk_level": "medium",
        "security_score": {"score": 92, "grade": "A"},
        "findings": [
            {
                "severity": "medium",
                "finding": "Missing CSP",
                "remediation": "Configure Content-Security-Policy",
            }
        ],
    }


def test_save_security_scan(scan_database):
    scan_id = save_security_scan(sample_result())

    connection = sqlite3.connect(scan_database)
    row = connection.execute(
        "SELECT hostname, security_score, grade, risk_level, findings_json "
        "FROM security_scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    connection.close()

    assert scan_id == 1
    assert row[0] == "example.com"
    assert row[1] == 92
    assert row[2] == "A"
    assert row[3] == "medium"
    assert json.loads(row[4])[0]["finding"] == "Missing CSP"


def test_save_report_paths(scan_database):
    scan_id = save_security_scan(
        sample_result(),
        html_report_path="/reports/report.html",
        json_report_path="/reports/report.json",
    )

    connection = sqlite3.connect(scan_database)
    row = connection.execute(
        "SELECT html_report_path, json_report_path "
        "FROM security_scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    connection.close()

    assert row == ("/reports/report.html", "/reports/report.json")


def test_reject_invalid_score(scan_database):
    result = sample_result()
    result["security_score"]["score"] = 120

    with pytest.raises(ValueError):
        save_security_scan(result)


def test_reject_invalid_result(scan_database):
    with pytest.raises(ValueError):
        save_security_scan({"hostname": "example.com"})
