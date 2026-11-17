import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TEST_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FEEDWARDEN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FEEDWARDEN_ADMIN_PASSWORD", TEST_PASSWORD)
    monkeypatch.setenv("FEEDWARDEN_DISABLE_SCHEDULER", "true")
    from app.config import reset_settings
    from app.security import account_throttle, login_throttle, reset_rate_limits

    from app import secretbox

    reset_settings()
    secretbox.reset()  # each test has its own data dir and therefore its own key
    login_throttle._failures.clear()
    account_throttle._failures.clear()
    reset_rate_limits()
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    reset_settings()


@pytest.fixture()
def authed(client):
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return client


@pytest.fixture(autouse=True)
def _reset_background_flags():
    """Tests mock background threads; make sure a mocked job never looks 'running' to the next test."""
    yield
    from app.api import automation

    automation._pack_job["running"] = False


@pytest.fixture(autouse=True)
def _no_background_fulltext(monkeypatch):
    """The full-text worker is a process-wide thread: in tests it would keep filling article ids from an earlier
    test into the next test's fresh database. Tests that need it patch it explicitly."""
    from app import fulltext

    monkeypatch.setattr(fulltext.fulltext_queue, "add", lambda ids: None)
