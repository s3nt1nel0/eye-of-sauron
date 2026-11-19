"""Regression tests for the 2026-11 secure-code review (rate limits, audit trail, password policy,
session lifetime, route permissions, first-run password file)."""

import logging
import sys
from pathlib import Path

import pytest

from conftest import TEST_PASSWORD

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))


def token(client, scope="write"):
    return {"Authorization": "Bearer " + client.post("/api/v1/tokens", json={"name": scope, "scope": scope}).json()["token"]}


def test_every_route_has_the_right_permission(client):
    import route_audit

    rows, problems = route_audit.audit(client.app)
    assert len(rows) > 80
    assert problems == []


def test_rate_limit_per_principal(authed):
    a, b = token(authed), token(authed)
    codes = [authed.post("/api/v1/feeds/refresh", headers=a).status_code for _ in range(7)]
    assert codes[:6] == [200] * 6 and codes[6] == 429
    r = authed.post("/api/v1/feeds/refresh", headers=a)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert authed.post("/api/v1/feeds/refresh", headers=b).status_code == 200  # other principal unaffected


def test_analytics_rate_limited(authed):
    t = token(authed, "read")
    codes = {authed.post("/api/v1/analytics/query", headers=t, json={"type": "kpi", "days": 1}).status_code for _ in range(130)}
    assert 429 in codes


def test_audit_log_records_admin_actions_without_secrets(authed, caplog):
    caplog.set_level(logging.INFO, logger="eos.audit")
    created = authed.post("/api/v1/tokens", json={"name": "ci", "scope": "read"}).json()
    authed.delete(f"/api/v1/tokens/{created['id']}")
    authed.patch("/api/v1/settings", json={"theme": "dark"})
    text = caplog.text
    assert "event=token_created" in text and "event=token_revoked" in text and "event=settings_changed" in text
    assert created["token"] not in text


@pytest.mark.parametrize("pw,msg", [
    ("password123456", "common"),
    ("aaaaaaaaaaaab", "repetitive"),
    ("my-admin-passphrase", "username"),
    ("short", "12"),
])
def test_password_policy(authed, pw, msg):
    r = authed.post("/api/v1/auth/password", json={"current_password": TEST_PASSWORD, "new_password": pw})
    assert r.status_code in (400, 422) and msg in r.text


def test_initial_password_file_removed_after_change(authed, tmp_path):
    f = tmp_path / "initial_admin_password.txt"
    f.write_text("username: admin\npassword: x\n")
    assert authed.get("/api/v1/auth/me").json()["initial_password_pending"] is True
    r = authed.post("/api/v1/auth/password", json={"current_password": TEST_PASSWORD, "new_password": "a-much-better-passphrase"})
    assert r.status_code == 200 and not f.exists()
    assert authed.get("/api/v1/auth/me").json()["initial_password_pending"] is False


def test_weak_bootstrap_password_rejected(tmp_path, monkeypatch):
    from app.config import reset_settings
    from app.db import init_db
    from app.security import ensure_admin_user

    monkeypatch.setenv("EOS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EOS_ADMIN_PASSWORD", "password123456")
    reset_settings()
    from app.config import get_settings

    init_db(get_settings().db_path)
    with pytest.raises(RuntimeError, match="common"):
        ensure_admin_user()
    reset_settings()


def test_session_lifetime_defaults(monkeypatch):
    from app.config import load_settings

    monkeypatch.delenv("EOS_SESSION_IDLE_HOURS", raising=False)
    monkeypatch.delenv("EOS_SESSION_MAX_DAYS", raising=False)
    s = load_settings()
    assert s.session_idle_hours == 24 and s.session_max_days == 14


def test_extra_security_headers(client):
    r = client.get("/")
    assert r.headers["x-permitted-cross-domain-policies"] == "none"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_huge_ids_are_client_errors_not_500(authed):
    assert authed.patch("/api/v1/feeds/99999999999999999999999", json={"title": "x"}).status_code == 422
    assert authed.get("/api/v1/articles", params={"feed_id": "9" * 30}).status_code == 422
    assert authed.post("/api/v1/folders", json={"name": "x", "position": 10 ** 30}).status_code == 422


def test_no_host_header_trailing_slash_redirect(client):
    r = client.get("/api/v1/sidebar/", headers={"Host": "evil.example"}, follow_redirects=False)
    assert r.status_code in (401, 404) and "location" not in r.headers


def test_about_endpoint_and_source_url(authed, monkeypatch):
    info = authed.get("/api/v1/about").json()
    assert info["license"] == "AGPL-3.0-or-later" and info["version"]
    from app.config import ConfigError, load_settings

    monkeypatch.setenv("EOS_SOURCE_URL", "https://github.com/example/eye-of-sauron")
    assert load_settings().source_url == "https://github.com/example/eye-of-sauron"
    monkeypatch.setenv("EOS_SOURCE_URL", "javascript:alert(1)")
    import pytest

    with pytest.raises(ConfigError):
        load_settings()
    anon = authed.__class__(authed.app)
    assert anon.get("/api/v1/about").status_code == 401
