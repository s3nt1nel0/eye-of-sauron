"""Regression tests for findings from the 2026-11 penetration test (see docs/PENTEST-REPORT.md)."""

import gzip
import hashlib
import hmac
import ipaddress
import sqlite3
import tracemalloc
import zlib
from unittest import mock

import httpx
import pytest

from app import netguard, secretbox
from app.fetcher import xml_guard
from app.security import LoginThrottle


# ---------------------------------------------------------------- FW-01 decompression bomb
def test_bounded_decoder_stops_bomb_with_bounded_memory():
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024), 9)
    decoder = netguard._BoundedDecoder("gzip", 1024 * 1024)
    tracemalloc.start()
    with pytest.raises(netguard.FetchError):
        for i in range(0, len(bomb), 65536):
            decoder.feed(bomb[i:i + 65536])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024  # was ~14x the limit before the fix


@pytest.mark.parametrize("encoding,data", [
    ("gzip", gzip.compress(b"hello world" * 100)),
    ("deflate", zlib.compress(b"hello world" * 100)),
    ("deflate", zlib.compress(b"hello world" * 100)[2:-4]),  # raw deflate (no zlib header)
    ("", b"hello world" * 100),
    ("identity", b"hello world" * 100),
])
def test_bounded_decoder_roundtrip(encoding, data):
    d = netguard._BoundedDecoder(encoding, 10_000)
    out = b"".join(d.feed(data[i:i + 7]) for i in range(0, len(data), 7)) + d.finish()
    assert out == b"hello world" * 100


def test_bounded_decoder_multi_member_and_unsupported():
    d = netguard._BoundedDecoder("gzip", 1000)
    assert d.feed(gzip.compress(b"a" * 10) + gzip.compress(b"b" * 10)) + d.finish() == b"a" * 10 + b"b" * 10
    with pytest.raises(netguard.FetchError):
        netguard._BoundedDecoder("br", 1000)


# ---------------------------------------------------------------- FW-02 XML guard bypass
DOC = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x">]><rss version="2.0"><channel><title>&a;</title></channel></rss>'


@pytest.mark.parametrize("payload,ctype", [
    (DOC.encode(), None),
    (DOC.replace('1.0"?', '1.0" encoding="UTF-16"?').encode("utf-16"), None),
    (DOC.encode("utf-16-be"), None),
    (DOC.encode("utf-16-le"), None),
    (DOC.encode("utf-32"), None),
    (b'<?xml version="1.0" encoding="UTF-7"?><rss/>', None),
    (b"<rss/>", "application/rss+xml; charset=utf-7"),
    ('<?xml version="1.0"?><rss/>'.encode("cp037"), None),
])
def test_xml_guard_rejects_entity_smuggling(payload, ctype):
    assert xml_guard(payload, ctype) is not None


@pytest.mark.parametrize("payload,ctype", [
    (b'<?xml version="1.0" encoding="utf-8"?><rss><channel><title>Entity Framework CVE</title></channel></rss>', None),
    ('<?xml version="1.0" encoding="utf-16"?><rss/>'.encode("utf-16"), "text/xml"),
    ('﻿<?xml version="1.0"?><rss/>'.encode("utf-8"), "application/xml; charset=utf-8"),
    (b'<?xml version="1.0" encoding="ISO-8859-1"?><rss/>', "text/xml; charset=iso-8859-1"),
])
def test_xml_guard_accepts_legitimate_feeds(payload, ctype):
    assert xml_guard(payload, ctype) is None


# ---------------------------------------------------------------- FW-03 IPv6 transition addresses
@pytest.mark.parametrize("addr,expected", [
    ("64:ff9b::7f00:1", False),      # NAT64 -> 127.0.0.1
    ("64:ff9b::a9fe:a9fe", False),   # NAT64 -> 169.254.169.254
    ("2002:c0a8:0101::", False),     # 6to4 -> 192.168.1.1
    ("2001:0:4136:e378:8000:63bf:80ff:fffe", False),  # Teredo with loopback client
    ("::ffff:10.0.0.1", False),
    ("64:ff9b::808:808", True),      # NAT64 to a public IPv4 stays usable (DNS64 networks)
    ("2606:4700:4700::1111", True),
])
def test_embedded_ipv4_policy(addr, expected):
    assert netguard.ip_allowed(ipaddress.ip_address(addr), False) is expected


# ---------------------------------------------------------------- FW-04 OpenAPI exposure
def test_openapi_requires_authentication(client):
    assert client.get("/api/v1/openapi.json").status_code == 401


def test_openapi_available_when_logged_in(authed):
    r = authed.get("/api/v1/openapi.json")
    assert r.status_code == 200 and "/api/v1/articles" in r.json()["paths"]


# ---------------------------------------------------------------- FW-05 account lockout DoS
def test_account_threshold_is_higher_than_ip_threshold(client):
    from app.security import account_throttle, login_throttle

    assert account_throttle.max_failures > login_throttle.max_failures
    t = LoginThrottle(max_failures=3)
    for _ in range(3):
        t.record_failure("user:admin")
    assert not t.allowed("user:admin") and t.allowed("user:other")


def test_ip_throttle_still_blocks_spraying(client):
    for i in range(8):
        assert client.post("/api/v1/auth/login", json={"username": f"u{i}", "password": "x" * 12}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "u9", "password": "x" * 12}).status_code == 429


# ---------------------------------------------------------------- FW-06 secrets at rest
def test_webhook_secret_encrypted_at_rest_and_signature_valid(authed, tmp_path):
    secret = "s3cr3t-signing-key-123456"
    hook = authed.post("/api/v1/webhooks", json={"name": "n8n", "url": "https://example.com/hook", "secret": secret}).json()
    assert "secret" not in hook and hook["has_secret"] is True
    db = sqlite3.connect(tmp_path / "eos.db")
    stored = db.execute("SELECT secret FROM webhooks WHERE id = ?", (hook["id"],)).fetchone()[0]
    db.close()
    assert stored.startswith("fw1:") and secret not in stored
    captured = {}

    def fake(method, url, **kw):
        captured.update(kw)
        return netguard.SafeResponse(200, httpx.Headers(), b"", url)

    with mock.patch("app.webhooks.netguard.request", side_effect=fake):
        assert authed.post(f"/api/v1/webhooks/{hook['id']}/test").json()["ok"] is True
    h = captured["headers"]
    expected = hmac.new(secret.encode(), h["X-EOS-Timestamp"].encode() + b"." + captured["content"], hashlib.sha256)
    assert h["X-EOS-Signature"] == "sha256=" + expected.hexdigest()


def test_legacy_plaintext_secrets_are_migrated(client, tmp_path):
    from app.db import get_db

    with get_db() as db:
        db.execute("INSERT INTO webhooks (name, url, secret) VALUES ('old', 'https://example.com', 'plaintext-secret-value')")
        assert secretbox.migrate_and_rotate(db) == 1
        value = db.execute("SELECT secret FROM webhooks WHERE name = 'old'").fetchone()[0]
    assert secretbox.is_encrypted(value) and secretbox.decrypt(value) == "plaintext-secret-value"


def test_key_rotation(client, monkeypatch):
    from cryptography.fernet import Fernet

    from app.config import get_settings, reset_settings
    from app.db import get_db

    old_value = secretbox.encrypt("rotate-me")
    old_key = (get_settings().data_dir / "secret.key").read_text().strip()
    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("EOS_SECRET_KEY", f"{new_key},{old_key}")
    reset_settings()
    secretbox.reset()
    with get_db() as db:
        db.execute("INSERT INTO webhooks (name, url, secret) VALUES ('r', 'https://example.com', ?)", (old_value,))
        secretbox.migrate_and_rotate(db, rotate_all=True)
        rotated = db.execute("SELECT secret FROM webhooks WHERE name = 'r'").fetchone()[0]
    monkeypatch.setenv("EOS_SECRET_KEY", new_key)  # old key retired
    reset_settings()
    secretbox.reset()
    assert secretbox.decrypt(rotated) == "rotate-me"
    with pytest.raises(secretbox.SecretError):
        secretbox.decrypt(old_value)


def test_invalid_secret_key_config_fails_fast(monkeypatch):
    from app.config import ConfigError, load_settings

    monkeypatch.setenv("EOS_SECRET_KEY", "not-a-fernet-key")
    with pytest.raises(ConfigError):
        load_settings()


def test_tampered_secret_detected(client):
    value = secretbox.encrypt("x" * 20)
    tampered = value[:-6] + ("A" if value[-6] != "A" else "B") + value[-5:]
    with pytest.raises(secretbox.SecretError):
        secretbox.decrypt(tampered)
