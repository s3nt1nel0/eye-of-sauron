"""The rename (feedwarden -> EOS): old deployments keep working."""

import sqlite3

from app import config
from app.db import _adopt_legacy_file, get_db
from app.security import token_hash


def test_legacy_env_names_are_still_read(monkeypatch):
    monkeypatch.delenv("EOS_FETCH_TIMEOUT", raising=False)
    monkeypatch.setenv("FEEDWARDEN_FETCH_TIMEOUT", "33")
    assert config._env("EOS_FETCH_TIMEOUT") == "33"
    monkeypatch.setenv("EOS_FETCH_TIMEOUT", "44")  # the new name wins
    assert config._env("EOS_FETCH_TIMEOUT") == "44"


def test_legacy_secret_file_is_still_read(monkeypatch, tmp_path):
    f = tmp_path / "key.txt"
    f.write_text("from-legacy-file\n", encoding="utf-8")
    monkeypatch.delenv("EOS_NVD_API_KEY_FILE", raising=False)
    monkeypatch.setenv("FEEDWARDEN_NVD_API_KEY_FILE", str(f))
    assert config._secret("EOS_NVD_API_KEY") == "from-legacy-file"


def test_legacy_database_file_is_adopted(tmp_path):
    old = tmp_path / "feedwarden.db"
    con = sqlite3.connect(old)
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    (tmp_path / "feedwarden.db-wal").write_bytes(b"")
    new = tmp_path / "eos.db"
    _adopt_legacy_file(new)
    assert new.exists() and not old.exists()
    assert (tmp_path / "eos.db-wal").exists()
    assert sqlite3.connect(new).execute("SELECT x FROM t").fetchone() == (1,)


def test_existing_database_is_never_replaced(tmp_path):
    (tmp_path / "eos.db").write_bytes(b"new")
    (tmp_path / "feedwarden.db").write_bytes(b"old")
    _adopt_legacy_file(tmp_path / "eos.db")
    assert (tmp_path / "eos.db").read_bytes() == b"new"
    assert (tmp_path / "feedwarden.db").exists()


def test_new_tokens_use_eos_prefix_and_old_fw_tokens_still_work(authed):
    token = authed.post("/api/v1/tokens", json={"name": "t", "scope": "read"}).json()["token"]
    assert token.startswith("eos_")
    legacy = "fw_" + "L" * 43
    with get_db() as db:
        db.execute("INSERT INTO api_tokens (name, token_hash, prefix, scopes, created_at) VALUES ('legacy', ?, 'fw_LLLL', 'read', 0)",
                   (token_hash(legacy),))
    authed.cookies.clear()
    authed.headers.pop("X-CSRF-Token")
    anon = authed
    assert anon.get("/api/v1/sidebar", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert anon.get("/api/v1/sidebar", headers={"Authorization": f"Bearer {legacy}"}).status_code == 200
    assert anon.get("/api/v1/sidebar", headers={"Authorization": "Bearer xx_" + "L" * 43}).status_code == 401
