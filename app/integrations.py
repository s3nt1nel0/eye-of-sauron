"""Credentials and settings for third-party sources (YouTube Data API, X, Telegram account).

Non-secret settings live in ``integrations.config`` (JSON); secrets live in ``integrations.secret``
as one secretbox-encrypted JSON object. Secrets are decrypted only server-side, at use, and are
never returned by any API - the status view only says whether each secret is set.
"""

from __future__ import annotations

import json
from typing import Any

from app import secretbox
from app.db import now

NAMES = ("youtube", "x", "telegram", "ai")


def _check(name: str) -> None:
    if name not in NAMES:
        raise ValueError("Unknown integration")


def load(db, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(config, secrets) for one integration; empty dicts when not configured."""
    _check(name)
    row = db.execute("SELECT config, secret FROM integrations WHERE name = ?", (name,)).fetchone()
    if row is None:
        return {}, {}
    config = json.loads(row["config"] or "{}")
    secrets = json.loads(secretbox.decrypt(row["secret"])) if row["secret"] else {}
    return config, secrets


def save(db, name: str, *, config: dict[str, Any] | None = None, secrets: dict[str, Any] | None = None,
         remove_secrets: tuple[str, ...] = (), remove_config: tuple[str, ...] = ()) -> None:
    """Merge values into the stored config/secrets. ``None`` values are dropped (= unset)."""
    current_config, current_secrets = load(db, name)
    current_config.update(config or {})
    current_secrets.update(secrets or {})
    for key in remove_secrets:
        current_secrets.pop(key, None)
    for key in remove_config:
        current_config.pop(key, None)
    current_config = {k: v for k, v in current_config.items() if v is not None}
    current_secrets = {k: v for k, v in current_secrets.items() if v not in (None, "")}
    stored_secret = secretbox.encrypt(json.dumps(current_secrets)) if current_secrets else None
    db.execute(
        "INSERT INTO integrations (name, config, secret, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET config = excluded.config, secret = excluded.secret, updated_at = excluded.updated_at",
        (name, json.dumps(current_config), stored_secret, now()),
    )


def secret(db, name: str, key: str) -> str | None:
    value = load(db, name)[1].get(key)
    return value if isinstance(value, str) and value else None


def status(db) -> dict[str, Any]:
    """Public view: non-secret settings plus booleans for which secrets are set."""
    out: dict[str, Any] = {}
    for name in NAMES:
        config, secrets = load(db, name)
        out[name] = {"config": config, "secrets_set": sorted(k for k, v in secrets.items() if v)}
    return out
