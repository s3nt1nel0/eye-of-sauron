"""Encryption at rest for third-party credentials.

Webhook signing secrets and integration credentials must be usable by the server
(so they cannot be hashed like passwords). They are encrypted with Fernet
(AES-128-CBC + HMAC-SHA256, authenticated) before they are written to SQLite, so a
leaked database file or backup does not leak the credentials.

Key material (first match wins):
  1. FEEDWARDEN_SECRET_KEY or FEEDWARDEN_SECRET_KEY_FILE (Docker secret) - one or more
     comma-separated Fernet keys; the FIRST key encrypts, all keys can decrypt (rotation).
  2. <data dir>/secret.key, generated on first start with mode 0600.

Keep the key OUT of the data volume (option 1) for the protection to be meaningful
against backup/volume theft. Losing the key means re-entering the credentials.
"""

from __future__ import annotations

import logging
import os
import threading

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings

log = logging.getLogger("feedwarden.secretbox")

PREFIX = "fw1:"
_lock = threading.Lock()
_box: MultiFernet | None = None


class SecretError(Exception):
    """A stored secret cannot be decrypted (wrong/missing key or tampered value)."""


def _load_keys() -> list[bytes]:
    cfg = get_settings()
    if cfg.secret_keys:
        return [k.encode("ascii") for k in cfg.secret_keys]
    path = cfg.data_dir / "secret.key"
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key + b"\n")
        log.warning(
            "Generated an encryption key for stored credentials at %s. For stronger protection "
            "move it to FEEDWARDEN_SECRET_KEY_FILE (a Docker secret) outside the data volume.",
            path,
        )
    try:
        Fernet(key)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"{path} does not contain a valid Fernet key") from exc
    return [key]


def _get_box() -> MultiFernet:
    global _box
    with _lock:
        if _box is None:
            _box = MultiFernet([Fernet(k) for k in _load_keys()])
        return _box


def ensure_key() -> None:
    """Load (or create) the key at start-up so problems surface immediately, not on first use."""
    _get_box()


def reset() -> None:
    """Testing hook / after key changes."""
    global _box
    with _lock:
        _box = None


def is_encrypted(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(plaintext: str) -> str:
    token = _get_box().encrypt(plaintext.encode("utf-8"))
    return PREFIX + token.decode("ascii")


def decrypt(stored: str) -> str:
    """Decrypt a stored value. Legacy plaintext (no prefix) is returned unchanged."""
    if not is_encrypted(stored):
        return stored
    try:
        return _get_box().decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise SecretError("Stored credential cannot be decrypted (wrong FEEDWARDEN_SECRET_KEY?)") from exc


def rotate(stored: str) -> str:
    """Re-encrypt with the primary key (also encrypts legacy plaintext)."""
    if not is_encrypted(stored):
        return encrypt(stored)
    try:
        token = _get_box().rotate(stored[len(PREFIX):].encode("ascii"))
    except InvalidToken as exc:
        raise SecretError("Stored credential cannot be decrypted") from exc
    return PREFIX + token.decode("ascii")


# Columns holding encrypted credentials: (table, column). Constants only - never user input.
ENCRYPTED_COLUMNS = (("webhooks", "secret"), ("integrations", "secret"), ("delivery_channels", "credentials"))


def migrate_and_rotate(db, *, rotate_all: bool = False) -> int:
    """Encrypt legacy plaintext values; with rotate_all also re-encrypt under the primary key."""
    changed = 0
    for table, column in ENCRYPTED_COLUMNS:
        rows = db.execute(f"SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL").fetchall()  # nosec B608
        for row in rows:
            value = row[1]
            if is_encrypted(value) and not rotate_all:
                continue
            db.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (rotate(value), row[0]))  # nosec B608
            changed += 1
    return changed
