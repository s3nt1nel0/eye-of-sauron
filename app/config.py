"""Runtime configuration, read once from environment variables.

All values are validated and clamped; invalid values fail fast at startup
instead of silently producing an insecure configuration.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app import __version__


class ConfigError(ValueError):
    pass



_ALLOW_ENTRY = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]{1,253}):(\d{1,5})$")


def _allowlist(raw: str) -> frozenset:
    """FEEDWARDEN_PRIVATE_ALLOWLIST: comma-separated host:port pairs (exact match, no wildcards)."""
    out = set()
    for item in (x.strip() for x in raw.split(",")):
        if not item:
            continue
        m = _ALLOW_ENTRY.match(item)
        if not m or not 0 < int(m.group(2)) < 65536:
            raise ConfigError(f"FEEDWARDEN_PRIVATE_ALLOWLIST: {item!r} is not host:port")
        out.add(f"{m.group(1).strip('[]').lower()}:{int(m.group(2))}")
    return frozenset(out)

def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean (true/false)")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    value = _env(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not lo <= parsed <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return parsed


def _secret(name: str) -> str | None:
    """Read a secret from NAME or from the file referenced by NAME_FILE (Docker secrets)."""
    file_path = _env(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip() or None
        except OSError as exc:
            raise ConfigError(f"Cannot read {name}_FILE") from exc
    return _env(name)


def _source_url() -> str | None:
    """Where users of this instance can get its source code (AGPL-3.0 section 13)."""
    url = _env("FEEDWARDEN_SOURCE_URL")
    if url is None:
        return None
    if not re.fullmatch(r"https?://[^\s<>\"']{3,500}", url):
        raise ConfigError("FEEDWARDEN_SOURCE_URL must be an http(s) URL")
    return url


def _nvd_key() -> str | None:
    key = _secret("FEEDWARDEN_NVD_API_KEY")
    if key is not None and not re.fullmatch(r"[A-Za-z0-9-]{20,64}", key):
        raise ConfigError("FEEDWARDEN_NVD_API_KEY looks invalid (expected a UUID-style key)")
    return key


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    allow_private_feeds: bool
    allow_private_webhooks: bool
    private_allowlist: frozenset  # "host:port" pairs that may be local/private (e.g. a bridge on 127.0.0.1:1200)
    cookie_secure: str  # "auto" | "true" | "false"
    session_idle_hours: int
    session_max_days: int
    fetch_timeout: int
    max_feed_bytes: int
    fetch_concurrency: int
    max_body_bytes: int
    max_opml_bytes: int
    allowed_hosts: list[str] = field(default_factory=lambda: ["*"])
    admin_user: str = "admin"
    admin_password: str | None = None
    log_level: str = "INFO"
    disable_scheduler: bool = False
    secret_keys: list[str] | None = None
    nvd_api_key: str | None = None
    source_url: str | None = None
    user_agent: str = f"EyeOfSauron/{__version__} (+self-hosted RSS reader)"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "feedwarden.db"


def load_settings() -> Settings:
    cookie_secure = (_env("FEEDWARDEN_COOKIE_SECURE", "auto") or "auto").lower()
    if cookie_secure not in {"auto", "true", "false"}:
        raise ConfigError("FEEDWARDEN_COOKIE_SECURE must be auto, true or false")

    log_level = (_env("FEEDWARDEN_LOG_LEVEL", "INFO") or "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError("FEEDWARDEN_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR")

    hosts_raw = _env("FEEDWARDEN_ALLOWED_HOSTS", "*") or "*"
    allowed_hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]

    admin_user = _env("FEEDWARDEN_ADMIN_USER", "admin") or "admin"

    secret_keys: list[str] | None = None
    raw_keys = _secret("FEEDWARDEN_SECRET_KEY")
    if raw_keys:
        secret_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        try:
            from cryptography.fernet import Fernet

            for key in secret_keys:
                Fernet(key.encode("ascii"))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ConfigError(
                "FEEDWARDEN_SECRET_KEY must be comma-separated Fernet keys "
                "(generate one with: python -m app.cli gen-secret-key)"
            ) from exc

    return Settings(
        data_dir=Path(_env("FEEDWARDEN_DATA_DIR", "/data") or "/data"),
        # Default deny: feeds/webhooks may not target internal networks (SSRF).
        allow_private_feeds=_bool("FEEDWARDEN_ALLOW_PRIVATE_FEEDS", False),
        allow_private_webhooks=_bool("FEEDWARDEN_ALLOW_PRIVATE_WEBHOOKS", False),
        private_allowlist=_allowlist(_env("FEEDWARDEN_PRIVATE_ALLOWLIST", "") or ""),
        cookie_secure=cookie_secure,
        session_idle_hours=_int("FEEDWARDEN_SESSION_IDLE_HOURS", 24, 1, 24 * 90),
        session_max_days=_int("FEEDWARDEN_SESSION_MAX_DAYS", 14, 1, 365),
        fetch_timeout=_int("FEEDWARDEN_FETCH_TIMEOUT", 20, 3, 120),
        max_feed_bytes=_int("FEEDWARDEN_MAX_FEED_BYTES", 10 * 1024 * 1024, 64 * 1024, 100 * 1024 * 1024),
        fetch_concurrency=_int("FEEDWARDEN_FETCH_CONCURRENCY", 6, 1, 32),
        max_body_bytes=_int("FEEDWARDEN_MAX_BODY_BYTES", 1024 * 1024, 16 * 1024, 20 * 1024 * 1024),
        max_opml_bytes=_int("FEEDWARDEN_MAX_OPML_BYTES", 5 * 1024 * 1024, 64 * 1024, 50 * 1024 * 1024),
        allowed_hosts=allowed_hosts or ["*"],
        admin_user=admin_user,
        admin_password=_secret("FEEDWARDEN_ADMIN_PASSWORD"),
        log_level=log_level,
        disable_scheduler=_bool("FEEDWARDEN_DISABLE_SCHEDULER", False),
        secret_keys=secret_keys,
        nvd_api_key=_nvd_key(),
        source_url=_source_url(),
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset_settings() -> None:
    """Testing hook."""
    global _settings
    _settings = None
