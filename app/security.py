"""Credentials, tokens, sessions, CSRF and login throttling."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status

from app.config import get_settings
from app.db import get_db, now

log = logging.getLogger("eos.security")

_hasher = PasswordHasher()  # argon2id with library-recommended parameters
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(24))

SESSION_COOKIE_SECURE = "__Host-eos_session"  # __Host- prefix: Secure, Path=/, no Domain
SESSION_COOKIE_PLAIN = "eos_session"
API_TOKEN_PREFIX = "eos_"
LEGACY_TOKEN_PREFIXES = ("fw_",)  # tokens created before the EOS rename keep working
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MIN_PASSWORD_LENGTH = 12
_COMMON_PASSWORDS = {
    "password1234", "password12345", "password123456", "123456789012", "qwertyuiopas", "1q2w3e4r5t6y",
    "letmein12345", "welcome12345", "administrator", "changeme1234", "iloveyou1234", "passw0rd1234",
    "qwerty123456", "abc123456789", "admin1234567", "trustno1trustno1", "sauron123456", "eyeofsauron1",
}
audit_log = logging.getLogger("eos.audit")


def password_problem(password: str, username: str = "") -> str | None:
    """Return why a new password is unacceptable, or None (OWASP ASVS V2.1: length over complexity)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        return "That password is too common"
    if len(set(password)) < 5:
        return "Password is too repetitive"
    if username and len(username) >= 3 and username.lower() in lowered:
        return "Password must not contain the username"
    return None


def audit(event: str, principal: "Principal | None" = None, **fields: object) -> None:
    """Security audit trail (OWASP Logging Cheat Sheet). Never pass secrets; values are length-capped."""
    who = "anonymous"
    if principal is not None:
        who = f"token:{principal.token_id}" if principal.kind == "token" else f"user:{principal.user_id}"
    detail = " ".join(f"{k}={str(v)[:120]!r}" for k, v in fields.items())
    audit_log.info("event=%s actor=%s %s", event, who, detail)


# --------------------------------------------------------------------------- rate limiting
class RateLimiter:
    """Token bucket per key (API4:2023 Unrestricted Resource Consumption)."""

    def __init__(self, per_minute: int, burst: int | None = None) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(burst or per_minute)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        at = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, at))
            tokens = min(self.capacity, tokens + (at - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, at)
                ok, retry = True, 0
            else:
                self._buckets[key] = (tokens, at)
                ok, retry = False, int((1 - tokens) / self.rate) + 1
            if len(self._buckets) > 20_000:  # bound memory
                self._buckets = {k: v for k, v in self._buckets.items() if at - v[1] < 600}
        return ok, retry

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_limiters: dict[str, RateLimiter] = {}


def rate_limit(name: str, per_minute: int, burst: int | None = None):
    """FastAPI dependency limiting an expensive endpoint per principal (session or token)."""
    limiter = _limiters.setdefault(name, RateLimiter(per_minute, burst))

    def dependency(principal: Principal = Depends(get_principal)) -> None:  # noqa: F821 - defined below, resolved at call time
        key = f"{principal.kind}:{principal.token_id if principal.kind == 'token' else principal.session_id}"
        ok, retry = limiter.allow(key)
        if not ok:
            audit("rate_limited", principal, endpoint=name)
            raise HTTPException(status_code=429, detail="Too many requests - slow down",
                                headers={"Retry-After": str(retry)})

    return dependency


def reset_rate_limits() -> None:
    for limiter in _limiters.values():
        limiter.reset()


# --------------------------------------------------------------------------- hashing
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification; a dummy hash is used when the user does not exist."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def token_hash(token: str) -> str:
    """Tokens are 256-bit random values, so a fast hash is appropriate (no brute force)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------- throttling
class LoginThrottle:
    """Sliding-window failure counter per client IP and per username."""

    def __init__(self, max_failures: int = 8, window_seconds: int = 900) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, at: float) -> deque[float]:
        bucket = self._failures.setdefault(key, deque())
        while bucket and bucket[0] <= at - self.window:
            bucket.popleft()
        return bucket

    def allowed(self, *keys: str) -> bool:
        at = time.monotonic()
        with self._lock:
            return all(len(self._prune(k, at)) < self.max_failures for k in keys)

    def record_failure(self, *keys: str) -> None:
        at = time.monotonic()
        with self._lock:
            for key in keys:
                self._prune(key, at).append(at)
            if len(self._failures) > 10_000:  # bound memory
                for key in [k for k, v in self._failures.items() if not v]:
                    del self._failures[key]

    def reset(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)


login_throttle = LoginThrottle()  # per client IP: 8 failures / 15 min
# Per account: a higher threshold, so a single attacker cannot lock the owner out
# (account-lockout DoS) while distributed guessing is still capped.
account_throttle = LoginThrottle(max_failures=30)


# --------------------------------------------------------------------------- bootstrap
def ensure_admin_user() -> None:
    """Create the initial admin account on first start.

    Uses EOS_ADMIN_PASSWORD(_FILE) when set, otherwise generates a strong
    random password and writes it to a 0600 file in the data directory (it is
    never written to logs).
    """
    cfg = get_settings()
    with get_db() as db:
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return
        password = cfg.admin_password
        problem = password_problem(password, cfg.admin_user) if password else None
        if problem:
            raise RuntimeError(f"EOS_ADMIN_PASSWORD rejected: {problem}")
        generated = password is None
        if generated:
            password = secrets.token_urlsafe(18)
        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (cfg.admin_user, hash_password(password), now()),
        )
    if generated:
        path = cfg.data_dir / "initial_admin_password.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"username: {cfg.admin_user}\npassword: {password}\n")
        log.warning(
            "Created admin user '%s'. Generated password stored in %s - "
            "log in, change it, then delete the file.",
            cfg.admin_user,
            path,
        )


# --------------------------------------------------------------------------- auth deps
@dataclass(frozen=True)
class Principal:
    kind: str  # "session" | "token"
    scopes: frozenset[str]
    user_id: int | None = None
    session_id: int | None = None
    token_id: int | None = None
    csrf_token: str | None = None


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def token_principal(value: str) -> Principal:
    """Validate an API token value (``eos_...``, or an older ``fw_...``) and return its principal. Raises 401."""
    current = now()
    value = value.strip()
    if not value.startswith((API_TOKEN_PREFIX, *LEGACY_TOKEN_PREFIXES)) or len(value) > 200:
        raise _unauthorized("Invalid authorization header")
    with get_db() as db:
        row = db.execute(
            "SELECT id, scopes, expires_at, last_used FROM api_tokens WHERE token_hash = ?",
            (token_hash(value),),
        ).fetchone()
        if row is None or (row["expires_at"] is not None and row["expires_at"] <= current):
            raise _unauthorized("Invalid or expired token")
        if row["last_used"] is None or row["last_used"] < current - 60:
            db.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (current, row["id"]))
    scopes = set(row["scopes"].split(","))
    if "write" in scopes:
        scopes.add("read")
    # "reader" (mobile-app tokens from the Google Reader API) deliberately implies nothing else:
    # such tokens only work on /api/greader*, never on the REST API.
    return Principal(kind="token", scopes=frozenset(scopes), token_id=row["id"])


def get_principal(request: Request) -> Principal:
    current = now()
    authorization = request.headers.get("authorization")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise _unauthorized("Invalid authorization header")
        return token_principal(value)

    raw = request.cookies.get(SESSION_COOKIE_SECURE) or request.cookies.get(SESSION_COOKIE_PLAIN)
    if not raw or len(raw) > 200:
        raise _unauthorized()
    cfg = get_settings()
    with get_db() as db:
        row = db.execute(
            "SELECT id, user_id, csrf_token, last_seen, expires_at FROM sessions WHERE token_hash = ?",
            (token_hash(raw),),
        ).fetchone()
        if row is None:
            raise _unauthorized()
        if row["expires_at"] <= current or row["last_seen"] < current - cfg.session_idle_hours * 3600:
            db.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
            raise _unauthorized("Session expired")
        if request.method not in SAFE_METHODS:
            supplied = request.headers.get("x-csrf-token", "")
            if not supplied or not safe_equals(supplied, row["csrf_token"]):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
        if row["last_seen"] < current - 60:
            db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (current, row["id"]))
    return Principal(
        kind="session",
        scopes=frozenset({"read", "write", "admin"}),
        user_id=row["user_id"],
        session_id=row["id"],
        csrf_token=row["csrf_token"],
    )


def require(scope: str):
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scope: {scope}")
        return principal

    return dependency


require_read = require("read")
require_write = require("write")
require_admin = require("admin")  # interactive session only (tokens never get it)


def client_ip(request: Request) -> str:
    # request.client honours X-Forwarded-For only for proxies trusted via
    # uvicorn's --forwarded-allow-ips, so it cannot be spoofed by clients.
    return request.client.host if request.client else "unknown"


def cookie_is_secure(request: Request) -> bool:
    mode = get_settings().cookie_secure
    if mode == "true":
        return True
    if mode == "false":
        return False
    return request.url.scheme == "https"
