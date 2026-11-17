"""Login / logout / password and API-token management."""

from __future__ import annotations

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, StringConstraints

from app.api.common import StrictModel, not_found
from app.config import get_settings
from app.db import get_db, now
from app.security import (
    API_TOKEN_PREFIX,
    MIN_PASSWORD_LENGTH,
    SESSION_COOKIE_PLAIN,
    SESSION_COOKIE_SECURE,
    Principal,
    account_throttle,
    client_ip,
    cookie_is_secure,
    get_principal,
    audit,
    hash_password,
    login_throttle,
    password_problem,
    rate_limit,
    needs_rehash,
    new_secret,
    require_admin,
    require_read,
    token_hash,
    verify_password,
)

log = logging.getLogger("eos.auth")
router = APIRouter(tags=["auth"])

Username = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")]
Password = Annotated[str, StringConstraints(min_length=1, max_length=256)]
MAX_SESSIONS_PER_USER = 20
INITIAL_PASSWORD_FILE = "initial_admin_password.txt"


def user_row_name(db, user_id: int) -> str:
    row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    return row["username"] if row else ""


class LoginIn(StrictModel):
    username: Username
    password: Password


class PasswordChangeIn(StrictModel):
    current_password: Password
    new_password: Annotated[str, StringConstraints(min_length=MIN_PASSWORD_LENGTH, max_length=256)]


class TokenIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    scope: Literal["read", "write"] = "read"
    expires_days: int | None = Field(default=90, ge=1, le=3650)


def _set_session_cookie(request: Request, response: Response, token: str) -> None:
    secure = cookie_is_secure(request)
    response.set_cookie(
        key=SESSION_COOKIE_SECURE if secure else SESSION_COOKIE_PLAIN,
        value=token,
        max_age=get_settings().session_max_days * 86400,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_SECURE, path="/", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(SESSION_COOKIE_PLAIN, path="/", httponly=True, samesite="strict")


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response) -> dict:
    ip = client_ip(request)
    ip_key, user_key = f"ip:{ip}", f"user:{body.username.lower()}"
    if not login_throttle.allowed(ip_key) or not account_throttle.allowed(user_key):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    with get_db() as db:
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (body.username,)
        ).fetchone()
    if not verify_password(user["password_hash"] if user else None, body.password) or user is None:
        login_throttle.record_failure(ip_key)
        account_throttle.record_failure(user_key)
        log.warning("Failed login attempt from %s", ip)
        audit("login_failed", None, ip=ip, username=body.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    login_throttle.reset(ip_key)
    account_throttle.reset(user_key)
    cfg = get_settings()
    token, csrf, ts = new_secret(), new_secret(), now()
    with get_db() as db:
        if needs_rehash(user["password_hash"]):
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(body.password), user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?", (user["id"], ts))
        db.execute(
            "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE user_id = ? "
            "ORDER BY last_seen DESC LIMIT -1 OFFSET ?)",
            (user["id"], MAX_SESSIONS_PER_USER - 1),
        )
        db.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (token_hash(token), user["id"], csrf, ts, ts, ts + cfg.session_max_days * 86400),
        )
    _set_session_cookie(request, response, token)
    log.info("User '%s' logged in from %s", user["username"], ip)
    audit("login", None, ip=ip, user_id=user["id"])
    return {"username": user["username"], "csrf_token": csrf}


@router.post("/auth/logout")
def logout(response: Response, principal: Principal = Depends(get_principal)) -> dict:
    if principal.session_id is not None:
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE id = ?", (principal.session_id,))
        audit("logout", principal)
    _clear_session_cookies(response)
    return {"ok": True}


PROJECT_URL = None  # set to the public repository URL once published (overridable with EOS_SOURCE_URL)


@router.get("/about")
def about(_: Principal = Depends(require_read)) -> dict:
    """Version, licence and where to get this instance's source code (AGPL-3.0 section 13)."""
    from app import __version__

    return {"name": "Eye of Sauron", "version": __version__, "license": "AGPL-3.0-or-later",
            "license_url": "https://www.gnu.org/licenses/agpl-3.0.html",
            "source_url": get_settings().source_url or PROJECT_URL}


@router.get("/auth/me")
def me(principal: Principal = Depends(get_principal)) -> dict:
    if principal.kind == "token":
        return {"kind": "token", "scopes": sorted(principal.scopes)}
    with get_db() as db:
        user = db.execute("SELECT username FROM users WHERE id = ?", (principal.user_id,)).fetchone()
    return {
        "kind": "session",
        "username": user["username"] if user else None,
        "csrf_token": principal.csrf_token,
        "scopes": sorted(principal.scopes),
        # The generated first-run password file still exists: nag until the password is changed.
        "initial_password_pending": (get_settings().data_dir / INITIAL_PASSWORD_FILE).exists(),
    }


@router.post("/auth/password")
def change_password(body: PasswordChangeIn, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        user = db.execute("SELECT id, password_hash FROM users WHERE id = ?", (principal.user_id,)).fetchone()
        if user is None or not verify_password(user["password_hash"], body.current_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if body.new_password == body.current_password:
            raise HTTPException(status_code=400, detail="New password must differ from the current one")
        problem = password_problem(body.new_password, user_row_name(db, user["id"]))
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(body.new_password), user["id"]))
        # Invalidate every other session after a credential change.
        db.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (user["id"], principal.session_id))
    log.info("Password changed for user id %s", principal.user_id)
    audit("password_changed", principal)
    # The generated first-run password is no longer valid: remove the file holding it.
    try:
        (get_settings().data_dir / INITIAL_PASSWORD_FILE).unlink(missing_ok=True)
    except OSError:
        log.warning("Could not delete %s - remove it manually", INITIAL_PASSWORD_FILE)
    return {"ok": True}


# ----------------------------------------------------------------------------- API tokens
@router.get("/tokens")
def list_tokens(_: Principal = Depends(require_admin)) -> list[dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, prefix, scopes, created_at, last_used, expires_at FROM api_tokens ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/tokens", status_code=201, dependencies=[Depends(rate_limit("tokens", 10))])
def create_token(body: TokenIn, principal: Principal = Depends(require_admin)) -> dict:
    token = API_TOKEN_PREFIX + new_secret()
    ts = now()
    expires = ts + body.expires_days * 86400 if body.expires_days else None
    with get_db() as db:
        count = db.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0]
        if count >= 50:
            raise HTTPException(status_code=400, detail="Token limit reached (50)")
        cur = db.execute(
            "INSERT INTO api_tokens (name, token_hash, prefix, scopes, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (body.name, token_hash(token), token[:10], body.scope, ts, expires),
        )
    audit("token_created", principal, token_id=cur.lastrowid, scope=body.scope, name=body.name)
    # The plaintext token is returned exactly once and never stored.
    return {"id": cur.lastrowid, "name": body.name, "token": token, "scopes": body.scope, "expires_at": expires}


@router.delete("/tokens/{token_id}")
def delete_token(token_id: int, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,)).rowcount == 0:
            raise not_found("Token")
    audit("token_revoked", principal, token_id=token_id)
    return {"ok": True}
