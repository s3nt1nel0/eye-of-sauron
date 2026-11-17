"""Stage-2 sources: resolve a link into a subscribable source, manage integrations (YouTube / X /
Telegram credentials) and the Telegram account login.

Integration settings and the Telegram login are **admin-only** (interactive session): they hold
credentials that act as the user on third-party services. Resolving a source needs write scope.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, StringConstraints

from app import integrations, netguard, sources
from app.api.common import StrictModel
from app.db import get_db
from app.security import Principal, audit, rate_limit, require_admin, require_write
from app.sanitize import to_text

router = APIRouter(tags=["sources"])


def _fail(exc: Exception, status: int = 422) -> HTTPException:
    return HTTPException(status_code=status, detail=str(exc)[:300])


# ============================================================================ resolve
class ResolveIn(StrictModel):
    input: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    kind: Literal["youtube", "hfpapers", "x", "telegram"] | None = None
    via: Literal["web", "account", "bridge", "api"] | None = None


PREVIEW_MAX = 25  # YouTube channel/playlist feeds carry 15 items, others vary


def _preview(entries: list[dict]) -> list[dict]:
    out = []
    for e in entries[:PREVIEW_MAX]:
        out.append({"title": e.get("title"), "link": e.get("link"), "summary": to_text(e.get("summary"), 200)})
    return out


@router.post("/sources/resolve", dependencies=[Depends(rate_limit("source_resolve", 20))])
def resolve(body: ResolveIn, _: Principal = Depends(require_write)) -> dict:
    """Turn a link / @handle into {kind, url, title, source, preview, notes} for POST /feeds."""
    kind = body.kind or sources.detect(body.input)
    if kind is None:
        raise HTTPException(status_code=422, detail="Not a YouTube, X, Telegram or Hugging Face Papers link - "
                                                    "use the normal Add feed for websites and RSS")
    notes: list[str] = []
    preview: list[dict] = []
    found_count: int | None = None
    title = None
    with get_db() as db:
        status = integrations.status(db)
    try:
        if kind == "youtube":
            found = sources.resolve_youtube(body.input)
            cfg = sources.parse_config(found["source"])
            got = sources.fetch_youtube(cfg, sources.canonical_url(cfg))
            title, preview = found["title"] or got.title, _preview(got.entries)
            found_count = len(got.entries)
            if "api_key" not in status["youtube"]["secrets_set"]:
                notes.append("Add a YouTube Data API key in Integrations for durations, view counts and older videos.")
                if found_count >= 15:
                    notes.append("YouTube's feed lists only the 15 most recent videos; with an API key the whole "
                                 "channel or playlist is loaded.")
        elif kind == "hfpapers":
            cfg = sources.HFPapersSource()
            got = sources.fetch_hfpapers(cfg)
            title, preview = got.title, _preview(got.entries)
        elif kind == "x":
            username = sources.parse_x_input(body.input)
            has_api = "bearer_token" in status["x"]["secrets_set"]
            has_bridge = bool(status["x"]["config"].get("bridge_type"))
            via = body.via if body.via in ("bridge", "api") else ("bridge" if has_bridge else "api" if has_api else None)
            if via is None:
                raise sources.SourceError("Set up an X bridge (RSSHub / Nitter / RSS-Bridge) or an X API bearer token "
                                          "in Settings → Integrations → X first")
            cfg = sources.XSource(username=username, via=via)
            if via == "bridge":
                got = sources.fetch_x_bridge(cfg)
                preview = _preview(got.entries)
            else:
                token = sources.x_token()
                if not token:
                    raise sources.SourceError("No X API bearer token is configured")
                sources.x_user_id(username, token)  # one cheap lookup; no posts read (they cost credits)
                notes.append("X API: posts are read every 6 hours by default to limit API costs.")
            title = f"@{username} on X"
        else:
            username = None if body.input.strip().lstrip("-").isdigit() else sources.parse_telegram_input(body.input)
            via = body.via if body.via in ("web", "account") else "web"
            if username is None:
                cfg = sources.TelegramSource(via="account", chat_id=int(body.input.strip()))
            else:
                cfg = sources.TelegramSource(via=via, channel=username)
            if cfg.via == "web":
                try:
                    t, entries, _ = sources.tg_web_page(username)  # type: ignore[arg-type]
                except sources.SourceError:
                    t, entries = None, []
                if not entries:
                    if status["telegram"]["config"].get("account"):
                        cfg = sources.TelegramSource(via="account", channel=username)
                        notes.append("No public preview - this will be read through your Telegram account.")
                    else:
                        raise sources.SourceError("This channel has no public web preview. Connect your Telegram "
                                                  "account (Settings → Integrations → Telegram) to follow it.")
                title, preview = t, _preview(entries)
            if cfg.via == "account":
                from app import telegram_mt

                got = telegram_mt.account.fetch(cfg, 0, limit=8, history=True)
                title, preview = got.title, _preview(got.entries)
    except sources.SourceError as exc:
        raise _fail(exc) from None
    except ValueError as exc:
        raise _fail(exc) from None
    return {"kind": cfg.kind, "url": sources.canonical_url(cfg), "title": title, "source": cfg.model_dump(exclude_none=True),
            "preview": preview, "found": found_count if found_count is not None else len(preview), "notes": notes, "refresh_minutes": sources.DEFAULT_REFRESH[cfg.kind]}


# ============================================================================ integrations
@router.get("/integrations")
def get_integrations(_: Principal = Depends(require_admin)) -> dict:
    """Non-secret settings and which secrets are set (secret values are never returned)."""
    with get_db() as db:
        return integrations.status(db)


class YouTubeIn(StrictModel):
    api_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{20,100}$")] | None = None
    clear: bool = False


@router.put("/integrations/youtube", dependencies=[Depends(rate_limit("integrations", 20))])
def put_youtube(body: YouTubeIn, principal: Principal = Depends(require_admin)) -> dict:
    if body.api_key and not body.clear:
        try:
            sources.yt_api("videos", {"part": "id", "id": "dQw4w9WgXcQ"}, body.api_key)  # validate the key (1 unit)
        except sources.SourceError as exc:
            raise _fail(exc) from None
    with get_db() as db:
        if body.clear:
            integrations.save(db, "youtube", remove_secrets=("api_key",))
        elif body.api_key:
            integrations.save(db, "youtube", secrets={"api_key": body.api_key})
        out = integrations.status(db)["youtube"]
    audit("integration_updated", principal, name="youtube", cleared=body.clear)
    return out


class XIn(StrictModel):
    bearer_token: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9%._~+/=-]{30,600}$")] | None = None
    clear_bearer: bool = False
    bridge_type: Literal["rsshub", "nitter", "rssbridge", "template", "none"] | None = None
    bridge_url: Annotated[str, StringConstraints(max_length=500)] | None = None
    bridge_template: Annotated[str, StringConstraints(max_length=600)] | None = None


@router.put("/integrations/x", dependencies=[Depends(rate_limit("integrations", 20))])
def put_x(body: XIn, principal: Principal = Depends(require_admin)) -> dict:
    config: dict = {}
    remove: tuple[str, ...] = ()
    if body.bridge_type == "none":
        remove = ("bridge_type", "bridge_url", "bridge_template")
    elif body.bridge_type:
        config["bridge_type"] = body.bridge_type
        try:
            if body.bridge_type == "template":
                if not body.bridge_template or "{username}" not in body.bridge_template:
                    raise HTTPException(status_code=422, detail="The template must contain {username}")
                netguard.normalize_url(body.bridge_template.replace("{username}", "test"))
                config["bridge_template"] = body.bridge_template
            else:
                if not body.bridge_url:
                    raise HTTPException(status_code=422, detail="Give the bridge base URL")
                config["bridge_url"] = netguard.normalize_url(body.bridge_url).rstrip("/")
        except netguard.UnsafeURLError as exc:
            raise _fail(exc) from None
    with get_db() as db:
        integrations.save(db, "x", config=config, secrets={"bearer_token": body.bearer_token} if body.bearer_token else None,
                          remove_secrets=("bearer_token",) if body.clear_bearer else (), remove_config=remove)
        out = integrations.status(db)["x"]
    audit("integration_updated", principal, name="x", bridge=body.bridge_type, token_set=bool(body.bearer_token),
          token_cleared=body.clear_bearer)
    return out


# ============================================================================ Telegram account
class TgStartIn(StrictModel):
    api_id: int = Field(ge=1, le=2**31 - 1)
    api_hash: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    phone: Annotated[str, StringConstraints(pattern=r"^\+[1-9][0-9]{6,14}$")]


class TgCodeIn(StrictModel):
    code: Annotated[str, StringConstraints(pattern=r"^[0-9]{4,8}$")]


class TgPasswordIn(StrictModel):
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]


def _tg():
    from app import telegram_mt

    return telegram_mt


@router.post("/integrations/telegram/login", dependencies=[Depends(rate_limit("tg_login", 5))])
def tg_login(body: TgStartIn, principal: Principal = Depends(require_admin)) -> dict:
    tg = _tg()
    try:
        tg.account.start_login(body.api_id, body.api_hash, body.phone)
    except (tg.LoginError, sources.SourceError) as exc:
        audit("telegram_login_failed", principal, step="start")
        raise _fail(exc, 400) from None
    audit("telegram_login_started", principal)
    return {"code_sent": True}


@router.post("/integrations/telegram/code", dependencies=[Depends(rate_limit("tg_login", 5))])
def tg_code(body: TgCodeIn, principal: Principal = Depends(require_admin)) -> dict:
    tg = _tg()
    try:
        result = tg.account.submit_code(body.code)
    except (tg.LoginError, sources.SourceError) as exc:
        audit("telegram_login_failed", principal, step="code")
        raise _fail(exc, 400) from None
    if result.get("connected"):
        audit("telegram_connected", principal)
    return result


@router.post("/integrations/telegram/password", dependencies=[Depends(rate_limit("tg_login", 5))])
def tg_password(body: TgPasswordIn, principal: Principal = Depends(require_admin)) -> dict:
    tg = _tg()
    try:
        result = tg.account.submit_password(body.password)
    except (tg.LoginError, sources.SourceError) as exc:
        audit("telegram_login_failed", principal, step="password")
        raise _fail(exc, 400) from None
    audit("telegram_connected", principal)
    return result


@router.post("/integrations/telegram/logout")
def tg_logout(principal: Principal = Depends(require_admin)) -> dict:
    _tg().account.logout()
    audit("telegram_disconnected", principal)
    return {"connected": False}


@router.get("/integrations/telegram/dialogs", dependencies=[Depends(rate_limit("tg_dialogs", 6))])
def tg_dialogs(_: Principal = Depends(require_admin)) -> list[dict]:
    try:
        return _tg().account.dialogs()
    except sources.SourceError as exc:
        raise _fail(exc, 400) from None

