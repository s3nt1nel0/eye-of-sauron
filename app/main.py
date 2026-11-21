"""Application factory: middleware, routers, static GUI."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import __version__
from app import cve_classify, entities, github, secretbox, topics
from app.api import attack, auth, automation, content, cves, greader, history, insights, library, scrape
from app.api import ai as ai_api
from app.api import sources as sources_api
from app.api import accounts as accounts_api
from app.api import podcasts as podcasts_api
from app.api import extras as extras_api
from app.api import repos as repos_api
from app.config import get_settings
from app.db import init_db
from app.scheduler import scheduler
from app.security import Principal, ensure_admin_user, require_read

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
log = logging.getLogger("eos")

CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: https: http:; "
    "font-src 'self'; "
    "media-src https:; "
    "connect-src 'self'; "
    "manifest-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Adds hardening headers to every HTTP response (pure ASGI, streaming-safe)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_api = scope.get("path", "").startswith("/api/")
        is_https = scope.get("scheme") == "https"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                extra = {
                    b"content-security-policy": CSP.encode(),
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                    b"x-permitted-cross-domain-policies": b"none",
                }
                if is_api:
                    extra[b"cache-control"] = b"no-store"
                else:
                    # Revalidate UI assets every load (cheap 304s) so upgrades apply immediately.
                    extra[b"cache-control"] = b"no-cache"
                if is_https:
                    extra[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                present = {k.lower() for k, _ in headers}
                headers.extend((k, v) for k, v in extra.items() if k not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than the configured limit (DoS protection)."""

    def __init__(self, app: ASGIApp, default_limit: int, opml_limit: int) -> None:
        self.app = app
        self.default_limit = default_limit
        self.opml_limit = opml_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.opml_limit if scope.get("path") == "/api/v1/opml/import" else self.default_limit

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > limit
                except ValueError:
                    too_big = True
                if too_big:
                    response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                    await response(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # HTTPException propagates through FastAPI's body parsing unchanged.
                    raise HTTPException(status_code=413, detail="Request body too large")
            return message

        await self.app(scope, limited_receive, send)


def _adopt_youtube_feeds(db) -> None:
    """Once: plain RSS subscriptions of YouTube channel/playlist feeds (OPML or FreshRSS imports) become channels, and
    channels are filed in the YouTube folder, so videos live in the Videos tab and the Reader stays tidy."""
    from app import sources

    if db.execute("SELECT 1 FROM sync_state WHERE key = 'youtube_adopted_v1'").fetchone():
        return
    for row in db.execute("SELECT id, url FROM feeds WHERE COALESCE(kind, 'rss') = 'rss' AND url LIKE 'https://www.youtube.com/feeds/%'").fetchall():
        source = sources.youtube_source_for_url(row["url"])
        if source:
            sources.adopt_as_youtube(db, row["id"], source)
    db.execute("UPDATE feeds SET folder_id = ? WHERE kind = 'youtube'", (sources.youtube_folder(db),))
    db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('youtube_adopted_v1', '1')")


def _add_observatory_panels_once() -> None:
    """Once: the 🔭 panels join the existing CVE tracker and Ransomware tracker dashboards (at the top), and an
    "Internet threats" dashboard is created - instead of new tabs that would overlap them."""
    import json as _json

    from app import observatory
    from app.api.insights import observatory_widgets
    from app.db import get_db, now

    try:
        with get_db() as db:
            if db.execute("SELECT 1 FROM sync_state WHERE key = 'observatory_panels_v1'").fetchone():
                done = True
            else:
                done = False
        if done:
            _plain_observatory_titles()
            return
        with get_db() as db:
            for name, panels in (("CVE tracker", observatory.CVE_PANELS), ("Ransomware tracker", observatory.RW_PANELS)):
                for row in db.execute("SELECT id, widgets FROM dashboards WHERE name = ?", (name,)).fetchall():
                    widgets = _json.loads(row["widgets"])
                    if any((w.get("query") or {}).get("dataset") == "observatory" for w in widgets):
                        continue
                    added = observatory_widgets(panels) + widgets
                    db.execute("UPDATE dashboards SET widgets = ?, updated_at = ? WHERE id = ?",
                               (_json.dumps(added[:40], separators=(",", ":")), now(), row["id"]))
            if not db.execute("SELECT 1 FROM dashboards WHERE name = 'Internet threats'").fetchone():
                pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM dashboards").fetchone()[0]
                db.execute("INSERT INTO dashboards (name, position, widgets, created_at, updated_at) VALUES ('Internet threats', ?, ?, ?, ?)",
                           (pos, _json.dumps(observatory_widgets(observatory.NET_PANELS), separators=(",", ":")), now(), now()))
            db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('observatory_panels_v1', ?)", (str(now()),))
        _plain_observatory_titles()
    except Exception:  # optional: tried again next start
        log.exception("Adding the observatory panels failed")


def _plain_observatory_titles() -> None:
    """Panel titles without the 🔭 (Windows drew it as a faint glyph); the exposure panel's period is no longer fixed."""
    import json as _json

    from app.db import get_db

    with get_db() as db:
        for row in db.execute("SELECT id, widgets FROM dashboards WHERE widgets LIKE '%observatory%'").fetchall():
            widgets = _json.loads(row["widgets"])
            changed = False
            for w in widgets:
                if (w.get("query") or {}).get("dataset") == "observatory":
                    title = w["title"].removeprefix("🔭 ").replace("Exposure by technology · 90 days", "Exposure by technology")
                    if title != w["title"]:
                        w["title"], changed = title, True
            if changed:
                db.execute("UPDATE dashboards SET widgets = ? WHERE id = ?", (_json.dumps(widgets, separators=(",", ":")), row["id"]))


def _retag_episodes_once() -> None:
    """Once, in the background: podcast episodes stored before episode tagging got the format-topic rule and the
    show / General fallback are re-tagged."""
    import threading

    def run() -> None:
        from app import topics
        from app.db import get_db

        try:
            with get_db() as db:
                if db.execute("SELECT 1 FROM sync_state WHERE key = 'episode_topics_v1'").fetchone():
                    return
                ids = [r[0] for r in db.execute("SELECT a.id FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE f.kind = 'podcast'")]
            for start in range(0, len(ids), 500):  # short transactions: fetching and the UI keep going
                chunk = ids[start:start + 500]
                with get_db() as db:
                    db.execute(f"DELETE FROM article_topics WHERE article_id IN ({','.join('?' * len(chunk))})", chunk)  # nosec B608
                    topics.classify(db, chunk)
            with get_db() as db:
                added = topics.fill_episode_topics(db)
                db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('episode_topics_v1', ?)", (str(len(ids)),))
            log.info("Podcast episodes re-tagged: %d (fallback topics: %d)", len(ids), added)
        except Exception:  # optional; tried again next start
            log.exception("Episode re-tag failed")

    threading.Thread(target=run, name="episode-topics", daemon=True).start()



def _repair_saved_posts() -> None:
    """Once, in the background: posts saved before links were made clickable get clickable links, and LinkedIn /
    Instagram / Facebook posts get their public preview image."""
    import html
    import re
    import threading

    def run() -> None:
        from app import social_posts
        from app.db import get_db
        from app.sanitize import sanitize_html

        try:
            with get_db() as db:
                if db.execute("SELECT 1 FROM sync_state WHERE key = 'saved_posts_links_v1'").fetchone():
                    return
                rows = db.execute("SELECT a.id, a.url, a.content_html, f.social_platform FROM articles a JOIN feeds f ON f.id = a.feed_id "
                                  "WHERE f.url LIKE 'https://eye-of-sauron.invalid/saved-posts/%'").fetchall()
            for r in rows:
                body = r["content_html"] or ""
                if "<a " not in body:  # plain paragraphs → linked paragraphs
                    body = re.sub(r"<p>([^<]*)</p>", lambda m: social_posts.para_html(html.unescape(m.group(1))) or "", body)
                if "<img" not in body and r["social_platform"] in social_posts.PASTE_ONLY.values() and r["url"]:
                    image = social_posts.public_preview(r["url"]).get("image")
                    if image:
                        body = f'<p><img src="{html.escape(image, quote=True)}" alt=""></p>' + body
                with get_db() as db:
                    db.execute("UPDATE articles SET content_html = ? WHERE id = ?", (sanitize_html(body), r["id"]))
            with get_db() as db:
                db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('saved_posts_links_v1', ?)", (str(len(rows)),))
            log.info("Saved posts: links/images updated on %d post(s)", len(rows))
        except Exception:  # optional clean-up; try again next start
            log.exception("Saved-post repair failed")

    threading.Thread(target=run, name="saved-post-repair", daemon=True).start()


def _repair_youtube_titles() -> None:
    """Once, in the background: fix videos stored with YouTube's "Deleted video" placeholder title (needs the key)."""
    import threading

    from app import sources
    from app.db import get_db

    def run() -> None:
        try:
            key = sources.yt_key()
            if not key:
                return
            with get_db() as db:
                if db.execute("SELECT 1 FROM sync_state WHERE key = 'yt_placeholder_titles_v1'").fetchone():
                    return
                result = sources.repair_placeholder_titles(db, key)
                db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('yt_placeholder_titles_v1', ?)", (str(result),))
            log.info("YouTube placeholder titles: %s", result)
        except Exception:  # optional clean-up; try again next start
            log.exception("YouTube placeholder-title repair failed")

    threading.Thread(target=run, name="yt-title-repair", daemon=True).start()


def _reddit_subreddits_follow_new_posts(db) -> None:
    """Subreddit accounts added before 2026-11-15 followed the "hot" listing (/r/x/.rss); follow the newest posts
    (/r/x/new/.rss) so every new post arrives. Plain reader feeds of Reddit are left alone."""
    db.execute(
        "UPDATE feeds SET url = substr(url, 1, length(url) - 5) || '/new/.rss', refresh_minutes = COALESCE(refresh_minutes, 30), "
        "etag = NULL, last_modified = NULL, error_count = 0, next_fetch = NULL "
        "WHERE social_platform = 'reddit' AND url LIKE 'https://www.reddit.com/r/%/.rss' AND url NOT LIKE '%/new/.rss' "
        "AND url NOT LIKE '%/comments/%' "
        "AND NOT EXISTS (SELECT 1 FROM feeds g WHERE g.url = substr(feeds.url, 1, length(feeds.url) - 5) || '/new/.rss')")
    # ...and ask for 100 posts per fetch (Reddit sends 25 by default)
    db.execute("UPDATE feeds SET url = url || '?limit=100', etag = NULL, last_modified = NULL "
               "WHERE social_platform = 'reddit' AND url LIKE 'https://www.reddit.com/r/%/new/.rss' "
               "AND NOT EXISTS (SELECT 1 FROM feeds g WHERE g.url = feeds.url || '?limit=100')")


def _name_untitled_youtube_feeds(db) -> None:
    """YouTube channels added while YouTube's feed was down kept their feed URL as their name: use the channel name
    their videos carry (names you set yourself are left alone)."""
    db.execute(
        "UPDATE feeds SET title = (SELECT MAX(v.channel_title) FROM videos v JOIN articles a ON a.id = v.article_id "
        "WHERE a.feed_id = feeds.id) WHERE kind = 'youtube' AND custom_title = 0 AND (title = url OR title LIKE 'http%') "
        "AND source LIKE '%\"channel_id\"%' "
        "AND EXISTS (SELECT 1 FROM videos v JOIN articles a ON a.id = v.article_id WHERE a.feed_id = feeds.id "
        "AND v.channel_title IS NOT NULL AND v.channel_title != '')")


def _ttp_upkeep() -> None:
    """Tactic collections follow MITRE's matrices: fetch the tactic lists once when they were never stored (releases
    synced by an earlier version), and re-file the collections when the filing logic is newer than the stored state."""
    from app import atlas_sync, attack_sync, ttp_filing, ttp_subs
    from app.db import get_db

    with get_db() as db:
        have_attack = db.execute("SELECT 1 FROM attack_techniques WHERE domain = 'enterprise-attack' LIMIT 1").fetchone()
        have_atlas = db.execute("SELECT 1 FROM attack_techniques WHERE domain = 'atlas' LIMIT 1").fetchone()
        tac_attack = db.execute("SELECT 1 FROM attack_tactics WHERE domain = 'enterprise-attack' LIMIT 1").fetchone()
        tac_atlas = db.execute("SELECT 1 FROM attack_tactics WHERE domain = 'atlas' LIMIT 1").fetchone()
        stale = ttp_filing.stale(db)
    if have_atlas and (stale or not tac_atlas):
        atlas_sync.refresh_entities()  # sub-technique entities from the stored release
    if stale:
        ttp_filing.refile_all()
    if have_attack and not tac_attack:
        attack_sync.attack_sync.start(force=True)   # re-reads the current release from MITRE's repository
    if have_atlas and not tac_atlas:
        atlas_sync.atlas_sync.start(force=True)
    ttp_subs.ensure_current()  # a newer list of sub-technique context terms: re-index the sub-techniques once
    from app import threat_actors

    threat_actors.ensure_current()  # the bundled threat-actor catalogue (a file; nothing is downloaded)
    from app import reports

    reports.ensure_current()  # 📑 reports & guidance among the stored items (once per rule revision)
    from app import entities, entities_seed

    with get_db() as db:
        fixed = entities_seed.fix_seeded(db)  # built-in entries that matched too much (e.g. "Conti", also a surname)
    if fixed:
        entities.invalidate()
        entities.reindexer.request(fixed)


def _smart_feature_upkeep() -> None:
    """Background, once per start: apply a newer ATT&CK name list and regroup stories when their setting changed."""
    import threading

    from app import attack_sync, declutter, stories

    def work() -> None:
        attack_sync.refresh_if_stale()
        try:
            _ttp_upkeep()
        except Exception:
            logging.getLogger("eos").exception("Tactic collections could not be brought up to date")
        try:
            stories.ensure_current()
        except Exception:
            logging.getLogger("eos").exception("Story grouping could not start")
        try:
            declutter.ensure_current()
        except Exception:
            logging.getLogger("eos").exception("Ad clean-up could not start")

    threading.Thread(target=work, name="smart-upkeep", daemon=True).start()


@asynccontextmanager
async def lifespan(_: FastAPI):
    cfg = get_settings()
    _add_observatory_panels_once()
    if not cfg.disable_scheduler:
        scheduler.start()
        _repair_youtube_titles()
        _repair_saved_posts()
        _retag_episodes_once()
        _smart_feature_upkeep()
    yield
    scheduler.stop()
    from app.cve_sync import cve_sync

    cve_sync.stop()


def create_app() -> FastAPI:
    cfg = get_settings()
    os.umask(0o077)  # database, WAL and secret files are readable by the service user only
    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    init_db(cfg.db_path)
    ensure_admin_user()
    secretbox.ensure_key()
    from app.db import get_db

    with get_db() as db:
        migrated = secretbox.migrate_and_rotate(db)  # encrypt legacy plaintext credentials
    if migrated:
        log.info("Encrypted %d stored credential(s) at rest", migrated)
    with get_db() as db:
        cve_classify.seed_builtin(db)
        _adopt_youtube_feeds(db)
        _name_untitled_youtube_feeds(db)
        _reddit_subreddits_follow_new_posts(db)
        seeded = topics.seed_builtin(db)
        upgraded = topics.upgrade_builtin(db)
        github.classify(db)        # repos too (name + description + GitHub topics)
    if seeded or upgraded:  # after the commit above, so the re-tag sees the new topics
        topics.reclassifier.start()  # tag existing articles with the (new) built-in topics
    if entities.seed_builtin_watchlists():
        entities.reindexer.request(None)  # index existing articles in the background
    if cfg.allow_private_feeds or cfg.allow_private_webhooks:
        log.warning("Private-network targets are ENABLED for feeds/webhooks - SSRF protection relaxed.")

    app = FastAPI(
        title="Eye of Sauron API",
        version=__version__,
        description="Authenticate with `Authorization: Bearer eos_...` (create tokens in Settings → API).",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # served below, behind authentication (no anonymous API map)
        # No automatic trailing-slash redirects: Starlette builds them from the Host header
        # (host-header redirect vector when EOS_ALLOWED_HOSTS is "*").
        redirect_slashes=False,
        lifespan=lifespan,
    )

    @app.get("/api/v1/openapi.json", include_in_schema=False)
    def openapi_schema(_: Principal = Depends(require_read)) -> JSONResponse:
        return JSONResponse(app.openapi())

    # Order: last added = outermost.
    if cfg.allowed_hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.allowed_hosts)
    app.add_middleware(BodySizeLimitMiddleware, default_limit=cfg.max_body_bytes, opml_limit=cfg.max_opml_bytes)
    app.add_middleware(SecurityHeadersMiddleware)

    for router in (accounts_api.router, podcasts_api.router, attack.router, auth.router, content.router, automation.router, insights.router, cves.router, history.router, scrape.router, greader.admin_router,
                   sources_api.router, library.router, ai_api.router, extras_api.router, repos_api.router):
        app.include_router(router, prefix="/api/v1")
    # Google Reader-compatible API for native RSS apps (FreshRSS-style path and a short alias).
    app.include_router(greader.build_router("/api/greader.php"))
    app.include_router(greader.build_router("/api/greader"))

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Return field locations and messages only - never echo the submitted input back.
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "invalid")} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.exception_handler(OverflowError)
    async def overflow_handler(_: Request, __: OverflowError) -> JSONResponse:
        # e.g. a 25-digit id reaching SQLite (64-bit INTEGER): a client error, not a server error.
        return JSONResponse({"detail": "Number out of range"}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/login", include_in_schema=False)
    def login_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "login.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
