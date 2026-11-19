"""Folders, feeds, articles and collections (tags)."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field

from app import app_settings, atlas_sync, feed_doctor, intel, related, sources, stories, threat_actors
from app.scraper import ScrapeConfig
from app.api.common import Color, HttpUrlStr, Name, StrictModel, conflict, not_found
from app.db import get_db, now, placeholders
from app.fetcher import fetch_feed
from app.sanitize import sanitize_html
from app.scheduler import scheduler
from app.search import fts_query  # noqa: F401  (re-exported for callers/tests)
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter()

RefreshMinutes = Annotated[int, Field(ge=5, le=10080)]


# A feed whose items are articles (not videos, podcast episodes or account posts) - fixed SQL fragment, alias f
ARTICLE_FEED = "COALESCE(f.kind, 'rss') NOT IN ('youtube', 'podcast') AND f.social_platform IS NULL"


# ============================================================================ sidebar
@router.get("/sidebar", tags=["overview"])
def sidebar(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        # The Articles tab is articles only: videos, podcast episodes and account posts live in their own tabs. Every
        # folder is returned (Settings and the other tabs use them) with how many article feeds / other feeds it holds;
        # the Articles sidebar leaves out a folder that only holds other feeds (YouTube, Podcasts, Social Accounts).
        folders = [dict(r) for r in db.execute(
            "SELECT fo.id, fo.name, fo.position, "
            f"(SELECT COUNT(*) FROM feeds f WHERE f.folder_id = fo.id AND {ARTICLE_FEED}) AS article_feeds, "  # nosec B608 - fixed fragment
            f"(SELECT COUNT(*) FROM feeds f WHERE f.folder_id = fo.id AND NOT ({ARTICLE_FEED})) AS other_feeds "
            "FROM folders fo ORDER BY fo.position, fo.name")]
        account_feeds = [dict(r) for r in db.execute(
            "SELECT id, title, folder_id FROM feeds WHERE social_platform IS NOT NULL ORDER BY title COLLATE NOCASE")]
        media_feeds = [dict(r) for r in db.execute(
            "SELECT id, title, url, folder_id, enabled, error_count, last_error, "
            "CASE kind WHEN 'podcast' THEN 'podcasts' ELSE 'videos' END AS section "
            "FROM feeds WHERE kind IN ('youtube', 'podcast') ORDER BY title COLLATE NOCASE")]
        feeds = [
            dict(r)
            for r in db.execute(
                # One grouped pass over the unread articles. A per-feed correlated COUNT made SQLite walk the whole
                # unread index once per feed (O(feeds × unread)): ~12 s with ~190 feeds and ~25k unread articles.
                "SELECT f.id, f.title, f.url, f.site_url, f.folder_id, f.enabled, f.error_count, f.last_error, "
                "f.last_fetched, COALESCE(u.n, 0) AS unread "
                "FROM feeds f LEFT JOIN (SELECT feed_id, COUNT(*) AS n FROM articles WHERE is_read = 0 GROUP BY feed_id) u "
                f"ON u.feed_id = f.id WHERE {ARTICLE_FEED} ORDER BY f.title COLLATE NOCASE"  # nosec B608 - fixed fragment
            )
        ]
        tags = [
            dict(r)
            for r in db.execute(
                "SELECT t.id, t.name, t.color, COUNT(at.article_id) AS total, "
                "COALESCE(SUM(CASE WHEN a.is_read = 0 THEN 1 ELSE 0 END), 0) AS unread "
                "FROM tags t LEFT JOIN (article_tags at JOIN articles a ON a.id = at.article_id "
                f"JOIN feeds f ON f.id = a.feed_id AND {ARTICLE_FEED}) ON at.tag_id = t.id "  # nosec B608 - fixed fragment
                "GROUP BY t.id ORDER BY t.name COLLATE NOCASE"
            )
        ]
        # the ATT&CK / ATLAS tactic collections in the order of MITRE's matrix (kill chain), not alphabetically
        from app import ttp_filing

        order = {(ttp_filing.FRAMEWORKS[fw][0] + t["name"]).lower(): i for fw in ttp_filing.FRAMEWORKS
                 for i, t in enumerate(ttp_filing.tactics(db, fw))}

        def tag_key(t: dict) -> tuple:
            low = t["name"].lower()
            return (low.split(": ", 1)[0] + ": ", order[low], low) if low in order else (low, 0, low)

        tags.sort(key=tag_key)
        counts = db.execute(
            "SELECT COUNT(*) AS total, "
            "COALESCE(SUM(CASE WHEN a.is_read = 0 THEN 1 ELSE 0 END), 0) AS unread, "
            "COALESCE(SUM(a.is_starred), 0) AS starred FROM articles a JOIN feeds f ON f.id = a.feed_id "
            f"WHERE {ARTICLE_FEED}"  # nosec B608 - fixed fragment
        ).fetchone()
        reports_unread = db.execute("SELECT COUNT(*) FROM publications p JOIN articles a ON a.id = p.article_id WHERE a.is_read = 0").fetchone()[0]
    return {"folders": folders, "feeds": feeds, "media_feeds": media_feeds, "account_feeds": account_feeds, "tags": tags,
            "counts": {**dict(counts), "reports_unread": reports_unread}}


# ============================================================================ folders
class FolderIn(StrictModel):
    name: Name
    position: int = Field(default=0, ge=0, le=100000)


class FolderPatch(StrictModel):
    name: Name | None = None
    position: int | None = Field(default=None, ge=0, le=100000)


@router.get("/folders", tags=["folders"])
def list_folders(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT id, name, position FROM folders ORDER BY position, name")]


@router.post("/folders", status_code=201, tags=["folders"])
def create_folder(body: FolderIn, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            cur = db.execute("INSERT INTO folders (name, position) VALUES (?, ?)", (body.name, body.position))
    except sqlite3.IntegrityError:
        raise conflict("A folder with that name already exists") from None
    return {"id": cur.lastrowid, "name": body.name, "position": body.position}


@router.patch("/folders/{folder_id}", tags=["folders"])
def update_folder(folder_id: int, body: FolderPatch, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            row = db.execute("SELECT id FROM folders WHERE id = ?", (folder_id,)).fetchone()
            if row is None:
                raise not_found("Folder")
            if body.name is not None:
                db.execute("UPDATE folders SET name = ? WHERE id = ?", (body.name, folder_id))
            if body.position is not None:
                db.execute("UPDATE folders SET position = ? WHERE id = ?", (body.position, folder_id))
            return dict(db.execute("SELECT id, name, position FROM folders WHERE id = ?", (folder_id,)).fetchone())
    except sqlite3.IntegrityError:
        raise conflict("A folder with that name already exists") from None


@router.delete("/folders/{folder_id}", tags=["folders"])
def delete_folder(folder_id: int, _: Principal = Depends(require_write)) -> dict:
    """Deletes the folder; its feeds are kept and become unfiled."""
    with get_db() as db:
        if db.execute("DELETE FROM folders WHERE id = ?", (folder_id,)).rowcount == 0:
            raise not_found("Folder")
    return {"ok": True}


# ============================================================================ feeds
class FeedIn(StrictModel):
    url: HttpUrlStr
    title: Annotated[str, Field(max_length=300)] | None = None
    folder_id: int | None = None
    refresh_minutes: RefreshMinutes | None = None
    scrape: ScrapeConfig | None = None  # set = website scraping feed (HTML/CSS or JSON paths)
    source: sources.SourceConfig | None = None  # YouTube / HF papers / X / Telegram (url is derived from it)
    retention_days: int | None = Field(default=None, ge=0, le=36500)  # keep N days (0 = forever); None = the default


class FeedPatch(StrictModel):
    url: HttpUrlStr | None = None
    title: Annotated[str, Field(max_length=300)] | None = None
    folder_id: int | None = None
    clear_folder: bool = False
    refresh_minutes: RefreshMinutes | None = None
    use_default_refresh: bool = False
    enabled: bool | None = None
    scrape: ScrapeConfig | None = None
    clear_scrape: bool = False  # turn a scraped feed back into a normal RSS/Atom feed
    source: sources.SourceConfig | None = None  # same kind only (e.g. switch X bridge/API, HF min upvotes)
    full_text: Literal["auto", "always", "never"] | None = None  # fetch the full article page for summary-only items
    translate_titles: bool | None = None  # translate titles with the AI provider (turning it off restores the originals)


FEED_COLUMNS = (
    "id, folder_id, title, url, site_url, refresh_minutes, enabled, last_fetched, next_fetch, "
    "error_count, last_error, created_at, kind, social_platform, COALESCE(full_text, 'auto') AS full_text, "
    "translate_titles, adaptive_minutes"
)


def _check_folder(db: sqlite3.Connection, folder_id: int | None) -> None:
    if folder_id is not None and db.execute("SELECT 1 FROM folders WHERE id = ?", (folder_id,)).fetchone() is None:
        raise HTTPException(status_code=422, detail="Folder does not exist")


def _refresh_async(feed_id: int) -> None:
    threading.Thread(target=fetch_feed, args=(feed_id,), name=f"fetch-{feed_id}", daemon=True).start()


@router.get("/feeds", tags=["feeds"])
def list_feeds(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {FEED_COLUMNS} FROM feeds ORDER BY title COLLATE NOCASE")]


@router.post("/feeds", status_code=201, tags=["feeds"])
def create_feed(body: FeedIn, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            _check_folder(db, body.folder_id)
            if db.execute("SELECT COUNT(*) FROM feeds").fetchone()[0] >= 5000:
                raise HTTPException(status_code=400, detail="Feed limit reached")
            title = (body.title or "").strip()
            if body.source and body.scrape:
                raise HTTPException(status_code=422, detail="A feed is either scraped or a source, not both")
            if not body.source and not body.scrape:
                yt = sources.youtube_source_for_url(body.url)
                if yt:  # a YouTube channel/playlist feed address: follow it as a channel (Videos tab), not as articles
                    body = body.model_copy(update={"source": sources.parse_config(json.dumps(yt))})
            url, kind, refresh = body.url, (body.scrape.mode if body.scrape else "rss"), body.refresh_minutes
            if body.source:
                url, kind = sources.canonical_url(body.source), body.source.kind
                refresh = refresh or sources.DEFAULT_REFRESH[kind]
            # YouTube channels are a video library, not news: keep their videos (otherwise the global news
            # retention, 90 days by default, silently drops every upload of channels that post rarely).
            keep = 0 if kind == "youtube" else None
            days = body.retention_days if body.retention_days is not None else keep  # chosen when adding
            if kind == "youtube" and body.folder_id is None:
                body = body.model_copy(update={"folder_id": sources.youtube_folder(db)})  # channels live together
            cur = db.execute(
                "INSERT INTO feeds (folder_id, title, custom_title, url, refresh_minutes, created_at, kind, scrape, source, "
                "retention_days, max_articles) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (body.folder_id, title or url, 1 if title else 0, url, refresh, now(), kind,
                 body.scrape.model_dump_json() if body.scrape else None,
                 body.source.model_dump_json(exclude_none=True) if body.source else None, days, keep),
            )
            feed_id = cur.lastrowid
            row = dict(db.execute(f"SELECT {FEED_COLUMNS} FROM feeds WHERE id = ?", (feed_id,)).fetchone())
    except sqlite3.IntegrityError:
        adopted = _adopt_existing(body)
        if adopted is None:
            if body.source and body.source.kind == "youtube":
                raise conflict("This channel or playlist is already in your Videos") from None
            raise conflict("You are already subscribed to that feed") from None
        return adopted
    _refresh_async(feed_id)
    return row


def _adopt_existing(body: FeedIn) -> dict | None:
    """Adding a YouTube channel that is already subscribed as a plain RSS feed (same address) upgrades that feed
    to a channel instead of failing - its articles are kept and its videos appear in the Videos tab."""
    if not body.source or body.source.kind != "youtube":
        return None
    url = sources.canonical_url(body.source)
    with get_db() as db:
        row = db.execute("SELECT id, kind FROM feeds WHERE url = ?", (url,)).fetchone()
        if row is None or row["kind"] == "youtube":
            return None
        sources.adopt_as_youtube(db, row["id"], json.loads(body.source.model_dump_json(exclude_none=True)))
        if body.title and body.title.strip():
            db.execute("UPDATE feeds SET title = ?, custom_title = 1 WHERE id = ?", (body.title.strip(), row["id"]))
        out = dict(db.execute(f"SELECT {FEED_COLUMNS} FROM feeds WHERE id = ?", (row["id"],)).fetchone())
    _refresh_async(out["id"])
    return {**out, "adopted": True}


@router.patch("/feeds/{feed_id}", tags=["feeds"])
def update_feed(feed_id: int, body: FeedPatch, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            current = db.execute("SELECT kind FROM feeds WHERE id = ?", (feed_id,)).fetchone()
            if current is None:
                raise not_found("Feed")
            is_source = current["kind"] in sources.KINDS
            if is_source and (body.url is not None or body.scrape is not None or body.clear_scrape):
                raise HTTPException(status_code=422, detail="This feed's address comes from its source settings")
            if body.source is not None:
                if body.source.kind != current["kind"]:
                    raise HTTPException(status_code=422, detail="Source settings must keep the same kind")
                db.execute("UPDATE feeds SET source = ?, url = ?, next_fetch = NULL, error_count = 0 WHERE id = ?",
                           (body.source.model_dump_json(exclude_none=True), sources.canonical_url(body.source), feed_id))
            if body.url is not None:
                db.execute(
                    "UPDATE feeds SET url = ?, etag = NULL, last_modified = NULL, next_fetch = NULL, "
                    "error_count = 0, last_error = NULL WHERE id = ?",
                    (body.url, feed_id),
                )
            if body.title is not None:
                title = body.title.strip()
                db.execute(
                    "UPDATE feeds SET title = CASE WHEN ? = '' THEN title ELSE ? END, custom_title = ? WHERE id = ?",
                    (title, title, 1 if title else 0, feed_id),
                )
            if body.clear_folder:
                db.execute("UPDATE feeds SET folder_id = NULL WHERE id = ?", (feed_id,))
            elif body.folder_id is not None:
                _check_folder(db, body.folder_id)
                db.execute("UPDATE feeds SET folder_id = ? WHERE id = ?", (body.folder_id, feed_id))
            if body.use_default_refresh:
                db.execute("UPDATE feeds SET refresh_minutes = NULL WHERE id = ?", (feed_id,))
            elif body.refresh_minutes is not None:
                db.execute("UPDATE feeds SET refresh_minutes = ? WHERE id = ?", (body.refresh_minutes, feed_id))
            if body.enabled is not None:
                db.execute(
                    "UPDATE feeds SET enabled = ?, next_fetch = NULL, error_count = 0 WHERE id = ?",
                    (int(body.enabled), feed_id),
                )
            if body.full_text is not None:
                db.execute("UPDATE feeds SET full_text = ? WHERE id = ?", (None if body.full_text == "auto" else body.full_text, feed_id))
            if body.translate_titles is not None:
                db.execute("UPDATE feeds SET translate_titles = ? WHERE id = ?", (int(body.translate_titles), feed_id))
            if body.clear_scrape:
                db.execute("UPDATE feeds SET kind = 'rss', scrape = NULL, next_fetch = NULL WHERE id = ?", (feed_id,))
            elif body.scrape is not None:
                db.execute(
                    "UPDATE feeds SET kind = ?, scrape = ?, next_fetch = NULL, error_count = 0, etag = NULL, "
                    "last_modified = NULL WHERE id = ?",
                    (body.scrape.mode, body.scrape.model_dump_json(), feed_id),
                )
            row = dict(db.execute(f"SELECT {FEED_COLUMNS} FROM feeds WHERE id = ?", (feed_id,)).fetchone())
    except sqlite3.IntegrityError:
        raise conflict("Another feed already uses that URL") from None
    if body.translate_titles is not None:
        from app import translate

        if body.translate_titles:  # the latest 100 titles now, new ones as they arrive
            translate.worker.add(translate.recent_ids(feed_id))
        else:
            translate.undo(feed_id)
    scheduler.wake()
    return row


@router.delete("/feeds/{feed_id}", tags=["feeds"])
def delete_feed(feed_id: int, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM feeds WHERE id = ?", (feed_id,)).rowcount == 0:
            raise not_found("Feed")
        # Per-feed source cursors (X since_id, Telegram last id): SQLite may reuse the id for a new feed.
        db.execute("DELETE FROM sync_state WHERE key IN (?, ?)", (f"x_since:{feed_id}", f"tg_last:{feed_id}"))
    audit("feed_deleted", principal, feed_id=feed_id)
    return {"ok": True}


@router.post("/feeds/{feed_id}/refresh", tags=["feeds"], dependencies=[Depends(rate_limit("feed_refresh", 30))])
def refresh_feed(feed_id: int, _: Principal = Depends(require_write)) -> dict:
    """Synchronously refresh one feed and return the result."""
    with get_db() as db:
        if db.execute("SELECT 1 FROM feeds WHERE id = ?", (feed_id,)).fetchone() is None:
            raise not_found("Feed")
    return fetch_feed(feed_id)


REFRESH_SCOPES = {  # fixed SQL fragments chosen by an enum
    "all": "1",
    "reader": "COALESCE(kind, 'rss') NOT IN ('youtube', 'podcast')",
    "podcasts": "kind = 'podcast'",
    "videos": "kind = 'youtube'",
    "accounts": "(social_platform IS NOT NULL OR kind IN ('x', 'telegram'))",
}


@router.post("/feeds/refresh", tags=["feeds"], dependencies=[Depends(rate_limit("refresh_all", 6))])
def refresh_all(section: Literal["all", "reader", "videos", "accounts", "podcasts"] = "all", _: Principal = Depends(require_write)) -> dict:
    """Mark enabled feeds as due (all, or one section's: reader feeds, YouTube channels, social accounts);
    the scheduler fetches them in the background."""
    with get_db() as db:
        count = db.execute(f"UPDATE feeds SET next_fetch = 0 WHERE enabled = 1 AND {REFRESH_SCOPES[section]}").rowcount  # nosec B608
    scheduler.wake()
    return {"queued": count}


class BulkIntervalIn(StrictModel):
    scope: Literal["all", "folder", "unfiled"]
    folder_id: int | None = None
    refresh_minutes: RefreshMinutes | None = None  # None = use the global default


@router.post("/feeds/bulk-interval", tags=["feeds"])
def bulk_interval(body: BulkIntervalIn, _: Principal = Depends(require_write)) -> dict:
    """Set (or reset to default) the refresh interval for many feeds at once."""
    with get_db() as db:
        if body.scope == "folder":
            if body.folder_id is None:
                raise HTTPException(status_code=422, detail="folder_id is required for scope=folder")
            _check_folder(db, body.folder_id)
            cur = db.execute(
                "UPDATE feeds SET refresh_minutes = ?, next_fetch = NULL WHERE folder_id = ?",
                (body.refresh_minutes, body.folder_id),
            )
        elif body.scope == "unfiled":
            cur = db.execute(
                "UPDATE feeds SET refresh_minutes = ?, next_fetch = NULL WHERE folder_id IS NULL",
                (body.refresh_minutes,),
            )
        else:
            cur = db.execute("UPDATE feeds SET refresh_minutes = ?, next_fetch = NULL", (body.refresh_minutes,))
    scheduler.wake()
    return {"updated": cur.rowcount}


class BulkFeedsIn(StrictModel):
    ids: list[Annotated[int, Field(ge=1)]] = Field(min_length=1, max_length=5000)
    action: Literal["move", "set_refresh", "enable", "disable", "fetch_now", "reset_errors", "delete"]
    folder_id: int | None = None          # move: target folder, None = unfiled
    refresh_minutes: RefreshMinutes | None = None  # set_refresh: None = use the global default


@router.post("/feeds/bulk", tags=["feeds"], dependencies=[Depends(rate_limit("feeds_bulk", 30))])
def bulk_feeds(body: BulkFeedsIn, principal: Principal = Depends(require_write)) -> dict:
    """Apply one change to many feeds at once (Settings -> Feeds -> Select)."""
    ids = sorted(set(body.ids))
    marks = placeholders(len(ids))
    with get_db() as db:
        if body.action == "move":
            _check_folder(db, body.folder_id)
            cur = db.execute(f"UPDATE feeds SET folder_id = ? WHERE id IN ({marks})", (body.folder_id, *ids))
        elif body.action == "set_refresh":
            cur = db.execute(f"UPDATE feeds SET refresh_minutes = ?, next_fetch = NULL WHERE id IN ({marks})",
                             (body.refresh_minutes, *ids))
        elif body.action in ("enable", "disable"):
            cur = db.execute(f"UPDATE feeds SET enabled = ?, next_fetch = NULL, error_count = 0 WHERE id IN ({marks})",
                             (int(body.action == "enable"), *ids))
        elif body.action == "fetch_now":
            cur = db.execute(f"UPDATE feeds SET next_fetch = 0 WHERE enabled = 1 AND id IN ({marks})", ids)
        elif body.action == "reset_errors":
            cur = db.execute(f"UPDATE feeds SET error_count = 0, last_error = NULL, next_fetch = 0 WHERE id IN ({marks})",
                             ids)
        else:
            cur = db.execute(f"DELETE FROM feeds WHERE id IN ({marks})", ids)
            keys = [k for i in ids for k in (f"x_since:{i}", f"tg_last:{i}")]
            for start in range(0, len(keys), 500):
                chunk = keys[start : start + 500]
                db.execute(f"DELETE FROM sync_state WHERE key IN ({placeholders(len(chunk))})", chunk)
    if body.action == "delete":
        audit("feeds_bulk_deleted", principal, count=cur.rowcount)
    scheduler.wake()
    return {"updated": cur.rowcount}


# Reader feeds (not YouTube, not social accounts) - fixed SQL fragment
READER_FEED = "COALESCE(kind, 'rss') NOT IN ('youtube', 'podcast') AND social_platform IS NULL"
# What each kind of feed is (the Settings -> Feeds tabs) - fixed SQL fragments, chosen from a Literal
FEED_TYPE_SQL = {
    "articles": READER_FEED,
    "podcasts": "kind = 'podcast'",
    "videos": "kind = 'youtube'",
    "accounts": "social_platform IS NOT NULL",
}
KEEP_SAFE = ("is_starred = 0 AND id NOT IN (SELECT article_id FROM article_tags WHERE source = 'manual') "
             "AND id NOT IN (SELECT article_id FROM video_group_items)")


class KeepArticlesIn(StrictModel):
    scope: Literal["all", "folder", "feeds"]
    folder_id: int | None = None                                                       # scope=folder
    feed_ids: list[Annotated[int, Field(ge=1)]] | None = Field(None, min_length=1, max_length=5000)  # scope=feeds
    days: int = Field(ge=0, le=36500)   # keep items from the last N days; 0 = keep everything (no limit)
    dry_run: bool = False               # only count what would be removed
    # which kinds of feed (the Settings -> Feeds tabs); None = every kind: articles, podcasts, YouTube and accounts
    kinds: list[Literal["articles", "podcasts", "videos", "accounts"]] | None = Field(None, min_length=1, max_length=4)


@router.post("/feeds/keep", tags=["feeds"], dependencies=[Depends(rate_limit("feeds_keep", 60))])
def keep_articles(body: KeepArticlesIn, principal: Principal = Depends(require_write)) -> dict:
    """Keep feeds to a time frame: items older than it are removed now and as they age (the feeds' retention is set to
    it). Applies to the chosen feeds of the chosen kinds - article feeds, podcasts, YouTube channels and accounts, or
    all of them (``kinds`` omitted). Starred, hand-filed and video-group items are always kept. days = 0 keeps
    everything from now on (removed items are not brought back)."""
    skipped = 0
    kinds = body.kinds or list(FEED_TYPE_SQL)
    kind_sql = "(" + " OR ".join(f"({FEED_TYPE_SQL[k]})" for k in kinds) + ")"  # fixed fragments only
    with get_db() as db:
        if body.scope == "feeds":
            if not body.feed_ids:
                raise HTTPException(status_code=422, detail="feed_ids is required for scope=feeds")
            wanted = sorted(set(body.feed_ids))
            ids = [r[0] for r in db.execute(  # nosec B608 - fixed fragment + placeholders
                f"SELECT id FROM feeds WHERE {kind_sql} AND id IN ({placeholders(len(wanted))})", wanted)]
            skipped = len(wanted) - len(ids)
        elif body.scope == "folder":
            if body.folder_id is None or db.execute("SELECT 1 FROM folders WHERE id = ?", (body.folder_id,)).fetchone() is None:
                raise HTTPException(status_code=422, detail="Folder does not exist")
            ids = [r[0] for r in db.execute(f"SELECT id FROM feeds WHERE {kind_sql} AND folder_id = ?", (body.folder_id,))]  # nosec B608
        else:
            ids = [r[0] for r in db.execute(f"SELECT id FROM feeds WHERE {kind_sql}")]  # nosec B608
        if not ids:
            return {"feeds": 0, "removed": 0, "oldest": None, "days": body.days, "dry_run": body.dry_run, "skipped": skipped}
        removed, oldest, cutoff = 0, None, now() - body.days * 86400
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = placeholders(len(chunk))
            cond = f"feed_id IN ({marks}) AND sort_ts < ? AND {KEEP_SAFE}"
            if body.days:
                n, low = db.execute(f"SELECT COUNT(*), MIN(sort_ts) FROM articles WHERE {cond}", [*chunk, cutoff]).fetchone()  # nosec B608
                oldest = low if oldest is None or (low is not None and low < oldest) else oldest
                if not body.dry_run and n:
                    db.execute(f"INSERT OR IGNORE INTO article_tombstones (feed_id, guid, removed_at) "  # nosec B608
                               f"SELECT feed_id, guid, ? FROM articles WHERE {cond}", [now(), *chunk, cutoff])
                    n = db.execute(f"DELETE FROM articles WHERE {cond}", [*chunk, cutoff]).rowcount  # nosec B608
                removed += n
            if not body.dry_run:  # 0 = keep everything: the item cap is lifted too, so nothing is trimmed by count
                db.execute(f"UPDATE feeds SET retention_days = ?, max_articles = CASE WHEN ? = 0 THEN 0 ELSE max_articles END "  # nosec B608
                           f"WHERE id IN ({marks})", [body.days, body.days, *chunk])
    if not body.dry_run:
        audit("articles_scaled_back", principal, feeds=len(ids), days=body.days, removed=removed)
    return {"feeds": len(ids), "removed": removed, "oldest": oldest, "days": body.days, "dry_run": body.dry_run, "skipped": skipped}


DOCTOR_COLUMNS = "id, url, site_url, kind, title, last_error, error_count"


@router.post("/feeds/{feed_id}/diagnose", tags=["feeds"], dependencies=[Depends(rate_limit("feed_diagnose", 20))])
def diagnose_feed(feed_id: int, _: Principal = Depends(require_write)) -> dict:
    """Troubleshoot one feed: why it fails, and a working replacement address if one exists."""
    with get_db() as db:
        row = db.execute(f"SELECT {DOCTOR_COLUMNS} FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    if row is None:
        raise not_found("Feed")
    report = feed_doctor.diagnose(dict(row))
    report["title"] = row["title"]
    return report


class DiagnoseManyIn(StrictModel):
    ids: list[Annotated[int, Field(ge=1)]] | None = Field(default=None, max_length=1000)  # None = every failing feed


@router.post("/feeds/diagnose", tags=["feeds"], dependencies=[Depends(rate_limit("feed_diagnose_many", 4))])
def diagnose_many(body: DiagnoseManyIn, _: Principal = Depends(require_write)) -> dict:
    """Troubleshoot many feeds in the background; poll GET /feeds/diagnose for the results."""
    with get_db() as db:
        if body.ids:
            ids = sorted(set(body.ids))
            rows = db.execute(f"SELECT {DOCTOR_COLUMNS} FROM feeds WHERE id IN ({placeholders(len(ids))}) "
                              "ORDER BY title COLLATE NOCASE", ids).fetchall()
        else:
            rows = db.execute(f"SELECT {DOCTOR_COLUMNS} FROM feeds WHERE error_count > 0 "
                              "ORDER BY title COLLATE NOCASE").fetchall()
    if not rows:
        return {"started": False, "total": 0}
    if not feed_doctor.doctor.start([dict(r) for r in rows]):
        raise conflict("A troubleshooting run is already in progress")
    return {"started": True, "total": len(rows)}


@router.get("/feeds/diagnose", tags=["feeds"])
def diagnose_status(_: Principal = Depends(require_read)) -> dict:
    return feed_doctor.doctor.state


@router.post("/feeds/diagnose/cancel", tags=["feeds"])
def diagnose_cancel(_: Principal = Depends(require_write)) -> dict:
    feed_doctor.doctor.cancel()
    return {"ok": True}


# ============================================================================ articles
READER_ONLY = ARTICLE_FEED  # articles only: videos, podcast episodes and account posts have their own tabs


def _article_filters(
    feed_id: int | None,
    folder_id: int | None,
    tag_id: int | None,
    unread: bool,
    starred: bool,
    since: int | None,
    until: int | None,
    q: str | None,
    read: bool = False,
    technique: str | None = None,
    entity_id: int | None = None,
    publication: str | None = None,
) -> tuple[list[str], list]:
    # Videos, podcast episodes and account posts stay out of the Articles lists (All, Unread, Starred, folders,
    # collections, search): they have their own tabs. Only an explicit feed_id still opens that feed's own items.
    where: list[str] = [] if feed_id is not None else [READER_ONLY]
    params: list = []
    if read:
        where.append("a.is_read = 1")
    if feed_id is not None:
        where.append("a.feed_id = ?")
        params.append(feed_id)
    if folder_id is not None:
        where.append("f.folder_id = ?")
        params.append(folder_id)
    if tag_id is not None:
        where.append("EXISTS (SELECT 1 FROM article_tags at WHERE at.article_id = a.id AND at.tag_id = ?)")
        params.append(tag_id)
    if technique is not None:  # an ATT&CK / ATLAS technique ID: articles the technique watchlists matched
        where.append("a.id IN (SELECT ae.article_id FROM article_entities ae WHERE ae.entity_id = "
                     "(SELECT e.id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                     "WHERE w.slug = ? AND e.name LIKE ? ESCAPE '\\' LIMIT 1))")
        params += ["mitre-atlas-techniques" if technique.startswith("AML.") else "mitre-attack-techniques", f"%({technique})"]
    if publication is not None:  # 📑 reports & guidance: all, by kind (government / vendor) or by document type
        if publication == "all":
            where.append("a.id IN (SELECT article_id FROM publications)")
        elif publication in ("government", "vendor"):
            where.append("a.id IN (SELECT article_id FROM publications WHERE kind = ?)")
            params.append(publication)
        else:
            where.append("a.id IN (SELECT article_id FROM publications WHERE doc_type = ?)")
            params.append(publication)
    if entity_id is not None:  # a watchlist entity: the articles that mention it (a threat actor: under any of its names)
        with get_db() as db:
            members = threat_actors.expand(db, entity_id)
        where.append(f"a.id IN (SELECT ae.article_id FROM article_entities ae WHERE ae.entity_id IN ({placeholders(len(members))}))")  # nosec B608
        params += members
    if unread:
        where.append("a.is_read = 0")
    if starred:
        where.append("a.is_starred = 1")
    if since is not None:
        where.append("a.sort_ts >= ?")
        params.append(since)
    if until is not None:
        where.append("a.sort_ts <= ?")
        params.append(until)
    if q:
        match = fts_query(q)
        if match is None:
            where.append("0")
        else:
            where.append("a.id IN (SELECT rowid FROM articles_fts WHERE articles_fts MATCH ?)")
            params.append(match)
    return where, params


def _attach_tags(db: sqlite3.Connection, articles: list[dict]) -> None:
    if not articles:
        return
    ids = [a["id"] for a in articles]
    by_id: dict[int, list[dict]] = {i: [] for i in ids}
    for r in db.execute(
        "SELECT at.article_id, t.id, t.name, t.color, at.source FROM article_tags at "
        f"JOIN tags t ON t.id = at.tag_id WHERE at.article_id IN ({placeholders(len(ids))}) ORDER BY t.name",
        ids,
    ):
        by_id[r["article_id"]].append({"id": r["id"], "name": r["name"], "color": r["color"], "source": r["source"]})
    for a in articles:
        a["tags"] = by_id[a["id"]]


@router.get("/articles", tags=["articles"], dependencies=[Depends(rate_limit("articles", 300, 120))])
def list_articles(
    _: Principal = Depends(require_read),
    feed_id: int | None = None,
    folder_id: int | None = None,
    tag_id: int | None = None,
    unread: bool = False,
    read: bool = False,
    starred: bool = False,
    since: Annotated[int | None, Query(ge=0)] = None,
    until: Annotated[int | None, Query(ge=0)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    technique: Annotated[str | None, Query(pattern=r"^(AML\.)?T\d{4}(\.\d{3})?$")] = None,
    publication: Literal["all", "government", "vendor", "advisory", "guidance", "report"] | None = None,
    entity_id: Annotated[int | None, Query(ge=1, le=2**31 - 1)] = None,
    sort: Literal["newest", "oldest"] = "newest",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> dict:
    if unread and read:
        raise HTTPException(status_code=422, detail="Choose either unread or read, not both")
    where, params = _article_filters(feed_id, folder_id, tag_id, unread, starred, since, until, q, read, technique, entity_id, publication)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    direction = "DESC" if sort == "newest" else "ASC"  # from a Literal: never user text
    with get_db() as db:
        total = db.execute(
            f"SELECT COUNT(*) FROM articles a JOIN feeds f ON f.id = a.feed_id {clause}", params
        ).fetchone()[0]
        rows = db.execute(
            "SELECT a.id, a.feed_id, f.title AS feed_title, a.title, a.url, a.author, a.published, "
            "a.fetched_at, a.sort_ts, a.is_read, a.is_starred, a.story_id, substr(a.text_content, 1, 280) AS snippet, "
            "(length(a.text_content) + 1199) / 1200 AS read_minutes, "  # ~200 words a minute
            "(SELECT i.fetched_at FROM feed_icons i WHERE i.feed_id = a.feed_id AND i.data IS NOT NULL) AS icon_v "
            f"FROM articles a JOIN feeds f ON f.id = a.feed_id {clause} "
            f"ORDER BY a.sort_ts {direction}, a.id {direction} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        articles = [dict(r) for r in rows]
        _attach_tags(db, articles)
        atlas_sync.attach_ttps(db, articles)
        if app_settings.get(db, "story_grouping"):
            stories.attach(db, articles)
    return {"total": total, "offset": offset, "limit": limit, "items": articles}


@router.get("/articles/{article_id}/story", tags=["articles"])
def article_story(article_id: int, _: Principal = Depends(require_read)) -> dict:
    """The other sources of the same story (every article that shares this one's story, oldest first)."""
    with get_db() as db:
        items = stories.members(db, article_id)
    if items is None:
        raise not_found("Article")
    return {"items": items}


class FullTextIn(StrictModel):
    force: bool = False  # try again even if an earlier attempt failed


@router.post("/articles/{article_id}/fulltext", tags=["articles"], dependencies=[Depends(rate_limit("fulltext", 30))])
def article_fulltext(article_id: int, body: FullTextIn | None = None, _: Principal = Depends(require_write)) -> dict:
    """Fetch the article's page and replace the feed's summary with the full text (when the site allows it)."""
    from app import fulltext

    with get_db() as db:
        if db.execute("SELECT 1 FROM articles WHERE id = ?", (article_id,)).fetchone() is None:
            raise not_found("Article")
    return fulltext.fill_article(article_id, force=bool(body and body.force))


@router.get("/articles/{article_id}/related", tags=["articles"], dependencies=[Depends(rate_limit("related_media", 240))])
def related_media(article_id: int, kind: Literal["videos", "podcasts"], limit: int = Query(40, ge=1, le=100),
                  _: Principal = Depends(require_read)) -> dict:
    """Videos or podcast episodes that name the same specific things as this article (threat actors, malware,
    techniques…), strongest match first, each with what it shares."""
    with get_db() as db:
        if db.execute("SELECT 1 FROM articles WHERE id = ?", (article_id,)).fetchone() is None:
            raise not_found("Article")
        return related.related(db, article_id, kind, limit)


@router.get("/reports/summary", tags=["insights"], dependencies=[Depends(rate_limit("threat_actors", 240))])
def reports_summary(_: Principal = Depends(require_read)) -> dict:
    """📑 Reports & guidance: how many by kind and type, and the publishers with their latest item."""
    from app import reports

    with get_db() as db:
        return reports.counts(db)


@router.get("/threat-actors", tags=["insights"], dependencies=[Depends(rate_limit("threat_actors", 240))])
def threat_actor_list(q: Annotated[str, Query(max_length=80)] = "", days: int = 0, limit: int = Query(200, ge=1, le=500),
                      _: Principal = Depends(require_read)) -> dict:
    """Tracked threat actors (MITRE ATT&CK groups, the bundled catalogue, your own lists - the same actor under
    several names counts once) with how many articles / videos / podcast episodes mention each."""
    if days not in (0, 7, 30, 90, 365):
        raise HTTPException(status_code=422, detail="days must be 0, 7, 30, 90 or 365")
    with get_db() as db:
        return threat_actors.listing(db, q.strip(), days, limit)


@router.get("/articles/{article_id}", tags=["articles"])
def get_article(article_id: int, _: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        row = db.execute(
            "SELECT a.id, a.feed_id, f.title AS feed_title, f.site_url AS feed_site_url, a.title, a.url, "
            "a.author, a.content_html, a.published, a.fetched_at, a.sort_ts, a.is_read, a.is_starred, a.fulltext, a.title_original, "
            "(length(a.text_content) + 1199) / 1200 AS read_minutes, "
            "length(a.text_content) AS text_length, COALESCE(f.full_text, 'auto') AS full_text_mode, "
            "(COALESCE(f.kind, 'rss') IN ('rss', 'html') AND f.social_platform IS NULL) AS full_text_possible "
            "FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id = ?",
            (article_id,),
        ).fetchone()
        if row is None:
            raise not_found("Article")
        article = dict(row)
        _attach_tags(db, [article])
        atlas_sync.attach_ttps(db, [article])
        prefs = app_settings.get_all(db)
        load_images = prefs["load_images"]
        article["entities"] = intel.article_entities(db, article_id) if prefs["entity_chips"] else []
        # how many videos / podcast episodes name the same actors, malware, techniques… (the reader's ▶ and 🎙 buttons)
        article["related"] = related.counts(db, article_id) if prefs["related_media"] else {"videos": 0, "podcasts": 0}
    # Re-sanitise on output (defence in depth, and honours the images setting).
    article["content_html"] = sanitize_html(article["content_html"], allow_images=load_images)
    if load_images and prefs["image_proxy"]:  # images through this server: publishers don't see the reader's IP
        from app import media

        article["content_html"] = media.rewrite_images(article["content_html"])
    return article


class ArticlePatch(StrictModel):
    is_read: bool | None = None
    is_starred: bool | None = None


@router.patch("/articles/{article_id}", tags=["articles"])
def update_article(article_id: int, body: ArticlePatch, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        old = db.execute("SELECT is_read, EXISTS (SELECT 1 FROM videos v WHERE v.article_id = articles.id) AS video "
                         "FROM articles WHERE id = ?", (article_id,)).fetchone()
        if old is None:
            raise not_found("Article")
        if body.is_read is not None:
            db.execute("UPDATE articles SET is_read = ? WHERE id = ?", (int(body.is_read), article_id))
            if old["is_read"] and not body.is_read:  # traceable: "my watched videos went back to unwatched"
                audit("video_unwatched" if old["video"] else "article_unread", principal, article_id=article_id)
        if body.is_starred is not None:
            db.execute(
                "UPDATE articles SET is_starred = ?, starred_at = CASE WHEN ? THEN ? ELSE NULL END WHERE id = ?",
                (int(body.is_starred), int(body.is_starred), now(), article_id),
            )
        row = db.execute("SELECT id, is_read, is_starred FROM articles WHERE id = ?", (article_id,)).fetchone()
    return dict(row)


class MarkReadIn(StrictModel):
    ids: list[int] | None = Field(default=None, max_length=1000)
    feed_id: int | None = None
    folder_id: int | None = None
    tag_id: int | None = None
    starred: bool = False
    all: bool = False
    before: int | None = Field(default=None, ge=0)
    read: bool = True


@router.post("/articles/mark-read", tags=["articles"])
def mark_read(body: MarkReadIn, principal: Principal = Depends(require_write)) -> dict:
    value = int(body.read)
    if not body.read:
        audit("articles_marked_unread", principal, ids=len(body.ids or []), feed_id=body.feed_id, folder_id=body.folder_id,
              tag_id=body.tag_id, starred=body.starred, all=body.all)
    with get_db() as db:
        if body.ids:
            count = db.execute(
                f"UPDATE articles SET is_read = ? WHERE id IN ({placeholders(len(body.ids))})",
                [value, *body.ids],
            ).rowcount
            return {"updated": count}
        if not (body.all or body.feed_id or body.folder_id or body.tag_id or body.starred):
            raise HTTPException(status_code=422, detail="Specify ids, a scope, or all=true")
        where, params = _article_filters(
            body.feed_id, body.folder_id, body.tag_id, False, body.starred, None, body.before, None
        )
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        count = db.execute(
            "UPDATE articles SET is_read = ? WHERE id IN "
            f"(SELECT a.id FROM articles a JOIN feeds f ON f.id = a.feed_id {clause})",
            [value, *params],
        ).rowcount
    return {"updated": count}


ArticleId = Annotated[int, Field(ge=1, le=2**62)]


class BulkArticlesIn(StrictModel):
    """One action on several selected articles (the list's selection mode)."""
    ids: list[ArticleId] = Field(min_length=1, max_length=1000)
    action: Literal["read", "unread", "star", "unstar", "add_tag", "remove_tag"]
    tag_id: int | None = Field(default=None, ge=1, le=2**62)   # required for add_tag / remove_tag


@router.post("/articles/bulk", tags=["articles"])
def bulk_articles(body: BulkArticlesIn, principal: Principal = Depends(require_write)) -> dict:
    ids = list(dict.fromkeys(body.ids))  # de-duplicate, keep order
    if body.action == "unread":
        audit("articles_marked_unread", principal, ids=len(ids), first=ids[0])
    marks = placeholders(len(ids))
    with get_db() as db:
        if body.action in ("read", "unread"):
            count = db.execute(f"UPDATE articles SET is_read = ? WHERE id IN ({marks})",  # nosec B608 - placeholders only
                               [int(body.action == "read"), *ids]).rowcount
        elif body.action in ("star", "unstar"):
            star = body.action == "star"
            # Only rows whose state changes, so re-starring keeps the original starred_at.
            count = db.execute(
                "UPDATE articles SET is_starred = ?, starred_at = CASE WHEN ? THEN ? ELSE NULL END "
                f"WHERE id IN ({marks}) AND is_starred = ?",  # nosec B608 - placeholders only
                [int(star), int(star), now(), *ids, int(not star)]).rowcount
        else:
            if body.tag_id is None:
                raise HTTPException(status_code=422, detail="tag_id is required for this action")
            if db.execute("SELECT 1 FROM tags WHERE id = ?", (body.tag_id,)).fetchone() is None:
                raise not_found("Collection")
            if body.action == "add_tag":
                count = db.execute(
                    "INSERT INTO article_tags (article_id, tag_id, source, created_at) "
                    f"SELECT id, ?, 'manual', ? FROM articles WHERE id IN ({marks}) "  # nosec B608 - placeholders only
                    "ON CONFLICT(article_id, tag_id) DO UPDATE SET source = 'manual'",
                    [body.tag_id, now(), *ids]).rowcount
            else:
                count = db.execute(f"DELETE FROM article_tags WHERE tag_id = ? AND article_id IN ({marks})",  # nosec B608
                                   [body.tag_id, *ids]).rowcount
    return {"updated": count}


@router.post("/articles/{article_id}/tags/{tag_id}", tags=["articles"])
def add_article_tag(article_id: int, tag_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT 1 FROM articles WHERE id = ?", (article_id,)).fetchone() is None:
            raise not_found("Article")
        if db.execute("SELECT 1 FROM tags WHERE id = ?", (tag_id,)).fetchone() is None:
            raise not_found("Collection")
        db.execute(
            "INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'manual', ?) "
            "ON CONFLICT(article_id, tag_id) DO UPDATE SET source = 'manual'",
            (article_id, tag_id, now()),
        )
        db.execute("DELETE FROM ttp_tag_removed WHERE article_id = ? AND tag_id = ?", (article_id, tag_id))
    return {"ok": True}


@router.delete("/articles/{article_id}/tags/{tag_id}", tags=["articles"])
def remove_article_tag(article_id: int, tag_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        gone = db.execute("DELETE FROM article_tags WHERE article_id = ? AND tag_id = ?", (article_id, tag_id)).rowcount
        if gone and db.execute("SELECT 1 FROM ttp_entity_tags WHERE tag_id = ? LIMIT 1", (tag_id,)).fetchone():
            # an ATT&CK / ATLAS tactic collection: remember it, or the technique filing would put the article back
            db.execute("INSERT OR IGNORE INTO ttp_tag_removed (article_id, tag_id) VALUES (?, ?)", (article_id, tag_id))
    return {"ok": True}


# ============================================================================ collections (tags)
class TagIn(StrictModel):
    name: Name
    color: Color = "#6b7280"


class TagPatch(StrictModel):
    name: Name | None = None
    color: Color | None = None


@router.get("/tags", tags=["collections"])
def list_tags(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT id, name, color FROM tags ORDER BY name COLLATE NOCASE")]


@router.post("/tags", status_code=201, tags=["collections"])
def create_tag(body: TagIn, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            cur = db.execute("INSERT INTO tags (name, color) VALUES (?, ?)", (body.name, body.color))
    except sqlite3.IntegrityError:
        raise conflict("A collection with that name already exists") from None
    return {"id": cur.lastrowid, "name": body.name, "color": body.color}


class TagColorsIn(StrictModel):
    ids: list[Annotated[int, Field(ge=1, le=2**31 - 1)]] = Field(min_length=1, max_length=500)
    color: Color


@router.post("/tags/colors", tags=["collections"])
def set_tag_colors(body: TagColorsIn, _: Principal = Depends(require_write)) -> dict:
    """Give several collections the same colour in one go (unknown ids are ignored)."""
    ids = list(dict.fromkeys(body.ids))
    with get_db() as db:
        updated = db.execute(f"UPDATE tags SET color = ? WHERE id IN ({placeholders(len(ids))})", [body.color, *ids]).rowcount  # nosec B608
    return {"updated": updated}


@router.patch("/tags/{tag_id}", tags=["collections"])
def update_tag(tag_id: int, body: TagPatch, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            if db.execute("SELECT 1 FROM tags WHERE id = ?", (tag_id,)).fetchone() is None:
                raise not_found("Collection")
            if body.name is not None:
                db.execute("UPDATE tags SET name = ? WHERE id = ?", (body.name, tag_id))
            if body.color is not None:
                db.execute("UPDATE tags SET color = ? WHERE id = ?", (body.color, tag_id))
            return dict(db.execute("SELECT id, name, color FROM tags WHERE id = ?", (tag_id,)).fetchone())
    except sqlite3.IntegrityError:
        raise conflict("A collection with that name already exists") from None


@router.delete("/tags/{tag_id}", tags=["collections"])
def delete_tag(tag_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM tags WHERE id = ?", (tag_id,)).rowcount == 0:
            raise not_found("Collection")
    return {"ok": True}
