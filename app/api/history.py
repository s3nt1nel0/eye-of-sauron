"""Feed details (for the in-place feed editor), per-feed retention and history back-fill."""

from __future__ import annotations

import json
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import Field

from app import app_settings, history
from app.api.common import StrictModel, conflict, not_found
from app.db import get_db
from app.fetcher import effective_retention
from app.security import Principal, audit, rate_limit, require_admin, require_read, require_write

router = APIRouter(tags=["history"])


@router.get("/feeds/{feed_id}/details", tags=["feeds"])
def feed_details(feed_id: int, _: Principal = Depends(require_read)) -> dict:
    """Everything that applies to one feed: settings, effective values, health, stats and rules."""
    with get_db() as db:
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        if feed is None:
            raise not_found("Feed")
        prefs = app_settings.get_all(db)
        stats = db.execute(
            "SELECT COUNT(*) AS total, COALESCE(SUM(1 - is_read), 0) AS unread, COALESCE(SUM(is_starred), 0) AS starred, "
            "MIN(sort_ts) AS oldest, MAX(sort_ts) AS newest, "
            "COALESCE(SUM(CASE WHEN sort_ts >= strftime('%s','now') - 30 * 86400 THEN 1 ELSE 0 END), 0) AS last_30d "
            "FROM articles WHERE feed_id = ?", (feed_id,)).fetchone()
        rules = [dict(r) for r in db.execute(
            "SELECT r.id, r.name, r.enabled, r.feed_id, r.folder_id, r.keywords, t.name AS collection, "
            "r.star, r.mark_read, r.webhook_id IS NOT NULL AS webhook "
            "FROM rules r LEFT JOIN tags t ON t.id = r.tag_id "
            "WHERE r.feed_id = ? OR (r.feed_id IS NULL AND (r.folder_id IS NULL OR r.folder_id = ?)) "
            "ORDER BY r.position, r.id", (feed_id, feed["folder_id"]))]
        folder = db.execute("SELECT name FROM folders WHERE id = ?", (feed["folder_id"],)).fetchone() if feed["folder_id"] else None
    for r in rules:
        r["keywords"] = json.loads(r["keywords"])[:8]
        r["scope"] = "this feed" if r["feed_id"] else ("this folder" if r["folder_id"] else "all feeds")
        for k in ("enabled", "star", "mark_read", "webhook"):
            r[k] = bool(r[k])
    days, cap = effective_retention(feed, prefs)
    out = {k: feed[k] for k in ("id", "title", "custom_title", "url", "site_url", "folder_id", "refresh_minutes",
                                "retention_days", "max_articles", "enabled", "last_fetched", "next_fetch",
                                "error_count", "last_error", "created_at", "kind", "adaptive_minutes")}
    out["full_text"] = feed["full_text"] or "auto"
    out["translate_titles"] = bool(feed["translate_titles"])
    out["social_platform"] = feed["social_platform"]
    out["scrape"] = json.loads(feed["scrape"]) if feed["scrape"] else None
    out["source"] = json.loads(feed["source"]) if feed["source"] else None
    out.update(
        enabled=bool(feed["enabled"]), custom_title=bool(feed["custom_title"]),
        folder_name=folder["name"] if folder else None,
        effective={"refresh_minutes": feed["refresh_minutes"] or (feed["adaptive_minutes"] if prefs["adaptive_refresh"] and feed["adaptive_minutes"] else prefs["default_refresh_minutes"]),
                   "adaptive": not feed["refresh_minutes"] and bool(prefs["adaptive_refresh"]),
                   "retention_days": days, "max_articles": cap},
        stats=dict(stats), rules=rules,
        backfill=history.backfill_job.status if history.backfill_job.status.get("feed_id") == feed_id else None,
    )
    return out


class RetentionIn(StrictModel):
    retention_days: int | None = Field(default=None, ge=0, le=36500)  # None = global, 0 = forever
    max_articles: int | None = Field(default=None, ge=0, le=1_000_000)  # None = global, 0 = unlimited


@router.put("/feeds/{feed_id}/retention", tags=["feeds"])
def set_retention(feed_id: int, body: RetentionIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        # Clearing the conditional-GET validators makes the next fetch re-read the whole feed, so items that were
        # skipped under a shorter retention window are picked up after switching to a longer one / keep forever.
        cur = db.execute("UPDATE feeds SET retention_days = ?, max_articles = ?, etag = NULL, last_modified = NULL, "
                         "next_fetch = NULL WHERE id = ?", (body.retention_days, body.max_articles, feed_id))
        if cur.rowcount == 0:
            raise not_found("Feed")
    return {"ok": True, "retention_days": body.retention_days, "max_articles": body.max_articles}


Method = Literal["auto", "paged", "wayback"]


class BackfillIn(StrictModel):
    max_pages: int = Field(default=20, ge=1, le=history.MAX_BACKFILL_PAGES)
    method: Method = "auto"                  # auto = the site's own older pages, else the Internet Archive
    since_days: int | None = Field(default=None, ge=1, le=36500)   # how far back; None = as far as possible
    keep_forever: bool = False               # set the feed to keep forever so retention doesn't drop what we fetch
    whole_playlists: bool = False            # YouTube playlists among the feeds are loaded whole (no time frame)
    # One setting for history: the feed keeps this many days AND older items are fetched back to it (0 = everything).
    # Replaces since_days + keep_forever (still accepted from older clients).
    keep_days: int | None = Field(default=None, ge=0, le=36500)


@router.post("/feeds/{feed_id}/backfill", tags=["feeds"], dependencies=[Depends(rate_limit("backfill", 6))])
def backfill(feed_id: int, body: BackfillIn, principal: Principal = Depends(require_write)) -> dict:
    audit("backfill_requested", principal, feed_id=feed_id, max_pages=body.max_pages, method=body.method, keep_days=body.keep_days)
    with get_db() as db:
        if db.execute("SELECT 1 FROM feeds WHERE id = ?", (feed_id,)).fetchone() is None:
            raise not_found("Feed")
    if not history.backfill_job.start(history.backfill_feed, feed_id, body.model_dump()):
        raise conflict("Another history back-fill is running - wait for it to finish")
    return {"started": True}


class BulkBackfillIn(BackfillIn):
    max_pages: int = Field(default=30, ge=1, le=history.MAX_BACKFILL_PAGES)   # per feed
    folder_id: int | None = Field(default=None, ge=1, le=2**31)               # None = all feeds
    only_missing: bool = True                # skip feeds whose history already reaches back that far
    keep_forever: bool = True
    feed_ids: list[Annotated[int, Field(ge=1)]] | None = Field(default=None, max_length=5000)  # only these feeds


@router.post("/history/backfill-all", dependencies=[Depends(rate_limit("backfill_all", 2))])
def backfill_all(body: BulkBackfillIn, principal: Principal = Depends(require_admin)) -> dict:
    """Fetch older articles for every feed (or one folder), one feed after another, in the background."""
    if body.folder_id is not None:
        with get_db() as db:
            if db.execute("SELECT 1 FROM folders WHERE id = ?", (body.folder_id,)).fetchone() is None:
                raise not_found("Folder")
    ids = history.bulk_feed_ids(body.folder_id, body.only_missing, body.since_days, body.keep_days)
    if body.feed_ids is not None:  # e.g. the channels just added together in the Library
        wanted = set(body.feed_ids)
        ids = [i for i in ids if i in wanted]
    audit("backfill_all_requested", principal, feeds=len(ids), method=body.method, since_days=body.since_days)
    if not ids:
        return {"started": False, "feeds": 0}
    opts = body.model_dump(exclude={"folder_id", "only_missing", "feed_ids"})
    if not history.backfill_job.start(history.backfill_many, ids, opts):
        raise conflict("Another history back-fill is running - wait for it to finish")
    return {"started": True, "feeds": len(ids)}


@router.get("/history/status")
def status(_: Principal = Depends(require_read)) -> dict:
    return {"backfill": history.backfill_job.status}


@router.post("/history/cancel")
def cancel(_: Principal = Depends(require_write)) -> dict:
    history.backfill_job.stop.set()
    return {"ok": True}
