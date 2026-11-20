"""🎙 Podcasts tab: follow shows by their open RSS feeds and listen to episodes in the app."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StringConstraints

import json
import threading

from app import app_settings, podcast_youtube, podcasts, related, sources
from app.api import content
from app.api.common import date_clause, StrictModel, TopicIds, not_found, topic_clause
from app.db import get_db, placeholders
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(prefix="/podcasts", tags=["podcasts"])

PODCAST_FOLDER = "Podcasts"
FeedIdList = Annotated[str, StringConstraints(pattern=r"^\d{1,9}(,\d{1,9}){0,199}$")]
EPISODE_COLUMNS = ("a.id, a.title, a.url, a.sort_ts AS published, a.is_read, a.is_starred, a.feed_id, f.title AS show, f.site_url AS show_site, "
                   "substr(a.text_content, 1, 600) AS summary, e.audio_url, e.audio_type, e.duration_s, e.image")
SORTS = {"newest": "a.sort_ts DESC, a.id DESC", "oldest": "a.sort_ts ASC, a.id ASC",
         "longest": "e.duration_s DESC, a.sort_ts DESC", "shortest": "COALESCE(e.duration_s, 1e9) ASC, a.sort_ts DESC"}
STATES = {"all": "", "unplayed": " AND a.is_read = 0", "played": " AND a.is_read = 1", "starred": " AND a.is_starred = 1"}


def _folder(db) -> int:
    db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES (?, 11)", (PODCAST_FOLDER,))
    return db.execute("SELECT id FROM folders WHERE name = ?", (PODCAST_FOLDER,)).fetchone()["id"]


@router.get("/search", dependencies=[Depends(rate_limit("podcast_search", 60))])
def search(q: Annotated[str, StringConstraints(min_length=2, max_length=200)], _: Principal = Depends(require_write)) -> dict:
    """Shows matching a name (Apple's public podcast directory)."""
    try:
        return {"results": podcasts.search(q)}
    except podcasts.PodcastError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None


class PodcastIn(StrictModel):
    input: Annotated[str, StringConstraints(min_length=2, max_length=2000)]   # feed, Apple / Spotify link, or name
    retention_days: int | None = Field(default=None, ge=0, le=36500)


@router.post("", status_code=201, dependencies=[Depends(rate_limit("podcast_add", 30))])
def add_podcast(body: PodcastIn, principal: Principal = Depends(require_write)) -> dict:
    try:
        show = podcasts.resolve(body.input)
    except podcasts.PodcastError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    with get_db() as db:
        existing = db.execute("SELECT id, kind FROM feeds WHERE url = ?", (show["feed_url"],)).fetchone()
        if existing is not None and existing["kind"] == "podcast":
            raise HTTPException(status_code=409, detail=f"“{show['title']}” is already in your podcasts")
        folder = _folder(db)
        if existing is not None:  # followed as an Articles feed: move it here (its episodes leave Articles)
            if existing["kind"] not in (None, "rss"):
                raise HTTPException(status_code=409, detail=f"“{show['title']}” is already followed as a {existing['kind']} feed")
            db.execute("UPDATE feeds SET kind = 'podcast', folder_id = ?, retention_days = COALESCE(?, retention_days), "
                       "etag = NULL, last_modified = NULL, next_fetch = 0 WHERE id = ?", (folder, body.retention_days, existing["id"]))
            # episodes the Articles retention removed may come back (ones you removed yourself stay removed)
            db.execute("DELETE FROM article_tombstones WHERE feed_id = ? AND manual = 0", (existing["id"],))
    if existing is not None:
        filled = podcasts.fill_episodes(existing["id"], show["feed_url"])
        audit("podcast_added", principal, feed_id=existing["id"], moved=True)
        return {"id": existing["id"], "title": show["title"], "author": show.get("author"), "artwork": show.get("artwork"),
                "feed_url": show["feed_url"], "moved": True, "episodes_filled": filled}
    feed = content.create_feed(content.FeedIn(url=show["feed_url"], title=show["title"], folder_id=folder,
                                              retention_days=body.retention_days if body.retention_days is not None else 0), principal)
    with get_db() as db:  # a podcast feed: kept out of Articles, its episodes' audio is stored on fetch
        db.execute("UPDATE feeds SET kind = 'podcast', next_fetch = 0 WHERE id = ?", (feed["id"],))
    audit("podcast_added", principal, feed_id=feed["id"])
    return {"id": feed["id"], "title": show["title"], "author": show.get("author"), "artwork": show.get("artwork"),
            "feed_url": show["feed_url"]}


@router.get("/meta")
def podcasts_meta(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        g_days = int(app_settings.get_all(db)["retention_days"] or 0)
        shows = [dict(r) for r in db.execute(
            "SELECT f.id AS feed_id, f.title, f.url, f.site_url, f.error_count, f.last_error, f.retention_days, "
            "(SELECT COUNT(*) FROM articles a WHERE a.feed_id = f.id) AS episodes, "
            "(SELECT COUNT(*) FROM articles a WHERE a.feed_id = f.id AND +a.is_read = 0) AS unplayed, "
            "(SELECT e.image FROM articles a JOIN episodes e ON e.article_id = a.id WHERE a.feed_id = f.id "
            " ORDER BY a.sort_ts DESC LIMIT 1) AS artwork "
            "FROM feeds f WHERE f.kind = 'podcast' ORDER BY f.title COLLATE NOCASE")]
        yt = {r["feed_id"]: dict(r) for r in db.execute("SELECT feed_id, sources, how FROM podcast_youtube")}
        linked = dict(db.execute("SELECT a.feed_id, COUNT(*) FROM episode_youtube y JOIN articles a ON a.id = y.article_id GROUP BY a.feed_id").fetchall())
    for s in shows:
        s["keeps"] = s["retention_days"] if s["retention_days"] is not None else g_days
        y = yt.get(s["feed_id"])
        srcs = json.loads(y["sources"]) if y else []
        s["youtube"] = {"how": y["how"] if y else None, "linked": linked.get(s["feed_id"], 0),
                        "sources": [{**x, "url": podcast_youtube.source_url(x)} for x in srcs]}
    return {"shows": shows}


@router.get("/episodes", dependencies=[Depends(rate_limit("podcast_read", 240))])
def episodes(feed_ids: FeedIdList | None = None, q: Annotated[str, StringConstraints(max_length=200)] = "",
             category: Annotated[str, StringConstraints(max_length=120)] | None = None,
             state: Literal["all", "unplayed", "played", "starred"] = "all", topic_ids: TopicIds | None = None,
             sort: Literal["newest", "oldest", "longest", "shortest"] = "newest",
             limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000),
             entity_id: int | None = Query(None, ge=1, le=2**31 - 1), days: int = 0,  # episodes that mention a watchlist entity
             related_to: int | None = Query(None, ge=1, le=2**31 - 1),               # episodes related to this article
             since: int | None = Query(None, ge=0, le=2**40), until: int | None = Query(None, ge=0, le=2**40),  # custom date range (unix seconds)
             _: Principal = Depends(require_read)) -> dict:
    if days not in (0, 7, 30, 90, 365):
        raise HTTPException(status_code=422, detail="days must be 0, 7, 30, 90 or 365")
    where, params = ["f.kind = 'podcast'"], []
    if feed_ids:
        ids = sorted({int(x) for x in feed_ids.split(",")})
        where.append(f"a.feed_id IN ({placeholders(len(ids))})")
        params += ids
    if q.strip():
        like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(a.title LIKE ? ESCAPE '\\' OR a.text_content LIKE ? ESCAPE '\\' OR f.title LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    if category:
        where.append("EXISTS (SELECT 1 FROM episode_categories c WHERE c.article_id = a.id AND c.category = ?)")
        params.append(category)
    base = (f"FROM articles a JOIN feeds f ON f.id = a.feed_id JOIN episodes e ON e.article_id = a.id "  # nosec B608 - fixed fragments
            f"WHERE {' AND '.join(where)}{STATES[state]}")
    extra, extra_params = topic_clause(topic_ids, "any")
    dates, date_params = date_clause(since, until)
    base, params = base + extra + dates, params + extra_params + date_params
    with get_db() as db:
        ment, ment_params = related.media_filter(db, entity_id, days, related_to, "podcasts")
        base, params = base + ment, params + ment_params
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608
        rows = [dict(r) for r in db.execute(f"SELECT {EPISODE_COLUMNS} {base} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",  # nosec B608
                                            [*params, limit, offset])]
        if rows:
            ids = [r["id"] for r in rows]
            tmap: dict[int, list[int]] = {}
            for t in db.execute(f"SELECT article_id, topic_id FROM article_topics WHERE article_id IN ({placeholders(len(ids))})", ids):  # nosec B608
                tmap.setdefault(t["article_id"], []).append(t["topic_id"])
            cmap: dict[int, list[str]] = {}
            for c in db.execute(f"SELECT article_id, category FROM episode_categories WHERE article_id IN ({placeholders(len(ids))}) ORDER BY category", ids):  # nosec B608
                cmap.setdefault(c["article_id"], []).append(c["category"])
            for r in rows:
                r["topics"], r["is_read"], r["is_starred"] = tmap.get(r["id"], []), bool(r["is_read"]), bool(r["is_starred"])
                r["categories"] = cmap.get(r["id"], [])
            _youtube_matches(db, rows, ids)
    return {"total": total, "items": rows}


def _norm_title(text: str | None) -> str:
    """Titles compared loosely: case, punctuation and an "Ep 12:" / "#593:" number prefix ignored."""
    t = re.sub(r"^\s*(?:ep(?:isode)?\.?\s*)?#?\d{1,5}\s*[:.\-–|]\s*", "", (text or "").lower())
    return " ".join(re.findall(r"[a-z0-9]+", t))


def _youtube_matches(db, rows: list[dict], ids: list[int]) -> None:
    """r["youtube_url"]: the episode's own video (matched from the show's YouTube channel / playlist); else
    r["youtube_search"]: a search inside the show's channel (or all of YouTube) for the episode title."""
    found = dict(db.execute(f"SELECT article_id, video_id FROM episode_youtube WHERE article_id IN ({placeholders(len(ids))})", ids).fetchall())  # nosec B608
    chan: dict[int, str] = {}
    for r in db.execute("SELECT feed_id, sources FROM podcast_youtube"):
        cid = next((s["id"] for s in json.loads(r["sources"] or "[]") if s.get("kind") == "channel"), None)
        if cid:
            chan[r["feed_id"]] = cid
    _library_matches(db, [r for r in rows if r["id"] not in found])
    for r in rows:
        vid = found.get(r["id"])
        r.setdefault("youtube_url", None)
        if vid and sources.VIDEO_ID.match(vid):
            r["youtube_url"] = f"https://www.youtube.com/watch?v={vid}"
        q = f"{r['show']} {r['title']}"[:200] if r["feed_id"] not in chan else (r["title"] or "")[:200]
        base = f"https://www.youtube.com/channel/{chan[r['feed_id']]}/search?query=" if r["feed_id"] in chan else "https://www.youtube.com/results?search_query="
        r["youtube_search"] = base + quote(q)


def _library_matches(db, rows: list[dict]) -> None:
    """r["youtube_url"]: the episode's own video when the show's YouTube channel is in Videos and a video's title
    matches the episode's (most shows post the same title on YouTube). None = no match (the page searches YouTube)."""
    by_show: dict[str, list[tuple[str, str]]] = {}
    for show in {r["show"] for r in rows}:
        name = _norm_title(show).removesuffix(" audio").removesuffix(" podcast").strip()
        if len(name) < 3:
            continue
        vids = db.execute("SELECT a.title, a.url FROM videos v JOIN articles a ON a.id = v.article_id "
                          "WHERE lower(v.channel_title) = ? OR lower(v.channel_title) = ? LIMIT 20000",
                          (name, (show or "").lower())).fetchall()
        by_show[show] = [(_norm_title(v["title"]), v["url"]) for v in vids if v["url"]]
    for r in rows:
        r["youtube_url"] = None
        core = _norm_title(r["title"])
        if len(core) < 12:
            continue
        for vt, url in by_show.get(r["show"], []):
            if vt == core or (len(vt) >= 12 and (core in vt or vt in core)):
                r["youtube_url"] = url
                break


class YouTubeIn(StrictModel):
    url: Annotated[str, StringConstraints(min_length=10, max_length=500)] | None = None   # None = no YouTube for this show


@router.put("/{feed_id}/youtube", dependencies=[Depends(rate_limit("podcast_youtube", 30))])
def set_youtube(feed_id: int, body: YouTubeIn, principal: Principal = Depends(require_write)) -> dict:
    """Set the show's YouTube channel / playlist by hand (a link), or say it has none; then match in the background."""
    _podcast_or_404(feed_id)
    if body.url and not podcast_youtube.host_ok(body.url if "://" in body.url else "https://" + body.url):
        raise HTTPException(status_code=422, detail="Paste a youtube.com channel or playlist link")
    try:
        found = podcast_youtube.set_manual(feed_id, body.url)
    except sources.SourceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    audit("podcast_youtube_set", principal, feed_id=feed_id, sources=len(found))
    if found:
        threading.Thread(target=_sync_quietly, args=(feed_id, False), name="podcast-youtube", daemon=True).start()
    return {"sources": [{**x, "url": podcast_youtube.source_url(x)} for x in found]}


@router.post("/{feed_id}/youtube/find", status_code=202, dependencies=[Depends(rate_limit("podcast_youtube", 30))])
def find_youtube(feed_id: int, principal: Principal = Depends(require_write)) -> dict:
    """Look for the show's YouTube channel again (automatically) and re-match its episodes - in the background."""
    _podcast_or_404(feed_id)
    if not sources.yt_key():
        raise HTTPException(status_code=409, detail="Add a YouTube API key in Settings → Integrations first")
    audit("podcast_youtube_find", principal, feed_id=feed_id)
    threading.Thread(target=_sync_quietly, args=(feed_id, True), name="podcast-youtube", daemon=True).start()
    return {"started": True}


def _sync_quietly(feed_id: int, force: bool) -> None:
    try:
        podcast_youtube.sync(feed_id, force_detect=force)
    except Exception:  # quota / network: shown as "not found yet"; the daily run tries again
        import logging
        logging.getLogger(__name__).warning("YouTube links for show %d failed", feed_id, exc_info=True)


def _podcast_or_404(feed_id: int) -> None:
    with get_db() as db:
        if db.execute("SELECT 1 FROM feeds WHERE id = ? AND kind = 'podcast'", (feed_id,)).fetchone() is None:
            raise not_found("Podcast")


@router.get("/categories")
def categories(feed_ids: FeedIdList | None = None, _: Principal = Depends(require_read)) -> dict:
    """The shows' own categories (with episode counts) for the chosen shows - for the Categories filter."""
    where, params = ["f.kind = 'podcast'"], []
    if feed_ids:
        ids = sorted({int(x) for x in feed_ids.split(",")})
        where.append(f"a.feed_id IN ({placeholders(len(ids))})")
        params += ids
    with get_db() as db:
        rows = db.execute(f"SELECT c.category, COUNT(*) AS n FROM episode_categories c JOIN articles a ON a.id = c.article_id "  # nosec B608
                          f"JOIN feeds f ON f.id = a.feed_id WHERE {' AND '.join(where)} GROUP BY c.category ORDER BY c.category", params).fetchall()
    return {"categories": [{"name": r["category"], "episodes": r["n"]} for r in rows]}


@router.delete("/{feed_id}")
def remove_podcast(feed_id: int, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT 1 FROM feeds WHERE id = ? AND kind = 'podcast'", (feed_id,)).fetchone() is None:
            raise not_found("Podcast")
    return content.delete_feed(feed_id, principal)
