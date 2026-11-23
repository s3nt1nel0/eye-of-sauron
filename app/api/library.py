"""YouTube video library and keyword topics."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StrictBool, StringConstraints, model_validator

from app import app_settings, sources, topics
from app.api.common import date_clause, Color, StrictModel, TopicIds, conflict, not_found, topic_clause
from app import related
from app.db import get_db, now, placeholders
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(tags=["library"])

SORTS = {
    "added": "a.fetched_at DESC, a.sort_ts DESC, a.id DESC",   # recently added first (a playlist you just added)
    "added_oldest": "a.fetched_at ASC, a.sort_ts ASC, a.id ASC",
    "newest": "a.sort_ts DESC, a.id DESC",
    "oldest": "a.sort_ts ASC, a.id ASC",
    "views": "COALESCE(v.views, -1) DESC, a.sort_ts DESC",
    "longest": "COALESCE(v.duration_s, -1) DESC, a.sort_ts DESC",
    "shortest": "COALESCE(v.duration_s, 1000000000) ASC, a.sort_ts DESC",
}
LENGTHS = {  # fixed SQL fragments selected by an enum, never user text
    "any": "",
    "short": "AND v.duration_s IS NOT NULL AND v.duration_s <= 180",
    "medium": "AND v.duration_s > 180 AND v.duration_s <= 1200",
    "long": "AND v.duration_s > 1200",
}
STATES = {"all": "", "unwatched": "AND a.is_read = 0", "watched": "AND a.is_read = 1", "starred": "AND a.is_starred = 1"}
VIDEO_COLUMNS = ("a.id, a.title, a.url, a.sort_ts AS published, a.is_read, a.is_starred, a.feed_id, f.title AS feed_title, "
                 "v.video_id, v.channel_id, v.channel_title, v.thumbnail, v.duration_s, v.views")


def _video_filters(feed_id: int | None, topic_id: int | None, q: str | None, length: str, state: str) -> tuple[str, list]:
    """FROM/WHERE for the library queries. Only fixed fragments chosen by enums are interpolated; values are bound."""
    where = ["1"]
    params: list = []
    if feed_id is not None:  # the feed's own videos and those it shares with another playlist / channel
        where.append("(a.feed_id = ? OR a.id IN (SELECT article_id FROM video_links WHERE feed_id = ?))")
        params += [feed_id, feed_id]
    if topic_id is not None:
        where.append("EXISTS (SELECT 1 FROM article_topics t WHERE t.article_id = a.id AND t.topic_id = ?)")
        params.append(topic_id)
    if q:
        # Every word must appear in the title, the channel name or the description (case-insensitive). Spaces in the
        # title are also ignored for the match, so "homelab" finds "Home Lab" and "home lab" finds "Homelab".
        for word in q.split()[:8]:
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(a.title LIKE ? ESCAPE '\\' OR v.channel_title LIKE ? ESCAPE '\\' "
                         "OR a.text_content LIKE ? ESCAPE '\\' OR REPLACE(a.title, ' ', '') LIKE ? ESCAPE '\\')")
            params += [like, like, like, like]
    base = (f"FROM videos v JOIN articles a ON a.id = v.article_id JOIN feeds f ON f.id = a.feed_id "
            f"WHERE {' AND '.join(where)} {LENGTHS[length]} {STATES[state]}")  # nosec B608 - fixed fragments, values bound
    return base, params


def _check_days(days: int) -> None:
    if days not in (0, 7, 30, 90, 365):
        raise HTTPException(status_code=422, detail="days must be 0, 7, 30, 90 or 365")


ChannelKeys = Annotated[str, StringConstraints(  # up to 200: a channel group can hold many channels
    max_length=6000, pattern=r"^(UC[A-Za-z0-9_-]{22}|feed:\d{1,9})(,(UC[A-Za-z0-9_-]{22}|feed:\d{1,9})){0,199}$")]
ChannelKey = Annotated[str, StringConstraints(pattern=r"^(UC[A-Za-z0-9_-]{22}|feed:\d{1,9})$")]


def _channel_clause(keys_csv: str | None) -> tuple[str, list]:
    """Videos from any of these YouTube channels, wherever they came from (the channel's feed, its playlists,
    single saved videos). "feed:<id>" stands for videos without a known channel in that feed."""
    if not keys_csv:
        return "", []
    keys = list(dict.fromkeys(keys_csv.split(",")))
    ids = [k for k in keys if k.startswith("UC")]
    feeds = [int(k[5:]) for k in keys if k.startswith("feed:")]
    parts, params = [], []
    if ids:
        parts.append(f"v.channel_id IN ({placeholders(len(ids))})")
        params += ids
        # Single videos saved without an API key have no channel id, only the channel's name: match those by name.
        with get_db() as db:
            names = [r[0] for r in db.execute(
                f"SELECT DISTINCT channel_title FROM videos WHERE channel_id IN ({placeholders(len(ids))}) "
                "AND channel_title IS NOT NULL", ids)]
        if names:
            parts.append(f"(v.channel_id IS NULL AND v.channel_title IN ({placeholders(len(names))}))")
            params += names
    if feeds:
        parts.append(f"(v.channel_id IS NULL AND a.feed_id IN ({placeholders(len(feeds))}))")
        params += feeds
    return " AND (" + " OR ".join(parts) + ")", params


def _playlist_feeds(db) -> dict[int, str]:
    """feed id -> title for YouTube feeds that are playlists (each one is a group automatically)."""
    out = {}
    for r in db.execute("SELECT id, title, source FROM feeds WHERE kind = 'youtube' AND source LIKE '%playlist_id%'"):
        try:
            if json.loads(r["source"] or "{}").get("playlist_id"):
                out[r["id"]] = r["title"]
        except ValueError:
            continue
    return out


def _attach_groups(db, rows: list[dict]) -> None:
    """r["groups"] = [{"id": "p:12" | "g:3", "name"}] - the playlist it came from and the groups you put it in."""
    if not rows:
        return
    playlists = _playlist_feeds(db)
    ids = [r["id"] for r in rows]
    linked: dict[int, list[int]] = {}  # other playlists the same video is in (one copy, several playlists)
    for lk in db.execute(f"SELECT article_id, feed_id FROM video_links WHERE article_id IN ({placeholders(len(ids))}) "
                         "ORDER BY feed_id", ids):
        if lk["feed_id"] in playlists:
            linked.setdefault(lk["article_id"], []).append(lk["feed_id"])
    custom: dict[int, list[dict]] = {}
    for g in db.execute(f"SELECT i.article_id, g.id, g.name FROM video_group_items i JOIN video_groups g ON g.id = i.group_id "
                        f"WHERE i.article_id IN ({placeholders(len(ids))}) ORDER BY g.name COLLATE NOCASE", ids):
        custom.setdefault(g["article_id"], []).append({"id": f"g:{g['id']}", "name": g["name"]})
    for r in rows:
        fids = list(dict.fromkeys(([r["feed_id"]] if r.get("feed_id") in playlists else []) + linked.get(r["id"], [])))
        r["groups"] = [{"id": f"p:{fid}", "name": playlists[fid]} for fid in fids] + custom.get(r["id"], [])


def _attach_topics(db, rows: list[dict]) -> None:
    _attach_groups(db, rows)
    if not rows:
        return
    ids = [r["id"] for r in rows]
    tmap: dict[int, list[int]] = {}
    for t in db.execute(f"SELECT article_id, topic_id FROM article_topics WHERE article_id IN ({placeholders(len(ids))})", ids):
        tmap.setdefault(t["article_id"], []).append(t["topic_id"])
    for r in rows:
        r["topics"] = tmap.get(r["id"], [])
        r["is_read"], r["is_starred"] = bool(r["is_read"]), bool(r["is_starred"])


@router.get("/library/videos", dependencies=[Depends(rate_limit("library", 240))])
def videos(
    feed_id: int | None = None,
    topic_id: int | None = None,
    channels: ChannelKeys | None = None,               # several YouTube channels: "UC...,UC..." (feed:<id> = no channel id)
    topic_ids: TopicIds | None = None,                 # several topics: "3,7,12" (0 = no topic)
    topic_match: Literal["any", "all"] = "any",        # any of them, or all of them
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: Literal["added", "added_oldest", "newest", "oldest", "views", "longest", "shortest"] = "newest",
    length: Literal["any", "short", "medium", "long"] = "any",
    state: Literal["all", "unwatched", "watched", "starred"] = "all",
    limit: int = Query(60, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    entity_id: int | None = Query(None, ge=1, le=2**31 - 1),   # only items that mention this watchlist entity…
    days: int = 0,                                              # …in the last n days (0 = any time)
    related_to: int | None = Query(None, ge=1, le=2**31 - 1),  # only items related to this article (see app/related.py)
    since: int | None = Query(None, ge=0, le=2**40),                  # custom date range: published at or after…
    until: int | None = Query(None, ge=0, le=2**40),                  # …and before (unix seconds)
    _: Principal = Depends(require_read),
) -> dict:
    base, params = _video_filters(feed_id, topic_id, q, length, state)
    dates, date_params = date_clause(since, until)
    base, params = base + dates, params + date_params
    extra, extra_params = topic_clause(topic_ids, topic_match)
    chan, chan_params = _channel_clause(channels)
    _check_days(days)
    base, params = base + extra + chan, params + extra_params + chan_params
    with get_db() as db:
        ment, ment_params = related.media_filter(db, entity_id, days, related_to, "videos")
        base, params = base + ment, params + ment_params
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608
        rows = [dict(r) for r in db.execute(
            f"SELECT {VIDEO_COLUMNS} {base} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?", [*params, limit, offset])]  # nosec B608
        _attach_topics(db, rows)
    return {"total": total, "items": rows}


@router.get("/library/shelves", dependencies=[Depends(rate_limit("library", 240))])
def shelves(
    feed_id: int | None = None,
    channels: ChannelKeys | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: Literal["added", "added_oldest", "newest", "oldest", "views", "longest", "shortest"] = "newest",
    length: Literal["any", "short", "medium", "long"] = "any",
    state: Literal["all", "unwatched", "watched", "starred"] = "all",
    per: int = Query(12, ge=1, le=48),
    since: int | None = Query(None, ge=0, le=2**40),
    until: int | None = Query(None, ge=0, le=2**40),
    _: Principal = Depends(require_read),
) -> dict:
    """Videos split into categories by topic: one shelf per topic (a video with several topics is on each of
    their shelves), plus "Other" for videos no enabled topic matched. Same filters as /library/videos."""
    base, params = _video_filters(feed_id, None, q, length, state)
    dates, date_params = date_clause(since, until)
    base, params = base + dates, params + date_params
    chan, chan_params = _channel_clause(channels)
    base, params = base + chan, params + chan_params
    no_topic = (" AND NOT EXISTS (SELECT 1 FROM article_topics x JOIN topics xt ON xt.id = x.topic_id "
                "WHERE x.article_id = a.id AND xt.enabled = 1)")
    out: list[dict] = []
    with get_db() as db:
        names = {t["id"]: t for t in db.execute("SELECT id, name, color FROM topics WHERE enabled = 1")}
        # one pass for every shelf: the same filtered videos joined to their topics, counted and ranked per topic
        joined = base.replace("FROM videos v ", "FROM article_topics x JOIN videos v ON v.article_id = x.article_id ", 1)
        joined += " AND x.topic_id IN (SELECT id FROM topics WHERE enabled = 1)"
        # Rank only (topic, id) pairs: sorting whole rows (titles, URLs, thumbnails) of a big library needs tens of MB
        # of SQLite temp space, more than a read-only container's small /tmp has ("database or disk is full").
        picks = db.execute(
            "SELECT shelf_topic, id, shelf_total FROM (SELECT x.topic_id AS shelf_topic, a.id AS id, "  # nosec B608 - fixed fragments, values bound
            "COUNT(*) OVER (PARTITION BY x.topic_id) AS shelf_total, "
            f"ROW_NUMBER() OVER (PARTITION BY x.topic_id ORDER BY {SORTS[sort]}) AS shelf_rank {joined}) "
            "WHERE shelf_rank <= ? ORDER BY shelf_topic, shelf_rank", [*params, per]).fetchall()
        rows_by_id: dict[int, dict] = {}
        wanted = sorted({p["id"] for p in picks})
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            for r in db.execute(
                    f"SELECT {VIDEO_COLUMNS} FROM videos v JOIN articles a ON a.id = v.article_id "  # nosec B608 - fixed columns
                    f"JOIN feeds f ON f.id = a.feed_id WHERE a.id IN ({placeholders(len(chunk))})", chunk):
                rows_by_id[r["id"]] = dict(r)
        _attach_topics(db, list(rows_by_id.values()))
        totals: dict[int, int] = {}
        by_topic: dict[int, list[dict]] = {}
        for p in picks:
            tid = p["shelf_topic"]
            totals[tid] = p["shelf_total"]
            if p["id"] in rows_by_id:
                by_topic.setdefault(tid, []).append(dict(rows_by_id[p["id"]]))
        for tid, total in totals.items():
            if tid in names and total:
                t = names[tid]
                out.append({"id": tid, "name": t["name"], "color": t["color"], "total": total, "items": by_topic.get(tid, [])})
        other_total = db.execute(f"SELECT COUNT(*) {base}{no_topic}", params).fetchone()[0]  # nosec B608
        other = [dict(r) for r in db.execute(
            f"SELECT {VIDEO_COLUMNS} {base}{no_topic} ORDER BY {SORTS[sort]} LIMIT ?", [*params, per])]  # nosec B608
        _attach_topics(db, other)
    out.sort(key=lambda s: -s["total"])
    return {"shelves": out, "other": {"total": other_total, "items": other}}


class AddVideoIn(StrictModel):
    url: Annotated[str, StringConstraints(min_length=5, max_length=500)]


@router.post("/library/videos", status_code=201, dependencies=[Depends(rate_limit("library_add", 30))])
def add_video(body: AddVideoIn, principal: Principal = Depends(require_write)) -> dict:
    """Add one video (not its whole channel) to the library, in the "Saved YouTube videos" feed."""
    video_id = sources.parse_video_id(body.url)
    if not video_id:
        raise HTTPException(status_code=422, detail="Not a YouTube video link (watch?v=…, youtu.be/…, /shorts/…)")
    with get_db() as db:
        row = db.execute("SELECT a.id, a.title FROM videos v JOIN articles a ON a.id = v.article_id WHERE v.video_id = ? LIMIT 1",
                         (video_id,)).fetchone()
    if row is not None:
        return {"article_id": row["id"], "title": row["title"], "already": True}
    try:
        entry, meta = sources.single_video(video_id)
    except sources.SourceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)[:300]) from None
    from app.fetcher import store_entries
    from app.history import _post_process

    with get_db() as db:
        feed = db.execute("SELECT id FROM feeds WHERE url = ?", (sources.SAVED_VIDEOS_URL,)).fetchone()
        if feed is None:
            feed_id = int(db.execute(
                "INSERT INTO feeds (title, custom_title, url, refresh_minutes, created_at, kind, source, retention_days, max_articles) "
                "VALUES ('Saved YouTube videos', 0, ?, 10080, ?, 'youtube', ?, 0, 0)",
                (sources.SAVED_VIDEOS_URL, now(), json.dumps({"kind": "youtube", "saved": True}))).lastrowid)
        else:
            feed_id = int(feed["id"])
        new_ids = store_entries(db, feed_id, [entry], None, now(), video_of=lambda _e: meta,
                                on_new=lambda d, _e, article_id, published: sources.store_video(d, article_id, meta, published))
        if not new_ids:  # added meanwhile from a playlist / channel refresh: that copy is the one
            row = db.execute("SELECT a.id, a.title FROM videos v JOIN articles a ON a.id = v.article_id WHERE v.video_id = ?",
                             (video_id,)).fetchone()
            if row is not None:
                return {"article_id": row["id"], "title": row["title"], "already": True}
        _post_process(db, new_ids)
    audit("library_video_added", principal, video_id=video_id)
    if not new_ids:
        raise HTTPException(status_code=409, detail="That video was removed earlier and is remembered as deleted")
    return {"article_id": new_ids[0], "title": entry["title"], "already": False, "feed_id": feed_id}


@router.get("/library/topic-counts", dependencies=[Depends(rate_limit("library", 240))])
def topic_counts(
    feed_id: int | None = None,
    channels: ChannelKeys | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    length: Literal["any", "short", "medium", "long"] = "any",
    state: Literal["all", "unwatched", "watched", "starred"] = "all",
    entity_id: int | None = Query(None, ge=1, le=2**31 - 1),   # only items that mention this watchlist entity…
    days: int = 0,                                              # …in the last n days (0 = any time)
    related_to: int | None = Query(None, ge=1, le=2**31 - 1),  # only items related to this article (see app/related.py)
    since: int | None = Query(None, ge=0, le=2**40),                  # custom date range: published at or after…
    until: int | None = Query(None, ge=0, le=2**40),                  # …and before (unix seconds)
    _: Principal = Depends(require_read),
) -> dict:
    """Videos per topic under the current channel / length / watched / search filters, so the numbers next to
    the topic names match what clicking a topic shows."""
    base, params = _video_filters(feed_id, None, q, length, state)
    dates, date_params = date_clause(since, until)
    base, params = base + dates, params + date_params
    chan, chan_params = _channel_clause(channels)
    _check_days(days)
    base, params = base + chan, params + chan_params
    with get_db() as db:
        ment, ment_params = related.media_filter(db, entity_id, days, related_to, "videos")
        base, params = base + ment, params + ment_params
        counts = {str(r[0]): r[1] for r in db.execute(
            f"SELECT t.topic_id, COUNT(*) FROM article_topics t WHERE t.article_id IN (SELECT a.id {base}) "  # nosec B608
            "GROUP BY t.topic_id", params)}
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608 - fixed fragments, values bound
    return {"counts": counts, "total": total}


@router.get("/library/meta")
def library_meta(_: Principal = Depends(require_read)) -> dict:
    """Channels for the Videos filter: one entry per YouTube channel (not per feed), so a channel's playlists and
    single saved videos are included when you pick it. Each entry lists the feeds its videos came from."""
    with get_db() as db:
        feeds = {r["id"]: dict(r) for r in db.execute(
            "SELECT id, title, url, source, retention_days FROM feeds WHERE kind = 'youtube'")}
        global_days = int(app_settings.get_all(db)["retention_days"] or 0)
        rows = db.execute(
            "SELECT a.feed_id, COALESCE(v.channel_id, 'feed:' || a.feed_id) AS ckey, "
            "MAX(v.channel_title) AS ctitle, COUNT(*) AS videos, COALESCE(SUM(1 - a.is_read), 0) AS unwatched "
            "FROM videos v JOIN articles a ON a.id = v.article_id JOIN feeds f ON f.id = a.feed_id "
            "WHERE f.kind = 'youtube' GROUP BY a.feed_id, ckey").fetchall()
        # videos a feed lists but that are stored once under another feed (counted in that feed's list, not twice
        # in the channel's total)
        linked_rows = db.execute(
            "SELECT l.feed_id, COUNT(*) AS videos FROM video_links l JOIN articles a ON a.id = l.article_id "
            "JOIN feeds f ON f.id = l.feed_id WHERE l.feed_id != a.feed_id AND f.kind = 'youtube' GROUP BY l.feed_id").fetchall()
        tops = [dict(r) for r in db.execute(
            "SELECT t.id, t.name, t.color, t.enabled, (SELECT COUNT(*) FROM article_topics x JOIN videos v ON v.article_id = x.article_id "
            "WHERE x.topic_id = t.id) AS videos FROM topics t ORDER BY t.name COLLATE NOCASE")]

    def kind_of(feed: dict) -> tuple[str, str | None]:
        if feed["url"] == sources.SAVED_VIDEOS_URL:
            return "saved", None
        try:
            cfg = json.loads(feed["source"] or "{}")
        except ValueError:
            cfg = {}
        return ("playlist", None) if cfg.get("playlist_id") else ("channel", cfg.get("channel_id"))

    def keeps(feed: dict) -> int:  # the retention in force: the feed's own, else the global setting
        return feed["retention_days"] if feed["retention_days"] is not None else global_days

    channels: dict[str, dict] = {}
    playlist_ids: dict[int, str] = {}
    for fid, feed in feeds.items():
        try:
            pid = json.loads(feed["source"] or "{}").get("playlist_id")
        except ValueError:
            pid = None
        if isinstance(pid, str):
            playlist_ids[fid] = pid

    def entry(key: str, title: str) -> dict:
        return channels.setdefault(key, {"key": key, "title": title, "videos": 0, "unwatched": 0, "feeds": [],
                                         "feed_id": None, "saved": False, "retention_days": None})

    for fid, feed in feeds.items():  # channel feeds first: they name the channel (also when they have no videos yet)
        kind, cid = kind_of(feed)
        if kind == "channel" and cid:
            c = entry(cid, feed["title"])
            c["feed_id"] = fid
            c["retention_days"] = keeps(feed)
    by_title = {}
    for r in rows:
        if not r["ckey"].startswith("feed:") and r["ctitle"]:
            by_title.setdefault(r["ctitle"].lower(), r["ckey"])
    for r in rows:
        feed = feeds[r["feed_id"]]
        kind, _cid = kind_of(feed)
        key = r["ckey"]
        if key.startswith("feed:") and r["ctitle"] and r["ctitle"].lower() in by_title:
            key = by_title[r["ctitle"].lower()]  # a saved single video of a channel we know: same entry
        c = entry(key, r["ctitle"] or feed["title"])
        if r["ctitle"] and c["title"].startswith(("http://", "https://")):
            c["title"] = r["ctitle"]  # the feed never got a name (added while YouTube's feed was down)
        c["videos"] += r["videos"]
        c["unwatched"] += r["unwatched"]
        c["feeds"].append({"id": r["feed_id"], "title": feed["title"], "type": kind, "videos": r["videos"], "retention_days": keeps(feed)})
    for r in linked_rows:
        listed = [f for c in channels.values() for f in c["feeds"] if f["id"] == r["feed_id"]]
        if listed:
            listed[0]["videos"] += r["videos"]
        elif r["feed_id"] in feeds:  # every video of this playlist is stored under the channel: list it with its count
            feed = feeds[r["feed_id"]]
            kind, cid = kind_of(feed)
            c = entry(cid or f"feed:{r['feed_id']}", feed["title"])
            c["feeds"].append({"id": r["feed_id"], "title": feed["title"], "type": kind, "videos": r["videos"], "retention_days": keeps(feed)})
    for fid, feed in feeds.items():  # feeds with no videos yet (just added playlists) still show up
        if not any(f["id"] == fid for c in channels.values() for f in c["feeds"]):
            kind, cid = kind_of(feed)
            c = entry(cid or f"feed:{fid}", feed["title"])
            c["feeds"].append({"id": fid, "title": feed["title"], "type": kind, "videos": 0, "retention_days": keeps(feed)})
    for c in channels.values():
        for f in c["feeds"]:  # so the page can tell which of a channel's playlists are already followed
            f["playlist_id"] = playlist_ids.get(f["id"])
        c["saved"] = bool(c["feeds"]) and all(f["type"] == "saved" for f in c["feeds"])
        c["feeds"].sort(key=lambda f: ({"channel": 0, "playlist": 1, "saved": 2}[f["type"]], f["title"].lower()))
    out = sorted(channels.values(), key=lambda c: c["title"].lower())
    with get_db() as db:
        favs = {r[0] for r in db.execute("SELECT channel_key FROM favorite_channels")}
        for c in out:
            c["favorite"] = c["key"] in favs
        groups = [{"id": g["id"], "name": g["name"],
                   "channels": [r[0] for r in db.execute("SELECT channel_key FROM channel_group_members WHERE group_id = ? ORDER BY channel_key", (g["id"],))]}
                  for g in db.execute("SELECT id, name FROM channel_groups ORDER BY name COLLATE NOCASE")]
        fav_topics = {r[0] for r in db.execute("SELECT topic_id FROM favorite_topics")}
    for t in tops:
        t["favorite"] = t["id"] in fav_topics
    return {"channels": out, "topics": tops, "reclassifying": topics.reclassifier.running, "channel_groups": groups}


# ============================================================================ favourite channels
class FavoriteChannelsIn(StrictModel):
    channels: list[ChannelKey] = Field(min_length=1, max_length=500)
    favorite: StrictBool = True   # "yes" / 1 refused: only true or false


@router.post("/library/favorite-channels", dependencies=[Depends(rate_limit("library_favorites", 120))])
def set_favorite_channels(body: FavoriteChannelsIn, _: Principal = Depends(require_write)) -> dict:
    """★ / ☆ one or many channels at once. Returns every favourite channel key."""
    keys = list(dict.fromkeys(body.channels))
    with get_db() as db:
        if body.favorite:
            db.executemany("INSERT OR IGNORE INTO favorite_channels (channel_key, created_at) VALUES (?, ?)", [(k, now()) for k in keys])
        else:
            db.executemany("DELETE FROM favorite_channels WHERE channel_key = ?", [(k,) for k in keys])
        favs = [r[0] for r in db.execute("SELECT channel_key FROM favorite_channels ORDER BY channel_key")]
    return {"favorites": favs}


class FavoriteTopicsIn(StrictModel):
    topic_ids: list[Annotated[int, Field(ge=1, le=10**9)]] = Field(min_length=1, max_length=200)
    favorite: StrictBool = True


@router.post("/library/favorite-topics", dependencies=[Depends(rate_limit("library_favorites", 120))])
def set_favorite_topics(body: FavoriteTopicsIn, _: Principal = Depends(require_write)) -> dict:
    """★ / ☆ one or many topics at once (unknown ids are ignored). Returns every favourite topic id."""
    ids = list(dict.fromkeys(body.topic_ids))
    with get_db() as db:
        if body.favorite:
            db.executemany("INSERT OR IGNORE INTO favorite_topics (topic_id, created_at) SELECT id, ? FROM topics WHERE id = ?", [(now(), i) for i in ids])
        else:
            db.executemany("DELETE FROM favorite_topics WHERE topic_id = ?", [(i,) for i in ids])
        favs = [r[0] for r in db.execute("SELECT topic_id FROM favorite_topics ORDER BY topic_id")]
    return {"favorites": favs}


# ============================================================================ channel groups
class ChannelGroupIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=60)]
    channels: list[ChannelKey] = Field(default_factory=list, max_length=500)


class ChannelGroupPatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=60)] | None = None
    channels: list[ChannelKey] | None = Field(default=None, max_length=500)   # the whole membership
    add: list[ChannelKey] | None = Field(default=None, max_length=500)        # or just add these


def _set_members(db, gid: int, keys: list[str], replace: bool) -> None:
    if replace:
        db.execute("DELETE FROM channel_group_members WHERE group_id = ?", (gid,))
    db.executemany("INSERT OR IGNORE INTO channel_group_members (group_id, channel_key) VALUES (?, ?)", [(gid, k) for k in dict.fromkeys(keys)])


@router.post("/library/channel-groups", status_code=201, dependencies=[Depends(rate_limit("library_groups", 60))])
def create_channel_group(body: ChannelGroupIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        try:
            gid = db.execute("INSERT INTO channel_groups (name, created_at) VALUES (?, ?)", (body.name.strip(), now())).lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="A channel group with that name already exists") from None
        _set_members(db, gid, body.channels, replace=True)
    return {"id": gid, "name": body.name.strip(), "channels": list(dict.fromkeys(body.channels))}


@router.patch("/library/channel-groups/{group_id}", dependencies=[Depends(rate_limit("library_groups", 60))])
def update_channel_group(group_id: int, body: ChannelGroupPatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT 1 FROM channel_groups WHERE id = ?", (group_id,)).fetchone() is None:
            raise not_found("Channel group")
        if body.name is not None:
            try:
                db.execute("UPDATE channel_groups SET name = ? WHERE id = ?", (body.name.strip(), group_id))
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=409, detail="A channel group with that name already exists") from None
        if body.channels is not None:
            _set_members(db, group_id, body.channels, replace=True)
        if body.add:
            _set_members(db, group_id, body.add, replace=False)
        name = db.execute("SELECT name FROM channel_groups WHERE id = ?", (group_id,)).fetchone()[0]
        keys = [r[0] for r in db.execute("SELECT channel_key FROM channel_group_members WHERE group_id = ? ORDER BY channel_key", (group_id,))]
    return {"id": group_id, "name": name, "channels": keys}


@router.delete("/library/channel-groups/{group_id}")
def delete_channel_group(group_id: int, _: Principal = Depends(require_write)) -> dict:
    """Deletes the group only - its channels and videos stay."""
    with get_db() as db:
        if db.execute("DELETE FROM channel_groups WHERE id = ?", (group_id,)).rowcount == 0:
            raise not_found("Channel group")
    return {"ok": True}


# ============================================================================ playlists & groups
GroupRef = Annotated[str, StringConstraints(pattern=r"^(p|g):\d{1,9}$")]
GROUP_COLUMNS = VIDEO_COLUMNS


class GroupIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    description: Annotated[str, StringConstraints(max_length=500)] = ""


class GroupPatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    description: Annotated[str, StringConstraints(max_length=500)] | None = None


class GroupVideosIn(StrictModel):
    """Either some videos, or every video of a playlist / another group (`from_ref`, e.g. dragged onto the group)."""
    article_ids: list[Annotated[int, Field(ge=1)]] | None = Field(None, min_length=1, max_length=500)
    from_ref: GroupRef | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "GroupVideosIn":
        if (self.article_ids is None) == (self.from_ref is None):
            raise ValueError("Give either article_ids or from_ref")
        return self


MAX_GROUP_COPY = 50_000


def _group_where(db, ref: str) -> tuple[str, list, str, dict]:
    """(FROM/WHERE, params, ORDER BY, info) for one playlist ("p:<feed id>") or group ("g:<id>")."""
    kind, num = ref.split(":")
    if kind == "p":
        feed = db.execute("SELECT id, title FROM feeds WHERE id = ?", (int(num),)).fetchone()
        if feed is None or int(num) not in _playlist_feeds(db):
            raise not_found("Playlist")
        fid = int(num)
        return ("FROM videos v JOIN articles a ON a.id = v.article_id JOIN feeds f ON f.id = a.feed_id "
                "LEFT JOIN video_links pl ON pl.article_id = a.id AND pl.feed_id = ? "
                "WHERE a.id IN (SELECT id FROM articles WHERE feed_id = ? UNION ALL SELECT article_id FROM video_links WHERE feed_id = ?)",
                [fid, fid, fid], "COALESCE(pl.position, 1000000000) ASC, a.sort_ts ASC, a.id ASC",
                {"id": ref, "type": "playlist", "name": feed["title"], "description": ""})
    g = db.execute("SELECT id, name, description FROM video_groups WHERE id = ?", (int(num),)).fetchone()
    if g is None:
        raise not_found("Group")
    return ("FROM video_group_items i JOIN videos v ON v.article_id = i.article_id JOIN articles a ON a.id = v.article_id "
            "JOIN feeds f ON f.id = a.feed_id WHERE i.group_id = ?", [int(num)], "i.position ASC, i.added_at ASC, a.id ASC",
            {"id": ref, "type": "group", "name": g["name"], "description": g["description"]})


def _group_all_where(gid: int) -> tuple[str, list, str]:
    """A group's own videos plus the videos of the playlists moved into it (for its card)."""
    # The candidate ids come from the indexes first (the group's items + its playlists' articles); an OR over the
    # LEFT JOIN made SQLite scan every video (~0.4 s per group, x3 per card - the ＋ menu and the page felt stuck).
    return ("FROM videos v JOIN articles a ON a.id = v.article_id JOIN feeds f ON f.id = a.feed_id "
            "LEFT JOIN video_group_items i ON i.article_id = a.id AND i.group_id = ? "
            "WHERE a.id IN (SELECT article_id FROM video_group_items WHERE group_id = ? "
            "UNION ALL SELECT id FROM articles WHERE feed_id IN (SELECT feed_id FROM video_group_playlists WHERE group_id = ?) "
            "UNION ALL SELECT article_id FROM video_links WHERE feed_id IN (SELECT feed_id FROM video_group_playlists WHERE group_id = ?))",
            [gid, gid, gid, gid], "COALESCE(i.position, 1e9) ASC, a.sort_ts ASC, a.id ASC")


def _order_key(db):
    """Sort key for "p:<feed>" / "g:<id>": the dragged position first; the rest by when they were added (new ones last)."""
    pos = {r[0]: r[1] for r in db.execute("SELECT ref, position FROM video_group_order")}
    born = {f"p:{r[0]}": r[1] for r in db.execute("SELECT id, created_at FROM feeds WHERE kind = 'youtube'")}
    born.update({f"g:{r[0]}": r[1] for r in db.execute("SELECT id, created_at FROM video_groups")})
    return lambda ref: (0, pos[ref], 0) if ref in pos else (1, born.get(ref, 0), int(ref[2:]))


class OrderIn(StrictModel):
    refs: list[GroupRef] = Field(min_length=1, max_length=2000)


def _playlist_card(db, fid: int, name: str) -> dict:
    base, params, order, _info = _group_where(db, f"p:{fid}")
    stats = db.execute(f"SELECT COUNT(*), COALESCE(SUM(a.is_read), 0) {base}", params).fetchone()  # nosec B608
    thumbs = [dict(r) for r in db.execute(f"SELECT v.video_id, v.thumbnail {base} ORDER BY {order} LIMIT 4", params)]  # nosec B608
    return {"id": f"p:{fid}", "type": "playlist", "name": name, "videos": stats[0], "watched": stats[1], "thumbs": thumbs}


@router.get("/library/groups", dependencies=[Depends(rate_limit("library", 240))])
def list_groups(_: Principal = Depends(require_read)) -> dict:
    """Every playlist (automatic) and every group you made, with up to four thumbnails for the card."""
    out = []
    with get_db() as db:
        grouped = {r[0] for r in db.execute("SELECT feed_id FROM video_group_playlists")}
        refs = ([f"p:{fid}" for fid in _playlist_feeds(db) if fid not in grouped]
                + [f"g:{r[0]}" for r in db.execute("SELECT id FROM video_groups")])
        for ref in refs:
            base, params, order, info = _group_where(db, ref)
            if ref.startswith("g:"):  # numbers and thumbnails cover the group's own videos and its playlists
                base, params, order = _group_all_where(int(ref[2:]))
                info["playlists"] = db.execute("SELECT COUNT(*) FROM video_group_playlists WHERE group_id = ?",
                                               (int(ref[2:]),)).fetchone()[0]
            stats = db.execute(f"SELECT COUNT(*), COALESCE(SUM(a.is_read), 0), MAX(a.fetched_at) {base}", params).fetchone()  # nosec B608
            thumbs = [dict(r) for r in db.execute(f"SELECT v.video_id, v.thumbnail {base} ORDER BY {order} LIMIT 4", params)]  # nosec B608
            channels = [r[0] for r in db.execute(
                f"SELECT COALESCE(v.channel_title, f.title) {base} GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 2", params)]  # nosec B608
            out.append({**info, "videos": stats[0], "watched": stats[1], "updated": stats[2], "channels": channels, "thumbs": thumbs})
        order_key = _order_key(db)
    # your groups always come first, then playlists that aren't in a group; inside each: your dragged order, then new ones last
    out.sort(key=lambda g: (0 if str(g["id"]).startswith("g:") else 1, order_key(g["id"])))
    return {"groups": out}


@router.get("/library/groups/{ref}", dependencies=[Depends(rate_limit("library", 240))])
def group_videos(ref: GroupRef, limit: int = Query(300, ge=1, le=1000), offset: int = Query(0, ge=0, le=1_000_000),
                 scope: Literal["own", "all"] = "own", _: Principal = Depends(require_read)) -> dict:
    """The videos of one playlist (in publishing order) or group (in the order you added them), a page at a time.
    scope=all on a group: its own videos and every video of the playlists moved into it, in one list."""
    with get_db() as db:
        base, params, order, info = _group_where(db, ref)
        if scope == "all" and ref.startswith("g:"):
            base, params, order = _group_all_where(int(ref[2:]))
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608
        rows = [dict(r) for r in db.execute(f"SELECT {GROUP_COLUMNS} {base} ORDER BY {order} LIMIT ? OFFSET ?",  # nosec B608
                                            [*params, limit, offset])]
        _attach_topics(db, rows)
        if ref.startswith("g:"):
            names = _playlist_feeds(db)
            key = _order_key(db)
            nested = sorted((r[0] for r in db.execute("SELECT feed_id FROM video_group_playlists WHERE group_id = ?",
                                                      (int(ref[2:]),)) if r[0] in names), key=lambda fid: key(f"p:{fid}"))
            info["playlists"] = [_playlist_card(db, fid, names[fid]) for fid in nested]
        else:
            g = db.execute("SELECT g.id, g.name FROM video_group_playlists p JOIN video_groups g ON g.id = p.group_id "
                           "WHERE p.feed_id = ?", (int(ref[2:]),)).fetchone()
            info["in_group"] = {"id": f"g:{g['id']}", "name": g["name"]} if g else None
    return {**info, "total": total, "items": rows}


@router.put("/library/groups/order", dependencies=[Depends(rate_limit("library_groups", 120))])
def set_group_order(body: OrderIn, _: Principal = Depends(require_write)) -> dict:
    """Save the order you dragged playlists and groups into: send every card of the page (the main page, or the
    playlists inside one group) in the new order."""
    refs = list(dict.fromkeys(body.refs))
    with get_db() as db:
        for n, ref in enumerate(refs):
            db.execute("INSERT OR REPLACE INTO video_group_order (ref, position) VALUES (?, ?)", (ref, n * 10))
    return {"ok": True, "count": len(refs)}


@router.post("/library/groups", status_code=201, dependencies=[Depends(rate_limit("library_groups", 60))])
def create_group(body: GroupIn, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM video_groups").fetchone()[0] >= 500:
            raise HTTPException(status_code=400, detail="Group limit reached")
        if db.execute("SELECT 1 FROM video_groups WHERE name = ?", (body.name.strip(),)).fetchone():
            raise conflict("A group with that name exists")
        gid = db.execute("INSERT INTO video_groups (name, description, created_at) VALUES (?, ?, ?)",
                         (body.name.strip(), body.description.strip(), now())).lastrowid
    audit("video_group_created", principal, group_id=gid)
    return {"id": f"g:{gid}", "type": "group", "name": body.name.strip(), "description": body.description.strip()}


@router.patch("/library/groups/{ref}", dependencies=[Depends(rate_limit("library_groups", 60))])
def update_group(ref: GroupRef, body: GroupPatch, _: Principal = Depends(require_write)) -> dict:
    if not ref.startswith("g:"):
        raise HTTPException(status_code=422, detail="Playlists are named by YouTube - rename the feed instead")
    gid = int(ref[2:])
    with get_db() as db:
        if db.execute("SELECT 1 FROM video_groups WHERE id = ?", (gid,)).fetchone() is None:
            raise not_found("Group")
        if body.name is not None:
            if db.execute("SELECT 1 FROM video_groups WHERE name = ? AND id != ?", (body.name.strip(), gid)).fetchone():
                raise conflict("A group with that name exists")
            db.execute("UPDATE video_groups SET name = ? WHERE id = ?", (body.name.strip(), gid))
        if body.description is not None:
            db.execute("UPDATE video_groups SET description = ? WHERE id = ?", (body.description.strip(), gid))
    return {"ok": True}


@router.delete("/library/groups/{ref}")
def delete_group(ref: GroupRef, principal: Principal = Depends(require_write)) -> dict:
    """A group you made: deleted, its videos stay and its playlists go back to the main page. A playlist: unsubscribed,
    and its videos are deleted too - except videos the channel or another followed playlist also lists, which stay
    (videos you starred or put in one of your groups are deleted with it - the playlist was their source)."""
    with get_db() as db:
        if ref.startswith("g:"):
            if db.execute("DELETE FROM video_groups WHERE id = ?", (int(ref[2:]),)).rowcount == 0:
                raise not_found("Group")
            audit("video_group_deleted", principal, group=ref)
            return {"ok": True}
        fid = int(ref[2:])
        if fid not in _playlist_feeds(db):
            raise not_found("Playlist")
        videos = db.execute("SELECT COUNT(*) FROM articles a WHERE a.feed_id = ? AND NOT EXISTS (SELECT 1 FROM video_links l "
                            "WHERE l.article_id = a.id AND l.feed_id != a.feed_id)", (fid,)).fetchone()[0]
        db.execute("DELETE FROM feeds WHERE id = ?", (fid,))
    audit("playlist_deleted", principal, feed_id=fid, videos=videos)
    return {"ok": True, "videos_removed": videos}


@router.delete("/library/videos/{article_id}")
def remove_video(article_id: int, principal: Principal = Depends(require_write)) -> dict:
    """Remove one video from the library for good: it is not re-added by later fetches or "load whole" back-fills."""
    with get_db() as db:
        row = db.execute("SELECT a.feed_id, a.guid FROM articles a JOIN videos v ON v.article_id = a.id WHERE a.id = ?",
                         (article_id,)).fetchone()
        if row is None:
            raise not_found("Video")
        fids = [row["feed_id"]] + [r[0] for r in db.execute(  # every playlist / channel that lists it
            "SELECT feed_id FROM video_links WHERE article_id = ? AND feed_id != ?", (article_id, row["feed_id"]))]
        for fid in fids:
            db.execute("INSERT INTO article_tombstones (feed_id, guid, removed_at, manual) VALUES (?, ?, ?, 1) "
                       "ON CONFLICT(feed_id, guid) DO UPDATE SET manual = 1, removed_at = excluded.removed_at",
                       (fid, row["guid"], now()))
        db.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    audit("video_removed", principal, article_id=article_id)
    return {"ok": True}


class KeepIn(StrictModel):
    feed_ids: list[Annotated[int, Field(ge=1)]] = Field(min_length=1, max_length=5000)  # one channel or all of them
    days: int = Field(ge=0, le=36500)   # keep videos published in the last N days; 0 = keep everything
    load: bool = True                   # also download older videos inside the time frame (needs the API key)


@router.post("/library/keep", dependencies=[Depends(rate_limit("library_groups", 60))])
def keep_window(body: KeepIn, principal: Principal = Depends(require_write)) -> dict:
    """Keep a channel/playlist to a time frame: videos published before it are removed now and as they age (the
    feeds' retention is set to it), and - with a YouTube API key - older videos inside it are loaded in the background.
    Starred videos, hand-filed ones and videos in your groups are kept. days = 0 = everything."""
    ids = sorted(set(body.feed_ids))
    with get_db() as db:
        found = [r[0] for r in db.execute(
            f"SELECT id FROM feeds WHERE kind = 'youtube' AND url != ? AND id IN ({placeholders(len(ids))})",
            [sources.SAVED_VIDEOS_URL, *ids])]
        if len(found) != len(ids):
            raise HTTPException(status_code=422, detail="Only YouTube channels and playlists can be scaled back")
        marks = placeholders(len(ids))
        db.execute(f"UPDATE feeds SET retention_days = ?, max_articles = 0 WHERE id IN ({marks})", [body.days, *ids])
        removed = 0
        if body.days:
            cutoff = now() - body.days * 86400
            cond = (f"feed_id IN ({marks}) AND sort_ts < ? AND is_starred = 0 "
                    "AND id NOT IN (SELECT article_id FROM article_tags WHERE source = 'manual') "
                    "AND id NOT IN (SELECT article_id FROM video_group_items) "
                    "AND NOT EXISTS (SELECT 1 FROM video_links l WHERE l.article_id = articles.id AND l.feed_id != articles.feed_id)")
            db.execute(f"INSERT OR IGNORE INTO article_tombstones (feed_id, guid, removed_at) SELECT feed_id, guid, ? "  # nosec B608
                       f"FROM articles WHERE {cond}", [now(), *ids, cutoff])
            removed = db.execute(f"DELETE FROM articles WHERE {cond}", [*ids, cutoff]).rowcount  # nosec B608
    audit("videos_scaled_back", principal, feeds=len(ids), days=body.days, removed=removed)
    # Fill the time frame too: fetch the older videos that fall inside it (missing because only part of the history
    # was ever loaded, or removed by an earlier, shorter Keep…). Needs the YouTube Data API key.
    loading = busy = False
    if body.load and sources.yt_key():
        from app import history  # local import: history imports the fetcher stack
        loading = history.backfill_job.start(history.backfill_many, ids, {
            "max_pages": history.MAX_BACKFILL_PAGES, "method": "auto", "since_days": None, "keep_days": body.days})
        busy = not loading
    return {"removed": removed, "days": body.days, "loading": loading, "busy": busy, "has_key": bool(sources.yt_key())}


@router.get("/library/youtube/owner", dependencies=[Depends(rate_limit("library_add", 60))])
def youtube_owner(url: Annotated[str, StringConstraints(min_length=8, max_length=500)], _: Principal = Depends(require_write)) -> dict:
    """The channel a video or playlist link belongs to (for "also follow the channel")."""
    from urllib.parse import parse_qs, urlsplit
    import re as _re
    vid = sources.parse_video_id(url)
    pl = (parse_qs(urlsplit(url if "://" in url else "https://" + url).query).get("list") or [""])[0]
    key = sources.yt_key()
    try:
        if vid and key:
            items = sources.yt_api("videos", {"part": "snippet", "id": vid}, key).get("items") or []
            if items:
                sn = items[0].get("snippet") or {}
                return {"channel_id": sn.get("channelId"), "title": sn.get("channelTitle")}
        if pl and _re.match(sources.PLAYLIST_ID, pl) and not pl.startswith("RD") and key and not vid:
            items = sources.yt_api("playlists", {"part": "snippet", "id": pl}, key).get("items") or []
            if items:
                sn = items[0].get("snippet") or {}
                return {"channel_id": sn.get("channelId"), "title": sn.get("channelTitle")}
        if vid:  # no key: the video page names its channel
            res = sources.resolve_youtube(f"https://www.youtube.com/watch?v={vid}")
            return {"channel_id": res["source"].get("channel_id"), "title": res.get("title")}
        if pl and _re.match(sources.PLAYLIST_ID, pl):  # no key: the playlist's feed names its owner
            resp = sources.http_get(f"https://www.youtube.com/feeds/videos.xml?playlist_id={pl}",
                                    accept="application/atom+xml", max_bytes=sources.JSON_LIMIT)
            m = _re.search(rb"<yt:channelId>(UC[A-Za-z0-9_-]{22})</yt:channelId>", resp.content or b"")
            if resp.status_code < 400 and m:
                name = _re.search(rb"<author>\s*<name>([^<]{1,300})</name>", resp.content)
                return {"channel_id": m.group(1).decode(), "title": name.group(1).decode("utf-8", "replace") if name else None}
    except sources.SourceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    raise HTTPException(status_code=422, detail="Could not tell which channel this link belongs to")


ChannelId = Annotated[str, StringConstraints(pattern=r"^UC[A-Za-z0-9_-]{22}$")]


@router.get("/library/youtube/playlists", dependencies=[Depends(rate_limit("library_add", 30))])
def channel_playlists(channel_id: ChannelId, _: Principal = Depends(require_write)) -> dict:
    """A channel's public playlists (needs the YouTube Data API key), for "add its playlists"."""
    key = sources.yt_key()
    if not key:
        raise HTTPException(status_code=422, detail="Listing a channel's playlists needs a YouTube Data API key "
                                                    "(Settings → Integrations → YouTube)")
    out, token = [], ""
    try:
        for _page in range(10):  # up to 500 playlists
            params = {"part": "snippet,contentDetails", "channelId": channel_id, "maxResults": "50"}
            if token:
                params["pageToken"] = token
            data = sources.yt_api("playlists", params, key)
            for item in data.get("items") or []:
                pid = item.get("id") if isinstance(item, dict) else None
                if isinstance(pid, str) and sources.re.fullmatch(r"[A-Za-z0-9_-]{10,64}", pid):
                    sn = item.get("snippet") or {}
                    out.append({"playlist_id": pid, "title": sources.to_text(sn.get("title"), 300) or pid,
                                "videos": int((item.get("contentDetails") or {}).get("itemCount") or 0)})
            token = data.get("nextPageToken") if isinstance(data.get("nextPageToken"), str) else ""
            if not token:
                break
    except sources.SourceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return {"playlists": out}


@router.post("/library/groups/{ref}/videos", dependencies=[Depends(rate_limit("library_groups", 120))])
def add_to_group(ref: GroupRef, body: GroupVideosIn, _: Principal = Depends(require_write)) -> dict:
    if not ref.startswith("g:"):
        raise HTTPException(status_code=422, detail="Videos can only be added to your own groups")
    gid = int(ref[2:])
    with get_db() as db:
        if db.execute("SELECT 1 FROM video_groups WHERE id = ?", (gid,)).fetchone() is None:
            raise not_found("Group")
        if body.from_ref is not None and body.from_ref.startswith("p:"):
            fid = int(body.from_ref[2:])
            if fid not in _playlist_feeds(db):
                raise not_found("Playlist")
            # the playlist itself moves into the group (out of any other group); its videos are not copied
            db.execute("INSERT OR REPLACE INTO video_group_playlists (feed_id, group_id, added_at) VALUES (?, ?, ?)",
                       (fid, gid, now()))
            db.execute("DELETE FROM video_group_order WHERE ref = ?", (body.from_ref,))  # joins the end of the group
            return {"added": 0, "skipped": 0, "moved": 1}
        if body.from_ref is not None:
            if body.from_ref == ref:
                raise HTTPException(status_code=422, detail="A group cannot be added to itself")
            where, params, order, _info = _group_where(db, body.from_ref)  # 404 for an unknown playlist/group
            ids = [r[0] for r in db.execute(f"SELECT a.id {where} ORDER BY {order} LIMIT ?", [*params, MAX_GROUP_COPY])]
            if not ids:
                return {"added": 0, "skipped": 0}
        else:
            ids = list(dict.fromkeys(body.article_ids))
        valid: list[int] = []
        for start in range(0, len(ids), 500):  # SQLite caps bound parameters
            chunk = ids[start:start + 500]
            valid += [r[0] for r in db.execute(f"SELECT article_id FROM videos WHERE article_id IN ({placeholders(len(chunk))})", chunk)]
        pos = db.execute("SELECT COALESCE(MAX(position), 0) FROM video_group_items WHERE group_id = ?", (gid,)).fetchone()[0]
        added = 0
        valid_set = set(valid)
        for aid in [i for i in ids if i in valid_set]:
            pos += 1
            added += db.execute("INSERT OR IGNORE INTO video_group_items (group_id, article_id, position, added_at) VALUES (?, ?, ?, ?)",
                                (gid, aid, pos, now())).rowcount
    return {"added": added, "skipped": len(ids) - added}


@router.delete("/library/groups/{ref}/playlists/{feed_id}")
def move_playlist_out(ref: GroupRef, feed_id: int, _: Principal = Depends(require_write)) -> dict:
    """Take a playlist out of a group: it is back on the main Playlists & groups page."""
    if not ref.startswith("g:"):
        raise HTTPException(status_code=422, detail="Playlists are only inside your own groups")
    with get_db() as db:
        if db.execute("DELETE FROM video_group_playlists WHERE group_id = ? AND feed_id = ?", (int(ref[2:]), feed_id)).rowcount == 0:
            raise not_found("Playlist in group")
        db.execute("DELETE FROM video_group_order WHERE ref = ?", (f"p:{feed_id}",))  # joins the end of the main page
    return {"ok": True}


@router.delete("/library/groups/{ref}/videos/{article_id}")
def remove_from_group(ref: GroupRef, article_id: int, _: Principal = Depends(require_write)) -> dict:
    if not ref.startswith("g:"):
        raise HTTPException(status_code=422, detail="Videos can only be removed from your own groups")
    with get_db() as db:
        if db.execute("DELETE FROM video_group_items WHERE group_id = ? AND article_id = ?", (int(ref[2:]), article_id)).rowcount == 0:
            raise not_found("Video in group")
    return {"ok": True}


# ============================================================================ topics CRUD
Keyword = Annotated[str, StringConstraints(min_length=1, max_length=60)]


class TopicIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=60)]
    keywords: list[Keyword] = Field(min_length=1, max_length=100)
    color: Color = "#64748b"
    enabled: bool = True


class TopicPatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=60)] | None = None
    keywords: list[Keyword] | None = Field(default=None, min_length=1, max_length=100)
    color: Color | None = None
    enabled: bool | None = None


def _topic_row(r) -> dict:
    return {"id": r["id"], "name": r["name"], "keywords": json.loads(r["keywords"]), "color": r["color"],
            "builtin": bool(r["builtin"]), "enabled": bool(r["enabled"])}


@router.get("/topics")
def list_topics(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [_topic_row(r) for r in db.execute("SELECT * FROM topics ORDER BY name COLLATE NOCASE")]


@router.post("/topics", status_code=201, dependencies=[Depends(rate_limit("topics_write", 30))])
def create_topic(body: TopicIn, principal: Principal = Depends(require_write)) -> dict:
    try:
        words = topics.validate_keywords(body.keywords)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM topics").fetchone()[0] >= topics.MAX_TOPICS:
            raise HTTPException(status_code=400, detail="Topic limit reached")
        if db.execute("SELECT 1 FROM topics WHERE name = ?", (body.name,)).fetchone():
            raise conflict("A topic with that name exists")
        cur = db.execute("INSERT INTO topics (name, keywords, color, enabled) VALUES (?, ?, ?, ?)",
                         (body.name, json.dumps(words), body.color, int(body.enabled)))
        row = db.execute("SELECT * FROM topics WHERE id = ?", (cur.lastrowid,)).fetchone()
    topics.reclassifier.start(row["id"])  # tag articles with just this new topic
    audit("topic_created", principal, topic_id=row["id"])
    return _topic_row(row)


@router.patch("/topics/{topic_id}", dependencies=[Depends(rate_limit("topics_write", 30))])
def update_topic(topic_id: int, body: TopicPatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM topics WHERE id = ?", (topic_id,)).fetchone()
        if row is None:
            raise not_found("Topic")
        if body.name is not None and body.name.lower() != row["name"].lower():
            if db.execute("SELECT 1 FROM topics WHERE name = ? AND id != ?", (body.name, topic_id)).fetchone():
                raise conflict("A topic with that name exists")
            db.execute("UPDATE topics SET name = ? WHERE id = ?", (body.name, topic_id))
        if body.keywords is not None:
            try:
                words = topics.validate_keywords(body.keywords)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from None
            db.execute("UPDATE topics SET keywords = ? WHERE id = ?", (json.dumps(words), topic_id))
        if body.color is not None:
            db.execute("UPDATE topics SET color = ? WHERE id = ?", (body.color, topic_id))
        if body.enabled is not None:
            db.execute("UPDATE topics SET enabled = ? WHERE id = ?", (int(body.enabled), topic_id))
        row = db.execute("SELECT * FROM topics WHERE id = ?", (topic_id,)).fetchone()
    if body.keywords is not None or body.enabled is not None:
        topics.reclassifier.start(topic_id)  # re-tag just this topic
    return _topic_row(row)


@router.delete("/topics/{topic_id}")
def delete_topic(topic_id: int, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM topics WHERE id = ?", (topic_id,)).rowcount == 0:
            raise not_found("Topic")
    audit("topic_deleted", principal, topic_id=topic_id)
    topics.reclassifier.start(topic_id)  # its videos fall back to their channel's topic (or General)
    return {"ok": True}


@router.post("/topics/reclassify", dependencies=[Depends(rate_limit("topics_reclassify", 4))])
def reclassify(_: Principal = Depends(require_write)) -> dict:
    topics.reclassifier.start()
    return {"started": True}
