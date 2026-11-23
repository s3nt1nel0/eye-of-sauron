"""One stored copy per YouTube video, shared by every playlist and channel it is in.

A video is an article of the feed it first came from (``articles.feed_id``). When another followed playlist or
channel lists the same video, no second copy is made: a ``video_links`` row says "this video is in that feed too"
(with its place in the playlist, when YouTube gave one). So a channel added after its playlists - or playlists
added after their channel - only adds the videos that are missing, and the rest are linked.

``merge_duplicates`` folds copies made before this existed into one (groups, topics, tags, watched, starred,
summaries all move to the kept copy), after which ``videos.video_id`` carries a UNIQUE index.

Only stdlib here: app.db imports this during its migration.
"""

from __future__ import annotations

import re
import sqlite3
import time

VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
UNIQUE_INDEX = "idx_videos_video_unique"

# Columns that point at an article but are not called article_id (none today; listed so a future one is not missed).
_SKIP_TABLES = {"videos", "articles", "articles_fts"}


def _article_tables(db: sqlite3.Connection) -> list[str]:
    """Every table with an article_id column (groups, topics, tags, summaries, links, ...), except videos."""
    out = []
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                              "AND name NOT LIKE '%_fts%' ORDER BY name").fetchall():
        if name in _SKIP_TABLES or not re.fullmatch(r"[A-Za-z0-9_]+", name):
            continue
        cols = {r[1] for r in db.execute(f"PRAGMA table_info('{name}')")}  # nosec B608 - names from sqlite_master
        if "article_id" in cols:
            out.append(name)
    return out


def link(db: sqlite3.Connection, feed_id: int, article_id: int, position: int | None, added_at: int | None = None) -> None:
    """Record that a stored video is also in this feed (or, for its own feed, its place in the playlist)."""
    db.execute("INSERT INTO video_links (feed_id, article_id, position, added_at) VALUES (?, ?, ?, ?) "
               "ON CONFLICT(feed_id, article_id) DO UPDATE SET position = COALESCE(excluded.position, video_links.position)",
               (feed_id, article_id, position, added_at or int(time.time())))


def link_existing(db: sqlite3.Connection, feed_id: int, video_id: str, position: int | None = None) -> bool:
    """The video is already stored (from any feed): link it to this feed and return True, so no copy is made.
    False = not stored yet - the caller adds it."""
    if not VIDEO_ID.match(video_id or ""):
        return False
    row = db.execute("SELECT v.article_id, a.feed_id FROM videos v JOIN articles a ON a.id = v.article_id "
                     "WHERE v.video_id = ? ORDER BY v.article_id LIMIT 1", (video_id,)).fetchone()
    if row is None:
        return False
    if row[1] != feed_id or position is not None:
        link(db, feed_id, row[0], position)
    return True


def merge_into(db: sqlite3.Connection, keep: int, dup: int, tables: list[str] | None = None) -> None:
    """Fold article ``dup`` (a second copy of a video) into ``keep``: every group, topic, tag, summary and link
    moves over, watched / starred are kept if either copy had them, and dup's feed becomes a link of keep."""
    if keep == dup:
        return
    k = db.execute("SELECT feed_id FROM articles WHERE id = ?", (keep,)).fetchone()
    d = db.execute("SELECT feed_id, is_read, is_starred, starred_at, fetched_at FROM articles WHERE id = ?", (dup,)).fetchone()
    if k is None or d is None:
        return
    for table in tables if tables is not None else _article_tables(db):
        # move what keep doesn't have yet; rows keep already has (same group / topic / tag) are dropped with dup
        db.execute(f"UPDATE OR IGNORE {table} SET article_id = ? WHERE article_id = ?", (keep, dup))  # nosec B608
    if d[0] != k[0]:
        db.execute("INSERT OR IGNORE INTO video_links (feed_id, article_id, position, added_at) VALUES (?, ?, NULL, ?)",
                   (d[0], keep, d[4]))
    db.execute("UPDATE articles SET is_read = MAX(is_read, ?), is_starred = MAX(is_starred, ?), "
               "starred_at = CASE WHEN starred_at IS NULL THEN ? WHEN ? IS NULL THEN starred_at ELSE MIN(starred_at, ?) END, "
               "fetched_at = MIN(fetched_at, ?) WHERE id = ?", (d[1], d[2], d[3], d[3], d[3], d[4], keep))
    dv = db.execute("SELECT channel_id, channel_title, thumbnail, duration_s, views FROM videos WHERE article_id = ?",
                    (dup,)).fetchone()
    if dv is not None:
        db.execute("UPDATE videos SET channel_id = COALESCE(channel_id, ?), channel_title = COALESCE(channel_title, ?), "
                   "thumbnail = COALESCE(thumbnail, ?), duration_s = COALESCE(duration_s, ?), "
                   "views = MAX(COALESCE(views, 0), COALESCE(?, 0)) WHERE article_id = ?", (*dv, keep))
    db.execute("DELETE FROM videos WHERE article_id = ?", (dup,))
    db.execute("DELETE FROM articles WHERE id = ?", (dup,))  # cascades whatever was left behind (dropped duplicates)


def duplicate_sets(db: sqlite3.Connection) -> list[list[int]]:
    """[[kept article id, copy, copy...], ...] - the oldest copy of each video is the one kept."""
    out = []
    for (vid,) in db.execute("SELECT video_id FROM videos GROUP BY video_id HAVING COUNT(*) > 1").fetchall():
        out.append([r[0] for r in db.execute("SELECT article_id FROM videos WHERE video_id = ? ORDER BY article_id", (vid,))])
    return out


def merge_duplicates(db: sqlite3.Connection) -> dict:
    """Fold every duplicate copy into its oldest copy. Returns {"sets", "removed"}."""
    sets = duplicate_sets(db)
    tables = _article_tables(db) if sets else []
    removed = 0
    for ids in sets:
        for dup in ids[1:]:
            merge_into(db, ids[0], dup, tables)
            removed += 1
    return {"sets": len(sets), "removed": removed}


def ensure_unique(db: sqlite3.Connection) -> dict | None:
    """Merge duplicates (once) and put the UNIQUE index on videos.video_id. None = it was already there."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?", (UNIQUE_INDEX,)).fetchone():
        return None
    result = merge_duplicates(db)
    db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {UNIQUE_INDEX} ON videos(video_id)")  # nosec B608 - constant
    db.execute("DROP INDEX IF EXISTS idx_videos_video")  # the unique one serves the same lookups
    return result
