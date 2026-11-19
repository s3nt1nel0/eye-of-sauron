"""What a feed delivers - articles, podcast episodes, YouTube videos or a social account's posts - so each one lands in
its own tab (Articles, Podcasts, Videos, Accounts) whatever way it was added: one by one, from an OPML file written by
this app (which records the kind), or from another reader's OPML (where it is recognised here).

* ``guess(url)``: the kind of a feed address on its own - YouTube channel / playlist feeds, Telegram / X addresses,
  Bluesky / Mastodon / Reddit profile feeds and RSSHub routes for Instagram, Threads, TikTok, Facebook and LinkedIn.
* ``reclassify(db)``: puts feeds that were stored as plain article feeds in the right tab - account feeds by their
  address, podcast shows by their content (most of their items carry an audio file). Run at start-up, after an OPML
  import and after a feed's first fetches.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

log = logging.getLogger("eos.feedkinds")

SOCIAL_FOLDER = "Social Accounts"
PODCAST_FOLDER = "Podcasts"
PODCAST_SHARE = 0.6   # at least 60 % of a feed's items carry an audio file...
PODCAST_MIN = 3       # ...and it has at least 3 items

_RSSHUB = (  # path prefix of an RSSHub route -> platform
    ("/twitter/user/", "x"), ("/x/user/", "x"), ("/instagram/user/", "instagram"), ("/picuki/profile/", "instagram"),
    ("/threads/", "threads"), ("/tiktok/user/", "tiktok"), ("/facebook/page/", "facebook"),
    ("/linkedin/company/", "linkedin"), ("/telegram/channel/", "telegram"), ("/bsky/profile/", "bluesky"),
    ("/mastodon/acct/", "mastodon"), ("/reddit/", "reddit"),
)
_MASTODON_FEED = re.compile(r"^/@[A-Za-z0-9_]{1,30}(?:\.rss|/feed\.rss)$")
_TG_PUBLIC = re.compile(r"^/s/([A-Za-z][A-Za-z0-9_]{3,31})/?$")
_X_USER = re.compile(r"^/([A-Za-z0-9_]{1,15})/?$")


def social_folder(db) -> int:
    db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES (?, 9)", (SOCIAL_FOLDER,))
    return db.execute("SELECT id FROM folders WHERE name = ?", (SOCIAL_FOLDER,)).fetchone()["id"]


def podcast_folder(db) -> int:
    db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES (?, 11)", (PODCAST_FOLDER,))
    return db.execute("SELECT id FROM folders WHERE name = ?", (PODCAST_FOLDER,)).fetchone()["id"]


def social_platform(url: str) -> str | None:
    """The social platform of an account's feed address, or None for anything else."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().removeprefix("www.").removeprefix("old.")
    path = parts.path or "/"
    if host == "bsky.app" and path.startswith("/profile/") and path.rstrip("/").endswith("/rss"):
        return "bluesky"
    if host == "reddit.com" and (path.startswith(("/r/", "/user/", "/u/")) and ".rss" in path):
        return "reddit"
    if _MASTODON_FEED.match(path):
        return "mastodon"
    for prefix, platform in _RSSHUB:
        if path.startswith(prefix):
            return platform
    return None


def guess(url: str) -> dict:
    """{"kind", "source"?, "social_platform"?} for a feed address that came without any other information."""
    from app import sources

    yt = sources.youtube_source_for_url(url)
    if yt:
        return {"kind": "youtube", "source": yt}
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    if host in ("t.me", "telegram.me") and (m := _TG_PUBLIC.match(parts.path or "")):
        return {"kind": "telegram", "source": {"kind": "telegram", "via": "web", "channel": m.group(1)},
                "social_platform": "telegram"}
    if host in ("x.com", "twitter.com") and (m := _X_USER.match(parts.path or "")):
        return {"kind": "x", "source": {"kind": "x", "username": m.group(1), "via": "bridge"}, "social_platform": "x"}
    platform = social_platform(url)
    if platform:
        return {"kind": "rss", "social_platform": platform}
    return {"kind": "rss"}


def podcast_like(db, feed_id: int) -> bool:
    row = db.execute("SELECT COUNT(*), SUM(EXISTS (SELECT 1 FROM episodes e WHERE e.article_id = a.id)) "
                     "FROM articles a WHERE a.feed_id = ?", (feed_id,)).fetchone()
    total, audio = row[0] or 0, row[1] or 0
    return total >= PODCAST_MIN and audio >= PODCAST_SHARE * total


def make_podcast(db, feed) -> None:
    folder = feed["folder_id"]
    if folder is None:
        folder = podcast_folder(db)
    db.execute("UPDATE feeds SET kind = 'podcast', folder_id = ?, retention_days = COALESCE(retention_days, 0) WHERE id = ?",
               (folder, feed["id"]))
    log.info("Feed %d (%s) is a podcast show: moved to Podcasts", feed["id"], feed["title"])


def check_feed(db, feed_id: int) -> str | None:
    """After a fetch: a plain article feed that turns out to be a podcast show moves to Podcasts. Returns the new kind."""
    feed = db.execute("SELECT id, title, kind, folder_id, social_platform FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    if feed is None or (feed["kind"] or "rss") != "rss" or feed["social_platform"]:
        return None
    if podcast_like(db, feed_id):
        make_podcast(db, feed)
        return "podcast"
    return None


def reclassify(db) -> dict:
    """Plain article feeds that are really account feeds or podcast shows go to their own tabs."""
    moved = {"accounts": 0, "podcasts": 0}
    for feed in db.execute("SELECT id, title, url, kind, folder_id FROM feeds "
                           "WHERE COALESCE(kind, 'rss') = 'rss' AND social_platform IS NULL").fetchall():
        platform = social_platform(feed["url"])
        if platform:
            db.execute("UPDATE feeds SET social_platform = ?, folder_id = COALESCE(folder_id, ?) WHERE id = ?",
                       (platform, social_folder(db), feed["id"]))
            moved["accounts"] += 1
        elif podcast_like(db, feed["id"]):
            make_podcast(db, feed)
            moved["podcasts"] += 1
    if any(moved.values()):
        log.info("Feed kinds: %d account feed(s) and %d podcast show(s) moved out of Articles", moved["accounts"], moved["podcasts"])
    return moved
