"""Reddit posts for the Accounts reading view: the post's own text, its photos / video / gallery, and its thread.

Everything comes from Reddit's public RSS (Reddit refuses its JSON to apps, and the app never gets around that):
the subreddit feed gives each post's body and media links; a post's own feed (/comments/<id>/.rss) gives the post
followed by its comments. Media URLs are only ever Reddit's / Imgur's https hosts.
"""

from __future__ import annotations

import calendar
import html as htmlmod
import re
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from app.sanitize import sanitize_html, to_text

POST_PATH = re.compile(r"^/r/[A-Za-z0-9_]{2,21}/comments/[a-z0-9]{3,12}(?:/[^/?#]*)?/?$")
IMAGE = re.compile(r"https://(?:i\.redd\.it|i\.imgur\.com)/[A-Za-z0-9_-]{4,40}\.(?:jpe?g|png|gif|webp)", re.I)
PREVIEW = re.compile(r"https://(?:external-)?preview\.redd\.it/[A-Za-z0-9_-]{4,60}\.(?:jpe?g|png|gif|webp)(?:\?[^\"'\s<>]*)?", re.I)
VIDEO = re.compile(r"https://v\.redd\.it/([a-z0-9]{6,20})", re.I)
GALLERY = re.compile(r"https://(?:www\.)?reddit\.com/gallery/([a-z0-9]{3,12})", re.I)
MD = re.compile(r"<div[^>]*>(.*)</div>", re.S)
THREAD_TTL = 120          # seconds a fetched thread is reused (Reddit rate-limits anonymous readers)
MAX_COMMENTS = 300

_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


SUBREDDIT_FEED = re.compile(r"^https://www\.reddit\.com/r/[A-Za-z0-9_]{2,21}/new/\.rss(?:\?limit=100)?$")
HISTORY_PAGES = 1   # older pages (100 posts each) per scheduled fetch - Reddit is strict with anonymous readers
POST_ID = re.compile(r"\b(t3_[a-z0-9]{3,12})\b")


def older_pages(feed_id: int, feed_url: str, cutoff: int | None) -> int:
    """Fill a subreddit's older posts: up to HISTORY_PAGES pages of 100 before the oldest stored post. Stops for good
    at the retention cutoff or at the end of Reddit's listing (about 1,000 posts); a rate limit just waits for the
    next fetch. Requests are paced by netguard."""
    from app import netguard, topics
    from app.config import get_settings
    from app.db import get_db, now
    from app.fetcher import parse_bytes, store_entries, xml_guard

    if not SUBREDDIT_FEED.match(feed_url or "") or netguard.cooling("www.reddit.com"):
        return 0                      # not a subreddit feed, or Reddit asked us to slow down: the next fetch tries
    key = f"reddit_history_done:{feed_id}"
    with get_db() as db:
        if db.execute("SELECT 1 FROM sync_state WHERE key = ?", (key,)).fetchone():
            return 0
        row = db.execute("SELECT guid, sort_ts FROM articles WHERE feed_id = ? ORDER BY sort_ts ASC, id ASC LIMIT 1", (feed_id,)).fetchone()
    m = POST_ID.search(row["guid"] or "") if row else None
    if not m:
        return 0
    if cutoff and row["sort_ts"] and row["sort_ts"] < cutoff:
        done = True
    else:
        done = False
    after, added, cfg = m.group(1), 0, get_settings()
    base = feed_url.split("?", 1)[0]
    for _ in range(0 if done else HISTORY_PAGES):
        resp = netguard.request("GET", f"{base}?limit=100&after={after}", headers={"User-Agent": cfg.user_agent},
                                timeout=cfg.fetch_timeout, max_bytes=cfg.max_feed_bytes)
        if resp.status_code == 429 or resp.status_code >= 500:
            break                     # try again with the next fetch
        if resp.status_code >= 400 or xml_guard(resp.content, resp.headers.get("content-type")):
            done = True
            break
        entries = (parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}).get("entries") or []
        if not entries:
            done = True               # the end of Reddit's listing
            break
        with get_db() as db:
            new_ids = store_entries(db, feed_id, entries, cutoff, now())
            if new_ids:
                topics.classify(db, new_ids)
        added += len(new_ids)
        last = POST_ID.search(str(entries[-1].get("id") or entries[-1].get("link") or ""))
        stamps = [e.get("published_parsed") or e.get("updated_parsed") for e in entries]
        oldest = min((calendar.timegm(t) for t in stamps if t), default=None)  # feedparser gives UTC
        if not last or len(entries) < 100 or (cutoff and oldest and oldest < cutoff):
            done = True
            break
        after = last.group(1)
    if done:
        with get_db() as db:
            db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, '1')", (key,))
    return added


def is_post_url(url: str | None) -> bool:
    p = urlsplit(url or "")
    host = (p.hostname or "").lower()
    return p.scheme == "https" and (host == "reddit.com" or host.endswith(".reddit.com")) and bool(POST_PATH.match(p.path))


def media(html: str) -> list[dict]:
    """Photos (full size, de-duplicated), a video, or a gallery link found in a Reddit post's HTML."""
    raw = htmlmod.unescape(html or "")
    out: list[dict] = []
    seen: set[str] = set()

    def add_image(url: str) -> None:
        key = re.sub(r"\?.*$", "", url.rsplit("/", 1)[-1]).split(".")[0]  # same picture, other size
        if key not in seen:
            seen.add(key)
            out.append({"type": "image", "src": url})

    for m in IMAGE.finditer(raw):
        add_image(m.group(0))
    for m in PREVIEW.finditer(raw):
        width = re.search(r"[?&]width=(\d+)", m.group(0))
        if not width or int(width.group(1)) >= 320:  # skip the 140-px list thumbnails
            add_image(m.group(0))
    thumb = next((m.group(0) for m in PREVIEW.finditer(raw)), None)
    for m in VIDEO.finditer(raw):
        vid = m.group(1)
        out.append({"type": "video", "id": vid, "page": f"https://v.redd.it/{vid}", "poster": thumb,
                    # the browser tries these in turn (Reddit keeps the sound in a separate file)
                    "sources": [f"https://v.redd.it/{vid}/HLSPlaylist.m3u8", f"https://v.redd.it/{vid}/DASH_720.mp4",
                                f"https://v.redd.it/{vid}/DASH_480.mp4", f"https://v.redd.it/{vid}/DASH_360.mp4"]})
        break
    for m in GALLERY.finditer(raw):
        out.append({"type": "gallery", "href": f"https://www.reddit.com/gallery/{m.group(1)}", "poster": thumb if not seen else None})
        break
    return out


def body(html: str) -> str:
    """The post's / comment's own text (Reddit wraps it in <div class="md">, then adds "submitted by … [link]")."""
    m = MD.search(html or "")
    return sanitize_html(m.group(1)) if m else ""


def _post_url(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit(("https", "www.reddit.com", p.path.rstrip("/"), "", ""))


def thread(url: str) -> dict:
    """{"post": {...}, "comments": [...], "source": "rss"} for a Reddit post. Raises social_posts.PostError."""
    from app import social_posts  # shares the fetch helpers (netguard, sizes, timeouts)

    base = _post_url(url)
    with _lock:
        hit = _cache.get(base)
        if hit and time.time() - hit[0] < THREAD_TTL:
            return hit[1]
    entries = social_posts._feed_entries(base + "/.rss")
    if not entries:
        raise social_posts.PostError("Reddit sent an empty thread - it may have been deleted")

    def html_of(e: dict) -> str:
        content = e.get("content") or []
        return (content[0] or {}).get("value", "") if content else e.get("summary", "")

    def when(e: dict) -> int | None:
        t = e.get("updated_parsed") or e.get("published_parsed")
        return calendar.timegm(t) if t else None  # feedparser gives UTC

    first = entries[0]
    raw = html_of(first)
    out = {"post": {"title": to_text(first.get("title"), 500), "author": to_text(first.get("author"), 100) or None,
                    "published": when(first), "link": base, "body": body(raw), "media": media(raw)},
           "comments": [{"author": to_text(e.get("author"), 100) or None, "published": when(e),
                         "html": body(html_of(e)) or sanitize_html(html_of(e)), "link": e.get("link") if is_post_url(e.get("link")) else None}
                        for e in entries[1:MAX_COMMENTS + 1]],
           "source": "rss"}
    with _lock:
        _cache[base] = (time.time(), out)
        for key in [k for k, (t, _) in _cache.items() if time.time() - t > THREAD_TTL]:
            _cache.pop(key, None)
    return out
