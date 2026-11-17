"""🎙 Podcasts: find a show's open RSS feed and read its episodes (audio files).

A show can be added by its RSS feed address, an Apple Podcasts link (Apple's free public directory API gives the
feed), a Spotify show link (Spotify's public oEmbed gives the show's name, which is then looked up in Apple's
directory - Spotify itself gives apps no audio), or simply its name. Everything goes through netguard.
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import quote, urlsplit

from app import netguard
from app.config import get_settings
from app.sanitize import to_text


class PodcastError(ValueError):
    """User-facing failure; the message is safe to show."""


APPLE_ID = re.compile(r"/id(\d{3,12})(?:[/?#]|$)")
SPOTIFY_SHOW = re.compile(r"^/(?:intl-[a-z]{2}/)?(show|episode)/([A-Za-z0-9]{10,40})")
JSON_LIMIT = 2_000_000


def _get(url: str, accept: str = "application/json", limit: int = JSON_LIMIT):
    cfg = get_settings()
    try:
        return netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": accept},
                                timeout=cfg.fetch_timeout, max_bytes=limit)
    except netguard.UnsafeURLError as exc:
        raise PodcastError(f"That address can't be used: {exc}") from None
    except netguard.FetchError as exc:
        raise PodcastError(f"Could not reach {urlsplit(url).hostname}: {exc}") from None


def _json(url: str) -> dict:
    resp = _get(url)
    if resp.status_code >= 400:
        return {}
    try:
        data = json.loads(resp.content.decode("utf-8", "replace"))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _https(url) -> str | None:
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        return None
    try:
        return netguard.normalize_url(url)
    except netguard.UnsafeURLError:
        return None


def _show(r: dict) -> dict | None:
    feed = _https(r.get("feedUrl"))
    if not feed:
        return None
    return {"title": to_text(r.get("collectionName") or r.get("trackName"), 300), "author": to_text(r.get("artistName"), 200),
            "feed_url": feed, "artwork": _https(r.get("artworkUrl600") or r.get("artworkUrl100")),
            "episodes": r.get("trackCount") if isinstance(r.get("trackCount"), int) else None,
            "genre": to_text(r.get("primaryGenreName"), 80)}


def search(term: str, limit: int = 10) -> list[dict]:
    """Shows matching a name, from Apple's public podcast directory (no key, no account)."""
    term = " ".join((term or "").split())[:200]
    if len(term) < 2:
        return []
    data = _json(f"https://itunes.apple.com/search?media=podcast&entity=podcast&limit={int(limit)}&term={quote(term)}")
    return [s for s in (_show(r) for r in data.get("results") or [] if isinstance(r, dict)) if s]


def _apple(show_id: str) -> dict | None:
    data = _json(f"https://itunes.apple.com/lookup?entity=podcast&id={int(show_id)}")
    return next((s for s in (_show(r) for r in data.get("results") or [] if isinstance(r, dict)) if s), None)


def _norm(name: str | None) -> str:
    """Show names compared loosely: case, "(Audio)" / "(Video)" / "Podcast" suffixes and punctuation ignored."""
    n = re.sub(r"\((audio|video|podcast)\)|\bpodcast\b", " ", (name or "").lower())
    return " ".join(re.findall(r"[a-z0-9]+", n))


def _spotify_show(url: str) -> tuple[str | None, str | None]:
    """A Spotify show page's link preview (Open Graph): the show's name and its author ("Podcast · TWiT · …")."""
    resp = _get(url, "text/html", 3_000_000)
    if resp.status_code >= 400:
        return None, None
    page = resp.content.decode("utf-8", "replace")
    def meta(key: str) -> str:
        m = re.search(rf'<meta[^>]+property="{key}"[^>]+content="([^"]*)"', page)
        return html.unescape(m.group(1)).strip() if m else ""
    parts = [x.strip() for x in meta("og:description").split("·")]
    author = parts[1].removeprefix("by ").strip() if len(parts) > 2 and parts[0].lower() == "podcast" else None
    return to_text(meta("og:title"), 300) or None, to_text(author, 200) or None


def _best_match(found: list[dict], title: str, author: str | None) -> dict | None:
    """The directory entry that is this show: same name (loosely), the author breaking ties; else none."""
    same = [s for s in found if _norm(s["title"]) == _norm(title)]
    if not same:
        same = [s for s in found if _norm(title) and (_norm(title) in _norm(s["title"]) or _norm(s["title"]) in _norm(title))]
    if author and len(same) > 1:
        same.sort(key=lambda s: _norm(author) not in _norm(s.get("author")))
    return same[0] if same else None


def _spotify_title(url: str) -> str | None:
    data = _json(f"https://open.spotify.com/oembed?url={quote(url, safe='')}")
    return to_text(data.get("title"), 300) or None


def _feed_preview(url: str) -> dict:
    """Read a feed address: is it a podcast (episodes with audio)? Its title, author and artwork."""
    from app.fetcher import parse_bytes, xml_guard  # local import: fetcher is heavy

    resp = _get(url, "application/rss+xml,application/xml;q=0.9,*/*;q=0.5", max(get_settings().max_feed_bytes, 60 * 1024 * 1024))
    if resp.status_code >= 400:
        raise PodcastError(f"The feed answered HTTP {resp.status_code}")
    if xml_guard(resp.content, resp.headers.get("content-type")):
        raise PodcastError("That address is not a podcast feed")
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}
    entries = parsed.get("entries") or []
    audio = sum(1 for e in entries if episode_audio(e))
    if not audio:
        raise PodcastError("That feed has no audio episodes - is it a podcast feed?")
    feed = parsed.get("feed") or {}
    image = (feed.get("image") or {}).get("href") if isinstance(feed.get("image"), dict) else None
    return {"title": to_text(feed.get("title"), 300) or url, "author": to_text(feed.get("author") or feed.get("itunes_author"), 200),
            "feed_url": resp.url if resp.url.startswith("https://") else url, "artwork": _https(image), "episodes": len(entries)}


def resolve(text: str) -> dict:
    """A pasted link or name → {title, author, feed_url, artwork}. Raises PodcastError with advice."""
    raw = (text or "").strip()
    if not raw:
        raise PodcastError("Paste a podcast's feed, an Apple Podcasts or Spotify link, or type its name.")
    if not re.match(r"^(https?://|www\.)", raw, re.I):
        found = search(raw, 1)
        if not found:
            raise PodcastError(f"No podcast called “{raw[:80]}” found in Apple's podcast directory.")
        return found[0]
    url = raw if "://" in raw else "https://" + raw
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.endswith("podcasts.apple.com") or host.endswith("itunes.apple.com"):
        m = APPLE_ID.search(parts.path)
        show = _apple(m.group(1)) if m else None
        if not show:
            raise PodcastError("Couldn't find that show in Apple's directory - paste its RSS feed instead.")
        return show
    if host == "open.spotify.com":
        m = SPOTIFY_SHOW.match(parts.path)
        if not m:
            raise PodcastError("Paste a Spotify show link (open.spotify.com/show/…).")
        page = f"https://open.spotify.com/{m.group(1)}/{m.group(2)}"
        title, author = _spotify_show(page) if m.group(1) == "show" else (None, None)
        title = title or _spotify_title(page)
        found = _best_match(search(title, 10), title, author) if title else None
        if not found:
            raise PodcastError(f"“{title or 'That show'}” has no open feed (it may be a Spotify exclusive). "
                               "Search for it by name, or paste its RSS feed.")
        return found
    return _feed_preview(url)


# ------------------------------------------------------------------------------------------------ episodes
def episode_audio(entry: dict) -> dict | None:
    """The audio file of a feed entry (its enclosure): {url, type, length}."""
    for enc in entry.get("enclosures") or []:
        if not isinstance(enc, dict):
            continue
        href = _https(enc.get("href") or enc.get("url"))
        kind = str(enc.get("type") or "").lower()
        if href and (kind.startswith("audio/") or kind in ("", "application/octet-stream") and
                     re.search(r"\.(mp3|m4a|aac|ogg|opus|wav)(\?|$)", href, re.I) or kind == "video/mp4"):
            length = enc.get("length")
            return {"url": href, "type": kind or "audio/mpeg", "length": int(length) if str(length or "").isdigit() else None}
    return None


def duration_seconds(value) -> int | None:
    """itunes:duration: "3725", "62:05" or "1:02:05" → seconds."""
    text = str(value or "").strip()
    if text.isdigit():
        return int(text)
    if re.fullmatch(r"\d{1,3}(:\d{1,2}){1,2}", text):
        secs = 0
        for part in text.split(":"):
            secs = secs * 60 + int(part)
        return secs
    return None


# Shows that publish a page sorting their episodes into categories (a heading, then links to its episodes).
CATEGORY_PAGES = {"darknetdiaries.com": "https://darknetdiaries.com/categories/"}
CATEGORY_EVERY = 7 * 86400
_HEADING = re.compile(r"<h[1-3][^>]*>(.*?)</h[1-3]>", re.S | re.I)
_EP_LINK = re.compile(r'<a[^>]+href="([^"]*?/episode/(\d{1,5})/?)"', re.I)


def category_page(db, feed_id: int) -> str | None:
    """The categories page for a show, if it's one we know (matched on its episodes' / feed's host)."""
    row = db.execute("SELECT url, site_url FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    link = db.execute("SELECT url FROM articles WHERE feed_id = ? AND url IS NOT NULL ORDER BY sort_ts DESC LIMIT 1", (feed_id,)).fetchone()
    for candidate in (link[0] if link else None, row["site_url"] if row else None, row["url"] if row else None):
        host = (urlsplit(candidate or "").hostname or "").lower().removeprefix("www.").removeprefix("podcast.")
        if host in CATEGORY_PAGES:
            return CATEGORY_PAGES[host]
    return None


def parse_categories(page: str) -> dict[int, set[str]]:
    """{episode number: {category, ...}} from a page of "heading, then links to /episode/N/"."""
    out: dict[int, set[str]] = {}
    marks = [(m.start(), to_text(html.unescape(re.sub(r"<[^>]+>", " ", m.group(1))), 120)) for m in _HEADING.finditer(page)]
    for i, (start, name) in enumerate(marks):
        if not name or len(name) < 2:
            continue
        end = marks[i + 1][0] if i + 1 < len(marks) else len(page)
        for link in _EP_LINK.finditer(page, start, end):
            out.setdefault(int(link.group(2)), set()).add(name)
    return out


def sync_categories(feed_id: int, force: bool = False) -> int:
    """Label a show's episodes with its own categories (weekly; the page is public). Returns episodes labelled."""
    from app import topics
    from app.db import get_db, now

    with get_db() as db:
        page_url = category_page(db, feed_id)
        last = db.execute("SELECT value FROM sync_state WHERE key = ?", (f"podcast_categories:{feed_id}",)).fetchone()
    if not page_url or (not force and last and str(last[0]).isdigit() and now() - int(last[0]) < CATEGORY_EVERY):
        return 0
    resp = _get(page_url, "text/html", 5_000_000)
    if resp.status_code >= 400:
        return 0
    cats = parse_categories(resp.content.decode("utf-8", "replace"))
    labelled = 0
    with get_db() as db:
        rows = db.execute("SELECT id, url, title FROM articles WHERE feed_id = ?", (feed_id,)).fetchall()
        db.execute(f"DELETE FROM episode_categories WHERE article_id IN (SELECT id FROM articles WHERE feed_id = ?)", (feed_id,))
        for r in rows:
            m = re.search(r"/episode/(\d{1,5})/?", r["url"] or "") or re.match(r"^\s*(?:ep(?:isode)?\.?\s*)?(\d{1,5})\s*[:.\-]", r["title"] or "", re.I)
            names = cats.get(int(m.group(1))) if m else None
            if names:
                db.executemany("INSERT OR IGNORE INTO episode_categories (article_id, category) VALUES (?, ?)", [(r["id"], n) for n in names])
                labelled += 1
        topics.apply_category_topics(db, [r["id"] for r in rows])
        db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)", (f"podcast_categories:{feed_id}", str(now())))
    return labelled


def fill_episodes(feed_id: int, url: str) -> int:
    """Attach audio to the episodes of a feed that were stored before it was a podcast (an Articles feed moved to
    Podcasts): read the feed once and match its entries to the saved articles."""
    from app.db import get_db
    from app.fetcher import _guid, _timestamp, parse_bytes, xml_guard  # local import: fetcher is heavy

    resp = _get(url, "application/rss+xml,application/xml;q=0.9,*/*;q=0.5", max(get_settings().max_feed_bytes, 60 * 1024 * 1024))
    if resp.status_code >= 400 or xml_guard(resp.content, resp.headers.get("content-type")):
        return 0
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}
    feed = parsed.get("feed") or {}
    show_image = _https((feed.get("image") or {}).get("href")) if isinstance(feed.get("image"), dict) else None
    filled = 0
    with get_db() as db:
        for entry in parsed.get("entries") or []:
            title = to_text(entry.get("title"), 1000) or "(untitled)"
            row = db.execute("SELECT id FROM articles WHERE feed_id = ? AND guid = ?", (feed_id, _guid(entry, title, _timestamp(entry)))).fetchone()
            if row and episode_audio(entry):
                store_episode(db, row["id"], entry, show_image)
                filled += 1
    return filled


def store_episode(db, article_id: int, entry: dict, show_image: str | None) -> None:
    audio = episode_audio(entry)
    if not audio:
        return
    image = entry.get("image") or {}
    img = _https(image.get("href")) if isinstance(image, dict) else None
    db.execute("INSERT OR REPLACE INTO episodes (article_id, audio_url, audio_type, duration_s, image) VALUES (?, ?, ?, ?, ?)",
               (article_id, audio["url"], audio["type"][:60], duration_seconds(entry.get("itunes_duration")), img or show_image))
