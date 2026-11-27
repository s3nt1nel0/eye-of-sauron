"""Fetch, parse, sanitise and store a single feed."""

from __future__ import annotations

import calendar
import hashlib
import io
import logging
import random
import re
import time

import feedparser

from app import app_settings, netguard, sources, topics, webhooks
from app.config import get_settings
from app.db import get_db, now
from app.entities import extract_for_articles
from app import stories
from app.rules import apply_rules
from app.sanitize import sanitize_html, to_text

log = logging.getLogger("eos.fetcher")

MAX_ENTRIES_PER_FETCH = 500
MAX_BACKOFF_SECONDS = 24 * 3600
_ENTITY_DECL = re.compile(rb"<!ENTITY", re.IGNORECASE)
_XML_ENCODING = re.compile(rb"""^\s*<\?xml[^>]{0,200}?encoding\s*=\s*["']([A-Za-z0-9._:-]{1,40})""", re.IGNORECASE)
_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._:-]{1,40})", re.IGNORECASE)
# Encodings in which "<!ENTITY" is not a plain ASCII byte sequence (so a byte-level guard
# could be bypassed) and which no legitimate feed needs. UTF-16/32 are handled separately.
_UNSAFE_ENCODING = re.compile(r"^(?:utf-?7|.*ebcdic.*|cp0?37|cp500|cp875|cp1026|cp1140|ibm0?37|ibm500|ibm1026|ibm1140|csibm.*|utf-?7-imap)$", re.IGNORECASE)
_EBCDIC_XML_DECL = b"\x4c\x6f\xa7\x94"  # "<?xm" in EBCDIC
_UTF7_BOM = b"+/v"

ACCEPT = (
    "application/rss+xml, application/atom+xml, application/feed+json;q=0.9, "
    "application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5"
)


def _safe_link(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return netguard.normalize_url(value)
    except netguard.UnsafeURLError:
        return None


def xml_guard(content: bytes, content_type: str | None) -> str | None:
    """Return a rejection reason if the document could smuggle entity declarations.

    Defence in depth against XXE / entity expansion ("billion laughs"): feedparser
    already drops unsafe entities, but we refuse such documents outright. The check must
    also hold for documents encoded as UTF-16/32 (NUL bytes between ASCII characters)
    and refuse encodings where the marker is not ASCII at all (UTF-7, EBCDIC).
    """
    if _ENTITY_DECL.search(content):
        return "Rejected: XML entity declarations are not allowed"
    head = content[:4096]
    if b"\x00" in head[:4] or head.startswith((b"\xff\xfe", b"\xfe\xff")):
        if _ENTITY_DECL.search(content.replace(b"\x00", b"")):
            return "Rejected: XML entity declarations are not allowed"
        head = head.replace(b"\x00", b"")
    if head.startswith((_EBCDIC_XML_DECL, _UTF7_BOM)):
        return "Rejected: unsupported character encoding"
    declared = _XML_ENCODING.search(head.lstrip(b"\xef\xbb\xbf\xff\xfe"))
    candidates = [declared.group(1).decode("ascii", "replace")] if declared else []
    header = _CHARSET.search(content_type or "")
    if header:
        candidates.append(header.group(1))
    if any(_UNSAFE_ENCODING.match(c) for c in candidates):
        return "Rejected: unsupported character encoding"
    return None


def _timestamp(entry: dict) -> int | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                return calendar.timegm(parsed)
            except (TypeError, ValueError, OverflowError):
                continue
    return None


def _guid(entry: dict, title: str, ts: int | None) -> str:
    raw = entry.get("id") or entry.get("guid") or entry.get("link")
    if isinstance(raw, str) and raw.strip():
        guid = raw.strip()
        return guid if len(guid) <= 512 else "sha256:" + hashlib.sha256(guid.encode()).hexdigest()
    return "sha256:" + hashlib.sha256(f"{title}|{ts}".encode()).hexdigest()


def _entry_html(entry: dict) -> str:
    contents = entry.get("content") or []
    for item in contents:
        value = item.get("value") if isinstance(item, dict) else None
        if value:
            return value
    return entry.get("summary") or entry.get("description") or ""


def _schedule_next(refresh_minutes: int, error_count: int) -> int:
    base = refresh_minutes * 60
    if error_count:
        base = min(base * (2 ** min(error_count, 6)), MAX_BACKOFF_SECONDS)
    return now() + base


ADAPTIVE_MAX_MINUTES = 12 * 60   # a quiet feed is still checked at least twice a day
ADAPTIVE_WINDOW = 60 * 86400     # posting rhythm learnt from the last 60 days


def adaptive_minutes(db, feed_id: int, default: int) -> int:
    """Refresh interval from how often the feed posts (FreshRSS "AutoTTL" idea): a feed that posts every few days
    does not need checking every hour. Never shorter than the default interval (no extra load on any site), never
    longer than 12 hours."""
    times = [r[0] for r in db.execute(
        "SELECT sort_ts FROM articles WHERE feed_id = ? AND sort_ts > ? ORDER BY sort_ts DESC LIMIT 40",
        (feed_id, now() - ADAPTIVE_WINDOW))]
    if len(times) < 2:
        return max(default, ADAPTIVE_MAX_MINUTES) if times or db.execute(
            "SELECT 1 FROM articles WHERE feed_id = ? LIMIT 1", (feed_id,)).fetchone() else default
    gaps = sorted(a - b for a, b in zip(times, times[1:]) if a > b)
    if not gaps:
        return default
    median_gap_min = gaps[len(gaps) // 2] / 60
    return int(min(max(default, median_gap_min / 4), max(default, ADAPTIVE_MAX_MINUTES)))


def refresh_for(db, feed, prefs: dict) -> int:
    """The feed's interval: its own setting, else the default - adapted to its posting rhythm when enabled."""
    if feed["refresh_minutes"]:
        return int(feed["refresh_minutes"])
    default = int(prefs["default_refresh_minutes"])
    if not prefs.get("adaptive_refresh"):
        return default
    minutes = adaptive_minutes(db, feed["id"], default)
    if feed["adaptive_minutes"] != minutes:
        db.execute("UPDATE feeds SET adaptive_minutes = ? WHERE id = ?", (minutes, feed["id"]))
    return minutes


def _record_error(feed_id: int, refresh: int, error: str, retry_after: int | None = None) -> dict:
    with get_db() as db:
        row = db.execute("SELECT error_count FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        count = (row["error_count"] if row else 0) + 1
        next_fetch = max(_schedule_next(refresh, count), now() + retry_after) if retry_after else _schedule_next(refresh, count)
        db.execute(
            "UPDATE feeds SET error_count = ?, last_error = ?, last_fetched = ?, next_fetch = ? WHERE id = ?",
            (count, error[:500], now(), next_fetch, feed_id),
        )
    log.info("Feed %d failed: %s", feed_id, error)
    return {"ok": False, "error": error, "new": 0}


RATE_LIMIT_WAIT = 15 * 60       # a site that answers 429 is asked again after this (or its Retry-After)
RATE_LIMIT_MAX_WAIT = 6 * 3600


def _rate_limited(feed_id: int, refresh: int, retry_after: str | None) -> dict:
    """HTTP 429: the site wants fewer requests (Reddit does this to anonymous readers). Wait and try again - it is
    not a broken feed, so the error count (and the "failing" warnings) stay as they are."""
    try:
        wait = int(str(retry_after or "").strip())
    except ValueError:
        wait = 0
    wait = min(max(wait, RATE_LIMIT_WAIT), RATE_LIMIT_MAX_WAIT)
    # spread the retries: feeds limited together must not all come back together
    next_fetch = max(now() + wait, _schedule_next(refresh, 0)) + random.randint(0, 600)
    with get_db() as db:
        db.execute("UPDATE feeds SET last_error = ?, last_fetched = ?, next_fetch = ? WHERE id = ?",
                   (f"Rate limited by the site (HTTP 429) - trying again in {(next_fetch - now()) // 60} min", now(),
                    next_fetch, feed_id))
    log.info("Feed %d rate limited (429); next try in %d s", feed_id, wait)
    return {"ok": False, "error": "HTTP 429 (rate limited - will retry)", "new": 0, "rate_limited": True}


def effective_retention(feed, prefs: dict) -> tuple[int, int]:
    """(days, max_articles) for a feed; 0 means unlimited. Per-feed values override the globals."""
    days = feed["retention_days"] if feed["retention_days"] is not None else prefs["retention_days"]
    cap = feed["max_articles"] if feed["max_articles"] is not None else prefs["max_articles_per_feed"]
    return int(days or 0), int(cap or 0)


def insert_article(db, feed_id: int, *, guid: str, url: str | None, title: str, author: str | None,
                   raw_html: str | None, published: int | None, fetched_at: int,
                   ignore_tombstone: bool = False, match_url: bool = True, any_feed: bool = False) -> int | None:
    """Sanitise and store one article. Returns the new id, or None if it already exists.

    Duplicates are detected by GUID and, when a link is present, by URL within the same feed
    (imports from other readers carry different GUIDs for the same story).
    """
    body_html = sanitize_html(raw_html)
    tomb = "" if ignore_tombstone else "AND NOT EXISTS (SELECT 1 FROM article_tombstones WHERE feed_id = ? AND guid = ?) "
    params: list = [feed_id, guid[:600], url, title, author, body_html, to_text(body_html), published, fetched_at,
                    published or fetched_at]
    if not ignore_tombstone:
        params += [feed_id, guid[:600]]
    url_check = ""
    if url and match_url and any_feed:  # a scraped page: skip posts the site's RSS feed (or any feed) already stored
        url_check = "AND NOT EXISTS (SELECT 1 FROM articles WHERE url = ?) "
        params += [url]
    elif url and match_url:  # podcasts: off - many shows link every episode to the same home page
        url_check = "AND NOT EXISTS (SELECT 1 FROM articles WHERE feed_id = ? AND url = ?) "
        params += [feed_id, url]
    cur = db.execute(
        "INSERT INTO articles (feed_id, guid, url, title, author, content_html, text_content, "
        "published, fetched_at, sort_ts) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE 1 "
        f"{tomb}{url_check}ON CONFLICT(feed_id, guid) DO NOTHING",  # fragments are fixed strings
        params,
    )
    return int(cur.lastrowid) if cur.rowcount == 1 else None


PODCAST_MAX_ENTRIES = 20000         # a podcast feed is its whole archive (CyberWire Daily alone lists 3,000+)
PODCAST_MAX_FEED_BYTES = 60 * 1024 * 1024  # ...and long-running daily shows publish big feeds


def store_entries(db, feed_id: int, entries, cutoff: int | None, ts_now: int, on_new=None,
                  podcast: bool = False, page: bool = False, video_of=None) -> list[int]:
    """Store parsed feedparser entries; returns new article ids. ``on_new(db, entry, id, published)``
    runs for each inserted entry (e.g. to store YouTube video metadata). ``podcast``: episodes are matched by
    their id only, and up to PODCAST_MAX_ENTRIES are stored. ``video_of(entry)`` -> the entry's video metadata:
    a video already in the library (from another playlist / channel) is linked to this feed, not copied."""
    new_ids: list[int] = []
    for entry in entries[:PODCAST_MAX_ENTRIES if podcast else MAX_ENTRIES_PER_FETCH]:
        title = to_text(entry.get("title"), 1000) or "(untitled)"
        published = _timestamp(entry)
        if published is not None and published > ts_now + 86400:
            published = ts_now  # clamp bogus future dates
        if cutoff is not None and published is not None and published < cutoff:
            continue
        if video_of is not None and sources.link_existing_video(db, feed_id, video_of(entry)):
            continue  # one copy per video: already stored, now also listed under this feed
        new_id = insert_article(
            db, feed_id, guid=_guid(entry, title, published), url=_safe_link(entry.get("link")), title=title,
            author=to_text(entry.get("author"), 300) or None, raw_html=_entry_html(entry), published=published,
            fetched_at=ts_now, match_url=not podcast, any_feed=page,
        )
        if new_id is not None:
            if on_new is not None:
                on_new(db, entry, new_id, published)
                if video_of is not None and db.execute("SELECT 1 FROM articles WHERE id = ?", (new_id,)).fetchone() is None:
                    continue  # store_video folded it into the copy that already existed
            new_ids.append(new_id)
    return new_ids


def parse_bytes(content: bytes, content_type: str | None, url: str):
    return feedparser.parse(
        io.BytesIO(content),  # never pass a str: feedparser would treat it as a URL/path
        response_headers={"content-type": content_type or "application/xml", "content-location": url},
        sanitize_html=True,
        resolve_relative_uris=True,
    )


def _feed_in_redirect(feed, headers: dict[str, str], cfg):
    """Some sites answer a feed request with a redirect to their home page while still sending the feed itself in the
    redirect's own body (gbhackers.com since 2026-11-24). Following the redirect gives the home page, which is not a
    feed. Then ask once more without following redirects and use that body - only when it really is a feed with
    entries. Same URL, same request: nothing is bypassed, the site's own answer is just read."""
    try:
        first = netguard.request("GET", feed["url"], headers=headers, allow_private=cfg.allow_private_feeds,
                                 timeout=cfg.fetch_timeout, max_bytes=cfg.max_feed_bytes, max_redirects=0)
    except (netguard.FetchError, netguard.UnsafeURLError):
        return None
    if first.status_code not in netguard.REDIRECT_CODES or xml_guard(first.content, first.headers.get("content-type")):
        return None
    parsed = parse_bytes(first.content, first.headers.get("content-type"), first.url)
    if not parsed.get("entries"):
        return None
    log.info("Feed %s: read the feed from the body of its redirect to %s", feed["id"], first.headers.get("location", "?")[:200])
    return first, parsed


def fetch_feed(feed_id: int) -> dict:
    cfg = get_settings()
    with get_db() as db:
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        if feed is None:
            return {"ok": False, "error": "Feed not found", "new": 0}
        prefs = app_settings.get_all(db)
        refresh = refresh_for(db, feed, prefs)
    if (feed["kind"] or "rss") in sources.KINDS:
        return _fetch_source(feed, prefs, refresh)

    accept = {"html": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "json": "application/json,*/*;q=0.5"}
    headers = {"User-Agent": cfg.user_agent, "Accept": accept.get(feed["kind"] or "rss", ACCEPT)}
    if feed["etag"]:
        headers["If-None-Match"] = feed["etag"]
    if feed["last_modified"]:
        headers["If-Modified-Since"] = feed["last_modified"]

    try:
        resp = netguard.request(
            "GET",
            feed["url"],
            headers=headers,
            allow_private=cfg.allow_private_feeds,
            timeout=cfg.fetch_timeout,
            max_bytes=max(cfg.max_feed_bytes, PODCAST_MAX_FEED_BYTES) if feed["kind"] == "podcast" else cfg.max_feed_bytes,
        )
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        return _record_error(feed_id, refresh, str(exc))

    if resp.status_code == 304:
        with get_db() as db:
            db.execute(
                "UPDATE feeds SET last_fetched = ?, next_fetch = ?, error_count = 0, last_error = NULL WHERE id = ?",
                (now(), _schedule_next(refresh, 0), feed_id),
            )
        return {"ok": True, "error": None, "new": 0}
    if resp.status_code == 429:
        return _rate_limited(feed_id, refresh, resp.headers.get("retry-after"))
    if resp.status_code >= 400:
        return _record_error(feed_id, refresh, f"HTTP {resp.status_code}")
    ts_now = now()
    kind = feed["kind"] or "rss"
    if kind in ("rss", "podcast"):
        rejection = xml_guard(resp.content, resp.headers.get("content-type"))
        if rejection:
            return _record_error(feed_id, refresh, rejection)
        parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url)
        if parsed.get("bozo") and not parsed.get("entries") and resp.url != netguard.normalize_url(feed["url"]):
            first = _feed_in_redirect(feed, headers, cfg)
            if first is not None:
                resp, parsed = first
        if parsed.get("bozo") and not parsed.get("entries"):
            return _record_error(feed_id, refresh, "Could not parse feed (not valid RSS/Atom?)")
        entries, feed_meta = parsed.entries, parsed.get("feed", {})
    else:  # scraped web page (HTML + CSS selectors) or JSON API (dotted paths)
        from app import scraper

        try:
            rules = scraper.ScrapeConfig.model_validate_json(feed["scrape"] or "{}")
            items = scraper.extract(resp.content, resp.url, rules, ts_now)
        except (ValueError, scraper.ScrapeError) as exc:
            return _record_error(feed_id, refresh, f"Scraping failed: {str(exc)[:200]}")
        if not items:
            # Usually means the site changed its layout: surface it instead of silently fetching nothing.
            return _record_error(feed_id, refresh, "Scraping rules matched no items - the page layout may have changed")
        entries, feed_meta = [i.to_entry() for i in items], {}

    show_image = (feed_meta.get("image") or {}).get("href") if isinstance(feed_meta.get("image"), dict) else None

    def on_new(db, entry, article_id, published):  # an entry with an audio file (podcast episode): keep its audio
        from app import podcasts

        podcasts.store_episode(db, article_id, entry, podcasts._https(show_image))

    result = _store(feed, prefs, refresh, entries, to_text(feed_meta.get("title"), 300), _safe_link(feed_meta.get("link")),
                    (resp.headers.get("etag") or "")[:200] or None, (resp.headers.get("last-modified") or "")[:100] or None,
                    on_new=on_new)
    if feed["kind"] == "podcast":
        from app import podcasts

        try:  # the show's own categories page (weekly), if it has one we know
            podcasts.sync_categories(feed["id"])
        except Exception:  # optional extra; never fails the fetch
            log.exception("Show categories for feed %d failed", feed["id"])
        from app import podcast_youtube

        try:  # each episode's own YouTube video (channel found once; new videos daily)
            podcast_youtube.sync(feed["id"])
        except Exception:  # optional extra (quota, YouTube down): never fails the fetch
            log.warning("YouTube links for show %d: not this time", feed["id"], exc_info=True)
    if (feed["kind"] or "rss") == "rss" and not feed["social_platform"] and result.get("new"):
        from app import feedkinds

        with get_db() as db:  # an article feed whose items are mostly audio files is a podcast show (e.g. from OPML)
            if feedkinds.check_feed(db, feed["id"]) == "podcast":
                ids = [r[0] for r in db.execute("SELECT id FROM articles WHERE feed_id = ?", (feed["id"],))]
                topics.fill_episode_topics(db, ids)
    if feed["kind"] == "podcast" and result.get("new"):
        with get_db() as db:  # new episodes no keyword matched: their show's topic, else General
            new_ids = [r[0] for r in db.execute("SELECT id FROM articles WHERE feed_id = ? ORDER BY id DESC LIMIT ?", (feed["id"], int(result["new"])))]
            topics.fill_episode_topics(db, new_ids)
    if feed["social_platform"] == "reddit":
        from app import reddit

        try:  # a subreddit's older posts, a few pages per fetch, until its retention / Reddit's ~1000-post limit
            days, _cap = effective_retention(feed, prefs)
            reddit.older_pages(feed["id"], feed["url"], now() - days * 86400 if days else None)
        except Exception:  # optional extra; never fails the fetch
            log.exception("Reddit history for feed %d failed", feed["id"])
    return result


def _fetch_source(feed, prefs: dict, refresh: int) -> dict:
    """YouTube / HF papers / X / Telegram: source-specific fetch, then the normal store pipeline."""
    try:
        got = sources.fetch(feed)
    except sources.SourceError as exc:
        return _record_error(feed["id"], refresh, str(exc), exc.retry_after)

    def on_new(db, entry, article_id, published):
        meta = got.videos.get(entry.get("id"))
        if meta:
            sources.store_video(db, article_id, meta, published)

    result = _store(feed, prefs, refresh, got.entries, got.title, _safe_link(got.site_url), None, None, on_new=on_new,
                    video_of=(lambda e: got.videos.get(e.get("id"))) if got.videos else None)
    with get_db() as db:
        for key, value in got.state.items():
            sources.set_state(db, key, value)
        if got.videos:
            sources.refresh_video_stats(db, got.videos)
    return result


def _store(feed, prefs: dict, refresh: int, entries, meta_title: str | None, site_url: str | None,
           etag: str | None, last_modified: str | None, on_new=None, video_of=None) -> dict:
    feed_id = feed["id"]
    ts_now = now()
    retention_days, _cap = effective_retention(feed, prefs)
    cutoff = ts_now - retention_days * 86400 if retention_days else None

    published: list[int] = []
    with get_db() as db:
        new_ids = store_entries(db, feed_id, entries, cutoff, ts_now, on_new=on_new, podcast=feed["kind"] == "podcast",
                                page=feed["kind"] == "html", video_of=video_of)
        title = feed["title"]
        if not feed["custom_title"]:
            title = meta_title or title or feed["url"]
        db.execute(
            "UPDATE feeds SET title = ?, site_url = COALESCE(?, site_url), etag = ?, last_modified = ?, "
            "last_fetched = ?, next_fetch = ?, error_count = 0, last_error = NULL WHERE id = ?",
            (title, site_url, etag, last_modified, ts_now, _schedule_next(refresh, 0), feed_id),
        )
        from app import declutter

        declutter.clean_new(db, feed, new_ids)  # ads and site promotion out, before the text is indexed
        extract_for_articles(db, new_ids)
        from app import ttp_filing, ttp_subs

        ttp_subs.assign(db, new_ids)  # sub-techniques named next to their technique
        from app import reports

        published = reports.assign(db, new_ids)  # 📑 advisories, guidance and reports
        ttp_filing.file(db, new_ids)  # tactic collections, from the techniques the articles name
        stories.assign(db, new_ids)  # same story from several sources -> one story_id
        topics.classify(db, new_ids)
        topics.fill_video_topics(db, new_ids)
        events = apply_rules(db, new_ids)
        from app import fulltext

        fulltext.queue_new(db, feed, new_ids)  # summary-only items: fetch the article page in the background
        from app import translate

        translate.queue_new(db, feed, new_ids)  # titles in another language -> the AI provider, in the background

    if published:
        reports.notify(published)
    if events:
        webhooks.dispatch(events)
        from app import alerts

        alerts.article_alerts(events)  # instant alerts + AI auto-summaries for rule matches
    if new_ids:
        log.info("Feed %d: %d new articles", feed_id, len(new_ids))
    return {"ok": True, "error": None, "new": len(new_ids)}


def run_retention() -> None:
    """Remove old/excess articles; starred or manually-filed articles are always kept."""
    with get_db() as db:
        prefs = app_settings.get_all(db)
        ts = now()
        keep = (  # never pruned: starred, filed by hand, in one of your video groups, or a video another feed also lists
            "is_starred = 0 AND id NOT IN "
            "(SELECT article_id FROM article_tags WHERE source = 'manual') "
            "AND id NOT IN (SELECT article_id FROM video_group_items) "
            "AND NOT EXISTS (SELECT 1 FROM video_links l WHERE l.article_id = articles.id AND l.feed_id != articles.feed_id)"
        )
        g_days, g_cap = int(prefs["retention_days"] or 0), int(prefs["max_articles_per_feed"] or 0)
        # Per feed: feeds.retention_days / max_articles override the globals (NULL = global, 0 = keep forever).
        days_expr = "COALESCE((SELECT retention_days FROM feeds f WHERE f.id = articles.feed_id), ?)"
        cond = f"{keep} AND {days_expr} > 0 AND sort_ts < ? - {days_expr} * 86400"
        db.execute(
            "INSERT OR IGNORE INTO article_tombstones (feed_id, guid, removed_at) "
            f"SELECT feed_id, guid, ? FROM articles WHERE {cond}",
            (ts, g_days, ts, g_days),
        )
        db.execute(f"DELETE FROM articles WHERE {cond}", (g_days, ts, g_days))
        excess = (
            "SELECT a.id FROM (SELECT id, feed_id, ROW_NUMBER() OVER (PARTITION BY feed_id ORDER BY sort_ts DESC, id DESC) rn "
            f"FROM articles WHERE {keep}) a JOIN feeds f ON f.id = a.feed_id "
            # the global per-feed cap is for article feeds: podcasts and videos keep by time (unless a feed sets its own)
            "WHERE COALESCE(f.max_articles, CASE WHEN f.kind IN ('podcast', 'youtube') THEN 0 ELSE ? END) > 0 "
            "AND a.rn > COALESCE(f.max_articles, CASE WHEN f.kind IN ('podcast', 'youtube') THEN 0 ELSE ? END)"
        )
        db.execute(
            "INSERT OR IGNORE INTO article_tombstones (feed_id, guid, removed_at) "
            f"SELECT feed_id, guid, ? FROM articles WHERE id IN ({excess})",
            (ts, g_cap, g_cap),
        )
        db.execute(f"DELETE FROM articles WHERE id IN ({excess})", (g_cap, g_cap))
        db.execute("DELETE FROM article_tombstones WHERE manual = 0 AND removed_at < ?", (ts - 400 * 86400,))
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (ts,))
    log.debug("Retention pass complete at %s", time.strftime("%Y-%m-%d %H:%M:%S"))
