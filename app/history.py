"""Getting *older* articles in: history back-fill for one feed or many.

An RSS/Atom document only carries the latest items (usually 10-50), so history has to come from
elsewhere. In order of preference:

* **Paged / archived feeds** - RFC 5005 ``rel="next"`` / ``rel="prev-archive"`` links, then the paging
  conventions of common platforms: Blogger (``start-index``), Ghost (``/rss/2/``), WordPress
  (``?paged=N``) and a generic ``?page=N``. A pager is only used when its page 2 really contains items
  page 1 doesn't (many servers silently ignore unknown parameters).
* **Internet Archive (Wayback Machine)** - most public feeds have been captured regularly for years.
  The public CDX API lists the captures of *the feed's own URL*; we walk back through them, each
  capture covering the window of items the feed listed that day. Captures are fetched in raw
  (``id_``) mode, so links point at the original articles.
* **Source-specific history** - YouTube (Data API), Hugging Face daily papers, Telegram.

Every document goes through the same SSRF guard, XML guard, parser and sanitiser as normal refreshes.
Back-filled articles get entity extraction, topics and rules (collections, stars), but never fire
webhooks or alerts - those are for genuinely new articles.
"""

from __future__ import annotations

import bisect
import calendar
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from app import app_settings, netguard, sources, topics
from app.config import get_settings
from app.db import get_db, now
from app.entities import extract_for_articles
from app.fetcher import (PODCAST_MAX_FEED_BYTES, _guid, _timestamp, effective_retention, parse_bytes, store_entries,
                         xml_guard, ACCEPT)
from app.rules import apply_rules
from app.sanitize import to_text

log = logging.getLogger("eos.history")

MAX_BACKFILL_PAGES = 1000  # YouTube: 50 videos a page = 50,000 (playlists hold at most 5,000)
METHODS = ("auto", "paged", "wayback")
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW = "https://web.archive.org/web/{stamp}id_/{url}"
WAYBACK_DELAY = 1.5     # seconds between archive requests - be a polite client
PAGE_DELAY = 1.0        # seconds between pages on the publisher's own site
BULK_FEED_DELAY = 1.0
GAP_DAYS = 60           # a hole this long in a feed's history counts as "history starts here"
MAX_BULK_RESULTS = 500
_STAMP = re.compile(r"^\d{14}$")


class Job:
    """One background job at a time per kind; progress is polled by the UI."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.stop = threading.Event()
        self.status: dict[str, Any] = {"state": "idle"}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, target, *args) -> bool:
        with self._lock:
            if self.running:
                return False
            self.stop.clear()
            self.status = {"state": "running", "started": now()}
            self._thread = threading.Thread(target=self._wrap, args=(target, *args), name=f"history-{self.kind}", daemon=True)
            self._thread.start()
            return True

    def update(self, **kw: Any) -> None:
        self.status = {**self.status, **kw}

    def _wrap(self, target, *args) -> None:
        try:
            target(self, *args)
            self.update(state="done" if not self.stop.is_set() else "cancelled", finished=now())
        except ImportError_ as exc:
            self.update(state="error", error=str(exc)[:300], finished=now())
        except Exception:
            log.exception("History job %s crashed", self.kind)
            self.update(state="error", error="Unexpected error (see server log)", finished=now())


class ImportError_(Exception):  # noqa: N801 - avoid shadowing the builtin ImportError
    """User-facing failure (message is safe to show)."""


backfill_job = Job("backfill")


def default_options(**overrides: Any) -> dict[str, Any]:
    opts = {"max_pages": 20, "method": "auto", "since_days": None, "keep_forever": False}
    opts.update(overrides)
    return opts


def _post_process(db, ids: list[int]) -> None:
    if ids:
        extract_for_articles(db, ids)
        topics.classify(db, ids)
        topics.fill_video_topics(db, ids)
        apply_rules(db, ids)  # events are discarded: no webhooks/alerts for history


def _feed_bytes(feed, cfg) -> int:
    """Size limit for one document of this feed: podcast feeds (a show's whole archive) may be much bigger."""
    return max(cfg.max_feed_bytes, PODCAST_MAX_FEED_BYTES) if (feed["kind"] or "") == "podcast" else cfg.max_feed_bytes


def _get(url: str, cfg, *, timeout: float | None = None, max_bytes: int | None = None) -> netguard.SafeResponse:
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": ACCEPT},
                                allow_private=cfg.allow_private_feeds, timeout=timeout or cfg.fetch_timeout,
                                max_bytes=max_bytes or cfg.max_feed_bytes)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise ImportError_(str(exc)) from None
    if resp.status_code >= 400:
        raise ImportError_(f"HTTP {resp.status_code}")
    reason = xml_guard(resp.content, resp.headers.get("content-type"))
    if reason:
        raise ImportError_(reason)
    return resp


def _parse(resp: netguard.SafeResponse, *, trust_content_type: bool = True, base: str | None = None):
    ctype = resp.headers.get("content-type") if trust_content_type else None
    return parse_bytes(resp.content, ctype, base or resp.url)


def _entry_keys(entries) -> set[str]:
    keys = set()
    for e in entries:
        title = to_text(e.get("title"), 1000) or "(untitled)"
        keys.add(_guid(e, title, _timestamp(e)))
    return keys


def _oldest(entries) -> int | None:
    stamps = [t for t in (_timestamp(e) for e in entries) if t]
    return min(stamps) if stamps else None


# =========================================================================== one feed
def backfill_feed(job: Job, feed_id: int, opts: dict) -> None:
    """Fetch older articles for one feed (``opts``: max_pages, method, since_days, keep_forever)."""
    feed, cutoff = _prepare(feed_id, opts)
    job.update(feed_id=feed_id, feed_title=feed["title"], pages=0, new=0, method=None)
    _backfill_one(job, feed, opts, cutoff)


def _is_playlist(feed) -> bool:
    if (feed["kind"] or "") != "youtube":
        return False
    try:
        return bool(json.loads(feed["source"] or "{}").get("playlist_id"))
    except (ValueError, AttributeError):
        return False


def _prepare(feed_id: int, opts: dict):
    with get_db() as db:
        if opts.get("keep_days") is not None:
            # Keep… in Videos: the feed keeps this time frame (0 = everything) and the videos retention or an earlier
            # Keep… removed may come back (videos you removed with 🗑 stay removed).
            db.execute("UPDATE feeds SET retention_days = ?, max_articles = 0 WHERE id = ?", (int(opts["keep_days"]), feed_id))
            db.execute("DELETE FROM article_tombstones WHERE feed_id = ? AND manual = 0", (feed_id,))
        elif opts.get("keep_forever"):
            # Keep what we fetch: lift this feed's age/count limits and forget articles that retention removed
            # (their tombstones would otherwise stop them being stored again).
            db.execute("UPDATE feeds SET retention_days = 0, max_articles = 0 WHERE id = ?", (feed_id,))
            db.execute("DELETE FROM article_tombstones WHERE feed_id = ? AND manual = 0", (feed_id,))  # yours stay removed
        # Older items the retention clean-up removed earlier may come back now that you ask for them; items you
        # deleted yourself (manual tombstones) stay removed.
        db.execute("DELETE FROM article_tombstones WHERE feed_id = ? AND manual = 0", (feed_id,))
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        if feed is None:
            raise ImportError_("Feed not found")
        whole = bool(opts.get("whole_playlists")) and _is_playlist(feed)
        if whole:
            # A playlist is a hand-picked set: keep every video in it, whatever the time frame chosen for channels.
            db.execute("UPDATE feeds SET retention_days = 0, max_articles = 0 WHERE id = ?", (feed_id,))
            db.execute("DELETE FROM article_tombstones WHERE feed_id = ? AND manual = 0", (feed_id,))
            feed = db.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        prefs = app_settings.get_all(db)
    days, _ = effective_retention(feed, prefs)
    cutoff = now() - days * 86400 if days else None
    if opts.get("since_days") and not whole:
        since = now() - int(opts["since_days"]) * 86400
        cutoff = max(cutoff or 0, since)
    return feed, cutoff


def _backfill_one(job: Job, feed, opts: dict, cutoff: int | None) -> None:
    kind = feed["kind"] or "rss"
    max_pages = int(opts.get("max_pages") or 20)
    if kind in sources.KINDS:
        return _backfill_source(job, feed, max_pages, cutoff)
    if kind == "podcast":
        # A podcast feed is usually the show's whole archive: read all of it again first (episodes an earlier
        # time frame or the old 3,000-episode cap left out). Many shows list only their latest 100-300, so the
        # show's own older pages and the Internet Archive follow, as for article feeds.
        _reread_podcast(job, feed, cutoff)
        if job.stop.is_set():
            return
    elif kind != "rss":
        raise ImportError_("Scraped web pages have no older pages to fetch - only what the page shows now.")
    method = opts.get("method") or "auto"
    if method in ("auto", "paged"):
        found = _backfill_paged(job, feed, max_pages, cutoff)
        if found or method == "paged":
            if not found:
                raise ImportError_("This feed does not offer older pages (no archive links, and none of the "
                                   "WordPress / Blogger / Ghost / ?page=N paging styles work). "
                                   "Try the Internet Archive method instead.")
            if job.status.get("new") or method == "paged":
                return
            # The site pages back, but we already had all of it: the archive may reach further.
    if job.stop.is_set():
        return
    _backfill_wayback(job, feed, max_pages, cutoff)


# --------------------------------------------------------------------------- paging on the site itself
def _with_params(url: str, **params: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in params]
    query += list(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _archive_link(parsed) -> str | None:
    for link in (parsed.get("feed", {}) or {}).get("links", []) or []:
        if isinstance(link, dict) and link.get("rel") in ("next", "prev-archive") and isinstance(link.get("href"), str):
            try:
                return netguard.normalize_url(link["href"])
            except netguard.UnsafeURLError:
                return None
    return None


BLOGGER_PAGE = 100


def _pagers(url: str) -> list[tuple[str, Any]]:
    """Candidate page-URL builders for this feed URL, most specific first. Each maps page number -> URL."""
    path = urlsplit(url).path
    out: list[tuple[str, Any]] = []
    if "/feeds/posts/" in path:
        out.append(("blogger", lambda n: _with_params(url, **{"start-index": str(1 + (n - 1) * BLOGGER_PAGE),
                                                            "max-results": str(BLOGGER_PAGE)})))
    if re.search(r"/rss/?$", path):
        base = urlunsplit(urlsplit(url)._replace(path=path.rstrip("/") + "/", query="", fragment=""))
        out.append(("ghost", lambda n: f"{base}{n}/"))
    out.append(("paged", lambda n: _with_params(url, paged=str(n))))
    out.append(("page", lambda n: _with_params(url, page=str(n))))
    return out


def _store(feed_id: int, entries, cutoff: int | None) -> int:
    with get_db() as db:
        row = db.execute("SELECT kind FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        podcast = bool(row) and row["kind"] == "podcast"
        on_new = None
        if podcast:  # an episode keeps its audio (and art: its own, else the show's)
            from app import podcasts

            art = db.execute("SELECT e.image FROM episodes e JOIN articles a ON a.id = e.article_id WHERE a.feed_id = ? "
                             "AND e.image IS NOT NULL ORDER BY a.sort_ts DESC LIMIT 1", (feed_id,)).fetchone()

            def on_new(db, entry, article_id, published):
                podcasts.store_episode(db, article_id, entry, art[0] if art else None)
        new_ids = store_entries(db, feed_id, entries, cutoff, now(), on_new=on_new, podcast=podcast)
        _post_process(db, new_ids)
        if podcast and new_ids:
            topics.fill_episode_topics(db, new_ids)
    return len(new_ids)


def _reread_podcast(job: Job, feed, cutoff: int | None) -> None:
    cfg = get_settings()
    job.update(method="feed")
    parsed = _parse(_get(feed["url"], cfg, max_bytes=_feed_bytes(feed, cfg)))
    added = _store(feed["id"], parsed.entries, cutoff)
    job.update(pages=1, new=(job.status.get("new") or 0) + added, reached=_oldest(parsed.entries))


def _backfill_paged(job: Job, feed, max_pages: int, cutoff: int | None) -> bool:
    """Walk the site's own older pages. Returns False if the site offers none."""
    cfg = get_settings()
    feed_id = feed["id"]
    big = _feed_bytes(feed, cfg)
    first = _parse(_get(feed["url"], cfg, max_bytes=big))
    total = _store(feed_id, first.entries, cutoff) + (job.status.get("new") or 0)
    nxt = _archive_link(first)
    if nxt:
        job.update(method="rfc5005")
        pages, seen = 0, {feed["url"]}
        while nxt and nxt not in seen and pages < max_pages and not job.stop.is_set():
            seen.add(nxt)
            time.sleep(PAGE_DELAY)
            try:
                parsed = _parse(_get(nxt, cfg, max_bytes=big))
            except ImportError_:
                break
            pages += 1
            total += _store(feed_id, parsed.entries, cutoff)
            job.update(pages=pages, new=total)
            oldest = _oldest(parsed.entries)
            if cutoff and oldest and oldest < cutoff:
                break
            nxt = _archive_link(parsed)
        log.info("Back-filled feed %d via rfc5005: %d older articles", feed_id, total)
        return True

    page1 = _entry_keys(first.entries)
    for name, page_url in _pagers(feed["url"]):
        if job.stop.is_set():
            return True
        time.sleep(PAGE_DELAY)
        try:
            probe = _parse(_get(page_url(2), cfg, max_bytes=big))
        except ImportError_:
            continue
        if not probe.entries or not (_entry_keys(probe.entries) - page1):
            continue  # parameter ignored (same items again) or nothing there
        job.update(method=name)
        total += _store(feed_id, probe.entries, cutoff)
        job.update(pages=1, new=total)
        previous, empty_streak = _entry_keys(probe.entries), 0
        for n in range(3, max_pages + 2):
            oldest = _oldest(probe.entries)
            if job.stop.is_set() or (cutoff and oldest and oldest < cutoff):
                break
            time.sleep(PAGE_DELAY)
            try:
                probe = _parse(_get(page_url(n), cfg, max_bytes=big))
            except ImportError_:
                break
            keys = _entry_keys(probe.entries)
            if not probe.entries or keys == previous:
                break  # past the last page (empty, or the server repeats its last page)
            previous = keys
            added = _store(feed_id, probe.entries, cutoff)
            total += added
            job.update(pages=n - 1, new=total)
            empty_streak = empty_streak + 1 if not added else 0
            if empty_streak >= 3:
                break  # reached what we already have
        log.info("Back-filled feed %d via %s: %d older articles", feed_id, name, total)
        return True
    if total:
        job.update(new=total)
    return False


# --------------------------------------------------------------------------- Internet Archive
def _history_start(feed_id: int) -> int:
    """Where the feed's continuous history begins: walking back from the newest article, the first gap
    longer than GAP_DAYS ends it. A few stray very old items don't count as 'already have that period'."""
    with get_db() as db:
        rows = [r[0] for r in db.execute(
            "SELECT sort_ts FROM articles WHERE feed_id = ? ORDER BY sort_ts DESC LIMIT 20000", (feed_id,))]
    if not rows:
        return now()
    start = rows[0]
    for ts in rows[1:]:
        if start - ts > GAP_DAYS * 86400:
            break
        start = ts
    return start


def wayback_captures(url: str, since: int | None) -> list[int]:
    """Unix times of the archive's captures of ``url`` (at most one per day), oldest first."""
    cfg = get_settings()
    params = {"url": url, "output": "json", "fl": "timestamp,statuscode", "filter": "statuscode:200",
              "collapse": "timestamp:8", "limit": "20000"}
    if since:
        params["from"] = time.strftime("%Y%m%d", time.gmtime(max(since - 30 * 86400, 0)))
    try:
        resp = netguard.request("GET", f"{WAYBACK_CDX}?{urlencode(params)}", headers={"User-Agent": cfg.user_agent},
                                timeout=90, max_bytes=8 * 1024 * 1024)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise ImportError_(f"Internet Archive: {exc}") from None
    if resp.status_code == 429:
        raise ImportError_("The Internet Archive is rate-limiting requests - try again in a few minutes.")
    if resp.status_code >= 400:
        raise ImportError_(f"Internet Archive: HTTP {resp.status_code}")
    if not resp.content.strip():
        return []
    try:
        rows = json.loads(resp.content)
    except ValueError:
        raise ImportError_("Internet Archive returned an unexpected answer") from None
    out: set[int] = set()
    for row in rows[1:] if isinstance(rows, list) else []:
        if isinstance(row, list) and row and isinstance(row[0], str) and _STAMP.match(row[0]):
            try:
                out.add(calendar.timegm(time.strptime(row[0], "%Y%m%d%H%M%S")))
            except ValueError:
                continue
    return sorted(out)


def _backfill_wayback(job: Job, feed, max_pages: int, cutoff: int | None) -> None:
    cfg = get_settings()
    feed_id, url = feed["id"], feed["url"]
    job.update(method="wayback")
    captures = wayback_captures(url, cutoff)
    if not captures:
        raise ImportError_("The Internet Archive has no saved copies of this feed"
                           + (" for that period." if cutoff else "."))
    idx = bisect.bisect_right(captures, _history_start(feed_id)) - 1
    total = job.status.get("new") or 0
    pages = 0
    while idx >= 0 and pages < max_pages and not job.stop.is_set():
        snap = captures[idx]
        if cutoff and snap < cutoff:
            break  # this copy and every older one only list items from before the chosen period
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(snap))
        # The capture URL is built from our own feed URL and a validated timestamp - never from archive output.
        snap_url = WAYBACK_RAW.format(stamp=stamp, url=quote(url, safe=":/?&=%#@+,;~"))
        if pages:
            time.sleep(WAYBACK_DELAY)
        try:
            resp = _get(snap_url, cfg, timeout=60, max_bytes=_feed_bytes(feed, cfg))
        except ImportError_ as exc:
            if "HTTP 429" in str(exc):
                job.update(pages=pages, new=total, note="Stopped early: the Internet Archive is rate-limiting.")
                break
            idx -= 1  # skip a broken copy and try the next older one
            continue
        pages += 1
        # Archived copies are often served as text/html; let the parser read the XML's own declaration.
        # Relative IDs and links resolve against the feed's own address, as on a normal refresh: an episode's ID is
        # then the same in the live feed and in every archived copy (no duplicates).
        entries = _parse(resp, trust_content_type=False, base=url).entries
        total += _store(feed_id, entries, cutoff)
        job.update(pages=pages, new=total, reached=snap)
        oldest = _oldest(entries)
        # Next: the earliest copy taken at or after the oldest item this copy listed. It still overlaps this
        # one (so nothing in between is missed) while reaching as far back as possible; copies in between
        # would only repeat items we have. If there is none, step to the next older copy (a gap the
        # archive simply didn't capture).
        nxt = bisect.bisect_left(captures, oldest) if oldest else idx
        idx = nxt if nxt < idx else idx - 1
    log.info("Back-filled feed %d via the Internet Archive: %d older articles from %d copies", feed_id, total, pages)


# --------------------------------------------------------------------------- source-specific history
def _backfill_source(job: Job, feed, max_pages: int, cutoff: int | None) -> None:
    """History for YouTube (Data API), HF Daily Papers (by day) and Telegram (paging back)."""
    try:
        cfg = sources.parse_config(feed["source"])
    except (ValueError, TypeError):
        raise ImportError_("Source settings are invalid - edit the feed") from None
    feed_id, total = feed["id"], 0

    def store(entries, videos=None) -> int:
        def on_new(db, entry, article_id, published):
            meta = (videos or {}).get(entry.get("id"))
            if meta:
                sources.store_video(db, article_id, meta, published)

        # In batches: store_entries caps one call at MAX_ENTRIES_PER_FETCH (a safety limit for live feeds), which used
        # to cut a big channel/playlist back-fill off after 500 videos. Short transactions keep the app responsive.
        added = 0
        for start in range(0, len(entries), 500):
            with get_db() as db:
                new_ids = store_entries(db, feed_id, entries[start : start + 500], cutoff, now(), on_new=on_new,
                                        video_of=(lambda e: videos.get(e.get("id"))) if videos else None)
                _post_process(db, new_ids)
            added += len(new_ids)
        return added

    try:
        if isinstance(cfg, sources.YouTubeSource) and cfg.saved:
            raise ImportError_("Saved videos are added one at a time - there is no channel to page through.")
        if isinstance(cfg, sources.YouTubeSource):
            key = sources.yt_key()
            if not key:
                raise ImportError_("YouTube history needs a YouTube Data API key (Settings → Integrations → YouTube). "
                                   "Without one, only the latest 15 videos are available.")
            job.update(method="youtube-api")
            pairs = sources.youtube_backfill(cfg, key, max_pages * 50, job.stop.is_set, since=cutoff)
            total = store([p[0] for p in pairs], {p[0]["id"]: p[1] for p in pairs})
            job.update(pages=(len(pairs) + 49) // 50, new=total)
        elif isinstance(cfg, sources.HFPapersSource):
            job.update(method="hf-daily")
            day = datetime.now(timezone.utc) - timedelta(days=2)
            for page in range(1, max_pages + 1):
                if job.stop.is_set() or (cutoff and day.timestamp() < cutoff):
                    break
                total += store(sources.hf_fetch_day(day.strftime("%Y-%m-%d"), cfg.min_upvotes))
                job.update(pages=page, new=total)
                day -= timedelta(days=1)
                time.sleep(1)
        elif isinstance(cfg, sources.TelegramSource):
            job.update(method=f"telegram-{cfg.via}")
            cursor: int | None = None  # oldest message id seen so far; pages go further back from it
            for page in range(1, max_pages + 1):
                if job.stop.is_set():
                    break
                if cfg.via == "account":
                    from app import telegram_mt

                    got = telegram_mt.account.fetch(cfg, feed_id, offset_id=cursor or 0, limit=100, history=True)
                    entries, nxt = got.entries, got.cursor
                else:
                    _, entries, nxt = sources.tg_web_page(cfg.channel, before=cursor)
                total += store(entries)
                job.update(pages=page, new=total)
                if not nxt or (cursor is not None and nxt >= cursor):
                    break  # no older messages
                cursor = nxt
                oldest = min((calendar.timegm(e["published_parsed"]) for e in entries if e.get("published_parsed")), default=None)
                if cutoff and oldest and oldest < cutoff:
                    break
                time.sleep(1.5)
        else:
            raise ImportError_("History back-fill is not available for X (bridges only show recent posts and the "
                               "official API charges per post read).")
    except sources.SourceError as exc:
        raise ImportError_(str(exc)) from None


# =========================================================================== many feeds
def bulk_feed_ids(folder_id: int | None, only_missing: bool, since_days: int | None, keep_days: int | None = None) -> list[int]:
    """Feeds a bulk back-fill should visit: enabled RSS and history-capable sources (not X, not scraped pages).
    ``only_missing`` skips feeds whose history already reaches back to the chosen period."""
    clauses = ["enabled = 1", "COALESCE(kind, 'rss') IN ('rss', 'youtube', 'hfpapers', 'telegram')", "url != ?"]
    params: list[Any] = [sources.SAVED_VIDEOS_URL]
    if folder_id is not None:
        clauses.append("folder_id = ?")
        params.append(folder_id)
    with get_db() as db:
        ids = [r[0] for r in db.execute(f"SELECT id FROM feeds WHERE {' AND '.join(clauses)} ORDER BY id", params)]  # nosec B608 - fixed clauses
    back = keep_days if keep_days is not None else since_days  # keep & fetch back (one setting) wins
    if not only_missing:
        return ids
    if not back:  # "everything": feeds whose history is under 5 years are worth a visit
        back = 5 * 365
    target = now() - int(back) * 86400 + 14 * 86400  # two weeks' slack
    return [i for i in ids if _history_start(i) > target]


def backfill_many(job: Job, feed_ids: list[int], opts: dict) -> None:
    job.update(bulk=True, total=len(feed_ids), done=0, new_total=0, failed=0, results=[])
    results: list[dict[str, Any]] = []
    new_total = failed = 0
    for n, feed_id in enumerate(feed_ids, 1):
        if job.stop.is_set():
            break
        result: dict[str, Any] = {"feed_id": feed_id}
        try:
            feed, cutoff = _prepare(feed_id, opts)
        except ImportError_:
            continue  # deleted meanwhile
        result["title"] = feed["title"]
        job.update(feed_id=feed_id, feed_title=feed["title"], current=n, pages=0, new=0, method=None, note=None)
        try:
            _backfill_one(job, feed, opts, cutoff)
        except ImportError_ as exc:
            result["error"] = str(exc)[:200]
            failed += 1
        except Exception:
            log.exception("Bulk back-fill crashed on feed %d", feed_id)
            result["error"] = "Unexpected error (see server log)"
            failed += 1
        result.update(new=job.status.get("new") or 0, method=job.status.get("method"))
        new_total += result["new"]
        results.append(result)
        job.update(done=n, new_total=new_total, failed=failed, results=results[-MAX_BULK_RESULTS:])
        if n < len(feed_ids):
            time.sleep(BULK_FEED_DELAY)
    log.info("Bulk back-fill: %d feeds, %d older articles, %d failed", len(results), new_total, failed)
