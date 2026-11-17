"""Story grouping: articles from different sources that report the same story share a story_id.

How it works (no network, no AI):
  * A title is reduced to its significant words (lower-case, without filler words).
  * Two articles are the same story when they come from *different* feeds, were published within a few days of
    each other and their titles share most of those words (Jaccard overlap; the threshold is the "how alike"
    setting). Titles that carry different long numbers (two different CVE IDs, two different case numbers) are
    never merged, and very short titles are left alone.
  * articles.story_id is the id of the first article of the story; NULL = on its own.

Only Reader articles are grouped (not videos, podcast episodes or account posts).
New articles are grouped as they arrive (assign); rebuild() regroups everything, in the background, after the
setting changes.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
from collections import deque

from app import app_settings
from app.cve_sync import get_state, set_state
from app.db import get_db, now, placeholders

log = logging.getLogger("feedwarden.stories")

REV = 1
WINDOW = 4 * 86400
MIN_WORDS = 4
MIN_SHARED = 3
THRESHOLDS = {"strict": 0.75, "normal": 0.6, "loose": 0.5}
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
YEAR = re.compile(r"^(19|20)\d\d$")
STOP = frozenset("""
a an the and or but nor of in on at to for from by with without into onto over under after before about against
between during through via per as is are was were be been being it its this that these those their his her our your
has have had will would can could may might should must do does did not no new now how why what when where who which
says said say report reports reported reportedly according amid here there than then more most just also still
you we they he she us them out up down off all any some after again update updated
""".split())
ELIGIBLE = "COALESCE(f.kind, 'rss') NOT IN ('youtube', 'podcast') AND f.social_platform IS NULL"  # fixed SQL fragment


def words(title: str) -> frozenset[str]:
    return frozenset(w for w in (t.lower() for t in TOKEN.findall(title or "")) if w not in STOP and (len(w) > 1 or w.isdigit()))


def _long_numbers(ws: frozenset[str]) -> frozenset[str]:
    return frozenset(w for w in ws if w.isdigit() and len(w) >= 4 and not YEAR.match(w))


def same_story(a: frozenset[str], b: frozenset[str], threshold: float) -> float:
    """Overlap score (0 = not the same story)."""
    if len(a) < MIN_WORDS or len(b) < MIN_WORDS:
        return 0.0
    shared = len(a & b)
    if shared < MIN_SHARED:
        return 0.0
    score = shared / len(a | b)
    if score < threshold:
        return 0.0
    na, nb = _long_numbers(a), _long_numbers(b)
    if na and nb and not (na & nb):
        return 0.0  # two different CVEs / case numbers with otherwise similar wording
    return score


class _Index:
    """Recent articles by word, for finding candidates without comparing against everything."""

    def __init__(self) -> None:
        self.docs: dict[int, tuple[int, frozenset[str], int]] = {}  # id -> (feed_id, words, ts)
        self.story: dict[int, int | None] = {}
        self.start: dict[int, int] = {}                             # story id -> when its first article appeared
        self.postings: dict[str, set[int]] = {}
        self.order: deque[tuple[int, int]] = deque()                # (ts, id), oldest first

    def add(self, aid: int, feed_id: int, ws: frozenset[str], ts: int, story: int | None) -> None:
        if aid in self.docs:
            return
        self.docs[aid] = (feed_id, ws, ts)
        self.story[aid] = story
        if story is not None:
            self.start[story] = min(self.start.get(story, ts), ts)
        for w in ws:
            self.postings.setdefault(w, set()).add(aid)
        self.order.append((ts, aid))

    def prune(self, before: int) -> None:
        while self.order and self.order[0][0] < before:
            _, aid = self.order.popleft()
            doc = self.docs.pop(aid, None)
            self.story.pop(aid, None)  # self.start is kept: it is what stops a story from chaining on
            if doc:
                for w in doc[1]:
                    ids = self.postings.get(w)
                    if ids:
                        ids.discard(aid)
                        if not ids:
                            del self.postings[w]

    def best(self, feed_id: int, ws: frozenset[str], ts: int, threshold: float) -> int | None:
        if len(ws) < MIN_WORDS:
            return None
        shared: dict[int, int] = {}
        for w in ws:
            for other in self.postings.get(w, ()):
                shared[other] = shared.get(other, 0) + 1
        best_id, best_score = None, 0.0
        for other, n in shared.items():
            if n < MIN_SHARED:
                continue
            ofeed, ows, ots = self.docs[other]
            if ofeed == feed_id or abs(ts - ots) > WINDOW:
                continue
            ostory = self.story.get(other)
            if ostory is not None and ts - self.start.get(ostory, ots) > WINDOW:
                continue  # a story ends a few days after it began: recurring headlines must not chain for weeks
            score = same_story(ws, ows, threshold)
            if score > best_score or (score == best_score and score and other < (best_id or other + 1)):
                best_id, best_score = other, score
        return best_id


_lock = threading.Lock()
_live: _Index | None = None


def _prefs(db: sqlite3.Connection) -> tuple[bool, float]:
    prefs = app_settings.get_all(db)
    return bool(prefs["story_grouping"]), THRESHOLDS[prefs["story_match"]]


def _join(db: sqlite3.Connection, index: _Index, aid: int, feed_id: int, ws: frozenset[str], ts: int, threshold: float) -> int | None:
    """Put one article into the index and return its story id (None = on its own)."""
    other = index.best(feed_id, ws, ts, threshold)
    story = None
    if other is not None:
        story = index.story.get(other) or other
        index.start.setdefault(story, index.docs[other][2])
        if index.story.get(other) is None:
            index.story[other] = story
            db.execute("UPDATE articles SET story_id = ? WHERE id = ?", (story, other))
    index.add(aid, feed_id, ws, ts, story)
    return story


def assign(db: sqlite3.Connection, article_ids: list[int]) -> None:
    """Called by the fetcher, inside its transaction, for newly stored articles."""
    global _live
    if not article_ids:
        return
    on, threshold = _prefs(db)
    if not on:
        return
    with _lock:
        rows = db.execute(
            "SELECT a.id, a.feed_id, a.title, a.sort_ts FROM articles a JOIN feeds f ON f.id = a.feed_id "
            f"WHERE a.id IN ({placeholders(len(article_ids))}) AND {ELIGIBLE} ORDER BY a.sort_ts, a.id",  # nosec B608 - fixed fragments
            article_ids).fetchall()
        if not rows:
            return
        if _live is None:
            _live = _Index()
            new = set(article_ids)
            for r in db.execute(
                    "SELECT a.id, a.feed_id, a.title, a.sort_ts, a.story_id FROM articles a JOIN feeds f ON f.id = a.feed_id "
                    f"WHERE a.sort_ts >= ? AND {ELIGIBLE} ORDER BY a.sort_ts, a.id", (now() - 2 * WINDOW,)):  # nosec B608
                if r["id"] not in new:
                    _live.add(r["id"], r["feed_id"], words(r["title"]), r["sort_ts"], r["story_id"])
        _live.prune(now() - 2 * WINDOW)
        for r in rows:
            story = _join(db, _live, r["id"], r["feed_id"], words(r["title"]), r["sort_ts"], threshold)
            if story is not None:
                db.execute("UPDATE articles SET story_id = ? WHERE id = ?", (story, r["id"]))


def reset_live() -> None:
    global _live
    with _lock:
        _live = None


# ------------------------------------------------------------------ regroup everything
class Rebuilder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False
        self.again = False

    def start(self) -> bool:
        with self._lock:
            if self.running:
                self.again = True
                return False
            self.running = True
        threading.Thread(target=self._run, name="story-rebuild", daemon=True).start()
        return True

    def _run(self) -> None:
        try:
            while True:
                rebuild()
                with self._lock:
                    if not self.again:
                        return
                    self.again = False
        except Exception:
            log.exception("Story regrouping failed")
        finally:
            self.running = False


rebuilder = Rebuilder()


def _wanted(db: sqlite3.Connection) -> str:
    on, _ = _prefs(db)
    return f"{REV}:{app_settings.get_all(db)['story_match']}" if on else "off"


def rebuild() -> dict:
    """Regroup every stored article with the current setting (short transactions; the app stays usable)."""
    with get_db() as db:
        on, threshold = _prefs(db)
        wanted = _wanted(db)
        ids = [r[0] for r in db.execute(
            f"SELECT a.id FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE {ELIGIBLE} ORDER BY a.sort_ts, a.id")] if on else []  # nosec B608
    for start in range(0, 10**9, 20000):  # clear in slices so writers are never blocked for long
        with get_db() as db:
            if db.execute("UPDATE articles SET story_id = NULL WHERE id IN "
                          "(SELECT id FROM articles WHERE story_id IS NOT NULL LIMIT 20000)").rowcount == 0:
                break
    index = _Index()
    grouped = 0
    for start in range(0, len(ids), 2000):
        chunk = ids[start : start + 2000]
        with get_db() as db:
            rows = db.execute(f"SELECT id, feed_id, title, sort_ts FROM articles WHERE id IN ({placeholders(len(chunk))}) "
                              "ORDER BY sort_ts, id", chunk).fetchall()
            for r in rows:
                index.prune(r["sort_ts"] - WINDOW)
                story = _join(db, index, r["id"], r["feed_id"], words(r["title"]), r["sort_ts"], threshold)
                if story is not None:
                    db.execute("UPDATE articles SET story_id = ? WHERE id = ?", (story, r["id"]))
                    grouped += 1
    reset_live()
    with get_db() as db:
        set_state(db, "stories_rev", wanted)
    log.info("Stories regrouped: %d of %d articles joined a story", grouped, len(ids))
    return {"articles": len(ids), "grouped": grouped}


def ensure_current() -> bool:
    """Start a regroup when the stored grouping was made with another setting (or never)."""
    with get_db() as db:
        stale = get_state(db, "stories_rev", "") != _wanted(db)
    return rebuilder.start() if stale else False


def status() -> dict:
    with get_db() as db:
        row = db.execute("SELECT COUNT(DISTINCT story_id) AS stories, COUNT(story_id) AS articles FROM articles "
                         "WHERE story_id IS NOT NULL").fetchone()
    return {"running": rebuilder.running, "stories": row["stories"], "articles": row["articles"]}


# ------------------------------------------------------------------ for the article list
def attach(db: sqlite3.Connection, articles: list[dict]) -> None:
    """a["story_count"] = how many articles share the article's story (1 = on its own)."""
    ids = sorted({a["story_id"] for a in articles if a.get("story_id")})
    counts: dict[int, int] = {}
    for start in range(0, len(ids), 400):
        chunk = ids[start : start + 400]
        for r in db.execute(f"SELECT story_id, COUNT(*) AS n FROM articles WHERE story_id IN ({placeholders(len(chunk))}) "
                            "GROUP BY story_id", chunk):
            counts[r["story_id"]] = r["n"]
    for a in articles:
        a["story_count"] = counts.get(a.get("story_id") or 0, 1)


def members(db: sqlite3.Connection, article_id: int, limit: int = 60) -> list[dict] | None:
    row = db.execute("SELECT story_id FROM articles WHERE id = ?", (article_id,)).fetchone()
    if row is None:
        return None
    if row["story_id"] is None:
        return []
    return [dict(r) for r in db.execute(
        "SELECT a.id, a.title, a.url, a.sort_ts, a.is_read, f.title AS feed_title FROM articles a JOIN feeds f ON f.id = a.feed_id "
        "WHERE a.story_id = ? ORDER BY a.sort_ts, a.id LIMIT ?", (row["story_id"], limit))]
