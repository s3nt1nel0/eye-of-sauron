"""Story grouping: articles from different sources that report the same story share a story_id.

How it works (no network, no AI):
  * Two articles can only be the same story when they come from *different* feeds and were published within a few
    days of each other. Titles that carry different long numbers (two case numbers), or articles whose title and
    opening lines name different CVE IDs, are never merged; very short titles are left alone.
  * Then any of three tests joins them (the "how alike" setting sets how strict each one is):
      1. the titles share most of their words (plain word overlap - the original rule);
      2. the titles share most of their *rare* words: words are reduced to a simple stem ("Bulgarian" / "Bulgaria",
         "hackers" / "hacker", "five" / "5") and each counts by how rare it is among the last week's articles,
         so "Fortinet" or "Bulgaria" weigh far more than "hackers" or "flaw";
      3. the titles share at least one rare word and enough weight, AND the title plus the first ~40 words of the
         two articles say much the same (cosine of rare-word weights) - this catches re-worded headlines of one story.
  * articles.story_id is the id of the first article of the story; NULL = on its own.

Only Reader articles are grouped (not videos, podcast episodes or account posts).
New articles are grouped as they arrive (assign); rebuild() regroups everything, in the background, after the
setting (or this matcher, REV) changes.
"""

from __future__ import annotations

import logging
import math
import re
import sqlite3
import threading
from collections import deque

from app import app_settings
from app.cve_sync import get_state, set_state
from app.db import get_db, now, placeholders

log = logging.getLogger("eos.stories")

REV = 2
WINDOW = 4 * 86400
KEEP = 2 * WINDOW            # how far back the index looks (word rarity is measured over this span)
MIN_WORDS = 4
MIN_SHARED = 3
THRESHOLDS = {"strict": 0.75, "normal": 0.6, "loose": 0.5}
# per "how alike" setting: (weighted title overlap, opening-lines cosine (0 = off), min shared title weight,
#                           a shared title word must be in at most this many recent articles)
PROFILES = {"strict": (0.65, 0.0, 0.0, 0), "normal": (0.5, 0.40, 14.0, 12), "loose": (0.42, 0.36, 10.0, 16)}
LEAD_WORDS = 40              # opening words of the article compared in test 3
LEAD_CHARS = 700             # read at most this much text per article (bounded work, whatever the feed sends)
MIN_DOCS = 300               # word rarity is never judged against fewer articles than this
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
YEAR = re.compile(r"^(19|20)\d\d$")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
STOP = frozenset("""
a an the and or but nor of in on at to for from by with without into onto over under after before about against
between during through via per as is are was were be been being it its this that these those their his her our your
has have had will would can could may might should must do does did not no new now how why what when where who which
says said say report reports reported reportedly according amid here there than then more most just also still
you we they he she us them out up down off all any some after again update updated
""".split())
ELIGIBLE = "COALESCE(f.kind, 'rss') NOT IN ('youtube', 'podcast') AND f.social_platform IS NULL"  # fixed SQL fragment
LEAD_SQL = f"substr(COALESCE(a.text_content, ''), 1, {LEAD_CHARS}) AS lead"                         # fixed SQL fragment
NUMBER_WORDS = {"one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
                "eight": "8", "nine": "9", "ten": "10", "twelve": "12", "twenty": "20", "hundred": "100"}
IRREGULAR = {"stole": "steal", "stolen": "steal", "spies": "spy", "spying": "spy", "led": "lead", "found": "find",
             "took": "take", "taken": "take", "children": "child", "men": "man", "says": "say"}


def words(title: str) -> frozenset[str]:
    return frozenset(w for w in (t.lower() for t in TOKEN.findall(title or "")) if w not in STOP and (len(w) > 1 or w.isdigit()))


def stem(w: str) -> str:
    """A deliberately small stemmer: plurals, -ing/-ed, country adjectives (Bulgarian -> bulgar), number words."""
    if w in NUMBER_WORDS:
        return NUMBER_WORDS[w]
    if w in IRREGULAR:
        return IRREGULAR[w]
    if w.isdigit() or len(w) <= 3:
        return w
    for suffix, repl, keep in (("ies", "y", 3), ("ing", "", 4), ("ied", "y", 3), ("ed", "", 4), ("es", "", 4), ("s", "", 3)):
        if w.endswith(suffix) and len(w) - len(suffix) >= keep and not w.endswith("ss"):
            w = w[: -len(suffix)] + repl
            break
    for suffix in ("ians", "ian", "ia", "ese"):
        if w.endswith(suffix) and len(w) - len(suffix) >= 4:
            return w[: -len(suffix)]
    return w


def stems(text: str, limit: int | None = None) -> list[str]:
    out: list[str] = []
    for t in TOKEN.finditer(text or ""):
        w = t.group(0).lower()
        if w in STOP or (len(w) < 2 and not w.isdigit()):
            continue
        out.append(stem(w))
        if limit is not None and len(out) >= limit:
            break
    return out


class Doc:
    """What the matcher keeps of one article."""

    __slots__ = ("raw", "title", "bag", "cves")

    def __init__(self, title: str, text: str = "") -> None:
        lead = (text or "")[:LEAD_CHARS]
        self.raw = words(title)                       # test 1 + the long-number guard
        self.title = frozenset(stems(title))          # test 2
        self.bag = self.title | frozenset(stems(lead, LEAD_WORDS))  # test 3
        self.cves = frozenset(m.group(0).upper() for m in CVE.finditer(f"{title or ''} {lead}"))


def _long_numbers(ws: frozenset[str]) -> frozenset[str]:
    return frozenset(w for w in ws if w.isdigit() and len(w) >= 4 and not YEAR.match(w))


def same_story(a: frozenset[str], b: frozenset[str], threshold: float) -> float:
    """Test 1, plain title-word overlap (0 = not the same story)."""
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
    """Recent articles by title word (for finding candidates) and how many recent articles use each word."""

    def __init__(self) -> None:
        self.docs: dict[int, tuple[int, Doc, int]] = {}            # id -> (feed_id, doc, ts)
        self.story: dict[int, int | None] = {}
        self.start: dict[int, int] = {}                             # story id -> when its first article appeared
        self.postings: dict[str, set[int]] = {}                     # title stem -> ids
        self.df: dict[str, int] = {}                                # stem -> how many recent articles use it
        self.order: deque[tuple[int, int]] = deque()                # (ts, id), oldest first

    def add(self, aid: int, feed_id: int, doc: Doc, ts: int, story: int | None) -> None:
        if aid in self.docs:
            return
        self.docs[aid] = (feed_id, doc, ts)
        self.story[aid] = story
        if story is not None:
            self.start[story] = min(self.start.get(story, ts), ts)
        for w in doc.title:
            self.postings.setdefault(w, set()).add(aid)
        for w in doc.bag:
            self.df[w] = self.df.get(w, 0) + 1
        self.order.append((ts, aid))

    def prune(self, before: int) -> None:
        while self.order and self.order[0][0] < before:
            _, aid = self.order.popleft()
            item = self.docs.pop(aid, None)
            self.story.pop(aid, None)  # self.start is kept: it is what stops a story from chaining on
            if item is None:
                continue
            doc = item[1]
            for w in doc.title:
                ids = self.postings.get(w)
                if ids:
                    ids.discard(aid)
                    if not ids:
                        del self.postings[w]
            for w in doc.bag:
                n = self.df.get(w, 0) - 1
                if n > 0:
                    self.df[w] = n
                else:
                    self.df.pop(w, None)

    def best(self, feed_id: int, doc: Doc, ts: int, threshold: float, profile: tuple = PROFILES["normal"]) -> int | None:
        if len(doc.title) < MIN_WORDS or len(doc.raw) < MIN_WORDS:
            return None
        title_th, lead_th, min_weight, rare_df = profile
        total = max(len(self.docs), MIN_DOCS)
        weights: dict[str, float] = {}

        def weight(w: str) -> float:
            v = weights.get(w)
            if v is None:
                v = weights[w] = math.log((total + 1) / (1 + self.df.get(w, 0)))
            return v

        candidates: set[int] = set()
        for w in doc.title:
            candidates.update(self.postings.get(w, ()))
        mine = _long_numbers(doc.raw)
        best_id, best_score = None, 0.0
        for other in candidates:
            ofeed, odoc, ots = self.docs[other]
            if ofeed == feed_id or abs(ts - ots) > WINDOW or len(odoc.title) < MIN_WORDS:
                continue
            ostory = self.story.get(other)
            if ostory is not None and ts - self.start.get(ostory, ots) > WINDOW:
                continue  # a story ends a few days after it began: recurring headlines must not chain for weeks
            theirs = _long_numbers(odoc.raw)
            if (mine and theirs and not (mine & theirs)) or (doc.cves and odoc.cves and not (doc.cves & odoc.cves)):
                continue  # different case numbers / CVE IDs: different stories, however alike the wording
            score = 0.0
            plain = same_story(doc.raw, odoc.raw, threshold)
            if plain:
                score = 2.0 + plain                                   # test 1 ranks first
            else:
                shared = doc.title & odoc.title
                if len(shared) < 2:
                    continue
                shared_w = sum(weight(w) for w in shared)
                union_w = sum(weight(w) for w in doc.title | odoc.title)
                title_score = shared_w / union_w if union_w else 0.0
                if title_score >= title_th:
                    score = 1.0 + title_score                         # test 2
                elif lead_th and shared_w >= min_weight and any(self.df.get(w, 0) <= rare_df for w in shared):
                    common = doc.bag & odoc.bag
                    num = sum(weight(w) ** 2 for w in common)
                    den = math.sqrt(sum(weight(w) ** 2 for w in doc.bag) * sum(weight(w) ** 2 for w in odoc.bag))
                    cosine = num / den if den else 0.0
                    if cosine >= lead_th:
                        score = cosine                                # test 3
            if score > best_score or (score == best_score and score and other < (best_id or other + 1)):
                best_id, best_score = other, score
        return best_id


_lock = threading.Lock()
_live: _Index | None = None


def _prefs(db: sqlite3.Connection) -> tuple[bool, float, tuple]:
    prefs = app_settings.get_all(db)
    return bool(prefs["story_grouping"]), THRESHOLDS[prefs["story_match"]], PROFILES[prefs["story_match"]]


def _join(db: sqlite3.Connection, index: _Index, aid: int, feed_id: int, doc: Doc, ts: int, threshold: float,
          profile: tuple) -> int | None:
    """Put one article into the index and return its story id (None = on its own)."""
    other = index.best(feed_id, doc, ts, threshold, profile)
    story = None
    if other is not None:
        story = index.story.get(other) or other
        index.start.setdefault(story, index.docs[other][2])
        if index.story.get(other) is None:
            index.story[other] = story
            db.execute("UPDATE articles SET story_id = ? WHERE id = ?", (story, other))
    index.add(aid, feed_id, doc, ts, story)
    return story


def assign(db: sqlite3.Connection, article_ids: list[int]) -> None:
    """Called by the fetcher, inside its transaction, for newly stored articles."""
    global _live
    if not article_ids:
        return
    on, threshold, profile = _prefs(db)
    if not on:
        return
    with _lock:
        rows = db.execute(
            f"SELECT a.id, a.feed_id, a.title, a.sort_ts, {LEAD_SQL} FROM articles a JOIN feeds f ON f.id = a.feed_id "
            f"WHERE a.id IN ({placeholders(len(article_ids))}) AND {ELIGIBLE} ORDER BY a.sort_ts, a.id",  # nosec B608 - fixed fragments
            article_ids).fetchall()
        if not rows:
            return
        if _live is None:
            _live = _Index()
            new = set(article_ids)
            for r in db.execute(
                    f"SELECT a.id, a.feed_id, a.title, a.sort_ts, a.story_id, {LEAD_SQL} FROM articles a JOIN feeds f ON f.id = a.feed_id "
                    f"WHERE a.sort_ts >= ? AND {ELIGIBLE} ORDER BY a.sort_ts, a.id", (now() - KEEP,)):  # nosec B608
                if r["id"] not in new:
                    _live.add(r["id"], r["feed_id"], Doc(r["title"], r["lead"]), r["sort_ts"], r["story_id"])
        _live.prune(now() - KEEP)
        for r in rows:
            story = _join(db, _live, r["id"], r["feed_id"], Doc(r["title"], r["lead"]), r["sort_ts"], threshold, profile)
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
    on = _prefs(db)[0]
    return f"{REV}:{app_settings.get_all(db)['story_match']}" if on else "off"


def rebuild() -> dict:
    """Regroup every stored article with the current setting (short transactions; the app stays usable)."""
    with get_db() as db:
        on, threshold, profile = _prefs(db)
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
            rows = db.execute(f"SELECT a.id, a.feed_id, a.title, a.sort_ts, {LEAD_SQL} FROM articles a "  # nosec B608 - fixed fragments
                              f"WHERE a.id IN ({placeholders(len(chunk))}) ORDER BY a.sort_ts, a.id", chunk).fetchall()
            for r in rows:
                index.prune(r["sort_ts"] - KEEP)
                story = _join(db, index, r["id"], r["feed_id"], Doc(r["title"], r["lead"]), r["sort_ts"], threshold, profile)
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
