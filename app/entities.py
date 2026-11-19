"""Entity extraction: maps articles to the watchlist entities they mention.

Matching is done on *tokens*, not regexes: text and aliases are split into
alphanumeric tokens and looked up as n-grams in hash maps. Cost is linear in
the text length, independent of the number of aliases, and user input can
never create a pathological pattern (no ReDoS).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading

from app.db import get_db, placeholders
from app.entities_seed import BUILTIN_WATCHLISTS

log = logging.getLogger("eos.entities")

TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
MAX_ALIAS_TOKENS = 8
MAX_TEXT_TOKENS = 6000          # title + first ~6000 words of content
MAX_ALIASES = 40
MAX_ALIAS_LENGTH = 80
MAX_ENTITIES_PER_LIST = 1000
MAX_WATCHLISTS = 50
SEED_FLAG = "builtin_watchlists_seeded"


# --------------------------------------------------------------------------- aliases
def alias_key(alias: str) -> tuple[bool, tuple[str, ...]] | None:
    """Return (case_sensitive, tokens) for an alias, or None if it has no usable tokens."""
    forced = alias.startswith("=")
    raw = alias[1:] if forced else alias
    tokens = TOKEN.findall(raw)
    if not tokens or len(tokens) > MAX_ALIAS_TOKENS:
        return None
    letters = [c for c in raw if c.isalpha()]
    case_sensitive = forced or (bool(letters) and all(c.isupper() for c in letters))
    if case_sensitive:
        return True, tuple(tokens)
    return False, tuple(t.lower() for t in tokens)


def clean_aliases(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values[:MAX_ALIASES]:
        value = " ".join(str(value).split())[:MAX_ALIAS_LENGTH]
        if value and alias_key(value) is not None and value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


class Matcher:
    def __init__(self, rows: list[tuple]) -> None:
        self.ci: dict[tuple[str, ...], set[int]] = {}
        self.cs: dict[tuple[str, ...], set[int]] = {}
        self.first_ci: set[str] = set()
        self.first_cs: set[str] = set()
        self.max_n = 1
        for entity_id, name, aliases_json, *rest in rows:
            try:
                aliases = json.loads(aliases_json)
            except (TypeError, ValueError):
                aliases = []
            try:  # names the user muted ("stop matching this name"): skipped here, kept in the alias list
                muted = {str(m).lower() for m in json.loads(rest[0])} if rest and rest[0] else set()
            except (TypeError, ValueError):
                muted = set()
            for alias in [name, *[a for a in aliases if isinstance(a, str)]]:
                if alias.lower() in muted:
                    continue
                key = alias_key(alias)
                if key is None:
                    continue
                case_sensitive, tokens = key
                table, first = (self.cs, self.first_cs) if case_sensitive else (self.ci, self.first_ci)
                table.setdefault(tokens, set()).add(entity_id)
                first.add(tokens[0])
                self.max_n = max(self.max_n, len(tokens))

    @property
    def empty(self) -> bool:
        return not self.ci and not self.cs

    def match(self, text: str) -> set[int]:
        tokens = TOKEN.findall(text)[:MAX_TEXT_TOKENS]
        lower = [t.lower() for t in tokens]
        found: set[int] = set()
        count = len(tokens)
        for i in range(count):
            check_ci = lower[i] in self.first_ci
            check_cs = tokens[i] in self.first_cs
            if not (check_ci or check_cs):
                continue
            for n in range(1, min(self.max_n, count - i) + 1):
                if check_ci:
                    hit = self.ci.get(tuple(lower[i : i + n]))
                    if hit:
                        found |= hit
                if check_cs:
                    hit = self.cs.get(tuple(tokens[i : i + n]))
                    if hit:
                        found |= hit
        return found


# --------------------------------------------------------------------------- cache
_cache_lock = threading.Lock()
_version = 0
_cached: tuple[int, Matcher] | None = None


def invalidate() -> None:
    global _version
    with _cache_lock:
        _version += 1


def _load_matcher(db: sqlite3.Connection, entity_ids: list[int] | None = None) -> Matcher:
    if entity_ids:
        rows = db.execute(
            f"SELECT id, name, aliases, muted FROM entities WHERE id IN ({placeholders(len(entity_ids))})", entity_ids
        ).fetchall()
    else:
        rows = db.execute("SELECT id, name, aliases, muted FROM entities").fetchall()
    return Matcher([(r["id"], r["name"], r["aliases"], r["muted"]) for r in rows])


def get_matcher(db: sqlite3.Connection) -> Matcher:
    global _cached
    with _cache_lock:
        version = _version
        if _cached is not None and _cached[0] == version:
            return _cached[1]
    matcher = _load_matcher(db)
    with _cache_lock:
        if version == _version:
            _cached = (version, matcher)
    return matcher


# --------------------------------------------------------------------------- extraction
def _index_articles(db: sqlite3.Connection, matcher: Matcher, article_ids: list[int]) -> int:
    inserted = 0
    for start in range(0, len(article_ids), 500):
        chunk = article_ids[start : start + 500]
        rows = db.execute(
            f"SELECT id, title, substr(text_content, 1, 60000) AS body FROM articles "
            f"WHERE id IN ({placeholders(len(chunk))})",
            chunk,
        ).fetchall()
        rejected = {(r[0], r[1]) for r in db.execute(
            f"SELECT article_id, entity_id FROM entity_rejections WHERE article_id IN ({placeholders(len(chunk))})", chunk)}
        pairs = []
        for row in rows:
            for entity_id in matcher.match(f"{row['title']}\n{row['body']}"):
                if (row["id"], entity_id) not in rejected:
                    pairs.append((row["id"], entity_id))
        if pairs:
            db.executemany("INSERT OR IGNORE INTO article_entities (article_id, entity_id) VALUES (?, ?)", pairs)
            inserted += len(pairs)
    return inserted


def matched_aliases(db: sqlite3.Connection, entity_id: int, article_id: int) -> list[str]:
    """Which of an entity's names occur in an article (why it was matched)."""
    ent = db.execute("SELECT aliases, muted FROM entities WHERE id = ?", (entity_id,)).fetchone()
    art = db.execute("SELECT title, substr(text_content, 1, 60000) AS body FROM articles WHERE id = ?", (article_id,)).fetchone()
    if ent is None or art is None:
        return []
    text = f"{art['title']}\n{art['body']}"
    muted = {str(m).lower() for m in json.loads(ent["muted"] or "[]")}
    return [a for a in json.loads(ent["aliases"]) if isinstance(a, str) and a.lower() not in muted
            and Matcher([(1, a, "[]")]).match(text)]


def extract_for_articles(db: sqlite3.Connection, article_ids: list[int]) -> None:
    """Called by the fetcher, inside its transaction, for newly stored articles."""
    if not article_ids:
        return
    matcher = get_matcher(db)
    if not matcher.empty:
        _index_articles(db, matcher, article_ids)


# --------------------------------------------------------------------------- background reindex
class Reindexer:
    """Single background worker; requests are coalesced."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._pending_all = False
        self._pending: set[int] = set()
        self._thread: threading.Thread | None = None
        self.running = False

    def request(self, entity_ids: list[int] | None = None) -> None:
        with self._cond:
            if entity_ids is None:
                self._pending_all = True
            else:
                self._pending.update(entity_ids)
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="entity-reindex", daemon=True)
                self._thread.start()
            self._cond.notify()

    @property
    def busy(self) -> bool:
        with self._cond:
            return self.running or self._pending_all or bool(self._pending)

    def _run(self) -> None:
        while True:
            with self._cond:
                if not self._pending_all and not self._pending:
                    self.running = False
                    return
                do_all, ids = self._pending_all, sorted(self._pending)
                self._pending_all, self._pending = False, set()
                self.running = True
            try:
                self._reindex(None if do_all else ids)
            except Exception:
                log.exception("Entity reindex failed")
            try:  # sub-techniques recognised next to their technique, then the tactic collections (both read the index)
                from app import ttp_filing, ttp_subs

                ttp_subs.after_reindex(None if do_all else ids)
                ttp_filing.refile_all()
            except Exception:
                log.exception("Re-filing the tactic collections failed")

    @staticmethod
    def _reindex(entity_ids: list[int] | None) -> None:
        invalidate()
        with get_db() as db:
            if entity_ids is None:
                db.execute("DELETE FROM article_entities")
            else:
                entity_ids = [r[0] for r in db.execute(
                    f"SELECT id FROM entities WHERE id IN ({placeholders(len(entity_ids))})", entity_ids)]
                if not entity_ids:
                    return
                db.execute(
                    f"DELETE FROM article_entities WHERE entity_id IN ({placeholders(len(entity_ids))})", entity_ids
                )
            matcher = _load_matcher(db, entity_ids)
            article_ids = [r[0] for r in db.execute("SELECT id FROM articles ORDER BY id")]
        if matcher.empty:
            return
        total = 0
        # Separate short transactions so the fetcher/UI are never blocked for long.
        for start in range(0, len(article_ids), 2000):
            with get_db() as db:
                total += _index_articles(db, matcher, article_ids[start : start + 2000])
        log.info("Entity index rebuilt (%s): %d mentions over %d articles",
                 "all" if entity_ids is None else f"{len(entity_ids)} entities", total, len(article_ids))


reindexer = Reindexer()


# --------------------------------------------------------------------------- seeding
SEEDED_SLUGS_KEY = "builtin_watchlist_slugs"
# Lists that existed before seeding became versioned (0.9). Installs seeded earlier had all of these.
LEGACY_SLUGS = ["ransomware-groups", "threat-actors", "ai-threats", "countries", "sectors", "vendors", "malware-families"]


def seed_builtin_watchlists() -> bool:
    """Create built-in watchlists that this install has not received yet. Returns True if any were created.

    Each built-in list is offered exactly once: the slugs already offered are remembered in
    settings, so a list the user deleted is not re-created, while lists added in a newer
    version appear automatically after an upgrade.
    """
    created = False
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (SEEDED_SLUGS_KEY,)).fetchone()
        if row is not None:
            offered = set(json.loads(row["value"]))
        elif db.execute("SELECT 1 FROM settings WHERE key = ?", (SEED_FLAG,)).fetchone():
            offered = set(LEGACY_SLUGS)  # seeded by a pre-0.9 version
        else:
            offered = set()
        for position, (slug, name, description, entities) in enumerate(BUILTIN_WATCHLISTS):
            if slug in offered:
                continue
            offered.add(slug)
            db.execute(
                "INSERT OR IGNORE INTO watchlists (name, slug, description, position) VALUES (?, ?, ?, ?)",
                (name, slug, description, position),
            )
            wid = db.execute("SELECT id FROM watchlists WHERE slug = ?", (slug,)).fetchone()
            if wid is None:  # a user list already uses that name
                continue
            created = True
            for entity_name, aliases in entities:
                db.execute(
                    "INSERT OR IGNORE INTO entities (watchlist_id, name, aliases) VALUES (?, ?, ?)",
                    (wid["id"], entity_name, json.dumps(clean_aliases(aliases))),
                )
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (SEEDED_SLUGS_KEY, json.dumps(sorted(offered))))
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, 'true')", (SEED_FLAG,))
    if created:
        invalidate()
    return created
