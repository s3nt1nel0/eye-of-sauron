"""Keyword rules: auto-file articles into collections, star, mark read, fire webhooks.

Keywords are treated as *literal* text (re.escape) with word boundaries, so
user input can never produce a catastrophic-backtracking regex (ReDoS).
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from functools import lru_cache

from app.db import get_db, now, placeholders

MAX_KEYWORDS = 100
MAX_KEYWORD_LENGTH = 100


@lru_cache(maxsize=512)
def compile_keywords(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    terms = [k for k in keywords if k]
    if not terms:
        return None
    alternation = "|".join(re.escape(k) for k in sorted(terms, key=len, reverse=True))
    return re.compile(rf"(?<!\w)(?:{alternation})(?!\w)", re.IGNORECASE)


def parse_keywords(raw: str) -> tuple[str, ...]:
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return ()
    if not isinstance(value, list):
        return ()
    return tuple(str(v)[:MAX_KEYWORD_LENGTH] for v in value[:MAX_KEYWORDS] if str(v).strip())


@dataclass(frozen=True)
class WebhookEvent:
    webhook_id: int
    rule_id: int
    rule_name: str
    article_id: int


@dataclass(frozen=True)
class AlertEvent:
    """A rule matched a new article and asks for an instant alert on a delivery channel."""

    channel_id: int
    rule_id: int
    rule_name: str
    article_id: int
    summarize: bool


@dataclass(frozen=True)
class SummarizeEvent:
    """A rule matched a new article and asks for an AI summary."""

    rule_id: int
    article_id: int


CVE_ID = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
MAX_CVES_PER_ARTICLE = 50


def _scoped(rule: sqlite3.Row) -> bool:
    return rule["feed_id"] is not None or rule["folder_id"] is not None


def _matches(rule: sqlite3.Row, article: sqlite3.Row, cve_info: dict[int, tuple[set, set]] | None = None) -> bool:
    """feed/folder scope AND (any keyword) AND (any required keyword) AND (CVE condition) AND NOT (any excluded).

    A rule with no keywords matches everything in its feed/folder scope, or every article that meets its
    CVE condition; an unscoped rule with neither matches nothing.
    """
    if rule["feed_id"] is not None and rule["feed_id"] != article["feed_id"]:
        return False
    if rule["folder_id"] is not None and rule["folder_id"] != article["folder_id"]:
        return False
    text = article["title"] or ""
    if rule["match_in"] == "title_content":
        text = f"{text}\n{article['text_content'] or ''}"
    keywords = parse_keywords(rule["keywords"])
    severity, owasp = _row_get(rule, "cve_severity"), _row_get(rule, "cve_owasp")
    category = _row_get(rule, "cve_category")
    if keywords:
        include = compile_keywords(keywords)
        where = (article["title"] or "") if _row_get(rule, "keywords_in_title") else text
        if include is None or not include.search(where):
            return False
    elif not (_scoped(rule) or severity or owasp or category):
        return False
    required = compile_keywords(parse_keywords(_row_get(rule, "require_keywords") or "[]"))
    if required is not None and not required.search(text):
        return False
    if severity or owasp or category:
        severities, owasp_codes, cve_cats = (cve_info or {}).get(article["id"], (set(), set(), set()))
        if severity and severity not in severities:
            return False
        if owasp and owasp not in owasp_codes:
            return False
        if category and category not in cve_cats:
            return False
    exclude = compile_keywords(parse_keywords(rule["exclude_keywords"]))
    return not (exclude is not None and exclude.search(text))


def _row_get(row: sqlite3.Row, key: str):
    return row[key] if key in row.keys() else None


def mentioned_cves(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in CVE_ID.finditer(text or ""):
        seen[f"CVE-{m.group(1)}-{m.group(2)}"] = None
        if len(seen) >= MAX_CVES_PER_ARTICLE:
            break
    return list(seen)


KEV_CATEGORIES = ("kev", "kev-ransomware")  # pseudo-categories: in CISA KEV / KEV and used by ransomware


def cve_facts(db: sqlite3.Connection, articles: list[sqlite3.Row]) -> dict[int, tuple[set, set, set]]:
    """article id -> ({severities of the CVEs it mentions}, {'2025:A01', ...} OWASP categories of their CWEs,
    {CVE-tracking category slugs, plus 'kev' / 'kev-ransomware'})."""
    per_article = {a["id"]: mentioned_cves(f"{a['title'] or ''}\n{a['text_content'] or ''}") for a in articles}
    wanted = sorted({c for ids in per_article.values() for c in ids})
    severity: dict[str, str] = {}
    owasp: dict[str, set] = {}
    cats: dict[str, set] = {}
    for start in range(0, len(wanted), 500):
        chunk = wanted[start : start + 500]
        marks = placeholders(len(chunk))
        for row in db.execute(f"SELECT id, severity, kev, kev_ransomware FROM cves WHERE id IN ({marks})", chunk):
            severity[row["id"]] = row["severity"]
            if row["kev"]:
                cats.setdefault(row["id"], set()).add("kev")
            if row["kev_ransomware"]:
                cats.setdefault(row["id"], set()).add("kev-ransomware")
        for row in db.execute(
            f"SELECT m.cve_id, k.slug FROM cve_category_map m JOIN cve_categories k ON k.id = m.category_id "
            f"WHERE k.enabled = 1 AND m.cve_id IN ({marks})", chunk,
        ):
            cats.setdefault(row["cve_id"], set()).add(row["slug"])
        for row in db.execute(
            f"SELECT c.cve_id, o.edition, o.code FROM cve_cwes c JOIN cwe_owasp o ON o.cwe_id = c.cwe_id "
            f"WHERE c.cve_id IN ({marks})", chunk,
        ):
            owasp.setdefault(row["cve_id"], set()).add(f"{row['edition']}:{row['code']}")
    return {
        aid: ({severity[c] for c in ids if c in severity}, set().union(*(owasp.get(c, set()) for c in ids)),
              set().union(*(cats.get(c, set()) for c in ids)))
        for aid, ids in per_article.items()
    }


def refile_tags(tag_ids: list[int]) -> int:
    """After a rule lost keywords: take rule-filed articles out of these collections when none of the collection's
    rules matches them any more. Manually filed articles are never touched. Returns how many were removed."""
    removed = 0
    for tag_id in dict.fromkeys(tag_ids):
        with get_db() as db:
            rules = db.execute("SELECT * FROM rules WHERE tag_id = ?", (tag_id,)).fetchall()  # disabled rules still count
            ids = [r[0] for r in db.execute("SELECT article_id FROM article_tags WHERE tag_id = ? AND source = 'rule'", (tag_id,))]
        needs_cves = any(_row_get(r, "cve_severity") or _row_get(r, "cve_owasp") or _row_get(r, "cve_category") for r in rules)
        for start in range(0, len(ids), 500):
            chunk = ids[start : start + 500]
            with get_db() as db:
                articles = db.execute(
                    "SELECT a.id, a.feed_id, a.title, a.text_content, f.folder_id "
                    f"FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id IN ({placeholders(len(chunk))})", chunk).fetchall()
                facts = cve_facts(db, articles) if needs_cves else None
                drop = [a["id"] for a in articles if not any(_matches(r, a, facts) for r in rules)]
                if drop:
                    db.execute(f"DELETE FROM article_tags WHERE tag_id = ? AND source = 'rule' AND article_id IN ({placeholders(len(drop))})",
                               [tag_id, *drop])
                    removed += len(drop)
    return removed


def apply_rules(
    db: sqlite3.Connection, article_ids: list[int], rule_ids: list[int] | None = None
) -> list[WebhookEvent | AlertEvent | SummarizeEvent]:
    if not article_ids:
        return []
    if rule_ids:
        rules = db.execute(
            f"SELECT * FROM rules WHERE enabled = 1 AND id IN ({placeholders(len(rule_ids))}) ORDER BY position, id",
            rule_ids,
        ).fetchall()
    else:
        rules = db.execute("SELECT * FROM rules WHERE enabled = 1 ORDER BY position, id").fetchall()
    if not rules:
        return []
    needs_cves = any(_row_get(r, "cve_severity") or _row_get(r, "cve_owasp") or _row_get(r, "cve_category") for r in rules)

    events: list[WebhookEvent | AlertEvent | SummarizeEvent] = []
    ts = now()
    for start in range(0, len(article_ids), 500):
        chunk = article_ids[start : start + 500]
        articles = db.execute(
            "SELECT a.id, a.feed_id, a.title, a.text_content, f.folder_id "
            f"FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id IN ({placeholders(len(chunk))})",
            chunk,
        ).fetchall()
        facts = cve_facts(db, articles) if needs_cves else None
        for article in articles:
            for rule in rules:
                if not _matches(rule, article, facts):
                    continue
                if rule["tag_id"] is not None:
                    db.execute(
                        "INSERT OR IGNORE INTO article_tags (article_id, tag_id, source, created_at) "
                        "VALUES (?, ?, 'rule', ?)",
                        (article["id"], rule["tag_id"], ts),
                    )
                if rule["star"]:
                    db.execute(
                        "UPDATE articles SET is_starred = 1, starred_at = COALESCE(starred_at, ?) WHERE id = ?",
                        (ts, article["id"]),
                    )
                if rule["mark_read"]:
                    db.execute("UPDATE articles SET is_read = 1 WHERE id = ?", (article["id"],))
                if rule["webhook_id"] is not None:
                    events.append(WebhookEvent(rule["webhook_id"], rule["id"], rule["name"], article["id"]))
                if rule["ai_summarize"]:
                    events.append(SummarizeEvent(rule["id"], article["id"]))
                if rule["alert_channel_id"] is not None:
                    events.append(AlertEvent(rule["alert_channel_id"], rule["id"], rule["name"], article["id"],
                                             bool(rule["ai_summarize"])))
    return events
