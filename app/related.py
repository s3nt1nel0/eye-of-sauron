"""Videos and podcast episodes related to an article - by what they both mention.

An article names threat actors, malware, techniques, vendors… (the mention index), and its headline usually carries
the name of the thing it is about (a malware family, a victim, a product, a CVE). A video or episode is related when
it names the same specific things. Each shared thing counts by how rare it is (a threat actor named in 40 items says
much more than "Microsoft" named in 11,000) and by its kind: actors, ransomware groups and malware count double,
distinctive headline names once, techniques and vendors only half (they support a match, they never make one alone),
countries / sectors / generic attack types not at all. An item is listed when its score reaches MIN_SCORE - roughly
one rare shared name, or two fairly specific ones.

Read-only, local: the mention index and the full-text index.
"""

from __future__ import annotations

import math
import sqlite3

import re

from app import stories, threat_actors
from app.db import placeholders

MIN_SCORE = 7.0
MAX_SHARE = 0.03            # a name in more than this share of all items says nothing
TITLE_WORDS = 6             # distinctive headline names looked up in the full-text index
TITLE_MAX_DF = 400          # a headline word in more items than this is not distinctive
WORD = re.compile(r"[^\W_]+(?:[-.][^\W_]+)*", re.UNICODE)
KIND_SQL = {"videos": "COALESCE(f.kind, 'rss') = 'youtube'", "podcasts": "f.kind = 'podcast'"}  # fixed SQL fragments
BOOST = {  # by watchlist slug; anything not listed counts 1.0
    **dict.fromkeys(threat_actors.ACTOR_SLUGS, 2.0), "malware-families": 2.0, "ics-malware": 2.0,
    "mitre-attack-techniques": 0.5, "mitre-atlas-techniques": 0.5, "vendors": 0.5,
    "countries": 0.0, "sectors": 0.0, "ot-sectors": 0.0, "ot-context": 0.0, "attack-types": 0.0, "ot-attack-types": 0.0,
    "ai-threats": 0.0,
}


def _units(db: sqlite3.Connection, article_id: int) -> list[dict]:
    """What the article names, as scoring units: {"name", "ids" (entities that stand for it), "weight"}."""
    total = max(1, db.execute("SELECT COALESCE(MAX(id), 1) FROM articles").fetchone()[0])
    units: dict[str, dict] = {}
    for r in db.execute("SELECT e.id, e.name, COALESCE(w.slug, '') AS slug FROM article_entities ae JOIN entities e ON e.id = ae.entity_id "
                        "JOIN watchlists w ON w.id = e.watchlist_id WHERE ae.article_id = ?", (article_id,)):
        boost = BOOST.get(r["slug"], 1.0)
        if not boost:
            continue
        if r["slug"].startswith("mitre-at") and r["slug"].endswith("techniques"):
            m = threat_actors.PAREN.search(r["name"])
            ident = m.group(0).strip(" ()") if m else ""
            if "TA" in ident or ident.count(".") > (1 if ident.startswith("AML.") else 0):
                continue  # tactics say too little; a sub-technique is already counted through its technique
        ids = threat_actors.expand(db, r["id"])
        name = threat_actors.PAREN.sub("", r["name"]) or r["name"]
        key = name.lower()  # the same technique in Enterprise / ICS / Mobile, or one actor in several lists: one unit
        if key in units:
            units[key]["ids"] = sorted(set(units[key]["ids"]) | set(ids))
            units[key]["boost"] = max(units[key]["boost"], boost)
        else:
            units[key] = {"name": name, "ids": ids, "boost": boost}
    out = []
    for u in units.values():
        df = db.execute(f"SELECT COUNT(DISTINCT article_id) FROM article_entities WHERE entity_id IN ({placeholders(len(u['ids']))})",  # nosec B608
                        u["ids"]).fetchone()[0]
        if df < 2 or df > total * MAX_SHARE:
            continue  # only this article names it, or nearly everything does
        out.append({"name": u["name"], "ids": u["ids"], "weight": u["boost"] * math.log(total / df)})
    return out


def _title_names(db: sqlite3.Connection, article_id: int, known: set[str]) -> list[dict]:
    """Coined names in the headline (CoffeeLoader, GeoVision, LOTUSLITE, CVE-2026-1234)
    that few stored items contain: {"name", "match" (full-text query), "weight"}."""
    row = db.execute("SELECT title FROM articles WHERE id = ?", (article_id,)).fetchone()
    if row is None or not row["title"]:
        return []
    total = max(1, db.execute("SELECT COALESCE(MAX(id), 1) FROM articles").fetchone()[0])
    significant = stories.words(row["title"])
    shouting = sum(1 for c in row["title"] if c.isupper()) > 0.5 * max(1, sum(1 for c in row["title"] if c.isalpha()))  # AN ALL-CAPS HEADLINE
    seen: set[str] = set()
    found = []
    for word in WORD.findall(row["title"]):
        low = word.lower()
        tokens = [t.lower() for t in threat_actors.TOKEN.findall(word)]
        letters = [c for c in word if c.isalpha()]
        # a coined name: CamelCase (CoffeeLoader, GeoVision), ALL CAPS (LOTUSLITE) or a CVE ID - a merely capitalised
        # word is not enough (headlines capitalise everything)
        named = low.startswith("cve-") or (len(letters) >= 4 and not shouting and "-" not in word and (
            (word.isupper() and not any(c.isdigit() for c in word)) or (word[0].isupper() and any(c.isupper() for c in word[1:]) and not word.isupper())))
        if not named or len(low) < 4 or low in seen or low in known or not any(t in significant for t in tokens):
            continue
        seen.add(low)
        match = '"' + " ".join(tokens) + '"'
        try:
            df = db.execute("SELECT COUNT(*) FROM articles_fts WHERE articles_fts MATCH ?", (match,)).fetchone()[0]
        except sqlite3.OperationalError:
            continue
        if 2 <= df <= TITLE_MAX_DF:
            found.append({"name": word, "match": match, "weight": math.log(total / df)})
    found.sort(key=lambda u: -u["weight"])
    return found[:TITLE_WORDS]


def _scores(db: sqlite3.Connection, article_id: int) -> dict[str, list[tuple[float, int, list[str]]]]:
    """{"videos": [(score, article id, [shared names, strongest first])], "podcasts": […]} above MIN_SCORE."""
    units = _units(db, article_id)
    words = _title_names(db, article_id, {t for u in units for t in u["name"].lower().split()} | {u["name"].lower() for u in units})
    out: dict[str, list[tuple[float, int, list[str]]]] = {"videos": [], "podcasts": []}
    if not units and not words:
        return out
    unit_of = {eid: i for i, u in enumerate(units) for eid in u["ids"]}
    ids = list(unit_of)
    hits: dict[int, tuple[str, set[int]]] = {}
    for start in range(0, len(ids), 400):
        chunk = ids[start : start + 400]
        for r in db.execute(
                "SELECT ae.article_id, ae.entity_id, CASE WHEN f.kind = 'podcast' THEN 'podcasts' ELSE 'videos' END AS kind "
                "FROM article_entities ae JOIN articles a ON a.id = ae.article_id JOIN feeds f ON f.id = a.feed_id "
                f"WHERE ae.entity_id IN ({placeholders(len(chunk))}) AND f.kind IN ('youtube', 'podcast') AND ae.article_id != ?",  # nosec B608
                [*chunk, article_id]):
            hits.setdefault(r["article_id"], (r["kind"], set()))[1].add(unit_of[r["entity_id"]])
    for w in words:  # headline names, through the full-text index
        index = len(units)
        units.append(w)
        for r in db.execute(
                "SELECT a.id, CASE WHEN f.kind = 'podcast' THEN 'podcasts' ELSE 'videos' END AS kind FROM articles_fts "
                "JOIN articles a ON a.id = articles_fts.rowid JOIN feeds f ON f.id = a.feed_id "
                "WHERE articles_fts MATCH ? AND f.kind IN ('youtube', 'podcast') AND a.id != ? LIMIT 400",
                ("title : " + w["match"], article_id)):  # in the video's / episode's own title: it is about it, not a passing word
            hits.setdefault(r["id"], (r["kind"], set()))[1].add(index)
    for aid, (kind, shared) in hits.items():
        score = sum(units[i]["weight"] for i in shared)
        if score >= MIN_SCORE:
            names = [units[i]["name"] for i in sorted(shared, key=lambda i: -units[i]["weight"])]
            out[kind].append((score, aid, names))
    return out


def counts(db: sqlite3.Connection, article_id: int) -> dict:
    s = _scores(db, article_id)
    return {"videos": len(s["videos"]), "podcasts": len(s["podcasts"])}


def related(db: sqlite3.Connection, article_id: int, kind: str, limit: int = 40) -> dict:
    scored = _scores(db, article_id)[kind]
    if not scored:
        return {"kind": kind, "total": 0, "items": []}
    info = {}
    ids = [aid for _s, aid, _n in scored]
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        for r in db.execute("SELECT a.id, a.feed_id, a.title, a.url, a.sort_ts, a.is_read, f.title AS feed_title FROM articles a "
                            f"JOIN feeds f ON f.id = a.feed_id WHERE a.id IN ({placeholders(len(chunk))})", chunk):  # nosec B608
            info[r["id"]] = dict(r)
    scored.sort(key=lambda x: (-round(x[0], 1), -(info.get(x[1], {}).get("sort_ts") or 0)))
    items = [{**info[aid], "score": round(score, 1), "shared": names[:5]} for score, aid, names in scored[:limit] if aid in info]
    return {"kind": kind, "total": len(scored), "items": items}


def media_filter(db: sqlite3.Connection, entity_id: int | None, days: int, related_to: int | None, kind: str) -> tuple[str, list]:
    """SQL (" AND …", params) that narrows the Videos / Podcasts list to the items that mention an entity (a whole
    threat actor when the entity is one) in the last `days`, and / or to the items related to an article."""
    clause, params = "", []
    if entity_id is not None:
        ids = threat_actors.expand(db, entity_id)
        clause += f" AND EXISTS (SELECT 1 FROM article_entities ae WHERE ae.article_id = a.id AND ae.entity_id IN ({placeholders(len(ids))}))"  # nosec B608
        params += ids
        if days:
            from app.db import now

            clause += " AND a.sort_ts >= ?"
            params.append(now() - days * 86400)
    if related_to is not None:
        ids = [aid for _s, aid, _n in _scores(db, related_to)[kind]][:900]
        clause += f" AND a.id IN ({placeholders(len(ids))})" if ids else " AND 0"  # nosec B608
        params += ids
    return clause, params
