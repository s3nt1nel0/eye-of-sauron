"""ATT&CK / ATLAS tactic collections, filed from the techniques an article names.

An article is in "ATT&CK: Stealth" because it names a technique (or sub-technique) that MITRE lists under
Stealth - or names the tactic itself - never because of a loose keyword. So every filing can show which
technique put it there, and the collections are exactly the tactics of MITRE's current matrices:

  * tactics       table ``attack_tactics`` (id, name, order), written by the ATT&CK and ATLAS syncs from MITRE's
                  data (Enterprise matrix order; ATLAS matrix order);
  * collections   one tag per tactic, "ATT&CK: <Tactic>" / "ATLAS: <Tactic>" in MITRE's spelling. They are
                  created / renamed / removed to follow the matrix - only when the pack is installed (at least
                  one such tag exists), and a collection you filed articles into by hand is never deleted;
  * mapping       ``ttp_entity_tags``: which watchlist entity (technique, sub-technique, tactic) files into
                  which collection;
  * filing        two SQL statements: add the filings the mention index supports, remove the ones it no longer
                  does (source = 'rule'; manual filings are never touched). A collection you took an article out
                  of by hand (``ttp_tag_removed``) is not filed again.

The ATT&CK collections are the Enterprise matrix: only Enterprise techniques file into them. ICS and Mobile
techniques an article names still show as technique chips, without a tactic collection.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading

from app.cve_sync import get_state, set_state
from app.db import get_db, now, placeholders

log = logging.getLogger("eos.ttp")

REV = "1"
ATTACK_SLUG, ATLAS_SLUG = "mitre-attack-techniques", "mitre-atlas-techniques"
FRAMEWORKS = {"attack": ("ATT&CK: ", ATTACK_SLUG, "enterprise-attack", "#475569"),
              "atlas": ("ATLAS: ", ATLAS_SLUG, "atlas", "#7c3aed")}
# "Name (T1566)", "Name (T1566.001)", "Name (TA0001)", "Name (AML.T0051)", "Name (AML.TA0002)"
ANY_ID = re.compile(r"\(((?:AML\.)?TA?\d{4}(?:\.\d{3})?)\)$")
TACTIC_ID = re.compile(r"^(?:AML\.)?TA\d{4}$")
# The matrices as of ATT&CK v20 / ATLAS 2026.10 - only used until a sync has stored MITRE's own list.
DEFAULT_TACTICS = {
    "attack": ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
               "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection",
               "Command and Control", "Exfiltration", "Impact"],
    "atlas": ["Reconnaissance", "Resource Development", "AI Attack Adaptation", "Initial Access", "AI Model Access", "Execution",
              "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
              "Collection", "Command and Control", "Exfiltration", "Impact"],
}
_lock = threading.Lock()


def tactics(db: sqlite3.Connection, fw: str) -> list[dict]:
    """The framework's tactics in matrix order: [{id, name, url}] (id None until a sync has stored MITRE's list)."""
    domain = FRAMEWORKS[fw][2]
    rows = db.execute("SELECT id, name, url FROM attack_tactics WHERE domain = ? ORDER BY position, id", (domain,)).fetchall()
    if rows:
        return [dict(r) for r in rows]
    known = {n.lower() for n in DEFAULT_TACTICS[fw]}
    extra = sorted({t for r in db.execute("SELECT tactics FROM attack_techniques WHERE domain = ?", (domain,))
                    for t in json.loads(r["tactics"] or "[]") if t.lower() not in known})  # a release newer than this list
    return [{"id": None, "name": name, "url": ""} for name in [*DEFAULT_TACTICS[fw], *extra]]


def store_tactics(db: sqlite3.Connection, domain: str, items: list[dict]) -> None:
    """Called by the syncs: replace one domain's tactics ([{id, name, url}] in matrix order)."""
    db.execute("DELETE FROM attack_tactics WHERE domain = ?", (domain,))
    db.executemany("INSERT OR REPLACE INTO attack_tactics (id, name, domain, position, url) VALUES (?, ?, ?, ?, ?)",
                   [(t["id"], t["name"][:80], domain, i, t.get("url") or "") for i, t in enumerate(items)])


def collection_name(fw: str, tactic: str) -> str:
    return FRAMEWORKS[fw][0] + tactic


def installed(db: sqlite3.Connection, fw: str) -> bool:
    return db.execute("SELECT 1 FROM tags WHERE name LIKE ? LIMIT 1", (FRAMEWORKS[fw][0] + "%",)).fetchone() is not None


def _managed_tags(db: sqlite3.Connection, fw: str) -> dict[str, int]:
    """{tactic name (lower): tag id} for the framework's tactic collections that exist."""
    prefix = FRAMEWORKS[fw][0]
    have = {r["name"][len(prefix):].lower(): r["id"] for r in db.execute("SELECT id, name FROM tags WHERE name LIKE ?", (prefix + "%",))}
    return {t["name"].lower(): have[t["name"].lower()] for t in tactics(db, fw) if t["name"].lower() in have}


def sync_collections(db: sqlite3.Connection) -> dict:
    """Bring the tactic collections and the entity -> collection mapping in line with the stored matrices."""
    out = {"created": 0, "renamed": 0, "removed": 0, "rules_removed": 0}
    db.execute("DELETE FROM ttp_entity_tags")
    for fw, (prefix, slug, domain, color) in FRAMEWORKS.items():
        if not installed(db, fw):
            continue
        official = tactics(db, fw)
        if not official:
            continue
        # the keyword rules of earlier versions ("Auto: ATT&CK: Impact", "… #2"): filings now come from techniques
        out["rules_removed"] += db.execute("DELETE FROM rules WHERE name LIKE ?", (f"Auto: {prefix}%",)).rowcount
        existing = {r["name"][len(prefix):].lower(): r for r in db.execute("SELECT id, name FROM tags WHERE name LIKE ?", (prefix + "%",))}
        wanted = {t["name"].lower() for t in official}
        for t in official:
            row = existing.get(t["name"].lower())
            name = collection_name(fw, t["name"])
            if row is None:
                db.execute("INSERT INTO tags (name, color) VALUES (?, ?)", (name, color))
                out["created"] += 1
            elif row["name"] != name:
                db.execute("UPDATE tags SET name = ? WHERE id = ?", (name, row["id"]))
                out["renamed"] += 1
        for key, row in existing.items():
            if key in wanted:
                continue  # a tactic MITRE no longer has (Defense Evasion in Enterprise): the collection goes…
            kept = db.execute("SELECT 1 FROM article_tags WHERE tag_id = ? AND source = 'manual' LIMIT 1", (row["id"],)).fetchone() \
                or db.execute("SELECT 1 FROM rules WHERE tag_id = ? LIMIT 1", (row["id"],)).fetchone()
            if kept:
                continue  # …unless you filed into it by hand or pointed a rule of your own at it
            db.execute("DELETE FROM tags WHERE id = ?", (row["id"],))
            out["removed"] += 1
        tags = _managed_tags(db, fw)
        by_id = {t["id"]: tags.get(t["name"].lower()) for t in official if t["id"]}
        tech = {r["id"]: r for r in db.execute(
            "SELECT id, tactics, domain FROM attack_techniques WHERE domain = ?", (domain,))}  # the matrix's own techniques
        pairs: set[tuple[int, int]] = set()
        for e in db.execute("SELECT e.id, e.name FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (slug,)):
            m = ANY_ID.search(e["name"])
            if not m:
                continue
            mid = m.group(1)
            if TACTIC_ID.match(mid):
                if by_id.get(mid):
                    pairs.add((e["id"], by_id[mid]))
                continue
            row = tech.get(mid)
            if row is None:
                continue
            for tactic in json.loads(row["tactics"] or "[]"):
                tag_id = tags.get(tactic.lower())
                if tag_id:
                    pairs.add((e["id"], tag_id))
        db.executemany("INSERT OR IGNORE INTO ttp_entity_tags (entity_id, tag_id) VALUES (?, ?)", sorted(pairs))
    return out


def file(db: sqlite3.Connection, article_ids: list[int] | None = None) -> tuple[int, int]:
    """File articles into the tactic collections their technique mentions support, and take them out of the ones
    they no longer support. ``article_ids`` None = every article. Returns (added, removed)."""
    if article_ids is not None and not article_ids:
        return 0, 0
    managed = [r[0] for r in db.execute(
        "SELECT t.id FROM tags t WHERE (t.name LIKE 'ATT&CK: %' OR t.name LIKE 'ATLAS: %') "
        "AND NOT EXISTS (SELECT 1 FROM rules r WHERE r.tag_id = t.id)")]  # a tag with a rule of your own keeps its rule filings
    if not managed:
        return 0, 0
    added = removed = 0
    chunks = [None] if article_ids is None else [article_ids[i : i + 500] for i in range(0, len(article_ids), 500)]
    for chunk in chunks:
        scope, args = ("", []) if chunk is None else (f" AND ae.article_id IN ({placeholders(len(chunk))})", list(chunk))
        added += db.execute(
            "INSERT OR IGNORE INTO article_tags (article_id, tag_id, source, created_at) "
            "SELECT DISTINCT ae.article_id, m.tag_id, 'rule', ? FROM article_entities ae "
            f"JOIN ttp_entity_tags m ON m.entity_id = ae.entity_id WHERE 1 = 1{scope} "  # nosec B608 - placeholders only
            "AND NOT EXISTS (SELECT 1 FROM ttp_tag_removed x WHERE x.article_id = ae.article_id AND x.tag_id = m.tag_id)",
            [now(), *args]).rowcount
        scope, args = ("", []) if chunk is None else (f" AND article_id IN ({placeholders(len(chunk))})", list(chunk))
        removed += db.execute(
            f"DELETE FROM article_tags WHERE source = 'rule' AND tag_id IN ({placeholders(len(managed))}){scope} "  # nosec B608
            "AND NOT EXISTS (SELECT 1 FROM article_entities ae JOIN ttp_entity_tags m ON m.entity_id = ae.entity_id "
            "WHERE ae.article_id = article_tags.article_id AND m.tag_id = article_tags.tag_id)", [*managed, *args]).rowcount
    return added, removed


def refile_all() -> dict:
    """Collections + mapping + every article. Cheap (set-based SQL); safe to call after any change."""
    with _lock, get_db() as db:
        out = sync_collections(db)
        added, removed = file(db, None)
        set_state(db, "ttp_filing_rev", REV)
    out.update(filed=added, unfiled=removed)
    if any(out.values()):
        log.info("Tactic collections: %s", ", ".join(f"{k} {v}" for k, v in out.items() if v))
    return out


def stale(db: sqlite3.Connection) -> bool:
    return get_state(db, "ttp_filing_rev", "") != REV
