"""Entity pages and the ATT&CK / ATLAS technique matrix (read-only views over the mention index).

Videos, podcast episodes and account posts are stored as articles of their own feed kinds, so the one mention
index (article_entities) already covers every tab: an entity page only has to split its mentions by feed kind.
"""

from __future__ import annotations

import json
import sqlite3

from app import atlas_sync, attack_sync, threat_actors, ttp_filing, entities
from app.db import now, placeholders

KIND = ("CASE WHEN COALESCE(f.kind, 'rss') = 'youtube' THEN 'videos' WHEN f.kind = 'podcast' THEN 'podcasts' "
        "WHEN f.social_platform IS NOT NULL THEN 'posts' ELSE 'articles' END")  # fixed SQL fragment
KINDS = ("articles", "videos", "podcasts", "posts")
def _mitre(db: sqlite3.Connection, slug: str | None, name: str) -> dict | None:
    """What MITRE says about an entity of the synced ATT&CK / ATLAS watchlists."""
    if slug in atlas_sync.TTP_SLUGS:
        m = atlas_sync.TTP_ANY.search(name)
        if m and ttp_filing.TACTIC_ID.match(m.group(1)):
            tac = db.execute("SELECT id, name, domain, url FROM attack_tactics WHERE id = ?", (m.group(1),)).fetchone()
            if tac is None:
                return None
            techs = [r for r in db.execute(
                "SELECT id, name, tactics FROM attack_techniques WHERE is_subtechnique = 0 AND domain = ? ORDER BY id", (tac["domain"],))
                if tac["name"] in json.loads(r["tactics"])]
            return {"kind": "tactic", "id": tac["id"], "framework": atlas_sync.framework(tac["id"]), "url": tac["url"],
                    "description": "", "techniques": [{"id": t["id"], "name": t["name"], "entity_id": atlas_sync.entity_for(db, t["id"])}
                                                       for t in techs[:120]]}
        row = db.execute("SELECT id, name, tactics, domain, url, description FROM attack_techniques WHERE id = ?",
                         (m.group(1),)).fetchone() if m else None
        if row is None:
            return None
        parent = None
        if atlas_sync.parent_id(row["id"]) != row["id"]:
            p = db.execute("SELECT id, name FROM attack_techniques WHERE id = ?", (atlas_sync.parent_id(row["id"]),)).fetchone()
            parent = {"id": p["id"], "name": p["name"], "entity_id": atlas_sync.entity_for(db, p["id"])} if p else None
        groups = db.execute(
            "SELECT DISTINCT g.id, g.name FROM attack_group_techniques x JOIN attack_groups g ON g.id = x.group_id "
            "WHERE x.technique_id = ? OR x.technique_id LIKE ? ORDER BY g.name COLLATE NOCASE LIMIT 60",
            (row["id"], row["id"] + ".%")).fetchall()
        subs = db.execute("SELECT id, name FROM attack_techniques WHERE id LIKE ? ORDER BY id LIMIT 80", (row["id"] + ".%",)).fetchall()
        return {"kind": "technique", "id": row["id"], "framework": atlas_sync.framework(row["id"]), "url": row["url"],
                "description": row["description"], "tactics": json.loads(row["tactics"]), "parent": parent,
                "subtechniques": [{**dict(s), "entity_id": atlas_sync.entity_for(db, s["id"])} for s in subs],
                "groups": [{**dict(g), "entity_id": _group_entity(db, g["id"])} for g in groups]}
    if slug == attack_sync.GROUPS_SLUG:
        m = attack_sync.MANAGED.search(name)
        row = db.execute("SELECT id, name, aliases, description, url FROM attack_groups WHERE id = ?", (m.group(1),)).fetchone() if m else None
        if row is None:
            return None
        techs = db.execute(
            "SELECT t.id, t.name FROM attack_group_techniques x JOIN attack_techniques t ON t.id = x.technique_id "
            "WHERE x.group_id = ? AND t.is_subtechnique = 0 ORDER BY t.id LIMIT 80", (row["id"],)).fetchall()
        return {"kind": "group", "id": row["id"], "url": row["url"], "description": row["description"],
                "techniques": [{**dict(t), "entity_id": atlas_sync.entity_for(db, t["id"])} for t in techs]}
    return None


def _group_entity(db: sqlite3.Connection, gid: str) -> int | None:
    row = db.execute("SELECT e.id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ? AND e.name LIKE ?",
                     (attack_sync.GROUPS_SLUG, f"%({gid})")).fetchone()
    return int(row["id"]) if row else None


def _count_subtechniques(db: sqlite3.Connection, since: int, subs: list[dict]) -> None:
    """sub["n"] = how many articles (in the period) name that sub-technique - its own mentions in the index."""
    for s in subs:
        s["n"] = db.execute("SELECT COUNT(*) FROM article_entities ae JOIN articles a ON a.id = ae.article_id "
                            "WHERE ae.entity_id = ? AND a.sort_ts >= ?", (s["entity_id"], since)).fetchone()[0] if s.get("entity_id") else 0


def entity_page(db: sqlite3.Connection, entity_id: int, days: int = 90, per_kind: int = 8) -> dict | None:
    ent = db.execute("SELECT e.id, e.name, e.aliases, e.muted, w.id AS watchlist_id, w.name AS watchlist, w.slug "
                     "FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE e.id = ?", (entity_id,)).fetchone()
    if ent is None:
        return None
    muted = {m.lower() for m in json.loads(ent["muted"] or "[]")}
    members = threat_actors.expand(db, entity_id)  # a threat actor: every entity that stands for it
    actor = threat_actors.actor_of(db, entity_id)
    marks = placeholders(len(members))
    seen = db.execute("SELECT MIN(a.sort_ts) AS first, MAX(a.sort_ts) AS last, COUNT(DISTINCT a.id) AS n FROM article_entities ae "
                      f"JOIN articles a ON a.id = ae.article_id WHERE ae.entity_id IN ({marks})", members).fetchone()  # nosec B608
    first, last = seen["first"], seen["last"]
    ts_now = now()
    since = ts_now - days * 86400 if days else 0  # every number on the page is for this period (days = 0: all time)
    totals = dict.fromkeys(KINDS, 0)
    for r in db.execute(
            f"SELECT {KIND} AS kind, COUNT(DISTINCT a.id) AS n "  # nosec B608 - fixed fragment
            "FROM article_entities ae JOIN articles a ON a.id = ae.article_id JOIN feeds f ON f.id = a.feed_id "
            f"WHERE ae.entity_id IN ({marks}) AND a.sort_ts >= ? GROUP BY kind", (*members, since)):
        totals[r["kind"]] = r["n"]
    latest: dict[str, list[dict]] = {k: [] for k in KINDS}
    for kind in KINDS:
        if totals[kind]:
            latest[kind] = [dict(r) for r in db.execute(
                "SELECT DISTINCT a.id, a.feed_id, a.title, a.url, a.sort_ts, a.is_read, f.title AS feed_title "  # nosec B608 - fixed fragment
                "FROM article_entities ae JOIN articles a ON a.id = ae.article_id JOIN feeds f ON f.id = a.feed_id "
                f"WHERE ae.entity_id IN ({marks}) AND a.sort_ts >= ? AND {KIND} = ? ORDER BY a.sort_ts DESC, a.id DESC LIMIT ?",
                (*members, since, kind, per_kind))]
    if days:
        step = 86400 if days <= 30 else 7 * 86400
        buckets = max(1, (days * 86400) // step)
    else:  # all time: months since the first mention (wider steps for very old entities, at most 120 bars)
        span = max(1, ts_now - (first or ts_now))
        step = 30 * 86400
        while span // step + 1 > 120:
            step *= 2
        buckets = span // step + 1
    start = ts_now - buckets * step
    counts = {int(r["b"]): r["n"] for r in db.execute(
        "SELECT (a.sort_ts - ?) / ? AS b, COUNT(DISTINCT a.id) AS n FROM article_entities ae JOIN articles a ON a.id = ae.article_id "
        f"WHERE ae.entity_id IN ({marks}) AND a.sort_ts >= ? GROUP BY b", (start, step, *members, max(start, since)))}  # nosec B608
    timeline = [{"ts": start + i * step, "n": counts.get(i, 0)} for i in range(buckets)]
    if buckets in counts:  # the last few seconds fall into one more bucket
        timeline[-1]["n"] += counts[buckets]
    related = [dict(r) for r in db.execute(
        "SELECT e.id, e.name, w.name AS watchlist, COUNT(*) AS n FROM article_entities ae "
        "JOIN entities e ON e.id = ae.entity_id JOIN watchlists w ON w.id = e.watchlist_id "
        "WHERE ae.article_id IN (SELECT x.article_id FROM article_entities x JOIN articles a ON a.id = x.article_id "
        f"WHERE x.entity_id IN ({marks}) AND a.sort_ts >= ? ORDER BY x.article_id DESC LIMIT 1500) "  # nosec B608
        f"AND ae.entity_id NOT IN ({marks}) GROUP BY e.id ORDER BY n DESC, e.name LIMIT 14", (*members, since, *members))]
    mitre = _mitre(db, ent["slug"], ent["name"])
    if mitre and mitre["kind"] == "technique" and mitre["subtechniques"]:
        _count_subtechniques(db, since, mitre["subtechniques"])
        mitre["subtechniques"].sort(key=lambda s: (-s["n"], s["id"]))
    return {
        "id": ent["id"], "name": ent["name"], "watchlist": {"id": ent["watchlist_id"], "name": ent["watchlist"]},
        # a threat actor is recognised by the names of every list entry that stands for it
        "aliases": [a for a in (actor["matched"] if actor else json.loads(ent["aliases"])) if a.lower() not in muted][:160],
        "mitre": mitre, "actor": actor,
        "totals": totals, "all_time": seen["n"], "first_seen": first, "last_seen": last, "latest": latest,
        "days": days, "step": step, "timeline": timeline, "related": related,
    }


def article_entities(db: sqlite3.Connection, article_id: int, limit: int = 40) -> list[dict]:
    """Who and what an article mentions (watchlist entities other than the technique lists, which have their own chips)."""
    out: dict[str, dict] = {}
    for r in db.execute(
            "SELECT e.id, e.name, w.name AS watchlist FROM article_entities ae JOIN entities e ON e.id = ae.entity_id "
            "JOIN watchlists w ON w.id = e.watchlist_id WHERE ae.article_id = ? AND COALESCE(w.slug, '') NOT IN (?, ?) "
            "ORDER BY w.position, w.name, e.name COLLATE NOCASE", (article_id, *atlas_sync.TTP_SLUGS)):
        out.setdefault(r["name"].lower(), dict(r))  # the same name in two watchlists: one chip
    return list(out.values())[:limit]


def matrix(db: sqlite3.Connection, fw: str, days: int) -> dict:
    """Tactics (columns, in kill-chain order) with their techniques and how many stored articles name each."""
    atlas = fw == "atlas"
    listed = ttp_filing.tactics(db, fw)  # MITRE's matrix order
    order = [t["name"] for t in listed]
    slug = atlas_sync.SLUG if atlas else attack_sync.TECH_SLUG
    ents: dict[str, int] = {}
    for r in db.execute("SELECT e.id, e.name FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (slug,)):
        m = atlas_sync.TTP_ID.search(r["name"])
        if m:
            ents[m.group(1)] = r["id"]
    if days:
        counted = db.execute(
            "SELECT ae.entity_id, COUNT(*) AS n FROM article_entities ae JOIN articles a ON a.id = ae.article_id "
            "JOIN entities e ON e.id = ae.entity_id JOIN watchlists w ON w.id = e.watchlist_id "
            "WHERE w.slug = ? AND a.sort_ts >= ? GROUP BY ae.entity_id", (slug, now() - days * 86400))
    else:
        counted = db.execute(
            "SELECT ae.entity_id, COUNT(*) AS n FROM article_entities ae JOIN entities e ON e.id = ae.entity_id "
            "JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ? GROUP BY ae.entity_id", (slug,))
    counts = {r["entity_id"]: r["n"] for r in counted}
    columns: dict[str, dict[str, dict]] = {t.lower(): {} for t in order}
    rows = db.execute("SELECT id, name, tactics, domain, url FROM attack_techniques WHERE is_subtechnique = 0 AND domain = ?",
                      ("atlas" if atlas else "enterprise-attack",)).fetchall()  # the Enterprise matrix, as on attack.mitre.org
    for r in sorted(rows, key=lambda r: (atlas_sync.DOMAIN_ORDER.get(r["domain"], 3), r["id"])):
        n = counts.get(ents.get(r["id"], -1), 0)
        for tactic in json.loads(r["tactics"]):
            col = columns.get(tactic.lower())
            if col is None:
                continue
            name_key = r["name"].lower()
            if name_key in col:  # same name in Enterprise / ICS / Mobile: one cell
                col[name_key]["n"] = max(col[name_key]["n"], n)
            else:
                col[name_key] = {"id": r["id"], "name": r["name"], "n": n, "url": r["url"], "domain": r["domain"],
                                 "entity_id": ents.get(r["id"])}
    tactics = []
    for t in listed:
        techs = sorted(columns[t["name"].lower()].values(), key=lambda x: (-x["n"], x["id"]))
        tactics.append({"id": t["id"], "name": t["name"], "url": t["url"], "total": sum(x["n"] for x in techs), "techniques": techs})
    version = db.execute("SELECT value FROM sync_state WHERE key = ?",
                         ("atlas_version" if atlas else "attack_version:enterprise-attack",)).fetchone()
    return {"framework": fw, "days": days, "version": version[0] if version else None,
            "max": max([x["n"] for t in tactics for x in t["techniques"]] or [0]), "tactics": tactics}
