"""Threat actors: one catalogue, one list to filter by.

Where actors come from
  * MITRE ATT&CK groups (watchlist "MITRE ATT&CK groups", kept by app/attack_sync.py);
  * the bundled catalogue app/data/threat_actors.json (built by tools/build_threat_actors.py from the open MISP
    threat-actor galaxy plus the adversary names on CrowdStrike's and Dragos' public pages and MITRE ATLAS' activity
    clusters) -> watchlist "Threat actor catalog" (slug threat-actor-catalog), managed here;
  * the lists you can edit yourself: "Threat actors & APTs", "Ransomware groups", "OT / ICS threat actors".

The same actor is usually in several of them under different names (APT28 / FANCY BEAR / Forest Blizzard). They are
shown as ONE actor: entities are joined when the main name of one is a name of the other; the actor's numbers are the
articles that mention any of its entities. `expand()` gives the entities behind an entity id, and every "by entity"
filter (articles, videos, podcasts, the entity page) uses it - so filtering by an actor always means the whole actor.

No request is made here: the catalogue is a file shipped with the app.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from pathlib import Path

from app import entities
from app.cve_sync import get_state, set_state
from app.db import get_db, now, placeholders

log = logging.getLogger("eos.actors")

CATALOG = Path(__file__).resolve().parent / "data" / "threat_actors.json"
SLUG = "threat-actor-catalog"
GROUPS_SLUG = "mitre-attack-groups"
# watchlists whose entities are threat actors, in the order that picks an actor's display name
ACTOR_SLUGS = (GROUPS_SLUG, SLUG, "threat-actors", "ransomware-groups", "ot-threat-actors")
SOURCE_LABEL = {GROUPS_SLUG: "MITRE ATT&CK", "threat-actors": "Your list", "ransomware-groups": "Your list", "ot-threat-actors": "Your list"}
READER = "COALESCE(f.kind, 'rss') NOT IN ('youtube', 'podcast') AND f.social_platform IS NULL"  # fixed SQL fragment
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
PAREN = re.compile(r"\s*\([^)]*\)\s*$")
_lock = threading.Lock()
_cache: tuple[tuple, dict] | None = None


def _key(name: str) -> str:
    return "".join(TOKEN.findall(name.lower()))


def load_catalog() -> dict:
    try:
        data = json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": 0, "built": "", "actors": []}
    return data if isinstance(data, dict) and isinstance(data.get("actors"), list) else {"version": 0, "built": "", "actors": []}


def _rev(data: dict) -> str:
    return f"{data.get('version')}:{data.get('built')}:{len(data.get('actors') or [])}"


# ------------------------------------------------------------------ the catalogue watchlist
def apply_catalog() -> dict:
    """Bring the "Threat actor catalog" watchlist in line with the bundled file. Returns what changed."""
    from app import attack_sync

    data = load_catalog()
    changed: list[int] = []
    removed = 0
    with get_db() as db:
        wid = attack_sync._watchlist(
            db, SLUG, "Threat actor catalog",
            "Threat actors and their alternative names from the open MISP threat-actor galaxy, CrowdStrike's and Dragos' "
            "adversary lists and MITRE ATLAS. Managed by the app (replaced when the catalogue is updated); the same actor "
            "in other lists is shown as one in the Threat actors filter.")
        if wid is None:
            set_state(db, "threat_actors_rev", _rev(data))
            return {"entities_changed": 0, "entities_removed": 0, "skipped": "list deleted"}
        current = {r["key"]: r for r in db.execute(
            "SELECT m.key, m.entity_id, e.name, e.aliases FROM threat_actor_meta m JOIN entities e ON e.id = m.entity_id")}
        seen: set[str] = set()
        for a in data["actors"]:
            name = " ".join(str(a.get("name", "")).split())[:80]
            key = _key(name)
            if not key or key in seen:
                continue
            seen.add(key)
            shown = name if a.get("match_name") else f"{name} (threat actor)"  # an everyday word: only its other names match
            aliases = json.dumps(attack_sync._aliases([x for x in a.get("aliases") or [] if isinstance(x, str)], 40))
            meta = (str(a.get("country") or "")[:2], str(a.get("kind") or "")[:20], json.dumps([str(s)[:40] for s in a.get("sources") or []][:6]))
            row = current.get(key)
            if row is None:
                db.execute("DELETE FROM entities WHERE watchlist_id = ? AND name = ?", (wid, shown))
                eid = int(db.execute("INSERT INTO entities (watchlist_id, name, aliases) VALUES (?, ?, ?)", (wid, shown, aliases)).lastrowid)
                db.execute("INSERT INTO threat_actor_meta (entity_id, key, country, kind, sources) VALUES (?, ?, ?, ?, ?)", (eid, key, *meta))
                changed.append(eid)
            else:
                if row["name"] != shown or row["aliases"] != aliases:
                    db.execute("UPDATE entities SET name = ?, aliases = ? WHERE id = ?", (shown, aliases, row["entity_id"]))
                    changed.append(int(row["entity_id"]))
                db.execute("UPDATE threat_actor_meta SET country = ?, kind = ?, sources = ? WHERE entity_id = ?", (*meta, row["entity_id"]))
        for key, row in current.items():
            if key not in seen:
                db.execute("DELETE FROM entities WHERE id = ?", (row["entity_id"],))
                removed += 1
        set_state(db, "threat_actors_rev", _rev(data))
    if changed or removed:
        entities.invalidate()
    if changed:
        entities.reindexer.request(changed)
    if changed or removed:
        log.info("Threat actor catalogue applied: %d entities changed, %d removed (%d actors in the file)", len(changed), removed, len(data["actors"]))
    return {"entities_changed": len(changed), "entities_removed": removed}


def ensure_current() -> bool:
    """Startup hook: apply the bundled catalogue when it is newer than what the database holds."""
    with get_db() as db:
        stale = get_state(db, "threat_actors_rev", "") != _rev(load_catalog())
    if stale:
        apply_catalog()
    return stale


# ------------------------------------------------------------------ one actor = several entities
def _clusters(db: sqlite3.Connection) -> dict:
    """{"primary": {entity id: actor id}, "members": {actor id: [entity ids]}, "info": {actor id: {...}}} - cached
    until a watchlist changes."""
    global _cache
    sig = (entities._version, db.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM entities").fetchone()[:])
    with _lock:
        if _cache is not None and _cache[0] == sig:
            return _cache[1]
    rows = db.execute(
        "SELECT e.id, e.name, e.aliases, w.slug FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
        f"WHERE w.slug IN ({placeholders(len(ACTOR_SLUGS))})", ACTOR_SLUGS).fetchall()  # nosec B608 - placeholders only
    meta = {r["entity_id"]: r for r in db.execute("SELECT entity_id, country, kind, sources FROM threat_actor_meta")}
    main: dict[int, str] = {}
    names: dict[int, set[str]] = {}
    for r in rows:
        base = PAREN.sub("", r["name"]) or r["name"]
        main[r["id"]] = _key(base)
        keys = {_key(base)} | {_key(a) for a in json.loads(r["aliases"] or "[]") if isinstance(a, str)}
        names[r["id"]] = {k for k in keys if len(k) >= 4}
    owners: dict[str, list[int]] = {}
    for eid, keys in names.items():
        for k in keys:
            owners.setdefault(k, []).append(eid)
    parent = {r["id"]: r["id"] for r in rows}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for eid, k in main.items():  # joined when the MAIN name of one is a name of the other (never alias-to-alias)
        if len(k) < 4:
            continue
        for other in owners.get(k, ()):
            a, b = find(eid), find(other)
            if a != b:
                parent[b] = a
    rank = {s: i for i, s in enumerate(ACTOR_SLUGS)}
    by_id = {r["id"]: r for r in rows}
    groups: dict[int, list[int]] = {}
    for r in rows:
        groups.setdefault(find(r["id"]), []).append(r["id"])
    primary: dict[int, int] = {}
    members: dict[int, list[int]] = {}
    info: dict[int, dict] = {}
    for ids in groups.values():
        ids.sort(key=lambda i: (rank[by_id[i]["slug"]], i))
        pid = ids[0]
        members[pid] = ids
        for i in ids:
            primary[i] = pid
        sources: list[str] = []
        kind = ""
        countries: dict[str, list[int]] = {}
        other_names: list[str] = []
        for i in ids:
            label = SOURCE_LABEL.get(by_id[i]["slug"])
            if label and label not in sources:
                sources.append(label)
            m = meta.get(i)
            if m:
                kind = kind or m["kind"]
                if m["country"]:
                    countries.setdefault(m["country"], []).append(i)
                sources += [s for s in json.loads(m["sources"] or "[]") if s not in sources]
            if i != pid:
                other_names.append(PAREN.sub("", by_id[i]["name"]) or by_id[i]["name"])
        # the country most of its catalogue entries agree on; on a tie, the entry named most like the actor
        country = max(countries, key=lambda cc: (len(countries[cc]), any(main[i] and (main[i] in main[pid] or main[pid] in main[i]) for i in countries[cc])),
                      default="")
        aliases = [a for i in ids for a in json.loads(by_id[i]["aliases"] or "[]") if isinstance(a, str)]
        info[pid] = {"id": pid, "name": by_id[pid]["name"], "country": country, "kind": kind, "sources": sources,
                     "also": list(dict.fromkeys(other_names + aliases))[:60]}
    out = {"primary": primary, "members": members, "info": info}
    with _lock:
        _cache = (sig, out)
    return out


def expand(db: sqlite3.Connection, entity_id: int) -> list[int]:
    """The entities that stand for the same threat actor as this one (itself only, for anything that is not an actor)."""
    c = _clusters(db)
    pid = c["primary"].get(entity_id)
    return list(c["members"][pid]) if pid is not None else [entity_id]


def actor_of(db: sqlite3.Connection, entity_id: int) -> dict | None:
    c = _clusters(db)
    pid = c["primary"].get(entity_id)
    return dict(c["info"][pid], members=len(c["members"][pid])) if pid is not None else None


def listing(db: sqlite3.Connection, q: str = "", days: int = 0, limit: int = 200, with_zero: bool = False) -> dict:
    """Actors with how many articles / videos / podcast episodes mention them (in the last `days`; 0 = all time),
    most-mentioned first. `q` searches names and alternative names."""
    c = _clusters(db)
    ids = list(c["primary"])
    seen: dict[int, dict[str, set[int]]] = {}
    since = now() - days * 86400 if days else 0
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        for r in db.execute(
                "SELECT ae.entity_id, ae.article_id, CASE WHEN COALESCE(f.kind, 'rss') = 'youtube' THEN 'videos' "
                "WHEN f.kind = 'podcast' THEN 'podcasts' WHEN f.social_platform IS NOT NULL THEN 'posts' ELSE 'articles' END AS kind "
                "FROM article_entities ae JOIN articles a ON a.id = ae.article_id JOIN feeds f ON f.id = a.feed_id "
                f"WHERE ae.entity_id IN ({placeholders(len(chunk))}) AND a.sort_ts >= ?", [*chunk, since]):  # nosec B608
            seen.setdefault(c["primary"][r["entity_id"]], {}).setdefault(r["kind"], set()).add(r["article_id"])
    needle = _key(q)
    items = []
    for pid, inf in c["info"].items():
        counts = seen.get(pid, {})
        n = {k: len(counts.get(k, ())) for k in ("articles", "videos", "podcasts")}
        if not with_zero and not needle and not any(n.values()):
            continue
        if needle and needle not in _key(inf["name"]) and not any(needle in _key(a) for a in inf["also"]):
            continue
        items.append({**inf, **n, "also": inf["also"][:12]})
    items.sort(key=lambda a: (-(a["articles"] + a["videos"] + a["podcasts"]), a["name"].lower()))
    return {"total": len(items), "tracked": len(c["info"]), "days": days, "items": items[:limit]}
