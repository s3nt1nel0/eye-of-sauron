"""MITRE ATLAS sync: tactics and techniques for attacks on (and with) AI systems, from MITRE's official data.

Source: https://github.com/mitre-atlas/atlas-data (the YAML files atlas.mitre.org is built from).
  * dist/manifest.yaml lists the releases, newest first. When the release is unchanged, nothing else is downloaded.
  * The release file is only fetched from inside that repository's dist/ folder.

What a sync updates:
  * attack_techniques rows with domain = 'atlas' (IDs "AML.T0051", sub-techniques "AML.T0051.000").
  * attack_tactics rows with domain = 'atlas': the tactics in the order of the ATLAS matrix.
  * Watchlist "MITRE ATLAS techniques" (slug mitre-atlas-techniques): one entity per technique "Name (AML.T0051)",
    per sub-technique "Name (AML.T0051.000)" and per tactic "Name (AML.TA0005)". Techniques match by ID, by their
    AI-specific names and by the everyday terms in collection_packs.ATLAS_TERMS ("prompt injection" for *LLM Prompt
    Injection*). Names ATLAS shares with ATT&CK (Phishing, Valid Accounts) and generic names ("AI Agent", "Models")
    only match through their ID, so ordinary articles aren't labelled as AI attacks. Tactics match by ID only.
  * The "ATLAS: <tactic>" collections follow the ATLAS matrix and are filed from those entities
    (app/ttp_filing.py) - when the ATLAS collection pack is installed.

Deleting the watchlist stops the sync from re-creating it.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any

import yaml

from app import app_settings, attack_sync, collection_packs, entities, ttp_filing
from app import netguard
from app.cve_sync import get_state, set_state
from app.db import get_db, now

log = logging.getLogger("feedwarden.atlas")

DIST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/"
MANIFEST_URL = DIST + "manifest.yaml"
RELEASE_PATH = re.compile(r"^v\d{1,2}/ATLAS-[0-9A-Za-z.]{1,20}\.yaml$")
MAX_FILE = 20 * 1024 * 1024
SLUG = "mitre-atlas-techniques"
TECH_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
TACTIC_ID = re.compile(r"^AML\.TA\d{4}$")
MANAGED = re.compile(r"\((AML\.TA?\d{4}(?:\.\d{3})?)\)$")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
SITE = "https://atlas.mitre.org/techniques/"
TACTIC_SITE = "https://atlas.mitre.org/tactics/"

# A name counts as AI-specific when it carries one of these words; everything else matches through its ID only.
AI_WORDS = {"ai", "llm", "llms", "rag", "model", "models", "agent", "agents", "agentic", "prompt", "prompts",
            "deepfake", "deepfakes", "adversarial", "inference", "hallucinated", "hallucinations", "multimodal",
            "training", "dataset"}
GENERIC = {n.lower() for n in (
    "AI Agent", "AI Agent Tool", "AI Agent Tools", "AI Artifacts", "Generative AI", "Local AI Agent", "Models",
    "Datasets", "System Prompt", "System Instructions", "Model Repository", "Data Repository", "AI Service API",
    "AI Agent Configuration", "Tool Definitions", "Deploy AI Agent", "Outputs from AI Models", "Data from AI Services",
    "Discover AI Artifacts", "Acquire Public AI Artifacts", "Full AI Model Access")}


class AtlasError(Exception):
    pass


def _get(url: str, max_bytes: int) -> bytes:
    try:
        return attack_sync._get(url, max_bytes)
    except attack_sync.AttackError as exc:
        raise AtlasError(str(exc)) from exc


def _yaml(raw: bytes, what: str) -> Any:
    try:
        return yaml.safe_load(raw)  # safe_load: plain data only, no object construction
    except yaml.YAMLError as exc:
        raise AtlasError(f"{what} is not valid YAML") from exc


def release() -> dict:
    """{"version", "url"} of the newest release in MITRE's manifest (URL restricted to the repository's dist/)."""
    manifest = _yaml(_get(MANIFEST_URL, 1024 * 1024), "The ATLAS manifest")
    if not isinstance(manifest, list) or not manifest or not isinstance(manifest[0], dict):
        raise AtlasError("No ATLAS releases found in the manifest")
    latest = manifest[0]
    versions = latest.get("versions") or []
    path = str((versions[0] if versions and isinstance(versions[0], dict) else {}).get("path", ""))
    if not RELEASE_PATH.match(path):
        raise AtlasError("Unexpected ATLAS release location")
    return {"version": str(latest.get("release", ""))[:20], "url": DIST + path}


def _clean_text(text: Any, limit: int = 600) -> str:
    text = " ".join(MD_LINK.sub(r"\1", str(text or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def parse(doc: Any) -> dict[str, dict]:
    """{technique id: row} from one ATLAS release file."""
    if not isinstance(doc, dict) or not isinstance(doc.get("techniques"), dict) or not isinstance(doc.get("tactics"), dict):
        raise AtlasError("The ATLAS release has an unexpected layout")
    tactics = {str(k): str((v or {}).get("name", ""))[:80] for k, v in doc["tactics"].items()
               if TACTIC_ID.match(str(k)) and isinstance(v, dict)}
    rel = doc.get("relationships") if isinstance(doc.get("relationships"), dict) else {}
    out: dict[str, dict] = {}
    for tid, t in doc["techniques"].items():
        tid = str(tid)
        if not TECH_ID.match(tid) or not isinstance(t, dict) or t.get("deprecated"):
            continue
        name = " ".join(str(t.get("name", "")).split())[:120]
        if not name:
            continue
        links = (rel.get(tid) or {}).get("achieves") if isinstance(rel.get(tid), dict) else None
        names = [tactics.get(str(x.get("target")), "") for x in links or [] if isinstance(x, dict)]
        out[tid] = {"id": tid, "name": name, "tactics": sorted({n for n in names if n}), "domain": "atlas",
                    "is_subtechnique": int(tid.count(".") == 2), "url": SITE + tid,
                    "description": _clean_text(t.get("description")), "modified": str(t.get("modified-date") or "")[:40] or None}
    return out


def parse_tactics(doc: Any) -> list[dict]:
    """The tactics in the order of the ATLAS matrix: [{id, name, url}]."""
    if not isinstance(doc, dict) or not isinstance(doc.get("tactics"), dict):
        return []
    names = {str(k): " ".join(str((v or {}).get("name", "")).split())[:80] for k, v in doc["tactics"].items()
             if TACTIC_ID.match(str(k)) and isinstance(v, dict) and not v.get("deprecated")}
    # the matrix order: relationships[<matrix id>]["sequences"] = [{target: AML.TA…, position: n}]
    order: list[str] = []
    rel = doc.get("relationships") if isinstance(doc.get("relationships"), dict) else {}
    matrix = doc.get("matrix") if isinstance(doc.get("matrix"), dict) else {}
    seq = (rel.get(str(matrix.get("id") or "ATLAS-matrix")) or {}).get("sequences") if isinstance(rel.get(str(matrix.get("id") or "ATLAS-matrix")), dict) else None
    steps = [x for x in seq or [] if isinstance(x, dict) and isinstance(x.get("position"), int)]
    for step in sorted(steps, key=lambda x: x["position"]):
        tid = str(step.get("target"))
        if tid in names and tid not in order:
            order.append(tid)
    order += [k for k in names if k not in order]  # a tactic the matrix does not place yet goes last
    return [{"id": k, "name": names[k], "url": TACTIC_SITE + k} for k in order if names[k]]


# ------------------------------------------------------------------ aliases
def _tokens(name: str) -> list[str]:
    return [w.lower() for w in entities.TOKEN.findall(name)]


def ai_specific(name: str, attack_names: set[str]) -> bool:
    """Can this official name be matched in text without labelling ordinary articles as AI attacks?"""
    low = name.lower()
    words = _tokens(name)
    return len(words) >= 2 and low not in attack_names and low not in GENERIC and any(w in AI_WORDS for w in words)


def _own_aliases(t: dict, attack_names: set[str]) -> list[str]:
    return [t["id"]] + ([t["name"]] if ai_specific(t["name"], attack_names) else []) \
        + list(collection_packs.ATLAS_TERMS.get(t["id"], ((), ()))[1])


def technique_entity(t: dict, subs: list[dict], attack_names: set[str]) -> tuple[str, list[str]]:
    """A technique matches through its own names and through everything its sub-techniques match through."""
    aliases = _own_aliases(t, attack_names)
    for s in subs:
        aliases += _own_aliases(s, attack_names)
    return f"{t['name']} ({t['id']})", attack_sync._aliases(aliases)


def _entities(techniques: dict[str, dict], tactics: list[dict], attack_names: set[str]) -> dict[str, tuple[str, list[str]]]:
    """{MITRE id: (entity name, aliases)} for every technique, sub-technique and tactic."""
    subs: dict[str, list[dict]] = {}
    for t in techniques.values():
        if t["is_subtechnique"]:
            subs.setdefault(t["id"].rsplit(".", 1)[0], []).append(t)
    out = {t["id"]: technique_entity(t, sorted(subs.get(t["id"], []), key=lambda s: s["id"]), attack_names)
           for t in techniques.values() if not t["is_subtechnique"]}
    out.update({t["id"]: (f"{t['name']} ({t['id']})", attack_sync._aliases(_own_aliases(t, attack_names)))
                for t in techniques.values() if t["is_subtechnique"]})
    out.update({t["id"]: (f"{t['name']} ({t['id']})", [t["id"]]) for t in tactics if t.get("id")})  # tactics: by ID only
    return out


def apply(techniques: dict[str, dict], tactics: list[dict] | None = None) -> dict:
    with get_db() as db:
        old = {r["id"]: r["name"] for r in db.execute("SELECT id, name FROM attack_techniques WHERE domain = 'atlas'")}
        attack_names = {r[0].lower() for r in db.execute("SELECT name FROM attack_techniques WHERE domain != 'atlas'")}
        db.execute("DELETE FROM attack_techniques WHERE domain = 'atlas'")
        db.executemany("INSERT OR REPLACE INTO attack_techniques (id, name, tactics, domain, is_subtechnique, url, description, modified) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       [(t["id"], t["name"], json.dumps(t["tactics"]), "atlas", t["is_subtechnique"], t["url"],
                         t["description"], t["modified"]) for t in techniques.values()])
        if tactics:
            ttp_filing.store_tactics(db, "atlas", tactics)
        tactics = [dict(r) for r in db.execute("SELECT id, name, url FROM attack_tactics WHERE domain = 'atlas' ORDER BY position")]
        changed: list[int] = []
        removed = 0
        wid = attack_sync._watchlist(db, SLUG, "MITRE ATLAS techniques",
                                     "MITRE ATLAS tactics, techniques and sub-techniques (attacks on and with AI systems), "
                                     "matched by ID (AML.T0051), AI-specific names and everyday terms like \"prompt injection\". "
                                     "Kept up to date automatically; entities ending in (AML.T…) or (AML.TA…) are replaced on each sync.")
        if wid:
            changed, removed = attack_sync._sync_entities(db, wid, _entities(techniques, tactics, attack_names), MANAGED)
            attack_sync.inherit_muted(db, wid)
    if changed:
        entities.invalidate()
        entities.reindexer.request(changed)  # the tactic collections are re-filed when the index is ready
    elif removed:
        entities.invalidate()
    ttp_filing.refile_all()
    return {"techniques": len(techniques), "tactics": [t["name"] for t in tactics],
            "techniques_added": sorted(f"{t['name']} ({i})" for i, t in techniques.items() if i not in old)[:100] if old else [],
            "techniques_removed": sorted(f"{n} ({i})" for i, n in old.items() if i not in techniques)[:100],
            "entities_changed": len(changed), "entities_removed": removed, "first_sync": not old}


def refresh_entities() -> dict:
    """Rebuild the ATLAS watchlist from the stored release (no download), e.g. after the entity layout changed."""
    with get_db() as db:
        techniques = {r["id"]: {**dict(r), "tactics": json.loads(r["tactics"])} for r in db.execute(
            "SELECT id, name, tactics, is_subtechnique FROM attack_techniques WHERE domain = 'atlas'")}
        attack_names = {r[0].lower() for r in db.execute("SELECT name FROM attack_techniques WHERE domain != 'atlas'")}
        tactics = [dict(r) for r in db.execute("SELECT id, name, url FROM attack_tactics WHERE domain = 'atlas' ORDER BY position")]
        wl = db.execute("SELECT id FROM watchlists WHERE slug = ?", (SLUG,)).fetchone()
        changed: list[int] = []
        removed = 0
        if techniques and wl:
            changed, removed = attack_sync._sync_entities(db, wl["id"], _entities(techniques, tactics, attack_names), MANAGED)
            attack_sync.inherit_muted(db, wl["id"])
    if changed:
        entities.invalidate()
        entities.reindexer.request(changed)
    elif removed:
        entities.invalidate()
    ttp_filing.refile_all()
    return {"entities_changed": len(changed), "entities_removed": removed}


# ------------------------------------------------------------------ job
class AtlasSync:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False
        self.phase = ""

    def start(self, force: bool = False) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, args=(force,), name="atlas-sync", daemon=True).start()
        return True

    def maybe_start(self) -> None:
        """Scheduler hook: same schedule as ATT&CK (Settings → Watchlists → MITRE ATT&CK)."""
        if self.running:
            return
        with get_db() as db:
            every = attack_sync.INTERVALS.get(app_settings.get_all(db)["attack_sync"])
            last = int(get_state(db, "atlas_checked_at", "0") or 0)
        if every and now() - last >= every:
            self.start()

    def _run(self, force: bool) -> None:
        started = now()
        result: dict[str, Any] = {"started": started}
        try:
            self.phase = "checking MITRE ATLAS releases"
            rel = release()
            with get_db() as db:
                stored = get_state(db, "atlas_version")
                have = db.execute("SELECT COUNT(*) FROM attack_techniques WHERE domain = 'atlas'").fetchone()[0]
            if not force and have and stored == rel["version"]:
                result.update(status="up to date", version=rel["version"])
            else:
                self.phase = f"downloading ATLAS {rel['version']}"
                doc = _yaml(_get(rel["url"], MAX_FILE), "The ATLAS release")
                techniques = parse(doc)
                if len(techniques) < 50:
                    raise AtlasError("The release looks incomplete - keeping the current data")
                self.phase = "updating ATLAS tactics, techniques, watchlist and collections"
                report = apply(techniques, parse_tactics(doc))
                with get_db() as db:
                    set_state(db, "atlas_version", rel["version"])
                    set_state(db, "atlas_synced_at", str(now()))
                result.update(status="updated", version=rel["version"], report=report)
                log.info("ATLAS updated: %s techniques", report["techniques"])
        except (AtlasError, netguard.FetchError, netguard.UnsafeURLError) as exc:
            result.update(status="error", error=str(exc)[:300])
            log.warning("ATLAS sync failed: %s", exc)
        except Exception as exc:  # never kill the scheduler
            log.exception("ATLAS sync crashed")
            result.update(status="error", error=f"Unexpected error: {type(exc).__name__}")
        finally:
            result["finished"] = now()
            result["seconds"] = int(time.time()) - started
            with get_db() as db:
                set_state(db, "atlas_checked_at", str(now()))
                set_state(db, "atlas_last_result", json.dumps(result))
            self.phase = ""
            self.running = False


atlas_sync = AtlasSync()


def status() -> dict:
    with get_db() as db:
        state = {k: get_state(db, k) for k in ("atlas_checked_at", "atlas_synced_at", "atlas_version", "atlas_last_result")}
        count = db.execute("SELECT COUNT(*) FROM attack_techniques WHERE domain = 'atlas'").fetchone()[0]
        wl = db.execute("SELECT id FROM watchlists WHERE slug = ?", (SLUG,)).fetchone()
        pack = db.execute("SELECT COUNT(*) FROM tags WHERE name LIKE 'ATLAS: %'").fetchone()[0]
    return {"running": atlas_sync.running, "phase": atlas_sync.phase, "version": state["atlas_version"] or None,
            "techniques": count, "watchlist": wl["id"] if wl else None, "collections": pack,
            "checked_at": int(state["atlas_checked_at"] or 0) or None, "synced_at": int(state["atlas_synced_at"] or 0) or None,
            "last_result": json.loads(state["atlas_last_result"]) if state["atlas_last_result"] else None}


# ------------------------------------------------------------------ techniques on articles (ATT&CK and ATLAS)
TTP_SLUGS = (attack_sync.TECH_SLUG, SLUG)
TTP_ID = re.compile(r"\(((?:AML\.)?T\d{4})\)$")   # a technique's entity (not a sub-technique's, not a tactic's)
TTP_ANY = ttp_filing.ANY_ID                          # technique, sub-technique or tactic
DOMAIN_ORDER = {"enterprise-attack": 0, "atlas": 0, "ics-attack": 1, "mobile-attack": 2}


def framework(tid: str) -> str:
    return "atlas" if tid.startswith("AML.") else "attack"


def parent_id(tid: str) -> str:
    """T1566.001 -> T1566, AML.T0051.000 -> AML.T0051; a technique's own ID unchanged."""
    return tid.rsplit(".", 1)[0] if tid.count(".") == (2 if tid.startswith("AML.") else 1) else tid


def entity_for(db, tid: str) -> int | None:
    row = db.execute("SELECT e.id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                     "WHERE w.slug = ? AND e.name LIKE ? ESCAPE '\\'",
                     (SLUG if tid.startswith("AML.") else attack_sync.TECH_SLUG, f"%({tid})")).fetchone()
    return int(row["id"]) if row else None


def family_entities(db, tid: str) -> list[int]:
    """The entities of a technique and of its sub-techniques (what "not this technique" has to cover)."""
    slug = SLUG if tid.startswith("AML.") else attack_sync.TECH_SLUG
    return [int(r[0]) for r in db.execute(
        "SELECT e.id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ? "
        "AND (e.name LIKE ? ESCAPE '\\' OR e.name LIKE ? ESCAPE '\\')", (slug, f"%({tid})", f"%({tid}.___)"))]


def attach_ttps(db, articles: list[dict]) -> None:
    """What each article names, straight from the mention index:
      a["ttps"]        techniques [{id, name, framework, tactics, url, also, subs: [{id, name, url}]}] - same-named
                       ATT&CK techniques of several domains (Enterprise / ICS / Mobile) are shown once, the others'
                       IDs under "also"; "subs" are the sub-techniques the article names;
      a["ttp_tactics"] tactics the article names directly [{id, name, framework}] (TA0008, "lateral movement")."""
    if not articles:
        return
    ids = [a["id"] for a in articles]
    marks = ",".join("?" * len(ids))
    found: dict[int, list[str]] = {i: [] for i in ids}
    for r in db.execute(
            "SELECT ae.article_id, e.name FROM article_entities ae JOIN entities e ON e.id = ae.entity_id "
            f"JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug IN (?, ?) AND ae.article_id IN ({marks})",  # nosec B608 - placeholders only
            [*TTP_SLUGS, *ids]):
        m = TTP_ANY.search(r["name"])
        if m:
            found[r["article_id"]].append(m.group(1))
    named = {t for v in found.values() for t in v}
    wanted = sorted({x for t in named if not ttp_filing.TACTIC_ID.match(t) for x in (t, parent_id(t))})
    info: dict[str, Any] = {}
    for start in range(0, len(wanted), 400):
        chunk = wanted[start : start + 400]
        for r in db.execute("SELECT id, name, tactics, domain, url FROM attack_techniques "
                            f"WHERE id IN ({','.join('?' * len(chunk))})", chunk):  # nosec B608 - placeholders only
            info[r["id"]] = r
    tactic_ids = sorted(t for t in named if ttp_filing.TACTIC_ID.match(t))
    tactic_info = {r["id"]: r for r in db.execute(
        f"SELECT id, name FROM attack_tactics WHERE id IN ({','.join('?' * len(tactic_ids))})", tactic_ids)} if tactic_ids else {}  # nosec B608
    for a in articles:
        mine = set(found[a["id"]])
        subs: dict[str, list[dict]] = {}
        for tid in sorted(mine):
            if tid in info and parent_id(tid) != tid:
                subs.setdefault(parent_id(tid), []).append({"id": tid, "name": info[tid]["name"], "url": info[tid]["url"]})
        parents = {parent_id(t) for t in mine if not ttp_filing.TACTIC_ID.match(t)}
        best: dict[tuple[str, str], dict] = {}
        for tid in sorted(parents, key=lambda t: (DOMAIN_ORDER.get(info[t]["domain"], 3) if t in info else 9, t)):
            row = info.get(tid)
            if row is None:
                continue
            key = (framework(tid), row["name"].lower())
            if key in best:
                best[key]["also"].append(tid)
                best[key]["subs"] += subs.get(tid, [])
            else:
                best[key] = {"id": tid, "name": row["name"], "framework": key[0], "tactics": json.loads(row["tactics"]),
                             "url": row["url"], "also": [], "subs": subs.get(tid, [])}
        a["ttps"] = sorted(best.values(), key=lambda t: (t["framework"], t["id"]))
        a["ttp_tactics"] = [{"id": t, "name": tactic_info[t]["name"], "framework": framework(t)}
                            for t in sorted(mine) if t in tactic_info]


def techniques_for(db, fw: str, tactic: str, limit: int = 40) -> list[dict]:
    """Techniques of one tactic that stored articles name, most-mentioned first (for the collection's technique strip)."""
    want = tactic.strip().lower()
    rows = db.execute("SELECT id, name, tactics, domain, url FROM attack_techniques WHERE is_subtechnique = 0 AND domain = ?",
                      ("atlas" if fw == "atlas" else "enterprise-attack",)).fetchall()
    slug = SLUG if fw == "atlas" else attack_sync.TECH_SLUG
    ents = {}
    for r in db.execute("SELECT e.id, e.name, (SELECT COUNT(*) FROM article_entities ae WHERE ae.entity_id = e.id) AS n "
                        "FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (slug,)):
        m = TTP_ID.search(r["name"])
        if m:
            ents[m.group(1)] = r["n"]
    out: dict[str, dict] = {}
    for r in sorted(rows, key=lambda r: (DOMAIN_ORDER.get(r["domain"], 3), r["id"])):
        if not any(t.lower() == want for t in json.loads(r["tactics"])):
            continue
        n = ents.get(r["id"], 0)
        if not n:
            continue
        key = r["name"].lower()
        if key in out:
            out[key]["articles"] = max(out[key]["articles"], n)
        else:
            out[key] = {"id": r["id"], "name": r["name"], "url": r["url"], "articles": n}
    return sorted(out.values(), key=lambda t: (-t["articles"], t["id"]))[:limit]
