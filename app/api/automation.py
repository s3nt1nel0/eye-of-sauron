"""Rules, webhooks, settings and OPML."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import Field, StringConstraints

from app import app_settings, collection_packs, opml, secretbox, webhooks
from app.api.common import HttpUrlStr, Keyword, Name, StrictModel, not_found
from app.config import get_settings
from app.db import get_db
from app.rules import KEV_CATEGORIES, apply_rules
from app.scheduler import scheduler
from app.security import Principal, audit, rate_limit, require_admin, require_read, require_write

log = logging.getLogger("eos.rules")
router = APIRouter()


# ============================================================================ rules
class RuleIn(StrictModel):
    name: Name
    keywords: list[Keyword] = Field(default_factory=list, max_length=100)  # [] = everything in the feed/folder scope
    exclude_keywords: list[Keyword] = Field(default_factory=list, max_length=100)
    require_keywords: list[Keyword] = Field(default_factory=list, max_length=100)  # AND: one of these must match too
    cve_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None  # article names a CVE of this severity
    cve_owasp: Annotated[str, StringConstraints(pattern=r"^(2021|2025):A(0[1-9]|10)$")] | None = None
    # ... or a CVE in this CVE-tracking category (slug), or "kev" / "kev-ransomware" (CISA KEV)
    cve_category: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,59}$")] | None = None
    # "title_opening" = the title and the opening lines of the article (stored as title_content + opening_only)
    match_in: Literal["title", "title_opening", "title_content"] = "title_content"
    keywords_in_title: bool = False  # the main keywords must be in the title; the other lists follow match_in
    feed_id: int | None = None
    folder_id: int | None = None
    tag_id: int | None = None
    webhook_id: int | None = None
    alert_channel_id: int | None = None   # instant alert to a delivery channel (admin only)
    ai_summarize: bool = False            # summarise matching new articles with the AI provider
    star: bool = False
    mark_read: bool = False
    enabled: bool = True
    position: int = Field(default=0, ge=0, le=100000)


def _rule_out(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["keywords"] = json.loads(row["keywords"])
    out["exclude_keywords"] = json.loads(row["exclude_keywords"])
    out["require_keywords"] = json.loads(row["require_keywords"] or "[]")
    for key in ("star", "mark_read", "enabled", "ai_summarize", "keywords_in_title"):
        out[key] = bool(out[key])
    if out.pop("opening_only", 0) and out["match_in"] == "title_content":
        out["match_in"] = "title_opening"
    return out


def _stored_match(match_in: str) -> tuple[str, int]:
    """API match_in -> (rules.match_in, rules.opening_only)."""
    return ("title_content", 1) if match_in == "title_opening" else (match_in, 0)


def _check_refs(db: sqlite3.Connection, body: RuleIn, principal: Principal) -> None:
    if body.alert_channel_id is not None and "admin" not in principal.scopes:
        # Alert rules make the server send messages to external services.
        raise HTTPException(status_code=403, detail="Missing scope: admin")
    checks = (("feeds", body.feed_id, "Feed"), ("folders", body.folder_id, "Folder"),
              ("tags", body.tag_id, "Collection"), ("webhooks", body.webhook_id, "Webhook"),
              ("delivery_channels", body.alert_channel_id, "Delivery channel"))
    for table, value, label in checks:
        # table names come from the constant tuple above, never from the request
        if value is not None and db.execute(f"SELECT 1 FROM {table} WHERE id = ?", (value,)).fetchone() is None:
            raise HTTPException(status_code=422, detail=f"{label} does not exist")
    if body.cve_category and body.cve_category not in KEV_CATEGORIES and db.execute(
            "SELECT 1 FROM cve_categories WHERE slug = ?", (body.cve_category,)).fetchone() is None:
        raise HTTPException(status_code=422, detail="CVE category does not exist")
    if not body.keywords and body.feed_id is None and body.folder_id is None and not (
            body.cve_severity or body.cve_owasp or body.cve_category):
        raise HTTPException(status_code=422, detail="Add keywords, or limit the rule to a feed or folder, or set a CVE condition")
    if (body.tag_id is None and body.webhook_id is None and body.alert_channel_id is None and not body.ai_summarize and not body.star and not body.mark_read):
        raise HTTPException(status_code=422, detail="A rule needs at least one action")


def _rule_values(body: RuleIn) -> tuple:
    match_in, opening_only = _stored_match(body.match_in)
    return (
        body.name, json.dumps(body.keywords), json.dumps(body.exclude_keywords), match_in,
        body.feed_id, body.folder_id, body.tag_id, body.webhook_id,
        int(body.star), int(body.mark_read), int(body.enabled), body.position,
        body.alert_channel_id, int(body.ai_summarize),
        json.dumps(body.require_keywords), body.cve_severity, body.cve_owasp, int(body.keywords_in_title),
        body.cve_category, opening_only,
    )


@router.get("/rules", tags=["rules"])
def list_rules(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [_rule_out(r) for r in db.execute("SELECT * FROM rules ORDER BY position, id")]


@router.post("/rules", status_code=201, tags=["rules"])
def create_rule(body: RuleIn, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        _check_refs(db, body, principal)
        if db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] >= 500:
            raise HTTPException(status_code=400, detail="Rule limit reached")
        cur = db.execute(
            "INSERT INTO rules (name, keywords, exclude_keywords, match_in, feed_id, folder_id, tag_id, "
            "webhook_id, star, mark_read, enabled, position, alert_channel_id, ai_summarize, "
            "require_keywords, cve_severity, cve_owasp, keywords_in_title, cve_category, opening_only) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            _rule_values(body),
        )
        return _rule_out(db.execute("SELECT * FROM rules WHERE id = ?", (cur.lastrowid,)).fetchone())


@router.put("/rules/{rule_id}", tags=["rules"])
def replace_rule(rule_id: int, body: RuleIn, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        _check_refs(db, body, principal)
        current = db.execute("SELECT alert_channel_id FROM rules WHERE id = ?", (rule_id,)).fetchone()
        if current is not None and current["alert_channel_id"] is not None and "admin" not in principal.scopes:
            raise HTTPException(status_code=403, detail="Missing scope: admin")
        cur = db.execute(
            "UPDATE rules SET name=?, keywords=?, exclude_keywords=?, match_in=?, feed_id=?, folder_id=?, "
            "tag_id=?, webhook_id=?, star=?, mark_read=?, enabled=?, position=?, "
            "alert_channel_id=?, ai_summarize=?, require_keywords=?, cve_severity=?, cve_owasp=?, keywords_in_title=?, "
            "cve_category=?, opening_only=? "
            "WHERE id = ?",
            (*_rule_values(body), rule_id),
        )
        if cur.rowcount == 0:
            raise not_found("Rule")
        return _rule_out(db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone())


@router.delete("/rules/{rule_id}", tags=["rules"])
def delete_rule(rule_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM rules WHERE id = ?", (rule_id,)).rowcount == 0:
            raise not_found("Rule")
    return {"ok": True}


BACKFILL_LIMIT = 200_000


def _backfill_rules(rule_ids: list[int]) -> int:
    """Run rules over stored articles, newest first (webhooks/alerts are NOT fired for back-fills)."""
    with get_db() as db:
        ids = [r[0] for r in db.execute("SELECT id FROM articles ORDER BY id DESC LIMIT ?", (BACKFILL_LIMIT,))]
    for start in range(0, len(ids), 2000):  # short transactions so the fetcher is never blocked for long
        with get_db() as db:
            apply_rules(db, ids[start : start + 2000], rule_ids=rule_ids)
    return len(ids)


_pack_job: dict[str, Any] = {"running": False, "packs": None, "rules": 0, "error": None}
_pack_lock = threading.Lock()


def _run_pack_backfill(rule_ids: list[int]) -> None:
    try:
        _backfill_rules(rule_ids)
    except Exception as exc:  # noqa: BLE001 - reported to the UI, never raised out of the thread
        _pack_job["error"] = type(exc).__name__
    finally:
        _pack_job["running"] = False


@router.post("/rules/{rule_id}/apply", tags=["rules"], dependencies=[Depends(rate_limit("rule_apply", 10))])
def apply_rule_to_existing(rule_id: int, _: Principal = Depends(require_write)) -> dict:
    """Run one rule over all stored articles (webhooks are NOT fired for back-fills)."""
    with get_db() as db:
        if db.execute("SELECT 1 FROM rules WHERE id = ? AND enabled = 1", (rule_id,)).fetchone() is None:
            raise not_found("Enabled rule")
        before = db.execute("SELECT COUNT(*) FROM article_tags").fetchone()[0]
    scanned = _backfill_rules([rule_id])
    with get_db() as db:
        after = db.execute("SELECT COUNT(*) FROM article_tags").fetchone()[0]
    return {"scanned": scanned, "newly_filed": after - before}


def _install_pack(db: sqlite3.Connection, pack: collection_packs.Pack) -> tuple[list[int], int]:
    """Create the pack's collections and rules; existing ones (same name) are left untouched."""
    new_rule_ids: list[int] = []
    created_tags = 0
    for coll in pack["collections"]:
        created_tags += db.execute("INSERT OR IGNORE INTO tags (name, color) VALUES (?, ?)",
                                   (coll["name"], coll["color"])).rowcount
        tag_id = db.execute("SELECT id FROM tags WHERE name = ?", (coll["name"],)).fetchone()["id"]
        for index, spec in enumerate(coll["rules"]):
            name = collection_packs.rule_name(coll["name"], index)
            if db.execute("SELECT 1 FROM rules WHERE name = ?", (name,)).fetchone():
                continue
            folder_id = None
            if spec.get("folder"):
                db.execute("INSERT OR IGNORE INTO folders (name) VALUES (?)", (spec["folder"],))
                folder_id = db.execute("SELECT id FROM folders WHERE name = ?", (spec["folder"],)).fetchone()["id"]
            match_in, opening_only = _stored_match(spec.get("match_in", "title_content"))
            cur = db.execute(
                "INSERT INTO rules (name, keywords, exclude_keywords, require_keywords, match_in, folder_id, tag_id, "
                "cve_severity, cve_owasp, keywords_in_title, position, cve_category, opening_only) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, json.dumps(spec.get("keywords", [])), json.dumps(spec.get("exclude", [])),
                 json.dumps(spec.get("require", [])), match_in, folder_id, tag_id,
                 spec.get("cve_severity"), spec.get("cve_owasp"), int(spec.get("title_keywords", False)), 1000,
                 spec.get("cve_category"), opening_only),
            )
            new_rule_ids.append(int(cur.lastrowid))
    return new_rule_ids, created_tags


def _spec_matches(row: sqlite3.Row, spec: collection_packs.RuleSpec) -> bool:
    """True when an installed rule is exactly what the pack spec would install (keywords compared case-insensitively)."""
    def norm(raw: str | None) -> list[str]:
        return sorted(str(k).lower() for k in json.loads(raw or "[]"))
    match_in, opening_only = _stored_match(spec.get("match_in", "title_content"))
    return (norm(row["keywords"]) == sorted(k.lower() for k in spec.get("keywords", []))
            and norm(row["require_keywords"]) == sorted(k.lower() for k in spec.get("require", []))
            and norm(row["exclude_keywords"]) == sorted(k.lower() for k in spec.get("exclude", []))
            and row["match_in"] == match_in and int(row["opening_only"] or 0) == opening_only
            and bool(row["keywords_in_title"]) == bool(spec.get("title_keywords", False))
            and row["feed_id"] is None and not spec.get("folder"))


def upgrade_pack_rules() -> dict:
    """Once per pack revision: bring unedited "Auto: ..." rules up to the current pack spec, add rules the spec gained,
    take out filings the stricter rules no longer make and file what the new rules match. Rules you edited stay as they are."""
    from app.cve_sync import get_state, set_state
    from app.rules import refile_tags

    with get_db() as db:
        if get_state(db, "pack_rules_rev", "") == collection_packs.PACK_RULES_REV:
            return {"upgraded": 0}
        changed: list[int] = []
        tags: set[int] = set()
        for name, old in collection_packs.PREVIOUS.items():
            row = db.execute("SELECT * FROM rules WHERE name = ?", (name,)).fetchone()
            if row is None or not _spec_matches(row, old):
                continue
            coll, index, spec = collection_packs.CURRENT[name]
            match_in, opening_only = _stored_match(spec.get("match_in", "title_content"))
            db.execute("UPDATE rules SET keywords = ?, require_keywords = ?, exclude_keywords = ?, match_in = ?, "
                       "opening_only = ?, keywords_in_title = ? WHERE id = ?",
                       (json.dumps(spec.get("keywords", [])), json.dumps(spec.get("require", [])),
                        json.dumps(spec.get("exclude", [])), match_in, opening_only,
                        int(spec.get("title_keywords", False)), row["id"]))
            changed.append(row["id"])
            if row["tag_id"] is not None:
                tags.add(row["tag_id"])
            # rules the collection gained (e.g. "Auto: APT & Nation-State #2"), only beside an upgraded first rule
            for extra, (ecoll, eindex, espec) in collection_packs.CURRENT.items():
                if ecoll != coll or eindex <= index or row["tag_id"] is None:
                    continue
                if db.execute("SELECT 1 FROM rules WHERE name = ?", (extra,)).fetchone():
                    continue
                emi, eoo = _stored_match(espec.get("match_in", "title_content"))
                changed.append(int(db.execute(
                    "INSERT INTO rules (name, keywords, exclude_keywords, require_keywords, match_in, tag_id, "
                    "keywords_in_title, position, opening_only, enabled) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (extra, json.dumps(espec.get("keywords", [])), json.dumps(espec.get("exclude", [])),
                     json.dumps(espec.get("require", [])), emi, row["tag_id"], int(espec.get("title_keywords", False)),
                     row["position"], eoo, row["enabled"])).lastrowid))
        set_state(db, "pack_rules_rev", collection_packs.PACK_RULES_REV)
    removed = refile_tags(sorted(tags)) if tags else 0
    if changed:
        _backfill_rules(changed)
    log.info("Collection rules upgraded: %d rules, %d filings no longer matched", len(changed), removed)
    return {"upgraded": len(changed), "removed": removed}


@router.get("/rules/packs", tags=["rules"])
def list_packs(_: Principal = Depends(require_read)) -> dict:
    """Ready-made collection packs and how much of each is installed."""
    with get_db() as db:
        names = {r[0].lower() for r in db.execute("SELECT name FROM tags")}
        rule_names = {r[0] for r in db.execute("SELECT name FROM rules")}
    packs = []
    for p in collection_packs.PACKS:
        wanted = [collection_packs.rule_name(c["name"], i) for c in p["collections"] for i in range(len(c["rules"]))]
        packs.append({"slug": p["slug"], "title": p["title"], "description": p["description"],
                      "collections": [c["name"] for c in p["collections"]],
                      "installed": sum(1 for c in p["collections"] if c["name"].lower() in names),
                      "rules_missing": sum(1 for n in wanted if n not in rule_names)})
    return {"packs": packs, "backfill": dict(_pack_job)}


class PackInstallIn(StrictModel):
    slugs: list[Annotated[str, StringConstraints(pattern=r"^[a-z]{2,20}$")]] = Field(min_length=1, max_length=20)


@router.post("/rules/packs", tags=["rules"], dependencies=[Depends(rate_limit("rule_packs", 6))])
def install_packs(body: PackInstallIn, principal: Principal = Depends(require_write)) -> dict:
    """Install one or more packs (idempotent). New rules are back-filled over stored articles in the background."""
    unknown = [s for s in body.slugs if s not in collection_packs.PACK_BY_SLUG]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown pack: {unknown[0]}")
    slugs = list(dict.fromkeys(body.slugs))
    rule_ids: list[int] = []
    tags = 0
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM rules").fetchone()[0] >= 400:
            raise HTTPException(status_code=400, detail="Rule limit reached")
        for slug in slugs:
            ids, created = _install_pack(db, collection_packs.PACK_BY_SLUG[slug])
            rule_ids += ids
            tags += created
    if {"attack", "atlas"} & set(slugs):  # these are filed from the techniques articles name, not by keyword rules
        from app import ttp_filing

        ttp_filing.refile_all()
    started = False
    if rule_ids:
        with _pack_lock:
            if not _pack_job["running"]:
                _pack_job.update(running=True, packs=",".join(slugs), rules=len(rule_ids), error=None)
                threading.Thread(target=_run_pack_backfill, args=(rule_ids,), name="pack-backfill", daemon=True).start()
                started = True
    audit("collection_packs_installed", principal, packs=",".join(slugs), rules=len(rule_ids))
    return {"collections_created": tags, "rules_created": len(rule_ids), "backfill_started": started,
            "backfill_busy": bool(rule_ids) and not started}


@router.post("/rules/packs/remove", tags=["rules"], dependencies=[Depends(rate_limit("rule_packs", 6))])
def remove_packs(body: PackInstallIn, principal: Principal = Depends(require_write)) -> dict:
    """Delete the packs' collections (and every filing in them) and their "Auto: ..." rules."""
    unknown = [s for s in body.slugs if s not in collection_packs.PACK_BY_SLUG]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown pack: {unknown[0]}")
    tags = rules = 0
    with get_db() as db:
        for slug in dict.fromkeys(body.slugs):
            for coll in collection_packs.PACK_BY_SLUG[slug]["collections"]:
                base = collection_packs.rule_name(coll["name"], 0)
                # "Auto: X" and its numbered extras "Auto: X #2"...; LIKE metacharacters in names are escaped
                pattern = base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + " #%"
                rules += db.execute("DELETE FROM rules WHERE name = ? OR name LIKE ? ESCAPE '\\'", (base, pattern)).rowcount
                tags += db.execute("DELETE FROM tags WHERE name = ?", (coll["name"],)).rowcount
            if slug in ("attack", "atlas"):  # the collections follow MITRE's matrix: remove them by their prefix
                prefix = "ATT&CK: " if slug == "attack" else "ATLAS: "
                tags += db.execute("DELETE FROM tags WHERE name LIKE ?", (prefix + "%",)).rowcount
    audit("collection_packs_removed", principal, packs=",".join(body.slugs), rules=rules, collections=tags)
    return {"collections_removed": tags, "rules_removed": rules}


@router.post("/rules/starter-pack", tags=["rules"])
def install_starter_pack(_: Principal = Depends(require_write)) -> dict:
    """Create the core cyber-security collections plus matching keyword rules (idempotent).

    New rules are also back-filled over already-stored articles (no webhooks fired).
    """
    with get_db() as db:
        new_rule_ids, _created = _install_pack(db, collection_packs.PACK_BY_SLUG["core"])
    if new_rule_ids:
        _backfill_rules(new_rule_ids)
    return {"rules_created": len(new_rule_ids)}


# ============================================================================ webhooks
Secret = Annotated[str, StringConstraints(min_length=16, max_length=200)]


class WebhookIn(StrictModel):
    name: Name
    url: HttpUrlStr
    secret: Secret | None = None
    enabled: bool = True


class WebhookPatch(StrictModel):
    name: Name | None = None
    url: HttpUrlStr | None = None
    secret: Secret | None = None
    clear_secret: bool = False
    enabled: bool | None = None


def _webhook_out(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["has_secret"] = bool(out.pop("secret"))  # never return the secret
    out["enabled"] = bool(out["enabled"])
    return out


@router.get("/webhooks", tags=["webhooks"])
def list_webhooks(_: Principal = Depends(require_admin)) -> list[dict]:
    with get_db() as db:
        return [_webhook_out(r) for r in db.execute("SELECT * FROM webhooks ORDER BY name")]


@router.post("/webhooks", status_code=201, tags=["webhooks"])
def create_webhook(body: WebhookIn, principal: Principal = Depends(require_admin)) -> dict:
    audit("webhook_created", principal, name=body.name, url=body.url, signed=bool(body.secret))
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0] >= 50:
            raise HTTPException(status_code=400, detail="Webhook limit reached")
        cur = db.execute(
            "INSERT INTO webhooks (name, url, secret, enabled) VALUES (?, ?, ?, ?)",
            (body.name, body.url, secretbox.encrypt(body.secret) if body.secret else None, int(body.enabled)),
        )
        return _webhook_out(db.execute("SELECT * FROM webhooks WHERE id = ?", (cur.lastrowid,)).fetchone())


@router.patch("/webhooks/{webhook_id}", tags=["webhooks"])
def update_webhook(webhook_id: int, body: WebhookPatch, principal: Principal = Depends(require_admin)) -> dict:
    audit("webhook_updated", principal, webhook_id=webhook_id, fields=",".join(sorted(body.model_fields_set)))
    with get_db() as db:
        if db.execute("SELECT 1 FROM webhooks WHERE id = ?", (webhook_id,)).fetchone() is None:
            raise not_found("Webhook")
        if body.name is not None:
            db.execute("UPDATE webhooks SET name = ? WHERE id = ?", (body.name, webhook_id))
        if body.url is not None:
            db.execute("UPDATE webhooks SET url = ? WHERE id = ?", (body.url, webhook_id))
        if body.clear_secret:
            db.execute("UPDATE webhooks SET secret = NULL WHERE id = ?", (webhook_id,))
        elif body.secret is not None:
            db.execute("UPDATE webhooks SET secret = ? WHERE id = ?", (secretbox.encrypt(body.secret), webhook_id))
        if body.enabled is not None:
            db.execute("UPDATE webhooks SET enabled = ? WHERE id = ?", (int(body.enabled), webhook_id))
        return _webhook_out(db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone())


@router.delete("/webhooks/{webhook_id}", tags=["webhooks"])
def delete_webhook(webhook_id: int, principal: Principal = Depends(require_admin)) -> dict:
    audit("webhook_deleted", principal, webhook_id=webhook_id)
    with get_db() as db:
        if db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,)).rowcount == 0:
            raise not_found("Webhook")
    return {"ok": True}


@router.post("/webhooks/{webhook_id}/test", tags=["webhooks"], dependencies=[Depends(rate_limit("webhook_test", 10))])
def test_webhook(webhook_id: int, _: Principal = Depends(require_admin)) -> dict:
    ok, message = webhooks.send(webhook_id, {"event": "test", "message": "Eye of Sauron webhook test"})
    return {"ok": ok, "message": message}


# ============================================================================ settings
@router.get("/settings", tags=["settings"])
def get_app_settings(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        return app_settings.get_all(db)


@router.patch("/settings", tags=["settings"])
def patch_app_settings(changes: dict[str, Any], principal: Principal = Depends(require_admin)) -> dict:
    if len(changes) > len(app_settings.SCHEMA):
        raise HTTPException(status_code=422, detail="Too many keys")
    try:
        with get_db() as db:
            result = app_settings.update(db, changes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=exc.args[0]) from None
    scheduler.wake()
    audit("settings_changed", principal, keys=",".join(sorted(changes)))
    if "story_grouping" in changes or "story_match" in changes:
        from app import stories

        stories.ensure_current()  # regroups in the background when the setting really changed
    if "ttp_everyday_terms" in changes:
        from app import attack_sync

        threading.Thread(target=attack_sync.refresh_aliases, name="attack-names", daemon=True).start()
    return result


# ============================================================================ OPML
@router.get("/opml/export", tags=["opml"])
def export_opml(_: Principal = Depends(require_read)) -> Response:
    with get_db() as db:
        data = opml.export_opml(db)
    return Response(
        content=data,
        media_type="text/x-opml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="eye-of-sauron.opml"'},
    )


@router.post("/opml/import", tags=["opml"], dependencies=[Depends(rate_limit("opml_import", 6))])
async def import_opml(request: Request, _: Principal = Depends(require_write)) -> dict:
    """Body: the raw OPML XML document (Content-Type: text/xml or application/xml)."""
    data = await request.body()
    if len(data) > get_settings().max_opml_bytes:
        raise HTTPException(status_code=413, detail="OPML file too large")
    def _import() -> dict:
        with get_db() as db:
            return opml.import_opml(db, data)

    try:
        result = await run_in_threadpool(_import)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    scheduler.wake()
    return result
