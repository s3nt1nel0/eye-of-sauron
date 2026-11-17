"""MITRE ATT&CK: sync status, manual sync, and the synced groups (threat actors) with their techniques."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StringConstraints

import json

from app import atlas_sync, attack_sync, entities, intel, ttp_filing
from app.api.common import StrictModel, conflict, not_found
from app.db import get_db, now
from app.security import Principal, audit, rate_limit, require_admin, require_read, require_write

router = APIRouter(prefix="/attack", tags=["mitre-attack"])


@router.get("/status")
def status(_: Principal = Depends(require_read)) -> dict:
    return {**attack_sync.status(), "atlas": atlas_sync.status()}


@router.post("/sync", dependencies=[Depends(rate_limit("attack_sync", 4))])
def sync_now(principal: Principal = Depends(require_admin)) -> dict:
    """Check MITRE's ATT&CK and ATLAS releases now and apply new ones (or re-apply the current ones)."""
    started = [attack_sync.attack_sync.start(force=True), atlas_sync.atlas_sync.start(force=True)]
    if not any(started):
        raise conflict("An ATT&CK / ATLAS sync is already running")
    audit("attack_sync_requested", principal)
    return {"started": True}


@router.get("/techniques", dependencies=[Depends(rate_limit("attack_read", 240))])
def tactic_techniques(framework: Literal["attack", "atlas"],
                      tactic: Annotated[str, StringConstraints(min_length=2, max_length=60, pattern=r"^[A-Za-z &-]+$")],
                      _: Principal = Depends(require_read)) -> dict:
    """Techniques of one tactic that stored articles name, most-mentioned first (each with its article count)."""
    with get_db() as db:
        return {"items": atlas_sync.techniques_for(db, framework, tactic)}


@router.get("/groups", dependencies=[Depends(rate_limit("attack_read", 240))])
def list_groups(q: Annotated[str, StringConstraints(max_length=100)] = "",
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
                _: Principal = Depends(require_read)) -> dict:
    return attack_sync.groups(q.strip(), limit, offset)


@router.get("/groups/{group_id}")
def group(group_id: Annotated[str, StringConstraints(pattern=r"^G\d{4}$")], _: Principal = Depends(require_read)) -> dict:
    found = attack_sync.group_detail(group_id)
    if found is None:
        raise not_found("Group")
    return found


# ------------------------------------------------------------------ technique matrix
@router.get("/matrix", dependencies=[Depends(rate_limit("attack_read", 240))])
def technique_matrix(framework: Literal["attack", "atlas"], days: int = 30, _: Principal = Depends(require_read)) -> dict:
    """Tactics in kill-chain order with their techniques and how many stored articles name each (days = 0: all time)."""
    if days not in (0, 7, 30, 90, 365):
        raise HTTPException(status_code=422, detail="days must be 0, 7, 30, 90 or 365")
    with get_db() as db:
        return intel.matrix(db, framework, days)


# ------------------------------------------------------------------ "not this technique" feedback
TechniqueId = Annotated[str, StringConstraints(pattern=r"^(AML\.)?T\d{4}(\.\d{3})?$")]  # a technique or one sub-technique
AliasText = Annotated[str, StringConstraints(min_length=1, max_length=80)]


def _technique_entity(db, tid: str) -> int:
    eid = atlas_sync.entity_for(db, tid)
    if eid is None:
        raise not_found("Technique")
    return eid


def _refresh_after_mute(entity_ids: list[int]) -> None:
    """Re-index the technique (and its sub-techniques) without / with the name; the tactic collections are
    re-filed when the index is ready (background)."""
    entities.invalidate()
    entities.reindexer.request(entity_ids)


AnyTtpId = Annotated[str, StringConstraints(pattern=r"^(AML\.)?TA?\d{4}(\.\d{3})?$")]


@router.get("/techniques/{tid}/entity", dependencies=[Depends(rate_limit("attack_read", 240))])
def ttp_entity(tid: AnyTtpId, _: Principal = Depends(require_read)) -> dict:
    """The watchlist entity of a technique, sub-technique or tactic ID (its page is the entity's page)."""
    with get_db() as db:
        eid = atlas_sync.entity_for(db, tid)
    if eid is None:
        raise not_found("Technique")
    return {"id": tid, "entity_id": eid}


@router.get("/techniques/{tid}/why", dependencies=[Depends(rate_limit("attack_read", 240))])
def why_matched(tid: TechniqueId, article_id: int = Query(ge=1, le=2**31 - 1), _: Principal = Depends(require_read)) -> dict:
    """Which of the technique's names the article contains (so a wrong match can be reported precisely)."""
    with get_db() as db:
        eid = _technique_entity(db, tid)
        found = entities.matched_aliases(db, eid, article_id)
    ids = [a for a in found if attack_sync.TECH_ID.match(a) or a.startswith("AML.")]
    return {"technique": tid, "names": [a for a in found if a not in ids], "ids": ids}


class RejectIn(StrictModel):
    article_id: int = Field(ge=1, le=2**31 - 1)
    mute: AliasText | None = None  # also stop matching this name everywhere


@router.post("/techniques/{tid}/reject", dependencies=[Depends(rate_limit("attack_feedback", 60))])
def reject_technique(tid: TechniqueId, body: RejectIn, principal: Principal = Depends(require_write)) -> dict:
    """"Not this technique": take it off one article (it is never re-added there); with `mute`, also stop matching
    that name in every article (the technique still matches through its ID and its other names)."""
    with get_db() as db:
        eid = _technique_entity(db, tid)
        if db.execute("SELECT 1 FROM articles WHERE id = ?", (body.article_id,)).fetchone() is None:
            raise not_found("Article")
        if body.mute is not None and not attack_sync.set_muted(db, eid, body.mute, True):
            raise HTTPException(status_code=422, detail="That is not one of this technique's names")
        family = atlas_sync.family_entities(db, tid)  # the technique and its sub-techniques
        for member in family:
            if body.mute is not None and member != eid:
                attack_sync.set_muted(db, member, body.mute, True)  # the sub-technique that carries the same name
            db.execute("INSERT OR IGNORE INTO entity_rejections (article_id, entity_id, created_at) VALUES (?, ?, ?)",
                       (body.article_id, member, now()))
            db.execute("DELETE FROM article_entities WHERE article_id = ? AND entity_id = ?", (body.article_id, member))
        ttp_filing.file(db, [body.article_id])  # the tactic collections follow at once
    if body.mute is not None:
        _refresh_after_mute(family)
    audit("technique_rejected", principal, technique=tid, article_id=body.article_id, muted=body.mute or "")
    return {"ok": True, "muted": body.mute}


@router.get("/muted")
def muted_names(_: Principal = Depends(require_read)) -> dict:
    """Technique names you told the matcher to stop using."""
    items = []
    with get_db() as db:
        for r in db.execute("SELECT e.name, e.muted FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                            "WHERE w.slug IN (?, ?) AND e.muted != '[]' ORDER BY e.name COLLATE NOCASE", atlas_sync.TTP_SLUGS):
            m = atlas_sync.TTP_ID.search(r["name"])
            if m:
                items += [{"technique": m.group(1), "technique_name": r["name"], "name": a} for a in json.loads(r["muted"])]
    return {"items": items}


class RestoreIn(StrictModel):
    technique: TechniqueId
    name: AliasText


@router.post("/muted/restore", dependencies=[Depends(rate_limit("attack_feedback", 60))])
def restore_name(body: RestoreIn, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        eid = _technique_entity(db, body.technique)
        if not attack_sync.set_muted(db, eid, body.name, False):
            raise not_found("Muted name")
        family = atlas_sync.family_entities(db, body.technique)
        for member in family:
            if member != eid:
                attack_sync.set_muted(db, member, body.name, False)
    _refresh_after_mute(family)
    audit("technique_name_restored", principal, technique=body.technique, name=body.name)
    return {"ok": True}
