"""CVE tracking API: sync status/control, CVE details, classification categories."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, StringConstraints

from app import cve_analytics, cve_classify
from app.api.common import Name, StrictModel, conflict, not_found
from app.cve_sync import CVE_ID_RE, cve_sync, get_state
from app.db import get_db
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(prefix="/cves", tags=["cves"])

Keyword = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Pattern = Annotated[str, StringConstraints(min_length=1, max_length=140)]
SlugStr = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]


@router.get("/status")
def status(_: Principal = Depends(require_read)) -> dict:
    from app.config import get_settings

    with get_db() as db:
        counts = db.execute(
            "SELECT COUNT(*) AS total, COALESCE(SUM(kev), 0) AS kev, "
            "COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical, "
            "MIN(published) AS oldest, MAX(published) AS newest FROM cves WHERE status != 'Rejected'"
        ).fetchone()
        state = {k: get_state(db, k) for k in ("nvd_synced", "kev_synced", "cwe_synced", "last_finished", "last_error", "kev_count")}
        cwe_count = db.execute("SELECT COUNT(*) FROM cwe_entries").fetchone()[0]
    return {
        **dict(counts), "cwe_entries": cwe_count, "running": cve_sync.running, "progress": cve_sync.progress,
        "reclassifying": cve_classify.reclassifier.busy, "nvd_api_key": bool(get_settings().nvd_api_key),
        **{k: (int(v) if v and v.isdigit() else v) for k, v in state.items()},
    }


class SyncIn(StrictModel):
    force: bool = False  # also refresh the CWE catalog and KEV now


@router.post("/sync", dependencies=[Depends(rate_limit("cve_sync", 6))])
def sync_now(body: SyncIn, principal: Principal = Depends(require_write)) -> dict:
    audit("cve_sync_requested", principal, force=body.force)
    started = cve_sync.start(force=body.force)
    return {"started": started, "running": cve_sync.running}


@router.get("/meta")
def meta(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        return cve_analytics.meta(db)


@router.get("/{cve_id}")
def get_cve(cve_id: str, _: Principal = Depends(require_read)) -> dict:
    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(status_code=422, detail="Not a CVE identifier")
    with get_db() as db:
        row = db.execute("SELECT * FROM cves WHERE id = ?", (cve_id,)).fetchone()
        if row is None:
            raise not_found("CVE")
        out = dict(row)
        out["refs"] = json.loads(out["refs"])
        out["products"] = [dict(r) for r in db.execute(
            "SELECT vendor_label, product_label, vendor_key FROM cve_products WHERE cve_id = ? ORDER BY vendor_label", (cve_id,))]
        out["cwes"] = [dict(r) for r in db.execute(
            "SELECT w.cwe_id AS id, e.name FROM cve_cwes w LEFT JOIN cwe_entries e ON e.id = w.cwe_id WHERE w.cve_id = ?", (cve_id,))]
        out["owasp"] = [dict(r) for r in db.execute(
            "SELECT DISTINCT o.edition, o.code, o.name FROM cve_cwes w JOIN cwe_owasp o ON o.cwe_id = w.cwe_id "
            "WHERE w.cve_id = ? ORDER BY o.edition DESC, o.code", (cve_id,))]
        out["categories"] = [dict(r) for r in db.execute(
            "SELECT k.slug, k.name FROM cve_category_map m JOIN cve_categories k ON k.id = m.category_id "
            "WHERE m.cve_id = ? ORDER BY k.position", (cve_id,))]
    out["links"] = {"nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "cve_org": f"https://www.cve.org/CVERecord?id={cve_id}"}
    return out


# ============================================================================ categories
class CategoryIn(StrictModel):
    name: Name
    slug: SlugStr | None = None
    description: Annotated[str, StringConstraints(max_length=300)] = ""
    cwe_ids: list[Annotated[int, Field(ge=1, le=99999)]] = Field(default_factory=list, max_length=200)
    keywords: list[Keyword] = Field(default_factory=list, max_length=200)
    products: list[Pattern] = Field(default_factory=list, max_length=cve_classify.MAX_PATTERNS)
    enabled: bool = True


class CategoryPatch(StrictModel):
    name: Name | None = None
    description: Annotated[str, StringConstraints(max_length=300)] | None = None
    cwe_ids: list[Annotated[int, Field(ge=1, le=99999)]] | None = Field(default=None, max_length=200)
    keywords: list[Keyword] | None = Field(default=None, max_length=200)
    products: list[Pattern] | None = Field(default=None, max_length=cve_classify.MAX_PATTERNS)
    enabled: bool | None = None


def _patterns(products: list[str]) -> list[str]:
    try:
        return cve_classify.validate_patterns(products)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _category(db: sqlite3.Connection, cat_id: int) -> dict:
    for c in cve_analytics.meta(db)["categories"]:
        if c["id"] == cat_id:
            return c
    raise not_found("Category")


@router.post("/categories", status_code=201)
def create_category(body: CategoryIn, principal: Principal = Depends(require_write)) -> dict:
    audit("cve_category_created", principal, name=body.name)
    slug = body.slug or re.sub(r"[^a-z0-9]+", "-", body.name.lower()).strip("-")[:40] or "category"
    if not body.cwe_ids and not body.keywords and not body.products:
        raise HTTPException(status_code=422, detail="Add at least one CWE, keyword or product pattern")
    try:
        with get_db() as db:
            if db.execute("SELECT COUNT(*) FROM cve_categories").fetchone()[0] >= cve_classify.MAX_CATEGORIES:
                raise HTTPException(status_code=400, detail="Category limit reached")
            cur = db.execute(
                "INSERT INTO cve_categories (slug, name, description, enabled, cwe_ids, keywords, products, position) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1000)",
                (slug, body.name, body.description, int(body.enabled), json.dumps(sorted(set(body.cwe_ids))),
                 json.dumps(body.keywords), json.dumps(_patterns(body.products))),
            )
            cat = _category(db, int(cur.lastrowid))
    except sqlite3.IntegrityError:
        raise conflict("A category with that slug already exists") from None
    cve_classify.reclassifier.request()
    return cat


@router.patch("/categories/{cat_id}")
def update_category(cat_id: int, body: CategoryPatch, principal: Principal = Depends(require_write)) -> dict:
    audit("cve_category_updated", principal, category_id=cat_id)
    with get_db() as db:
        if db.execute("SELECT 1 FROM cve_categories WHERE id = ?", (cat_id,)).fetchone() is None:
            raise not_found("Category")
        sets = {
            "name": body.name, "description": body.description,
            "cwe_ids": json.dumps(sorted(set(body.cwe_ids))) if body.cwe_ids is not None else None,
            "keywords": json.dumps(body.keywords) if body.keywords is not None else None,
            "products": json.dumps(_patterns(body.products)) if body.products is not None else None,
            "enabled": int(body.enabled) if body.enabled is not None else None,
        }
        for column, value in sets.items():  # column names come from the fixed dict above
            if value is not None:
                db.execute(f"UPDATE cve_categories SET {column} = ? WHERE id = ?", (value, cat_id))  # nosec B608
        cat = _category(db, cat_id)
    cve_classify.reclassifier.request()
    return cat


@router.delete("/categories/{cat_id}")
def delete_category(cat_id: int, principal: Principal = Depends(require_write)) -> dict:
    audit("cve_category_deleted", principal, category_id=cat_id)
    with get_db() as db:
        if db.execute("DELETE FROM cve_categories WHERE id = ?", (cat_id,)).rowcount == 0:
            raise not_found("Category")
    return {"ok": True}
