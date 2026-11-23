"""🔗 Resources tab: websites, training platforms, courses, labs, cheat sheets, tools and docs, sorted into categories.

Reading needs read scope; adding, importing, editing, categories and bulk changes need write scope. Nothing here makes an
outbound request (titles come from bookmarks or the address)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StringConstraints

from app import resources
from app.api.common import Color, StrictModel, conflict, not_found
from app.config import get_settings
from app.db import get_db, now, placeholders
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(prefix="/resources", tags=["resources"])

Kind = Literal["course", "labs", "ctf", "platform", "cheatsheet", "tool", "docs", "blog", "video", "repo", "community", "site"]
Status = Literal["todo", "doing", "done"]
SORTS = {"title": "r.title COLLATE NOCASE ASC", "added": "r.added_at DESC, r.id DESC", "opened": "r.last_opened IS NULL, r.last_opened DESC, r.id DESC",
         "popular": "r.open_count DESC, r.title COLLATE NOCASE", "host": "r.host, r.title COLLATE NOCASE"}
COLUMNS = "r.id, r.url, r.title, r.host, r.kind, r.trail, r.notes, r.summary, r.status, r.favourite, r.manual, r.open_count, r.last_opened, r.added_at"
MAX_CATEGORIES = 200


def _cats_of(db, ids: list[int]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in db.execute(f"SELECT resource_id, category_id FROM resource_category_items WHERE resource_id IN ({placeholders(len(chunk))})", chunk):  # nosec B608
            out.setdefault(r[0], []).append(r[1])
    return out


def _row(r, cats: dict[int, list[int]], folders: dict[int, list[int]] | None = None) -> dict:
    d = dict(r)
    d["favourite"], d["manual"] = bool(d["favourite"]), bool(d["manual"])
    d["categories"] = cats.get(d["id"], [])
    d["folders"] = (folders or {}).get(d["id"], [])
    return d


def _folders_of(db, ids: list[int]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for r in db.execute(f"SELECT resource_id, folder_id FROM resource_folder_items WHERE resource_id IN ({placeholders(len(chunk))})", chunk):  # nosec B608
            out.setdefault(r[0], []).append(r[1])
    return out


@router.get("/meta", dependencies=[Depends(rate_limit("resources_read", 240))])
def meta(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        resources.seed_categories(db)
        cats = [dict(r) for r in db.execute(
            "SELECT c.id, c.key, c.name, c.emoji, c.color, c.position, (SELECT COUNT(*) FROM resource_category_items i WHERE i.category_id = c.id) AS count "
            "FROM resource_categories c ORDER BY c.position, c.name COLLATE NOCASE")]
        fav = db.execute(f"SELECT {COLUMNS} FROM resources r WHERE r.favourite = 1 ORDER BY r.open_count DESC, r.title COLLATE NOCASE LIMIT 40").fetchall()  # nosec B608
        recent = db.execute(f"SELECT {COLUMNS} FROM resources r WHERE r.last_opened IS NOT NULL ORDER BY r.last_opened DESC LIMIT 12").fetchall()  # nosec B608
        cmap = _cats_of(db, [r["id"] for r in [*fav, *recent]])
        return {
            "total": db.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
            "training": db.execute(f"SELECT COUNT(*) FROM resources WHERE kind IN ({placeholders(len(resources.TRAINING_KINDS))})",  # nosec B608
                                   resources.TRAINING_KINDS).fetchone()[0],
            "uncategorised": db.execute("SELECT COUNT(*) FROM resources WHERE id NOT IN (SELECT resource_id FROM resource_category_items)").fetchone()[0],
            "kinds": {k: n for k, n in db.execute("SELECT kind, COUNT(*) FROM resources GROUP BY kind")},
            "kind_labels": resources.KINDS,
            "categories": cats,
            "favourites": [_row(r, cmap) for r in fav],
            "recent": [_row(r, cmap) for r in recent],
        }


@router.get("", dependencies=[Depends(rate_limit("resources_read", 240))])
def list_resources(q: Annotated[str, StringConstraints(max_length=200)] = "", category_id: int | None = Query(None, ge=0, le=2**31),
                   folder_id: int | None = Query(None, ge=0, le=2**31), include_sub: bool = False,
                   kind: Kind | None = None, training: bool = False, status: Status | None = None, favourite: bool = False,
                   sort: Literal["title", "added", "opened", "popular", "host"] = "title",
                   limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000), _: Principal = Depends(require_read)) -> dict:
    where, params = ["1 = 1"], []
    if q.strip():
        for word in q.strip().split()[:8]:   # every word must appear somewhere (title, address, notes, summary, folder trail)
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(r.title LIKE ? ESCAPE '\\' OR r.url LIKE ? ESCAPE '\\' OR r.notes LIKE ? ESCAPE '\\' OR r.summary LIKE ? ESCAPE '\\' "
                         "OR r.trail LIKE ? ESCAPE '\\')")
            params += [like] * 5
    if category_id is not None:
        if category_id == 0:
            where.append("r.id NOT IN (SELECT resource_id FROM resource_category_items)")
        else:
            where.append("r.id IN (SELECT resource_id FROM resource_category_items WHERE category_id = ?)")
            params.append(category_id)
    if folder_id is not None:
        if folder_id == 0:
            where.append("r.id NOT IN (SELECT resource_id FROM resource_folder_items)")
        elif include_sub:
            where.append("r.id IN (SELECT resource_id FROM resource_folder_items WHERE folder_id IN (WITH RECURSIVE sub(id) AS "
                         "(SELECT ? UNION ALL SELECT f.id FROM resource_folders f JOIN sub ON f.parent_id = sub.id) SELECT id FROM sub))")
            params.append(folder_id)
        else:
            where.append("r.id IN (SELECT resource_id FROM resource_folder_items WHERE folder_id = ?)")
            params.append(folder_id)
    if kind:
        where.append("r.kind = ?")
        params.append(kind)
    if training:
        where.append(f"r.kind IN ({placeholders(len(resources.TRAINING_KINDS))})")
        params += list(resources.TRAINING_KINDS)
    if status:
        where.append("r.status = ?")
        params.append(status)
    if favourite:
        where.append("r.favourite = 1")
    clause = " AND ".join(where)
    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM resources r WHERE {clause}", params).fetchone()[0]  # nosec B608 - fixed fragments
        rows = db.execute(f"SELECT {COLUMNS} FROM resources r WHERE {clause} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()  # nosec B608
        cmap = _cats_of(db, [r["id"] for r in rows])
        fmap = _folders_of(db, [r["id"] for r in rows])
        return {"total": total, "items": [_row(r, cmap, fmap) for r in rows]}


class BatchIn(StrictModel):
    lines: Annotated[list[Annotated[str, StringConstraints(max_length=2400)]], Field(min_length=1, max_length=500)]
    category_id: int | None = Field(None, ge=1, le=2**31)
    folder_id: int | None = Field(None, ge=1, le=2**31)   # put them in this folder (also links already here)
    auto_file: bool = True                                # else: file new links into the topics that fit them best
    read_pages: bool = False                              # read each new page's title + description (≤ READ_PAGES_MAX lines)


READ_PAGES_MAX = 20


class ImportIn(StrictModel):
    html: Annotated[str, StringConstraints(min_length=1, max_length=5 * 1024 * 1024)]
    category_id: int | None = Field(None, ge=1, le=2**31)
    preview: bool = False        # only list the folders (with counts) so you can untick the ones to leave out
    make_folders: bool = True    # recreate your bookmark folders (and subfolders) and file each link there
    skip_folders: Annotated[list[Annotated[str, StringConstraints(max_length=600)]], Field(max_length=2000)] = []


def _folder_counts(items: list[dict]) -> tuple[list[dict], int]:
    """Every folder (and parent folder) in the file with how many links sit in it or below it, in file order."""
    counts: dict[str, int] = {}
    loose = 0
    for it in items:
        trail = (it.get("trail") or "").strip()
        if not trail:
            loose += 1
            continue
        parts = [p for p in trail.split(" / ") if p]
        for depth in range(1, len(parts) + 1):
            path = " / ".join(parts[:depth])
            counts[path] = counts.get(path, 0) + 1
    return [{"path": p, "name": p.rsplit(" / ", 1)[-1], "depth": p.count(" / "), "count": n} for p, n in counts.items()][:2000], loose


def _skipped(trail: str, skip: set[str]) -> bool:
    trail = (trail or "").strip()
    return any(trail == s or trail.startswith(s + " / ") for s in skip)


def _check_category(db, cid: int | None) -> None:
    if cid and not db.execute("SELECT 1 FROM resource_categories WHERE id = ?", (cid,)).fetchone():
        raise not_found("Category")


@router.post("/batch", dependencies=[Depends(rate_limit("resources_write", 30))])
def add_batch(body: BatchIn, principal: Principal = Depends(require_write)) -> dict:
    """Add pasted lines ("address", or "title | address"). Duplicates are reported, not added twice."""
    items = resources.parse_lines(body.lines)
    pages: dict[str, dict[str, str]] | None = None
    with get_db() as db:
        _check_category(db, body.category_id)
        if body.folder_id:
            _folder(db, body.folder_id)
        have = {resources.url_key(r[0]) for r in db.execute("SELECT url FROM resources")}
    if body.read_pages:                                      # outside the database: the network can be slow
        fresh = []
        for it in items:
            u = resources.clean_url(it.get("url") or "")
            if u and resources.url_key(u) not in have and u not in fresh:
                fresh.append(u)
        cfg = get_settings()
        pages = {u: resources.page_info(u, cfg.user_agent, min(cfg.fetch_timeout, 10)) for u in fresh[:READ_PAGES_MAX]}
    with get_db() as db:
        cats = resources.seed_categories(db)
        out = resources.store(db, items, cats, body.category_id, target_folder=body.folder_id,
                              auto_file=body.auto_file and not body.folder_id, pages=pages)
    out["pages_read"] = sum(1 for v in (pages or {}).values() if v)
    audit("resources_added", principal, added=out["added"], skipped=out["skipped"], pages_read=out["pages_read"])
    return out


@router.post("/import", dependencies=[Depends(rate_limit("resources_import", 6))])
def import_bookmarks(body: ImportIn, principal: Principal = Depends(require_write)) -> dict:
    """Import a browser bookmarks export (Netscape HTML). Folders are kept as a trail and help the sorting."""
    try:
        items = resources.parse_bookmarks(body.html)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if not items:
        raise HTTPException(status_code=422, detail="No bookmarks found - export them from your browser as an HTML file.")
    if body.preview:   # nothing is saved: the folders, so you can leave some out (personal, shopping…)
        folders, loose = _folder_counts(items)
        return {"found": len(items), "folders": folders, "no_folder": loose}
    if body.skip_folders:
        skip = {s.strip() for s in body.skip_folders if s.strip()}
        left_out = sum(1 for it in items if _skipped(it.get("trail", ""), skip))
        items = [it for it in items if not _skipped(it.get("trail", ""), skip)]
    else:
        left_out = 0
    with get_db() as db:
        _check_category(db, body.category_id)
        cats = resources.seed_categories(db)
        out = resources.store(db, items, cats, body.category_id, folders=body.make_folders)
    audit("resources_imported", principal, found=len(items), added=out["added"], skipped=out["skipped"], left_out=left_out)
    out["found"] = len(items) + left_out
    out["left_out"] = left_out
    out.pop("results", None)
    return out


class ResourcePatch(StrictModel):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)] | None = None
    notes: Annotated[str, StringConstraints(max_length=4000)] | None = None
    summary: Annotated[str, StringConstraints(strip_whitespace=True, max_length=600)] | None = None
    status: Status | Literal[""] | None = None
    kind: Kind | None = None
    favourite: bool | None = None
    category_ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(max_length=50)] | None = None


@router.patch("/{resource_id}", dependencies=[Depends(rate_limit("resources_write", 240))])
def update_resource(resource_id: int, body: ResourcePatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT 1 FROM resources WHERE id = ?", (resource_id,)).fetchone() is None:
            raise not_found("Resource")
        sets, params = [], []
        for col in ("title", "notes", "summary", "kind"):
            v = getattr(body, col)
            if v is not None:
                sets.append(f"{col} = ?")
                params.append(v)
        if body.status is not None:
            sets.append("status = ?")
            params.append(body.status or None)
        if body.favourite is not None:
            sets.append("favourite = ?")
            params.append(int(body.favourite))
        if body.category_ids is not None:
            known = {r[0] for r in db.execute("SELECT id FROM resource_categories")}
            if any(c not in known for c in body.category_ids):
                raise not_found("Category")
            db.execute("DELETE FROM resource_category_items WHERE resource_id = ?", (resource_id,))
            db.executemany("INSERT OR IGNORE INTO resource_category_items (category_id, resource_id) VALUES (?, ?)",
                           [(c, resource_id) for c in dict.fromkeys(body.category_ids)])
            sets.append("manual = 1")   # your choice: automatic sorting leaves it alone from now on
        if sets:
            db.execute(f"UPDATE resources SET {', '.join(sets)}, updated_at = ? WHERE id = ?", [*params, now(), resource_id])  # nosec B608
        row = db.execute(f"SELECT {COLUMNS} FROM resources r WHERE r.id = ?", (resource_id,)).fetchone()  # nosec B608
        return _row(row, _cats_of(db, [resource_id]))


@router.post("/{resource_id}/opened", dependencies=[Depends(rate_limit("resources_open", 600))])
def opened(resource_id: int, _: Principal = Depends(require_write)) -> dict:
    """Counts an open (for Recently opened / Most used)."""
    with get_db() as db:
        if db.execute("UPDATE resources SET open_count = open_count + 1, last_opened = ? WHERE id = ?", (now(), resource_id)).rowcount == 0:
            raise not_found("Resource")
    return {"ok": True}


@router.delete("/{resource_id}", dependencies=[Depends(rate_limit("resources_write", 240))])
def delete_resource(resource_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM resources WHERE id = ?", (resource_id,)).rowcount == 0:
            raise not_found("Resource")
    return {"ok": True}


class BulkIn(StrictModel):
    ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=2000)]
    action: Literal["delete", "add", "remove", "favourite", "unfavourite"]
    category_id: int | None = Field(None, ge=1, le=2**31)


@router.post("/bulk", dependencies=[Depends(rate_limit("resources_write", 60))])
def bulk(body: BulkIn, principal: Principal = Depends(require_write)) -> dict:
    ids = list(dict.fromkeys(body.ids))
    marks = placeholders(len(ids))
    with get_db() as db:
        if body.action in ("add", "remove"):
            if not body.category_id:
                raise HTTPException(status_code=422, detail="Choose a category.")
            _check_category(db, body.category_id)
        if body.action == "delete":
            n = db.execute(f"DELETE FROM resources WHERE id IN ({marks})", ids).rowcount  # nosec B608
        elif body.action == "add":
            real = [r[0] for r in db.execute(f"SELECT id FROM resources WHERE id IN ({marks})", ids)]  # nosec B608
            n = sum(db.execute("INSERT OR IGNORE INTO resource_category_items (category_id, resource_id) VALUES (?, ?)", (body.category_id, i)).rowcount for i in real)
            db.execute(f"UPDATE resources SET manual = 1 WHERE id IN ({marks})", ids)  # nosec B608
        elif body.action == "remove":
            n = db.execute(f"DELETE FROM resource_category_items WHERE category_id = ? AND resource_id IN ({marks})", [body.category_id, *ids]).rowcount  # nosec B608
            db.execute(f"UPDATE resources SET manual = 1 WHERE id IN ({marks})", ids)  # nosec B608
        else:
            n = db.execute(f"UPDATE resources SET favourite = ? WHERE id IN ({marks})", [int(body.action == "favourite"), *ids]).rowcount  # nosec B608
    if body.action == "delete":
        audit("resources_deleted", principal, count=n)
    return {"ok": True, "changed": n}


@router.post("/reclassify", dependencies=[Depends(rate_limit("resources_write", 6))])
def reclassify(_: Principal = Depends(require_write)) -> dict:
    """Sort again everything whose categories you haven't set yourself."""
    with get_db() as db:
        return {"sorted": resources.reclassify(db)}


# ============================================================================ 🌳 folders (your tree)
FolderName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
MAX_FOLDERS = 5000


class FolderIn(StrictModel):
    name: FolderName
    parent_id: int | None = Field(None, ge=1, le=2**31)


class FolderPatch(StrictModel):
    name: FolderName | None = None
    parent_id: int | None = Field(None, ge=0, le=2**31)   # 0 = move to the top level
    position: int | None = Field(None, ge=0, le=1_000_000)


class FolderItems(StrictModel):
    resource_ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=2000)]
    action: Literal["add", "remove", "move"] = "add"
    from_folder_id: int | None = Field(None, ge=1, le=2**31)   # with "move": take them out of this folder


def _folder(db, fid: int):
    row = db.execute("SELECT id, parent_id, name, position FROM resource_folders WHERE id = ?", (fid,)).fetchone()
    if row is None:
        raise not_found("Folder")
    return row


def _subtree(db, fid: int) -> list[int]:
    return [r[0] for r in db.execute("WITH RECURSIVE sub(id) AS (SELECT ? UNION ALL SELECT f.id FROM resource_folders f "
                                     "JOIN sub ON f.parent_id = sub.id) SELECT id FROM sub", (fid,))]


@router.get("/folders", dependencies=[Depends(rate_limit("resources_read", 240))])
def list_folders(_: Principal = Depends(require_read)) -> dict:
    """Your folder tree, flat (parent_id + position give the order): each folder's own links and its links in total."""
    with get_db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT f.id, f.parent_id, f.name, f.position, (SELECT COUNT(*) FROM resource_folder_items i WHERE i.folder_id = f.id) AS count "
            "FROM resource_folders f ORDER BY f.parent_id IS NOT NULL, f.parent_id, f.position, f.name COLLATE NOCASE")]
        unfiled = db.execute("SELECT COUNT(*) FROM resources WHERE id NOT IN (SELECT resource_id FROM resource_folder_items)").fetchone()[0]
    kids: dict[int | None, list[dict]] = {}
    for r in rows:
        kids.setdefault(r["parent_id"], []).append(r)

    def total(f: dict) -> int:
        f["total"] = f["count"] + sum(total(c) for c in kids.get(f["id"], []))
        return f["total"]
    for f in kids.get(None, []):
        total(f)
    return {"folders": rows, "unfiled": unfiled}


@router.get("/tree", dependencies=[Depends(rate_limit("resources_read", 60))])
def tree(_: Principal = Depends(require_read)) -> dict:
    """Everything for the tree and map views in one go: folders, links (short) and which folders each link is in."""
    folders = list_folders(_)
    with get_db() as db:
        rows = db.execute("SELECT id, title, url, host, kind, favourite, status, summary FROM resources ORDER BY title COLLATE NOCASE").fetchall()
        places = {}
        for r in db.execute("SELECT resource_id, folder_id, position FROM resource_folder_items ORDER BY folder_id, position"):
            places.setdefault(r[0], []).append(r[1])
        cmap = _cats_of(db, [r["id"] for r in rows])
    items = [{"id": r["id"], "title": r["title"], "url": r["url"], "host": r["host"], "kind": r["kind"], "favourite": bool(r["favourite"]),
              "status": r["status"], "summary": r["summary"], "folders": places.get(r["id"], []), "categories": cmap.get(r["id"], [])} for r in rows]
    return {**folders, "items": items}


@router.post("/folders", status_code=201, dependencies=[Depends(rate_limit("resources_write", 120))])
def create_folder(body: FolderIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM resource_folders").fetchone()[0] >= MAX_FOLDERS:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_FOLDERS} folders.")
        if body.parent_id:
            _folder(db, body.parent_id)
        if db.execute("SELECT 1 FROM resource_folders WHERE name = ? AND parent_id IS ?", (body.name, body.parent_id)).fetchone():
            raise conflict(f"There's already a folder called {body.name} here.")
        pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM resource_folders WHERE parent_id IS ?", (body.parent_id,)).fetchone()[0]
        fid = db.execute("INSERT INTO resource_folders (parent_id, name, position, created_at) VALUES (?, ?, ?, ?)",
                         (body.parent_id, body.name, pos, now())).lastrowid
    return {"id": fid, "parent_id": body.parent_id, "name": body.name, "position": pos, "count": 0}


@router.patch("/folders/{folder_id}", dependencies=[Depends(rate_limit("resources_write", 240))])
def update_folder(folder_id: int, body: FolderPatch, _: Principal = Depends(require_write)) -> dict:
    """Rename, move under another folder (0 = top level; never into itself or its own subfolders) or reorder."""
    with get_db() as db:
        f = _folder(db, folder_id)
        parent = f["parent_id"]
        if body.parent_id is not None:
            parent = body.parent_id or None
            if parent is not None:
                _folder(db, parent)
                if parent in _subtree(db, folder_id):
                    raise HTTPException(status_code=422, detail="A folder can't go inside itself.")
        name = body.name if body.name is not None else f["name"]
        if (name, parent) != (f["name"], f["parent_id"]) and db.execute(
                "SELECT 1 FROM resource_folders WHERE name = ? AND parent_id IS ? AND id != ?", (name, parent, folder_id)).fetchone():
            raise conflict(f"There's already a folder called {name} there.")
        pos = body.position if body.position is not None else (
            f["position"] if parent == f["parent_id"] else db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM resource_folders WHERE parent_id IS ?",
                                                                       (parent,)).fetchone()[0])
        db.execute("UPDATE resource_folders SET name = ?, parent_id = ?, position = ? WHERE id = ?", (name, parent, pos, folder_id))
        return dict(_folder(db, folder_id))


@router.delete("/folders/{folder_id}", dependencies=[Depends(rate_limit("resources_write", 120))])
def delete_folder(folder_id: int, with_links: bool = False, principal: Principal = Depends(require_write)) -> dict:
    """Removes the folder and its subfolders. Links stay (in their other folders, or unfiled) - unless ``with_links``:
    then links that are only in this folder and its subfolders are deleted too."""
    with get_db() as db:
        _folder(db, folder_id)
        sub = _subtree(db, folder_id)
        marks = placeholders(len(sub))
        gone = 0
        if with_links:
            only_here = [r[0] for r in db.execute(
                f"SELECT DISTINCT resource_id FROM resource_folder_items WHERE folder_id IN ({marks}) AND resource_id NOT IN "  # nosec B608
                f"(SELECT resource_id FROM resource_folder_items WHERE folder_id NOT IN ({marks}))", [*sub, *sub])]
            for i in range(0, len(only_here), 500):
                chunk = only_here[i:i + 500]
                gone += db.execute(f"DELETE FROM resources WHERE id IN ({placeholders(len(chunk))})", chunk).rowcount  # nosec B608
        db.execute("DELETE FROM resource_folders WHERE id = ?", (folder_id,))
    audit("resource_folder_deleted", principal, folders=len(sub), links_deleted=gone)
    return {"ok": True, "folders": len(sub), "links_deleted": gone}


@router.post("/folders/{folder_id}/items", dependencies=[Depends(rate_limit("resources_write", 240))])
def folder_items(folder_id: int, body: FolderItems, _: Principal = Depends(require_write)) -> dict:
    """Add links to a folder (they can be in several), take them out, or move them here from another folder."""
    ids = list(dict.fromkeys(body.resource_ids))
    with get_db() as db:
        _folder(db, folder_id)
        if body.action == "move" and body.from_folder_id:
            _folder(db, body.from_folder_id)
        real = [r[0] for r in db.execute(f"SELECT id FROM resources WHERE id IN ({placeholders(len(ids))})", ids)]  # nosec B608
        if body.action == "remove":
            n = db.execute(f"DELETE FROM resource_folder_items WHERE folder_id = ? AND resource_id IN ({placeholders(len(ids))})",  # nosec B608
                           [folder_id, *ids]).rowcount
        else:
            n = sum(1 for i in real if resources.place(db, folder_id, i))
            if body.action == "move" and body.from_folder_id and body.from_folder_id != folder_id:
                db.execute(f"DELETE FROM resource_folder_items WHERE folder_id = ? AND resource_id IN ({placeholders(len(real))})",  # nosec B608
                           [body.from_folder_id, *real])
    return {"ok": True, "changed": n}


# ============================================================================ 📦 repos linked to a topic folder
class FolderRepos(StrictModel):
    repo_ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=500)]
    action: Literal["add", "remove"] = "add"


def _has_repos(db) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'repos'").fetchone() is not None


def _repo_view(r) -> dict:
    """A repo / gist / doc from the Repos tab, as Resources shows it (title, address, a short description)."""
    kind = r["kind"] or "repo"
    first = (r["description"] or "").split("\n", 1)[0].strip()
    url = r["url"] or (f"https://github.com/{r['full_name']}" if kind == "repo" else "")
    title = r["full_name"] if kind == "repo" else (first or r["full_name"])
    return {"id": r["id"], "title": title, "kind": kind, "url": url, "description": first[:300] if kind == "repo" else "",
            "stars": r["stars"], "language": r["language"]}


@router.get("/repos", dependencies=[Depends(rate_limit("resources_read", 240))])
def folder_repos(_: Principal = Depends(require_read)) -> dict:
    """Every folder → repo link (repos that no longer exist are left out) and the linked repos themselves."""
    with get_db() as db:
        if not _has_repos(db):
            return {"links": [], "repos": []}
        links = [[r[0], r[1]] for r in db.execute(   # by name: survives the repo being removed and added back (new id)
            "SELECT l.folder_id, p.id FROM resource_folder_repos l JOIN repos p ON p.full_name = l.full_name COLLATE NOCASE "
            "ORDER BY l.folder_id, p.full_name COLLATE NOCASE")]
        ids = sorted({x[1] for x in links})
        rows = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            rows += db.execute(f"SELECT id, full_name, kind, description, url, stars, language FROM repos WHERE id IN ({placeholders(len(chunk))})",  # nosec B608
                               chunk).fetchall()
    return {"links": links, "repos": [_repo_view(r) for r in rows]}


@router.get("/repo-search", dependencies=[Depends(rate_limit("resources_read", 240))])
def repo_search(q: Annotated[str, Query(max_length=100)] = "", _: Principal = Depends(require_read)) -> dict:
    """Find repos from the Repos tab by name or description (for "📦 Link repos…")."""
    with get_db() as db:
        if not _has_repos(db):
            return {"items": []}
        where, params = [], []
        for word in q.strip().split()[:6]:
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(full_name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
            params += [like, like]
        clause = " AND ".join(where) or "1 = 1"
        rows = db.execute(f"SELECT id, full_name, kind, description, url, stars, language FROM repos WHERE {clause} "  # nosec B608
                          "ORDER BY kind = 'repo' DESC, stars DESC, full_name COLLATE NOCASE LIMIT 40", params).fetchall()
    return {"items": [_repo_view(r) for r in rows]}


@router.post("/folders/{folder_id}/repos", dependencies=[Depends(rate_limit("resources_write", 240))])
def link_folder_repos(folder_id: int, body: FolderRepos, _: Principal = Depends(require_write)) -> dict:
    """Link repos to a folder (a repo can sit under several topics) or unlink them."""
    ids = list(dict.fromkeys(body.repo_ids))
    with get_db() as db:
        _folder(db, folder_id)
        if not _has_repos(db):
            raise HTTPException(status_code=422, detail="There are no repos to link.")
        names = [r[0] for r in db.execute(f"SELECT full_name FROM repos WHERE id IN ({placeholders(len(ids))})", ids)]  # nosec B608
        if body.action == "remove":
            n = sum(db.execute("DELETE FROM resource_folder_repos WHERE folder_id = ? AND full_name = ? COLLATE NOCASE",
                               (folder_id, name)).rowcount for name in names)
            return {"ok": True, "changed": n}
        if not names:
            raise not_found("Repo")
        n = sum(db.execute("INSERT OR IGNORE INTO resource_folder_repos (folder_id, full_name, added_at) VALUES (?, ?, ?)",
                           (folder_id, name, now())).rowcount for name in names)
    return {"ok": True, "changed": n}


# ============================================================================ 🧠 mind map: topics that go well together
MAX_RELATIONS = 5000
RelationNote = Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)]


class RelationIn(StrictModel):
    a: int = Field(ge=1, le=2**31)
    b: int = Field(ge=1, le=2**31)
    note: RelationNote = ""


class RelationPatch(StrictModel):
    note: RelationNote


@router.get("/relations", dependencies=[Depends(rate_limit("resources_read", 240))])
def list_relations(_: Principal = Depends(require_read)) -> dict:
    """Every "goes well with" between two folders (a < b), with its note."""
    with get_db() as db:
        return {"relations": [dict(r) for r in db.execute("SELECT id, a, b, note FROM resource_folder_links ORDER BY id")]}


@router.post("/relations", status_code=201, dependencies=[Depends(rate_limit("resources_write", 240))])
def create_relation(body: RelationIn, _: Principal = Depends(require_write)) -> dict:
    if body.a == body.b:
        raise HTTPException(status_code=422, detail="A folder can't go with itself.")
    a, b = sorted((body.a, body.b))
    with get_db() as db:
        _folder(db, a)
        _folder(db, b)
        if db.execute("SELECT COUNT(*) FROM resource_folder_links").fetchone()[0] >= MAX_RELATIONS:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_RELATIONS} connections.")
        if db.execute("SELECT 1 FROM resource_folder_links WHERE a = ? AND b = ?", (a, b)).fetchone():
            raise conflict("These two are already connected.")
        rid = db.execute("INSERT INTO resource_folder_links (a, b, note, created_at) VALUES (?, ?, ?, ?)", (a, b, body.note, now())).lastrowid
    return {"id": rid, "a": a, "b": b, "note": body.note}


@router.patch("/relations/{relation_id}", dependencies=[Depends(rate_limit("resources_write", 240))])
def update_relation(relation_id: int, body: RelationPatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if not db.execute("UPDATE resource_folder_links SET note = ? WHERE id = ?", (body.note, relation_id)).rowcount:
            raise not_found("Connection")
        return dict(db.execute("SELECT id, a, b, note FROM resource_folder_links WHERE id = ?", (relation_id,)).fetchone())


@router.delete("/relations/{relation_id}", dependencies=[Depends(rate_limit("resources_write", 240))])
def delete_relation(relation_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if not db.execute("DELETE FROM resource_folder_links WHERE id = ?", (relation_id,)).rowcount:
            raise not_found("Connection")
    return {"ok": True}


# ============================================================================ categories
class CategoryIn(StrictModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]
    emoji: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=8)] | None = None
    color: Color | None = None


class CategoryPatch(StrictModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)] | None = None
    emoji: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=8)] | None = None
    color: Color | None = None


class CategoryOrder(StrictModel):
    ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=MAX_CATEGORIES)]


@router.post("/categories", status_code=201, dependencies=[Depends(rate_limit("resources_write", 60))])
def create_category(body: CategoryIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM resource_categories").fetchone()[0] >= MAX_CATEGORIES:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_CATEGORIES} categories.")
        if db.execute("SELECT 1 FROM resource_categories WHERE name = ?", (body.name,)).fetchone():
            raise conflict(f"There's already a category called {body.name}.")
        pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM resource_categories").fetchone()[0]
        cid = db.execute("INSERT INTO resource_categories (name, emoji, color, position, created_at) VALUES (?, ?, ?, ?, ?)",
                         (body.name, body.emoji or "🔗", body.color or "#64748b", pos, now())).lastrowid
    return {"id": cid, "name": body.name, "emoji": body.emoji or "🔗", "color": body.color or "#64748b", "position": pos, "count": 0}


@router.patch("/categories/{category_id}", dependencies=[Depends(rate_limit("resources_write", 120))])
def update_category(category_id: int, body: CategoryPatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT 1 FROM resource_categories WHERE id = ?", (category_id,)).fetchone() is None:
            raise not_found("Category")
        if body.name is not None:
            if db.execute("SELECT 1 FROM resource_categories WHERE name = ? AND id != ?", (body.name, category_id)).fetchone():
                raise conflict(f"There's already a category called {body.name}.")
            db.execute("UPDATE resource_categories SET name = ? WHERE id = ?", (body.name, category_id))
        if body.emoji is not None:
            db.execute("UPDATE resource_categories SET emoji = ? WHERE id = ?", (body.emoji, category_id))
        if body.color is not None:
            db.execute("UPDATE resource_categories SET color = ? WHERE id = ?", (body.color, category_id))
        return dict(db.execute("SELECT id, key, name, emoji, color, position FROM resource_categories WHERE id = ?", (category_id,)).fetchone())


@router.post("/categories/reorder", dependencies=[Depends(rate_limit("resources_write", 120))])
def reorder_categories(body: CategoryOrder, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        known = {r[0] for r in db.execute("SELECT id FROM resource_categories")}
        order = [i for i in dict.fromkeys(body.ids) if i in known]
        rest = [r[0] for r in db.execute("SELECT id FROM resource_categories ORDER BY position") if r[0] not in order]
        for pos, cid in enumerate(order + rest, start=1):
            db.execute("UPDATE resource_categories SET position = ? WHERE id = ?", (pos, cid))
    return {"ok": True}


@router.delete("/categories/{category_id}", dependencies=[Depends(rate_limit("resources_write", 60))])
def delete_category(category_id: int, _: Principal = Depends(require_write)) -> dict:
    """Removes the category only - its resources stay (in their other categories, or uncategorised)."""
    with get_db() as db:
        if db.execute("SELECT 1 FROM resource_categories WHERE id = ?", (category_id,)).fetchone() is None:
            raise not_found("Category")
        n = db.execute("SELECT COUNT(*) FROM resource_category_items WHERE category_id = ?", (category_id,)).fetchone()[0]
        db.execute("DELETE FROM resource_categories WHERE id = ?", (category_id,))
    return {"ok": True, "resources_kept": n}
