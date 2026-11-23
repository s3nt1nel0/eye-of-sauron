"""📦 Repos tab: GitHub owners, repos, topics and stars you follow - repo cards, shelves, releases, sources, token.

Reading needs read scope; following / unfollowing, ★ and refreshes need write scope; the GitHub token is admin-only
(interactive session) and is never returned - only whether one is set.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StringConstraints

from app import github, integrations
from app.api.common import Color, StrictModel, TopicIds, conflict, date_clause, not_found
from app.db import get_db, now, placeholders
from app.security import Principal, audit, rate_limit, require_admin, require_read, require_write

router = APIRouter(prefix="/repos", tags=["repos"])

Search = Annotated[str, StringConstraints(max_length=200)]
Language = Annotated[str, StringConstraints(pattern=r"^[\w#+.' -]{1,50}$")]
Owner = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")]  # exact rule: github.OWNER
GhTopic = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,49}$")]
Sort = Literal["stars", "pushed", "name", "added", "created"]
SORTS = {"stars": "r.stars DESC, r.id DESC", "pushed": "r.pushed_ts IS NULL, r.pushed_ts DESC, r.id DESC",
         "name": "r.full_name COLLATE NOCASE ASC", "added": "r.added_at DESC, r.id DESC",
         "created": "r.created_ts IS NULL, r.created_ts DESC, r.id DESC"}
COLUMNS = ("r.id, r.full_name, r.owner, r.name, r.description, r.language, r.stars, r.forks, r.open_issues, r.gh_topics, "
           "r.license, r.homepage, r.archived, r.is_fork, r.owner_avatar, r.created_ts, r.pushed_ts, r.added_at, r.starred, r.kind, r.url")
SHELF_SCAN = 50_000


def _row(r, topic_map: dict[int, list[int]], folder_map: dict[int, list[int]] | None = None) -> dict:
    d = dict(r)
    try:
        d["gh_topics"] = json.loads(d["gh_topics"] or "[]")
    except ValueError:
        d["gh_topics"] = []
    d["archived"], d["is_fork"], d["starred"] = bool(d["archived"]), bool(d["is_fork"]), bool(d["starred"])
    d["url"] = d["url"] if str(d.get("url") or "").startswith("https://") else f"{github.WEB}/{d['full_name']}"
    d["topics"] = topic_map.get(d["id"], [])
    d["folders"] = (folder_map or {}).get(d["id"], [])
    return d


def _folder_map(db, ids: list[int]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for t in db.execute(f"SELECT repo_id, folder_id FROM repo_folder_items WHERE repo_id IN ({placeholders(len(chunk))})", chunk):  # nosec B608
            out.setdefault(t["repo_id"], []).append(t["folder_id"])
    return out


def _topic_map(db, ids: list[int]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for t in db.execute(f"SELECT repo_id, topic_id FROM repo_topics WHERE repo_id IN ({placeholders(len(chunk))})", chunk):  # nosec B608
            out.setdefault(t["repo_id"], []).append(t["topic_id"])
    return out


def _filters(q: str, language: str | None, owner: str | None, topic_ids: str | None, source_id: int | None, gh_topic: str | None,
             min_stars: int, starred: bool, hide_archived: bool, hide_forks: bool, since: int | None, until: int | None,
             folder_id: int | None = None, kind: str | None = None) -> tuple[str, list]:
    where, params = ["1 = 1"], []
    if kind:
        where.append("r.kind = ?")
        params.append(kind)
    if folder_id is not None:
        if folder_id == 0:
            where.append("r.id NOT IN (SELECT repo_id FROM repo_folder_items)")
        else:
            where.append("r.id IN (SELECT repo_id FROM repo_folder_items WHERE folder_id = ?)")
            params.append(folder_id)
    if q.strip():
        like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(r.full_name LIKE ? ESCAPE '\\' OR r.description LIKE ? ESCAPE '\\' OR r.gh_topics LIKE ? ESCAPE '\\')")
        params += [like] * 3
    if language:
        if language == "Unknown":
            where.append("r.language IS NULL")
        else:
            where.append("r.language = ?")
            params.append(language)
    if owner:
        if not github.OWNER.match(owner):
            raise HTTPException(status_code=422, detail="Invalid owner name")
        where.append("r.owner = ?")
        params.append(owner)
    if gh_topic:
        where.append("EXISTS (SELECT 1 FROM json_each(r.gh_topics) WHERE json_each.value = ?)")
        params.append(gh_topic)
    if source_id:
        where.append("r.id IN (SELECT repo_id FROM repo_source_links WHERE source_id = ?)")
        params.append(source_id)
    if topic_ids:
        ids = [int(t) for t in topic_ids.split(",")]
        real = [t for t in ids if t]
        parts = []
        if real:
            parts.append(f"r.id IN (SELECT repo_id FROM repo_topics WHERE topic_id IN ({placeholders(len(real))}))")
            params += real
        if 0 in ids:
            parts.append("r.id NOT IN (SELECT repo_id FROM repo_topics)")
        where.append("(" + " OR ".join(parts) + ")")
    if min_stars:
        where.append("r.stars >= ?")
        params.append(min_stars)
    if starred:
        where.append("r.starred = 1")
    if hide_archived:
        where.append("r.archived = 0")
    if hide_forks:
        where.append("r.is_fork = 0")
    dates, dparams = date_clause(since, until, "r.pushed_ts")
    if dates:
        where.append(dates.removeprefix(" AND ").removeprefix("AND ").strip() or "1 = 1")
        params += dparams
    return " AND ".join(where), params


class _F:
    """The shared filter query parameters (one place, so list / shelves / counts always agree)."""

    def __init__(self, q: Search = "", language: Language | None = None, owner: Owner | None = None, topic_ids: TopicIds | None = None,
                 source_id: int | None = Query(None, ge=1, le=2**31), gh_topic: GhTopic | None = None,
                 min_stars: int = Query(0, ge=0, le=10_000_000), starred: bool = False, hide_archived: bool = False,
                 hide_forks: bool = False, since: int | None = Query(None, ge=0, le=2**40), until: int | None = Query(None, ge=0, le=2**40),
                 folder_id: int | None = Query(None, ge=0, le=2**31), kind: Literal["repo", "gist", "doc"] | None = None):
        self.clause, self.params = _filters(q, language, owner, topic_ids, source_id, gh_topic, min_stars, starred,
                                            hide_archived, hide_forks, since, until, folder_id, kind)


@router.get("", dependencies=[Depends(rate_limit("repos_read", 240))])
def list_repos(f: _F = Depends(), sort: Sort = "stars", limit: int = Query(60, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
               _: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM repos r WHERE {f.clause}", f.params).fetchone()[0]  # nosec B608 - fixed fragments
        rows = db.execute(f"SELECT {COLUMNS} FROM repos r WHERE {f.clause} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",  # nosec B608
                          [*f.params, limit, offset]).fetchall()
        tmap = _topic_map(db, [r["id"] for r in rows])
        fmap = _folder_map(db, [r["id"] for r in rows])
        return {"total": total, "items": [_row(r, tmap, fmap) for r in rows]}


@router.get("/shelves", dependencies=[Depends(rate_limit("repos_read", 240))])
def shelves(by: Literal["topic", "owner", "language"] = "topic", f: _F = Depends(), sort: Sort = "stars",
            per: int = Query(12, ge=1, le=48), _: Principal = Depends(require_read)) -> dict:
    """Repos grouped by topic, owner or language: each shelf has its total and its first ``per`` repos."""
    with get_db() as db:
        rows = db.execute(f"SELECT {COLUMNS} FROM repos r WHERE {f.clause} ORDER BY {SORTS[sort]} LIMIT ?",  # nosec B608
                          [*f.params, SHELF_SCAN]).fetchall()
        tmap = _topic_map(db, [r["id"] for r in rows])
        fmap = _folder_map(db, [r["id"] for r in rows])
        topic_info = {t["id"]: t for t in db.execute("SELECT id, name, color FROM topics")}
    groups: dict = {}
    for r in rows:
        if by == "topic":
            keys = [t for t in tmap.get(r["id"], []) if t in topic_info] or [0]
        elif by == "owner":
            keys = [r["owner"]]
        else:
            keys = [r["language"] or "Unknown"]
        for k in keys:
            g = groups.setdefault(k, {"total": 0, "items": []})
            g["total"] += 1
            if len(g["items"]) < per:
                g["items"].append(_row(r, tmap, fmap))
    out = []
    for k, g in groups.items():
        if by == "topic":
            t = topic_info.get(k)
            label, color = (t["name"], t["color"]) if t else ("No topic", "#6b7280")
        else:
            label, color = str(k), None
        out.append({"key": k, "label": label, "color": color, "total": g["total"], "items": g["items"]})
    out.sort(key=lambda s: (s["key"] in (0, "Unknown"), -s["total"], str(s["label"]).lower()))
    return {"by": by, "repos": len(rows), "shelves": out}


@router.get("/releases", dependencies=[Depends(rate_limit("repos_read", 240))])
def releases(q: Search = "", since: int | None = Query(None, ge=0, le=2**40), until: int | None = Query(None, ge=0, le=2**40),
             limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000), _: Principal = Depends(require_read)) -> dict:
    where, params = ["1 = 1"], []
    if q.strip():
        like = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(r.full_name LIKE ? ESCAPE '\\' OR x.title LIKE ? ESCAPE '\\' OR x.tag LIKE ? ESCAPE '\\')")
        params += [like] * 3
    dates, dparams = date_clause(since, until, "x.published_ts")
    clause = " AND ".join(where) + (dates if dates.startswith(" AND") else (f" AND {dates}" if dates else ""))
    params += dparams
    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM repo_releases x JOIN repos r ON r.id = x.repo_id WHERE {clause}", params).fetchone()[0]  # nosec B608
        rows = db.execute(f"SELECT x.id, x.tag, x.title, x.url, x.published_ts, x.summary, r.id AS repo_id, r.full_name, r.owner_avatar, "  # nosec B608
                          f"r.language FROM repo_releases x JOIN repos r ON r.id = x.repo_id WHERE {clause} "
                          "ORDER BY x.published_ts DESC, x.id DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


@router.get("/meta", dependencies=[Depends(rate_limit("repos_read", 240))])
def meta(_: Principal = Depends(require_read)) -> dict:
    """Counts for the toolbar: totals, languages, owners, topics, sources and GitHub's request budget."""
    with get_db() as db:
        one = lambda sql: db.execute(sql).fetchone()[0]  # noqa: E731
        sources = [dict(r) for r in db.execute(
            "SELECT id, kind, value, title, avatar_url, created_at, last_fetch, next_fetch, last_error, repo_count, origin, note FROM repo_sources "
            "ORDER BY kind, value COLLATE NOCASE")]
        for s in sources:
            s["url"] = github.source_url(s["kind"], s["value"])
        return {
            "total": one("SELECT COUNT(*) FROM repos"), "starred": one("SELECT COUNT(*) FROM repos WHERE starred = 1"),
            "archived": one("SELECT COUNT(*) FROM repos WHERE archived = 1"), "forks": one("SELECT COUNT(*) FROM repos WHERE is_fork = 1"),
            "releases": one("SELECT COUNT(*) FROM repo_releases"),
            "kinds": {r[0]: r[1] for r in db.execute("SELECT kind, COUNT(*) FROM repos GROUP BY kind")},
            "languages": [{"name": r[0] or "Unknown", "count": r[1]} for r in db.execute(
                "SELECT language, COUNT(*) FROM repos GROUP BY language ORDER BY COUNT(*) DESC, language LIMIT 200")],
            "owners": [{"name": r[0], "count": r[1]} for r in db.execute(
                "SELECT owner, COUNT(*) FROM repos GROUP BY owner ORDER BY COUNT(*) DESC, owner LIMIT 300")],
            "topics": [dict(r) for r in db.execute(
                "SELECT t.id, t.name, t.color, t.enabled, (SELECT COUNT(*) FROM repo_topics x WHERE x.topic_id = t.id) AS repos "
                "FROM topics t ORDER BY t.name COLLATE NOCASE")],
            "untagged": one("SELECT COUNT(*) FROM repos WHERE id NOT IN (SELECT repo_id FROM repo_topics)"),
            "sources": sources,
            "token_set": integrations.secret(db, "github", "token") is not None,
            "rate": github.rate_status(),
        }


class StarIn(StrictModel):
    starred: bool


@router.delete("/{repo_id}", dependencies=[Depends(rate_limit("repos_write", 120))])
def remove_repo(repo_id: int, principal: Principal = Depends(require_write)) -> dict:
    """Remove one repo (or gist / doc / website link) from Repos: out of every folder; a link you pasted for just this
    item goes too; if a list (owner / topic / stars) also brings it in, it's remembered as removed so it doesn't come back."""
    with get_db() as db:
        row = db.execute("SELECT id, full_name FROM repos WHERE id = ?", (repo_id,)).fetchone()
        if row is None:
            raise not_found("Repo")
        sources = db.execute("SELECT s.id, s.kind, s.value FROM repo_source_links l JOIN repo_sources s ON s.id = l.source_id "
                             "WHERE l.repo_id = ?", (repo_id,)).fetchall()
        single = [s for s in sources if s["kind"] in ("repo", "gitlab", "gist", "doc")]
        lists = [s for s in sources if s["kind"] not in ("repo", "gitlab", "gist", "doc")]
        for s in single:
            db.execute("DELETE FROM repo_sources WHERE id = ?", (s["id"],))
        if lists:
            db.execute("INSERT OR REPLACE INTO repo_hidden (full_name, hidden_at) VALUES (?, ?)", (row["full_name"], now()))
        db.execute("DELETE FROM repos WHERE id = ?", (repo_id,))
    audit("repo_removed", principal, full_name=row["full_name"], sources_removed=len(single), hidden=bool(lists))
    return {"ok": True, "sources_removed": len(single), "hidden": bool(lists), "lists": [f"{s['kind']}:{s['value']}" for s in lists]}


@router.patch("/{repo_id}", dependencies=[Depends(rate_limit("repos_write", 120))])
def star(repo_id: int, body: StarIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("UPDATE repos SET starred = ? WHERE id = ?", (int(body.starred), repo_id)).rowcount == 0:
            raise not_found("Repo")
        if not body.starred:
            github.drop_orphans(db)   # an un-starred repo no source lists any more goes
    return {"ok": True, "starred": body.starred}


# ============================================================================ 📁 folders
FolderName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]
Emoji = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=8)]
MAX_FOLDERS = 200
PEEK = 4


class FolderIn(StrictModel):
    name: FolderName
    emoji: Emoji | None = None
    color: Color | None = None


class FolderPatch(StrictModel):
    name: FolderName | None = None
    emoji: Emoji | None = None
    color: Color | None = None


class FolderOrder(StrictModel):
    ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=MAX_FOLDERS)]


class FolderItems(StrictModel):
    repo_ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(min_length=1, max_length=500)]
    action: Literal["add", "remove"] = "add"


class RepoFolders(StrictModel):
    folder_ids: Annotated[list[Annotated[int, Field(ge=1, le=2**31)]], Field(max_length=MAX_FOLDERS)]


def _folder_or_404(db, folder_id: int):
    row = db.execute("SELECT id, name, emoji, color, position FROM repo_folders WHERE id = ?", (folder_id,)).fetchone()
    if row is None:
        raise not_found("Folder")
    return row


@router.get("/folders", dependencies=[Depends(rate_limit("repos_read", 240))])
def list_folders(_: Principal = Depends(require_read)) -> dict:
    """Your folders in order, each with its count and a peek at its most-starred repos, plus the unfiled count."""
    with get_db() as db:
        folders = []
        for f in db.execute("SELECT f.id, f.name, f.emoji, f.color, f.position, (SELECT COUNT(*) FROM repo_folder_items i WHERE i.folder_id = f.id) AS repos "
                            "FROM repo_folders f ORDER BY f.position, f.name COLLATE NOCASE"):
            d = dict(f)
            d["peek"] = [dict(r) for r in db.execute(
                "SELECT r.id, r.full_name, r.name, r.owner, r.owner_avatar, r.language, r.stars FROM repo_folder_items i "
                "JOIN repos r ON r.id = i.repo_id WHERE i.folder_id = ? ORDER BY r.stars DESC, r.id LIMIT ?", (f["id"], PEEK))]
            folders.append(d)
        unfiled = db.execute("SELECT COUNT(*) FROM repos WHERE id NOT IN (SELECT repo_id FROM repo_folder_items)").fetchone()[0]
        peek = [dict(r) for r in db.execute("SELECT id, full_name, name, owner, owner_avatar, language, stars FROM repos "
                                            "WHERE id NOT IN (SELECT repo_id FROM repo_folder_items) ORDER BY stars DESC, id LIMIT ?", (PEEK,))]
    return {"folders": folders, "unfiled": unfiled, "unfiled_peek": peek}


@router.post("/folders", dependencies=[Depends(rate_limit("repos_write", 120))])
def create_folder(body: FolderIn, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM repo_folders").fetchone()[0] >= MAX_FOLDERS:
            raise HTTPException(status_code=422, detail=f"Up to {MAX_FOLDERS} folders.")
        if db.execute("SELECT 1 FROM repo_folders WHERE name = ?", (body.name,)).fetchone():
            raise conflict(f"There's already a folder called {body.name}.")
        pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM repo_folders").fetchone()[0]
        fid = db.execute("INSERT INTO repo_folders (name, emoji, color, position, created_at) VALUES (?, ?, ?, ?, ?)",
                         (body.name, body.emoji or "📁", body.color or "#64748b", pos, now())).lastrowid
    audit("repo_folder_created", principal, folder_id=fid)
    return {"id": fid, "name": body.name, "emoji": body.emoji or "📁", "color": body.color or "#64748b", "position": pos, "repos": 0}


@router.patch("/folders/{folder_id}", dependencies=[Depends(rate_limit("repos_write", 120))])
def update_folder(folder_id: int, body: FolderPatch, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        _folder_or_404(db, folder_id)
        if body.name is not None:
            if db.execute("SELECT 1 FROM repo_folders WHERE name = ? AND id != ?", (body.name, folder_id)).fetchone():
                raise conflict(f"There's already a folder called {body.name}.")
            db.execute("UPDATE repo_folders SET name = ? WHERE id = ?", (body.name, folder_id))
        if body.emoji is not None:
            db.execute("UPDATE repo_folders SET emoji = ? WHERE id = ?", (body.emoji, folder_id))
        if body.color is not None:
            db.execute("UPDATE repo_folders SET color = ? WHERE id = ?", (body.color, folder_id))
        return dict(_folder_or_404(db, folder_id))


@router.post("/folders/reorder", dependencies=[Depends(rate_limit("repos_write", 120))])
def reorder_folders(body: FolderOrder, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        known = {r[0] for r in db.execute("SELECT id FROM repo_folders")}
        order = [i for i in dict.fromkeys(body.ids) if i in known]
        rest = [i for i in (r[0] for r in db.execute("SELECT id FROM repo_folders ORDER BY position, name COLLATE NOCASE")) if i not in order]
        for pos, fid in enumerate(order + rest, start=1):
            db.execute("UPDATE repo_folders SET position = ? WHERE id = ?", (pos, fid))
    return {"ok": True}


@router.delete("/folders/{folder_id}", dependencies=[Depends(rate_limit("repos_write", 120))])
def delete_folder(folder_id: int, principal: Principal = Depends(require_write)) -> dict:
    """Removes the folder only - its repos stay in Repos (and in any other folder)."""
    with get_db() as db:
        _folder_or_404(db, folder_id)
        n = db.execute("SELECT COUNT(*) FROM repo_folder_items WHERE folder_id = ?", (folder_id,)).fetchone()[0]
        db.execute("DELETE FROM repo_folders WHERE id = ?", (folder_id,))
    audit("repo_folder_deleted", principal, folder_id=folder_id, repos=n)
    return {"ok": True, "repos_kept": n}


@router.post("/folders/{folder_id}/items", dependencies=[Depends(rate_limit("repos_write", 120))])
def folder_items(folder_id: int, body: FolderItems, _: Principal = Depends(require_write)) -> dict:
    """Add repos to a folder, or take them out (they stay in Repos)."""
    ids = list(dict.fromkeys(body.repo_ids))
    with get_db() as db:
        _folder_or_404(db, folder_id)
        real = [r[0] for r in db.execute(f"SELECT id FROM repos WHERE id IN ({placeholders(len(ids))})", ids)]  # nosec B608
        if body.action == "add":
            changed = sum(db.execute("INSERT OR IGNORE INTO repo_folder_items (folder_id, repo_id, added_at) VALUES (?, ?, ?)",
                                     (folder_id, i, now())).rowcount for i in real)
        else:
            changed = db.execute(f"DELETE FROM repo_folder_items WHERE folder_id = ? AND repo_id IN ({placeholders(len(ids))})",  # nosec B608
                                 [folder_id, *ids]).rowcount
            github.drop_orphans(db)     # a repo that was only kept for this folder (no source, no ★) goes
    return {"ok": True, "changed": changed}


@router.put("/{repo_id}/folders", dependencies=[Depends(rate_limit("repos_write", 120))])
def set_repo_folders(repo_id: int, body: RepoFolders, _: Principal = Depends(require_write)) -> dict:
    """Exactly these folders for one repo (the 📁 Folders… ticks on a card)."""
    wanted = list(dict.fromkeys(body.folder_ids))
    with get_db() as db:
        if db.execute("SELECT 1 FROM repos WHERE id = ?", (repo_id,)).fetchone() is None:
            raise not_found("Repo")
        known = {r[0] for r in db.execute("SELECT id FROM repo_folders")}
        if any(f not in known for f in wanted):
            raise not_found("Folder")
        db.execute("DELETE FROM repo_folder_items WHERE repo_id = ?", (repo_id,))
        db.executemany("INSERT INTO repo_folder_items (folder_id, repo_id, added_at) VALUES (?, ?, ?)", [(f, repo_id, now()) for f in wanted])
        left = db.execute("SELECT 1 FROM repos WHERE id = ?", (repo_id,)).fetchone() is not None
        if not wanted:
            github.drop_orphans(db)
            left = db.execute("SELECT 1 FROM repos WHERE id = ?", (repo_id,)).fetchone() is not None
    return {"ok": True, "folders": wanted, "still_here": left}


# ============================================================================ sources
class SourceIn(StrictModel):
    input: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    follow_owner: bool = False   # a repo link: also follow its owner (all their public repos)


def _reason(kind: str, value: str, parsed: github.Parsed, exc: github.GitHubError) -> HTTPException:
    """One precise reason per pasted line."""
    if isinstance(exc, github.NotFound):
        return HTTPException(status_code=404, detail=github.not_found_text(kind, value, parsed.note, parsed.pages or None))
    return HTTPException(status_code=502, detail=str(exc)[:300])


def _insert_source(db, kind: str, value: str, *, next_fetch: int | None = None, title: str | None = None, avatar: str | None = None,
                   origin: str | None = None, note: str | None = None, alt: str | None = None) -> int | None:
    """New source id, or None when it is already there. ``next_fetch`` set = the background sync leaves it alone until then
    (it is being stored right now, or it waits for GitHub's reset)."""
    if db.execute("SELECT 1 FROM repo_sources WHERE kind = ? AND value = ?", (kind, value)).fetchone():
        return None
    if db.execute("SELECT COUNT(*) FROM repo_sources").fetchone()[0] >= github.MAX_SOURCES:
        raise HTTPException(status_code=422, detail=f"Up to {github.MAX_SOURCES} GitHub sources.")
    return db.execute("INSERT INTO repo_sources (kind, value, title, avatar_url, created_at, next_fetch, origin, note, alt_value) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (kind, value, title or value, avatar, now(), next_fetch, (origin or "")[:500] or None, note or None, alt or None)).lastrowid


@router.post("/sources", dependencies=[Depends(rate_limit("repos_sources", 60))])
def add_source(body: SourceIn, principal: Principal = Depends(require_write)) -> dict:
    """Add a repo, an owner, a GitHub topic or someone's stars - one API request per line at most (none when another
    source stored the repo in the last 12 hours). Every line gets a precise answer: added / already there / doesn't exist /
    a website / a gist. When GitHub's free limit is spent the line is saved and finished after the reset."""
    try:
        parsed = github.parse_input(body.input)
    except github.GitHubError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    kind, value = parsed
    note = parsed.note or None
    origin = body.input.strip()
    sent_before = github.requests_sent()
    with get_db() as db:
        token = integrations.secret(db, "github", "token")
        if db.execute("SELECT 1 FROM repo_sources WHERE kind = ? AND value = ?", (kind, value)).fetchone() and not body.follow_owner:
            raise conflict(f"{value} is already in your Repos.")
        stored_row = db.execute("SELECT full_name FROM repos WHERE full_name = ? AND updated_at > ?",
                                (value, now() - github.REFRESH_SECONDS)).fetchone() if kind == "repo" else None
    info: dict = {}
    repos = None
    etag = None
    pending_until = None
    if stored_row is None:
        try:
            info, repos, etag = github.verify(kind, value, token)
        except github.NotFound as exc:
            if not parsed.alt:
                page = github.page_url(origin) if parsed.via == "pages" else None
                if not page:
                    raise _reason(kind, value, parsed, exc) from None
                kind, value, note = "doc", page, github.PAGE_NOTE
                info, repos, etag = github.verify("doc", page, token)
                parsed = github.Parsed("doc", page, via="pages", note=github.PAGE_NOTE)
            try:   # a website link: not a project site - try the website's own repo
                info, repos, etag = github.verify(kind, parsed.alt, token)
                value, note = parsed.alt, github.POST_NOTE
            except github.NotFound as exc2:
                page = github.page_url(origin)
                if not page:
                    raise _reason(kind, parsed.alt, parsed, exc2) from None
                kind, value, note = "doc", page, github.PAGE_NOTE
                info, repos, etag = github.verify("doc", page, token)
            except github.RateLimited as rl:
                value, note, pending_until = parsed.alt, github.POST_NOTE, rl.reset
            except github.GitHubError as exc2:
                raise _reason(kind, parsed.alt, parsed, exc2) from None
        except github.RateLimited as rl:
            pending_until = rl.reset             # saved now, finished by the background sync after GitHub's reset
        except github.GitHubError as exc:
            raise _reason(kind, value, parsed, exc) from None
    else:
        value = stored_row["full_name"]
    if kind == "repo" and repos:
        value = repos[0]["full_name"]            # GitHub's own spelling (and the new name of a renamed repo)
    elif kind == "doc" and parsed.via == "pages" and repos is None:
        pass
    elif kind in ("owner", "stars") and info.get("login"):
        value = info["login"]
    alt = parsed.alt if pending_until and parsed.alt and value != parsed.alt else None
    with get_db() as db:
        sid = _insert_source(db, kind, value, next_fetch=(pending_until + 30) if pending_until else (now() + github.REFRESH_SECONDS if repos is not None or stored_row else None),
                             title=info.get("title"), avatar=info.get("avatar_url") if kind == "owner" else None,
                             origin=origin, note=note, alt=alt)
    owner_out = None
    if kind == "repo" and body.follow_owner:
        owner = value.split("/", 1)[0]
        with get_db() as db:
            oid = _insert_source(db, "owner", owner, next_fetch=(pending_until + 30) if pending_until else None, origin=origin)
        owner_out = {"id": oid, "value": owner, "added": oid is not None}
        if oid is not None:
            audit("repo_source_added", principal, kind="owner", value=owner)
    if sid is None and not (owner_out and owner_out["added"]):
        raise conflict(f"{value} is already in your Repos.")
    stored = 0
    if sid is not None:
        audit("repo_source_added", principal, kind=kind, value=value, pending=bool(pending_until))
        if stored_row is not None:
            stored = 1 if github.link_stored_repo(sid, value) else 0
        elif repos is not None:
            try:
                stored = github.refresh_source(sid, (info, repos, etag)).get("repos", 0)
            except github.RateLimited:
                pass                                 # saved; its releases follow after GitHub's reset
    if not pending_until:
        github.repo_sync.maybe_start()
    return {"id": sid, "kind": kind, "value": value, "url": github.source_url(kind, value), "added": sid is not None,
            "stored": stored, "via": parsed.via, "note": note, "pending": bool(pending_until), "until": pending_until,
            "requests": github.requests_sent() - sent_before, "owner": owner_out}


class BatchIn(StrictModel):
    lines: Annotated[list[Annotated[str, StringConstraints(max_length=500)]], Field(min_length=1, max_length=github.MAX_BATCH)]
    follow_owner: bool = False
    folder_id: int | None = Field(None, ge=1, le=2**31)   # 📁 put what these lines bring in into this folder
    # a bare profile link (github.com/<name>): "ask" = hold it and let the person choose; "follow" = follow all its repos;
    # "profile" = save just the profile as a link
    owner_mode: Literal["ask", "follow", "profile"] = "ask"


@router.post("/sources/batch", dependencies=[Depends(rate_limit("repos_batch", 10))])
def add_batch(body: BatchIn, principal: Principal = Depends(require_write)) -> dict:
    """Save up to 200 pasted lines at once - no GitHub request here. Each valid line becomes a queued source that the
    background sync checks and fills in (one request per repo; none when it is already stored), pacing itself to GitHub's
    hourly limit. Answers per line: queued (source id), already here, duplicate in this paste, or why it can't be added.
    Progress: GET /repos/sources/status?ids=…"""
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()
    added = 0
    with get_db() as db:
        if body.folder_id and not db.execute("SELECT 1 FROM repo_folders WHERE id = ?", (body.folder_id,)).fetchone():
            raise not_found("Folder")
        room = github.MAX_SOURCES - db.execute("SELECT COUNT(*) FROM repo_sources").fetchone()[0]
        for raw in body.lines:
            line = raw.strip()
            if not line:
                continue
            try:
                parsed = github.parse_input(line)
            except github.GitHubError as exc:
                results.append({"line": line, "status": "invalid", "detail": str(exc)})
                continue
            kind, value = parsed
            if kind == "owner" and body.owner_mode == "ask":   # following a whole account is a big step: ask first
                already = db.execute("SELECT id FROM repo_sources WHERE kind = 'owner' AND value = ?", (value,)).fetchone()
                results.append({"line": line, "kind": "owner", "value": value, "status": "exists" if already else "ask",
                                "id": already["id"] if already else None})
                continue
            if kind == "owner" and body.owner_mode == "profile":
                url = github.profile_url(value)
                parsed = github.Parsed("doc", url, via="profile", note=github.PROFILE_NOTE)
                kind, value = "doc", url
            wanted = [(kind, value, parsed)]
            if kind == "repo" and body.follow_owner:
                wanted.append(("owner", value.split("/", 1)[0], None))
            out = {"line": line, "kind": kind, "value": value, "note": parsed.note or None}
            for k, v, p in wanted:
                key = (k, v.lower())
                existing = db.execute("SELECT id FROM repo_sources WHERE kind = ? AND value = ?", (k, v)).fetchone()
                if key in seen:
                    state = "duplicate"
                elif existing:
                    state, sid = "exists", existing["id"]
                    if body.folder_id and p is not None:   # already here: file what it brought in now
                        ids = [x[0] for x in db.execute("SELECT repo_id FROM repo_source_links WHERE source_id = ?", (sid,))]
                        db.executemany("INSERT OR IGNORE INTO repo_folder_items (folder_id, repo_id, added_at) VALUES (?, ?, ?)",
                                       [(body.folder_id, i, now()) for i in ids])
                elif room <= 0:
                    state = "full"
                else:
                    sid = db.execute("INSERT INTO repo_sources (kind, value, title, created_at, next_fetch, origin, note, alt_value, folder_id) "
                                     "VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                                     (k, v, v, now(), line[:500], (p.note or None) if p else None, (p.alt or None) if p else None,
                                      body.folder_id if p is not None else None)).lastrowid
                    state, room, added = "queued", room - 1, added + 1
                seen.add(key)
                if p is not None:
                    out.update(status=state, id=sid if state in ("queued", "exists") else None)
                    if state == "full":
                        out["detail"] = f"Up to {github.MAX_SOURCES} GitHub sources."
                else:
                    out["owner"] = {"value": v, "status": state}
            results.append(out)
    audit("repo_sources_batch", principal, lines=len(body.lines), queued=added)
    if added:
        github.repo_sync.maybe_start()
    return {"queued": added, "results": results, "rate": github.rate_status()}


SourceIds = Annotated[str, StringConstraints(max_length=2000, pattern=r"^\d{1,9}(,\d{1,9}){0,199}$")]


@router.get("/sources/{source_id}/only", dependencies=[Depends(rate_limit("repos_read", 240))])
def source_only(source_id: int, _: Principal = Depends(require_read)) -> dict:
    """What removing a source would touch: its repos, and how many only it lists (not starred, no other source)."""
    with get_db() as db:
        if db.execute("SELECT 1 FROM repo_sources WHERE id = ?", (source_id,)).fetchone() is None:
            raise not_found("Source")
        total = db.execute("SELECT COUNT(*) FROM repo_source_links WHERE source_id = ?", (source_id,)).fetchone()[0]
        only = db.execute("SELECT COUNT(*) FROM repo_source_links l JOIN repos r ON r.id = l.repo_id WHERE l.source_id = ? AND r.starred = 0 "
                          "AND NOT EXISTS (SELECT 1 FROM repo_source_links o WHERE o.repo_id = l.repo_id AND o.source_id != l.source_id)",
                          (source_id,)).fetchone()[0]
        foldered = db.execute("SELECT COUNT(*) FROM repo_source_links l WHERE l.source_id = ? AND l.repo_id IN (SELECT repo_id FROM repo_folder_items) "
                              "AND NOT EXISTS (SELECT 1 FROM repo_source_links o WHERE o.repo_id = l.repo_id AND o.source_id != l.source_id)",
                              (source_id,)).fetchone()[0]
    return {"repos": total, "only_here": only, "only_here_in_folders": foldered}


@router.get("/sources/status", dependencies=[Depends(rate_limit("repos_read", 240))])
def sources_status(ids: SourceIds, _: Principal = Depends(require_read)) -> dict:
    """Where queued sources are: queued (being checked), waiting (GitHub's limit - finishes after ``until``), done, error."""
    wanted = [int(i) for i in ids.split(",")]
    t = now()
    out = []
    with get_db() as db:
        rows = db.execute(f"SELECT id, kind, value, note, last_fetch, next_fetch, last_error, repo_count FROM repo_sources "  # nosec B608
                          f"WHERE id IN ({placeholders(len(wanted))})", wanted).fetchall()
    for r in rows:
        if r["last_error"]:
            state = "error"
        elif r["last_fetch"]:
            state = "done"
        elif r["next_fetch"] and r["next_fetch"] > t:
            state = "waiting"
        else:
            state = "queued"
        out.append({"id": r["id"], "kind": r["kind"], "value": r["value"], "note": r["note"], "state": state,
                    "until": r["next_fetch"] if state == "waiting" else None, "repos": r["repo_count"], "error": r["last_error"]})
    return {"items": out, "rate": github.rate_status()}


@router.delete("/sources/{source_id}", dependencies=[Depends(rate_limit("repos_sources", 60))])
def remove_source(source_id: int, with_repos: bool = False, principal: Principal = Depends(require_write)) -> dict:
    """Remove a source. Its repos go unless another source lists them, you starred them or they're in a folder.
    ``with_repos``: also remove the repos only this source brought in even if they're in folders (starred ones and
    ones another source lists - e.g. a repo you pasted yourself - always stay)."""
    with get_db() as db:
        row = db.execute("SELECT kind, value FROM repo_sources WHERE id = ?", (source_id,)).fetchone()
        if row is None:
            raise not_found("Source")
        listed = [r[0] for r in db.execute("SELECT repo_id FROM repo_source_links WHERE source_id = ?", (source_id,))]
        db.execute("DELETE FROM repo_sources WHERE id = ?", (source_id,))
        forced = 0
        if with_repos and listed:
            forced = db.execute(f"DELETE FROM repos WHERE id IN ({placeholders(len(listed))}) AND starred = 0 "  # nosec B608 - fixed fragments
                                "AND id NOT IN (SELECT repo_id FROM repo_source_links)", listed).rowcount
        removed = forced + github.drop_orphans(db)
        kept = db.execute(f"SELECT COUNT(DISTINCT repo_id) FROM repo_folder_items WHERE repo_id IN ({placeholders(len(listed))})",  # nosec B608
                          listed).fetchone()[0] if listed else 0
    audit("repo_source_removed", principal, kind=row["kind"], value=row["value"], repos_removed=removed, with_repos=with_repos)
    return {"ok": True, "repos_removed": removed, "kept_in_folders": kept}


@router.post("/sources/{source_id}/refresh", dependencies=[Depends(rate_limit("repos_refresh", 20))])
def refresh_source(source_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("UPDATE repo_sources SET next_fetch = NULL WHERE id = ?", (source_id,)).rowcount == 0:
            raise not_found("Source")
    return {"started": github.repo_sync.maybe_start()}


@router.post("/refresh", dependencies=[Depends(rate_limit("repos_refresh", 6))])
def refresh_all(_: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        n = db.execute("UPDATE repo_sources SET next_fetch = NULL").rowcount
    return {"sources": n, "started": github.repo_sync.maybe_start()}


# ============================================================================ token
class TokenIn(StrictModel):
    token: Annotated[str, StringConstraints(min_length=20, max_length=300, pattern=r"^[A-Za-z0-9_]+$")] | None = None
    clear: bool = False


@router.put("/token", dependencies=[Depends(rate_limit("integrations", 20))])
def put_token(body: TokenIn, principal: Principal = Depends(require_admin)) -> dict:
    """Save (after checking it with GitHub) or remove the optional read-only GitHub token."""
    if not body.clear and not body.token:
        raise HTTPException(status_code=422, detail="Paste a token, or choose Remove.")
    info = None
    if body.token and not body.clear:
        try:
            info = github.check_token(body.token)
        except github.GitHubError as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from None
    with get_db() as db:
        if body.clear:
            integrations.save(db, "github", remove_secrets=("token",))
        else:
            integrations.save(db, "github", secrets={"token": body.token})
            # a token brings a fresh (much bigger) budget: lines waiting for the free limit go now
            resumed = db.execute("UPDATE repo_sources SET next_fetch = NULL WHERE last_fetch IS NULL AND last_error IS NULL "
                                 "AND next_fetch > ?", (now(),)).rowcount
        is_set = integrations.secret(db, "github", "token") is not None
    github.reset_rate()
    audit("integration_updated", principal, name="github", cleared=body.clear)
    if not body.clear:
        github.repo_sync.maybe_start()
    return {"token_set": is_set, "limit": (info or {}).get("limit"), "resumed": 0 if body.clear else resumed}
