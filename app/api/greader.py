"""Google Reader-compatible API for native mobile/desktop RSS apps (same protocol as FreshRSS).

Mounted at ``/api/greader.php`` (what apps expect for a "FreshRSS" account) and ``/api/greader``.
Works with Reeder, NetNewsWire, FeedMe, Read You, FocusReader, Fluent Reader, News+ and others.

Security design
* Apps never receive the admin password: they log in with a per-app **app password** (Settings →
  Mobile apps), stored as an argon2id hash and revocable individually.
* ClientLogin issues a normal API token with the **reader** scope only: it works on these endpoints and
  nowhere else (the REST API requires read/write scopes), so a phone app cannot manage tokens, settings,
  webhooks or social accounts.
* Authentication is header-only (``Authorization: GoogleLogin auth=...``); cookies are ignored, so there
  is no CSRF exposure. Credentials are accepted only in the POST body (never the query string, which
  would end up in access logs). ClientLogin shares the login brute-force throttles.
* All inputs are parsed defensively (bounded counts, strict id/stream grammar, bound SQL parameters);
  article HTML is re-sanitised on output exactly like the web UI.
"""

from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import StringConstraints
from typing import Annotated

from app import app_settings, netguard
from app.api.common import StrictModel, not_found
from app.db import get_db, now, placeholders
from app.sanitize import sanitize_html, to_text
from app.security import (
    API_TOKEN_PREFIX,
    Principal,
    _unauthorized,
    account_throttle,
    audit,
    client_ip,
    hash_password,
    login_throttle,
    new_secret,
    rate_limit,
    require_admin,
    token_hash,
    token_principal,
    verify_password,
)

log = logging.getLogger("eos.greader")

ITEM_PREFIX = "tag:google.com,2005:reader/item/"
STATE = "user/-/state/com.google/"
READING_LIST, READ, STARRED, KEPT_UNREAD = (STATE + s for s in ("reading-list", "read", "starred", "kept-unread"))
MAX_APPS = 10
TOKENS_PER_APP = 5
_LABEL_RE = re.compile(r"^user/(?:-|\d{1,20})/label/(.{1,100})$")
_STATE_RE = re.compile(r"^user/(?:-|\d{1,20})/state/com\.google/([a-z-]{1,30})$")


# =========================================================================== helpers
async def _params(request: Request) -> list[tuple[str, str]]:
    """Query string + urlencoded body (multi-valued, e.g. several i= / a= / r=). Body size is capped by middleware."""
    pairs = list(request.query_params.multi_items())
    if request.method == "POST":
        body = await request.body()
        if body:
            try:
                pairs += parse_qsl(body.decode("utf-8", "strict"), keep_blank_values=True, max_num_fields=5000)
            except (UnicodeDecodeError, ValueError):
                raise HTTPException(status_code=400, detail="Malformed form body") from None
    return pairs


def _get(pairs: list[tuple[str, str]], key: str, default: str = "") -> str:
    for k, v in pairs:
        if k == key:
            return v
    return default


def _all(pairs: list[tuple[str, str]], key: str) -> list[str]:
    return [v for k, v in pairs if k == key][:5000]


def _int(value: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def long_id(article_id: int) -> str:
    return f"{ITEM_PREFIX}{article_id:016x}"


def parse_item_id(value: str) -> int | None:
    value = value.strip()
    try:
        if value.startswith(ITEM_PREFIX):
            n = int(value[len(ITEM_PREFIX):], 16)
        elif re.fullmatch(r"-?\d{1,20}", value):
            n = int(value)
            if n < 0:  # some clients send the signed 64-bit form
                n += 2**64
        elif re.fullmatch(r"[0-9a-fA-F]{16}", value):
            n = int(value, 16)
        else:
            return None
    except ValueError:
        return None
    return n if 0 < n < 2**63 else None


def reader_principal(request: Request) -> Principal:
    """``Authorization: GoogleLogin auth=<token>`` (or Bearer). Requires the reader scope."""
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    value = value.strip()
    if scheme == "GoogleLogin" and value.startswith("auth="):
        value = value[5:]
    elif scheme.lower() != "bearer":
        raise _unauthorized("Missing GoogleLogin authorization")
    principal = token_principal(value)
    if "reader" not in principal.scopes:
        raise HTTPException(status_code=403, detail="This token is not a reader-app token")
    return principal


def _label_target(db, name: str) -> tuple[str, int] | None:
    row = db.execute("SELECT id FROM folders WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if row:
        return "folder", row["id"]
    row = db.execute("SELECT id FROM tags WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if row:
        return "tag", row["id"]
    return None


def _stream_filter(db, stream: str) -> tuple[str, list]:
    """SQL condition (over articles a JOIN feeds f) for a Google Reader stream id."""
    if not stream or stream == READING_LIST:
        return "1", []
    if stream == STARRED or stream.endswith("/state/com.google/starred"):
        return "a.is_starred = 1", []
    if stream == READ or stream.endswith("/state/com.google/read"):
        return "a.is_read = 1", []
    if stream.startswith("feed/"):
        ref = stream[5:]
        if ref.isdigit():
            return "a.feed_id = ?", [int(ref)]
        row = db.execute("SELECT id FROM feeds WHERE url = ?", (ref[:2048],)).fetchone()
        return ("a.feed_id = ?", [row["id"]]) if row else ("0", [])
    m = _LABEL_RE.match(stream)
    if m:
        target = _label_target(db, m.group(1))
        if target and target[0] == "folder":
            return "f.folder_id = ?", [target[1]]
        if target:
            return "EXISTS (SELECT 1 FROM article_tags x WHERE x.article_id = a.id AND x.tag_id = ?)", [target[1]]
        return "0", []
    if _STATE_RE.match(stream):
        return "1", []
    return "0", []


def _state_filter(stream: str, include: bool) -> tuple[str, list]:
    if stream.endswith("/state/com.google/read"):
        return ("a.is_read = 1" if include else "a.is_read = 0"), []
    if stream.endswith("/state/com.google/starred"):
        return ("a.is_starred = 1" if include else "a.is_starred = 0"), []
    return "1", []


def _query(db, pairs: list[tuple[str, str]], stream: str, max_n: int) -> tuple[list, str | None]:
    """Shared by stream/contents and stream/items/ids: filters, ordering and keyset continuation."""
    where, params = _stream_filter(db, stream)
    clauses, values = [where], list(params)
    for xt in _all(pairs, "xt")[:5]:
        sql, p = _state_filter(xt, include=False)
        clauses.append(sql)
        values += p
    for it in _all(pairs, "it")[:5]:
        sql, p = _state_filter(it, include=True)
        if sql == "1":
            sql, p = _stream_filter(db, it)
        clauses.append(sql)
        values += p
    ot = _int(_get(pairs, "ot"), 0, 0, 2**40)
    nt = _int(_get(pairs, "nt"), 0, 0, 2**40)
    if ot:
        clauses.append("a.sort_ts >= ?")
        values.append(ot)
    if nt:
        clauses.append("a.sort_ts <= ?")
        values.append(nt)
    oldest_first = _get(pairs, "r") == "o"
    cont = _get(pairs, "c")
    m = re.fullmatch(r"(\d{1,12}):(\d{1,19})", cont) if cont else None
    if m:
        ts, aid = int(m.group(1)), int(m.group(2))
        if oldest_first:
            clauses.append("(a.sort_ts > ? OR (a.sort_ts = ? AND a.id > ?))")
        else:
            clauses.append("(a.sort_ts < ? OR (a.sort_ts = ? AND a.id < ?))")
        values += [ts, ts, aid]
    n = _int(_get(pairs, "n"), 20, 1, max_n)
    direction = "ASC" if oldest_first else "DESC"  # derived from a fixed comparison, never user text
    rows = db.execute(
        "SELECT a.id, a.feed_id, a.title, a.url, a.author, a.content_html, a.published, a.fetched_at, a.sort_ts, "
        "a.is_read, a.is_starred, f.title AS feed_title, f.site_url, f.url AS feed_url, f.folder_id "
        f"FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE {' AND '.join(clauses)} "  # nosec B608
        f"ORDER BY a.sort_ts {direction}, a.id {direction} LIMIT ?",
        [*values, n + 1],
    ).fetchall()
    more = len(rows) > n
    rows = rows[:n]
    continuation = f"{rows[-1]['sort_ts']}:{rows[-1]['id']}" if more and rows else None
    return rows, continuation


def _items(db, rows) -> list[dict]:
    if not rows:
        return []
    ids = [r["id"] for r in rows]
    ph = placeholders(len(ids))
    labels: dict[int, list[str]] = {i: [] for i in ids}
    for r in db.execute(f"SELECT at.article_id, t.name FROM article_tags at JOIN tags t ON t.id = at.tag_id "
                        f"WHERE at.article_id IN ({ph})", ids):
        labels[r[0]].append(r[1])
    folders = {r[0]: r[1] for r in db.execute("SELECT id, name FROM folders")}
    load_images = app_settings.get(db, "load_images")
    out = []
    for r in rows:
        cats = [READING_LIST]
        if r["is_read"]:
            cats.append(READ)
        if r["is_starred"]:
            cats.append(STARRED)
        if r["folder_id"] in folders:
            cats.append(f"user/-/label/{folders[r['folder_id']]}")
        cats += [f"user/-/label/{name}" for name in labels[r["id"]]]
        ts = r["published"] or r["sort_ts"]
        link = r["url"] or ""
        out.append({
            "id": long_id(r["id"]),
            "crawlTimeMsec": str(r["fetched_at"] * 1000),
            "timestampUsec": str(r["sort_ts"] * 1_000_000),
            "published": ts,
            "updated": ts,
            "title": r["title"],
            "author": r["author"] or "",
            "canonical": [{"href": link}] if link else [],
            "alternate": [{"href": link, "type": "text/html"}] if link else [],
            "summary": {"direction": "ltr", "content": sanitize_html(r["content_html"], allow_images=load_images)},
            "categories": cats,
            "origin": {"streamId": f"feed/{r['feed_id']}", "title": r["feed_title"], "htmlUrl": r["site_url"] or r["feed_url"]},
        })
    return out


def _ok() -> PlainTextResponse:
    return PlainTextResponse("OK")


# =========================================================================== router
def build_router(prefix: str) -> APIRouter:
    router = APIRouter(prefix=prefix, include_in_schema=False)
    reader = Depends(reader_principal)

    @router.post("/accounts/ClientLogin")
    async def client_login(request: Request) -> PlainTextResponse:
        if request.query_params.get("Passwd") is not None:
            # Never accept credentials in the URL: they would be written to access logs.
            raise HTTPException(status_code=400, detail="Send Email and Passwd in the POST body")
        body = await request.body()
        try:
            form = dict(parse_qsl(body.decode("utf-8", "strict"), keep_blank_values=True, max_num_fields=20))
        except (UnicodeDecodeError, ValueError):
            raise HTTPException(status_code=400, detail="Malformed form body") from None
        username, password = form.get("Email", "")[:64], form.get("Passwd", "")[:256]
        ip = client_ip(request)
        ip_key, user_key = f"ip:{ip}", f"user:{username.lower()}"
        if not login_throttle.allowed(ip_key) or not account_throttle.allowed(user_key):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
        app_row = None
        with get_db() as db:
            user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
            apps = db.execute("SELECT id, name, password_hash FROM reader_apps").fetchall() if user else []
        for row in apps:  # at most MAX_APPS argon2 verifications
            if verify_password(row["password_hash"], password):
                app_row = row
                break
        if user is None or app_row is None:
            verify_password(None, password)  # uniform timing when there is no user / no apps
            login_throttle.record_failure(ip_key)
            account_throttle.record_failure(user_key)
            audit("reader_login_failed", None, ip=ip, username=username)
            return PlainTextResponse("Error=BadAuthentication\n", status_code=401)
        login_throttle.reset(ip_key)
        account_throttle.reset(user_key)
        token = API_TOKEN_PREFIX + new_secret()
        ts = now()
        name_prefix = f"reader-app:{app_row['id']}:"
        with get_db() as db:
            db.execute(
                "INSERT INTO api_tokens (name, token_hash, prefix, scopes, created_at, expires_at) VALUES (?, ?, ?, 'reader', ?, NULL)",
                (f"{name_prefix}{app_row['name']}", token_hash(token), token[:10], ts),
            )
            # Keep the newest few sessions per app password (one per device); older ones are revoked.
            db.execute(
                "DELETE FROM api_tokens WHERE id IN (SELECT id FROM api_tokens WHERE name LIKE ? ESCAPE '\\' "
                "ORDER BY id DESC LIMIT -1 OFFSET ?)",
                (name_prefix.replace("_", "\\_").replace("%", "\\%") + "%", TOKENS_PER_APP),
            )
            db.execute("UPDATE reader_apps SET last_used = ? WHERE id = ?", (ts, app_row["id"]))
        audit("reader_login", None, ip=ip, app=app_row["name"])
        return PlainTextResponse(f"SID={token}\nLSID=null\nAuth={token}\n")

    @router.get("/reader/api/0/token")
    def edit_token(principal: Principal = reader) -> PlainTextResponse:
        # Auth is header-based (no cookies), so the action token is informational; any value is accepted.
        return PlainTextResponse(f"{principal.token_id:x}{'Z' * 41}"[:57] + "\n")

    @router.get("/reader/api/0/user-info")
    def user_info(_: Principal = reader) -> dict:
        with get_db() as db:
            user = db.execute("SELECT id, username FROM users ORDER BY id LIMIT 1").fetchone()
        return {"userId": str(user["id"]), "userName": user["username"], "userProfileId": str(user["id"]),
                "userEmail": "", "isBloggerUser": False, "signupTimeSec": 0, "isMultiLoginEnabled": False}

    @router.get("/reader/api/0/subscription/list")
    def subscription_list(_: Principal = reader) -> dict:
        with get_db() as db:
            rows = db.execute(
                "SELECT f.id, f.title, f.url, f.site_url, fo.name AS folder FROM feeds f "
                "LEFT JOIN folders fo ON fo.id = f.folder_id ORDER BY f.title COLLATE NOCASE").fetchall()
        subs = []
        for r in rows:
            cats = [{"id": f"user/-/label/{r['folder']}", "label": r["folder"]}] if r["folder"] else []
            subs.append({"id": f"feed/{r['id']}", "title": r["title"], "categories": cats, "url": r["url"],
                         "htmlUrl": r["site_url"] or r["url"], "iconUrl": ""})
        return {"subscriptions": subs}

    @router.get("/reader/api/0/tag/list")
    def tag_list(_: Principal = reader) -> dict:
        with get_db() as db:
            folders = [r[0] for r in db.execute("SELECT name FROM folders ORDER BY name COLLATE NOCASE")]
            tags = [r[0] for r in db.execute("SELECT name FROM tags ORDER BY name COLLATE NOCASE")]
        out = [{"id": STARRED}]
        out += [{"id": f"user/-/label/{n}", "type": "folder"} for n in folders]
        out += [{"id": f"user/-/label/{n}", "type": "tag"} for n in tags if n.lower() not in {f.lower() for f in folders}]
        return {"tags": out}

    @router.get("/reader/api/0/unread-count")
    def unread_count(_: Principal = reader) -> dict:
        with get_db() as db:
            per_feed = db.execute(
                "SELECT feed_id, COUNT(*) AS n, MAX(sort_ts) AS newest FROM articles WHERE is_read = 0 GROUP BY feed_id"
            ).fetchall()
            per_folder = db.execute(
                "SELECT fo.name, COUNT(*) AS n, MAX(a.sort_ts) AS newest FROM articles a JOIN feeds f ON f.id = a.feed_id "
                "JOIN folders fo ON fo.id = f.folder_id WHERE a.is_read = 0 GROUP BY fo.id").fetchall()
        counts = [{"id": f"feed/{r['feed_id']}", "count": r["n"], "newestItemTimestampUsec": str((r["newest"] or 0) * 1_000_000)}
                  for r in per_feed]
        counts += [{"id": f"user/-/label/{r['name']}", "count": r["n"], "newestItemTimestampUsec": str((r["newest"] or 0) * 1_000_000)}
                   for r in per_folder]
        total = sum(r["n"] for r in per_feed)
        newest = max((r["newest"] or 0 for r in per_feed), default=0)
        counts.append({"id": READING_LIST, "count": total, "newestItemTimestampUsec": str(newest * 1_000_000)})
        return {"max": total, "unreadcounts": counts}

    @router.get("/reader/api/0/stream/contents/{stream:path}", dependencies=[Depends(_rl("greader_stream", 300, 120))])
    async def stream_contents(stream: str, request: Request, _: Principal = reader) -> dict:
        pairs = await _params(request)
        stream = stream or _get(pairs, "s") or READING_LIST
        with get_db() as db:
            rows, cont = _query(db, pairs, stream, 1000)
            items = _items(db, rows)
        out: dict = {"id": stream, "updated": now(), "items": items}
        if cont:
            out["continuation"] = cont
        return out

    @router.get("/reader/api/0/stream/contents", dependencies=[Depends(_rl("greader_stream", 300, 120))])
    async def stream_contents_query(request: Request, _: Principal = reader) -> dict:
        """Same as above for clients that pass the stream as ?s= instead of in the path."""
        return await stream_contents("", request, _)

    @router.get("/reader/api/0/stream/items/ids", dependencies=[Depends(_rl("greader_ids", 300, 120))])
    async def stream_item_ids(request: Request, _: Principal = reader) -> dict:
        pairs = await _params(request)
        with get_db() as db:
            rows, cont = _query(db, pairs, _get(pairs, "s") or READING_LIST, 10_000)
        out: dict = {"itemRefs": [{"id": str(r["id"]), "directStreamIds": [], "timestampUsec": str(r["sort_ts"] * 1_000_000)}
                                  for r in rows]}
        if cont:
            out["continuation"] = cont
        return out

    @router.api_route("/reader/api/0/stream/items/contents", methods=["GET", "POST"],
                      dependencies=[Depends(_rl("greader_items", 300, 120))])
    async def stream_items_contents(request: Request, _: Principal = reader) -> dict:
        pairs = await _params(request)
        ids = [i for i in (parse_item_id(v) for v in _all(pairs, "i")[:1000]) if i]
        with get_db() as db:
            rows = db.execute(
                "SELECT a.id, a.feed_id, a.title, a.url, a.author, a.content_html, a.published, a.fetched_at, a.sort_ts, "
                "a.is_read, a.is_starred, f.title AS feed_title, f.site_url, f.url AS feed_url, f.folder_id "
                f"FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id IN ({placeholders(len(ids))}) "  # nosec B608
                "ORDER BY a.sort_ts DESC", ids).fetchall() if ids else []
            items = _items(db, rows)
        return {"id": READING_LIST, "updated": now(), "items": items}

    @router.post("/reader/api/0/edit-tag")
    async def edit_tag(request: Request, principal: Principal = reader) -> PlainTextResponse:
        pairs = await _params(request)
        ids = [i for i in (parse_item_id(v) for v in _all(pairs, "i")) if i]
        if not ids:
            return _ok()
        adds, removes = _all(pairs, "a")[:20], _all(pairs, "r")[:20]
        ts = now()
        with get_db() as db:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                ph = placeholders(len(chunk))
                for tag, on in [(t, True) for t in adds] + [(t, False) for t in removes]:
                    if tag.endswith("/state/com.google/read"):
                        db.execute(f"UPDATE articles SET is_read = ? WHERE id IN ({ph})", [int(on), *chunk])  # nosec B608
                    elif tag.endswith("/state/com.google/kept-unread"):
                        if on:
                            db.execute(f"UPDATE articles SET is_read = 0 WHERE id IN ({ph})", chunk)  # nosec B608
                    elif tag.endswith("/state/com.google/starred"):
                        db.execute(
                            f"UPDATE articles SET is_starred = ?, starred_at = CASE WHEN ? THEN COALESCE(starred_at, ?) ELSE NULL END "
                            f"WHERE id IN ({ph})", [int(on), int(on), ts, *chunk])  # nosec B608
                    else:
                        m = _LABEL_RE.match(tag)
                        name = to_text(m.group(1), 100) if m else ""
                        if not name:
                            continue
                        row = db.execute("SELECT id FROM tags WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
                        if row is None and on:
                            row = {"id": db.execute("INSERT INTO tags (name) VALUES (?)", (name,)).lastrowid}
                        if row is None:
                            continue
                        if on:
                            db.executemany(
                                "INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'manual', ?) "
                                "ON CONFLICT(article_id, tag_id) DO UPDATE SET source = 'manual'",
                                [(i, row["id"], ts) for i in chunk if db.execute("SELECT 1 FROM articles WHERE id = ?", (i,)).fetchone()])
                        else:
                            db.execute(f"DELETE FROM article_tags WHERE tag_id = ? AND article_id IN ({ph})", [row["id"], *chunk])  # nosec B608
        return _ok()

    @router.post("/reader/api/0/mark-all-as-read")
    async def mark_all_as_read(request: Request, _: Principal = reader) -> PlainTextResponse:
        pairs = await _params(request)
        stream = _get(pairs, "s") or READING_LIST
        ts_usec = _int(_get(pairs, "ts"), 0, 0, 2**62)
        with get_db() as db:
            where, params = _stream_filter(db, stream)
            extra, extra_p = ("AND a.sort_ts <= ?", [ts_usec // 1_000_000]) if ts_usec else ("", [])
            db.execute(
                "UPDATE articles SET is_read = 1 WHERE id IN (SELECT a.id FROM articles a JOIN feeds f ON f.id = a.feed_id "
                f"WHERE {where} {extra})", [*params, *extra_p])  # nosec B608
        return _ok()

    @router.post("/reader/api/0/subscription/quickadd", dependencies=[Depends(_rl("greader_add", 20))])
    async def quickadd(request: Request, principal: Principal = reader) -> dict:
        pairs = await _params(request)
        feed_id, title, url = _subscribe(_get(pairs, "quickadd"), "", "")
        audit("reader_subscribe", principal, feed_id=feed_id)
        return {"numResults": 1, "query": url, "streamId": f"feed/{feed_id}", "streamName": title}

    @router.post("/reader/api/0/subscription/edit", dependencies=[Depends(_rl("greader_sub_edit", 60))])
    async def subscription_edit(request: Request, principal: Principal = reader) -> PlainTextResponse:
        pairs = await _params(request)
        action = _get(pairs, "ac")
        title = to_text(_get(pairs, "t"), 300)
        add_label = _LABEL_RE.match(_get(pairs, "a"))
        remove_label = _LABEL_RE.match(_get(pairs, "r"))
        for stream in _all(pairs, "s")[:50]:
            if action == "subscribe":
                feed_id, _, _ = _subscribe(stream[5:] if stream.startswith("feed/") else stream, title,
                                           add_label.group(1) if add_label else "")
                audit("reader_subscribe", principal, feed_id=feed_id)
                continue
            if not stream.startswith("feed/") or not stream[5:].isdigit():
                raise HTTPException(status_code=400, detail="Unknown stream")
            feed_id = int(stream[5:])
            with get_db() as db:
                if db.execute("SELECT 1 FROM feeds WHERE id = ?", (feed_id,)).fetchone() is None:
                    raise not_found("Feed")
                if action == "unsubscribe":
                    db.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
                    audit("reader_unsubscribe", principal, feed_id=feed_id)
                elif action == "edit":
                    if title:
                        db.execute("UPDATE feeds SET title = ?, custom_title = 1 WHERE id = ?", (title, feed_id))
                    if add_label:
                        db.execute("UPDATE feeds SET folder_id = ? WHERE id = ?", (_folder_id(db, add_label.group(1)), feed_id))
                    elif remove_label:
                        db.execute("UPDATE feeds SET folder_id = NULL WHERE id = ?", (feed_id,))
                else:
                    raise HTTPException(status_code=400, detail="Unknown action")
        return _ok()

    @router.post("/reader/api/0/rename-tag")
    async def rename_tag(request: Request, principal: Principal = reader) -> PlainTextResponse:
        pairs = await _params(request)
        src, dest = _LABEL_RE.match(_get(pairs, "s")), _LABEL_RE.match(_get(pairs, "dest"))
        if not src or not dest:
            raise HTTPException(status_code=400, detail="s and dest must be labels")
        new = to_text(dest.group(1), 100)
        with get_db() as db:
            target = _label_target(db, src.group(1))
            if target is None:
                raise not_found("Label")
            table = "folders" if target[0] == "folder" else "tags"  # fixed table names
            try:
                db.execute(f"UPDATE {table} SET name = ? WHERE id = ?", (new, target[1]))  # nosec B608
            except Exception:
                raise HTTPException(status_code=409, detail="A label with that name already exists") from None
        return _ok()

    @router.post("/reader/api/0/disable-tag")
    async def disable_tag(request: Request, principal: Principal = reader) -> PlainTextResponse:
        pairs = await _params(request)
        src = _LABEL_RE.match(_get(pairs, "s"))
        if not src:
            raise HTTPException(status_code=400, detail="s must be a label")
        with get_db() as db:
            target = _label_target(db, src.group(1))
            if target is None:
                raise not_found("Label")
            table = "folders" if target[0] == "folder" else "tags"  # fixed table names; feeds become unfiled
            db.execute(f"DELETE FROM {table} WHERE id = ?", (target[1],))  # nosec B608
        audit("reader_label_deleted", principal, label=src.group(1))
        return _ok()

    return router


def _rl(name: str, per_minute: int, burst: int | None = None):
    """Rate limit keyed on the reader token (reader_principal instead of the cookie/bearer principal)."""
    from app.security import RateLimiter, _limiters

    limiter = _limiters.setdefault(name, RateLimiter(per_minute, burst))

    def dependency(principal: Principal = Depends(reader_principal)) -> None:
        ok, retry = limiter.allow(f"token:{principal.token_id}")
        if not ok:
            raise HTTPException(status_code=429, detail="Too many requests - slow down", headers={"Retry-After": str(retry)})

    return dependency


def _folder_id(db, name: str) -> int:
    name = to_text(name, 100)
    row = db.execute("SELECT id FROM folders WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if row:
        return row["id"]
    return int(db.execute("INSERT INTO folders (name) VALUES (?)", (name,)).lastrowid)


def _subscribe(url: str, title: str, label: str) -> tuple[int, str, str]:
    try:
        url = netguard.normalize_url(url)
    except netguard.UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    import sqlite3
    import threading

    from app.fetcher import fetch_feed

    with get_db() as db:
        row = db.execute("SELECT id, title FROM feeds WHERE url = ?", (url,)).fetchone()
        if row:
            return row["id"], row["title"], url
        if db.execute("SELECT COUNT(*) FROM feeds").fetchone()[0] >= 5000:
            raise HTTPException(status_code=400, detail="Feed limit reached")
        folder_id = _folder_id(db, label) if label else None
        try:
            feed_id = int(db.execute(
                "INSERT INTO feeds (folder_id, title, custom_title, url, created_at) VALUES (?, ?, ?, ?, ?)",
                (folder_id, title or url, 1 if title else 0, url, now())).lastrowid)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Already subscribed") from None
    threading.Thread(target=fetch_feed, args=(feed_id,), name=f"fetch-{feed_id}", daemon=True).start()
    return feed_id, title or url, url


# =========================================================================== REST: manage app passwords (admin)
admin_router = APIRouter(prefix="/reader-apps", tags=["mobile apps"])
AppName = Annotated[str, StringConstraints(min_length=1, max_length=60, pattern=r"^[\w .,'()+-]+$")]


class ReaderAppIn(StrictModel):
    name: AppName


@admin_router.get("")
def list_apps(_: Principal = Depends(require_admin)) -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT id, name, created_at, last_used FROM reader_apps ORDER BY id").fetchall()
        out = []
        for r in rows:
            n = db.execute("SELECT COUNT(*) FROM api_tokens WHERE name LIKE ?", (f"reader-app:{r['id']}:%",)).fetchone()[0]
            out.append({**dict(r), "devices": n})
    return out


@admin_router.post("", status_code=201, dependencies=[Depends(rate_limit("reader_app_create", 10))])
def create_app(body: ReaderAppIn, principal: Principal = Depends(require_admin)) -> dict:
    password = "-".join(secrets.token_urlsafe(6) for _ in range(4))  # ~140 bits, easy to type on a phone
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM reader_apps").fetchone()[0] >= MAX_APPS:
            raise HTTPException(status_code=400, detail=f"App password limit reached ({MAX_APPS})")
        cur = db.execute("INSERT INTO reader_apps (name, password_hash, created_at) VALUES (?, ?, ?)",
                         (body.name, hash_password(password), now()))
        user = db.execute("SELECT username FROM users ORDER BY id LIMIT 1").fetchone()
    audit("reader_app_created", principal, app_id=cur.lastrowid, name=body.name)
    # Shown exactly once; only the argon2 hash is stored.
    return {"id": cur.lastrowid, "name": body.name, "username": user["username"], "password": password}


@admin_router.delete("/{app_id}")
def delete_app(app_id: int, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM reader_apps WHERE id = ?", (app_id,)).rowcount == 0:
            raise not_found("App password")
        db.execute("DELETE FROM api_tokens WHERE name LIKE ?", (f"reader-app:{app_id}:%",))
    audit("reader_app_revoked", principal, app_id=app_id)
    return {"ok": True}
