"""Accounts tab: follow social media accounts and read their posts by topic (like the Videos tab)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StringConstraints

from app import accounts, app_settings, integrations, netguard, reddit, social_posts, topics
from app.api import content
from app.api import sources as sources_api
from app.api.common import StrictModel, TopicIds, not_found, topic_clause
from app.config import get_settings
from app.db import get_db, placeholders
from app.fetcher import ACCEPT, parse_bytes, xml_guard
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(prefix="/accounts", tags=["accounts"])

SOCIAL = "(f.social_platform IS NOT NULL OR f.kind IN ('x', 'telegram'))"  # fixed SQL fragment
PLATFORM = "COALESCE(f.social_platform, f.kind)"
STATES = {"all": "", "unread": "AND a.is_read = 0", "starred": "AND a.is_starred = 1"}
SORTS = {"newest": "a.sort_ts DESC, a.id DESC", "oldest": "a.sort_ts ASC, a.id ASC"}
POST_COLUMNS = (f"a.id, a.title, a.url, a.author, a.sort_ts AS published, a.is_read, a.is_starred, a.feed_id, "
                f"f.title AS feed_title, {PLATFORM} AS platform, substr(a.text_content, 1, 400) AS text")
Platform = Literal["x", "telegram", "bluesky", "mastodon", "reddit", "linkedin", "instagram", "facebook", "threads", "tiktok", "other"]


class AccountIn(StrictModel):
    input: Annotated[str, StringConstraints(min_length=2, max_length=2000)]
    platform: Platform | None = None          # for bridge feed URLs (LinkedIn, Instagram...)
    title: Annotated[str, Field(max_length=300)] | None = None
    folder_id: int | None = None
    retention_days: int | None = Field(default=None, ge=0, le=36500)  # keep N days (0 = forever); None = the default


class RecognizeIn(StrictModel):
    input: Annotated[str, StringConstraints(min_length=2, max_length=2000)]


@router.post("/recognize", dependencies=[Depends(rate_limit("accounts_read", 240))])
def recognize(body: RecognizeIn, _: Principal = Depends(require_write)) -> dict:  # part of adding: writers only
    """What a pasted line is - a single post, a subreddit / community, or an account - without fetching anything."""
    raw = body.input.strip()
    if raw.startswith(("http://", "https://", "www.")) and social_posts.is_post_url(raw):
        plat = social_posts.platform_of(raw if "://" in raw else "https://" + raw)
        return {"kind": "post", "platform": plat, "label": accounts.PLATFORMS.get(plat, "Other"),
                "needs_text": plat in social_posts.PASTE_ONLY.values()}
    with get_db() as db:
        rsshub = _rsshub_base(db)
    try:
        found = accounts.detect(raw, None, rsshub)
    except accounts.AccountError as exc:
        return {"kind": "unknown", "error": str(exc)}
    kind = "community" if str(found.get("handle", "")).startswith("r/") else "account"
    return {"kind": kind, "platform": found["platform"], "label": accounts.PLATFORMS.get(found["platform"], "Other"),
            "handle": found.get("handle")}


def _rsshub_base(db) -> str | None:
    """The RSSHub bridge set up for X (Settings → Integrations → X), reused for Instagram, Threads, TikTok..."""
    config, _ = integrations.load(db, "x")
    if config.get("bridge_type") == "rsshub" and config.get("bridge_url"):
        return str(config["bridge_url"])
    return None


def _store_first_posts(feed_id: int, entries) -> None:
    """Keep the posts the add check already downloaded, so a new account fills at once - without asking the site a
    second time straight away (Reddit answers a quick second request with 429)."""
    from app import fetcher  # local import: the fetcher pulls in the scheduler stack

    with get_db() as db:
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        prefs = app_settings.get_all(db)
    if feed is not None:
        fetcher._store(feed, prefs, feed["refresh_minutes"] or prefs["default_refresh_minutes"], entries, None, None, None, None)


def _social_folder(db) -> int:
    db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES ('Social Accounts', 9)")
    return db.execute("SELECT id FROM folders WHERE name = 'Social Accounts'").fetchone()["id"]


@router.post("", status_code=201, dependencies=[Depends(rate_limit("accounts_add", 30))])
def add_account(body: AccountIn, principal: Principal = Depends(require_write)) -> dict:
    """Follow a profile: X / Telegram through their sources, Bluesky / Mastodon / Reddit through their own RSS,
    anything else through a feed URL (e.g. from a bridge) labelled with the chosen platform."""
    with get_db() as db:
        rsshub = _rsshub_base(db)
    try:
        found = accounts.detect(body.input, body.platform, rsshub)
    except accounts.AccountError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    with get_db() as db:
        folder_id = body.folder_id if body.folder_id is not None else _social_folder(db)
        if found["platform"] == "reddit" and found.get("feed_url", "").endswith("/new/.rss?limit=100"):
            new = found["feed_url"]
            same = (new, new.replace("?limit=100", ""), new.replace("/new/.rss?limit=100", "/.rss"))  # older addresses too
            if db.execute("SELECT 1 FROM feeds WHERE url IN (?, ?, ?)", same).fetchone():
                raise HTTPException(status_code=409, detail=f"{found['handle']} is already followed")
    if found["via"] in ("x", "telegram"):
        res = sources_api.resolve(sources_api.ResolveIn(input=body.input, kind=found["via"]), principal)
        feed = content.create_feed(content.FeedIn(url=res["url"], title=body.title or res["title"], folder_id=folder_id,
                                                  source=res["source"], refresh_minutes=res["refresh_minutes"],
                                                  retention_days=body.retention_days), principal)
    else:
        url = found["feed_url"]
        cfg = get_settings()
        try:
            resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": ACCEPT},
                                    allow_private=cfg.allow_private_feeds, timeout=cfg.fetch_timeout, max_bytes=cfg.max_feed_bytes)
        except netguard.UnsafeURLError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except netguard.FetchError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach the account's feed: {exc}") from None
        busy = resp.status_code == 429 and found["platform"] == "reddit"  # Reddit's rate limit: follow it, fetch later
        if resp.status_code >= 400 and not busy:
            hint = f" {found['note']}" if found.get("note") else ""
            raise HTTPException(status_code=502, detail=f"The account's feed answered HTTP {resp.status_code} - check the "
                                                        f"address (private or deleted accounts have no feed).{hint}")
        parsed = {"version": "busy"} if busy else (None if xml_guard(resp.content, resp.headers.get("content-type")) else parse_bytes(
            resp.content, resp.headers.get("content-type"), resp.url))
        if not parsed or not (parsed.get("version") or parsed.get("entries")):
            raise HTTPException(status_code=422, detail="That address is not a feed. For LinkedIn, Instagram and similar, "
                                                        "paste the feed address your bridge (RSSHub, RSS-Bridge...) gives you.")
        named = found["handle"] if found["platform"] == "reddit" else None  # "r/homelab", not "newest submissions : homelab"
        title = body.title or named or str((parsed.get("feed") or {}).get("title") or found["handle"])[:300]
        feed = content.create_feed(content.FeedIn(url=url, title=title, folder_id=folder_id, retention_days=body.retention_days,
                                                  refresh_minutes=found.get("refresh_minutes")), principal)
        if not busy and parsed.get("entries"):
            _store_first_posts(feed["id"], parsed["entries"])
    with get_db() as db:
        db.execute("UPDATE feeds SET social_platform = ? WHERE id = ?", (found["platform"], feed["id"]))
    audit("account_added", principal, feed_id=feed["id"], platform=found["platform"])
    return {**feed, "platform": found["platform"]}


class PostIn(StrictModel):
    url: Annotated[str, StringConstraints(min_length=8, max_length=2000)]
    text: Annotated[str, StringConstraints(max_length=social_posts.MAX_TEXT)] | None = None  # pasted post text


SAVED_POSTS_URL = "https://eye-of-sauron.invalid/saved-posts/{platform}"  # placeholder address, never fetched


@router.post("/posts", status_code=201, dependencies=[Depends(rate_limit("accounts_add", 30))])
def add_post(body: PostIn, principal: Principal = Depends(require_write)) -> dict:
    """Save one post by its link: read through the site's public/official endpoint where one exists, otherwise from
    the text you pasted (LinkedIn, Instagram, Facebook...). It is tagged with topics like everything else."""
    with get_db() as db:
        rsshub = _rsshub_base(db)
    try:
        post = social_posts.fetch(body.url, body.text, rsshub)
    except social_posts.PostError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    from app.fetcher import insert_article  # local import: fetcher pulls in the scheduler stack
    from app.db import now
    plat = post["platform"]
    with get_db() as db:
        url = SAVED_POSTS_URL.format(platform=plat)
        row = db.execute("SELECT id FROM feeds WHERE url = ?", (url,)).fetchone()
        if row is None:  # one "Saved … posts" list per platform, never fetched (enabled = 0)
            feed_id = db.execute(
                "INSERT INTO feeds (folder_id, title, custom_title, url, created_at, enabled, social_platform, retention_days, max_articles) "
                "VALUES (?, ?, 1, ?, ?, 0, ?, 0, 0)",
                (_social_folder(db), f"Saved {accounts.PLATFORMS.get(plat, 'other')} posts", url, now(), plat)).lastrowid
        else:
            feed_id = row["id"]
        article_id = insert_article(db, feed_id, guid=post["link"], url=post["link"], title=post["title"][:1000],
                                    author=post["author"], raw_html=post["html"], published=post["published"],
                                    fetched_at=now(), ignore_tombstone=True)
        if article_id is None:
            raise HTTPException(status_code=409, detail="That post is already saved")
        topics.classify(db, [article_id])
    audit("post_saved", principal, platform=plat)
    return {"id": article_id, "platform": plat, "title": post["title"], "feed_id": feed_id}


FeedIdList = Annotated[str, StringConstraints(pattern=r"^\d{1,9}(,\d{1,9}){0,199}$")]
PlatformList = Annotated[str, StringConstraints(pattern=r"^[a-z]{1,12}(,[a-z]{1,12}){0,15}$")]


def _filters(feed_id, platform, topic_id, q, state, feed_ids: str | None = None, platforms: str | None = None) -> tuple[str, list]:
    where, params = [SOCIAL], []
    if feed_id is not None:
        where.append("a.feed_id = ?")
        params.append(feed_id)
    if feed_ids:
        ids = sorted({int(x) for x in feed_ids.split(",")})
        where.append(f"a.feed_id IN ({placeholders(len(ids))})")
        params += ids
    if platform:
        where.append(f"{PLATFORM} = ?")
        params.append(platform)
    if platforms:
        names = sorted(set(platforms.split(",")) & set(accounts.PLATFORMS))
        if not names:
            raise HTTPException(status_code=422, detail="Unknown platform")
        where.append(f"{PLATFORM} IN ({placeholders(len(names))})")
        params += names
    if topic_id is not None:
        where.append("EXISTS (SELECT 1 FROM article_topics t WHERE t.article_id = a.id AND t.topic_id = ?)")
        params.append(topic_id)
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(a.title LIKE ? ESCAPE '\\' OR a.text_content LIKE ? ESCAPE '\\' OR f.title LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    return f"FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE {' AND '.join(where)} {STATES[state]}", params  # nosec B608


def _attach_topics(db, rows: list[dict]) -> list[dict]:
    if rows:
        ids = [r["id"] for r in rows]
        tmap: dict[int, list[int]] = {}
        for t in db.execute(f"SELECT article_id, topic_id FROM article_topics WHERE article_id IN ({placeholders(len(ids))})", ids):
            tmap.setdefault(t["article_id"], []).append(t["topic_id"])
        for r in rows:
            r["topics"] = tmap.get(r["id"], [])
            r["is_read"], r["is_starred"] = bool(r["is_read"]), bool(r["is_starred"])
    return rows


Q = Annotated[str, StringConstraints(max_length=200)]


@router.get("/posts", dependencies=[Depends(rate_limit("accounts_read", 240))])
def posts(feed_id: int | None = Query(None, ge=1), platform: Platform | None = None, topic_id: int | None = Query(None, ge=0),
          topic_ids: TopicIds | None = None, topic_match: Literal["any", "all"] = "any",
          feed_ids: FeedIdList | None = None, platforms: PlatformList | None = None, full: bool = False,
          q: Q = "", state: Literal["all", "unread", "starred"] = "all", sort: Literal["newest", "oldest"] = "newest",
          limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000),
          _: Principal = Depends(require_read)) -> dict:
    base, params = _filters(feed_id, platform, topic_id or None, q.strip(), state, feed_ids, platforms)
    if topic_id == 0:  # "Other": no topic matched
        base += " AND NOT EXISTS (SELECT 1 FROM article_topics t WHERE t.article_id = a.id)"
    extra, extra_params = topic_clause(topic_ids, topic_match)
    base, params = base + extra, params + extra_params
    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608 - fixed fragments, values bound
        cols = POST_COLUMNS + (", a.content_html AS html" if full else "")
        rows = [dict(r) for r in db.execute(f"SELECT {cols} {base} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",  # nosec B608
                                            [*params, min(limit, 60) if full else limit, offset])]
        if full:  # the reading view: Reddit posts as their own text + photos / video / gallery
            for r in rows:
                if r["platform"] == "reddit" and reddit.is_post_url(r["url"]):
                    r["body"], r["media"], r["thread"] = reddit.body(r["html"]), reddit.media(r["html"]), True
        return {"total": total, "items": _attach_topics(db, rows)}


@router.get("/posts/{article_id}/thread", dependencies=[Depends(rate_limit("accounts_thread", 30))])
def post_thread(article_id: int, _: Principal = Depends(require_read)) -> dict:
    """A Reddit post with its comments, read from the post's public feed (cached for two minutes)."""
    with get_db() as db:
        row = db.execute(f"SELECT a.url FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id = ? AND {SOCIAL}",  # nosec B608
                         (article_id,)).fetchone()
    if row is None:
        raise not_found("Post")
    if not reddit.is_post_url(row["url"]):
        raise HTTPException(status_code=422, detail="Threads can be shown for Reddit posts - open the others on their site")
    try:
        return reddit.thread(row["url"])
    except social_posts.PostError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None


@router.get("/shelves", dependencies=[Depends(rate_limit("accounts_read", 240))])
def shelves(feed_id: int | None = Query(None, ge=1), platform: Platform | None = None, q: Q = "",
            state: Literal["all", "unread", "starred"] = "all", per: int = Query(12, ge=1, le=48),
            feed_ids: FeedIdList | None = None, platforms: PlatformList | None = None,
            _: Principal = Depends(require_read)) -> dict:
    """Posts split into categories by topic (a post with several topics is on each shelf), plus "Other"."""
    base, params = _filters(feed_id, platform, None, q.strip(), state, feed_ids, platforms)
    out = []
    with get_db() as db:
        topics = db.execute("SELECT id, name, color FROM topics WHERE enabled = 1").fetchall()
        for t in topics:
            tb = base + " AND EXISTS (SELECT 1 FROM article_topics x WHERE x.article_id = a.id AND x.topic_id = ?)"
            total = db.execute(f"SELECT COUNT(*) {tb}", [*params, t["id"]]).fetchone()[0]  # nosec B608
            if total:
                rows = [dict(r) for r in db.execute(f"SELECT {POST_COLUMNS} {tb} ORDER BY a.sort_ts DESC LIMIT ?",  # nosec B608
                                                    [*params, t["id"], per])]
                out.append({"topic": dict(t), "total": total, "items": _attach_topics(db, rows)})
        ob = base + " AND NOT EXISTS (SELECT 1 FROM article_topics x WHERE x.article_id = a.id)"
        other = db.execute(f"SELECT COUNT(*) {ob}", params).fetchone()[0]  # nosec B608
        out.sort(key=lambda s: -s["total"])
        if other:
            rows = [dict(r) for r in db.execute(f"SELECT {POST_COLUMNS} {ob} ORDER BY a.sort_ts DESC LIMIT ?", [*params, per])]  # nosec B608
            out.append({"topic": {"id": 0, "name": "Other (no topic matched)", "color": "#6b7280"}, "total": other,
                        "items": _attach_topics(db, rows)})
    return {"shelves": out}


@router.get("/meta")
def meta(_: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        rows = [dict(r) for r in db.execute(
            f"SELECT f.id AS feed_id, f.title, f.url, {PLATFORM} AS platform, f.error_count, f.last_error, f.enabled, "
            "f.retention_days, f.refresh_minutes, "
            "(SELECT COUNT(*) FROM articles a WHERE a.feed_id = f.id) AS posts, "
            "(SELECT COUNT(*) FROM articles a WHERE a.feed_id = f.id AND +a.is_read = 0) AS unread "
            f"FROM feeds f WHERE {SOCIAL} ORDER BY f.title COLLATE NOCASE")]  # nosec B608 - fixed fragments
    with get_db() as db:
        global_days = int(app_settings.get_all(db)["retention_days"] or 0)
    platforms: dict[str, int] = {}
    for r in rows:
        r["keeps"] = r["retention_days"] if r["retention_days"] is not None else global_days  # the retention in force
        platforms[r["platform"]] = platforms.get(r["platform"], 0) + 1
    return {"accounts": rows, "platforms": [{"id": k, "label": accounts.PLATFORMS.get(k, k), "icon": accounts.ICONS.get(k, "◎"),
                                             "accounts": n} for k, n in sorted(platforms.items())],
            "labels": accounts.PLATFORMS, "icons": accounts.ICONS}


@router.delete("/{feed_id}")
def remove_account(feed_id: int, principal: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute(f"SELECT 1 FROM feeds f WHERE f.id = ? AND {SOCIAL}", (feed_id,)).fetchone() is None:  # nosec B608
            raise not_found("Account")
    return content.delete_feed(feed_id, principal)
