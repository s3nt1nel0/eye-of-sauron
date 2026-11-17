"""Extras: image proxy, site icons and read-later (ideas from FreshRSS extensions)."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app import media, readlater
from app.api.common import StrictModel, not_found
from app.db import get_db
from app.security import Principal, audit, rate_limit, require_read, require_write

router = APIRouter(tags=["extras"])

IMAGE_HEADERS = {
    "Cache-Control": "private, max-age=86400",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Content-Disposition": "inline",
}


@router.get("/img", dependencies=[Depends(rate_limit("image_proxy", 600, 200))])
def image_proxy(u: Annotated[str, Query(min_length=8, max_length=4000)], s: Annotated[str, Query(pattern=r"^[0-9a-f]{32}$")],
                _: Principal = Depends(require_read)) -> Response:
    """An image from an article, fetched by this server (only addresses the server signed itself)."""
    if not media.verify(u, s):
        raise HTTPException(status_code=403, detail="Unsigned image address")
    try:
        data, mime = media.fetch_image(u)
    except media.MediaError:
        raise HTTPException(status_code=404, detail="Image not available") from None
    return Response(content=data, media_type=mime, headers=IMAGE_HEADERS)


@router.get("/feeds/{feed_id}/icon", dependencies=[Depends(rate_limit("site_icons", 1200, 400))])
def feed_icon(feed_id: int, _: Principal = Depends(require_read)) -> Response:
    """The feed's site icon (cached; fetched in the background)."""
    with get_db() as db:
        row = db.execute("SELECT mime, data FROM feed_icons WHERE feed_id = ?", (feed_id,)).fetchone()
    if row is None or row["data"] is None or media.sniff(bytes(row["data"])) is None:
        raise not_found("Icon")
    return Response(content=bytes(row["data"]), media_type=media.sniff(bytes(row["data"])),
                    headers={**IMAGE_HEADERS, "Cache-Control": "private, max-age=604800"})


@router.get("/readlater")
def readlater_status(_: Principal = Depends(require_read)) -> dict:
    """Which read-later services are set up (for the reader's 🔖 menu). No secrets."""
    with get_db() as db:
        return readlater.status(db)


class SaveIn(StrictModel):
    service: Literal["wallabag", "linkwarden"]


@router.post("/articles/{article_id}/save", dependencies=[Depends(rate_limit("readlater", 30))])
def save_for_later(article_id: int, body: SaveIn, principal: Principal = Depends(require_write)) -> dict:
    """Send the article's link to Wallabag or Linkwarden."""
    with get_db() as db:
        row = db.execute("SELECT a.url, a.title, f.title AS feed_title FROM articles a JOIN feeds f ON f.id = a.feed_id "
                         "WHERE a.id = ?", (article_id,)).fetchone()
        if row is None:
            raise not_found("Article")
        tags = [r[0] for r in db.execute("SELECT t.name FROM article_tags at JOIN tags t ON t.id = at.tag_id "
                                         "WHERE at.article_id = ? LIMIT 10", (article_id,))]
    if not row["url"] or not str(row["url"]).startswith(("https://", "http://")):
        raise HTTPException(status_code=422, detail="This item has no web address to save")
    try:
        out = readlater.save(body.service, row["url"], row["title"], ["eye-of-sauron", *tags])
    except readlater.ReadLaterError as exc:
        raise HTTPException(status_code=502, detail=str(exc)[:300]) from None
    audit("read_later", principal, article_id=article_id, service=body.service)
    return out
