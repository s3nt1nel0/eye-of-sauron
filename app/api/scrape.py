"""Feed discovery and website scraping: find a page's real feed, or suggest + preview scraping rules."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app import netguard, scraper
from app.api.common import HttpUrlStr, StrictModel
from app.config import get_settings
from app.fetcher import parse_bytes, xml_guard
from app.security import Principal, rate_limit, require_write

router = APIRouter(prefix="/scrape", tags=["scraping"])

PAGE_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.5"


def _fetch(url: str, max_bytes: int = scraper.MAX_PAGE_BYTES) -> netguard.SafeResponse:
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": PAGE_ACCEPT},
                                allow_private=cfg.allow_private_feeds, timeout=cfg.fetch_timeout, max_bytes=max_bytes)
    except netguard.UnsafeURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except netguard.FetchError as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch the page: {exc}") from None
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"The site answered HTTP {resp.status_code}")
    return resp


def _as_feed(resp: netguard.SafeResponse) -> dict | None:
    """If the response itself is an RSS/Atom/JSON feed, describe it."""
    if xml_guard(resp.content, resp.headers.get("content-type")):
        return None
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url)
    if parsed.get("version") and parsed.get("entries"):
        return {"url": resp.url, "title": (parsed.get("feed") or {}).get("title", "")[:200],
                "type": parsed.get("version"), "items": len(parsed.entries)}
    return None


class DiscoverIn(StrictModel):
    url: HttpUrlStr


@router.post("/discover", dependencies=[Depends(rate_limit("scrape_discover", 20))])
def discover(body: DiscoverIn, _: Principal = Depends(require_write)) -> dict:
    """1) Is the URL already a feed?  2) Feeds the page declares.  3) Common feed paths on the site.
    4) If none: suggested scraping rules with a preview of what they extract."""
    resp = _fetch(body.url)
    direct = _as_feed(resp)
    if direct:
        return {"is_feed": True, "feeds": [direct], "suggestion": None, "preview": []}
    feeds = []
    for cand in scraper.feed_links(resp.content, resp.url):
        try:
            info = _as_feed(_fetch(cand["url"], 10 * 1024 * 1024))
        except HTTPException:
            info = None
        if info:
            feeds.append({**info, "title": info["title"] or cand["title"]})
    if not feeds:
        for guess in scraper.same_site_guesses(resp.url)[:6]:
            try:
                info = _as_feed(_fetch(guess, 10 * 1024 * 1024))
            except HTTPException:
                continue
            if info:
                feeds.append(info)
                break
    suggestion, preview = None, []
    try:
        suggestion = scraper.suggest(resp.content, resp.url)
        if suggestion:
            preview = [i.preview() for i in scraper.extract(resp.content, resp.url, suggestion)[:15]]
    except (ValueError, scraper.ScrapeError):
        suggestion = None
    js_hint = not feeds and not preview and b"<script" in resp.content[:200_000].lower()
    return {"is_feed": False, "feeds": feeds, "page_url": resp.url,
            "suggestion": suggestion.model_dump() if suggestion else None, "preview": preview,
            "hint": ("This page seems to build its list with JavaScript, which scraping cannot see. Look for an "
                     "RSS link, a JSON API used by the page (browser DevTools → Network), or use an RSS-Bridge/RSSHub "
                     "instance.") if js_hint else None}


class PreviewIn(StrictModel):
    url: HttpUrlStr
    scrape: scraper.ScrapeConfig


@router.post("/preview", dependencies=[Depends(rate_limit("scrape_preview", 30))])
def preview(body: PreviewIn, _: Principal = Depends(require_write)) -> dict:
    """Run scraping rules against the live page and show what would be imported (nothing is saved)."""
    resp = _fetch(body.url)
    try:
        items = scraper.extract(resp.content, resp.url, body.scrape)
    except scraper.ScrapeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    warnings = []
    if not items:
        warnings.append("No items matched. Check the items selector (Firefox/Chrome: right-click → Inspect).")
    elif not any(i.published for i in items) and body.scrape.date:
        warnings.append("The date field matched nothing parseable; articles will be dated when fetched.")
    elif not body.scrape.date:
        warnings.append("No date selector: articles will be dated when first fetched.")
    return {"count": len(items), "items": [i.preview() for i in items[:25]], "warnings": warnings}
