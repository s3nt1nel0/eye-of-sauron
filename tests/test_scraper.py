"""Website scraping: rules, extraction, dates, suggestions, discovery, fetch integration and safety."""

import json
import time
from unittest import mock

import httpx
import pytest

from app import netguard, scraper

PAGE = b"""<!doctype html><html><head><title>Vendor blog</title></head><body>
<nav><a href="/about">About us and our long navigation link text</a></nav>
<div class="posts">
  <div class="post-card"><h2><a href="/blog/one">LockBit returns with a new leak site</a></h2>
    <time datetime="2026-11-10T09:00:00Z">Nov 10</time><p class="excerpt">Summary one <script>alert(1)</script></p>
    <span class="author">Alice</span><img src="/img/1.png"></div>
  <div class="post-card"><h2><a href="https://other.example/two">Critical Fortinet bug exploited</a></h2>
    <span class="date">November 9, 2026</span><p class="excerpt">Summary two <img src=x onerror=alert(1)></p></div>
  <div class="post-card"><h2><a href="javascript:alert(1)">Evil link item stays but loses link</a></h2>
    <span class="date">3 days ago</span><p class="excerpt">Three</p></div>
  <div class="post-card"><h2><a href="/blog/one">Duplicate of the first item, same link</a></h2></div>
</div></body></html>"""

RULES = {"mode": "html", "items": "div.post-card", "title": "h2", "link": "h2 a @href", "content": "p.excerpt",
         "date": "time, .date", "author": ".author", "image": "img @src"}


def resp(body, url="https://vendor.example/blog", status=200, ctype="text/html"):
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


def test_extract_html():
    cfg = scraper.ScrapeConfig(**RULES)
    items = scraper.extract(PAGE, "https://vendor.example/blog", cfg, now_ts=1794400000)
    assert [i.title for i in items][:2] == ["LockBit returns with a new leak site", "Critical Fortinet bug exploited"]
    assert len(items) == 3  # duplicate link removed
    assert items[0].link == "https://vendor.example/blog/one" and items[1].link == "https://other.example/two"
    assert items[2].link is None  # javascript: dropped
    assert items[0].published == 1794301200 and items[1].published is not None
    assert items[2].published == 1794400000 - 3 * 86400
    assert items[0].author == "Alice" and items[0].image == "https://vendor.example/img/1.png"


@pytest.mark.parametrize("text,expected", [
    ("2026-11-10", 1794268800), ("Tue, 10 Nov 2026 00:00:00 GMT", 1794268800), ("November 10th, 2026", 1794268800),
    ("10 Nov 2026", 1794268800), ("yesterday", 1794400000 - 86400), ("2 hours ago", 1794400000 - 7200), ("garbage", None),
])
def test_parse_date(text, expected):
    assert scraper.parse_date(text, now_ts=1794400000) == expected


@pytest.mark.parametrize("bad", [
    {"items": "div[[["}, {"items": "div", "title": "h2 >>> x"}, {"mode": "json", "items": "data..x"},
    {"mode": "json", "items": "a;b"}, {"items": "div", "date_format": "%d %B %Y'; DROP"}, {"items": ""},
    {"items": "x" * 301},
])
def test_invalid_rules_rejected(bad):
    with pytest.raises(ValueError):
        scraper.ScrapeConfig(**bad)


def test_extract_json():
    doc = json.dumps({"data": {"items": [
        {"title": "AI model jailbreak", "url": "/p/1", "published_at": "2026-11-10T00:00:00Z", "source": "Lab",
         "author": {"name": "Bob"}},
        {"title": "Second", "url": "https://x.example/2"}, {"nope": 1}]}}).encode()
    cfg = scraper.ScrapeConfig(mode="json", items="data.items", title='title & " (" & source & ")"', link="url",
                               date="published_at", author="author.name")
    items = scraper.extract(doc, "https://api.example/v1", cfg)
    assert items[0].title == "AI model jailbreak (Lab)" and items[0].link == "https://api.example/p/1"
    assert items[0].author == "Bob" and items[0].published == 1794268800 and len(items) == 2
    with pytest.raises(scraper.ScrapeError):
        scraper.extract(b"not json", "https://x.example", cfg)


def test_suggest_and_feed_links():
    cfg = scraper.suggest(PAGE, "https://vendor.example/blog")
    assert cfg is not None and cfg.items == "div.post-card" and cfg.title == "h2"
    page = b'<html><head><link rel="alternate" type="application/rss+xml" title="RSS" href="/feed.xml"></head></html>'
    assert scraper.feed_links(page, "https://v.example/x")[0]["url"] == "https://v.example/feed.xml"


def test_scraped_feed_end_to_end(authed):
    with mock.patch("app.api.content._refresh_async"):
        f = authed.post("/api/v1/feeds", json={"url": "https://vendor.example/blog", "scrape": RULES}).json()
    assert f["kind"] == "html"
    authed.put(f"/api/v1/feeds/{f['id']}/retention", json={"retention_days": 0})
    with mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE)):
        r = authed.post(f"/api/v1/feeds/{f['id']}/refresh").json()
    assert r["ok"] and r["new"] == 3
    arts = authed.get("/api/v1/articles", params={"feed_id": f["id"]}).json()["items"]
    full = authed.get(f"/api/v1/articles/{arts[0]['id']}").json()
    assert "<script" not in full["content_html"] and "onerror" not in full["content_html"]
    details = authed.get(f"/api/v1/feeds/{f['id']}/details").json()
    assert details["scrape"]["items"] == "div.post-card"
    # layout change -> nothing matches -> visible error instead of silent emptiness
    with mock.patch("app.fetcher.netguard.request", return_value=resp(b"<html><body>redesigned</body></html>")):
        r = authed.post(f"/api/v1/feeds/{f['id']}/refresh").json()
    assert not r["ok"] and "matched no items" in r["error"]
    # rules can be edited, and a feed can go back to RSS
    upd = authed.patch(f"/api/v1/feeds/{f['id']}", json={"scrape": {**RULES, "items": "article"}}).json()
    assert upd["kind"] == "html"
    assert authed.patch(f"/api/v1/feeds/{f['id']}", json={"clear_scrape": True}).json()["kind"] == "rss"
    assert authed.post("/api/v1/feeds", json={"url": "https://v2.example/", "scrape": {"items": "div[["}}).status_code == 422


def test_discover_and_preview_endpoints(authed):
    page = PAGE.replace(b"<title>", b'<link rel="alternate" type="application/rss+xml" href="/feed.xml"><title>')
    rss = b'<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor</title><item><title>a</title><link>https://vendor.example/a</link></item></channel></rss>'

    def fake(method, url, **kw):
        if url.endswith("/feed.xml"):
            return resp(rss, url, ctype="application/rss+xml")
        return resp(page, url)

    with mock.patch("app.api.scrape.netguard.request", side_effect=fake):
        d = authed.post("/api/v1/scrape/discover", json={"url": "https://vendor.example/blog"}).json()
        assert not d["is_feed"] and d["feeds"][0]["url"] == "https://vendor.example/feed.xml"
        assert d["suggestion"]["items"] == "div.post-card" and d["preview"]
        p = authed.post("/api/v1/scrape/preview", json={"url": "https://vendor.example/blog", "scrape": RULES}).json()
        assert p["count"] == 3 and p["items"][0]["summary"].startswith("Summary one")
        d2 = authed.post("/api/v1/scrape/discover", json={"url": "https://vendor.example/feed.xml"}).json()
        assert d2["is_feed"]


def test_scrape_endpoints_ssrf_and_scopes(authed):
    assert authed.post("/api/v1/scrape/discover", json={"url": "http://127.0.0.1:8080/"}).status_code == 422
    assert authed.post("/api/v1/scrape/discover", json={"url": "file:///etc/passwd"}).status_code == 422
    r = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    assert authed.post("/api/v1/scrape/preview", headers=r, json={"url": "https://x.example", "scrape": RULES}).status_code == 403
