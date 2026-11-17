"""Feed editor details, per-feed retention and history back-fill (site paging, Internet Archive, bulk)."""

import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app import history, netguard


def rss(items):
    body = "".join(f"<item><title>{t}</title><link>https://blog.example/{g}</link><guid>{g}</guid>"
                   f"<pubDate>{d}</pubDate><description>Body {t}</description></item>" for t, g, d in items)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>Blog</title><link>https://blog.example/</link>{body}</channel></rss>'.encode()


NOW = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
OLD = "Mon, 06 Jan 2025 10:00:00 GMT"
PAGE1 = rss([("New post", "p10", NOW)])
PAGE2 = rss([("Older A", "p9", OLD), ("Older B", "p8", OLD)])
PAGE3 = rss([("Oldest", "p1", OLD)])


def resp(body, status=200, url="https://blog.example/feed/"):
    return netguard.SafeResponse(status, httpx.Headers({"content-type": "application/rss+xml"}), body, url)


def wait(job):
    # time.sleep may be mocked in these tests (it is the shared time module), so join the thread.
    if job._thread is not None:
        job._thread.join(10)
    assert not job.running, "job did not finish"
    return job.status


@pytest.fixture()
def feed(authed):
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE1)):
        f = authed.post("/api/v1/feeds", json={"url": "https://blog.example/feed/"}).json()
        authed.post(f"/api/v1/feeds/{f['id']}/refresh")
    return f["id"]


def test_feed_details(authed, feed):
    rule = authed.post("/api/v1/rules", json={"name": "Everything", "keywords": ["post"], "star": True}).json()
    d = authed.get(f"/api/v1/feeds/{feed}/details").json()
    assert d["stats"]["total"] == 1 and d["effective"]["retention_days"] == 90 and d["effective"]["refresh_minutes"] == 60
    assert [r["id"] for r in d["rules"]] == [rule["id"]] and d["rules"][0]["scope"] == "all feeds"
    assert authed.get("/api/v1/feeds/9999/details").status_code == 404


def test_old_items_skipped_by_retention_unless_kept_forever(authed, feed):
    # Global retention (90 d) drops 2025 items while fetching...
    with mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE2)):
        assert authed.post(f"/api/v1/feeds/{feed}/refresh").json()["new"] == 0
    # ...a per-feed "keep forever" keeps them, and the retention pass leaves them alone.
    assert authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": 0, "max_articles": 0}).status_code == 200
    with mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE2)):
        assert authed.post(f"/api/v1/feeds/{feed}/refresh").json()["new"] == 2
    from app.fetcher import run_retention

    run_retention()
    assert authed.get(f"/api/v1/feeds/{feed}/details").json()["stats"]["total"] == 3
    # back to the global setting: the old ones are pruned
    authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": None, "max_articles": None})
    run_retention()
    assert authed.get(f"/api/v1/feeds/{feed}/details").json()["stats"]["total"] == 1
    assert authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": -1}).status_code == 422


def test_per_feed_max_articles(authed, feed):
    authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": 0, "max_articles": 1})
    with mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE2)):
        authed.post(f"/api/v1/feeds/{feed}/refresh")
    from app.fetcher import run_retention

    run_retention()
    assert authed.get(f"/api/v1/feeds/{feed}/details").json()["stats"]["total"] == 1


def test_backfill_wordpress_paged(authed, feed):
    authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": 0, "max_articles": None})
    seen = []

    def fake(method, url, **kw):
        seen.append(url)
        page = parse_qs(urlsplit(url).query).get("paged", ["1"])[0]
        return {"1": resp(PAGE1), "2": resp(PAGE2), "3": resp(PAGE3)}.get(page, resp(b"", 404))

    with mock.patch("app.history.netguard.request", side_effect=fake), mock.patch("app.history.time.sleep"):
        assert authed.post(f"/api/v1/feeds/{feed}/backfill", json={"max_pages": 10}).json()["started"]
        st = wait(history.backfill_job)
    assert st["state"] == "done" and st["method"] == "paged" and st["new"] == 3
    assert any("paged=3" in u for u in seen)
    assert authed.get(f"/api/v1/feeds/{feed}/details").json()["stats"]["total"] == 4


def test_backfill_unsupported_feed(authed, feed):
    # Every pager gets page 1 back (the parameter is ignored) -> "site pages only" reports no older pages.
    with mock.patch("app.history.netguard.request", side_effect=lambda m, u, **k: resp(PAGE1)), \
            mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{feed}/backfill", json={"method": "paged"})
        st = wait(history.backfill_job)
    assert st["state"] == "error" and "older pages" in st["error"] and "Internet Archive" in st["error"]


def test_backfill_rfc5005(authed, feed):
    authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": 0})
    first = PAGE1.replace(b"<title>Blog</title>", b'<title>Blog</title><atom:link xmlns:atom="http://www.w3.org/2005/Atom" rel="prev-archive" href="https://blog.example/archive/1.xml"/>')

    def fake(method, url, **kw):
        return resp(PAGE2 if "archive" in url else first, url=url)

    with mock.patch("app.history.netguard.request", side_effect=fake), mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{feed}/backfill", json={"max_pages": 5})
        st = wait(history.backfill_job)
    assert st["method"] == "rfc5005" and st["new"] == 2


# ---------------------------------------------------------------- other paging styles
def test_backfill_blogger_paging(authed):
    from app.db import get_db

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, retention_days) VALUES "
                         "('b', 'https://x.blogspot.com/feeds/posts/default?alt=rss', 0, 0)").lastrowid
    seen = []

    def fake(method, url, **kw):
        seen.append(url)
        start = parse_qs(urlsplit(url).query).get("start-index", ["1"])[0]
        return {"1": resp(PAGE1), "101": resp(PAGE2), "201": resp(PAGE3)}.get(start, resp(rss([])))

    with mock.patch("app.history.netguard.request", side_effect=fake), mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{fid}/backfill", json={"method": "paged"})
        st = wait(history.backfill_job)
    assert st["state"] == "done" and st["method"] == "blogger" and st["new"] == 4, st
    assert any("max-results=100" in u and "alt=rss" in u for u in seen)


def test_backfill_ghost_paging(authed):
    from app.db import get_db

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, retention_days) VALUES "
                         "('g', 'https://ghost.example/rss/', 0, 0)").lastrowid
    pages = {"https://ghost.example/rss/": PAGE1, "https://ghost.example/rss/2/": PAGE2}
    with mock.patch("app.history.netguard.request", side_effect=lambda m, u, **k: resp(pages[u]) if u in pages else resp(b"", 404)), \
            mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{fid}/backfill", json={"method": "paged"})
        st = wait(history.backfill_job)
    assert st["method"] == "ghost" and st["new"] == 3, st


# ---------------------------------------------------------------- Internet Archive
def _wayback_fake(snapshots, calls):
    """snapshots: {YYYYMMDDhhmmss: feed bytes}. Serves the CDX listing and raw (id_) captures."""
    def fake(method, url, **kw):
        calls.append(url)
        if url.startswith(history.WAYBACK_CDX):
            q = parse_qs(urlsplit(url).query)
            assert q["url"] == ["https://blog.example/feed/"] and q["collapse"] == ["timestamp:8"]
            rows = [["timestamp", "statuscode"]] + [[k, "200"] for k in sorted(snapshots)] + [["bogus", "200"]]
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/json"}), json.dumps(rows).encode(), url)
        if url.startswith("https://web.archive.org/web/"):
            stamp = url.split("/web/", 1)[1].split("id_/", 1)[0]
            assert url.endswith("id_/https://blog.example/feed/")
            # archived copies come back labelled text/html
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "text/html; charset=utf-8"}), snapshots[stamp], url)
        return resp(PAGE1)  # the live feed: no archive links, and paging is ignored
    return fake


def test_backfill_from_internet_archive_walks_back_through_copies(authed, feed):
    snaps = {
        "20250301120000": rss([("Mar B", "m2", "Sat, 01 Mar 2025 10:00:00 GMT"), ("Feb A", "f1", "Mon, 10 Feb 2025 10:00:00 GMT")]),
        # redundant: taken after the oldest item the March copy listed... but a closer copy (Feb 11) exists
        "20250220000000": rss([("Should not be needed", "x1", "Wed, 19 Feb 2025 09:00:00 GMT")]),
        "20250211000000": rss([("Feb A", "f1", "Mon, 10 Feb 2025 10:00:00 GMT"), ("Jan Z", "j9", "Mon, 06 Jan 2025 10:00:00 GMT")]),
        "20250120000000": rss([("Also not needed", "x2", "Wed, 15 Jan 2025 09:00:00 GMT")]),
        "20250107000000": rss([("Jan Z", "j9", "Mon, 06 Jan 2025 10:00:00 GMT"), ("Dec", "d1", "Mon, 30 Dec 2024 10:00:00 GMT")]),
        "20250101000000": rss([("Dec", "d1", "Mon, 30 Dec 2024 10:00:00 GMT"), ("Nov", "n1", "Fri, 15 Nov 2024 10:00:00 GMT")]),
    }
    calls = []
    with mock.patch("app.history.netguard.request", side_effect=_wayback_fake(snaps, calls)), mock.patch("app.history.time.sleep"):
        r = authed.post(f"/api/v1/feeds/{feed}/backfill", json={"keep_forever": True})
        assert r.status_code == 200
        st = wait(history.backfill_job)
    assert st["state"] == "done" and st["method"] == "wayback", st
    assert st["new"] == 5 and st["pages"] == 4, st
    titles = {a["title"] for a in authed.get("/api/v1/articles", params={"feed_id": feed, "limit": 50}).json()["items"]}
    assert {"Mar B", "Feb A", "Jan Z", "Dec", "Nov"} <= titles and not titles & {"Should not be needed", "Also not needed"}
    d = authed.get(f"/api/v1/feeds/{feed}/details").json()
    assert d["retention_days"] == 0 and d["max_articles"] == 0  # keep_forever applied
    archive = [c for c in calls if "/web/" in c]
    # each copy overlaps the previous one; copies that would only repeat known items are skipped
    assert archive == [f"https://web.archive.org/web/{s}id_/https://blog.example/feed/"
                       for s in ("20250301120000", "20250211000000", "20250107000000", "20250101000000")]


def test_wayback_respects_how_far_back_and_reports_no_copies(authed, feed):
    from app.db import get_db

    recent = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() - 20 * 86400))
    old_day = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() - 25 * 86400))
    older = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() - 200 * 86400))
    snaps = {recent: rss([("Recent", "r1", old_day), ("Too old", "t1", older)])}
    with get_db() as db:  # pretend our history starts after that copy
        db.execute("UPDATE articles SET sort_ts = ?, published = ? WHERE feed_id = ?", (time.time() - 5 * 86400,) * 2 + (feed,))
    with mock.patch("app.history.netguard.request", side_effect=_wayback_fake(snaps, [])), mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{feed}/backfill", json={"method": "wayback", "since_days": 90, "keep_forever": True})
        st = wait(history.backfill_job)
    assert st["state"] == "done" and st["new"] == 1, st  # the 200-day-old item is outside "last 90 days"

    with mock.patch("app.history.netguard.request", side_effect=_wayback_fake({}, [])), mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{feed}/backfill", json={"method": "wayback"})
        st = wait(history.backfill_job)
    assert st["state"] == "error" and "no saved copies" in st["error"]


def test_backfill_validation_and_scraped_feeds(authed, feed):
    assert authed.post(f"/api/v1/feeds/{feed}/backfill", json={"method": "everything"}).status_code == 422
    assert authed.post(f"/api/v1/feeds/{feed}/backfill", json={"since_days": 0}).status_code == 422
    assert authed.post(f"/api/v1/feeds/{feed}/backfill", json={"max_pages": 10_000}).status_code == 422
    assert authed.post(f"/api/v1/feeds/{feed}/backfill", json={"surprise": 1}).status_code == 422
    from app.db import get_db

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('s', 'https://site.example/news', 'html', 0)").lastrowid
    authed.post(f"/api/v1/feeds/{fid}/backfill", json={})
    st = wait(history.backfill_job)
    assert st["state"] == "error" and "Scraped" in st["error"]


# ---------------------------------------------------------------- all feeds at once
def test_backfill_all_feeds(authed, feed):
    from app.db import get_db

    with get_db() as db:
        folder = db.execute("INSERT INTO folders (name) VALUES ('Intel')").lastrowid
        other = db.execute("INSERT INTO feeds (title, url, folder_id, created_at) VALUES ('o', 'https://other.example/feed/', ?, 0)",
                           (folder,)).lastrowid
        db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('x', 'https://x.example/', 'x', 0)")  # X: skipped
        db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('h', 'https://h.example/', 'html', 0)")  # scraped: skipped

    def fake(method, url, **kw):
        if url.startswith("https://blog.example/"):
            page = parse_qs(urlsplit(url).query).get("paged", ["1"])[0]
            return {"1": resp(PAGE1), "2": resp(PAGE2)}.get(page, resp(b"", 404))
        return resp(b"", 404)  # other.example has nothing: an error for that feed, the run goes on

    assert authed.post("/api/v1/history/backfill-all", json={"folder_id": 999999}).status_code == 404
    with mock.patch("app.history.netguard.request", side_effect=fake), mock.patch("app.history.time.sleep"):
        r = authed.post("/api/v1/history/backfill-all", json={"method": "paged", "only_missing": False})
        assert r.json() == {"started": True, "feeds": 2}
        st = wait(history.backfill_job)
    assert st["state"] == "done" and st["bulk"] and st["done"] == 2 and st["failed"] == 1, st
    assert st["new_total"] == 2
    by_id = {x["feed_id"]: x for x in st["results"]}
    assert by_id[feed]["new"] == 2 and by_id[feed]["method"] == "paged" and "error" in by_id[other]
    assert authed.get(f"/api/v1/feeds/{feed}/details").json()["retention_days"] == 0  # keep_forever defaults on

    # A folder limits the run to that folder's feeds.
    assert history.bulk_feed_ids(folder, False, None) == [other]
    # only_missing skips feeds whose continuous history already reaches the chosen date.
    with get_db() as db:
        db.execute("UPDATE articles SET sort_ts = ? WHERE feed_id = ?", (time.time() - 30 * 86400, feed))
    assert feed not in history.bulk_feed_ids(None, True, 20) and feed in history.bulk_feed_ids(None, True, 365)


def test_backfill_all_needs_admin_and_freshrss_import_is_gone(authed, feed):
    w = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "w", "scope": "write"}).json()["token"]}
    assert authed.post("/api/v1/history/backfill-all", json={}, headers=w).status_code == 403
    body = {"base_url": "http://localhost:8080", "username": "alice", "api_password": "x"}
    assert authed.post("/api/v1/import/freshrss", json=body).status_code in (404, 405)
    assert "freshrss" not in authed.get("/api/v1/history/status").json()
    assert authed.post("/api/v1/history/cancel", json={}).json() == {"ok": True}


def test_read_and_unread_filters(authed, feed):
    with mock.patch("app.fetcher.netguard.request", return_value=resp(PAGE2)):
        authed.put(f"/api/v1/feeds/{feed}/retention", json={"retention_days": 0})
        authed.post(f"/api/v1/feeds/{feed}/refresh")
    items = authed.get("/api/v1/articles").json()["items"]
    authed.patch(f"/api/v1/articles/{items[0]['id']}", json={"is_read": True})
    read = authed.get("/api/v1/articles", params={"read": True}).json()
    unread = authed.get("/api/v1/articles", params={"unread": True}).json()
    assert read["total"] == 1 and all(a["is_read"] for a in read["items"])
    assert unread["total"] == len(items) - 1 and not any(a["is_read"] for a in unread["items"])
    assert authed.get("/api/v1/articles", params={"read": True, "unread": True}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"default_view": "read"}).status_code == 200


def test_retention_change_forces_full_refetch(authed):
    """Switching to a longer retention must clear ETag/Last-Modified so skipped older items are fetched."""
    from app.db import get_db

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, etag, last_modified, next_fetch) "
                         "VALUES ('x', 'https://x.example/feed', 0, '\"abc\"', 'Mon, 01 Jan 2026 00:00:00 GMT', 9999999999)").lastrowid
    assert authed.put(f"/api/v1/feeds/{fid}/retention", json={"retention_days": 0}).status_code == 200
    with get_db() as db:
        row = db.execute("SELECT etag, last_modified, next_fetch FROM feeds WHERE id = ?", (fid,)).fetchone()
    assert tuple(row) == (None, None, None)
