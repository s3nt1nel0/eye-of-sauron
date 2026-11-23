"""Older podcast episodes: the whole feed again, then the Internet Archive; one keep & fetch-back window; podcasts and
videos are not trimmed by the article-feed count cap."""

import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import httpx

from app import history, netguard
from app.db import get_db, now

SHOW = "https://pod.example/feed.xml"


def podcast(items):
    body = "".join(
        f"<item><title>{t}</title><guid>{g}</guid><pubDate>{d}</pubDate><itunes:duration>1800</itunes:duration>"
        f'<enclosure url="https://pod.example/{g}.mp3" type="audio/mpeg" length="1"/></item>' for t, g, d in items)
    return ('<?xml version="1.0"?><rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">'
            f"<channel><title>Show</title><link>https://pod.example/</link>{body}</channel></rss>").encode()


def day(days_ago):
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() - days_ago * 86400))


def stamp(days_ago):
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() - days_ago * 86400))


LIVE = podcast([("Ep 10", "e10", day(2)), ("Ep 9", "e9", day(9)), ("Ep 8", "e8", day(400))])


def wait(job):
    if job._thread is not None:
        job._thread.join(10)
    assert not job.running
    return job.status


def fake_net(snapshots, calls):
    def fake(method, url, **kw):
        calls.append((url, kw.get("max_bytes")))
        if url.startswith(history.WAYBACK_CDX):
            assert parse_qs(urlsplit(url).query)["url"] == [SHOW]
            rows = [["timestamp", "statuscode"]] + [[k, "200"] for k in sorted(snapshots)]
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/json"}), json.dumps(rows).encode(), url)
        if url.startswith("https://web.archive.org/web/"):
            s = url.split("/web/", 1)[1].split("id_/", 1)[0]
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "text/html"}), snapshots[s], url)
        if url == SHOW:
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/rss+xml"}), LIVE, url)
        return netguard.SafeResponse(404, httpx.Headers({}), b"", url)  # no ?paged= / ?page= pages
    return fake


def make_show(retention_days):
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, kind, created_at, retention_days) VALUES ('Show', ?, 'podcast', ?, ?)",
                         (SHOW, now(), retention_days)).lastrowid
        # what an earlier time frame removed: the clean-up's tombstone would block it - asking for history lifts it
        # (relative IDs resolve against the show's feed address, live and in archived copies alike)
        db.execute("INSERT INTO article_tombstones (feed_id, guid, removed_at, manual) VALUES (?, 'https://pod.example/e8', ?, 0)", (fid, now()))
        db.execute("INSERT INTO article_tombstones (feed_id, guid, removed_at, manual) VALUES (?, 'https://pod.example/mine', ?, 1)", (fid, now()))
    return fid


def episodes(authed, fid):
    return {e["title"]: e for e in authed.get(f"/api/v1/podcasts/episodes?feed_ids={fid}&limit=100").json()["items"]}


def test_podcast_history_rereads_the_feed_then_the_archive(authed):
    fid = make_show(30)
    snaps = {stamp(500): podcast([("Ep 2", "e2", day(700)), ("Ep 1", "e1", day(900)), ("My deleted one", "mine", day(950))])}
    calls = []
    with mock.patch("app.history.netguard.request", side_effect=fake_net(snaps, calls)), mock.patch("app.history.time.sleep"):
        # one setting: keep everything, and fetch back that far
        r = authed.post(f"/api/v1/feeds/{fid}/backfill", json={"keep_days": 0})
        assert r.status_code == 200, r.text
        st = wait(history.backfill_job)
    assert st["state"] == "done", st
    got = episodes(authed, fid)
    assert {"Ep 10", "Ep 9", "Ep 8", "Ep 2", "Ep 1"} <= set(got) and "My deleted one" not in got  # yours stay deleted
    assert got["Ep 1"]["audio_url"] == "https://pod.example/e1.mp3"   # playable: the audio came along
    with get_db() as db:
        f = db.execute("SELECT retention_days, max_articles FROM feeds WHERE id = ?", (fid,)).fetchone()
    assert f["retention_days"] == 0 and f["max_articles"] == 0          # the window became the feed's Keep setting
    # podcast-sized documents are allowed (a show's feed can be tens of MB)
    show_calls = [b for u, b in calls if u == SHOW]
    assert show_calls and all(b and b >= 60 * 1024 * 1024 for b in show_calls)
    assert st.get("method") in ("wayback", "feed")
    # an episode in the live feed and in an archived copy is stored once
    assert sum(1 for t in got if t == "Ep 9") == 1
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM articles WHERE feed_id = ? AND url LIKE '%web.archive.org%'", (fid,)).fetchone()[0] == 0


def test_podcast_history_stays_inside_the_keep_window(authed):
    fid = make_show(None)
    snaps = {stamp(500): podcast([("Ep 2", "e2", day(700))])}
    with mock.patch("app.history.netguard.request", side_effect=fake_net(snaps, [])), mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{fid}/backfill", json={"keep_days": 365})
        wait(history.backfill_job)
    got = episodes(authed, fid)
    assert {"Ep 10", "Ep 9"} <= set(got) and not {"Ep 8", "Ep 2"} & set(got)  # 400 and 700 days old: outside 1 year
    with get_db() as db:
        assert db.execute("SELECT retention_days FROM feeds WHERE id = ?", (fid,)).fetchone()[0] == 365


def test_keep_days_validation(authed):
    fid = make_show(30)
    assert authed.post(f"/api/v1/feeds/{fid}/backfill", json={"keep_days": -1}).status_code == 422
    assert authed.post(f"/api/v1/feeds/{fid}/backfill", json={"keep_days": 99999}).status_code == 422
    assert authed.post(f"/api/v1/feeds/{fid}/backfill", json={"keep_days": "all"}).status_code == 422


def test_count_cap_is_for_article_feeds_only(authed):
    from app import app_settings
    from app.fetcher import run_retention

    with get_db() as db:
        app_settings.update(db, {"max_articles_per_feed": 50, "retention_days": 0})
        pod = db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('P', 'https://p.example/r', 'podcast', ?)", (now(),)).lastrowid
        art = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('A', 'https://a.example/r', ?)", (now(),)).lastrowid
        for fid in (pod, art):
            for n in range(60):
                db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                           (fid, f"g{n}", f"t{n}", now(), now() - n * 60))
    run_retention()
    with get_db() as db:
        count = lambda fid: db.execute("SELECT COUNT(*) FROM articles WHERE feed_id = ?", (fid,)).fetchone()[0]  # noqa: E731
        assert count(art) == 50 and count(pod) == 60
