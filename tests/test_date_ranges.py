"""Custom date ranges on every list, collection folders as one list, the By-topic shelves on a small /tmp, and the
SQLite temp folder in the data volume."""

import json

from app.db import get_db, now

DAY = 86400
T0 = 1_700_000_000  # 2023-11-14


def _video(db, n, ts, cid="UCaaaaaaaaaaaaaaaaaaaaaa", title=None):
    fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                     (f"yt{n}", f"https://y.example/{n}", now(), json.dumps({"kind": "youtube", "channel_id": cid}))).lastrowid
    aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, published) VALUES (?, ?, ?, ?, ?, ?)",
                     (fid, f"v{n}", title or f"clip {n}", now(), ts, ts)).lastrowid
    db.execute("INSERT INTO videos (article_id, video_id, channel_id, channel_title) VALUES (?, ?, ?, 'Chan')", (aid, f"vid{n:08d}", cid))
    return aid


def test_videos_shelves_and_counts_follow_the_date_range(authed):
    with get_db() as db:
        topic = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('Rangey', '[]', '#112233')").lastrowid
        ids = [_video(db, n, T0 + n * DAY) for n in range(5)]
        for aid in ids:
            db.execute("INSERT INTO article_topics (article_id, topic_id, source) VALUES (?, ?, 'manual')", (aid, topic))
    since, until = T0 + DAY, T0 + 3 * DAY  # days 1 and 2 only
    got = authed.get(f"/api/v1/library/videos?state=all&since={since}&until={until}").json()
    assert {v["id"] for v in got["items"]} == set(ids[1:3]) and got["total"] == 2
    assert authed.get(f"/api/v1/library/videos?state=all&since={T0 + 4 * DAY}").json()["total"] == 1
    assert authed.get(f"/api/v1/library/videos?state=all&until={T0 + DAY}").json()["total"] == 1
    shelves = authed.get(f"/api/v1/library/shelves?per=12&state=all&sort=newest&since={since}&until={until}").json()
    shelf = next(s for s in shelves["shelves"] if s["id"] == topic)
    assert shelf["total"] == 2 and [v["id"] for v in shelf["items"]] == [ids[2], ids[1]]  # ranked newest first
    assert all("title" in v and "topics" in v for v in shelf["items"])                    # full rows come back
    counts = authed.get(f"/api/v1/library/topic-counts?state=all&since={since}&until={until}").json()["counts"]
    assert counts[str(topic)] == 2
    # an end before the start is refused; bad values are refused
    assert authed.get(f"/api/v1/library/videos?since={until}&until={since}").status_code == 422
    assert authed.get("/api/v1/library/videos?since=-5").status_code == 422
    assert authed.get("/api/v1/library/videos?since=abc").status_code == 422


def test_shelves_rank_per_topic_and_limit(authed):
    with get_db() as db:
        a = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('ShelfA', '[]', '#000001')").lastrowid
        b = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('ShelfB', '[]', '#000002')").lastrowid
        ids = [_video(db, 100 + n, T0 + n * 60) for n in range(6)]
        for aid in ids:
            db.execute("INSERT INTO article_topics (article_id, topic_id, source) VALUES (?, ?, 'manual')", (aid, a))
        db.execute("INSERT INTO article_topics (article_id, topic_id, source) VALUES (?, ?, 'manual')", (ids[0], b))
    res = authed.get("/api/v1/library/shelves?per=3&state=all&sort=oldest").json()
    by = {s["id"]: s for s in res["shelves"]}
    assert by[a]["total"] == 6 and [v["id"] for v in by[a]["items"]] == ids[:3]
    assert by[b]["total"] == 1 and [v["id"] for v in by[b]["items"]] == [ids[0]]
    assert sorted(by[a]["items"][0]["topics"]) == sorted([a, b])  # a video on two shelves carries both topics


def test_podcast_and_account_lists_follow_the_date_range(authed):
    with get_db() as db:
        pod = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Show', 'https://p.example/rss', ?, 'podcast')",
                         (now(),)).lastrowid
        for n in range(3):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (pod, f"e{n}", f"Episode {n}", now(), T0 + n * DAY)).lastrowid
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, ?)", (aid, f"https://p.example/{n}.mp3"))
        acc = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES ('r/x', 'https://www.reddit.com/r/x/.rss', ?, 'reddit')",
                         (now(),)).lastrowid
        for n in range(3):
            db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                       (acc, f"p{n}", f"Post {n}", now(), T0 + n * DAY))
    ep = authed.get(f"/api/v1/podcasts/episodes?since={T0 + DAY}").json()
    assert ep["total"] == 2
    assert authed.get(f"/api/v1/podcasts/episodes?since={T0}&until={T0 + DAY}").json()["total"] == 1
    posts = authed.get(f"/api/v1/accounts/posts?until={T0 + 2 * DAY}").json()
    assert posts["total"] == 2
    assert authed.get(f"/api/v1/accounts/posts?since={T0 + 2 * DAY}&until={T0}").status_code == 422


def test_collection_folder_lists_every_collection(authed):
    """The "ATT&CK" heading over "ATT&CK: Stealth", "ATT&CK: Execution"… lists the articles of all of them."""
    with get_db() as db:
        feed = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('News', 'https://n.example/rss', ?)", (now(),)).lastrowid
        t1 = db.execute("INSERT INTO tags (name, color) VALUES ('Fold: One', '#111111')").lastrowid
        t2 = db.execute("INSERT INTO tags (name, color) VALUES ('Fold: Two', '#222222')").lastrowid
        t3 = db.execute("INSERT INTO tags (name, color) VALUES ('Elsewhere', '#333333')").lastrowid
        arts = []
        for n, tag in enumerate((t1, t2, t3, t1)):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (feed, f"a{n}", f"Story {n}", now(), T0 + n * DAY)).lastrowid
            db.execute("INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'manual', ?)", (aid, tag, now()))
            arts.append(aid)
        db.execute("INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'manual', ?)", (arts[0], t2, now()))
    got = authed.get(f"/api/v1/articles?tag_ids={t1},{t2}").json()
    assert got["total"] == 3 and {a["id"] for a in got["items"]} == {arts[0], arts[1], arts[3]}  # no duplicates
    dated = authed.get(f"/api/v1/articles?tag_ids={t1},{t2}&since={T0 + DAY}&until={T0 + 2 * DAY}").json()
    assert [a["id"] for a in dated["items"]] == [arts[1]]
    assert authed.get("/api/v1/articles?tag_ids=1,,2").status_code == 422
    assert authed.get("/api/v1/articles?tag_ids=" + ",".join(str(i) for i in range(1, 202))).status_code == 422
    assert authed.get("/api/v1/articles?tag_ids=1%20OR%201=1").status_code == 422
    csrf = authed.get("/api/v1/auth/me").json()["csrf_token"]
    r = authed.post("/api/v1/articles/mark-read", json={"tag_ids": [t1, t2]}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["updated"] == 3
    with get_db() as db:
        assert db.execute("SELECT is_read FROM articles WHERE id = ?", (arts[2],)).fetchone()[0] == 0  # other collection untouched
    assert authed.post("/api/v1/articles/mark-read", json={"tag_ids": [0]}, headers={"X-CSRF-Token": csrf}).status_code == 422


def test_sqlite_tmpdir_is_created_private(tmp_path, monkeypatch):
    from app import db as dbmod

    target = tmp_path / "data" / "tmp"
    monkeypatch.setenv("SQLITE_TMPDIR", str(target))
    dbmod._sqlite_tmpdir()
    assert target.is_dir()
    monkeypatch.delenv("SQLITE_TMPDIR")
    dbmod._sqlite_tmpdir()  # unset: nothing to do, never fails
