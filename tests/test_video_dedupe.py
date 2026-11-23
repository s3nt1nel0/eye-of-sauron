"""One stored copy per YouTube video: overlapping playlists / channels add only the missing videos and link the
rest, old duplicates merge into one copy (keeping groups, watched, starred), and video ids are normalised."""

import json
import time

from test_sources import CH, YT_RSS, add_source, patch_net, resp

KEY = "test-youtube-key-abcdefghijklmnopqrstu"
PL = "PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz"


def _set_key(authed):
    _fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        assert authed.put("/api/v1/integrations/youtube", json={"api_key": KEY}).status_code == 200


def _playlist_items(videos):
    """playlistItems answer: [(video id, title, position)] in the playlist's own order."""
    return resp({"items": [{"snippet": {"title": t, "publishedAt": "2024-01-01T00:00:00Z", "channelTitle": "John Hammond",
                                        "videoOwnerChannelId": CH, "videoOwnerChannelTitle": "John Hammond", "position": pos},
                            "contentDetails": {"videoId": vid, "videoPublishedAt": f"2024-01-0{pos + 1}T00:00:00Z"}}
                           for vid, t, pos in videos]})


def _backfill(authed, feed_id, videos):
    from app import history

    _fake, p = patch_net({"playlistItems": _playlist_items(videos), "/videos?": resp({"items": []})})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed_id}/backfill", json={"max_pages": 10, "keep_forever": True})
        assert r.status_code == 200, r.text
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status


def _refresh_channel(authed, feed_id):
    _fake, p = patch_net({"feeds/videos.xml": resp(YT_RSS, ctype="application/atom+xml"), "/videos?": resp({"items": []})})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed_id}/refresh").json()
    assert r["ok"], r
    return r


def _copies():
    from app.db import get_db

    with get_db() as db:
        return db.execute("SELECT COUNT(*), COUNT(DISTINCT video_id) FROM videos").fetchone()[:]


def test_playlist_added_after_its_channel_adds_only_the_missing_videos(authed):
    _set_key(authed)
    channel = add_source(authed, {"kind": "youtube", "channel_id": CH})
    assert _refresh_channel(authed, channel["id"])["new"] == 2                     # AAAAAAAAAA1, BBBBBBBBBB2
    playlist = add_source(authed, {"kind": "youtube", "playlist_id": PL})
    # the playlist holds one video the channel feed already brought (B2) and one new one (C3), C3 first
    _backfill(authed, playlist["id"], [("CCCCCCCCCC3", "Part 1", 0), ("BBBBBBBBBB2", "Part 2", 1)])
    assert _copies() == (3, 3)                                                       # no second copy of B2
    assert authed.get("/api/v1/library/videos").json()["total"] == 3
    group = authed.get(f"/api/v1/library/groups/p:{playlist['id']}").json()
    assert [v["video_id"] for v in group["items"]] == ["CCCCCCCCCC3", "BBBBBBBBBB2"]  # the playlist's own order
    own = authed.get(f"/api/v1/library/videos?feed_id={channel['id']}").json()
    assert {v["video_id"] for v in own["items"]} == {"AAAAAAAAAA1", "BBBBBBBBBB2"}
    b2 = next(v for v in own["items"] if v["video_id"] == "BBBBBBBBBB2")
    assert {"id": f"p:{playlist['id']}", "name": playlist["title"]} in b2["groups"] or any(
        g["id"] == f"p:{playlist['id']}" for g in b2["groups"])
    meta = authed.get("/api/v1/library/meta").json()
    chan = next(c for c in meta["channels"] if c["key"] == CH)
    assert chan["videos"] == 3                                                       # each video counted once
    assert next(f for f in chan["feeds"] if f["id"] == playlist["id"])["videos"] == 2
    assert next(f for f in chan["feeds"] if f["id"] == playlist["id"])["playlist_id"] == PL
    # adding / refreshing again changes nothing
    _backfill(authed, playlist["id"], [("CCCCCCCCCC3", "Part 1", 0), ("BBBBBBBBBB2", "Part 2", 1)])
    assert _refresh_channel(authed, channel["id"])["new"] == 0
    assert _copies() == (3, 3)


def test_channel_added_after_its_playlist_links_instead_of_copying(authed):
    _set_key(authed)
    playlist = add_source(authed, {"kind": "youtube", "playlist_id": PL})
    _backfill(authed, playlist["id"], [("BBBBBBBBBB2", "Part 1", 0), ("AAAAAAAAAA1", "Part 2", 1)])
    channel = add_source(authed, {"kind": "youtube", "channel_id": CH})
    assert _refresh_channel(authed, channel["id"])["new"] == 0                     # both already stored
    assert _copies() == (2, 2)
    assert authed.get(f"/api/v1/library/videos?feed_id={channel['id']}").json()["total"] == 2
    # unfollowing the playlist keeps the videos the channel also lists (they move to the channel)
    assert authed.delete(f"/api/v1/library/groups/p:{playlist['id']}").json() == {"ok": True, "videos_removed": 0}
    left = authed.get(f"/api/v1/library/videos?feed_id={channel['id']}").json()
    assert left["total"] == 2 and all(v["feed_id"] == channel["id"] for v in left["items"])


def test_removed_video_is_not_brought_back_by_another_feed(authed):
    _set_key(authed)
    playlist = add_source(authed, {"kind": "youtube", "playlist_id": PL})
    _backfill(authed, playlist["id"], [("BBBBBBBBBB2", "Part 1", 0)])
    channel = add_source(authed, {"kind": "youtube", "channel_id": CH})
    _refresh_channel(authed, channel["id"])                                           # links B2, adds A1
    b2 = next(v for v in authed.get("/api/v1/library/videos").json()["items"] if v["video_id"] == "BBBBBBBBBB2")
    assert authed.delete(f"/api/v1/library/videos/{b2['id']}").json() == {"ok": True}
    assert _refresh_channel(authed, channel["id"])["new"] == 0                       # remembered for the channel too
    assert _copies() == (1, 1)


def test_adding_a_single_video_twice_and_in_any_spelling_is_one_copy(authed):
    entry_meta = ({"id": "yt:video:dQw4w9WgXcQ", "title": "Clip", "link": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
                  {"video_id": "dQw4w9WgXcQ", "channel_id": None, "channel_title": "C", "thumbnail": None})
    from unittest import mock

    with mock.patch("app.sources.single_video", return_value=entry_meta):
        first = authed.post("/api/v1/library/videos", json={"url": "https://youtu.be/dQw4w9WgXcQ?si=abc&t=42"}).json()
        assert first["already"] is False
        for url in ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx&t=10s", "youtube.com/shorts/dQw4w9WgXcQ",
                    "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ?start=3", "https://m.youtube.com/watch?v=dQw4w9WgXcQ#t=1"):
            again = authed.post("/api/v1/library/videos", json={"url": url}).json()
            assert again == {"article_id": first["article_id"], "title": "Clip", "already": True}, url
    assert _copies() == (1, 1)


def test_normalize_video_id():
    from app.sources import normalize_video_id

    for text in ("dQw4w9WgXcQ", "yt:video:dQw4w9WgXcQ", "https://youtu.be/dQw4w9WgXcQ", "https://youtu.be/dQw4w9WgXcQ?t=5",
                 "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1m&list=PLabc", "https://www.youtube.com/shorts/dQw4w9WgXcQ",
                 "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ", "https://www.youtube.com/live/dQw4w9WgXcQ?feature=share",
                 "music.youtube.com/watch?v=dQw4w9WgXcQ", " https://www.youtube.com/embed/dQw4w9WgXcQ "):
        assert normalize_video_id(text) == "dQw4w9WgXcQ", text
    for bad in ("", "dQw4w9WgXc", "https://evil.example/watch?v=dQw4w9WgXcQ", "https://www.youtube.com/@chan",
                "yt:video:short", "https://youtu.be/../../x"):
        assert normalize_video_id(bad) is None, bad


def test_old_duplicates_merge_into_one_copy_keeping_state(authed):
    from app import video_links
    from app.db import get_db

    now = int(time.time())
    with get_db() as db:
        db.execute(f"DROP INDEX {video_links.UNIQUE_INDEX}")  # a database from before the fix
        ch = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Chan', 'https://y/c', ?, 'youtube', ?)",
                        (now, json.dumps({"kind": "youtube", "channel_id": CH}))).lastrowid
        pl = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Course', 'https://y/p', ?, 'youtube', ?)",
                        (now, json.dumps({"kind": "youtube", "playlist_id": PL}))).lastrowid
        keep = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, is_read) VALUES (?, 'yt:video:AAAAAAAAAA1', 'A', ?, ?, 1)",
                          (pl, now, now)).lastrowid
        dup = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, is_starred, starred_at) "
                         "VALUES (?, 'yt:video:AAAAAAAAAA1', 'A', ?, ?, 1, ?)", (ch, now + 5, now, now + 5)).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, 'AAAAAAAAAA1')", (keep,))
        db.execute("INSERT INTO videos (article_id, video_id, duration_s, views) VALUES (?, 'AAAAAAAAAA1', 300, 99)", (dup,))
        gid = db.execute("INSERT INTO video_groups (name, created_at) VALUES ('Later', ?)", (now,)).lastrowid
        db.execute("INSERT INTO video_group_items (group_id, article_id, added_at) VALUES (?, ?, ?)", (gid, dup, now))
        assert video_links.duplicate_sets(db) == [[keep, dup]]
        assert video_links.ensure_unique(db) == {"sets": 1, "removed": 1}
        assert video_links.ensure_unique(db) is None                                  # once only
        row = db.execute("SELECT is_read, is_starred, starred_at FROM articles WHERE id = ?", (keep,)).fetchone()
        assert tuple(row) == (1, 1, now + 5)                                          # watched AND starred kept
        assert db.execute("SELECT duration_s, views FROM videos WHERE article_id = ?", (keep,)).fetchone()[:] == (300, 99)
        assert db.execute("SELECT article_id FROM video_group_items WHERE group_id = ?", (gid,)).fetchone()[0] == keep
        assert db.execute("SELECT feed_id FROM video_links WHERE article_id = ?", (keep,)).fetchone()[0] == ch
        assert db.execute("SELECT COUNT(*) FROM articles WHERE id = ?", (dup,)).fetchone()[0] == 0
        # the index now refuses a second copy outright
        other = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 'x', 'x', ?, ?)",
                           (ch, now, now)).lastrowid
        try:
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, 'AAAAAAAAAA1')", (other,))
            raise AssertionError("duplicate video id accepted")
        except Exception as exc:  # sqlite3.IntegrityError
            assert "UNIQUE" in str(exc)
    # the channel lists it too: shown under both, one copy
    assert authed.get(f"/api/v1/library/videos?feed_id={ch}").json()["total"] == 1
    assert authed.get(f"/api/v1/library/groups/p:{pl}").json()["total"] == 1


def test_store_video_folds_a_copy_made_by_a_path_without_the_check(authed):
    """Safety net: a path that inserts a video article without checking first (e.g. adopting a plain RSS feed)
    is folded into the copy that exists, instead of failing on the UNIQUE index."""
    from app import sources
    from app.db import get_db

    now = int(time.time())
    with get_db() as db:
        a = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('A', 'https://y/a', ?, 'youtube')", (now,)).lastrowid
        b = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('B', 'https://y/b', ?, 'youtube')", (now,)).lastrowid
        first = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 'g1', 'v', ?, ?)", (a, now, now)).lastrowid
        sources.store_video(db, first, {"video_id": "https://youtu.be/AAAAAAAAAA1"}, now)       # a URL: normalised
        second = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, is_read) VALUES (?, 'g2', 'v', ?, ?, 1)",
                            (b, now, now)).lastrowid
        sources.store_video(db, second, {"video_id": "AAAAAAAAAA1", "position": 4}, now)
        assert db.execute("SELECT COUNT(*) FROM videos").fetchone()[0] == 1
        assert db.execute("SELECT video_id FROM videos").fetchone()[0] == "AAAAAAAAAA1"
        assert db.execute("SELECT is_read FROM articles WHERE id = ?", (first,)).fetchone()[0] == 1
        assert db.execute("SELECT feed_id, position FROM video_links WHERE article_id = ?", (first,)).fetchone()[:] == (b, 4)


# ============================================================================ in-app player
def test_player_frames_only_youtube_nocookie(client):
    """The CSP allows exactly one frame host (YouTube's privacy-enhanced player); nothing can frame the app."""
    csp = client.get("/login").headers["content-security-policy"]
    directives = dict((d.strip().split(" ", 1) + [""])[:2] for d in csp.split(";") if d.strip())
    assert directives["frame-src"] == "https://www.youtube-nocookie.com"
    assert directives["frame-ancestors"] == "'none'" and "child-src" not in directives
    assert client.get("/login").headers["referrer-policy"] == "no-referrer"   # the app-wide policy is unchanged


def test_player_iframe_is_sandboxed_and_validated():
    """Static check of the player: only an 11-character id goes into the embed URL, the frame is sandboxed without
    top-navigation, and only this frame sends the app's origin (never a path) as referrer."""
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent / "static" / "sources.js").read_text(encoding="utf-8")
    player = src[src.index("function playVideo("):src.index("// ======================================================================= topics editor")]
    assert "YT_VIDEO_ID.test(v.video_id" in player and "/^[A-Za-z0-9_-]{11}$/" in src
    assert "https://www.youtube-nocookie.com/embed/${v.video_id}" in player
    assert 'sandbox: "allow-scripts allow-same-origin allow-presentation allow-popups allow-popups-to-escape-sandbox"' in player
    assert "allow-top-navigation" not in player and "allow-forms" not in player
    assert 'referrerpolicy: "strict-origin"' in player and player.count("iframe") == 1
