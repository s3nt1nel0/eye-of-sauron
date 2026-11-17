"""🎙 Podcasts: finding shows (Apple directory / Spotify oEmbed / feed), storing episodes' audio, the API, Articles
stays free of episodes."""

import json
from unittest import mock

import httpx

from app import netguard, podcasts

FEED = "https://feeds.example.com/darknet.xml"
RSS = (b'<?xml version="1.0"?><rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"><channel>'
       b'<title>Darknet Diaries</title><itunes:author>Jack Rhysider</itunes:author><itunes:image href="https://img.example.com/show.jpg"/>'
       b'<item><title>EP 1: Ransomware gang</title><guid>ep1</guid><link>https://darknetdiaries.com/episode/1/</link>'
       b'<pubDate>Sat, 15 Nov 2026 10:00:00 GMT</pubDate><description>A ransomware story</description>'
       b'<enclosure url="https://cdn.example.com/ep1.mp3" type="audio/mpeg" length="12345"/><itunes:duration>1:02:05</itunes:duration></item>'
       b'<item><title>EP 2: Phishing</title><guid>ep2</guid><pubDate>Fri, 14 Nov 2026 10:00:00 GMT</pubDate>'
       b'<enclosure url="https://cdn.example.com/ep2.m4a" type="audio/x-m4a" length="999"/><itunes:duration>2725</itunes:duration></item>'
       b'</channel></rss>')
APPLE = {"results": [{"collectionName": "Darknet Diaries", "artistName": "Jack Rhysider", "feedUrl": FEED,
                      "artworkUrl600": "https://img.example.com/show.jpg", "trackCount": 160, "primaryGenreName": "Technology"}]}


def _resp(body, status=200, url="https://x.example/", ctype="application/json"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


def fake(method, url, **kw):
    if "itunes.apple.com/search" in url:
        return _resp(APPLE if "Darknet" in url else {"results": []})
    if "itunes.apple.com/lookup" in url:
        return _resp(APPLE if "id=1296350485" in url else {"results": []})
    if "open.spotify.com/oembed" in url:
        return _resp({"title": "Darknet Diaries"})
    if url.startswith(FEED):
        return _resp(RSS, url=FEED, ctype="application/rss+xml")
    if "notapodcast" in url:
        return _resp(b'<?xml version="1.0"?><rss version="2.0"><channel><title>Blog</title><item><title>post</title></item></channel></rss>',
                     url=url, ctype="application/rss+xml")
    return _resp(b"", status=404)


def test_resolve_and_parse_helpers():
    with mock.patch("app.podcasts.netguard.request", side_effect=fake):
        assert podcasts.resolve("Darknet Diaries")["feed_url"] == FEED
        assert podcasts.resolve("https://podcasts.apple.com/us/podcast/darknet-diaries/id1296350485")["title"] == "Darknet Diaries"
        assert podcasts.resolve("https://open.spotify.com/show/4XPl3uEEL9hvqMkoZrzbx5?si=abc")["feed_url"] == FEED
        assert podcasts.resolve(FEED)["title"] == "Darknet Diaries"
        for bad, msg in (("https://blog.example/notapodcast.xml", "no audio"), ("Nothing like it", "No podcast"),
                         ("https://open.spotify.com/artist/abc", "show link")):
            try:
                podcasts.resolve(bad)
                raise AssertionError(bad)
            except podcasts.PodcastError as exc:
                assert msg in str(exc), (bad, exc)
    assert podcasts.duration_seconds("1:02:05") == 3725 and podcasts.duration_seconds("62:05") == 3725 and podcasts.duration_seconds("x") is None
    assert podcasts.episode_audio({"enclosures": [{"href": "javascript:alert(1)", "type": "audio/mpeg"}]}) is None


def test_podcast_add_episodes_play_data_and_articles_stay_clean(authed):
    with mock.patch("app.podcasts.netguard.request", side_effect=fake), mock.patch("app.fetcher.netguard.request", side_effect=fake), \
            mock.patch("app.api.content._refresh_async"):
        r = authed.post("/api/v1/podcasts", json={"input": "https://podcasts.apple.com/us/podcast/x/id1296350485"})
        assert r.status_code == 201, r.text
        fid = r.json()["id"]
        assert authed.post("/api/v1/podcasts", json={"input": "Darknet Diaries"}).status_code == 409
        assert authed.post(f"/api/v1/feeds/{fid}/refresh").json()["ok"]
        search = authed.get("/api/v1/podcasts/search?q=Darknet").json()["results"]
        assert search[0]["feed_url"] == FEED
    eps = authed.get(f"/api/v1/podcasts/episodes?feed_ids={fid}").json()
    assert eps["total"] == 2
    first = eps["items"][0]
    assert first["title"] == "EP 1: Ransomware gang" and first["audio_url"] == "https://cdn.example.com/ep1.mp3"
    assert first["duration_s"] == 3725 and first["image"] == "https://img.example.com/show.jpg" and first["show"] == "Darknet Diaries"
    assert authed.get(f"/api/v1/podcasts/episodes?sort=longest").json()["items"][0]["title"] == "EP 1: Ransomware gang"
    assert authed.get("/api/v1/podcasts/episodes?q=phishing").json()["total"] == 1
    authed.post("/api/v1/articles/bulk", json={"ids": [first["id"]], "action": "read"})
    assert authed.get("/api/v1/podcasts/episodes?state=unplayed").json()["total"] == 1
    meta = authed.get("/api/v1/podcasts/meta").json()["shows"][0]
    assert meta["episodes"] == 2 and meta["unplayed"] == 1 and meta["keeps"] == 0
    # Articles stays free of podcast episodes
    titles = [a["title"] for a in authed.get("/api/v1/articles?limit=50").json()["items"]]
    assert not any(t.startswith("EP ") for t in titles)
    assert authed.get("/api/v1/podcasts/episodes?feed_ids=1;drop").status_code == 422
    assert authed.delete(f"/api/v1/podcasts/{fid}").status_code == 200
    assert authed.get("/api/v1/podcasts/meta").json()["shows"] == []


def test_podcasts_need_a_session(client):
    assert client.get("/api/v1/podcasts/meta").status_code == 401
    assert client.get("/api/v1/podcasts/search?q=abc").status_code == 401
    assert client.post("/api/v1/podcasts", json={"input": "abc"}).status_code == 401


def test_articles_feed_moves_to_podcasts(authed):
    """A show already followed in Articles is moved to Podcasts: its saved episodes get their audio and leave Articles."""
    with mock.patch("app.fetcher.netguard.request", side_effect=fake), mock.patch("app.api.content._refresh_async"):
        old = authed.post("/api/v1/feeds", json={"url": FEED}).json()["id"]
        authed.post(f"/api/v1/feeds/{old}/refresh")       # stored as plain articles (an Articles feed)
    assert any(a["title"].startswith("EP ") for a in authed.get("/api/v1/articles?limit=50").json()["items"])
    from app.db import get_db, now
    with get_db() as db:  # an episode the Articles retention removed earlier
        db.execute("INSERT INTO article_tombstones (feed_id, guid, removed_at) VALUES (?, 'ep-old', ?)", (old, now()))
    with mock.patch("app.podcasts.netguard.request", side_effect=fake):
        r = authed.post("/api/v1/podcasts", json={"input": "Darknet Diaries"})
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM article_tombstones WHERE feed_id = ?", (old,)).fetchone()[0] == 0
    assert r.status_code == 201 and r.json()["moved"] is True and r.json()["id"] == old and r.json()["episodes_filled"] == 2
    eps = authed.get(f"/api/v1/podcasts/episodes?feed_ids={old}").json()
    assert eps["total"] == 2 and eps["items"][0]["audio_url"] == "https://cdn.example.com/ep1.mp3"
    assert not any(a["title"].startswith("EP ") for a in authed.get("/api/v1/articles?limit=50").json()["items"])
    with mock.patch("app.podcasts.netguard.request", side_effect=fake):
        assert authed.post("/api/v1/podcasts", json={"input": FEED}).status_code == 409   # now it really is there


def test_spotify_show_page_names_the_show():
    """Spotify's oEmbed gives the latest episode's title, so the show page's link preview names the show; the
    directory entry with that name (and author) is picked, never a look-alike."""
    page = ('<html><head><meta property="og:title" content="Security Now (Audio)">'
            '<meta property="og:description" content="Podcast · TWiT · Steve Gibson and Leo Laporte"></head></html>').encode()
    results = {"results": [
        {"collectionName": "Security Now Clips", "artistName": "Fans", "feedUrl": "https://f.example/clips.xml"},
        {"collectionName": "Security Now (Video HD)", "artistName": "TWiT", "feedUrl": "https://f.example/video.xml"},
        {"collectionName": "Security Now (Audio)", "artistName": "TWiT", "feedUrl": "https://f.example/audio.xml"}]}

    def net(method, url, **kw):
        if url.startswith("https://open.spotify.com/show/"):
            return _resp(page, url=url, ctype="text/html")
        if "itunes.apple.com/search" in url:
            return _resp(results)
        return _resp({"title": "SN 1104: The hole in OpenSSH"})   # oEmbed: an episode title
    with mock.patch("app.podcasts.netguard.request", side_effect=net):
        assert podcasts._spotify_show("https://open.spotify.com/show/7vAbYigR3zs8GYJP3EoVWw") == ("Security Now (Audio)", "TWiT")
        assert podcasts.resolve("https://open.spotify.com/show/7vAbYigR3zs8GYJP3EoVWw?si=x")["feed_url"] == "https://f.example/audio.xml"
    assert podcasts._norm("Security Now (Audio)") == "security now" and podcasts._norm("Podcasting 2.0 Podcast") == "podcasting 2 0"
    assert podcasts._best_match([{"title": "Other show", "author": "x"}], "Hacked", None) is None


def test_episodes_sharing_one_link_are_all_kept(authed):
    """Some shows link every episode to the same home page: podcast episodes are matched by their id, not their
    link (article feeds still drop same-link reposts)."""
    items = "".join(f'<item><title>Ep {n}</title><guid>uuid-{n}</guid><link>https://show.example.com</link>'
                    f'<pubDate>Sat, {10 + n} Oct 2026 10:00:00 GMT</pubDate><enclosure url="https://cdn.example.com/{n}.mp3" type="audio/mpeg"/></item>'
                    for n in range(5))
    same = f'<?xml version="1.0"?><rss version="2.0"><channel><title>Same Link Show</title>{items}</channel></rss>'.encode()
    feed_url = "https://feeds.example.com/samelink.xml"

    def net(method, url, **kw):
        return _resp(same, url=feed_url, ctype="application/rss+xml")
    with mock.patch("app.podcasts.netguard.request", side_effect=net), mock.patch("app.fetcher.netguard.request", side_effect=net),             mock.patch("app.api.content._refresh_async"):
        fid = authed.post("/api/v1/podcasts", json={"input": feed_url}).json()["id"]
        assert authed.post(f"/api/v1/feeds/{fid}/refresh").json()["ok"]
    assert authed.get(f"/api/v1/podcasts/episodes?feed_ids={fid}").json()["total"] == 5


def test_episode_topics(authed):
    """Episodes are tagged by subject: never the format topics (they're all podcasts); an episode nothing matches gets
    its show's main topic, and a show with no matches at all gets General."""
    from app import topics
    from app.db import get_db, now

    with get_db() as db:
        show = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Sec Show', 'https://s.example/f.xml', ?, 'podcast')", (now(),)).lastrowid
        quiet = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Story Show', 'https://s.example/g.xml', ?, 'podcast')", (now(),)).lastrowid
        ids = {}
        for fid, title in ((show, "Ransomware gang interview"), (show, "Ransomware negotiations"), (show, "McBroke"), (quiet, "Part 1: Nascent")):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, '', ?, ?)",
                             (fid, title, title, now(), now())).lastrowid
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://cdn.example/a.mp3')", (aid,))
            ids[title] = aid
        topics.classify(db, list(ids.values()))
        topics.fill_episode_topics(db)
        names = lambda aid: {r[0] for r in db.execute("SELECT t.name FROM article_topics x JOIN topics t ON t.id = x.topic_id WHERE x.article_id = ?", (aid,))}  # noqa: E731
        assert "Ransomware" in names(ids["Ransomware gang interview"])
        assert "Podcasts & interviews" not in names(ids["Ransomware gang interview"])      # a format, not a subject
        assert names(ids["McBroke"]) == {"Ransomware"}                                      # the show's main topic
        assert names(ids["Part 1: Nascent"]) == {"General"}                                 # nothing to go on
    shown = authed.get(f"/api/v1/podcasts/episodes?feed_ids={show}").json()["items"]
    assert all(e["topics"] for e in shown)


def test_show_categories(authed):
    """A show's own categories page labels its episodes (by episode number), adds matching topics that survive a
    full re-tag, and filters the episode list."""
    from app import topics
    from app.db import get_db, now

    page = ('<div class="archive-group"><h2 class="category-head">ransomware</h2>'
            '<article><h4><a href="/episode/2/">Ep 2</a></h4></article></div>'
            '<div class="archive-group"><h2 class="category-head">Advanced Persistent Threat/Nation State Actor</h2>'
            '<article><h4><a href="/episode/1/">Ep 1</a></h4></article><article><h4><a href="/episode/2/">Ep 2</a></h4></article></div>').encode()
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, site_url, created_at, kind) VALUES ('Darknet Diaries', 'https://podcast.darknetdiaries.com/', "
                         "'https://darknetdiaries.com', ?, 'podcast')", (now(),)).lastrowid
        ids = []
        for n in (1, 2, 3):
            aid = db.execute("INSERT INTO articles (feed_id, guid, url, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, '', ?, ?)",
                             (fid, f"g{n}", f"https://darknetdiaries.com/episode/{n}/", f"{n}: Story", now(), now() - n)).lastrowid
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://cdn.example/a.mp3')", (aid,))
            ids.append(aid)
    with mock.patch("app.podcasts.netguard.request", return_value=_resp(page, url="https://darknetdiaries.com/categories/", ctype="text/html")) as net:
        assert podcasts.sync_categories(fid) == 2
        assert net.call_args[0][1] == "https://darknetdiaries.com/categories/"
        assert podcasts.sync_categories(fid) == 0                        # weekly: not again so soon
    eps = {e["title"]: e for e in authed.get(f"/api/v1/podcasts/episodes?feed_ids={fid}").json()["items"]}
    assert eps["2: Story"]["categories"] == ["Advanced Persistent Threat/Nation State Actor", "ransomware"] and eps["3: Story"]["categories"] == []
    def names(aid):
        with get_db() as db:
            return {r[0] for r in db.execute("SELECT t.name FROM article_topics x JOIN topics t ON t.id = x.topic_id WHERE x.article_id = ?", (aid,))}
    assert "Ransomware" in names(ids[1])                                  # the category added the topic
    topics.reclassifier._retag(topics.ALL_TOPICS)                         # a full re-tag keeps it
    assert "Ransomware" in names(ids[1])
    assert authed.get(f"/api/v1/podcasts/episodes?category=ransomware").json()["total"] == 1
    cats = authed.get(f"/api/v1/podcasts/categories?feed_ids={fid}").json()["categories"]
    assert {"name": "Advanced Persistent Threat/Nation State Actor", "episodes": 2} in cats


def test_episode_youtube_and_official_links(authed):
    """An episode links to its own YouTube video when the show's channel is in Videos (titles matched loosely,
    "#620:" prefixes ignored); the show's website is there for the official page."""
    from app.db import get_db, now

    with get_db() as db:
        show = db.execute("INSERT INTO feeds (title, url, site_url, created_at, kind) VALUES ('David Bombal', 'https://s.example/db.xml', "
                          "'https://davidbombal.com', ?, 'podcast')", (now(),)).lastrowid
        yt = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('David Bombal', 'https://y.example/ch', ?, 'youtube')", (now(),)).lastrowid
        vid = db.execute("INSERT INTO articles (feed_id, guid, url, title, fetched_at, sort_ts) VALUES (?, 'v1', 'https://www.youtube.com/watch?v=o_19eye8L9o', "
                         "'He Invented the USB Rubber Ducky (and it changed hacking)', ?, ?)", (yt, now(), now())).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id, channel_title) VALUES (?, 'o_19eye8L9o', 'David Bombal')", (vid,))
        for guid, title in (("e1", "#620: He Invented the USB Rubber Ducky (and it changed hacking)"), ("e2", "#621: Something else entirely here")):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, '', ?, ?)",
                             (show, guid, title, now(), now())).lastrowid
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://cdn.example/a.mp3')", (aid,))
    eps = {e["title"][:4]: e for e in authed.get(f"/api/v1/podcasts/episodes?feed_ids={show}").json()["items"]}
    assert eps["#620"]["youtube_url"] == "https://www.youtube.com/watch?v=o_19eye8L9o"
    assert eps["#621"]["youtube_url"] is None                     # no match: the page offers a YouTube search
    assert eps["#620"]["show_site"] == "https://davidbombal.com"


def test_episode_youtube_from_the_shows_channel(authed):
    """The show's YouTube channel is found on its website (no search), its uploads are listed (titles + dates only),
    and episodes are matched by title, by episode number near the date, or by shared words within 3 days. The user can
    set the channel by hand or say there's none; bad links are refused."""
    from app import podcast_youtube, sources
    from app.db import get_db, now

    day = 86400
    t0 = now() - 30 * day
    with get_db() as db:
        show = db.execute("INSERT INTO feeds (title, url, site_url, created_at, kind) VALUES ('Risky Business', 'https://s.example/rb.xml', "
                          "'https://risky.example/', ?, 'podcast')", (now(),)).lastrowid
        for guid, title, ts in (("r1", "Risky Business #800 -- Salt Typhoon is back", t0), ("r2", "Episode 801: Patch Tuesday chaos", t0 + 7 * day),
                                ("r3", "Snake oil vendors and AI agents ruin everything", t0 + 14 * day), ("r4", "Totally unrelated bonus", t0 + 20 * day)):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, '', ?, ?)",
                             (show, guid, title, now(), ts)).lastrowid
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://cdn.example/a.mp3')", (aid,))
    site = '<a href="https://www.youtube.com/@riskybizmedia">YouTube</a>'
    uploads = {"items": [
        {"snippet": {"title": "Risky Business #800 -- Salt Typhoon is back"}, "contentDetails": {"videoId": "AAAAAAAAAA1", "videoPublishedAt": "2000-01-01T00:00:00Z"}},
        {"snippet": {"title": "RB 801 | Patch Tuesday", "publishedAt": "x"}, "contentDetails": {"videoId": "AAAAAAAAAA2"}},
        {"snippet": {"title": "AI agents and snake oil vendors"}, "contentDetails": {"videoId": "AAAAAAAAAA3"}},
        {"snippet": {"title": "Deleted video"}, "contentDetails": {"videoId": "AAAAAAAAAA4"}}]}
    stamps = {"AAAAAAAAAA1": t0 + 3600, "AAAAAAAAAA2": t0 + 8 * day, "AAAAAAAAAA3": t0 + 15 * day}
    for it in uploads["items"]:  # published dates relative to the episodes
        vid = it["contentDetails"]["videoId"]
        if vid in stamps:
            import datetime
            it["contentDetails"]["videoPublishedAt"] = datetime.datetime.fromtimestamp(stamps[vid], datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    calls = []

    def yt_api(path, params, key):
        calls.append(path)
        if path == "channels":
            assert params == {"part": "snippet", "forHandle": "@riskybizmedia"}
            return {"items": [{"id": "UCaaaaaaaaaaaaaaaaaaaaab", "snippet": {"title": "Risky Business Media"}}]}
        if path == "playlistItems":
            assert params["playlistId"] == "UUaaaaaaaaaaaaaaaaaaaaab"
            return uploads
        raise AssertionError(path)

    with mock.patch.object(sources, "yt_key", return_value="k"), mock.patch.object(sources, "yt_api", side_effect=yt_api),          mock.patch.object(podcast_youtube, "_page", side_effect=lambda u: site if u and "risky" in u else ""):
        res = podcast_youtube.sync(show)
    assert res["how"] == "site" and res["new_links"] == 3 and "search" not in calls
    eps = {e["title"][:12]: e for e in authed.get(f"/api/v1/podcasts/episodes?feed_ids={show}").json()["items"]}
    assert eps["Risky Busine"]["youtube_url"] == "https://www.youtube.com/watch?v=AAAAAAAAAA1"   # same title
    assert eps["Episode 801:"]["youtube_url"] == "https://www.youtube.com/watch?v=AAAAAAAAAA2"   # number 801, a day later
    assert eps["Snake oil ve"]["youtube_url"] == "https://www.youtube.com/watch?v=AAAAAAAAAA3"   # same words, a day later
    assert eps["Totally unre"]["youtube_url"] is None
    assert eps["Totally unre"]["youtube_search"].startswith("https://www.youtube.com/channel/UCaaaaaaaaaaaaaaaaaaaaab/search?query=")
    meta = next(s for s in authed.get("/api/v1/podcasts/meta").json()["shows"] if s["feed_id"] == show)
    assert meta["youtube"]["how"] == "site" and meta["youtube"]["linked"] == 3
    assert meta["youtube"]["sources"][0]["url"] == "https://www.youtube.com/channel/UCaaaaaaaaaaaaaaaaaaaaab"
    with mock.patch.object(sources, "yt_key", return_value="k"), mock.patch.object(sources, "yt_api", side_effect=yt_api):
        assert podcast_youtube.sync(show)["new_videos"] == 0       # listed today already: no API calls
    # by hand: none / a bad link / not YouTube
    assert authed.put(f"/api/v1/podcasts/{show}/youtube", json={"url": None}).json() == {"sources": []}
    assert authed.get(f"/api/v1/podcasts/episodes?feed_ids={show}").json()["items"][0]["youtube_url"] is None
    assert authed.put(f"/api/v1/podcasts/{show}/youtube", json={"url": "https://evil.example/@x"}).status_code == 422
    assert authed.put(f"/api/v1/podcasts/{show}/youtube", json={"url": "https://www.youtube.com/watch?v=x", "x": 1}).status_code == 422
    assert authed.put("/api/v1/podcasts/999999/youtube", json={"url": None}).status_code == 404
    with mock.patch.object(sources, "yt_key", return_value=None):
        assert authed.post(f"/api/v1/podcasts/{show}/youtube/find").status_code == 409


def test_youtube_name_and_number_helpers():
    from app import podcast_youtube as py

    assert py.ep_number("Episode 801: x") == 801 and py.ep_number("#620: y") == 620 and py.ep_number("RB #800 -- z") == 800
    assert py.ep_number("No number here") is None
    assert py.name_close("Security Now (Audio)", "Security Now") and py.name_close("Darknet Diaries", "Darknet Diaries Podcast")
    assert not py.name_close("Hacked", "Jack Rhysider") and not py.name_close("LOW", "LOW")  # too short to trust


def test_youtube_wrong_channels_are_dropped(authed):
    """A search hit must carry the show's very name; a found channel none of the episodes are on is forgotten."""
    from app import podcast_youtube as py
    from app.db import get_db, now

    assert py._bare("The Click Here Podcast") == "click here" and py._bare("Just Click Here") != py._bare("Click Here")
    with get_db() as db:
        show = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Namesake', 'https://n.example/x.xml', ?, 'podcast')", (now(),)).lastrowid
        for i in range(4):
            db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)", (show, f"n{i}", f"Episode title {i}", now(), now()))
        db.execute("INSERT INTO podcast_youtube (feed_id, sources, how, detected_at, listed_at) VALUES (?, '[{\"kind\": \"channel\", \"id\": \"UCaaaaaaaaaaaaaaaaaaaaab\", \"title\": \"x\"}]', 'site', ?, ?)",
                   (show, now(), now()))
        db.execute("INSERT INTO podcast_youtube_videos (feed_id, video_id, title, published) VALUES (?, 'AAAAAAAAAA9', 'Something else', ?)", (show, now()))
        assert py.match(db, show) == 0 and py.drop_if_unmatched(db, show)
        assert tuple(db.execute("SELECT sources, how FROM podcast_youtube WHERE feed_id = ?", (show,)).fetchone()) == ("[]", "none")
        assert db.execute("SELECT COUNT(*) FROM podcast_youtube_videos WHERE feed_id = ?", (show,)).fetchone()[0] == 0
