"""OPML keeps what each feed is: article feeds, podcasts, YouTube channels and social accounts each land in their own
tab after an export / import round trip, and other readers' OPML files are recognised by address."""

import json

from app.db import get_db, now


def _add(title, url, **cols):
    keys = ["title", "url", "created_at", *cols]
    with get_db() as db:
        return db.execute(f"INSERT INTO feeds ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                          [title, url, now(), *cols.values()]).lastrowid


def _types(client):
    out = {}
    for f in client.get("/api/v1/feeds").json():
        out[f["url"]] = ("accounts" if f["social_platform"] else {"podcast": "podcasts", "youtube": "videos"}.get(f["kind"], "articles"), f["kind"])
    return out


def test_export_import_round_trip_keeps_every_kind(authed):
    _add("News", "https://news.example/rss", retention_days=90, refresh_minutes=30)
    _add("Show", "https://show.example/podcast.xml", kind="podcast", retention_days=0)
    _add("Chan", "https://www.youtube.com/feeds/videos.xml?channel_id=UC" + "a" * 22, kind="youtube",
         source=json.dumps({"kind": "youtube", "channel_id": "UC" + "a" * 22}))
    _add("r/netsec", "https://www.reddit.com/r/netsec/new/.rss?limit=100", social_platform="reddit")
    _add("Scraped", "https://site.example/blog", kind="html", scrape=json.dumps({"mode": "html", "items": "article"}))
    _add("Kept as article", "https://www.reddit.com/r/blueteam/.rss")   # an account address the user keeps in Articles
    before = _types(authed)
    exported = authed.get("/api/v1/opml/export").content
    assert b'xmlns:eos="https://github.com/s3nt1nel0/eye-of-sauron/ns/opml"' in exported and b'eos:kind="podcast"' in exported
    with get_db() as db:
        db.execute("DELETE FROM feeds")
    r = authed.post("/api/v1/opml/import", content=exported, headers={"Content-Type": "text/xml"}).json()
    assert r["added"] == 6 and r["invalid"] == 0
    assert r["by_type"] == {"articles": 3, "podcasts": 1, "videos": 1, "accounts": 1}
    assert _types(authed) == before                       # every feed back in its own tab - nothing guessed differently
    with get_db() as db:
        news = db.execute("SELECT retention_days, refresh_minutes FROM feeds WHERE url = 'https://news.example/rss'").fetchone()
    assert tuple(news) == (90, 30)


def test_reimport_moves_wrongly_imported_feeds_to_their_tabs(authed):
    _add("Show", "https://show.example/podcast.xml", kind="podcast")
    _add("Acct", "https://infosec.exchange/@someone.rss", social_platform="mastodon")
    exported = authed.get("/api/v1/opml/export").content
    with get_db() as db:  # an older import that put everything in Articles
        db.execute("UPDATE feeds SET kind = 'rss', social_platform = NULL")
    r = authed.post("/api/v1/opml/import", content=exported, headers={"Content-Type": "text/xml"}).json()
    assert (r["added"], r["skipped"], r["updated"]) == (0, 2, 2)
    t = _types(authed)
    assert t["https://show.example/podcast.xml"][0] == "podcasts" and t["https://infosec.exchange/@someone.rss"][0] == "accounts"


def test_plain_opml_from_another_reader_is_recognised_by_address(authed):
    opml = b"""<?xml version="1.0"?><opml version="2.0"><body><outline text="Mixed">
      <outline type="rss" text="Blog" xmlUrl="https://blog.example/feed"/>
      <outline type="rss" text="Sub" xmlUrl="https://www.reddit.com/r/netsec/.rss"/>
      <outline type="rss" text="Toot" xmlUrl="https://infosec.exchange/@alice.rss"/>
      <outline type="rss" text="Sky" xmlUrl="https://bsky.app/profile/alice.bsky.social/rss"/>
      <outline type="rss" text="IG" xmlUrl="http://127.0.0.1:1200/instagram/user/somebody"/>
      <outline type="rss" text="Chan" xmlUrl="https://www.youtube.com/feeds/videos.xml?channel_id=UCbbbbbbbbbbbbbbbbbbbbbb"/>
      <outline type="rss" text="TG" xmlUrl="https://t.me/s/somechannel"/>
    </outline></body></opml>"""
    r = authed.post("/api/v1/opml/import", content=opml, headers={"Content-Type": "text/xml"}).json()
    assert r["by_type"] == {"articles": 1, "podcasts": 0, "videos": 1, "accounts": 5}
    t = _types(authed)
    assert t["https://t.me/s/somechannel"] == ("accounts", "telegram")


def test_hostile_eos_attributes_are_validated(authed):
    opml = b"""<?xml version="1.0"?><opml version="2.0" xmlns:eos="https://github.com/s3nt1nel0/eye-of-sauron/ns/opml"><body>
      <outline type="rss" text="A" xmlUrl="https://a.example/f" eos:kind="evil" eos:social="javascript" eos:retention="-5" eos:refresh="1"/>
      <outline type="rss" text="B" xmlUrl="https://b.example/f" eos:kind="telegram" eos:source='{"kind":"telegram","channel":"x\" OR 1"}'/>
      <outline type="rss" text="C" xmlUrl="https://c.example/f" eos:kind="html" eos:scrape='{"items":"","evil":1}'/>
    </body></opml>"""
    r = authed.post("/api/v1/opml/import", content=opml, headers={"Content-Type": "text/xml"}).json()
    assert r["added"] == 3 and r["invalid"] == 0          # bad descriptions fall back to a plain feed at that address
    with get_db() as db:
        rows = [tuple(x) for x in db.execute("SELECT kind, social_platform, retention_days, refresh_minutes, source, scrape FROM feeds")]
    assert rows == [("rss", None, None, None, None, None)] * 3


def test_an_article_feed_of_audio_episodes_becomes_a_podcast(authed):
    from app import feedkinds

    fid = _add("Pod", "https://pod.example/feed")
    with get_db() as db:
        for i in range(4):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, 'ep', 0, 0)", (fid, f"g{i}")).lastrowid
            if i:
                db.execute("INSERT INTO episodes (article_id, audio_url, audio_type) VALUES (?, 'https://pod.example/a.mp3', 'audio/mpeg')", (aid,))
        assert feedkinds.check_feed(db, fid) == "podcast"
        row = db.execute("SELECT f.kind, d.name FROM feeds f JOIN folders d ON d.id = f.folder_id WHERE f.id = ?", (fid,)).fetchone()
    assert tuple(row) == ("podcast", "Podcasts")
