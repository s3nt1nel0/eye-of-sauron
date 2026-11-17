"""Stage-2 sources: YouTube library, HF Daily Papers, X (bridge/API), Telegram (web/account),
integrations secrets, topics and the security properties around them."""

import json
import sqlite3
import time
from unittest import mock

import httpx
import pytest

from app import netguard, sources

CH = "UCVeW9qkBjo3zosnqUbG7CFw"


def resp(body, url="https://example.com/", status=200, ctype="text/html", headers=None):
    if isinstance(body, (dict, list)):
        body, ctype = json.dumps(body).encode(), "application/json"
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype, **(headers or {})}), body, url)


class FakeNet:
    """Routes netguard.request by URL substring and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, **kw):
        self.calls.append({"url": url, **kw})
        for key, value in self.routes.items():
            if key in url:
                return value(url) if callable(value) else value
        raise AssertionError(f"unexpected request {url}")


def patch_net(routes):
    fake = FakeNet(routes)
    return fake, mock.patch("app.netguard.request", side_effect=fake)


YT_RSS = f"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns:yt="http://www.youtube.com/xml/schemas/2015" xmlns:media="http://search.yahoo.com/mrss/" xmlns="http://www.w3.org/2005/Atom">
 <title>John Hammond</title>
 <entry><id>yt:video:AAAAAAAAAA1</id><yt:videoId>AAAAAAAAAA1</yt:videoId><yt:channelId>{CH}</yt:channelId>
  <title>Ransomware malware analysis &lt;script&gt;</title><link rel="alternate" href="https://www.youtube.com/watch?v=AAAAAAAAAA1"/>
  <author><name>John Hammond</name></author><published>2026-11-10T13:54:16+00:00</published>
  <media:group><media:title>x</media:title><media:thumbnail url="https://i2.ytimg.com/vi/AAAAAAAAAA1/hqdefault.jpg" width="480" height="360"/>
  <media:description>Learn more at https://jh.live/x &lt;img src=x onerror=alert(1)&gt;</media:description>
  <media:community><media:statistics views="1234"/></media:community></media:group></entry>
 <entry><id>yt:video:BBBBBBBBBB2</id><yt:videoId>BBBBBBBBBB2</yt:videoId><yt:channelId>{CH}</yt:channelId>
  <title>Hack The Box walkthrough</title><link rel="alternate" href="https://www.youtube.com/watch?v=BBBBBBBBBB2"/>
  <author><name>John Hammond</name></author><published>2026-11-09T13:54:16+00:00</published>
  <media:group><media:description>CTF</media:description></media:group></entry>
</feed>""".encode()


def add_source(client, source, **extra):
    with mock.patch("app.api.content._refresh_async"):
        r = client.post("/api/v1/feeds", json={"url": "https://ignored.example/", "source": source, **extra})
    assert r.status_code == 201, r.text
    return r.json()


# ============================================================================ YouTube
def test_youtube_feed_library_and_topics(authed):
    feed = add_source(authed, {"kind": "youtube", "channel_id": CH})
    assert feed["url"] == f"https://www.youtube.com/feeds/videos.xml?channel_id={CH}" and feed["kind"] == "youtube"
    fake, p = patch_net({"feeds/videos.xml": resp(YT_RSS, ctype="application/atom+xml")})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert r["ok"] and r["new"] == 2, r
    lib = authed.get("/api/v1/library/videos").json()
    assert lib["total"] == 2
    first = lib["items"][0]
    assert first["video_id"] == "AAAAAAAAAA1" and first["views"] == 1234 and first["channel_title"] == "John Hammond"
    art = authed.get(f"/api/v1/articles/{first['id']}").json()
    assert "<script" not in art["content_html"] and "onerror" not in art["content_html"]
    assert 'href="https://jh.live/x"' in art["content_html"]
    meta = authed.get("/api/v1/library/meta").json()
    assert meta["channels"][0]["videos"] == 2
    topic_ids = {t["name"]: t["id"] for t in meta["topics"]}
    ransom = authed.get(f"/api/v1/library/videos?topic_id={topic_ids['Ransomware']}").json()
    assert [i["video_id"] for i in ransom["items"]] == ["AAAAAAAAAA1"]
    ctf = authed.get(f"/api/v1/library/videos?topic_id={topic_ids['Red team & pentesting']}").json()
    assert [i["video_id"] for i in ctf["items"]] == ["BBBBBBBBBB2"]
    assert authed.get("/api/v1/library/videos?q=walkthrough").json()["total"] == 1
    assert authed.get("/api/v1/library/videos?q=%25").json()["total"] == 0  # LIKE wildcards escaped
    assert authed.get("/api/v1/library/videos?sort=views;DROP").status_code == 422
    assert authed.get("/api/v1/library/videos?length=short").json()["total"] == 0  # no durations without API key


def test_youtube_api_key_header_not_url_and_backfill(authed):
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        r = authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    assert r.status_code == 200 and r.json()["secrets_set"] == ["api_key"]
    assert "test-youtube-key" not in fake.calls[0]["url"] and fake.calls[0]["headers"]["X-Goog-Api-Key"].startswith("test-youtube-key")
    assert "test-youtube-key" not in authed.get("/api/v1/integrations").text
    feed = add_source(authed, {"kind": "youtube", "channel_id": CH})
    items = {"items": [{"snippet": {"title": f"Old video {i}", "publishedAt": "2025-01-0%dT00:00:00Z" % (i + 1),
                                    "channelTitle": "John Hammond", "thumbnails": {"high": {"url": f"https://i.ytimg.com/vi/OLDVIDEO00{i}/hq.jpg"}}},
                        "contentDetails": {"videoId": f"OLDVIDEO00{i}", "videoPublishedAt": "2025-01-0%dT00:00:00Z" % (i + 1)}} for i in range(3)]}
    details = {"items": [{"id": f"OLDVIDEO00{i}", "contentDetails": {"duration": "PT1H2M3S" if i == 0 else "PT45S"},
                          "statistics": {"viewCount": str(1000 * i)}} for i in range(3)]}
    fake, p = patch_net({"playlistItems": resp(items), "/videos?": resp(details)})
    authed.put(f"/api/v1/feeds/{feed['id']}/retention", json={"retention_days": 0})
    from app import history

    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 1}).status_code == 200
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status
    assert "playlistId=UU" + CH[2:] in fake.calls[0]["url"]
    longest = authed.get("/api/v1/library/videos?sort=longest").json()["items"]
    assert longest[0]["duration_s"] == 3723 and longest[0]["video_id"] == "OLDVIDEO000"
    assert authed.get("/api/v1/library/videos?length=short").json()["total"] == 2
    assert all("test-youtube-key" not in c["url"] for c in fake.calls)


def test_youtube_resolve(authed):
    page = b'<html><meta property="og:title" content="John Hammond"><script>{"externalId":"' + CH.encode() + b'"}</script></html>'
    fake, p = patch_net({"youtube.com/@_JohnHammond": resp(page, url="https://www.youtube.com/@_JohnHammond"),
                         "feeds/videos.xml": resp(YT_RSS, ctype="application/atom+xml")})
    with p:
        r = authed.post("/api/v1/sources/resolve", json={"input": "https://www.youtube.com/@_JohnHammond"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "youtube" and body["source"] == {"kind": "youtube", "channel_id": CH}
    assert body["title"] == "John Hammond" and len(body["preview"]) == 2
    assert authed.post("/api/v1/sources/resolve", json={"input": "https://evil.example/@x", "kind": "youtube"}).status_code == 422


# ============================================================================ Hugging Face Daily Papers
HF = [{"paper": {"id": "2611.14116", "title": "LLM jailbreak <img src=x onerror=alert(1)>", "summary": "Prompt injection study",
                 "upvotes": 12, "authors": [{"name": "A. Author"}], "submittedOnDailyAt": "2026-11-11T00:00:00.000Z",
                 "ai_summary": "TLDR", "ai_keywords": ["prompt injection"]},
       "numComments": 3, "thumbnail": "https://cdn-thumbnails.huggingface.co/x.png"},
      {"paper": {"id": "../../evil", "title": "bad id", "upvotes": 99}},
      {"paper": {"id": "2611.00001", "title": "Low votes", "upvotes": 0, "submittedOnDailyAt": "2026-11-11T00:00:00.000Z"}}]


def test_hf_papers(authed):
    feed = add_source(authed, {"kind": "hfpapers", "min_upvotes": 1})
    assert feed["url"] == "https://huggingface.co/papers" and feed["refresh_minutes"] == 180
    fake, p = patch_net({"api/daily_papers": resp(HF)})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert r["new"] == 1, r  # bad id dropped, low votes filtered
    art = authed.get("/api/v1/articles", params={"feed_id": feed["id"]}).json()
    items = art["items"] if isinstance(art, dict) else art
    assert items[0]["url"] == "https://huggingface.co/papers/2611.14116"
    full = authed.get(f"/api/v1/articles/{items[0]['id']}").json()
    assert "onerror" not in full["content_html"] and "arxiv.org/pdf/2611.14116" in full["content_html"]
    assert len(fake.calls) == 2 and "date=" in fake.calls[1]["url"]  # today + yesterday


# ============================================================================ X
BRIDGE_RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>New CVE in Fortinet</title><link>http://nitter.lan/vxunderground/status/111</link><guid>a</guid><description>one</description></item>
<item><title>RT by @vxunderground: something</title><link>http://nitter.lan/other/status/222</link><guid>b</guid></item>
<item><title>R to @someone: reply</title><link>http://nitter.lan/vxunderground/status/333</link><guid>c</guid></item>
</channel></rss>"""


def test_x_bridge(authed):
    assert authed.put("/api/v1/integrations/x", json={"bridge_type": "nitter", "bridge_url": "file:///etc"}).status_code == 422
    assert authed.put("/api/v1/integrations/x", json={"bridge_type": "template", "bridge_template": "http://b.lan/x"}).status_code == 422
    r = authed.put("/api/v1/integrations/x", json={"bridge_type": "nitter", "bridge_url": "http://nitter.lan/"})
    assert r.status_code == 200 and r.json()["config"]["bridge_url"] == "http://nitter.lan"
    feed = add_source(authed, {"kind": "x", "username": "vxunderground", "via": "bridge", "include_reposts": False})
    assert feed["url"] == "https://x.com/vxunderground"
    fake, p = patch_net({"nitter.lan/vxunderground/rss": resp(BRIDGE_RSS, ctype="application/rss+xml")})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert r["new"] == 1, r
    assert fake.calls[0]["allow_private"] is True  # only the admin-configured bridge may be on the LAN
    items = authed.get("/api/v1/articles", params={"feed_id": feed["id"]}).json()
    items = items["items"] if isinstance(items, dict) else items
    assert items[0]["url"] == "https://x.com/vxunderground/status/111"
    with pytest.raises(Exception):
        sources.XSource(username="bad/../name")


def test_x_api_since_id_rate_limit_and_secret(authed):
    token = "AAAAAAAAAAAAAAAAAAAAAMLheAAAAAAA0%2BuSeid%2BULvsea4JtiGRiSDSJSI%3DEUifiRBkKG5E2XzMDjRfl76ZC9Ub0wnz4XsNiRVBChTYbJcE3F"
    authed.put("/api/v1/integrations/x", json={"bearer_token": token})
    assert token not in authed.get("/api/v1/integrations").text
    with sqlite3.connect(_db_path()) as db:
        stored = db.execute("SELECT secret FROM integrations WHERE name = 'x'").fetchone()[0]
    assert stored.startswith("fw1:") and token not in stored
    feed = add_source(authed, {"kind": "x", "username": "CISAgov", "via": "api"})
    assert feed["refresh_minutes"] == 360
    tweets = {"data": [{"id": "1855", "text": "Patch now https://t.co/abc", "created_at": "2026-11-11T10:00:00.000Z",
                        "entities": {"urls": [{"url": "https://t.co/abc", "expanded_url": "https://www.cisa.gov/kev"}]},
                        "public_metrics": {"like_count": 5, "retweet_count": 2, "reply_count": 1}}],
              "meta": {"newest_id": "1855", "result_count": 1}}
    fake, p = patch_net({"users/by/username/CISAgov": resp({"data": {"id": "42", "name": "CISA"}}),
                         "users/42/tweets": resp(tweets)})
    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["new"] == 1
        assert fake.calls[1]["headers"]["Authorization"] == f"Bearer {token}" and token not in fake.calls[1]["url"]
        assert "exclude=replies" in fake.calls[1]["url"]
        authed.post(f"/api/v1/feeds/{feed['id']}/refresh")
    assert "since_id=1855" in fake.calls[-1]["url"]  # second call only asks for newer posts (user id cached)
    full = authed.get("/api/v1/articles", params={"feed_id": feed["id"]}).json()
    full = full["items"] if isinstance(full, dict) else full
    body = authed.get(f"/api/v1/articles/{full[0]['id']}").json()["content_html"]
    assert "https://www.cisa.gov/kev" in body and "t.co" not in body
    fake, p = patch_net({"users/42/tweets": resp({"title": "Too Many Requests"}, status=429, headers={"x-rate-limit-reset": str(int(time.time()) + 900)})})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert not r["ok"] and "rate limit" in r["error"]
    details = authed.get(f"/api/v1/feeds/{feed['id']}/details").json()
    assert details["next_fetch"] >= int(time.time()) + 800


def _db_path():
    from app.config import get_settings

    return get_settings().db_path


# ============================================================================ Telegram
TG_PAGE = b"""<html><body>
<div class="tgme_channel_info_header_title"><span dir="auto">The Hacker News</span></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="thehackernews/10618">
 <a class="tgme_widget_message_photo_wrap" href="https://t.me/thehackernews/10618" style="width:800px;background-image:url('https://cdn4.telesco.pe/file/abc.jpg')"></a>
 <div class="tgme_widget_message_text js-message_text">Apple iOS sandbox escape<br/><br/>Details: <a href="https://thehackernews.com/x.html" onclick="return confirm('x');">link</a><script>alert(1)</script></div>
 <div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">5.82K</span>
 <a class="tgme_widget_message_date" href="https://t.me/thehackernews/10618"><time datetime="2026-11-10T12:17:34+00:00">12:17</time></a></div>
</div></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="thehackernews/10619">
 <div class="tgme_widget_message_text">Second post about ransomware</div>
 <a class="tgme_widget_message_date"><time datetime="2026-11-10T13:00:00+00:00">13:00</time></a></div></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="thehackernews/10620"></div></div>
</body></html>"""


def test_telegram_web(authed):
    fake, p = patch_net({"t.me/s/thehackernews": resp(TG_PAGE, url="https://t.me/s/thehackernews")})
    with p:
        r = authed.post("/api/v1/sources/resolve", json={"input": "https://t.me/thehackernews"})
    assert r.status_code == 200, r.text
    assert r.json()["source"] == {"kind": "telegram", "via": "web", "channel": "thehackernews"} and r.json()["title"] == "The Hacker News"
    feed = add_source(authed, r.json()["source"])
    assert feed["url"] == "https://t.me/s/thehackernews" and feed["refresh_minutes"] == 30
    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["new"] == 2  # service message skipped
    items = authed.get("/api/v1/articles", params={"feed_id": feed["id"]}).json()
    items = items["items"] if isinstance(items, dict) else items
    first = next(i for i in items if i["url"].endswith("/10618"))
    assert first["title"] == "Apple iOS sandbox escape"
    html = authed.get(f"/api/v1/articles/{first['id']}").json()["content_html"]
    assert "onclick" not in html and "<script" not in html and "cdn4.telesco.pe" in html
    # channel without a public preview redirects away from /s/
    fake, p = patch_net({"t.me/s/privchan": resp(b"<html></html>", url="https://t.me/privchan")})
    with p:
        r = authed.post("/api/v1/sources/resolve", json={"input": "@privchan", "kind": "telegram"})
    assert r.status_code == 422 and "account" in r.json()["detail"]


def test_telegram_web_backfill(authed):
    feed = add_source(authed, {"kind": "telegram", "via": "web", "channel": "thehackernews"})
    authed.put(f"/api/v1/feeds/{feed['id']}/retention", json={"retention_days": 0})
    older = TG_PAGE.replace(b"10618", b"10500").replace(b"10619", b"10501").replace(b"10620", b"10502")

    def route(url):
        return resp(older if "before=10618" in url else (b"<html></html>" if "before=" in url else TG_PAGE), url="https://t.me/s/thehackernews")

    fake, p = patch_net({"t.me/s/thehackernews": route})
    from app import history

    with p, mock.patch("app.history.time.sleep"):
        authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 5})
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status
    assert history.backfill_job.status["new"] == 4


def test_telegram_account_endpoints_admin_only_and_mocked_fetch(authed):
    w = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "w", "scope": "write"}).json()["token"]}
    for path, body in [("/integrations/telegram/login", {"api_id": 1, "api_hash": "0" * 32, "phone": "+441234567890"}),
                       ("/integrations/telegram/code", {"code": "12345"}), ("/integrations/telegram/logout", None)]:
        assert authed.post(f"/api/v1{path}", headers=w, json=body).status_code == 403
    assert authed.get("/api/v1/integrations/telegram/dialogs", headers=w).status_code == 403
    assert authed.put("/api/v1/integrations/youtube", headers=w, json={"clear": True}).status_code == 403
    assert authed.get("/api/v1/integrations", headers=w).status_code == 403
    # input validation before anything reaches Telegram
    assert authed.post("/api/v1/integrations/telegram/login", json={"api_id": 1, "api_hash": "xyz", "phone": "+1"}).status_code == 422
    assert authed.post("/api/v1/integrations/telegram/code", json={"code": "12345"}).status_code == 400  # no login pending
    feed = add_source(authed, {"kind": "telegram", "via": "account", "chat_id": -1001234567890})
    assert feed["url"] == "https://t.me/c/1001234567890"
    got = sources.Fetched(entries=[sources.entry(guid="tg:1234567890:5", title="Private intel", link="https://t.me/c/1234567890/5",
                                                 html_body="<p>hi<script>x</script></p>", ts=1794400000)],
                          title="Intel group", state={f"tg_last:{feed['id']}": "5"})
    with mock.patch("app.telegram_mt.account.fetch", return_value=got):
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["new"] == 1
    assert sources.get_state(f"tg_last:{feed['id']}") == "5"


def test_telegram_login_flow_mocked(authed):
    from app import telegram_mt

    calls = {}

    def start(api_id, api_hash, phone):
        calls["start"] = (api_id, phone)

    def code(c):
        from app import integrations
        from app.db import get_db

        with get_db() as db:
            integrations.save(db, "telegram", config={"api_id": 1, "account": {"name": "Me", "username": "me"}},
                              secrets={"api_hash": "a" * 32, "session": "SESSIONSTRING"})
        return {"connected": True, "account": {"name": "Me", "username": "me"}}

    with mock.patch.object(telegram_mt.account, "start_login", side_effect=start), \
         mock.patch.object(telegram_mt.account, "submit_code", side_effect=code):
        assert authed.post("/api/v1/integrations/telegram/login", json={"api_id": 1, "api_hash": "a" * 32, "phone": "+441234567890"}).json() == {"code_sent": True}
        assert authed.post("/api/v1/integrations/telegram/code", json={"code": "12345"}).json()["connected"]
    st = authed.get("/api/v1/integrations").json()["telegram"]
    assert st["config"]["account"]["name"] == "Me" and set(st["secrets_set"]) == {"api_hash", "session"}
    assert "SESSIONSTRING" not in authed.get("/api/v1/integrations").text
    with sqlite3.connect(_db_path()) as db:
        stored = db.execute("SELECT secret FROM integrations WHERE name = 'telegram'").fetchone()[0]
    assert stored.startswith("fw1:") and "SESSIONSTRING" not in stored
    with mock.patch.object(telegram_mt.account, "_loop") as loop:
        loop.run.side_effect = lambda coro, timeout=None: coro.close()
        assert authed.post("/api/v1/integrations/telegram/logout").json() == {"connected": False}
    st = authed.get("/api/v1/integrations").json()["telegram"]
    assert "session" not in st["secrets_set"] and "account" not in st["config"]


# ============================================================================ feed API rules
def test_source_feed_rules(authed):
    feed = add_source(authed, {"kind": "hfpapers"})
    assert authed.patch(f"/api/v1/feeds/{feed['id']}", json={"url": "http://169.254.169.254/"}).status_code == 422
    assert authed.patch(f"/api/v1/feeds/{feed['id']}", json={"source": {"kind": "x", "username": "a"}}).status_code == 422
    assert authed.patch(f"/api/v1/feeds/{feed['id']}", json={"source": {"kind": "hfpapers", "min_upvotes": 5}}).status_code == 200
    assert authed.get(f"/api/v1/feeds/{feed['id']}/details").json()["source"] == {"kind": "hfpapers", "min_upvotes": 5}
    with mock.patch("app.api.content._refresh_async"):
        assert authed.post("/api/v1/feeds", json={"url": "https://x.example/", "source": {"kind": "hfpapers"}}).status_code == 409
        assert authed.post("/api/v1/feeds", json={"url": "https://x.example/", "source": {"kind": "youtube"}}).status_code == 422
        assert authed.post("/api/v1/feeds", json={"url": "https://x.example/", "source": {"kind": "telegram", "via": "web", "chat_id": 5}}).status_code == 422
        assert authed.post("/api/v1/feeds", json={"url": "https://x.example/", "source": {"kind": "x", "username": "a", "extra": 1}}).status_code == 422
    r = authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 1})
    assert r.status_code == 200
    x = add_source(authed, {"kind": "x", "username": "someone"})
    from app import history

    history.backfill_job._thread.join(10)
    authed.post(f"/api/v1/feeds/{x['id']}/backfill", json={"max_pages": 1})
    history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "error" and "X" in history.backfill_job.status["error"]


def test_resolve_needs_write_and_rejects_unknown(authed):
    r = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    assert authed.post("/api/v1/sources/resolve", headers=r, json={"input": "https://t.me/x"}).status_code == 403
    assert authed.post("/api/v1/sources/resolve", json={"input": "https://example.com/blog"}).status_code == 422
    assert authed.post("/api/v1/sources/resolve", json={"input": "https://x.com/home"}).status_code == 422
    assert authed.post("/api/v1/sources/resolve", json={"input": "https://x.com/someone"}).status_code == 422  # no bridge/API set


# ============================================================================ topics
def test_topics_crud_and_validation(authed):
    tops = authed.get("/api/v1/topics").json()
    assert len(tops) >= 10 and all(t["builtin"] for t in tops)
    r = authed.post("/api/v1/topics", json={"name": "Fortinet", "keywords": ["fortigate", "FortiOS", "fortigate"], "color": "#ff0000"})
    assert r.status_code == 201 and r.json()["keywords"] == ["fortigate", "fortios"]
    assert authed.post("/api/v1/topics", json={"name": "fortinet", "keywords": ["x"]}).status_code == 409
    assert authed.post("/api/v1/topics", json={"name": "Bad", "keywords": ["x"], "color": "red;background:url(x)"}).status_code == 422
    assert authed.post("/api/v1/topics", json={"name": "Bad", "keywords": []}).status_code == 422
    assert authed.post("/api/v1/topics", json={"name": "Bad", "keywords": ["x" * 61]}).status_code == 422
    tid = r.json()["id"]
    assert authed.patch(f"/api/v1/topics/{tid}", json={"enabled": False}).json()["enabled"] is False
    assert authed.delete(f"/api/v1/topics/{tid}").status_code == 200
    # regex metacharacters in keywords are literal
    from app import topics

    assert topics._pattern(["c++", "a.b"]).search("I love c++ code") and not topics._pattern(["a.b"]).search("axb")
    assert topics._pattern(["ai"]).search("New AI model") and not topics._pattern(["ai"]).search("maintain")


def test_text_to_html_escapes():
    out = sources.text_to_html('<script>x</script> see https://a.example/p?q=1&r=2. "quoted"')
    assert "<script>" not in out and 'href="https://a.example/p?q=1&amp;r=2"' in out and out.count("<a ") == 1


def test_topics_ignore_feed_boilerplate(authed):
    """A sponsor blurb repeated in every description must not tag every item with its keywords."""
    feed = add_source(authed, {"kind": "hfpapers"})
    from app import topics
    from app.db import get_db, now

    blurb = "Get blue team training and SOC analyst certifications with our partner. Host your own VPN today."
    with get_db() as db:
        ids = []
        for i, title in enumerate(["Kubernetes escape", "Prompt injection in agents", "Ghidra tips", "Cooking show", "Weekly news"]):
            cur = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, published, fetched_at, sort_ts) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)", (feed["id"], f"g{i}", title, f"Episode {i} body. {blurb}", now(), now(), now() - i))
            ids.append(cur.lastrowid)
        topics.classify(db, ids)
        names = {r[0]: r[1] for r in db.execute("SELECT id, name FROM topics")}
        tagged = {}
        for aid, tid in db.execute("SELECT article_id, topic_id FROM article_topics"):
            tagged.setdefault(aid, set()).add(names[tid])
    assert "Blue team & DFIR" not in set().union(*tagged.values())
    assert "Network security" not in set().union(*tagged.values())
    assert tagged[ids[0]] == {"Cloud & containers"} and "AI security" in tagged[ids[1]] and ids[3] not in tagged


def test_youtube_playlist_preview_shows_every_item(authed):
    """A 10-video playlist previews all 10 (the add dialog used to show only 8 and looked like 8 were found)."""
    entries = "".join(
        f'<entry><id>yt:video:PLVIDEO{i:04d}</id><yt:videoId>PLVIDEO{i:04d}</yt:videoId><title>Episode {i}</title>'
        f'<link rel="alternate" href="https://www.youtube.com/watch?v=PLVIDEO{i:04d}"/><author><name>Chan</name></author>'
        f'<published>2021-0{1 + i % 9}-01T00:00:00+00:00</published></entry>' for i in range(10))
    feed = f'<?xml version="1.0"?><feed xmlns:yt="http://www.youtube.com/xml/schemas/2015" xmlns="http://www.w3.org/2005/Atom"><title>Course</title>{entries}</feed>'.encode()
    fake, p = patch_net({"feeds/videos.xml": resp(feed, ctype="application/atom+xml")})
    with p:
        r = authed.post("/api/v1/sources/resolve", json={"input": "https://www.youtube.com/playlist?list=PLIhvC56v63IJIujb5cyE13oLuyORZpdkL"})
    assert r.status_code == 200, r.text
    assert len(r.json()["preview"]) == 10 and r.json()["found"] == 10


def test_whole_playlist_loads_beyond_15(authed):
    """A playlist's back-fill pages through that playlist (not the channel's uploads) and gets every video."""
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    pl = "PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz"
    feed = add_source(authed, {"kind": "youtube", "playlist_id": pl})

    def page(start, count, token=None):
        items = [{"snippet": {"title": f"Episode {i}", "publishedAt": "2024-01-01T00:00:00Z", "channelTitle": "Deep"},
                  "contentDetails": {"videoId": f"EPISODE{i:04d}", "videoPublishedAt": "2024-01-01T00:00:00Z"}}
                 for i in range(start, start + count)]
        return resp({"items": items, **({"nextPageToken": token} if token else {})})
    pages = iter([page(0, 50, "T2"), page(50, 44)])
    details = resp({"items": []})
    fake, p = patch_net({"playlistItems": lambda url: next(pages), "/videos?": details})
    from app import history

    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 200, "keep_forever": True}).status_code == 200
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status
    assert all(f"playlistId={pl}" in c["url"] for c in fake.calls if "playlistItems" in c["url"])
    assert authed.get(f"/api/v1/library/videos?channels=feed:{feed['id']}&limit=200").json()["total"] == 94


def test_huge_playlist_has_no_500_cap(authed):
    """1,200 videos over 24 pages are all stored (back-fills used to stop at the 500-entries-per-fetch cap)."""
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    feed = add_source(authed, {"kind": "youtube", "playlist_id": "PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz"})

    def page(n):
        items = [{"snippet": {"title": f"Episode {i}", "publishedAt": "2024-01-01T00:00:00Z", "channelTitle": "Big"},
                  "contentDetails": {"videoId": f"BIG{i:08d}", "videoPublishedAt": "2024-01-01T00:00:00Z"}}
                 for i in range(n * 50, n * 50 + 50)]
        return resp({"items": items, **({"nextPageToken": f"T{n + 1}"} if n < 23 else {})})
    pages = iter(page(n) for n in range(24))
    fake, p = patch_net({"playlistItems": lambda url: next(pages), "/videos?": resp({"items": []})})
    from app import history

    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 1000, "keep_forever": True}).status_code == 200
        history.backfill_job._thread.join(20)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status
    assert authed.get(f"/api/v1/library/videos?channels=feed:{feed['id']}&limit=1").json()["total"] == 1200
    g = authed.get(f"/api/v1/library/groups/p:{feed['id']}?limit=300&offset=900").json()
    assert g["total"] == 1200 and len(g["items"]) == 300


def test_youtube_feed_failure_falls_back_to_api(authed):
    """YouTube's public feed answers 404/500 now and then for channels that exist; with a key the Data API fills in."""
    feed = add_source(authed, {"kind": "youtube", "channel_id": CH})
    fake, p = patch_net({"feeds/videos.xml": resp(b"not found", status=404)})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert not r["ok"] and "404" in r["error"] and "API key" in r["error"], r  # no key: honest error, hint
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    items = {"items": [{"snippet": {"title": "Fresh upload", "publishedAt": "2026-11-12T00:00:00Z", "channelTitle": "John Hammond"},
                        "contentDetails": {"videoId": "FRESHVIDEO1", "videoPublishedAt": "2026-11-12T00:00:00Z"}}]}
    fake, p = patch_net({"feeds/videos.xml": resp(b"oops", status=500), "playlistItems": resp(items),
                         "/videos?": resp({"items": [{"id": "FRESHVIDEO1", "contentDetails": {"duration": "PT10M"}}]})})
    with p:
        r = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert r["ok"] and r["new"] == 1, r
    assert "playlistId=UU" + CH[2:] in next(c["url"] for c in fake.calls if "playlistItems" in c["url"])
    vids = authed.get("/api/v1/library/videos").json()["items"]
    assert vids[0]["video_id"] == "FRESHVIDEO1" and vids[0]["duration_s"] == 600


def test_youtube_playlist_links_resolve_to_the_playlist_only():
    pid = "PLIhvC56v63IKrRHh3gvZZBAGvsvOhwrRF"
    for link in (f"https://www.youtube.com/playlist?list={pid}", f"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list={pid}&index=3",
                 f"youtube.com/watch?list={pid}&v=dQw4w9WgXcQ"):
        assert sources.resolve_youtube(link)["source"] == {"kind": "youtube", "playlist_id": pid}, link


def test_topic_retag_is_per_topic_and_in_short_transactions(authed):
    """Adding a topic tags only that topic, in small batches, and never blocks other writers for long."""
    import threading

    from app import topics
    from app.db import get_db, now

    with get_db() as db:
        feed = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Blog', 'https://b/retag', ?)", (now(),)).lastrowid
        for n in range(30):
            db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, '', ?, ?)",
                       (feed, f"r{n}", f"CTF writeup {n}" if n % 3 == 0 else f"Ransomware news {n}", now(), now()))
    def wait():
        for _ in range(200):
            if not topics.reclassifier.running:
                return
            threading.Event().wait(0.05)
    wait()
    with get_db() as db:
        before = db.execute("SELECT COUNT(*) FROM article_topics WHERE topic_id != (SELECT MAX(id) FROM topics) OR 1").fetchone()[0]
    calls = []
    real_classify = topics.classify
    def spy(db, ids, compiled=None, boiler=None):
        calls.append((len(ids), [c[0] for c in compiled]))
        return real_classify(db, ids, compiled, boiler)
    with mock.patch.object(topics, "RETAG_BATCH", 10), mock.patch.object(topics, "classify", side_effect=spy):
        t = authed.post("/api/v1/topics", json={"name": "Capture the flag", "keywords": ["ctf", "capture the flag"]}).json()
        wait()
    assert calls and all(n <= 10 for n, _ in calls)                 # batches, each its own short transaction
    assert all(ids == [t["id"]] for _, ids in calls)                 # only the new topic is matched
    with get_db() as db:
        tagged = db.execute("SELECT COUNT(*) FROM article_topics WHERE topic_id = ?", (t["id"],)).fetchone()[0]
        others = db.execute("SELECT COUNT(*) FROM article_topics WHERE topic_id != ?", (t["id"],)).fetchone()[0]
    assert tagged == 10 and others == before                         # other topics' tags untouched
    authed.patch(f"/api/v1/topics/{t['id']}", json={"enabled": False}); wait()
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM article_topics WHERE topic_id = ?", (t["id"],)).fetchone()[0] == 0


def test_topics_are_precise_title_for_videos_lead_for_articles(authed):
    """Videos get a topic only from their title; articles from the title or 2+ mentions early in the text."""
    from app import topics
    from app.db import get_db, now

    with get_db() as db:
        tid = db.execute("INSERT INTO topics (name, keywords, color, enabled) VALUES ('Homelab test', '[\"homelab\", \"home lab\"]', '#123456', 1)").lastrowid
        yt = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Chan', 'https://y/p1', ?, 'youtube', '{\"kind\":\"youtube\",\"channel_id\":\"UC9x0AN7BWHpCDHSm9NiJFJQ\"}')", (now(),)).lastrowid
        rss = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Blog', 'https://b/p1', ?)", (now(),)).lastrowid
        rows = {
            "vid_title": (yt, "My homelab tour", "sponsor text"),
            "vid_desc": (yt, "Kali basics", "check my homelab gear and my home lab links"),   # description only -> no
            "art_title": (rss, "Building a home lab", "text"),
            "art_lead2": (rss, "Weekly notes", "Homelab news: this homelab build uses Proxmox."),  # 2 early mentions -> yes
            "art_once": (rss, "Weekly notes 2", "One homelab mention, then other news."),           # once -> no
        }
        ids = {}
        for key, (feed, title, text) in rows.items():
            ids[key] = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                                  (feed, key, title, text, now(), now())).lastrowid
            if feed == yt:
                db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (ids[key], f"{key[:11]:x<11}"))
        topics.classify(db, list(ids.values()), [(tid, topics._pattern(["homelab", "home lab"]))], {})
        tagged = {k for k, i in ids.items() if db.execute("SELECT 1 FROM article_topics WHERE article_id = ? AND topic_id = ?", (i, tid)).fetchone()}
    assert tagged == {"vid_title", "art_title", "art_lead2"}


def test_hide_watched_setting_defaults_on(authed):
    assert authed.get("/api/v1/settings").json()["hide_watched"] is True
    assert authed.patch("/api/v1/settings", json={"hide_watched": False}).json()["hide_watched"] is False


def test_topics_v3_new_builtins_and_channel_names(authed):
    """The v3 built-in topics exist, and a video's channel name counts (a Black Hat talk rarely says so in its title)."""
    from app import topics
    from app.db import get_db, now

    names = {t["name"] for t in authed.get("/api/v1/topics").json()}
    assert {"Cyber news", "Careers & development", "Certifications & study", "Podcasts & interviews"} <= names
    with get_db() as db:
        yt = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('BH', 'https://y/bh', ?, 'youtube', '{\"kind\":\"youtube\",\"channel_id\":\"UC9x0AN7BWHpCDHSm9NiJFJQ\"}')", (now(),)).lastrowid
        ids = {}
        for key, title, chan in (("talk", "Protecting Ethical Hackers - BH2020", "Black Hat"),
                                 ("news", "Sep 11's Top Cyber News NOW! - Ep 1242", "Simply Cyber"),
                                 ("cert", "Protecting Data - CompTIA Security+ SY0-701 - 3.3", "Professor Messer")):
            ids[key] = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)", (yt, key, title, now(), now())).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id, channel_title) VALUES (?, ?, ?)", (ids[key], f"{key:x<11}", chan))
        topics.classify(db, list(ids.values()))
        got = lambda k: {r[0] for r in db.execute("SELECT t.name FROM article_topics x JOIN topics t ON t.id = x.topic_id WHERE x.article_id = ?", (ids[k],))}
        assert "Conferences & talks" in got("talk")
        assert "Cyber news" in got("news")
        assert "Certifications & study" in got("cert")


def test_backfill_uses_real_title_not_deleted_placeholder(authed):
    """The uploads playlist can list a public video as "Deleted video" (no thumbnail): the video's own details win;
    one that YouTube really doesn't return is skipped. Stored placeholders are repaired once."""
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    feed = add_source(authed, {"kind": "youtube", "channel_id": CH})
    ph = {"title": "Deleted video", "publishedAt": "2025-02-01T00:00:00Z", "channelTitle": "John Hammond", "thumbnails": {}}
    items = {"items": [{"snippet": ph, "contentDetails": {"videoId": "LIVEVIDEO01", "videoPublishedAt": "2025-02-01T00:00:00Z"}},
                       {"snippet": ph, "contentDetails": {"videoId": "GONEVIDEO01", "videoPublishedAt": "2025-02-02T00:00:00Z"}}]}
    details = {"items": [{"id": "LIVEVIDEO01", "contentDetails": {"duration": "PT10M"}, "statistics": {"viewCount": "5"},
                          "snippet": {"title": "Kubernetes on bare metal", "description": "",
                                      "thumbnails": {"high": {"url": "https://i.ytimg.com/vi/LIVEVIDEO01/hq.jpg"}}}}]}
    fake, p = patch_net({"playlistItems": resp(items), "/videos?": resp(details)})
    authed.put(f"/api/v1/feeds/{feed['id']}/retention", json={"retention_days": 0})
    from app import history

    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/backfill", json={"max_pages": 1}).status_code == 200
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "done", history.backfill_job.status
    assert any("part=snippet" in c["url"] for c in fake.calls if "/videos?" in c["url"])
    got = authed.get(f"/api/v1/library/videos?feed_id={feed['id']}").json()["items"]
    assert [v["title"] for v in got] == ["Kubernetes on bare metal"] and got[0]["thumbnail"].endswith("/hq.jpg")
    assert authed.get("/api/v1/library/videos?q=kubernetes").json()["total"] == 1

    # an old placeholder already in the database gets repaired
    from app import sources
    from app.db import get_db

    with get_db() as db:
        aid = db.execute("SELECT article_id FROM videos WHERE video_id = 'LIVEVIDEO01'").fetchone()[0]
        db.execute("UPDATE articles SET title = 'Deleted video' WHERE id = ?", (aid,))
    fake, p = patch_net({"/videos?": resp(details)})
    with p, get_db() as db:
        assert sources.repair_placeholder_titles(db, sources.yt_key()) == {"placeholders": 1, "fixed": 1, "gone": 0}
    assert authed.get("/api/v1/library/videos?q=kubernetes").json()["total"] == 1


def test_added_playlist_is_kept_whole_and_follow_only_loads_nothing(authed):
    """A playlist added with a channel time frame ("last year") still gets every video, however old; Keep with
    load=false only sets the time frame (Follow the channel alone = new uploads only, no back-catalogue)."""
    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    pl = add_source(authed, {"kind": "youtube", "playlist_id": "PLljFlTO9rB17E0hOetV_R4Lc0WbEy8q_Y"})
    old = {"items": [{"snippet": {"title": f"2019 talk {i}", "publishedAt": "2019-03-01T00:00:00Z", "channelTitle": "SO"},
                      "contentDetails": {"videoId": f"OLDTALK000{i}", "videoPublishedAt": "2019-03-01T00:00:00Z"}} for i in range(3)]}
    fake, p = patch_net({"playlistItems": resp(old), "/videos?": resp({"items": []})})
    from app import history

    with p:
        r = authed.post("/api/v1/history/backfill-all", json={"feed_ids": [pl["id"]], "max_pages": 10, "only_missing": False,
                                                               "keep_forever": False, "since_days": 365, "whole_playlists": True})
        assert r.status_code == 200 and r.json()["started"], r.text
        history.backfill_job._thread.join(10)
    assert authed.get(f"/api/v1/library/videos?feed_id={pl['id']}").json()["total"] == 3
    from app.db import get_db

    with get_db() as db:
        assert db.execute("SELECT retention_days FROM feeds WHERE id = ?", (pl["id"],)).fetchone()[0] == 0

    ch = add_source(authed, {"kind": "youtube", "channel_id": CH})
    fake, p = patch_net({})
    with p:
        r = authed.post("/api/v1/library/keep", json={"feed_ids": [ch["id"]], "days": 365, "load": False})
    assert r.status_code == 200 and r.json()["loading"] is False and not fake.calls


def test_channel_named_from_its_videos_when_feed_title_is_a_url(authed):
    """A channel added while YouTube's feed was down kept its feed URL as its name: the channels menu uses the
    videos' channel name, and the start-up repair renames the feed (a name you set yourself is kept)."""
    import json as _json

    from app.db import get_db, now
    from app.main import _name_untitled_youtube_feeds

    url = "https://www.youtube.com/feeds/videos.xml?channel_id=UCVThyXNYXDC9UhDbI8LtghQ"
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                         (url, url, now(), _json.dumps({"kind": "youtube", "channel_id": "UCVThyXNYXDC9UhDbI8LtghQ"}))).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 'g1', 'Guide', ?, ?)",
                         (fid, now(), now())).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id, channel_id, channel_title) VALUES (?, 'v1', ?, ?)",
                   (aid, "UCVThyXNYXDC9UhDbI8LtghQ", "Proton Guides & Updates"))
    titles = [c["title"] for c in authed.get("/api/v1/library/meta").json()["channels"]]
    assert "Proton Guides & Updates" in titles and url not in titles
    with get_db() as db:
        _name_untitled_youtube_feeds(db)
        assert db.execute("SELECT title FROM feeds WHERE id = ?", (fid,)).fetchone()[0] == "Proton Guides & Updates"
        db.execute("UPDATE feeds SET title = 'https://mine', custom_title = 1 WHERE id = ?", (fid,))
        _name_untitled_youtube_feeds(db)
        assert db.execute("SELECT title FROM feeds WHERE id = ?", (fid,)).fetchone()[0] == "https://mine"


def test_retention_chosen_when_adding_and_shown_for_channels(authed):
    """Add feed → Keep: the feed is created with that retention; the channels menu reports each channel's retention
    (its own, else the global setting); out-of-range values are refused."""
    ch = add_source(authed, {"kind": "youtube", "channel_id": CH}, retention_days=365)
    from unittest import mock

    with mock.patch("app.api.content._refresh_async"):
        tg = authed.post("/api/v1/feeds", json={"url": "https://ignored.example/", "retention_days": 30,
                                                 "source": {"kind": "telegram", "channel": "durov"}})
    assert tg.status_code == 201, tg.text
    details = lambda fid: authed.get(f"/api/v1/feeds/{fid}/details").json()  # noqa: E731
    assert details(ch["id"])["retention_days"] == 365 and details(tg.json()["id"])["effective"]["retention_days"] == 30
    meta = authed.get("/api/v1/library/meta").json()["channels"]
    c = next(c for c in meta if c["key"] == CH)
    assert c["retention_days"] == 365 and c["feeds"][0]["retention_days"] == 365
    with mock.patch("app.api.content._refresh_async"):
        for bad in (-1, 36501, "lots"):
            r = authed.post("/api/v1/feeds", json={"url": "https://x.example/feed", "retention_days": bad})
            assert r.status_code == 422, (bad, r.text)
    # a channel added without a choice keeps everything (videos are a library, not news)
    other = add_source(authed, {"kind": "youtube", "channel_id": "UCaaaaaaaaaaaaaaaaaaaaaa"})
    assert details(other["id"])["retention_days"] == 0


def test_unwatching_is_audit_logged(authed, caplog):
    """Watched → unwatched (and bulk unread) leave an audit line, so a Watched list that empties can be traced."""
    import logging

    from app.db import get_db, now

    feed = add_source(authed, {"kind": "youtube", "channel_id": CH})
    with get_db() as db:
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, is_read) VALUES (?, 'gw', 'Watched one', ?, ?, 1)",
                         (feed["id"], now(), now())).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, 'vw1')", (aid,))
    with caplog.at_level(logging.INFO):
        assert authed.patch(f"/api/v1/articles/{aid}", json={"is_read": False}).json()["is_read"] == 0
        assert authed.post("/api/v1/articles/bulk", json={"ids": [aid], "action": "unread"}).status_code == 200
    text = caplog.text
    assert "event=video_unwatched" in text and f"article_id='{aid}'" in text and "event=articles_marked_unread" in text


def test_video_cards_carry_channel_id(authed):
    """Each video says which channel it's from, so its channel name can open "follow this channel"."""
    from app.db import get_db, now

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Saved YouTube videos', 'https://saved.invalid/', ?, 'youtube', '{}')",
                         (now(),)).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 'yt:video:abcdefghijk', 'One video', ?, ?)",
                         (fid, now(), now())).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id, channel_id, channel_title) VALUES (?, 'abcdefghijk', ?, 'Some Channel')", (aid, CH))
    item = authed.get(f"/api/v1/library/videos?feed_id={fid}").json()["items"][0]
    assert item["channel_id"] == CH and item["channel_title"] == "Some Channel"


def test_channel_groups(authed):
    """Channel groups: create with channels, add more, replace, rename, delete (channels stay); bad keys refused;
    the group's channels filter the library together."""
    from app.db import get_db, now

    a, b = CH, "UCaaaaaaaaaaaaaaaaaaaaaa"
    with get_db() as db:
        for n, cid in enumerate((a, b)):
            fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                             (f"Chan {n}", f"https://y/{n}", now(), json.dumps({"kind": "youtube", "channel_id": cid}))).lastrowid
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, 'v', ?, ?)", (fid, f"g{n}", now(), now())).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id, channel_id) VALUES (?, ?, ?)", (aid, f"vid{n}", cid))
    g = authed.post("/api/v1/library/channel-groups", json={"name": "Podcasts", "channels": [a]})
    assert g.status_code == 201 and g.json()["channels"] == [a]
    gid = g.json()["id"]
    assert authed.post("/api/v1/library/channel-groups", json={"name": "podcasts"}).status_code == 409      # names are unique
    assert authed.patch(f"/api/v1/library/channel-groups/{gid}", json={"add": [b, a]}).json()["channels"] == sorted([a, b])
    meta = authed.get("/api/v1/library/meta").json()["channel_groups"]
    assert meta == [{"id": gid, "name": "Podcasts", "channels": sorted([a, b])}]
    assert authed.get(f"/api/v1/library/videos?channels={a},{b}").json()["total"] == 2
    assert authed.patch(f"/api/v1/library/channel-groups/{gid}", json={"channels": [b], "name": "Talk shows"}).json() == \
        {"id": gid, "name": "Talk shows", "channels": [b]}
    for bad in ({"add": ["evil;drop"]}, {"channels": ["UCshort"]}, {"name": ""}):
        assert authed.patch(f"/api/v1/library/channel-groups/{gid}", json=bad).status_code == 422, bad
    assert authed.delete(f"/api/v1/library/channel-groups/{gid}").status_code == 200
    assert authed.get("/api/v1/library/meta").json()["channel_groups"] == []
    assert authed.get(f"/api/v1/library/videos?channels={a}").json()["total"] == 1     # the channel itself stays
    assert authed.patch("/api/v1/library/channel-groups/999999", json={"name": "x"}).status_code == 404


def test_favorite_channels(authed):
    """★ channels one or many at once, ☆ them again; meta says which are favourites; bad keys refused."""
    from app.db import get_db, now

    a, b = CH, "UCbbbbbbbbbbbbbbbbbbbbbb"
    with get_db() as db:
        for n, cid in enumerate((a, b)):
            fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                             (f"Fav {n}", f"https://f/{n}", now(), json.dumps({"kind": "youtube", "channel_id": cid}))).lastrowid
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, 'v', ?, ?)", (fid, f"fg{n}", now(), now())).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id, channel_id) VALUES (?, ?, ?)", (aid, f"fvid{n}", cid))
    favs = lambda: {c["key"]: c["favorite"] for c in authed.get("/api/v1/library/meta").json()["channels"]}
    assert favs() == {a: False, b: False}
    assert authed.post("/api/v1/library/favorite-channels", json={"channels": [a, b, a]}).json()["favorites"] == sorted([a, b])
    assert favs() == {a: True, b: True}
    assert authed.post("/api/v1/library/favorite-channels", json={"channels": [b], "favorite": False}).json()["favorites"] == [a]
    assert favs() == {a: True, b: False}
    for bad in ({"channels": []}, {"channels": ["evil;drop"]}, {"channels": [a], "extra": 1}, {"channels": [a], "favorite": "yes"}):
        assert authed.post("/api/v1/library/favorite-channels", json=bad).status_code == 422, bad


def test_playlist_read_in_full_every_six_hours(authed):
    """The playlist feed lists only the first 15 videos: with a key, a playlist is read in full (new videos added
    at the end arrive), then not again for 6 hours."""
    from app import sources

    fake, p = patch_net({"videos?": resp({"items": [{"id": "dQw4w9WgXcQ"}]})})
    with p:
        authed.put("/api/v1/integrations/youtube", json={"api_key": "test-youtube-key-abcdefghijklmnopqrstu"})
    feed = add_source(authed, {"kind": "youtube", "playlist_id": "PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz"})
    items = {"items": [{"snippet": {"title": f"Part {i}", "publishedAt": "2025-01-01T00:00:00Z", "channelTitle": "Course"},
                        "contentDetails": {"videoId": f"PART{i:07d}", "videoPublishedAt": "2025-01-01T00:00:00Z"}} for i in range(20)]}
    fake, p = patch_net({"playlistItems": resp(items), "/videos?": resp({"items": []}), "feeds/videos.xml": resp(YT_RSS, ctype="application/atom+xml")})
    with p:
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["ok"]
        first = sum("playlistItems" in c["url"] for c in fake.calls)
        authed.post(f"/api/v1/feeds/{feed['id']}/refresh")                       # within 6 hours: the feed, not the API
        second = sum("playlistItems" in c["url"] for c in fake.calls)
    assert first == 1 and second == 1
    assert authed.get(f"/api/v1/library/videos?feed_id={feed['id']}&limit=100").json()["total"] >= 20   # parts 16-20 too
    assert sources.get_state("yt_playlist_full:PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz")


def test_articles_tab_is_articles_only(authed):
    """Videos, podcast episodes and account posts live in their own tabs: they are not in the Articles lists, totals,
    collection counts or folder views, and a folder that only holds such feeds is flagged so the sidebar leaves it out."""
    from app.db import get_db, now

    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES ('YouTube', 0)")
        db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES ('Mixed', 1)")
        yt_folder = db.execute("SELECT id FROM folders WHERE name = 'YouTube'").fetchone()[0]
        mixed = db.execute("SELECT id FROM folders WHERE name = 'Mixed'").fetchone()[0]
        rss = db.execute("INSERT INTO feeds (title, url, created_at, folder_id) VALUES ('Blog', 'https://b.example/rss', ?, ?)", (now(), mixed)).lastrowid
        yt = db.execute("INSERT INTO feeds (title, url, created_at, kind, source, folder_id) VALUES ('Some Channel', 'https://y.example/', ?, 'youtube', '{}', ?)",
                        (now(), yt_folder)).lastrowid
        pod = db.execute("INSERT INTO feeds (title, url, created_at, kind, folder_id) VALUES ('Show', 'https://p.example/rss', ?, 'podcast', ?)", (now(), mixed)).lastrowid
        acct = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES ('@someone', 'https://m.example/@someone.rss', ?, 'mastodon')",
                          (now(),)).lastrowid
        tag = db.execute("INSERT INTO tags (name, color) VALUES ('Probe', '#112233')").lastrowid
        for fid, g in ((rss, "a1"), (yt, "v1"), (pod, "e1"), (acct, "p1")):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)", (fid, g, g, now(), now())).lastrowid
            db.execute("INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'manual', ?)", (aid, tag, now()))
    sb = authed.get("/api/v1/sidebar").json()
    folders = {f["name"]: (f["article_feeds"], f["other_feeds"]) for f in sb["folders"]}
    assert folders["YouTube"] == (0, 1) and folders["Mixed"] == (1, 1)          # the sidebar skips (0, n>0) folders
    assert [f["id"] for f in sb["feeds"]] == [rss]                               # article feeds only - no account, channel or show
    assert [(m["id"], m["section"]) for m in sb["media_feeds"]] == [(pod, "podcasts"), (yt, "videos")]
    assert [a["id"] for a in sb["account_feeds"]] == [acct]
    assert sb["counts"]["total"] == 1 and sb["counts"]["unread"] == 1
    assert next(t for t in sb["tags"] if t["name"] == "Probe")["total"] == 1
    titles = lambda q: [a["title"] for a in authed.get(f"/api/v1/articles?{q}").json()["items"]]  # noqa: E731
    assert titles("unread=true") == ["a1"] and titles("") == ["a1"] and titles(f"tag_id={tag}") == ["a1"]
    assert titles(f"folder_id={mixed}") == ["a1"] and titles(f"folder_id={yt_folder}") == []
    assert titles(f"feed_id={yt}") == ["v1"] and titles(f"feed_id={acct}") == ["p1"]   # an explicit feed id still opens its items (API)


def test_favorite_topics(authed):
    """★ topics one or many at once, ☆ them again; meta marks them; unknown ids ignored; bad input refused."""
    topics = authed.get("/api/v1/library/meta").json()["topics"]
    a, b = topics[0]["id"], topics[1]["id"]
    assert not any(t["favorite"] for t in topics)
    assert authed.post("/api/v1/library/favorite-topics", json={"topic_ids": [a, b, a, 999999]}).json()["favorites"] == sorted([a, b])
    favs = {t["id"] for t in authed.get("/api/v1/library/meta").json()["topics"] if t["favorite"]}
    assert favs == {a, b}
    assert authed.post("/api/v1/library/favorite-topics", json={"topic_ids": [b], "favorite": False}).json()["favorites"] == [a]
    for bad in ({"topic_ids": []}, {"topic_ids": ["x"]}, {"topic_ids": [0]}, {"topic_ids": [a], "favorite": "yes"}, {"topic_ids": [a], "x": 1}):
        assert authed.post("/api/v1/library/favorite-topics", json=bad).status_code == 422, bad
