"""Articles quality pass (2026-11-26): "title + opening lines" rules, stricter ready-made collections and their one-time
upgrade, and feeds whose server sends the feed inside a redirect to its home page."""

import json
from unittest import mock

import httpx

from app import collection_packs, netguard
from app.api import automation
from app.db import get_db, now

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>Jensen Huang returns as Nvidia CEO</title><link>https://n.example/a</link><guid>a1</guid>
<description><![CDATA[<p>Nvidia shares rose 30 per cent on Monday after the board reinstated its chief executive, a move investors had pushed
for since his resignation two weeks ago, when the company named its finance chief as interim head. Analysts said the
return removes uncertainty about the chip roadmap and the next product cycle, and the stock recovered most of its losses.</p>
<p>The board had sought assurance on the national security questions tied to the alleged Chinese espionage case.</p>]]></description></item>
<item><title>Volt Typhoon hackers breach water utility</title><link>https://n.example/b</link><guid>b1</guid>
<description>The China-linked group broke into the network of a US water utility.</description></item>
<item><title>Researchers detail new campaign</title><link>https://n.example/c</link><guid>c1</guid>
<description>A state-sponsored group used spear-phishing and a new backdoor against embassies, researchers said.</description></item>
</channel></rss>"""


def _refresh(authed, body=RSS, url="https://n.example/feed"):
    resp = netguard.SafeResponse(200, httpx.Headers({"content-type": "application/rss+xml"}), body, url)
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp):
        feed = authed.post("/api/v1/feeds", json={"url": url}).json()
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["ok"]
    return feed


def _in(authed, collection):
    tags = {t["name"]: t["id"] for t in authed.get("/api/v1/tags").json()}
    return {a["title"] for a in authed.get("/api/v1/articles", params={"tag_id": tags[collection], "limit": 50}).json()["items"]}


def test_apt_collection_needs_its_words_in_the_title_or_opening_lines(authed):
    assert authed.post("/api/v1/rules/starter-pack").status_code == 200
    _refresh(authed)
    apt = _in(authed, "APT & Nation-State")
    assert "Jensen Huang returns as Nvidia CEO" not in apt          # "espionage" only deep in the text
    assert "Volt Typhoon hackers breach water utility" in apt       # a named group
    assert "Researchers detail new campaign" in apt                # state-sponsored + backdoor in the opening lines


def test_title_opening_round_trips_through_the_api(authed):
    tag = authed.post("/api/v1/tags", json={"name": "Espionage"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "Esp", "keywords": ["espionage"], "match_in": "title_opening", "tag_id": tag})
    assert r.status_code == 201 and r.json()["match_in"] == "title_opening" and "opening_only" not in r.json()
    rid = r.json()["id"]
    with get_db() as db:
        row = db.execute("SELECT match_in, opening_only FROM rules WHERE id = ?", (rid,)).fetchone()
    assert tuple(row) == ("title_content", 1)
    put = authed.put(f"/api/v1/rules/{rid}", json={"name": "Esp", "keywords": ["espionage"], "match_in": "title_content", "tag_id": tag})
    assert put.json()["match_in"] == "title_content"
    assert authed.post("/api/v1/rules", json={"name": "X", "keywords": ["x"], "match_in": "body", "tag_id": tag}).status_code == 422


def _old_rule(name, spec, tag_id, **over):
    with get_db() as db:
        db.execute("INSERT INTO rules (name, keywords, exclude_keywords, require_keywords, match_in, tag_id, position) "
                   "VALUES (?, ?, ?, ?, 'title_content', ?, 1000)",
                   (name, json.dumps(over.get("keywords", spec.get("keywords", []))), json.dumps(spec.get("exclude", [])),
                    json.dumps(spec.get("require", [])), tag_id))


def test_upgrade_brings_unedited_pack_rules_up_to_date_once_and_leaves_edited_ones(authed):
    with get_db() as db:
        apt = db.execute("INSERT INTO tags (name, color) VALUES ('APT & Nation-State', '#000')").lastrowid
        mal = db.execute("INSERT INTO tags (name, color) VALUES ('Malware', '#000')").lastrowid
        db.execute("DELETE FROM sync_state WHERE key = 'pack_rules_rev'")
    _old_rule("Auto: APT & Nation-State", collection_packs.PREVIOUS["Auto: APT & Nation-State"], apt)
    _old_rule("Auto: Malware", collection_packs.PREVIOUS["Auto: Malware"], mal, keywords=["malware", "my own word"])  # edited
    with get_db() as db:  # filed by the old, loose rule
        fid = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('F', 'https://f.example/rss', ?)", (now(),)).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, 'g', ?, ?, ?, ?)",
                         (fid, "Nvidia CEO returns", "Long text. " * 80 + "a Chinese espionage case", now(), now())).lastrowid
        db.execute("INSERT INTO article_tags (article_id, tag_id, source, created_at) VALUES (?, ?, 'rule', ?)", (aid, apt, now()))
    result = automation.upgrade_pack_rules()
    assert result["upgraded"] == 2 and result["removed"] == 1      # APT rule + its new #2; the Nvidia filing is gone
    with get_db() as db:
        rows = {r["name"]: r for r in db.execute("SELECT * FROM rules")}
        assert rows["Auto: APT & Nation-State"]["opening_only"] == 1
        assert "Volt Typhoon" in json.loads(rows["Auto: APT & Nation-State"]["keywords"])
        assert rows["Auto: APT & Nation-State #2"]["tag_id"] == apt
        assert rows["Auto: Malware"]["opening_only"] == 0 and "my own word" in rows["Auto: Malware"]["keywords"]
    assert automation.upgrade_pack_rules() == {"upgraded": 0}       # once per pack revision


def test_feed_sent_inside_a_redirect_to_the_home_page_is_read(authed):
    home = netguard.SafeResponse(200, httpx.Headers({"content-type": "text/html"}), b"<html><body>Home</body></html>",
                                 "https://site.example/")
    redirect = netguard.SafeResponse(302, httpx.Headers({"content-type": "application/rss+xml", "location": "https://site.example/"}),
                                     RSS, "https://site.example/feed/")
    calls = []

    def fake(method, url, **kw):
        calls.append(kw.get("max_redirects", 5))
        return redirect if kw.get("max_redirects") == 0 else home

    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", side_effect=fake):
        feed = authed.post("/api/v1/feeds", json={"url": "https://site.example/feed/"}).json()
        res = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert res == {"ok": True, "error": None, "new": 3} and calls == [5, 0]
    # a redirect whose body is not a feed is still an error
    with mock.patch("app.api.content._refresh_async"), mock.patch(
            "app.fetcher.netguard.request", side_effect=lambda m, u, **kw: home if kw.get("max_redirects") != 0 else
            netguard.SafeResponse(302, httpx.Headers({"location": "https://other.example/"}), b"<html>moved</html>", u)):
        feed2 = authed.post("/api/v1/feeds", json={"url": "https://other.example/feed/"}).json()
        res2 = authed.post(f"/api/v1/feeds/{feed2['id']}/refresh").json()
    assert res2["ok"] is False and "parse" in res2["error"]
