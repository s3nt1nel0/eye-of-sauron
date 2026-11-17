"""Smart features: story grouping, ATT&CK name clean-up + "not this technique", entity pages, technique matrix."""

import json
from unittest import mock

from app import attack_sync, entities, stories
from app.db import get_db, now


def feed(n):
    with get_db() as db:
        return db.execute("INSERT INTO feeds (title, url, created_at) VALUES (?, ?, ?)", (f"Feed {n}", f"https://f{n}.example/rss", now())).lastrowid


def article(fid, title, text="", ts=None):
    ts = ts or now()
    with get_db() as db:
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                         (fid, f"{fid}:{title}", title, text, ts, ts)).lastrowid
        entities.invalidate()
        entities.extract_for_articles(db, [aid])
        stories.assign(db, [aid])
    return aid


def seed_techniques():
    """A tiny stored ATT&CK release + its watchlist, as a sync would leave them."""
    rows = [("T1669", "Wi-Fi Networks", ["Initial Access"]), ("T1498", "Network Denial of Service", ["Impact"]),
            ("T1055", "Process Injection", ["Privilege Escalation", "Stealth"]), ("T1566", "Phishing", ["Initial Access"])]
    with get_db() as db:
        for tid, name, tactics in rows:
            db.execute("INSERT INTO attack_techniques (id, name, tactics, domain, url) VALUES (?, ?, ?, 'enterprise-attack', ?)",
                       (tid, name, json.dumps(tactics), f"https://attack.mitre.org/techniques/{tid}"))
        db.execute("INSERT INTO attack_groups (id, name, aliases, description, domains, url) VALUES ('G0007', 'APT28', '[]', 'A group.', '[]', 'https://attack.mitre.org/groups/G0007')")
        db.execute("INSERT INTO attack_group_techniques (group_id, technique_id) VALUES ('G0007', 'T1055')")
        attack_sync._watchlist(db, attack_sync.TECH_SLUG, "MITRE ATT&CK techniques", "x")
    with mock.patch("app.attack_sync.entities.reindexer.request"):
        attack_sync.refresh_aliases()
    entities.invalidate()


# ------------------------------------------------------------------ stories
def test_same_story_rules():
    w = stories.words
    a = w("Microsoft patches actively exploited Windows kernel zero-day")
    assert stories.same_story(a, w("Microsoft patches Windows kernel zero-day exploited in the wild"), 0.6)
    assert not stories.same_story(a, w("Google patches actively exploited Chrome zero-day"), 0.6)
    assert not stories.same_story(w("CVE-2026-1234 SQL injection in Acme Portal plugin"), w("CVE-2026-5678 SQL injection in Acme Portal plugin"), 0.6)
    assert not stories.same_story(w("Weekly recap"), w("Weekly recap"), 0.5)  # too short to judge


def test_stories_group_across_feeds_and_fold_in_the_api(authed):
    stories.reset_live()
    f1, f2, f3 = feed(1), feed(2), feed(3)
    a = article(f1, "Akira ransomware gang breaches Acme Hospital network and leaks patient data")
    b = article(f2, "Akira ransomware breaches Acme Hospital network, leaks patient data")
    same_feed = article(f1, "Akira ransomware gang breaches Acme Hospital network and leaks patient data again")
    other = article(f3, "Researchers publish a new method for detecting kernel rootkits on Linux servers")
    items = {x["id"]: x for x in authed.get("/api/v1/articles?limit=50").json()["items"]}
    assert items[a]["story_id"] == a and items[b]["story_id"] == a and items[a]["story_count"] == items[b]["story_count"]
    assert items[other]["story_id"] is None and items[other]["story_count"] == 1
    assert items[same_feed]["story_id"] in (None, a)  # the same feed alone never starts a story
    members = authed.get(f"/api/v1/articles/{b}/story").json()["items"]
    assert {m["id"] for m in members} >= {a, b} and members[0]["feed_title"] == "Feed 1"
    assert authed.get(f"/api/v1/articles/{other}/story").json() == {"items": []}
    assert authed.get("/api/v1/articles/999999/story").status_code == 404
    # switching it off: nothing is attached, and a regroup clears the ids
    assert authed.patch("/api/v1/settings", json={"story_grouping": False}).status_code == 200
    stories.rebuild()
    off = authed.get("/api/v1/articles?limit=50").json()["items"]
    assert all(x["story_id"] is None and "story_count" not in x for x in off)
    # back on: the regroup finds the story again
    with mock.patch("app.stories.rebuilder.start"):
        authed.patch("/api/v1/settings", json={"story_grouping": True, "story_match": "loose"})
    assert stories.rebuild()["grouped"] >= 1
    assert authed.patch("/api/v1/settings", json={"story_match": "sloppy"}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"matrix_days": True}).status_code == 422
    stories.reset_live()


# ------------------------------------------------------------------ ATT&CK names
def test_generic_names_and_everyday_terms(authed):
    seed_techniques()
    assert not attack_sync.matchable("Wi-Fi Networks") and not attack_sync.matchable("Phishing") and attack_sync.matchable("Process Injection")
    f = feed(1)
    wifi = article(f, "Free Wi-Fi networks arrive at the airport", "Travellers get free Wi-Fi networks.")
    ddos = article(f, "Record DDoS attack hits a bank", "The DDoS attack lasted an hour.")
    by_id = article(f, "Report mentions T1669 explicitly")
    ttps = lambda aid: [t["id"] for t in authed.get(f"/api/v1/articles/{aid}").json()["ttps"]]  # noqa: E731
    assert ttps(wifi) == [] and ttps(ddos) == ["T1498"] and ttps(by_id) == ["T1669"]
    # everyday terms off: only official names and IDs
    with mock.patch("app.api.automation.threading.Thread") as thread:
        assert authed.patch("/api/v1/settings", json={"ttp_everyday_terms": False}).status_code == 200
        assert thread.call_args.kwargs["target"] is attack_sync.refresh_aliases
    with mock.patch("app.attack_sync.entities.reindexer.request") as req:
        attack_sync.refresh_aliases()
        assert req.called
    with get_db() as db:
        aliases = json.loads(db.execute("SELECT aliases FROM entities WHERE name = 'Network Denial of Service (T1498)'").fetchone()[0])
    assert aliases == ["T1498", "Network Denial of Service"]


def test_not_this_technique_and_mute(authed):
    seed_techniques()
    f = feed(1)
    a = article(f, "Malware uses process injection to hide", "Process Injection again.")
    b = article(f, "Another loader relies on process injection")
    url = "/api/v1/attack/techniques/T1055"
    why = authed.get(f"{url}/why?article_id={a}").json()
    assert why["names"] == ["Process Injection"] and why["ids"] == []
    # this article only
    assert authed.post(f"{url}/reject", json={"article_id": a}).json() == {"ok": True, "muted": None}
    assert authed.get(f"/api/v1/articles/{a}").json()["ttps"] == []
    with get_db() as db:  # a re-index never adds it back
        entities.invalidate()
        entities.extract_for_articles(db, [a])
    assert authed.get(f"/api/v1/articles/{a}").json()["ttps"] == []
    assert [t["id"] for t in authed.get(f"/api/v1/articles/{b}").json()["ttps"]] == ["T1055"]
    # mute the name everywhere
    assert authed.post(f"{url}/reject", json={"article_id": b, "mute": "T1055"}).status_code == 422  # IDs always match
    assert authed.post(f"{url}/reject", json={"article_id": b, "mute": "not a name"}).status_code == 422
    with mock.patch("app.api.attack.entities.reindexer.request") as thread:
        assert authed.post(f"{url}/reject", json={"article_id": b, "mute": "process injection"}).status_code == 200
        assert thread.called
    assert authed.get("/api/v1/attack/muted").json()["items"] == [
        {"technique": "T1055", "technique_name": "Process Injection (T1055)", "name": "Process Injection"}]
    c = article(f, "A third sample with process injection")
    assert authed.get(f"/api/v1/articles/{c}").json()["ttps"] == []
    with mock.patch("app.attack_sync.entities.reindexer.request"):
        attack_sync.refresh_aliases()  # a refresh / MITRE sync keeps the mute
    assert len(authed.get("/api/v1/attack/muted").json()["items"]) == 1
    # restore
    with mock.patch("app.api.attack.entities.reindexer.request"):
        assert authed.post("/api/v1/attack/muted/restore", json={"technique": "T1055", "name": "Process Injection"}).json() == {"ok": True}
        assert authed.post("/api/v1/attack/muted/restore", json={"technique": "T1055", "name": "Process Injection"}).status_code == 404
    d = article(f, "A fourth sample with process injection")
    assert [t["id"] for t in authed.get(f"/api/v1/articles/{d}").json()["ttps"]] == ["T1055"]
    assert authed.post("/api/v1/attack/techniques/T9999/reject", json={"article_id": a}).status_code == 404
    assert authed.post("/api/v1/attack/techniques/bad/reject", json={"article_id": a}).status_code == 422
    assert authed.post(f"{url}/reject", json={"article_id": 999999}).status_code == 404


def test_refile_removes_only_rule_filed_articles(authed):
    from app.rules import apply_rules, refile_tags

    f = feed(1)
    a = article(f, "Free Wi-Fi networks arrive at the airport")
    b = article(f, "Another Wi-Fi networks story")
    tag = authed.post("/api/v1/tags", json={"name": "Probe", "color": "#112233"}).json()["id"]
    with get_db() as db:
        rid = db.execute("INSERT INTO rules (name, keywords, exclude_keywords, match_in, tag_id, position) "
                         "VALUES ('r', '[\"Wi-Fi Networks\"]', '[]', 'title_content', ?, 1)", (tag,)).lastrowid
        apply_rules(db, [a, b], rule_ids=[rid])
        db.execute("UPDATE article_tags SET source = 'manual' WHERE article_id = ?", (b,))
        db.execute("UPDATE rules SET keywords = '[\"T1669\"]' WHERE id = ?", (rid,))
    assert refile_tags([tag]) == 1
    with get_db() as db:
        assert [r[0] for r in db.execute("SELECT article_id FROM article_tags WHERE tag_id = ?", (tag,))] == [b]


# ------------------------------------------------------------------ entity page + matrix
def test_entity_page_matrix_and_entity_filter(authed):
    seed_techniques()
    f = feed(1)
    with get_db() as db:
        video_feed = db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('Channel', 'https://yt.example/x', 'youtube', ?)", (now(),)).lastrowid
        wl = db.execute("INSERT INTO watchlists (name, slug, description) VALUES ('Actors', NULL, '')").lastrowid
        actor = db.execute("INSERT INTO entities (watchlist_id, name, aliases) VALUES (?, 'Lazarus Group', '[\"Hidden Cobra\"]')", (wl,)).lastrowid
    entities.invalidate()
    a = article(f, "Lazarus Group uses process injection in new campaign")
    article(video_feed, "Video: tracking Hidden Cobra")
    article(f, "Old story about Lazarus Group", ts=now() - 200 * 86400)
    everything = authed.get(f"/api/v1/entities/{actor}/page?days=0").json()
    assert everything["totals"] == {"articles": 2, "videos": 1, "podcasts": 0, "posts": 0} and everything["all_time"] == 3
    assert sum(b["n"] for b in everything["timeline"]) == 3 and everything["step"] == 30 * 86400
    # a period: every number on the page is for that period (the 200-day-old article is out)
    page = authed.get(f"/api/v1/entities/{actor}/page?days=90").json()
    assert page["totals"] == {"articles": 1, "videos": 1, "podcasts": 0, "posts": 0} and page["all_time"] == 3
    assert len(page["latest"]["articles"]) == 1 and len(authed.get(f"/api/v1/entities/{actor}/page?days=7").json()["timeline"]) == 7
    assert sum(b["n"] for b in page["timeline"]) == 2 and page["step"] == 7 * 86400
    assert [x["id"] for x in page["latest"]["articles"]][0] == a and len(page["latest"]["videos"]) == 1
    assert any(r["name"] == "Process Injection (T1055)" for r in page["related"]) and page["mitre"] is None
    assert authed.get(f"/api/v1/entities/{actor}/page?days=12").status_code == 422
    assert authed.get("/api/v1/entities/999999/page").status_code == 404
    with get_db() as db:
        tech = db.execute("SELECT id FROM entities WHERE name = 'Process Injection (T1055)'").fetchone()[0]
    with get_db() as db:  # two sub-techniques; the technique is recognised by the first one's name
        db.execute("INSERT INTO attack_techniques (id, name, tactics, domain, is_subtechnique, url) VALUES "
                   "('T1055.012', 'Process Hollowing', '[]', 'enterprise-attack', 1, ''), ('T1055.001', 'Thread Hijack Trick', '[]', 'enterprise-attack', 1, '')")
    with mock.patch("app.attack_sync.entities.reindexer.request"):
        attack_sync.refresh_aliases()
    entities.invalidate()
    article(f, "Loader combines process hollowing with other tricks", "It is also catalogued as T1055.012.")
    with get_db() as db:
        db.execute("INSERT INTO articles_fts(articles_fts) VALUES ('rebuild')")
    tpage = authed.get(f"/api/v1/entities/{tech}/page?days=30").json()
    assert [(s["id"], s["n"]) for s in tpage["mitre"]["subtechniques"]] == [("T1055.012", 1), ("T1055.001", 0)]
    assert tpage["mitre"]["kind"] == "technique" and tpage["mitre"]["groups"][0]["id"] == "G0007" and tpage["step"] == 86400
    # the reader lists what the article mentions (not the technique lists), and the setting hides it
    detail = authed.get(f"/api/v1/articles/{a}").json()
    assert [e["name"] for e in detail["entities"]] == ["Lazarus Group"]
    authed.patch("/api/v1/settings", json={"entity_chips": False})
    assert authed.get(f"/api/v1/articles/{a}").json()["entities"] == []
    # entity filter: Reader articles only
    listed = authed.get(f"/api/v1/articles?entity_id={actor}").json()
    assert listed["total"] == 2
    # matrix
    m = authed.get("/api/v1/attack/matrix?framework=attack&days=30").json()
    cols = {t["name"]: t for t in m["tactics"]}
    assert len(m["tactics"]) == 15 and m["max"] == 2
    assert [(x["id"], x["n"]) for x in cols["Stealth"]["techniques"]] == [("T1055", 2)]
    assert cols["Privilege Escalation"]["total"] == 2 and cols["Initial Access"]["total"] == 0
    assert authed.get("/api/v1/attack/matrix?framework=atlas&days=0").json()["tactics"][4]["name"] == "AI Model Access"
    assert authed.get("/api/v1/attack/matrix?framework=attack&days=5").status_code == 422
    assert authed.get("/api/v1/attack/matrix?framework=other").status_code == 422


def test_new_routes_need_a_session(client):
    for path in ("/api/v1/attack/matrix?framework=attack", "/api/v1/attack/muted", "/api/v1/entities/1/page", "/api/v1/articles/1/story",
                 "/api/v1/attack/techniques/T1055/why?article_id=1"):
        assert client.get(path).status_code == 401, path
    assert client.post("/api/v1/attack/techniques/T1055/reject", json={"article_id": 1}).status_code in (401, 403)
    assert client.post("/api/v1/attack/muted/restore", json={"technique": "T1055", "name": "x"}).status_code in (401, 403)


def test_videos_and_podcasts_can_be_listed_by_what_they_mention(authed):
    seed_techniques()
    with get_db() as db:
        yt = db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('Chan', 'https://yt.example/c', 'youtube', ?)", (now(),)).lastrowid
        pod = db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES ('Show', 'https://pod.example/rss', 'podcast', ?)", (now(),)).lastrowid
    vid = article(yt, "Talk: process injection in depth", ts=now() - 3 * 86400)
    old = article(yt, "Older talk on process injection", ts=now() - 200 * 86400)
    other = article(yt, "Unrelated video about gardening")
    ep = article(pod, "Episode 12: process injection explained")
    article(pod, "Episode 13: nothing to see")
    with get_db() as db:
        for i, a in enumerate((vid, old, other)):
            db.execute("INSERT INTO videos (article_id, video_id, channel_title) VALUES (?, ?, 'Chan')", (a, f"vid{i:08d}"))
        db.execute("UPDATE articles SET is_read = 1 WHERE id = ?", (old,))
        for a in (ep, ep + 1):
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://pod.example/a.mp3')", (a,))
    eid = authed.get("/api/v1/attack/techniques/T1055/entity").json()["entity_id"]
    page = authed.get(f"/api/v1/entities/{eid}/page?days=30").json()
    assert page["totals"]["videos"] == 1 and page["totals"]["podcasts"] == 1
    got = authed.get(f"/api/v1/library/videos?entity_id={eid}&days=30").json()
    assert got["total"] == 1 and [v["id"] for v in got["items"]] == [vid]                   # the page's number, the page's period
    assert sorted(v["id"] for v in authed.get(f"/api/v1/library/videos?entity_id={eid}").json()["items"]) == sorted([vid, old])
    assert authed.get("/api/v1/library/videos").json()["total"] == 3                          # no entity: unchanged
    eps = authed.get(f"/api/v1/podcasts/episodes?entity_id={eid}&days=30").json()
    assert eps["total"] == 1 and eps["items"][0]["id"] == ep
    assert authed.get("/api/v1/podcasts/episodes").json()["total"] == 2
    assert authed.get(f"/api/v1/library/topic-counts?entity_id={eid}").status_code == 200
    for url in ("/api/v1/library/videos?entity_id=0", "/api/v1/library/videos?entity_id=abc", f"/api/v1/library/videos?entity_id={eid}&days=5",
                "/api/v1/library/videos?entity_id=1%20OR%201=1", f"/api/v1/podcasts/episodes?entity_id={eid}&days=5", "/api/v1/podcasts/episodes?entity_id=-1"):
        assert authed.get(url).status_code == 422, url
    assert authed.get("/api/v1/library/videos?entity_id=999999").json()["total"] == 0
