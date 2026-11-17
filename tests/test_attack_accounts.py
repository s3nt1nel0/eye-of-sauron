"""MITRE ATT&CK sync, the Accounts tab, pack removal/update, and back-fill for chosen feeds."""

import json
import time
from unittest import mock

import httpx
import pytest

from app import accounts, attack_sync, netguard

NOW = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def resp(body, status=200, url="https://x.example/", ctype="application/json"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


# ------------------------------------------------------------------ ATT&CK
def bundle(groups, techniques, uses, domain="enterprise-attack"):
    src = {"enterprise-attack": "mitre-attack"}.get(domain, "mitre-attack")
    ref = lambda tid: [{"source_name": src, "external_id": tid, "url": f"https://attack.mitre.org/tactics/{tid}"}]  # noqa: E731
    objs = [{"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "x_mitre_shortname": "initial-access", "name": "Initial Access",
             "external_references": ref("TA0001")},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "x_mitre_shortname": "stealth", "name": "Stealth",
             "external_references": ref("TA0005")},
            # the matrix lists the tactics in kill-chain order (not the order of the objects)
            {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK",
             "tactic_refs": ["x-mitre-tactic--1", "x-mitre-tactic--2"]}]
    for gid, name, aliases in groups:
        objs.append({"type": "intrusion-set", "id": f"intrusion-set--{gid}", "name": name, "aliases": [name, *aliases],
                     "description": "A group (Citation: Vendor 2020). See [ref](https://example.org).", "modified": "2026-01-01",
                     "external_references": [{"source_name": src, "external_id": gid, "url": f"https://attack.mitre.org/groups/{gid}"}]})
    for tid, name, tactic, sub in techniques:
        objs.append({"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name, "x_mitre_is_subtechnique": sub,
                     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}], "modified": "2026-01-01",
                     "external_references": [{"source_name": src, "external_id": tid, "url": f"https://attack.mitre.org/techniques/{tid}"}]})
    objs.append({"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old", "revoked": True,
                 "external_references": [{"source_name": src, "external_id": "T9999"}]})
    for g, t in uses:
        objs.append({"type": "relationship", "id": f"relationship--{g}{t}", "relationship_type": "uses",
                     "source_ref": f"intrusion-set--{g}", "target_ref": f"attack-pattern--{t}"})
    return {"type": "bundle", "objects": objs}


def run_sync(release, monkeypatch, minimums=True):
    groups, techniques, uses = release
    index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"version": release_version[0], "modified": "x",
             "url": attack_sync.REPO + "enterprise-attack/enterprise-attack-1.json"}]}]}

    def fake(method, url, **kw):
        if url == attack_sync.INDEX_URL:
            return resp(index, url=url)
        assert url.startswith(attack_sync.REPO + "enterprise-attack/")
        return resp(bundle(groups, techniques, uses), url=url)

    if not minimums:
        monkeypatch.setattr(attack_sync, "_get", attack_sync._get)
    with mock.patch("app.attack_sync.netguard.request", side_effect=fake), \
            mock.patch.object(attack_sync.threading, "Thread") as thread:
        assert attack_sync.attack_sync.start(force=True)
        thread.call_args.kwargs["target"](*thread.call_args.kwargs["args"])


release_version = ["20.1"]
GROUPS = [(f"G{n:04d}", f"Group{n}", [f"Alias {n}"]) for n in range(101, 125)] + [("G0091", "Silence", ["Whisper Spider"]),
                                                                              ("G0007", "APT28", ["Fancy Bear", "STRONTIUM"])]
TECHS = [(f"T{3000 + n}", f"Technique Number {n}", "initial-access", False) for n in range(110)] + \
        [("T1566", "Phishing", "initial-access", False), ("T1566.001", "Spearphishing Attachment", "initial-access", True),
         ("T1027", "Obfuscated Files or Information", "stealth", False)]


@pytest.fixture()
def no_reindex():
    with mock.patch("app.attack_sync.entities.reindexer.request") as req:
        yield req


def test_attack_sync_builds_watchlists_and_collections(authed, monkeypatch, no_reindex):
    # the ATT&CK collections pack: one collection per tactic of the Enterprise matrix
    with mock.patch("app.api.automation.threading.Thread"):
        authed.post("/api/v1/rules/packs", json={"slugs": ["attack"]})
    run_sync((GROUPS, TECHS, [("G0007", "T1566"), ("G0007", "T1027")]), monkeypatch)
    st = authed.get("/api/v1/attack/status").json()
    assert st["counts"] == {"groups": 26, "techniques": 113, "relationships": 2}
    assert st["last_result"]["status"] == "updated" and st["versions"]["enterprise-attack"] == "20.1"
    lists = {w["name"]: w for w in authed.get("/api/v1/watchlists").json()}
    g = authed.get(f"/api/v1/watchlists/{lists['MITRE ATT&CK groups']['id']}").json()
    ents = {e["name"]: e["aliases"] for e in g["entities"]}
    assert ents["APT28 (G0007)"] == ["G0007", "APT28", "Fancy Bear", "STRONTIUM"]
    assert ents["Silence (G0091)"] == ["G0091", "Whisper Spider"]  # "Silence" alone would match ordinary text
    t = authed.get(f"/api/v1/watchlists/{lists['MITRE ATT&CK techniques']['id']}").json()
    tents = {e["name"]: e["aliases"] for e in t["entities"]}
    # ID, the everyday terms (ATTACK_TERMS), then the sub-techniques
    # ID, the everyday terms (ATTACK_TERMS), then everything the sub-techniques match through
    assert tents["Phishing (T1566)"] == ["T1566", *attack_sync.ATTACK_TERMS["T1566"], "T1566.001", "Spearphishing Attachment",
                                         *attack_sync.ATTACK_TERMS["T1566.001"]]
    # the sub-technique and the tactics have entities of their own
    assert tents["Spearphishing Attachment (T1566.001)"] == ["T1566.001", "Spearphishing Attachment", *attack_sync.ATTACK_TERMS["T1566.001"]]
    assert tents["Initial Access (TA0001)"] == ["TA0001", "Initial Access"]
    assert tents["Stealth (TA0005)"] == ["TA0005", *attack_sync.TACTIC_TERMS["stealth"]]  # a one-word name: ID and terms only
    detail = authed.get("/api/v1/attack/groups/G0007").json()
    assert [x["id"] for x in detail["techniques"]] == ["T1027", "T1566"] and "Citation" not in detail["description"]
    assert authed.get("/api/v1/attack/groups?q=fancy").json()["total"] == 1
    assert authed.get("/api/v1/attack/groups/X1").status_code == 422
    # no keyword rules; the collections are exactly the release's tactics, in MITRE's spelling and matrix order
    assert not [r for r in authed.get("/api/v1/rules").json() if r["name"].startswith("Auto: ATT&CK")]
    assert sorted(t["name"] for t in authed.get("/api/v1/tags").json() if t["name"].startswith("ATT&CK: ")) == [
        "ATT&CK: Initial Access", "ATT&CK: Stealth"]
    matrix = authed.get("/api/v1/attack/matrix?framework=attack&days=0").json()
    assert [(t["id"], t["name"]) for t in matrix["tactics"]] == [("TA0001", "Initial Access"), ("TA0005", "Stealth")]
    assert st["last_result"]["report"]["tactics"] == ["Initial Access", "Stealth"]

    # next release: one group gone, one new, an alias changed; user-added entities survive
    authed.post(f"/api/v1/watchlists/{lists['MITRE ATT&CK groups']['id']}/entities", json={"name": "My own actor", "aliases": []})
    release_version[0] = "20.2"
    new_groups = [x for x in GROUPS if x[0] != "G0101"] + [("G0200", "Brand New", [])]
    new_groups = [("G0007", "APT28", ["Fancy Bear", "STRONTIUM", "Forest Blizzard"]) if x[0] == "G0007" else x for x in new_groups]
    run_sync((new_groups, TECHS, []), monkeypatch)
    upd = authed.get("/api/v1/attack/status").json()["last_update"]["report"]
    assert upd["groups_added"] == ["Brand New (G0200)"] and upd["groups_removed"] == ["Group101 (G0101)"]
    assert "APT28 (G0007)" in upd["groups_updated"]
    names = {e["name"] for e in authed.get(f"/api/v1/watchlists/{lists['MITRE ATT&CK groups']['id']}").json()["entities"]}
    assert "My own actor" in names and "Group101 (G0101)" not in names and "Brand New (G0200)" in names
    release_version[0] = "20.1"


def test_attack_sync_rejects_foreign_bundle_urls_and_incomplete_releases(authed, monkeypatch, no_reindex):
    evil = {"collections": [{"name": "Enterprise ATT&CK", "versions": [{"version": "9", "url": "https://evil.example/x.json"}]}]}
    with mock.patch("app.attack_sync.netguard.request", return_value=resp(evil, url=attack_sync.INDEX_URL)):
        with pytest.raises(attack_sync.AttackError):
            attack_sync.releases()
    run_sync((GROUPS[:3], TECHS[:5], []), monkeypatch)  # far too small: keep what we have
    assert authed.get("/api/v1/attack/status").json()["last_result"]["status"] == "error"
    assert authed.get("/api/v1/attack/status").json()["counts"]["groups"] == 0


def test_attack_schedule_and_admin(authed, client):
    assert authed.patch("/api/v1/settings", json={"attack_sync": "daily"}).status_code == 200
    assert authed.patch("/api/v1/settings", json={"attack_sync": "hourly"}).status_code == 422
    with mock.patch.object(attack_sync.attack_sync, "start") as start:
        attack_sync.attack_sync.maybe_start()  # never checked -> due
        start.assert_called_once()
    with mock.patch.object(attack_sync.attack_sync, "start", return_value=True), \
            mock.patch("app.atlas_sync.atlas_sync.start", return_value=True):
        assert authed.post("/api/v1/attack/sync").json() == {"started": True}


# ------------------------------------------------------------------ accounts
def test_account_detection():
    assert accounts.detect("https://bsky.app/profile/troyhunt.com")["feed_url"] == "https://bsky.app/profile/troyhunt.com/rss"
    assert accounts.detect("@GossiTheDog@cyberplace.social")["feed_url"] == "https://cyberplace.social/@GossiTheDog.rss"
    assert accounts.detect("https://infosec.exchange/@briankrebs")["platform"] == "mastodon"
    assert accounts.detect("reddit.com/r/netsec")["feed_url"] == "https://www.reddit.com/r/netsec/new/.rss?limit=100"  # newest posts
    assert accounts.detect("https://x.com/vxunderground")["via"] == "x"
    assert accounts.detect("https://bridge.example/feed/li", "linkedin")["platform"] == "linkedin"
    for bad in ("https://www.linkedin.com/company/dragos", "https://instagram.com/someone", "https://youtube.com/@x", "not a link"):
        with pytest.raises(accounts.AccountError):
            accounts.detect(bad)


RSS = (f'<?xml version="1.0"?><rss version="2.0"><channel><title>Troy Hunt (@troyhunt.com)</title><link>https://bsky.app/</link>'
       f'<item><title>New ransomware breach loaded into HIBP</title><link>https://bsky.app/p/1</link><guid>p1</guid>'
       f'<pubDate>{NOW}</pubDate><description>Ransomware gang leak added today.</description></item></channel></rss>').encode()


def test_accounts_add_list_shelves_remove(authed):
    feed_resp = resp(RSS, url="https://bsky.app/profile/troyhunt.com/rss", ctype="application/rss+xml")
    with mock.patch("app.api.accounts.netguard.request", return_value=feed_resp), \
            mock.patch("app.fetcher.netguard.request", return_value=feed_resp), \
            mock.patch("app.api.content._refresh_async"):
        r = authed.post("/api/v1/accounts", json={"input": "https://bsky.app/profile/troyhunt.com"})
        assert r.status_code == 201, r.text
        fid = r.json()["id"]
        assert r.json()["platform"] == "bluesky" and r.json()["title"] == "Troy Hunt (@troyhunt.com)"
        authed.post(f"/api/v1/feeds/{fid}/refresh")
        assert authed.post("/api/v1/accounts", json={"input": "https://bsky.app/profile/troyhunt.com"}).status_code == 409
    meta = authed.get("/api/v1/accounts/meta").json()
    assert meta["accounts"][0]["platform"] == "bluesky" and meta["platforms"][0]["id"] == "bluesky"
    posts = authed.get(f"/api/v1/accounts/posts?platform=bluesky").json()
    assert posts["total"] == 1 and posts["items"][0]["feed_title"].startswith("Troy Hunt")
    shelves = authed.get("/api/v1/accounts/shelves").json()["shelves"]
    assert any(s["topic"]["name"] == "Ransomware" for s in shelves)
    assert authed.get("/api/v1/accounts/posts?platform=myspace").status_code == 422
    # a normal (non-social) feed is not an account
    with mock.patch("app.api.content._refresh_async"):
        other = authed.post("/api/v1/feeds", json={"url": "https://blog.example/feed"}).json()["id"]
    assert authed.delete(f"/api/v1/accounts/{other}").status_code == 404
    assert authed.delete(f"/api/v1/accounts/{fid}").status_code == 200
    assert authed.get("/api/v1/accounts/meta").json()["accounts"] == []


def test_accounts_refuse_non_feeds_and_bridge_only_sites(authed):
    page = resp(b"<html><body>hi</body></html>", url="https://bridge.example/x", ctype="text/html")
    with mock.patch("app.api.accounts.netguard.request", return_value=page):
        r = authed.post("/api/v1/accounts", json={"input": "https://bridge.example/x", "platform": "instagram"})
    assert r.status_code == 422 and "not a feed" in r.json()["detail"]
    r = authed.post("/api/v1/accounts", json={"input": "https://www.linkedin.com/in/someone"})
    assert r.status_code == 422 and "no feed for personal profiles" in r.json()["detail"]
    r = authed.post("/api/v1/accounts", json={"input": "https://www.instagram.com/nasa/"})   # no RSSHub bridge set up
    assert r.status_code == 422 and "RSSHub bridge" in r.json()["detail"]


# ------------------------------------------------------------------ packs + back-fill for chosen feeds
def test_pack_remove_and_update(authed):
    with mock.patch("app.api.automation.threading.Thread"):
        authed.post("/api/v1/rules/packs", json={"slugs": ["crypto"]})
    pack = next(p for p in authed.get("/api/v1/rules/packs").json()["packs"] if p["slug"] == "crypto")
    assert pack["installed"] == 2 and pack["rules_missing"] == 0
    rule = next(r for r in authed.get("/api/v1/rules").json() if r["name"] == "Auto: Crypto: News #2")
    authed.delete(f"/api/v1/rules/{rule['id']}")
    assert next(p for p in authed.get("/api/v1/rules/packs").json()["packs"] if p["slug"] == "crypto")["rules_missing"] == 1
    with mock.patch("app.api.automation.threading.Thread"):
        assert authed.post("/api/v1/rules/packs", json={"slugs": ["crypto"]}).json()["rules_created"] == 1
    res = authed.post("/api/v1/rules/packs/remove", json={"slugs": ["crypto"]}).json()
    assert res == {"collections_removed": 2, "rules_removed": 4}
    assert not [t for t in authed.get("/api/v1/tags").json() if t["name"].startswith("Crypto:")]
    assert authed.post("/api/v1/rules/packs/remove", json={"slugs": ["nope"]}).status_code == 422


def test_backfill_all_for_chosen_feeds(authed):
    from app import history

    with mock.patch("app.api.content._refresh_async"):
        a = authed.post("/api/v1/feeds", json={"url": "https://a.example/feed"}).json()["id"]
        authed.post("/api/v1/feeds", json={"url": "https://b.example/feed"})
    with mock.patch.object(history.backfill_job, "start", return_value=True) as start:
        r = authed.post("/api/v1/history/backfill-all", json={"feed_ids": [a], "only_missing": False})
    assert r.json() == {"started": True, "feeds": 1} and start.call_args.args[1] == [a]
    assert "feed_ids" not in start.call_args.args[2]


def test_filter_by_several_topics(authed):
    """Videos and Accounts accept topic_ids=1,2 with topic_match any|all (0 = no topic)."""
    from app.db import get_db, now

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, social_platform) VALUES ('Acc', 'https://s.example/rss', ?, 'rss', 'bluesky')",
                         (now(),)).lastrowid
        t1, t2 = (db.execute("INSERT INTO topics (name, keywords, color) VALUES (?, '[\"x\"]', '#000000')", (n,)).lastrowid for n in ("TA", "TB"))
        ids = []
        for n, tops in enumerate(([t1], [t2], [t1, t2], [])):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (fid, f"g{n}", f"post {n}", now(), now() - n)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, f"v{n}"))
            for t in tops:
                db.execute("INSERT OR IGNORE INTO article_topics (article_id, topic_id) VALUES (?, ?)", (aid, t))
            ids.append(aid)

    def titles(path):
        r = authed.get(path)
        assert r.status_code == 200, r.text
        return sorted(i["title"] for i in r.json()["items"])

    for base in ("/api/v1/library/videos?", "/api/v1/accounts/posts?"):
        assert titles(f"{base}topic_ids={t1},{t2}") == ["post 0", "post 1", "post 2"]
        assert titles(f"{base}topic_ids={t1},{t2}&topic_match=all") == ["post 2"]
        assert titles(f"{base}topic_ids=0,{t2}") == ["post 1", "post 2", "post 3"]
        assert authed.get(f"{base}topic_ids=1;DROP").status_code == 422
        assert authed.get(base + "topic_ids=" + ",".join(["1"] * 21)).status_code == 422


def test_topic_counts_follow_filters(authed):
    from app.db import get_db, now

    with get_db() as db:
        feeds = [db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES (?, ?, ?, 'youtube')", (n, f"https://y/{n}", now())).lastrowid
                 for n in ("A", "B")]
        tid = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('OT', '[\"x\"]', '#000000')").lastrowid
        for n, (fid, read) in enumerate([(feeds[0], 0), (feeds[0], 1), (feeds[1], 0)]):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, is_read) VALUES (?, ?, ?, ?, ?, ?)",
                             (fid, f"g{n}", f"v{n}", now(), now(), read)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, f"v{n}"))
            db.execute("INSERT INTO article_topics (article_id, topic_id) VALUES (?, ?)", (aid, tid))
    count = lambda q="": authed.get(f"/api/v1/library/topic-counts?{q}").json()["counts"].get(str(tid), 0)  # noqa: E731
    assert count() == 3
    assert count(f"feed_id={feeds[0]}") == 2
    assert count(f"feed_id={feeds[0]}&state=unwatched") == 1
    # and the number matches what clicking the topic shows
    shown = authed.get(f"/api/v1/library/videos?feed_id={feeds[0]}&state=unwatched&topic_ids={tid}").json()["total"]
    assert shown == 1


def test_youtube_channels_keep_their_videos(authed):
    from app import sources

    with mock.patch("app.api.content._refresh_async"):
        f = authed.post("/api/v1/feeds", json={"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UCqGONXW1ORgz5Y4qK-0JdkQ",
                                               "source": {"kind": "youtube", "channel_id": "UCqGONXW1ORgz5Y4qK-0JdkQ"}}).json()
        n = authed.post("/api/v1/feeds", json={"url": "https://news.example/feed"}).json()
    d = authed.get(f"/api/v1/feeds/{f['id']}/details").json()
    assert d["effective"]["retention_days"] == 0  # old uploads are not dropped by the 90-day news retention
    assert authed.get(f"/api/v1/feeds/{n['id']}/details").json()["effective"]["retention_days"] == 90
    assert sources  # imported for the source model


def test_videos_grouped_by_youtube_channel(authed):
    """A channel's playlists and saved single videos count as that channel; several channels can be combined."""
    import json as _json

    from app import sources as src
    from app.db import get_db, now

    chuck, other = "UC9x0AN7BWHpCDHSm9NiJFJQ", "UCOuGATIAbd2DvzJmUgXn2IQ"
    with get_db() as db:
        def feed(title, url, source):
            return db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                              (title, url, now(), _json.dumps(source))).lastrowid
        ch = feed("NetworkChuck", "https://y/ch", {"kind": "youtube", "channel_id": chuck})
        pl = feed("Linux for Hackers", "https://y/pl", {"kind": "youtube", "playlist_id": "PLIhvC56v63IJIujb5cyE13oLuyORZpdkL"})
        ot = feed("Other channel", "https://y/ot", {"kind": "youtube", "channel_id": other})
        sv = feed("Saved YouTube videos", src.SAVED_VIDEOS_URL, {"kind": "youtube", "saved": True})
        linux = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('Linux', '[\"linux\"]', '#000000')").lastrowid
        n = 0
        for fid, cid, title, count, is_linux in ((ch, chuck, "NetworkChuck", 3, False), (pl, chuck, "NetworkChuck", 4, True),
                                                 (ot, other, "Other", 2, True), (sv, None, "NetworkChuck", 1, True)):
            for _ in range(count):
                n += 1
                aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                                 (fid, f"g{n}", f"video {n}", now() + n, 1_600_000_000 + n)).lastrowid
                db.execute("INSERT INTO videos (article_id, video_id, channel_id, channel_title) VALUES (?, ?, ?, ?)",
                           (aid, f"v{n}", cid, title))
                if is_linux:
                    db.execute("INSERT INTO article_topics (article_id, topic_id) VALUES (?, ?)", (aid, linux))
    meta = authed.get("/api/v1/library/meta").json()["channels"]
    nc = next(c for c in meta if c["key"] == chuck)
    assert nc["videos"] == 8 and {f["type"] for f in nc["feeds"]} == {"channel", "playlist", "saved"} and nc["feed_id"] == ch
    assert len([c for c in meta if c["title"] == "NetworkChuck"]) == 1  # the saved video joined the channel by name
    total = lambda q: authed.get(f"/api/v1/library/videos?{q}").json()["total"]  # noqa: E731
    assert total(f"channels={chuck}") == 8
    assert total(f"channels={chuck}&topic_ids={linux}") == 5          # playlist (4) + saved single video (1)
    assert total(f"channels={chuck},{other}&topic_ids={linux}") == 7  # two channels and a topic together
    counts = authed.get(f"/api/v1/library/topic-counts?channels={chuck}").json()["counts"]
    assert counts[str(linux)] == 5
    first = authed.get(f"/api/v1/library/videos?sort=added&limit=1").json()["items"][0]["title"]
    assert first == f"video {n}"                                       # most recently added first
    assert authed.get("/api/v1/library/videos?channels=evil;drop").status_code == 422


def test_topic_upgrade_extends_builtins_and_spares_user_topics(authed):
    import json as _json

    from app import topics
    from app.db import get_db

    with get_db() as db:
        # simulate an install from before the upgrade: v1 keywords, no new topics, a user topic
        db.execute("UPDATE topics SET keywords = ? WHERE name = 'Cloud & containers'", (_json.dumps(["aws", "azure"]),))
        db.execute("DELETE FROM topics WHERE name IN ('AI & machine learning', 'Conferences & talks')")
        db.execute("INSERT INTO topics (name, keywords, color) VALUES ('My Linux', '[\"linux\"]', '#000000')")
        db.execute("DELETE FROM sync_state WHERE key = 'topics_version'")
        assert topics.upgrade_builtin(db) is True
        cloud = _json.loads(db.execute("SELECT keywords FROM topics WHERE name = 'Cloud & containers'").fetchone()[0])
        assert cloud[:2] == ["aws", "azure"] and "cloudfront" in cloud        # merged, existing words first
        assert db.execute("SELECT 1 FROM topics WHERE name = 'AI & machine learning'").fetchone()
        assert _json.loads(db.execute("SELECT keywords FROM topics WHERE name = 'My Linux'").fetchone()[0]) == ["linux"]
        assert topics.upgrade_builtin(db) is False                             # once only
        compiled = topics._compiled(db)
    # the words that used to leave videos untagged now match
    pats = {name: p for (tid, p) in compiled for (i, name) in [(tid, None)]}
    text = "A worm moved through npm like it owned the place"
    with get_db() as db:
        names = {r[0]: r[1] for r in db.execute("SELECT id, name FROM topics")}
    hits = {names[tid] for tid, p in compiled if p.search(text)}
    assert "Malware analysis" in hits and pats
    assert {names[tid] for tid, p in compiled if p.search("How to Create an Amazon CloudFront Distribution")} >= {"Cloud & containers"}
    assert {names[tid] for tid, p in compiled if p.search("Generating wordlists #bugbounty")} >= {"Bug bounty"}


def test_videos_sort_by_date(authed):
    from app.db import get_db, now

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('C', 'https://y/c', ?, 'youtube')", (now(),)).lastrowid
        # published 2021 / 2023 / 2022, added in the order a, b, c
        for n, (title, published) in enumerate((("a", 1_610_000_000), ("b", 1_680_000_000), ("c", 1_650_000_000))):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, published, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                             (fid, title, title, published, now() + n, published)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, title))
    order = lambda sort: [v["title"] for v in authed.get(f"/api/v1/library/videos?sort={sort}").json()["items"]]  # noqa: E731
    assert order("newest") == ["b", "c", "a"] and order("oldest") == ["a", "c", "b"]           # date published
    assert order("added") == ["c", "b", "a"] and order("added_oldest") == ["a", "b", "c"]     # date added
    assert authed.get("/api/v1/library/videos?sort=random").status_code == 422


def test_playlists_and_groups(authed):
    import json as _json

    from app.db import get_db, now

    with get_db() as db:
        ch = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Chan', 'https://y/c', ?, 'youtube', ?)",
                        (now(), _json.dumps({"kind": "youtube", "channel_id": "UC9x0AN7BWHpCDHSm9NiJFJQ"}))).lastrowid
        pl = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Course', 'https://y/p', ?, 'youtube', ?)",
                        (now(), _json.dumps({"kind": "youtube", "playlist_id": "PLIhvC56v63IJIujb5cyE13oLuyORZpdkL"}))).lastrowid
        ids = []
        for n, fid in enumerate((pl, pl, pl, ch, ch)):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (fid, f"g{n}", f"video {n}", now(), 1_600_000_000 + n)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, f"v{n}"))
            ids.append(aid)
    groups = authed.get("/api/v1/library/groups").json()["groups"]
    assert [(g["id"], g["type"], g["videos"]) for g in groups] == [(f"p:{pl}", "playlist", 3)]
    course = authed.get(f"/api/v1/library/groups/p:{pl}").json()
    assert [v["title"] for v in course["items"]] == ["video 0", "video 1", "video 2"]          # publishing order
    assert course["items"][0]["groups"] == [{"id": f"p:{pl}", "name": "Course"}]
    # your own group: add in a chosen order, duplicates ignored, non-videos refused
    g = authed.post("/api/v1/library/groups", json={"name": "Watch later"}).json()
    assert authed.post("/api/v1/library/groups", json={"name": "watch later"}).status_code == 409
    r = authed.post(f"/api/v1/library/groups/{g['id']}/videos", json={"article_ids": [ids[4], ids[0], ids[4], 999999]}).json()
    assert r == {"added": 2, "skipped": 1}
    mine = authed.get(f"/api/v1/library/groups/{g['id']}").json()
    assert [v["title"] for v in mine["items"]] == ["video 4", "video 0"]                      # order you added them
    v4 = next(v for v in authed.get("/api/v1/library/videos?limit=50").json()["items"] if v["title"] == "video 4")
    assert v4["groups"] == [{"id": g["id"], "name": "Watch later"}]
    assert authed.post(f"/api/v1/library/groups/p:{pl}/videos", json={"article_ids": [ids[3]]}).status_code == 422
    # a playlist dropped onto the group MOVES there: off the main page, listed inside the group, videos not copied
    r = authed.post(f"/api/v1/library/groups/{g['id']}/videos", json={"from_ref": f"p:{pl}"}).json()
    assert r == {"added": 0, "skipped": 0, "moved": 1}
    main = {x["id"]: x for x in authed.get("/api/v1/library/groups").json()["groups"]}
    assert f"p:{pl}" not in main and main[g["id"]]["playlists"] == 1 and main[g["id"]]["videos"] == 4   # 2 own + 3 playlist, 1 shared
    inside = authed.get(f"/api/v1/library/groups/{g['id']}").json()
    assert [x["id"] for x in inside["playlists"]] == [f"p:{pl}"] and inside["playlists"][0]["videos"] == 3
    assert [v["title"] for v in inside["items"]] == ["video 4", "video 0"]                       # own videos unchanged
    assert authed.get(f"/api/v1/library/groups/p:{pl}").json()["in_group"] == {"id": g["id"], "name": "Watch later"}
    # moving it into another group takes it out of the first; a group's videos can still be copied into another group
    other = authed.post("/api/v1/library/groups", json={"name": "Copy"}).json()
    assert authed.post(f"/api/v1/library/groups/{other['id']}/videos", json={"from_ref": f"p:{pl}"}).json()["moved"] == 1
    assert authed.get(f"/api/v1/library/groups/{g['id']}").json()["playlists"] == []
    assert authed.post(f"/api/v1/library/groups/{other['id']}/videos", json={"from_ref": g["id"]}).json() == {"added": 2, "skipped": 0}
    # move out: back on the main page
    assert authed.delete(f"/api/v1/library/groups/{other['id']}/playlists/{pl}").json() == {"ok": True}
    assert authed.delete(f"/api/v1/library/groups/{other['id']}/playlists/{pl}").status_code == 404
    assert f"p:{pl}" in {x["id"] for x in authed.get("/api/v1/library/groups").json()["groups"]}
    assert authed.get(f"/api/v1/library/groups/p:{pl}").json()["in_group"] is None
    # deleting a group puts its playlists back on the main page
    authed.post(f"/api/v1/library/groups/{other['id']}/videos", json={"from_ref": f"p:{pl}"})
    for bad in ({"from_ref": g["id"]}, {}, {"from_ref": f"p:{pl}", "article_ids": [ids[0]]}, {"from_ref": "p:999999"}, {"from_ref": "x:1"}):
        code = authed.post(f"/api/v1/library/groups/{g['id']}/videos", json=bad).status_code
        assert code in (404, 422), (bad, code)
    assert authed.delete(f"/api/v1/library/groups/{other['id']}").json() == {"ok": True}
    assert f"p:{pl}" in {x["id"] for x in authed.get("/api/v1/library/groups").json()["groups"]}
    # (deleting the playlist itself is allowed now - covered in test_remove_video_for_good_and_delete_playlist)
    assert authed.patch(f"/api/v1/library/groups/{g['id']}", json={"name": "Series"}).json() == {"ok": True}
    assert authed.delete(f"/api/v1/library/groups/{g['id']}/videos/{ids[0]}").json() == {"ok": True}
    assert authed.delete(f"/api/v1/library/groups/{g['id']}").json() == {"ok": True}
    assert authed.get("/api/v1/library/videos?limit=50").json()["total"] == 5                 # videos stay
    assert authed.get("/api/v1/library/groups/x:1").status_code == 422


def test_plain_youtube_feed_becomes_a_channel(authed):
    """Adding a channel that an OPML/FreshRSS import already subscribed as plain RSS upgrades it instead of failing."""
    from app.db import get_db

    cid = "UC3s0BtrBJpwNDaflRSoiieQ"
    url = f"https://www.youtube.com/feeds/videos.xml?channel_id={cid}"
    with get_db() as db:  # how an OPML/FreshRSS import added it: a plain RSS feed
        plain = {"id": db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Hak5', ?, 1, 'rss')", (url,)).lastrowid}
    with get_db() as db:
        for n, link in enumerate(("https://www.youtube.com/watch?v=ECsXL6-KjqU", "https://www.youtube.com/shorts/_GvkKcwm37E")):
            db.execute("INSERT INTO articles (feed_id, guid, url, title, author, fetched_at, sort_ts) VALUES (?, ?, ?, ?, 'Hak5', 1, 1)",
                       (plain["id"], link, link, f"video {n}"))
    with mock.patch("app.api.content._refresh_async"):
        r = authed.post("/api/v1/feeds", json={"url": "https://ignored.example/", "source": {"kind": "youtube", "channel_id": cid}})
    assert r.status_code == 201 and r.json()["adopted"] is True and r.json()["id"] == plain["id"]
    with get_db() as db:
        feed = db.execute("SELECT kind, retention_days, folder_id FROM feeds WHERE id = ?", (plain["id"],)).fetchone()
        folder = db.execute("SELECT name FROM folders WHERE id = ?", (feed["folder_id"],)).fetchone()["name"]
        guids = sorted(r[0] for r in db.execute("SELECT guid FROM articles WHERE feed_id = ?", (plain["id"],)))
    assert feed["kind"] == "youtube" and feed["retention_days"] == 0 and folder == "YouTube"
    assert guids == ["yt:video:ECsXL6-KjqU", "yt:video:_GvkKcwm37E"]          # re-keyed: the next fetch adds no duplicates
    assert authed.get("/api/v1/library/videos").json()["total"] == 2           # its videos are in the Videos tab now
    # a second add of the same channel is a real duplicate
    with mock.patch("app.api.content._refresh_async"):
        assert authed.post("/api/v1/feeds", json={"url": "https://ignored.example/", "source": {"kind": "youtube", "channel_id": cid}}).status_code == 409


def test_startup_adopts_imported_youtube_feeds(authed):
    from app.db import get_db
    from app.main import _adopt_youtube_feeds

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Imported', "
                         "'https://www.youtube.com/feeds/videos.xml?playlist_id=PLIhvC56v63IJIujb5cyE13oLuyORZpdkL', 1)").lastrowid
        db.execute("DELETE FROM sync_state WHERE key = 'youtube_adopted_v1'")
        _adopt_youtube_feeds(db)
        row = db.execute("SELECT kind, source FROM feeds WHERE id = ?", (fid,)).fetchone()
    assert row["kind"] == "youtube" and "playlist_id" in row["source"]


def test_refresh_per_section(authed):
    from app.db import get_db

    with get_db() as db:
        db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('News', 'https://n/f', 1, 'rss')")
        db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Chan', 'https://y/c2', 1, 'youtube')")
        db.execute("INSERT INTO feeds (title, url, created_at, kind, social_platform) VALUES ('Acc', 'https://b/a', 1, 'rss', 'bluesky')")
    queued = lambda s: authed.post(f"/api/v1/feeds/refresh?section={s}").json()["queued"]  # noqa: E731
    assert queued("videos") == 1 and queued("accounts") == 1 and queued("reader") == 2
    from app.security import reset_rate_limits

    reset_rate_limits()
    assert queued("all") == 3 and authed.post("/api/v1/feeds/refresh?section=everything").status_code == 422



def test_youtube_feed_address_in_add_feed_becomes_a_channel(authed):
    url = "https://www.youtube.com/feeds/videos.xml?channel_id=UC9x0AN7BWHpCDHSm9NiJFJQ"
    with mock.patch("app.api.content._refresh_async"):
        f = authed.post("/api/v1/feeds", json={"url": url}).json()
    assert f["kind"] == "youtube"


def test_reader_lists_exclude_youtube_videos(authed):
    from app.db import get_db, now

    with get_db() as db:
        news = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('News', 'https://n/x', 1, 'rss')").lastrowid
        yt = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Chan', 'https://y/x', 1, 'youtube')").lastrowid
        for fid, title in ((news, "an article"), (yt, "a video")):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (fid, title, title, now(), now())).lastrowid
        db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, 'v1')", (aid,))
    items = authed.get("/api/v1/articles?limit=50").json()["items"]
    assert [a["title"] for a in items] == ["an article"]
    side = authed.get("/api/v1/sidebar").json()
    assert side["counts"]["total"] == 1 and all(f["id"] != yt for f in side["feeds"])
    assert authed.get("/api/v1/library/videos").json()["total"] == 1          # still in Videos
    assert authed.get(f"/api/v1/articles/{aid}").status_code == 200          # "Open in reader" still works
    assert authed.post("/api/v1/articles/mark-read", json={"all": True}).json()["updated"] == 1  # videos untouched


def _yt_feed(db, title, source):
    import json as _json

    from app.db import now
    return db.execute("INSERT INTO feeds (title, url, created_at, kind, source, retention_days, max_articles) "
                      "VALUES (?, ?, ?, 'youtube', ?, 0, 0)", (title, f"https://y/{title}", now(), _json.dumps(source))).lastrowid


def _video(db, fid, guid, published, starred=0):
    from app.db import now
    aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts, published, is_starred) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (fid, guid, guid, now(), published, published, starred)).lastrowid
    db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, guid[-11:]))
    return aid


def test_remove_video_for_good_and_delete_playlist(authed):
    import time as _time

    from app.db import get_db
    from app.fetcher import store_entries
    from app.history import _prepare

    with get_db() as db:
        pl = _yt_feed(db, "PL", {"kind": "youtube", "playlist_id": "PLUc6uuGl4Y3clxiFzVodtaIi6xNaNjmjz"})
        keep = _video(db, pl, "yt:video:AAAAAAAAAA1", int(_time.time()))
        gone = _video(db, pl, "yt:video:BBBBBBBBBB2", int(_time.time()))
    assert authed.delete(f"/api/v1/library/videos/{gone}").json() == {"ok": True}
    assert authed.delete(f"/api/v1/library/videos/{gone}").status_code == 404
    with get_db() as db:  # a later fetch, even after "load whole" (keep_forever clears automatic tombstones), skips it
        _prepare(pl, {"keep_forever": True, "since_days": None, "max_pages": 1, "method": "auto"})
        new = store_entries(db, pl, [{"id": "yt:video:BBBBBBBBBB2", "title": "again", "link": "https://www.youtube.com/watch?v=BBBBBBBBBB2"}],
                            None, int(_time.time()))
    assert new == []
    r = authed.delete(f"/api/v1/library/groups/p:{pl}").json()
    assert r == {"ok": True, "videos_removed": 1}
    assert authed.get("/api/v1/library/videos").json()["total"] == 0 and keep


def test_keep_time_frame_scales_back(authed):
    import time as _time

    from app.db import get_db

    day = 86400
    t = int(_time.time())
    with get_db() as db:
        ch = _yt_feed(db, "CH", {"kind": "youtube", "channel_id": "UC9x0AN7BWHpCDHSm9NiJFJQ"})
        recent = _video(db, ch, "yt:video:RECENT00001", t - 2 * day)
        old = _video(db, ch, "yt:video:OLDOLD00001", t - 200 * day)
        old_star = _video(db, ch, "yt:video:OLDSTAR0001", t - 200 * day, starred=1)
        old_grouped = _video(db, ch, "yt:video:OLDGROUP001", t - 200 * day)
        gid = db.execute("INSERT INTO video_groups (name, created_at) VALUES ('Keep me', 1)").lastrowid
        db.execute("INSERT INTO video_group_items (group_id, article_id, added_at) VALUES (?, ?, 1)", (gid, old_grouped))
    r = authed.post("/api/v1/library/keep", json={"feed_ids": [ch], "days": 90}).json()
    assert {k: r[k] for k in ("removed", "days")} == {"removed": 1, "days": 90}
    ids = {v["id"] for v in authed.get("/api/v1/library/videos?limit=50").json()["items"]}
    assert ids == {recent, old_star, old_grouped} and old not in ids
    with get_db() as db:
        assert db.execute("SELECT retention_days FROM feeds WHERE id = ?", (ch,)).fetchone()[0] == 90  # stays trimmed
        from app.fetcher import run_retention
    run_retention()  # the hourly pass keeps the grouped and starred ones too
    assert len(authed.get("/api/v1/library/videos?limit=50").json()["items"]) == 3
    assert authed.post("/api/v1/library/keep", json={"feed_ids": [ch], "days": 0}).json()["removed"] == 0
    with get_db() as db:
        news = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('n', 'https://n/f2', 1)").lastrowid
    assert authed.post("/api/v1/library/keep", json={"feed_ids": [news], "days": 7}).status_code == 422


def test_channel_playlists_listing(authed):
    from app import netguard

    assert authed.get("/api/v1/library/youtube/playlists?channel_id=UC9x0AN7BWHpCDHSm9NiJFJQ").status_code == 422  # no key
    with mock.patch("app.sources.yt_key", return_value="AIzaFAKE"), \
            mock.patch("app.sources.netguard.request", return_value=resp({"items": [
                {"id": "PLIhvC56v63IJIujb5cyE13oLuyORZpdkL", "snippet": {"title": "Linux for Hackers"}, "contentDetails": {"itemCount": 10}},
                {"id": "bad id!", "snippet": {"title": "x"}}]}, url="https://www.googleapis.com/")):
        r = authed.get("/api/v1/library/youtube/playlists?channel_id=UC9x0AN7BWHpCDHSm9NiJFJQ")
    assert r.json()["playlists"] == [{"playlist_id": "PLIhvC56v63IJIujb5cyE13oLuyORZpdkL", "title": "Linux for Hackers", "videos": 10}]
    assert authed.get("/api/v1/library/youtube/playlists?channel_id=nope").status_code == 422
    assert netguard


def test_group_all_videos_view(authed):
    import json as _json

    from app.db import get_db, now

    with get_db() as db:
        pl = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Course', 'https://y/p2', ?, 'youtube', ?)",
                        (now(), _json.dumps({"kind": "youtube", "playlist_id": "PLIhvC56v63ILPDA2DQBv0IKzqsWTZxCkp"}))).lastrowid
        ids = []
        for n in range(3):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (pl, f"a{n}", f"clip {n}", now(), 1_600_000_000 + n)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id) VALUES (?, ?)", (aid, f"c{n}"))
            ids.append(aid)
    g = authed.post("/api/v1/library/groups", json={"name": "Mixed"}).json()
    authed.post(f"/api/v1/library/groups/{g['id']}/videos", json={"article_ids": [ids[2]]})
    authed.post(f"/api/v1/library/groups/{g['id']}/videos", json={"from_ref": f"p:{pl}"})
    own = authed.get(f"/api/v1/library/groups/{g['id']}").json()
    assert own["total"] == 1 and len(own["playlists"]) == 1
    every = authed.get(f"/api/v1/library/groups/{g['id']}?scope=all").json()
    assert every["total"] == 3 and [v["title"] for v in every["items"]][0] == "clip 2"   # hand-added first, then the playlist
    assert authed.get(f"/api/v1/library/groups/{g['id']}?scope=bad").status_code == 422


def test_playlists_and_groups_keep_the_dragged_order(authed):
    import json as _json

    from app.db import get_db, now

    with get_db() as db:
        pls = [db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                          (f"List {n}", f"https://y/o{n}", now() - 100 + n,
                           _json.dumps({"kind": "youtube", "playlist_id": f"PLorder{n}xxxxxxxxxxxx"}))).lastrowid for n in range(3)]
    g = authed.post("/api/v1/library/groups", json={"name": "Shelf"}).json()
    ids = lambda: [x["id"] for x in authed.get("/api/v1/library/groups").json()["groups"]]
    assert ids() == [f"p:{pls[0]}", f"p:{pls[1]}", f"p:{pls[2]}", g["id"]]          # default: oldest first, new ones last
    want = [g["id"], f"p:{pls[2]}", f"p:{pls[0]}", f"p:{pls[1]}"]
    assert authed.put("/api/v1/library/groups/order", json={"refs": want}).json()["ok"]
    assert ids() == want                                                              # fixed until you drag again
    assert authed.put("/api/v1/library/groups/order", json={"refs": ["x:1"]}).status_code == 422
    # inside a group: the playlists keep their own order too
    for p in (pls[0], pls[1]):
        authed.post(f"/api/v1/library/groups/{g['id']}/videos", json={"from_ref": f"p:{p}"})
    authed.put("/api/v1/library/groups/order", json={"refs": [f"p:{pls[1]}", f"p:{pls[0]}"]})
    assert [x["id"] for x in authed.get(f"/api/v1/library/groups/{g['id']}").json()["playlists"]] == [f"p:{pls[1]}", f"p:{pls[0]}"]
    authed.delete(f"/api/v1/library/groups/{g['id']}/playlists/{pls[1]}")
    assert ids()[-1] == f"p:{pls[1]}"                                                 # moved out: joins the end


def test_keep_fills_the_time_frame_with_older_videos(authed):
    """Keep… also loads the older videos inside the time frame (with a key), and a channel back-fill stops at that date."""
    import json as _json

    from app import history, sources
    from app.db import get_db, now

    with get_db() as db:
        ch = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Chan', 'https://y/k', ?, 'youtube', ?)",
                        (now(), _json.dumps({"kind": "youtube", "channel_id": "UC9x0AN7BWHpCDHSm9NiJFJQ"}))).lastrowid
    with mock.patch("app.sources.yt_key", return_value="AIzaFAKE"), mock.patch.object(history.backfill_job, "start", return_value=True) as start:
        r = authed.post("/api/v1/library/keep", json={"feed_ids": [ch], "days": 730}).json()
    assert r["loading"] is True and start.call_args.args[1] == [ch] and start.call_args.args[2]["keep_days"] == 730
    # paging stops once the uploads (newest first) are older than "since"
    old, new = "2020-01-01T00:00:00Z", "2026-11-01T00:00:00Z"
    page = lambda ts, tok: {"items": [{"snippet": {"title": "v", "publishedAt": ts}, "contentDetails": {"videoId": f"VID{ts[:4]}{tok}x0000"[:11], "videoPublishedAt": ts}}],
                            "nextPageToken": tok}
    calls = []
    def fake_api(endpoint, params, key):
        calls.append(params.get("pageToken"))
        return [page(new, "p2"), page(old, "p3"), page(old, "")][len(calls) - 1]
    cfg = sources.YouTubeSource(kind="youtube", channel_id="UC9x0AN7BWHpCDHSm9NiJFJQ")
    with mock.patch("app.sources.yt_api", side_effect=fake_api), mock.patch("app.sources.video_details", return_value={}):
        pairs = sources.youtube_backfill(cfg, "k", 1000, lambda: False, since=now() - 730 * 86400)
    assert len(calls) == 2 and len(pairs) == 2      # page 1 (new) + page 2 (reaches 2020) - then it stops


def test_video_search_title_channel_description_and_spacing(authed):
    import json as _json

    from app.db import get_db, now

    with get_db() as db:
        ch = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES ('Chan', 'https://y/s', ?, 'youtube', ?)",
                        (now(), _json.dumps({"kind": "youtube", "channel_id": "UC9x0AN7BWHpCDHSm9NiJFJQ"}))).lastrowid
        for n, (title, text, chan) in enumerate([("My Home Lab tour", "", "Raid Owl"), ("Proxmox cluster", "building a homelab server", "Techno Tim"),
                                                 ("Homelab on a budget", "", "Hardware Haven"), ("Kali basics", "nmap scans", "NetworkChuck")]):
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                             (ch, f"s{n}", title, text, now(), now() - n)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id, channel_title) VALUES (?, ?, ?)", (aid, f"s{n}xxxxxxxxx", chan))
    titles = lambda q: sorted(v["title"] for v in authed.get(f"/api/v1/library/videos?q={q}&limit=50").json()["items"])
    assert titles("homelab") == ["Homelab on a budget", "My Home Lab tour", "Proxmox cluster"]   # title, spacing, description
    assert titles("home%20lab") == ["Homelab on a budget", "My Home Lab tour", "Proxmox cluster"]  # every word, anywhere
    assert titles("networkchuck") == ["Kali basics"]                                               # channel name
    assert titles("%25") == []                                                                     # LIKE wildcards are literal


def test_accounts_bridge_routes_for_bridge_only_sites():
    from app import accounts as A

    base = "http://127.0.0.1:1200"
    assert A.detect("https://www.instagram.com/nasa/", None, base)["feed_url"] == f"{base}/instagram/user/nasa"
    assert A.detect("https://www.threads.com/@zuck", None, base)["feed_url"] == f"{base}/threads/zuck"
    assert A.detect("https://www.tiktok.com/@nasa", None, base)["feed_url"] == f"{base}/tiktok/user/@nasa"
    assert A.detect("https://www.linkedin.com/company/microsoft/", None, base)["feed_url"] == f"{base}/linkedin/company/microsoft/posts"
    with pytest.raises(A.AccountError, match="no feed for personal profiles"):
        A.detect("https://www.linkedin.com/in/someone/", None, base)
    with pytest.raises(A.AccountError, match="RSSHub bridge"):
        A.detect("https://www.instagram.com/nasa/", None, None)          # no bridge configured


def test_add_single_posts_by_link(authed):
    from app import netguard

    def fake(method, url, **kw):
        if "publish.twitter.com/oembed" in url:
            body = {"author_name": "NASA", "html": '<blockquote><p lang="en">Ransomware hits a <a href="x">lab</a> &amp; more</p>&mdash; NASA <a href="y">November 10, 2026</a></blockquote>'}
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/json"}), json.dumps(body).encode(), url)
        if url.endswith("/.json?raw_json=1"):
            return netguard.SafeResponse(403, httpx.Headers({}), b"blocked", url)
        if url.endswith("/.rss"):
            feed = (b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>CVE writeup thread</title>'
                    b'<author><name>/u/alice</name></author><content type="html">&lt;p&gt;details&lt;/p&gt;</content></entry></feed>')
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/atom+xml"}), feed, url)
        raise AssertionError(url)

    with mock.patch("app.netguard.request", side_effect=fake):
        x = authed.post("/api/v1/accounts/posts", json={"url": "https://x.com/NASA/status/2121364270281822467?s=20"})
        assert x.status_code == 201, x.text
        assert x.json()["platform"] == "x" and x.json()["title"] == "Ransomware hits a lab & more"
        assert authed.post("/api/v1/accounts/posts", json={"url": "https://x.com/NASA/status/2121364270281822467"}).status_code == 409
        r = authed.post("/api/v1/accounts/posts", json={"url": "https://www.reddit.com/r/netsec/comments/abc123/cve_writeup/"})
        assert r.status_code == 201 and r.json()["title"] == "CVE writeup thread"      # JSON refused -> RSS
    li = authed.post("/api/v1/accounts/posts", json={"url": "https://www.linkedin.com/posts/someone_activity-1"})
    assert li.status_code == 422 and "copy the post" in li.text.lower()                  # no login-wall bypass
    li = authed.post("/api/v1/accounts/posts", json={"url": "https://www.linkedin.com/posts/someone_activity-1",
                                                     "text": "Our OT security team found <script>x</script> issues."})
    assert li.status_code == 201 and li.json()["platform"] == "linkedin"
    art = authed.get(f"/api/v1/articles/{li.json()['id']}").json()
    assert "<script" not in art["content_html"]
    posts = authed.get("/api/v1/accounts/posts?limit=50").json()
    assert {p["platform"] for p in posts["items"]} >= {"x", "reddit", "linkedin"}
    assert authed.post("/api/v1/accounts/posts", json={"url": "javascript:alert(1)"}).status_code == 422


def test_youtube_owner_of_video_and_playlist(authed):
    from app import sources

    def fake_api(path, params, key):
        assert key == "AIzaFAKE"
        snippet = {"channelId": "UC9x0AN7BWHpCDHSm9NiJFJQ", "channelTitle": "NetworkChuck"}
        return {"items": [{"snippet": snippet}]}

    with mock.patch("app.sources.yt_key", return_value="AIzaFAKE"), mock.patch.object(sources, "yt_api", side_effect=fake_api) as api:
        r = authed.get("/api/v1/library/youtube/owner?url=https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert r.json() == {"channel_id": "UC9x0AN7BWHpCDHSm9NiJFJQ", "title": "NetworkChuck"} and api.call_args.args[0] == "videos"
        r = authed.get("/api/v1/library/youtube/owner?url=https://www.youtube.com/playlist?list=PLIhvC56v63IKrRHh3gvZZBAGvsvOhwrRF")
        assert r.json()["channel_id"].startswith("UC") and api.call_args.args[0] == "playlists"
    assert authed.get("/api/v1/library/youtube/owner?url=https://example.com/nothing").status_code == 422


def test_every_video_gets_a_topic_channel_then_general(authed):
    """No keyword match: the channel's main topic; a channel with no matched video: General. A later keyword match
    replaces the fallback; the By topic shelves have no "Other" left."""
    import json as _json

    from app import topics
    from app.db import get_db, now

    with get_db() as db:
        zz = db.execute("INSERT INTO topics (name, keywords, color) VALUES ('Zzq', '[\"zzqword\"]', '#000000')").lastrowid
        db.execute("UPDATE topics SET enabled = 0 WHERE id != ? AND name != 'General'", (zz,))  # only our topic matches
        ids = {}
        for n, (cid, title) in enumerate((("UCaaaaaaaaaaaaaaaaaaaaaa", "zzqword one"), ("UCaaaaaaaaaaaaaaaaaaaaaa", "zzqword two"),
                                          ("UCaaaaaaaaaaaaaaaaaaaaaa", "a plain clip"), ("UCbbbbbbbbbbbbbbbbbbbbbb", "another plain clip"))):
            fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, source) VALUES (?, ?, ?, 'youtube', ?)",
                             (f"f{n}", f"https://y/{n}", now(), _json.dumps({"kind": "youtube", "channel_id": cid}))).lastrowid
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?)",
                             (fid, f"g{n}", title, now(), 1_700_000_000 + n)).lastrowid
            db.execute("INSERT INTO videos (article_id, video_id, channel_id, channel_title) VALUES (?, ?, ?, ?)", (aid, f"vid{n}", cid, "Chan"))
            ids[title] = aid
        topics.classify(db, list(ids.values()))
        topics.fill_video_topics(db)
        links = lambda aid: {(r[0], r[1]) for r in db.execute(  # noqa: E731
            "SELECT t.name, x.source FROM article_topics x JOIN topics t ON t.id = x.topic_id WHERE x.article_id = ?", (aid,))}
        assert links(ids["zzqword one"]) == {("Zzq", "keyword")}
        assert links(ids["a plain clip"]) == {("Zzq", "channel")}          # its channel's main topic
        assert links(ids["another plain clip"]) == {("General", "general")}  # a channel with no matched video
        db.execute("UPDATE articles SET title = 'zzqword at last' WHERE id = ?", (ids["another plain clip"],))
        topics.classify(db, [ids["another plain clip"]])
        assert links(ids["another plain clip"]) == {("Zzq", "keyword")}     # the fallback went away
        topics.fill_video_topics(db, [ids["a plain clip"]])                 # idempotent for new-video fills
        assert links(ids["a plain clip"]) == {("Zzq", "channel")}
    shelves = authed.get("/api/v1/library/shelves?per=12&state=all").json()
    assert shelves["other"]["total"] == 0
    # a deleted topic: its videos fall back again once the background re-tag runs
    assert authed.delete(f"/api/v1/topics/{zz}").status_code == 200
    topics.reclassifier._thread and topics.reclassifier._thread.join(10)
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM videos v WHERE NOT EXISTS (SELECT 1 FROM article_topics x "
                          "WHERE x.article_id = v.article_id)").fetchone()[0] == 0


def test_accounts_recognise_subreddit_and_filter_several(authed):
    """One ＋: links are recognised (post / subreddit / account) without fetching; a subreddit follows its newest
    posts, is named r/…, checked every 30 min, keeps the chosen retention, and a Reddit rate limit doesn't block it.
    Several accounts / platforms can be filtered together."""
    rec = lambda s: authed.post("/api/v1/accounts/recognize", json={"input": s}).json()  # noqa: E731
    assert rec("https://www.reddit.com/r/homelab/?solution=46d6&js_challenge=1&rdt=54097")["kind"] == "community"
    assert rec("https://www.reddit.com/r/homelab/comments/abc123/my_rack/")["kind"] == "post"
    li = rec("https://www.linkedin.com/posts/someone_activity-123")
    assert li["kind"] == "post" and li["needs_text"] is True
    assert rec("https://bsky.app/profile/troyhunt.com")["kind"] == "account"
    assert rec("hello there")["kind"] == "unknown"
    with mock.patch("app.api.accounts.netguard.request", return_value=resp(b"", status=429)) as net, \
            mock.patch("app.api.content._refresh_async"):
        r = authed.post("/api/v1/accounts", json={"input": "https://www.reddit.com/r/homelab/?js_challenge=1", "retention_days": 365})
    assert r.status_code == 201, r.text
    assert net.call_args[0][1] == "https://www.reddit.com/r/homelab/new/.rss?limit=100"
    sub = r.json()
    assert sub["title"] == "r/homelab" and sub["platform"] == "reddit" and sub["refresh_minutes"] == 30
    feed_resp = resp(RSS, url="https://bsky.app/profile/troyhunt.com/rss", ctype="application/rss+xml")
    with mock.patch("app.api.accounts.netguard.request", return_value=feed_resp), \
            mock.patch("app.fetcher.netguard.request", return_value=feed_resp), mock.patch("app.api.content._refresh_async"):
        bsky = authed.post("/api/v1/accounts", json={"input": "https://bsky.app/profile/troyhunt.com"}).json()
        authed.post(f"/api/v1/feeds/{bsky['id']}/refresh")
    meta = {a["feed_id"]: a for a in authed.get("/api/v1/accounts/meta").json()["accounts"]}
    assert meta[sub["id"]]["retention_days"] == 365 and meta[sub["id"]]["keeps"] == 365
    total = lambda q: authed.get(f"/api/v1/accounts/posts?{q}").json()["total"]  # noqa: E731
    assert total(f"feed_ids={bsky['id']},{sub['id']}") == total("") == 1
    assert total("platforms=reddit") == 0 and total("platforms=bluesky,reddit") == 1
    assert authed.get("/api/v1/accounts/posts?platforms=myspace").status_code == 422
    assert authed.get("/api/v1/accounts/posts?feed_ids=1;drop").status_code == 422
    assert authed.get(f"/api/v1/accounts/shelves?platforms=bluesky").status_code == 200


def test_reddit_rate_limit_first_posts_dedupe_and_migration(authed):
    """A 429 waits instead of counting as a failure; the posts from the add check are stored at once (no second
    request); a subreddit already followed under its old address is not added twice; old subreddit accounts move
    to the newest-posts feed at start-up."""
    import httpx as _httpx

    from app.db import get_db, now
    from app.main import _reddit_subreddits_follow_new_posts

    atom = (b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>newest submissions : homelab</title>'
            b'<entry><id>t3_a</id><title>My new rack</title><link href="https://www.reddit.com/r/homelab/comments/a/x/"/>'
            b'<updated>2026-11-15T10:00:00Z</updated><content type="html">ok</content></entry></feed>')
    with mock.patch("app.api.accounts.netguard.request", return_value=resp(atom, url="https://www.reddit.com/r/homelab/new/.rss",
                                                                           ctype="application/atom+xml")), \
            mock.patch("app.api.content._refresh_async"):
        r = authed.post("/api/v1/accounts", json={"input": "reddit.com/r/homelab"})
    assert r.status_code == 201, r.text
    fid = r.json()["id"]
    assert authed.get(f"/api/v1/accounts/posts?feed_ids={fid}").json()["total"] == 1   # there straight away
    limited = netguard.SafeResponse(429, _httpx.Headers({"retry-after": "120"}), b"", "https://www.reddit.com/r/homelab/new/.rss")
    with mock.patch("app.fetcher.netguard.request", return_value=limited):
        out = authed.post(f"/api/v1/feeds/{fid}/refresh").json()
    assert out["ok"] is False
    with get_db() as db:
        row = db.execute("SELECT error_count, last_error, next_fetch FROM feeds WHERE id = ?", (fid,)).fetchone()
        assert row["error_count"] == 0 and "429" in row["last_error"] and row["next_fetch"] >= now() + 15 * 60 - 5
        # an old-style subreddit account: same subreddit → refused; start-up moves it to /new/
        db.execute("UPDATE feeds SET url = 'https://www.reddit.com/r/homelab/.rss' WHERE id = ?", (fid,))
    with mock.patch("app.api.accounts.netguard.request") as net:
        dup = authed.post("/api/v1/accounts", json={"input": "https://www.reddit.com/r/homelab/?js_challenge=1"})
    assert dup.status_code == 409 and "already followed" in dup.text and not net.called
    with get_db() as db:
        db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Reddit NetSec', 'https://www.reddit.com/r/netsec/.rss', ?)", (now(),))
        _reddit_subreddits_follow_new_posts(db)
        assert db.execute("SELECT url FROM feeds WHERE id = ?", (fid,)).fetchone()[0] == "https://www.reddit.com/r/homelab/new/.rss?limit=100"
        # a plain Articles feed of a subreddit is not an account: left alone
        assert db.execute("SELECT url FROM feeds WHERE title = 'Reddit NetSec'").fetchone()[0] == "https://www.reddit.com/r/netsec/.rss"


def test_linkedin_post_gets_links_and_public_preview_image(authed):
    """A saved LinkedIn post: web addresses in the text are links, and the image/author come from the page's public
    preview (Open Graph). A login wall gives no preview - pasted text still works; no text and no preview = refused."""
    from app import social_posts

    page = ('<html><head><meta property="og:title" content="Free OT lab tools | Ana Sousa">'
            '<meta property="og:description" content="You don&#39;t need a PLC to start">'
            '<meta property="og:image" content="https://media.licdn.com/dms/image/abc/feedshare.jpg?e=1&amp;v=beta">'
            '</head><body></body></html>').encode()
    link = "https://www.linkedin.com/feed/update/urn:li:activity:7527177742136713216/"
    with mock.patch("app.social_posts.netguard.request", return_value=resp(page, url=link, ctype="text/html; charset=utf-8")):
        r = authed.post("/api/v1/accounts/posts", json={"url": link, "text": "AtomICS 🔗 https://lnkd.in/eaxAmYF8\nNmap: https://insecure.org."})
    assert r.status_code == 201, r.text
    authed.patch("/api/v1/settings", json={"image_proxy": False})  # this test checks the stored address
    body = authed.get(f"/api/v1/articles/{r.json()['id']}").json()
    html = body["content_html"]
    assert '<a href="https://lnkd.in/eaxAmYF8"' in html and '<a href="https://insecure.org"' in html
    assert '<img src="https://media.licdn.com/dms/image/abc/feedshare.jpg?e=1&amp;v=beta"' in html
    assert body["author"] == "Ana Sousa"
    wall = resp(b"<html><body>Sign in to see this</body></html>", url=link, ctype="text/html")
    with mock.patch("app.social_posts.netguard.request", return_value=wall):
        assert social_posts.public_preview(link) == {}
        p = social_posts.fetch("https://www.linkedin.com/posts/x_activity-1", "Just text https://example.org")
        assert "<img" not in p["html"] and '<a href="https://example.org"' in p["html"]
        with pytest.raises(social_posts.PostError):
            social_posts.fetch("https://www.linkedin.com/posts/x_activity-2", None)
    # pasted markup is text, never HTML
    assert "<script" not in social_posts.para_html("<script>alert(1)</script> https://a.example")


def test_reading_view_reddit_media_and_thread(authed):
    """☰ Read: full posts; Reddit posts carry their own text and photos / video / gallery (only Reddit/Imgur https
    hosts), and a thread endpoint returns the post with its comments from the post's public feed."""
    from app import reddit
    from app.db import get_db, now

    html = ('<table><tr><td><a href="https://www.reddit.com/r/homelab/comments/1abcde/rack/">'
            '<img src="https://preview.redd.it/thumb1.jpeg?width=140&amp;height=93" /></a></td><td> &#32; submitted by '
            '<a href="https://www.reddit.com/user/me">/u/me</a> <span><a href="https://i.redd.it/bigpic1.jpeg">[link]</a></span>'
            '<a href="https://v.redd.it/abc123xyz">video</a> <a href="https://evil.example/x.jpg">x</a></td></tr></table>')
    m = reddit.media(html)
    assert {"type": "image", "src": "https://i.redd.it/bigpic1.jpeg"} in m
    assert [x["type"] for x in m].count("image") == 1                     # the 140-px thumbnail is skipped
    vid = next(x for x in m if x["type"] == "video")
    assert vid["sources"][0] == "https://v.redd.it/abc123xyz/HLSPlaylist.m3u8" and all(s.startswith("https://v.redd.it/") for s in vid["sources"])
    assert not any("evil.example" in json.dumps(x) for x in m)
    assert reddit.body('<!-- SC_OFF --><div class="md"><p>Hello <script>x</script></p></div><!-- SC_ON --> submitted by') == "<p>Hello </p>"
    assert reddit.is_post_url("https://www.reddit.com/r/homelab/comments/1abcde/rack/") and not reddit.is_post_url("https://evil.example/r/x/comments/1abcde/")

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES ('r/homelab', 'https://www.reddit.com/r/homelab/new/.rss', ?, 'reddit')", (now(),)).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, url, title, content_html, fetched_at, sort_ts) VALUES (?, 't3_1', ?, 'My rack', ?, ?, ?)",
                         (fid, "https://www.reddit.com/r/homelab/comments/1abcde/rack/", html, now(), now())).lastrowid
    full = authed.get(f"/api/v1/accounts/posts?feed_ids={fid}&full=true").json()["items"][0]
    assert full["thread"] is True and full["media"] and "html" in full
    assert "html" not in authed.get(f"/api/v1/accounts/posts?feed_ids={fid}").json()["items"][0]   # cards stay light

    thread_feed = (b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>My rack</title>'
                   b'<entry><id>t3_1</id><title>My rack</title><author><name>/u/me</name></author><updated>2026-11-15T10:00:00Z</updated>'
                   b'<content type="html">&lt;div class="md"&gt;&lt;p&gt;Look at it&lt;/p&gt;&lt;/div&gt; &lt;a href="https://i.redd.it/bigpic1.jpeg"&gt;[link]&lt;/a&gt;</content></entry>'
                   b'<entry><id>t1_a</id><title>/u/fan on My rack</title><author><name>/u/fan</name></author><updated>2026-11-15T11:00:00Z</updated>'
                   b'<content type="html">&lt;div class="md"&gt;&lt;p&gt;Nice! &lt;img src=x onerror=alert(1)&gt;&lt;/p&gt;&lt;/div&gt;</content></entry></feed>')
    reddit._cache.clear()
    with mock.patch("app.social_posts.netguard.request", return_value=resp(thread_feed, url="https://www.reddit.com/r/homelab/comments/1abcde/rack/.rss",
                                                                           ctype="application/atom+xml")) as net:
        t = authed.get(f"/api/v1/accounts/posts/{aid}/thread").json()
        assert net.call_args[0][1] == "https://www.reddit.com/r/homelab/comments/1abcde/rack/.rss"
        authed.get(f"/api/v1/accounts/posts/{aid}/thread")                    # second time: from the cache
        assert net.call_count == 1
    assert t["post"]["body"] == "<p>Look at it</p>" and t["post"]["media"][0]["src"] == "https://i.redd.it/bigpic1.jpeg"
    assert t["post"]["published"] == 1794736800                                # 2026-11-15T10:00:00Z, read as UTC
    assert len(t["comments"]) == 1 and t["comments"][0]["author"] == "/u/fan" and "onerror" not in t["comments"][0]["html"]
    # not a Reddit post / not a social post
    with get_db() as db:
        other = db.execute("INSERT INTO articles (feed_id, guid, url, title, fetched_at, sort_ts) VALUES (?, 'x', 'https://example.org/p', 'P', ?, ?)",
                           (fid, now(), now())).lastrowid
    assert authed.get(f"/api/v1/accounts/posts/{other}/thread").status_code == 422
    assert authed.get("/api/v1/accounts/posts/999999/thread").status_code == 404
