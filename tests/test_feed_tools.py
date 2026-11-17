"""Bulk feed actions, the feed troubleshooter, richer collection rules and the collection packs."""

import time
from unittest import mock

import httpx
import pytest

from app import collection_packs, netguard

NOW = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def rss(items, title="Blog"):
    body = "".join(f"<item><title>{t}</title><link>https://blog.example/{g}</link><guid>{g}</guid>"
                   f"<pubDate>{NOW}</pubDate><description>{d}</description></item>" for t, g, d in items)
    return (f'<?xml version="1.0"?><rss version="2.0"><channel><title>{title}</title>'
            f"<link>https://blog.example/</link>{body}</channel></rss>").encode()


def resp(body, status=200, url="https://blog.example/feed/", ctype="application/rss+xml", headers=None):
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype, **(headers or {})}), body, url)


ITEMS = [
    ("Hackers hit a water utility SCADA system", "a1", "An intrusion at a wastewater plant PLC."),
    ("Siemens patches SIMATIC flaws", "a2", "Advisory for CVE-2026-1111 in SIMATIC PLCs."),
    ("New LLM jailbreak technique", "a3", "Prompt injection against an AI agent."),
    ("Weekly roundup", "a4", "Mentions CVE-2026-2222 in passing."),
]


@pytest.fixture()
def feed(authed):
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp(rss(ITEMS))):
        f = authed.post("/api/v1/feeds", json={"url": "https://blog.example/feed/"}).json()
        assert authed.post(f"/api/v1/feeds/{f['id']}/refresh").json()["new"] == 4
    return f["id"]


def tagged(authed, tag_id):
    return sorted(a["title"] for a in authed.get(f"/api/v1/articles?tag_id={tag_id}&limit=50").json()["items"])


def seed_cves():
    from app.db import get_db, now

    with get_db() as db:
        for cid, sev in (("CVE-2026-1111", "CRITICAL"), ("CVE-2026-2222", "LOW")):
            db.execute("INSERT INTO cves (id, severity, fetched_at) VALUES (?, ?, ?)", (cid, sev, now()))
        db.execute("INSERT INTO cve_cwes (cve_id, cwe_id) VALUES ('CVE-2026-1111', 79)")
        db.execute("INSERT OR IGNORE INTO cwe_owasp (cwe_id, edition, code, name) VALUES (79, '2025', 'A05', 'Injection')")


# ------------------------------------------------------------------ rules
def test_rule_and_groups_and_cve_conditions(authed, feed):
    seed_cves()
    tag = authed.post("/api/v1/tags", json={"name": "OT attacks"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "OT attacks", "keywords": ["SCADA", "PLC", "SIMATIC"],
                                          "require_keywords": ["intrusion", "hackers"], "tag_id": tag})
    assert r.status_code == 201 and r.json()["require_keywords"] == ["intrusion", "hackers"]
    assert authed.post(f"/api/v1/rules/{r.json()['id']}/apply").json()["newly_filed"] == 1
    assert tagged(authed, tag) == ["Hackers hit a water utility SCADA system"]

    crit = authed.post("/api/v1/tags", json={"name": "CVE: Critical"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "crit", "cve_severity": "CRITICAL", "tag_id": crit})
    assert r.status_code == 201
    authed.post(f"/api/v1/rules/{r.json()['id']}/apply")
    assert tagged(authed, crit) == ["Siemens patches SIMATIC flaws"]

    inj = authed.post("/api/v1/tags", json={"name": "OWASP A05"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "a05", "cve_owasp": "2025:A05", "tag_id": inj})
    authed.post(f"/api/v1/rules/{r.json()['id']}/apply")
    assert tagged(authed, inj) == ["Siemens patches SIMATIC flaws"]


def test_rule_validation(authed, feed):
    tag = authed.post("/api/v1/tags", json={"name": "T"}).json()["id"]
    # no keywords, no scope, no CVE condition: would match nothing (or everything) - refused
    assert authed.post("/api/v1/rules", json={"name": "x", "tag_id": tag}).status_code == 422
    assert authed.post("/api/v1/rules", json={"name": "x", "cve_owasp": "2025:A11", "tag_id": tag}).status_code == 422
    assert authed.post("/api/v1/rules", json={"name": "x", "cve_severity": "SEVERE", "tag_id": tag}).status_code == 422
    # empty keywords + a feed scope = everything from that feed
    r = authed.post("/api/v1/rules", json={"name": "all", "feed_id": feed, "tag_id": tag})
    assert r.status_code == 201
    assert authed.post(f"/api/v1/rules/{r.json()['id']}/apply").json()["newly_filed"] == 4


def test_new_rules_run_on_new_articles(authed, feed):
    tag = authed.post("/api/v1/tags", json={"name": "AI sec"}).json()["id"]
    authed.post("/api/v1/rules", json={"name": "ai", "keywords": ["jailbreak"], "require_keywords": ["prompt injection"], "tag_id": tag})
    more = rss(ITEMS + [("Another jailbreak", "a5", "More prompt injection.")])
    with mock.patch("app.fetcher.netguard.request", return_value=resp(more)):
        assert authed.post(f"/api/v1/feeds/{feed}/refresh").json()["new"] == 1
    assert tagged(authed, tag) == ["Another jailbreak"]  # rules run on new articles only, until applied


# ------------------------------------------------------------------ packs
def test_collection_packs_install_idempotent_and_backfill(authed, feed):
    from app.api import automation

    packs = authed.get("/api/v1/rules/packs").json()["packs"]
    assert {p["slug"] for p in packs} == set(collection_packs.PACK_BY_SLUG)
    with mock.patch.object(automation.threading, "Thread") as thread:
        res = authed.post("/api/v1/rules/packs", json={"slugs": ["ot", "cve"]}).json()
        assert res["collections_created"] == 4 + len(collection_packs.PACK_BY_SLUG["cve"]["collections"]) and res["backfill_started"]
        target, args = thread.call_args.kwargs["target"], thread.call_args.kwargs["args"]
    target(*args)  # run the back-fill inline
    seed_cves()
    tags = {t["name"]: t["id"] for t in authed.get("/api/v1/tags").json()}
    assert tagged(authed, tags["OT/ICS: Attacks & breaches"]) == ["Hackers hit a water utility SCADA system"]
    assert "Siemens patches SIMATIC flaws" in tagged(authed, tags["OT/ICS: Vulnerabilities & CVEs"])
    # again: nothing new, nothing duplicated
    again = authed.post("/api/v1/rules/packs", json={"slugs": ["ot"]}).json()
    assert again["collections_created"] == 0 and again["rules_created"] == 0
    assert authed.post("/api/v1/rules/packs", json={"slugs": ["nope"]}).status_code == 422
    assert next(p for p in authed.get("/api/v1/rules/packs").json()["packs"] if p["slug"] == "ot")["installed"] == 4
    # the legacy starter-pack endpoint is the core pack
    assert authed.post("/api/v1/rules/starter-pack").json()["rules_created"] == 7


def test_pack_rules_are_well_formed():
    names = set()
    for pack in collection_packs.PACKS:
        for coll in pack["collections"]:
            assert coll["name"].lower() not in names and len(coll["name"]) <= 100
            names.add(coll["name"].lower())
            for spec in coll["rules"]:
                kws = spec.get("keywords", []) + spec.get("require", []) + spec.get("exclude", [])
                assert len(spec.get("keywords", [])) <= 100 and all(0 < len(k) <= 100 for k in kws)
                assert (spec.get("keywords") or spec.get("folder") or spec.get("cve_severity") or spec.get("cve_owasp")
                        or spec.get("cve_category"))


# ------------------------------------------------------------------ bulk feeds
def test_bulk_feed_actions(authed, feed):
    with mock.patch("app.api.content._refresh_async"):
        other = authed.post("/api/v1/feeds", json={"url": "https://other.example/rss"}).json()["id"]
    folder = authed.post("/api/v1/folders", json={"name": "OT"}).json()["id"]
    ids = [feed, other]
    assert authed.post("/api/v1/feeds/bulk", json={"ids": ids, "action": "move", "folder_id": folder}).json()["updated"] == 2
    assert authed.post("/api/v1/feeds/bulk", json={"ids": ids, "action": "set_refresh", "refresh_minutes": 30}).json()["updated"] == 2
    assert authed.post("/api/v1/feeds/bulk", json={"ids": [other], "action": "disable"}).json()["updated"] == 1
    feeds = {f["id"]: f for f in authed.get("/api/v1/feeds").json()}
    assert feeds[feed]["folder_id"] == folder and feeds[feed]["refresh_minutes"] == 30 and not feeds[other]["enabled"]
    assert authed.post("/api/v1/feeds/bulk", json={"ids": ids, "action": "move", "folder_id": None}).json()["updated"] == 2
    assert authed.post("/api/v1/feeds/bulk", json={"ids": ids, "action": "move", "folder_id": 999}).status_code == 422
    assert authed.post("/api/v1/feeds/bulk", json={"ids": ids, "action": "explode"}).status_code == 422
    assert authed.post("/api/v1/feeds/bulk", json={"ids": [], "action": "enable"}).status_code == 422
    assert authed.post("/api/v1/feeds/bulk", json={"ids": [other], "action": "delete"}).json()["updated"] == 1
    assert [f["id"] for f in authed.get("/api/v1/feeds").json()] == [feed]


def test_changing_url_clears_errors(authed, feed):
    from app.db import get_db

    with get_db() as db:
        db.execute("UPDATE feeds SET error_count = 5, last_error = 'HTTP 404' WHERE id = ?", (feed,))
    f = authed.patch(f"/api/v1/feeds/{feed}", json={"url": "https://blog.example/new-feed/"}).json()
    assert f["error_count"] == 0 and f["last_error"] is None


# ------------------------------------------------------------------ troubleshooter
HOME = b'<html><head><link rel="alternate" type="application/rss+xml" href="/blog/rss.xml"></head><body>hi</body></html>'


def fake_web(routes):
    def request(method, url, **kw):
        if url not in routes:
            return resp(b"<html>not found</html>", 404, url, "text/html")
        value = routes[url]
        if isinstance(value, Exception):
            raise value
        return value
    return request


def diagnose(authed, feed, routes, resolves=True):
    resolve = (lambda *a, **k: []) if resolves else mock.Mock(side_effect=netguard.FetchError("DNS resolution failed"))
    with mock.patch("app.feed_doctor.netguard.request", side_effect=fake_web(routes)), \
            mock.patch("app.feed_doctor.netguard.resolve_host", resolve):
        r = authed.post(f"/api/v1/feeds/{feed}/diagnose")
    assert r.status_code == 200, r.text
    return r.json()


def test_doctor_finds_the_new_address(authed, feed):
    rep = diagnose(authed, feed, {
        "https://blog.example/": resp(HOME, url="https://blog.example/", ctype="text/html"),
        "https://blog.example/blog/rss.xml": resp(rss(ITEMS, "New feed"), url="https://blog.example/blog/rss.xml"),
    })
    assert rep["verdict"] == "moved"
    assert rep["suggestions"][0]["url"] == "https://blog.example/blog/rss.xml"
    assert rep["suggestions"][0]["how"] == "declared" and rep["suggestions"][0]["items"] == 4


def test_doctor_working_blocked_dns_gone(authed, feed):
    ok = diagnose(authed, feed, {"https://blog.example/feed/": resp(rss(ITEMS))})
    assert ok["verdict"] == "working" and not ok["suggestions"]
    cf = resp(b"<html>Just a moment...</html>", 403, ctype="text/html", headers={"cf-ray": "abc", "server": "cloudflare"})
    blocked = diagnose(authed, feed, {"https://blog.example/feed/": cf, "https://blog.example/": cf})
    assert blocked["verdict"] == "blocked" and any("bot checks" in a for a in blocked["advice"])
    dns = diagnose(authed, feed, {}, resolves=False)
    assert dns["verdict"] == "dns"
    gone = diagnose(authed, feed, {"https://blog.example/": resp(b"<html>home</html>", url="https://blog.example/", ctype="text/html")})
    assert gone["verdict"] == "gone"
    assert authed.post("/api/v1/feeds/9999/diagnose").status_code == 404


def test_doctor_background_run(authed, feed):
    from app import feed_doctor
    from app.db import get_db

    with get_db() as db:
        db.execute("UPDATE feeds SET error_count = 3, last_error = 'HTTP 404' WHERE id = ?", (feed,))
    with mock.patch.object(feed_doctor.threading, "Thread") as thread, \
            mock.patch("app.feed_doctor.time.sleep"):
        assert authed.post("/api/v1/feeds/diagnose", json={}).json() == {"started": True, "total": 1}
        run, args = thread.call_args.kwargs["target"], thread.call_args.kwargs["args"]
        with mock.patch("app.feed_doctor.netguard.request", side_effect=fake_web({"https://blog.example/feed/": resp(rss(ITEMS))})), \
                mock.patch("app.feed_doctor.netguard.resolve_host", lambda *a, **k: []):
            run(*args)
    st = authed.get("/api/v1/feeds/diagnose").json()
    assert not st["running"] and st["done"] == 1 and st["results"][0]["verdict"] == "working"
    assert authed.post("/api/v1/feeds/diagnose/cancel").json() == {"ok": True}


def test_keywords_in_title(authed, feed):
    tag = authed.post("/api/v1/tags", json={"name": "Title OT"}).json()["id"]
    # "PLC" is in the body of the first item and the title of none: with keywords_in_title nothing matches on it
    r = authed.post("/api/v1/rules", json={"name": "t", "keywords": ["PLC", "PLCs"], "keywords_in_title": True, "tag_id": tag})
    assert r.status_code == 201 and r.json()["keywords_in_title"] is True
    assert authed.post(f"/api/v1/rules/{r.json()['id']}/apply").json()["newly_filed"] == 0
    r = authed.post("/api/v1/rules", json={"name": "t2", "keywords": ["SCADA"], "require_keywords": ["wastewater"],
                                          "keywords_in_title": True, "tag_id": tag})
    assert authed.post(f"/api/v1/rules/{r.json()['id']}/apply").json()["newly_filed"] == 1  # title + body word


def test_cve_category_and_kev_conditions(authed, feed):
    from app.db import get_db

    seed_cves()
    with get_db() as db:
        db.execute("UPDATE cves SET kev = 1, kev_ransomware = 1 WHERE id = 'CVE-2026-2222'")
        db.execute("INSERT OR IGNORE INTO cve_categories (slug, name, builtin) VALUES ('rce', 'Remote code execution', 1)")
        cat = db.execute("SELECT id FROM cve_categories WHERE slug = 'rce'").fetchone()["id"]
        db.execute("INSERT INTO cve_category_map (cve_id, category_id) VALUES ('CVE-2026-1111', ?)", (cat,))
    rce = authed.post("/api/v1/tags", json={"name": "CVEs: RCE"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "rce", "cve_category": "rce", "tag_id": rce})
    assert r.status_code == 201 and r.json()["cve_category"] == "rce"
    authed.post(f"/api/v1/rules/{r.json()['id']}/apply")
    assert tagged(authed, rce) == ["Siemens patches SIMATIC flaws"]
    kev = authed.post("/api/v1/tags", json={"name": "CVEs: KEV"}).json()["id"]
    r = authed.post("/api/v1/rules", json={"name": "kev", "cve_category": "kev-ransomware", "tag_id": kev})
    authed.post(f"/api/v1/rules/{r.json()['id']}/apply")
    assert tagged(authed, kev) == ["Weekly roundup"]
    # unknown category or malformed slug: refused
    assert authed.post("/api/v1/rules", json={"name": "x", "cve_category": "nope", "tag_id": kev}).status_code == 422
    assert authed.post("/api/v1/rules", json={"name": "x", "cve_category": "../x", "tag_id": kev}).status_code == 422


def test_threat_advisories_pack_rules_keep_cve_listings_out(authed):
    from app.api import automation

    folder = authed.post("/api/v1/folders", json={"name": "Advisories"}).json()["id"]
    items = [("Chinese state actors target telecoms: joint advisory", "b1", "Guidance from partners."),
             ("CISA Adds Two Known Exploited Vulnerabilities to Catalog", "b2", "CVE-2026-1111."),
             ("Siemens SIMATIC S7 (Update A)", "b3", "Affected products.")]
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp(rss(items, "CISA"), url="https://gov.example/feed/")):
        f = authed.post("/api/v1/feeds", json={"url": "https://gov.example/feed/", "folder_id": folder}).json()
        authed.post(f"/api/v1/feeds/{f['id']}/refresh")
    news = [("FBI and CISA warn of new ransomware tactics", "c1", "An alert."),
            ("CVE-2026-1111 exploited: CISA warns", "c2", "A CVE story."),
            ("Startup raises money", "c3", "Nothing to see.")]
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp(rss(news, "News"), url="https://news.example/feed/")):
        g = authed.post("/api/v1/feeds", json={"url": "https://news.example/feed/"}).json()
        authed.post(f"/api/v1/feeds/{g['id']}/refresh")
    with mock.patch.object(automation.threading, "Thread") as thread:
        authed.post("/api/v1/rules/packs", json={"slugs": ["practice"]})
        target, args = thread.call_args.kwargs["target"], thread.call_args.kwargs["args"]
    target(*args)
    tags = {t["name"]: t["id"] for t in authed.get("/api/v1/tags").json()}
    assert tagged(authed, tags["Threat advisories"]) == [
        "Chinese state actors target telecoms: joint advisory", "FBI and CISA warn of new ransomware tactics",
        "Siemens SIMATIC S7 (Update A)"]


def test_hide_read_setting_defaults_on(authed):
    assert authed.get("/api/v1/settings").json()["hide_read"] is True
    assert authed.patch("/api/v1/settings", json={"hide_read": False}).json()["hide_read"] is False
    assert authed.patch("/api/v1/settings", json={"hide_read": "yes"}).status_code == 422


def test_keep_articles_time_frame(authed, feed):
    from app.db import get_db, now

    old = now() - 3 * 365 * 86400
    with get_db() as db:  # two of the four articles become 3 years old; one of those is starred, so it stays
        ids = [r[0] for r in db.execute("SELECT id FROM articles WHERE feed_id = ? ORDER BY id", (feed,))]
        db.execute(f"UPDATE articles SET sort_ts = ? WHERE id IN ({ids[0]}, {ids[1]})", (old,))
        db.execute("UPDATE articles SET is_starred = 1 WHERE id = ?", (ids[1],))
    dry = authed.post("/api/v1/feeds/keep", json={"scope": "all", "days": 365, "dry_run": True}).json()
    assert dry["removed"] == 1 and dry["feeds"] == 1 and dry["oldest"] == old
    assert authed.get(f"/api/v1/articles?feed_id={feed}").json()["total"] == 4      # dry run removed nothing
    r = authed.post("/api/v1/feeds/keep", json={"scope": "feeds", "feed_ids": [feed], "days": 365}).json()
    assert r["removed"] == 1
    assert authed.get(f"/api/v1/articles?feed_id={feed}").json()["total"] == 3
    with get_db() as db:
        assert db.execute("SELECT retention_days FROM feeds WHERE id = ?", (feed,)).fetchone()[0] == 365  # stays trimmed
    assert authed.post("/api/v1/feeds/keep", json={"scope": "all", "days": 0}).json()["removed"] == 0
    for bad in ({"scope": "folder", "days": 30}, {"scope": "feeds", "days": 30}, {"scope": "all", "days": -1},
                {"scope": "all", "days": 40000}, {"scope": "nope", "days": 30}):
        assert authed.post("/api/v1/feeds/keep", json=bad).status_code == 422, bad


def test_keep_feeds_applies_to_the_chosen_kinds(authed):
    from app.db import get_db, now

    old = now() - 2000 * 86400
    with get_db() as db:
        ids = {}
        for kind, plat in (("rss", None), ("podcast", None), ("youtube", None), ("rss", "mastodon")):
            fid = db.execute("INSERT INTO feeds (title, url, kind, social_platform, created_at) VALUES (?, ?, ?, ?, ?)",
                             (f"{kind}{plat}", f"https://{kind}{plat}.example/f", kind, plat, now())).lastrowid
            ids[(kind, plat)] = fid
            db.execute("INSERT INTO articles (feed_id, guid, title, text_content, published, fetched_at, sort_ts) VALUES (?, 'old', 'Old item', '', ?, ?, ?)",
                       (fid, old, now(), old))
    body = {"scope": "feeds", "feed_ids": list(ids.values()), "days": 365}
    # one kind: only the article feed changes
    dry = authed.post("/api/v1/feeds/keep", json={**body, "kinds": ["articles"], "dry_run": True}).json()
    assert (dry["feeds"], dry["removed"], dry["skipped"]) == (1, 1, 3)
    # several kinds, or all together (kinds omitted): every chosen feed changes - podcasts, YouTube and accounts too
    two = authed.post("/api/v1/feeds/keep", json={**body, "kinds": ["podcasts", "videos"], "dry_run": True}).json()
    assert (two["feeds"], two["removed"]) == (2, 2)
    done = authed.post("/api/v1/feeds/keep", json=body).json()
    assert (done["feeds"], done["removed"], done["skipped"]) == (4, 4, 0)
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM articles WHERE guid = 'old'").fetchone()[0] == 0
        kept = {r[0]: r[1] for r in db.execute("SELECT id, retention_days FROM feeds")}
    assert set(kept.values()) == {365}
    # scope=all with a kind: a long retention reaches podcasts, YouTube and accounts as well
    forever = authed.post("/api/v1/feeds/keep", json={"scope": "all", "days": 0, "kinds": ["podcasts", "videos", "accounts"]}).json()
    assert forever["feeds"] == 3
    with get_db() as db:
        rows = {r[0]: (r[1], r[2]) for r in db.execute("SELECT id, retention_days, max_articles FROM feeds")}
    assert rows[ids[("rss", None)]][0] == 365
    assert all(rows[ids[k]] == (0, 0) for k in (("podcast", None), ("youtube", None), ("rss", "mastodon")))
    assert authed.post("/api/v1/feeds/keep", json={**body, "kinds": ["bogus"]}).status_code == 422
