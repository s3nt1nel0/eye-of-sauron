import time
from unittest import mock

import httpx
import pytest

from app import netguard
from app.entities import Matcher, alias_key

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Intel</title><link>https://example.com/</link>
<item><title>LockBit hits US hospital</title><link>https://example.com/1</link><guid>1</guid>
<description>The LockBit ransomware gang attacked a hospital in the United States.</description></item>
<item><title>Akira ransomware targets German manufacturer</title><link>https://example.com/2</link><guid>2</guid>
<description>Akira claimed a manufacturing firm in Germany.</description></item>
<item><title>Lazarus Group uses deepfake job interviews</title><link>https://example.com/3</link><guid>3</guid>
<description>North Korean hackers (Lazarus) used deepfakes. Let us polish the report.</description></item>
<item><title>Children play outside</title><link>https://example.com/4</link><guid>4</guid>
<description>Nothing to see; a hive of bees and some fog.</description></item>
</channel></rss>"""


def wait_index(client):
    for _ in range(100):
        if not client.get("/api/v1/watchlists/status").json()["indexing"]:
            return
        time.sleep(0.05)
    raise AssertionError("indexing did not finish")


@pytest.fixture()
def loaded(authed):
    resp = netguard.SafeResponse(200, httpx.Headers({"content-type": "application/rss+xml"}), RSS,
                                 "https://example.com/feed")
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp):
        feed = authed.post("/api/v1/feeds", json={"url": "https://example.com/feed"}).json()
        assert authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()["new"] == 4
    wait_index(authed)
    return authed


def entity_id(client, slug, name):
    wl = next(w for w in client.get("/api/v1/watchlists").json() if w["slug"] == slug)
    detail = client.get(f"/api/v1/watchlists/{wl['id']}").json()
    return wl["id"], next(e["id"] for e in detail["entities"] if e["name"] == name)


# ------------------------------------------------------------------ matcher
def test_alias_case_rules():
    assert alias_key("US") == (True, ("US",))
    assert alias_key("=Polish") == (True, ("Polish",))
    assert alias_key("Lazarus Group") == (False, ("lazarus", "group"))
    assert alias_key("U.S.") == (True, ("U", "S"))
    assert alias_key("!!!") is None


def test_matcher_tokens_and_case():
    m = Matcher([(1, "United States", '["US", "U.S."]'), (2, "Poland", '["=Polish"]'),
                 (3, "Play (ransomware)", "[]")])
    assert m.match("Attack on US firms") == {1}
    assert m.match("tell us more") == set()
    assert m.match("The U.S. government") == {1}
    assert m.match("polish your shoes") == set()
    assert m.match("Polish bank") == {2}
    assert m.match("Kids play outside") == set()
    assert m.match("Play ransomware strikes") == {3}
    assert m.match("unitedstates") == set()


# ------------------------------------------------------------------ extraction + analytics
def test_builtin_watchlists_seeded(authed):
    slugs = {w["slug"] for w in authed.get("/api/v1/watchlists").json()}
    assert {"ransomware-groups", "threat-actors", "ai-threats", "countries", "sectors", "vendors"} <= slugs


def test_extraction_and_breakdown(loaded):
    rw, _ = entity_id(loaded, "ransomware-groups", "LockBit")
    res = loaded.post("/api/v1/analytics/query", json={
        "type": "breakdown", "group_by": "watchlist", "group_watchlist_id": rw, "days": 30}).json()
    labels = {i["label"]: i["count"] for i in res["items"]}
    assert labels == {"LockBit": 1, "Akira": 1}  # "play", "hive", "fog" in article 4 are not matched

    co, _ = entity_id(loaded, "countries", "United States")
    res = loaded.post("/api/v1/analytics/query", json={
        "type": "breakdown", "group_by": "watchlist", "group_watchlist_id": co,
        "filters": {"watchlist_ids": [rw]}}).json()
    labels = {i["label"] for i in res["items"]}
    assert labels == {"United States", "Germany"}  # co-mentioned with ransomware; "Polish"/"us" not matched


def test_kpi_timeseries_articles(loaded):
    ta, lazarus = entity_id(loaded, "threat-actors", "Lazarus Group")
    kpi = loaded.post("/api/v1/analytics/query", json={"type": "kpi", "days": 7,
                                                       "filters": {"entity_ids": [lazarus]}}).json()
    assert kpi["value"] == 1 and kpi["previous"] == 0
    ts = loaded.post("/api/v1/analytics/query", json={"type": "timeseries", "days": 14, "bucket": "day",
                                                      "group_by": "watchlist", "group_watchlist_id": ta}).json()
    assert len(ts["buckets"]) in (14, 15)
    assert ts["series"][0]["label"] == "Lazarus Group" and sum(ts["series"][0]["values"]) == 1
    for bucket in ("week", "month"):
        r = loaded.post("/api/v1/analytics/query", json={"type": "timeseries", "days": 120, "bucket": bucket})
        assert r.status_code == 200 and sum(r.json()["series"][0]["values"]) == 4
    arts = loaded.post("/api/v1/analytics/query", json={"type": "articles", "filters": {"q": "deepfake"}}).json()
    assert [a["title"] for a in arts["items"]] == ["Lazarus Group uses deepfake job interviews"]
    inj = loaded.post("/api/v1/analytics/query", json={"type": "kpi", "filters": {"q": '") OR 1=1 --'}}).json()
    assert inj["value"] == 0


def test_analytics_validation(authed):
    q = lambda body: authed.post("/api/v1/analytics/query", json=body).status_code  # noqa: E731
    assert q({"type": "breakdown"}) == 422                      # needs group_by
    assert q({"type": "kpi", "group_by": "watchlist"}) == 422   # needs watchlist id
    assert q({"type": "kpi", "days": 99999}) == 422
    assert q({"type": "kpi", "filters": {"tag_ids": list(range(500))}}) == 422
    assert q({"type": "kpi", "evil": 1}) == 422


def test_user_entity_triggers_reindex(loaded):
    wl = loaded.post("/api/v1/watchlists", json={"name": "My org", "entities": [
        {"name": "Acme Corp", "aliases": ["Acme"]}]}).json()
    eid = wl["entities"][0]["id"]
    loaded.patch(f"/api/v1/entities/{eid}", json={"aliases": ["hospital"]})
    wait_index(loaded)
    detail = loaded.get(f"/api/v1/watchlists/{wl['id']}").json()
    assert detail["entities"][0]["mentions"] == 1
    assert loaded.post("/api/v1/watchlists", json={"name": "x", "entities": [{"name": "!!!"}]}).status_code == 422


# ------------------------------------------------------------------ dashboards
def test_dashboard_crud_and_validation(authed):
    widget = {"id": "w1", "title": "Total", "chart": "number", "size": "s", "query": {"type": "kpi"}}
    d = authed.post("/api/v1/dashboards", json={"name": "Mine", "widgets": [widget]}).json()
    assert d["widgets"][0]["query"]["days"] == 30
    bad = {**widget, "chart": "donut"}
    assert authed.put(f"/api/v1/dashboards/{d['id']}", json={"name": "Mine", "widgets": [bad]}).status_code == 422
    bad_id = {**widget, "id": "<script>"}
    assert authed.put(f"/api/v1/dashboards/{d['id']}", json={"name": "Mine", "widgets": [bad_id]}).status_code == 422
    assert authed.get("/api/v1/dashboards").json()[0]["widget_count"] == 1
    assert authed.delete(f"/api/v1/dashboards/{d['id']}").status_code == 200


def test_all_templates_build_and_run(loaded):
    for t in loaded.get("/api/v1/dashboard-templates").json():
        d = loaded.post(f"/api/v1/dashboard-templates/{t['key']}").json()
        assert len(d["widgets"]) >= (4 if t["key"] == "internet" else 8), t["key"]
        for w in d["widgets"]:
            r = loaded.post("/api/v1/analytics/query", json=w["query"])
            assert r.status_code == 200, (t["key"], w["title"], r.text)


def test_read_token_can_query_but_not_edit(authed):
    tok = authed.post("/api/v1/tokens", json={"name": "ro", "scope": "read"}).json()["token"]
    authed.cookies.clear()
    authed.headers.pop("X-CSRF-Token")
    h = {"Authorization": f"Bearer {tok}"}
    assert authed.post("/api/v1/analytics/query", json={"type": "kpi"}, headers=h).status_code == 200
    assert authed.post("/api/v1/dashboards", json={"name": "x"}, headers=h).status_code == 403


# ------------------------------------------------------------------ refresh intervals
def test_bulk_interval_and_ui_mode(authed):
    with mock.patch("app.api.content._refresh_async"):
        folder = authed.post("/api/v1/folders", json={"name": "Intel"}).json()
        authed.post("/api/v1/feeds", json={"url": "https://a.example/f", "folder_id": folder["id"]})
        authed.post("/api/v1/feeds", json={"url": "https://b.example/f"})
    r = authed.post("/api/v1/feeds/bulk-interval", json={"scope": "folder", "folder_id": folder["id"],
                                                         "refresh_minutes": 10})
    assert r.json() == {"updated": 1}
    assert authed.post("/api/v1/feeds/bulk-interval", json={"scope": "all", "refresh_minutes": 2}).status_code == 422
    assert authed.post("/api/v1/feeds/bulk-interval", json={"scope": "all", "refresh_minutes": None}).json() == {"updated": 2}
    assert authed.patch("/api/v1/settings", json={"ui_mode": "dashboard"}).json()["ui_mode"] == "dashboard"


def test_drilldown_filters(loaded):
    _, lockbit = entity_id(loaded, "ransomware-groups", "LockBit")
    _, us = entity_id(loaded, "countries", "United States")
    _, de = entity_id(loaded, "countries", "Germany")
    q = lambda f: loaded.post("/api/v1/analytics/query", json={"type": "kpi", "filters": f}).json()["value"]  # noqa: E731
    assert q({"require_entity_ids": [lockbit, us]}) == 1
    assert q({"require_entity_ids": [lockbit, de]}) == 0
    old = loaded.post("/api/v1/analytics/query", json={"type": "kpi", "days": 1, "until_ts": 1000}).json()
    assert old["value"] == 0


def test_ot_watchlists_aliases_and_versioned_seeding(authed):
    """OT actors resolve through any vendor alias; new built-in lists reach existing installs once."""
    from app import entities
    from app.db import get_db, now

    lists = {w["slug"]: w for w in authed.get("/api/v1/watchlists").json()}
    assert {"ot-threat-actors", "ics-malware", "ot-attack-types"} <= set(lists)
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('OT', 'https://ot.example/feed', ?)", (now(),)).lastrowid
        texts = {
            "volt": "Vanguard Panda keeps pre-positioning in US utilities, Microsoft calls it Volt Typhoon",
            "sandworm": "APT44 tied to Polish grid wiper attack",
            "cyber": "Storm-0784 defaced Unitronics PLCs at a water utility",
            "mineral": "Graphite and azurite prices rose; the Electrum wallet released an update",
        }
        ids = {}
        for k, t in texts.items():
            ids[k] = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, published, fetched_at, sort_ts) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?)", (fid, k, t, t, now(), now(), now())).lastrowid
        entities.extract_for_articles(db, list(ids.values()))
        found = {k: {r[0] for r in db.execute("SELECT e.name FROM article_entities ae JOIN entities e ON e.id = ae.entity_id "
                                              "JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = 'ot-threat-actors' "
                                              "AND ae.article_id = ?", (aid,))} for k, aid in ids.items()}
    assert found["volt"] == {"VOLTZITE (Volt Typhoon)"}
    assert found["sandworm"] == {"ELECTRUM (Sandworm / APT44)"}
    assert found["cyber"] == {"BAUXITE (CyberAv3ngers)"}
    assert found["mineral"] == set()  # case-sensitive Dragos names don't hit minerals / products
    # deleting a built-in list keeps it deleted; a newly added built-in would still be offered
    authed.delete(f"/api/v1/watchlists/{lists['ics-malware']['id']}")
    assert entities.seed_builtin_watchlists() is False
    assert "ics-malware" not in {w["slug"] for w in authed.get("/api/v1/watchlists").json()}


def test_legacy_install_receives_new_builtin_lists(authed):
    from app import entities
    from app.db import get_db

    with get_db() as db:  # simulate a pre-0.9 install: old flag only, OT lists absent
        db.execute("DELETE FROM watchlists WHERE slug IN ('ot-threat-actors', 'ics-malware', 'ot-attack-types')")
        db.execute("DELETE FROM settings WHERE key = ?", (entities.SEEDED_SLUGS_KEY,))
    assert entities.seed_builtin_watchlists() is True
    slugs = {w["slug"] for w in authed.get("/api/v1/watchlists").json()}
    assert {"ot-threat-actors", "ics-malware", "ot-attack-types", "ransomware-groups"} <= slugs


def test_threat_map_assets_and_ot_sector_lists(authed):
    """The Threat Map's static geometry is served same-origin; OT sector/context lists drive its OT layers."""
    r = authed.get("/static/world-map.json")
    assert r.status_code == 200
    geo = r.json()
    names = {c["name"] for c in geo["countries"]}
    assert len(geo["countries"]) > 150 and "Antarctica" not in names
    assert {"United States of America", "Russia", "China", "Turkey"} <= names
    assert all(c["d"].startswith("M") and "<" not in c["d"] for c in geo["countries"])
    slugs = {w["slug"] for w in authed.get("/api/v1/watchlists").json()}
    assert {"ot-sectors", "ot-context"} <= slugs
    d = authed.post("/api/v1/dashboard-templates/ot-sectors").json()
    assert d["name"] == "OT sectors & industries" and len(d["widgets"]) >= 12


def test_threat_map_actor_and_attack_type_focus(authed):
    """Threat Map focus: one actor + one attack type → the countries and sectors it was reported against."""
    from app import entities
    from app.db import get_db, now

    assert "attack-types" in {w["slug"] for w in authed.get("/api/v1/watchlists").json()}
    co, _ = entity_id(authed, "countries", "Germany")
    se, _ = entity_id(authed, "sectors", "Healthcare")
    _, lockbit = entity_id(authed, "ransomware-groups", "LockBit")
    _, ransom = entity_id(authed, "attack-types", "Ransomware")
    _, ddos = entity_id(authed, "attack-types", "DDoS")
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('TM', 'https://tm.example/feed', ?)", (now(),)).lastrowid
        texts = {
            "a": "LockBit ransomware attack hits a German hospital",
            "b": "LockBit affiliates arrested in France",
            "c": "DDoS attack disrupts banks in Japan",
        }
        ids = [db.execute("INSERT INTO articles (feed_id, guid, title, text_content, published, fetched_at, sort_ts) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?)", (fid, k, t, t, now(), now(), now())).lastrowid for k, t in texts.items()]
        entities.extract_for_articles(db, ids)

    def breakdown(watchlist, filters):
        res = authed.post("/api/v1/analytics/query", json={"type": "breakdown", "group_by": "watchlist",
                                                             "group_watchlist_id": watchlist, "days": 30, "filters": filters})
        assert res.status_code == 200
        return {i["label"]: i["count"] for i in res.json()["items"]}

    focus = {"entity_ids": [lockbit], "require_entity_ids": [ransom]}
    assert breakdown(co, focus) == {"Germany": 1}           # the France article never says "ransomware"
    assert breakdown(se, focus) == {"Healthcare": 1}
    assert breakdown(co, {"entity_ids": [lockbit]}) == {"Germany": 1, "France": 1}
    assert breakdown(co, {"require_entity_ids": [ddos]}) == {"Japan": 1}
