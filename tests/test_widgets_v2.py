"""Widget builder v2: all/any filter matching, drill-down focus, the News + CVEs data source,
new chart styles, free-form widths, and the library's topic shelves / single videos."""
from unittest import mock

import httpx

from app import netguard
from test_cves import ITEMS, cwe_zip  # noqa: F401  (fixtures' data)
from test_insights import entity_id, loaded  # noqa: F401  (pytest fixture re-export)


def aq(client, **body):
    r = client.post("/api/v1/analytics/query", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _load_cves():
    from app import cve_classify, cve_sync
    from app.db import get_db

    with get_db() as db:
        cve_classify.seed_builtin(db)
    entries, owasp = cve_sync.parse_cwe_zip(cwe_zip())
    with get_db() as db:
        db.executemany("INSERT OR REPLACE INTO cwe_entries (id, name, kind) VALUES (?, ?, ?)", entries)
        db.executemany("INSERT OR IGNORE INTO cwe_owasp VALUES (?, ?, ?, ?)", owasp)
        ids = cve_sync.upsert(db, [r for r in (cve_sync.parse_nvd(i) for i in ITEMS) if r])
        cve_classify.classify(db, ids)


# ------------------------------------------------------------------ all / any matching (articles)
def test_article_filters_all_vs_any(loaded):
    _, lockbit = entity_id(loaded, "ransomware-groups", "LockBit")
    _, akira = entity_id(loaded, "ransomware-groups", "Akira")
    _, lazarus = entity_id(loaded, "threat-actors", "Lazarus Group")
    kpi = lambda **f: aq(loaded, type="kpi", days=7, filters=f)["value"]  # noqa: E731
    # one box with several entities: any of them (default) vs all of them
    assert kpi(entity_ids=[lockbit, akira]) == 2
    assert kpi(require_entity_ids=[lockbit, akira]) == 0
    # two boxes: entity AND keyword ("all", default) vs entity OR keyword ("any")
    assert kpi(entity_ids=[lockbit], q="deepfake") == 0
    assert kpi(entity_ids=[lockbit], q="deepfake", match="any") == 2
    assert kpi(entity_ids=[lockbit], q="deepfake", match="all") == 0
    # exclusions always apply, even in "any" mode
    assert kpi(entity_ids=[lockbit, akira], q="deepfake", exclude_entity_ids=[lazarus], match="any") == 2
    # "any" with one box behaves like "all"
    assert kpi(entity_ids=[lockbit], match="any") == 1
    assert loaded.post("/api/v1/analytics/query", json={"type": "kpi", "filters": {"match": "some"}}).status_code == 422


def test_drilldown_focus_is_always_anded(loaded):
    rw, lockbit = entity_id(loaded, "ransomware-groups", "LockBit")
    _, lazarus = entity_id(loaded, "threat-actors", "Lazarus Group")
    base = {"entity_ids": [lazarus], "q": "ransomware", "match": "any"}   # Lazarus OR "ransomware" -> 3 articles
    assert aq(loaded, type="kpi", days=7, filters=base)["value"] == 3
    # clicking the LockBit bar must give LockBit articles only, not "LockBit OR ..."
    arts = aq(loaded, type="articles", days=7, filters={**base, "focus": {"entity_id": lockbit}})["items"]
    assert [a["title"] for a in arts] == ["LockBit hits US hospital"]
    res = aq(loaded, type="breakdown", group_by="watchlist", group_watchlist_id=rw, days=7, filters=base)
    assert {i["label"] for i in res["items"]} == {"LockBit", "Akira"}
    assert loaded.post("/api/v1/analytics/query", json={"type": "kpi", "filters": {"focus": {"entity_id": 0}}}).status_code == 422
    assert loaded.post("/api/v1/analytics/query", json={"type": "kpi", "filters": {"focus": {"sql": "1"}}}).status_code == 422


# ------------------------------------------------------------------ all / any matching (CVEs)
def test_cve_filters_all_vs_any_and_focus(authed):
    _load_cves()
    kpi = lambda **f: aq(authed, dataset="cves", type="kpi", days=7, filters=f)["value"]  # noqa: E731
    crit = kpi(severities=["CRITICAL"])
    kev = kpi(kev_only=True)
    both = kpi(severities=["CRITICAL"], kev_only=True)
    either = kpi(severities=["CRITICAL"], kev_only=True, match="any")
    assert either == crit + kev - both and either >= max(crit, kev) and both <= min(crit, kev)
    # drill-down focus narrows even in "any" mode
    focused = kpi(severities=["CRITICAL"], kev_only=True, match="any", focus={"severity": "HIGH"})
    assert focused == kpi(severities=["HIGH"], kev_only=True)
    assert authed.post("/api/v1/analytics/query", json={"dataset": "cves", "type": "kpi",
                                                        "filters": {"focus": {"severity": "EVIL"}}}).status_code == 422


# ------------------------------------------------------------------ news + CVEs
def test_combined_widget_queries(loaded):
    _load_cves()
    _, lockbit = entity_id(loaded, "ransomware-groups", "LockBit")
    body = {"dataset": "combined", "days": 7, "articles": {"q": "ransomware"}, "cves": {"severities": ["CRITICAL"]}}
    pair = aq(loaded, type="kpi", **body)
    assert pair["type"] == "kpi_pair" and [i["key"] for i in pair["items"]] == ["articles", "cves"]
    assert pair["items"][0]["value"] == 2
    assert pair["items"][1]["value"] == aq(loaded, dataset="cves", type="kpi", days=7, filters={"severities": ["CRITICAL"]})["value"]
    ts = aq(loaded, type="timeseries", bucket="day", **body)
    assert [s["key"] for s in ts["series"]] == ["articles", "cves"] and len(ts["series"][1]["values"]) == len(ts["buckets"])
    assert sum(ts["series"][0]["values"]) == 2 and sum(ts["series"][1]["values"]) == pair["items"][1]["value"]
    mixed = aq(loaded, type="mixed", limit=50, **{**body, "articles": {"entity_ids": [lockbit]}})
    kinds = {i["kind"] for i in mixed["items"]}
    assert kinds == {"article", "cve"}
    stamps = [i["ts"] for i in mixed["items"]]
    assert stamps == sorted(stamps, reverse=True)
    # validation: each side's filters are strict
    bad = loaded.post("/api/v1/analytics/query", json={**body, "type": "kpi", "cves": {"severities": ["NOPE"]}})
    assert bad.status_code == 422
    assert loaded.post("/api/v1/analytics/query", json={**body, "type": "breakdown"}).status_code == 422


# ------------------------------------------------------------------ widgets: styles and widths
def _put(client, widgets):
    d = client.post("/api/v1/dashboards", json={"name": "v2"}).json()
    return client.put(f"/api/v1/dashboards/{d['id']}", json={"name": "v2", "widgets": widgets})


def test_new_chart_styles_widths_and_combined_widgets(authed):
    art = {"type": "timeseries", "days": 30, "group_by": "none", "filters": {}}
    brk = {"type": "breakdown", "days": 30, "group_by": "feed", "filters": {}}
    widgets = [
        {"id": "a1", "title": "Stacked area", "chart": "stackedarea", "query": art, "width": 37.5},
        {"id": "a2", "title": "100%", "chart": "percent", "query": art, "width": 62.5, "height": 333},
        {"id": "a3", "title": "Columns", "chart": "bar", "query": brk, "size": "s"},
        {"id": "a4", "title": "Pie", "chart": "pie", "query": brk},
        {"id": "c1", "title": "Both", "chart": "line", "query": {"dataset": "combined", "type": "timeseries", "days": 30}},
        {"id": "c2", "title": "Both numbers", "chart": "number", "query": {"dataset": "combined", "type": "kpi", "days": 30}},
        {"id": "c3", "title": "Latest", "chart": "list", "query": {"dataset": "combined", "type": "mixed", "days": 30, "limit": 30}},
    ]
    r = _put(authed, widgets)
    assert r.status_code == 200, r.text
    saved = {w["id"]: w for w in r.json()["widgets"]}
    assert saved["a1"]["width"] == 37.5 and saved["a2"]["height"] == 333 and saved["a3"].get("width") is None
    assert saved["c3"]["query"]["dataset"] == "combined"
    # invalid combinations are refused
    for bad in (
        {"id": "x", "title": "x", "chart": "pie", "query": art},                                     # pie is not a time chart
        {"id": "x", "title": "x", "chart": "hbar", "query": {"dataset": "combined", "type": "kpi"}},   # combined kpi = number
        {"id": "x", "title": "x", "chart": "line", "query": art, "width": 5},                        # too narrow
        {"id": "x", "title": "x", "chart": "line", "query": art, "width": 101},
        {"id": "x", "title": "x", "chart": "sparkles", "query": art},
    ):
        assert _put(authed, [bad]).status_code == 422, bad


# ------------------------------------------------------------------ library: single videos and topic shelves
OEMBED = b'{"title": "Intro to ransomware forensics", "author_name": "DFIR Channel", "thumbnail_url": "https://i.ytimg.com/vi/abcdefghijk/hqdefault.jpg"}'


def test_parse_video_id():
    from app.sources import parse_video_id

    good = {"https://www.youtube.com/watch?v=abcdefghijk": "abcdefghijk", "https://youtu.be/abcdefghijk?t=4": "abcdefghijk",
            "youtube.com/shorts/abcdefghijk": "abcdefghijk", "https://m.youtube.com/watch?feature=x&v=abcdefghijk": "abcdefghijk",
            "https://www.youtube.com/live/abcdefghijk": "abcdefghijk"}
    for url, vid in good.items():
        assert parse_video_id(url) == vid, url
    for url in ("https://www.youtube.com/@channel", "https://www.youtube.com/playlist?list=PL123456789012",
                "https://evil.example/watch?v=abcdefghijk", "https://www.youtube.com/watch?v=short", "javascript:alert(1)"):
        assert parse_video_id(url) is None, url


def test_add_single_video_and_shelves(authed):
    calls = []

    def fake(method, url, **kw):
        calls.append(url)
        assert url.startswith("https://www.youtube.com/oembed?")
        return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/json"}), OEMBED, url)

    with mock.patch("app.sources.netguard.request", side_effect=fake):
        r = authed.post("/api/v1/library/videos", json={"url": "https://youtu.be/abcdefghijk"})
        assert r.status_code == 201, r.text
        again = authed.post("/api/v1/library/videos", json={"url": "https://www.youtube.com/watch?v=abcdefghijk"})
    assert r.json()["title"] == "Intro to ransomware forensics" and again.json()["already"] is True
    assert len(calls) == 1  # the duplicate is answered from the database
    meta = authed.get("/api/v1/library/meta").json()
    saved = [c for c in meta["channels"] if c["saved"]]
    # listed under the video's own channel (it was saved from there); its only feed is the saved-videos feed
    assert len(saved) == 1 and saved[0]["videos"] == 1 and saved[0]["title"] == "DFIR Channel"
    assert [f["type"] for f in saved[0]["feeds"]] == ["saved"] and saved[0]["feeds"][0]["title"] == "Saved YouTube videos"
    # the saved-videos feed refreshes without contacting YouTube, and has no channel to back-fill
    from app import history

    with mock.patch("app.sources.netguard.request", side_effect=AssertionError("no network")):
        assert authed.post(f"/api/v1/feeds/{saved[0]['feeds'][0]['id']}/refresh").json()["ok"] is True
        authed.post(f"/api/v1/feeds/{saved[0]['feeds'][0]['id']}/backfill", json={})
        history.backfill_job._thread.join(10)
    assert history.backfill_job.status["state"] == "error" and "one at a time" in history.backfill_job.status["error"]
    assert saved[0]["feeds"][0]["id"] not in history.bulk_feed_ids(None, False, None)
    # categorised by topic: the title says "ransomware" -> on the Ransomware shelf
    sh = authed.get("/api/v1/library/shelves").json()
    names = {s["name"]: s for s in sh["shelves"]}
    assert "Ransomware" in names and names["Ransomware"]["items"][0]["video_id"] == "abcdefghijk"
    assert sh["other"]["total"] == 0
    assert authed.get("/api/v1/library/shelves", params={"state": "watched"}).json()["shelves"] == []
    # validation
    assert authed.post("/api/v1/library/videos", json={"url": "https://www.youtube.com/@somechannel"}).status_code == 422
    assert authed.post("/api/v1/library/videos", json={"url": "https://evil.example/watch?v=abcdefghijk"}).status_code == 422
    assert authed.get("/api/v1/library/shelves", params={"per": 1000}).status_code == 422
    assert authed.get("/api/v1/library/shelves", params={"sort": "1;DROP"}).status_code == 422


def test_single_video_with_api_key_uses_header_and_data_api(authed):
    payload = (b'{"items": [{"id": "abcdefghijk", "snippet": {"title": "Zero-day talk", "channelTitle": "Con", '
               b'"channelId": "UCaaaaaaaaaaaaaaaaaaaaaa", "publishedAt": "2025-02-01T10:00:00Z", "thumbnails": {}}, '
               b'"contentDetails": {"duration": "PT12M3S"}, "statistics": {"viewCount": "1234"}}]}')
    seen = []

    def fake(method, url, **kw):
        seen.append((url, kw.get("headers", {})))
        return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/json"}), payload, url)

    with mock.patch("app.sources.yt_key", return_value="test-key-not-real"), \
         mock.patch("app.sources.netguard.request", side_effect=fake):
        r = authed.post("/api/v1/library/videos", json={"url": "https://www.youtube.com/watch?v=abcdefghijk"})
    assert r.status_code == 201, r.text
    url, headers = seen[0]
    assert url.startswith("https://www.googleapis.com/youtube/v3/videos?") and "test-key-not-real" not in url
    assert headers.get("X-Goog-Api-Key") == "test-key-not-real"
    vid = authed.get("/api/v1/library/videos").json()["items"][0]
    assert vid["duration_s"] == 723 and vid["views"] == 1234 and vid["channel_title"] == "Con"
