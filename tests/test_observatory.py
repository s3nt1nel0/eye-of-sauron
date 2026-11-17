"""🔭 Observatory: the background refresh (sources simulated - nothing is fetched), every panel, the query dataset,
the templates and the one-time dashboard update."""

import datetime as dt
from unittest import mock

from app import observatory as obs

NOW = dt.datetime.now(dt.UTC)


def fake_get(url, limit=5_000_000):
    if "spamhaus" in url:
        return [{"asn": 64500, "cc": "RU", "asname": "BAD-NET", "domain": "bad.example"},
                {"asn": 64501, "cc": "SC", "asname": "WORSE-NET", "domain": "worse.example"}]
    if "topports" in url:
        return {"0": {"rank": 1, "targetport": 23, "records": 900, "targets": 280, "sources": 7000},
                "1": {"rank": 2, "targetport": 22, "records": 300, "targets": 280, "sources": 7300}, "date": "x", "limit": 2}
    if "/api/sources/attacks" in url:
        return [{"ip": "192.0.2.10", "attacks": 400, "count": 5000, "firstseen": "2024-01-01", "lastseen": "2026-11-15"},
                {"ip": "192.0.2.11", "attacks": 300, "count": 3000, "firstseen": "2024-01-01", "lastseen": "2026-11-15"}]
    if "/api/ip/" in url:
        return {"ip": {"as": 64500, "asname": "BAD-NET", "ascountry": "RU"}}
    if "recentvictims" in url:
        return [{"victim": "Acme Corp", "group": "lockbit", "country": "US", "activity": "Manufacturing",
                 "discovered": "2026-11-14T10:00:00+00:00", "url": "https://www.ransomware.live/id/abc",
                 "claim_url": "http://leak.onion/x"},
                {"victim": "<script>x</script>", "group": "akira", "country": "DE", "activity": "Not Found",
                 "discovered": "2026-11-13T10:00:00+00:00", "url": "javascript:alert(1)"}]
    if "/v2/victims/" in url:
        return [{"victim": f"v{i}", "group": "lockbit" if i % 2 else "akira", "country": "US", "activity": "Healthcare"} for i in range(10)]
    if "nvd.nist.gov" in url:
        return {"totalResults": 3000}
    raise AssertionError(url)


def _refresh():
    with mock.patch.object(obs, "_get_json", side_effect=fake_get) as g:
        done = obs.refresh(budget=600, sleep=lambda s: None)
    return done, g


def test_refresh_then_every_panel(authed):
    done, g = _refresh()
    assert done["asndrop"] == 2 and done["isc_ports"] == 2 and done["isc_sources"] == 2 and done["rw_recent"] == 2
    assert done["rw_months"] >= 12 and done["nvd_months"] >= 100
    calls = g.call_count
    done2, g2 = _refresh()                      # nothing due: only the current / previous months come back later
    assert g2.call_count == 0 and done2 == {}
    for key in obs.PANELS:
        r = authed.post("/api/v1/analytics/query", json={"dataset": "observatory", "type": "panel", "panel": key, "tz_offset_minutes": 0})
        assert r.status_code == 200, (key, r.text)
        body = r.json()
        assert body["dataset"] == "observatory" and body["blocks"] and body["how"] and body["sources"], key
    recent = authed.post("/api/v1/analytics/query", json={"dataset": "observatory", "panel": "rw_recent"}).json()
    rows = recent["blocks"][0]["rows"]
    assert rows[0][1] == "Acme Corp" and rows[0][5] == "https://www.ransomware.live/id/abc"
    assert rows[1][5] is None and rows[1][4] == ""            # no javascript: links; "Not Found" sector hidden
    assert all("onion" not in str(c) for row in rows for c in row)   # leak-site links never shown
    asn = authed.post("/api/v1/analytics/query", json={"dataset": "observatory", "panel": "net_asn"}).json()
    assert asn["blocks"][0]["rows"][0][:3] == ["AS64500", "BAD-NET 🚫", "Russia"]
    ports = authed.post("/api/v1/analytics/query", json={"dataset": "observatory", "panel": "net_ports"}).json()
    assert ports["blocks"][0]["items"][0] == {"label": "23 · Telnet", "count": 900}
    assert calls > 0


def test_panels_before_any_data_say_so(authed):
    r = authed.post("/api/v1/analytics/query", json={"dataset": "observatory", "panel": "cve_vs_kev"}).json()
    assert r["blocks"][0]["kind"] == "note" and "Collecting" in r["blocks"][0]["text"]
    for bad in ({"dataset": "observatory", "panel": "nope"}, {"dataset": "observatory", "panel": "net_asn", "evil": 1}):
        assert authed.post("/api/v1/analytics/query", json=bad).status_code == 422


def test_templates_and_one_time_dashboard_update(authed):
    from app.db import get_db
    from app.main import _add_observatory_panels_once

    t = authed.post("/api/v1/dashboard-templates/internet")
    assert t.status_code == 201 and all(w["chart"] == "panel" for w in t.json()["widgets"])
    cve = authed.post("/api/v1/dashboard-templates/cve").json()
    assert cve["widgets"][0]["query"]["dataset"] == "observatory"
    rw = authed.post("/api/v1/dashboards", json={"name": "Ransomware tracker", "widgets": []}).json()
    with get_db() as db:
        db.execute("DELETE FROM sync_state WHERE key = 'observatory_panels_v1'")
        db.execute("DELETE FROM dashboards WHERE name = 'Internet threats'")
    _add_observatory_panels_once()
    _add_observatory_panels_once()                                   # once only
    got = authed.get(f"/api/v1/dashboards/{rw['id']}").json()["widgets"]
    assert [w["query"]["panel"] for w in got] == [k for k, _, _ in obs.RW_PANELS]
    names = [d["name"] for d in authed.get("/api/v1/dashboards").json()]
    assert names.count("Internet threats") == 1
    # a saved panel widget survives a round trip through the dashboard API
    assert authed.put(f"/api/v1/dashboards/{rw['id']}", json={"name": "Ransomware tracker", "widgets": got}).status_code == 200


def test_observatory_needs_a_session(client):
    assert client.post("/api/v1/analytics/query", json={"dataset": "observatory", "panel": "net_asn"}).status_code == 401
