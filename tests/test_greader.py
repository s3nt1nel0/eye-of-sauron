"""Google Reader-compatible API (native RSS apps): auth model, protocol behaviour, isolation."""

from unittest import mock

import httpx
import pytest

from app import netguard

GR = "/api/greader.php"
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Intel</title><link>https://intel.example/</link>
<item><title>First</title><link>https://intel.example/1</link><guid>1</guid><pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate>
<description><![CDATA[<p>One</p><script>alert(1)</script><img src=x onerror=alert(1)>]]></description></item>
<item><title>Second</title><link>https://intel.example/2</link><guid>2</guid><pubDate>Tue, 10 Nov 2026 10:00:00 GMT</pubDate><description>Two</description></item>
<item><title>Third</title><link>https://intel.example/3</link><guid>3</guid><pubDate>Wed, 11 Nov 2026 10:00:00 GMT</pubDate><description>Three</description></item>
</channel></rss>"""


@pytest.fixture()
def setup(authed):
    folder = authed.post("/api/v1/folders", json={"name": "Vendors"}).json()
    resp = netguard.SafeResponse(200, httpx.Headers({"content-type": "application/rss+xml"}), RSS, "https://intel.example/feed")
    with mock.patch("app.api.content._refresh_async"), mock.patch("app.fetcher.netguard.request", return_value=resp):
        feed = authed.post("/api/v1/feeds", json={"url": "https://intel.example/feed", "folder_id": folder["id"]}).json()
        authed.put(f"/api/v1/feeds/{feed['id']}/retention", json={"retention_days": 0})
        authed.post(f"/api/v1/feeds/{feed['id']}/refresh")
    app_pw = authed.post("/api/v1/reader-apps", json={"name": "iPhone Reeder"}).json()
    return {"feed": feed["id"], "folder": folder["id"], "app": app_pw}


def login(client, username, password):
    return client.post(f"{GR}/accounts/ClientLogin", content=f"Email={username}&Passwd={password}",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})


def auth(client, setup):
    r = login(client, setup["app"]["username"], setup["app"]["password"])
    assert r.status_code == 200, r.text
    token = dict(line.split("=", 1) for line in r.text.strip().splitlines())["Auth"]
    return {"Authorization": f"GoogleLogin auth={token}"}


# ------------------------------------------------------------------ auth model
def test_login_and_isolation(client, setup):
    client.cookies.clear()
    h = auth(client, setup)
    assert client.get(f"{GR}/reader/api/0/user-info", headers=h).json()["userName"] == "admin"
    # reader tokens cannot use the REST API (no read/write scopes)
    assert client.get("/api/v1/articles", headers={"Authorization": h["Authorization"].replace("GoogleLogin auth=", "Bearer ")}).status_code == 403
    # the main admin password is NOT accepted by ClientLogin
    from conftest import TEST_PASSWORD
    assert login(client, "admin", TEST_PASSWORD).status_code == 401
    assert login(client, "admin", "wrong").text.startswith("Error=BadAuthentication")
    # credentials in the URL are refused (would land in access logs)
    assert client.post(f"{GR}/accounts/ClientLogin?Email=admin&Passwd=x").status_code == 400
    # no auth / cookie-only / normal API tokens are rejected
    assert client.get(f"{GR}/reader/api/0/subscription/list").status_code == 401


def test_rest_tokens_rejected_and_revocation(authed, setup):
    rest = authed.post("/api/v1/tokens", json={"name": "w", "scope": "write"}).json()["token"]
    assert authed.get(f"{GR}/reader/api/0/subscription/list", headers={"Authorization": f"GoogleLogin auth={rest}"}).status_code == 403
    h = auth(authed, setup)
    authed.delete(f"/api/v1/reader-apps/{setup['app']['id']}")
    assert authed.get(f"{GR}/reader/api/0/subscription/list", headers=h).status_code == 401
    assert login(authed, "admin", setup["app"]["password"]).status_code == 401


def test_sessions_per_app_capped(authed, setup):
    for _ in range(7):
        auth(authed, setup)
    assert authed.get("/api/v1/reader-apps").json()[0]["devices"] == 5


def test_clientlogin_throttled(client, setup):
    codes = [login(client, "admin", f"wrong{i}").status_code for i in range(10)]
    assert 429 in codes


def test_reader_apps_admin_only(authed, setup):
    w = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "w", "scope": "write"}).json()["token"]}
    assert authed.get("/api/v1/reader-apps", headers=w).status_code == 403
    assert authed.post("/api/v1/reader-apps", headers=w, json={"name": "x"}).status_code == 403
    assert authed.post("/api/v1/reader-apps", json={"name": "<script>"}).status_code == 422
    assert "password_hash" not in authed.get("/api/v1/reader-apps").text


# ------------------------------------------------------------------ protocol
def test_subscriptions_tags_counts(client, setup):
    h = auth(client, setup)
    subs = client.get(f"{GR}/reader/api/0/subscription/list?output=json", headers=h).json()["subscriptions"]
    assert subs[0]["id"] == f"feed/{setup['feed']}" and subs[0]["categories"][0]["label"] == "Vendors"
    tags = client.get(f"{GR}/reader/api/0/tag/list?output=json", headers=h).json()["tags"]
    assert {"id": "user/-/label/Vendors", "type": "folder"} in tags
    counts = {c["id"]: c["count"] for c in client.get(f"{GR}/reader/api/0/unread-count?output=json", headers=h).json()["unreadcounts"]}
    assert counts["user/-/state/com.google/reading-list"] == 3 and counts[f"feed/{setup['feed']}"] == 3
    assert counts["user/-/label/Vendors"] == 3


def test_stream_contents_paging_and_filters(client, setup):
    h = auth(client, setup)
    page = client.get(f"{GR}/reader/api/0/stream/contents/user/-/state/com.google/reading-list?n=2", headers=h).json()
    assert [i["title"] for i in page["items"]] == ["Third", "Second"] and "continuation" in page
    rest = client.get(f"{GR}/reader/api/0/stream/contents/user/-/state/com.google/reading-list?n=2&c={page['continuation']}", headers=h).json()
    assert [i["title"] for i in rest["items"]] == ["First"] and "continuation" not in rest
    first = rest["items"][0]
    assert first["id"].startswith("tag:google.com,2005:reader/item/") and first["origin"]["streamId"] == f"feed/{setup['feed']}"
    assert "<script" not in first["summary"]["content"] and "onerror" not in first["summary"]["content"]
    assert "user/-/label/Vendors" in first["categories"]
    oldest = client.get(f"{GR}/reader/api/0/stream/contents/feed/{setup['feed']}?r=o&n=1", headers=h).json()
    assert oldest["items"][0]["title"] == "First"
    by_label = client.get(f"{GR}/reader/api/0/stream/contents/user/-/label/Vendors", headers=h).json()
    assert len(by_label["items"]) == 3
    via_query = client.get(f"{GR}/reader/api/0/stream/contents?s=feed/{setup['feed']}", headers=h).json()
    assert len(via_query["items"]) == 3
    for evil in ["feed/1 OR 1=1", "user/-/label/' OR '1'='1", "feed/../../etc", "user/-/state/com.google/x'--"]:
        r = client.get(f"{GR}/reader/api/0/stream/contents/{evil}", headers=h)
        assert (r.status_code == 200 and r.json()["items"] == []) or r.status_code == 404  # ../ is normalised away


def test_ids_contents_and_edit_tag(client, setup):
    h = auth(client, setup)
    refs = client.get(f"{GR}/reader/api/0/stream/items/ids?s=user/-/state/com.google/reading-list&n=10", headers=h).json()["itemRefs"]
    assert len(refs) == 3
    ids = [r["id"] for r in refs]
    long_ids = [f"tag:google.com,2005:reader/item/{int(i):016x}" for i in ids]
    body = "&".join(f"i={i}" for i in [ids[0], long_ids[1]])
    items = client.post(f"{GR}/reader/api/0/stream/items/contents", content=body,
                        headers={**h, "Content-Type": "application/x-www-form-urlencoded"}).json()["items"]
    assert len(items) == 2
    form = {**h, "Content-Type": "application/x-www-form-urlencoded"}
    assert client.post(f"{GR}/reader/api/0/edit-tag", headers=form,
                       content=f"i={ids[0]}&a=user/-/state/com.google/read&a=user/-/state/com.google/starred&a=user/-/label/Ransomware").text == "OK"
    unread = client.get(f"{GR}/reader/api/0/stream/items/ids?s=user/-/state/com.google/reading-list&xt=user/-/state/com.google/read", headers=h).json()
    assert len(unread["itemRefs"]) == 2
    starred = client.get(f"{GR}/reader/api/0/stream/contents/user/-/state/com.google/starred", headers=h).json()["items"]
    assert len(starred) == 1 and "user/-/label/Ransomware" in starred[0]["categories"]
    client.post(f"{GR}/reader/api/0/edit-tag", headers=form, content=f"i={ids[0]}&r=user/-/state/com.google/read")
    client.post(f"{GR}/reader/api/0/mark-all-as-read", headers=form, content=f"s=feed/{setup['feed']}")
    counts = {c["id"]: c["count"] for c in client.get(f"{GR}/reader/api/0/unread-count", headers=h).json()["unreadcounts"]}
    assert counts["user/-/state/com.google/reading-list"] == 0
    assert client.post(f"{GR}/reader/api/0/edit-tag", headers=form, content="i=not-an-id&a=user/-/state/com.google/read").text == "OK"


def test_subscription_management(client, setup):
    h = auth(client, setup)
    form = {**h, "Content-Type": "application/x-www-form-urlencoded"}
    with mock.patch("app.fetcher.fetch_feed"):
        r = client.post(f"{GR}/reader/api/0/subscription/quickadd", headers=form, content="quickadd=https://new.example/rss").json()
    new_stream = r["streamId"]
    assert new_stream.startswith("feed/")
    assert client.post(f"{GR}/reader/api/0/subscription/quickadd", headers=form, content="quickadd=file:///etc/passwd").status_code == 400
    client.post(f"{GR}/reader/api/0/subscription/edit", headers=form, content=f"ac=edit&s={new_stream}&t=Renamed&a=user/-/label/Intel")
    subs = {s["id"]: s for s in client.get(f"{GR}/reader/api/0/subscription/list", headers=h).json()["subscriptions"]}
    assert subs[new_stream]["title"] == "Renamed" and subs[new_stream]["categories"][0]["label"] == "Intel"
    client.post(f"{GR}/reader/api/0/rename-tag", headers=form, content="s=user/-/label/Intel&dest=user/-/label/Threat%20Intel")
    assert any(t["id"] == "user/-/label/Threat Intel" for t in client.get(f"{GR}/reader/api/0/tag/list", headers=h).json()["tags"])
    client.post(f"{GR}/reader/api/0/disable-tag", headers=form, content="s=user/-/label/Threat%20Intel")
    client.post(f"{GR}/reader/api/0/subscription/edit", headers=form, content=f"ac=unsubscribe&s={new_stream}")
    assert new_stream not in {s["id"] for s in client.get(f"{GR}/reader/api/0/subscription/list", headers=h).json()["subscriptions"]}


def test_short_alias_path(client, setup):
    h = auth(client, setup)
    assert client.get("/api/greader/reader/api/0/user-info", headers=h).status_code == 200
