from unittest import mock

from app import netguard
from tests.conftest import TEST_PASSWORD

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Test Feed</title><link>https://example.com/</link>
<item><title>LockBit ransomware hits hospital</title><link>https://example.com/1</link>
<guid>1</guid><description>&lt;p&gt;Details&lt;/p&gt;&lt;script&gt;alert(1)&lt;/script&gt;</description>
<pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Patch Tuesday advisory</title><link>javascript:alert(1)</link><guid>2</guid>
<description>CVE-2026-1234 fixed</description></item>
</channel></rss>"""


def fake_response(content=RSS, status=200):
    import httpx

    return netguard.SafeResponse(status, httpx.Headers({"content-type": "application/rss+xml"}), content,
                                 "https://example.com/feed")


def test_healthz_and_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_requires_auth(client):
    assert client.get("/api/v1/articles").status_code == 401
    assert client.get("/api/v1/feeds").status_code == 401


def test_login_failure_and_throttle(client):
    for _ in range(8):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-password"})
        assert r.status_code == 401
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert r.status_code == 429


def test_session_cookie_flags(client):
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_csrf_required_for_cookie_writes(authed):
    token = authed.headers.pop("X-CSRF-Token")
    assert authed.post("/api/v1/folders", json={"name": "APT"}).status_code == 403
    authed.headers["X-CSRF-Token"] = "wrong"
    assert authed.post("/api/v1/folders", json={"name": "APT"}).status_code == 403
    authed.headers["X-CSRF-Token"] = token
    assert authed.post("/api/v1/folders", json={"name": "APT"}).status_code == 201


def test_unknown_fields_rejected(authed):
    r = authed.post("/api/v1/folders", json={"name": "x", "is_admin": True})
    assert r.status_code == 422


def test_feed_rejects_unsafe_url(authed):
    for url in ["file:///etc/passwd", "http://user:pw@example.com/", "ftp://x.org/"]:
        assert authed.post("/api/v1/feeds", json={"url": url}).status_code == 422


def test_full_flow_fetch_sanitize_rules_search(authed):
    assert authed.post("/api/v1/rules/starter-pack").status_code == 200
    with mock.patch("app.api.content._refresh_async"), \
         mock.patch("app.fetcher.netguard.request", return_value=fake_response()):
        feed = authed.post("/api/v1/feeds", json={"url": "https://example.com/feed"}).json()
        result = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert result == {"ok": True, "error": None, "new": 2}

    items = authed.get("/api/v1/articles").json()["items"]
    assert len(items) == 2
    by_title = {a["title"]: a for a in items}
    lockbit = by_title["LockBit ransomware hits hospital"]
    assert "Ransomware" in [t["name"] for t in lockbit["tags"]]
    assert by_title["Patch Tuesday advisory"]["url"] is None  # javascript: link dropped

    detail = authed.get(f"/api/v1/articles/{lockbit['id']}").json()
    assert "<script" not in detail["content_html"]

    assert authed.get("/api/v1/articles", params={"q": "cve-2026-1234"}).json()["total"] == 1
    assert authed.get("/api/v1/articles", params={"q": '") OR ("'}).json()["total"] == 0

    authed.patch(f"/api/v1/articles/{lockbit['id']}", json={"is_starred": True})
    assert authed.get("/api/v1/articles", params={"starred": True}).json()["total"] == 1
    authed.post("/api/v1/articles/mark-read", json={"all": True})
    assert authed.get("/api/v1/articles", params={"unread": True}).json()["total"] == 0


def test_bulk_article_actions(authed):
    """Selection mode: one action on several ticked articles."""
    with mock.patch("app.api.content._refresh_async"), \
         mock.patch("app.fetcher.netguard.request", return_value=fake_response()):
        feed = authed.post("/api/v1/feeds", json={"url": "https://example.com/feed"}).json()
        authed.post(f"/api/v1/feeds/{feed['id']}/refresh")
    ids = [a["id"] for a in authed.get("/api/v1/articles").json()["items"]]
    assert len(ids) == 2

    def bulk(action, **kw):
        return authed.post("/api/v1/articles/bulk", json={"ids": ids, "action": action, **kw})

    assert bulk("read").json() == {"updated": 2}
    assert authed.get("/api/v1/articles", params={"unread": True}).json()["total"] == 0
    assert bulk("unread").json() == {"updated": 2}
    assert authed.get("/api/v1/articles", params={"unread": True}).json()["total"] == 2

    assert bulk("star").json() == {"updated": 2}
    first = authed.get(f"/api/v1/articles/{ids[0]}").json()
    assert first["is_starred"]
    assert bulk("star").json() == {"updated": 0}  # already starred: unchanged (keeps starred_at)
    assert bulk("unstar").json() == {"updated": 2}
    assert authed.get("/api/v1/articles", params={"starred": True}).json()["total"] == 0

    tag = authed.post("/api/v1/tags", json={"name": "Brief"}).json()
    assert bulk("add_tag", tag_id=tag["id"]).json() == {"updated": 2}
    assert authed.get("/api/v1/articles", params={"tag_id": tag["id"]}).json()["total"] == 2
    assert bulk("remove_tag", tag_id=tag["id"]).json() == {"updated": 2}
    assert authed.get("/api/v1/articles", params={"tag_id": tag["id"]}).json()["total"] == 0

    # validation and permissions
    assert bulk("add_tag").status_code == 422                      # collection required
    assert bulk("add_tag", tag_id=999999).status_code == 404
    assert bulk("delete").status_code == 422                       # unknown action
    assert authed.post("/api/v1/articles/bulk", json={"ids": [], "action": "read"}).status_code == 422
    assert authed.post("/api/v1/articles/bulk", json={"ids": list(range(1, 1002)), "action": "read"}).status_code == 422
    assert authed.post("/api/v1/articles/bulk", json={"ids": [0], "action": "read"}).status_code == 422
    assert authed.post("/api/v1/articles/bulk", json={"ids": ["1 OR 1=1"], "action": "read"}).status_code == 422
    assert authed.post("/api/v1/articles/bulk", json={"ids": [2**63], "action": "read"}).status_code == 422
    assert authed.post("/api/v1/articles/bulk", json={"ids": [999999], "action": "read"}).json() == {"updated": 0}
    read_token = authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]
    r = authed.post("/api/v1/articles/bulk", json={"ids": ids, "action": "read"}, headers={"Authorization": f"Bearer {read_token}"})
    assert r.status_code == 403


def test_entity_declarations_rejected(authed):
    bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel><title>&a;</title></channel></rss>'
    with mock.patch("app.api.content._refresh_async"), \
         mock.patch("app.fetcher.netguard.request", return_value=fake_response(bomb)):
        feed = authed.post("/api/v1/feeds", json={"url": "https://example.com/bomb"}).json()
        result = authed.post(f"/api/v1/feeds/{feed['id']}/refresh").json()
    assert result["ok"] is False and "entity" in result["error"].lower()


def test_api_token_scopes(authed):
    read_tok = authed.post("/api/v1/tokens", json={"name": "ro", "scope": "read"}).json()["token"]
    write_tok = authed.post("/api/v1/tokens", json={"name": "rw", "scope": "write"}).json()["token"]
    authed.cookies.clear()
    authed.headers.pop("X-CSRF-Token")

    ro = {"Authorization": f"Bearer {read_tok}"}
    rw = {"Authorization": f"Bearer {write_tok}"}
    assert authed.get("/api/v1/articles", headers=ro).status_code == 200
    assert authed.post("/api/v1/folders", json={"name": "x"}, headers=ro).status_code == 403
    assert authed.post("/api/v1/folders", json={"name": "x"}, headers=rw).status_code == 201
    # tokens can never manage tokens, webhooks or the password
    assert authed.get("/api/v1/tokens", headers=rw).status_code == 403
    assert authed.post("/api/v1/tokens", json={"name": "y"}, headers=rw).status_code == 403
    assert authed.get("/api/v1/articles", headers={"Authorization": "Bearer fw_bogus"}).status_code == 401


def test_settings_validation(authed):
    assert authed.patch("/api/v1/settings", json={"theme": "dark"}).json()["theme"] == "dark"
    assert authed.patch("/api/v1/settings", json={"theme": "<script>"}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"evil_key": 1}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"page_size": 100000}).status_code == 422


def test_opml_roundtrip_and_xxe(authed):
    opml = b"""<?xml version="1.0"?><opml version="2.0"><body>
    <outline text="Threat Intel"><outline type="rss" text="A" xmlUrl="https://a.example/feed"/></outline>
    <outline type="rss" text="Bad" xmlUrl="file:///etc/passwd"/></body></opml>"""
    r = authed.post("/api/v1/opml/import", content=opml, headers={"Content-Type": "text/xml"})
    assert r.json() == {"added": 1, "skipped": 0, "invalid": 1, "updated": 0,
                        "by_type": {"articles": 1, "podcasts": 0, "videos": 0, "accounts": 0}}
    xxe = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
    <opml><body><outline text="&e;" xmlUrl="https://b.example/"/></body></opml>"""
    assert authed.post("/api/v1/opml/import", content=xxe, headers={"Content-Type": "text/xml"}).status_code == 422
    assert b"a.example/feed" in authed.get("/api/v1/opml/export").content


def test_body_size_limit(authed):
    r = authed.post("/api/v1/folders", content=b"x" * (2 * 1024 * 1024), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_password_change_revokes_other_sessions(client):
    from fastapi.testclient import TestClient

    other = TestClient(client.app)
    r1 = other.post("/api/v1/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    r2 = client.post("/api/v1/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    client.headers["X-CSRF-Token"] = r2.json()["csrf_token"]
    assert client.post("/api/v1/auth/password", json={"current_password": TEST_PASSWORD,
                                                      "new_password": "short"}).status_code == 422
    assert client.post("/api/v1/auth/password", json={"current_password": TEST_PASSWORD,
                                                      "new_password": "another-long-passphrase"}).status_code == 200
    assert r1.status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 200


def test_colour_several_collections_at_once(authed, client):
    ids = [authed.post("/api/v1/tags", json={"name": n, "color": "#111111"}).json()["id"] for n in ("ATT&CK: A", "ATT&CK: B", "Other")]
    r = authed.post("/api/v1/tags/colors", json={"ids": [ids[0], ids[1], ids[1], 999999], "color": "#22AA44"})  # stored in lower case
    assert r.status_code == 200 and r.json() == {"updated": 2}
    colors = {t["name"]: t["color"] for t in authed.get("/api/v1/tags").json()}
    assert colors == {"ATT&CK: A": "#22aa44", "ATT&CK: B": "#22aa44", "Other": "#111111"}
    for bad in ({"ids": [], "color": "#22aa44"}, {"ids": [ids[0]], "color": "red"}, {"ids": [ids[0]], "color": "#22aa44;x"},
                {"ids": ["1 OR 1=1"], "color": "#22aa44"}, {"ids": list(range(1, 502)), "color": "#22aa44"}, {"ids": [0], "color": "#22aa44"},
                {"ids": [ids[0]], "color": "#22aa44", "name": "x"}):
        assert authed.post("/api/v1/tags/colors", json=bad).status_code == 422, bad
    fresh = {k: v for k, v in authed.headers.items() if k.lower() != "x-csrf-token"}
    assert authed.post("/api/v1/tags/colors", json={"ids": [ids[2]], "color": "#000000"}, headers={"X-CSRF-Token": "wrong"}).status_code in (401, 403)
    assert {t["name"]: t["color"] for t in authed.get("/api/v1/tags").json()}["Other"] == "#111111" and fresh is not None
