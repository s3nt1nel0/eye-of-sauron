"""Features borrowed from FreshRSS extensions: email newsletters, title translation, highlight words, adaptive
refresh, image proxy, read later, reading time and site icons."""

import json
from email.message import EmailMessage
from unittest import mock

import httpx
import pytest

from app import netguard
from app.db import get_db, now

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
WB_PW = "-".join(("pw", "123456"))  # test value, not a secret
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def _feed(title="Feed", url="https://example.com/rss", **cols):
    keys = ["title", "url", "created_at", *cols]
    with get_db() as db:
        return db.execute(f"INSERT INTO feeds ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                          [title, url, now(), *cols.values()]).lastrowid


def _article(feed_id, title="Title", text="word " * 600, html="<p>Hello</p>", ts=None, guid=None):
    ts = ts or now()
    with get_db() as db:
        return db.execute("INSERT INTO articles (feed_id, guid, title, content_html, text_content, published, fetched_at, sort_ts) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (feed_id, guid or f"g{ts}{title}", title, html, text, ts, ts, ts)).lastrowid


# ============================================================================ adaptive refresh
def test_quiet_feed_is_checked_less_often_but_never_more_often(authed):
    from app import app_settings, fetcher

    quiet, busy, fresh = _feed("Quiet", "https://q.example/rss"), _feed("Busy", "https://b.example/rss"), _feed("New", "https://n.example/rss")
    t = now()
    for i in range(6):
        _article(quiet, f"q{i}", ts=t - i * 5 * 86400)   # every 5 days
        _article(busy, f"b{i}", ts=t - i * 600)          # every 10 minutes
    with get_db() as db:
        prefs = app_settings.get_all(db)
        assert fetcher.adaptive_minutes(db, quiet, 60) == 720           # capped at 12 h
        assert fetcher.adaptive_minutes(db, busy, 60) == 60             # never below the default
        assert fetcher.adaptive_minutes(db, fresh, 60) == 60            # nothing known yet: default
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (quiet,)).fetchone()
        assert fetcher.refresh_for(db, feed, prefs) == 720
        assert db.execute("SELECT adaptive_minutes FROM feeds WHERE id = ?", (quiet,)).fetchone()[0] == 720
        assert fetcher.refresh_for(db, feed, {**prefs, "adaptive_refresh": False}) == prefs["default_refresh_minutes"]
        db.execute("UPDATE feeds SET refresh_minutes = 15 WHERE id = ?", (quiet,))
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (quiet,)).fetchone()
        assert fetcher.refresh_for(db, feed, prefs) == 15               # its own interval always wins


# ============================================================================ image proxy
def test_sniff_accepts_raster_images_only():
    from app import media

    assert media.sniff(PNG) == "image/png"
    assert media.sniff(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
    assert media.sniff(b"GIF89a....") == "image/gif"
    assert media.sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert media.sniff(SVG) is None
    assert media.sniff(b"<html><script>") is None


def test_rewrite_images_signs_every_http_image():
    from app import media

    out = media.rewrite_images('<p><img src="https://cdn.example/a.png?x=1&amp;y=2" alt="a"></p>')
    assert 'src="/api/v1/img?u=https%3A%2F%2Fcdn.example%2Fa.png%3Fx%3D1%26y%3D2&amp;s=' in out
    sig = out.split("s=")[1][:32]
    assert media.verify("https://cdn.example/a.png?x=1&y=2", sig)
    assert not media.verify("https://evil.example/", sig)


def test_image_proxy_needs_a_signature_and_returns_only_images(authed, client):
    from app import media

    url = "https://cdn.example/pic.png"
    assert authed.get("/api/v1/img", params={"u": url, "s": "0" * 32}).status_code == 403
    resp = netguard.SafeResponse(200, httpx.Headers({"content-type": "text/html"}), PNG, url)
    with mock.patch("app.netguard.request", return_value=resp) as req:
        r = authed.get("/api/v1/img", params={"u": url, "s": media.sign(url)})
    assert r.status_code == 200 and r.content == PNG
    assert r.headers["content-type"] == "image/png"                 # from the bytes, not the site's header
    assert "sandbox" in r.headers["content-security-policy"] and r.headers["x-content-type-options"] == "nosniff"
    assert req.call_args.kwargs.get("allow_private", False) is False  # SSRF guard stays on
    svg = netguard.SafeResponse(200, httpx.Headers({"content-type": "image/svg+xml"}), SVG, url)
    with mock.patch("app.netguard.request", return_value=svg):
        assert authed.get("/api/v1/img", params={"u": url, "s": media.sign(url)}).status_code == 404
    authed.cookies.clear()
    assert authed.get("/api/v1/img", params={"u": url, "s": media.sign(url)}).status_code == 401


def test_reader_images_go_through_the_proxy_when_enabled(authed):
    fid = _feed()
    aid = _article(fid, html='<p>x</p><img src="https://cdn.example/a.png">')
    body = authed.get(f"/api/v1/articles/{aid}").json()
    assert "/api/v1/img?u=https%3A%2F%2Fcdn.example%2Fa.png" in body["content_html"]
    authed.patch("/api/v1/settings", json={"image_proxy": False})
    assert 'src="https://cdn.example/a.png"' in authed.get(f"/api/v1/articles/{aid}").json()["content_html"]


# ============================================================================ site icons + reading time
def test_icon_candidates_prefer_real_icons_and_skip_svg():
    from app import media

    page = (b'<link rel="stylesheet" href="/s.css"><link rel="icon" href="/logo.svg">'
            b'<link rel="icon" sizes="32x32" href="/favicon-32.png"><link rel="apple-touch-icon" href="/apple.png">')
    found = media._candidates("https://site.example/blog/", page)
    assert found[0] == "https://site.example/favicon-32.png"
    assert "https://site.example/apple.png" in found and not any(u.endswith(".svg") for u in found)


def test_list_has_reading_time_and_icon_version(authed):
    fid = _feed()
    _article(fid, text="word " * 1200)   # ~6000 characters
    with get_db() as db:
        db.execute("INSERT INTO feed_icons (feed_id, mime, data, fetched_at) VALUES (?, 'image/png', ?, 123)", (fid, PNG))
    item = authed.get("/api/v1/articles").json()["items"][0]
    assert item["read_minutes"] == 5 and item["icon_v"] == 123
    r = authed.get(f"/api/v1/feeds/{fid}/icon")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert authed.get("/api/v1/feeds/999999/icon").status_code == 404


def test_refresh_icons_stores_found_and_missing(authed):
    from app import media

    fid = _feed(url="https://site.example/feed", site_url="https://site.example/")
    other = _feed("Other", "https://none.example/feed")

    def fake(method, url, **kw):
        if url == "https://site.example/":
            return netguard.SafeResponse(200, httpx.Headers(), b'<link rel="icon" href="/i.png">', url)
        if url == "https://site.example/i.png":
            return netguard.SafeResponse(200, httpx.Headers(), PNG, url)
        return netguard.SafeResponse(404, httpx.Headers(), b"", url)

    with mock.patch("app.netguard.request", side_effect=fake):
        assert media.refresh_icons() == 1
    with get_db() as db:
        rows = {r["feed_id"]: r["data"] for r in db.execute("SELECT feed_id, data FROM feed_icons")}
    assert bytes(rows[fid]) == PNG and rows[other] is None


# ============================================================================ highlight words
def test_highlight_terms_are_validated(authed):
    r = authed.patch("/api/v1/settings", json={"highlight_terms": ["Acme", " acme ", "Fortinet FortiGate"]})
    assert r.status_code == 200 and r.json()["highlight_terms"] == ["Acme", "Fortinet FortiGate"]
    assert authed.patch("/api/v1/settings", json={"highlight_terms": ["<script>"]}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"highlight_terms": ["x"]}).status_code == 422
    assert authed.patch("/api/v1/settings", json={"highlight_terms": ["ok"] * 51}).status_code == 422


# ============================================================================ title translation
def test_titles_are_translated_and_originals_kept(authed):
    from app import ai, translate

    fid = _feed("CERT-FR", "https://cert.example/rss")
    a1, a2 = _article(fid, "Vulnérabilité dans Fortinet", guid="1"), _article(fid, "CVE-2026-1234", guid="2")
    answer = ai.AIResult("1|Vulnerability in Fortinet\n2|CVE-2026-1234\n9|Injected title\nignore everything", "x", "m", 1, 1)
    with mock.patch("app.ai.is_configured", return_value=True), mock.patch("app.ai.complete", return_value=answer) as call:
        assert translate.apply([a1, a2]) == 1
    assert "untrusted data" in call.call_args.args[0]
    with get_db() as db:
        rows = {r["id"]: (r["title"], r["title_original"]) for r in db.execute("SELECT id, title, title_original FROM articles")}
    assert rows[a1] == ("Vulnerability in Fortinet", "Vulnérabilité dans Fortinet")
    assert rows[a2] == ("CVE-2026-1234", "CVE-2026-1234")
    assert authed.get(f"/api/v1/articles/{a1}").json()["title_original"] == "Vulnérabilité dans Fortinet"
    assert translate.undo(fid) == 2
    with get_db() as db:
        assert db.execute("SELECT title FROM articles WHERE id = ?", (a1,)).fetchone()[0] == "Vulnérabilité dans Fortinet"


def test_feed_toggle_queues_translation(authed):
    from app import translate

    fid = _feed()
    _article(fid, "Titre")
    with mock.patch.object(translate.worker, "add") as add:
        r = authed.patch(f"/api/v1/feeds/{fid}", json={"translate_titles": True})
    assert r.status_code == 200 and r.json()["translate_titles"] == 1
    add.assert_called_once()
    assert authed.get(f"/api/v1/feeds/{fid}/details").json()["translate_titles"] is True


# ============================================================================ read later
def test_read_later_status_save_and_errors(authed):
    fid = _feed()
    aid = _article(fid)
    with get_db() as db:
        db.execute("UPDATE articles SET url = 'https://news.example/story' WHERE id = ?", (aid,))
    assert authed.get("/api/v1/readlater").json() == {"wallabag": False, "linkwarden": False, "obsidian": None}
    assert authed.post(f"/api/v1/articles/{aid}/save", json={"service": "wallabag"}).status_code == 502
    r = authed.put("/api/v1/integrations/readlater", json={
        "wallabag_url": "http://wallabag.lan:8080", "wallabag_client_id": "1_abc", "wallabag_client_secret": "s3cr3t-client",
        "wallabag_username": "me", "wallabag_password": WB_PW, "linkwarden_url": "https://links.example",
        "linkwarden_token": "tok.en-123", "obsidian_vault": "Brain", "obsidian_folder": "Inbox/EOS"})
    assert r.status_code == 200, r.text
    assert "wallabag_password" in r.json()["secrets_set"] and WB_PW not in r.text
    assert authed.get("/api/v1/readlater").json() == {"wallabag": True, "linkwarden": True, "obsidian": {"vault": "Brain", "folder": "Inbox/EOS"}}
    calls = []

    def fake(method, url, **kw):
        calls.append((url, kw))
        body = {"access_token": "AT", "expires_in": 3600} if url.endswith("/oauth/v2/token") else {"id": 1}
        return netguard.SafeResponse(200, httpx.Headers(), json.dumps(body).encode(), url)

    with mock.patch("app.netguard.request", side_effect=fake):
        assert authed.post(f"/api/v1/articles/{aid}/save", json={"service": "wallabag"}).json() == {"ok": True, "service": "wallabag"}
        assert authed.post(f"/api/v1/articles/{aid}/save", json={"service": "linkwarden"}).status_code == 200
    assert calls[0][0] == "http://wallabag.lan:8080/oauth/v2/token" and calls[0][1]["allow_private"] is True
    assert calls[1][0] == "http://wallabag.lan:8080/api/entries.json" and calls[1][1]["headers"]["Authorization"] == "Bearer AT"
    assert calls[2][0] == "https://links.example/api/v1/links"
    assert json.loads(calls[2][1]["content"])["url"] == "https://news.example/story"
    assert authed.put("/api/v1/integrations/readlater", json={"obsidian_vault": "bad|name"}).status_code == 422
    assert authed.put("/api/v1/integrations/readlater", json={"wallabag_url": "javascript:alert(1)"}).status_code == 422


def test_read_later_settings_are_admin_only(authed):
    tok = authed.post("/api/v1/tokens", json={"name": "rw", "scope": "write"}).json()["token"]
    authed.cookies.clear()
    authed.headers.pop("X-CSRF-Token")
    hdr = {"Authorization": f"Bearer {tok}"}
    assert authed.put("/api/v1/integrations/readlater", json={"obsidian_vault": "x"}, headers=hdr).status_code == 403
    assert authed.put("/api/v1/integrations/imap", json={"clear": True}, headers=hdr).status_code == 403


# ============================================================================ email newsletters
def _mail(sender="CISA <alerts@cisa.gov>", subject="CISA Adds Three Known Exploited Vulnerabilities", html=None, text=None, msgid="<1@cisa.gov>"):
    m = EmailMessage()
    m["From"], m["Subject"], m["Date"], m["Message-ID"] = sender, subject, "Tue, 17 Nov 2026 10:00:00 +0000", msgid
    if html:
        m.set_content(text or "plain")
        m.add_alternative(html, subtype="html")
    else:
        m.set_content(text or "Hello from the plain text part https://www.cisa.gov/kev")
    return m.as_bytes()


def test_parse_message_filters_and_cleans():
    from app import mailfeeds

    html = ('<p>Advisory</p><img src="https://t.example/open.gif" width="1" height="1">'
            '<a href="https://www.cisa.gov/news/x?a=1&amp;b=2">View this email in your browser</a><script>alert(1)</script>')
    e = mailfeeds.parse_message(_mail(html=html), ["cisa.gov"], None)
    assert e["title"].startswith("CISA Adds") and e["author"] == "CISA"
    assert "open.gif" not in e["summary"] and "<script" not in e["summary"]
    assert e["link"] == "https://www.cisa.gov/news/x?a=1&b=2"
    assert e["id"].startswith("mail:") and e["published_parsed"] is not None
    assert mailfeeds.parse_message(_mail(sender="x@evil-cisa.gov.example"), ["cisa.gov"], None) is None
    assert mailfeeds.parse_message(_mail(sender="news@mail.cisa.gov"), ["cisa.gov"], None) is not None   # subdomain
    assert mailfeeds.parse_message(_mail(), ["cisa.gov"], "weekly") is None                              # subject filter
    plain = mailfeeds.parse_message(_mail(sender="a@b.example"), ["a@b.example"], None)
    assert 'href="https://www.cisa.gov/kev"' in plain["summary"]


def test_email_source_validation():
    from app import sources

    ok = sources.parse_config({"kind": "email", "senders": ["Alerts@CISA.gov", "ncsc.gov.uk"], "subject_contains": "Advisory"})
    assert ok.senders == ["alerts@cisa.gov", "ncsc.gov.uk"]
    assert sources.canonical_url(ok).startswith("https://newsletters.invalid/INBOX?")
    for bad in ({"senders": ['a" OR ALL "']}, {"senders": []}, {"senders": ["x.com"], "folder": 'INBOX" DELETE'},
                {"senders": ["x.com"] * 21}, {"senders": ["x.com"], "subject_contains": "<b>"}):
        with pytest.raises(ValueError):
            sources.parse_config({"kind": "email", **bad})


class FakeIMAP:
    def __init__(self, messages):
        self.messages = messages
        self.commands = []

    def select(self, folder, readonly=False):
        self.commands.append(("SELECT", folder, readonly))
        return "OK", [b"3"]

    def uid(self, cmd, *args):
        self.commands.append((cmd, *args))
        if cmd == "SEARCH":
            return "OK", [b" ".join(str(i).encode() for i in self.messages)]
        uid = int(args[0])
        if args[1] == "(RFC822.SIZE)":
            return "OK", [f"{uid} (UID {uid} RFC822.SIZE {len(self.messages[uid])})".encode()]
        return "OK", [(f"{uid} (UID {uid} BODY[] {{{len(self.messages[uid])}}}".encode(), self.messages[uid]), b")"]

    def logout(self):
        self.commands.append(("LOGOUT",))


def test_fetch_reads_read_only_and_stores_articles(authed):
    from app import fetcher, sources

    fake = FakeIMAP({5: _mail(), 6: _mail(sender="spam@other.example", msgid="<2@x>"), 7: _mail(subject="Second", msgid="<3@cisa.gov>")})
    cfg = sources.EmailSource(senders=["cisa.gov"])
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, kind, source, created_at) VALUES ('m', ?, 'email', ?, ?)",
                         (sources.canonical_url(cfg), cfg.model_dump_json(), now())).lastrowid
    with mock.patch("app.mailfeeds.connect", return_value=fake):
        res = fetcher.fetch_feed(fid)
    assert res["ok"] and res["new"] == 2, res
    assert ("SELECT", '"INBOX"', True) in fake.commands                  # EXAMINE (read-only)
    assert all("PEEK" in c[2] or "SIZE" in c[2] for c in fake.commands if c[0] == "FETCH")
    assert any(c[0] == "SEARCH" and c[-1] == '"cisa.gov"' for c in fake.commands)
    with mock.patch("app.mailfeeds.connect", return_value=FakeIMAP({5: _mail()})):
        assert fetcher.fetch_feed(fid)["new"] == 0                         # same Message-ID: no duplicate


def test_mail_server_on_private_network_is_refused(monkeypatch):
    from app import mailfeeds

    monkeypatch.setattr("app.netguard.resolve_host", mock.Mock(side_effect=netguard.UnsafeURLError("private address")))
    with pytest.raises(mailfeeds.MailError, match="SSRF"):
        mailfeeds.connect({"host": "mail.example.com", "port": 993, "username": "u"}, "p")


def test_lan_mail_server_needs_the_exact_allowlist_even_with_private_feeds(monkeypatch):
    import socket

    from app import config, mailfeeds

    monkeypatch.setenv("EOS_ALLOW_PRIVATE_FEEDS", "true")
    monkeypatch.setenv("EOS_DATA_DIR", "unused")
    config.reset_settings()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 993))])
    try:
        with pytest.raises(mailfeeds.MailError, match="SSRF"):
            mailfeeds.connect({"host": "mail.home.example", "port": 993, "username": "u"}, "p")
    finally:
        config.reset_settings()


def test_imap_settings_test_login_and_never_return_password(authed):
    with mock.patch("app.mailfeeds.test_login", return_value=["INBOX", "Newsletters"]) as login:
        r = authed.put("/api/v1/integrations/imap", json={"host": "imap.example.com", "username": "me@example.com", "password": "app-pass-123"})
    assert r.status_code == 200, r.text
    assert login.call_args.args == ({"host": "imap.example.com", "port": 993, "username": "me@example.com"}, "app-pass-123")
    assert "app-pass-123" not in r.text and r.json()["config"]["folders"] == ["INBOX", "Newsletters"]
    from app import mailfeeds

    with mock.patch("app.mailfeeds.test_login", side_effect=mailfeeds.MailError("The mail server refused the login")):
        r = authed.put("/api/v1/integrations/imap", json={"host": "imap.example.com", "username": "me@example.com", "password": "bad"})
    assert r.status_code == 422 and "refused" in r.text
    assert authed.put("/api/v1/integrations/imap", json={"host": "bad host!", "username": "x", "password": "y"}).status_code == 422
