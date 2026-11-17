"""Full article text for summary-only feeds: extraction, the article endpoint, blocked sites, feed settings."""

import json
from unittest import mock

import httpx

from app import fulltext, netguard

BODY = " ".join(f"Sentence number {i} of the real article, long enough to count as a paragraph." for i in range(6))
PAGE = f"""<html><head><title>x</title></head><body>
<header><nav>Home News About</nav></header>
<div class="cs-site-content cs-sidebar-enabled">
  <div class="entry-content">
    <p>{BODY}</p><p>{BODY}</p><p>{BODY}</p>
    <div class="share-buttons"><p>Share this on X</p></div>
    <script>alert(1)</script>
    <img data-src="/img/photo.jpg" src="data:image/gif;base64,R0lGOD">
    <p><a href="/related">a link</a> and <b>bold</b> text that belongs to the story itself, quite long indeed.</p>
  </div>
  <aside class="sidebar"><p>Popular posts popular posts popular posts popular posts popular posts</p></aside>
</div>
<footer>© site</footer></body></html>""".encode()


def page(body=PAGE, status=200, ctype="text/html; charset=utf-8", url="https://news.example/story"):
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


def test_extract_main_content_keeps_wrapped_story():
    html = fulltext.extract(PAGE, "https://news.example/story")
    assert html and BODY in html
    assert "<script" not in html and "Share this on X" not in html and "Popular posts" not in html and "© site" not in html
    assert 'src="https://news.example/img/photo.jpg"' in html            # lazy image resolved and absolute
    assert 'href="https://news.example/related"' in html


def test_extract_json_ld_article_body():
    body = "First paragraph of the story. " * 10 + "\n\n" + "Second <b>paragraph</b> & more. " * 10
    doc = f'<html><script type="application/ld+json">{json.dumps({"@type": "NewsArticle", "articleBody": body})}</script></html>'
    html = fulltext.extract(doc.encode(), "https://x.example/")
    assert html.count("<p>") == 2 and "&lt;b&gt;" in html and "<b>" not in html  # text, not markup


def test_extract_refuses_thin_pages():
    assert fulltext.extract(b"<html><body><p>Only a teaser.</p></body></html>", "https://x.example/") is None


def _article(db, text="One sentence summary.", url="https://news.example/story", feed_mode=None, kind="rss"):
    fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, full_text) VALUES ('F', ?, 1, ?, ?)",
                     (f"https://feeds.example/{abs(hash(url))}/{kind}", kind, feed_mode)).lastrowid
    return db.execute("INSERT INTO articles (feed_id, guid, url, title, content_html, text_content, fetched_at, sort_ts) "
                      "VALUES (?, ?, ?, 'Story', ?, ?, 1, 1)", (fid, url, url, f"<p>{text}</p>", text)).lastrowid


def test_fulltext_endpoint_fills_and_blocks(authed):
    from app.db import get_db

    with get_db() as db:
        aid = _article(db)
        blocked = _article(db, url="https://blocked.example/story")
    with mock.patch("app.fulltext.netguard.request", return_value=page()), mock.patch("app.fulltext.PER_HOST_GAP", 0):
        r = authed.post(f"/api/v1/articles/{aid}/fulltext").json()
    assert r["ok"] is True and r["length"] > 1000
    a = authed.get(f"/api/v1/articles/{aid}").json()
    assert a["fulltext"] == 1 and BODY in a["content_html"] and a["full_text_possible"] == 1
    assert authed.get("/api/v1/articles?q=Sentence").json()["total"] >= 1          # search sees the full text
    # a site that refuses feed readers: summary kept, site left alone, no second request
    calls = []
    def deny(*a, **k):
        calls.append(1)
        return page(b"<html>Just a moment...</html>", 403, url="https://blocked.example/story")
    with mock.patch("app.fulltext.netguard.request", side_effect=deny), mock.patch("app.fulltext.PER_HOST_GAP", 0):
        r1 = authed.post(f"/api/v1/articles/{blocked}/fulltext").json()
        r2 = authed.post(f"/api/v1/articles/{blocked}/fulltext", json={"force": True}).json()
    assert r1["ok"] is False and "refuses" in r1["reason"] and r2["ok"] is False and len(calls) == 1
    assert authed.get(f"/api/v1/articles/{blocked}").json()["fulltext"] == -1
    assert authed.post("/api/v1/articles/999999/fulltext").status_code == 404


def test_queue_new_respects_feed_mode(authed):
    from app.db import get_db

    with get_db() as db:
        short = _article(db, url="https://a.example/1")
        never = _article(db, url="https://a.example/2", feed_mode="never")
        yt = _article(db, url="https://a.example/3", kind="youtube")
        rows = {r["id"]: r for r in db.execute("SELECT f.*, a.id AS aid FROM feeds f JOIN articles a ON a.feed_id = f.id")}
        with mock.patch.object(fulltext.fulltext_queue, "add") as add:
            for aid in (short, never, yt):
                feed = next(r for r in rows.values() if r["aid"] == aid)
                fulltext.queue_new(db, feed, [aid])
    assert [c.args[0] for c in add.call_args_list] == [[short]]
    assert fulltext.wants_full_text("always", 50_000) and not fulltext.wants_full_text("auto", 5000)


def test_feed_full_text_setting(authed):
    with mock.patch("app.api.content._refresh_async"):
        f = authed.post("/api/v1/feeds", json={"url": "https://news.example/rss"}).json()
    assert f["full_text"] == "auto"
    assert authed.patch(f"/api/v1/feeds/{f['id']}", json={"full_text": "never"}).json()["full_text"] == "never"
    assert authed.get(f"/api/v1/feeds/{f['id']}/details").json()["full_text"] == "never"
    assert authed.patch(f"/api/v1/feeds/{f['id']}", json={"full_text": "sometimes"}).status_code == 422


def test_story_block_is_narrowed_and_menus_dropped():
    from app import fulltext

    menu = "<nav-ish><ul>" + "".join(f'<li><a href="/blog/post-{i}"><img src="/i{i}.png"><div>Featured post number {i}</div></a></li>' for i in range(8)) + "</ul>"
    story = "".join(f"<p>{'Paragraph %d of the real story, long enough to count as body text for the extractor. ' % i * 2}</p>" for i in range(6))
    page = f"<html><body><div class='wrap'><div class='header'>{menu}</div><div class='post'>{story}</div><div class='footer'><p>Copyright</p></div></div></body></html>"
    html = fulltext.extract(page.encode(), "https://vendor.example/blog/a")
    assert html and "Featured post" not in html and "Paragraph 0 of the real story" in html and "<img" not in html
    refs = "<ul>" + "".join(f'<li><a href="https://ref{i}.example/">Reference {i}</a></li>' for i in range(6)) + "</ul>"
    page2 = f"<html><body><div class='post'>{story}{refs}</div></body></html>"
    assert "Reference 3" in fulltext.extract(page2.encode(), "https://vendor.example/blog/b")   # a plain list of references stays


def test_page_source_skips_urls_another_feed_already_has(client):
    from app.db import get_db, now
    from app.fetcher import insert_article

    with get_db() as db:
        rss = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('RSS', 'https://v.example/feed', ?)", (now(),)).lastrowid
        page = db.execute("INSERT INTO feeds (title, url, created_at, kind) VALUES ('Page', 'https://v.example/blog', ?, 'html')", (now(),)).lastrowid
        assert insert_article(db, rss, guid="g1", url="https://v.example/blog/a/", title="A", author=None, raw_html="x", published=now(), fetched_at=now())
        assert insert_article(db, page, guid="p1", url="https://v.example/blog/a/", title="A", author=None, raw_html="", published=now(),
                              fetched_at=now(), any_feed=True) is None
        assert insert_article(db, page, guid="p2", url="https://v.example/blog/b/", title="B", author=None, raw_html="", published=now(),
                              fetched_at=now(), any_feed=True)
