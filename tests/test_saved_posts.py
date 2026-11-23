"""Single saved posts in the Accounts tab: read readably (author, handle, date, picture, whole text), a collapsed preview
with the full text on demand, the Follow offer, pasting / re-reading - using only official or public endpoints."""

import json
from unittest import mock

import httpx
import pytest

from app import netguard, social_posts

KARPATHY = "https://x.com/karpathy/status/2039805659525644595"
LI_LINK = "https://www.linkedin.com/feed/update/urn:li:activity:7527177742136713216/"
LI_BODY = ("🏭 YOUR LAPTOP CAN BECOME AN OT/ICS LAB 🏭\n\nYou don't need a $400 PLC.\n\n1️⃣ AtomICS 🔗 https://lnkd.in/eaxAmYF8\n"
           + "More text. " * 60 + "\n\n#OTSecurity")


def resp(body, status=200, url="https://x.example/", ctype="application/json"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


def oembed(text_html="LLM Knowledge Bases<br><br>Something I&#39;m finding very useful recently, and more into manipulating…"):
    return {"url": KARPATHY, "author_name": "Andrej Karpathy", "author_url": "https://x.com/karpathy",
            "html": f'<blockquote class="twitter-tweet"><p lang="en" dir="ltr">{text_html}</p>&mdash; Andrej Karpathy (@karpathy) '
                    f'<a href="{KARPATHY}?ref_src=twsrc%5Etfw">April 2, 2026</a></blockquote>'}


def li_page(ld=None, og_desc="You don't need a $400 PLC", og_image="https://media.licdn.com/dms/image/v2/feed.jpg?e=1&amp;v=beta"):
    ld = ld if ld is not None else {
        "@context": "http://schema.org", "@type": "DiscussionForumPosting", "datePublished": "2026-11-14T01:17:01.923Z",
        "headline": "YOUR LAPTOP", "articleBody": LI_BODY,
        "image": {"@type": "ImageObject", "url": "https://media.licdn.com/dms/image/v2/feedshare.jpg?e=2&v=beta"},
        "author": {"@type": "Person", "name": "António Sousa", "url": "https://ao.linkedin.com/in/antoniosousait",
                   "image": {"@type": "ImageObject", "url": "https://media.licdn.com/dms/image/v2/avatar.jpg"}},
        "comment": [{"@type": "Comment", "text": "a comment", "author": {"name": "Someone"}}]}
    return (f'<html><head><meta property="og:title" content="YOUR LAPTOP | António Sousa">'
            f'<meta property="og:description" content="{og_desc}"><meta property="og:image" content="{og_image}">'
            f'<script type="application/ld+json">{json.dumps(ld)}</script></head><body>Sign in</body></html>')


# ------------------------------------------------------------------ parsing (no app)
def test_plain_text_keeps_paragraphs_and_line_breaks():
    assert social_posts.plain_text("<p>A &amp; b<br>B</p><p>C</p>") == "A & b\nB\n\nC"
    assert social_posts.search_text("<p>Bases</p><p>Something</p>") == "Bases Something"   # words no longer run together
    assert social_posts.strip_lead_image('<p><img src="https://a/b.jpg" alt=""></p><p>x</p>') == "<p>x</p>"


def test_x_embed_gives_author_handle_date_breaks_and_says_when_shortened():
    with mock.patch("app.social_posts.netguard.request", return_value=resp(oembed())) as req:
        p = social_posts.fetch(KARPATHY + "?s=20")
    assert "publish.twitter.com/oembed" in req.call_args.args[1]
    assert req.call_args.kwargs["headers"]["User-Agent"].startswith("EyeOfSauron/")      # the app's own honest name
    assert p["author"] == "Andrej Karpathy" and p["handle"] == "@karpathy" and p["profile_url"] == "https://x.com/karpathy"
    assert p["text"].startswith("LLM Knowledge Bases\n\nSomething I'm finding") and p["title"] == "LLM Knowledge Bases"
    assert p["truncated"] is True and p["source"] == "oembed" and p["dated"]


def test_x_shortened_post_is_completed_by_your_rsshub_bridge():
    full = ('<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>LLM</title><summary type="html">'
            '&lt;p&gt;LLM Knowledge Bases&lt;br&gt;&lt;br&gt;Something I am finding very useful recently, and the whole long '
            'rest of the post is here.&lt;/p&gt;&lt;img src="https://pbs.twimg.com/media/abc.jpg"&gt;</summary></entry></feed>')

    def fake(method, url, **kw):
        if "publish.twitter.com" in url:
            return resp(oembed(), url=url)
        assert url == "http://127.0.0.1:1200/twitter/tweet/karpathy/status/2039805659525644595"
        assert kw["allow_private"] is True                                                 # your own bridge on this machine
        return resp(full, url=url, ctype="application/atom+xml")

    with mock.patch("app.social_posts.netguard.request", side_effect=fake):
        p = social_posts.fetch(KARPATHY, rsshub="http://127.0.0.1:1200")
    assert p["truncated"] is False and p["source"] == "bridge" and "whole long rest" in p["text"]
    assert p["image"] == "https://pbs.twimg.com/media/abc.jpg"


def test_x_official_api_when_a_token_is_set():
    data = {"data": {"id": "2039805659525644595", "text": "short…", "created_at": "2026-04-02T16:00:00.000Z",
                     "note_tweet": {"text": "LLM Knowledge Bases\n\nThe whole note."}},
            "includes": {"users": [{"username": "karpathy", "name": "Andrej Karpathy", "profile_image_url": "https://pbs.twimg.com/p/a.jpg"}],
                         "media": [{"type": "photo", "url": "https://pbs.twimg.com/media/b.jpg"}]}}
    with mock.patch("app.social_posts.netguard.request", return_value=resp(data)) as req:
        p = social_posts.fetch(KARPATHY, x_token="TOKEN")
    assert req.call_args.args[1].startswith("https://api.x.com/2/tweets/2039805659525644595?")
    assert req.call_args.kwargs["headers"]["Authorization"] == "Bearer TOKEN"
    assert p["text"] == "LLM Knowledge Bases\n\nThe whole note." and p["truncated"] is False and p["source"] == "api"
    assert p["avatar"] == "https://pbs.twimg.com/p/a.jpg" and p["image"] == "https://pbs.twimg.com/media/b.jpg"


def test_linkedin_public_structured_data_gives_the_whole_post():
    with mock.patch("app.social_posts.netguard.request", return_value=resp(li_page(), url=LI_LINK, ctype="text/html")):
        p = social_posts.fetch(LI_LINK)
    assert p["text"].startswith("🏭 YOUR LAPTOP") and "#OTSecurity" in p["text"] and "\n\n" in p["text"]
    assert p["source"] == "jsonld" and p["truncated"] is False
    assert p["author"] == "António Sousa" and p["handle"] == "in/antoniosousait"
    assert p["profile_url"] == "https://www.linkedin.com/in/antoniosousait"                 # ao.linkedin.com → www
    assert p["avatar"] == "https://media.licdn.com/dms/image/v2/avatar.jpg"
    assert p["image"].startswith("https://media.licdn.com/dms/image/v2/feedshare.jpg")
    assert p["published"] == 1794619021 and '<a href="https://lnkd.in/eaxAmYF8"' in p["html"]


def test_open_graph_only_is_marked_shortened_and_foreign_hosts_are_dropped():
    long_desc = "Opening of the post " * 10
    page = li_page(ld={"@type": "SocialMediaPosting", "image": "https://evil.example/pixel.gif",
                       "author": {"name": "X", "url": "https://evil.example/in/x", "image": "javascript:alert(1)"}}, og_desc=long_desc)
    with mock.patch("app.social_posts.netguard.request", return_value=resp(page, url=LI_LINK, ctype="text/html")):
        p = social_posts.fetch("https://www.linkedin.com/posts/janedoe_some-post-activity-1")
    assert p["source"] == "og" and p["truncated"] is True
    assert p["image"].startswith("https://media.licdn.com/")                                # the tracker pixel was dropped
    assert p["avatar"] is None
    assert p["profile_url"] == "https://www.linkedin.com/in/janedoe"                         # from the post link, not evil.example
    assert social_posts.safe_image("http://media.licdn.com/a.jpg", "linkedin") is None       # https only


def test_login_wall_still_refuses_without_pasted_text():
    wall = resp("<html><body>Sign in to see this</body></html>", url=LI_LINK, ctype="text/html")
    with mock.patch("app.social_posts.netguard.request", return_value=wall):
        with pytest.raises(social_posts.PostError, match="never gets around"):
            social_posts.fetch(LI_LINK)
        p = social_posts.fetch(LI_LINK, "My copy <script>x</script>")
    assert p["source"] == "pasted" and "<script" not in p["html"]


# ------------------------------------------------------------------ the API
def _add_karpathy(authed):
    with mock.patch("app.social_posts.netguard.request", return_value=resp(oembed())):
        r = authed.post("/api/v1/accounts/posts", json={"url": KARPATHY})
    assert r.status_code == 201, r.text
    return r.json()


def test_saved_post_card_data_detail_paste_and_refresh(authed):
    authed.patch("/api/v1/settings", json={"image_proxy": False})
    added = _add_karpathy(authed)
    assert added["handle"] == "@karpathy" and added["truncated"] is True
    assert added["follow"]["possible"] is False and "RSSHub bridge" in added["follow"]["reason"]   # nothing set up for X
    item = next(p for p in authed.get("/api/v1/accounts/posts?limit=50").json()["items"] if p["id"] == added["id"])
    assert item["saved"] and item["author"] == "Andrej Karpathy" and item["handle"] == "@karpathy"
    assert item["text"].startswith("LLM Knowledge Bases\n\n") and item["text_len"] == len(item["text"]) and item["truncated"]
    shelf_items = [p for s in authed.get("/api/v1/accounts/shelves").json()["shelves"] for p in s["items"]]
    assert any(p.get("handle") == "@karpathy" for p in shelf_items)                           # By topic view too
    detail = authed.get(f"/api/v1/accounts/posts/{added['id']}").json()
    assert detail["html"].startswith("<p>LLM Knowledge Bases<br>") and detail["follow"]["url"] == "https://x.com/karpathy"
    # your pasted copy replaces the shortened text, as text (never HTML)
    r = authed.put(f"/api/v1/accounts/posts/{added['id']}/text", json={"text": "LLM Knowledge Bases\n\nAll of it <script>x</script>"})
    assert r.status_code == 200 and r.json()["truncated"] is False and r.json()["source"] == "pasted"
    assert "<script" not in r.json()["html"] and "All of it" in r.json()["text"]
    hits = authed.get("/api/v1/accounts/posts?q=All%20of%20it").json()
    assert [p["id"] for p in hits["items"]] == [added["id"]]                                   # search sees the pasted text
    # reading it again keeps the paste, refreshes the rest
    with mock.patch("app.social_posts.netguard.request", return_value=resp(oembed())):
        again = authed.post(f"/api/v1/accounts/posts/{added['id']}/refresh").json()
    assert "All of it" in again["text"] and again["source"] == "pasted" and again["handle"] == "@karpathy"
    # only saved posts have these routes; validation
    assert authed.get("/api/v1/accounts/posts/999999").status_code == 404
    assert authed.put(f"/api/v1/accounts/posts/{added['id']}/text", json={"text": ""}).status_code == 422
    assert authed.put(f"/api/v1/accounts/posts/{added['id']}/text", json={"text": "x" * 20001}).status_code == 422


def test_saved_post_routes_need_sign_in_and_csrf(authed):
    added = _add_karpathy(authed)
    token = authed.headers.pop("X-CSRF-Token")
    assert authed.put(f"/api/v1/accounts/posts/{added['id']}/text", json={"text": "x"}).status_code in (401, 403)
    assert authed.post(f"/api/v1/accounts/posts/{added['id']}/refresh").status_code in (401, 403)
    authed.headers["X-CSRF-Token"] = token
    authed.cookies.clear()
    assert authed.get(f"/api/v1/accounts/posts/{added['id']}").status_code == 401


def test_pictures_go_through_the_image_proxy_when_it_is_on(authed):
    authed.patch("/api/v1/settings", json={"image_proxy": True, "load_images": True})
    with mock.patch("app.social_posts.netguard.request", return_value=resp(li_page(), url=LI_LINK, ctype="text/html")):
        added = authed.post("/api/v1/accounts/posts", json={"url": LI_LINK}).json()
    assert added["follow"]["possible"] is False and "personal profiles" in added["follow"]["reason"]  # LinkedIn has no feed
    item = authed.get(f"/api/v1/accounts/posts/{added['id']}").json()
    assert item["image"].startswith("/api/v1/img?u=https%3A%2F%2Fmedia.licdn.com") and item["avatar"].startswith("/api/v1/img?u=")
    assert "<img" not in item["html"]                                                         # the card shows the picture once
    authed.patch("/api/v1/settings", json={"load_images": False})
    assert authed.get(f"/api/v1/accounts/posts/{added['id']}").json()["image"] is None


def test_follow_the_author_of_a_saved_post(authed):
    post = {"thread": {"post": {"record": {"text": "Patch now: a long Bluesky post", "createdAt": "2026-11-01T10:00:00Z"},
                                "author": {"handle": "alice.bsky.social", "displayName": "Alice", "avatar": "https://cdn.bsky.app/img/avatar/a.jpg"},
                                "embed": {"$type": "app.bsky.embed.images#view", "images": [{"fullsize": "https://cdn.bsky.app/img/feed/b.jpg"}]}}}}
    rss = ('<?xml version="1.0"?><rss version="2.0"><channel><title>@alice.bsky.social</title>'
           '<item><title>hello</title><link>https://bsky.app/profile/alice.bsky.social/post/3abcdefg</link></item></channel></rss>')

    def fake(method, url, **kw):
        if "public.api.bsky.app" in url:
            return resp(post, url=url)
        assert url == "https://bsky.app/profile/alice.bsky.social/rss", url
        return resp(rss, url=url, ctype="application/rss+xml")

    with mock.patch("app.netguard.request", side_effect=fake):
        added = authed.post("/api/v1/accounts/posts", json={"url": "https://bsky.app/profile/alice.bsky.social/post/3abcdefg"}).json()
        assert added["follow"] == {"url": "https://bsky.app/profile/alice.bsky.social", "possible": True, "followed": False,
                                   "reason": None, "platform": "bluesky", "note": None}
        r = authed.post("/api/v1/accounts", json={"input": added["follow"]["url"]})              # what the ＋ Follow button sends
        assert r.status_code == 201, r.text
    item = authed.get(f"/api/v1/accounts/posts/{added['id']}").json()
    assert item["follow"]["followed"] is True and item["handle"] == "@alice.bsky.social"


def test_recognize_says_which_sites_will_be_contacted(authed):
    x = authed.post("/api/v1/accounts/recognize", json={"input": KARPATHY}).json()
    assert x["kind"] == "post" and x["contacts"] == ["publish.twitter.com (X's public embed)"]
    li = authed.post("/api/v1/accounts/recognize", json={"input": LI_LINK}).json()
    assert li["contacts"] == ["www.linkedin.com (its public link preview)"] and li["needs_text"] is True


def test_older_saved_posts_get_details_and_keep_a_longer_pasted_copy(authed):
    """Posts saved before this change (no details row) are read again; a longer stored copy is taken to be pasted."""
    from app.db import get_db

    with mock.patch("app.social_posts.netguard.request", return_value=resp(oembed())):
        added = authed.post("/api/v1/accounts/posts", json={"url": KARPATHY}).json()
    pasted = "<p>LLM Knowledge Bases</p><p>" + "The complete text I pasted long ago. " * 20 + "</p>"
    with get_db() as db:
        db.execute("DELETE FROM social_post_meta WHERE article_id = ?", (added["id"],))
        db.execute("UPDATE articles SET content_html = ?, author = NULL WHERE id = ?", (pasted, added["id"]))
    with mock.patch("app.social_posts.netguard.request", return_value=resp(oembed())):
        social_posts.refresh_saved(added["id"])
    item = authed.get(f"/api/v1/accounts/posts/{added['id']}").json()
    assert "complete text I pasted" in item["text"] and item["truncated"] is False and item["source"] == "pasted"
    assert item["author"] == "Andrej Karpathy" and item["handle"] == "@karpathy"


# ------------------------------------------------------------------ deleting posts (🗑)
def test_delete_posts_for_good_only_in_this_tab(authed):
    from app.db import get_db, now
    from app.fetcher import insert_article

    added = _add_karpathy(authed)
    with get_db() as db:
        followed = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES ('r/x', 'https://www.reddit.com/r/x/new/.rss', ?, "
                              "'reddit')", (now(),)).lastrowid
        other = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Blog', 'https://blog.example/feed', ?)", (now(),)).lastrowid
        post = insert_article(db, followed, guid="t3_abc", url="https://www.reddit.com/r/x/comments/abc/", title="A post", author=None,
                              raw_html="<p>hi</p>", published=now(), fetched_at=now())
        article = insert_article(db, other, guid="blog-1", url="https://blog.example/1", title="Blog post", author=None,
                                 raw_html="<p>x</p>", published=now(), fetched_at=now())
    # one saved post: gone with its details; pasting its link again brings it back
    assert authed.delete(f"/api/v1/accounts/posts/{added['id']}").json() == {"ok": True, "deleted": 1}
    assert authed.get(f"/api/v1/accounts/posts/{added['id']}").status_code == 404
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM social_post_meta WHERE article_id = ?", (added["id"],)).fetchone()[0] == 0
    assert _add_karpathy(authed)["id"] != added["id"]
    # several: an Articles item is never touched by this tab
    r = authed.post("/api/v1/accounts/posts/delete", json={"ids": [post, article, 999999]})
    assert r.status_code == 200 and r.json()["deleted"] == 1
    assert authed.get(f"/api/v1/articles/{article}").status_code == 200
    assert authed.delete(f"/api/v1/accounts/posts/{article}").status_code == 404
    with get_db() as db:  # the account's next check doesn't bring it back
        assert insert_article(db, followed, guid="t3_abc", url="https://www.reddit.com/r/x/comments/abc/", title="A post", author=None,
                              raw_html="<p>hi</p>", published=now(), fetched_at=now()) is None
    assert authed.post("/api/v1/accounts/posts/delete", json={"ids": []}).status_code == 422
    assert authed.post("/api/v1/accounts/posts/delete", json={"ids": list(range(1, 502))}).status_code == 422
    token = authed.headers.pop("X-CSRF-Token")       # writers only, with CSRF
    assert authed.post("/api/v1/accounts/posts/delete", json={"ids": [post]}).status_code in (401, 403)
    authed.headers["X-CSRF-Token"] = token


# ------------------------------------------------------------------ no duplicates
def test_the_same_post_cannot_be_added_twice_in_any_link_form(authed):
    from app.db import get_db, now
    from app.fetcher import insert_article

    first = _add_karpathy(authed)
    never = mock.patch("app.netguard.request", side_effect=AssertionError("no site is asked for a duplicate"))
    with never:
        for again in ("https://twitter.com/Karpathy/status/2039805659525644595?s=20", "x.com/karpathy/status/2039805659525644595/",
                      "https://mobile.twitter.com/karpathy/status/2039805659525644595"):
            r = authed.post("/api/v1/accounts/posts", json={"url": again})
            assert r.status_code == 409 and "already saved" in r.text and "Saved X posts" in r.text, again
        seen = authed.post("/api/v1/accounts/recognize", json={"input": "https://twitter.com/karpathy/status/2039805659525644595"}).json()
    assert seen["exists"] == {"id": first["id"], "where": "Saved X posts"}
    # LinkedIn: /feed/update/urn:li:activity:N/ and /posts/name_…-activity-N-… are the same post
    with mock.patch("app.social_posts.netguard.request", return_value=resp(li_page(), url=LI_LINK, ctype="text/html")):
        assert authed.post("/api/v1/accounts/posts", json={"url": LI_LINK}).status_code == 201
    with never:
        r = authed.post("/api/v1/accounts/posts", json={
            "url": "https://www.linkedin.com/posts/antoniosousait_%F0%9D%90%98-activity-7527177742136713216-hB49?utm_source=share"})
        assert r.status_code == 409
    # a post that's already here from an account you follow
    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, kind, social_platform) VALUES ('@nasa on X', 'https://x.com/nasa', ?, 'x', 'x')",
                         (now(),)).lastrowid
        insert_article(db, fid, guid="x:status:2121364270281822467", url="https://x.com/NASA/status/2121364270281822467", title="Launch",
                       author=None, raw_html="<p>Launch</p>", published=now(), fetched_at=now())
    with never:
        r = authed.post("/api/v1/accounts/posts", json={"url": "https://twitter.com/nasa/status/2121364270281822467"})
    assert r.status_code == 409 and "@nasa on X" in r.text
    # deleted on purpose → may be added again
    authed.delete(f"/api/v1/accounts/posts/{first['id']}")
    assert authed.post("/api/v1/accounts/recognize", json={"input": KARPATHY}).json()["exists"] is None
    _add_karpathy(authed)


def test_different_facebook_permalink_posts_are_not_mistaken_for_one():
    a = social_posts.post_key("https://www.facebook.com/permalink.php?story_fbid=111&id=9&utm_source=x")
    b = social_posts.post_key("https://www.facebook.com/permalink.php?story_fbid=222&id=9")
    assert a != b and a == social_posts.post_key(social_posts._clean_url("https://www.facebook.com/permalink.php?story_fbid=111&id=9"))
    assert social_posts._clean_url("https://www.facebook.com/permalink.php?story_fbid=111&id=9&fbclid=zz").endswith("?story_fbid=111&id=9")
    assert social_posts.post_key("https://www.reddit.com/r/netsec/comments/abc123/x/") == social_posts.post_key("https://old.reddit.com/r/netsec/comments/abc123")
    assert social_posts.post_key("javascript:alert(1)") is None
