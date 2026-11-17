"""Add a single social media post by its link (+ optional pasted text), using only official/public endpoints.

* X: the public embed service (publish.twitter.com/oembed) - no login.
* Reddit: the post's public .json.
* Bluesky: the public AppView API (public.api.bsky.app).
* Mastodon / fediverse: the server's public /api/v1/statuses/<id>.
* TikTok: the public oEmbed (www.tiktok.com/oembed).
* Threads: your RSSHub bridge's post route, when a bridge is configured.
* LinkedIn, Instagram, Facebook and anything else: these sites put posts behind a login and bot checks, which the app
  never gets around - paste the post's text with its link and it is saved as it is.
Every request goes through the SSRF-guarded client; text is sanitised like feed content.
"""

from __future__ import annotations

import html as htmlmod
import json
import re
import time
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit

from app import netguard
from app.config import get_settings
from app.sanitize import sanitize_html, to_text

MAX_TEXT = 20_000
X_STATUS = re.compile(r"^/([A-Za-z0-9_]{1,15})/status(?:es)?/(\d{5,25})")
REDDIT_POST = re.compile(r"^/r/([A-Za-z0-9_]{2,21})/comments/([a-z0-9]{3,12})")
BSKY_POST = re.compile(r"^/profile/([A-Za-z0-9.:-]{3,253})/post/([a-z0-9]{5,20})$")
MASTO_STATUS = re.compile(r"^/@([A-Za-z0-9_]{1,30})(?:@[a-z0-9.-]+)?/(\d{5,25})$")
THREADS_POST = re.compile(r"^/@([A-Za-z0-9._]{1,40})/post/([A-Za-z0-9_-]{5,40})")
TIKTOK_VIDEO = re.compile(r"^/@([A-Za-z0-9._]{1,40})/video/(\d{5,25})")
PASTE_ONLY = {"linkedin.com": "linkedin", "instagram.com": "instagram", "facebook.com": "facebook", "fb.com": "facebook"}


class PostError(ValueError):
    pass


def _get_json(url: str) -> dict | list:
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
                                timeout=cfg.fetch_timeout, max_bytes=2_000_000)
    except netguard.UnsafeURLError as exc:
        raise PostError(str(exc)) from None
    except netguard.FetchError as exc:
        raise PostError(f"Could not reach the site: {exc}") from None
    if resp.status_code >= 400:
        raise PostError(f"The site answered HTTP {resp.status_code} (deleted or private post?)")
    try:
        return json.loads(resp.content)
    except ValueError:
        raise PostError("The site did not answer with post data") from None


def _feed_entries(url: str) -> list[dict]:
    from app.fetcher import parse_bytes  # local import: fetcher is heavy
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.fetch_timeout,
                                max_bytes=cfg.max_feed_bytes)
    except (netguard.UnsafeURLError, netguard.FetchError) as exc:
        raise PostError(f"Could not reach the site: {exc}") from None
    if resp.status_code == 429:
        raise PostError("The site is rate-limiting requests right now - try again in a few minutes")
    if resp.status_code >= 400:
        raise PostError(f"The site answered HTTP {resp.status_code} (deleted or private post?)")
    return (parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}).get("entries") or []


def _first_feed_entry(url: str) -> dict:
    entries = _feed_entries(url)
    if not entries:
        raise PostError("The post could not be read")
    return entries[0]


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+")
_TRAILING = ".,;:!?)]}"
PREVIEW_MAX = 2_000_000


def para_html(text: str) -> str:
    """Plain text → paragraphs with every web address made a link (escaped first, then sanitised by the caller)."""
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts, pos = [], 0
        for m in _URL_IN_TEXT.finditer(line):
            url = m.group(0).rstrip(_TRAILING)
            parts.append(htmlmod.escape(line[pos:m.start()]))
            parts.append(f'<a href="{htmlmod.escape(url, quote=True)}">{htmlmod.escape(url)}</a>')
            pos = m.start() + len(url)
        parts.append(htmlmod.escape(line[pos:]))
        out.append("<p>" + "".join(parts) + "</p>")
    return "".join(out)


def _meta(page: str, key: str) -> str:
    for pat in (rf'<meta[^>]+(?:property|name)="{re.escape(key)}"[^>]+content="([^"]*)"',
                rf'<meta[^>]+content="([^"]*)"[^>]+(?:property|name)="{re.escape(key)}"'):
        m = re.search(pat, page)
        if m:
            return htmlmod.unescape(m.group(1)).strip()
    return ""


def public_preview(link: str) -> dict:
    """The preview a site shows anyone (Open Graph tags: image, title, description) - what a link preview in a chat
    app shows. A login wall (no tags) simply gives {}; nothing is ever done to get around it."""
    cfg = get_settings()
    try:
        resp = netguard.request("GET", link, headers={"User-Agent": cfg.user_agent, "Accept": "text/html"},
                                timeout=cfg.fetch_timeout, max_bytes=PREVIEW_MAX)
    except (netguard.FetchError, netguard.UnsafeURLError):
        return {}
    if resp.status_code >= 400 or "html" not in (resp.headers.get("content-type") or ""):
        return {}
    page = resp.content.decode("utf-8", "replace")
    title, desc, image = _meta(page, "og:title"), _meta(page, "og:description"), _meta(page, "og:image")
    if not (title or desc):
        return {}
    try:
        image = netguard.normalize_url(image) if image.startswith("https://") else ""
    except netguard.UnsafeURLError:
        image = ""
    author = title.rsplit(" | ", 1)[1].strip()[:200] if " | " in title else None  # "Post text… | Jane Doe"
    return {"image": image or None, "title": to_text(title, 500), "text": to_text(desc), "author": author}


def _host(url: str) -> str:
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _clean_url(url: str) -> str:
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise PostError("Paste the post's full link (https://…)")
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))  # drop tracking query strings


def _iso(value) -> int | None:
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return None


LI_POST = re.compile(r"^/(?:posts/|feed/update/|pulse/)")
IG_POST = re.compile(r"^/(?:p|reel|reels|tv)/[A-Za-z0-9_-]{4,}")
FB_POST = re.compile(r"/(?:posts|videos|permalink\.php|story\.php|share/[prv]|photo|reel)/?")


def is_post_url(url: str) -> bool:
    """Is this a link to one post (not a profile / subreddit)? No network."""
    p = urlsplit(url.strip() if "://" in url else "https://" + url.strip())
    path, plat = p.path or "/", platform_of(urlunsplit((p.scheme or "https", p.netloc, p.path, "", "")))
    return bool(
        (plat == "x" and X_STATUS.match(path)) or (plat == "reddit" and REDDIT_POST.match(path))
        or (plat == "bluesky" and BSKY_POST.match(path)) or MASTO_STATUS.match(path)
        or (plat == "threads" and THREADS_POST.match(path)) or (plat == "tiktok" and TIKTOK_VIDEO.match(path))
        or (plat == "linkedin" and LI_POST.match(path)) or (plat == "instagram" and IG_POST.match(path))
        or (plat == "facebook" and FB_POST.search(path)))


def platform_of(url: str) -> str:
    h = _host(url)
    if h in ("x.com", "twitter.com", "mobile.twitter.com"):
        return "x"
    if h.endswith("reddit.com"):
        return "reddit"
    if h == "bsky.app":
        return "bluesky"
    if h in ("threads.net", "threads.com"):
        return "threads"
    if h.endswith("tiktok.com"):
        return "tiktok"
    for dom, name in PASTE_ONLY.items():
        if h == dom or h.endswith("." + dom):
            return name
    if MASTO_STATUS.match(urlsplit(url).path):
        return "mastodon"
    return "other"


def fetch(url: str, pasted: str | None = None, rsshub: str | None = None) -> dict:
    """-> {platform, link, title, text (plain), html, author, published}. Pasted text is used when given, and is
    required for sites that don't let apps read posts (LinkedIn, Instagram, Facebook...)."""
    link = _clean_url(url)
    plat = platform_of(link)
    path = urlsplit(link).path
    pasted = (pasted or "").strip()[:MAX_TEXT]
    out = {"platform": plat, "link": link, "title": "", "text": "", "html": "", "author": None, "published": None}
    try:
        if plat == "x" and (m := X_STATUS.match(path)):
            data = _get_json(f"https://publish.twitter.com/oembed?omit_script=1&dnt=true&url={quote(link, safe='')}")
            block = str(data.get("html") or "")
            para = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
            out["text"] = to_text(para.group(1) if para else block)
            out["author"] = to_text(data.get("author_name"), 200) or f"@{m.group(1)}"
            date = re.findall(r">([A-Z][a-z]+ \d{1,2}, \d{4})</a>", block)
            if date:
                try:
                    out["published"] = int(datetime.strptime(date[-1], "%B %d, %Y").timestamp())
                except ValueError:
                    pass
        elif plat == "reddit" and REDDIT_POST.match(path):
            try:
                data = _get_json(link.rstrip("/") + "/.json?raw_json=1")
                post = data[0]["data"]["children"][0]["data"] if isinstance(data, list) else {}
                out["title"] = to_text(post.get("title"), 500)
                out["text"] = to_text(post.get("selftext") or "")
                out["author"] = f"u/{post.get('author')}" if post.get("author") else None
                out["published"] = int(post["created_utc"]) if post.get("created_utc") else None
            except PostError:  # Reddit often refuses its JSON to apps; the post's RSS (first entry = the post) still works
                entry = _first_feed_entry(link.rstrip("/") + "/.rss")
                out["title"] = to_text(entry.get("title"), 500)
                out["html"] = sanitize_html((entry.get("content") or [{}])[0].get("value") or entry.get("summary") or "")
                out["text"] = to_text(out["html"])
                out["author"] = to_text(entry.get("author"), 200) or None
        elif plat == "bluesky" and (m := BSKY_POST.match(path)):
            uri = f"at://{m.group(1)}/app.bsky.feed.post/{m.group(2)}"
            data = _get_json(f"https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?depth=0&uri={quote(uri, safe='')}")
            post = (data.get("thread") or {}).get("post") or {}
            out["text"] = to_text(((post.get("record") or {}).get("text")) or "")
            author = post.get("author") or {}
            out["author"] = to_text(author.get("displayName") or author.get("handle"), 200) or m.group(1)
            out["published"] = _iso((post.get("record") or {}).get("createdAt"))
        elif plat == "mastodon" and (m := MASTO_STATUS.match(path)):
            data = _get_json(f"https://{urlsplit(link).netloc}/api/v1/statuses/{m.group(2)}")
            out["html"] = sanitize_html(str(data.get("content") or ""))
            out["text"] = to_text(out["html"])
            out["author"] = f"@{(data.get('account') or {}).get('acct') or m.group(1)}"
            out["published"] = _iso(data.get("created_at"))
        elif plat == "tiktok" and (m := TIKTOK_VIDEO.match(path)):
            data = _get_json(f"https://www.tiktok.com/oembed?url={quote(link, safe='')}")
            out["text"] = to_text(data.get("title") or "")
            out["author"] = to_text(data.get("author_name"), 200) or f"@{m.group(1)}"
            if not out["text"] and rsshub:  # the embed sometimes omits the caption: find the video in the bridge's feed
                for e in _feed_entries(f"{rsshub.rstrip('/')}/tiktok/user/@{quote(m.group(1))}"):
                    if m.group(2) in str(e.get("link") or ""):
                        out["html"] = sanitize_html(e.get("summary") or "")
                        out["text"] = to_text(e.get("title") or out["html"])
                        break
        elif plat == "threads" and rsshub and (m := THREADS_POST.match(path)):
            from app.fetcher import parse_bytes  # local import: fetcher is heavy
            cfg = get_settings()
            resp = netguard.request("GET", f"{rsshub.rstrip('/')}/threads/{quote(m.group(1))}/post/{quote(m.group(2))}",
                                    headers={"User-Agent": cfg.user_agent}, timeout=cfg.fetch_timeout, max_bytes=cfg.max_feed_bytes)
            if resp.status_code < 400:
                entries = (parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}).get("entries") or []
                if entries:
                    e = entries[0]
                    out["html"] = sanitize_html(e.get("summary") or "")
                    out["text"] = to_text(out["html"])
                    out["author"] = f"@{m.group(1)}"
    except PostError:
        if not pasted:
            raise
    image = None
    if plat in PASTE_ONLY.values():  # LinkedIn, Instagram, Facebook: the public preview (image, author, opening text)
        preview = public_preview(link)
        image = preview.get("image")
        out["author"] = out["author"] or preview.get("author")
        if not pasted and preview.get("text"):
            out["text"] = preview["text"]  # the opening of the post; paste the text for all of it
    if pasted:  # your copy of the post wins (and is the only way to get all of a LinkedIn / Instagram / Facebook post)
        out["text"] = to_text(pasted)
        out["html"] = para_html(pasted)
    if not out["text"] and not out["title"]:
        names = {"linkedin": "LinkedIn", "instagram": "Instagram", "facebook": "Facebook", "threads": "Threads", "other": "This site"}
        raise PostError(f"{names.get(plat, 'This site')} doesn't let apps read posts without logging in, and the app never gets "
                        "around that. Copy the post's text into the box below the link and add it again.")
    if not out["html"]:
        out["html"] = para_html(out["text"])
    if image:
        out["html"] = f'<p><img src="{htmlmod.escape(image, quote=True)}" alt=""></p>' + out["html"]
    out["html"] = sanitize_html(out["html"])
    if not out["title"]:
        first = out["text"].strip().split("\n")[0]
        out["title"] = first if len(first) <= 140 else first[:137].rstrip() + "…"
    out["published"] = out["published"] or int(time.time())
    return out
