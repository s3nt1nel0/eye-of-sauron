"""Add a single social media post by its link (+ optional pasted text), using only official/public endpoints.

* X: the official X API when a bearer token is set (Settings → Integrations → X), otherwise the public embed service
  (publish.twitter.com/oembed) - no login. The embed shortens long posts ("…"): then your RSSHub bridge is asked for
  the whole post when one is set up, and otherwise the post is marked as shortened and you can paste the rest.
* Reddit: the post's public .json (its RSS when Reddit refuses the JSON).
* Bluesky: the public AppView API (public.api.bsky.app).
* Mastodon / fediverse: the server's public /api/v1/statuses/<id>.
* TikTok: the public oEmbed (www.tiktok.com/oembed).
* Threads: your RSSHub bridge's post route, when a bridge is configured.
* LinkedIn, Instagram, Facebook and anything else: the page's public link-preview data - the schema.org JSON-LD and
  Open Graph tags a site hands to anyone (LinkedIn's carries the whole post, its author and date). When a site puts the
  post behind a login there is nothing there, and the app never gets around that - paste the post's text instead.
Every request goes through the SSRF-guarded client with the app's own honest User-Agent; text is sanitised (nh3) like
feed content, and pictures / profile links are only kept when they are https addresses on the post's own platform.
"""

from __future__ import annotations

import html as htmlmod
import json
import re
import time
from datetime import datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import nh3

from app import netguard
from app.config import get_settings
from app.sanitize import MAX_HTML_LENGTH, sanitize_html, to_text

MAX_TEXT = 20_000
X_STATUS = re.compile(r"^/([A-Za-z0-9_]{1,15})/status(?:es)?/(\d{5,25})")
REDDIT_POST = re.compile(r"^/r/([A-Za-z0-9_]{2,21})/comments/([a-z0-9]{3,12})")
BSKY_POST = re.compile(r"^/profile/([A-Za-z0-9.:-]{3,253})/post/([a-z0-9]{5,20})$")
MASTO_STATUS = re.compile(r"^/@([A-Za-z0-9_]{1,30})(?:@[a-z0-9.-]+)?/(\d{5,25})$")
THREADS_POST = re.compile(r"^/@([A-Za-z0-9._]{1,40})/post/([A-Za-z0-9_-]{5,40})")
TIKTOK_VIDEO = re.compile(r"^/@([A-Za-z0-9._]{1,40})/video/(\d{5,25})")
PASTE_ONLY = {"linkedin.com": "linkedin", "instagram.com": "instagram", "facebook.com": "facebook", "fb.com": "facebook"}
SAVED_FEED_PREFIX = "https://eye-of-sauron.invalid/saved-posts/"  # the per-platform "Saved … posts" lists (never fetched)
# The platform's own domains: a profile link or picture from a post is only kept when it points at one of these.
OWN_DOMAINS = {
    "x": ("x.com", "twitter.com", "twimg.com"), "reddit": ("reddit.com", "redd.it", "redditmedia.com"),
    "bluesky": ("bsky.app", "bsky.social", "bsky.network", "cdn.bsky.app"), "tiktok": ("tiktok.com", "tiktokcdn.com", "tiktokcdn-us.com"),
    "threads": ("threads.net", "threads.com", "cdninstagram.com", "fbcdn.net"), "linkedin": ("linkedin.com", "licdn.com"),
    "instagram": ("instagram.com", "cdninstagram.com", "fbcdn.net"), "facebook": ("facebook.com", "fb.com", "fbcdn.net"),
}
LD_POST_TYPES = {"SocialMediaPosting", "DiscussionForumPosting", "BlogPosting", "Article", "NewsArticle", "VideoObject", "Comment"}


class PostError(ValueError):
    pass


def _get_json(url: str, headers: dict | None = None) -> dict | list:
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": "application/json", **(headers or {})},
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


def _feed_entries(url: str, allow_private: bool = False) -> list[dict]:
    """``allow_private``: only for your own bridge (RSSHub), which normally runs on this machine or the LAN."""
    from app.fetcher import parse_bytes  # local import: fetcher is heavy
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.fetch_timeout,
                                max_bytes=cfg.max_feed_bytes, allow_private=allow_private)
    except (netguard.UnsafeURLError, netguard.FetchError) as exc:
        raise PostError(f"Could not reach the site: {exc}") from None
    if resp.status_code == 429:
        raise PostError("The site is rate-limiting requests right now - try again in a few minutes")
    if resp.status_code >= 400:
        raise PostError(f"The site answered HTTP {resp.status_code} (deleted or private post?)")
    return (parse_bytes(resp.content, resp.headers.get("content-type"), resp.url) or {}).get("entries") or []


def _first_feed_entry(url: str, allow_private: bool = False) -> dict:
    entries = _feed_entries(url, allow_private)
    if not entries:
        raise PostError("The post could not be read")
    return entries[0]


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+")
_TRAILING = ".,;:!?)]}"
PREVIEW_MAX = 2_000_000
_LEAD_IMG = re.compile(r"^\s*<p>\s*<img\b[^>]*>\s*</p>", re.I)


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


def plain_text(body: str | None) -> str:
    """Sanitised HTML → plain text that keeps its paragraphs and line breaks (``to_text`` runs them together)."""
    s = re.sub(r"(?i)<br\s*/?>", "\n", (body or "")[:MAX_HTML_LENGTH])
    s = re.sub(r"(?i)</(?:p|div|li|h[1-6]|blockquote|tr|pre)>", "\n\n", s)
    s = htmlmod.unescape(nh3.clean(s, tags=set()))
    lines = [re.sub(r"[ \t ]+", " ", line).strip() for line in s.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def search_text(body: str | None) -> str:
    """The text stored for search (one line, words kept apart where paragraphs meet)."""
    return re.sub(r"\s+", " ", plain_text(body)).strip()


def strip_lead_image(body: str | None) -> str:
    """The post's HTML without the picture the app put in front of it (cards show the picture on its own)."""
    return _LEAD_IMG.sub("", body or "", count=1)


def _on_platform(url, plat: str, link: str = "") -> bool:
    host = (urlsplit(url).hostname or "").lower() if isinstance(url, str) else ""
    domains = OWN_DOMAINS.get(plat) or ((urlsplit(link).hostname or "").lower(),)
    return bool(host) and any(host == d or host.endswith("." + d) for d in domains if d)


def safe_image(url, plat: str = "", link: str = "") -> str | None:
    """An https picture address on the post's own platform (its CDN), or None."""
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 2000:
        return None
    if plat and not _on_platform(url, plat, link):
        return None
    try:
        return netguard.normalize_url(url)
    except netguard.UnsafeURLError:
        return None


def _profile(url, plat: str, link: str = "") -> str | None:
    """The author's profile link, kept only when it is an https address on the same platform (the Follow button)."""
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 500 or not _on_platform(url, plat, link):
        return None
    p = urlsplit(url)
    host = "www.linkedin.com" if plat == "linkedin" else p.netloc  # ao.linkedin.com/in/x → www.linkedin.com/in/x
    try:
        return netguard.normalize_url(urlunsplit(("https", host, p.path.rstrip("/") or "/", "", "")))
    except netguard.UnsafeURLError:
        return None


def _meta(page: str, key: str) -> str:
    for pat in (rf'<meta[^>]+(?:property|name)="{re.escape(key)}"[^>]+content="([^"]*)"',
                rf'<meta[^>]+content="([^"]*)"[^>]+(?:property|name)="{re.escape(key)}"'):
        m = re.search(pat, page)
        if m:
            return htmlmod.unescape(m.group(1)).strip()
    return ""


def _ld_nodes(data, depth: int = 0):
    if depth > 4:
        return
    if isinstance(data, list):
        for item in data[:50]:
            yield from _ld_nodes(item, depth + 1)
    elif isinstance(data, dict):
        yield data
        if "@graph" in data:
            yield from _ld_nodes(data["@graph"], depth + 1)


def _ld_url(value) -> str:
    """schema.org fields hold a URL as a string, an object with "url", or a list of either."""
    if isinstance(value, list):
        value = value[0] if value else ""
    if isinstance(value, dict):
        value = value.get("url") or value.get("contentUrl") or ""
    return value if isinstance(value, str) else ""


def _ld_post(page: str) -> dict:
    """The first schema.org post object (SocialMediaPosting, DiscussionForumPosting, Article…) in the page's JSON-LD."""
    for m in re.finditer(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', page, re.S | re.I):
        try:
            data = json.loads(m.group(1).strip()[:1_000_000])
        except ValueError:
            continue
        for node in _ld_nodes(data):
            kinds = node.get("@type")
            kinds = kinds if isinstance(kinds, list) else [kinds]
            if any(isinstance(k, str) and k in LD_POST_TYPES for k in kinds):
                return node
    return {}


WALL_TITLE = re.compile(r"^(?:(?:sign ?up|sign ?in|log ?in|join)\b[^|]*\|\s*linkedin|linkedin:? log ?in or sign ?up|linkedin login.*"
                        r"|log ?in or sign ?up to view|login\s*•\s*instagram|instagram|facebook|log into facebook.*)$", re.I)
WALL_TEXT = ("Manage your professional identity", "Log in or sign up to view", "Create an account or log in to Instagram",
             "See posts, photos and more on Facebook")
WALL_PATHS = ("", "/", "/login", "/login/", "/signup", "/signup/", "/authwall", "/accounts/login/", "/uas/login")


def is_wall_text(text: str | None) -> bool:
    """Is this the generic text of a site's sign-in / sign-up page (LinkedIn's "500 million+ members | Manage your
    professional identity…") rather than a post?"""
    return any(w.lower() in (text or "").lower() for w in WALL_TEXT)


def login_wall(link: str, title: str, desc: str, og_url: str = "") -> bool:
    """The page a site shows instead of the post when it wants you to sign in (its link preview then describes the site,
    or points at its front / login page, not the post)."""
    if WALL_TITLE.match((title or "").strip()) or is_wall_text(desc):
        return True
    if og_url:
        page_path, post_path = urlsplit(og_url).path, urlsplit(link).path
        return page_path in WALL_PATHS and post_path not in WALL_PATHS
    return False


def public_preview(link: str) -> dict:
    """The preview a site shows anyone - what a link preview in a chat app shows: the schema.org JSON-LD (LinkedIn's has
    the whole post, author, profile link and date) and the Open Graph tags. A login wall (no data) simply gives {};
    nothing is ever done to get around it. -> {text, title, author, profile_url, avatar, image, published, full}"""
    cfg = get_settings()
    try:
        resp = netguard.request("GET", link, headers={"User-Agent": cfg.user_agent, "Accept": "text/html"},
                                timeout=cfg.fetch_timeout, max_bytes=PREVIEW_MAX)
    except (netguard.FetchError, netguard.UnsafeURLError):
        return {}
    if resp.status_code >= 400 or "html" not in (resp.headers.get("content-type") or ""):
        return {}
    page = resp.content.decode("utf-8", "replace")
    plat = platform_of(link)
    ld = _ld_post(page)
    body = ld.get("articleBody") or ld.get("text") if ld else ""
    body = body if isinstance(body, str) else ""
    author = ld.get("author") if ld else None
    author = (author[0] if author else {}) if isinstance(author, list) else author
    author = author if isinstance(author, dict) else {}
    title, desc = _meta(page, "og:title"), _meta(page, "og:description")
    image = safe_image(_ld_url(ld.get("image")) if ld else "", plat, link) or safe_image(_meta(page, "og:image"), plat, link)
    if not (body or title or desc):
        return {}
    if not body.strip() and login_wall(link, title, desc, _meta(page, "og:url")):
        return {}  # a sign-in / sign-up page instead of the post: there is no preview (the app never gets around it)
    og_author = title.rsplit(" | ", 1)[1].strip()[:200] if " | " in title else None  # "Post text… | Jane Doe"
    published = _iso(ld.get("datePublished")) if ld else None
    return {"image": image, "title": to_text(title, 500), "text": body.strip()[:MAX_TEXT] or to_text(desc),
            "author": to_text(author.get("name"), 200) or og_author, "profile_url": _profile(author.get("url"), plat, link),
            "avatar": safe_image(_ld_url(author.get("image")), plat, link), "published": published, "full": bool(body.strip())}


def _host(url: str) -> str:
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _clean_url(url: str) -> str:
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise PostError("Paste the post's full link (https://…)")
    query = ""
    if platform_of(urlunsplit((p.scheme, p.netloc, p.path, "", ""))) == "facebook":  # permalink.php?story_fbid=…&id=…
        query = urlencode([(k, v) for k, v in parse_qsl(p.query) if k in FB_ID_PARAMS])
    return urlunsplit((p.scheme, p.netloc, p.path, query, ""))  # drop tracking query strings


def _iso(value) -> int | None:
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return None


LI_POST = re.compile(r"^/(?:posts/|feed/update/|pulse/)")
LI_VANITY = re.compile(r"^/posts/([A-Za-z0-9-]{2,100})_")
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


LI_ACTIVITY = re.compile(r"(?:activity|ugcPost|share)(?::|%3A|-)(\d{10,25})", re.I)
FB_ID_PARAMS = ("story_fbid", "fbid", "v", "id")


def post_key(url: str) -> str | None:
    """One key per post, whatever its link looks like (x.com / twitter.com, a trailing slash, old.reddit.com, LinkedIn's
    /feed/update/urn:li:activity:N and /posts/name_…-activity-N-… forms, tracking parameters…): "x:2039805659525644595",
    "linkedin:7527177742136713216", "reddit:1abcde"… - used to refuse adding a post that is already in the tab. No network."""
    raw = (url or "").strip()
    if "://" not in raw and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:(?!\d)", raw):
        return None  # javascript:, mailto:, data: … - not a web link
    try:
        link = _clean_url(raw if "://" in raw else "https://" + raw)
    except PostError:
        return None
    parts = urlsplit(link)
    path, host, plat = parts.path or "/", _host(link), platform_of(link)
    if plat == "x" and (m := X_STATUS.match(path)):
        return f"x:{m.group(2)}"
    if plat == "linkedin" and (m := LI_ACTIVITY.search(path)):
        return f"linkedin:{m.group(1)}"
    if plat == "reddit" and (m := REDDIT_POST.match(path)):
        return f"reddit:{m.group(2)}"
    if plat == "bluesky" and (m := BSKY_POST.match(path)):
        return f"bluesky:{m.group(1).lower()}/{m.group(2)}"
    if plat == "threads" and (m := THREADS_POST.match(path)):
        return f"threads:{m.group(2)}"
    if plat == "tiktok" and (m := TIKTOK_VIDEO.match(path)):
        return f"tiktok:{m.group(2)}"
    if plat == "instagram" and (m := re.match(r"^/(?:p|reels?|tv)/([A-Za-z0-9_-]{4,})", path)):
        return f"instagram:{m.group(1)}"
    if plat == "mastodon" and (m := MASTO_STATUS.match(path)):
        return f"mastodon:{host}/{m.group(2)}"
    if plat == "facebook":  # permalink.php?story_fbid=…&id=… - the post is in the query string
        query = dict(parse_qsl(parts.query))
        ids = "&".join(f"{k}={query[k]}" for k in FB_ID_PARAMS if query.get(k))
        return f"facebook:{path.rstrip('/').lower()}" + (f"?{ids}" if ids else "")
    return f"url:{host}{path.rstrip('/') or '/'}"


def key_token(key: str) -> str:
    """The most distinctive part of a post key (the post's own id), for a quick LIKE search of stored links."""
    tail = key.split(":", 1)[1]
    return re.split(r"[/?=&]", tail)[-1] if not key.startswith(("url:", "facebook:")) else tail.rsplit("/", 1)[-1].split("?")[-1]


def contacts(url: str, rsshub: str | None = None, x_token: bool = False) -> list[str]:
    """The outside sites adding / refreshing this post will contact (shown before you add it)."""
    try:
        link = _clean_url(url if "://" in url else "https://" + url)
    except PostError:
        return []
    plat, host = platform_of(link), (urlsplit(link).hostname or "").lower()
    bridge = "your RSSHub bridge"
    return {
        "x": (["api.x.com (official X API)"] if x_token else []) + ["publish.twitter.com (X's public embed)"]
             + ([f"{bridge} (only if the embed shortens the post)"] if rsshub else []),
        "reddit": ["www.reddit.com"], "bluesky": ["public.api.bsky.app (Bluesky's public API)"],
        "mastodon": [f"{host} (the post's server)"], "tiktok": ["www.tiktok.com (TikTok's public embed)"],
        "threads": [bridge] if rsshub else [],
    }.get(plat, [f"{host} (its public link preview)"])


def _x_oembed(out: dict, data: dict, user: str) -> None:
    block = str(data.get("html") or "")
    para = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
    out["html"] = sanitize_html(f"<p>{para.group(1)}</p>") if para else ""
    out["text"] = plain_text(out["html"])
    out["author"] = to_text(data.get("author_name"), 200) or f"@{user}"
    who = re.match(r"^https://(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/?$", str(data.get("author_url") or ""))
    if who:  # the account's own spelling of its name
        out["handle"], out["profile_url"] = f"@{who.group(1)}", f"https://x.com/{who.group(1)}"
    date = re.findall(r">([A-Z][a-z]+ \d{1,2}, \d{4})</a>", block)
    if date:
        try:
            out["published"] = int(datetime.strptime(date[-1], "%B %d, %Y").timestamp())
        except ValueError:
            pass
    out["truncated"] = out["text"].rstrip().endswith(("…", "..."))  # the embed shortens long posts
    out["source"] = "oembed"


def _x_api(out: dict, status_id: str, token: str) -> None:
    """The official X API v2 (your bearer token): the whole text, the author and the first picture."""
    data = _get_json(f"https://api.x.com/2/tweets/{status_id}?tweet.fields=created_at,note_tweet,attachments"
                     "&expansions=author_id,attachments.media_keys&user.fields=username,name,profile_image_url"
                     "&media.fields=url,preview_image_url,type", headers={"Authorization": f"Bearer {token}"})
    tweet = data.get("data") if isinstance(data, dict) else None
    if not isinstance(tweet, dict):
        raise PostError("X did not return the post")
    text = ((tweet.get("note_tweet") or {}).get("text") or tweet.get("text") or "")[:MAX_TEXT]
    includes = data.get("includes") or {}
    user = ((includes.get("users") or [{}])[0]) or {}
    media = [m for m in (includes.get("media") or []) if isinstance(m, dict)]
    out["text"], out["html"] = text, para_html(text)
    if isinstance(user.get("username"), str) and re.fullmatch(r"[A-Za-z0-9_]{1,15}", user["username"]):
        out["handle"], out["profile_url"] = f"@{user['username']}", f"https://x.com/{user['username']}"
    out["author"] = to_text(user.get("name"), 200) or out["handle"]
    out["avatar"] = safe_image(user.get("profile_image_url"), "x")
    out["image"] = next((safe_image(m.get("url") or m.get("preview_image_url"), "x") for m in media
                         if safe_image(m.get("url") or m.get("preview_image_url"), "x")), None)
    out["published"] = _iso(tweet.get("created_at"))
    out["truncated"], out["source"] = False, "api"


def _x_bridge(out: dict, rsshub: str, user: str, status_id: str) -> None:
    """Your own RSSHub bridge's single-post route, for a post the public embed shortened."""
    entry = _first_feed_entry(f"{rsshub.rstrip('/')}/twitter/tweet/{quote(user)}/status/{quote(status_id)}", allow_private=True)
    body = sanitize_html(entry.get("summary") or (entry.get("content") or [{}])[0].get("value") or "")
    text = plain_text(body)
    if len(text) > len(out["text"]):
        img = re.search(r'<img[^>]+src="([^"]+)"', body)
        out["html"], out["text"], out["truncated"], out["source"] = _LEAD_IMG.sub("", body), text, False, "bridge"
        out["image"] = out["image"] or (safe_image(htmlmod.unescape(img.group(1)), "x") if img else None)


def _bsky_image(embed) -> str | None:
    if not isinstance(embed, dict):
        return None
    for img in embed.get("images") or []:
        if isinstance(img, dict) and (src := safe_image(img.get("fullsize") or img.get("thumb"), "bluesky")):
            return src
    if isinstance(embed.get("thumbnail"), str):  # a video
        return safe_image(embed["thumbnail"], "bluesky")
    if isinstance(embed.get("external"), dict):
        return safe_image(embed["external"].get("thumb"), "bluesky")
    return _bsky_image(embed.get("media"))  # recordWithMedia


def fetch(url: str, pasted: str | None = None, rsshub: str | None = None, x_token: str | None = None) -> dict:
    """-> {platform, link, title, text (plain), html, author, handle, profile_url, avatar, image, published, dated,
    truncated, source}. Pasted text is used when given, and is the way in for sites that don't let apps read posts."""
    link = _clean_url(url)
    plat = platform_of(link)
    path = urlsplit(link).path
    pasted = (pasted or "").strip()[:MAX_TEXT]
    out = {"platform": plat, "link": link, "title": "", "text": "", "html": "", "author": None, "handle": None,
           "profile_url": None, "avatar": None, "image": None, "published": None, "truncated": False, "source": ""}
    try:
        if plat == "x" and (m := X_STATUS.match(path)):
            out["handle"], out["profile_url"] = f"@{m.group(1)}", f"https://x.com/{m.group(1)}"
            done = False
            if x_token:
                try:
                    _x_api(out, m.group(2), x_token)
                    done = True
                except PostError:
                    pass  # plan limits / rate limit: the public embed still works
            if not done:
                _x_oembed(out, _get_json(f"https://publish.twitter.com/oembed?omit_script=1&dnt=true&url={quote(link, safe='')}"),
                          m.group(1))
                if out["truncated"] and rsshub:
                    try:
                        _x_bridge(out, rsshub, out["handle"][1:], m.group(2))
                    except PostError:
                        pass  # bridge down / no X login on it: stays marked as shortened
        elif plat == "reddit" and REDDIT_POST.match(path):
            try:
                data = _get_json(link.rstrip("/") + "/.json?raw_json=1")
                post = data[0]["data"]["children"][0]["data"] if isinstance(data, list) else {}
                out["title"] = to_text(post.get("title"), 500)
                out["text"] = str(post.get("selftext") or "")[:MAX_TEXT]
                if post.get("author") and re.fullmatch(r"[A-Za-z0-9_-]{3,20}", str(post["author"])):
                    out["author"] = out["handle"] = f"u/{post['author']}"
                    out["profile_url"] = f"https://www.reddit.com/user/{post['author']}"
                out["published"] = int(post["created_utc"]) if post.get("created_utc") else None
                images = ((post.get("preview") or {}).get("images") or [{}])[0].get("source") or {}
                out["image"] = safe_image(images.get("url"), "reddit") or safe_image(post.get("url_overridden_by_dest"), "reddit")
                out["source"] = "public"
            except PostError:  # Reddit often refuses its JSON to apps; the post's RSS (first entry = the post) still works
                entry = _first_feed_entry(link.rstrip("/") + "/.rss")
                out["title"] = to_text(entry.get("title"), 500)
                out["html"] = sanitize_html((entry.get("content") or [{}])[0].get("value") or entry.get("summary") or "")
                out["text"] = plain_text(out["html"])
                out["author"] = to_text(entry.get("author"), 200) or None
                out["source"] = "public"
        elif plat == "bluesky" and (m := BSKY_POST.match(path)):
            uri = f"at://{m.group(1)}/app.bsky.feed.post/{m.group(2)}"
            data = _get_json(f"https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?depth=0&uri={quote(uri, safe='')}")
            post = (data.get("thread") or {}).get("post") or {}
            out["text"] = str(((post.get("record") or {}).get("text")) or "")[:MAX_TEXT]
            author = post.get("author") or {}
            handle = author.get("handle") if isinstance(author.get("handle"), str) else m.group(1)
            out["author"] = to_text(author.get("displayName") or handle, 200) or m.group(1)
            if re.fullmatch(r"[A-Za-z0-9.:-]{3,253}", handle or ""):
                out["handle"], out["profile_url"] = f"@{handle}", f"https://bsky.app/profile/{handle}"
            out["avatar"] = safe_image(author.get("avatar"), "bluesky")
            out["image"] = _bsky_image(post.get("embed"))
            out["published"] = _iso((post.get("record") or {}).get("createdAt"))
            out["source"] = "public"
        elif plat == "mastodon" and (m := MASTO_STATUS.match(path)):
            data = _get_json(f"https://{urlsplit(link).netloc}/api/v1/statuses/{m.group(2)}")
            out["html"] = sanitize_html(str(data.get("content") or ""))
            out["text"] = plain_text(out["html"])
            account = data.get("account") or {}
            out["handle"] = f"@{account.get('acct') or m.group(1)}"
            out["author"] = to_text(account.get("display_name"), 200) or out["handle"]
            out["profile_url"] = _profile(account.get("url"), "mastodon", link)
            out["avatar"] = safe_image(account.get("avatar"), "mastodon", link)
            for media in data.get("media_attachments") or []:
                if isinstance(media, dict) and (src := safe_image(media.get("preview_url"), "mastodon", link)):
                    out["image"] = src
                    break
            out["published"] = _iso(data.get("created_at"))
            out["source"] = "public"
        elif plat == "tiktok" and (m := TIKTOK_VIDEO.match(path)):
            data = _get_json(f"https://www.tiktok.com/oembed?url={quote(link, safe='')}")
            out["text"] = to_text(data.get("title") or "")
            out["author"] = to_text(data.get("author_name"), 200) or f"@{m.group(1)}"
            out["handle"], out["profile_url"] = f"@{m.group(1)}", f"https://www.tiktok.com/@{m.group(1)}"
            out["image"] = safe_image(data.get("thumbnail_url"), "tiktok")
            out["source"] = "oembed"
            if not out["text"] and rsshub:  # the embed sometimes omits the caption: find the video in the bridge's feed
                for e in _feed_entries(f"{rsshub.rstrip('/')}/tiktok/user/@{quote(m.group(1))}", allow_private=True):
                    if m.group(2) in str(e.get("link") or ""):
                        out["html"] = sanitize_html(e.get("summary") or "")
                        out["text"] = to_text(e.get("title") or out["html"])
                        break
        elif plat == "threads" and (m := THREADS_POST.match(path)):
            out["handle"], out["profile_url"] = f"@{m.group(1)}", f"https://www.threads.net/@{m.group(1)}"
            out["author"] = out["handle"]
            if rsshub:
                entry = _first_feed_entry(f"{rsshub.rstrip('/')}/threads/{quote(m.group(1))}/post/{quote(m.group(2))}",
                                          allow_private=True)
                out["html"] = sanitize_html(entry.get("summary") or "")
                out["text"] = plain_text(out["html"])
                out["source"] = "bridge"
    except PostError:
        if not pasted:
            raise
    if plat in (*PASTE_ONLY.values(), "other"):  # LinkedIn, Instagram, Facebook...: the page's public preview data
        preview = public_preview(link)
        for key in ("image", "author", "profile_url", "avatar", "published"):
            out[key] = out[key] or preview.get(key)
        if plat == "linkedin" and not out["profile_url"] and (v := LI_VANITY.match(path)):
            out["profile_url"] = f"https://www.linkedin.com/in/{v.group(1)}"  # /posts/<their name>_… links
        if plat == "linkedin" and not out["published"]:
            out["published"] = linkedin_posted_at(link)  # the post's own number carries its date
        if preview.get("text"):
            out["text"] = preview["text"]
            out["source"] = "jsonld" if preview.get("full") else "og"
            # Open Graph only carries the opening of a post: say so (paste the text for all of it)
            out["truncated"] = not preview.get("full") and (preview["text"].rstrip().endswith(("…", "...")) or len(preview["text"]) >= 140)
    if plat == "linkedin" and out["profile_url"]:
        lp = urlsplit(out["profile_url"]).path.strip("/")
        out["handle"] = out["handle"] or (lp if re.fullmatch(r"(?:in|company)/[A-Za-z0-9-]{2,100}", lp) else None)
    if pasted:  # your copy of the post wins (and is the only way to get all of some LinkedIn / Instagram / Facebook posts)
        out["text"], out["html"], out["truncated"], out["source"] = pasted, "", False, "pasted"
    if not out["text"].strip() and not out["title"]:
        names = {"linkedin": "LinkedIn", "instagram": "Instagram", "facebook": "Facebook", "threads": "Threads", "other": "This site"}
        raise PostError(f"{names.get(plat, 'This site')} doesn't let apps read this post without logging in, and the app never "
                        "gets around that. Copy the post's text into the box below the link and add it again.")
    if not out["html"]:
        out["html"] = para_html(out["text"])
    out["html"] = sanitize_html(out["html"])
    out["text"] = plain_text(out["html"]) or to_text(out["text"])
    out["author"] = out["author"] or out["handle"]
    if out["image"] and "<img" not in out["html"]:  # the Articles reader shows the picture above the text
        out["html"] = sanitize_html(f'<p><img src="{htmlmod.escape(out["image"], quote=True)}" alt=""></p>' + out["html"])
    if not out["title"]:
        first = out["text"].strip().split("\n")[0]
        out["title"] = first if len(first) <= 140 else first[:137].rstrip() + "…"
    out["dated"] = out["published"] is not None
    out["published"] = out["published"] or int(time.time())
    return out


# ============================================================================ stored posts (Accounts tab)
def save_meta(db, article_id: int, post: dict) -> None:
    from app.db import now
    db.execute(
        "INSERT INTO social_post_meta (article_id, handle, profile_url, avatar_url, image_url, source, truncated, fetched_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(article_id) DO UPDATE SET handle = excluded.handle, "
        "profile_url = excluded.profile_url, avatar_url = excluded.avatar_url, image_url = excluded.image_url, "
        "source = excluded.source, truncated = excluded.truncated, fetched_at = excluded.fetched_at",
        (article_id, (post.get("handle") or None) and str(post["handle"])[:200], post.get("profile_url"), post.get("avatar"),
         post.get("image"), str(post.get("source") or "")[:20], 1 if post.get("truncated") else 0, now()))


def _saved_row(db, article_id: int):
    return db.execute(
        "SELECT a.id, a.url, a.content_html, f.social_platform, m.source AS meta_source, m.image_url FROM articles a "
        "JOIN feeds f ON f.id = a.feed_id LEFT JOIN social_post_meta m ON m.article_id = a.id "
        "WHERE a.id = ? AND f.url LIKE ?", (article_id, SAVED_FEED_PREFIX + "%")).fetchone()


def _write(db, article_id: int, post: dict, body: str) -> None:
    """Store a post's text + picture back on its article (search index and topics follow)."""
    from app import topics
    body = sanitize_html(body)
    if post.get("image") and "<img" not in body:
        body = sanitize_html(f'<p><img src="{htmlmod.escape(post["image"], quote=True)}" alt=""></p>' + body)
    text = plain_text(body)
    first = text.split("\n")[0] if text else (post.get("title") or "")
    title = first if len(first) <= 140 else first[:137].rstrip() + "…"
    sets, params = ["title = ?", "author = ?", "content_html = ?", "text_content = ?"], [title[:1000] or "(untitled)", post.get("author"), body,
                                                                                   search_text(body)]
    if post.get("dated"):
        sets += ["published = ?", "sort_ts = ?"]
        params += [post["published"], post["published"]]
    db.execute(f"UPDATE articles SET {', '.join(sets)} WHERE id = ?", [*params, article_id])  # nosec B608 - fixed fragments
    db.execute("DELETE FROM article_topics WHERE article_id = ? AND source = 'keyword'", (article_id,))
    topics.classify(db, [article_id])
    save_meta(db, article_id, post)


def refresh_saved(article_id: int, rsshub: str | None = None, x_token: str | None = None) -> dict:
    """Read a saved post again from its platform. Text you pasted is kept (and so is a longer copy than the platform now
    hands over); author, handle, picture and date are updated. Raises PostError / LookupError."""
    from app.db import get_db
    with get_db() as db:
        row = _saved_row(db, article_id)
    if row is None:
        raise LookupError("Post")
    post = fetch(row["url"], None, rsshub, x_token)
    old_body = strip_lead_image(row["content_html"])
    old_text = plain_text(old_body)
    keep_old = row["meta_source"] == "pasted" or (row["meta_source"] is None and len(old_text) > len(post["text"]) + 20)
    if keep_old:  # older saves had no record of a paste: a longer stored copy is taken to be your pasted text
        post["truncated"], post["source"] = False, "pasted"
    with get_db() as db:
        _write(db, article_id, post, old_body if keep_old else strip_lead_image(post["html"]))
    return post


def set_text(article_id: int, text: str) -> None:
    """Your pasted copy of a saved post replaces what the platform handed over (author, picture and link stay)."""
    from app.db import get_db
    text = (text or "").strip()[:MAX_TEXT]
    if not text:
        raise PostError("Paste the post's text")
    with get_db() as db:
        row = _saved_row(db, article_id)
        if row is None:
            raise LookupError("Post")
        meta = db.execute("SELECT * FROM social_post_meta WHERE article_id = ?", (article_id,)).fetchone()
        author = db.execute("SELECT author FROM articles WHERE id = ?", (article_id,)).fetchone()["author"]
        post = {"author": author, "image": row["image_url"], "source": "pasted", "truncated": False,
                "handle": meta["handle"] if meta else None, "profile_url": meta["profile_url"] if meta else None,
                "avatar": meta["avatar_url"] if meta else None}
        _write(db, article_id, post, para_html(text))


def mark_unavailable(article_id: int) -> None:
    """The platform showed its sign-in page instead of this saved post: drop that page's text, "author" and logo and mark
    the post so its card asks for the post's text (✎ Paste) - the link stays, so ↻ can try again later."""
    from app.db import get_db
    with get_db() as db:
        row = _saved_row(db, article_id)
        if row is None:
            return
        name = {"linkedin": "LinkedIn", "instagram": "Instagram", "facebook": "Facebook", "x": "X"}.get(row["social_platform"] or "", "Saved")
        db.execute("UPDATE articles SET title = ?, author = NULL, content_html = '', text_content = '' WHERE id = ?",
                   (f"{name} post - its text wasn't handed over", article_id))
        posted = linkedin_posted_at(row["url"] or "")
        if posted:  # at least the day it was posted (from its number), not the day it was saved
            db.execute("UPDATE articles SET published = ?, sort_ts = ? WHERE id = ?", (posted, posted, article_id))
        db.execute("DELETE FROM article_topics WHERE article_id = ? AND source = 'keyword'", (article_id,))
        save_meta(db, article_id, {"source": "unavailable"})


def linkedin_posted_at(url: str) -> int | None:
    """When a LinkedIn post was made, from its own number: activity / share / ugcPost ids are time-ordered ids whose top bits
    are the creation time in milliseconds (id >> 22). Public in the link itself - no request. None if it doesn't look right."""
    if platform_of(url) != "linkedin" or not (m := LI_ACTIVITY.search(urlsplit(url).path)):
        return None
    ts = (int(m.group(1)) >> 22) // 1000
    return ts if 1262304000 <= ts <= int(time.time()) + 86400 else None  # 2010 … tomorrow


def repair_login_walls(rsshub: str | None = None, x_token: str | None = None) -> tuple[int, int]:
    """Saved posts that stored a sign-in page's text (before sign-in pages were recognised): read each once more - fixed if
    the platform now shows the post - otherwise mark it for pasting. -> (fixed, marked). Safe to run on every start."""
    from app.db import get_db
    with get_db() as db:
        rows = [r["id"] for r in db.execute(
            "SELECT a.id, a.text_content FROM articles a JOIN feeds f ON f.id = a.feed_id LEFT JOIN social_post_meta m ON m.article_id = a.id "
            "WHERE f.url LIKE ? AND COALESCE(m.source, '') NOT IN ('pasted', 'unavailable')", (SAVED_FEED_PREFIX + "%",))
            if is_wall_text(r["text_content"])]
    fixed = marked = 0
    for article_id in rows:
        try:
            post = refresh_saved(article_id, rsshub, x_token)
            if is_wall_text(post.get("text")):
                raise PostError("still the sign-in page")
            fixed += 1
        except PostError as exc:
            if str(exc).startswith(("Could not reach", "The site is rate-limiting")):
                continue  # offline: try again next start
            mark_unavailable(article_id)
            marked += 1
        except LookupError:
            continue
    with get_db() as db:  # posts already waiting for their text: show the day they were posted, not the day they were saved
        for r in db.execute("SELECT a.id, a.url, a.published FROM articles a JOIN social_post_meta m ON m.article_id = a.id "
                            "WHERE m.source = 'unavailable'").fetchall():
            posted = linkedin_posted_at(r["url"] or "")
            if posted and r["published"] != posted:
                db.execute("UPDATE articles SET published = ?, sort_ts = ? WHERE id = ?", (posted, posted, r["id"]))
    return fixed, marked
