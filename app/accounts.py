"""Social accounts: recognise a profile link and work out how to follow it - honestly.

* X and Telegram use the existing sources (X: your bridge or the official API; Telegram: public preview or account).
* Bluesky, Mastodon (and other fediverse servers) and Reddit publish real RSS feeds for profiles - used directly.
* LinkedIn, Instagram, Facebook, Threads and TikTok publish no feeds and forbid scraping. They can only be followed
  through a feed bridge you run (RSSHub, RSS-Bridge...): paste the bridge's feed URL for the profile and pick the
  platform. The app never scrapes these sites itself.
"""

from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

PLATFORMS = {
    "x": "X", "telegram": "Telegram", "bluesky": "Bluesky", "mastodon": "Mastodon", "reddit": "Reddit",
    "linkedin": "LinkedIn", "instagram": "Instagram", "facebook": "Facebook", "threads": "Threads", "tiktok": "TikTok",
    "other": "Other",
}
ICONS = {"x": "𝕏", "telegram": "✈", "bluesky": "🦋", "mastodon": "🐘", "reddit": "👽", "linkedin": "in", "instagram": "📷",
         "facebook": "f", "threads": "@", "tiktok": "♪", "other": "◎"}
BRIDGE_ONLY = {
    "linkedin": ("linkedin.com",), "instagram": ("instagram.com",), "facebook": ("facebook.com", "fb.com"),
    "threads": ("threads.net", "threads.com"), "tiktok": ("tiktok.com",),
}
BSKY = re.compile(r"^(?:www\.)?bsky\.app/profile/([A-Za-z0-9.:-]{3,253})/?$")
MASTO_URL = re.compile(r"^([a-z0-9.-]+\.[a-z]{2,})/@([A-Za-z0-9_]{1,30})/?$")
MASTO_HANDLE = re.compile(r"^@?([A-Za-z0-9_]{1,30})@([a-z0-9.-]+\.[a-z]{2,})$")
REDDIT_USER = re.compile(r"^(?:www\.|old\.)?reddit\.com/(?:user|u)/([A-Za-z0-9_-]{3,20})/?")
REDDIT_SUB = re.compile(r"^(?:www\.|old\.)?reddit\.com/r/([A-Za-z0-9_]{2,21})/?")
NOT_MASTODON = ("youtube.com", "medium.com", "tiktok.com", "threads.net", "threads.com", "x.com", "twitter.com")


class AccountError(ValueError):
    pass


# Profiles followed through your RSSHub bridge (the same feeds Folo uses). What each route needs on the RSSHub side:
# X needs TWITTER_AUTH_TOKEN; Instagram works for public profiles (INSTAGRAM_COOKIE for more); Facebook needs
# FACEBOOK_COOKIE; LinkedIn company pages need the RSSHub image with a browser (chromium-bundled). LinkedIn has no feed
# for personal profiles anywhere - add their posts one by one instead.
IG_USER = re.compile(r"^/([A-Za-z0-9._]{1,30})/?$")
THREADS_USER = re.compile(r"^/@([A-Za-z0-9._]{1,40})/?$")
TIKTOK_USER = re.compile(r"^/@([A-Za-z0-9._]{1,40})/?$")
FB_PAGE = re.compile(r"^/([A-Za-z0-9.\-]{2,80})/?$")
LI_COMPANY = re.compile(r"^/company/([A-Za-z0-9-]{2,100})/?")
LI_PERSON = re.compile(r"^/in/([A-Za-z0-9-]{2,100})/?")
NEEDS = {"instagram": "Instagram works for public profiles (private ones need INSTAGRAM_COOKIE in the bridge).",
         "facebook": "Facebook pages need FACEBOOK_COOKIE (from a spare account) in the RSSHub bridge.",
         "linkedin": "LinkedIn company pages need the RSSHub image with a browser (chromium-bundled)."}


def bridge_route(platform: str, path: str, query: str, base: str) -> str | None:
    base = base.rstrip("/")
    if platform == "instagram" and (m := IG_USER.match(path)) and m.group(1) not in ("p", "reel", "explore", "stories"):
        return f"{base}/instagram/user/{m.group(1)}"
    if platform == "threads" and (m := THREADS_USER.match(path)):
        return f"{base}/threads/{m.group(1)}"
    if platform == "tiktok" and (m := TIKTOK_USER.match(path)):
        return f"{base}/tiktok/user/@{m.group(1)}"
    if platform == "facebook":
        pid = re.search(r"(?:^|&)id=(\d{3,25})", query)
        if path.startswith("/profile.php") and pid:
            return f"{base}/facebook/page/{pid.group(1)}"
        if (m := FB_PAGE.match(path)) and m.group(1) not in ("groups", "watch", "events", "share"):
            return f"{base}/facebook/page/{m.group(1)}"
    if platform == "linkedin" and (m := LI_COMPANY.match(path)):
        return f"{base}/linkedin/company/{m.group(1)}/posts"
    return None


def detect(text: str, platform: str | None = None, rsshub: str | None = None) -> dict:
    """-> {"platform", "via": "x"|"telegram"|"rss", "feed_url"?, "handle"}. Raises AccountError with advice."""
    raw = text.strip()
    bare = re.sub(r"^https?://", "", raw, flags=re.I)
    host = bare.split("/")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    if host in ("x.com", "twitter.com", "mobile.twitter.com") or (platform == "x" and not bare.startswith(("http", "www"))):
        return {"platform": "x", "via": "x", "handle": raw}
    if host in ("youtube.com", "m.youtube.com", "youtu.be"):
        raise AccountError("YouTube channels and videos go in the 📺 Videos tab (+ Add channels or video).")
    if host in ("t.me", "telegram.me"):
        return {"platform": "telegram", "via": "telegram", "handle": raw}
    m = BSKY.match(bare)
    if m:
        handle = m.group(1)
        return {"platform": "bluesky", "via": "rss", "handle": handle,
                "feed_url": f"https://bsky.app/profile/{quote(handle, safe='.:-')}/rss"}
    m = MASTO_HANDLE.match(raw)
    if m:
        return {"platform": "mastodon", "via": "rss", "handle": f"@{m.group(1)}@{m.group(2)}",
                "feed_url": f"https://{m.group(2)}/@{m.group(1)}.rss"}
    m = REDDIT_USER.match(bare)
    if m:
        return {"platform": "reddit", "via": "rss", "handle": f"u/{m.group(1)}",
                "feed_url": f"https://www.reddit.com/user/{m.group(1)}/submitted/.rss"}
    m = REDDIT_SUB.match(bare)
    if m:
        # the subreddit's newest posts (not "hot"), so every new post arrives as it is submitted
        return {"platform": "reddit", "via": "rss", "handle": f"r/{m.group(1)}", "feed_url": f"https://www.reddit.com/r/{m.group(1)}/new/.rss?limit=100",
                "refresh_minutes": 30}
    for name, hosts in BRIDGE_ONLY.items():
        if any(host == h or host.endswith("." + h) for h in hosts):
            parts0 = urlsplit(raw if "://" in raw else "https://" + raw)
            if name == "linkedin" and LI_PERSON.match(parts0.path):
                raise AccountError(
                    "LinkedIn offers no feed for personal profiles - not to this app, RSSHub or Folo. Follow their company "
                    "page instead (linkedin.com/company/…), or add their posts one by one with “＋ Add post”.")
            if rsshub:
                route = bridge_route(name, parts0.path, parts0.query, rsshub)
                if route:
                    return {"platform": name, "via": "rss", "handle": raw, "feed_url": route, "note": NEEDS.get(name)}
                raise AccountError(f"Paste the {PLATFORMS[name]} profile link itself (for example "
                                   f"{'linkedin.com/company/name' if name == 'linkedin' else name + '.com/name'}).")
            raise AccountError(
                f"{PLATFORMS[name]} publishes no feeds, so it is followed through an RSSHub bridge you run (the way Folo "
                "does it). Set one up in Settings → Integrations → X (Bridge: RSSHub) and add the profile link again - or "
                f"paste a bridge feed address and choose “{PLATFORMS[name]}” as the platform.")
    first = bare.split("?")[0]
    m = MASTO_URL.match(host + first[len(first.split("/")[0]):])  # host lower-cased, username as typed
    if m and platform in (None, "mastodon") and not any(host == h or host.endswith("." + h) for h in NOT_MASTODON):
        return {"platform": "mastodon", "via": "rss", "handle": f"@{m.group(2)}@{m.group(1)}",
                "feed_url": f"https://{m.group(1)}/@{m.group(2)}.rss"}
    parts = urlsplit(raw if "://" in raw else "")
    if parts.scheme in ("http", "https") and parts.netloc:
        # A feed URL (e.g. from a bridge): followed as is, labelled with the chosen platform.
        return {"platform": platform if platform in PLATFORMS else "other", "via": "rss", "handle": raw, "feed_url": raw}
    raise AccountError("Paste a profile link (x.com, t.me, bsky.app, a Mastodon profile, reddit.com/user or /r/...) "
                       "or a feed address from a bridge.")
