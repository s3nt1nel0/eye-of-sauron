"""🎙 → ▶ Each podcast episode's own YouTube video.

1. Find the show's YouTube channel / playlist (once, again after 30 days if none was found): YouTube links on the
   show's website and in its feed's show header (not episode notes - those link guests), else a show already
   followed in Videos with the same name, else one YouTube channel search (100 quota units) accepted only on a close
   name match. The user can set or clear it by hand (Shows → ▶ YouTube…).
2. List those channels' / playlists' videos (titles + dates only: 1 quota unit per 50 videos) - in full once, then
   just the newest page(s) daily.
3. Match episodes to videos: same title, else the same episode number within 14 days, else most title words in
   common within 3 days. Stored in ``episode_youtube``; the episode's ▶ YouTube opens that video.
"""
from __future__ import annotations

import bisect
import json
import logging
import re
import threading
from urllib.parse import urlsplit

from app import netguard, sources
from app.config import get_settings
from app.db import get_db, now
from app.sanitize import to_text

log = logging.getLogger(__name__)

DETECT_AGAIN = 30 * 86400        # no channel found: look again after 30 days
LIST_EVERY = 86400               # new videos: daily
MAX_SOURCES = 3
MAX_PAGES_FIRST = 100            # 5,000 videos per channel / playlist on the first read
MAX_PAGES_DAILY = 4
PAGE_LIMIT = 3_000_000
_lock = threading.Lock()

_YT_LINK = re.compile(r'https?://(?:www\.|m\.)?youtube\.com/(@[A-Za-z0-9._-]{3,100}|channel/UC[A-Za-z0-9_-]{22}|'
                      r'user/[A-Za-z0-9._-]{2,100}|c/[A-Za-z0-9._-]{2,100}|playlist\?list=(?:PL|UU)[A-Za-z0-9_-]{10,60})')
_EP_NUM = re.compile(r"(?<![A-Za-z0-9])(?:ep(?:isode)?\.?\s*|#|no\.\s*)(\d{1,5})\b|^\s*(\d{1,5})\s*[:.\-–|]", re.I)
_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "are", "how", "what", "why",
         "episode", "ep", "podcast", "audio", "video", "full", "part", "feat", "ft", "w", "s"}


# ---------------------------------------------------------------- text helpers
def norm_title(text: str | None) -> str:
    """Case, punctuation and an "Ep 12:" / "#593:" number prefix ignored."""
    t = re.sub(r"^\s*(?:ep(?:isode)?\.?\s*)?#?\d{1,5}\s*[:.\-–|]\s*", "", (text or "").lower())
    return " ".join(_WORD.findall(t))


def ep_number(text: str | None) -> int | None:
    m = _EP_NUM.search(text or "")
    return int(m.group(1) or m.group(2)) if m else None


def words(text: str | None) -> set[str]:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOP and len(w) > 1}


def _bare(name: str | None) -> str:
    """A show / channel name without "podcast", "audio", "the" and punctuation."""
    return " ".join(w for w in norm_title(name).split() if w not in ("podcast", "audio", "the", "show"))


def name_close(a: str | None, b: str | None) -> bool:
    """Show name vs channel / playlist title: one contains the other, or most words shared."""
    na, nb = norm_title(a).replace(" podcast", "").replace(" audio", "").strip(), norm_title(b).replace(" podcast", "").strip()
    if len(na) < 4 or len(nb) < 4:   # "LOW": too short to trust a match
        return False
    if na in nb or nb in na:
        return True
    wa, wb = words(na), words(nb)
    return bool(wa and wb) and len(wa & wb) / min(len(wa), len(wb)) >= 0.75


# ---------------------------------------------------------------- 1. find the show's channel / playlist
def _page(url: str | None) -> str:
    if not url or not url.startswith(("https://", "http://")):
        return ""
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": get_settings().user_agent, "Accept": "text/html,application/xml"},
                                timeout=get_settings().fetch_timeout, max_bytes=PAGE_LIMIT)
    except (netguard.UnsafeURLError, netguard.FetchError):
        return ""
    return resp.content.decode("utf-8", "replace") if resp.status_code < 400 else ""


def _refs(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in _YT_LINK.finditer(text):
        seen.setdefault(m.group(1), None)
    return list(seen)


def _resolve_ref(ref: str, key: str) -> dict | None:
    """'@handle' / 'channel/UC…' / 'user/x' / 'c/x' / 'playlist?list=…' → {"kind", "id", "title"} (1 unit each)."""
    if ref.startswith("playlist?list="):
        pid = ref.split("=", 1)[1]
        items = sources.yt_api("playlists", {"part": "snippet", "id": pid}, key).get("items") or []
        return {"kind": "playlist", "id": pid, "title": to_text((items[0].get("snippet") or {}).get("title"), 200)} if items else None
    params = {"part": "snippet"}
    if ref.startswith("channel/"):
        params["id"] = ref.split("/", 1)[1]
    elif ref.startswith("@"):
        params["forHandle"] = ref
    elif ref.startswith("user/"):
        params["forUsername"] = ref.split("/", 1)[1]
    else:  # c/custom: no API lookup - read the public page like adding a channel does
        try:
            got = sources.resolve_youtube(f"https://www.youtube.com/{ref}")
        except sources.SourceError:
            return None
        cid = got["source"].get("channel_id")
        return {"kind": "channel", "id": cid, "title": got.get("title") or ref} if cid else None
    items = sources.yt_api("channels", params, key).get("items") or []
    if not items or not re.match(r"^UC[A-Za-z0-9_-]{22}$", str(items[0].get("id"))):
        return None
    return {"kind": "channel", "id": items[0]["id"], "title": to_text((items[0].get("snippet") or {}).get("title"), 200)}


def _feed_header(feed_url: str | None) -> str:
    """The show's part of its feed (before the first episode): links there are the show's own."""
    text = _page(feed_url)
    cut = re.search(r"<item[\s>]|<entry[\s>]", text)
    return text[:cut.start()] if cut else text[:20000]


def detect(db_feed: dict, key: str) -> tuple[list[dict], str]:
    """The show's channel(s) / playlist(s) and how they were found."""
    title, site, feed_url = db_feed["title"], db_feed["site_url"], db_feed["url"]
    found: list[dict] = []
    for how, text in (("site", _page(site)), ("feed", _feed_header(feed_url))):
        for ref in _refs(text)[:6]:
            src = _resolve_ref(ref, key)
            if src and all(s["id"] != src["id"] for s in found):
                found.append(src)
        if found:
            # several links (a company site): keep the ones named like the show, else the first two
            close = [s for s in found if name_close(title, s["title"])]
            return (close or found[:2])[:MAX_SOURCES], how
    with get_db() as db:  # a channel already followed in Videos with the show's name
        for r in db.execute("SELECT DISTINCT channel_id, channel_title FROM videos WHERE channel_id LIKE 'UC%' AND channel_title IS NOT NULL"):
            if name_close(title, r["channel_title"]) and norm_title(r["channel_title"]) and len(norm_title(r["channel_title"])) >= 5:
                return [{"kind": "channel", "id": r["channel_id"], "title": r["channel_title"]}], "videos"
    items = sources.yt_api("search", {"part": "snippet", "type": "channel", "maxResults": "5", "q": title[:100]}, key).get("items") or []
    for it in items:
        cid = (it.get("id") or {}).get("channelId") or (it.get("snippet") or {}).get("channelId")
        name = (it.get("snippet") or {}).get("title") or (it.get("snippet") or {}).get("channelTitle")
        # a search hit must carry the show's very name ("Click Here" ≠ "Just Click Here")
        if isinstance(cid, str) and re.match(r"^UC[A-Za-z0-9_-]{22}$", cid) and _bare(title) == _bare(name):
            return [{"kind": "channel", "id": cid, "title": to_text(name, 200)}], "search"
    return [], "none"


# ---------------------------------------------------------------- 2. list their videos
def _list_source(db, feed_id: int, src: dict, key: str, first: bool) -> int:
    playlist = src["id"] if src["kind"] == "playlist" else "UU" + src["id"][2:]
    known = {r[0] for r in db.execute("SELECT video_id FROM podcast_youtube_videos WHERE feed_id = ?", (feed_id,))}
    token, added = "", 0
    for _ in range(MAX_PAGES_FIRST if first else MAX_PAGES_DAILY):
        params = {"part": "snippet,contentDetails", "playlistId": playlist, "maxResults": "50"}
        if token:
            params["pageToken"] = token
        try:
            data = sources.yt_api("playlistItems", params, key)
        except sources.SourceError as exc:
            if "quota" in str(exc).lower():
                raise
            log.info("YouTube list %s for show %d: %s", playlist, feed_id, exc)
            break
        rows, new_on_page = [], 0
        for item in data.get("items") or []:
            sn = item.get("snippet") if isinstance(item, dict) and isinstance(item.get("snippet"), dict) else {}
            vid = (item.get("contentDetails") or {}).get("videoId") if isinstance(item, dict) else None
            title = to_text(sn.get("title"), 500)
            if not isinstance(vid, str) or not sources.VIDEO_ID.match(vid) or not title or title in sources.PLACEHOLDER_TITLES:
                continue
            published = sources.iso_ts((item.get("contentDetails") or {}).get("videoPublishedAt")) or sources.iso_ts(sn.get("publishedAt"))
            if vid not in known:
                new_on_page += 1
            rows.append((feed_id, vid, title, published))
        db.executemany("INSERT OR REPLACE INTO podcast_youtube_videos (feed_id, video_id, title, published) VALUES (?, ?, ?, ?)", rows)
        added += new_on_page
        token = data.get("nextPageToken") if isinstance(data.get("nextPageToken"), str) else ""
        if not token or not rows or (not first and new_on_page == 0):
            break
    return added


# ---------------------------------------------------------------- 3. match
def match(db, feed_id: int) -> int:
    """Link unmatched episodes of a show to its videos. Returns new links."""
    vids = [dict(r) for r in db.execute("SELECT video_id, title, published FROM podcast_youtube_videos WHERE feed_id = ? AND published IS NOT NULL "
                                        "ORDER BY published", (feed_id,))]
    if not vids:
        return 0
    for v in vids:
        v["norm"], v["num"], v["words"] = norm_title(v["title"]), ep_number(v["title"]), words(v["title"])
    exact = {v["norm"]: v for v in vids if len(v["norm"]) >= 8}
    times = [v["published"] for v in vids]
    used = {r[0] for r in db.execute("SELECT e.video_id FROM episode_youtube e JOIN articles a ON a.id = e.article_id WHERE a.feed_id = ?", (feed_id,))}
    eps = db.execute("SELECT a.id, a.title, a.sort_ts FROM articles a WHERE a.feed_id = ? AND NOT EXISTS "
                     "(SELECT 1 FROM episode_youtube y WHERE y.article_id = a.id) ORDER BY a.sort_ts DESC", (feed_id,)).fetchall()
    links = []
    for e in eps:
        core, ts = norm_title(e["title"]), e["sort_ts"] or 0
        hit, how = None, None
        if core in exact and exact[core]["video_id"] not in used:
            hit, how = exact[core], "title"
        if hit is None and ts:
            lo, hi = bisect.bisect_left(times, ts - 60 * 86400), bisect.bisect_right(times, ts + 60 * 86400)
            near = [v for v in vids[lo:hi] if v["video_id"] not in used]
            if len(core) >= 15:
                hit = next((v for v in near if len(v["norm"]) >= 15 and (core in v["norm"] or v["norm"] in core)), None)
                how = "title" if hit else None
            num = ep_number(e["title"])
            if hit is None and num is not None:
                hit = next((v for v in near if v["num"] == num and abs(v["published"] - ts) <= 14 * 86400), None)
                how = "number" if hit else None
            if hit is None:
                ew = words(e["title"])
                best, score = None, 0.0
                for v in near:
                    if abs(v["published"] - ts) > 3 * 86400 or not ew or not v["words"]:
                        continue
                    s = len(ew & v["words"]) / min(len(ew), len(v["words"]))
                    if s > score:
                        best, score = v, s
                if best is not None and score >= 0.6:
                    hit, how = best, "words"
        if hit is not None:
            used.add(hit["video_id"])
            links.append((e["id"], hit["video_id"], how))
    db.executemany("INSERT OR IGNORE INTO episode_youtube (article_id, video_id, how) VALUES (?, ?, ?)", links)
    return len(links)


# ---------------------------------------------------------------- the job
def sync(feed_id: int, force_detect: bool = False) -> dict:
    """Find (if due) → list new videos (daily) → match. Safe to call after every fetch of the show."""
    key = sources.yt_key()
    if not key:
        return {"ok": False, "reason": "no YouTube API key"}
    with _lock:  # one show at a time (the scheduler and a "Find again" click never overlap)
        with get_db() as db:
            feed = db.execute("SELECT id, title, url, site_url FROM feeds WHERE id = ? AND kind = 'podcast'", (feed_id,)).fetchone()
            row = db.execute("SELECT * FROM podcast_youtube WHERE feed_id = ?", (feed_id,)).fetchone()
        if feed is None:
            return {"ok": False, "reason": "not a podcast"}
        t = now()
        row = dict(row) if row else None
        if row is None or force_detect or (row["how"] == "none" and t - (row["detected_at"] or 0) > DETECT_AGAIN):
            if row is None or row["how"] != "manual" or force_detect:
                found, how = detect(dict(feed), key)
                with get_db() as db:
                    db.execute("INSERT INTO podcast_youtube (feed_id, sources, how, detected_at, listed_at) VALUES (?, ?, ?, ?, 0) "
                               "ON CONFLICT(feed_id) DO UPDATE SET sources = excluded.sources, how = excluded.how, "
                               "detected_at = excluded.detected_at, listed_at = 0", (feed_id, json.dumps(found), how, t))
                    db.execute("DELETE FROM podcast_youtube_videos WHERE feed_id = ?", (feed_id,))
                    if force_detect:  # matched again from scratch against what was found now
                        db.execute("DELETE FROM episode_youtube WHERE article_id IN (SELECT id FROM articles WHERE feed_id = ?)", (feed_id,))
                row = {"sources": json.dumps(found), "how": how, "listed_at": 0}
        srcs = json.loads(row["sources"] or "[]")
        added, first = 0, False
        if srcs and t - (row["listed_at"] or 0) >= LIST_EVERY:
            first = not row["listed_at"]
            with get_db() as db:
                for src in srcs[:MAX_SOURCES]:
                    added += _list_source(db, feed_id, src, key, first)
                db.execute("UPDATE podcast_youtube SET listed_at = ? WHERE feed_id = ?", (t, feed_id))
        with get_db() as db:
            linked = match(db, feed_id)
            if first and row["how"] != "manual":
                drop_if_unmatched(db, feed_id)
                row = dict(db.execute("SELECT * FROM podcast_youtube WHERE feed_id = ?", (feed_id,)).fetchone())
                srcs = json.loads(row["sources"] or "[]")
        return {"ok": True, "how": row["how"], "sources": srcs, "new_videos": added, "new_links": linked}


def drop_if_unmatched(db, feed_id: int) -> bool:
    """An automatically found channel none of the show's episodes are on is the wrong one (a company site linking its
    main channel, a namesake): forget it and its videos; looked for again in 30 days, or set by hand."""
    episodes = db.execute("SELECT COUNT(*) FROM articles WHERE feed_id = ?", (feed_id,)).fetchone()[0]
    linked = db.execute("SELECT COUNT(*) FROM episode_youtube y JOIN articles a ON a.id = y.article_id WHERE a.feed_id = ?", (feed_id,)).fetchone()[0]
    if linked or episodes < 3:
        return False
    db.execute("UPDATE podcast_youtube SET sources = '[]', how = 'none' WHERE feed_id = ?", (feed_id,))
    db.execute("DELETE FROM podcast_youtube_videos WHERE feed_id = ?", (feed_id,))
    return True


def set_manual(feed_id: int, url: str | None) -> list[dict]:
    """The user's own choice: a channel / playlist link, or None = this show has no YouTube."""
    found: list[dict] = []
    if url:
        key = sources.yt_key()
        got = sources.resolve_youtube(url)
        src = got["source"]
        kind, sid = ("playlist", src["playlist_id"]) if src.get("playlist_id") else ("channel", src.get("channel_id"))
        if not sid:
            raise sources.SourceError("Not a YouTube channel or playlist link")
        title = got.get("title")
        if key and not title:
            ref = f"playlist?list={sid}" if kind == "playlist" else f"channel/{sid}"
            title = (_resolve_ref(ref, key) or {}).get("title")
        found = [{"kind": kind, "id": sid, "title": to_text(title, 200) or sid}]
    with get_db() as db:
        db.execute("INSERT INTO podcast_youtube (feed_id, sources, how, detected_at, listed_at) VALUES (?, ?, 'manual', ?, 0) "
                   "ON CONFLICT(feed_id) DO UPDATE SET sources = excluded.sources, how = 'manual', detected_at = excluded.detected_at, listed_at = 0",
                   (feed_id, json.dumps(found), now()))
        db.execute("DELETE FROM podcast_youtube_videos WHERE feed_id = ?", (feed_id,))
        db.execute("DELETE FROM episode_youtube WHERE article_id IN (SELECT id FROM articles WHERE feed_id = ?)", (feed_id,))
    return found


def source_url(src: dict) -> str:
    return (f"https://www.youtube.com/playlist?list={src['id']}" if src.get("kind") == "playlist"
            else f"https://www.youtube.com/channel/{src['id']}")


def host_ok(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in ("youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be")
