"""Non-RSS sources: YouTube channels/playlists, Hugging Face Daily Papers, X profiles, Telegram channels.

Every source produces feedparser-like entry dicts that go through the normal pipeline
(``fetcher.store_entries`` -> sanitiser -> entities -> rules -> topics), so the same XSS, SSRF
and dedup protections apply as for RSS. HTML built here escapes every remote value; the
sanitiser runs again on insert.

Network access always goes through ``netguard`` (SSRF guard, size caps, timeouts). The only
private-address exception is the X *bridge* URL, which the admin configures explicitly
(self-hosted RSSHub / Nitter / RSS-Bridge usually live on the LAN). Telegram account access
uses MTProto through ``app.telegram_mt``.
"""

from __future__ import annotations

import html
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Union
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app import integrations, netguard
from app.config import get_settings
from app.db import get_db, now
from app.sanitize import to_text

log = logging.getLogger("feedwarden.sources")

KINDS = ("youtube", "hfpapers", "x", "telegram")
DEFAULT_REFRESH = {"youtube": 60, "hfpapers": 180, "x": 360, "telegram": 30}

CHANNEL_ID = r"^UC[A-Za-z0-9_-]{22}$"
PLAYLIST_ID = r"^[A-Za-z0-9_-]{12,64}$"
VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
X_USER = r"^[A-Za-z0-9_]{1,15}$"
TG_USER = r"^[A-Za-z][A-Za-z0-9_]{3,31}$"
ARXIV_ID = re.compile(r"^[0-9]{4}\.[0-9]{4,5}(?:v[0-9]{1,3})?$")
JSON_LIMIT = 5 * 1024 * 1024
PAGE_LIMIT = 6 * 1024 * 1024  # YouTube channel pages are ~1.6 MB
SAVED_VIDEOS_URL = "https://www.youtube.com/feed/library#eye-of-sauron-saved-videos"  # feeds.url of the Saved videos feed
OEMBED = "https://www.youtube.com/oembed"


class SourceError(Exception):
    """User-facing failure; the message is safe to show. ``retry_after`` = seconds to back off."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


# ============================================================================ config models
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class YouTubeSource(_Strict):
    kind: Literal["youtube"] = "youtube"
    channel_id: Annotated[str, StringConstraints(pattern=CHANNEL_ID)] | None = None
    playlist_id: Annotated[str, StringConstraints(pattern=PLAYLIST_ID)] | None = None
    saved: bool | None = None   # True = the "Saved videos" collection: single videos added one by one, nothing to poll

    def model_post_init(self, _ctx: Any) -> None:
        if sum((bool(self.channel_id), bool(self.playlist_id), bool(self.saved))) != 1:
            raise ValueError("Give exactly one of channel_id, playlist_id or saved")


class HFPapersSource(_Strict):
    kind: Literal["hfpapers"] = "hfpapers"
    min_upvotes: Annotated[int, Field(ge=0, le=10_000)] = 0


class XSource(_Strict):
    kind: Literal["x"] = "x"
    username: Annotated[str, StringConstraints(pattern=X_USER)]
    via: Literal["bridge", "api"] = "bridge"
    include_replies: bool = False
    include_reposts: bool = True


class TelegramSource(_Strict):
    kind: Literal["telegram"] = "telegram"
    via: Literal["web", "account"] = "web"
    channel: Annotated[str, StringConstraints(pattern=TG_USER)] | None = None  # public @username
    chat_id: Annotated[int, Field(ge=-(10**15), le=10**15)] | None = None    # account mode: private chat/group

    def model_post_init(self, _ctx: Any) -> None:
        if not self.channel and self.chat_id is None:
            raise ValueError("Give a channel username or a chat id")
        if self.via == "web" and not self.channel:
            raise ValueError("Public web preview needs a channel username")


SourceConfig = Annotated[Union[YouTubeSource, HFPapersSource, XSource, TelegramSource], Field(discriminator="kind")]


class _Wrapper(_Strict):
    source: SourceConfig


def parse_config(raw: str | dict | None):
    data = json.loads(raw) if isinstance(raw, str) else raw
    return _Wrapper.model_validate({"source": data}).source


def canonical_url(cfg) -> str:
    """The feeds.url for a source (unique per subscription)."""
    if isinstance(cfg, YouTubeSource):
        if cfg.saved:
            return SAVED_VIDEOS_URL
        key = f"channel_id={cfg.channel_id}" if cfg.channel_id else f"playlist_id={cfg.playlist_id}"
        return f"https://www.youtube.com/feeds/videos.xml?{key}"
    if isinstance(cfg, HFPapersSource):
        return "https://huggingface.co/papers"
    if isinstance(cfg, XSource):
        return f"https://x.com/{cfg.username.lower()}"
    if isinstance(cfg, TelegramSource):
        if cfg.channel:
            return f"https://t.me/s/{cfg.channel.lower()}"
        return f"https://t.me/c/{abs(cfg.chat_id or 0)}"
    raise ValueError("Unknown source")


# ============================================================================ helpers
@dataclass
class Fetched:
    entries: list[dict]
    title: str | None = None
    site_url: str | None = None
    videos: dict[str, dict] = field(default_factory=dict)  # guid -> video metadata
    state: dict[str, str] = field(default_factory=dict)    # sync_state updates after a successful store
    cursor: int | None = None                              # paging cursor for history back-fill


def get_state(key: str) -> str | None:
    with get_db() as db:
        row = db.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(db, key: str, value: str) -> None:
    db.execute("INSERT INTO sync_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
               (key, value))


def iso_ts(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


_ESC_URL = re.compile(r"https?://[^\s<>\"']{1,2000}")


def text_to_html(text: str | None) -> str:
    """Escape plain text, link bare http(s) URLs and keep line breaks."""
    escaped = html.escape(text or "", quote=True)

    def link(m: re.Match) -> str:
        url = m.group(0)
        tail = ""
        while url and url[-1] in ".,;:!?)":
            tail, url = url[-1] + tail, url[:-1]
        return f'<a href="{url}">{url}</a>{tail}'

    return _ESC_URL.sub(link, escaped).replace("\n", "<br>")


def _attr(value: str) -> str:
    return html.escape(value, quote=True)


def _https(value: Any) -> str | None:
    if isinstance(value, str) and value.startswith(("https://", "http://")):
        try:
            return netguard.normalize_url(value)
        except netguard.UnsafeURLError:
            return None
    return None


def entry(*, guid: str, title: str, link: str | None, html_body: str, ts: int | None, author: str | None = None) -> dict:
    e: dict[str, Any] = {"id": guid, "title": title, "link": link, "summary": html_body, "author": author}
    if ts:
        e["published_parsed"] = time.gmtime(ts)
    return e


def _title_from(text: str, fallback: str) -> str:
    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    if not line:
        return fallback
    return line if len(line) <= 140 else line[:137].rstrip() + "…"


def http_get(url: str, *, accept: str, headers: dict[str, str] | None = None, max_bytes: int = JSON_LIMIT,
             allow_private: bool = False) -> netguard.SafeResponse:
    cfg = get_settings()
    try:
        return netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": accept, **(headers or {})},
                                allow_private=allow_private or cfg.allow_private_feeds, timeout=cfg.fetch_timeout,
                                max_bytes=max_bytes)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise SourceError(str(exc)) from None


def _json(resp: netguard.SafeResponse) -> Any:
    try:
        return json.loads(resp.content)
    except (ValueError, UnicodeDecodeError):
        raise SourceError("The service returned invalid JSON") from None


# ============================================================================ Hugging Face Daily Papers
HF_API = "https://huggingface.co/api/daily_papers"


def _hf_entries(items: Any, min_upvotes: int) -> list[dict]:
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        paper = item.get("paper") if isinstance(item.get("paper"), dict) else {}
        pid = paper.get("id")
        if not isinstance(pid, str) or not ARXIV_ID.match(pid):
            continue
        upvotes = paper.get("upvotes") if isinstance(paper.get("upvotes"), int) else 0
        if upvotes < min_upvotes:
            continue
        title = to_text(paper.get("title") or item.get("title"), 1000) or pid
        authors = [to_text(a.get("name"), 100) for a in paper.get("authors") or [] if isinstance(a, dict) and a.get("name")]
        comments = item.get("numComments") if isinstance(item.get("numComments"), int) else 0
        parts = []
        thumb = _https(item.get("thumbnail"))
        if thumb:
            parts.append(f'<p><img src="{_attr(thumb)}" alt=""></p>')
        parts.append(f"<p><strong>▲ {upvotes}</strong> upvotes · {comments} comments</p>")
        if authors:
            shown = ", ".join(authors[:12]) + (f" +{len(authors) - 12} more" if len(authors) > 12 else "")
            parts.append(f"<p><em>{html.escape(shown)}</em></p>")
        ai = to_text(paper.get("ai_summary"), 2000)
        if ai:
            parts.append(f"<p><strong>TL;DR:</strong> {html.escape(ai)}</p>")
        parts.append(f"<p>{text_to_html(to_text(paper.get('summary'), 20000))}</p>")
        keywords = [to_text(k, 60) for k in paper.get("ai_keywords") or [] if isinstance(k, str)][:15]
        if keywords:
            parts.append(f"<p><small>{html.escape(' · '.join(keywords))}</small></p>")
        parts.append(f'<p><a href="https://arxiv.org/abs/{pid}">arXiv</a> · <a href="https://arxiv.org/pdf/{pid}">PDF</a> · '
                     f'<a href="https://huggingface.co/papers/{pid}">Discussion</a></p>')
        ts = iso_ts(paper.get("submittedOnDailyAt")) or iso_ts(item.get("publishedAt")) or iso_ts(paper.get("publishedAt"))
        out.append(entry(guid=f"hf:paper:{pid}", title=title, link=f"https://huggingface.co/papers/{pid}",
                         html_body="".join(parts), ts=ts, author=", ".join(authors[:3]) or None))
    return out


def hf_fetch_day(day: str | None, min_upvotes: int) -> list[dict]:
    params = {"limit": "100"}
    if day:
        params["date"] = day
    resp = http_get(f"{HF_API}?{urlencode(params)}", accept="application/json")
    if resp.status_code >= 400:
        raise SourceError(f"Hugging Face answered HTTP {resp.status_code}")
    return _hf_entries(_json(resp), min_upvotes)


def fetch_hfpapers(cfg: HFPapersSource) -> Fetched:
    # Today's list plus yesterday's (papers keep gaining upvotes after they appear).
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    entries = hf_fetch_day(None, cfg.min_upvotes) + hf_fetch_day(yesterday, cfg.min_upvotes)
    return Fetched(entries=entries, title="Hugging Face Daily Papers", site_url="https://huggingface.co/papers")


# ============================================================================ YouTube
YT_API = "https://www.googleapis.com/youtube/v3/"
_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")
_EXTERNAL_ID = re.compile(rb'"externalId":"(UC[A-Za-z0-9_-]{22})"')
_RSS_CHANNEL = re.compile(rb'feeds/videos\.xml\?channel_id=(UC[A-Za-z0-9_-]{22})')
_OG_TITLE = re.compile(rb'<meta property="og:title" content="([^"]{1,300})"')


def parse_duration(value: Any) -> int | None:
    m = _DURATION.match(value) if isinstance(value, str) else None
    if not m:
        return None
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def yt_key() -> str | None:
    from app import secretbox  # local import: secretbox is only needed here
    try:
        with get_db() as db:
            return integrations.secret(db, "youtube", "api_key")
    except secretbox.SecretError:  # key file changed/missing: behave as if no key is stored (and say so in the log)
        log.warning("The stored YouTube API key cannot be decrypted - re-enter it in Settings → Integrations")
        return None


def yt_api(path: str, params: dict[str, str], key: str) -> dict:
    """YouTube Data API v3 call. The key goes in a header, never in the URL (keeps it out of logs)."""
    resp = http_get(YT_API + path + "?" + urlencode(params), accept="application/json",
                    headers={"X-Goog-Api-Key": key}, max_bytes=JSON_LIMIT)
    data = _json(resp)
    if resp.status_code >= 400:
        reason = ""
        try:
            reason = data["error"]["errors"][0]["reason"]
        except (KeyError, IndexError, TypeError):
            pass
        if reason in ("quotaExceeded", "rateLimitExceeded"):
            raise SourceError("YouTube API quota exceeded - try again tomorrow", retry_after=6 * 3600)
        if resp.status_code in (400, 403):
            raise SourceError(f"YouTube API rejected the request ({to_text(reason, 60) or resp.status_code}) - check the API key")
        raise SourceError(f"YouTube API answered HTTP {resp.status_code}")
    return data if isinstance(data, dict) else {}


PLACEHOLDER_TITLES = ("Deleted video", "Private video")  # what playlistItems sometimes says for a live video


def video_details(ids: list[str], key: str, snippet: bool = False) -> dict[str, dict]:
    """duration/views for up to 50 ids per call (same 1 quota unit either way). ``snippet=True`` also returns the
    video's own title/description/thumbnail/channel under "snippet" - the uploads playlist sometimes lists a public
    video as "Deleted video" with no thumbnail. Videos YouTube doesn't return are deleted or private."""
    out: dict[str, dict] = {}
    ids = [i for i in ids if VIDEO_ID.match(i)]
    parts = "snippet,contentDetails,statistics" if snippet else "contentDetails,statistics"
    for start in range(0, len(ids), 50):
        data = yt_api("videos", {"part": parts, "id": ",".join(ids[start:start + 50]), "maxResults": "50"}, key)
        for item in data.get("items") or []:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            views = (item.get("statistics") or {}).get("viewCount")
            out[item["id"]] = {"duration_s": parse_duration((item.get("contentDetails") or {}).get("duration")),
                               "views": int(views) if isinstance(views, str) and views.isdigit() else None}
            if snippet and isinstance(item.get("snippet"), dict):
                out[item["id"]]["snippet"] = item["snippet"]
    return out


def _best_thumb(thumbs) -> str | None:
    thumbs = thumbs if isinstance(thumbs, dict) else {}
    return next((_https((thumbs.get(k) or {}).get("url")) for k in ("high", "medium", "default") if thumbs.get(k)), None)


def repair_placeholder_titles(db, key: str) -> dict:
    """Once: videos stored as "Deleted video"/"Private video" get their real title, description and thumbnail
    (and topics) when YouTube still has them; ones that are really gone are left as they are."""
    rows = db.execute("SELECT a.id, v.video_id FROM articles a JOIN videos v ON v.article_id = a.id "
                      f"WHERE a.title IN ({', '.join('?' * len(PLACEHOLDER_TITLES))})", PLACEHOLDER_TITLES).fetchall()  # nosec B608 - fixed placeholders
    details = video_details([r["video_id"] for r in rows], key, snippet=True) if rows else {}
    fixed = []
    for r in rows:
        d = details.get(r["video_id"]) or {}
        sn = d.get("snippet") or {}
        title = to_text(sn.get("title"), 1000)
        if not title or title in PLACEHOLDER_TITLES:
            continue
        thumb = _best_thumb(sn.get("thumbnails"))
        db.execute("UPDATE articles SET title = ?, content_html = ?, text_content = ? WHERE id = ?",
                   (title, video_html(r["video_id"], thumb, sn.get("description"), d.get("duration_s")),
                    to_text(sn.get("description"), 20000) or "", r["id"]))
        db.execute("UPDATE videos SET thumbnail = COALESCE(?, thumbnail), channel_title = COALESCE(?, channel_title) "
                   "WHERE article_id = ?", (thumb, to_text(sn.get("channelTitle"), 300) or None, r["id"]))
        fixed.append(r["id"])
    if fixed:
        from app import topics

        topics.classify(db, fixed)
    return {"placeholders": len(rows), "fixed": len(fixed), "gone": len(rows) - len(fixed)}


def video_html(video_id: str, thumb: str | None, description: str | None, duration_s: int | None = None) -> str:
    watch = f"https://www.youtube.com/watch?v={video_id}"
    thumb = thumb or f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"
    meta = f"<p><small>Duration {duration_s // 3600:d}:{duration_s % 3600 // 60:02d}:{duration_s % 60:02d}</small></p>" if duration_s else ""
    return (f'<p><a href="{watch}"><img src="{_attr(thumb)}" alt="Watch on YouTube"></a></p>{meta}'
            f"<p>{text_to_html((description or '')[:20000])}</p>")


def _thumb(e: dict) -> str | None:
    for t in e.get("media_thumbnail") or []:
        if isinstance(t, dict):
            url = _https(t.get("url"))
            if url:
                return url
    return None


PLAYLIST_FULL_EVERY = 6 * 3600  # a playlist is read in full (Data API) this often


def _playlist_full_read(cfg: YouTubeSource) -> Fetched | None:
    """YouTube's playlist feed lists only the playlist's first 15 videos, so videos added to the end of a longer
    playlist (a course, a series) never showed up. Every PLAYLIST_FULL_EVERY, with an API key, the whole playlist is
    read (1 quota unit per 50 videos) and anything new is stored. None = not due / no key: use the feed."""
    key = yt_key()
    state_key = f"yt_playlist_full:{cfg.playlist_id}"
    last = get_state(state_key)
    if not key or (last and last.isdigit() and time.time() - int(last) < PLAYLIST_FULL_EVERY):
        return None
    try:
        pairs = youtube_backfill(cfg, key, 5000, lambda: False)
    except SourceError as exc:
        log.info("Full read of playlist %s skipped: %s", cfg.playlist_id, exc)
        return None
    pairs = pairs[-500:]  # one store takes 500; new videos are added at the end of a playlist
    out = Fetched(entries=[p[0] for p in pairs], title=None, site_url=f"https://www.youtube.com/playlist?list={cfg.playlist_id}")
    out.videos = {p[0]["id"]: p[1] for p in pairs}
    out.state[state_key] = str(int(time.time()))
    return out


def fetch_youtube(cfg: YouTubeSource, url: str) -> Fetched:
    from app.fetcher import parse_bytes, xml_guard  # local: fetcher imports this module

    if cfg.saved:  # single videos are added on request; there is no feed to poll
        return Fetched(entries=[], title="Saved YouTube videos", site_url="https://www.youtube.com/")
    if cfg.playlist_id:
        full = _playlist_full_read(cfg)
        if full is not None:
            return full

    resp = http_get(url, accept="application/atom+xml,application/xml;q=0.9,*/*;q=0.5", max_bytes=JSON_LIMIT)
    if resp.status_code >= 400:
        # YouTube's public feed is flaky (it answers 404/500 for channels that exist, then works again). With an
        # API key, read the newest uploads from the Data API instead; without one, report the error and retry later.
        key = yt_key()
        if key:
            try:
                pairs = youtube_backfill(cfg, key, 50, lambda: False)
            except SourceError:
                pairs = []
            if pairs:
                # name the channel from its videos (the feed's own title is what failed to load)
                name = next((p[1].get("channel_title") for p in pairs if p[1].get("channel_title")), None) if cfg.channel_id else None
                out = Fetched(entries=[p[0] for p in pairs], title=name,
                              site_url=(f"https://www.youtube.com/channel/{cfg.channel_id}" if cfg.channel_id
                                        else f"https://www.youtube.com/playlist?list={cfg.playlist_id}"))
                out.videos = {p[0]["id"]: p[1] for p in pairs}
                return out
        if resp.status_code == 404:
            raise SourceError("YouTube's feed answered 404 (it does this now and then for channels that exist; "
                              "retrying later - add a YouTube API key for a fallback)" if not key else
                              "YouTube says this channel/playlist does not exist (HTTP 404)")
        raise SourceError(f"YouTube answered HTTP {resp.status_code}")
    rejection = xml_guard(resp.content, resp.headers.get("content-type"))
    if rejection:
        raise SourceError(rejection)
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url)
    out = Fetched(entries=[], title=to_text(parsed.get("feed", {}).get("title"), 300) or None)
    if cfg.channel_id:
        out.site_url = f"https://www.youtube.com/channel/{cfg.channel_id}"
    else:
        out.site_url = f"https://www.youtube.com/playlist?list={cfg.playlist_id}"
    for e in parsed.entries[:200]:
        vid = e.get("yt_videoid")
        if not isinstance(vid, str) or not VIDEO_ID.match(vid):
            continue
        guid = f"yt:video:{vid}"
        thumb = _thumb(e)
        views = (e.get("media_statistics") or {}).get("views")
        out.entries.append(entry(guid=guid, title=to_text(e.get("title"), 1000) or vid,
                                 link=f"https://www.youtube.com/watch?v={vid}",
                                 html_body=video_html(vid, thumb, e.get("summary")),
                                 ts=iso_ts(e.get("published")), author=to_text(e.get("author"), 300) or None))
        out.videos[guid] = {"video_id": vid, "channel_id": e.get("yt_channelid") if isinstance(e.get("yt_channelid"), str) else cfg.channel_id,
                            "channel_title": to_text(e.get("author"), 300) or out.title, "thumbnail": thumb,
                            "views": int(views) if isinstance(views, str) and views.isdigit() and views != "0" else None}
    key = yt_key()
    if key and out.videos:
        try:
            details = video_details([v["video_id"] for v in out.videos.values()], key)
            for meta in out.videos.values():
                meta.update({k: v for k, v in details.get(meta["video_id"], {}).items() if v is not None})
        except SourceError as exc:  # enrichment is optional
            log.info("YouTube enrichment skipped: %s", exc)
    return out


def store_video(db, article_id: int, meta: dict, published: int | None) -> None:
    db.execute(
        "INSERT INTO videos (article_id, video_id, channel_id, channel_title, thumbnail, duration_s, views, published) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(article_id) DO UPDATE SET duration_s = COALESCE(excluded.duration_s, duration_s), "
        "views = COALESCE(excluded.views, views)",
        (article_id, meta["video_id"], meta.get("channel_id"), meta.get("channel_title"), meta.get("thumbnail"),
         meta.get("duration_s"), meta.get("views"), published),
    )


def refresh_video_stats(db, metas: dict[str, dict]) -> None:
    """Update views/duration for videos we already have (RSS re-lists the latest 15)."""
    for meta in metas.values():
        if meta.get("views") is None and meta.get("duration_s") is None:
            continue
        db.execute("UPDATE videos SET views = COALESCE(?, views), duration_s = COALESCE(?, duration_s) WHERE video_id = ?",
                   (meta.get("views"), meta.get("duration_s"), meta["video_id"]))


YOUTUBE_FOLDER = "YouTube"
_YT_FEED_URL = re.compile(r"^https://www\.youtube\.com/feeds/videos\.xml\?(channel_id|playlist_id)=([A-Za-z0-9_-]{10,64})$")


def youtube_folder(db) -> int:
    """The folder YouTube channels live in (Reader sidebar), created on first use."""
    db.execute("INSERT OR IGNORE INTO folders (name, position) VALUES (?, 10)", (YOUTUBE_FOLDER,))
    return db.execute("SELECT id FROM folders WHERE name = ?", (YOUTUBE_FOLDER,)).fetchone()["id"]


def youtube_source_for_url(url: str) -> dict | None:
    """{"kind": "youtube", "channel_id"|"playlist_id": ...} when a plain feed URL is really a YouTube channel/playlist feed."""
    m = _YT_FEED_URL.match((url or "").strip())
    return {"kind": "youtube", m.group(1): m.group(2)} if m else None


def adopt_as_youtube(db, feed_id: int, source: dict) -> int:
    """Turn a plain RSS subscription of a YouTube feed (e.g. from an OPML/FreshRSS import) into a YouTube channel:
    kind/source set, kept forever, moved to the YouTube folder, and its stored articles re-keyed to the channel
    format ("yt:video:<id>") with video records, so the next fetch adds no duplicates. Returns videos attached."""
    feed = db.execute("SELECT id, title, folder_id FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    db.execute("UPDATE feeds SET kind = 'youtube', source = ?, retention_days = 0, max_articles = 0, etag = NULL, "
               "last_modified = NULL, next_fetch = 0, error_count = 0, last_error = NULL, folder_id = ? WHERE id = ?",
               (json.dumps(source), youtube_folder(db), feed_id))
    attached = 0
    for a in db.execute("SELECT id, guid, url, author, published FROM articles WHERE feed_id = ?", (feed_id,)).fetchall():
        vid = parse_video_id(a["url"] or "") or parse_video_id(a["guid"] or "")
        if not vid:
            continue
        new_guid = f"yt:video:{vid}"
        if a["guid"] != new_guid and not db.execute("SELECT 1 FROM articles WHERE feed_id = ? AND guid = ?", (feed_id, new_guid)).fetchone():
            db.execute("UPDATE articles SET guid = ? WHERE id = ?", (new_guid, a["id"]))
        store_video(db, a["id"], {"video_id": vid, "channel_id": source.get("channel_id"),
                                  "channel_title": a["author"] or feed["title"]}, a["published"])
        attached += 1
    return attached


_VIDEO_PATHS = re.compile(r"^/(?:shorts|live|embed|v)/([A-Za-z0-9_-]{11})(?:[/?#]|$)")


def parse_video_id(text: str) -> str | None:
    """The video id of a single-video link (watch?v=, youtu.be/, /shorts/, /live/, /embed/), else None."""
    text = text.strip()
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    if host == "youtu.be":
        vid = parts.path.strip("/").split("/")[0]
        return vid if VIDEO_ID.match(vid) else None
    if host not in ("youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com"):
        return None
    if parts.path == "/watch":
        vid = (parse_qs(parts.query).get("v") or [""])[0]
        return vid if VIDEO_ID.match(vid) else None
    m = _VIDEO_PATHS.match(parts.path)
    return m.group(1) if m else None


def single_video(video_id: str) -> tuple[dict, dict]:
    """(entry, video meta) for one video: the Data API when a key is set (date, duration, views),
    otherwise YouTube's public oEmbed endpoint (title, channel and thumbnail only)."""
    if not VIDEO_ID.match(video_id):
        raise SourceError("Not a YouTube video id")
    watch = f"https://www.youtube.com/watch?v={video_id}"
    key = yt_key()
    if key:
        data = yt_api("videos", {"part": "snippet,contentDetails,statistics", "id": video_id}, key)
        items = [i for i in data.get("items") or [] if isinstance(i, dict) and i.get("id") == video_id]
        if not items:
            raise SourceError("YouTube says this video does not exist or is private")
        sn = items[0].get("snippet") if isinstance(items[0].get("snippet"), dict) else {}
        thumbs = sn.get("thumbnails") or {}
        thumb = next((_https((thumbs.get(k) or {}).get("url")) for k in ("high", "medium", "default") if thumbs.get(k)), None)
        views = (items[0].get("statistics") or {}).get("viewCount")
        duration = parse_duration((items[0].get("contentDetails") or {}).get("duration"))
        channel = to_text(sn.get("channelTitle"), 300) or None
        e = entry(guid=f"yt:video:{video_id}", title=to_text(sn.get("title"), 1000) or video_id, link=watch,
                  html_body=video_html(video_id, thumb, sn.get("description"), duration), ts=iso_ts(sn.get("publishedAt")),
                  author=channel)
        cid = sn.get("channelId") if isinstance(sn.get("channelId"), str) and re.match(CHANNEL_ID, sn["channelId"]) else None
        return e, {"video_id": video_id, "channel_id": cid, "channel_title": channel, "thumbnail": thumb,
                   "duration_s": duration, "views": int(views) if isinstance(views, str) and views.isdigit() else None}
    resp = http_get(f"{OEMBED}?{urlencode({'url': watch, 'format': 'json'})}", accept="application/json", max_bytes=64 * 1024)
    if resp.status_code in (400, 401, 403, 404):
        raise SourceError("YouTube says this video does not exist, is private or can't be embedded")
    if resp.status_code >= 400:
        raise SourceError(f"YouTube answered HTTP {resp.status_code}")
    data = _json(resp)
    if not isinstance(data, dict):
        raise SourceError("YouTube returned an unexpected answer")
    thumb = _https(data.get("thumbnail_url"))
    channel = to_text(data.get("author_name"), 300) or None
    e = entry(guid=f"yt:video:{video_id}", title=to_text(data.get("title"), 1000) or video_id, link=watch,
              html_body=video_html(video_id, thumb, None), ts=None, author=channel)
    return e, {"video_id": video_id, "channel_id": None, "channel_title": channel, "thumbnail": thumb}


def resolve_youtube(text: str) -> dict:
    """Channel URL / @handle / channel id / playlist URL -> source config + title."""
    text = text.strip()
    if re.match(CHANNEL_ID, text):
        return {"source": {"kind": "youtube", "channel_id": text}, "title": None}
    if text.startswith("@") and re.match(r"^@[A-Za-z0-9._-]{3,100}$", text):
        text = f"https://www.youtube.com/{text}"
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    if host not in ("youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be", "music.youtube.com"):
        raise SourceError("Not a YouTube link")
    query = parse_qs(parts.query)
    playlist = (query.get("list") or [""])[0]
    # a playlist link, or a video played inside a playlist (watch?v=…&list=…): the playlist itself, never its channel.
    # "RD…" lists are YouTube's automatic mixes, not real playlists.
    if playlist and re.match(PLAYLIST_ID, playlist) and parts.path in ("/playlist", "/watch") and not playlist.startswith("RD"):
        return {"source": {"kind": "youtube", "playlist_id": playlist}, "title": None}
    m = re.match(r"^/channel/(UC[A-Za-z0-9_-]{22})", parts.path)
    if m:
        return {"source": {"kind": "youtube", "channel_id": m.group(1)}, "title": None}
    key = yt_key()
    handle = re.match(r"^/(@[A-Za-z0-9._-]{3,100})", parts.path)
    if key and handle:
        data = yt_api("channels", {"part": "id,snippet", "forHandle": handle.group(1)}, key)
        items = data.get("items") or []
        if items and re.match(CHANNEL_ID, str(items[0].get("id"))):
            return {"source": {"kind": "youtube", "channel_id": items[0]["id"]},
                    "title": to_text((items[0].get("snippet") or {}).get("title"), 300) or None}
    # Fall back to reading the public page (channel, handle, /c/, /user/ or a video page).
    page_url = f"https://www.youtube.com{parts.path}" + (f"?v={quote((query.get('v') or [''])[0])}" if parts.path == "/watch" else "")
    if host == "youtu.be" and VIDEO_ID.match(parts.path.strip("/")):
        page_url = f"https://www.youtube.com/watch?v={parts.path.strip('/')}"
    resp = http_get(page_url, accept="text/html", max_bytes=PAGE_LIMIT)
    if resp.status_code >= 400:
        raise SourceError(f"YouTube answered HTTP {resp.status_code} for that link")
    m2 = _RSS_CHANNEL.search(resp.content) or _EXTERNAL_ID.search(resp.content)
    if not m2:
        raise SourceError("Could not find the channel on that page (YouTube may be showing a consent page - "
                          "paste the /channel/UC… link or add a YouTube API key in Integrations)")
    title = _OG_TITLE.search(resp.content)
    return {"source": {"kind": "youtube", "channel_id": m2.group(1).decode()},
            "title": html.unescape(title.group(1).decode("utf-8", "replace")) if title and parts.path != "/watch" else None}


def youtube_backfill(cfg: YouTubeSource, key: str, max_videos: int, stop, since: int | None = None) -> list[tuple[dict, dict]]:
    """Older uploads via the Data API (uploads playlist). Returns (entry, video meta) pairs.
    ``since``: for a channel, stop paging once its uploads (newest first) are older than this (a playlist is read whole)."""
    playlist = cfg.playlist_id or ("UU" + (cfg.channel_id or "")[2:])
    token = ""
    pairs: list[tuple[dict, dict]] = []
    while len(pairs) < max_videos and not stop():
        params = {"part": "snippet,contentDetails", "playlistId": playlist, "maxResults": "50"}
        if token:
            params["pageToken"] = token
        data = yt_api("playlistItems", params, key)
        batch = []
        for item in data.get("items") or []:
            if not isinstance(item, dict):
                continue
            sn = item.get("snippet") if isinstance(item.get("snippet"), dict) else {}
            vid = (item.get("contentDetails") or {}).get("videoId")
            if not isinstance(vid, str) or not VIDEO_ID.match(vid):
                continue
            thumb = _best_thumb(sn.get("thumbnails"))
            published = iso_ts((item.get("contentDetails") or {}).get("videoPublishedAt")) or iso_ts(sn.get("publishedAt"))
            batch.append((vid, sn, thumb, published))
        details = video_details([b[0] for b in batch], key, snippet=True) if batch else {}
        for vid, sn, thumb, ts in batch:
            d = dict(details.get(vid, {}))
            own = d.pop("snippet", None)
            if own:  # the video's own details: the playlist entry can be a stale "Deleted video" placeholder
                sn = {**sn, "title": own.get("title") or sn.get("title"), "description": own.get("description", sn.get("description"))}
                thumb = _best_thumb(own.get("thumbnails")) or thumb
            elif to_text(sn.get("title"), 100) in PLACEHOLDER_TITLES:
                continue  # really deleted or private: nothing to watch
            e = entry(guid=f"yt:video:{vid}", title=to_text(sn.get("title"), 1000) or vid,
                      link=f"https://www.youtube.com/watch?v={vid}",
                      html_body=video_html(vid, thumb, sn.get("description"), d.get("duration_s")), ts=ts,
                      author=to_text(sn.get("videoOwnerChannelTitle") or sn.get("channelTitle"), 300) or None)
            pairs.append((e, {"video_id": vid, "channel_id": sn.get("videoOwnerChannelId") or cfg.channel_id,
                              "channel_title": to_text(sn.get("videoOwnerChannelTitle") or sn.get("channelTitle"), 300),
                              "thumbnail": thumb, **d}))
        token = data.get("nextPageToken") if isinstance(data.get("nextPageToken"), str) else ""
        if not token or not batch:
            break
        if since and not cfg.playlist_id and min((b[3] or 0) for b in batch) < since:
            break  # the rest of this channel's uploads are older than the time frame
    return pairs[:max_videos]


# ============================================================================ X (bridge or official API)
X_API = "https://api.x.com/2/"
BRIDGE_TYPES = ("rsshub", "nitter", "rssbridge", "template")


def bridge_url(config: dict, username: str) -> str:
    kind = config.get("bridge_type")
    base = (config.get("bridge_url") or "").rstrip("/")
    user = quote(username, safe="")
    if kind == "template":
        template = config.get("bridge_template") or ""
        if "{username}" not in template:
            raise SourceError("The X bridge template must contain {username}")
        url = template.replace("{username}", user)
    elif not base:
        raise SourceError("No X bridge is configured (Settings → Integrations → X)")
    elif kind == "rsshub":
        url = f"{base}/twitter/user/{user}"
    elif kind == "nitter":
        url = f"{base}/{user}/rss"
    elif kind == "rssbridge":
        url = f"{base}/?action=display&bridge=TwitterBridge&context=By+username&u={user}&format=Atom"
    else:
        raise SourceError("No X bridge is configured (Settings → Integrations → X)")
    try:
        return netguard.normalize_url(url)
    except netguard.UnsafeURLError as exc:
        raise SourceError(f"Invalid bridge URL: {exc}") from None


def fetch_x_bridge(cfg: XSource) -> Fetched:
    from app.fetcher import parse_bytes, xml_guard

    with get_db() as db:
        config, _ = integrations.load(db, "x")
    url = bridge_url(config, cfg.username)
    # The bridge is admin-configured and normally self-hosted on the LAN, so private addresses are allowed for it.
    resp = http_get(url, accept="application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.5",
                    allow_private=True, max_bytes=JSON_LIMIT)
    if resp.status_code >= 400:
        raise SourceError(f"The X bridge answered HTTP {resp.status_code}")
    rejection = xml_guard(resp.content, resp.headers.get("content-type"))
    if rejection:
        raise SourceError(rejection)
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url)
    if parsed.get("bozo") and not parsed.get("entries"):
        raise SourceError("The X bridge did not return a valid feed")
    entries = []
    for e in parsed.entries[:200]:
        title = to_text(e.get("title"), 1000)
        if not cfg.include_reposts and (title.startswith("RT ") or title.startswith("RT by")):
            continue
        if not cfg.include_replies and title.startswith(("R to @", "Re @")):
            continue
        link = e.get("link") if isinstance(e.get("link"), str) else None
        # Normalise bridge links (nitter host etc.) to x.com status URLs where possible.
        m = re.search(r"/([A-Za-z0-9_]{1,15})/status/(\d{1,25})", link or "")
        if m:
            link = f"https://x.com/{m.group(1)}/status/{m.group(2)}"
        e = dict(e)
        e["link"] = link
        if m:
            e["id"] = f"x:status:{m.group(2)}"
        entries.append(e)
    return Fetched(entries=entries, title=f"@{cfg.username} on X", site_url=f"https://x.com/{cfg.username}")


def x_token() -> str | None:
    with get_db() as db:
        return integrations.secret(db, "x", "bearer_token")


def x_api(path: str, params: dict[str, str], token: str) -> dict:
    resp = http_get(X_API + path + ("?" + urlencode(params) if params else ""), accept="application/json",
                    headers={"Authorization": f"Bearer {token}"}, max_bytes=JSON_LIMIT)
    if resp.status_code == 429:
        reset = resp.headers.get("x-rate-limit-reset", "")
        wait = max(60, int(reset) - now()) if reset.isdigit() else 15 * 60
        raise SourceError("X API rate limit reached", retry_after=min(wait, 24 * 3600))
    if resp.status_code in (401, 403):
        raise SourceError(f"X API refused the request (HTTP {resp.status_code}) - check the bearer token and your API plan")
    if resp.status_code >= 400:
        raise SourceError(f"X API answered HTTP {resp.status_code}")
    data = _json(resp)
    return data if isinstance(data, dict) else {}


def x_user_id(username: str, token: str) -> tuple[str, str | None]:
    cached = get_state(f"x_uid:{username.lower()}")
    if cached:
        return cached, None
    data = x_api(f"users/by/username/{quote(username, safe='')}", {}, token).get("data") or {}
    uid = data.get("id")
    if not isinstance(uid, str) or not uid.isdigit():
        raise SourceError(f"X user @{username} was not found")
    with get_db() as db:
        set_state(db, f"x_uid:{username.lower()}", uid)
    return uid, to_text(data.get("name"), 200) or None


def _tweet_html(t: dict) -> str:
    text = ((t.get("note_tweet") or {}).get("text") if isinstance(t.get("note_tweet"), dict) else None) or t.get("text") or ""
    text = to_text(text, 30000) if "<" in text else text[:30000]
    for u in ((t.get("entities") or {}).get("urls") or []) if isinstance(t.get("entities"), dict) else []:
        if isinstance(u, dict) and isinstance(u.get("url"), str) and _https(u.get("expanded_url")):
            text = text.replace(u["url"], u["expanded_url"])
    m = t.get("public_metrics") if isinstance(t.get("public_metrics"), dict) else {}
    stats = " · ".join(f"{label} {int(m[k])}" for k, label in (("like_count", "♥"), ("retweet_count", "⟲"), ("reply_count", "💬"))
                       if isinstance(m.get(k), int))
    return f"<p>{text_to_html(text)}</p>" + (f"<p><small>{stats}</small></p>" if stats else "")


def fetch_x_api(cfg: XSource, feed_id: int) -> Fetched:
    token = x_token()
    if not token:
        raise SourceError("No X API bearer token is configured (Settings → Integrations → X)")
    uid, _name = x_user_id(cfg.username, token)
    params = {"max_results": "20", "tweet.fields": "created_at,entities,public_metrics,note_tweet,referenced_tweets"}
    exclude = [x for x, keep in (("replies", cfg.include_replies), ("retweets", cfg.include_reposts)) if not keep]
    if exclude:
        params["exclude"] = ",".join(exclude)
    since = get_state(f"x_since:{feed_id}")
    if since and since.isdigit():
        params["since_id"] = since
    data = x_api(f"users/{uid}/tweets", params, token)
    entries = []
    for t in data.get("data") or []:
        if not isinstance(t, dict) or not str(t.get("id", "")).isdigit():
            continue
        text = t.get("text") if isinstance(t.get("text"), str) else ""
        entries.append(entry(guid=f"x:status:{t['id']}", title=_title_from(to_text(text, 500), f"Post {t['id']}"),
                             link=f"https://x.com/{cfg.username}/status/{t['id']}", html_body=_tweet_html(t),
                             ts=iso_ts(t.get("created_at")), author=f"@{cfg.username}"))
    out = Fetched(entries=entries, title=f"@{cfg.username} on X", site_url=f"https://x.com/{cfg.username}")
    newest = (data.get("meta") or {}).get("newest_id") if isinstance(data.get("meta"), dict) else None
    if isinstance(newest, str) and newest.isdigit():
        out.state[f"x_since:{feed_id}"] = newest
    return out


# ============================================================================ Telegram (public web preview)
_BG_URL = re.compile(r"url\(['\"]?(https://[^'\")]{1,2000})['\"]?\)")


def parse_tg_page(content: bytes, channel: str) -> tuple[str | None, list[dict], int | None]:
    """Parse t.me/s/<channel>: (channel title, entries, smallest message id on the page)."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(content[:PAGE_LIMIT], "html.parser")
    head = soup.select_one(".tgme_channel_info_header_title")
    title = to_text(head.get_text(" ", strip=True), 300) if head else None
    entries, min_id = [], None
    for msg in soup.select(".tgme_widget_message[data-post]")[:200]:
        post = str(msg.get("data-post") or "")
        m = re.match(r"^([A-Za-z0-9_]{1,64})/(\d{1,12})$", post)
        if not m:
            continue
        mid = int(m.group(2))
        min_id = mid if min_id is None else min(min_id, mid)
        parts = []
        for sel in (".tgme_widget_message_photo_wrap", ".tgme_widget_message_video_thumb"):
            for node in msg.select(sel)[:4]:
                bg = _BG_URL.search(str(node.get("style") or ""))
                if bg and _https(bg.group(1)):
                    parts.append(f'<p><img src="{_attr(bg.group(1))}" alt=""></p>')
        text_node = msg.select_one(".tgme_widget_message_text")
        text = ""
        if text_node:
            parts.append(f"<div>{text_node.decode_contents()}</div>")  # sanitised on insert (drops onclick etc.)
            # Line breaks only where Telegram has <br>; inline emoji/bold markup stays on the same line.
            plain = BeautifulSoup(str(text_node).replace("<br/>", "\n").replace("<br>", "\n"), "html.parser")
            text = plain.get_text("")
        preview = msg.select_one("a.tgme_widget_message_link_preview")
        if preview and _https(preview.get("href")):
            ptitle = preview.select_one(".link_preview_title")
            pdesc = preview.select_one(".link_preview_description")
            parts.append(f'<blockquote><a href="{_attr(_https(preview.get("href")) or "")}">'
                         f'{html.escape(ptitle.get_text(" ", strip=True) if ptitle else preview.get("href"))}</a>'
                         + (f"<br>{html.escape(pdesc.get_text(' ', strip=True)[:500])}" if pdesc else "") + "</blockquote>")
        if not parts:
            continue  # service message / unsupported media only
        views = msg.select_one(".tgme_widget_message_views")
        if views:
            parts.append(f"<p><small>{html.escape(views.get_text(strip=True)[:20])} views</small></p>")
        when = msg.select_one(".tgme_widget_message_date time[datetime]") or msg.select_one("time[datetime]")
        ts = iso_ts(when.get("datetime")) if when else None
        fallback = f"{title or channel} - post {mid}"
        entries.append(entry(guid=f"tg:{channel.lower()}:{mid}", title=_title_from(text, fallback),
                             link=f"https://t.me/{channel}/{mid}", html_body="".join(parts), ts=ts, author=title))
    return title, entries, min_id


def tg_web_page(channel: str, before: int | None = None) -> tuple[str | None, list[dict], int | None]:
    url = f"https://t.me/s/{quote(channel, safe='')}" + (f"?before={int(before)}" if before else "")
    resp = http_get(url, accept="text/html", max_bytes=PAGE_LIMIT)
    if resp.status_code >= 400:
        raise SourceError(f"Telegram answered HTTP {resp.status_code}")
    if not resp.url.startswith("https://t.me/s/"):
        raise SourceError("This channel has no public web preview - connect your Telegram account to follow it")
    return parse_tg_page(resp.content, channel)


def fetch_telegram(cfg: TelegramSource, feed_id: int) -> Fetched:
    if cfg.via == "account":
        from app import telegram_mt

        return telegram_mt.account.fetch(cfg, feed_id)
    assert cfg.channel
    title, entries, _ = tg_web_page(cfg.channel)
    if not entries and not title:
        raise SourceError("This channel has no public web preview - connect your Telegram account to follow it")
    return Fetched(entries=entries, title=title, site_url=f"https://t.me/{cfg.channel}")


# ============================================================================ dispatch
def fetch(feed) -> Fetched:
    try:
        cfg = parse_config(feed["source"])
    except (ValueError, TypeError):
        raise SourceError("Source settings are invalid - edit the feed") from None
    if isinstance(cfg, YouTubeSource):
        return fetch_youtube(cfg, feed["url"])
    if isinstance(cfg, HFPapersSource):
        return fetch_hfpapers(cfg)
    if isinstance(cfg, XSource):
        return fetch_x_api(cfg, feed["id"]) if cfg.via == "api" else fetch_x_bridge(cfg)
    if isinstance(cfg, TelegramSource):
        return fetch_telegram(cfg, feed["id"])
    raise SourceError("Unknown source")


# ============================================================================ input detection
def detect(text: str) -> str | None:
    t = text.strip().lower()
    t = re.sub(r"^https?://", "", t)
    if t.startswith(("t.me/", "telegram.me/", "www.t.me/")):
        return "telegram"
    if t.startswith(("youtube.com/", "www.youtube.com/", "m.youtube.com/", "youtu.be/")) or re.match(CHANNEL_ID, text.strip()):
        return "youtube"
    if t.startswith(("x.com/", "www.x.com/", "twitter.com/", "www.twitter.com/", "mobile.twitter.com/")):
        return "x"
    if t.startswith(("huggingface.co/papers", "hf.co/papers")):
        return "hfpapers"
    return None


def parse_telegram_input(text: str) -> str:
    t = re.sub(r"^https?://", "", text.strip())
    t = re.sub(r"^(?:www\.)?(?:t|telegram)\.me/(?:s/)?", "", t).lstrip("@").split("/")[0].split("?")[0]
    if not re.match(TG_USER, t):
        raise SourceError("That is not a public Telegram channel username or t.me link")
    return t


def parse_x_input(text: str) -> str:
    t = re.sub(r"^https?://", "", text.strip())
    t = re.sub(r"^(?:www\.|mobile\.)?(?:x|twitter)\.com/", "", t).lstrip("@").split("/")[0].split("?")[0]
    if not re.match(X_USER, t) or t.lower() in ("home", "explore", "search", "i", "settings", "notifications", "messages"):
        raise SourceError("That is not an X profile link or @username")
    return t
