"""Images served from our own origin: the reader's image proxy and each feed's site icon.

Image proxy
-----------
With ``image_proxy`` on, ``<img>`` addresses in the reader are rewritten to ``/api/v1/img?u=<url>&s=<sig>`` so
publishers (and their trackers) see this server, not the reader's IP address. The proxy is not an open relay:

* only addresses this server signed (HMAC with a per-process random key) are fetched - a signed URL is valid until
  the server restarts, after which the reader simply asks for the article again;
* fetching goes through ``netguard`` (SSRF guard: no private / loopback / link-local targets, pinned DNS, size cap,
  timeout, at most 3 redirects, each re-checked);
* only raster images are passed on, recognised by their **bytes** (PNG, JPEG, GIF, WebP, AVIF, BMP, ICO) - never SVG
  or anything that could run script - and served with the type we detected, ``nosniff`` and a sandbox CSP;
* the endpoint needs a signed-in session or a read token, like every other API route.

Site icons
----------
``feed_icons`` caches one small icon per feed (the page's ``<link rel="icon">`` or ``/favicon.ico``), fetched in the
background through ``netguard`` and checked the same way. Missing icons are retried after a month.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import re
import secrets
import threading
import time
from urllib.parse import quote, urljoin, urlsplit

from app import netguard
from app.config import get_settings
from app.db import get_db, now

log = logging.getLogger("eos.media")

_KEY = secrets.token_bytes(32)
PROXY_PATH = "/api/v1/img"
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_ICON_BYTES = 200 * 1024
ICON_RETRY = 30 * 86400
ICON_REFRESH = 90 * 86400
_IMG_SRC = re.compile(r'(<img\b[^>]*?\ssrc=")([^"]{1,4000})(")', re.IGNORECASE)
_ICON_LINK = re.compile(rb"<link\b[^>]{0,400}>", re.IGNORECASE)
_REL = re.compile(rb"""\brel\s*=\s*["']?([^"'>]{1,80})""", re.IGNORECASE)
_HREF = re.compile(rb"""\bhref\s*=\s*["']?([^"'\s>]{1,1000})""", re.IGNORECASE)
_SIZES = re.compile(rb"""\bsizes\s*=\s*["']?(\d{1,4})x\d{1,4}""", re.IGNORECASE)


class MediaError(Exception):
    pass


# ============================================================================ type detection (bytes, not headers)
def sniff(data: bytes) -> str | None:
    """The image type of these bytes, or None if they are not a raster image we pass on."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:12] in (b"ftypavif", b"ftypavis"):
        return "image/avif"
    if data.startswith(b"BM") and len(data) > 26:
        return "image/bmp"
    if data.startswith(b"\x00\x00\x01\x00") and len(data) > 22:
        return "image/x-icon"
    return None


# ============================================================================ image proxy
def sign(url: str) -> str:
    return hmac.new(_KEY, url.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify(url: str, sig: str) -> bool:
    return hmac.compare_digest(sign(url), sig or "")


def proxied(url: str) -> str:
    return f"{PROXY_PATH}?u={quote(url, safe='')}&s={sign(url)}"


def rewrite_images(sanitized_html: str) -> str:
    """Point every http(s) <img src> of already-sanitised HTML at the image proxy."""
    def swap(m: re.Match) -> str:
        url = html.unescape(m.group(2))
        if not url.lower().startswith(("https://", "http://")):
            return m.group(0)
        return m.group(1) + html.escape(proxied(url), quote=True) + m.group(3)

    return _IMG_SRC.sub(swap, sanitized_html or "")


def fetch_image(url: str, max_bytes: int = MAX_IMAGE_BYTES) -> tuple[bytes, str]:
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": "image/avif,image/webp,image/png,image/*;q=0.8"},
                                timeout=15, max_bytes=max_bytes, max_redirects=3)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise MediaError(str(exc)) from None
    if resp.status_code != 200:
        raise MediaError(f"HTTP {resp.status_code}")
    mime = sniff(resp.content)
    if mime is None:
        raise MediaError("Not a supported image")
    return resp.content, mime


# ============================================================================ site icons
def _candidates(page_url: str, body: bytes) -> list[str]:
    found: list[tuple[int, str]] = []
    for tag in _ICON_LINK.findall(body[:300_000]):
        rel = _REL.search(tag)
        href = _HREF.search(tag)
        if not rel or not href:
            continue
        rels = rel.group(1).lower().split()
        if not ({b"icon", b"apple-touch-icon"} & set(rels)):
            continue
        link = html.unescape(href.group(1).decode("utf-8", "replace"))
        if link.lower().endswith(".svg") or link.startswith("data:"):
            continue  # SVG is never served; data: URLs are not fetched
        size = int(_SIZES.search(tag).group(1)) if _SIZES.search(tag) else (180 if b"apple-touch-icon" in rels else 32)
        found.append((abs(size - 48), urljoin(page_url, link)))  # closest to 48 px first (crisp at 16-24 px, still small)
    return [u for _, u in sorted(found)][:4]


def find_icon(site: str) -> tuple[bytes, str] | None:
    cfg = get_settings()
    parts = urlsplit(site)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    home = f"{parts.scheme}://{parts.netloc}/"
    tries: list[str] = []
    try:
        resp = netguard.request("GET", site, headers={"User-Agent": cfg.user_agent, "Accept": "text/html"}, timeout=15,
                                max_bytes=1024 * 1024, max_redirects=3)
        if resp.status_code == 200:
            tries += _candidates(resp.url, resp.content)
    except (netguard.FetchError, netguard.UnsafeURLError):
        pass
    tries.append(urljoin(home, "/favicon.ico"))
    for url in dict.fromkeys(tries):
        try:
            data, mime = fetch_image(url, MAX_ICON_BYTES)
            return data, mime
        except MediaError:
            continue
    return None


def icon_site(feed) -> str | None:
    """The page to take a feed's icon from (its website, else the feed's own host)."""
    if feed["kind"] in ("email", "telegram", "x", "hfpapers"):
        return None
    for value in (feed["site_url"], feed["url"]):
        if value and str(value).startswith(("https://", "http://")) and ".invalid/" not in str(value):
            return str(value)
    return None


def refresh_icons(limit: int = 40) -> int:
    """Fetch icons for feeds that have none (or a stale one). Returns how many were stored."""
    ts = now()
    with get_db() as db:
        feeds = db.execute(
            "SELECT f.id, f.kind, f.url, f.site_url FROM feeds f LEFT JOIN feed_icons i ON i.feed_id = f.id "
            "WHERE f.enabled = 1 AND COALESCE(f.kind, 'rss') IN ('rss', 'html', 'json', 'podcast') "
            "AND (i.feed_id IS NULL OR (i.data IS NULL AND i.fetched_at < ?) OR i.fetched_at < ?) "
            "ORDER BY i.fetched_at IS NOT NULL, f.id LIMIT ?",
            (ts - ICON_RETRY, ts - ICON_REFRESH, limit),
        ).fetchall()
    stored = 0
    by_host: dict[str, tuple[bytes, str] | None] = {}
    for feed in feeds:
        site = icon_site(feed)
        host = urlsplit(site).netloc.lower() if site else ""
        if host and host not in by_host:
            try:
                by_host[host] = find_icon(site)
            except Exception:  # noqa: BLE001 - one bad site never stops the others
                log.debug("Icon lookup failed for feed %d", feed["id"], exc_info=True)
                by_host[host] = None
        got = by_host.get(host) if host else None
        with get_db() as db:
            db.execute("INSERT INTO feed_icons (feed_id, mime, data, fetched_at) VALUES (?, ?, ?, ?) "
                       "ON CONFLICT(feed_id) DO UPDATE SET mime = excluded.mime, data = excluded.data, fetched_at = excluded.fetched_at",
                       (feed["id"], got[1] if got else None, got[0] if got else None, now()))
        stored += bool(got)
    return stored


class IconWorker:
    """Fills missing icons in the background (once at start-up, then every few hours)."""

    INTERVAL = 6 * 3600

    def __init__(self) -> None:
        self._last = 0.0
        self._lock = threading.Lock()

    def maybe_start(self) -> None:
        if time.monotonic() - self._last < self.INTERVAL and self._last:
            return
        if not self._lock.acquire(blocking=False):
            return
        self._last = time.monotonic()

        def run() -> None:
            try:
                while refresh_icons(40) or self._more():
                    time.sleep(2)
            except Exception:  # noqa: BLE001
                log.exception("Site icons: background refresh failed")
            finally:
                self._lock.release()

        threading.Thread(target=run, name="site-icons", daemon=True).start()

    @staticmethod
    def _more() -> bool:
        with get_db() as db:
            return db.execute(
                "SELECT 1 FROM feeds f LEFT JOIN feed_icons i ON i.feed_id = f.id WHERE f.enabled = 1 "
                "AND COALESCE(f.kind, 'rss') IN ('rss', 'html', 'json', 'podcast') AND i.feed_id IS NULL LIMIT 1").fetchone() is not None


icons = IconWorker()
