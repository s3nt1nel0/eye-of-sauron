"""Full article text for feeds that only publish a summary (one or two sentences).

When an item's text is short, the article page is fetched once and its main content is extracted:
  1. schema.org JSON-LD `articleBody` when the page provides it;
  2. otherwise the element holding most of the paragraph text (<article>, [itemprop=articleBody], common
     content classes, or the parent with the densest paragraphs), minus navigation, ads, share bars, comments.
The result goes through the same HTML sanitiser as feed content.

Honest client only: the normal User-Agent, netguard (SSRF policy, size and time caps), one request per site
every few seconds, and a site that answers 401/403/429 or shows a bot check is left alone for a while - the
summary stays and the reader offers the original link. Nothing is bypassed or disguised.
"""

from __future__ import annotations

import json
from html import escape
import logging
import queue
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Tag

from app import netguard
from app.config import get_settings
from app.db import get_db
from app.sanitize import sanitize_html, to_text

log = logging.getLogger("eos.fulltext")

SHORT_TEXT = 700            # items with less plain text than this are summaries
MIN_GAIN = 400              # extracted text must be at least this long, and clearly longer than the summary
MAX_PAGE = 5 * 1024 * 1024
PER_HOST_GAP = 3.0          # seconds between requests to the same site
BLOCK_FOR = 6 * 3600        # a site that refused us is left alone this long
PAGE_ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"
NOISE = re.compile(r"(^|[-_ ])(ad|ads|advert|promo|sponsor|related|recommend|newsletter|subscribe|signup|share|social|"
                   r"comment|comments|cookie|consent|sidebar|breadcrumb|popup|modal|paywall|outbrain|taboola|"
                   r"author-bio|byline-share|tags|tag-list|read-more|more-stories|trending)([-_ ]|$)", re.I)
CONTENT_HINT = ("[itemprop=articleBody]", "article", ".entry-content", ".post-content", ".article-content", ".article-body",
                ".article__body", ".article__content", ".story-body", ".post-body", ".content-body", ".rich-text",
                ".post__content", "main")
BOT_MARKERS = (b"just a moment", b"attention required", b"captcha", b"cf-browser-verification", b"challenge-platform",
               b"enable javascript and cookies")


class Blocked(Exception):
    pass


def _json_ld_body(soup: BeautifulSoup) -> str | None:
    for script in soup.find_all("script", type="application/ld+json", limit=20):
        try:
            data = json.loads(script.string or "")
        except (ValueError, TypeError):
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                body = item.get("articleBody")
                if isinstance(body, str) and len(body) >= MIN_GAIN:
                    return body
                stack.extend(v for v in item.values() if isinstance(v, (list, dict)))
            elif isinstance(item, list):
                stack.extend(item)
    return None


def _holds_article(node: Tag) -> bool:
    """True when the element contains several real paragraphs (so it is a wrapper, not a widget)."""
    count = 0
    for p in node.find_all("p", limit=200):
        if len(p.get_text(" ", strip=True)) >= 60:
            count += 1
            if count >= 3:
                return True
    return False


def _clean(node: Tag, base_url: str) -> None:
    for t in node.find_all(["script", "style", "noscript", "nav", "header", "footer", "aside", "form", "iframe", "svg",
                            "button", "input", "select", "template"]):
        t.decompose()
    for t in node.find_all(True):
        if t.attrs is None:
            continue
        ident = " ".join([*(t.get("class") or []), t.get("id") or "", t.get("role") or ""])
        if ident and NOISE.search(ident) and t.name not in ("article", "main", "body") and not _holds_article(t):
            # e.g. a share bar or "related posts" box - but never a wrapper like "content sidebar-enabled"
            # that holds the story's paragraphs
            t.decompose()
            continue
        if t.name == "img":  # lazy-loaded images
            src = t.get("src") or ""
            lazy = t.get("data-src") or t.get("data-lazy-src") or t.get("data-original")
            if lazy and (not src or src.startswith("data:")):
                t["src"] = lazy
            if t.get("src"):
                t["src"] = urljoin(base_url, t["src"])
        elif t.name == "a" and t.get("href"):
            t["href"] = urljoin(base_url, t["href"])


def _score(node: Tag) -> float:
    paras = [p.get_text(" ", strip=True) for p in node.find_all("p")]
    text = sum(len(p) for p in paras if len(p) >= 40)
    links = sum(len(a.get_text(" ", strip=True)) for a in node.find_all("a"))
    total = max(1, len(node.get_text(" ", strip=True)))
    return text * (1 - min(0.9, links / total))


def _para_text(node: Tag) -> int:
    return sum(len(t) for t in (p.get_text(" ", strip=True) for p in node.find_all("p")) if len(t) >= 40)


def _narrow(best: Tag) -> Tag:
    """The scored winner is often a page wrapper that also holds the site's menus, "featured posts" and footers.
    Step down to the smallest block that still holds nearly all of the story's paragraph text."""
    total = _para_text(best)
    if total < MIN_GAIN:
        return best
    chosen, chosen_len = best, len(best.get_text(" ", strip=True))
    for node in best.find_all(["div", "section", "article", "main"], limit=4000):
        if not _holds_article(node):
            continue
        size = len(node.get_text(" ", strip=True))
        if size < chosen_len and _para_text(node) >= 0.85 * total:
            chosen, chosen_len = node, size
    return chosen


def _drop_link_lists(node: Tag) -> None:
    """Menus and "related posts" grids inside the story block: lists / tables that are mostly links and carry images
    or nested lists (a list of references - plain links - is kept)."""
    for lst in node.find_all(["ul", "ol", "dl", "table"]):
        if lst.decomposed:
            continue
        text = len(lst.get_text(" ", strip=True)) or 1
        links = sum(len(a.get_text(" ", strip=True)) for a in lst.find_all("a"))
        if links / text > 0.6 and len(lst.find_all("a")) >= 3 and (lst.find("img") is not None or lst.find(["ul", "ol", "dl"]) is not None):
            lst.decompose()


def extract(content: bytes, base_url: str) -> str | None:
    """Main article HTML (sanitised), or None when no substantial body is found."""
    soup = BeautifulSoup(content[:MAX_PAGE], "html.parser")
    body = _json_ld_body(soup)
    if body:
        paras = [p.strip() for p in re.split(r"\n\s*\n|\r\n\r\n", body) if p.strip()]
        out = sanitize_html("".join(f"<p>{escape(p)}</p>" for p in (paras or [body])))
        return out if len(to_text(out)) >= MIN_GAIN else None
    root = soup.body or soup
    _clean(root, base_url)
    candidates: list[Tag] = []
    for sel in CONTENT_HINT:
        try:
            candidates += [c for c in root.select(sel, limit=10) if isinstance(c, Tag)]
        except Exception:  # noqa: BLE001 - selector support varies
            continue
    for p in root.find_all("p", limit=2000):  # readability-style: parents of the real paragraphs
        if len(p.get_text(" ", strip=True)) >= 60 and isinstance(p.parent, Tag):
            candidates.append(p.parent)
            if isinstance(p.parent.parent, Tag):
                candidates.append(p.parent.parent)
    if not candidates:
        return None
    best = max(dict.fromkeys(candidates), key=_score)
    if _score(best) < MIN_GAIN:
        return None
    best = _narrow(best)
    _drop_link_lists(best)
    out = sanitize_html(str(best))
    return out if len(to_text(out)) >= MIN_GAIN else None


def fetch_page(url: str) -> bytes:
    cfg = get_settings()
    resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": PAGE_ACCEPT},
                            allow_private=cfg.allow_private_feeds, timeout=min(cfg.fetch_timeout, 20), max_bytes=MAX_PAGE)
    head = resp.content[:20000].lower()
    if resp.status_code in (401, 403, 429) or (resp.status_code == 503 and any(m in head for m in BOT_MARKERS)):
        raise Blocked(f"HTTP {resp.status_code}")
    if resp.status_code >= 400:
        raise netguard.FetchError(f"HTTP {resp.status_code}")
    if any(m in head for m in BOT_MARKERS) and len(resp.content) < 60000:
        raise Blocked("bot check page")
    ctype = (resp.headers.get("content-type") or "").lower()
    if "html" not in ctype and not head.lstrip().startswith((b"<!doctype html", b"<html")):
        raise netguard.FetchError("not a web page")
    return resp.content


def wants_full_text(feed_mode: str | None, text_len: int) -> bool:
    mode = feed_mode or "auto"
    return mode == "always" or (mode == "auto" and text_len < SHORT_TEXT)


# ------------------------------------------------------------------ apply to an article
def fill_article(article_id: int, force: bool = False) -> dict:
    """Fetch and store the full text of one article. Returns {"ok", "reason"?, "length"?}."""
    with get_db() as db:
        row = db.execute("SELECT a.id, a.feed_id, a.url, a.text_content, a.fulltext, f.full_text, f.kind, f.social_platform "
                         "FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id = ?", (article_id,)).fetchone()
    if row is None:
        return {"ok": False, "reason": "not found"}
    if row["kind"] not in (None, "rss", "html") or row["social_platform"]:
        return {"ok": False, "reason": "not a web article"}
    url = row["url"] or ""
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "reason": "no article link"}
    if not force and row["fulltext"] is not None:
        return {"ok": row["fulltext"] == 1, "reason": "already tried"}
    host = (urlsplit(url).hostname or "").lower()
    if _limiter.blocked(host):
        return {"ok": False, "reason": "the site refuses automated readers right now"}
    _limiter.wait(host)
    try:
        html = extract(fetch_page(url), url)
    except Blocked as exc:
        _limiter.block(host)
        _mark(article_id, -1)
        return {"ok": False, "reason": f"the site refuses automated readers ({exc})"}
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        _mark(article_id, -1)
        return {"ok": False, "reason": str(exc)[:120]}
    if html:
        from app import declutter

        with get_db() as db:
            html = declutter.clean_page(db, row["feed_id"], url, html)
    old = len(row["text_content"] or "")
    text = to_text(html) if html else ""
    # a forced re-read may come out SHORTER: the old text could be a whole page wrapper (menus, featured posts)
    if not html or len(text) < (MIN_GAIN if force else max(MIN_GAIN, int(old * 1.3))):
        _mark(article_id, -1)
        return {"ok": False, "reason": "no longer text found on the page"}
    with get_db() as db:
        db.execute("UPDATE articles SET content_html = ?, text_content = ?, fulltext = 1 WHERE id = ?", (html, text, article_id))
        from app import topics
        from app.entities import extract_for_articles
        from app.rules import apply_rules

        extract_for_articles(db, [article_id])
        from app import ttp_filing, ttp_subs

        ttp_subs.assign(db, [article_id])
        ttp_filing.file(db, [article_id])
        topics.classify(db, [article_id])
        apply_rules(db, [article_id])  # tags/stars only: webhooks and alerts already ran when the item arrived
    return {"ok": True, "length": len(text)}


def _mark(article_id: int, value: int) -> None:
    with get_db() as db:
        db.execute("UPDATE articles SET fulltext = ? WHERE id = ?", (value, article_id))


class _Limiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}
        self._blocked: dict[str, float] = {}

    def wait(self, host: str) -> None:
        with self._lock:
            gap = self._last.get(host, 0) + PER_HOST_GAP - time.monotonic()
            self._last[host] = time.monotonic() + max(0.0, gap)
        if gap > 0:
            time.sleep(gap)

    def block(self, host: str) -> None:
        with self._lock:
            self._blocked[host] = time.monotonic() + BLOCK_FOR

    def blocked(self, host: str) -> bool:
        with self._lock:
            return self._blocked.get(host, 0) > time.monotonic()


_limiter = _Limiter()


class FullTextQueue:
    """Background worker: new short items are filled in one by one (never blocks feed fetching)."""

    def __init__(self) -> None:
        self._q: queue.Queue[int] = queue.Queue(maxsize=5000)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def add(self, article_ids: list[int]) -> None:
        for aid in article_ids:
            try:
                self._q.put_nowait(aid)
            except queue.Full:
                break
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="fulltext", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                aid = self._q.get(timeout=30)
            except queue.Empty:
                return
            try:
                fill_article(aid)
            except Exception:  # noqa: BLE001 - one bad page must not stop the worker
                log.exception("Full text failed for article %s", aid)


fulltext_queue = FullTextQueue()


def queue_new(db, feed, article_ids: list[int]) -> None:
    """Called after a fetch: queue the new items of this feed whose text is only a summary."""
    if not article_ids or (feed["kind"] or "rss") not in ("rss", "html") or feed["social_platform"]:
        return
    mode = feed["full_text"] if "full_text" in feed.keys() else None
    if mode == "never":
        return
    rows = db.execute(f"SELECT id, length(text_content) FROM articles WHERE id IN ({','.join('?' * len(article_ids))})",  # nosec B608
                      article_ids).fetchall()
    todo = [r[0] for r in rows if wants_full_text(mode, r[1] or 0)]
    if todo:
        fulltext_queue.add(todo)

