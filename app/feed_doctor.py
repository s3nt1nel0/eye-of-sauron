"""Feed troubleshooter: work out *why* a feed fails and look for a working address.

What it does, per feed (a bounded number of requests, all through netguard, honest User-Agent):
  1. DNS: does the host resolve? If not, does the www/non-www twin?
  2. Fetch the feed URL as the fetcher does (no caching headers) and classify the answer.
  3. If that fails: try https:// for http:// feeds, the redirect target, the feed URL without its query.
  4. Look on the site itself: <link rel="alternate"> feeds declared by the home page / blog page, then the
     common feed paths (/feed, /rss.xml, /atom.xml ...). Every candidate is fetched and parsed; only real
     feeds with entries are suggested, newest first.

What it never does: change the User-Agent, solve or bypass bot checks (Cloudflare, Akamai, CAPTCHAs),
or scrape around a block. A 403 behind bot protection is reported as such, with honest options.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app import netguard, scraper
from app.config import get_settings
from app.fetcher import ACCEPT, parse_bytes, xml_guard

PAGE_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5"
MAX_REQUESTS = 14
MAX_SUGGESTIONS = 5
BOT_MARKERS = (b"just a moment", b"attention required", b"cf-browser-verification", b"captcha", b"challenge-platform",
               b"access denied", b"request unsuccessful. incapsula", b"perimeterx", b"datadome")

VERDICTS = {
    "working": "The feed works now - the earlier errors were temporary.",
    "moved": "The feed has moved - a working address was found.",
    "blocked": "The site blocks automated feed readers (bot protection).",
    "not_feed": "The address now returns a web page, not a feed.",
    "gone": "The feed address no longer exists.",
    "dns": "The website's domain no longer resolves - the site is probably gone or renamed.",
    "server": "The website is failing on its side (server error).",
    "network": "The website could not be reached (connection failed or timed out).",
    "unsafe": "The address is not allowed (private, local or reserved network).",
    "broken": "The site answers, but the feed is not valid RSS/Atom.",
}


@dataclass
class Probe:
    url: str
    status: int | None = None
    final_url: str | None = None
    error: str | None = None
    content_type: str = ""
    is_feed: bool = False
    items: int = 0
    newest: int | None = None
    title: str = ""
    bot_wall: bool = False
    html: bytes = b""


@dataclass
class Session:
    budget: int = MAX_REQUESTS
    steps: list[dict] = field(default_factory=list)
    seen: dict[str, Probe] = field(default_factory=dict)

    def step(self, label: str, ok: bool | None, detail: str) -> None:
        self.steps.append({"step": label, "ok": ok, "detail": detail[:300]})


def _newest(parsed) -> int | None:
    best = None
    for entry in parsed.entries[:50]:
        for key in ("published_parsed", "updated_parsed"):
            value = entry.get(key)
            if value:
                try:
                    ts = int(time.mktime(value))
                except (OverflowError, ValueError, TypeError):
                    continue
                best = ts if best is None else max(best, ts)
                break
    return best


def _probe(sess: Session, url: str, accept: str = ACCEPT) -> Probe | None:
    """Fetch once (cached per session, counted against the budget)."""
    if url in sess.seen:
        return sess.seen[url]
    if sess.budget <= 0:
        return None
    sess.budget -= 1
    cfg = get_settings()
    probe = Probe(url=url)
    sess.seen[url] = probe
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": accept},
                                allow_private=cfg.allow_private_feeds, timeout=min(cfg.fetch_timeout, 15),
                                max_bytes=cfg.max_feed_bytes)
    except netguard.UnsafeURLError as exc:
        probe.error = f"unsafe: {exc}"
        return probe
    except netguard.FetchError as exc:
        probe.error = str(exc)[:200]
        return probe
    probe.status, probe.final_url = resp.status_code, resp.url
    probe.content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    head = resp.content[:20_000].lower()
    server = (resp.headers.get("server") or "").lower()
    protected = "cf-ray" in resp.headers or "cloudflare" in server or "akamai" in server or "x-iinfo" in resp.headers
    probe.bot_wall = resp.status_code in (401, 403, 429, 503) and (protected or any(m in head for m in BOT_MARKERS))
    if resp.status_code < 400:
        if not xml_guard(resp.content, resp.headers.get("content-type")):
            parsed = parse_bytes(resp.content, resp.headers.get("content-type"), resp.url)
            if parsed.get("entries") and (parsed.get("version") or not parsed.get("bozo")):
                probe.is_feed, probe.items = True, len(parsed.entries)
                probe.newest = _newest(parsed)
                probe.title = str((parsed.get("feed") or {}).get("title") or "")[:200]
        if not probe.is_feed and ("html" in probe.content_type or head.lstrip().startswith((b"<!doctype html", b"<html"))):
            probe.html = resp.content
    return probe


def _describe(p: Probe) -> str:
    if p.error:
        return p.error
    bits = [f"HTTP {p.status}"]
    if p.final_url and p.final_url.rstrip("/") != p.url.rstrip("/"):
        bits.append(f"redirected to {p.final_url}")
    if p.is_feed:
        bits.append(f"valid feed, {p.items} items")
    elif p.html:
        bits.append("a web page (HTML), not a feed")
    elif p.content_type:
        bits.append(p.content_type)
    if p.bot_wall:
        bits.append("bot protection detected")
    return ", ".join(bits)


def _twin_host(url: str) -> str | None:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or netguard._ip_literal(host) is not None:  # noqa: SLF001 - same package helper
        return None
    twin = host[4:] if host.startswith("www.") else f"www.{host}"
    netloc = twin if parts.port is None else f"{twin}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def _resolves(url: str) -> tuple[bool, str]:
    parts = urlsplit(url)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        netguard.resolve_host(parts.hostname or "", port,
                              netguard.private_ok(parts.hostname or "", port, get_settings().allow_private_feeds))
        return True, "resolves"
    except netguard.UnsafeURLError as exc:
        return False, f"unsafe: {exc}"
    except netguard.FetchError as exc:
        return False, str(exc)


def _site_pages(feed_url: str, site_url: str | None) -> list[str]:
    parts = urlsplit(feed_url)
    root = f"{parts.scheme}://{parts.netloc}/"
    pages = []
    if site_url:
        pages.append(site_url)
    path = parts.path.rstrip("/")
    for marker in ("/feed", "/rss", "/atom", "/feeds"):
        if marker in path:  # https://site/blog/feed/ -> https://site/blog/
            pages.append(f"{parts.scheme}://{parts.netloc}{path[: path.index(marker)]}/")
            break
    pages.append(root)
    https_root = f"https://{parts.netloc}/"
    if parts.scheme == "http":
        pages.insert(0, https_root)
    return list(dict.fromkeys(pages))


def _alternatives(feed_url: str) -> list[str]:
    parts = urlsplit(feed_url)
    out = []
    if parts.scheme == "http":
        out.append(urlunsplit(("https", parts.netloc, parts.path, parts.query, "")))
    if parts.query:
        out.append(urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
    return out


def diagnose(feed: dict) -> dict:
    """feed: {"id", "url", "site_url", "kind", "last_error", "error_count"} -> report dict."""
    url = feed["url"]
    sess = Session()
    suggestions: dict[str, Probe] = {}

    origin: dict[str, str] = {}

    def consider(p: Probe | None, how: str = "alternative") -> None:
        if p and p.is_feed and (p.final_url or p.url).rstrip("/") != url.rstrip("/"):
            suggestions.setdefault(p.final_url or p.url, p)
            origin.setdefault(p.final_url or p.url, how)

    if (feed.get("kind") or "rss") not in ("rss",):
        return {"feed_id": feed["id"], "verdict": "skipped", "summary": "Only RSS/Atom feeds can be checked here - "
                "open the feed's settings to re-test its scraping rules or source.", "steps": [], "suggestions": [],
                "advice": []}

    ok_dns, dns_detail = _resolves(url)
    sess.step("DNS lookup", ok_dns, f"{urlsplit(url).hostname}: {dns_detail}")
    if not ok_dns and dns_detail.startswith("unsafe"):
        return _report(feed, "unsafe", sess, [], ["Edit the feed's address - it points at a blocked network."])
    first = None
    if ok_dns:
        first = _probe(sess, url)
        sess.step("Fetch the feed address", bool(first and first.is_feed), _describe(first) if first else "skipped")
        if first and first.is_feed:
            if first.final_url and first.final_url.rstrip("/") != url.rstrip("/"):
                consider(first, "redirect")
                return _report(feed, "moved", sess, list(suggestions.values()), origin=origin, advice=
                               ["The old address redirects to the new one. Switching to the new address avoids the redirect."])
            return _report(feed, "working", sess, [], ["Reset the error counter and fetch it again now."])

    candidates = _alternatives(url)
    if not ok_dns:
        twin = _twin_host(url)
        if twin and _resolves(twin)[0]:
            sess.step("Try the www/non-www twin", True, f"{urlsplit(twin).hostname} resolves")
            candidates.insert(0, twin)
        else:
            sess.step("Try the www/non-www twin", False, "does not resolve either" if twin else "not applicable")
    for alt in candidates:
        p = _probe(sess, alt)
        if p is not None:
            sess.step(f"Try {alt}", p.is_feed, _describe(p))
            consider(p)

    # Look on the site: declared feeds first, then the usual paths.
    if not suggestions:
        bases = _site_pages(candidates[0] if not ok_dns and candidates else url, feed.get("site_url"))
        moved_to = first.final_url if first and first.final_url else None
        if moved_to and urlsplit(moved_to).netloc != urlsplit(url).netloc:
            # The old address redirects to another site (rebrand, acquisition): look there first.
            bases = list(dict.fromkeys([moved_to, *_site_pages(moved_to, None), *bases]))
        guesses: list[str] = []
        for page in bases[:4]:
            p = _probe(sess, page, PAGE_ACCEPT)
            if p is None:
                break
            declared = scraper.feed_links(p.html, p.final_url or page) if p.html else []
            sess.step(f"Look for feeds on {page}", bool(declared),
                      f"{_describe(p)}; declares {len(declared)} feed(s)" if not p.error else p.error)
            for cand in declared:
                c = _probe(sess, cand["url"])
                if c is not None:
                    consider(c, "declared")
            if p.status and p.status < 400:
                here = (p.final_url or page).split("?")[0].rstrip("/")
                if urlsplit(here).path:  # a section page (/blog): its own /feed first, then the site's
                    guesses += [here + tail for tail in ("/feed/", "/rss.xml", "/feed.xml", "/atom.xml", "/index.xml")]
                guesses += scraper.same_site_guesses(p.final_url or page)
            if suggestions:
                break
        if not suggestions:
            tried = 0
            for guess in dict.fromkeys(guesses):
                if sess.budget <= 0 or tried >= 8:
                    break
                c = _probe(sess, guess)
                tried += 1
                consider(c, "guess")
            sess.step("Try common feed paths", bool(suggestions), f"{tried} tried, {len(suggestions)} working")

    found = sorted(suggestions.values(), key=lambda p: (p.newest or 0, p.items), reverse=True)[:MAX_SUGGESTIONS]
    if found:
        return _report(feed, "moved", sess, found, origin=origin, advice=["Pick the working address to switch the feed to it - "
                                                     "its articles are kept."])
    if not ok_dns:
        return _report(feed, "dns", sess, [], [
            "If the publisher renamed its site, search for its new feed and edit the address.",
            "Otherwise disable or delete the feed."])
    if first is None or first.error:
        err = (first.error if first else "") or ""
        if err.startswith("unsafe"):
            return _report(feed, "unsafe", sess, [], ["Edit the feed's address - it points at a blocked network."])
        return _report(feed, "network", sess, [], [
            "This can be temporary - try again later.",
            "If it keeps failing for days, the site may be gone: disable or delete the feed."])
    if first.bot_wall or first.status in (401, 403, 429):
        return _report(feed, "blocked", sess, [], [
            "Eye of Sauron does not disguise itself or get around bot checks, so this feed can't be fetched as is.",
            "Look for the same content another way: the publisher's newsletter, a mirror (e.g. their posts "
            "syndicated elsewhere), or another source covering it.",
            "If you run the site, allow-list this reader's User-Agent. Otherwise disable the feed."])
    if first.status in (404, 410):
        return _report(feed, "gone", sess, [], [
            "The site no longer publishes a feed at this address and none was found on the site.",
            "If the site has a news page without a feed, add it as a website (scraping) source instead.",
            "Otherwise disable or delete the feed."])
    if first.status and first.status >= 500:
        return _report(feed, "server", sess, [], ["Usually temporary - try again later. If it lasts for weeks, "
                                                  "disable the feed."])
    if first.html:
        return _report(feed, "not_feed", sess, [], [
            "The site stopped offering this feed. Add the page as a website (scraping) source if you still want it.",
            "Otherwise disable or delete the feed."])
    return _report(feed, "broken", sess, [], ["The publisher's feed is malformed. Try again later, or disable it."])


def _report(feed: dict, verdict: str, sess: Session, found: list[Probe], advice: list[str],
            origin: dict[str, str] | None = None) -> dict:
    return {
        "feed_id": feed["id"], "url": feed["url"], "verdict": verdict, "summary": VERDICTS[verdict],
        "steps": sess.steps, "advice": advice, "requests": MAX_REQUESTS - sess.budget,
        # how: redirect (the old address forwards there) | declared (the site's own page links it) |
        # alternative (https / no query) | guess (a common path on the site - may be a site-wide feed)
        "suggestions": [{"url": p.final_url or p.url, "title": p.title, "items": p.items, "newest": p.newest,
                         "how": (origin or {}).get(p.final_url or p.url, "alternative")} for p in found],
    }


# ------------------------------------------------------------------ background job (many feeds)
class DoctorJob:
    """One troubleshooting run over many feeds at a time; results stay in memory for the UI."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.state: dict = {"running": False, "total": 0, "done": 0, "results": [], "started": None, "finished": None}

    def start(self, feeds: list[dict]) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            self._stop.clear()
            self.state = {"running": True, "total": len(feeds), "done": 0, "results": [], "started": int(time.time()),
                          "finished": None, "current": None}
        threading.Thread(target=self._run, args=(feeds,), name="feed-doctor", daemon=True).start()
        return True

    def cancel(self) -> None:
        self._stop.set()

    def _run(self, feeds: list[dict]) -> None:
        try:
            for feed in feeds:
                if self._stop.is_set():
                    break
                self.state["current"] = feed.get("title") or feed["url"]
                try:
                    report = diagnose(feed)
                except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the run
                    report = {"feed_id": feed["id"], "url": feed["url"], "verdict": "network",
                              "summary": f"Check failed: {type(exc).__name__}", "steps": [], "advice": [],
                              "suggestions": []}
                report["title"] = feed.get("title") or ""
                self.state["results"].append(report)
                self.state["done"] += 1
                time.sleep(0.5)  # be polite: never hammer many sites back to back
        finally:
            self.state["running"] = False
            self.state["current"] = None
            self.state["finished"] = int(time.time())


doctor = DoctorJob()
