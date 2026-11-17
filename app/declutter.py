"""Remove ads and site promotion from article bodies, so the reader shows the article only.

Publishers put promotion into the feed text itself (and it is on the article page that "full text" reads):
sponsor lines, "follow us" / newsletter boxes, "Buy now" links, "The post … appeared first on …" footers,
tracking pixels. Three layers, all local (no request is made):

  1. fixed rules  - short blocks that are a feed footer, a follow / subscribe line, a call-to-action link,
                    a sponsor label, or an image / link served by an ad network;
  2. learned      - a short block with a link that repeats across many articles of the SAME feed and either
                    reads like promotion or links to another site through a campaign link / in a large share
                    of the feed's articles (per-feed counts in ``feed_blocks``);
  3. tail         - at the end of an article: repeated blocks after promotion go too, and so do the few
                    repeated blocks leading up to a call-to-action (the heading and sales lines of a
                    multi-part ad).

Deliberately conservative: only short blocks, never a block holding the story's paragraphs, and repeated text
without a link or a promotion cue (a vendor's standing advice, "Relevant CWE: …" lines, a legal notice) is kept.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
import threading
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, NavigableString, Tag

from app.cve_sync import get_state, set_state
from app.db import get_db, now, placeholders
from app.sanitize import to_text

log = logging.getLogger("eos.declutter")

REV = "1"
MAX_BLOCK = 400            # only blocks with less text than this are ever removed
TAIL_BLOCKS = 8            # the last blocks of an article are counted even without a link
MAX_TAGS = 20000           # markup with more elements than this is left as it is (cost guard)
MAX_SIGS = 40              # counted blocks per article
MIN_REPEAT = 3             # a block is "repeated" when this many articles of the feed carry it…
MIN_SHARE = 0.02           # …and at least this share of the feed's counted articles
BIG_SHARE = 0.30           # an outside link without campaign parameters must be in this share of the articles
TAIL_BACK = 4              # repeated blocks removed before a closing call-to-action
WINDOW = 400               # counted articles per feed before the counts are halved (old campaigns fade)
TOTAL = "*"                # feed_blocks row holding the number of counted articles
ELIGIBLE = "COALESCE(f.kind, 'rss') IN ('rss', 'html') AND f.social_platform IS NULL"  # fixed SQL fragment

BLOCK_TAGS = ("p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "figure", "blockquote", "section", "table", "ul", "ol",
              "dl", "pre", "details")
EMPTY_OK = ("img", "br", "hr", "td", "th", "tr", "tbody", "thead", "tfoot", "table", "pre", "code")
AD_HOSTS = ("doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com", "amazon-adsystem.com",
            "taboola.com", "outbrain.com", "adnxs.com", "criteo.com", "criteo.net", "zemanta.com", "revcontent.com", "mgid.com",
            "buysellads.com", "carbonads.net", "carbonads.com", "pubmatic.com", "rubiconproject.com", "moatads.com",
            "scorecardresearch.com", "pixel.wp.com", "stats.wordpress.com", "feedads.g.doubleclick.net", "adsrvr.org",
            "quantserve.com", "openx.net")
AFFILIATE_HOSTS = ("amzn.to", "shareasale.com", "awin1.com", "anrdoezrs.net", "jdoqocy.com", "tkqlhce.com", "dpbolvw.net",
                   "kqzyfj.com", "go.redirectingat.com", "go.skimresources.com", "howl.me", "pntra.com", "sjv.io", "linksynergy.com")
CAMPAIGN = re.compile(r"(^|[?&#;])(utm_[a-z]+|aff(iliate)?(_?id)?|ref(errer|_?id|src)?|campaign(_?id)?|sponsor\w*|partner(_?id)?|"
                      r"clickid|irclickid|cid|tag|mc_cid|promo(code)?|coupon)=", re.I)
SOCIAL = r"(twitter|x|linkedin|facebook|instagram|mastodon|bluesky|telegram|whatsapp|google news|youtube|tiktok|threads|discord|reddit)"

# a block whose whole text is one of these
FOOTER = re.compile(
    r"^(the post .{0,300} (appeared first|first appeared) on .{0,160}"
    r"|this (article|post|story),? .{0,300} (first appeared|appeared first|originally appeared|was originally published) (on|in|at) .{0,160}"
    r"|(read|view|see) (the )?(full|whole|entire|original|rest of the) (article|story|post)( (at|on) .{0,80})?"
    r"|continue reading( .{0,120})?|comments|discuss this article.{0,60}"
    r"|(advertisement|advertisements|sponsored( content| post| link)?|partner content|paid post|promoted( content)?)"
    r"|(sponsored by|presented by|brought to you by|in partnership with) .{0,80})[\s.:»→>…]*$", re.I | re.S)
# a short block that contains one of these
PROMO = re.compile(
    rf"follow (me|us|[\w@.' -]{{1,40}}) (on|at|via) {SOCIAL}\b"
    r"|(subscribe to|sign up (for|to)|join) (our|the|my) .{0,60}(newsletter|channel|mailing list|community|podcast)"
    r"|subscribe (today|now)[\s.!]*$|^join [\d.,+k ]+ ?(readers|subscribers|professionals)"
    r"|create an account to save|sign up here|(delivered|straight|directly|stories like this) (to|in) your inbox"
    r"|as a preferred source|\(buy now\)|^buyer'?s guide:|\b(buy now|shop now|order now)[\s!.→»]*$"
    r"|get notified about new (publications|posts|articles)", re.I | re.S)
# a block that is nothing but a link saying this
CTA = re.compile(
    r"^(try (it |now )?(for )?free|start (your |a )?free trial|free trial|(book|request|get|schedule) a (free )?demo"
    r"|register (now|here|today)( for free)?|sign up( now| today| for free| free)?|subscribe( now| today)?"
    r"|buy now|shop now|order now|contact sales|talk to (sales|an expert)|see pricing|join (now|today|the waitlist))[\s!.:»→>…]*$", re.I)
# …or this, but only when the feed repeats it (once, it may be the article's own link)
CTA_SOFT = re.compile(
    r"^(get started( for free| free| now| today)?|download (the|our|your|now|free)( [\w-]+){0,4}|learn more( about [\w .&-]{1,60})?"
    r"|click here|watch (the )?(webinar|demo|video)|read (their|the|our) review|find out more|see how|get the (report|guide|ebook))"
    r"[\s!.:»→>…]*$", re.I)
NEWSLETTER_HEAD = re.compile(r"^[\w' &-]{0,40}newsletter[\s:!.]*$", re.I)
# softer wording: only counts for a block that repeats across the feed
CUE = re.compile(r"newsletter|subscribe|follow (us|me)|sponsor|free trial|try (it )?(for )?free|\bdemo\b|webinar|check out|listen to|"
                 r"get notified|sign up|discount|% off|\bdeals?\b|upgrade to|premium|coupon|promo code|learn more|get started|"
                 r"register (now|here|today|for)", re.I)
_WS = re.compile(r"\s+")
_TWO_PART = {"co", "com", "org", "net", "gov", "ac", "edu"}


# ------------------------------------------------------------------ helpers
def _text(node: Tag) -> str:
    return _WS.sub(" ", node.get_text(" ", strip=True)).strip()


def site_of(url: str | None) -> str:
    """Rough registrable domain ("blog.example.co.uk" -> "example.co.uk"); "" when unknown."""
    try:
        host = (urlsplit(url or "").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    keep = 3 if len(parts[-1]) == 2 and parts[-2] in _TWO_PART else 2
    return ".".join(parts[-keep:])


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _ad_host(url: str | None) -> bool:
    host = _host(url)
    return bool(host) and any(host == h or host.endswith("." + h) for h in AD_HOSTS)


def _sig(text: str) -> str:
    return hashlib.sha1(text.casefold().encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:16]


def _parse(html: str) -> BeautifulSoup:
    soup = BeautifulSoup(html, "html.parser")
    _wrap_loose_text(soup)
    return soup


def _wrap_loose_text(soup: BeautifulSoup) -> None:
    """Top-level text between <br>s / blocks becomes its own <p>, so "footer after a <br>" is a block too.
    Only when the body has such breaks - a plain one-paragraph summary is left exactly as it is."""
    top = list(soup.contents)
    if not any(isinstance(n, Tag) and (n.name == "br" or n.name in BLOCK_TAGS) for n in top):
        return
    run: list = []

    def flush() -> None:
        if any((isinstance(n, NavigableString) and n.strip()) or isinstance(n, Tag) for n in run):
            p = soup.new_tag("p")
            run[0].insert_before(p)
            for n in run:
                p.append(n.extract())
        run.clear()

    for node in top:
        if isinstance(node, Tag) and (node.name == "br" or node.name in BLOCK_TAGS):
            flush()
        else:
            run.append(node)
    flush()


def _leaf_blocks(soup: BeautifulSoup) -> list[Tag]:
    """Blocks that hold text directly (no block inside them), in document order. One pass: every block marks
    its nearest block ancestor as "not a leaf"; ancestors already walked are not walked again."""
    blocks = soup.find_all(BLOCK_TAGS)
    parents: set[int] = set()
    walked: set[int] = set()
    for b in blocks:
        node = b.parent
        while node is not None and id(node) not in walked:
            if isinstance(node, Tag) and node.name in BLOCK_TAGS:
                parents.add(id(node))
                break
            walked.add(id(node))
            node = node.parent
    return [b for b in blocks if id(b) not in parents]


def _link_only(block: Tag, text: str) -> bool:
    links = block.find_all("a", href=True)
    return bool(links) and len(_WS.sub(" ", " ".join(a.get_text(" ", strip=True) for a in links)).strip()) >= len(text) - 2


def _rule(block: Tag, text: str, rep: bool) -> str:
    """Layers 1 and 2 by wording: "" (keep), "promo", or "cta" (a call to action - what a multi-part ad ends in)."""
    if not text or len(text) > MAX_BLOCK:
        return ""
    has_link = block.find("a", href=True) is not None
    if FOOTER.match(text):
        return "promo" if has_link or len(text) <= 60 else ""
    if len(text) <= 300 and PROMO.search(text):
        return "promo" if has_link or len(text) <= 180 else ""
    if len(text) <= 70 and has_link and _link_only(block, text) and (CTA.match(text) or (rep and CTA_SOFT.match(text))):
        return "cta"
    if len(text) <= 50 and block.name in ("h2", "h3", "h4", "h5", "h6", "div", "p") and NEWSLETTER_HEAD.match(text):
        return "promo"
    if rep and has_link and CUE.search(text):
        return "cta"
    return ""


def _campaign_links(block: Tag) -> list[str]:
    """Links that carry campaign / affiliate parameters (how placements are sold)."""
    out = []
    for a in block.find_all("a", href=True):
        href = a["href"]
        host = _host(href)
        try:
            parts = urlsplit(href)
        except ValueError:
            continue
        if any(host == h or host.endswith("." + h) for h in AFFILIATE_HOSTS) or CAMPAIGN.search(parts.query) or CAMPAIGN.search(parts.fragment):
            out.append(href)
    return out


def _link_sig(href: str) -> str:
    """Where a campaign link leads (site + path), whatever the wording around it - ads rotate their text."""
    parts = urlsplit(href)
    return "L" + hashlib.sha1(f"{(parts.hostname or '').lower()}{parts.path.rstrip('/')}".encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:15]


def _placement(block: Tag, own: frozenset[str], rep: bool, repeated: frozenset[str]) -> bool:
    """A campaign link to another site, in a block the feed repeats or leading where many of its articles lead."""
    if not own:
        return False
    for href in _campaign_links(block):
        site = site_of(href)
        if site and site not in own and (rep or _link_sig(href) in repeated):
            return True
    return False


def _offsite(block: Tag, own: frozenset[str]) -> bool:
    if not own:
        return False
    for a in block.find_all("a", href=True):
        site = site_of(a["href"])
        if site and site not in own:
            return True
    return False


def signatures(html: str) -> list[str]:
    """Blocks of one article that are worth counting across its feed (before it is cleaned)."""
    if not html or html.count("<") > 2 * MAX_TAGS:
        return []
    blocks = _leaf_blocks(_parse(html))
    tail = {id(b) for b in blocks[-TAIL_BLOCKS:]}
    out: dict[str, None] = {}
    for b in blocks:
        text = _text(b)
        if 8 <= len(text) <= MAX_BLOCK and (id(b) in tail or b.find("a", href=True) is not None):
            out[_sig(text)] = None
            for href in _campaign_links(b):
                out[_link_sig(href)] = None
            if len(out) >= MAX_SIGS:
                break
    return list(out)


# ------------------------------------------------------------------ cleaning one article
def clean(html: str, *, own_sites: frozenset[str] = frozenset(), repeated: frozenset[str] = frozenset(),
          common: frozenset[str] = frozenset()) -> tuple[str, int]:
    """(cleaned HTML, blocks removed). Repeats until nothing more goes (removing a footer can uncover the ad's
    last lines), so cleaning a cleaned article changes nothing."""
    total = 0
    if not html or html.count("<") > 2 * MAX_TAGS:   # opening + closing tags
        return html, 0
    for _ in range(4):
        html, n = _clean_once(html, own_sites, repeated, common)
        total += n
        if not n:
            break
    return html, total


def _clean_once(html: str, own_sites: frozenset[str], repeated: frozenset[str], common: frozenset[str]) -> tuple[str, int]:
    """(cleaned HTML, number of blocks removed). ``html`` is already sanitised; the result needs no new pass
    (elements are only removed, or loose text wrapped in <p>). ``repeated``: blocks many articles of the feed
    carry; ``common``: the ones a large share of them carry."""
    if not html:
        return html, 0
    soup = _parse(html)
    removed = 0
    for el in soup.find_all(["img", "a"]):
        if el.decomposed:
            continue
        if el.name == "img":
            tiny = any(str(el.get(k) or "").isdigit() and int(el.get(k)) <= 2 for k in ("width", "height"))
            if tiny or _ad_host(el.get("src")):
                el.decompose()
                removed += 1
        elif _ad_host(el.get("href")) and (el.find("img") is not None or not el.get_text(strip=True)):  # a banner, not a mention
            el.decompose()
            removed += 1
    blocks = _leaf_blocks(soup)
    gone: dict[int, str] = {}                    # id(block) -> why
    info: list[tuple[Tag, str, bool]] = []       # block, text, repeated in the feed
    for b in blocks:
        text = _text(b)
        sig = _sig(text) if text and len(text) <= MAX_BLOCK else ""
        rep = sig in repeated
        info.append((b, text, rep))
        kind = _rule(b, text, rep)
        if not kind and 25 <= len(text) <= MAX_BLOCK and b.find("a", href=True) is not None and (
                _placement(b, own_sites, rep, repeated) or (sig in common and _offsite(b, own_sites))):
            kind = "promo"                        # layer 2: a placement that links out
        if kind:
            gone[id(b)] = kind
    # layer 3, at the end of the article: repeated blocks after promotion; a few before a call to action
    seen_promo = False
    back = 0
    after: list[Tag] = []
    for b, text, rep in reversed(info):
        kind = gone.get(id(b))
        if kind:
            for x in after:                       # repeated blocks that follow this promotion
                gone[id(x)] = "tail"
            after.clear()
            seen_promo = True
            back = TAIL_BACK if kind == "cta" else 0
        elif not text and b.find("img") is None:
            continue
        elif rep:
            if seen_promo and back > 0:
                gone[id(b)] = "tail"              # the ad's own heading / sales lines
                back -= 1
            elif seen_promo:
                break
            else:
                after.append(b)
        else:
            break
    for b, _text_, _rep in info:
        if id(b) in gone and not b.decomposed:
            b.decompose()
            removed += 1
    if not removed:
        return html, 0
    _drop_empty(soup)
    return str(soup).strip(), removed


def _drop_empty(soup: BeautifulSoup) -> None:
    """Wrappers left with nothing in them, and line breaks left at the very end."""
    # bottom-up, looking at direct children only: linear even for absurdly deep markup
    for t in reversed(soup.find_all(True)):
        if t.name in EMPTY_OK:
            continue
        if all(isinstance(c, NavigableString) and not c.strip() for c in t.contents):
            t.decompose()
    while soup.contents:
        last = soup.contents[-1]
        if (isinstance(last, Tag) and last.name in ("br", "hr")) or (isinstance(last, NavigableString) and not last.strip()):
            last.extract()
        else:
            break


# ------------------------------------------------------------------ per-feed counts
def enabled(db: sqlite3.Connection) -> bool:
    """Always on: an article should show the article, not the publisher's promotion (there is no setting for it)."""
    return True


def _own_sites(feed, url: str | None) -> frozenset[str]:
    keys = feed.keys() if hasattr(feed, "keys") else feed
    return frozenset(s for s in (site_of(url), site_of(feed["site_url"] if "site_url" in keys else None),
                                 site_of(feed["url"] if "url" in keys else None)) if s)


def repeated_blocks(db: sqlite3.Connection, feed_id: int) -> tuple[frozenset[str], frozenset[str]]:
    """(blocks repeated in the feed, the ones a large share of its articles carry)."""
    total = db.execute("SELECT n FROM feed_blocks WHERE feed_id = ? AND sig = ?", (feed_id, TOTAL)).fetchone()
    count = total[0] if total else 0
    need = max(MIN_REPEAT, int(count * MIN_SHARE))
    big = max(5, int(count * BIG_SHARE) + 1)
    rows = db.execute("SELECT sig, n FROM feed_blocks WHERE feed_id = ? AND n >= ? AND sig != ?", (feed_id, need, TOTAL)).fetchall()
    return frozenset(r[0] for r in rows), frozenset(r[0] for r in rows if r[1] >= big)


def _count(db: sqlite3.Connection, feed_id: int, per_article: list[list[str]]) -> None:
    if not per_article:
        return
    ts = now()
    counts: dict[str, int] = {}
    for sigs in per_article:
        for s in sigs:
            counts[s] = counts.get(s, 0) + 1
    counts[TOTAL] = len(per_article)
    db.executemany("INSERT INTO feed_blocks (feed_id, sig, n, last_seen) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT(feed_id, sig) DO UPDATE SET n = n + excluded.n, last_seen = excluded.last_seen",
                   [(feed_id, s, n, ts) for s, n in counts.items()])
    total = db.execute("SELECT n FROM feed_blocks WHERE feed_id = ? AND sig = ?", (feed_id, TOTAL)).fetchone()[0]
    if total > WINDOW:  # sliding window: halve everything, forget what was seen once
        db.execute("UPDATE feed_blocks SET n = n / 2 WHERE feed_id = ?", (feed_id,))
        db.execute("DELETE FROM feed_blocks WHERE feed_id = ? AND n = 0", (feed_id,))
    db.execute("DELETE FROM feed_blocks WHERE feed_id = ? AND n <= 1 AND last_seen < ? AND sig != ?", (feed_id, ts - 14 * 86400, TOTAL))


def clean_new(db: sqlite3.Connection, feed, article_ids: list[int]) -> int:
    """Called by the fetcher inside its transaction, before the text is indexed. Returns articles changed."""
    if not article_ids or (feed["kind"] or "rss") not in ("rss", "html") or feed["social_platform"] or not enabled(db):
        return 0
    rows = db.execute(f"SELECT id, url, content_html FROM articles WHERE id IN ({placeholders(len(article_ids))})",  # nosec B608
                      article_ids).fetchall()
    _count(db, feed["id"], [signatures(r["content_html"] or "") for r in rows])
    repeated, common = repeated_blocks(db, feed["id"])
    changed = 0
    for r in rows:
        try:
            html, n = clean(r["content_html"] or "", own_sites=_own_sites(feed, r["url"]), repeated=repeated, common=common)
        except Exception:  # noqa: BLE001 - odd markup must never stop a fetch; the article is stored as it came
            log.exception("Could not clean article %s", r["id"])
            continue
        if n:
            db.execute("UPDATE articles SET content_html = ?, text_content = ? WHERE id = ?", (html, to_text(html), r["id"]))
            changed += 1
    return changed


def clean_page(db: sqlite3.Connection, feed_id: int, url: str | None, html: str) -> str:
    """Full text read from the article page: same rules, with what the feed has taught us."""
    if not html or not enabled(db):
        return html
    feed = db.execute("SELECT id, url, site_url FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    if feed is None:
        return html
    try:
        repeated, common = repeated_blocks(db, feed_id)
        return clean(html, own_sites=_own_sites(feed, url), repeated=repeated, common=common)[0]
    except Exception:  # noqa: BLE001
        log.exception("Could not clean the page text of %s", url)
        return html


# ------------------------------------------------------------------ stored articles (once, in the background)
def rebuild() -> dict:
    """Learn each feed's repeated blocks from what is stored, then clean the stored articles. Short transactions."""
    from app import ttp_filing, ttp_subs
    from app.entities import extract_for_articles

    with get_db() as db:
        if not enabled(db):
            return {"articles": 0, "changed": 0}
        feeds = db.execute(f"SELECT f.id, f.url, f.site_url FROM feeds f WHERE {ELIGIBLE}").fetchall()  # nosec B608
    seen = changed = 0
    for feed in feeds:
        with get_db() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM articles WHERE feed_id = ? ORDER BY sort_ts DESC, id DESC", (feed["id"],))]
            learned = db.execute("SELECT 1 FROM feed_blocks WHERE feed_id = ? AND sig = ?", (feed["id"], TOTAL)).fetchone()
        if not ids:
            continue
        if not learned:  # what does this feed repeat?
            with get_db() as db:
                per_article: list[list[str]] = []   # every stored article: older ones carry older campaigns
                for start in range(0, len(ids), 500):
                    part = ids[start : start + 500]
                    per_article += [signatures(r[0] or "") for r in db.execute(
                        f"SELECT content_html FROM articles WHERE id IN ({placeholders(len(part))})", part)]  # nosec B608
                _count(db, feed["id"], per_article)
        for start in range(0, len(ids), 200):
            chunk = ids[start : start + 200]
            with get_db() as db:
                repeated, common = repeated_blocks(db, feed["id"])
                rows = db.execute(f"SELECT id, url, content_html FROM articles WHERE id IN ({placeholders(len(chunk))})", chunk).fetchall()  # nosec B608
                done: list[int] = []
                for r in rows:
                    seen += 1
                    try:
                        html, n = clean(r["content_html"] or "", own_sites=_own_sites(feed, r["url"]), repeated=repeated, common=common)
                    except Exception:  # noqa: BLE001
                        log.exception("Could not clean article %s", r["id"])
                        continue
                    if n:
                        db.execute("UPDATE articles SET content_html = ?, text_content = ? WHERE id = ?", (html, to_text(html), r["id"]))
                        done.append(r["id"])
                if done:  # names that only the removed promotion mentioned are no longer mentions of the article
                    db.execute(f"DELETE FROM article_entities WHERE article_id IN ({placeholders(len(done))})", done)  # nosec B608
                    extract_for_articles(db, done)
                    ttp_subs.assign(db, done)
                    ttp_filing.file(db, done)
                    changed += len(done)
    with get_db() as db:
        set_state(db, "declutter_rev", REV)
    log.info("Ad clean-up of stored articles: %d of %d articles changed", changed, seen)
    return {"articles": seen, "changed": changed}


class Rebuilder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, name="declutter", daemon=True).start()
        return True

    def _run(self) -> None:
        try:
            rebuild()
        except Exception:
            log.exception("Ad clean-up of stored articles failed")
        finally:
            self.running = False


rebuilder = Rebuilder()


def ensure_current() -> bool:
    """Clean the stored articles once (per rule revision), when the setting is on."""
    with get_db() as db:
        stale = enabled(db) and get_state(db, "declutter_rev", "") != REV
    return rebuilder.start() if stale else False
