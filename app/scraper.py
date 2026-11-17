"""Website scraping: turn a page without RSS into a feed (HTML + CSS selectors, or JSON + dotted paths),
plus feed auto-discovery and automatic rule suggestions with a live preview.

Rule syntax (HTML mode)
* ``items``   - CSS selector matching one element per article, e.g. ``article`` or ``div.post-card``.
* fields     - CSS selector *relative to the item*, optionally followed by ``@attr`` to read an attribute:
               ``h2 a`` (text), ``h2 a @href`` (attribute), ``@href`` (attribute of the item itself),
               ``.`` (the item's own text). Empty = not used.
* ``link`` defaults to the first ``a @href`` in the item; relative URLs are resolved against the page.

JSON mode: ``items`` is a dotted path to a list (``data.articles``, ``results[0].items``); fields are
dotted paths relative to each item (``title``, ``links[0].href``, ``author.name``); combine with
``&`` and quoted literals like FreshRSS: ``title & " (" & source & ")"``.

Safety: the page is fetched by the caller through netguard (SSRF policy, size/time caps); parsing uses
Python's own ``html.parser`` (no XML, no entities, no network); selectors are length-limited and
pre-compiled (invalid ones are rejected on save); the number of items is capped; every output field is
reduced to plain text or sanitised HTML downstream; links must be http(s).
"""

from __future__ import annotations

import html as htmllib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Annotated, Any, Literal
from urllib.parse import urljoin, urlsplit

import soupsieve
from bs4 import BeautifulSoup, Tag
from pydantic import Field, StringConstraints, field_validator, model_validator

from app import netguard
from app.api.common import StrictModel
from app.sanitize import to_text

MAX_ITEMS = 200
MAX_PAGE_BYTES = 5 * 1024 * 1024
Selector = Annotated[str, StringConstraints(max_length=300)]
_ATTR_RE = re.compile(r"^(?P<css>.*?)\s*@(?P<attr>[A-Za-z_:][-A-Za-z0-9_:.]{0,60})$")
_JSON_PATH_RE = re.compile(r"^[A-Za-z0-9_$\-]+(\[\d{1,4}\])*(\.[A-Za-z0-9_$\-]+(\[\d{1,4}\])*)*$")
_FEED_TYPES = ("application/rss+xml", "application/atom+xml", "application/feed+json", "application/json",
               "application/rdf+xml", "text/xml", "application/xml")
COMMON_FEED_PATHS = ("/feed", "/rss", "/feed.xml", "/rss.xml", "/atom.xml", "/index.xml")


class ScrapeError(ValueError):
    """Invalid rules or unusable page (message is safe to show)."""


class ScrapeConfig(StrictModel):
    mode: Literal["html", "json"] = "html"
    items: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    title: Selector = ""
    link: Selector = ""
    content: Selector = ""
    date: Selector = ""
    author: Selector = ""
    image: Selector = ""
    date_format: Annotated[str, StringConstraints(max_length=60)] = ""

    @field_validator("date_format")
    @classmethod
    def _fmt(cls, v: str) -> str:
        if v and not re.fullmatch(r"[%A-Za-z0-9 ,.:/\-_]+", v):
            raise ValueError("date_format may only use strftime codes and simple separators")
        return v

    @model_validator(mode="after")
    def _compile(self) -> "ScrapeConfig":
        # Reject broken selectors/paths at save time instead of failing silently on every refresh.
        fields = {"items": self.items, "title": self.title, "link": self.link, "content": self.content,
                  "date": self.date, "author": self.author, "image": self.image}
        for name, value in fields.items():
            if not value:
                continue
            try:
                if self.mode == "html":
                    css, _ = split_attr(value)
                    if css and css != ".":
                        soupsieve.compile(css)
                else:
                    for part in _concat_parts(value):
                        if not part.startswith(('"', "'")) and not _JSON_PATH_RE.match(part):
                            raise ValueError("invalid path")
            except Exception as exc:  # soupsieve raises SelectorSyntaxError (a ValueError subclass)
                raise ValueError(f"{name}: invalid {'CSS selector' if self.mode == 'html' else 'JSON path'}") from exc
        return self


def split_attr(selector: str) -> tuple[str, str | None]:
    selector = selector.strip()
    m = _ATTR_RE.match(selector)
    if m:
        return m.group("css").strip(), m.group("attr")
    return selector, None


# =========================================================================== dates
_FORMATS = ("%Y-%m-%d", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y",
            "%B %d %Y", "%b %d %Y", "%d/%m/%Y", "%m/%d/%Y", "%d.%m.%Y", "%Y/%m/%d", "%A, %B %d, %Y", "%a, %d %b %Y",
            "%d %B %Y %H:%M", "%B %d, %Y %I:%M %p", "%b %d, %Y %I:%M %p")
_RELATIVE = re.compile(r"(\d+)\s*(second|sec|minute|min|hour|hr|day|week|month|year)s?\s+ago", re.I)
_UNIT = {"second": 1, "sec": 1, "minute": 60, "min": 60, "hour": 3600, "hr": 3600, "day": 86400, "week": 604800,
         "month": 2_592_000, "year": 31_536_000}


def parse_date(text: str, fmt: str = "", now_ts: int | None = None) -> int | None:
    text = (text or "").strip()[:100]
    if not text:
        return None
    current = now_ts or int(time.time())
    candidates = [fmt] if fmt else []
    for f in candidates:
        try:
            dt = datetime.strptime(text, f)
            return int(dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp())
        except ValueError:
            pass
    iso = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        return int(dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp())
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(text)
        return int(dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp())
    except (TypeError, ValueError, IndexError):
        pass
    cleaned = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", text)
    cleaned = re.sub(r"\s+", " ", cleaned.replace("Published", "").replace("Updated", "").strip(" :|·-"))
    for f in _FORMATS:
        try:
            return int(datetime.strptime(cleaned, f).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    lowered = cleaned.lower()
    if lowered in ("today", "just now", "now"):
        return current
    if lowered == "yesterday":
        return current - 86400
    m = _RELATIVE.search(lowered)
    if m:
        return current - int(m.group(1)) * _UNIT[m.group(2).lower()]
    return None


# =========================================================================== HTML extraction
def _select_value(item: Tag, selector: str, *, html: bool = False) -> tuple[str, Tag | None]:
    css, attr = split_attr(selector)
    node: Tag | None = item if css in ("", ".") else item.select_one(css)
    if node is None:
        return "", None
    if attr:
        value = node.get(attr)
        if isinstance(value, list):
            value = " ".join(value)
        return (str(value) if value is not None else ""), node
    if html:
        return node.decode_contents(), node
    return node.get_text(" ", strip=True), node


def _abs_link(base: str, value: str) -> str | None:
    if not value:
        return None
    try:
        return netguard.normalize_url(urljoin(base, value.strip()))
    except netguard.UnsafeURLError:
        return None


@dataclass
class Item:
    title: str
    link: str | None
    content: str
    published: int | None
    author: str | None
    image: str | None

    def to_entry(self) -> dict:
        """feedparser-like dict for fetcher.store_entries()."""
        html = self.content
        if self.image:
            html = f'<p><img src="{htmllib.escape(self.image, quote=True)}" alt=""></p>{html}'  # sanitised again on insert
        entry: dict[str, Any] = {"title": self.title, "link": self.link, "id": self.link or None,
                                 "author": self.author, "summary": html}
        if self.published:
            entry["published_parsed"] = time.gmtime(self.published)
        return entry

    def preview(self) -> dict:
        return {"title": self.title, "link": self.link, "published": self.published, "author": self.author,
                "image": self.image, "summary": to_text(self.content, 300)}


def extract_html(content: bytes, base_url: str, cfg: ScrapeConfig, now_ts: int | None = None) -> list[Item]:
    soup = BeautifulSoup(content[:MAX_PAGE_BYTES], "html.parser")
    try:
        nodes = soup.select(cfg.items, limit=MAX_ITEMS)
    except Exception as exc:
        raise ScrapeError("items selector is invalid") from exc
    out: list[Item] = []
    seen: set[str] = set()
    for node in nodes:
        title = to_text(_select_value(node, cfg.title)[0] if cfg.title else node.get_text(" ", strip=True), 300)
        raw_link = _select_value(node, cfg.link)[0] if cfg.link else ""
        if not raw_link:
            a = node if node.name == "a" else node.find("a", href=True)
            raw_link = a.get("href", "") if a is not None else ""
        link = _abs_link(base_url, str(raw_link))
        if not title and not link:
            continue
        key = link or title
        if key in seen:
            continue
        seen.add(key)
        content_html = _select_value(node, cfg.content, html=True)[0] if cfg.content else ""
        published = None
        if cfg.date:
            value, date_node = _select_value(node, cfg.date)
            if date_node is not None and date_node.has_attr("datetime") and not split_attr(cfg.date)[1]:
                value = str(date_node["datetime"])
            published = parse_date(value, cfg.date_format, now_ts)
        author = to_text(_select_value(node, cfg.author)[0], 200) if cfg.author else None
        image = None
        if cfg.image:
            raw_img = _select_value(node, cfg.image if split_attr(cfg.image)[1] else f"{cfg.image} @src")[0]
            image = _abs_link(base_url, raw_img)
        out.append(Item(title or (link or ""), link, content_html[:100_000], published, author or None, image))
    return out


# =========================================================================== JSON extraction
def _concat_parts(expr: str) -> list[str]:
    parts, buf, quote = [], "", None
    for ch in expr:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf += ch
        elif ch == "&":
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _json_get(obj: Any, path: str) -> Any:
    for segment in path.split("."):
        name, *indexes = re.split(r"\[|\]", segment)
        name = name.strip()
        if name:
            if not isinstance(obj, dict) or name not in obj:
                return None
            obj = obj[name]
        for idx in [i for i in indexes if i != ""]:
            if not isinstance(obj, list) or int(idx) >= len(obj):
                return None
            obj = obj[int(idx)]
    return obj


def _json_value(item: Any, expr: str) -> str:
    if not expr:
        return ""
    out = []
    resolved = False
    for part in _concat_parts(expr):
        if part[:1] in ("'", '"') and part[-1:] == part[:1]:
            out.append(part[1:-1])
        else:
            value = _json_get(item, part)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                out.append(str(value))
                resolved = True
    # Literals alone ("(" & ")") are not a value: an item missing every field yields nothing.
    return "".join(out) if resolved else ""


def extract_json(content: bytes, base_url: str, cfg: ScrapeConfig, now_ts: int | None = None) -> list[Item]:
    try:
        data = json.loads(content[:MAX_PAGE_BYTES])
    except ValueError as exc:
        raise ScrapeError("The page is not valid JSON") from exc
    items = _json_get(data, cfg.items)
    if not isinstance(items, list):
        raise ScrapeError("The items path does not point to a list")
    out: list[Item] = []
    for item in items[:MAX_ITEMS]:
        title = to_text(_json_value(item, cfg.title or "title"), 300)
        link = _abs_link(base_url, _json_value(item, cfg.link or "url"))
        if not title and not link:
            continue
        published = parse_date(_json_value(item, cfg.date), cfg.date_format, now_ts) if cfg.date else None
        image = _abs_link(base_url, _json_value(item, cfg.image)) if cfg.image else None
        out.append(Item(title or (link or ""), link, _json_value(item, cfg.content)[:100_000], published,
                        to_text(_json_value(item, cfg.author), 200) or None, image))
    return out


def extract(content: bytes, base_url: str, cfg: ScrapeConfig, now_ts: int | None = None) -> list[Item]:
    return extract_json(content, base_url, cfg, now_ts) if cfg.mode == "json" else extract_html(content, base_url, cfg, now_ts)


# =========================================================================== discovery & suggestions
def feed_links(content: bytes, base_url: str) -> list[dict]:
    """<link rel="alternate" type="application/rss+xml" ...> declared by the page."""
    soup = BeautifulSoup(content[:MAX_PAGE_BYTES], "html.parser")
    out, seen = [], set()
    for link in soup.find_all("link", href=True, limit=200):
        rel = " ".join(link.get("rel") or []).lower()
        typ = (link.get("type") or "").lower().split(";")[0].strip()
        if "alternate" in rel and typ in _FEED_TYPES:
            url = _abs_link(base_url, link["href"])
            if url and url not in seen:
                seen.add(url)
                out.append({"url": url, "title": to_text(link.get("title") or "", 200), "type": typ})
    return out[:10]


def _css_ident(value: str) -> str:
    return soupsieve.escape(value)


def _signature(tag: Tag) -> str:
    classes = [c for c in (tag.get("class") or []) if re.fullmatch(r"[A-Za-z][\w-]{1,40}", c) and not re.search(r"\d{3,}", c)]
    return tag.name + "".join("." + _css_ident(c) for c in classes[:2])


def suggest(content: bytes, base_url: str) -> ScrapeConfig | None:
    """Guess rules from repeated structure: <article>s, else repeated containers of heading links,
    else the largest group of sibling elements that each contain a substantial link."""
    soup = BeautifulSoup(content[:MAX_PAGE_BYTES], "html.parser")
    for tag in soup(["script", "style", "noscript", "nav", "footer", "header", "aside", "form"]):
        tag.decompose()
    articles = soup.find_all("article")
    if len(articles) >= 3:
        sig = _signature(articles[0])
        items = sig if sig != "article" and len(soup.select(sig)) >= 3 else "article"
        return ScrapeConfig(items=items, **_fields_for(articles[0]))
    groups: dict[str, list[Tag]] = {}
    for a in soup.find_all("a", href=True, limit=3000):
        text = a.get_text(" ", strip=True)
        href = a["href"]
        if not (20 <= len(text) <= 250) or href.startswith(("#", "javascript:", "mailto:")):
            continue
        node = a
        for _ in range(4):  # climb to the repeating container
            parent = node.parent
            if parent is None or parent.name in ("body", "html", "[document]"):
                break
            node = parent
            siblings = [s for s in parent.parent.find_all(parent.name, recursive=False)] if parent.parent else []
            if len(siblings) >= 3 and _signature(parent) == _signature(siblings[0]):
                break
        key = _signature(node)
        groups.setdefault(key, []).append(node)
    best = max(groups.items(), key=lambda kv: len(kv[1]), default=None)
    if not best or len(best[1]) < 3:
        return None
    sig, nodes = best
    try:
        if len(soup.select(sig)) < 3:
            return None
    except Exception:
        return None
    return ScrapeConfig(items=sig, **_fields_for(nodes[0]))


def _fields_for(item: Tag) -> dict:
    fields: dict[str, str] = {}
    heading = item.find(["h1", "h2", "h3", "h4", "h5"])
    if heading is not None:
        fields["title"] = heading.name
        if heading.find("a", href=True) is not None:
            fields["link"] = f"{heading.name} a @href"
    else:
        # No heading: the anchor (or titled element) with the longest text is almost always the headline.
        anchors = [a for a in item.find_all("a", href=True) if not a["href"].startswith(("#", "javascript:"))]
        best = max(anchors, key=lambda a: len(a.get_text(" ", strip=True)), default=None)
        titled = item.find(class_=re.compile(r"title|headline|heading", re.I))
        if titled is not None and len(titled.get_text(" ", strip=True)) >= 15:
            fields["title"] = _signature(titled)
        elif best is not None and len(best.get_text(" ", strip=True)) >= 15:
            fields["title"] = _signature(best)
        if best is not None and best is not item:
            sig = _signature(best)
            fields["link"] = f"{sig} @href" if sig != "a" else "a @href"
    if "link" not in fields:
        fields["link"] = "a @href"
    if item.find("time") is not None:
        fields["date"] = "time"
    elif item.find(class_=re.compile(r"date|time|posted|published", re.I)) is not None:
        node = item.find(class_=re.compile(r"date|time|posted|published", re.I))
        fields["date"] = _signature(node)
    if item.find("p") is not None:
        fields["content"] = "p"
    if item.find(class_=re.compile(r"author|byline", re.I)) is not None:
        fields["author"] = _signature(item.find(class_=re.compile(r"author|byline", re.I)))
    if item.find("img", src=True) is not None:
        fields["image"] = "img @src"
    return fields


def same_site_guesses(url: str) -> list[str]:
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    return [base + p for p in COMMON_FEED_PATHS]
