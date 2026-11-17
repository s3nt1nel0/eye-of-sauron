"""HTML sanitisation for untrusted feed content (stored-XSS defence).

Feed content is attacker-controlled. It is cleaned with an allow-list
sanitiser (nh3 / Rust ammonia) *before* it is stored, and again when served
(e.g. to drop images). The browser adds a strict CSP as a second layer.
"""

from __future__ import annotations

import html
import re

import nh3

ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "caption", "cite", "code", "dd", "del", "details",
    "div", "dl", "dt", "em", "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6",
    "hr", "i", "img", "ins", "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "samp",
    "small", "span", "strong", "sub", "summary", "sup", "table", "tbody", "td", "tfoot",
    "th", "thead", "time", "tr", "u", "ul",
}

ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "abbr": {"title"},
    "img": {"src", "alt", "title", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
    "time": {"datetime"},
    "ol": {"start"},
}

_NUMERIC_ATTRS = {"width", "height", "colspan", "rowspan", "start"}
MAX_HTML_LENGTH = 1_000_000
_WS = re.compile(r"\s+")


def _attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    if attribute in ("href", "src"):
        candidate = value.strip()
        lowered = candidate.lower()
        if lowered.startswith(("https://", "http://")):
            return candidate
        if attribute == "href" and lowered.startswith("mailto:"):
            return candidate
        return None  # drops javascript:, data:, relative and protocol-relative URLs
    if attribute in _NUMERIC_ATTRS:
        return value if value.isdigit() and len(value) <= 5 else None
    if attribute == "scope":
        return value if value in {"row", "col", "rowgroup", "colgroup"} else None
    return value


def sanitize_html(raw: str | None, *, allow_images: bool = True) -> str:
    if not raw:
        return ""
    raw = raw[:MAX_HTML_LENGTH]
    tags = ALLOWED_TAGS if allow_images else ALLOWED_TAGS - {"img"}
    attributes = {k: v for k, v in ALLOWED_ATTRIBUTES.items() if k in tags}
    return nh3.clean(
        raw,
        tags=tags,
        attributes=attributes,
        attribute_filter=_attribute_filter,
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer nofollow",
        set_tag_attribute_values={"a": {"target": "_blank"}},
        strip_comments=True,
    )


def to_text(raw: str | None, max_len: int = 200_000) -> str:
    """Strip all markup and return plain, unescaped text (for titles and search)."""
    if not raw:
        return ""
    cleaned = nh3.clean(raw[:MAX_HTML_LENGTH], tags=set())
    return _WS.sub(" ", html.unescape(cleaned)).strip()[:max_len]
