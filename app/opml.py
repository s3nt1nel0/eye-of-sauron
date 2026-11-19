"""OPML import/export. Imports are parsed with defusedxml (no XXE / entity bombs).

Exports are lossless between Eye of Sauron instances: besides the standard attributes each feed carries ``eos:*``
attributes (namespace ``NS``) with what it is (article feed, podcast, YouTube channel, social account, scraped page,
source settings) and its retention / refresh settings. Imports trust these attributes after validating every value;
OPML files from other readers have none, so the kind is recognised from the address (``app.feedkinds``) and podcast
shows move to Podcasts after their first fetch. Re-importing an Eye of Sauron OPML also corrects the kind of feeds
that are already there (for example after importing an older file that lacked the kinds).
"""

from __future__ import annotations

import json
import sqlite3
import xml.etree.ElementTree as ET  # used only to *build* XML, never to parse untrusted input

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from app import accounts, feedkinds, netguard, sources
from app.db import now
from app.sanitize import to_text

MAX_IMPORT_FEEDS = 5000
NS = "https://github.com/s3nt1nel0/eye-of-sauron/ns/opml"
ET.register_namespace("eos", NS)
KINDS = ("rss", "html", "json", "podcast", *sources.KINDS)


def _q(name: str) -> str:
    return f"{{{NS}}}{name}"


def export_opml(db: sqlite3.Connection) -> bytes:
    root = ET.Element("opml", version="2.0")
    head = ET.SubElement(root, "head")
    ET.SubElement(head, "title").text = "Eye of Sauron subscriptions"
    body = ET.SubElement(root, "body")

    folders = {r["id"]: r["name"] for r in db.execute("SELECT id, name FROM folders ORDER BY position, name")}
    folder_nodes: dict[int, ET.Element] = {}
    for fid, name in folders.items():
        folder_nodes[fid] = ET.SubElement(body, "outline", text=name, title=name)

    for feed in db.execute("SELECT title, custom_title, url, site_url, folder_id, kind, scrape, source, social_platform, "
                           "refresh_minutes, retention_days, max_articles, enabled, full_text, translate_titles "
                           "FROM feeds ORDER BY title"):
        parent = folder_nodes.get(feed["folder_id"], body)
        attrs = {"type": "rss", "text": feed["title"] or feed["url"], "title": feed["title"] or feed["url"],
                 "xmlUrl": feed["url"]}
        if feed["site_url"]:
            attrs["htmlUrl"] = feed["site_url"]
        kind = feed["kind"] or "rss"
        attrs[_q("kind")] = kind
        if feed["source"]:
            attrs[_q("source")] = feed["source"]
        if feed["scrape"]:
            attrs[_q("scrape")] = feed["scrape"]
        if feed["social_platform"]:
            attrs[_q("social")] = feed["social_platform"]
        for col, name in (("refresh_minutes", "refresh"), ("retention_days", "retention"), ("max_articles", "maxItems")):
            if feed[col] is not None:
                attrs[_q(name)] = str(int(feed[col]))
        if not feed["enabled"]:
            attrs[_q("enabled")] = "0"
        if feed["full_text"]:
            attrs[_q("fullText")] = feed["full_text"]
        if feed["translate_titles"]:
            attrs[_q("translate")] = "1"
        if feed["custom_title"]:
            attrs[_q("customTitle")] = "1"
        ET.SubElement(parent, "outline", attrs)

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _int(value: str | None, lo: int, hi: int) -> int | None:
    if value is None or not value.strip().isdigit():
        return None
    n = int(value)
    return n if lo <= n <= hi else None


def _described(outline: ET.Element, url: str) -> dict | None:
    """The feed as an Eye of Sauron export describes it (all values validated), or None for a plain OPML outline."""
    kind = outline.get(_q("kind"))
    if kind not in KINDS:
        return None
    out: dict = {"kind": kind, "url": url, "source": None, "scrape": None, "social_platform": None}
    if kind in sources.KINDS:
        try:
            cfg = sources.parse_config(outline.get(_q("source")) or "")
        except (ValueError, TypeError):
            return None
        out["source"] = cfg.model_dump_json(exclude_none=True)
        out["url"] = sources.canonical_url(cfg)
    elif kind in ("html", "json"):
        from app import scraper

        try:
            out["scrape"] = scraper.ScrapeConfig.model_validate_json(outline.get(_q("scrape")) or "").model_dump_json()
        except ValueError:
            return None
    social = outline.get(_q("social"))
    if social in accounts.PLATFORMS:
        out["social_platform"] = social
    out["refresh_minutes"] = _int(outline.get(_q("refresh")), 5, 10080)
    out["retention_days"] = _int(outline.get(_q("retention")), 0, 36500)
    out["max_articles"] = _int(outline.get(_q("maxItems")), 0, 1_000_000)
    out["enabled"] = 0 if outline.get(_q("enabled")) == "0" else 1
    full = outline.get(_q("fullText"))
    out["full_text"] = full if full in ("always", "never") else None
    out["translate_titles"] = 1 if outline.get(_q("translate")) == "1" else 0
    out["custom_title"] = outline.get(_q("customTitle")) == "1"
    return out


def _guessed(url: str) -> dict:
    g = feedkinds.guess(url)
    out = {"kind": g["kind"], "url": url, "source": None, "scrape": None, "social_platform": g.get("social_platform"),
           "refresh_minutes": None, "retention_days": None, "max_articles": None, "enabled": 1, "full_text": None,
           "translate_titles": 0, "custom_title": None}
    if g.get("source"):
        cfg = sources.parse_config(g["source"])
        out["source"], out["url"] = cfg.model_dump_json(exclude_none=True), sources.canonical_url(cfg)
        out["refresh_minutes"] = sources.DEFAULT_REFRESH.get(cfg.kind)
    if g["kind"] == "youtube":  # channels are a video library: kept
        out["retention_days"], out["max_articles"] = 0, 0
    return out


TYPE_OF = {"podcast": "podcasts", "youtube": "videos"}


def _type(feed: dict) -> str:
    return "accounts" if feed["social_platform"] else TYPE_OF.get(feed["kind"], "articles")


def import_opml(db: sqlite3.Connection, data: bytes) -> dict:
    try:
        root = SafeET.fromstring(data, forbid_dtd=True)
    except (DefusedXmlException, ET.ParseError, ValueError) as exc:
        raise ValueError("Invalid or unsafe OPML document") from exc
    if root.tag.lower() != "opml":
        raise ValueError("Not an OPML document")
    body = root.find("body")
    if body is None:
        raise ValueError("OPML has no body")

    added = skipped = invalid = updated = 0
    by_type = {"articles": 0, "podcasts": 0, "videos": 0, "accounts": 0}
    ts = now()

    def folder_id_for(name: str) -> int | None:
        name = to_text(name, 100)
        if not name:
            return None
        db.execute("INSERT OR IGNORE INTO folders (name) VALUES (?)", (name,))
        return db.execute("SELECT id FROM folders WHERE name = ?", (name,)).fetchone()["id"]

    def default_folder(feed: dict, folder_id: int | None) -> int | None:
        if folder_id is not None:
            return folder_id
        if feed["kind"] == "youtube":
            return sources.youtube_folder(db)
        if feed["kind"] == "podcast":
            return feedkinds.podcast_folder(db)
        if feed["social_platform"]:
            return feedkinds.social_folder(db)
        return None

    def walk(node: ET.Element, folder_id: int | None, depth: int) -> None:
        nonlocal added, skipped, invalid, updated
        if depth > 10:
            return
        for outline in node.findall("outline"):
            if added + skipped + invalid >= MAX_IMPORT_FEEDS:
                return
            xml_url = outline.get("xmlUrl") or outline.get("xmlurl")
            label = outline.get("title") or outline.get("text") or ""
            if not xml_url:
                # A container outline: treat as folder (nested folders are flattened).
                walk(outline, folder_id_for(label) if depth == 0 else folder_id, depth + 1)
                continue
            try:
                url = netguard.normalize_url(xml_url)
            except netguard.UnsafeURLError:
                invalid += 1
                continue
            described = _described(outline, url)
            try:
                feed = described or _guessed(url)
            except (ValueError, TypeError):
                invalid += 1
                continue
            title = to_text(label, 300)
            custom = feed["custom_title"] if feed["custom_title"] is not None else bool(title)
            existing = db.execute("SELECT id FROM feeds WHERE url = ?", (feed["url"],)).fetchone()
            if existing is not None:
                skipped += 1
                if described:  # an Eye of Sauron export knows what this feed is: put it in the right tab
                    cur = db.execute(
                        "UPDATE feeds SET kind = ?, source = COALESCE(?, source), scrape = COALESCE(?, scrape), "
                        "social_platform = ? WHERE id = ? AND (COALESCE(kind, 'rss') != ? OR social_platform IS NOT ?)",
                        (feed["kind"], feed["source"], feed["scrape"], feed["social_platform"], existing["id"],
                         feed["kind"], feed["social_platform"]))
                    updated += cur.rowcount
                continue
            cur = db.execute(
                "INSERT OR IGNORE INTO feeds (folder_id, title, custom_title, url, created_at, kind, source, scrape, "
                "social_platform, refresh_minutes, retention_days, max_articles, enabled, full_text, translate_titles) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (default_folder(feed, folder_id), title or feed["url"], 1 if custom and title else 0, feed["url"], ts,
                 feed["kind"], feed["source"], feed["scrape"], feed["social_platform"], feed["refresh_minutes"],
                 feed["retention_days"], feed["max_articles"], feed["enabled"], feed["full_text"], feed["translate_titles"]))
            if cur.rowcount == 1:
                added += 1
                by_type[_type(feed)] += 1
            else:
                skipped += 1

    walk(body, None, 0)
    return {"added": added, "skipped": skipped, "invalid": invalid, "updated": updated, "by_type": by_type}
