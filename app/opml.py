"""OPML import/export. Imports are parsed with defusedxml (no XXE / entity bombs)."""

from __future__ import annotations

import json
import sqlite3
import xml.etree.ElementTree as ET  # used only to *build* XML, never to parse untrusted input

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from app import netguard, sources
from app.db import now
from app.sanitize import to_text

MAX_IMPORT_FEEDS = 2000


def export_opml(db: sqlite3.Connection) -> bytes:
    root = ET.Element("opml", version="2.0")
    head = ET.SubElement(root, "head")
    ET.SubElement(head, "title").text = "Eye of Sauron subscriptions"
    body = ET.SubElement(root, "body")

    folders = {r["id"]: r["name"] for r in db.execute("SELECT id, name FROM folders ORDER BY position, name")}
    folder_nodes: dict[int, ET.Element] = {}
    for fid, name in folders.items():
        folder_nodes[fid] = ET.SubElement(body, "outline", text=name, title=name)

    for feed in db.execute("SELECT title, url, site_url, folder_id FROM feeds ORDER BY title"):
        parent = folder_nodes.get(feed["folder_id"], body)
        attrs = {"type": "rss", "text": feed["title"] or feed["url"], "title": feed["title"] or feed["url"],
                 "xmlUrl": feed["url"]}
        if feed["site_url"]:
            attrs["htmlUrl"] = feed["site_url"]
        ET.SubElement(parent, "outline", attrs)

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


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

    added = skipped = invalid = 0
    ts = now()

    def folder_id_for(name: str) -> int | None:
        name = to_text(name, 100)
        if not name:
            return None
        db.execute("INSERT OR IGNORE INTO folders (name) VALUES (?)", (name,))
        return db.execute("SELECT id FROM folders WHERE name = ?", (name,)).fetchone()["id"]

    def walk(node: ET.Element, folder_id: int | None, depth: int) -> None:
        nonlocal added, skipped, invalid
        if depth > 10:
            return
        for outline in node.findall("outline"):
            if added + skipped + invalid >= MAX_IMPORT_FEEDS:
                return
            xml_url = outline.get("xmlUrl") or outline.get("xmlurl")
            label = outline.get("title") or outline.get("text") or ""
            if xml_url:
                try:
                    url = netguard.normalize_url(xml_url)
                except netguard.UnsafeURLError:
                    invalid += 1
                    continue
                title = to_text(label, 300)
                yt = sources.youtube_source_for_url(url)
                if yt:  # a YouTube channel/playlist feed: follow it as a channel (Videos tab), kept forever
                    cur = db.execute(
                        "INSERT OR IGNORE INTO feeds (folder_id, title, custom_title, url, created_at, kind, source, "
                        "retention_days, max_articles) VALUES (?, ?, ?, ?, ?, 'youtube', ?, 0, 0)",
                        (sources.youtube_folder(db), title, 1 if title else 0, url, ts, json.dumps(yt)),
                    )
                else:
                    cur = db.execute(
                        "INSERT OR IGNORE INTO feeds (folder_id, title, custom_title, url, created_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (folder_id, title, 1 if title else 0, url, ts),
                    )
                if cur.rowcount == 1:
                    added += 1
                else:
                    skipped += 1
            else:
                # A container outline: treat as folder (nested folders are flattened).
                walk(outline, folder_id_for(label) if depth == 0 else folder_id, depth + 1)

    walk(body, None, 0)
    return {"added": added, "skipped": skipped, "invalid": invalid}
