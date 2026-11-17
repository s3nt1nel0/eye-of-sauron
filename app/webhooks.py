"""Outbound webhooks for automation (n8n, Node-RED, Home Assistant, Slack relays ...).

Payloads are signed with HMAC-SHA256 when a secret is configured:
    X-Feedwarden-Timestamp: <unix seconds>
    X-Feedwarden-Signature: sha256=<hex(hmac(secret, f"{timestamp}.{body}"))>
Receivers should verify the signature and reject stale timestamps (replay).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from app import netguard, secretbox
from app.config import get_settings
from app.db import get_db, now
from app.rules import WebhookEvent

log = logging.getLogger("feedwarden.webhooks")

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="webhook")
MAX_EVENTS_PER_BATCH = 200


def _article_payload(article_id: int) -> dict | None:
    with get_db() as db:
        row = db.execute(
            "SELECT a.id, a.title, a.url, a.author, a.published, a.fetched_at, a.is_starred, "
            "substr(a.text_content, 1, 1000) AS summary, f.id AS feed_id, f.title AS feed_title "
            "FROM articles a JOIN feeds f ON f.id = a.feed_id WHERE a.id = ?",
            (article_id,),
        ).fetchone()
        if row is None:
            return None
        tags = [
            r["name"]
            for r in db.execute(
                "SELECT t.name FROM article_tags at JOIN tags t ON t.id = at.tag_id WHERE at.article_id = ?",
                (article_id,),
            )
        ]
    return {
        "id": row["id"],
        "title": row["title"],
        "url": row["url"],
        "author": row["author"],
        "published": row["published"],
        "fetched_at": row["fetched_at"],
        "starred": bool(row["is_starred"]),
        "summary": row["summary"],
        "feed": {"id": row["feed_id"], "title": row["feed_title"]},
        "collections": tags,
    }


def sign(secret: str, ts: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), ts.encode() + b"." + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def send(webhook_id: int, payload: dict) -> tuple[bool, str]:
    cfg = get_settings()
    with get_db() as db:
        hook = db.execute("SELECT * FROM webhooks WHERE id = ? AND enabled = 1", (webhook_id,)).fetchone()
    if hook is None:
        return False, "Webhook not found or disabled"

    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ts = str(now())
    headers = {
        "Content-Type": "application/json",
        "User-Agent": cfg.user_agent,
        "X-Feedwarden-Timestamp": ts,
    }
    if hook["secret"]:
        try:
            secret = secretbox.decrypt(hook["secret"])
        except secretbox.SecretError as exc:
            return False, str(exc)
        headers["X-Feedwarden-Signature"] = sign(secret, ts, body)

    status: int | None = None
    error: str | None = None
    try:
        resp = netguard.request(
            "POST",
            hook["url"],
            headers=headers,
            content=body,
            allow_private=cfg.allow_private_webhooks,
            timeout=10,
            max_bytes=64 * 1024,
            max_redirects=0,  # never follow redirects for POSTs carrying data
        )
        status = resp.status_code
        if status >= 400:
            error = f"HTTP {status}"
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        error = str(exc)[:300]

    with get_db() as db:
        db.execute(
            "UPDATE webhooks SET last_status = ?, last_error = ?, last_sent = ? WHERE id = ?",
            (status, error, now(), webhook_id),
        )
    if error:
        log.warning("Webhook %d failed: %s", webhook_id, error)
    return error is None, error or f"HTTP {status}"


def _deliver(event: WebhookEvent) -> None:
    try:
        article = _article_payload(event.article_id)
        if article is None:
            return
        send(event.webhook_id, {
            "event": "rule.matched",
            "rule": {"id": event.rule_id, "name": event.rule_name},
            "article": article,
        })
    except Exception:  # never let a webhook crash the worker
        log.exception("Unexpected error delivering webhook %d", event.webhook_id)


def dispatch(events: list) -> None:
    events = [e for e in events if isinstance(e, WebhookEvent)]
    if len(events) > MAX_EVENTS_PER_BATCH:
        log.warning("Dropping %d webhook events (batch limit)", len(events) - MAX_EVENTS_PER_BATCH)
    for event in events[:MAX_EVENTS_PER_BATCH]:
        _pool.submit(_deliver, event)
