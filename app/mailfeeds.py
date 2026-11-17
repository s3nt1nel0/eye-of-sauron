"""Email newsletters as feeds: read a mailbox over IMAP and turn matching messages into articles.

Some publishers (CISA's GovDelivery updates, vendor threat-intel mailers, Substack-style newsletters) are easiest -
or only - followed by email. A newsletter source names the senders (addresses or domains) and, optionally, words
the subject must contain; every matching message becomes an article that goes through the normal pipeline
(sanitiser, entities, rules, reports, alerts).

Security
--------
* **TLS only** (IMAPS, implicit TLS, certificate and host name verified). No plain IMAP, no STARTTLS downgrade.
* **SSRF guard:** the mail server's address is resolved and checked like every other outbound request
  (``netguard``): private / loopback / link-local addresses are refused unless the exact host:port is in
  ``EOS_PRIVATE_ALLOWLIST``. The connection is pinned to the checked address (no DNS rebinding between check and
  connect), while TLS still verifies the real host name.
* **Read-only:** the folder is opened with EXAMINE and messages are read with BODY.PEEK - nothing is marked read,
  moved or deleted.
* **Credentials** live encrypted in ``integrations`` (name ``imap``) and are never returned by the API.
* **Untrusted content:** message HTML is sanitised like feed HTML; tracking pixels are dropped; sizes, counts and
  timeouts are capped.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import imaplib
import logging
import re
import socket
import ssl
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr, parsedate_to_datetime

from app import integrations, netguard
from app.db import get_db
from app.sanitize import sanitize_html, to_text

log = logging.getLogger("eos.mailfeeds")

TIMEOUT = 30
MAX_MESSAGE_BYTES = 3 * 1024 * 1024
MAX_MESSAGES = 60          # per fetch (newest first)
FIRST_DAYS = 30            # how far back the first fetch looks
LATER_DAYS = 4             # later fetches: a short overlap (duplicates are skipped by Message-ID)
SENDER = re.compile(r"^(?:[A-Za-z0-9._%+-]{1,64}@)?(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
FOLDER = re.compile(r"^[A-Za-z0-9 ._/&+-]{1,100}$")
HOST = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$|^\[?[0-9a-fA-F:.]+\]?$")
_PIXEL = re.compile(r"<img\b[^>]*\b(?:width|height)=\"[0-3]\"[^>]*>", re.IGNORECASE)
_VIEW_ONLINE = re.compile(r"<a\b[^>]*\bhref=\"(https?://[^\"]{1,2000})\"[^>]*>(?:(?!</a>).){0,200}?"
                          r"(?:view|read|open)\s+(?:this\s+(?:email|message|newsletter)\s+)?(?:it\s+)?"
                          r"(?:online|in\s+(?:your|a|the)\s+browser|on\s+the\s+web)", re.IGNORECASE | re.DOTALL)


class MailError(Exception):
    pass


class _PinnedIMAP(imaplib.IMAP4_SSL):
    """IMAPS to an already-checked IP address, verifying the certificate against the real host name."""

    def __init__(self, host: str, port: int, address: str, context: ssl.SSLContext) -> None:
        self._address = address
        super().__init__(host, port, ssl_context=context, timeout=TIMEOUT)

    def _create_socket(self, timeout):  # noqa: ANN001 - imaplib's signature
        sock = socket.create_connection((self._address, self.port), timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def account() -> tuple[dict, dict]:
    with get_db() as db:
        return integrations.load(db, "imap")


def connect(config: dict | None = None, password: str | None = None) -> imaplib.IMAP4_SSL:
    """Log in to the configured (or given) mailbox. Raises MailError with a readable message."""
    if config is None:
        config, secrets = account()
        password = secrets.get("password")
    host, port, user = config.get("host"), int(config.get("port") or 993), config.get("username")
    if not host or not user or not password:
        raise MailError("No mailbox is set up (Settings → Integrations → Email newsletters)")
    if not HOST.match(host) or not 1 <= port <= 65535:
        raise MailError("The mail server address is not valid")
    try:
        addresses = netguard.resolve_host(host.strip("[]"), port, netguard.private_ok(host.strip("[]"), port, False))  # LAN mail servers: EOS_PRIVATE_ALLOWLIST only
    except netguard.UnsafeURLError as exc:
        raise MailError(f"Mail server refused by the SSRF guard: {exc}") from None
    except netguard.FetchError:
        raise MailError(f"Could not find the mail server {host} (DNS lookup failed)") from None
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        conn = _PinnedIMAP(host.strip("[]"), port, str(addresses[0]), context)
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as exc:
        raise MailError(f"Could not connect to {host}:{port} over TLS ({type(exc).__name__})") from None
    try:
        conn.login(user, password)
    except imaplib.IMAP4.error:
        _close(conn)
        raise MailError("The mail server refused the login (for Gmail / Outlook use an app password)") from None
    return conn


def _close(conn) -> None:
    try:
        conn.logout()
    except Exception:  # noqa: BLE001 - best effort
        pass


def test_login(config: dict, password: str) -> list[str]:
    """Log in and list the folders (used when saving the mailbox settings)."""
    conn = connect(config, password)
    try:
        typ, data = conn.list()
        folders = []
        for raw in data or []:
            line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            name = line.rsplit(' "/" ', 1)[-1].rsplit(' "." ', 1)[-1].strip().strip('"')
            if FOLDER.match(name):
                folders.append(name)
        return sorted(set(folders))[:200]
    finally:
        _close(conn)


def _search(conn, senders: list[str], since: datetime) -> list[bytes]:
    date = since.strftime("%d-%b-%Y")
    uids: set[int] = set()
    for sender in senders:  # validated by SENDER: no quotes or spaces can reach the command
        typ, data = conn.uid("SEARCH", None, "SINCE", date, "FROM", f'"{sender}"')
        if typ == "OK" and data and data[0]:
            uids.update(int(u) for u in data[0].split() if u.isdigit())
    return [str(u).encode() for u in sorted(uids, reverse=True)[:MAX_MESSAGES]]


def _sender_ok(from_addr: str, senders: list[str]) -> bool:
    addr = from_addr.lower()
    domain = addr.rsplit("@", 1)[-1]
    for s in senders:
        s = s.lower()
        if "@" in s and addr == s:
            return True
        if "@" not in s and (domain == s or domain.endswith("." + s)):
            return True
    return False


def _body(msg) -> str:
    part = msg.get_body(preferencelist=("html", "plain"))
    if part is None:
        return ""
    try:
        text = part.get_content()
    except (LookupError, ValueError):
        payload = part.get_payload(decode=True) or b""
        text = payload.decode("utf-8", "replace")
    if part.get_content_type() == "text/plain":
        from app.sources import text_to_html

        return text_to_html(text[:200_000])
    return text


def parse_message(raw: bytes, senders: list[str], subject_contains: str | None) -> dict | None:
    """One email -> a feedparser-like entry, or None if it doesn't belong to this newsletter."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    name, from_addr = parseaddr(str(msg.get("From", "")))
    if not from_addr or not _sender_ok(from_addr, senders):
        return None
    subject = to_text(str(msg.get("Subject", "")), 1000) or "(no subject)"
    if subject_contains and subject_contains.lower() not in subject.lower():
        return None
    try:
        when = parsedate_to_datetime(str(msg.get("Date", "")))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        published = int(when.timestamp())
    except (TypeError, ValueError, IndexError, OverflowError):
        published = None
    message_id = str(msg.get("Message-ID", "")).strip()
    guid_src = message_id or f"{from_addr}|{subject}|{published}"
    guid = "mail:" + hashlib.sha256(guid_src.encode("utf-8", "replace")).hexdigest()
    html_body = sanitize_html(_body(msg))
    html_body = _PIXEL.sub("", html_body)  # 1x1 tracking images
    view = _VIEW_ONLINE.search(html_body)
    link = None
    if view:
        try:
            link = netguard.normalize_url(view.group(1).replace("&amp;", "&"))
        except netguard.UnsafeURLError:
            link = None
    published_parsed = datetime.fromtimestamp(published, timezone.utc).timetuple() if published else None
    return {"id": guid, "title": subject, "link": link, "author": to_text(name, 300) or from_addr,
            "summary": html_body, "published_parsed": published_parsed}


def fetch(cfg, first: bool) -> tuple[list[dict], str]:
    """Matching messages from the mailbox (newest first) and the mailbox name, for sources.fetch()."""
    conn = connect()
    try:
        folder = cfg.folder
        typ, _ = conn.select(f'"{folder}"', readonly=True)  # EXAMINE: read-only
        if typ != "OK":
            raise MailError(f"Folder {folder!r} not found in the mailbox")
        since = datetime.now(timezone.utc) - timedelta(days=FIRST_DAYS if first else LATER_DAYS)
        entries: list[dict] = []
        for uid in _search(conn, cfg.senders, since):
            typ, data = conn.uid("FETCH", uid, "(RFC822.SIZE)")
            size = 0
            if typ == "OK" and data and isinstance(data[0], bytes):
                m = re.search(rb"RFC822\.SIZE (\d+)", data[0])
                size = int(m.group(1)) if m else 0
            if size > MAX_MESSAGE_BYTES:
                log.info("Skipped a %d-byte message in %s (over the size limit)", size, folder)
                continue
            typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((item[1] for item in data or [] if isinstance(item, tuple) and len(item) > 1), None)
            if typ != "OK" or not raw or len(raw) > MAX_MESSAGE_BYTES:
                continue
            entry = parse_message(raw, cfg.senders, cfg.subject_contains)
            if entry:
                entries.append(entry)
        return entries, folder
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as exc:
        raise MailError(f"Reading the mailbox failed ({type(exc).__name__})") from None
    finally:
        _close(conn)
