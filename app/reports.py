"""Threat reports and guidance from government agencies, national CERTs and security vendors.

Which items count
  * the item comes from a known publisher - recognised by its FEED's address (not the article link, so news sites
    that write about a report do not count): government agencies and national CERTs (CISA, ASD's ACSC, NCSC UK,
    CERT-EU, ENISA, the Canadian Centre for Cyber Security, CERT-FR, JPCERT, FBI IC3, …) and security vendors'
    research teams (Mandiant, Microsoft Threat Intelligence, CrowdStrike, Unit 42, Talos, Check Point Research, …);
  * and it is a publication: an advisory, a piece of guidance or a report. Government items count unless they are
    plainly news / events; items from a vendor's *research* feed count unless they are marketing (webinar, event,
    award, careers…); items from a vendor's general blog count only when the wording says report / research /
    guidance or the item names a threat actor.

Each publication gets a row in ``publications`` (publisher, government|vendor, advisory|guidance|report). The
Articles tab shows them under 📑 Reports & guidance; ``notify()`` sends new ones to the delivery channels chosen in
Settings → Alerts & digests (one message per batch). Local only: no request is made here.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
from urllib.parse import urlsplit

from app import app_settings
from app.db import get_db, now, placeholders

log = logging.getLogger("eos.reports")

REV = "1"
# (host, path prefix, publisher, kind, research feed?)  - matched against the FEED's url / site url
PUBLISHERS: list[tuple[str, str, str, str, bool]] = [
    # ---- government agencies and national CERTs
    ("cisa.gov", "", "CISA", "government", True),
    ("github.com", "/cisagov/", "CISA", "government", True),
    ("cyber.gov.au", "", "ASD's ACSC", "government", True),
    ("ncsc.gov.uk", "", "NCSC UK", "government", True),
    ("cert.europa.eu", "", "CERT-EU", "government", True),
    ("enisa.europa.eu", "", "ENISA", "government", True),
    ("cyber.gc.ca", "", "Canadian Centre for Cyber Security", "government", True),
    ("cert.ssi.gouv.fr", "", "CERT-FR (ANSSI)", "government", True),
    ("jpcert.or.jp", "", "JPCERT/CC", "government", True),
    ("ic3.gov", "", "FBI IC3", "government", True),
    ("nsa.gov", "", "NSA", "government", True),
    ("defense.gov", "", "NSA / DoD", "government", True),
    ("ncsc.govt.nz", "", "NCSC New Zealand", "government", True),
    ("bsi.bund.de", "", "BSI", "government", True),
    ("cert.pl", "", "CERT Polska", "government", True),
    ("circl.lu", "", "CIRCL", "government", True),
    ("cisecurity.org", "", "CIS / MS-ISAC", "government", True),
    # ---- vendor research teams (research feeds)
    ("cloudblog.withgoogle.com", "/topics/threat-intelligence", "Google Threat Intelligence (Mandiant)", "vendor", True),
    ("unit42.paloaltonetworks.com", "", "Unit 42", "vendor", True),
    ("blog.talosintelligence.com", "", "Cisco Talos", "vendor", True),
    ("securelist.com", "", "Kaspersky GReAT", "vendor", True),
    ("research.checkpoint.com", "", "Check Point Research", "vendor", True),
    ("recordedfuture.com", "", "Recorded Future", "vendor", True),
    ("sentinelone.com", "/labs", "SentinelLABS", "vendor", True),
    ("proofpoint.com", "/us/threat-insight", "Proofpoint", "vendor", True),
    ("zscaler.com", "/blogs/feeds/security-research", "Zscaler ThreatLabz", "vendor", True),
    ("feeds.fortinet.com", "/fortinet/blog/threat-research", "FortiGuard Labs", "vendor", True),
    ("bitdefender.com", "/blog/api/rss/labs", "Bitdefender Labs", "vendor", True),
    ("welivesecurity.com", "", "ESET Research", "vendor", True),
    ("volexity.com", "", "Volexity", "vendor", True),
    ("elastic.co", "/security-labs", "Elastic Security Labs", "vendor", True),
    ("dragos.com", "", "Dragos", "vendor", True),
    ("claroty.com", "/team82", "Claroty Team82", "vendor", True),
    ("nozominetworks.com", "", "Nozomi Networks Labs", "vendor", True),
    ("infostealers.com", "", "Hudson Rock", "vendor", True),
    ("malware-traffic-analysis.net", "", "Malware-Traffic-Analysis", "vendor", True),
    # ---- vendor blogs that mix research with product news
    ("microsoft.com", "/en-us/security/blog", "Microsoft Threat Intelligence", "vendor", False),
    ("crowdstrike.com", "", "CrowdStrike", "vendor", False),
    ("paloaltonetworks.com", "/blog", "Palo Alto Networks", "vendor", False),
    ("redcanary.com", "", "Red Canary", "vendor", False),
    ("huntress.com", "", "Huntress", "vendor", False),
    ("rapid7.com", "", "Rapid7", "vendor", False),
    ("socradar.io", "", "SOCRadar", "vendor", False),
    ("sophos.com", "", "Sophos X-Ops", "vendor", False),
    ("malwarebytes.com", "", "Malwarebytes Labs", "vendor", False),
    ("darktrace.com", "", "Darktrace", "vendor", False),
    ("tenable.com", "", "Tenable", "vendor", False),
    ("feeds.feedburner.com", "/tenable/", "Tenable", "vendor", False),
    ("trendmicro.com", "", "Trend Micro Research", "vendor", False),
    ("kaspersky.co.uk", "", "Kaspersky", "vendor", False),
    ("huntress.com", "/blog", "Huntress", "vendor", False),
    ("levelblue.com", "", "LevelBlue", "vendor", False),
    ("nviso.eu", "", "NVISO Labs", "vendor", False),
    ("nextron-systems.com", "", "Nextron Systems", "vendor", False),
    ("security.googleblog.com", "", "Google Security", "vendor", False),
]
ADVISORY = re.compile(r"\b(advisory|advisories|alert|alerts|bulletin|flash|PSA|CSA|ICSA-\d|AA\d{2}-\d{3}|vulnerabilit(y|ies)|"
                      r"exploited|patch(es)?|KEV|known exploited)\b", re.I)
GUIDANCE = re.compile(r"\b(guidance|guide|guidelines|best practices?|recommendations?|how to|hardening|mitigations?|"
                      r"fact ?sheet|playbook|framework|principles|secure by (design|default)|checklist|toolkit|"
                      r"strategy|essential eight|baseline|standard|handbook|primer)\b", re.I)
REPORT = re.compile(r"\b(report|reports|threat report|annual|quarterly|year in review|review|landscape|trends|outlook|"
                    r"index|white ?paper|research|analysis|investigation|deep dive|campaign|operation|uncover(s|ed|ing)?|"
                    r"inside|tracking|threat assessment|assessment|intelligence (brief|summary)|technical|case study|"
                    r"\.pdf|download the)\b", re.I)
NOT_PUBLICATION = re.compile(r"\(AV\d{2}-\d+\)|\b(webinar|register now|join us|event|conference recap|award|awards|named a leader|"
                             r"a leader in|magic quadrant|forrester wave|datasheet|data sheet|"
                             r"careers?|hiring|we'?re hiring|press release|partnership|partners with|customer story|"
                             r"product (update|launch|news)|now available|introducing|announces?|podcast|livestream|"
                             r"newsletter|week in review|this week in)\b", re.I)
GOV_NEWS = re.compile(r"\b(news|speech|statement|remarks|testimony|appoint(s|ed|ment)|director|event|conference|"
                      r"job|vacanc(y|ies)|career|recruit|welcomes?|celebrat)\b", re.I)
DOC_TYPES = ("advisory", "guidance", "report")
KINDS = ("government", "vendor")
_lock = threading.Lock()


def publisher_of(feed_url: str | None, site_url: str | None) -> tuple[str, str, bool] | None:
    """(publisher, kind, research feed?) for a feed, or None."""
    for url in (feed_url, site_url):
        try:
            parts = urlsplit(url or "")
        except ValueError:
            continue
        host = (parts.hostname or "").lower().removeprefix("www.")
        path = parts.path.lower()
        best = None
        for h, prefix, name, kind, research in PUBLISHERS:
            if (host == h or host.endswith("." + h)) and path.startswith(prefix.lower()):
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, (name, kind, research))
        if best:
            return best[1]
    return None


def classify(title: str, text: str, kind: str, research: bool, names_actor: bool = False) -> str | None:
    """advisory | guidance | report, or None when the item is not a publication."""
    head = title or ""
    body = (text or "")[:1500]
    if NOT_PUBLICATION.search(head):
        return None
    for doc, rx in (("guidance", GUIDANCE), ("advisory", ADVISORY), ("report", REPORT)):
        if rx.search(head):
            return doc
    if kind == "government":
        if GOV_NEWS.search(head):
            return None
        for doc, rx in (("guidance", GUIDANCE), ("advisory", ADVISORY), ("report", REPORT)):
            if rx.search(body):
                return doc
        return "advisory"
    if research:
        return "report"
    if names_actor or REPORT.search(body[:600]):
        return "report"
    return None


def _feeds(db: sqlite3.Connection) -> dict[int, tuple[str, str, bool]]:
    out = {}
    for f in db.execute("SELECT id, url, site_url FROM feeds WHERE COALESCE(kind, 'rss') NOT IN ('youtube', 'podcast') "
                        "AND social_platform IS NULL"):
        pub = publisher_of(f["url"], f["site_url"])
        if pub:
            out[f["id"]] = pub
    return out


def assign(db: sqlite3.Connection, article_ids: list[int]) -> list[int]:
    """Classify new articles (called in the fetcher's transaction, after entity extraction). Returns the new
    publication ids."""
    if not article_ids:
        return []
    feeds = _feeds(db)
    if not feeds:
        return []
    from app import threat_actors

    actor_entities = set(threat_actors._clusters(db)["primary"])
    found = []
    for start in range(0, len(article_ids), 500):
        chunk = article_ids[start : start + 500]
        rows = db.execute(f"SELECT id, feed_id, title, substr(COALESCE(text_content, ''), 1, 1500) AS body FROM articles "  # nosec B608
                          f"WHERE id IN ({placeholders(len(chunk))})", chunk).fetchall()
        named = {r[0] for r in db.execute(f"SELECT DISTINCT article_id FROM article_entities WHERE article_id IN ({placeholders(len(chunk))}) "  # nosec B608
                                          f"AND entity_id IN (SELECT value FROM json_each(?))", [*chunk, _json(actor_entities)])}
        for r in rows:
            pub = feeds.get(r["feed_id"])
            if not pub:
                continue
            doc = classify(r["title"], r["body"], pub[1], pub[2], r["id"] in named)
            if doc:
                db.execute("INSERT OR IGNORE INTO publications (article_id, publisher, kind, doc_type, created_at) VALUES (?, ?, ?, ?, ?)",
                           (r["id"], pub[0], pub[1], doc, now()))
                found.append(r["id"])
    return found


def _json(ids) -> str:
    import json

    return json.dumps(sorted(ids))


def rebuild() -> int:
    """Classify every stored article once (per REV) - short transactions."""
    from app.cve_sync import set_state

    with _lock:
        with get_db() as db:
            db.execute("DELETE FROM publications")
            ids = [r[0] for r in db.execute("SELECT id FROM articles ORDER BY id")]
        total = 0
        for start in range(0, len(ids), 5000):
            with get_db() as db:
                total += len(assign(db, ids[start : start + 5000]))
        with get_db() as db:
            set_state(db, "reports_rev", REV)
    log.info("Reports & guidance: %d publications among %d items", total, len(ids))
    return total


def ensure_current() -> None:
    from app.cve_sync import get_state

    with get_db() as db:
        stale = get_state(db, "reports_rev", "") != REV
    if stale:
        threading.Thread(target=rebuild, name="reports", daemon=True).start()


def counts(db: sqlite3.Connection) -> dict:
    out = {"total": 0, "unread": 0, "government": 0, "vendor": 0, "advisory": 0, "guidance": 0, "report": 0}
    for r in db.execute("SELECT p.kind, p.doc_type, a.is_read, COUNT(*) AS n FROM publications p JOIN articles a ON a.id = p.article_id "
                        "GROUP BY p.kind, p.doc_type, a.is_read"):
        out["total"] += r["n"]
        out["unread"] += r["n"] if not r["is_read"] else 0
        out[r["kind"]] += r["n"]
        out[r["doc_type"]] += r["n"]
    out["publishers"] = [dict(r) for r in db.execute(
        "SELECT publisher, kind, COUNT(*) AS n, MAX(a.sort_ts) AS latest FROM publications p JOIN articles a ON a.id = p.article_id "
        "GROUP BY publisher ORDER BY latest DESC")]
    return out


# ------------------------------------------------------------------ notifications
def notify(article_ids: list[int]) -> None:
    """Send new publications to the channels chosen in Settings (background thread; one message per batch)."""
    if not article_ids:
        return
    threading.Thread(target=_notify, args=(list(article_ids),), name="report-alerts", daemon=True).start()


def _notify(article_ids: list[int]) -> None:
    from app import delivery

    with get_db() as db:
        prefs = app_settings.get_all(db)
        channels = [int(c) for c in prefs["report_alert_channels"]]
        if not channels:
            return
        want = prefs["report_alert_kinds"]
        rows = db.execute(
            "SELECT a.id, a.title, a.url, p.publisher, p.kind, p.doc_type FROM publications p JOIN articles a ON a.id = p.article_id "
            f"WHERE p.article_id IN ({placeholders(len(article_ids))}) ORDER BY a.sort_ts DESC", article_ids).fetchall()  # nosec B608
        fresh = []
        for r in rows:
            if want != "all" and r["kind"] != want:
                continue
            cur = db.execute("INSERT OR IGNORE INTO alerts_sent (source, rule_id, item_key, title, sent_at) VALUES ('publication', 0, ?, ?, ?)",
                             (str(r["id"]), (r["title"] or "")[:300], now()))
            if cur.rowcount:
                fresh.append(dict(r))
    if not fresh:
        return
    label = {"advisory": "Advisory", "guidance": "Guidance", "report": "Report"}
    if len(fresh) == 1:
        r = fresh[0]
        msg = delivery.Message(f"📑 {label[r['doc_type']]} from {r['publisher']}: {r['title']}"[:200],
                               f"{r['publisher']} ({r['kind']}) published: {r['title']}", link=r["url"])
    else:
        body = "\n\n".join(f"• [{label[r['doc_type']]}] {r['publisher']}: {r['title']}" + (f"\n  {r['url']}" if r["url"] else "")
                           for r in fresh[:25])
        msg = delivery.Message(f"📑 {len(fresh)} new reports and guidance", body)
    errors = delivery.send_many(channels, msg)
    if errors:
        with get_db() as db:
            db.execute("UPDATE alerts_sent SET status = 'failed', error = ? WHERE source = 'publication' AND sent_at >= ?",
                       ("; ".join(errors)[:500], now() - 120))
