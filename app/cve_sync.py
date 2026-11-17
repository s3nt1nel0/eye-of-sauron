"""CVE ingestion from official sources.

* **NVD CVE API 2.0** (https://services.nvd.nist.gov/rest/json/cves/2.0) - the source NIST
  recommends since retiring its RSS and legacy JSON feeds. Back-fill by publication date, then
  incremental sync by last-modified date. Public rate limit: 5 requests / 30 s (50 with a free
  API key in FEEDWARDEN_NVD_API_KEY), so requests are spaced accordingly.
* **CISA Known Exploited Vulnerabilities** JSON catalog - exploited-in-the-wild flag, date added,
  due date, known ransomware use. KEV CVEs missing locally are fetched from NVD (``hasKev``).
* **MITRE CWE catalog** (cwec_latest.xml.zip) - weakness names and the official OWASP Top Ten
  2021 / 2025 category mappings.

Every request goes through netguard (SSRF policy, size/time limits). All payloads are
untrusted: IDs are pattern-checked, text is length-capped and stored as plain text, URLs are
normalised, the CWE XML is parsed with defusedxml from a size-checked zip member.
"""

from __future__ import annotations

import io
import json
import logging
import re
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlencode

from defusedxml import ElementTree as SafeET

from app import app_settings, cve_classify, netguard
from app.config import get_settings
from app.db import get_db, now

log = logging.getLogger("feedwarden.cve")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CWE_RE = re.compile(r"^CWE-(\d{1,5})$")
OWASP_RE = re.compile(r"OWASP Top Ten (20\d\d) Category (A\d\d):20\d\d\s*-\s*(.+)$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED")
PAGE_SIZE = 1000
MAX_PAGES_PER_RUN = 300
MAX_WINDOW_DAYS = 119  # NVD allows at most 120 days per date range
KEV_INTERVAL = 6 * 3600
CWE_INTERVAL = 7 * 86400
MAX_CWE_XML = 120 * 1024 * 1024


class SyncError(Exception):
    pass


# =========================================================================== state
def get_state(db, key: str, default: str | None = None) -> str | None:
    row = db.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key: str, value: str) -> None:
    db.execute("INSERT INTO sync_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
               (key, value))


# =========================================================================== parsing
def _ts(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(value[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _pick_metric(metrics: dict) -> tuple[float | None, str | None, str, str | None]:
    """Preferred CVSS: v3.1, then v4.0, v3.0, v2. Within a version prefer NVD's Primary score."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = next((e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"), entries[0])
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        if not isinstance(score, (int, float)) or not 0 <= score <= 10:
            continue
        severity = severity.upper() if isinstance(severity, str) and severity.upper() in SEVERITIES else _severity_for(score)
        vector = data.get("vectorString")
        return float(score), version, severity, vector[:200] if isinstance(vector, str) else None
    return None, None, "UNSCORED", None


def _severity_for(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _cpe_parts(cpe: str) -> tuple[str, str] | None:
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3], parts[4]
    return None


_JUNK = {"na", "unknown", "none", "nothing", "notapplicable", "unspecified", "various", "multiple", "vendor", "product"}


def _products(cve: dict) -> dict[tuple[str, str], tuple[str, str]]:
    found: dict[tuple[str, str], tuple[str, str]] = {}

    def add(vendor: str, product: str) -> None:
        vk, pk = cve_classify.norm_key(vendor), cve_classify.norm_key(product)
        if not vk or not pk or vk in _JUNK or pk in _JUNK or len(found) >= 60:
            return
        label = (_text(vendor, 80).replace("_", " "), _text(product, 120).replace("_", " "))
        # Prefer human labels ("Palo Alto Networks") over CPE keys ("paloaltonetworks").
        if (vk, pk) not in found or (" " in label[0] and " " not in found[(vk, pk)][0]):
            found[(vk, pk)] = label

    for block in cve.get("affected") or []:
        for item in (block or {}).get("affectedData") or []:
            if not isinstance(item, dict):
                continue
            versions = item.get("versions") or []
            affected = item.get("defaultStatus") == "affected" or any(
                isinstance(v, dict) and v.get("status") == "affected" for v in versions)
            if not affected and not item.get("cpes"):
                continue
            if isinstance(item.get("vendor"), str) and isinstance(item.get("product"), str):
                add(item["vendor"], item["product"])
            for cpe in item.get("cpes") or []:
                parts = _cpe_parts(cpe) if isinstance(cpe, str) else None
                if parts:
                    add(*parts)
    for conf in cve.get("configurations") or []:
        for node in (conf or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("vulnerable") and isinstance(match.get("criteria"), str):
                    parts = _cpe_parts(match["criteria"])
                    if parts:
                        add(*parts)
    return found


def parse_nvd(item: dict) -> dict | None:
    cve = (item or {}).get("cve") or {}
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not CVE_ID_RE.match(cve_id):
        return None
    desc = next((d.get("value") for d in cve.get("descriptions") or []
                 if isinstance(d, dict) and d.get("lang") == "en"), "")
    score, version, severity, vector = _pick_metric(cve.get("metrics") or {})
    cwes: set[int] = set()
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            m = CWE_RE.match(str((d or {}).get("value", "")))
            if m:
                cwes.add(int(m.group(1)))
    exploitation = None
    for s in (cve.get("metrics") or {}).get("ssvcV203") or []:
        for opt in ((s or {}).get("ssvcData") or {}).get("options") or []:
            if isinstance(opt, dict) and isinstance(opt.get("exploitation"), str):
                exploitation = opt["exploitation"].lower()[:10]
    refs = []
    for r in cve.get("references") or []:
        try:
            refs.append(netguard.normalize_url(r.get("url", "")))
        except (netguard.UnsafeURLError, AttributeError):
            continue
        if len(refs) >= 8:
            break
    kev_added = _ts(cve.get("cisaExploitAdd"))
    return {
        "id": cve_id, "published": _ts(cve.get("published")), "last_modified": _ts(cve.get("lastModified")),
        "status": _text(cve.get("vulnStatus"), 40), "description": _text(desc, 4000), "score": score,
        "cvss_version": version, "severity": severity, "vector": vector,
        "kev": 1 if kev_added else 0, "kev_added": kev_added, "kev_due": _ts(cve.get("cisaActionDue")),
        "kev_name": _text(cve.get("cisaVulnerabilityName"), 300) or None,
        "exploitation": exploitation, "refs": json.dumps(refs), "cwes": cwes, "products": _products(cve),
    }


def upsert(db, records: Iterable[dict], source: str = "nvd") -> list[str]:
    ids: list[str] = []
    ts = now()
    for r in records:
        db.execute(
            "INSERT INTO cves (id, published, last_modified, status, description, score, cvss_version, severity, vector, "
            "kev, kev_added, kev_due, kev_name, exploitation, refs, source, fetched_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "published = COALESCE(excluded.published, cves.published), last_modified = excluded.last_modified, "
            "status = excluded.status, description = excluded.description, score = excluded.score, "
            "cvss_version = excluded.cvss_version, severity = excluded.severity, vector = excluded.vector, "
            "kev = MAX(cves.kev, excluded.kev), kev_added = COALESCE(excluded.kev_added, cves.kev_added), "
            "kev_due = COALESCE(excluded.kev_due, cves.kev_due), kev_name = COALESCE(excluded.kev_name, cves.kev_name), "
            "exploitation = excluded.exploitation, refs = excluded.refs, source = excluded.source, "
            "fetched_at = excluded.fetched_at",
            (r["id"], r["published"], r["last_modified"], r["status"], r["description"], r["score"], r["cvss_version"],
             r["severity"], r["vector"], r["kev"], r["kev_added"], r["kev_due"], r["kev_name"], r["exploitation"],
             r["refs"], source, ts),
        )
        db.execute("DELETE FROM cve_cwes WHERE cve_id = ?", (r["id"],))
        db.executemany("INSERT OR IGNORE INTO cve_cwes (cve_id, cwe_id) VALUES (?, ?)", [(r["id"], c) for c in r["cwes"]])
        db.execute("DELETE FROM cve_products WHERE cve_id = ?", (r["id"],))
        db.executemany(
            "INSERT OR IGNORE INTO cve_products (cve_id, vendor_key, product_key, vendor_label, product_label) VALUES (?,?,?,?,?)",
            [(r["id"], vk, pk, vl, pl) for (vk, pk), (vl, pl) in r["products"].items()])
        ids.append(r["id"])
    return ids


# =========================================================================== HTTP
class NvdClient:
    def __init__(self) -> None:
        self.key = get_settings().nvd_api_key
        self.spacing = 0.8 if self.key else 6.5  # stay under 50 / 5 requests per rolling 30 s
        self._last = 0.0

    def get(self, params: dict[str, str]) -> dict:
        headers = {"User-Agent": get_settings().user_agent, "Accept": "application/json"}
        if self.key:
            headers["apiKey"] = self.key  # header, never the query string
        url = f"{NVD_URL}?{urlencode(params)}"
        for attempt in range(4):
            wait = self.spacing - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                resp = netguard.request("GET", url, headers=headers, timeout=60, max_bytes=32 * 1024 * 1024)
            except (netguard.FetchError, netguard.UnsafeURLError) as exc:
                if attempt == 3:
                    raise SyncError(f"NVD request failed: {exc}") from None
                time.sleep(10 * (attempt + 1))
                continue
            if resp.status_code in (403, 429, 500, 502, 503, 504):
                if attempt == 3:
                    raise SyncError(f"NVD API HTTP {resp.status_code} (rate limited or unavailable)")
                time.sleep(30 * (attempt + 1))
                continue
            if resp.status_code != 200:
                raise SyncError(f"NVD API HTTP {resp.status_code}")
            try:
                data = json.loads(resp.content)
            except ValueError:
                raise SyncError("NVD API returned invalid JSON") from None
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise SyncError("NVD API returned an unexpected document")
            return data
        raise SyncError("NVD request failed")

    def iterate(self, params: dict[str, str], stop: threading.Event, progress) -> Iterable[list[dict]]:
        start, pages = 0, 0
        while not stop.is_set() and pages < MAX_PAGES_PER_RUN:
            data = self.get({**params, "resultsPerPage": str(PAGE_SIZE), "startIndex": str(start)})
            batch = [r for r in (parse_nvd(v) for v in data["vulnerabilities"]) if r]
            yield batch
            total = int(data.get("totalResults") or 0)
            start += int(data.get("resultsPerPage") or len(data["vulnerabilities"]) or PAGE_SIZE)
            pages += 1
            progress(min(start, total), total)
            if start >= total or not data["vulnerabilities"]:
                break


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    out, cur = [], start
    while cur < end:
        nxt = min(cur + timedelta(days=MAX_WINDOW_DAYS), end)
        out.append((cur, nxt))
        cur = nxt
    return out


def _fetch_json(url: str, max_bytes: int) -> Any:
    resp = netguard.request("GET", url, headers={"User-Agent": get_settings().user_agent, "Accept": "application/json"},
                            timeout=60, max_bytes=max_bytes)
    if resp.status_code != 200:
        raise SyncError(f"HTTP {resp.status_code}")
    return json.loads(resp.content)


# =========================================================================== CWE catalog
def parse_cwe_zip(blob: bytes) -> tuple[list[tuple[int, str, str]], list[tuple[int, str, str, str]]]:
    """Return (entries [(id, name, kind)], owasp [(cwe_id, edition, code, name)]) from cwec_latest.xml.zip."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        members = [i for i in zf.infolist() if i.filename.lower().endswith(".xml") and "/" not in i.filename.strip("/")]
        if len(members) != 1:
            raise SyncError("CWE archive: expected exactly one XML file")
        info = members[0]
        if info.file_size > MAX_CWE_XML or (info.compress_size and info.file_size / info.compress_size > 200):
            raise SyncError("CWE archive: XML too large / suspicious compression ratio")  # zip-bomb guard
        with zf.open(info) as fh:
            data = fh.read(MAX_CWE_XML + 1)
    if len(data) > MAX_CWE_XML:
        raise SyncError("CWE archive: XML too large")
    root = SafeET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    entries: list[tuple[int, str, str]] = []
    owasp: list[tuple[int, str, str, str]] = []

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for el in root.iter():
        kind = local(el.tag)
        if kind not in ("Weakness", "Category", "Grouping"):  # CWE 5.0 renamed Category -> Grouping
            continue
        try:
            cid = int(el.get("ID", ""))
        except ValueError:
            continue
        name = (el.get("Name") or "")[:300]
        entries.append((cid, name, kind.lower()))
        if kind in ("Category", "Grouping"):
            m = OWASP_RE.match(name)
            if m:
                edition, code, title = m.group(1), m.group(2), m.group(3).strip()[:120]
                for rel in el.iter():
                    if local(rel.tag) == "Has_Member":
                        try:
                            owasp.append((int(rel.get("CWE_ID", "")), edition, code, title))
                        except ValueError:
                            continue
    if len(entries) < 50:
        raise SyncError("CWE catalog looks empty")
    return entries, owasp


def sync_cwe() -> str:
    resp = netguard.request("GET", CWE_URL, headers={"User-Agent": get_settings().user_agent},
                            timeout=120, max_bytes=40 * 1024 * 1024)
    if resp.status_code != 200:
        raise SyncError(f"CWE download HTTP {resp.status_code}")
    entries, owasp = parse_cwe_zip(resp.content)
    with get_db() as db:
        db.execute("DELETE FROM cwe_entries")
        db.executemany("INSERT OR REPLACE INTO cwe_entries (id, name, kind) VALUES (?, ?, ?)", entries)
        db.execute("DELETE FROM cwe_owasp")
        db.executemany("INSERT OR IGNORE INTO cwe_owasp (cwe_id, edition, code, name) VALUES (?, ?, ?, ?)", owasp)
        set_state(db, "cwe_synced", str(now()))
    return f"{len(entries)} CWE entries, {len(owasp)} OWASP mappings"


# =========================================================================== KEV
def apply_kev(doc: dict) -> tuple[int, list[str]]:
    """Mark KEV entries; returns (count, ids missing locally)."""
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        raise SyncError("KEV catalog: unexpected format")
    missing: list[str] = []
    count = 0
    with get_db() as db:
        known = {r[0] for r in db.execute("SELECT id FROM cves")}
        for v in vulns:
            if not isinstance(v, dict) or not CVE_ID_RE.match(str(v.get("cveID", ""))):
                continue
            cid = v["cveID"]
            added, due = _ts(v.get("dateAdded")), _ts(v.get("dueDate"))
            ransomware = 1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0
            name = _text(v.get("vulnerabilityName"), 300) or None
            if cid not in known:
                # Placeholder until NVD enrichment (hasKev) fills in scores/CWEs/products.
                rec = {"id": cid, "published": added, "last_modified": added, "status": "KEV",
                       "description": _text(v.get("shortDescription"), 4000), "score": None, "cvss_version": None,
                       "severity": "UNSCORED", "vector": None, "kev": 1, "kev_added": added, "kev_due": due,
                       "kev_name": name, "exploitation": "active", "refs": "[]", "cwes": set(), "products": {}}
                for c in v.get("cwes") or []:
                    m = CWE_RE.match(str(c))
                    if m:
                        rec["cwes"].add(int(m.group(1)))
                vendor, product = _text(v.get("vendorProject"), 80), _text(v.get("product"), 120)
                if cve_classify.norm_key(vendor) and cve_classify.norm_key(product):
                    rec["products"] = {(cve_classify.norm_key(vendor), cve_classify.norm_key(product)): (vendor, product)}
                upsert(db, [rec], source="kev")
                missing.append(cid)
            db.execute(
                "UPDATE cves SET kev = 1, kev_added = COALESCE(?, kev_added), kev_due = COALESCE(?, kev_due), "
                "kev_ransomware = ?, kev_name = COALESCE(?, kev_name) WHERE id = ?",
                (added, due, ransomware, name, cid))
            count += 1
        set_state(db, "kev_synced", str(now()))
        set_state(db, "kev_count", str(count))
    return count, missing


# =========================================================================== orchestration
class CveSync:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.progress: dict[str, Any] = {"phase": "idle"}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        self._stop.set()

    def start(self, force: bool = False) -> bool:
        with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, args=(force,), name="cve-sync", daemon=True)
            self._thread.start()
            return True

    def maybe_start(self) -> None:
        """Scheduler hook: start a sync when enabled and due."""
        if self.running:
            return
        with get_db() as db:
            prefs = app_settings.get_all(db)
            last = int(get_state(db, "nvd_run_at", "0") or 0)
        if prefs["cve_enabled"] and now() - last >= prefs["cve_sync_minutes"] * 60:
            self.start()

    def _set(self, **kw: Any) -> None:
        self.progress = {**self.progress, **kw}

    def _run(self, force: bool) -> None:
        started = now()
        errors: list[str] = []
        self.progress = {"phase": "starting", "started": started}
        try:
            with get_db() as db:
                cve_classify.seed_builtin(db)
                prefs = app_settings.get_all(db)
                cwe_at = int(get_state(db, "cwe_synced", "0") or 0)
                kev_at = int(get_state(db, "kev_synced", "0") or 0)
            if force or now() - cwe_at >= CWE_INTERVAL:
                self._set(phase="CWE catalog")
                try:
                    msg = sync_cwe()
                    log.info("CWE catalog updated: %s", msg)
                except (SyncError, netguard.FetchError, netguard.UnsafeURLError, zipfile.BadZipFile,
                        SafeET.ParseError, ValueError) as exc:
                    errors.append(f"CWE: {exc}")
            client = NvdClient()
            self._sync_nvd(client, prefs["cve_backfill_days"], errors)
            if force or now() - kev_at >= KEV_INTERVAL:
                self._set(phase="CISA KEV")
                self._sync_kev(client, errors)
        except Exception as exc:  # never kill the scheduler
            log.exception("CVE sync crashed")
            errors.append(f"Unexpected error: {type(exc).__name__}")
        finally:
            with get_db() as db:
                set_state(db, "nvd_run_at", str(started))
                set_state(db, "last_error", "; ".join(errors)[:500])
                set_state(db, "last_finished", str(now()))
            self.progress = {"phase": "idle", "errors": errors}

    def _store(self, batch: list[dict], source: str = "nvd") -> int:
        if not batch:
            return 0
        with get_db() as db:
            ids = upsert(db, batch, source)
            cve_classify.classify(db, ids)
        from app import alerts  # local import: alerts -> ai -> integrations

        alerts.check_cves(ids)  # new high-severity / matching CVEs -> instant alerts (exactly once per rule)
        return len(ids)

    def _sync_nvd(self, client: NvdClient, backfill_days: int, errors: list[str]) -> None:
        end = datetime.now(timezone.utc)
        with get_db() as db:
            cursor = get_state(db, "nvd_last_mod")
        stored = 0
        try:
            last = datetime.fromisoformat(cursor) if cursor else None
            if last is None or end - last > timedelta(days=MAX_WINDOW_DAYS):
                # First run (or long outage): back-fill by publication date.
                start = end - timedelta(days=backfill_days)
                for a, b in _windows(start, end):
                    self._set(phase=f"NVD back-fill {a:%Y-%m-%d} → {b:%Y-%m-%d}")
                    for batch in client.iterate({"pubStartDate": _iso(a), "pubEndDate": _iso(b)}, self._stop,
                                                lambda d, t: self._set(done=d, total=t)):
                        stored += self._store(batch)
            else:
                start = last - timedelta(minutes=10)  # small overlap; upserts are idempotent
                self._set(phase="NVD changes since last sync")
                for batch in client.iterate({"lastModStartDate": _iso(start), "lastModEndDate": _iso(end)}, self._stop,
                                            lambda d, t: self._set(done=d, total=t)):
                    stored += self._store(batch)
            if not self._stop.is_set():
                with get_db() as db:
                    set_state(db, "nvd_last_mod", end.isoformat())
                    set_state(db, "nvd_synced", str(now()))
            log.info("NVD sync stored %d CVE records", stored)
        except SyncError as exc:
            errors.append(str(exc))
            log.warning("NVD sync: %s (stored %d before the error)", exc, stored)

    def _sync_kev(self, client: NvdClient, errors: list[str]) -> None:
        doc = None
        for url in (KEV_URL, KEV_MIRROR):
            try:
                doc = _fetch_json(url, 20 * 1024 * 1024)
                break
            except (SyncError, netguard.FetchError, netguard.UnsafeURLError, ValueError) as exc:
                errors.append(f"KEV ({url.split('/')[2]}): {exc}")
        if doc is None:
            return
        try:
            count, missing = apply_kev(doc)
            errors[:] = [e for e in errors if not e.startswith("KEV")]  # mirror worked
            if missing:
                self._set(phase=f"NVD details for {len(missing)} KEV entries")
                for batch in client.iterate({"hasKev": ""}, self._stop, lambda d, t: self._set(done=d, total=t)):
                    self._store(batch)
            with get_db() as db:
                cve_classify.classify(db, missing)
                recent_kev = [r[0] for r in db.execute("SELECT id FROM cves WHERE kev_added >= ?", (now() - 3 * 86400,))]
            from app import alerts

            alerts.check_cves(recent_kev)  # "added to KEV" alerts; alerts_sent dedupes repeats
            log.info("CISA KEV: %d entries (%d new locally)", count, len(missing))
        except SyncError as exc:
            errors.append(f"KEV: {exc}")


cve_sync = CveSync()
