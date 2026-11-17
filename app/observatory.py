"""Observatory: public, keyless threat data for the dashboards, in the spirit of zerodayclock.com - simplified.

Sources (free, no key, read-only; fetched in the background on a slow schedule, paced, cached in
``observatory_cache``):
* NVD (services.nvd.nist.gov) - how many CVEs were published each month (one tiny request per month).
* CISA KEV - already in the local ``cves`` table (``kev_added``).
* ransomware.live - ransomware leak-site claims (victims per month; the latest 100).
* SANS Internet Storm Center (isc.sans.edu) - DShield's top attacking IPs (with their network / ASN) and top ports.
* Spamhaus ASN-DROP - networks run by or hijacked for criminals.

Every panel says how to read it and where the numbers come from. Panels are computed when a dashboard asks
(``panel(db, key)``) from the cache plus local data; nothing here runs on page load except reading the cache.
"""
from __future__ import annotations

import calendar
import datetime as dt
import ipaddress
import json
import logging
import statistics
import threading
import time
from typing import Any, Callable

from app import netguard
from app.config import get_settings
from app.db import get_db, now
from app.sanitize import to_text

log = logging.getLogger(__name__)

NVD_FROM = (2017, 1)
RW_FROM = (2022, 1)
NVD_GAP, RW_GAP, ISC_GAP = 6.5, 2.0, 1.5      # seconds between requests to each service (NVD: 5 per 30 s without a key)
RUN_BUDGET = 240                                # seconds of fetching per background run
EVERY_RUN = 15 * 60                             # a run at most every 15 minutes
TOP_IPS = 60                                    # attacking IPs looked up for their network


class ObservatoryError(Exception):
    pass


# ============================================================================ cache
def _load(db, key: str) -> tuple[Any, int]:
    row = db.execute("SELECT data, fetched_at FROM observatory_cache WHERE key = ?", (key,)).fetchone()
    return (json.loads(row["data"]), int(row["fetched_at"])) if row else (None, 0)


def _save(key: str, data: Any) -> None:
    with get_db() as db:
        db.execute("INSERT INTO observatory_cache (key, data, fetched_at) VALUES (?, ?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at",
                   (key, json.dumps(data, separators=(",", ":")), now()))


def _get_json(url: str, limit: int = 5_000_000) -> Any:
    cfg = get_settings()
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
                                timeout=max(30, cfg.fetch_timeout), max_bytes=limit)
    except (netguard.UnsafeURLError, netguard.FetchError) as exc:
        raise ObservatoryError(str(exc)) from None
    if resp.status_code >= 400:
        raise ObservatoryError(f"HTTP {resp.status_code}")
    text = resp.content.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:  # Spamhaus: one JSON object per line
        return [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]


# ============================================================================ months
def _months(start: tuple[int, int], end: tuple[int, int]) -> list[str]:
    y, m = start
    out = []
    while (y, m) <= end:
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _this_month() -> tuple[int, int]:
    d = dt.datetime.now(dt.UTC)
    return d.year, d.month


def _prev(ym: tuple[int, int], n: int = 1) -> tuple[int, int]:
    y, m = ym
    for _ in range(n):
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return y, m


def _ym(s: str) -> tuple[int, int]:
    return int(s[:4]), int(s[5:7])


# ============================================================================ fetchers (background)
class Refresher:
    """One background run at a time; each run fetches what is due within RUN_BUDGET seconds (the first full history
    takes a few runs)."""

    def __init__(self) -> None:
        self.running = False
        self._lock = threading.Lock()
        self._last_run = 0.0

    def maybe_start(self) -> None:
        if self.running or time.monotonic() - self._last_run < EVERY_RUN and self._last_run:
            return
        self.start()

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        self._last_run = time.monotonic()
        threading.Thread(target=self._run, name="observatory", daemon=True).start()
        return True

    def _run(self) -> None:
        try:
            refresh(RUN_BUDGET)
        except Exception:  # never take the scheduler down
            log.exception("Observatory refresh failed")
        finally:
            self.running = False


refresher = Refresher()


def refresh(budget: float = RUN_BUDGET, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Fetch whatever is due. Returns {source: what happened}."""
    deadline = time.monotonic() + budget
    done: dict[str, Any] = {}
    with get_db() as db:
        state = {k: _load(db, k) for k in ("asndrop", "isc_ports", "isc_sources", "isc_ip", "rw_recent", "rw_months", "nvd_months")}
    t = now()

    def stale(key: str, age: int) -> bool:
        return t - state[key][1] >= age

    for key, url, age in (("asndrop", "https://www.spamhaus.org/drop/asndrop.json", 86400),
                          ("isc_ports", "https://isc.sans.edu/api/topports/records/25?json", 6 * 3600),
                          ("isc_sources", f"https://isc.sans.edu/api/sources/attacks/{TOP_IPS * 2}?json", 6 * 3600),
                          ("rw_recent", "https://api.ransomware.live/v2/recentvictims", 3600)):
        if not stale(key, age):
            continue
        try:
            data = _get_json(url)
            if key == "asndrop":
                data = [{"asn": int(r["asn"]), "cc": to_text(r.get("cc"), 4), "name": to_text(r.get("asname"), 120),
                         "domain": to_text(r.get("domain"), 120)} for r in data if isinstance(r, dict) and str(r.get("asn", "")).isdigit()]
            elif key == "isc_ports":
                rows = data.values() if isinstance(data, dict) else data
                data = [{"port": int(r["targetport"]), "records": int(r.get("records") or 0), "sources": int(r.get("sources") or 0),
                         "targets": int(r.get("targets") or 0)} for r in rows if isinstance(r, dict) and str(r.get("targetport", "")).isdigit()]
            elif key == "isc_sources":
                data = [{"ip": to_text(r["ip"], 45), "reports": int(r.get("count") or 0), "targets": int(r.get("attacks") or 0),
                         "first": to_text(r.get("firstseen"), 10), "last": to_text(r.get("lastseen"), 10)}
                        for r in data if isinstance(r, dict) and r.get("ip")]
            elif key == "rw_recent":
                data = [_claim(r) for r in data if isinstance(r, dict)]
            _save(key, data)
            state[key] = (data, t)
            done[key] = len(data)
        except (ObservatoryError, KeyError, TypeError, ValueError) as exc:
            done[key] = f"failed: {exc}"
        sleep(ISC_GAP)

    # attacking IPs → their network (ASN), cached a week per IP
    ips: dict = state["isc_ip"][0] or {}
    for src in (state["isc_sources"][0] or [])[:TOP_IPS]:
        if time.monotonic() > deadline:
            break
        known = ips.get(src["ip"])
        if known and t - known.get("at", 0) < 7 * 86400:
            continue
        try:  # outside data goes into a URL: only a real IP address
            ipaddress.ip_address(src["ip"])
        except ValueError:
            continue
        try:
            info = (_get_json(f"https://isc.sans.edu/api/ip/{src['ip']}?json") or {}).get("ip") or {}
            ips[src["ip"]] = {"asn": int(info["as"]) if str(info.get("as") or "").isdigit() else None,
                              "name": to_text(info.get("asname"), 120), "cc": to_text(info.get("ascountry"), 4), "at": t}
        except (ObservatoryError, AttributeError, TypeError, ValueError):
            pass
        sleep(ISC_GAP)
    if ips:
        _save("isc_ip", {k: v for k, v in ips.items() if t - v.get("at", 0) < 30 * 86400})

    # ransomware claims per month (recent months again every 6 h)
    rw: dict = state["rw_months"][0] or {}
    cur = _this_month()
    recent = {f"{y:04d}-{m:02d}" for y, m in (cur, _prev(cur))}
    for month in reversed(_months(RW_FROM, cur)):
        if time.monotonic() > deadline:
            break
        have = rw.get(month)
        if have and (month not in recent or t - have.get("at", 0) < 6 * 3600):
            continue
        try:
            rows = _get_json(f"https://api.ransomware.live/v2/victims/{month[:4]}/{month[5:]}", limit=40_000_000)
            rw[month] = _month_summary(rows if isinstance(rows, list) else [], t)
            _save("rw_months", rw)
            done.setdefault("rw_months", 0)
            done["rw_months"] += 1
        except ObservatoryError as exc:
            done["rw_months"] = f"failed at {month}: {exc}"
            break
        sleep(RW_GAP)

    # CVEs published per month (NVD totals; recent months again daily)
    nvd: dict = state["nvd_months"][0] or {}
    for month in reversed(_months(NVD_FROM, cur)):
        if time.monotonic() > deadline:
            break
        have = nvd.get(month)
        if have and (month not in recent or t - have.get("at", 0) < 86400):
            continue
        y, m = _ym(month)
        last = calendar.monthrange(y, m)[1]
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
               f"&pubStartDate={y:04d}-{m:02d}-01T00:00:00.000&pubEndDate={y:04d}-{m:02d}-{last:02d}T23:59:59.999")
        try:
            total = int((_get_json(url) or {}).get("totalResults"))
            nvd[month] = {"n": total, "at": t}
            _save("nvd_months", nvd)
            done.setdefault("nvd_months", 0)
            done["nvd_months"] += 1
        except (ObservatoryError, TypeError, ValueError) as exc:
            done["nvd_months"] = f"failed at {month}: {exc}"   # NVD busy / rate limit: next run carries on
            break
        sleep(NVD_GAP)
    return done


def _claim(r: dict) -> dict:
    url = r.get("url") if isinstance(r.get("url"), str) and r["url"].startswith("https://www.ransomware.live/") else None
    return {"date": to_text(r.get("discovered") or r.get("attackdate"), 25), "victim": to_text(r.get("victim"), 160),
            "group": to_text(r.get("group"), 60), "country": to_text(r.get("country"), 4),
            "sector": "" if to_text(r.get("activity"), 60) in ("Not Found", "None") else to_text(r.get("activity"), 60),
            "url": url}


def _month_summary(rows: list, t: int) -> dict:
    groups: dict[str, int] = {}
    countries: dict[str, int] = {}
    sectors: dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        c = _claim(r)
        for d, k in ((groups, c["group"]), (countries, c["country"]), (sectors, c["sector"])):
            if k:
                d[k] = d.get(k, 0) + 1
    return {"n": len(rows), "groups": groups, "countries": countries, "sectors": sectors, "at": t}


# ============================================================================ panels
COUNTRY = {"US": "United States", "GB": "United Kingdom", "CA": "Canada", "DE": "Germany", "FR": "France", "IT": "Italy",
           "ES": "Spain", "AU": "Australia", "BR": "Brazil", "IN": "India", "JP": "Japan", "MX": "Mexico", "NL": "Netherlands",
           "CN": "China", "RU": "Russia", "KR": "South Korea", "TW": "Taiwan", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
           "SE": "Sweden", "TR": "Türkiye", "IL": "Israel", "AE": "UAE", "SA": "Saudi Arabia", "ZA": "South Africa", "AR": "Argentina",
           "CO": "Colombia", "CL": "Chile", "PE": "Peru", "TH": "Thailand", "ID": "Indonesia", "MY": "Malaysia", "SG": "Singapore",
           "VN": "Vietnam", "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "IE": "Ireland", "DK": "Denmark", "NO": "Norway",
           "FI": "Finland", "CZ": "Czechia", "RO": "Romania", "UA": "Ukraine", "HK": "Hong Kong", "BD": "Bangladesh", "EG": "Egypt",
           "NG": "Nigeria", "KE": "Kenya", "PK": "Pakistan", "IR": "Iran", "NZ": "New Zealand", "GR": "Greece", "HU": "Hungary",
           "BG": "Bulgaria", "SC": "Seychelles", "PA": "Panama", "LT": "Lithuania", "MD": "Moldova", "KZ": "Kazakhstan",
           "XX": "Not routed / unknown", "KN": "Saint Kitts & Nevis", "BZ": "Belize", "VG": "British Virgin Islands", "LV": "Latvia",
           "EE": "Estonia", "RS": "Serbia", "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan", "BY": "Belarus", "UZ": "Uzbekistan",
           "CY": "Cyprus", "LU": "Luxembourg", "MT": "Malta", "IS": "Iceland", "HR": "Croatia", "SI": "Slovenia", "SK": "Slovakia",
           "BA": "Bosnia & Herzegovina", "MK": "North Macedonia", "AL": "Albania", "MN": "Mongolia", "KH": "Cambodia", "LK": "Sri Lanka",
           "NP": "Nepal", "MA": "Morocco", "DZ": "Algeria", "TN": "Tunisia", "JO": "Jordan", "LB": "Lebanon", "QA": "Qatar",
           "KW": "Kuwait", "OM": "Oman", "BH": "Bahrain", "IQ": "Iraq", "EC": "Ecuador", "VE": "Venezuela", "UY": "Uruguay",
           "CR": "Costa Rica", "GT": "Guatemala", "DO": "Dominican Republic", "PR": "Puerto Rico", "GH": "Ghana", "ET": "Ethiopia",
           "TZ": "Tanzania", "UG": "Uganda", "SN": "Senegal", "CM": "Cameroon", "AO": "Angola", "ZW": "Zimbabwe", "EU": "Europe (EU)"}
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP (alt)", 110: "POP3", 123: "NTP",
         135: "Windows RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB (Windows shares)",
         502: "Modbus (ICS)", 1433: "MS SQL", 1723: "PPTP VPN", 1883: "MQTT (IoT)", 2323: "Telnet (alt)", 3306: "MySQL",
         3389: "Remote Desktop (RDP)", 5060: "SIP (VoIP)", 5432: "PostgreSQL", 5555: "Android debug (ADB)", 5900: "VNC",
         6379: "Redis", 7547: "TR-069 (home routers)", 8080: "HTTP proxy / alt", 8443: "HTTPS (alt)", 8728: "MikroTik API",
         9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 37215: "Huawei router (UPnP)", 52869: "Realtek UPnP"}


def _country(cc: str | None) -> str:
    return COUNTRY.get((cc or "").upper(), cc or "Unknown")


def _src(*names: str) -> list[dict]:
    known = {
        "nvd": {"name": "NIST National Vulnerability Database (NVD)", "url": "https://nvd.nist.gov/"},
        "kev": {"name": "CISA Known Exploited Vulnerabilities (KEV)", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        "rw": {"name": "ransomware.live (leak-site claims)", "url": "https://www.ransomware.live/"},
        "isc": {"name": "SANS Internet Storm Center / DShield", "url": "https://isc.sans.edu/"},
        "drop": {"name": "Spamhaus ASN-DROP", "url": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
        "local": {"name": "This app's CVE data (NVD + CISA KEV, your categories)", "url": None},
    }
    return [known[n] for n in names]


def _pct(new: float, old: float) -> float | None:
    return round((new - old) / old * 100, 1) if old else None


def _delta(new: float, old: float, unit: str = "") -> str:
    p = _pct(new, old)
    if p is None:
        return "no earlier data to compare"
    arrow = "▲" if p > 0 else "▼" if p < 0 else "■"
    return f"{arrow} {abs(p)}% vs a year earlier ({old:,.0f}{unit})"


def _half_start(ym: str) -> str:
    y, m = _ym(ym)
    return f"{y:04d}-{'01' if m <= 6 else '07'}-01"


def _ts_ym(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.UTC).strftime("%Y-%m")


def _empty(text: str, sources: list[dict], how: str) -> dict:
    return {"blocks": [{"kind": "note", "text": text}], "how": how, "sources": sources}


def panel(db, key: str) -> dict:
    fn = PANELS.get(key)
    if fn is None:
        raise KeyError(key)
    out = fn(db)
    out["panel"] = key
    out.setdefault("updated", None)
    return out


# ---------------------------------------------------------------- CVE tracker
def _nvd(db) -> dict[str, int]:
    data, _ = _load(db, "nvd_months")
    return {k: v["n"] for k, v in (data or {}).items()}


def p_cve_vs_kev(db) -> dict:
    nvd = _nvd(db)
    how = ("Every half-year: how many new CVEs were published (top), and how many vulnerabilities CISA confirmed as "
           "exploited in real attacks (bottom: added to its KEV list; 'zero-day' = on KEV within a day of being published, "
           "or before). Thousands of bugs are disclosed for every one that's known to be exploited - that small group is "
           "what to patch first. KEV began in November 2021 (its first weeks listed older bugs).")
    if not nvd:
        return _empty("⏳ Collecting monthly CVE totals from NVD (first run takes about 15 minutes)…", _src("nvd", "kev"), how)
    halves: dict[str, int] = {}
    for month, n in nvd.items():
        halves[_half_start(month)] = halves.get(_half_start(month), 0) + n
    buckets = sorted(halves)
    kev, zero = {b: 0 for b in buckets}, {b: 0 for b in buckets}
    for r in db.execute("SELECT kev_added, published FROM cves WHERE kev_added IS NOT NULL"):
        b = _half_start(_ts_ym(r["kev_added"]))
        if b in kev:
            kev[b] += 1
            if r["published"] and r["kev_added"] - r["published"] <= 86400:
                zero[b] += 1
    kev_b = [b for b in buckets if b >= "2021-07-01"]
    last_full = buckets[-2] if len(buckets) > 1 else buckets[-1]
    per1k = round(kev[last_full] / halves[last_full] * 1000, 1) if halves[last_full] else 0
    return {"blocks": [
        {"kind": "stats", "items": [
            {"label": f"New CVEs · {_half_label(last_full)}", "value": f"{halves[last_full]:,}"},
            {"label": f"Confirmed exploited (KEV) · {_half_label(last_full)}", "value": f"{kev[last_full]:,}"},
            {"label": "Exploited per 1,000 new CVEs", "value": f"{per1k}", "sub": "share of new bugs known to be attacked"}]},
        {"kind": "chart", "chart": "bar", "bucket": "half", "buckets": buckets, "height": 170,
         "series": [{"key": "nvd", "label": "New CVEs (NVD)", "values": [halves[b] for b in buckets]}]},
        {"kind": "chart", "chart": "line", "bucket": "half", "buckets": kev_b, "height": 170,
         "series": [{"key": "kev", "label": "Added to KEV (exploited)", "values": [kev[b] for b in kev_b]},
                    {"key": "zero", "label": "Zero-day (on KEV within a day)", "values": [zero[b] for b in kev_b]}]}],
        "how": how, "sources": _src("nvd", "kev"), "note": "The current half-year is still running."}


def _half_label(b: str) -> str:
    return f"{'H1' if b[5:7] == '01' else 'H2'} {b[:4]}"


def p_cve_pressure(db) -> dict:
    nvd = _nvd(db)
    how = ("Is the pressure on defenders rising? Each number compares the latest period with the same period a year "
           "earlier: new CVEs (the last 3 complete months), and newly confirmed exploited bugs (CISA KEV, last 90 days). "
           "The pressure index averages the two: 100 = same as a year ago, 150 = half as much again.")
    cur = _this_month()
    last3 = [f"{y:04d}-{m:02d}" for y, m in (_prev(cur, 1), _prev(cur, 2), _prev(cur, 3))]
    year_ago = [f"{int(s[:4]) - 1:04d}{s[4:]}" for s in last3]
    t = now()
    kev_now = db.execute("SELECT COUNT(*) FROM cves WHERE kev_added >= ?", (t - 90 * 86400,)).fetchone()[0]
    kev_then = db.execute("SELECT COUNT(*) FROM cves WHERE kev_added >= ? AND kev_added < ?", (t - 455 * 86400, t - 365 * 86400)).fetchone()[0]
    zero_now = db.execute("SELECT COUNT(*) FROM cves WHERE kev_added >= ? AND published IS NOT NULL AND kev_added - published <= 86400",
                          (t - 90 * 86400,)).fetchone()[0]
    zero_then = db.execute("SELECT COUNT(*) FROM cves WHERE kev_added >= ? AND kev_added < ? AND published IS NOT NULL "
                           "AND kev_added - published <= 86400", (t - 455 * 86400, t - 365 * 86400)).fetchone()[0]
    items = []
    ratios = []
    if all(m in nvd for m in last3 + year_ago):
        a, b = sum(nvd[m] for m in last3), sum(nvd[m] for m in year_ago)
        items.append({"label": "New CVEs · last 3 full months", "value": f"{a:,}", "sub": _delta(a, b)})
        if b:
            ratios.append(a / b)
    items.append({"label": "Confirmed exploited (KEV) · 90 days", "value": f"{kev_now:,}", "sub": _delta(kev_now, kev_then)})
    if kev_then:
        ratios.append(kev_now / kev_then)
    items.append({"label": "Zero-days (on KEV within a day) · 90 days", "value": f"{zero_now:,}", "sub": _delta(zero_now, zero_then)})
    if ratios:
        idx = round(statistics.mean(ratios) * 100)
        items.insert(0, {"label": "Pressure index (100 = a year ago)", "value": str(idx),
                         "sub": "rising" if idx > 110 else "easing" if idx < 90 else "about the same", "tone": "warn" if idx > 110 else None})
    return {"blocks": [{"kind": "stats", "items": items}], "how": how, "sources": _src("nvd", "kev")}


def p_cve_monthly(db) -> dict:
    nvd = _nvd(db)
    how = ("New CVEs published each month over the last three years, and this year so far against the same months last "
           "year. More CVEs doesn't always mean more danger (many are minor or in niche software), but the trend shows "
           "how much there is to triage.")
    if not nvd:
        return _empty("⏳ Collecting monthly CVE totals from NVD…", _src("nvd"), how)
    cur = _this_month()
    months = _months(_prev(cur, 35), cur)
    full = _months((cur[0], 1), _prev(cur)) if cur[1] > 1 else []
    ytd = sum(nvd.get(m, 0) for m in full)
    last = sum(nvd.get(f"{cur[0] - 1:04d}{m[4:]}", 0) for m in full)
    years = sorted({m[:4] for m in nvd})
    totals = [{"label": y, "count": sum(n for m, n in nvd.items() if m.startswith(y))} for y in years[-6:]]
    stats = [{"label": f"This month so far ({calendar.month_abbr[cur[1]]})", "value": f"{nvd.get(months[-1], 0):,}"}]
    if full:
        stats.insert(0, {"label": f"{cur[0]} so far (Jan–{calendar.month_abbr[int(full[-1][5:])]})",
                         "value": f"{ytd:,}", "sub": _delta(ytd, last)})
    return {"blocks": [
        {"kind": "stats", "items": stats},
        {"kind": "chart", "chart": "bar", "bucket": "month", "buckets": [f"{m}-01" for m in months], "height": 190,
         "series": [{"key": "nvd", "label": "New CVEs", "values": [nvd.get(m, 0) for m in months]}]},
        {"kind": "hbar", "title": "Per year", "items": totals}], "how": how, "sources": _src("nvd")}


LAG_BINS = [("Before or on the day it was published", None, 0), ("1–7 days later", 1, 7), ("8–30 days", 8, 30),
            ("1–3 months", 31, 90), ("3–12 months", 91, 365), ("1–3 years", 366, 1095), ("Over 3 years", 1096, None)]


def p_kev_lag(db) -> dict:
    how = ("For bugs CISA confirmed as exploited in the last two years: how long after the CVE was published did that "
           "happen? The first bar is the scariest - attacked before or as soon as it was disclosed, leaving no time to "
           "patch. Long gaps show old, unpatched bugs still being used: patching late still matters.")
    t = now()
    lags = [max(0, (r[0] - r[1]) // 86400) if r[0] >= r[1] else -1
            for r in db.execute("SELECT kev_added, published FROM cves WHERE kev_added >= ? AND published IS NOT NULL", (t - 730 * 86400,))]
    if not lags:
        return _empty("No CISA KEV additions in the last two years in the local data.", _src("kev", "nvd"), how)
    items = []
    for label, lo, hi in LAG_BINS:
        n = sum(1 for d in lags if (lo is None and d <= 0) or (lo is not None and d >= lo and (hi is None or d <= hi)))
        items.append({"label": label, "count": n})
    med = statistics.median([max(0, d) for d in lags])
    return {"blocks": [
        {"kind": "stats", "items": [{"label": "Exploited bugs added · 2 years", "value": f"{len(lags):,}"},
                                    {"label": "Median wait: published → confirmed exploited", "value": f"{med:,.0f} days"},
                                    {"label": "Exploited at or before disclosure", "value": f"{items[0]['count'] / len(lags) * 100:.0f}%"}]},
        {"kind": "columns", "items": items}], "how": how, "sources": _src("kev", "nvd")}


def _complete_since(db) -> int:
    """From when the local CVE table is complete: the first day (of the last 400) with at least half the median daily
    count of the last 30 days. The app keeps a recent window, plus older CVEs only when they're on KEV."""
    t = now()
    days = {r[0]: r[1] for r in db.execute("SELECT CAST(published / 86400 AS INTEGER) d, COUNT(*) FROM cves WHERE published >= ? GROUP BY d",
                                            (t - 400 * 86400,))}
    today = t // 86400
    recent = [days.get(d, 0) for d in range(today - 30, today)]
    floor = statistics.median(recent) / 2 if any(recent) else 0
    start = today
    for d in range(today - 1, today - 400, -1):   # walk back while days stay busy (allow a quiet weekend)
        if days.get(d, 0) >= floor or days.get(d - 1, 0) >= floor or days.get(d - 2, 0) >= floor:
            start = d
        else:
            break
    return start * 86400


def p_cve_exposure(db) -> dict:
    t = now()
    since = _complete_since(db)
    span = max(7, min(90, (t - since) // 86400 // 2))
    how = ("Which kinds of technology are getting more vulnerable? New CVEs in the latest period against the period "
           f"before (here {span} days each - the app holds complete CVE data from {dt.datetime.fromtimestamp(since, dt.UTC):%d %b %Y}, "
           "so both periods fit inside it), per category (edge devices, remote access, browsers, AI…), with how many of them "
           "CISA confirmed as exploited in the latest period. Fast-rising rows with exploited bugs deserve attention first.")
    rows = db.execute(
        "SELECT g.name, SUM(c.published >= ?) AS now_n, SUM(c.published >= ? AND c.published < ?) AS prev_n, "
        "SUM(c.kev_added >= ?) AS kev_n FROM cve_category_map m JOIN cve_categories g ON g.id = m.category_id AND g.enabled = 1 "
        "JOIN cves c ON c.id = m.cve_id WHERE c.published >= ? OR c.kev_added >= ? GROUP BY g.id ORDER BY now_n DESC",
        (t - span * 86400, t - 2 * span * 86400, t - span * 86400, t - span * 86400, t - 2 * span * 86400, t - span * 86400)).fetchall()
    table = [[r["name"], int(r["now_n"] or 0), int(r["prev_n"] or 0),
              (f"{_pct(r['now_n'] or 0, r['prev_n']):+.0f}%" if r["prev_n"] else "new"), int(r["kev_n"] or 0)] for r in rows]
    return {"blocks": [{"kind": "table", "columns": ["Technology", f"Last {span} days", f"{span} days before", "Change", "Exploited (KEV)"],
                        "numeric": [1, 2, 4], "rows": table}], "how": how, "sources": _src("local"),
            "note": f"Last {span} days vs the {span} days before"}


# ---------------------------------------------------------------- ransomware
def _rw(db) -> dict:
    data, _ = _load(db, "rw_months")
    return data or {}


def _window(rw: dict, months: int) -> list[str]:
    cur = _this_month()
    return [m for m in _months(_prev(cur, months - 1), cur) if m in rw]


def p_rw_trend(db) -> dict:
    rw = _rw(db)
    how = ("Organisations that ransomware gangs claimed on their leak sites, per month. These are the criminals' own "
           "claims (collected by ransomware.live): most are real, some are exaggerated or re-posted, and many victims "
           "who pay are never listed - so it's a lower bound and a trend, not an exact count.")
    if not rw:
        return _empty("⏳ Collecting monthly ransomware claims from ransomware.live…", _src("rw"), how)
    cur = _this_month()
    months = [m for m in _months(_prev(cur, 35), cur)]
    full = _months((cur[0], 1), _prev(cur)) if cur[1] > 1 else []
    ytd = sum(rw.get(m, {}).get("n", 0) for m in full)
    last = sum(rw.get(f"{cur[0] - 1:04d}{m[4:]}", {}).get("n", 0) for m in full)
    years = sorted({m[:4] for m in rw})
    stats = [{"label": f"Claimed this month so far ({calendar.month_abbr[cur[1]]})", "value": f"{rw.get(months[-1], {}).get('n', 0):,}"}]
    if full:
        stats.insert(0, {"label": f"{cur[0]} so far (Jan–{calendar.month_abbr[int(full[-1][5:])]})", "value": f"{ytd:,}", "sub": _delta(ytd, last)})
    return {"blocks": [
        {"kind": "stats", "items": stats},
        {"kind": "chart", "chart": "bar", "bucket": "month", "buckets": [f"{m}-01" for m in months], "height": 190,
         "series": [{"key": "rw", "label": "Victims claimed", "values": [rw.get(m, {}).get("n", 0) for m in months]}]},
        {"kind": "hbar", "title": "Per year", "items": [{"label": y + (" (so far)" if y == str(cur[0]) else ""),
                                                         "count": sum(v.get("n", 0) for m, v in rw.items() if m.startswith(y))} for y in years]}],
        "how": how, "sources": _src("rw")}


def _rw_top(db, field: str, label: Callable[[str], str] = str, limit: int = 15) -> tuple[list[dict], int]:
    rw = _rw(db)
    agg: dict[str, int] = {}
    win = _window(rw, 4)
    for m in win:
        for k, n in (rw[m].get(field) or {}).items():
            agg[k] = agg.get(k, 0) + n
    top = sorted(agg.items(), key=lambda kv: -kv[1])[:limit]
    return [{"label": label(k), "count": n} for k, n in top], sum(rw[m].get("n", 0) for m in win)


def p_rw_groups(db) -> dict:
    items, total = _rw_top(db, "groups")
    how = ("The gangs posting the most victims over the last three months and this month so far. A sudden newcomer "
           "near the top often means a rebrand of an older gang or a new affiliate program.")
    if not items:
        return _empty("⏳ Collecting ransomware claims…", _src("rw"), how)
    return {"blocks": [{"kind": "hbar", "items": items}], "how": how, "sources": _src("rw"),
            "note": f"{total:,} claims in this period"}


def p_rw_countries(db) -> dict:
    items, total = _rw_top(db, "countries", _country)
    how = ("Where the claimed victims are based (last three months and this month). Rich, highly digitised countries "
           "top the list partly because more of their victims are named publicly.")
    if not items:
        return _empty("⏳ Collecting ransomware claims…", _src("rw"), how)
    return {"blocks": [{"kind": "hbar", "items": items}], "how": how, "sources": _src("rw"), "note": f"{total:,} claims in this period"}


def p_rw_sectors(db) -> dict:
    items, total = _rw_top(db, "sectors")
    how = ("Which industries the claimed victims are in (when known; last three months and this month). "
           "Manufacturing, business services and healthcare are usually hit hardest - they can't afford downtime.")
    if not items:
        return _empty("⏳ Collecting ransomware claims…", _src("rw"), how)
    return {"blocks": [{"kind": "hbar", "items": items}], "how": how, "sources": _src("rw"), "note": f"{total:,} claims in this period"}


def p_rw_recent(db) -> dict:
    data, at = _load(db, "rw_recent")
    how = ("The latest organisations named on ransomware leak sites. ⚠️ These are unconfirmed claims by criminals - an "
           "organisation listed here may not have been breached, or may have been breached long ago. Search by name, "
           "gang, country or sector; the link opens the claim's page on ransomware.live (no leak-site links here).")
    if not data:
        return _empty("⏳ Collecting the latest ransomware claims…", _src("rw"), how)
    rows = [[(c["date"] or "")[:10], c["victim"], c["group"], _country(c["country"]) if c["country"] else "", c["sector"],
             c["url"]] for c in data]
    return {"blocks": [{"kind": "table", "columns": ["Seen", "Organisation (claimed)", "Gang", "Country", "Sector", ""],
                        "link_col": 5, "rows": rows, "search": True}], "how": how, "sources": _src("rw"), "updated": at}


# ---------------------------------------------------------------- internet
def _attackers(db) -> tuple[list[dict], dict, set[int], int]:
    srcs, at = _load(db, "isc_sources")
    ips, _ = _load(db, "isc_ip")
    drop, _ = _load(db, "asndrop")
    return srcs or [], ips or {}, {d["asn"] for d in (drop or [])}, at


def p_net_asn(db) -> dict:
    srcs, ips, drop, at = _attackers(db)
    how = ("The networks (autonomous systems - an ISP, hosting company or cloud) behind the IP addresses attacking the "
           "most sensors in SANS' DShield network, which collects firewall logs from volunteers worldwide. "
           "'Reports' = log lines about those IPs. 🚫 marks networks on Spamhaus' do-not-route list (run by or hijacked "
           "for criminals). Blocking such networks at your firewall cuts a lot of noise.")
    if not srcs:
        return _empty("⏳ Collecting DShield's top attackers…", _src("isc", "drop"), how)
    agg: dict[str, dict] = {}
    for s in srcs[:TOP_IPS]:
        info = ips.get(s["ip"])
        if not info:
            continue
        k = str(info.get("asn") or "?")
        a = agg.setdefault(k, {"asn": info.get("asn"), "name": info.get("name") or "Unknown", "cc": info.get("cc"), "ips": 0, "reports": 0, "targets": 0})
        a["ips"] += 1
        a["reports"] += s["reports"]
        a["targets"] = max(a["targets"], s["targets"])
    rows = sorted(agg.values(), key=lambda a: -a["reports"])[:20]
    if not rows:
        return _empty("⏳ Looking up the attacking IPs' networks…", _src("isc", "drop"), how)
    table = [[f"AS{a['asn']}" if a["asn"] else "?", a["name"] + (" 🚫" if a["asn"] in drop else ""), _country(a["cc"]),
              a["ips"], a["reports"]] for a in rows]
    return {"blocks": [{"kind": "table", "columns": ["Network", "Name", "Country", "Top IPs", "Reports"], "numeric": [3, 4],
                        "rows": table}], "how": how, "sources": _src("isc", "drop"), "updated": at,
            "note": f"From the {min(TOP_IPS, len(srcs))} most-reported IP addresses"}


def p_net_countries(db) -> dict:
    srcs, ips, _, at = _attackers(db)
    how = ("Where the most-reported attacking IP addresses are registered (by their network's country). This is where "
           "the machines are, not necessarily the attackers - criminals rent servers and hijack devices everywhere.")
    agg: dict[str, int] = {}
    for s in srcs[:TOP_IPS]:
        info = ips.get(s["ip"])
        if info:
            agg[_country(info.get("cc"))] = agg.get(_country(info.get("cc")), 0) + s["reports"]
    if not agg:
        return _empty("⏳ Collecting DShield's top attackers…", _src("isc"), how)
    return {"blocks": [{"kind": "hbar", "items": [{"label": k, "count": v} for k, v in sorted(agg.items(), key=lambda kv: -kv[1])[:15]]}],
            "how": how, "sources": _src("isc"), "updated": at}


def p_net_ports(db) -> dict:
    data, at = _load(db, "isc_ports")
    how = ("The ports attackers knock on most across DShield's sensors today. Telnet and SSH top the list (botnets "
           "guessing passwords on routers and servers); unusual ports in the list often mean a new exploit campaign. "
           "If one of these is open on your network to the internet, make sure it's meant to be.")
    if not data:
        return _empty("⏳ Collecting DShield's top ports…", _src("isc"), how)
    items = [{"label": f"{r['port']} · {PORTS.get(r['port'], 'other')}", "count": r["records"]} for r in data[:15]]
    return {"blocks": [{"kind": "hbar", "items": items}], "how": how, "sources": _src("isc"), "updated": at,
            "note": "Reports per port, today"}


def p_net_drop(db) -> dict:
    data, at = _load(db, "asndrop")
    how = ("Spamhaus' ASN-DROP list: whole networks so dirty (spam, malware hosting, hijacked address space) that "
           "Spamhaus advises not to route traffic to them at all. Per country of registration. Many firewalls can "
           "import this list directly.")
    if not data:
        return _empty("⏳ Collecting Spamhaus ASN-DROP…", _src("drop"), how)
    agg: dict[str, int] = {}
    for d in data:
        agg[_country(d["cc"])] = agg.get(_country(d["cc"]), 0) + 1
    return {"blocks": [
        {"kind": "stats", "items": [{"label": "Networks on the do-not-route list", "value": f"{len(data):,}"},
                                    {"label": "Countries", "value": str(len(agg))}]},
        {"kind": "hbar", "items": [{"label": k, "count": v} for k, v in sorted(agg.items(), key=lambda kv: -kv[1])[:15]]}],
        "how": how, "sources": _src("drop"), "updated": at}


PANELS: dict[str, Callable[[Any], dict]] = {
    "cve_vs_kev": p_cve_vs_kev, "cve_pressure": p_cve_pressure, "cve_monthly": p_cve_monthly, "kev_lag": p_kev_lag,
    "cve_exposure": p_cve_exposure, "rw_trend": p_rw_trend, "rw_groups": p_rw_groups, "rw_countries": p_rw_countries,
    "rw_sectors": p_rw_sectors, "rw_recent": p_rw_recent, "net_asn": p_net_asn, "net_countries": p_net_countries,
    "net_ports": p_net_ports, "net_drop": p_net_drop,
}

# Panels per dashboard: (panel key, title, width %)
CVE_PANELS = [("cve_pressure", "Exploitation pressure", 100), ("cve_vs_kev", "New CVEs vs exploited · per half-year", 55),
              ("kev_lag", "How fast bugs get exploited", 45), ("cve_monthly", "New CVEs per month", 55),
              ("cve_exposure", "Exposure by technology", 45)]
RW_PANELS = [("rw_trend", "Ransomware victims claimed per month", 100), ("rw_groups", "Most active gangs · 3 months", 34),
             ("rw_countries", "Victims by country · 3 months", 33), ("rw_sectors", "Victims by sector · 3 months", 33),
             ("rw_recent", "Latest claimed victims (unconfirmed)", 100)]
NET_PANELS = [("net_asn", "Top attacking networks", 55), ("net_ports", "Most attacked ports · today", 45),
              ("net_countries", "Where attacking IPs are", 50), ("net_drop", "Criminal networks (Spamhaus ASN-DROP)", 50)]
