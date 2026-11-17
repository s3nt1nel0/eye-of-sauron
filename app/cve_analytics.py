"""Dashboard analytics over CVE records (KPIs, trends, breakdowns, sortable lists).

Same safety rules as app/analytics.py: every value is a bound parameter; the only
interpolated SQL fragments are placeholder lists and fixed snippets chosen from
dictionaries keyed by validated Literal values.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from app.analytics import _bucket_starts, combine
from app.api.common import StrictModel
from app.db import now, placeholders
from app.search import fts_query

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED"]
# Fixed status colours (critical/serious/warning/good + neutral); always shown with text labels.
SEVERITY_COLORS = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#0ca30c",
                   "NONE": "#8a8f98", "UNSCORED": "#8a8f98"}
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]
Key = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,64}$")]
OwaspCode = Annotated[str, StringConstraints(pattern=r"^A\d\d$")]
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class CveFilters(StrictModel):
    severities: list[Severity] = Field(default_factory=list, max_length=6)
    min_score: float | None = Field(default=None, ge=0, le=10)
    max_score: float | None = Field(default=None, ge=0, le=10)
    categories: list[Slug] = Field(default_factory=list, max_length=30)          # in ANY of these
    require_categories: list[Slug] = Field(default_factory=list, max_length=10)  # in ALL of these
    exclude_categories: list[Slug] = Field(default_factory=list, max_length=30)
    cwe_ids: list[Annotated[int, Field(ge=1, le=99999)]] = Field(default_factory=list, max_length=50)
    vendors: list[Key] = Field(default_factory=list, max_length=30)
    owasp_edition: Literal["2021", "2025"] = "2021"
    owasp: list[OwaspCode] = Field(default_factory=list, max_length=10)
    kev_only: bool = False
    exploited_only: bool = False          # in KEV or SSVC exploitation = active
    ransomware_only: bool = False         # KEV: known ransomware campaign use
    q: Annotated[str, StringConstraints(max_length=200)] | None = None
    include_rejected: bool = False
    # "all" = a CVE must match every filter that is set (AND); "any" = one is enough (OR).
    # The date window, excluded categories and rejected-status always apply.
    match: Literal["all", "any"] = "all"
    focus: "CveFocus | None" = None   # drill-down restriction (the clicked bar/slice): always ANDed


class CveFocus(StrictModel):
    severity: Severity | None = None
    category: Slug | None = None
    cwe_id: int | None = Field(default=None, ge=1, le=99999)
    vendor: Key | None = None
    owasp: OwaspCode | None = None
    owasp_edition: Literal["2021", "2025"] = "2021"
    kev: bool | None = None


CveFilters.model_rebuild()


CveType = Literal["kpi", "timeseries", "breakdown", "cves"]
CveGroup = Literal["none", "severity", "category", "cwe", "vendor", "owasp2021", "owasp2025", "kev"]


class CveQuery(StrictModel):
    dataset: Literal["cves"] = "cves"
    type: CveType
    days: int = Field(default=30, ge=1, le=3650)
    bucket: Literal["day", "week", "month"] = "day"
    group_by: CveGroup = "none"
    group_categories: list[Slug] = Field(default_factory=list, max_length=8)  # only these series/bars
    date_field: Literal["published", "modified", "kev_added"] = "published"
    sort: Literal["newest", "score", "kev_added"] = "newest"
    limit: int = Field(default=10, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=100_000)
    tz_offset_minutes: int = Field(default=0, ge=-840, le=840)
    until_ts: int | None = Field(default=None, ge=0, le=2**40)
    filters: CveFilters = Field(default_factory=CveFilters)

    @model_validator(mode="after")
    def _consistent(self) -> "CveQuery":
        if self.type == "breakdown" and self.group_by == "none":
            raise ValueError("a breakdown needs group_by")
        if self.type == "timeseries" and self.group_by != "none":
            self.limit = min(self.limit, 8)
        if self.type != "cves":
            self.limit = min(self.limit, 50)
        return self


_DATE_COL = {"published": "c.published", "modified": "c.last_modified", "kev_added": "c.kev_added"}
_BUCKET = {
    "day": "date({col} + ?, 'unixepoch')",
    "week": "date({col} + ?, 'unixepoch', 'weekday 0', '-6 days')",
    "month": "date({col} + ?, 'unixepoch', 'start of month')",
}
_GROUP = {
    "severity": ("", "c.severity"),
    "kev": ("", "c.kev"),
    "category": ("JOIN cve_category_map g ON g.cve_id = c.id JOIN cve_categories gc ON gc.id = g.category_id", "gc.slug"),
    "cwe": ("JOIN cve_cwes g ON g.cve_id = c.id", "g.cwe_id"),
    "vendor": ("JOIN cve_products g ON g.cve_id = c.id", "g.vendor_key"),
    "owasp2021": ("JOIN cve_cwes g ON g.cve_id = c.id JOIN cwe_owasp o ON o.cwe_id = g.cwe_id AND o.edition = '2021'", "o.code"),
    "owasp2025": ("JOIN cve_cwes g ON g.cve_id = c.id JOIN cwe_owasp o ON o.cwe_id = g.cwe_id AND o.edition = '2025'", "o.code"),
}
_SORT = {
    "newest": "{col} DESC, c.id DESC",
    "score": "c.score IS NULL, c.score DESC, {col} DESC",
    "kev_added": "c.kev_added IS NULL, c.kev_added DESC, c.id DESC",
}


def _where(q: CveQuery, since: int, until: int) -> tuple[str, list]:
    f = q.filters
    col = _DATE_COL[q.date_field]
    fixed = [f"{col} >= ?", f"{col} < ?"]
    fixed_params: list = [since, until]
    groups: list[tuple[str, list]] = []   # one entry per filter that is set; joined by AND or OR (f.match)
    if not f.include_rejected:
        fixed.append("c.status != 'Rejected'")
    if f.severities:
        groups.append((f"c.severity IN ({placeholders(len(f.severities))})", list(f.severities)))
    score: list[str] = []
    score_params: list = []
    if f.min_score is not None:
        score.append("c.score >= ?")
        score_params.append(f.min_score)
    if f.max_score is not None:
        score.append("c.score <= ?")
        score_params.append(f.max_score)
    if score:
        groups.append((" AND ".join(score), score_params))
    cat_sql = ("EXISTS (SELECT 1 FROM cve_category_map m JOIN cve_categories k ON k.id = m.category_id "
               "WHERE m.cve_id = c.id AND k.slug IN ({ph}))")
    if f.categories:
        groups.append((cat_sql.format(ph=placeholders(len(f.categories))), list(f.categories)))
    if f.require_categories:  # in ALL of these categories (one filter)
        groups.append((" AND ".join([cat_sql.format(ph="?")] * len(f.require_categories)), list(f.require_categories)))
    if f.exclude_categories:
        fixed.append("NOT " + cat_sql.format(ph=placeholders(len(f.exclude_categories))))
        fixed_params += f.exclude_categories
    if f.cwe_ids:
        groups.append((f"EXISTS (SELECT 1 FROM cve_cwes w WHERE w.cve_id = c.id AND w.cwe_id IN ({placeholders(len(f.cwe_ids))}))",
                       list(f.cwe_ids)))
    if f.vendors:
        groups.append((f"EXISTS (SELECT 1 FROM cve_products p WHERE p.cve_id = c.id AND p.vendor_key IN ({placeholders(len(f.vendors))}))",
                       list(f.vendors)))
    if f.owasp:
        groups.append(("EXISTS (SELECT 1 FROM cve_cwes w JOIN cwe_owasp o ON o.cwe_id = w.cwe_id "
                       f"WHERE w.cve_id = c.id AND o.edition = ? AND o.code IN ({placeholders(len(f.owasp))}))",
                       [f.owasp_edition, *f.owasp]))
    if f.kev_only:
        groups.append(("c.kev = 1", []))
    if f.exploited_only:
        groups.append(("(c.kev = 1 OR c.exploitation = 'active')", []))
    if f.ransomware_only:
        groups.append(("c.kev_ransomware = 1", []))
    if f.q:
        text = f.q.strip()
        if CVE_ID.match(text):
            groups.append(("c.id = ?", [text.upper()]))
        else:
            match = fts_query(text)
            groups.append(("0", []) if match is None else
                          ("c.rowid IN (SELECT rowid FROM cves_fts WHERE cves_fts MATCH ?)", [match]))
    fo = f.focus
    if fo is not None:
        if fo.severity is not None:
            fixed.append("c.severity = ?")
            fixed_params.append(fo.severity)
        if fo.category is not None:
            fixed.append(cat_sql.format(ph="?"))
            fixed_params.append(fo.category)
        if fo.cwe_id is not None:
            fixed.append("EXISTS (SELECT 1 FROM cve_cwes w WHERE w.cve_id = c.id AND w.cwe_id = ?)")
            fixed_params.append(fo.cwe_id)
        if fo.vendor is not None:
            fixed.append("EXISTS (SELECT 1 FROM cve_products p WHERE p.cve_id = c.id AND p.vendor_key = ?)")
            fixed_params.append(fo.vendor)
        if fo.owasp is not None:
            fixed.append("EXISTS (SELECT 1 FROM cve_cwes w JOIN cwe_owasp o ON o.cwe_id = w.cwe_id "
                         "WHERE w.cve_id = c.id AND o.edition = ? AND o.code = ?)")
            fixed_params += [fo.owasp_edition, fo.owasp]
        if fo.kev is not None:
            fixed.append("c.kev = ?")
            fixed_params.append(int(fo.kev))
    return combine(fixed, fixed_params, groups, f.match)


def _labels(db: sqlite3.Connection, group: str, keys: list) -> dict:
    out: dict = {}
    if group == "severity":
        return {k: {"label": str(k).title(), "color": SEVERITY_COLORS.get(k)} for k in keys}
    if group == "kev":
        return {1: {"label": "In CISA KEV", "color": "#d03b3b"}, 0: {"label": "Not in KEV", "color": "#8a8f98"}}
    real = [k for k in keys if k is not None]
    if not real:
        return out
    ph = placeholders(len(real))
    if group == "category":
        rows = db.execute(f"SELECT slug AS k, name AS label FROM cve_categories WHERE slug IN ({ph})", real)
    elif group == "cwe":
        names = {r[0]: r[1] for r in db.execute(f"SELECT id, name FROM cwe_entries WHERE id IN ({ph})", real)}
        return {k: {"label": f"CWE-{k}" + (f" {names[k]}" if k in names else ""), "color": None} for k in real}
    elif group == "vendor":
        rows = db.execute(f"SELECT vendor_key AS k, MIN(vendor_label) AS label FROM cve_products WHERE vendor_key IN ({ph}) "
                          "GROUP BY vendor_key", real)
    else:  # owasp
        edition = "2021" if group == "owasp2021" else "2025"
        rows = db.execute(f"SELECT code AS k, MAX(name) AS label FROM cwe_owasp WHERE edition = ? AND code IN ({ph}) "
                          "GROUP BY code", [edition, *real])
        return {r["k"]: {"label": f"{r['k']}:{edition} {r['label']}", "color": None} for r in rows}
    for r in rows:
        out[r["k"]] = {"label": r["label"], "color": None}
    return out


def _group_filter(q: CveQuery) -> tuple[str, list]:
    if q.group_by == "category" and q.group_categories:
        return f" AND gc.slug IN ({placeholders(len(q.group_categories))})", list(q.group_categories)
    return "", []


def _breakdown(db: sqlite3.Connection, q: CveQuery, since: int, until: int, limit: int) -> list[dict]:
    join, key = _GROUP[q.group_by]
    where, params = _where(q, since, until)
    gsql, gparams = _group_filter(q)
    where += gsql
    params = [*params, *gparams]
    order = "c DESC, k" if q.group_by not in ("severity", "kev") else "k"
    rows = db.execute(
        f"SELECT {key} AS k, COUNT(DISTINCT c.id) AS c FROM cves c {join} WHERE {where} GROUP BY k ORDER BY {order} LIMIT ?",
        [*params, limit if q.group_by not in ("severity", "kev") else 10],
    ).fetchall()
    if q.group_by == "severity":
        rows = sorted(rows, key=lambda r: SEVERITY_ORDER.index(r["k"]) if r["k"] in SEVERITY_ORDER else 99)
    labels = _labels(db, q.group_by, [r["k"] for r in rows])
    return [{"key": r["k"], "label": labels.get(r["k"], {}).get("label", str(r["k"])),
             "color": labels.get(r["k"], {}).get("color"), "count": r["c"]} for r in rows]


def _list(db: sqlite3.Connection, q: CveQuery, since: int, until: int) -> tuple[list[dict], int]:
    where, params = _where(q, since, until)
    col = _DATE_COL[q.date_field]
    total = db.execute(f"SELECT COUNT(*) FROM cves c WHERE {where}", params).fetchone()[0]
    rows = db.execute(
        "SELECT c.id, c.published, c.last_modified, c.severity, c.score, c.cvss_version, c.vector, c.kev, c.kev_added, "
        "c.kev_due, c.kev_ransomware, c.kev_name, c.exploitation, c.status, substr(c.description, 1, 600) AS description "
        f"FROM cves c WHERE {where} ORDER BY {_SORT[q.sort].format(col=col)} LIMIT ? OFFSET ?",
        [*params, q.limit, q.offset],
    ).fetchall()
    items = [dict(r) for r in rows]
    if items:
        ids = [i["id"] for i in items]
        ph = placeholders(len(ids))
        by = {i["id"]: i for i in items}
        for i in items:
            i.update(vendors=[], categories=[], cwes=[])
        for r in db.execute(f"SELECT cve_id, vendor_label, product_label FROM cve_products WHERE cve_id IN ({ph}) "
                            "ORDER BY vendor_label", ids):
            if len(by[r[0]]["vendors"]) < 4:
                by[r[0]]["vendors"].append(f"{r[1]} {r[2]}")
        for r in db.execute(f"SELECT m.cve_id, k.slug, k.name FROM cve_category_map m JOIN cve_categories k "
                            f"ON k.id = m.category_id WHERE m.cve_id IN ({ph}) ORDER BY k.position", ids):
            by[r[0]]["categories"].append({"slug": r[1], "name": r[2]})
        for r in db.execute(f"SELECT w.cve_id, w.cwe_id, e.name FROM cve_cwes w LEFT JOIN cwe_entries e ON e.id = w.cwe_id "
                            f"WHERE w.cve_id IN ({ph})", ids):
            by[r[0]]["cwes"].append({"id": r[1], "name": r[2]})
    return items, total


def run(db: sqlite3.Connection, q: CveQuery) -> dict:
    until = q.until_ts if q.until_ts is not None else now() + 1
    since = until - q.days * 86400
    base = {"dataset": "cves", "days": q.days}

    if q.type == "kpi":
        where, params = _where(q, since, until)
        value = db.execute(f"SELECT COUNT(*) FROM cves c WHERE {where}", params).fetchone()[0]
        pwhere, pparams = _where(q, since - q.days * 86400, since)
        previous = db.execute(f"SELECT COUNT(*) FROM cves c WHERE {pwhere}", pparams).fetchone()[0]
        change = None if previous == 0 else round((value - previous) * 100.0 / previous, 1)
        return {**base, "type": "kpi", "value": value, "previous": previous, "change_pct": change}

    if q.type == "breakdown":
        return {**base, "type": "breakdown", "group_by": q.group_by, "items": _breakdown(db, q, since, until, q.limit)}

    if q.type == "cves":
        items, total = _list(db, q, since, until)
        return {**base, "type": "cves", "items": items, "total": total, "offset": q.offset}

    offset = q.tz_offset_minutes * 60
    buckets = _bucket_starts(since, until, offset, q.bucket)
    index = {b: i for i, b in enumerate(buckets)}
    bucket_sql = _BUCKET[q.bucket].format(col=_DATE_COL[q.date_field])
    where, wparams = _where(q, since, until)
    if q.group_by == "none":
        values = [0] * len(buckets)
        for r in db.execute(f"SELECT {bucket_sql} AS b, COUNT(*) AS c FROM cves c WHERE {where} GROUP BY b", [offset, *wparams]):
            if r["b"] in index:
                values[index[r["b"]]] = r["c"]
        series = [{"key": "total", "label": "CVEs", "color": None, "values": values, "total": sum(values)}]
        return {**base, "type": "timeseries", "bucket": q.bucket, "buckets": buckets, "series": series}
    top = _breakdown(db, q, since, until, q.limit)
    series_map = {t["key"]: {**t, "values": [0] * len(buckets), "total": t["count"]} for t in top}
    keys = [k for k in series_map if k is not None]
    if keys:
        join, gkey = _GROUP[q.group_by]
        for r in db.execute(
            f"SELECT {bucket_sql} AS b, {gkey} AS k, COUNT(DISTINCT c.id) AS c FROM cves c {join} "
            f"WHERE {where} AND {gkey} IN ({placeholders(len(keys))}) GROUP BY b, k",
            [offset, *wparams, *keys],
        ):
            if r["b"] in index and r["k"] in series_map:
                series_map[r["k"]]["values"][index[r["b"]]] = r["c"]
    series = [series_map[t["key"]] for t in top]
    for s in series:
        s.pop("count", None)
    return {**base, "type": "timeseries", "bucket": q.bucket, "buckets": buckets, "series": series, "group_by": q.group_by}


def meta(db: sqlite3.Connection) -> dict:
    """Picker data for the widget editor and the CVE settings panel."""
    cats = [dict(r) for r in db.execute(
        "SELECT k.id, k.slug, k.name, k.description, k.builtin, k.enabled, k.cwe_ids, k.keywords, k.products, "
        "(SELECT COUNT(*) FROM cve_category_map m WHERE m.category_id = k.id) AS cve_count "
        "FROM cve_categories k ORDER BY k.position, k.id")]
    for c in cats:
        for key in ("cwe_ids", "keywords", "products"):
            c[key] = json.loads(c[key])
        c["builtin"], c["enabled"] = bool(c["builtin"]), bool(c["enabled"])
    vendors = [{"key": r[0], "label": r[1], "count": r[2]} for r in db.execute(
        "SELECT vendor_key, MIN(vendor_label), COUNT(DISTINCT cve_id) AS n FROM cve_products "
        "GROUP BY vendor_key ORDER BY n DESC LIMIT 400")]
    owasp = {}
    for r in db.execute("SELECT edition, code, MAX(name) FROM cwe_owasp GROUP BY edition, code ORDER BY edition, code"):
        owasp.setdefault(r[0], []).append({"code": r[1], "name": r[2]})
    cwes = [{"id": r[0], "name": r[1], "count": r[2]} for r in db.execute(
        "SELECT w.cwe_id, e.name, COUNT(*) AS n FROM cve_cwes w LEFT JOIN cwe_entries e ON e.id = w.cwe_id "
        "GROUP BY w.cwe_id ORDER BY n DESC LIMIT 300")]
    return {"categories": cats, "vendors": vendors, "owasp": owasp, "cwes": cwes}
