"""Widgets over *both* datasets: news articles and CVEs, side by side.

* ``kpi``        - two numbers (articles / CVEs in the period), each with its change vs. the previous period.
* ``timeseries`` - one chart with two series, "News articles" and "CVEs", on the same date buckets.
* ``mixed``      - one list of the latest matching articles and CVEs, newest first.

Each side keeps its own filters (article filters / CVE filters, each with its own all/any matching),
so this simply runs the existing, already-hardened article and CVE queries and merges their results.
"""

from __future__ import annotations

import sqlite3
from typing import Literal

from pydantic import Field

from app import analytics, cve_analytics
from app.api.common import StrictModel

ARTICLE_COLOR = "#3b82f6"
CVE_COLOR = "#e8590c"


class CombinedQuery(StrictModel):
    dataset: Literal["combined"] = "combined"
    type: Literal["kpi", "timeseries", "mixed"]
    days: int = Field(default=30, ge=1, le=3650)
    bucket: Literal["day", "week", "month"] = "day"
    limit: int = Field(default=20, ge=1, le=100)              # mixed list length
    tz_offset_minutes: int = Field(default=0, ge=-840, le=840)
    until_ts: int | None = Field(default=None, ge=0, le=2**40)
    date_field: Literal["published", "modified", "kev_added"] = "published"   # which CVE date counts
    articles: analytics.Filters = Field(default_factory=analytics.Filters)
    cves: cve_analytics.CveFilters = Field(default_factory=cve_analytics.CveFilters)


def _article_query(q: CombinedQuery, qtype: str, **extra) -> analytics.WidgetQuery:
    return analytics.WidgetQuery(type=qtype, days=q.days, bucket=q.bucket, tz_offset_minutes=q.tz_offset_minutes,
                                 until_ts=q.until_ts, filters=q.articles, **extra)


def _cve_query(q: CombinedQuery, qtype: str, **extra) -> cve_analytics.CveQuery:
    return cve_analytics.CveQuery(type=qtype, days=q.days, bucket=q.bucket, tz_offset_minutes=q.tz_offset_minutes,
                                  until_ts=q.until_ts, date_field=q.date_field, filters=q.cves, **extra)


def run(db: sqlite3.Connection, q: CombinedQuery) -> dict:
    base = {"dataset": "combined", "days": q.days}
    if q.type == "kpi":
        a = analytics.run(db, _article_query(q, "kpi"))
        c = cve_analytics.run(db, _cve_query(q, "kpi"))
        pick = ("value", "previous", "change_pct")
        return {**base, "type": "kpi_pair", "items": [
            {"key": "articles", "label": "News articles", "color": ARTICLE_COLOR, **{k: a[k] for k in pick}},
            {"key": "cves", "label": "CVEs", "color": CVE_COLOR, **{k: c[k] for k in pick}},
        ]}

    if q.type == "timeseries":
        a = analytics.run(db, _article_query(q, "timeseries"))
        c = cve_analytics.run(db, _cve_query(q, "timeseries"))
        buckets = a["buckets"]
        cve_by_bucket = dict(zip(c["buckets"], c["series"][0]["values"]))  # same window and bucketing; map defensively
        cve_values = [cve_by_bucket.get(b, 0) for b in buckets]
        art_values = a["series"][0]["values"]
        return {**base, "type": "timeseries", "bucket": q.bucket, "buckets": buckets, "group_by": "dataset", "series": [
            {"key": "articles", "label": "News articles", "color": ARTICLE_COLOR, "values": art_values, "total": sum(art_values)},
            {"key": "cves", "label": "CVEs", "color": CVE_COLOR, "values": cve_values, "total": sum(cve_values)},
        ]}

    # mixed: newest articles and CVEs interleaved
    arts = analytics.run(db, _article_query(q, "articles", limit=min(q.limit, 50)))["items"]
    cves = cve_analytics.run(db, _cve_query(q, "cves", limit=q.limit, sort="newest"))
    date_key = {"published": "published", "modified": "last_modified", "kev_added": "kev_added"}[q.date_field]
    items = [{"kind": "article", "ts": a["sort_ts"], **a} for a in arts]
    items += [{"kind": "cve", "ts": c.get(date_key) or c.get("published") or 0, **c} for c in cves["items"]]
    items.sort(key=lambda i: i["ts"] or 0, reverse=True)
    return {**base, "type": "mixed", "items": items[:q.limit], "cve_total": cves["total"]}
