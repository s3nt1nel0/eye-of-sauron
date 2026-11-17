"""Dashboard analytics: KPIs, trends, breakdowns and article lists over filtered articles.

Counts are *articles* (each article counted once per group). Entity counts are
mention-based: "Healthcare: 40" means 40 articles mention a healthcare term, not
40 verified incidents.

SQL safety: every value is a bound parameter. The only interpolated fragments
are (a) '?' placeholder lists, (b) fixed SQL snippets chosen from dictionaries
keyed by validated Literal values.
"""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from app.api.common import StrictModel
from app.db import now, placeholders
from app.search import fts_query

IdList = Annotated[list[int], Field(default_factory=list, max_length=200)]


class Filters(StrictModel):
    tag_ids: IdList
    feed_ids: IdList
    folder_ids: IdList
    entity_ids: IdList           # article mentions ANY of these entities
    watchlist_ids: IdList        # article mentions ANY entity of these watchlists
    exclude_entity_ids: IdList   # article mentions NONE of these
    require_entity_ids: Annotated[list[int], Field(default_factory=list, max_length=20)]  # mentions ALL
    require_tag_ids: Annotated[list[int], Field(default_factory=list, max_length=20)]     # filed in ALL
    q: Annotated[str, StringConstraints(max_length=200)] | None = None
    starred: bool = False
    unread: bool = False
    # How the filter boxes combine: "all" = an article must match every box that is set (AND);
    # "any" = matching one box is enough (OR). Exclusions, starred, unread and the date window always apply.
    match: Literal["all", "any"] = "all"
    focus: "Focus | None" = None   # drill-down restriction: always ANDed, whatever ``match`` is


class Focus(StrictModel):
    """The bar / slice / series the reader clicked. Applied on top of the widget's filters."""
    entity_id: int | None = Field(default=None, ge=1, le=2**62)
    tag_id: int | None = Field(default=None, ge=1, le=2**62)
    feed_id: int | None = Field(default=None, ge=1, le=2**62)
    folder_id: int | None = Field(default=None, ge=1, le=2**62)


Filters.model_rebuild()


WidgetType = Literal["kpi", "timeseries", "breakdown", "articles"]
GroupBy = Literal["none", "tag", "feed", "folder", "watchlist"]


class WidgetQuery(StrictModel):
    dataset: Literal["articles"] = "articles"
    type: WidgetType
    days: int = Field(default=30, ge=1, le=3650)
    bucket: Literal["day", "week", "month"] = "day"
    group_by: GroupBy = "none"
    group_watchlist_id: int | None = None
    group_entity_ids: IdList
    limit: int = Field(default=10, ge=1, le=50)
    tz_offset_minutes: int = Field(default=0, ge=-840, le=840)
    until_ts: int | None = Field(default=None, ge=0, le=2**40)  # window end (default: now)
    filters: Filters = Field(default_factory=Filters)

    @model_validator(mode="after")
    def _consistent(self) -> "WidgetQuery":
        if self.group_by == "watchlist" and self.group_watchlist_id is None:
            raise ValueError("group_watchlist_id is required when group_by is 'watchlist'")
        if self.type == "breakdown" and self.group_by == "none":
            raise ValueError("a breakdown needs group_by")
        if self.type == "timeseries" and self.group_by != "none":
            self.limit = min(self.limit, 8)  # at most 8 series (one per palette slot)
        return self


# Fixed SQL fragments, selected by validated literals only.
_BUCKET_SQL = {
    "day": "date(a.sort_ts + ?, 'unixepoch')",
    "week": "date(a.sort_ts + ?, 'unixepoch', 'weekday 0', '-6 days')",
    "month": "date(a.sort_ts + ?, 'unixepoch', 'start of month')",
}
_GROUP_KEY = {"tag": "g.tag_id", "feed": "a.feed_id", "folder": "f.folder_id", "watchlist": "g.entity_id"}


def combine(fixed: list[str], fixed_params: list, groups: list[tuple[str, list]], match: str) -> tuple[str, list]:
    """AND the fixed clauses; join the filter-box groups with AND ("all") or OR ("any").
    Every fragment is a fixed SQL string with '?' placeholders; values stay bound."""
    clauses, params = list(fixed), list(fixed_params)
    if groups:
        if match == "any" and len(groups) > 1:
            clauses.append("(" + " OR ".join(f"({sql})" for sql, _ in groups) + ")")
        else:
            clauses.extend(sql for sql, _ in groups)
        for _, p in groups:
            params.extend(p)
    return " AND ".join(clauses), params


def _where(q: WidgetQuery, since: int, until: int) -> tuple[str, list]:
    f = q.filters
    fixed = ["a.sort_ts >= ?", "a.sort_ts < ?"]
    fixed_params: list = [since, until]
    groups: list[tuple[str, list]] = []   # one entry per filter box that is set

    def ids_in(sql: str, ids: list[int]) -> tuple[str, list]:
        return sql.format(ph=placeholders(len(ids))), list(ids)

    if f.tag_ids:
        groups.append(ids_in("EXISTS (SELECT 1 FROM article_tags x WHERE x.article_id = a.id AND x.tag_id IN ({ph}))", f.tag_ids))
    if f.require_tag_ids:  # filed in ALL of these collections (one box)
        groups.append((" AND ".join(["EXISTS (SELECT 1 FROM article_tags x WHERE x.article_id = a.id AND x.tag_id = ?)"]
                                    * len(f.require_tag_ids)), list(f.require_tag_ids)))
    if f.entity_ids:
        groups.append(ids_in("EXISTS (SELECT 1 FROM article_entities x WHERE x.article_id = a.id AND x.entity_id IN ({ph}))",
                             f.entity_ids))
    if f.require_entity_ids:  # mentions ALL of these entities (one box)
        groups.append((" AND ".join(["EXISTS (SELECT 1 FROM article_entities x WHERE x.article_id = a.id AND x.entity_id = ?)"]
                                    * len(f.require_entity_ids)), list(f.require_entity_ids)))
    if f.watchlist_ids:
        groups.append(ids_in("EXISTS (SELECT 1 FROM article_entities x JOIN entities xe ON xe.id = x.entity_id "
                             "WHERE x.article_id = a.id AND xe.watchlist_id IN ({ph}))", f.watchlist_ids))
    if f.feed_ids:
        groups.append(ids_in("a.feed_id IN ({ph})", f.feed_ids))
    if f.folder_ids:
        groups.append(ids_in("f.folder_id IN ({ph})", f.folder_ids))
    if f.q:
        match = fts_query(f.q)
        groups.append(("0", []) if match is None else
                      ("a.id IN (SELECT rowid FROM articles_fts WHERE articles_fts MATCH ?)", [match]))
    # Always applied, whatever the match mode.
    if f.exclude_entity_ids:
        sql, p = ids_in("NOT EXISTS (SELECT 1 FROM article_entities x WHERE x.article_id = a.id AND x.entity_id IN ({ph}))",
                        f.exclude_entity_ids)
        fixed.append(sql)
        fixed_params.extend(p)
    if f.starred:
        fixed.append("a.is_starred = 1")
    if f.unread:
        fixed.append("a.is_read = 0")
    if f.focus is not None:
        for sql, value in (
            ("EXISTS (SELECT 1 FROM article_entities x WHERE x.article_id = a.id AND x.entity_id = ?)", f.focus.entity_id),
            ("EXISTS (SELECT 1 FROM article_tags x WHERE x.article_id = a.id AND x.tag_id = ?)", f.focus.tag_id),
            ("a.feed_id = ?", f.focus.feed_id),
            ("f.folder_id = ?", f.focus.folder_id),
        ):
            if value is not None:
                fixed.append(sql)
                fixed_params.append(value)
    return combine(fixed, fixed_params, groups, f.match)


def _group_join(q: WidgetQuery) -> tuple[str, list]:
    if q.group_by == "tag":
        return "JOIN article_tags g ON g.article_id = a.id", []
    if q.group_by == "watchlist":
        sql = ("JOIN article_entities g ON g.article_id = a.id "
               "JOIN entities ge ON ge.id = g.entity_id AND ge.watchlist_id = ?")
        params: list = [q.group_watchlist_id]
        if q.group_entity_ids:
            sql += f" AND g.entity_id IN ({placeholders(len(q.group_entity_ids))})"
            params.extend(q.group_entity_ids)
        return sql, params
    return "", []


FROM = "FROM articles a JOIN feeds f ON f.id = a.feed_id"


def _labels(db: sqlite3.Connection, group_by: GroupBy, keys: list) -> dict:
    real = [k for k in keys if k is not None]
    out: dict = {}
    if group_by == "folder" and None in keys:
        out[None] = {"label": "Unfiled", "color": None}
    if not real:
        return out
    ph = placeholders(len(real))
    if group_by == "tag":
        rows = db.execute(f"SELECT id, name AS label, color FROM tags WHERE id IN ({ph})", real)
    elif group_by == "feed":
        rows = db.execute(f"SELECT id, title AS label, NULL AS color FROM feeds WHERE id IN ({ph})", real)
    elif group_by == "folder":
        rows = db.execute(f"SELECT id, name AS label, NULL AS color FROM folders WHERE id IN ({ph})", real)
    else:
        rows = db.execute(f"SELECT id, name AS label, NULL AS color FROM entities WHERE id IN ({ph})", real)
    for r in rows:
        out[r["id"]] = {"label": r["label"], "color": r["color"]}
    return out


def _breakdown(db: sqlite3.Connection, q: WidgetQuery, since: int, until: int, limit: int) -> list[dict]:
    join, jparams = _group_join(q)
    where, wparams = _where(q, since, until)
    key = _GROUP_KEY[q.group_by]
    rows = db.execute(
        f"SELECT {key} AS k, COUNT(DISTINCT a.id) AS c {FROM} {join} WHERE {where} "
        f"GROUP BY k ORDER BY c DESC, k LIMIT ?",
        [*jparams, *wparams, limit],
    ).fetchall()
    labels = _labels(db, q.group_by, [r["k"] for r in rows])
    return [
        {"key": r["k"], "label": labels.get(r["k"], {}).get("label", "(deleted)"),
         "color": labels.get(r["k"], {}).get("color"), "count": r["c"]}
        for r in rows
    ]


def _bucket_starts(since: int, until: int, offset: int, bucket: str) -> list[str]:
    start = datetime.fromtimestamp(since + offset, tz=timezone.utc).date()
    end = datetime.fromtimestamp(until - 1 + offset, tz=timezone.utc).date()
    if bucket == "week":
        start -= timedelta(days=start.weekday())
    elif bucket == "month":
        start = start.replace(day=1)
    out: list[str] = []
    current: date = start
    while current <= end and len(out) < 4000:
        out.append(current.isoformat())
        if bucket == "day":
            current += timedelta(days=1)
        elif bucket == "week":
            current += timedelta(days=7)
        else:
            current = (current.replace(day=28) + timedelta(days=4)).replace(day=1)
    return out


def run(db: sqlite3.Connection, q: WidgetQuery) -> dict:
    until = q.until_ts if q.until_ts is not None else now() + 1
    since = until - q.days * 86400

    if q.type == "kpi":
        where, params = _where(q, since, until)
        value = db.execute(f"SELECT COUNT(*) {FROM} WHERE {where}", params).fetchone()[0]
        pwhere, pparams = _where(q, since - q.days * 86400, since)
        previous = db.execute(f"SELECT COUNT(*) {FROM} WHERE {pwhere}", pparams).fetchone()[0]
        change = None if previous == 0 else round((value - previous) * 100.0 / previous, 1)
        return {"type": "kpi", "value": value, "previous": previous, "change_pct": change, "days": q.days}

    if q.type == "breakdown":
        items = _breakdown(db, q, since, until, q.limit)
        return {"type": "breakdown", "group_by": q.group_by, "items": items, "days": q.days}

    if q.type == "articles":
        where, params = _where(q, since, until)
        rows = db.execute(
            "SELECT a.id, a.title, a.url, a.sort_ts, a.is_read, a.is_starred, f.title AS feed_title "
            f"{FROM} WHERE {where} ORDER BY a.sort_ts DESC, a.id DESC LIMIT ?",
            [*params, q.limit],
        ).fetchall()
        return {"type": "articles", "items": [dict(r) for r in rows], "days": q.days}

    # timeseries
    offset = q.tz_offset_minutes * 60
    buckets = _bucket_starts(since, until, offset, q.bucket)
    index = {b: i for i, b in enumerate(buckets)}
    bucket_sql = _BUCKET_SQL[q.bucket]
    where, wparams = _where(q, since, until)

    if q.group_by == "none":
        values = [0] * len(buckets)
        for r in db.execute(f"SELECT {bucket_sql} AS b, COUNT(*) AS c {FROM} WHERE {where} GROUP BY b",
                            [offset, *wparams]):
            if r["b"] in index:
                values[index[r["b"]]] = r["c"]
        series = [{"key": "total", "label": "Articles", "color": None, "values": values, "total": sum(values)}]
        return {"type": "timeseries", "bucket": q.bucket, "buckets": buckets, "series": series, "days": q.days}

    top = _breakdown(db, q, since, until, q.limit)
    keys = [t["key"] for t in top]
    series_map = {t["key"]: {**t, "values": [0] * len(buckets), "total": t["count"]} for t in top}
    if keys:
        join, jparams = _group_join(q)
        gkey = _GROUP_KEY[q.group_by]
        real = [k for k in keys if k is not None]
        key_filter = f"{gkey} IN ({placeholders(len(real))})" if real else "0"
        if None in keys:
            key_filter = f"({key_filter} OR {gkey} IS NULL)"
        rows = db.execute(
            f"SELECT {bucket_sql} AS b, {gkey} AS k, COUNT(DISTINCT a.id) AS c {FROM} {join} "
            f"WHERE {where} AND {key_filter} GROUP BY b, k",
            [offset, *jparams, *wparams, *real],
        )
        for r in rows:
            if r["b"] in index and r["k"] in series_map:
                series_map[r["k"]]["values"][index[r["b"]]] = r["c"]
    series = [series_map[k] for k in keys]
    for s in series:
        s.pop("count", None)
    return {"type": "timeseries", "bucket": q.bucket, "buckets": buckets, "series": series,
            "group_by": q.group_by, "days": q.days}
