"""Watchlists/entities, dashboards, dashboard templates and the analytics query endpoint."""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Annotated, Any, Literal, Union

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import Field, StringConstraints, TypeAdapter, model_validator

from app import analytics, combined_analytics, cve_analytics, entities, observatory
from app.api.common import Name, StrictModel, conflict, not_found
from app.db import get_db, now
from app.security import Principal, rate_limit, require_read, require_write

router = APIRouter()

Alias = Annotated[str, StringConstraints(min_length=1, max_length=entities.MAX_ALIAS_LENGTH)]
Description = Annotated[str, StringConstraints(max_length=300)]


# ============================================================================ analytics
PanelKey = Literal["cve_vs_kev", "cve_pressure", "cve_monthly", "kev_lag", "cve_exposure", "rw_trend", "rw_groups",
                   "rw_countries", "rw_sectors", "rw_recent", "net_asn", "net_countries", "net_ports", "net_drop"]


class ObservatoryQuery(StrictModel):
    """A ready-made 🔭 panel (public threat data + local CVE data); the other fields are accepted and ignored."""
    dataset: Literal["observatory"]
    type: Literal["panel"] = "panel"
    panel: PanelKey
    days: int | None = Field(default=None, ge=1, le=3650)
    bucket: Annotated[str, StringConstraints(max_length=10)] | None = None
    tz_offset_minutes: int | None = Field(default=None, ge=-900, le=900)
    sort: Annotated[str, StringConstraints(max_length=20)] | None = None


AnyQuery = Annotated[Union[analytics.WidgetQuery, cve_analytics.CveQuery, combined_analytics.CombinedQuery, ObservatoryQuery],
                     Field(discriminator="dataset")]
_QUERY = TypeAdapter(AnyQuery)


def _with_dataset(raw: Any) -> Any:
    # Widgets saved before CVE support have no "dataset": they are article queries.
    if isinstance(raw, dict) and "dataset" not in raw:
        return {**raw, "dataset": "articles"}
    return raw


def parse_query(raw: Any):
    return _QUERY.validate_python(_with_dataset(raw))


@router.post("/analytics/query", tags=["analytics"], dependencies=[Depends(rate_limit("analytics", 240, 120))])
def analytics_query(body: dict[str, Any] = Body(...), _: Principal = Depends(require_read)) -> dict:
    """Run one widget query: ``dataset: "articles"`` (default; mention-based counts), ``"cves"`` or ``"combined"`` (both)."""
    from pydantic import ValidationError
    from fastapi.exceptions import RequestValidationError

    try:
        query = parse_query(body)
    except ValidationError as exc:
        raise RequestValidationError([{**e, "loc": ("body", *e.get("loc", ()))} for e in exc.errors()]) from None
    with get_db() as db:
        if isinstance(query, ObservatoryQuery):
            result = {"dataset": "observatory", "type": "panel", **observatory.panel(db, query.panel)}
        elif isinstance(query, cve_analytics.CveQuery):
            result = cve_analytics.run(db, query)
        elif isinstance(query, combined_analytics.CombinedQuery):
            result = combined_analytics.run(db, query)
        else:
            result = analytics.run(db, query)
    result["indexing"] = entities.reindexer.busy
    return result


# ============================================================================ watchlists
class EntityIn(StrictModel):
    name: Name
    aliases: list[Alias] = Field(default_factory=list, max_length=entities.MAX_ALIASES)


class EntityPatch(StrictModel):
    name: Name | None = None
    aliases: list[Alias] | None = Field(default=None, max_length=entities.MAX_ALIASES)


class WatchlistIn(StrictModel):
    name: Name
    description: Description = ""
    entities: list[EntityIn] = Field(default_factory=list, max_length=entities.MAX_ENTITIES_PER_LIST)


class WatchlistPatch(StrictModel):
    name: Name | None = None
    description: Description | None = None


def _entity_out(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["aliases"] = json.loads(row["aliases"])
    return out


def _require_tokens(name: str) -> None:
    if entities.alias_key(name) is None:
        raise HTTPException(status_code=422, detail="Name must contain letters or digits (max 8 words)")


@router.get("/watchlists", tags=["watchlists"])
def list_watchlists(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT w.id, w.name, w.slug, w.description, w.position, COUNT(e.id) AS entity_count "
            "FROM watchlists w LEFT JOIN entities e ON e.watchlist_id = w.id "
            "GROUP BY w.id ORDER BY w.position, w.name"
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/watchlists/status", tags=["watchlists"])
def watchlist_status(_: Principal = Depends(require_read)) -> dict:
    return {"indexing": entities.reindexer.busy}


@router.post("/watchlists/reindex", tags=["watchlists"])
def reindex_all(_: Principal = Depends(require_write)) -> dict:
    entities.reindexer.request(None)
    return {"indexing": True}


@router.get("/entities", tags=["watchlists"])
def list_entities(_: Principal = Depends(require_read)) -> list[dict]:
    """Lightweight list of every entity (for dashboard pickers)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT e.id, e.name, e.watchlist_id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
            "ORDER BY w.position, w.name, e.name COLLATE NOCASE"
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/watchlists/{watchlist_id}", tags=["watchlists"])
def get_watchlist(watchlist_id: int, _: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        wl = db.execute("SELECT id, name, slug, description, position FROM watchlists WHERE id = ?",
                        (watchlist_id,)).fetchone()
        if wl is None:
            raise not_found("Watchlist")
        rows = db.execute(
            "SELECT e.id, e.name, e.aliases, "
            "(SELECT COUNT(*) FROM article_entities ae WHERE ae.entity_id = e.id) AS mentions "
            "FROM entities e WHERE e.watchlist_id = ? ORDER BY e.name COLLATE NOCASE",
            (watchlist_id,),
        ).fetchall()
    return {**dict(wl), "entities": [_entity_out(r) for r in rows]}


@router.post("/watchlists", status_code=201, tags=["watchlists"])
def create_watchlist(body: WatchlistIn, _: Principal = Depends(require_write)) -> dict:
    for e in body.entities:
        _require_tokens(e.name)
    try:
        with get_db() as db:
            if db.execute("SELECT COUNT(*) FROM watchlists").fetchone()[0] >= entities.MAX_WATCHLISTS:
                raise HTTPException(status_code=400, detail="Watchlist limit reached")
            cur = db.execute("INSERT INTO watchlists (name, description, position) VALUES (?, ?, 100)",
                             (body.name, body.description))
            wid = cur.lastrowid
            for e in body.entities:
                db.execute("INSERT OR IGNORE INTO entities (watchlist_id, name, aliases) VALUES (?, ?, ?)",
                           (wid, e.name, json.dumps(entities.clean_aliases(e.aliases))))
            ids = [r[0] for r in db.execute("SELECT id FROM entities WHERE watchlist_id = ?", (wid,))]
    except sqlite3.IntegrityError:
        raise conflict("A watchlist with that name already exists") from None
    if ids:
        entities.reindexer.request(ids)
    return get_watchlist(wid)


@router.patch("/watchlists/{watchlist_id}", tags=["watchlists"])
def update_watchlist(watchlist_id: int, body: WatchlistPatch, _: Principal = Depends(require_write)) -> dict:
    try:
        with get_db() as db:
            if db.execute("SELECT 1 FROM watchlists WHERE id = ?", (watchlist_id,)).fetchone() is None:
                raise not_found("Watchlist")
            if body.name is not None:
                db.execute("UPDATE watchlists SET name = ? WHERE id = ?", (body.name, watchlist_id))
            if body.description is not None:
                db.execute("UPDATE watchlists SET description = ? WHERE id = ?", (body.description, watchlist_id))
    except sqlite3.IntegrityError:
        raise conflict("A watchlist with that name already exists") from None
    return get_watchlist(watchlist_id)


@router.delete("/watchlists/{watchlist_id}", tags=["watchlists"])
def delete_watchlist(watchlist_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM watchlists WHERE id = ?", (watchlist_id,)).rowcount == 0:
            raise not_found("Watchlist")
    entities.invalidate()
    return {"ok": True}


@router.post("/watchlists/{watchlist_id}/entities", status_code=201, tags=["watchlists"])
def add_entity(watchlist_id: int, body: EntityIn, _: Principal = Depends(require_write)) -> dict:
    _require_tokens(body.name)
    try:
        with get_db() as db:
            if db.execute("SELECT 1 FROM watchlists WHERE id = ?", (watchlist_id,)).fetchone() is None:
                raise not_found("Watchlist")
            count = db.execute("SELECT COUNT(*) FROM entities WHERE watchlist_id = ?", (watchlist_id,)).fetchone()[0]
            if count >= entities.MAX_ENTITIES_PER_LIST:
                raise HTTPException(status_code=400, detail="Entity limit reached for this watchlist")
            cur = db.execute("INSERT INTO entities (watchlist_id, name, aliases) VALUES (?, ?, ?)",
                             (watchlist_id, body.name, json.dumps(entities.clean_aliases(body.aliases))))
            row = db.execute("SELECT id, name, aliases, 0 AS mentions FROM entities WHERE id = ?",
                             (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise conflict("That entity already exists in this watchlist") from None
    entities.reindexer.request([row["id"]])
    return _entity_out(row)


@router.get("/entities/{entity_id}/page", tags=["watchlists"], dependencies=[Depends(rate_limit("entity_page", 240))])
def entity_page(entity_id: int, days: int = 90, _: Principal = Depends(require_read)) -> dict:
    """Everything known about one watchlist entity: mentions per tab, a timeline, the latest items and what it is seen with."""
    from app import intel

    if days not in (0, 7, 30, 90, 365):  # the same periods as the technique matrix (0 = all time)
        raise HTTPException(status_code=422, detail="days must be 0, 7, 30, 90 or 365")

    with get_db() as db:
        page = intel.entity_page(db, entity_id, days)
    if page is None:
        raise not_found("Entity")
    return page


@router.patch("/entities/{entity_id}", tags=["watchlists"])
def update_entity(entity_id: int, body: EntityPatch, _: Principal = Depends(require_write)) -> dict:
    if body.name is not None:
        _require_tokens(body.name)
    try:
        with get_db() as db:
            if db.execute("SELECT 1 FROM entities WHERE id = ?", (entity_id,)).fetchone() is None:
                raise not_found("Entity")
            if body.name is not None:
                db.execute("UPDATE entities SET name = ? WHERE id = ?", (body.name, entity_id))
            if body.aliases is not None:
                db.execute("UPDATE entities SET aliases = ? WHERE id = ?",
                           (json.dumps(entities.clean_aliases(body.aliases)), entity_id))
            row = db.execute("SELECT id, name, aliases, 0 AS mentions FROM entities WHERE id = ?",
                             (entity_id,)).fetchone()
    except sqlite3.IntegrityError:
        raise conflict("That entity already exists in this watchlist") from None
    entities.reindexer.request([entity_id])
    return _entity_out(row)


@router.delete("/entities/{entity_id}", tags=["watchlists"])
def delete_entity(entity_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM entities WHERE id = ?", (entity_id,)).rowcount == 0:
            raise not_found("Entity")
    entities.invalidate()
    return {"ok": True}


# ============================================================================ dashboards
TIME_CHARTS = {"line", "area", "stackedarea", "bar", "stacked", "percent"}
CHARTS_FOR = {
    "kpi": {"number"},
    "timeseries": TIME_CHARTS,
    "breakdown": {"hbar", "bar", "donut", "pie", "table"},
    "articles": {"list"},
    "cves": {"cvelist"},
    "mixed": {"list"},
    "panel": {"panel"},
}
ChartKind = Literal["number", "line", "area", "stackedarea", "bar", "stacked", "percent", "hbar", "donut", "pie",
                    "table", "list", "cvelist", "panel"]


class Widget(StrictModel):
    id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,24}$")]
    title: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    size: Literal["s", "m", "l", "xl"] = "m"                          # legacy width (¼ ½ ¾ full), used when width is unset
    width: float | None = Field(default=None, ge=10, le=100)          # % of the dashboard row, set by drag-resizing
    height: int | None = Field(default=None, ge=120, le=1400)  # px set by drag-resizing; None = automatic
    chart: ChartKind
    query: AnyQuery

    @model_validator(mode="before")
    @classmethod
    def _default_dataset(cls, data: Any) -> Any:
        if isinstance(data, dict) and "query" in data:
            data = {**data, "query": _with_dataset(data["query"])}
        return data

    @model_validator(mode="after")
    def _chart_matches_type(self) -> "Widget":
        if self.chart not in CHARTS_FOR[self.query.type]:
            raise ValueError(f"chart '{self.chart}' is not valid for a {self.query.type} widget")
        return self


class DashboardIn(StrictModel):
    name: Name
    position: int = Field(default=0, ge=0, le=100000)
    widgets: list[Widget] = Field(default_factory=list, max_length=40)


def _dashboard_out(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["widgets"] = json.loads(row["widgets"])
    return out


def _widgets_json(widgets: list[Widget]) -> str:
    return json.dumps([w.model_dump() for w in widgets], separators=(",", ":"))


@router.get("/dashboards", tags=["dashboards"])
def list_dashboards(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, position, json_array_length(widgets) AS widget_count, updated_at "
            "FROM dashboards ORDER BY position, id"
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/dashboards/{dashboard_id}", tags=["dashboards"])
def get_dashboard(dashboard_id: int, _: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT id, name, position, widgets, updated_at FROM dashboards WHERE id = ?",
                         (dashboard_id,)).fetchone()
    if row is None:
        raise not_found("Dashboard")
    return _dashboard_out(row)


@router.post("/dashboards", status_code=201, tags=["dashboards"])
def create_dashboard(body: DashboardIn, _: Principal = Depends(require_write)) -> dict:
    ts = now()
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM dashboards").fetchone()[0] >= 50:
            raise HTTPException(status_code=400, detail="Dashboard limit reached")
        cur = db.execute(
            "INSERT INTO dashboards (name, position, widgets, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (body.name, body.position, _widgets_json(body.widgets), ts, ts),
        )
    return get_dashboard(cur.lastrowid)


@router.put("/dashboards/{dashboard_id}", tags=["dashboards"])
def replace_dashboard(dashboard_id: int, body: DashboardIn, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        cur = db.execute(
            "UPDATE dashboards SET name = ?, position = ?, widgets = ?, updated_at = ? WHERE id = ?",
            (body.name, body.position, _widgets_json(body.widgets), now(), dashboard_id),
        )
        if cur.rowcount == 0:
            raise not_found("Dashboard")
    return get_dashboard(dashboard_id)


@router.delete("/dashboards/{dashboard_id}", tags=["dashboards"])
def delete_dashboard(dashboard_id: int, _: Principal = Depends(require_write)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM dashboards WHERE id = ?", (dashboard_id,)).rowcount == 0:
            raise not_found("Dashboard")
    return {"ok": True}


# ============================================================================ templates
TEMPLATES = {
    "overview": ("Threat landscape", "Volume, top groups and actors, countries and sectors at a glance"),
    "ransomware": ("Ransomware tracker", "Ransomware groups over time, sectors and countries co-mentioned"),
    "apt": ("APT & nation-state activity", "Threat-actor trends, Russia/China/DPRK-linked activity, targets"),
    "ai": ("AI-powered threats", "Deepfakes, prompt injection, malicious LLMs and AI-assisted attacks"),
    "cve": ("CVE tracker", "New CVEs by severity, CISA KEV additions, edge devices, RCE, AI/ML and OWASP Top 10"),
    "ot-actors": ("OT threat actors — activity", "Latest activity of OT/ICS groups (VOLTZITE, ELECTRUM, KAMACITE, BAUXITE…) across all their aliases"),
    "ot-geo": ("OT attacks — locations & targets", "Countries, sectors and technologies co-mentioned with OT/ICS threat actors"),
    "ot-attacks": ("OT attacks — types & malware", "How OT/ICS groups attack: wipers, PLC/HMI tampering, edge exploitation, ICS malware"),
    "ot-sectors": ("OT sectors & industries", "Which industries are hit in the OT/ICS space: energy, water, manufacturing, transport… and by whom"),
    "ot-history": ("OT threat actors — history", "Multi-year timeline of OT/ICS threat-actor and ICS-malware coverage, per actor"),
    "internet": ("Internet threats", "Top attacking networks and ports (SANS DShield), where attacks come from, criminal networks (Spamhaus)"),
}


def observatory_widgets(panels: list[tuple[str, str, int]]) -> list[dict]:
    """🔭 panel widgets for a dashboard (validated like any widget)."""
    return [Widget.model_validate({"id": secrets.token_hex(4), "title": title, "chart": "panel", "size": "xl" if width >= 100 else "m",
                                   "width": width, "query": {"dataset": "observatory", "type": "panel", "panel": key}}).model_dump()
            for key, title, width in panels]

RUSSIA = ["APT28 / Fancy Bear", "APT29 / Cozy Bear", "Sandworm", "Turla", "Gamaredon", "Star Blizzard"]
CHINA = ["Volt Typhoon", "Salt Typhoon", "Silk Typhoon", "Flax Typhoon", "APT41", "APT40", "Mustang Panda"]
DPRK = ["Lazarus Group", "Kimsuky", "Andariel", "BlueNoroff"]
OT_VOLT_CLUSTER = ["VOLTZITE (Volt Typhoon)", "SYLVANITE (access broker for VOLTZITE)", "AZURITE (Flax Typhoon)"]
OT_SANDWORM = ["KAMACITE (Sandworm access team)", "ELECTRUM (Sandworm / APT44)"]
OT_IRAN = ["BAUXITE (CyberAv3ngers)", "PYROXENE (IRGC-aligned)", "MAGNALLIUM (APT33)", "CHRYSENE (OilRig)",
           "PARISITE (Fox Kitten)"]
OT_ENERGY = ["Electric power & grid", "Renewables (solar, wind, storage)", "Nuclear", "Oil & gas", "Dams & hydropower"]
OT_WATER = ["Water & wastewater"]
OT_MANUFACTURING = ["Manufacturing", "Chemical & process", "Pharmaceuticals & life sciences", "Food, beverage & agriculture",
                    "Mining & metals", "Semiconductors & electronics", "Automotive & EV charging"]
OT_TRANSPORT = ["Rail & road transport", "Maritime & ports", "Aviation & airports"]
OT_HACKTIVISTS = ["Cyber Army of Russia Reborn (CARR)", "Z-Pentest", "Sector 16 (hacktivists)", "TwoNet (hacktivists)",
                  "BAUXITE (CyberAv3ngers)"]
AI_ATTACKS = ["AI-powered attacks (general)", "Deepfakes", "Voice cloning", "Prompt injection & jailbreaks",
              "Malicious LLMs", "AI-generated phishing", "AI-powered malware", "Model & data poisoning"]


class _Refs:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.lists = {r["slug"]: r["id"] for r in db.execute("SELECT id, slug FROM watchlists WHERE slug IS NOT NULL")}
        self.entities: dict[tuple[str, str], int] = {}
        for r in db.execute("SELECT e.id, e.name, w.slug FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                            "WHERE w.slug IS NOT NULL"):
            self.entities[(r["slug"], r["name"])] = r["id"]
        self.tags = {r["name"].lower(): r["id"] for r in db.execute("SELECT id, name FROM tags")}

    def wl(self, slug: str) -> int | None:
        return self.lists.get(slug)

    def ents(self, slug: str, names: list[str]) -> list[int]:
        return [self.entities[(slug, n)] for n in names if (slug, n) in self.entities]


def _w(title: str, chart: str, size: str, qtype: str, **query) -> dict | None:
    filters = query.pop("filters", {})
    # Drop widgets whose required references no longer exist (user deleted a built-in list).
    if query.get("group_by") == "watchlist" and query.get("group_watchlist_id") is None:
        return None
    for key in ("watchlist_ids", "entity_ids"):
        if key in filters and not filters[key]:
            return None
    return {"id": secrets.token_hex(4), "title": title, "chart": chart, "size": size,
            "query": {"type": qtype, **query, "filters": filters}}


def _c(title: str, chart: str, size: str, qtype: str, **query) -> dict:
    """A CVE-dataset widget (NVD/KEV data, not article mentions)."""
    filters = query.pop("filters", {})
    return {"id": secrets.token_hex(4), "title": title, "chart": chart, "size": size,
            "query": {"dataset": "cves", "type": qtype, **query, "filters": filters}}


def _cve_template() -> list[dict]:
    hi = {"severities": ["CRITICAL", "HIGH"]}
    return [
        _c("New CVEs · 7 days", "number", "s", "kpi", days=7),
        _c("Critical · 7 days", "number", "s", "kpi", days=7, filters={"severities": ["CRITICAL"]}),
        _c("High · 7 days", "number", "s", "kpi", days=7, filters={"severities": ["HIGH"]}),
        _c("Added to CISA KEV · 30 days", "number", "s", "kpi", days=30, date_field="kev_added", filters={"kev_only": True}),
        _c("New CVEs per day by severity · 30d", "stacked", "xl", "timeseries", days=30, bucket="day",
           group_by="severity", limit=6),
        _c("Severity mix · 30d", "donut", "m", "breakdown", days=30, group_by="severity"),
        _c("By category · 30d", "hbar", "m", "breakdown", days=30, group_by="category", limit=15),
        _c("OWASP Top 10 (2021) · 30d", "hbar", "m", "breakdown", days=30, group_by="owasp2021", limit=10),
        _c("Top vendors · critical & high · 30d", "hbar", "m", "breakdown", days=30, group_by="vendor", limit=12,
           filters=hi),
        _c("Top weaknesses (CWE) · 30d", "hbar", "m", "breakdown", days=30, group_by="cwe", limit=12),
        _c("Edge devices — critical & high · 30d", "cvelist", "m", "cves", days=30, sort="score", limit=15,
           filters={**hi, "categories": ["edge-firewall-vpn", "edge-routers-iot", "remote-access-file-transfer"]}),
        _c("Latest CISA KEV additions", "cvelist", "xl", "cves", days=90, date_field="kev_added", sort="kev_added",
           limit=15, filters={"kev_only": True}),
        _c("Remote code execution — critical · 30d", "cvelist", "m", "cves", days=30, sort="score", limit=15,
           filters={"categories": ["rce"], "severities": ["CRITICAL"]}),
        _c("AI / ML & LLM vulnerabilities · 90d", "cvelist", "m", "cves", days=90, sort="newest", limit=15,
           filters={"categories": ["ai-ml"]}),
        _c("Weekly AI/ML vs edge vs RCE CVEs · 180d", "line", "xl", "timeseries", days=180, bucket="week",
           group_by="category", limit=8, group_categories=["ai-ml", "edge-firewall-vpn", "rce", "auth-bypass"]),
    ]


def _ot_template(key: str, r: _Refs) -> list[dict | None]:
    """OT/ICS dashboards. Every widget is driven by the 'OT / ICS threat actors' watchlist, so an article counts
    for a group whichever vendor's name it uses (VOLTZITE = Volt Typhoon = Vanguard Panda = UNC3236 ...)."""
    ot, mal, kinds, co, se, ve = (r.wl(s) for s in
                                  ("ot-threat-actors", "ics-malware", "ot-attack-types", "countries", "sectors", "vendors"))
    if ot is None:
        return []
    f_ot = {"watchlist_ids": [ot]}
    f_mal = {"watchlist_ids": [mal]} if mal else f_ot

    def ents(names: list[str]) -> dict:
        return {"entity_ids": r.ents("ot-threat-actors", names)}

    def kind(names: list[str]) -> dict:
        return {"watchlist_ids": [ot], "entity_ids": r.ents("ot-attack-types", names)}

    if key == "ot-actors":
        return [
            _w("OT threat-actor articles · 30d", "number", "s", "kpi", days=30, filters=f_ot),
            _w("VOLTZITE / SYLVANITE / AZURITE · 30d", "number", "s", "kpi", days=30, filters=ents(OT_VOLT_CLUSTER)),
            _w("ELECTRUM / KAMACITE (Sandworm) · 30d", "number", "s", "kpi", days=30, filters=ents(OT_SANDWORM)),
            _w("Iran-linked OT groups · 30d", "number", "s", "kpi", days=30, filters=ents(OT_IRAN)),
            _w("Weekly mentions · top OT groups · 180d", "line", "xl", "timeseries", days=180, bucket="week",
               group_by="watchlist", group_watchlist_id=ot, limit=8),
            _w("Most active OT groups · 90d", "hbar", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=ot, limit=15),
            _w("Attack types in OT-group coverage · 90d", "hbar", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=kinds, limit=12, filters=f_ot),
            _w("Latest OT threat-actor coverage", "list", "xl", "articles", days=60, limit=20, filters=f_ot),
            _w("Hacktivists hitting OT (CARR, Z-Pentest, CyberAv3ngers…) · 90d", "list", "m", "articles", days=90,
               limit=10, filters=ents(OT_HACKTIVISTS)),
            _w("China-nexus pre-positioning (VOLTZITE cluster) · 90d", "list", "m", "articles", days=90, limit=10,
               filters=ents(OT_VOLT_CLUSTER)),
        ]
    if key == "ot-geo":
        crit = r.ents("sectors", ["Critical infrastructure & OT", "Energy & utilities"])
        return [
            _w("Countries co-mentioned with OT groups · 365d", "hbar", "l", "breakdown", days=365, group_by="watchlist",
               group_watchlist_id=co, limit=20, filters=f_ot),
            _w("Sectors co-mentioned with OT groups · 365d", "donut", "m", "breakdown", days=365, group_by="watchlist",
               group_watchlist_id=se, limit=10, filters=f_ot),
            _w("Countries · last 90 days", "table", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=co, limit=25, filters=f_ot),
            _w("Countries over time · top 6 · 365d", "line", "xl", "timeseries", days=365, bucket="month",
               group_by="watchlist", group_watchlist_id=co, limit=6, filters=f_ot),
            _w("Technologies & vendors in OT-group coverage · 365d", "hbar", "m", "breakdown", days=365,
               group_by="watchlist", group_watchlist_id=ve, limit=12, filters=f_ot),
            _w("Where the VOLTZITE cluster is reported · 365d", "hbar", "m", "breakdown", days=365, group_by="watchlist",
               group_watchlist_id=co, limit=10, filters=ents(OT_VOLT_CLUSTER)),
            _w("Where Sandworm (ELECTRUM / KAMACITE) is reported · 365d", "hbar", "m", "breakdown", days=365,
               group_by="watchlist", group_watchlist_id=co, limit=10, filters=ents(OT_SANDWORM)),
            _w("Sandworm (ELECTRUM / KAMACITE) operations · 365d", "list", "m", "articles", days=365, limit=10,
               filters=ents(OT_SANDWORM)),
            _w("Latest OT-group coverage naming critical infrastructure", "list", "xl", "articles", days=90, limit=15,
               filters={"watchlist_ids": [ot], "entity_ids": crit} if crit else f_ot),
        ]
    if key == "ot-sectors":
        sec, ctx = r.wl("ot-sectors"), r.wl("ot-context")
        if sec is None:
            return []
        # "OT coverage" = mentions an OT threat group, ICS malware, or ICS terms / ICS vendors.
        f_cov = {"watchlist_ids": [w for w in (ot, mal, ctx) if w]}

        def sector(names: list[str], base: dict) -> dict:
            return {**base, "entity_ids": r.ents("ot-sectors", names)}

        def who(title: str, names: list[str]) -> dict | None:
            ids = r.ents("ot-sectors", names)
            return _w(title, "hbar", "m", "breakdown", days=3650, group_by="watchlist", group_watchlist_id=ot, limit=10,
                      filters={"entity_ids": ids}) if ids else None

        return [
            _w("Energy in OT coverage · 90d", "number", "s", "kpi", days=90, filters=sector(OT_ENERGY, f_cov)),
            _w("Water in OT coverage · 90d", "number", "s", "kpi", days=90, filters=sector(OT_WATER, f_cov)),
            _w("Manufacturing & process · 90d", "number", "s", "kpi", days=90, filters=sector(OT_MANUFACTURING, f_cov)),
            _w("Transport · 90d", "number", "s", "kpi", days=90, filters=sector(OT_TRANSPORT, f_cov)),
            _w("Sectors in OT / ICS coverage · 365d", "hbar", "l", "breakdown", days=365, group_by="watchlist",
               group_watchlist_id=sec, limit=20, filters=f_cov),
            _w("Sectors named with OT threat groups · all time", "donut", "m", "breakdown", days=3650, group_by="watchlist",
               group_watchlist_id=sec, limit=10, filters=f_ot),
            _w("Sectors over time · top 6 · 365d", "stacked", "xl", "timeseries", days=365, bucket="month",
               group_by="watchlist", group_watchlist_id=sec, limit=6, filters=f_cov),
            who("Who is reported against energy · all time", OT_ENERGY),
            who("Who is reported against water · all time", OT_WATER),
            who("Who is reported against manufacturing · all time", OT_MANUFACTURING),
            _w("Sectors · last 90 days", "table", "m", "breakdown", days=90, group_by="watchlist", group_watchlist_id=sec,
               limit=25, filters=f_cov),
            _w("Latest energy & water OT coverage", "list", "xl", "articles", days=90, limit=15,
               filters=sector(OT_ENERGY + OT_WATER, f_cov)),
            _w("Latest manufacturing & transport OT coverage", "list", "xl", "articles", days=90, limit=15,
               filters=sector(OT_MANUFACTURING + OT_TRANSPORT, f_cov)),
        ]
    if key == "ot-attacks":
        return [
            _w("Wiper / destructive · OT groups · 90d", "number", "s", "kpi", days=90,
               filters=kind(["Wiper / destructive attack"])),
            _w("PLC / HMI tampering · OT groups · 90d", "number", "s", "kpi", days=90,
               filters=kind(["PLC / controller targeting", "HMI / SCADA access & defacement"])),
            _w("Edge-device exploitation · OT groups · 90d", "number", "s", "kpi", days=90,
               filters=kind(["Edge device / VPN exploitation"])),
            _w("ICS malware mentions · 90d", "number", "s", "kpi", days=90, filters=f_mal),
            _w("Attack / compromise types · OT groups · 365d", "hbar", "l", "breakdown", days=365, group_by="watchlist",
               group_watchlist_id=kinds, limit=15, filters=f_ot),
            _w("ICS malware & frameworks · all time", "hbar", "m", "breakdown", days=3650, group_by="watchlist",
               group_watchlist_id=mal, limit=15),
            _w("Attack types over time · top 6 · 365d", "stacked", "xl", "timeseries", days=365, bucket="month",
               group_by="watchlist", group_watchlist_id=kinds, limit=6, filters=f_ot),
            _w("ICS malware over time · 3 years", "line", "xl", "timeseries", days=1095, bucket="month",
               group_by="watchlist", group_watchlist_id=mal, limit=8),
            _w("Latest destructive / ICS-malware coverage", "list", "xl", "articles", days=180, limit=15, filters=f_mal),
        ]
    # ot-history
    return [
        _w("OT threat-actor articles · all time", "number", "s", "kpi", days=3650, filters=f_ot),
        _w("OT threat-actor articles · 365d", "number", "s", "kpi", days=365, filters=f_ot),
        _w("ICS-malware articles · all time", "number", "s", "kpi", days=3650, filters=f_mal),
        _w("Monthly mentions per OT group · all time", "line", "xl", "timeseries", days=3650, bucket="month",
           group_by="watchlist", group_watchlist_id=ot, limit=8),
        _w("Total coverage per OT group · all time", "table", "m", "breakdown", days=3650, group_by="watchlist",
           group_watchlist_id=ot, limit=25),
        _w("OT-group coverage by month · 3 years", "bar", "m", "timeseries", days=1095, bucket="month", filters=f_ot),
        _w("VOLTZITE cluster history (Volt Typhoon, SYLVANITE, AZURITE)", "list", "m", "articles", days=3650, limit=15,
           filters=ents(OT_VOLT_CLUSTER)),
        _w("ELECTRUM / KAMACITE history (Sandworm, APT44)", "list", "m", "articles", days=3650, limit=15,
           filters=ents(OT_SANDWORM)),
        _w("BAUXITE history (CyberAv3ngers, Storm-0784)", "list", "m", "articles", days=3650, limit=15,
           filters=ents(["BAUXITE (CyberAv3ngers)"])),
        _w("XENOTIME / CHERNOVITE history (TRITON, PIPEDREAM)", "list", "m", "articles", days=3650, limit=15,
           filters=ents(["XENOTIME (TRITON operators)", "CHERNOVITE (PIPEDREAM developers)"])),
    ]


def _build_template(key: str, r: _Refs) -> list[dict]:
    if key == "cve":
        return observatory_widgets(observatory.CVE_PANELS) + [Widget.model_validate(w).model_dump() for w in _cve_template()]
    if key == "internet":
        return observatory_widgets(observatory.NET_PANELS)
    if key.startswith("ot-"):
        built = [w for w in _ot_template(key, r) if w is not None]
        return [Widget.model_validate(w).model_dump() for w in built]
    rw, ta, ai, co, se, ve = (r.wl(s) for s in
                              ("ransomware-groups", "threat-actors", "ai-threats", "countries", "sectors", "vendors"))
    lst = lambda v: [v] if v else []  # noqa: E731
    if key == "overview":
        zero_day = r.tags.get("zero-days & exploits")
        widgets = [
            _w("Articles · 7 days", "number", "s", "kpi", days=7),
            _w("Ransomware-group mentions · 7d", "number", "s", "kpi", days=7, filters={"watchlist_ids": lst(rw)}),
            _w("Threat-actor mentions · 7d", "number", "s", "kpi", days=7, filters={"watchlist_ids": lst(ta)}),
            _w("AI-threat mentions · 7d", "number", "s", "kpi", days=7,
               filters={"entity_ids": r.ents("ai-threats", AI_ATTACKS)}),
            _w("Daily volume by collection · 30d", "line", "xl", "timeseries", days=30, bucket="day",
               group_by="tag", limit=6),
            _w("Top ransomware groups · 30d", "hbar", "m", "breakdown", days=30, group_by="watchlist",
               group_watchlist_id=rw, limit=10),
            _w("Most-mentioned threat actors · 30d", "hbar", "m", "breakdown", days=30, group_by="watchlist",
               group_watchlist_id=ta, limit=10),
            _w("Countries mentioned · 30d", "hbar", "m", "breakdown", days=30, group_by="watchlist",
               group_watchlist_id=co, limit=12),
            _w("Sectors mentioned · 30d", "donut", "m", "breakdown", days=30, group_by="watchlist",
               group_watchlist_id=se, limit=8),
            _w("Latest exploitation & zero-day news", "list", "xl", "articles", days=14, limit=12,
               filters={"tag_ids": [zero_day]} if zero_day else {"q": "exploited"}),
        ]
    elif key == "ransomware":
        f_rw = {"watchlist_ids": lst(rw)}
        widgets = [
            _w("Ransomware articles · 30d", "number", "s", "kpi", days=30, filters=f_rw),
            _w("Ransomware articles · 7d", "number", "s", "kpi", days=7, filters=f_rw),
            _w("Healthcare + ransomware · 30d", "number", "s", "kpi", days=30,
               filters={**f_rw, "entity_ids": r.ents("sectors", ["Healthcare"])}),
            _w("Data leak / extortion · 30d", "number", "s", "kpi", days=30, filters={**f_rw, "q": "leak"}),
            _w("Weekly mentions · top 6 groups · 90d", "line", "xl", "timeseries", days=90, bucket="week",
               group_by="watchlist", group_watchlist_id=rw, limit=6),
            _w("Top groups · 90d", "hbar", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=rw, limit=12),
            _w("Sectors co-mentioned with ransomware · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=se, limit=10, filters=f_rw),
            _w("Countries co-mentioned with ransomware · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=co, limit=12, filters=f_rw),
            _w("Vendors / products co-mentioned · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=ve, limit=10, filters=f_rw),
            _w("Latest ransomware coverage", "list", "xl", "articles", days=30, limit=15, filters=f_rw),
        ]
    elif key == "apt":
        f_ta = {"watchlist_ids": lst(ta)}
        widgets = [
            _w("Threat-actor articles · 30d", "number", "s", "kpi", days=30, filters=f_ta),
            _w("Russia-linked actors · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("threat-actors", RUSSIA)}),
            _w("China-linked actors · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("threat-actors", CHINA)}),
            _w("North Korea-linked actors · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("threat-actors", DPRK)}),
            _w("Weekly mentions · top 6 actors · 180d", "line", "xl", "timeseries", days=180, bucket="week",
               group_by="watchlist", group_watchlist_id=ta, limit=6),
            _w("Most-mentioned actors · 90d", "hbar", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=ta, limit=12),
            _w("Countries co-mentioned with APTs · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=co, limit=12, filters=f_ta),
            _w("Sectors co-mentioned with APTs · 90d", "donut", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=se, limit=8, filters=f_ta),
            _w("Vendors / products co-mentioned · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=ve, limit=10, filters=f_ta),
            _w("Latest APT coverage", "list", "xl", "articles", days=30, limit=15, filters=f_ta),
        ]
    else:  # ai
        ai_ids = r.ents("ai-threats", AI_ATTACKS)
        f_ai = {"entity_ids": ai_ids}
        widgets = [
            _w("AI-threat articles · 30d", "number", "s", "kpi", days=30, filters=f_ai),
            _w("Deepfakes & voice cloning · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("ai-threats", ["Deepfakes", "Voice cloning"])}),
            _w("Prompt injection & jailbreaks · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("ai-threats", ["Prompt injection & jailbreaks"])}),
            _w("Malicious LLMs & AI malware · 30d", "number", "s", "kpi", days=30,
               filters={"entity_ids": r.ents("ai-threats", ["Malicious LLMs", "AI-powered malware"])}),
            _w("Weekly AI-threat topics · 180d", "line", "xl", "timeseries", days=180, bucket="week",
               group_by="watchlist", group_watchlist_id=ai, group_entity_ids=ai_ids, limit=6),
            _w("AI-threat topics · 90d", "hbar", "m", "breakdown", days=90, group_by="watchlist",
               group_watchlist_id=ai, limit=10),
            _w("Sectors co-mentioned with AI threats · 90d", "hbar", "m", "breakdown", days=90,
               group_by="watchlist", group_watchlist_id=se, limit=10, filters=f_ai),
            _w("Threat actors using AI · 180d", "hbar", "m", "breakdown", days=180,
               group_by="watchlist", group_watchlist_id=ta, limit=10, filters=f_ai),
            _w("Latest AI-threat coverage", "list", "xl", "articles", days=30, limit=15, filters=f_ai),
        ]
    built = [w for w in widgets if w is not None]
    # Re-validate through the model so templates obey exactly the same rules as user input.
    return [Widget.model_validate(w).model_dump() for w in built]


@router.get("/dashboard-templates", tags=["dashboards"])
def list_templates(_: Principal = Depends(require_read)) -> list[dict]:
    return [{"key": k, "name": n, "description": d} for k, (n, d) in TEMPLATES.items()]


@router.post("/dashboard-templates/{key}", status_code=201, tags=["dashboards"])
def create_from_template(key: str, _: Principal = Depends(require_write)) -> dict:
    if key not in TEMPLATES:
        raise not_found("Template")
    with get_db() as db:
        widgets = _build_template(key, _Refs(db))
        if db.execute("SELECT COUNT(*) FROM dashboards").fetchone()[0] >= 50:
            raise HTTPException(status_code=400, detail="Dashboard limit reached")
        ts = now()
        cur = db.execute(
            "INSERT INTO dashboards (name, position, widgets, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (TEMPLATES[key][0], 0, json.dumps(widgets, separators=(",", ":")), ts, ts),
        )
    return get_dashboard(cur.lastrowid)
