"""Stage 3 API: AI provider settings, article summaries, delivery channels, digests and CVE alerts.

Authorization
-------------
* AI provider settings, delivery channels, digests and alert rules: **admin session only**. They
  hold credentials or make the server send messages / spend AI credits on a schedule.
* Requesting an article summary: **write** scope (it spends AI budget), rate-limited.
* Reading cached summaries, usage, digest runs and the alert log: **read** scope.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, StringConstraints

from app import ai, alerts, delivery, digests, integrations, netguard, secretbox
from app.api.common import StrictModel, not_found
from app.db import get_db, now
from app.security import Principal, audit, rate_limit, require_admin, require_read, require_write

router = APIRouter(tags=["ai"])


def _422(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc)[:300])


# ============================================================================ AI settings
class AISettingsIn(StrictModel):
    provider: Literal["anthropic", "openai", "gemini", "openai_compatible", "none"] | None = None
    model: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/@-]{1,100}$")] | None = None
    base_url: Annotated[str, StringConstraints(max_length=300)] | None = None
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None
    max_input_chars: int | None = Field(default=None, ge=1000, le=200_000)
    daily_limit: int | None = Field(default=None, ge=0, le=100_000)
    language: Annotated[str, StringConstraints(pattern=r"^[A-Za-z ()\-]{2,40}$")] | None = None
    summary_style: Literal["bullets", "paragraph"] | None = None
    api_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._\-:]{8,300}$")] | None = None
    clear_api_key: bool = False


def _ai_status() -> dict:
    cfg, secrets = ai.settings()
    return {"config": cfg, "api_key_set": bool(secrets.get("api_key")), "configured": ai.is_configured(),
            "providers": list(ai.PROVIDERS), "default_models": ai.DEFAULT_MODELS, "usage": ai.usage(7)}


@router.get("/ai/settings")
def get_ai_settings(_: Principal = Depends(require_admin)) -> dict:
    return _ai_status()


@router.put("/ai/settings", dependencies=[Depends(rate_limit("ai_settings", 20))])
def put_ai_settings(body: AISettingsIn, principal: Principal = Depends(require_admin)) -> dict:
    config: dict[str, Any] = {k: v for k, v in body.model_dump(exclude={"api_key", "clear_api_key"}).items() if v is not None}
    if body.provider == "none":
        config["provider"] = None
    if body.base_url:
        try:
            config["base_url"] = netguard.normalize_url(body.base_url).rstrip("/")
        except netguard.UnsafeURLError as exc:
            raise _422(exc) from None
    with get_db() as db:
        integrations.save(db, "ai", config=config, secrets={"api_key": body.api_key} if body.api_key else None,
                          remove_secrets=("api_key",) if body.clear_api_key else (),
                          remove_config=("provider",) if body.provider == "none" else ())
    audit("ai_settings_updated", principal, provider=body.provider, model=body.model, key_set=bool(body.api_key),
          key_cleared=body.clear_api_key)
    return _ai_status()


@router.post("/ai/test", dependencies=[Depends(rate_limit("ai_test", 5))])
def test_ai(_: Principal = Depends(require_admin)) -> dict:
    try:
        result = ai.complete("Reply with one short sentence.", "Say hello to the Eye of Sauron security team.", max_tokens=1000)
    except ai.AIError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {"ok": True, "provider": result.provider, "model": result.model, "reply": result.text[:300],
            "tokens_in": result.tokens_in, "tokens_out": result.tokens_out}


@router.get("/ai/usage")
def ai_usage(_: Principal = Depends(require_read)) -> dict:
    cfg, _s = ai.settings()
    return {"days": ai.usage(30), "daily_limit": cfg["daily_limit"], "configured": ai.is_configured()}


# ============================================================================ summaries
@router.get("/articles/{article_id}/summary", tags=["articles"])
def get_summary(article_id: int, _: Principal = Depends(require_read)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM article_summaries WHERE article_id = ?", (article_id,)).fetchone()
    if row is None:
        if db_missing_article(article_id):
            raise not_found("Article")
        return {"article_id": article_id, "summary": None}  # no summary yet (not an error)
    return dict(row)


def db_missing_article(article_id: int) -> bool:
    with get_db() as db:
        return db.execute("SELECT 1 FROM articles WHERE id = ?", (article_id,)).fetchone() is None


class SummaryIn(StrictModel):
    force: bool = False


@router.post("/articles/{article_id}/summary", tags=["articles"], dependencies=[Depends(rate_limit("ai_summary", 30))])
def make_summary(article_id: int, body: SummaryIn | None = None, _: Principal = Depends(require_write)) -> dict:
    try:
        return ai.summarize_article(article_id, force=bool(body and body.force))
    except ai.AIError as exc:
        raise HTTPException(status_code=404 if "not found" in str(exc) else 400, detail=str(exc)) from None


# ============================================================================ delivery channels
class ChannelIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    config: delivery.ChannelConfig
    credentials: dict[str, Annotated[str, StringConstraints(max_length=600)]] = Field(default_factory=dict, max_length=5)
    enabled: bool = True


class ChannelPatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=80)] | None = None
    config: delivery.ChannelConfig | None = None
    credentials: dict[str, Annotated[str, StringConstraints(max_length=600)]] | None = Field(default=None, max_length=5)
    enabled: bool | None = None


def _channel_out(row) -> dict:
    """Public view: never includes credentials, only which ones are set."""
    creds_set: list[str] = []
    if row["credentials"]:
        try:
            creds_set = sorted(k for k, v in json.loads(secretbox.decrypt(row["credentials"])).items() if v)
        except (secretbox.SecretError, ValueError):
            creds_set = ["(unreadable)"]
    return {"id": row["id"], "name": row["name"], "kind": row["kind"], "config": json.loads(row["config"]),
            "credentials_set": creds_set, "enabled": bool(row["enabled"]), "created_at": row["created_at"],
            "last_sent": row["last_sent"], "last_error": row["last_error"]}


def _check_channel(db, cfg, creds: dict) -> dict:
    if isinstance(cfg, delivery.WebhookConfig) and db.execute("SELECT 1 FROM webhooks WHERE id = ?", (cfg.webhook_id,)).fetchone() is None:
        raise HTTPException(status_code=422, detail="Webhook does not exist")
    if isinstance(cfg, delivery.NtfyConfig):
        try:
            netguard.normalize_url(cfg.server)
        except netguard.UnsafeURLError as exc:
            raise _422(exc) from None
    try:
        return delivery.validate_credentials(cfg.kind, creds)
    except ValueError as exc:
        raise _422(exc) from None


@router.get("/delivery-channels")
def list_channels(_: Principal = Depends(require_admin)) -> list[dict]:
    with get_db() as db:
        return [_channel_out(r) for r in db.execute("SELECT * FROM delivery_channels ORDER BY name COLLATE NOCASE")]


@router.post("/delivery-channels", status_code=201, dependencies=[Depends(rate_limit("delivery_write", 30))])
def create_channel(body: ChannelIn, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM delivery_channels").fetchone()[0] >= 50:
            raise HTTPException(status_code=400, detail="Channel limit reached")
        creds = _check_channel(db, body.config, body.credentials)
        cur = db.execute("INSERT INTO delivery_channels (name, kind, config, credentials, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                         (body.name, body.config.kind, body.config.model_dump_json(),
                          secretbox.encrypt(json.dumps(creds)) if creds else None, int(body.enabled), now()))
        row = db.execute("SELECT * FROM delivery_channels WHERE id = ?", (cur.lastrowid,)).fetchone()
    audit("delivery_channel_created", principal, channel_id=row["id"], kind=row["kind"])
    return _channel_out(row)


@router.patch("/delivery-channels/{channel_id}", dependencies=[Depends(rate_limit("delivery_write", 30))])
def update_channel(channel_id: int, body: ChannelPatch, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM delivery_channels WHERE id = ?", (channel_id,)).fetchone()
        if row is None:
            raise not_found("Channel")
        cfg = body.config or delivery.parse_config(row["config"])
        if cfg.kind != row["kind"]:
            raise HTTPException(status_code=422, detail="A channel's kind cannot change - create a new channel")
        current = json.loads(secretbox.decrypt(row["credentials"])) if row["credentials"] else {}
        creds = _check_channel(db, cfg, {**current, **body.credentials} if body.credentials is not None else current)
        db.execute("UPDATE delivery_channels SET name = COALESCE(?, name), config = ?, credentials = ?, enabled = COALESCE(?, enabled) WHERE id = ?",
                   (body.name, cfg.model_dump_json(), secretbox.encrypt(json.dumps(creds)) if creds else None,
                    None if body.enabled is None else int(body.enabled), channel_id))
        row = db.execute("SELECT * FROM delivery_channels WHERE id = ?", (channel_id,)).fetchone()
    audit("delivery_channel_updated", principal, channel_id=channel_id, credentials_changed=body.credentials is not None)
    return _channel_out(row)


@router.delete("/delivery-channels/{channel_id}")
def delete_channel(channel_id: int, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM delivery_channels WHERE id = ?", (channel_id,)).rowcount == 0:
            raise not_found("Channel")
    audit("delivery_channel_deleted", principal, channel_id=channel_id)
    return {"ok": True}


@router.post("/delivery-channels/{channel_id}/test", dependencies=[Depends(rate_limit("delivery_test", 6))])
def test_channel(channel_id: int, _: Principal = Depends(require_admin)) -> dict:
    try:
        delivery.send(channel_id, delivery.Message("Eye of Sauron test message",
                                                   "If you can read this, alerts and digests can reach you here.", kind="test"))
    except delivery.DeliveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {"ok": True}


def _check_channel_ids(db, ids: list[int]) -> None:
    for cid in ids:
        if db.execute("SELECT 1 FROM delivery_channels WHERE id = ?", (cid,)).fetchone() is None:
            raise HTTPException(status_code=422, detail=f"Delivery channel {cid} does not exist")


# ============================================================================ digests
class DigestIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^\r\n]+$")]
    enabled: bool = True
    config: digests.DigestConfig


class DigestPatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^\r\n]+$")] | None = None
    enabled: bool | None = None
    config: digests.DigestConfig | None = None


def _digest_out(row) -> dict:
    return {"id": row["id"], "name": row["name"], "enabled": bool(row["enabled"]), "config": json.loads(row["config"]),
            "last_run": row["last_run"], "next_run": row["next_run"], "created_at": row["created_at"]}


@router.get("/digests")
def list_digests(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [_digest_out(r) for r in db.execute("SELECT * FROM digests ORDER BY name COLLATE NOCASE")]


@router.post("/digests", status_code=201, dependencies=[Depends(rate_limit("digest_write", 30))])
def create_digest(body: DigestIn, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM digests").fetchone()[0] >= 50:
            raise HTTPException(status_code=400, detail="Digest limit reached")
        _check_channel_ids(db, body.config.channel_ids)
        cur = db.execute("INSERT INTO digests (name, enabled, config, next_run, created_at) VALUES (?, ?, ?, ?, ?)",
                         (body.name, int(body.enabled), digests.config_json(body.config), digests.next_run(body.config, now()), now()))
        row = db.execute("SELECT * FROM digests WHERE id = ?", (cur.lastrowid,)).fetchone()
    audit("digest_created", principal, digest_id=row["id"])
    return _digest_out(row)


@router.patch("/digests/{digest_id}", dependencies=[Depends(rate_limit("digest_write", 30))])
def update_digest(digest_id: int, body: DigestPatch, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM digests WHERE id = ?", (digest_id,)).fetchone()
        if row is None:
            raise not_found("Digest")
        cfg = body.config or digests.DigestConfig.model_validate_json(row["config"])
        _check_channel_ids(db, cfg.channel_ids)
        db.execute("UPDATE digests SET name = COALESCE(?, name), enabled = COALESCE(?, enabled), config = ?, next_run = ? WHERE id = ?",
                   (body.name, None if body.enabled is None else int(body.enabled), digests.config_json(cfg),
                    digests.next_run(cfg, now()), digest_id))
        row = db.execute("SELECT * FROM digests WHERE id = ?", (digest_id,)).fetchone()
    audit("digest_updated", principal, digest_id=digest_id)
    return _digest_out(row)


@router.delete("/digests/{digest_id}")
def delete_digest(digest_id: int, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM digests WHERE id = ?", (digest_id,)).rowcount == 0:
            raise not_found("Digest")
    audit("digest_deleted", principal, digest_id=digest_id)
    return {"ok": True}


class RunIn(StrictModel):
    preview: bool = True   # preview = build and store, do not send


@router.post("/digests/{digest_id}/run", dependencies=[Depends(rate_limit("digest_run", 6))])
def run_digest(digest_id: int, body: RunIn, principal: Principal = Depends(require_admin)) -> dict:
    try:
        out = digests.run(digest_id, preview=body.preview)
    except ValueError:
        raise not_found("Digest") from None
    audit("digest_run", principal, digest_id=digest_id, preview=body.preview)
    return out


@router.get("/digests/{digest_id}/runs")
def digest_runs(digest_id: int, _: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM digest_runs WHERE digest_id = ? ORDER BY id DESC LIMIT 30", (digest_id,))]


# ============================================================================ CVE alert rules
class AlertRuleIn(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^\r\n]+$")]
    enabled: bool = True
    config: alerts.CveAlertConfig


class AlertRulePatch(StrictModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[^\r\n]+$")] | None = None
    enabled: bool | None = None
    config: alerts.CveAlertConfig | None = None


def _rule_out(row) -> dict:
    return {"id": row["id"], "name": row["name"], "enabled": bool(row["enabled"]), "config": json.loads(row["config"]),
            "created_at": row["created_at"], "last_fired": row["last_fired"]}


@router.get("/alert-rules")
def list_alert_rules(_: Principal = Depends(require_read)) -> list[dict]:
    with get_db() as db:
        return [_rule_out(r) for r in db.execute("SELECT * FROM alert_rules ORDER BY name COLLATE NOCASE")]


@router.post("/alert-rules", status_code=201, dependencies=[Depends(rate_limit("alert_write", 30))])
def create_alert_rule(body: AlertRuleIn, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0] >= 100:
            raise HTTPException(status_code=400, detail="Alert rule limit reached")
        _check_channel_ids(db, body.config.channel_ids)
        cur = db.execute("INSERT INTO alert_rules (name, enabled, config, created_at) VALUES (?, ?, ?, ?)",
                         (body.name, int(body.enabled), alerts.config_json(body.config), now()))
        row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (cur.lastrowid,)).fetchone()
    audit("alert_rule_created", principal, rule_id=row["id"])
    return _rule_out(row)


@router.patch("/alert-rules/{rule_id}", dependencies=[Depends(rate_limit("alert_write", 30))])
def update_alert_rule(rule_id: int, body: AlertRulePatch, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise not_found("Alert rule")
        cfg = body.config or alerts.CveAlertConfig.model_validate_json(row["config"])
        _check_channel_ids(db, cfg.channel_ids)
        db.execute("UPDATE alert_rules SET name = COALESCE(?, name), enabled = COALESCE(?, enabled), config = ? WHERE id = ?",
                   (body.name, None if body.enabled is None else int(body.enabled), alerts.config_json(cfg), rule_id))
        row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
    audit("alert_rule_updated", principal, rule_id=rule_id)
    return _rule_out(row)


@router.delete("/alert-rules/{rule_id}")
def delete_alert_rule(rule_id: int, principal: Principal = Depends(require_admin)) -> dict:
    with get_db() as db:
        if db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,)).rowcount == 0:
            raise not_found("Alert rule")
    audit("alert_rule_deleted", principal, rule_id=rule_id)
    return {"ok": True}


@router.post("/alert-rules/{rule_id}/preview", dependencies=[Depends(rate_limit("alert_preview", 20))])
def preview_alert_rule(rule_id: int, _: Principal = Depends(require_admin)) -> dict:
    """Which CVEs from the last 7 days would this rule have matched? (Nothing is sent.)"""
    with get_db() as db:
        row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise not_found("Alert rule")
        cfg = alerts.CveAlertConfig.model_validate_json(row["config"])
        since = now() - 7 * 86400
        ids = [r[0] for r in db.execute("SELECT id FROM cves WHERE published >= ? OR kev_added >= ?", (since, since))]
        rows = alerts._cve_rows(db, ids)
    hits = [{"id": c["id"], "score": c["score"], "severity": c["severity"], "kev": bool(c["kev"]), "event": kind}
            for c in rows if (kind := alerts._matches(cfg, c, since))]
    hits.sort(key=lambda h: (h["kev"], h["score"] or 0), reverse=True)
    return {"matches": len(hits), "sample": hits[:50]}


@router.get("/alerts/recent")
def recent_alerts(_: Principal = Depends(require_read)) -> list[dict]:
    return alerts.recent(100)

