"""Read later: send an article to Wallabag or Linkwarden (Obsidian is handled in the browser).

The service URLs are set by the admin and usually point at a self-hosted instance on the LAN, so - like the X bridge
and the local AI server - private addresses are allowed for them (and only for them). Credentials live encrypted in
``integrations`` (name ``readlater``) and are never returned. Requests go through ``netguard`` (timeouts, size caps,
pinned DNS, no redirects to other schemes).
"""

from __future__ import annotations

import json
import logging
import time
from urllib.parse import urlencode

from app import integrations, netguard
from app.db import get_db

log = logging.getLogger("eos.readlater")

TIMEOUT = 20
_token_cache: dict[str, tuple[str, float]] = {}  # wallabag base url -> (access token, expiry)


class ReadLaterError(Exception):
    pass


def service_url(value: str) -> str:
    try:
        url = netguard.normalize_url(value.strip()).rstrip("/")
    except netguard.UnsafeURLError as exc:
        raise ValueError(f"Not a valid http(s) address: {exc}") from None
    return url


def status(db) -> dict:
    config, secrets = integrations.load(db, "readlater")
    return {
        "wallabag": bool(config.get("wallabag_url") and config.get("wallabag_client_id") and secrets.get("wallabag_password")),
        "linkwarden": bool(config.get("linkwarden_url") and secrets.get("linkwarden_token")),
        "obsidian": {"vault": config.get("obsidian_vault"), "folder": config.get("obsidian_folder")} if config.get("obsidian_vault") else None,
    }


def _post(url: str, body: bytes, headers: dict[str, str]) -> dict:
    try:
        resp = netguard.request("POST", url, headers=headers, content=body, allow_private=True, timeout=TIMEOUT,
                                max_bytes=2 * 1024 * 1024, max_redirects=0)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise ReadLaterError(f"Could not reach the service: {exc}") from None
    if resp.status_code in (401, 403):
        raise ReadLaterError("The service refused the credentials (check Settings → Integrations → Read later)")
    if 300 <= resp.status_code < 400:
        raise ReadLaterError("The service redirected the request - check its address (https, no trailing path)")
    if resp.status_code >= 400:
        raise ReadLaterError(f"The service answered HTTP {resp.status_code}")
    try:
        return json.loads(resp.content or b"{}")
    except ValueError:
        return {}


def _wallabag_token(config: dict, secrets: dict) -> str:
    base = config["wallabag_url"]
    cached = _token_cache.get(base)
    if cached and cached[1] > time.time() + 30:
        return cached[0]
    form = urlencode({"grant_type": "password", "client_id": config.get("wallabag_client_id", ""),
                      "client_secret": secrets.get("wallabag_client_secret", ""),
                      "username": secrets.get("wallabag_username", ""), "password": secrets.get("wallabag_password", "")})
    data = _post(f"{base}/oauth/v2/token", form.encode(), {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise ReadLaterError("Wallabag did not return an access token")
    _token_cache[base] = (token, time.time() + float(data.get("expires_in") or 3600))
    return token


def save(service: str, url: str, title: str, tags: list[str]) -> dict:
    """Send one link to Wallabag or Linkwarden. Returns {"ok": True, "service": ...}."""
    with get_db() as db:
        config, secrets = integrations.load(db, "readlater")
    tags = [t[:50] for t in tags[:10]]
    if service == "wallabag":
        if not (config.get("wallabag_url") and secrets.get("wallabag_password")):
            raise ReadLaterError("Wallabag is not set up (Settings → Integrations → Read later)")
        token = _wallabag_token(config, secrets)
        body = urlencode({"url": url, "title": title[:300], "tags": ",".join(tags)}).encode()
        _post(f"{config['wallabag_url']}/api/entries.json", body,
              {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    elif service == "linkwarden":
        if not (config.get("linkwarden_url") and secrets.get("linkwarden_token")):
            raise ReadLaterError("Linkwarden is not set up (Settings → Integrations → Read later)")
        body = json.dumps({"url": url, "name": title[:300], "tags": [{"name": t} for t in tags]}).encode()
        _post(f"{config['linkwarden_url']}/api/v1/links", body,
              {"Authorization": f"Bearer {secrets['linkwarden_token']}", "Content-Type": "application/json", "Accept": "application/json"})
    else:
        raise ReadLaterError("Unknown read-later service")
    log.info("Saved a link to %s", service)
    return {"ok": True, "service": service}
