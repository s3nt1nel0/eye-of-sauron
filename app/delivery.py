"""Delivery channels for digests and alerts: email (SMTP), Telegram bot, ntfy, Discord, Slack and
the existing signed webhooks.

Every channel sends *plain text* (plus an escaped HTML alternative for email). Remote content in
messages (article titles, AI text) can't inject markup or mentions:

* Discord: ``allowed_mentions: {parse: []}`` so ``@everyone`` / role pings in a title do nothing.
* Slack: ``&``, ``<`` and ``>`` are escaped, which neutralises ``<!channel>`` and link syntax.
* Telegram: no ``parse_mode``, so text is never interpreted as HTML/Markdown.
* Email: headers are built with ``email.message.EmailMessage``; CR/LF in a subject is removed.

Credentials (SMTP password, bot token, Discord/Slack webhook URLs, ntfy token) are stored
encrypted in ``delivery_channels.credentials`` and never returned. SMTP always uses TLS
(implicit TLS or STARTTLS) with certificate verification.
"""

from __future__ import annotations

import html
import json
import logging
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app import netguard, secretbox
from app.config import get_settings
from app.db import get_db, now

log = logging.getLogger("eos.delivery")

KINDS = ("email", "telegram", "ntfy", "discord", "slack", "webhook")
EMAIL_RE = r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$"
HOST_RE = r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
_CRLF = re.compile(r"[\r\n\x00]+")


class DeliveryError(Exception):
    """User-facing delivery failure."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Email = Annotated[str, StringConstraints(pattern=EMAIL_RE, max_length=254)]


# ---------------------------------------------------------------- per-kind config (public) + credentials (secret)
class EmailConfig(_Strict):
    kind: Literal["email"] = "email"
    host: Annotated[str, StringConstraints(pattern=HOST_RE)]
    port: int = Field(587, ge=1, le=65535)
    security: Literal["starttls", "ssl"] = "starttls"
    username: Annotated[str, StringConstraints(max_length=254)] = ""
    sender: Email
    recipients: list[Email] = Field(min_length=1, max_length=10)


class TelegramConfig(_Strict):
    kind: Literal["telegram"] = "telegram"
    chat_id: Annotated[str, StringConstraints(pattern=r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$")]


class NtfyConfig(_Strict):
    kind: Literal["ntfy"] = "ntfy"
    server: Annotated[str, StringConstraints(max_length=300)] = "https://ntfy.sh"
    topic: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    priority: int = Field(3, ge=1, le=5)


class DiscordConfig(_Strict):
    kind: Literal["discord"] = "discord"


class SlackConfig(_Strict):
    kind: Literal["slack"] = "slack"


class WebhookConfig(_Strict):
    kind: Literal["webhook"] = "webhook"
    webhook_id: int = Field(ge=1)


ChannelConfig = Annotated[Union[EmailConfig, TelegramConfig, NtfyConfig, DiscordConfig, SlackConfig, WebhookConfig],
                          Field(discriminator="kind")]

DISCORD_URL = re.compile(r"^https://(?:discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)/api/webhooks/[0-9]{5,25}/[A-Za-z0-9_-]{20,100}$")
SLACK_URL = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,120}$")
TG_TOKEN = re.compile(r"^[0-9]{5,15}:[A-Za-z0-9_-]{30,50}$")


def validate_credentials(kind: str, creds: dict[str, Any]) -> dict[str, str]:
    """Check secret fields per kind; returns only the known keys."""
    if kind == "email":
        pw = creds.get("password", "")
        if not isinstance(pw, str) or len(pw) > 512:
            raise ValueError("Invalid SMTP password")
        return {"password": pw} if pw else {}
    if kind == "telegram":
        token = creds.get("bot_token", "")
        if not isinstance(token, str) or not TG_TOKEN.match(token):
            raise ValueError("Bot token looks wrong (expected 123456:ABC… from @BotFather)")
        return {"bot_token": token}
    if kind == "ntfy":
        token = creds.get("token", "")
        if token and (not isinstance(token, str) or not re.match(r"^[A-Za-z0-9_.-]{8,200}$", token)):
            raise ValueError("Invalid ntfy access token")
        return {"token": token} if token else {}
    if kind == "discord":
        url = creds.get("webhook_url", "")
        if not isinstance(url, str) or not DISCORD_URL.match(url):
            raise ValueError("Expected a Discord webhook URL (https://discord.com/api/webhooks/…)")
        return {"webhook_url": url}
    if kind == "slack":
        url = creds.get("webhook_url", "")
        if not isinstance(url, str) or not SLACK_URL.match(url):
            raise ValueError("Expected a Slack incoming-webhook URL (https://hooks.slack.com/services/…)")
        return {"webhook_url": url}
    return {}


@dataclass
class Message:
    subject: str
    text: str                       # plain text body
    link: str | None = None         # optional "open" link (from our DB, never from AI output)
    kind: str = "alert"             # alert | digest | test

    def clean_subject(self) -> str:
        return _CRLF.sub(" ", self.subject).strip()[:200] or "Eye of Sauron"


# ---------------------------------------------------------------- senders
def _post(url: str, payload: dict | None = None, *, data: bytes | None = None, headers: dict[str, str] | None = None,
          allow_private: bool = False) -> None:
    cfg = get_settings()
    body = data if data is not None else json.dumps(payload).encode()
    try:
        resp = netguard.request("POST", url, content=body, timeout=15, max_bytes=64 * 1024, max_redirects=0,
                                allow_private=allow_private,
                                headers={"User-Agent": cfg.user_agent,
                                         **({"Content-Type": "application/json"} if data is None else {}), **(headers or {})})
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise DeliveryError(str(exc)[:200]) from None
    if resp.status_code >= 400:
        raise DeliveryError(f"HTTP {resp.status_code}")


def _send_email(cfg: EmailConfig, creds: dict, msg: Message) -> None:
    em = EmailMessage()
    em["Subject"] = msg.clean_subject()
    em["From"] = cfg.sender
    em["To"] = ", ".join(cfg.recipients)
    em["Date"] = formatdate(localtime=False)
    em["Message-ID"] = make_msgid(domain=cfg.sender.split("@", 1)[1])
    body = msg.text + (f"\n\n{msg.link}" if msg.link else "")
    em.set_content(body)
    escaped = html.escape(body).replace("\n", "<br>\n")
    em.add_alternative(f"<!doctype html><html><body style=\"font-family:sans-serif;font-size:14px\">{escaped}</body></html>",
                       subtype="html")
    context = ssl.create_default_context()  # verifies certificates and hostnames
    try:
        if cfg.security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=20)
            server.ehlo()
            server.starttls(context=context)  # refuse to continue without TLS
            server.ehlo()
        with server:
            if cfg.username:
                server.login(cfg.username, creds.get("password", ""))
            server.send_message(em)
    except smtplib.SMTPAuthenticationError:
        raise DeliveryError("SMTP login failed") from None
    except smtplib.SMTPNotSupportedError:
        raise DeliveryError("The SMTP server does not offer STARTTLS - use port 465 with SSL") from None
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise DeliveryError(f"SMTP error: {str(exc)[:150]}") from None


def _chunks(text: str, size: int) -> list[str]:
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > size:
            out.append(line[:size])
            line = line[size:]
        if len(cur) + len(line) + 1 > size:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n{line}" if cur else line
    if cur:
        out.append(cur)
    return out[:10]


def _send_telegram(cfg: TelegramConfig, creds: dict, msg: Message) -> None:
    text = f"{msg.clean_subject()}\n\n{msg.text}" + (f"\n\n{msg.link}" if msg.link else "")
    for part in _chunks(text, 4000):
        # Telegram's Bot API puts the token in the path; it is never logged by us.
        _post(f"https://api.telegram.org/bot{creds['bot_token']}/sendMessage",
              {"chat_id": cfg.chat_id, "text": part, "disable_web_page_preview": True})


def _send_ntfy(cfg: NtfyConfig, creds: dict, msg: Message) -> None:
    try:
        server = netguard.normalize_url(cfg.server).rstrip("/")
    except netguard.UnsafeURLError as exc:
        raise DeliveryError(f"Invalid ntfy server: {exc}") from None
    title = msg.clean_subject().encode("ascii", "replace").decode()  # header values must be ASCII
    headers = {"Title": title, "Priority": str(cfg.priority), "Content-Type": "text/plain; charset=utf-8"}
    if msg.link:
        headers["Click"] = msg.link
    if creds.get("token"):
        headers["Authorization"] = f"Bearer {creds['token']}"
    # Self-hosted ntfy servers are usually on the LAN; the server URL is admin-set.
    _post(f"{server}/{cfg.topic}", data=msg.text[:4000].encode("utf-8"), headers=headers, allow_private=True)


def _send_discord(creds: dict, msg: Message) -> None:
    text = f"**{msg.clean_subject()}**\n{msg.text}" + (f"\n{msg.link}" if msg.link else "")
    for part in _chunks(text, 1900):
        _post(creds["webhook_url"], {"content": part, "allowed_mentions": {"parse": []}})


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _send_slack(creds: dict, msg: Message) -> None:
    text = f"*{_slack_escape(msg.clean_subject())}*\n{_slack_escape(msg.text)}" + (f"\n{msg.link}" if msg.link else "")
    _post(creds["webhook_url"], {"text": text[:39000], "unfurl_links": False})


def _send_webhook(cfg: WebhookConfig, msg: Message) -> None:
    from app import webhooks

    ok, detail = webhooks.send(cfg.webhook_id, {"event": f"eye_of_sauron.{msg.kind}", "subject": msg.clean_subject(),
                                                "text": msg.text, "link": msg.link, "sent_at": now()})
    if not ok:
        raise DeliveryError(detail)


# ---------------------------------------------------------------- public API
def parse_config(raw: str | dict):
    class _W(_Strict):
        c: ChannelConfig

    return _W.model_validate({"c": json.loads(raw) if isinstance(raw, str) else raw}).c


def send(channel_id: int, msg: Message) -> None:
    """Send one message; records last_sent / last_error on the channel. Raises DeliveryError."""
    with get_db() as db:
        row = db.execute("SELECT * FROM delivery_channels WHERE id = ?", (channel_id,)).fetchone()
    if row is None or not row["enabled"]:
        raise DeliveryError("Channel not found or disabled")
    error = None
    try:
        cfg = parse_config(row["config"])
        creds = json.loads(secretbox.decrypt(row["credentials"])) if row["credentials"] else {}
        if isinstance(cfg, EmailConfig):
            _send_email(cfg, creds, msg)
        elif isinstance(cfg, TelegramConfig):
            _send_telegram(cfg, creds, msg)
        elif isinstance(cfg, NtfyConfig):
            _send_ntfy(cfg, creds, msg)
        elif isinstance(cfg, DiscordConfig):
            _send_discord(creds, msg)
        elif isinstance(cfg, SlackConfig):
            _send_slack(creds, msg)
        elif isinstance(cfg, WebhookConfig):
            _send_webhook(cfg, msg)
    except DeliveryError as exc:
        error = str(exc)
    except (ValueError, KeyError, secretbox.SecretError):
        error = "Channel settings are invalid - edit the channel"
    except Exception:
        log.exception("Delivery channel %d crashed", channel_id)
        error = "Unexpected delivery error (see server log)"
    with get_db() as db:
        db.execute("UPDATE delivery_channels SET last_sent = ?, last_error = ? WHERE id = ?",
                   (now() if error is None else row["last_sent"], error, channel_id))
    if error:
        log.warning("Delivery via channel %d failed: %s", channel_id, error)
        raise DeliveryError(error)


def send_many(channel_ids: list[int], msg: Message) -> list[str]:
    """Send to several channels; returns the error strings (empty list = all delivered)."""
    errors = []
    for cid in channel_ids:
        try:
            send(cid, msg)
        except DeliveryError as exc:
            errors.append(f"channel {cid}: {exc}")
    return errors
