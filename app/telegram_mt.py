"""Telegram account access over MTProto (Telethon), for channels without a public preview and
private chats/groups the user is a member of.

Security model
--------------
* The user creates their own API id/hash at https://my.telegram.org. The hash and the session
  string (which is equivalent to a logged-in device) are stored only secretbox-encrypted in
  ``integrations.secret`` and are never returned by the API or logged.
* The phone number and login code / 2FA password are used only in memory during login and are
  never stored. A pending login expires after 10 minutes.
* Disconnecting calls ``log_out()`` so Telegram revokes the session server-side, then deletes it.
* The client identifies itself honestly (device "Eye of Sauron"), does not receive live updates,
  and only reads message history of chats the user explicitly adds.

Telethon is asyncio-based; it runs on one private event-loop thread and the rest of the app
(synchronous) calls into it with ``_run``.
"""

from __future__ import annotations

import asyncio
import html
import logging
import threading
import time
from typing import Any

from app import __version__, integrations
from app.db import get_db
from app.sanitize import to_text
from app.sources import Fetched, SourceError, TelegramSource, _title_from, entry, get_state

log = logging.getLogger("eos.telegram")

LOGIN_TTL = 600
FETCH_LIMIT = 50
CALL_TIMEOUT = 60


class LoginError(Exception):
    """User-facing login failure."""


class _Loop:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def run(self, coro, timeout: float = CALL_TIMEOUT):
        with self._lock:
            if self._loop is None or not self._loop.is_running():
                self._loop = asyncio.new_event_loop()
                threading.Thread(target=self._loop.run_forever, name="telegram", daemon=True).start()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout)
        except TimeoutError:
            future.cancel()
            raise SourceError("Telegram did not answer in time") from None


class TelegramAccount:
    def __init__(self) -> None:
        self._loop = _Loop()
        self._client = None
        self._client_key: str | None = None
        self._pending: dict[str, Any] | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _creds() -> tuple[int | None, str | None, str | None]:
        with get_db() as db:
            config, secrets = integrations.load(db, "telegram")
        api_id = config.get("api_id")
        return (api_id if isinstance(api_id, int) else None), secrets.get("api_hash"), secrets.get("session")

    @staticmethod
    def _new_client(session: str | None, api_id: int, api_hash: str):
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        return TelegramClient(StringSession(session or ""), api_id, api_hash, device_model="Eye of Sauron",
                              system_version="server", app_version=__version__, receive_updates=False,
                              flood_sleep_threshold=0, request_retries=2, connection_retries=2)

    async def _connected(self):
        api_id, api_hash, session = self._creds()
        if not (api_id and api_hash and session):
            raise SourceError("Telegram account is not connected (Settings → Integrations → Telegram)")
        key = f"{api_id}:{hash(session)}"
        if self._client is None or self._client_key != key:
            if self._client is not None:
                await self._client.disconnect()
            self._client = self._new_client(session, api_id, api_hash)
            self._client_key = key
        if not self._client.is_connected():
            await self._client.connect()
        if not await self._client.is_user_authorized():
            raise SourceError("The Telegram session is no longer valid - reconnect your account")
        return self._client

    # ------------------------------------------------------------------ login flow
    def start_login(self, api_id: int, api_hash: str, phone: str) -> None:
        async def go():
            from telethon import errors

            client = self._new_client(None, api_id, api_hash)
            await client.connect()
            try:
                sent = await client.send_code_request(phone)
            except errors.ApiIdInvalidError:
                await client.disconnect()
                raise LoginError("Telegram rejected the API id / hash") from None
            except errors.PhoneNumberInvalidError:
                await client.disconnect()
                raise LoginError("Telegram says the phone number is invalid") from None
            except errors.FloodWaitError as exc:
                await client.disconnect()
                raise LoginError(f"Too many attempts - Telegram asks to wait {exc.seconds} s") from None
            return client, sent.phone_code_hash

        with self._lock:
            self._drop_pending()
            client, code_hash = self._loop.run(go())
            self._pending = {"client": client, "phone": phone, "hash": code_hash, "api_id": api_id,
                             "api_hash": api_hash, "expires": time.monotonic() + LOGIN_TTL}

    def _drop_pending(self) -> None:
        if self._pending:
            client = self._pending["client"]
            self._pending = None
            try:
                self._loop.run(client.disconnect(), timeout=10)
            except Exception:  # noqa: BLE001 - best effort cleanup
                pass

    def _take_pending(self) -> dict:
        if not self._pending or self._pending["expires"] < time.monotonic():
            self._drop_pending()
            raise LoginError("No login in progress (or it expired) - start again")
        return self._pending

    def submit_code(self, code: str) -> dict:
        """Returns {"needs_password": True} for 2FA accounts, else the connected account info."""
        async def go(p):
            from telethon import errors

            try:
                await p["client"].sign_in(phone=p["phone"], code=code, phone_code_hash=p["hash"])
            except errors.SessionPasswordNeededError:
                return None
            except (errors.PhoneCodeInvalidError, errors.PhoneCodeEmptyError):
                raise LoginError("That code is not correct") from None
            except errors.PhoneCodeExpiredError:
                raise LoginError("The code expired - start again") from None
            return await self._finish(p)

        with self._lock:
            p = self._take_pending()
            result = self._loop.run(go(p))
            if result is None:
                return {"needs_password": True}
            self._pending = None
            return result

    def submit_password(self, password: str) -> dict:
        async def go(p):
            from telethon import errors

            try:
                await p["client"].sign_in(password=password)
            except errors.PasswordHashInvalidError:
                raise LoginError("Wrong two-step verification password") from None
            return await self._finish(p)

        with self._lock:
            p = self._take_pending()
            result = self._loop.run(go(p))
            self._pending = None
            return result

    async def _finish(self, p: dict) -> dict:
        client = p["client"]
        me = await client.get_me()
        session = client.session.save()
        account = {"name": to_text(" ".join(x for x in (me.first_name, me.last_name) if x), 120) or "Telegram user",
                   "username": me.username or None}
        with get_db() as db:
            integrations.save(db, "telegram", config={"api_id": p["api_id"], "account": account},
                              secrets={"api_hash": p["api_hash"], "session": session})
        await client.disconnect()
        return {"connected": True, "account": account}

    def logout(self) -> None:
        async def go():
            try:
                client = await self._connected()
                await client.log_out()  # revokes the session on Telegram's side
            except SourceError:
                pass
            finally:
                self._client = None
                self._client_key = None

        with self._lock:
            self._drop_pending()
            try:
                self._loop.run(go(), timeout=20)
            except Exception:  # noqa: BLE001 - still delete the local session
                log.warning("Telegram log-out call failed; deleting the local session anyway")
            with get_db() as db:
                integrations.save(db, "telegram", secrets={}, remove_secrets=("session",), remove_config=("account",))

    # ------------------------------------------------------------------ data
    def dialogs(self) -> list[dict]:
        async def go():
            client = await self._connected()
            out = []
            async for d in client.iter_dialogs(limit=500):
                if not (d.is_channel or d.is_group):
                    continue
                username = getattr(d.entity, "username", None)
                out.append({"chat_id": int(d.id), "title": to_text(d.name, 200) or str(d.id), "username": username,
                            "type": "channel" if getattr(d.entity, "broadcast", False) else "group"})
            return out

        return self._loop.run(go(), timeout=120)

    def fetch(self, cfg: TelegramSource, feed_id: int, *, offset_id: int = 0, limit: int = FETCH_LIMIT,
              history: bool = False) -> Fetched:
        async def go():
            from telethon import errors
            from telethon.extensions import html as tl_html

            client = await self._connected()
            target: Any = cfg.channel or cfg.chat_id
            try:
                try:
                    peer = await client.get_entity(target)
                except ValueError:
                    await client.get_dialogs(limit=500)  # fill the entity cache for numeric ids
                    peer = await client.get_entity(target)
                last = None if history else get_state(f"tg_last:{feed_id}")
                kwargs: dict[str, Any] = {"limit": limit}
                if offset_id:
                    kwargs["offset_id"] = offset_id
                elif last and last.isdigit():
                    kwargs["min_id"] = int(last)
                messages = await client.get_messages(peer, **kwargs)
            except errors.FloodWaitError as exc:
                raise SourceError(f"Telegram rate limit - waiting {exc.seconds} s", retry_after=int(exc.seconds) + 5) from None
            except (errors.ChannelPrivateError, errors.ChatAdminRequiredError):
                raise SourceError("No access to this chat (left it or it is private)") from None
            except ValueError:
                raise SourceError("Telegram could not find that chat") from None
            username = getattr(peer, "username", None)
            title = to_text(getattr(peer, "title", None) or username or "", 300) or None
            short_id = str(abs(int(cfg.chat_id or 0)))[3:] if cfg.chat_id and str(abs(cfg.chat_id)).startswith("100") else str(abs(cfg.chat_id or 0))
            out = Fetched(entries=[], title=title, site_url=f"https://t.me/{username}" if username else None)
            newest = 0
            for msg in messages:
                text = msg.message or ""
                parts = []
                if text:
                    parts.append(f"<p>{tl_html.unparse(text, msg.entities or []).replace(chr(10), '<br>')}</p>")
                webpage = getattr(getattr(msg, "media", None), "webpage", None)
                wp_url = getattr(webpage, "url", None)
                if isinstance(wp_url, str) and wp_url.startswith(("https://", "http://")):
                    wp_title = getattr(webpage, "title", None) or wp_url
                    parts.append(f'<blockquote><a href="{html.escape(wp_url, quote=True)}">{html.escape(str(wp_title)[:300])}</a></blockquote>')
                if msg.photo:
                    parts.append("<p><em>[photo]</em></p>")
                elif msg.document:
                    parts.append("<p><em>[media/file]</em></p>")
                if not parts:
                    continue
                newest = max(newest, msg.id)
                link = f"https://t.me/{username}/{msg.id}" if username else f"https://t.me/c/{short_id}/{msg.id}"
                ts = int(msg.date.timestamp()) if msg.date else None
                out.entries.append(entry(guid=f"tg:{(username or short_id).lower()}:{msg.id}",
                                         title=_title_from(text, f"{title or 'Telegram'} - message {msg.id}"),
                                         link=link, html_body="".join(parts), ts=ts, author=title))
            if newest and not history:
                out.state[f"tg_last:{feed_id}"] = str(newest)
            out.cursor = min((m.id for m in messages), default=0) or None
            return out

        return self._loop.run(go())


account = TelegramAccount()
