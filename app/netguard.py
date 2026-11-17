"""SSRF-hardened outbound HTTP client.

Every outbound request (feed fetches, webhooks) goes through ``request()``:

* only http/https, no credentials in URLs, bounded URL length;
* the host is resolved once, *every* resolved address is checked against an
  allow policy (public addresses only unless private targets are explicitly
  enabled), and the connection is pinned to the checked IP - this defeats DNS
  rebinding (TOCTOU between check and connect);
* TLS certificates are still verified against the original hostname (SNI);
* redirects are followed manually and each hop is re-validated;
* response size and total time are capped (decompression bombs, slowloris);
* proxy environment variables are ignored (trust_env=False).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import zlib
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
# Only encodings we can decompress with a hard output bound (see _BoundedDecoder).
ACCEPT_ENCODING = "gzip, deflate"
_NAT64 = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052 well-known prefix

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeURLError(ValueError):
    """The URL is malformed or points somewhere it must not."""


class FetchError(Exception):
    """The request failed (network, protocol, limits)."""


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str


def normalize_url(url: str) -> str:
    """Validate and canonicalise an absolute http(s) URL. Raises UnsafeURLError."""
    if not isinstance(url, str):
        raise UnsafeURLError("URL must be a string")
    url = url.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeURLError("URL is empty or too long")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        raise UnsafeURLError("URL contains whitespace or control characters")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise UnsafeURLError("Credentials in URLs are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("Invalid port") from exc
    if port == 0:
        raise UnsafeURLError("Invalid port")

    if _ip_literal(host) is not None:
        ascii_host = host
        netloc_host = f"[{host}]" if ":" in host else host
    else:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UnsafeURLError("Invalid hostname") from exc
        if not ascii_host or len(ascii_host) > 253:
            raise UnsafeURLError("Invalid hostname")
        netloc_host = ascii_host

    netloc = f"{netloc_host}:{port}" if port else netloc_host
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def _ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses carried inside IPv6 transition formats (mapped, 6to4, Teredo, NAT64).

    A NAT64/6to4/Teredo gateway would forward such a packet to the embedded IPv4
    address, so it must pass the same policy (e.g. 64:ff9b::7f00:1 -> 127.0.0.1).
    """
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)
    if ip in _NAT64:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def ip_allowed(ip: IPAddress, allow_private: bool) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded:
            # The packet ends up at the embedded IPv4 address(es): judge those instead.
            # (Also keeps DNS64/NAT64 networks working for public IPv4-only sites.)
            return all(ip_allowed(v4, allow_private) for v4 in embedded)
    # Never allowed, even in "private" mode.
    if ip.is_unspecified or ip.is_multicast:
        return False
    # Python flags the IPv6 loopback ::1 as reserved (it sits in ::/8), but it is simply the
    # local host - like 127.0.0.1, which private mode already allows. Without this, "localhost"
    # (which resolves to both) was refused even when private targets were explicitly allowed.
    if allow_private and ip.is_loopback:
        return True
    if ip.is_reserved:
        return False
    if allow_private:
        return True
    return ip.is_global


def private_ok(host: str, port: int, allow_private: bool) -> bool:
    """True when local/private targets are allowed for this host:port: globally, or by the exact allow-list
    (FEEDWARDEN_PRIVATE_ALLOWLIST, e.g. a self-hosted bridge on 127.0.0.1:1200). Reserved, unspecified and
    multicast addresses stay blocked either way (see ip_allowed)."""
    if allow_private:
        return True
    from app.config import get_settings  # late import: config does not depend on netguard

    return f"{host.strip('[]').lower()}:{port}" in get_settings().private_allowlist


def resolve_host(host: str, port: int, allow_private: bool) -> list[IPAddress]:
    literal = _ip_literal(host)
    if literal is not None:
        candidates = [literal]
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError) as exc:
            raise FetchError("DNS resolution failed") from exc
        seen: list[IPAddress] = []
        for info in infos:
            raw = str(info[4][0]).split("%", 1)[0]  # drop IPv6 scope id
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr not in seen:
                seen.append(addr)
        candidates = seen
    if not candidates:
        raise FetchError("DNS resolution returned no addresses")
    # Reject if ANY address is disallowed - avoids mixed public/private tricks.
    for addr in candidates:
        if not ip_allowed(addr, allow_private):
            raise UnsafeURLError(
                "Destination resolves to a private, local or reserved address, which is blocked"
            )
    return candidates


class _BoundedDecoder:
    """Incremental Content-Encoding decoder whose output can never exceed ``limit``.

    httpx decodes a whole network chunk at once, so a 64 KB gzip chunk can inflate to
    tens of MB before any size check runs (decompression bomb -> OOM). Here zlib's
    ``max_length`` bounds every step, so memory stays at most ``limit`` + one chunk.
    """

    def __init__(self, encoding: str, limit: int) -> None:
        enc = encoding.strip().lower()
        if enc in ("", "identity"):
            self._mode = "identity"
        elif enc in ("gzip", "x-gzip"):
            self._mode = "zlib"
            self._wbits = 16 + zlib.MAX_WBITS
        elif enc == "deflate":
            self._mode = "deflate"
            self._wbits = zlib.MAX_WBITS
        else:
            raise FetchError("Unsupported Content-Encoding")
        self._limit = limit
        self._size = 0
        self._obj = zlib.decompressobj(self._wbits) if self._mode != "identity" else None
        self._first = True

    def _emit(self, out: bytearray, data: bytes) -> None:
        self._size += len(data)
        if self._size > self._limit:
            raise FetchError("Response exceeds size limit")
        out.extend(data)

    def feed(self, chunk: bytes) -> bytes:
        out = bytearray()
        if self._obj is None:
            self._emit(out, chunk)
            return bytes(out)
        data = chunk
        while data:
            try:
                piece = self._obj.decompress(data, self._limit - self._size + 1)
            except zlib.error:
                if self._mode == "deflate" and self._first:
                    # Some servers send raw deflate without the zlib header.
                    self._wbits = -zlib.MAX_WBITS
                    self._obj = zlib.decompressobj(self._wbits)
                    self._first = False
                    continue
                raise FetchError("Invalid compressed response") from None
            self._first = False
            self._emit(out, piece)
            if self._obj.unconsumed_tail:
                data = self._obj.unconsumed_tail
            elif self._obj.eof and self._obj.unused_data:
                data = self._obj.unused_data  # concatenated gzip members
                self._obj = zlib.decompressobj(self._wbits)
            else:
                data = b""
        return bytes(out)

    def finish(self) -> bytes:
        out = bytearray()
        if self._obj is not None:
            self._emit(out, self._obj.flush(self._limit - self._size + 1))
        return bytes(out)


# Sites that rate-limit anonymous readers hard: requests to them are spaced app-wide (seconds between requests).
# Without this, the parallel fetch workers asked Reddit for many subreddits at once and every one got HTTP 429.
PACED_HOSTS = {"reddit.com": 15.0}
COOLDOWN_429 = 300.0   # after a 429 from a paced host, every request to it waits at least this long
_pace_lock = threading.Lock()
_next_slot: dict[str, float] = {}


def _paced_key(host: str) -> str | None:
    host = (host or "").lower()
    return next((k for k in PACED_HOSTS if host == k or host.endswith("." + k)), None)


def _cool_down(host: str, retry_after: str | None) -> None:
    """A paced host said 429: hold back all requests to it (its Retry-After, at least COOLDOWN_429 seconds) instead of
    every feed trying again on its own."""
    key = _paced_key(host)
    if key is None:
        return
    try:
        wait = max(float(str(retry_after or "0").strip()), COOLDOWN_429)
    except ValueError:
        wait = COOLDOWN_429
    with _pace_lock:
        _next_slot[key] = max(_next_slot.get(key, 0.0), time.monotonic() + min(wait, 3600.0))


def cooling(host: str) -> bool:
    """Is this paced host in a 429 cool-down right now (callers can skip optional requests)?"""
    key = _paced_key(host)
    return bool(key) and _next_slot.get(key, 0.0) - time.monotonic() > PACED_HOSTS[key] * 2


def _pace(host: str) -> None:
    host = (host or "").lower()
    key = next((k for k in PACED_HOSTS if host == k or host.endswith("." + k)), None)
    if key is None:
        return
    with _pace_lock:  # reserve the next free slot, then wait for it outside the lock
        slot = max(time.monotonic(), _next_slot.get(key, 0.0))
        _next_slot[key] = slot + PACED_HOSTS[key]
    delay = slot - time.monotonic()
    if delay > 0:
        time.sleep(delay)


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    allow_private: bool = False,
    timeout: float = 20.0,
    max_bytes: int = 10 * 1024 * 1024,
    max_redirects: int = 5,
) -> SafeResponse:
    if method not in {"GET", "POST"}:
        raise ValueError("Unsupported method")
    current = normalize_url(url)
    _pace(urlsplit(current).hostname or "")
    deadline = time.monotonic() + timeout * 2

    for _hop in range(max_redirects + 1):
        parts = urlsplit(current)
        scheme = parts.scheme
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)

        addresses = resolve_host(host, port, private_ok(host, port, allow_private))
        pinned = addresses[0]
        pinned_netloc = f"[{pinned}]:{port}" if pinned.version == 6 else f"{pinned}:{port}"
        target = urlunsplit((scheme, pinned_netloc, parts.path or "/", parts.query, ""))

        req_headers = dict(headers or {})
        req_headers["Host"] = parts.netloc
        req_headers["Accept-Encoding"] = ACCEPT_ENCODING
        extensions: dict[str, object] = {}
        if scheme == "https" and _ip_literal(host) is None:
            # Certificate is verified against the real hostname, not the pinned IP.
            extensions["sni_hostname"] = host

        try:
            with httpx.Client(
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
                trust_env=False,
                verify=True,
                # No connection reuse: pooled connections are keyed by IP and must
                # never be shared between different virtual hosts / SNI names.
                limits=httpx.Limits(max_keepalive_connections=0),
            ) as client:
                with client.stream(
                    method, target, headers=req_headers, content=content, extensions=extensions
                ) as resp:
                    if resp.status_code in REDIRECT_CODES and max_redirects > 0:
                        location = resp.headers.get("location")
                        if not location:
                            raise FetchError("Redirect without Location header")
                        current = normalize_url(urljoin(current, location))
                        if resp.status_code in (301, 302, 303) and method == "POST":
                            method, content = "GET", None
                        continue

                    encoding = resp.headers.get("content-encoding", "")
                    if "," in encoding:
                        raise FetchError("Unsupported Content-Encoding")
                    decoder = _BoundedDecoder(encoding, max_bytes)
                    body = bytearray()
                    raw_seen = 0
                    for chunk in resp.iter_raw():
                        raw_seen += len(chunk)
                        if raw_seen > max_bytes:
                            raise FetchError("Response exceeds size limit")
                        body.extend(decoder.feed(chunk))
                        if time.monotonic() > deadline:
                            raise FetchError("Response took too long")
                    body.extend(decoder.finish())
                    if resp.status_code == 429:
                        _cool_down(host, resp.headers.get("retry-after"))
                    return SafeResponse(resp.status_code, resp.headers, bytes(body), current)
        except httpx.HTTPError as exc:
            raise FetchError(f"HTTP error: {type(exc).__name__}") from exc

    raise FetchError("Too many redirects")
