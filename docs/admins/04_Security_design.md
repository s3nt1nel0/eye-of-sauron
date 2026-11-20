# Eye of Sauron security design

Eye of Sauron ingests **untrusted content from the internet** (feeds) and exposes an
authenticated web UI + API. This document records the threat model and the controls
in place, mapped to NIST SSDF (SP 800-218) practices and OWASP guidance.

## Threat model (summary)

| Asset / entry point | Threat | Control |
|---|---|---|
| Feed content (HTML, XML) | Stored XSS, XXE, entity bombs, parser abuse | Allow-list sanitiser, entity rejection, defusedxml, CSP |
| Feed / webhook URLs | SSRF to cloud metadata, LAN, localhost; DNS rebinding | `netguard` (resolve → validate all IPs → pin IP → SNI verify) |
| Login | Brute force, credential stuffing, user enumeration | argon2id, throttling per IP + user, generic errors, dummy hash |
| Session cookie | Theft, CSRF, fixation | HttpOnly, SameSite=Strict, `__Host-` + Secure on HTTPS, CSRF token, rotation on login |
| API tokens | Leakage, over-privilege | Stored as SHA-256 only, shown once, scoped (read/write), expiry, cannot manage tokens/webhooks/settings |
| Request bodies | DoS | Body-size limit middleware, Pydantic length limits, row caps |
| Search / rules | SQLi via FTS syntax, ReDoS | FTS tokens quoted as literals; rule keywords `re.escape`d |
| Container | Escape / lateral movement | Non-root uid 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, resource limits |
| Compressed responses | Decompression bombs (memory exhaustion) | Bounded incremental gzip/deflate decoder; other encodings refused |
| Stored third-party credentials (social, webhook secrets) | DB/backup theft, disclosure via API | Fernet encryption at rest, key outside the volume (Docker secret), write-only API, redaction in errors |

## Controls in detail

### Input handling (SSDF PW.5, OWASP ASVS V5)
* Every request model is a Pydantic model with `extra="forbid"` (no mass assignment) and
  explicit length/range limits. Sort direction and enum-like fields use `Literal` types.
* **All SQL uses bound parameters.** The only f-strings in SQL interpolate (a) a count of
  `?` placeholders, (b) fixed column/table names from code constants, or (c) a direction
  derived from a `Literal`. Bandit reports these as B608; they have been reviewed.
* Full-text search input is tokenised and every token is quoted, so FTS5 operators
  (`OR`, `NEAR`, `*`, `"`) supplied by users are inert.
* Rule keywords are literal strings (`re.escape`) with word boundaries — no user regex,
  no catastrophic backtracking.

### Feed tools and rules
* **Troubleshooter** (`/feeds/{id}/diagnose`, `/feeds/diagnose`; write scope, rate-limited 20/min and 4/min):
  * At most 14 outbound requests per feed, all through netguard (SSRF policy, IP pinning, size and time caps) with the normal honest User-Agent.
  * Candidate URLs come only from the feed's own address, its site's pages and fixed common paths. Pages are parsed with the same bounded parsers as discovery.
  * It never spoofs a browser or bypasses bot protection: a 401/403/429/503 behind a bot wall is reported, not worked around.
  * One background run at a time, with a 0.5 s pause between feeds. Results are kept in memory only.
* **Bulk feed actions** (`/feeds/bulk`): ids are integers (1–5,000 per call) bound as parameters; the action is a `Literal`; bulk deletes are audited (`feeds_bulk_deleted`).
* **Rules:** `require_keywords` use the same literal, whole-word matcher as `keywords` (no user regex, no ReDoS). `cve_severity` is a `Literal` and `cve_owasp` a strict pattern. CVE IDs are taken from article text with a fixed, bounded pattern (at most 50 per article) and looked up with bound parameters.
* **Collection packs:** pack slugs are checked against a fixed list; installs are audited (`collection_packs_installed`); the back-fill runs in short transactions and never fires webhooks, alerts or AI calls.

### Full article text
* Article pages are fetched through netguard (SSRF policy, 5 MB cap, timeouts) with the honest User-Agent; at most one request per site every 3 s; sites answering 401/403/429 or a bot-check page are left alone for 6 h. Nothing is spoofed or bypassed.
* Extracted HTML goes through the same allow-list sanitiser as feed content; JSON-LD text is escaped before wrapping; relative links and lazy images are resolved to absolute URLs and re-checked by the reader.

### Video groups
* Group references are a strict pattern (`p:<n>` / `g:<n>`); only your own groups can be changed (playlists come from feeds); names are length-capped and unique; added ids must be existing videos; all queries use bound parameters; create/delete are audited.

### MITRE ATT&CK and social accounts
* **ATT&CK sync:**
  * Only `raw.githubusercontent.com/mitre-attack/attack-stix-data/master/` is contacted, through netguard. Bundle URLs from the index must stay inside that path (else the sync aborts).
  * Size caps: 5 MB for the index, 200 MB per bundle. JSON is parsed with the standard library and text is cleaned and length-capped before storage.
  * Manual sync is admin-only and rate-limited. The schedule is a validated setting; one sync runs at a time.
  * Entities are written with bound parameters and the same alias cleaning as user input.
* **Accounts:**
  * Profile links are mapped to fixed URL templates (Bluesky, Mastodon, Reddit) or to the existing X/Telegram sources, with values restricted by strict patterns.
  * Any other feed URL goes through the normal SSRF-guarded fetch and must parse as a feed.
  * LinkedIn, Instagram, Facebook, Threads and TikTok profile links are refused with advice: the app never scrapes them or works around their blocks.

### Analytics, watchlists and dashboards
* **All/any matching:** `match` is a `Literal`. The OR form only regroups fixed SQL fragments with `?` placeholders (`analytics.combine`); values stay bound. Exclusions and the drill-down `focus` are always ANDed, so a reader can't widen a drill-down past the item clicked.
* **Combined widgets** reuse the article and CVE query builders unchanged. Widget `width` (10–100) and `height` (120–1,400) are range-checked, and `chart` must be valid for the widget type.
* Entity matching is **token-based** (hash lookups of word n-grams), not regex: linear in text
  length, independent of alias count, and user-defined aliases can never produce a pathological
  pattern (no ReDoS). Text scanned per article is capped.
* Analytics queries are Pydantic models (`extra="forbid"`, bounded id lists, bounded periods);
  group-by and bucket SQL fragments are selected from fixed dictionaries by validated `Literal`
  values; all values are bound parameters. FTS input reuses the quoted-literal builder.
* Dashboards are stored as JSON but re-validated through the same widget model on every write
  (widget ids restricted to `[A-Za-z0-9_-]`); templates go through the same validation.
* Re-indexing runs in one background worker with short transactions so it cannot starve the
  fetcher or UI; requests are coalesced.
* Charts are SVG built with `createElementNS` + text nodes, colours only from CSS variables or
  validated `#rrggbb` values — no HTML injection path. Sidebar drag-and-drop only accepts a private
  MIME type and verifies the dragged feed id against the known feed list (text/links dragged in
  from other pages are ignored).

### CVE ingestion & older-article import
* **Inputs:** NVD API JSON, CISA KEV JSON, MITRE CWE zip/XML, older feed pages and Internet Archive data (CDX listings and saved feed copies) are all **untrusted**.
  * Every request goes through netguard: SSRF policy, IP pinning, size and time caps, bounded decompression.
* **Parsing:**
  * CVE/CWE IDs are pattern-checked, text fields are length-capped, and reference URLs are normalised. `javascript:` and similar links are dropped.
* **CWE archive:**
  * Exactly one XML member is accepted.
  * Uncompressed size is capped (120 MB) and compression ratio is limited (zip-bomb guard).
  * Parsed with `defusedxml`, with DTDs, entities and external references forbidden.
* **Queries:**
  * CVE analytics use only fixed SQL fragments selected by `Literal` values, plus bound parameters.
  * Filters are bounded lists with strict patterns (slugs, vendor keys, OWASP codes, severities).
  * Free text goes through the FTS quoted-literal builder.
  * Category keywords are literal (`re.escape`). Product patterns follow a restricted grammar (no regex), and match-all patterns are rejected.
* **Secrets:**
  * The optional NVD API key is sent in a request header, never in the URL or logs.
* **Internet Archive back-fill:**
  * Only the fixed hosts `web.archive.org` (CDX API and raw `id_` captures) are contacted, through netguard like any feed. They are public, so private mode isn't involved.
  * The capture URL is built from **our own stored feed URL** plus a timestamp validated as 14 digits. Nothing from the archive's answer (URLs, redirects to other captures) decides what is fetched next, beyond netguard's re-validated redirects.
  * Captured documents go through the XML guard, parser and sanitiser exactly like a live fetch. The declared `text/html` content type of captures is ignored so the parser reads the XML's own declaration.
  * The client is polite (1.5 s between requests, a single job at a time) and stops on HTTP 429.
* **Permissions:**
  * History back-fill for one feed and per-feed retention need `write`.
  * The all-feeds back-fill (`POST /history/backfill-all`) is **admin-only** (interactive session + CSRF) and rate-limited to 2 per minute, because it makes many outbound requests and can change many feeds' retention.
  * The FreshRSS import was removed (it was a one-off migration tool), so the app no longer accepts third-party reader credentials at all.
* **Imported articles:**
  * Sanitised exactly like fetched ones.
  * Rules and entity tagging are applied, but they never fire webhooks or social drafts.

### Website scraping
* **Fetching and parsing:**
  * Pages are fetched through netguard (SSRF policy, IP pinning, 5 MB cap, timeouts).
  * They are parsed with BeautifulSoup on Python's built-in `html.parser`: no XML, no entities, no network access, no JavaScript execution.
* **Rules:**
  * Validated when saved: CSS selectors are pre-compiled by soupsieve; JSON paths follow a strict grammar; strftime formats are allow-listed; lengths are capped.
  * The number of items is capped at 200.
* **Output:**
  * Titles and authors become plain text, and content goes through the same nh3 sanitiser as feeds.
  * Links and images must be http(s); relative URLs are resolved and normalised, and `javascript:` is dropped.
* **Permissions:** discovery and preview need `write` and are rate-limited.

### Google Reader API (native apps)
* **Login:** only per-device **app passwords** (argon2id hashes, max 10) are accepted at `/accounts/ClientLogin`. The admin password is not.
  * Credentials are read from the POST body only; a query-string password is refused with 400, so it never reaches access logs.
  * Shared per-IP and per-account throttles, uniform timing for unknown users, audit events.
* **Tokens:** a successful login issues an API token with the **reader** scope only.
  * It is accepted by the reader endpoints and **rejected (403) by the entire REST API**, so a phone app can't reach settings, tokens, webhooks, social accounts, imports or admin functions.
  * At most 5 active tokens per app password; revoking the app password deletes all of them.
* **Requests:** auth is header-only (`Authorization: GoogleLogin auth=…`) and cookies are ignored, so CSRF doesn't apply.
  * Stream and item ids follow a strict grammar and all SQL values are bound.
  * Counts are bounded, endpoints are rate-limited per token, and article HTML is re-sanitised on output.
  * New subscriptions go through URL normalisation and the SSRF-guarded fetcher.
* **Fever API:** not implemented. Its MD5(username:password) API key can't be stored or verified safely.

### Third-party sources & integrations (YouTube, X, Telegram, HF papers)
* **Integration secrets:** the YouTube key, X bearer token, Telegram api_hash and Telegram session string live in `integrations.secret`, one secretbox-encrypted JSON object.
  * It is covered by key rotation (`rotate-secrets`) and never returned: `GET /integrations` shows only which secrets are set.
  * Every integration endpoint, including the Telegram login and dialog list, requires the **admin session**; write tokens get 403. Changes are audited.
* **Credentials never in URLs:** the YouTube key is sent as `X-Goog-Api-Key` and the X token as `Authorization: Bearer`, so neither reaches proxy or server logs.
* **Single videos** (`POST /library/videos`, write scope, rate-limited): the video id is parsed with a strict pattern from a YouTube host only, and the request goes to the fixed Data API or `https://www.youtube.com/oembed` through netguard. The response is length-capped JSON, and its title, channel and thumbnail are sanitised like any feed item.
* **Telegram account (MTProto via Telethon):**
  * Phone number, login code and 2FA password are held only in memory during login; a pending login expires after 10 minutes.
  * The client runs on one private event-loop thread, identifies itself honestly, receives no live updates, and reads history only for chats the user adds.
  * Disconnecting calls `log_out()`, so Telegram revokes the session server-side, then deletes it locally.
* **SSRF:** all source fetches use `netguard` (IP pinning, size caps, timeouts). The single exception is the **X bridge** base URL.
  * It is admin-set, normally a LAN-hosted RSSHub/Nitter/RSS-Bridge, and validated by `normalize_url` (http/https only, no credentials or control characters).
  * Telegram MTProto connects only to Telegram's data centres.
  * `/sources/resolve` checks the host before fetching (for example, `kind=youtube` only fetches youtube.com) and needs write scope.
* **Stored HTML:**
  * Remote text (titles, descriptions, posts, paper abstracts) is HTML-escaped when the article body is built. Only http(s) links are generated.
  * The nh3 sanitiser runs again on insert. Telegram's web HTML (inline `onclick`, scripts) is sanitised the same way.
* **Integrity:**
  * Source configs are a strict discriminated union (channel `UC` + 22 characters, X `[A-Za-z0-9_]{1,15}`, Telegram username pattern, bounded chat id).
  * A source feed's URL is derived from its config and cannot be repointed with `PATCH url`.
  * Library filters and sorts are fixed SQL fragments selected by enum.
  * Topic keywords are `re.escape`d, and topic colours must be `#rrggbb`.
* **Cost and abuse:**
  * X API feeds default to a 6-hour refresh and use `since_id`; 429 responses honour `x-rate-limit-reset`.
  * YouTube quota errors back off for 6 hours, and Telegram flood-waits are honoured.

### AI, delivery channels, digests and alerts
* **Prompt injection (OWASP LLM01):**
  * Article and CVE text is wrapped in `<article>` / `<items>` / `<cve>` delimiters, and the system prompt declares it untrusted data.
  * No tools or function calling are offered to the model.
  * Output is treated as untrusted (OWASP LLM02, insecure output handling): control and bidi characters and Markdown headings are stripped, length is capped at 8,000 characters, and it is stored as plain text and rendered only with `textContent`.
  * Digests and alerts append links from the database; model text is never turned into links or HTML.
* **Claude:**
  * Calls go through the official `anthropic` SDK (fixed host, key in a header).
  * Supported models use the server-side refusal fallback (`fallbacks: "default"`). A final `refusal` stop reason surfaces as an error and is not retried.
* **Other providers:**
  * OpenAI and Gemini go through netguard, with keys in headers (`Authorization`, `x-goog-api-key`) and no redirects.
  * The OpenAI-compatible base URL is admin-set and may be private (local models).
* **Cost (OWASP LLM10, unbounded consumption):**
  * A per-day request cap is reserved atomically before each call (`ai_usage`), and input is capped per article.
  * The summary endpoint is rate-limited, and the auto-summary queue is bounded and stops when the cap is hit.
* **Delivery:**
  * Credentials (SMTP password, Telegram bot token, Discord/Slack webhook URLs, ntfy token) are secretbox-encrypted in `delivery_channels.credentials` and never returned.
  * Discord and Slack URLs must match the official webhook hosts.
  * Telegram tokens, chat IDs, emails and SMTP hosts are pattern-validated, and POSTs never follow redirects.
* **Injection through article text:**
  * Discord uses `allowed_mentions.parse = []`, Slack text is entity-escaped, and Telegram uses no `parse_mode`.
  * Email is built with `EmailMessage` (header-injection safe); subjects are stripped of CR/LF and HTML bodies are escaped.
  * SMTP requires TLS with certificate verification; a server without STARTTLS fails closed.
* **Alerts:**
  * Exactly-once delivery: `alerts_sent` has a unique key per rule and item, claimed before sending.
  * Only CVEs newer than the rule (plus a 1-day grace) can fire, preventing floods from back-fills, and history imports never trigger alerts.
* **Authorization:**
  * The admin session is required for AI settings, delivery channels, digests, CVE alert rules, and creating or editing keyword rules that route to an alert channel.
  * Summaries need write scope; logs and usage need read.

### Abuse protection & audit (OWASP API4:2023, Logging Cheat Sheet)
* **Rate limits:**
  * Per-principal token buckets (one per session or API token) on expensive endpoints: analytics, articles listing, feed refreshes, OPML imports, history back-fills, rule back-fills, webhook/channel tests, compose/publish, CVE sync, scraping.
  * Responses are `429` with `Retry-After`.
  * Login has its own per-IP and per-account throttles.
* **Audit log:** the `eos.audit` logger records security-relevant actions with the actor (`user:N` / `token:N`): logins and failures, logout, password change, API token create/revoke, webhook and delivery-channel changes, settings changes, CVE category changes, imports, feed deletion, rate-limit hits.
  * Secret values are never logged, and every field is length-capped.

### Credentials at rest (OWASP Cryptographic Storage, ASVS V6)
* Webhook signing secrets and social credentials are encrypted with **Fernet** (AES-128-CBC + HMAC-SHA256, authenticated) by `app/secretbox.py`.
  * Values are prefixed `fw1:`.
  * Tampering is detected.
  * Legacy plaintext values are encrypted automatically on start-up.
* **Key** (`EOS_SECRET_KEY` / `_FILE`): comma-separated keys, where the first encrypts and all decrypt.
  * Rotate with `python -m app.cli rotate-secrets`.
  * Without a configured key one is generated in `/data/secret.key` (0600). That protects against DB-only leaks but **not** whole-volume theft, so supply the key as a Docker secret.

### Untrusted feed content (OWASP XSS Prevention, XXE Prevention)
* Feed HTML is cleaned with **nh3** (Rust *ammonia*) using a strict tag/attribute allow-list.
  `href`/`src` must be absolute `http(s)` (or `mailto:` for links); `style`, event handlers,
  `iframe`, `svg`, `form`, `script`, relative and protocol-relative URLs are removed.
  Content is sanitised **before storage and again on output**.
* Titles/authors are reduced to plain text; the UI inserts all text with `textContent`.
* Responses containing `<!ENTITY` are rejected before parsing (XXE / billion laughs).
  * The check also covers UTF-16/32 documents.
  * UTF-7 and EBCDIC are refused, whether declared in the prolog, the HTTP charset, or a BOM, because the marker would not be ASCII there.
  * feedparser receives a byte stream (never a URL or path).
  * OPML is parsed with `defusedxml` with `forbid_dtd=True`.
* CSP: `default-src 'none'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'` —
  no inline script is allowed, so even a sanitiser bypass cannot execute script.
* `Referrer-Policy: no-referrer` stops your internal hostname leaking to publishers when
  you click links; links carry `rel="noopener noreferrer nofollow"`.

### Outbound requests / SSRF (OWASP SSRF Prevention)
`app/netguard.py` is the only way the server makes HTTP requests:
1. URL must be `http`/`https`, ≤ 2048 chars, no credentials, no control characters.
2. Hostname is resolved; **every** returned address must be public (`is_global`).
   * Refused: loopback, RFC1918, link-local (incl. `169.254.169.254`), CGNAT, ULA, multicast, reserved and unspecified.
   * IPv6 transition addresses (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4, Teredo) are judged by the IPv4 address they embed.
3. The connection is made to the **validated IP** (prevents DNS-rebinding TOCTOU) while
   TLS is verified against the original hostname via SNI.
4. Redirects are followed manually (max 5) and every hop is re-validated; webhook POSTs
   never follow redirects.
5. Response size (10 MB default) and total time are capped.
   * Only `gzip`/`deflate` are accepted, decoded incrementally with a hard output bound, so a 300 KB bomb cannot inflate past the cap. Raw bytes are capped too.
   * Proxy env vars are ignored, and connections are never pooled across hosts.

Private targets can be enabled explicitly (`EOS_ALLOW_PRIVATE_FEEDS`,
`EOS_ALLOW_PRIVATE_WEBHOOKS`) for homelab use; a warning is logged at start-up.
Unspecified/multicast/reserved stay blocked even then. The one exception is the IPv6
loopback `::1`, which Python classes as reserved: in private mode it is treated like
`127.0.0.1`, so `localhost` targets work.

**Narrow alternative:** `EOS_PRIVATE_ALLOWLIST` lists exact `host:port` pairs (no wildcards, validated at start-up) that may resolve to local/private addresses, e.g. a self-hosted RSSHub on `127.0.0.1:1200`. Every other destination keeps the default policy; redirects are re-checked per hop against the redirect's own host and port; unspecified, multicast and reserved addresses stay blocked. Prefer it over the global switches. (The admin-configured X bridge was already allowed to be local.)

### Authentication & sessions (OWASP Authentication, Session Management, CSRF cheat sheets)
* Passwords: argon2id (argon2-cffi defaults), automatic re-hash on login.
  * Policy: at least 12 characters, not on a common-password denylist, must not contain the username, not repetitive.
  * Enforced for the API, CLI and bootstrap password.
  * The generated first-run password file is deleted on the first password change, and the UI warns until then.
* Unknown users are verified against a dummy hash (uniform timing, no enumeration);
  error messages are generic.
* Throttling → HTTP 429:
  * 8 failures / 15 min per client IP;
  * 30 failures / 15 min per username, a higher threshold so a single attacker cannot lock the owner out.
* Session token: 256-bit random, stored only as SHA-256; idle (24 h) and absolute (14 d)
  expiry; max 20 sessions per user; all other sessions revoked on password change.
* Cookie: `HttpOnly; SameSite=Strict; Path=/`, plus `Secure` and the `__Host-` prefix when
  served over HTTPS.
* CSRF: every non-GET cookie-authenticated request must send the per-session
  `X-CSRF-Token` (compared in constant time). Bearer-token requests are not cookie-based
  and therefore not CSRF-exposed. No CORS is enabled.
* Initial admin password comes from env/Docker secret, or is generated and written to a
  0600 file — never to logs.

### Authorization
* Scopes: `read` ⊂ `write` (tokens), plus `admin` (interactive sessions only).
  * Token, webhook, delivery-channel, settings-write and password endpoints require `admin`, so a leaked API token cannot escalate, read credentials or create persistence.
  * The OpenAPI schema requires authentication.
* Webhook secrets and social credentials are write-only through the API (`has_secret` / `credential_fields_set` are returned instead).

### Error handling & logging (SSDF PW.9, OWASP Logging)
* Unhandled exceptions return a generic 500; stack traces are only logged server-side.
* Validation errors return field locations and messages, never the submitted value.
* Logs record logins/failures with client IP; usernames are pattern-restricted
  (no log injection); passwords, tokens and secrets are never logged.

### Platform hardening (SSDF PO.5, CIS Docker Benchmark)
* Multi-stage image, no build tools at runtime, non-root user, app code owned by root.
* Compose: `read_only`, `tmpfs /tmp`, `cap_drop: [ALL]`, `no-new-privileges`, memory/PID
  limits, log rotation, health check. `umask 077` for the database and secret files.
* systemd unit (for LXC/VM installs) uses `ProtectSystem=strict`, `NoNewPrivileges`,
  empty capability set and address-family restrictions.
* Security headers on every response: CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `COOP`, `CORP`, `Permissions-Policy`, HSTS on HTTPS,
  `Cache-Control: no-store` for API responses.

### Supply chain (SSDF PS.3 / PW.4)
* `requirements.lock` pins **every** dependency, including transitive ones, with sha256 hashes.
  * The image installs with `pip install --require-hashes --no-deps`, so a tampered or substituted package fails the build.
  * The base image is pinned by digest.
* `tools/security_check.py` runs four gates:
  * secret scan (detect-secrets plus patterns, against a reviewed fingerprint baseline that holds no secret values);
  * route-permission audit;
  * bandit;
  * pip-audit on the lock, plus the full test suite.
* Exact-version pins in `requirements.txt`; `pip-audit` reported no known vulnerabilities (incl. `cryptography==50.0.2`)
  at time of writing. Recommended next steps: hash-pinned lock file (`pip-compile
  --generate-hashes`), base image pinned by digest, SBOM generation (e.g. `syft`), and image
  scanning (`trivy image eye-of-sauron:0.4.0`) in CI.

## Verification
* `pytest`: 258 tests, including CVE ingestion, classification, analytics injection, zip-bomb and XML guards, and history back-fill (site paging, Internet Archive, all-feeds); including regression tests for every pentest finding (`tests/test_security_regressions.py`).
  * Also covered: entity matching, analytics injection, SSRF, sanitiser bypass payloads, CSRF, scope enforcement, throttling, XXE, body limits and session revocation.
* **Penetration test** (2026-11, OWASP WSTG / Top 10): see [docs/PENTEST-REPORT.md](docs/PENTEST-REPORT.md).
  * Re-run the dynamic checks with `tools/pentest_harness.py`: 177 checks with the SSRF guard on, 183 with private feeds allowed.
* **OWASP WSTG v4.2 coverage** (2026-11-12): every test ID is mapped to its evidence in [docs/WSTG-COVERAGE.md](docs/WSTG-COVERAGE.md), with a checklist of what depends on your deployment (TLS, allowed hosts, exposure, file permissions).
* `bandit -r app` — no high-severity findings; medium B608 findings reviewed (see above).
* `pip-audit -r requirements.txt` — no known vulnerabilities.

## Known limitations / roadmap
* Single-user. Multi-user support would need per-user ownership on every table.
* Login throttling is in-memory (resets on restart; single worker by design).
* Remote images in articles are loaded by the browser directly from publishers (disable
  "Load remote images" for privacy); an image proxy could be added later.
* No TOTP/WebAuthn yet: put Eye of Sauron behind your SSO/reverse-proxy auth (Authelia, Authentik, Cloudflare Access) if it is exposed beyond your LAN.
* The default encryption key lives on the data volume. Move it to a Docker secret ([GUIDE §5.4](docs/GUIDE.md#54-encryption-key-management)).
* Social platform adapters are tested against API-shaped mocks, plus the X OAuth reference vector. Verify each channel with **Test** and a first manual post.
* The Telegram account login and the X API are tested against mocks (no live accounts were used). YouTube, HF Papers and Telegram public channels were verified live.
* AI providers are tested against mocks of the SDK / HTTP responses; verify yours with **Test connection**. AI summaries can be wrong or manipulated by a hostile article — they are labelled as AI-generated.
* `telethon` pulls in `pyaes` (pure-Python AES, unmaintained but with no known CVEs) as a fallback. Telethon prefers the system OpenSSL when it is available.
* Feed content is untrusted and can be misleading. Keep auto-approval of rule drafts off unless the rule is narrow.

## Reporting
This is a self-hosted personal project; open an issue or contact the maintainer privately.

- **Observatory (dashboards):** outbound read-only HTTPS to fixed hosts only - services.nvd.nist.gov, api.ransomware.live, isc.sans.edu, www.spamhaus.org - through the SSRF guard, paced, from the scheduler; responses are cached as data and rendered as text (no leak-site links; external IPs validated before use).

- **MITRE ATLAS sync:** outbound read-only HTTPS to raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ only, through the SSRF guard; the release path from the manifest must match a strict pattern; YAML is parsed with `yaml.safe_load` (no object construction); `technique` / `framework` / `tactic` parameters are pattern-validated and only ever bound as SQL parameters; chips render as text.

### Smart features (stories, entity pages, matrix, match feedback)

- All new routes require a session or token (`require_read`; the two feedback routes `require_write` + CSRF) and are rate-limited
  (`entity_page`, `attack_read`, `attack_feedback`). `tests/test_smart.py::test_new_routes_need_a_session` pins this.
- Inputs: technique IDs by pattern `^(AML\.)?T\d{4}$`; `days` from a fixed set; a name can only be muted when it is one of that
  technique's existing names (never an ID), max 80 characters. No user text reaches SQL other than as a bound parameter.
- Output: MITRE descriptions, titles and entity names are rendered as text nodes; links go through `safeUrl`. The Navigator layer
  is built in the browser from data already on the page and saved with a blob download - no outside request.
- Story grouping and the name clean-up make no network requests.

### Ad clean-up (`app/declutter.py`)

- Input is feed HTML that the sanitiser has already cleaned; the module only removes elements or wraps loose text in `<p>`, never
  adds attributes or markup from the feed (`test_output_is_still_sanitised_markup`).
- Cost: it runs inside the fetch transaction, so it is linear in the markup (one pass to find leaf blocks, direct-children checks),
  regexes only see blocks of at most 400 characters, and markup with more than 20,000 elements is left as it is
  (`test_hostile_markup_is_cheap_and_left_alone`). A failure on odd markup is logged and the article is stored unchanged.
- A feed can only influence what is removed from ITS OWN articles (counts are per feed); it cannot make another feed's text vanish.
- No network requests; hashes are of block text, not secrets (SHA-1, `usedforsecurity=False`).

### Tactic filing (`app/ttp_filing.py`)

- New route `GET /attack/techniques/{id}/entity` needs a session (`require_read`), is rate-limited (`attack_read`) and takes the
  ID by pattern `^(AML\.)?TA?\d{4}(\.\d{3})?$`; `technique=` on `/articles` accepts sub-technique IDs by the same kind of pattern.
- Filing is SQL with bound parameters over the app's own tables; tactic and technique names come from MITRE's release files
  (fetched only from the two pinned GitHub repositories through netguard) and are rendered as text nodes.
- Collections are only created / renamed / removed under the fixed prefixes "ATT&CK: " and "ATLAS: ", never when you filed into
  them by hand; rules are only deleted when named "Auto: ATT&CK: …" / "Auto: ATLAS: …" (the app's own).

### Bulk collection colours and sub-technique context matching

- `POST /tags/colors`: session + write permission + CSRF like every write route; `ids` are integers (1-500 of them), `color` must
  match the colour pattern (`#rrggbb`); the update uses bound parameters (`test_colour_several_collections_at_once`).
- `app/ttp_subs.py` only reads article text already stored and the built-in term list; it adds rows to the mention index, with the
  same 60,000-character cap per article as the entity matcher. No request is made.

### Entity filter on Videos / Podcasts

- `entity_id` (integer ≥ 1) and `days` (0/7/30/90/365, else 422) on `GET /library/videos`, `/library/topic-counts` and
  `/podcasts/episodes`: read-only, same session requirement and rate limits as before, bound parameters
  (`test_videos_and_podcasts_can_be_listed_by_what_they_mention`).

### Threat-actor catalogue and related media

- The catalogue is a JSON file shipped with the app (names, alternative names, country code, sources - no descriptions, no
  links); the app never downloads it. `tools/build_threat_actors.py` is run by hand on files you downloaded yourself.
  `test_bundled_catalogue_is_well_formed` pins its shape; names are rendered as text nodes.
- `GET /threat-actors` and `GET /articles/{id}/related` need a session, are rate-limited (`threat_actors`, `related_media`) and
  validate `q` (max 80), `days` (fixed set), `kind` (enum), `limit`; `related_to` on the Videos / Podcasts lists is an integer.
  All SQL uses bound parameters; the full-text lookups quote their terms and only use letters and digits taken from the title.
- Cost: related counts are computed when an article is opened (about 1-3 ms on 120k items); at most 6 headline names and 400
  full-text hits each.

### Email newsletters, image proxy, site icons and read later

- **Email newsletters (`app/mailfeeds.py`).** IMAPS only (implicit TLS, TLS 1.2+, certificate and host name verified);
  no plain IMAP and no STARTTLS. The mail server's address is resolved and checked by `netguard` (private, loopback and
  link-local addresses refused unless the exact host:port is in `EOS_PRIVATE_ALLOWLIST`) and the socket is pinned to
  the checked address while TLS verifies the real name. The folder is opened read-only (EXAMINE) and messages are read
  with `BODY.PEEK[]`, so nothing in the mailbox changes. Senders, folder and subject words are validated against strict
  patterns before they reach an IMAP command (no quotes, spaces or control characters). Message HTML goes through the
  same allow-list sanitiser as feed HTML; tracking pixels are dropped; at most 60 messages of at most 3 MB per fetch.
  The password is stored encrypted (`integrations`, name `imap`) and never returned. Settings are admin-only.
- **Image proxy (`GET /api/v1/img`).** Not an open relay: only addresses the server signed (HMAC-SHA256 with a random
  per-process key) are fetched, through `netguard` (SSRF guard, pinned DNS, 8 MB cap, 15 s timeout, at most 3
  redirects, each re-checked). Only raster images recognised by their bytes are passed on (PNG, JPEG, GIF, WebP, AVIF,
  BMP, ICO; never SVG or HTML), with the detected type, `nosniff`, `Content-Security-Policy: default-src 'none';
  sandbox` and private caching. Needs a session or a read token, and is rate limited.
- **Site icons (`app/media.py`, table `feed_icons`).** Fetched in the background through `netguard` from the feed's
  site (`<link rel="icon">`, then `/favicon.ico`), checked like proxy images (raster only, at most 200 KB) and served
  from our own origin with the same headers.
- **Read later (`app/readlater.py`).** Wallabag and Linkwarden addresses are admin-set and may be on the LAN (the same
  exception as the X bridge and the local AI server); requests go through `netguard` with no redirects followed.
  Client secrets, passwords and tokens are stored encrypted (`integrations`, name `readlater`) and never returned.
  Obsidian notes are created on the reader's device through an `obsidian://` link; nothing is sent to a server.
- **Highlight words** are validated (2-60 characters, no markup or control characters, at most 50) and applied in the
  browser by splitting text nodes - never through HTML.
- **Title translation** sends titles to the configured AI provider as numbered data lines with instructions to
  translate only; the answer is parsed strictly (only "<n>|<text>" lines for numbers that were sent), cleaned to plain
  text and length-capped. The daily AI request limit applies.


## 1.2.0: GitHub repos

- **GitHub repos (📦 Repos):** outbound read-only HTTPS to api.github.com and github.com (release Atom feeds) only, through the SSRF guard (redirects capped at 2, size and time caps). URLs are built from strictly validated names (owner: GitHub's login rule; repo: `[A-Za-z0-9._-]`, not `.`/`..`; topic: `[a-z0-9-]`); pasted links must be github.com. Responses are validated field by field: text stored markup-free, homepages only as http(s) without credentials, avatars only from avatars.githubusercontent.com, release links only under the repo's own `/releases/tag/` path, Atom feeds pass the XXE guard. Follow / unfollow / ★ / refresh need write scope and are rate-limited; source changes are audit-logged. The optional GitHub token is admin-only (interactive session), validated against GitHub before saving, secretbox-encrypted in `integrations`, never returned or logged. GitHub's rate limits are honoured (the sync stops at 0 and waits for the reset).

