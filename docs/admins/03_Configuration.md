# Configuration

Eye of Sauron is configured with environment variables (in Docker: `.env` next to `docker-compose.yml`, see
[`.env.example`](../../.env.example)). Everything else — feeds, rules, alerts, AI providers, integrations — is set in the
web interface and stored in the database.

The variables use the `FEEDWARDEN_` prefix (the project's original name); they are stable and will not change.

Secrets can be given directly or as a file: `FEEDWARDEN_ADMIN_PASSWORD_FILE=/run/secrets/admin_password` reads the value
from that file (works with Docker / Kubernetes secrets). This applies to every variable marked *secret*.

## Core

| Variable | Default | What it does |
|---|---|---|
| `FEEDWARDEN_DATA_DIR` | `/data` | Where the database, encryption key and logs live. Back this up. |
| `FEEDWARDEN_ADMIN_USER` | `admin` | Name of the account created on first start. |
| `FEEDWARDEN_ADMIN_PASSWORD` *(secret)* | — | Password for that account on first start. If unset, a random one is written to `DATA_DIR/initial_admin_password.txt`. |
| `FEEDWARDEN_SECRET_KEY` *(secret)* | — | Comma-separated Fernet keys that encrypt stored credentials (first key encrypts, all decrypt — for rotation). If unset, a key is generated in the data directory; move it out of the volume for stronger protection. Generate one with `python -m app.cli gen-secret-key`. |
| `FEEDWARDEN_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |
| `TZ` | `UTC` | Time zone of the container (digests have their own time zone setting). |

## Web and sessions

| Variable | Default | What it does |
|---|---|---|
| `FEEDWARDEN_ALLOWED_HOSTS` | `*` | Comma-separated host names the app answers to (e.g. `news.example.com`). **Set this when exposed**: it blocks Host-header attacks. |
| `FEEDWARDEN_COOKIE_SECURE` | `auto` | `true` forces Secure cookies (use behind HTTPS), `false` allows plain HTTP, `auto` decides per request. |
| `FEEDWARDEN_SESSION_IDLE_HOURS` | `24` | Sign out after this long without activity (1–2160). |
| `FEEDWARDEN_SESSION_MAX_DAYS` | `14` | Absolute session lifetime (1–365). |
| `FEEDWARDEN_MAX_BODY_BYTES` | `1048576` | Largest accepted request body. |
| `FEEDWARDEN_MAX_OPML_BYTES` | `5242880` | Largest accepted OPML import. |

## Fetching

| Variable | Default | What it does |
|---|---|---|
| `FEEDWARDEN_FETCH_TIMEOUT` | `20` | Seconds per request (3–120). |
| `FEEDWARDEN_FETCH_CONCURRENCY` | `6` | Feeds fetched in parallel (1–32). |
| `FEEDWARDEN_MAX_FEED_BYTES` | `10485760` | Largest feed accepted (podcast archives may be larger and have their own limit). |
| `FEEDWARDEN_ALLOW_PRIVATE_FEEDS` | `false` | Allow feeds on private / local addresses. Off by default: the fetcher refuses loopback, link-local, private and cloud-metadata addresses (SSRF protection). |
| `FEEDWARDEN_ALLOW_PRIVATE_WEBHOOKS` | `false` | The same for outgoing webhooks and self-hosted delivery channels. |
| `FEEDWARDEN_PRIVATE_ALLOWLIST` | — | Exact `host:port` pairs that may be private even when the two settings above are off, e.g. a self-hosted RSSHub bridge: `127.0.0.1:1200`. |
| `FEEDWARDEN_NVD_API_KEY` *(secret)* | — | Optional NVD API key: faster CVE synchronisation. |
| `FEEDWARDEN_DISABLE_SCHEDULER` | `false` | Do not fetch or run background jobs (useful for a read-only replica or tests). |

## Source code link (AGPL)

| Variable | Default | What it does |
|---|---|---|
| `FEEDWARDEN_SOURCE_URL` | — | If you run a modified version for others, set this to where your source code is published; it is shown in Settings → About, as the AGPL requires. |

## In the web interface

| Where | What |
|---|---|
| Settings → Appearance & reading | Theme, density, story grouping, related media, technique matrix period… |
| Settings → Feeds | Refresh intervals, retention, folders, full text, troubleshooting |
| Settings → Rules & auto-filing | Keyword rules, collection packs |
| Settings → Watchlists & entities | Built-in and your own watchlists; MITRE sync schedule |
| Settings → CVE tracking | NVD / KEV synchronisation, CVE categories |
| Settings → Alerts & digests | Delivery channels, report alerts, CVE alerts, digests |
| Settings → AI | Provider (Claude, OpenAI, Gemini, any OpenAI-compatible / local model), model, daily budget |
| Settings → Integrations | YouTube API key, X / Telegram bridges and accounts |
| Settings → API tokens · Mobile apps | REST tokens and per-device app passwords |
