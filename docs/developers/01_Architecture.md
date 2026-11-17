# Architecture & extension guide

This document explains how Eye of Sauron is put together, so you can find your way around the code, change it safely and extend it. User-facing behaviour is in [GUIDE.md](GUIDE.md), the security design in [SECURITY.md](../SECURITY.md), and the development workflow in [CONTRIBUTING.md](../CONTRIBUTING.md).

**Contents**
1. [Design principles](#1-design-principles)
2. [Runtime overview](#2-runtime-overview)
3. [Code map](#3-code-map)
4. [Data model](#4-data-model)
5. [Key flows](#5-key-flows)
6. [Security invariants (do not break these)](#6-security-invariants-do-not-break-these)
7. [How to extend](#7-how-to-extend)
8. [Frontend conventions](#8-frontend-conventions)
9. [Testing strategy](#9-testing-strategy)

---

## 1. Design principles

* **One process, one file database.**
  * FastAPI + SQLite (WAL mode, FTS5), background threads for scheduling.
  * No Redis, no worker cluster, no build step for the frontend.
  * A single container or systemd unit runs everything.
* **Secure by default.**
  * All outbound HTTP goes through one SSRF-hardened client.
  * All feed HTML is sanitised before storage.
  * All third-party credentials are encrypted at rest.
  * Request models reject unknown fields.
* **Untrusted in, untrusted out.**
  * Feed content, scraped pages, API responses and AI output are all treated as attacker-controlled.
  * They are escaped, sanitised or rendered as text, never executed.
* **Additive migrations.**
  * The schema only grows: new tables and new nullable/defaulted columns.
  * Older databases upgrade in place on start (`app/db.py::_migrate`).
* **Docs ship with the code.** Every behaviour change updates the CHANGELOG and the relevant guide in the same change.

## 2. Runtime overview

```
                    ┌──────────────────────────── FastAPI app (app/main.py) ───────────────────────────┐
 Browser (static/) ─┤ REST /api/v1/*  (session cookie + CSRF, or Bearer token with scopes)              │
 Native RSS apps ───┤ Google Reader API /api/greader.php (reader-scope tokens only)                      │
                    │ Middleware: security headers/CSP, body-size limit, trusted hosts                   │
                    └───────────────┬──────────────────────────────────────────────────────────────────┘
                                    │ SQLite (data/eos.db)
 Background threads ────────────────┤
   scheduler (app/scheduler.py) ── every tick: due feeds → fetcher (thread pool)
                                               cve_sync.maybe_start() · attack/atlas sync · observatory
                                               digests.run_due() · retention (hourly)
   cve_sync      NVD API 2.0 + CISA KEV + MITRE CWE → cves tables → classify → alerts.check_cves()
   history jobs  back-fill: one feed or all feeds (site paging, Internet Archive; one at a time)
   reclassifiers entities (watchlists) · topics
   telegram      private asyncio loop for Telethon (MTProto)
   ai queue      rule-driven auto-summaries (bounded)
```

* **Outbound traffic:**
  * Feeds, sources, webhooks, AI providers (except Claude) and push channels go through `app/netguard.py`.
  * Exceptions with fixed destinations:
    * Claude, via the official `anthropic` SDK, to `api.anthropic.com`;
    * Telegram MTProto, to Telegram's data centres;
    * SMTP, to the admin-configured mail server.

## 3. Code map

### Backend (`app/`)

| Module | Responsibility |
|---|---|
| `main.py` | App factory: middleware, routers, startup tasks (migrations, key setup, seeding) |
| `mailfeeds.py` | Email newsletters over IMAPS (read-only, pinned, SSRF-checked) |
| `translate.py` | Title translation through the AI provider (background worker) |
| `media.py` | Image proxy (signed URLs, byte-sniffed raster images) and site icons |
| `readlater.py` | Wallabag / Linkwarden |
| `config.py` | Environment configuration (`EOS_*`), read once |
| `db.py` | Schema (`SCHEMA`, `SCHEMA_VERSION`), additive `_migrate`, `get_db()` context manager |
| `security.py` | Password hashing (argon2id), sessions, API tokens and scopes, CSRF, throttling, rate limits, audit log |
| `secretbox.py` | Fernet/MultiFernet encryption for stored credentials (`fw1:` prefix), key rotation |
| `netguard.py` | SSRF-safe HTTP: scheme/host validation, DNS pinning, private-range blocking, size/time caps, safe decompression |
| `sanitize.py` | nh3 allow-list sanitiser and HTML→text |
| `fetcher.py` | Fetch → parse (feedparser, XML guard) → `store_entries` → entities → topics → rules → events |
| `sources.py` | Non-RSS sources (YouTube, HF Daily Papers, X, Telegram web) → feedparser-like entries |
| `telegram_mt.py` | Telegram account login and history via Telethon |
| `scraper.py` | Website scraping (CSS selectors / JSON paths), discovery and suggestions |
| `history.py` | Back-fill of older items: site paging (RFC 5005, Blogger, Ghost, WordPress, ?page=N), Internet Archive captures, source history; single-feed and all-feeds jobs |
| `rules.py` | Keyword rules → collections, star, read, webhook / alert / summary events |
| `entities.py`, `entities_seed.py` | Watchlists and entity mentions |
| `topics.py` | Keyword topics (boilerplate-aware) for every article |
| `analytics.py`, `cve_analytics.py` | Dashboard queries (whitelisted dimensions, bound parameters). Filters combine with `match` all/any via `analytics.combine()`; `focus` is the always-ANDed drill-down restriction |
| `fulltext.py` | Full article text for summary-only feeds: page fetch, main-content extraction, per-site pacing, background queue |
| `attack_sync.py` | MITRE ATT&CK sync (STIX bundles → attack_* tables, two watchlists, ATT&CK tactic rules), scheduled weekly/daily |
| `accounts.py` | Recognises social profile links and how to follow them (source, native RSS, or a bridge feed) |
| `collection_packs.py` | Ready-made collections (data only): packs of collections and the keyword rules that fill them |
| `feed_doctor.py` | Feed troubleshooter: DNS, fetch, redirect/HTTPS/declared-feed/common-path checks with a request budget; background job for many feeds |
| `combined_analytics.py` | "News articles + CVEs" widgets: runs the article and CVE queries with their own filters and merges them (KPI pair, two-series time chart, mixed list) |
| `cve_sync.py`, `cve_classify.py` | CVE ingestion and classification |
| `webhooks.py` | Signed outbound webhooks |
| `integrations.py` | Encrypted settings for YouTube / X / Telegram / AI |
| `ai.py` | AI provider layer, budget, output cleaning, article summaries |
| `delivery.py` | Email / Telegram bot / ntfy / Discord / Slack / webhook senders |
| `digests.py` | Scheduled digest collection, rendering and delivery |
| `alerts.py` | CVE alert rules and keyword-rule alerts (exactly-once) |
| `scheduler.py` | The background loop |
| `cli.py` | Admin CLI (reset password, rotate secrets, revoke tokens…) |

### API (`app/api/`)

| Router | Prefix / paths | Notes |
|---|---|---|
| `auth.py` | `/auth/*`, `/tokens` | Login, password, API tokens |
| `content.py` | `/folders`, `/feeds`, `/articles`, `/tags`, `/sidebar` | Core reader |
| `automation.py` | `/rules`, `/webhooks`, `/settings`, `/opml` | |
| `insights.py` | `/watchlists`, `/dashboards`, `/analytics` | |
| `cves.py` | `/cves/*` | |
| `history.py` | `/feeds/{id}/details`, `/feeds/{id}/backfill`, `/history/backfill-all`, `/history/status` | All-feeds back-fill is admin-only |
| `scrape.py` | `/scrape/*` | |
| `sources.py` | `/sources/resolve`, `/integrations/*` | |
| `attack.py` | `/attack/*` | |
| `accounts.py` | `/accounts/*` | Accounts tab: add, posts, shelves, meta, remove |
| `library.py` | `/library/*`, `/topics` | `/library/groups` (playlists & your groups), `/library/shelves` (videos by topic), `POST /library/videos` (one video into the Saved YouTube videos feed) |
| `ai.py` | `/ai/*`, `/articles/{id}/summary`, `/delivery-channels`, `/digests`, `/alert-rules`, `/alerts/recent` | |
| `greader.py` | `/api/greader.php`, `/api/greader` | Native-app protocol, outside `/api/v1` |

Every route declares its permission (`require_read`, `require_write`, `require_publish` or `require_admin`). `tools/route_audit.py` fails the build if one does not.

### Frontend (`static/`)

Plain ES2020 modules loaded with `defer`, sharing helpers through `window.FW`:

| File | What it renders |
|---|---|
| `app.js` | Shell, sidebar, list, reader, settings dialog, rules, mode switch; defines `FW` helpers (`h`, `fill`, `api`, `toast`…) |
| `feeds.js` | Feed editor, history tools, scraping wizard, mobile-apps panel |
| `sources.js` | Add-source wizard, Integrations panel, 📺 Library, topics editor |
| `ai.js` | Settings → AI, ✨ Summarize, Settings → Alerts & digests |
| `threatmap.js` | 🌍 Threat Map (SVG choropleth from `world-map.json` + analytics breakdowns; category / actor / attack-type focus, sectors list, drill-down; vendor live-map links) |
| `dashboard.js`, `charts.js`, `cve.js` | Dashboards, SVG charts, CVE tracker |
| `*.css` | Theme tokens in `styles.css`; feature styles per file |

## 4. Data model

The authoritative schema is `SCHEMA` in `app/db.py`; comments there explain each column. These are the main groups:

* **Reading:**
  * `folders`, `feeds` (`kind` = rss | html | json | youtube | hfpapers | x | telegram; `scrape` / `source` JSON);
  * `articles` (+ FTS `articles_fts`), `article_tombstones`, `tags`, `article_tags`.
* **Enrichment:** `watchlists`, `entities`, `article_entities`, `topics`, `article_topics`, `videos`, `article_summaries`.
* **Automation:** `rules`, `webhooks`, `delivery_channels`, `digests`, `digest_runs`, `alert_rules`, `alerts_sent`.
* **CVE:** `cves` (+ `cves_fts`), `cve_cwes`, `cve_products`, `cve_categories`, `cve_category_map`, `cwe_entries`, `cwe_owasp`.
* **Auth & config:** `users`, `sessions`, `api_tokens`, `reader_apps`, `settings`, `integrations`, `sync_state`, `ai_usage`.

**Encrypted columns** (listed in `secretbox.ENCRYPTED_COLUMNS`, rotated by `cli rotate-secrets`):

* `webhooks.secret`
* `integrations.secret`
* `delivery_channels.credentials`

**Adding a column or table:**
1. Add it to `SCHEMA`.
2. For columns on existing tables, add an `ALTER TABLE … ADD COLUMN` to `_migrate`, guarded by a `PRAGMA table_info` check.
3. Bump `SCHEMA_VERSION`.
4. Never rename or drop: deprecate instead.

## 5. Key flows

### Fetching a feed
1. `scheduler._tick()` picks feeds whose `next_fetch` is due.
2. `fetcher.fetch_feed(id)` runs the path for the feed's kind:
   * **rss:** `netguard.request` → `xml_guard` → `feedparser`.
   * **html / json:** `scraper.extract`.
   * **source kinds:** `sources.fetch(feed)`, which returns a `Fetched` (entries, title, video metadata, cursor state).
3. `_store()` saves the items:
   * `store_entries` sanitises each item, dedups by GUID and URL, and respects tombstones and retention.
   * It then runs entity extraction, `topics.classify` and `rules.apply_rules`.
4. Rule events fan out to `webhooks.dispatch` and `alerts.article_alerts`. The last of these handles instant alerts and AI auto-summaries.
5. Errors back off exponentially, or for the source's `retry_after` (rate limits, flood waits).

History imports use the same storage path but **never** fire events: no webhooks, drafts or alerts for old items.

### CVE alerts
1. `cve_sync._store()` upserts each NVD batch, then classifies it.
2. It calls `alerts.check_cves(ids)`. KEV sync also checks CVEs newly added to KEV.
3. For each rule:
   * Only CVEs published or KEV-added after the rule was created (minus a 1-day grace) can match.
   * The rule claims each match by inserting into `alerts_sent` (unique per rule and item), then sends.
4. More than 3 matches in one batch are combined into one message.

### Digests
1. `digests.run_due()` runs every scheduler tick.
2. Each due digest collects articles since its last run (capped by `window_hours`) and new CVEs.
3. It optionally asks the AI provider for a briefing that cites items as `[n]`.
4. It appends the item list with links from the database, stores a `digest_runs` row, delivers, and computes `next_run` in the digest's time zone.

### AI requests
1. `ai.complete()` loads the settings and reserves one request against the daily limit atomically.
2. It calls the provider:
   * **Claude:** official SDK; server-side refusal fallback on supported models.
   * **OpenAI / Gemini / compatible:** HTTPS via netguard.
3. It cleans the output (control/bidi characters, Markdown headings, length cap) and records token usage.

## 6. Security invariants (do not break these)

1. **Outbound HTTP:**
   * Outbound HTTP to user-supplied or remote-derived URLs goes through `netguard.request` with `allow_private=False`.
   * The only exceptions are explicitly admin-configured endpoints: the X bridge, the OpenAI-compatible AI base URL, the ntfy server, and private feeds/webhooks when enabled by environment variable.
2. **Stored HTML:**
   * HTML from outside is sanitised (`sanitize_html`) before it is stored.
   * Code that builds HTML from remote values must `html.escape` them first.
3. **The browser** renders only server-sanitised HTML, and only through `buildContent`. Everything else uses `textContent`. AI output is always text.
4. **Credentials:**
   * Third-party credentials are stored only through `secretbox`.
   * They are never returned by an API, never written to logs, and never put in URLs (except where a vendor's API requires it, such as the Telegram Bot API path).
5. **Routes:** every route has an explicit permission dependency. Admin-only covers anything that holds credentials, sends messages or spends money on a schedule.
6. **Request models:**
   * Request models extend `StrictModel` (`extra="forbid"`).
   * Enumerated values are `Literal`s.
   * SQL fragments are chosen from constant maps; values are always bound parameters.
7. **Background jobs** that act on history never trigger outbound side effects (webhooks, alerts).
8. **Dependencies** are exact-pinned in `requirements.txt` and hash-locked in `requirements.lock`, which is regenerated inside the pinned base image.

`tools/security_check.py` (secret scan, route audit, bandit, pip-audit, tests) must pass before every release.

## 7. How to extend

### Add a new source type (e.g. Mastodon accounts, Reddit, a vendor API)
1. **`app/sources.py`:**
   * Add a config model (`kind: Literal["newkind"]`, strict field patterns) to the `SourceConfig` union.
   * Add a `canonical_url()` branch (must be unique per subscription).
   * Add a `fetch_newkind(cfg) -> Fetched` that uses `http_get` (netguard) and `entry(...)`, escaping every remote value.
   * Add a branch in `fetch()` and `KINDS` / `DEFAULT_REFRESH`.
2. **Optional:** add a `detect()` hint, a `resolve` branch in `app/api/sources.py`, and history support in `history._backfill_source`.
3. **Frontend:**
   * `KIND_LABEL` / `KIND_ICON` and `sourceEditor()` in `static/sources.js`;
   * a type option in the Add-feed dialog (`static/index.html`).
4. **Tests:** mock `app.netguard.request` (see `tests/test_sources.py`). Cover hostile content and malformed configs.
5. **Docs:** GUIDE §2f, SECURITY (third-party sources), CHANGELOG.

### Add an AI provider
1. **`app/ai.py`:** add the name to `PROVIDERS` and write a `_provider()` function that returns an `AIResult`.
   * Send the key in a header, use netguard, and map auth, rate-limit and safety-filter errors to an `AIError` with a safe message.
   * Dispatch to it from `complete()`.
2. **`app/api/ai.py`:** add the name to the `AISettingsIn.provider` literal.
3. **`static/ai.js`:** add it to `PROVIDER_LABEL` and `MODEL_HINT`.
4. Add a test that checks the request shape and that no key appears in the URL.

### Add a delivery channel
1. **`app/delivery.py`:** add a config model to `ChannelConfig`, credential validation in `validate_credentials`, a `_send_x()` function, and a dispatch branch in `send()`.
   * Neutralise mentions and markup for that platform.
   * Use `max_redirects=0` for POSTs.
2. **`static/ai.js`:** add it to `KIND_LABEL` and a form branch in `channelForm()`.
3. Add tests for the formatting and validation.

### Add a dashboard widget dataset or CVE category
* **Analytics:** dimensions are whitelisted in `analytics.py` / `cve_analytics.py`; add new group-by keys there.
* **CVE categories:** built-in categories live in `cve_classify.BUILTIN`. Users can add more in the UI.

### Add a setting
* **`app_settings.SCHEMA`:** add `key: (default, validator)`.
* **UI:** in `renderGeneralPanel` (`static/app.js`) or the relevant panel.

## 8. Frontend conventions

* **Building DOM:**
  * Build with `h(tag, props, ...children)`. Never use `innerHTML` with data.
  * Links go through `safeUrl()` and colours through `safeColor()`.
* **Content Security Policy:** `default-src 'none'; script-src 'self'; style-src 'self'`. No inline scripts or styles. Set dynamic style values with `el.style.setProperty` (allowed via CSSOM).
* **Requests:** use `api(method, path, body)`, which adds the CSRF header and turns errors into `Error(message)`. Wrap user actions in `guarded()` to get toasts.
* **Theme:** use the CSS variables from `styles.css` (`--bg`, `--panel`, `--accent`, …) so light and dark themes both work.

## 9. Testing strategy

* **`tests/`** (pytest) runs against a fresh temporary data directory per test (`conftest.py`).
  * External services are always mocked: `app.netguard.request`, `anthropic.Anthropic`, `smtplib.SMTP`, Telethon calls.
  * Every security fix gets a regression test (`tests/test_security_regressions.py`).
* **`tools/pentest_harness.py`** starts a throwaway instance plus a hostile local server and runs about 180 attack checks (OWASP Top 10, API Top 10, OWASP WSTG v4.2, feature-specific). White-box WSTG checks (HTTPS behaviour, session timeouts, source-level sink scans) are in `tests/test_wstg.py`; the full mapping is in [WSTG-COVERAGE.md](WSTG-COVERAGE.md). Every check is expected to pass; results per release are in [PENTEST-REPORT.md](PENTEST-REPORT.md).
* **`tools/security_check.py`** is the release gate.

### Topic re-tagging
`topics.Reclassifier` runs in a background thread, one job at a time. Adding or editing a topic re-tags only that topic; `start()` with no topic (built-in topic changes, *Re-tag all*) re-tags everything. Work is done in transactions of `RETAG_BATCH` (500) articles with a short pause between them, so the fetcher and the UI keep writing. Never wrap a whole-table rewrite in one transaction: SQLite allows one writer, and other writers give up after the 15 s busy timeout.

- `article_topics.source`: `keyword` (matched), `channel` (the channel's main topic), `general` (last resort). Every video has at least one topic.

- **Observatory (dashboards):** outbound read-only HTTPS to fixed hosts only - services.nvd.nist.gov, api.ransomware.live, isc.sans.edu, www.spamhaus.org - through the SSRF guard, paced, from the scheduler; responses are cached as data and rendered as text (no leak-site links; external IPs validated before use).

- **MITRE ATLAS sync:** outbound read-only HTTPS to raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ only, through the SSRF guard; the release path from the manifest must match a strict pattern; YAML is parsed with `yaml.safe_load` (no object construction); `technique` / `framework` / `tactic` parameters are pattern-validated and only ever bound as SQL parameters; chips render as text.

## 10. Smart features (0.4)

- `app/stories.py` - story grouping. `assign()` runs in the fetcher's transaction for new articles (in-memory word index of the
  last 8 days, lock-protected); `rebuild()` regroups everything in short transactions; `ensure_current()` compares the setting
  with `sync_state.stories_rev`. Column `articles.story_id` (partial index).
- `app/intel.py` - `entity_page()`, `article_entities()` (reader chips) and `matrix()`. No tables of its own: it reads
  `article_entities`, split by feed kind, because videos / episodes / posts are articles of their own feed kinds.
- `app/attack_sync.py` - `GENERIC_NAMES`, `ATTACK_TERMS`, `matchable()`, `refresh_aliases()` (rebuild entities + tactic rules
  from the stored release), `set_muted()`; `entities.muted` is honoured by `entities.Matcher`; `entity_rejections` by
  `_index_articles`. `rules.refile_tags()` un-files rule-filed articles no rule matches any more.
- Front end: `static/intel.js` / `intel.css` (`FW.intel.entityPage / techniquePage / matrix / notThis`, one `<dialog id="intelDialog">`);
  story folding and the Settings card are in `app.js`.
- Tests: `tests/test_smart.py`.
- `app/declutter.py` - ad / site-promotion clean-up. `clean_new()` runs in the fetcher's transaction right after the articles
  are stored (before entity extraction, story grouping and rules, so promotion text is never indexed); `clean_page()` on page
  full text (`fulltext.fill_article`); `rebuild()` once for stored articles. Table `feed_blocks`. Works on sanitised HTML and only
  removes elements (or wraps loose text in `<p>`), so no second sanitiser pass is needed. Tests: `tests/test_declutter.py`.
- `app/ttp_filing.py` - tactic collections. `tactics()` (matrix order from `attack_tactics`), `sync_collections()` (tags follow
  the matrix; `ttp_entity_tags` maps technique / sub-technique / tactic entities to tags), `file()` (two set-based SQL statements
  over `article_entities`), `refile_all()`. Called by the fetcher and the full-text reader for new text, by the entity re-indexer
  when it finishes, by both syncs, by pack install and by the "not this technique" route. `attack_sync` / `atlas_sync` build the
  entities (`_technique_entities`, `_entities`) and `atlas_sync.attach_ttps` returns `ttps[].subs` and `ttp_tactics`.
  Tests: `tests/test_ttp_filing.py`.
- `app/ttp_subs.py` - sub-techniques recognised next to their technique: `assign(db, ids)` (fetcher, full text, ad clean-up),
  `assign_all()` / `after_reindex()` (entity re-indexer hook, before `ttp_filing.refile_all()`), `ensure_current()` (startup, `REV`).
  Writes plain `article_entities` rows for the sub-technique entities; honours `entity_rejections`.
- `app/threat_actors.py` - the bundled catalogue -> watchlist (`apply_catalog`, `ensure_current` at start), actor clusters
  (`_clusters`, cached on `entities._version`), `expand()` (used by `/articles?entity_id`, `related.media_filter`,
  `intel.entity_page`), `listing()`. `app/related.py` - `_units` (what an article names, weighted), `_title_names` (coined
  headline names via FTS), `related()`, `counts()`, `media_filter()`. Front end: `FW.intel.actors / related`,
  `FW.library.listRelated`, `FW.podcasts.listRelated`. Tests: `tests/test_threat_actors.py`.

## 11. Extras borrowed from FreshRSS extensions

| Feature | Where | Notes |
|---|---|---|
| Email newsletters | `app/mailfeeds.py`, source kind `email` in `app/sources.py`, `PUT /integrations/imap` | Each matching message -> one entry through `fetcher._store`; `sync_state` key `email_seen:<feed id>` makes later fetches look back 4 days instead of 30. |
| Title translation | `app/translate.py`, `feeds.translate_titles`, `articles.title_original` | Background worker, 25 titles per AI request; `undo()` restores originals. |
| Highlight words | setting `highlight_terms`; `marked()` / `highlightTree()` in `static/app.js` | Client-side, text nodes only. |
| Adaptive refresh | `fetcher.adaptive_minutes()` / `refresh_for()`, `feeds.adaptive_minutes`, setting `adaptive_refresh` | Only for feeds without their own interval; median posting gap / 4, clamped to [default, 12 h]. |
| Image proxy | `app/media.py` (`sign`, `rewrite_images`, `fetch_image`, `sniff`), `GET /img`, setting `image_proxy` | `get_article` rewrites `<img src>` after sanitising. |
| Site icons | `app/media.py` (`refresh_icons`, `IconWorker`), table `feed_icons`, `GET /feeds/{id}/icon` | Started from the scheduler loop every 6 hours. |
| Reading time | `read_minutes` in `/articles` and `/articles/{id}` | `ceil(len(text_content) / 1200)`. |
| Read later | `app/readlater.py`, `app/api/extras.py` (`/readlater`, `/articles/{id}/save`), `PUT /integrations/readlater` | Obsidian / Markdown are built in the browser. |
