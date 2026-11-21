# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] — 2026-11-21

### Added
- **📦 Repos tab (GitHub).** Follow single repos (with their releases), owners, GitHub topics and someone's stars; gists;
  GitHub Docs pages (titled from the link, never downloaded) and `<name>.github.io` websites. Paste up to 200 links at
  once — any page inside a repo works (`/blob/…`, `/tree/…`, `/wiki`, `?tab=…`, `#…`); every valid line is saved straight
  away and checked in the background with live per-line results. Profile links ask first (follow every repo / save the
  profile as a link / skip). Repo cards with language, stars, licence, archived / fork badges, GitHub tags and your
  topics; views by topic / owner / language and 🚀 Releases; filters for type, language, stars, last-updated dates,
  archived, forks and ★. **📁 Folders** of your own (a repo can be in several; folders view, bulk add / remove, file
  new repos straight into a folder). One GitHub request per repo; lines past GitHub's free hourly limit are saved and
  finish by themselves after its reset; an optional read-only token (stored encrypted, never returned) raises the limit
  to 5,000 an hour. API: `/api/v1/repos*`.
- **📅 Custom date range (from / to) on every tab** — Articles, Videos, Podcasts, Accounts, Dashboards and the Threat Map.
- **Whole collection folders at once:** click a folder heading in Collections (ATT&CK, ATLAS, AI, CVEs…) to read every
  article in it with the usual filters.
- **Podcasts:** ↺ 10 / 10 ↻ skip buttons (and headphone / lock-screen skip), and **older episodes** — the show's whole feed
  again, its older pages, then Internet Archive copies.
- **Custom keep time frame** in every add dialog (a number + days / weeks / months / years).
- **Tabs in your own order:** drag the tabs at the top, or Settings → Appearance → ⇄ Arrange tabs….
- **Sidebar hide / show button** and smoother tab switching.

### Changed
- **One history setting per feed:** *Keep & fetch … from* is both how long items are kept and how far back loading older
  items goes; feed settings adapt to articles, podcast episodes, YouTube videos and account posts. Podcasts and videos
  are no longer trimmed by the article count cap.
- **Reports, advisories and guidance are filed into your collections** (Threat advisories, Threat intelligence, Defensive
  security) instead of a separate sidebar view; alerts work as before.
- **Threat actors:** catalogue rebuilt from MITRE ATT&CK and ATLAS with every alias (e.g. APT40's full set of names).

### Fixed
- **Videos → By topic: "Internal server error" in Docker** on big libraries — the image now sets `SQLITE_TMPDIR=/data/tmp`
  so large sorts use the data volume instead of the 16 MB `/tmp`, and the query only ranks ids.
- Older GitHub user names ending in a hyphen, podcast history duplicates through archived copies, and smaller fixes.

## [1.1.0] — 2026-11-18

### Added (ideas borrowed from FreshRSS extensions)
- **✉ Email newsletters as feeds** (`app/mailfeeds.py`, source kind `email`): connect a mailbox (Settings → Integrations →
  Email newsletters; IMAPS only, TLS 1.2+, address checked by the SSRF guard and pinned, read-only EXAMINE + BODY.PEEK),
  then Add feed → Type → Email newsletter with the senders (addresses or domains) and optional subject words. Each matching
  message becomes an article (sanitised, tracking pixels removed, "view in browser" link kept). Useful for publishers that
  only send updates by email, such as CISA.
- **🌐 Translate titles** per feed (feed settings → Translate titles; `app/translate.py`): new titles go to your AI provider
  in batches of 25 (into its language setting); the original title is kept (`articles.title_original`) and shown under the
  translation. Turning it off restores the originals.
- **Highlight words** (Settings → Appearance & reading; setting `highlight_terms`, up to 50): marked in the article list
  and the reader (built as text nodes, never HTML).
- **Adaptive refresh** (setting `adaptive_refresh`, on): feeds on the default interval are checked less often when they
  post rarely (median gap ÷ 4, between the default and 12 hours; never more often than the default). Shown in the feed's
  settings (`feeds.adaptive_minutes`).
- **Image proxy** (setting `image_proxy`, on): reader images load through `GET /api/v1/img?u=&s=` — only addresses the
  server signed (HMAC), fetched through the SSRF guard, raster images only (recognised by their bytes; never SVG), served
  with `nosniff` and a sandbox CSP. Publishers see the server, not your device.
- **🔖 Read later** in the reader: Wallabag (OAuth password grant), Linkwarden (access token), Obsidian (`obsidian://new`
  on this device) and Markdown download. Settings → Integrations → Read later; `GET /readlater`,
  `POST /articles/{id}/save`, `PUT /integrations/readlater`.
- **Reading time and site icons** in the article list (settings `show_reading_time`, `show_site_icons`). Icons are fetched
  once per site in the background (`app/media.py`, table `feed_icons`; page `<link rel="icon">` or `/favicon.ico`, raster
  only, ≤ 200 KB, retried after a month) and served from our own origin (`GET /feeds/{id}/icon`).

### Changed
- **🗓️ Keep feeds…** (Settings → Feeds, and Settings → Appearance & reading) replaces both "Keep articles from…" and the
  separate "Fetch older articles for all feeds" section. One dialog sets how far back feeds keep items: choose article
  feeds, podcasts, YouTube channels, accounts or all together (preset to the tab you are on), optionally a folder or the
  ticked feeds, and a time frame; it shows how many items would go before removing anything, and can also fetch older
  items back to that date in the background (with progress and Stop). `POST /feeds/keep` takes `kinds`
  (`articles`, `podcasts`, `videos`, `accounts`; omitted = all) and "Everything" also lifts the item cap.
- **Retired the old working name "feedwarden".** Environment variables now use the `EOS_` prefix (`EOS_DATA_DIR`,
  `EOS_SECRET_KEY`, `EOS_ALLOWED_HOSTS`, …); the `FEEDWARDEN_*` names are still read as a fallback. The database file
  is `eos.db` (an existing `feedwarden.db` and its `-wal` / `-shm` files are renamed automatically). Webhook headers
  are `X-EOS-Signature` / `X-EOS-Timestamp` / `X-EOS-Event`. New API tokens start with `eos_` (existing `fw_` tokens
  keep working). The session cookie is `eos_session`, loggers are `eos.*`, the container user is `eos` and the
  systemd unit is `deploy/eye-of-sauron.service`.

### Fixed
- **Retention only reached article feeds**: keeping a longer (or shorter) period left podcasts, YouTube channels and
  account feeds untouched. It now applies to every feed you choose.
- **OPML export / import lost what each feed is**: podcasts and social accounts came back as article feeds (only YouTube
  was recognised). Exports now carry `eos:*` attributes (kind, source / scraping settings, social platform, retention,
  refresh, full-text and translation settings), imports restore them (every value validated), and re-importing such a
  file moves feeds an older import put in the wrong tab. OPML files from other readers are recognised by address
  (Reddit, Mastodon, Bluesky, RSSHub routes for Instagram / Threads / TikTok / Facebook / LinkedIn, Telegram, X,
  YouTube), and an article feed whose items are mostly audio episodes moves to Podcasts after its first fetch
  (`app/feedkinds.py`). The import message lists how many feeds of each kind were added.
- **Tablets** (for example a Galaxy Tab in Brave): Settings and other dialogs fit the visible screen (browser bars
  included) and scroll inside; on narrow screens Settings fills the screen; on touch screens the sidebar ⚙ / ↗ buttons
  sit after the item count instead of covering it.
- The bundled threat-actor catalogue (`app/data/threat_actors.json`) was missing from git checkouts because the
  `data/` ignore rule also matched `app/data/`; the rule is now anchored to the repository root (`/data/`). Fresh
  clones and CI get all 1,100+ actors again.

## [1.0.0] — first public release

### Reading
- RSS / Atom feeds, websites without feeds (CSS / JSON selectors with discovery and live preview), YouTube channels and
  playlists, podcasts with a built-in player, Mastodon / Bluesky / Reddit accounts, Telegram channels, X through a
  self-hosted bridge, Hugging Face daily papers.
- Three-pane reader, full text for summary-only feeds (with menu and "featured posts" stripping), automatic removal of
  ads and site promotion, story grouping across sources, folders, collections, keyword rules, search, keyboard
  shortcuts, themes, mobile layout.
- Google Reader-compatible API for native RSS apps, with per-device app passwords.
- OPML import / export; a security-focused starter list in `examples/`.

### Threat intelligence
- Reports & guidance: advisories, guidance and threat reports from government agencies, CERTs and vendor research
  teams, with a dedicated view and instant alerts.
- Threat actors: a catalogue of 1,100+ actors (MITRE ATT&CK groups, the MISP galaxy, CrowdStrike and Dragos naming,
  MITRE ATLAS activity clusters); one actor across all its names; filter articles, videos and podcasts by actor.
- MITRE ATT&CK and ATLAS: tactics, techniques and sub-techniques recognised in articles (including sub-techniques
  named only in context); tactic collections that follow MITRE's current matrices; technique matrix with ATT&CK
  Navigator export; technique, group and actor pages.
- CVE tracking from NVD, CISA KEV and MITRE CWE, with categories, OWASP mappings and alerts.
- Dashboards (threat landscape, ransomware, APT, AI-powered threats, OT/ICS, CVEs) and a threat map.
- Related videos and podcast episodes for articles, techniques and threat actors.

### Automation
- Delivery channels: email, Telegram, ntfy, Discord, Slack, webhook.
- Instant alerts (CVEs, keyword rules, new reports) and scheduled digests with reports, threat actors and CVEs.
- Optional AI summaries and briefings with Claude, OpenAI, Gemini or any OpenAI-compatible / local model.
- REST API with scoped tokens; outgoing signed webhooks.

### Security
- Strict CSP, CSRF protection, rate limits, session hardening, password policy, audit log.
- SSRF-guarded fetcher, sanitised HTML, encrypted credentials at rest, no secrets in API responses.
- Non-root, read-only container with all capabilities dropped; hash-locked dependencies; release gate
  (secret scan, route audit, SAST, dependency audit, tests) and an HTTP pentest harness.
