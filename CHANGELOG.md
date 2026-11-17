# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
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
