# Operations guide

New to Eye of Sauron? Start with the short, plain-language [User Guide](USER-GUIDE.md); for where and how to run it see [DEPLOYMENT.md](DEPLOYMENT.md). This guide covers using Eye of Sauron day to day, publishing to social media, and running it safely over time. For installation see the [README](../README.md); for the security design see [SECURITY.md](../SECURITY.md); for what changed in each version see the [CHANGELOG](../CHANGELOG.md).

**Contents**
1. [Concepts](#1-concepts)
2. [Daily use](#2-daily-use)
4. [Automation recipes](#4-automation-recipes)
5. [Administration](#5-administration)
6. [Maintenance schedule](#6-maintenance-schedule)
7. [Incident response](#7-incident-response)
8. [Troubleshooting](#8-troubleshooting)
9. [Changing the app & keeping docs current](#9-changing-the-app--keeping-docs-current)

---

## 1. Concepts

| Thing | What it is |
|---|---|
| **Feed** | An RSS/Atom/JSON feed URL. Fetched on its own interval (or the global default). |
| **Folder** | Groups feeds in the sidebar (drag a feed onto a folder to move it). |
| **Collection** | A label for *articles* (Ransomware, Advisories…). Filled manually or by rules. |
| **Watchlist / entity** | Named lists (ransomware groups, APTs, countries, your organisation…). Every article is indexed for mentions, and the indexed mentions drive dashboards and hashtags. |
| **Dashboard** | Charts and KPIs built from article mentions. |
| **Channel** | A social account or automation endpoint that posts can be sent to. |
| **Delivery channel** | Where alerts and digests go: email, Telegram bot, ntfy, Discord, Slack or a signed webhook. |
| **Digest** | A scheduled briefing of recent articles and CVEs, optionally written up by AI. |
| **CVE alert rule** | Conditions (CVSS, KEV, vendors, categories) that send an instant alert when a matching CVE appears. |
| **Post** | A draft or queued item for one channel. Lifecycle: `draft → approved/scheduled → publishing → published` (or `failed` / `cancelled`). |

There are four interfaces, switched from the top bar:
- **📰 Articles**: read and file articles.
- **📊 Dashboards**: track trends (`d` toggles between Reader and Dashboards).
- **📺 Library**: browse your YouTube channels' videos by channel and topic (§2f).

## 2. Daily use

- **Reading:**
  - `j`/`k` next/previous article · `s` star · `m` read/unread · `o` open the original · `/` search · `r` refresh all.
  - **Hide read** (setting `hide_read`, default on): read articles are left out of feeds, folders, collections, *All* and *Today* (the API is called with `unread=true`) and listed under **Read**; Starred and search show everything. An article you just read stays on screen until you open another one. The Read view works the other way round: articles marked unread there (one by one or in bulk) leave it and are back in their feeds and collections.
  - Search supports prefixes: `lockbit`, `CVE-2026`, `ransom*`.
- **Several articles at once:** **☑ Select** (or Ctrl/Cmd+click, or `x`) shows a tick box on each article. Shift+click ticks a range; *Select all* ticks everything loaded in the list.
  - The bar above the list marks the ticked articles read or unread, stars or unstars them, or adds them to or removes them from a collection. Up to 1,000 at a time.
  - **Done** or `Esc` leaves select mode. Ticks are cleared when you switch view.
- **Filing:** use **📁 File into…** on an article, or let rules do it (Settings → Rules → *Ready-made collections*).
- **Collection packs** (`GET/POST /rules/packs`, `POST /rules/packs/remove`; installed packs can be updated or removed, and `rules_missing` counts rules added in newer versions): *Core threats*, *OT / ICS*, *Security practice*, *AI*, *MITRE ATT&CK tactics*, *OWASP Top 10 (2025)*, *CVEs* and *Blockchain & crypto*.
  - Each collection is filled by rules named `Auto: <collection>` (plus `#2`… for extra rules).
  - Installing is idempotent: a collection or rule whose name already exists is left alone, so your edits survive a reinstall.
  - New rules are back-filled over stored articles in a background thread, in short transactions. Webhooks, alerts and AI summaries are not fired for the back-fill.
  - *Threat advisories* = the **Advisories** folder (minus CISA "Known Exploited Vulnerabilities added" notices) plus advisory-type headlines (advisory, alert, guidance, warns, threat report…) that name an agency, CERT, vendor or research team, excluding CVE stories. Keep feeds that list single CVEs (cvefeed.io, MSRC update guide, ZDI…) in another folder, e.g. *Vulnerabilities*.
  - *CVEs* = severity collections plus KEV, ransomware-linked, RCE, privilege escalation, memory corruption, DoS, edge devices & remote access, OS & browsers, virtualization, email servers and AI/ML, through `cve_severity` / `cve_category` conditions.
  - *AI: News & tools* and *Crypto: News* include everything in the **AI** and **Blockchain & Crypto** folders (crypto-folder headlines with hack words also go to *Crypto: Hacks & breaches*); the installer creates those folders if they are missing.
  - Names of the form `Group: Name` are grouped under a collapsible `Group` heading in the sidebar.
- **Rule conditions:** `keywords` (any) AND `require_keywords` (any, optional) AND the CVE condition AND NOT `exclude_keywords`.
  - `keywords_in_title`: the main keywords must appear in the title, while the other lists follow *Search in*. The OT, offensive/defensive AI and crypto-hack collections use it, because long articles mention "AI" or "OT" in passing.
  - `keywords` may be empty when the rule is limited to a feed or folder, or has a CVE condition; it then matches everything in scope.
  - `cve_severity` (`CRITICAL|HIGH|MEDIUM|LOW`) and `cve_owasp` (`2025:A01`…`2021:A10`) match articles that name a CVE (`CVE-YYYY-NNNN`, at most 50 per article) whose NVD severity, or whose CWE's OWASP mapping, fits. `cve_category` matches a CVE in a CVE-tracking category (slug such as `rce`, `privilege-escalation`, `edge-firewall-vpn`; Settings → CVE tracking) or `kev` / `kev-ransomware` (CISA KEV). They use the local CVE tables, so sync CVEs first (CVE tab).
- **Feed management:**
  - **Keep feeds…** (Settings → Feeds, or the ticked feeds): `POST /feeds/keep` with `scope` (`all`, a `folder` with `folder_id`, or `feeds` with `feed_ids`), `kinds` (`articles`, `podcasts`, `videos`, `accounts`; omitted = all), `days` (0 = keep everything, which also lifts the item cap) and `dry_run` (count only; returns `removed`, `oldest`, `feeds`). It deletes older items (tombstoned so a refresh doesn't re-add them) except starred, hand-filed and video-group ones and sets those feeds' `retention_days`, so retention keeps them trimmed. The same dialog can start a history back-fill (`POST /history/backfill-all` with the chosen `feed_ids`).
  - Add a feed with **+ Add feed**. Change the interval per feed or in bulk in Settings → Feeds.
  - A ⚠ on a feed means it is failing; hover to see the error. Failing feeds back off automatically.
- **Dashboards:** start from a template (Threat landscape, Ransomware, APT, AI threats). Click any bar or point to see the matching articles. Counts are **article mentions, not confirmed incidents**.

## 2a. Feeds: settings, history and long-term storage

**Editing a feed.** Any of these opens the feed editor:
- hover a feed in the sidebar and click **⚙**;
- right-click or double-click the feed;
- with a feed selected, click **⚙ Feed settings** above the list.

**What the editor shows:**
- **Stats:** articles, unread, starred, last 30 days, oldest and newest.
- **Settings:** title, URL, folder, refresh interval, enabled.
- **History & storage:** keep articles, max articles, fetch older articles.
- **Health:** last and next fetch, errors.
- **Rules that apply:** for this feed, its folder, or all feeds.
- **Actions:** refresh now, mark all read, delete.

**Keeping articles longer:**
- **Global default:** Settings → Appearance & reading → *Keep articles for (days)*. Enter `0` to keep forever.
- **Per feed:** the editor's *Keep articles* (*Use global*, *Keep forever*, 30 days … 5 years, or custom) and *Max articles*.
- **Fetch filter:** retention also decides which old items a fetch accepts. A feed set to 90 days ignores 2-year-old items even when the feed contains them.
- **Always kept:** starred and manually filed articles, whatever the retention.

**Getting older articles.** A feed only lists its latest 10–50 items, so a reader only has the history it collected while subscribed. To reach further back, use **Fetch older articles**: per feed in the editor (*History & storage*), or for many feeds at once in *Settings → Feeds → 🗓️ Keep feeds…* with *Also fetch older items back to this date* ticked.

**Where it looks** (*Where to look*):
- **Automatic** (default) tries the site first, then the Internet Archive.
- **The site's own older pages:**
  - RFC 5005 archive links;
  - Blogger (`start-index`), Ghost (`/rss/2/`), WordPress (`?paged=N`) and a generic `?page=N`.
  - A paging style only counts when its page 2 really lists items page 1 doesn't, because many servers silently ignore unknown parameters.
- **Internet Archive** (`web.archive.org`): most public feeds have been saved there almost daily for years.
  - The app lists the saved copies of *this feed's own address*.
  - It walks back from where your history begins. Each copy it reads is the earliest one that still overlaps the previous copy, so nothing is missed and repeats are skipped.
  - Copies are fetched raw, so links point at the original articles.
  - This is what recovers last year's articles for news sites, FeedBurner feeds and blogs that can't be paged.

**Settings:**
- **How far back:** last 90 days to last 5 years, or as far as possible.
- **Effort:** the maximum number of pages or saved copies per feed. A high-volume site such as The Hacker News needs more copies to cover a year than a weekly blog.
- **Keep them:** sets the feed to *Keep forever* with no article limit and forgets articles retention removed earlier. Without it, the retention window decides which fetched items are stored.
- **Only feeds missing that history** (all feeds): skips feeds whose continuous history already reaches the chosen date. A gap of more than 60 days ends a feed's "continuous" history.

**Behaviour:**
- It runs in the background, one feed after another: 1 s between pages on a site, 1.5 s between archive requests, 1 s between feeds. A full run over many feeds can take an hour or more. **Stop** ends it after the current request.
- **Skipped:** scraped web pages (they only show the current page) and X feeds (bridges only show recent posts; the API charges per post read).
- **Source feeds:** YouTube (needs a Data API key), Hugging Face papers and Telegram use their own history methods.
- **Duplicates:** articles already stored (same link or GUID) are skipped.
- **Rules:** fetched articles get watchlist tagging, topics and rules (collections, stars). Webhooks, alerts, AI auto-summaries and social drafts never fire for history.
- **Limits:** only one history job runs at a time. The all-feeds run is admin-only and can be started twice a minute.

## 2b. Website scraping (sites without RSS)

1. Click **+ Add feed** and paste the page address (e.g. a vendor's blog or advisories page).
2. Eye of Sauron checks it:
   * **It's a feed:** you're subscribed as usual.
   * **The site has a feed somewhere** (declared in the page, or at a common path such as `/feed`): you get a **Subscribe** button for it. Prefer this, since real feeds are more reliable.
   * **No feed:** rules are **suggested automatically** from the page's repeating article blocks, with a **live preview** of what would be imported. Adjust if needed, then **Subscribe to scraped feed**.
3. Later, open the feed's ⚙ to edit the rules and **▶ Test rules** against the live page.

**Rules (web pages, CSS selectors)**

| Field | Example | Notes |
|---|---|---|
| Items * | `article`, `div.post-card`, `li.news-item` | One element per article |
| Title | `h2`, `.title` | Empty = the item's text |
| Link | `h2 a @href` | `@attr` reads an attribute; empty = first link in the item |
| Content | `p`, `.excerpt` | Becomes the article summary (sanitised) |
| Date | `time`, `.date` | `<time datetime>` is used automatically; "3 days ago", "Nov 9, 2026" etc. are recognised |
| Author / Image | `.author` / `img @src` | Optional |
| Date format | `%d %B %Y` | Only if a date isn't recognised automatically |

**JSON APIs:** choose *JSON API (dotted paths)*.
* `items` is the path to the list (`data.articles`).
* Fields are paths inside each item (`title`, `links[0].href`, `author.name`).
* Combine fields with `&` and quoted text: `title & " - " & source`.

**Tips**
* Find selectors with your browser: right-click an article → **Inspect**, then look for the repeating element and its class.
* **Pages built by JavaScript** show nothing to a scraper (the wizard tells you). Options:
  * look for the JSON API the page calls (DevTools → Network → Fetch/XHR) and scrape that in JSON mode;
  * or use an RSSHub/RSS-Bridge instance.
* **When a site changes its layout,** the feed shows ⚠ "Scraping rules matched no items". Edit the selectors and test again.
* **Be a good citizen:** keep refresh intervals reasonable (hourly or slower) and respect sites' terms of use.

## 2c. Layout: resizing panes, panels and widgets
* **Reader:**
  * Drag the edge between the sidebar and the article list, or between the list and the reader.
  * Limits: sidebar up to 440 px (a medium feed name fits), list up to 820 px (an average full headline fits on one line). The reader always keeps at least 360 px.
  * Double-click a handle to reset.
* **Dashboard side panel** (click any bar, slice, number or CVE): opens wide enough to read everything without sideways scrolling. Drag its left edge to make it narrower or wider; it remembers your width, and double-click resets.
* **Widgets** (Dashboards → **✎ Edit**):
  * Drag the **right edge** to change width, the **bottom edge** to change height, or the **corner** for both.
  * Free-form: the widget follows the pointer exactly, with no snapping, and a readout shows the size. It is saved when you let go: width as a percentage of the row (15–100%), height in pixels (120–1,400).
  * Widgets flow into rows, so widths of 40% + 60% fill a row exactly. On screens under 1,100 px, narrow widgets become half width and wide ones full width; under 860 px everything is full width.
  * Arrow keys on a focused handle: ±5% width, ±20 px height. Double-clicking the bottom or corner handle returns to automatic height.
  * The *Width* menu in the widget editor offers presets (quarter, third, half, two thirds, three quarters, full).
* **Dialogs** (settings, widget editor, share, feed editor) can be resized from their bottom-right corner.

## 2d. Using it from your phone
The interface is responsive: on a phone the sidebar becomes a ☰ menu and articles open full-screen.
* **At home (same Wi-Fi/LAN):**
  1. Browse to `http://<server-ip>:8080`, e.g. the Proxmox LXC/VM address, and log in.
  2. Use your browser's **Add to Home Screen** for an app-like icon.
* **Away from home (pick one; never expose plain HTTP to the internet):**
  1. **Tailscale or WireGuard (recommended):** install it on the server (or the Proxmox host) and on your phone, then browse to the server's tailnet address. Nothing is exposed publicly.
  2. **Cloudflare Tunnel + Cloudflare Access:** a public HTTPS hostname, protected by an SSO/one-time-PIN login *before* traffic reaches Eye of Sauron.
  3. **Your own reverse proxy:** Caddy, Traefik or Nginx Proxy Manager with HTTPS, plus Authelia or Authentik for MFA (see README → Reverse proxy & TLS). Set `EOS_ALLOWED_HOSTS` and `FORWARDED_ALLOW_IPS`.
* **Automations on the phone:** apps such as iOS Shortcuts, Tasker or HTTP Shortcuts can call the REST API with a token from **Settings → API tokens**. Use a `read` token for viewing; never put an admin session cookie into an app.
* **Native RSS reader apps:** Eye of Sauron speaks the Google Reader API, like FreshRSS.
  1. In the web app: **Settings → Mobile apps → Create app password**, named after the device (e.g. "iPhone – Reeder"). Copy the password; it's shown once.
  2. In the app: add an account of type **FreshRSS** (or **Google Reader API**).
     * Server: `https://your-host`. If the app wants the full address, use `https://your-host/api/greader.php`.
     * Username: your Eye of Sauron username. Password: the app password.
  3. Read/unread, stars, folders (shown as labels/folders), collections (labels) and subscriptions sync both ways. Adding a feed in the app subscribes it here too.

  **Compatibility:** Reeder, NetNewsWire, FeedMe, Read You, FocusReader, Fluent Reader and News+ support
  FreshRSS/Google Reader accounts. Eye of Sauron implements the same endpoints FreshRSS does, and they are
  covered by protocol tests; individual apps have not been tested yet. If an app misbehaves, note which call
  fails (the server log shows the path) and report it.

  **Security:**
  * Use one app password per device and revoke a lost phone's password in the same panel.
  * App passwords can only read and sync articles; they can't open settings, tokens, webhooks, social accounts or the REST API.
  * Prefer HTTPS or Tailscale: on plain HTTP the app password crosses your network unencrypted.
  * The **Fever** API is intentionally not offered: its MD5-based login is too weak.

## 2e-1. OT / ICS threat-actor tracking

**Built-in watchlists** (Settings → Watchlists & entities):

* **OT / ICS threat actors:** one entity per group, with every published cross-vendor name as an alias.
  * **Dragos names are entered in ALL CAPS** (`VOLTZITE`, `GRAPHITE`, `AZURITE`). ALL-CAPS aliases are case-sensitive, so they don't fire on the mineral or product names (graphite, azurite, xenotime, the Electrum wallet, Microsoft's Azurite emulator).
  * **The aliases are vendor-published overlaps** (Dragos, Microsoft, Mandiant, CrowdStrike, Secureworks, Unit 42, MITRE). An overlap means shared tradecraft, infrastructure or victims, not proof of a single identical team. Treat the counts as "coverage mentioning this cluster".
  * **Sandworm aliases** (Sandworm, APT44, Seashell Blizzard, Voodoo Bear) are attached to **ELECTRUM**, Dragos's ICS-effects cluster. **KAMACITE**, Dragos's access/enablement cluster, only matches its own name. The KPI and history widgets add both together as "Sandworm".
  * **Hacktivists** (CARR, Z-Pentest, Sector 16, TwoNet, Predatory Sparrow) are included because they increasingly touch HMIs and PLCs.
* **ICS / OT malware:** Stuxnet, Industroyer/CrashOverride, Industroyer2, TRITON/TRISIS, PIPEDREAM/INCONTROLLER, FrostyGoop, Fuxnet, IOCONTROL, COSMICENERGY, BlackEnergy, Havex, KillDisk, CaddyWiper, AcidRain/AcidPour, VPNFilter, NotPetya, Shamoon, EKANS, Kapeka, Irongate.
* **OT attack & compromise types:**
  * **On the plant:** PLC and HMI tampering, wipers, grid disruption, water tampering, safety-system (SIS) attacks, ICS protocol abuse.
  * **Getting in:** edge-device exploitation, living off the land, pre-positioning and espionage, ransomware, DDoS, supply chain, phishing and credential theft, internet-exposed ICS.

**Dashboard templates:** *OT threat actors — activity*, *OT attacks — locations & targets*, *OT attacks — types & malware*, *OT threat actors — history*.

**How the widgets work:**
* **Locations and attack types are co-mentions:** the countries, sectors, technologies and attack types named in the same article as an OT group. Read them as "reported in connection with", not as a verified victim list.
* **History** widgets span up to 10 years in monthly buckets. They are only as deep as your stored articles.

**Getting good history:**
1. Subscribe to OT-heavy sources:
   * Dragos (`https://www.dragos.com/blog.rss`);
   * Claroty Team82 disclosures;
   * Nozomi Networks;
   * Darktrace (`/blog/rss.xml`);
   * Google Threat Intelligence (`https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/`);
   * Unit 42, CrowdStrike (`/en-us/blog/feed`), Tenable, MITRE ATT&CK, ASD/ACSC.
2. Set those feeds to **Keep forever**.
3. Run **Fetch older articles** (per feed, or *Settings → Feeds → 🗓️ Keep feeds…* → *In folder: OT* with *Also fetch older items* ticked). It uses the site's own paging where it exists (Unit 42, the Microsoft Security Blog) and the Internet Archive otherwise.

**Sources that block automated readers** (CISA, SecurityWeek, Industrial Cyber and Forescout answered HTTP 403 at the time of writing) are left alone. Eye of Sauron does not disguise itself to get around such blocks.

**Updating aliases:** vendors rename and split groups regularly. Edit the entity in the watchlist; existing articles are re-indexed in the background.

## 2e-2. Threat Map

* **What it shows:** the 🌍 Threat Map tab draws a choropleth of the **countries** watchlist.
  * For each country it counts the articles in the chosen period that mention the country **and** the chosen threat.
  * **The threat** is the category (any entity from the layer's watchlists), or one actor/family picked from the category (`entity_ids: [id]`). It can be combined with one attack type (`require_entity_ids: [id]`).
  * **The same filter drives** the article/country/sector counts in the summary line (a `kpi` query) and the **Sectors targeted** list (breakdowns of `sectors` and `ot-sectors`, merged by name).
  * **Drill-down:** clicking a country adds it to `require_entity_ids`, then shows its sectors and articles. Clicking a sector shows its countries and articles.
  * **Actor picker:** a breakdown of the category's watchlists over the period, so it only lists actors that were active, with counts.
  * **Attack-type picker:** uses the `attack-types` watchlist, or `ot-attack-types` for the OT categories. Edit either under Settings → Watchlists.
  * It uses the same analytics endpoint as the dashboards (`POST /api/v1/analytics/query`, breakdown by watchlist), so filters and permissions behave the same.
* **Layers:**

  | Layer | Watchlists |
  |---|---|
  | Threat actors | `threat-actors`, `ot-threat-actors` |
  | Ransomware | `ransomware-groups` |
  | OT / ICS groups & malware | `ot-threat-actors`, `ics-malware` |
  | All OT / ICS coverage | + `ot-context` |
  | Malware | `malware-families` |
  | All | everything |

* **Colour scale:** five distinct hues on a log scale, so a few heavily covered countries don't wash out the rest: yellow `--tm-1` → orange → red → crimson → purple `--tm-5`, defined in `threatmap.css`.
  * The legend walks the counts to show the exact range each colour covers, so unused colours are skipped when counts are small.
  * The bar lists use the same scale.
* **Not on the map:** countries too small for the 1:110m outlines (Singapore, Hong Kong) and the EU appear in the ranked list as "not on map".
* **Map data:** `static/world-map.json` is Natural Earth geometry (public domain) via world-atlas (ISC), converted to SVG path strings. Licence text is in `THIRD_PARTY_NOTICES.md`.
  * The page loads it from its own origin and makes no third-party requests; the CSP is unchanged.
  * To regenerate it, convert world-atlas `countries-110m.json` with a TopoJSON-to-path script. The projection is equirectangular, latitude is clipped to 84°N–58°S, and longitudes are unwrapped across the antimeridian.
* **Vendor live maps** (Kaspersky, Check Point, Fortinet, Radware, Bitdefender, NETSCOUT, Digital Attack Map, Talos, SonicWall, Imperva, HTTPCS) are **links only**.
  * They offer no public APIs. Scraping their internal feeds would break their terms.
  * Embedding them would mean loosening the Content Security Policy and loading third-party trackers into the app.

## 2e. CVE tracking

**Where the data comes from.** Eye of Sauron does not scrape: it uses the official machine-readable sources.

| Source | What it adds |
|---|---|
| **NVD CVE API 2.0** (NIST) | Every CVE: description, CVSS (3.1, 4.0, 3.0 or 2.0, in that order of preference), CWE, affected vendors/products, NVD status, CISA KEV fields, SSVC "exploitation" |
| **CISA KEV** catalog | Known Exploited Vulnerabilities: date added, due date, **known ransomware use** |
| **MITRE CWE** catalog | Weakness names and the official **OWASP Top 10 2021 and 2025** mappings |

> The old CVE.org "data feeds" page is archived. NIST retired the NVD RSS and legacy JSON feeds in favour of this API, and MITRE's CWE site offers downloads but no RSS. For *news* about CVEs, keep your news feeds (e.g. the cvefeed.io feeds you already follow, and the CWE/CAPEC blog `https://medium.com/feed/@CWE_CAPEC`).

**Sync**
- **First run:** back-fills *Initial history* days, 30 by default (~1,000–2,500 CVEs per day).
- **Afterwards:** fetches changes every *Check for changes every* interval (2 h default).
- **KEV:** refreshed every 6 h.
- **CWE catalog:** refreshed weekly.
- **Controls:** Settings → **CVE tracking** shows progress, counts and errors, with *Sync now* and *Full refresh*.
- **Without an NVD API key:** NVD allows 5 requests per 30 s, and the first 30-day back-fill takes about 5 minutes. A free key in `EOS_NVD_API_KEY` makes it roughly 10× faster.

**MITRE ATT&CK** (Settings → Watchlists & entities → MITRE ATT&CK; `GET /attack/status`, `POST /attack/sync` (admin), `GET /attack/groups?q=`, `GET /attack/groups/{G-ID}`):
* **Source:** MITRE's official STIX 2.1 data (`github.com/mitre-attack/attack-stix-data`), Enterprise, ICS and Mobile.
  * The sync reads `index.json` first and downloads the bundles (~50 MB in all) only when a release changed. Bundle URLs are followed only inside that repository.
  * A release with fewer than 20 groups or 100 techniques is rejected and the current data kept.
* **Schedule:** setting `attack_sync` = `weekly` (default), `daily` or `off`; the scheduler checks when the interval has passed.
* **What it updates:**
  * Tables `attack_groups`, `attack_techniques`, `attack_group_techniques` (which techniques each group uses).
  * Watchlist *MITRE ATT&CK groups*: one entity per group, `Name (G0007)`, with MITRE's aliases. Single common words (e.g. *Silence*, element names like *Nickel*) are not used as stand-alone aliases.
  * Watchlist *MITRE ATT&CK techniques*: `Name (T1566)`, matching the ID, multi-word names and sub-techniques. Generic sub-technique names that are everyday phrases (*Social Media*, *Email Accounts*, *Artificial Intelligence*…) only count through their T-ID.
  * Rules `Auto: ATT&CK: <tactic> #2` (when the ATT&CK pack is installed): Enterprise technique names and IDs per tactic, capped at 100. ATT&CK's *Stealth* and *Defense Impairment* feed *Defense evasion*.
* **Managed entities:** entities ending in `(Gxxxx)` / `(Txxxx)` are replaced on each sync; anything else you add to those lists is kept. Deleting either watchlist stops the sync re-creating it.
* **Change report:** new, updated and removed groups and techniques, shown in the card.

**Building widgets** (Dashboards → ✎ Edit → + Add widget):
* **Data source:** *News articles*, *CVEs*, or *News articles + CVEs*. The combined source shows two KPIs side by side, one time chart with a "News articles" and a "CVEs" series, or a single newest-first list of both. Each side has its own filter block; clicking a series, number or date opens that side's articles or CVEs.
* **Chart style:** one picture picker for every style.
  * *Big number*.
  * *Over time:* lines, area, stacked area, bars (total), stacked bars, 100% stacked bars (shares of each period).
  * *Ranking:* horizontal bars, columns, donut, pie, table.
  * *Lists:* articles, a CVE table, or the combined list.
* **Combine filters:** **All must match** (AND, the default and the behaviour of existing widgets) or **Any can match** (OR across the filter boxes).
  * Exclusions, *only starred*, *only unread*, excluded CVE categories and the date window always apply.
  * Inside the *Mentions…*, *In collections…* and CVE *In categories…* boxes you can also choose *any of these* or *all of these* (at most 20, 20 and 10).
  * Drill-downs always narrow to the item you clicked, even in *any* mode.

**Dashboards**
- **Template:** *+ New dashboard… → CVE tracker*.
  - KPIs: new, critical and high this week; KEV additions.
  - Daily new CVEs stacked by severity.
  - Breakdowns: severity mix, categories, OWASP Top 10, top vendors, top CWEs.
  - Lists: edge-device critical/high, latest KEV additions, critical RCE, AI/ML vulnerabilities.
  - Trend: AI/ML vs edge vs RCE vs auth bypass.
- **Your own widgets:** *Edit → + Add widget → Data: CVEs*.
  - **Type:** KPI, trend, breakdown, or a sortable CVE list.
  - **Split by:** severity, category, OWASP 2021/2025, vendor, CWE, or KEV.
  - **Date used:** published, last modified, or added to KEV.
  - **Filters:** severity, minimum CVSS, categories (and exclusions), OWASP categories, vendors, CWEs, KEV only, exploited only (KEV or SSVC "active"), known ransomware use, keyword or CVE ID.
- **Interacting:**
  - Click a column header in a CVE list to sort (newest / CVSS / KEV date).
  - Click any bar, slice or point to open the matching CVEs, and *Load more* to page.
  - Click a CVE ID for the full record: vector, CWE names, OWASP, KEV dates, affected products, NVD/CVE.org links and references.
- **Severity colours** use a fixed status palette and are always shown with their text label.

**Categories** (Settings → CVE tracking → Categories)
- **Built-in (23):** edge firewalls/VPNs/gateways, edge routers/NAS/IoT, remote access & file transfer, email/collaboration servers, RCE, auth bypass, privilege escalation, memory corruption, SQLi, XSS, SSRF, path traversal, XXE, CSRF, deserialization, DoS, info disclosure, **AI/ML & LLM**, operating systems, browsers, virtualization, ICS/OT, WordPress.
- **When a CVE joins a category:** when **any** of these match:
  - a CWE ID;
  - a keyword (whole word, in the description);
  - a product pattern.
- **Product patterns** use lowercase letters and digits, written as `vendor`, `vendor:product`, `*:product` or `prefix*`. Examples: `fortinet:fortios`, `paloaltonetworks`, `*:pytorch`, `microsoft:windows*`.
- **Tips:**
  - Create a category for **your own estate** (your vendors and products) and filter dashboards to it.
  - Edits re-classify all stored CVEs in the background.

## 2f. YouTube, X, Telegram and Hugging Face Papers

Paste a link into **+ Add feed**. The type is detected automatically, or pick it in **Type** (needed for a bare `@handle`). A preview shows the latest items before you subscribe.

| Source | What to paste | Setup | History (“Fetch older articles”) |
|---|---|---|---|
| YouTube | channel URL, `@handle`, `/channel/UC…`, playlist URL | none; an API key adds durations, views and the back-catalogue | needs the API key; 50 videos per page |
| Hugging Face Daily Papers | `https://huggingface.co/papers` | none | one earlier day per page |
| X | `https://x.com/name` | a bridge or an API token (below) | not available |
| Telegram | `https://t.me/name` or `@name` | none for public channels; your account for the rest | pages back through the channel |

**YouTube API key (optional, free):**
1. In Google Cloud Console, create a project and enable **YouTube Data API v3**.
2. Under **Credentials**, create an **API key** and restrict it to that API.
3. Paste it in **Settings → Integrations → YouTube**. The free quota of 10,000 units a day is plenty.

With a key, the app also **falls back to the API** when YouTube's public feed fails. That feed sometimes answers 404 or 500 for channels that exist, then works again minutes later. Each fallback costs about 2 quota units per channel. Without a key, the error shows on the channel and the app simply retries later.

**Topic matching** (`app/topics.py`): videos match on the title only; other articles on the title or `ARTICLE_MIN_HITS` (2) matches within the first `ARTICLE_LEAD` (800) characters of the text after per-feed boilerplate is removed. **Watched:** setting `hide_watched` (default on) makes the Videos grid/shelves use `state=unwatched` unless a search is active; the ✓ Watched tab uses `state=watched`.

**Video search** (`q` on `/library/videos`, `/library/shelves`, topic counts): split into words (up to 8); each must match the title, channel name or description (`LIKE`, wildcards escaped), or the title with spaces removed. **Topic edits** trigger a background re-tag; `/library/meta` reports `reclassifying` while it runs.

**Playlists into groups:** dropping a playlist on a group, ＋, or Select → move, *moves* the playlist (table `video_group_playlists`, one group per playlist): it is hidden from the main list and listed in the group's `playlists`; `DELETE /library/groups/g:<id>/playlists/<feed>` moves it out; deleting the group returns it. A group's card counts its own and its playlists' videos; `GET /library/groups/g:<id>?scope=all` lists all of them in one page. Dragging a group onto a group still copies its videos. Order: `PUT /library/groups/order {"refs": [...]}` (table `video_group_order`; unlisted items follow by creation time). Bulk delete in Select mode calls `DELETE /library/groups/<ref>` per item.

**Keeping channels small:** in the 📺 Videos tab, **🗓 Keep…** keeps a channel, a playlist, the ticked channels or all channels to a time frame. Choose a preset (last day … 2 years), or **Custom…** for any number of days, weeks, months or years. Older videos are removed now and as they age. Starred videos and videos in your own groups always stay. With a YouTube API key, Keep… also starts a background history load (`keep_days` option of the back-fill job) that fetches the older videos inside the time frame, stopping at that date for channels, and clears automatic removal markers first (🗑-removed videos stay removed). API: `POST /library/keep {"feed_ids": [...], "days": N}` (0 = keep everything).

**X:** there is no free read access, and Eye of Sauron never scrapes x.com. Choose one or both of these in **Settings → Integrations → X**:
* **Bridge:** run [RSSHub](https://docs.rsshub.app/) (route `/twitter/user/:id`), Nitter or RSS-Bridge yourself, then enter its base URL (for example `http://rsshub:1200`).
  * A bridge on your LAN is allowed. This is the only private address the SSRF guard lets through, because only an admin can set it.
* **Official API:** paste an app-only bearer token from the X developer portal.
  * Reads are billed per post, so X API feeds refresh every 6 hours by default and only ask for posts newer than the last one seen.
  * Per feed, the editor can switch between bridge and API and include or exclude replies and reposts.

**Telegram:**
* **Public channels** with a web preview (open `t.me/s/name` in a browser to check) work without logging in.
* **Your account**, for channels without a preview and for private groups and channels you belong to:
  1. Create an app at <https://my.telegram.org/apps> and copy its **api_id** and **api_hash**.
  2. In **Settings → Integrations → Telegram**, enter them with your phone number and press **Send login code**.
  3. Enter the code Telegram sends you, and your 2FA password if you have one.
  4. Use **Add channels / groups from my account…** to subscribe to chats from a list.
* **Security:**
  * The session is equivalent to a logged-in device. It is stored encrypted and never shown again.
  * **Disconnect** logs it out on Telegram's side. You can also end it in Telegram → Settings → Devices.
  * Your phone number, login code and 2FA password are not stored.
* **Media:** photos and files from account-mode chats are marked [photo] / [media] and not downloaded. Web-preview posts show their images.

**📺 Videos, 👥 Accounts and topics:**
* **Videos** (top bar, formerly Library) opens **▤ By topic**: one shelf per topic, largest first, plus *Other (no topic matched)*. A video with several topics appears on each shelf. **Show all →** opens one topic as a grid; **▦ Grid** lists everything with the usual filters: channel, topics (the dropdown takes several, matched *any* or *all*; `topic_ids=3,7&topic_match=any|all` on `/library/videos` and `/accounts/posts`, up to 20, `0` = no topic), length (Shorts ≤3 min / 3–20 min / over 20 min), watched/starred and search.
* **Whole channels:**
  * Subscribing to a channel or playlist automatically loads its **entire back-catalogue** (up to 10,000 videos), with the API key set, and sets the feed to keep forever. It runs as a background history job; if another one is running, use **⇣ Load whole channel** later.
  * Quota: about 2 units per 50 videos, so a 2,000-video channel costs ~80 of the free 10,000 daily units.
  * Without a key only the channel's RSS feed (latest 15) is available. The app does not scrape YouTube pages for more.
* **Retention:** new YouTube feeds are created with keep-forever retention (`retention_days = 0`), because the global news retention would drop older uploads of channels that post rarely. Change it per channel in its ⚙ settings.
* **Channels:** `GET /library/meta` lists one entry per YouTube channel (`key` = channel id, or `feed:<id>` for videos without one) with the feeds its videos came from (channel, playlists, saved). Filter with `channels=UC…,UC…` (up to 50) on `/library/videos`, `/library/shelves` and `/library/topic-counts`; single videos saved without an API key are matched by channel name. Sort `added` = recently added.

**Favourite channels:** table `favorite_channels(channel_key, created_at)` (key = `UC…` or `feed:<id>`, like channel groups). `GET /library/meta` marks `channels[].favorite`; `POST /library/favorite-channels` sets or clears many at once and returns every favourite key. The frontend's channel filter has a pseudo-entry `fav` that `channelKeys()` expands into the favourite keys (none → a key that matches nothing), the same way `cg:<id>` expands a group. **Podcast player:** a single `#podDock` bar appended to `<body>` (outside `#podcastsView`), so view re-renders and tab switches don't destroy the `<audio>`; `show()` keeps one in-flight load (`this.showing`).

**Media feeds in the Reader sidebar:** `/sidebar` returns every folder plus `media_feeds` (YouTube / podcast feeds, no counts) separately from `feeds`, so rules, retention, health and the aggregate views keep ignoring them. `_article_filters` drops the `READER_ONLY` clause only when `feed_id` or `folder_id` is given.
* **Built-in topics v2:** a one-time upgrade (`sync_state.topics_version = 2`) merges extra keywords into the built-in topics and adds *AI & machine learning* and *Conferences & talks*, then re-tags everything. Topics you created are never changed.
* **Plain YouTube feeds:** an RSS subscription of `youtube.com/feeds/videos.xml?channel_id=|playlist_id=` (typical after an OPML import) is converted to a YouTube channel when you add that channel, and once at start-up (`sync_state.youtube_adopted_v1`): kind/source set, keep-forever, moved to the YouTube folder, article guids re-keyed to `yt:video:<id>` with video rows.
* **Videos vs articles:** Reader queries (`/articles`, `/articles/mark-read`, `/sidebar`) exclude `kind = 'youtube'` feeds; their videos are only in `/library/*` (single articles stay reachable by id for *Open in reader*). Folders holding only YouTube channels are hidden from the Articles tab sidebar. Mobile apps on the Articles tab API still see everything.
* **Back-fill size:** `max_pages` up to 1,000 (YouTube: 50 per page); entries are stored in batches of 500 (the live-fetch cap no longer truncates history).
* **Full article text** (`app/fulltext.py`): items whose text is under 700 characters (feed setting `full_text` = auto; `always`/`never` per feed) are completed from the article page: new items by a background worker, older ones on open (`POST /articles/{id}/fulltext`, 30/min). JSON-LD `articleBody`, else the densest paragraph container (noise like share bars and related posts removed, wrappers kept). One request per site every 3 s; a 401/403/429 or bot-check page leaves the site alone for 6 h and marks the article (`articles.fulltext = -1`). Entities, topics and rule tags are refreshed from the full text (no webhooks or alerts).
* **Refresh sections:** `POST /feeds/refresh?section=all|reader|videos|accounts`.
* **Removing and trimming:** `DELETE /library/videos/{id}` deletes a video and leaves a *manual* tombstone (`article_tombstones.manual = 1`, never expired, not cleared by keep-forever back-fills). `POST /library/keep {feed_ids, days}` sets those feeds' retention to `days` (0 = forever) and removes older videos now; retention never prunes starred, hand-filed or grouped videos. `DELETE /library/groups/p:<feed>` unsubscribes a playlist and deletes its videos.
* **Adding with options:** the add dialog creates the channel feed and/or one feed per playlist (`GET /library/youtube/playlists?channel_id=` via the Data API), applies the time frame with `/library/keep`, then one `/history/backfill-all` job with `since_days`.
* **Playlists & groups:** playlists (YouTube feeds with a `playlist_id`) are groups automatically (`p:<feed id>`, publishing order); your own groups live in `video_groups` / `video_group_items` (`g:<id>`, order added, up to 500 groups, 500 videos per request). Video rows carry `groups` for the badges. Deleting a group never deletes videos.
* **Topic counts:** `GET /library/topic-counts` returns videos per topic under the current channel, length, watched and search filters; the Videos tab shows these next to the topic names.
* **Several channels at once:** *+ Add channels or video* takes one link per line. Each is resolved and subscribed in turn (waiting out the lookup rate limit if needed), then one bulk history job loads their back-catalogues (`POST /history/backfill-all` with `feed_ids`).
* **Removing a channel:** pick it and click *🗑 Remove channel* (deletes the feed and its videos).
* **👥 Accounts:** social media accounts, shown like Videos (topic shelves or one grid; platform, account, unread/starred filters).
  * Add with `POST /accounts` (`{"input": "<profile link>", "platform": "linkedin"}`; platform only for bridge feed links). Posts: `GET /accounts/posts`, `GET /accounts/shelves`, `GET /accounts/meta`, `DELETE /accounts/{id}`.
  * **How each platform is followed:**
    * X and Telegram: through their existing sources.
    * Bluesky (`bsky.app/profile/<handle>/rss`), Mastodon/fediverse (`<server>/@user.rss`) and Reddit (`/user/<name>/submitted/.rss`, `/r/<sub>/.rss`): through their own public feeds.
    * LinkedIn, Instagram, Facebook, Threads and TikTok publish no feeds and forbid scraping. They are refused as profile links; paste a feed URL from a bridge you run (RSSHub, RSS-Bridge) and choose the platform. The app never scrapes them itself.
  * Accounts are normal feeds with `feeds.social_platform` set (schema v9), filed in a *Social Accounts* folder, and get topics, rules and collections like any article.
* **Single videos:**
  * Pasting a video link (`watch?v=`, `youtu.be/`, `/shorts/`, `/live/`) offers **Add just this video** or **Subscribe to the whole channel**.
  * Single videos are stored in the **Saved YouTube videos** feed, which is never polled and is excluded from bulk back-fills.
  * Details come from the Data API when a key is set (date, duration, views), otherwise from YouTube's public oEmbed endpoint (title, channel and thumbnail; the date shown is when you added it).
* Clicking a card opens the video on YouTube and marks it watched. **Open in reader** shows the description.
* **Topics…** edits the keyword topics, which tag every article from every source.
  * Matching is case-insensitive and whole-word on the title and text.
  * Sentences repeated across a feed's recent items (sponsor plugs, “follow us” footers) are ignored.
  * Changes re-tag everything in the background.

## 2g. AI summaries, digests and alerts

### Choosing an AI provider (Settings → AI)

| Provider | What you need | Notes |
|---|---|---|
| **Claude** (Anthropic) | An API key from the [Claude Console](https://console.anthropic.com/) | Default model `claude-opus-5-5`. Lower *effort* to `low` for cheaper summaries. Server-side refusal fallback is enabled automatically. |
| **OpenAI** | An API key and a model name | Uses Chat Completions. |

**Setup:**
1. Choose the provider, enter the key and model, and press **Save**.
2. Press **Test connection**.
3. Set a **Daily request limit**. It covers summaries, digests and alert explanations together; 0 turns AI off.

**Max input per article** caps how much text is sent per summary.

### Summaries
* **On demand:** press **✨ Summarize** in the reader toolbar. The result is cached; **Regenerate** asks again.
* **Automatically:** in **Settings → Rules**, tick **AI summary** on a rule. Each new matching article is summarised in the background, and summaries also feed digests.
* **Accuracy:** summaries are AI-generated. Always check the original before acting on them.

### Delivery channels (Settings → Alerts & digests)
Add a channel, then press **Test**:

* **Email:**
  * Your SMTP server, port 587 with STARTTLS or 465 with SSL/TLS; TLS is required.
  * Up to 10 recipients.
  * For Gmail or Microsoft 365, use an *app password*.
* **Telegram bot:**
  1. Create a bot with @BotFather and send it `/start` (or add it to a group or channel).
  2. Enter the bot token and the chat ID. Message @userinfobot to find your ID.
* **ntfy:**
  * Push notifications to your phone through [ntfy](https://ntfy.sh).
  * On the public ntfy.sh server anyone who knows the topic can read it, so use a long random topic or your own server.
* **Discord / Slack:** paste the channel's incoming-webhook URL.
* **Webhook:** reuse a signed webhook from Settings → Webhooks (for n8n, Home Assistant and so on).

### CVE alerts
**+ New CVE alert** offers these conditions:
* **Minimum CVSS:** 9.0 means critical.
* **Only KEV:** only CVEs in CISA's Known Exploited Vulnerabilities catalog.
* **Alert when added to KEV:** also fire when an existing CVE is added to KEV, whatever its score.
* **Filters:** categories (Edge devices, RCE, AI/ML…), vendors (`fortinet, ivanti, cisco`) and description keywords.

**How alerts are sent:**
* **Timing:** alerts are checked after every CVE sync (hourly by default).
* **Exactly once:** each CVE fires once per rule.
* **No flood from old CVEs:** only CVEs published or KEV-added after you create the rule can fire.
* **Batching:** more than three matches at once arrive as one combined message.
* **Preview 7 days** shows what a rule would have caught.

### Keyword-rule alerts
On any rule, choose **Instant alert to** and a channel. New matching articles (never imported history) are sent as they arrive, with the AI summary when **AI summary** is also ticked.

### Digests
**+ New digest** asks for:
* **Schedule:** weekdays, a time and your time zone (IANA name, e.g. `Europe/London`).
* **Articles:** folders, collections, topics, keywords, starred/unread only, and a maximum count.
* **New CVEs:** minimum CVSS, KEV only, categories. KEV entries are always included.
* **Write-up:** the **AI briefing** groups the items into themes and cites them as [n].
  * Add **Extra instructions** such as "focus on edge devices".
  * The numbered list with links is always included and comes from your database, not from the AI.
* **Skip when empty** and the channels to send to.

**Running a digest:**
* **Preview** builds one without sending; **Send now** sends immediately.
* **History** shows the last runs: *ok*, *partial* (AI or one channel failed), *failed* or *skipped*.

### Costs, privacy and safety
* **Privacy:** with a cloud provider, the article text you summarise and digest excerpts are sent to it. Use a local server to avoid that.
* **Prompt injection:** articles are untrusted.
  * The model is told to ignore instructions inside them, it has no tools, and its output is shown as plain text.
  * A malicious article can at worst produce a misleading summary, never run code or add links.
* **Cost:** the daily limit is a hard cap. Check **Usage** in Settings → AI.

## 4. Automation recipes

### 4.1 API tokens for automations
**Settings → API tokens** offers two scopes:

| Scope | Can do |
|---|---|
| `read` | Read articles, dashboards, CVEs and intelligence views |
| `write` | Also add feeds, folders, collections and rules |


```bash
H="Authorization: Bearer eos_xxx"; B=https://feeds.example.com/api/v1
# Unread articles in a collection, newest first
curl -s -H "$H" "$B/articles?unread=true&tag_id=1&limit=20"
# Everything that mentions a threat actor (any of its names), last 30 days
curl -s -H "$H" "$B/articles?entity_id=42&since=$(date -u -d '-30 days' +%s)"
# New advisories and guidance from government agencies and CERTs
curl -s -H "$H" "$B/articles?publication=government&limit=50"
```

### 4.4 Other automations
- **Rule webhooks** (`rule.matched` events) for triage into Slack, Discord, Teams or a SOAR.
- **Analytics API** for Grafana or reports (see README → API).
- **Daily digest:** a read token plus cron: `GET /articles?starred=true&since=<yesterday>` → email.

## 5. Administration

### 5.1 Configuration you should know
All environment variables are in [`.env.example`](../.env.example). The security-relevant ones:

| Variable | Recommendation |
|---|---|
| `EOS_SECRET_KEY_FILE` | Point at a Docker secret holding a Fernet key (`python -m app.cli gen-secret-key`). Without it the key lives in `/data/secret.key`, next to the database. |
| `EOS_ALLOWED_HOSTS` | Set it to your hostname(s) when using a reverse proxy. |
| `FORWARDED_ALLOW_IPS` | The proxy's IP, so throttling and logs see real client IPs. |
| `EOS_ALLOW_PRIVATE_FEEDS/WEBHOOKS` | Keep `false` unless you need LAN targets (they relax the SSRF guard). |
| `EOS_PRIVATE_ALLOWLIST` | Prefer this for one local service: comma-separated exact `host:port` pairs (e.g. `127.0.0.1:1200` for RSSHub) that may resolve to local/private addresses. Everything else stays blocked. |
| `EOS_COOKIE_SECURE` | `auto` is fine behind HTTPS. Force `true` if TLS terminates at a proxy that does not send `X-Forwarded-Proto`. |

### 5.2 Backups & restore
**What to back up**
- The `/data` volume: `eos.db` (plus `-wal`/`-shm` while running) and `secret.key` if you did not move it out.
- **Store the encryption key separately from database backups.** A backup with its key next to it is not protected.

**Online backup (consistent while running)**
```bash
docker compose exec eye-of-sauron python -c "import sqlite3; s=sqlite3.connect('/data/eos.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close()"
docker compose cp eye-of-sauron:/data/backup.db ./eye-of-sauron-$(date +%F).db && docker compose exec eye-of-sauron rm /data/backup.db
```
On Proxmox, `vzdump` snapshots of the CT/VM also work.

**Restore**
1. Stop the container.
2. Copy the `.db` into the volume as `eos.db`.
3. Make sure the same secret key is configured. Without it, stored credentials must be re-entered; everything else still works.
4. Start the container.

**Test a restore at least once a quarter.**

### 5.3 Upgrading
1. Read the [CHANGELOG](../CHANGELOG.md).
2. Back up (§5.2).
3. `git pull` (or copy the new release), then `docker compose up -d --build`.
4. Check the logs: `docker compose logs -f eye-of-sauron`. Migrations run automatically on start and are additive.

**Rollback:** stop the container, restore the pre-upgrade backup, and run the previous image tag.

### 5.4 Encryption key management
- **First move off the volume:**
  1. Run `docker compose exec eye-of-sauron cat /data/secret.key` and save the value as `./secrets/secret_key.txt` (chmod 600).
  2. Enable the `eos_secret_key` secret in `docker-compose.yml` and set `EOS_SECRET_KEY_FILE=/run/secrets/eos_secret_key`.
  3. Restart, then delete `/data/secret.key`.
- **Rotation** (yearly, or after suspected exposure):
  1. `docker compose run --rm eye-of-sauron python -m app.cli gen-secret-key` creates a new key.
  2. Put `NEW,OLD` (comma-separated) in the secret file and restart.
  3. `docker compose exec eye-of-sauron python -m app.cli rotate-secrets`
  4. Remove `OLD` from the file and restart.
- **Lost key:** start with a new key, then re-enter the webhook secrets and channel credentials. Posts, articles and settings are unaffected.

### 5.5 Credential hygiene
- Prefer **expiring API tokens** and revoke unused ones (Settings → API tokens shows *last used*).
- Rotate social-platform tokens when people leave or apps change. Use app passwords and dedicated apps, never personal passwords.
- Long-lived Meta tokens expire after about 60 days unless they are system-user tokens. A failed **Test** usually means an expired token.

### 5.6 Monitoring
- **Health:** `GET /healthz` (used by the Docker healthcheck).
- **Log lines to alert on:**
  - `Failed login attempt` (bursts);
  - `Too many failed attempts`;
  - `Social post … failed`;
  - `Unhandled error`;
  - `Stored credential cannot be decrypted` (a key mismatch after restore).

## 6. Maintenance schedule

| When | Task |
|---|---|
| **Monthly** | Glance at Settings → CVE tracking for sync errors (NVD outages happen; it resumes automatically). |
| **Monthly** | `pip-audit -r requirements.txt`, then rebuild the image to pick up base-image security patches (`docker compose build --pull && docker compose up -d`). Run `trivy image eye-of-sauron:<tag>` if installed. Review API tokens and delivery channels. |
| **Quarterly** | Test a backup restore. Bump pinned dependencies (§9), run the full test suite plus the pentest harness. Check Graph API / LinkedIn-Version deprecation notices. |
| **Yearly** | Rotate the encryption key and platform tokens. Review exposure (is SSO in front?). Re-read SECURITY.md's limitations. |

## 7. Incident response

Suspect a leaked token or a stolen backup?

1. **Kill access:** `docker compose exec eye-of-sauron python -m app.cli revoke-all` (all sessions and API tokens), then `docker compose exec -it eye-of-sauron python -m app.cli set-password admin`.
2. **Rotate credentials at the services** (delivery channels, AI provider keys, integration tokens, webhook secrets), then re-enter them in Eye of Sauron.
3. **Rotate the encryption key** if the database or a backup may have leaked (§5.4).
4. **Investigate:**
   - container logs show logins and failures with IPs;
   - delete unwanted posts on the platforms themselves.
6. Re-enable channels one at a time with **Test**.

## 8. Troubleshooting

### Feeds that keep failing

**Settings → Feeds** lists every feed with its status.
* **Bulk changes:** tick feeds (Shift+click for a range) to move them to a folder, set the refresh interval, enable, disable, fetch now, reset errors, check or delete them together (`POST /feeds/bulk`, up to 5,000 ids).
* **🩺 Check** (`POST /feeds/{id}/diagnose`) or **🩺 Troubleshoot failing feeds** (`POST /feeds/diagnose`, background; poll `GET /feeds/diagnose`) works out why a feed fails, in at most 14 requests per feed:
  1. DNS for the host, and its www/non-www twin.
  2. The feed address itself (status, redirects, content type, bot-protection markers).
  3. `https://` instead of `http://`, the redirect target, the address without its query.
  4. Feeds the site declares (`<link rel="alternate">`) on its home page, section page or the site it now redirects to, then common feed paths.
* **Verdicts:** *working again*, *moved* (with the working addresses, newest first, and how each was found), *blocked by bot protection*, *no longer a feed*, *gone (404/410)*, *domain gone*, *server error*, *unreachable*, *malformed*.
* **Use this address** changes the feed URL (which also clears its error counter) and fetches it once. The articles already stored are kept.
* The troubleshooter never changes the User-Agent, never solves or bypasses bot checks (Cloudflare, Akamai, proof-of-work walls, CAPTCHAs) and never scrapes around a block. A blocked feed is reported as blocked, with honest options.


| Symptom | Likely cause / fix |
|---|---|
| "Destination resolves to a private … address" | The SSRF guard blocked a LAN or loopback target. Expected for internal IPs; add the exact `host:port` to `EOS_PRIVATE_ALLOWLIST` (preferred), or set `EOS_ALLOW_PRIVATE_FEEDS/WEBHOOKS=true`, if intended. |
| Feed error "Rejected: XML entity declarations…" / "unsupported character encoding" | The feed uses DTD entities, UTF-7 or EBCDIC, which are refused for safety. Ask the publisher, or use another feed URL. |
| Feed error "Unsupported Content-Encoding" | The server ignored our `Accept-Encoding: gzip, deflate` and sent brotli/zstd. Rare; report it to the publisher. |
| Social **Test** fails with HTTP 401/403 | Token expired, or the app lacks write permission. X: regenerate the access token *after* enabling Read+Write. |
| Instagram "needs a media URL" | Instagram cannot post text-only. Provide a public `https://` image or MP4. |
| Instagram "media processing timed out" | Large or slow video. Retry later, or use a smaller MP4. |
| Post stuck as approved | The channel is disabled, the spacing interval has not passed, or the scheduler is off (`EOS_DISABLE_SCHEDULER`). |
| "Stored credential cannot be decrypted" | The configured key differs from the one used to encrypt (restore or key change). Configure the old key, or re-enter the credentials. |
| A scraped feed shows "matched no items" | The site changed its layout. Open ⚙ → Scraping rules, fix the selectors, ▶ Test rules. |
| "Too many requests - slow down" (429) | A rate limit on an expensive action (refresh, analytics, imports…). Wait the seconds given in Retry-After. |
| Banner "still using the generated first-run password" | Change the password in Settings → Account. The generated password file is then deleted automatically. |
| CVE sync error "NVD API HTTP 403/503" | NVD rate limit or outage. It retries automatically next cycle; add a free `EOS_NVD_API_KEY`. |
| CVE dashboards show 0 for OWASP | The CWE catalog has not loaded yet. Use *Full refresh* in Settings → CVE tracking. |
| "Fetch older articles": *does not offer older pages* | You chose *The site's own older pages only*, and the site ignores paging. Use *Automatic* or *Internet Archive only*. |
| "Fetch older articles": *no saved copies of this feed* | The Internet Archive never captured this feed address, or not in that period. Small or new blogs often aren't archived. The feed's own window is all there is. |
| "Fetch older articles": *rate-limiting* / *stopped early* | The Internet Archive asked us to slow down. What was fetched is kept; run it again later. Feeds whose history is already complete are skipped when *Only feeds missing that history* is on. |
| A busy feed didn't reach back a full year | Each saved copy covers only the few days the feed listed. Raise *Effort* (pages per feed) and run it again; it continues from where your history now begins. |
| Imported old articles disappeared | Retention removed them. Set those feeds (or the global setting) to *Keep forever* and re-import; duplicates are skipped. |
| Login says "Too many failed attempts" | Wait 15 min, or restart the container (throttling is in-memory). Check the logs for attack sources. |
| UI shows old version after upgrade | Hard-refresh. Assets are revalidated on every load, so a restart is normally enough. |

## 2h. Smart features: stories, entity pages, technique matrix, match feedback

All four are on by default and are controlled in **Settings → Appearance & reading → Smart features**.

| Feature | Where | Setting |
|---|---|---|
| Story grouping | 🧩 +n sources under an article in the list | *Group articles about the same story*, *How alike titles must be* |
| Entity pages | **Mentions** chips in the reader; ⓘ on a technique; matrix cells | *Show who and what an article mentions* |
| Technique matrix | ▦ next to ATT&CK / ATLAS in the sidebar | *Technique matrix period* (also in the matrix itself) |
| Everyday technique terms | technique tags on articles | *Recognise techniques by everyday terms* |
| Wrong technique | ✕ in a tactic tag's technique list / on reader chips | muted names listed under the card (✕ restores) |
| No ads in articles | every Reader article (feed text and page full text) | always on (no setting) |

Operations notes: changing a story setting regroups every stored article in the background (`stories_rev` in `sync_state`
records the setting the grouping was made with). A new built-in name list (`attack_sync.ALIAS_REV`) is applied once at start
without contacting MITRE. Muting a name re-indexes that one technique and removes rule-filed articles that only that name put
into a tactic collection; manually filed articles are never removed.

Ad clean-up operations notes: `feed_blocks` holds per-feed counts (hash of a block's text / of a campaign link's target; row `*` =
articles counted; counts are halved when a feed passes 400 counted articles so old campaigns fade). Stored articles are cleaned
once per rule revision (`declutter.REV` vs `sync_state.declutter_rev`) at start, in the background, in short transactions. It is
always on (no setting); removed blocks are not restored (restore from a backup, or *Refetch full text*).

## 2i. ATT&CK / ATLAS: how articles get their tactics

| Level | Where it comes from | How an article gets it |
|---|---|---|
| Tactic collection ("ATT&CK: Stealth") | `attack_tactics` (MITRE's matrix, synced) | it names a technique / sub-technique of the tactic, or the tactic itself |
| Technique ("Phishing (T1566)") | MITRE's release | its ID, its official name (when not an everyday phrase), an everyday term, or any of its sub-techniques |
| Sub-technique ("… (T1566.001)") | MITRE's release | its ID, its official name, or an everyday term of its own |

There are no keyword rules behind these collections any more (rules named "Auto: ATT&CK: …" / "Auto: ATLAS: …" are removed on
upgrade). To change what is recognised: ✕ on a technique (this article only, or mute a name everywhere), the *everyday terms*
switch in Settings → Appearance & reading → Smart features, or `ATTACK_TERMS` / `TACTIC_TERMS` in `app/attack_sync.py` and
`ATLAS_TERMS` in `app/collection_packs.py` (bump `ALIAS_REV`). When MITRE adds, renames or retires a tactic the collections follow
after the next sync; a retired tactic's collection is kept only if you filed into it by hand or pointed a rule of your own at it.
A rule of your own that targets a tactic collection keeps working, and the technique filing then never removes articles from it.
On the first start after the upgrade the app re-reads the current ATT&CK and ATLAS releases from MITRE's repositories once (to
store the tactic lists) and re-files every stored article.

Sub-techniques in context (`app/ttp_subs.py`): a second pass over articles that name a technique adds the sub-techniques their
text supports (official name unless it is one of `SKIP_NAMES`, plus `CONTEXT_TERMS`). It runs for new articles in the fetcher,
after full text is read, and for all articles whenever the entity index of a technique list was rebuilt. After editing the term
list bump `ttp_subs.REV`: the sub-technique entities are re-indexed once at the next start.

## 2j. Threat actors and related media

- **Catalogue:** `app/data/threat_actors.json` ships with the app. To refresh it, download MISP's
  `clusters/threat-actor.json` and export the ATLAS entities, then run `python tools/build_threat_actors.py <misp.json>
  <atlas-entities.json> <date>` (the vendor name lists are in that script) and restart: the watchlist *Threat actor catalog* is
  brought in line and re-indexed. Deleting that watchlist stops the app from re-creating it.
- **One actor, several names:** MITRE ATT&CK groups, the catalogue and your own lists (*Threat actors & APTs*, *Ransomware
  groups*, *OT / ICS threat actors*) are joined when the main name of one entry is a name of another; the MITRE name leads.
  Add your own aliases in your own lists - they join the same actor.
- **Related media:** scored in `app/related.py` (`BOOST`, `MIN_SCORE`, `MAX_SHARE`); switch it off with *Related videos and
  podcasts in the reader*.

## Upgrading from 1.0.x

**Upgrading from 1.0.x:** nothing to do. `FEEDWARDEN_*` environment variables are still read when the matching
`EOS_*` one is not set (rename them when convenient), `feedwarden.db` is renamed to `eos.db` on the first start, and
existing `fw_` API tokens keep working. Everyone signs in once more (the session cookie is now `eos_session`). Webhook
receivers must check `X-EOS-Signature` / `X-EOS-Timestamp` instead of the `X-Feedwarden-*` headers. The systemd unit
is now `deploy/eye-of-sauron.service` (user `eos`, paths `/opt/eye-of-sauron`, `/var/lib/eye-of-sauron`).
