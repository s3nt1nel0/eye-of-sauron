# First steps

This page takes you from a fresh install to a useful reading list in about ten minutes. It assumes the app is running
(see [Installation & deployment](../admins/01_Deployment.md)).

## 1. Sign in

Open the app (by default <http://localhost:8080>). The first start creates an `admin` account with a random password:

```bash
docker compose exec eye-of-sauron cat /data/initial_admin_password.txt
```

Sign in, then go to **⚙ Settings → Account** and set your own password (at least 12 characters; common passwords are
refused). The password file is deleted when you change it.

## 2. Add what you want to follow

The app starts empty on purpose: you decide what goes in.

- **One source:** click **＋** in the sidebar and paste a link. It recognises RSS / Atom feeds, plain websites (it finds
  their feed, or lets you pick the parts of the page to follow), YouTube channels and playlists, podcasts, Mastodon,
  Bluesky and Reddit accounts, Telegram channels and Hugging Face papers.
- **Many at once:** **Settings → Feeds → Import OPML**. A security-focused starter list ships in
  [`examples/cyber-starter.opml`](../../examples/cyber-starter.opml) — news, government advisories, vendor research.
- **Ready-made collections:** **Settings → Rules & auto-filing → Collection packs**. Packs sort articles into collections
  (Ransomware, Zero-days, APT, Supply chain…), MITRE ATT&CK / ATLAS tactics, OWASP Top 10 classes and CVE categories.

New sources are fetched within a minute. Articles are tagged with threat actors, techniques, CVEs, countries and sectors
as they arrive.

## 3. Find your way around

| Screen | What it's for |
|---|---|
| 📰 **Articles** | The reader. The sidebar holds your folders and collections, 📑 Reports & guidance and the views (Unread, Starred, Today). |
| 📊 **Dashboards** | Charts and tables: threat landscape, ransomware, APT activity, CVEs, OT/ICS. Click any bar to see the articles behind it. |
| 📺 **Videos** · 🎙 **Podcasts** · 👥 **Accounts** | Videos, episodes and social posts, each with its own filters and player. |
| 🌍 **Threat Map** | Where the threats in your news were reported, by country and sector. |

Useful from day one:

- **🎭 Threat actors** (above the article list): every actor your sources mention, with buttons for its articles, videos
  and podcast episodes.
- **▦** next to *ATT&CK* or *ATLAS* in the sidebar: the technique matrix, coloured by how often each technique is named.
- **▶ Videos / 🎙 Podcasts** in the reader: talks and episodes about the same actors, malware or CVEs as the article.
- Keyboard: `j` / `k` next / previous, `o` open the original, `s` star, `m` read / unread, `x` select, `r` refresh, `/` search, `d` dashboards.

## 4. Get told when it matters (optional)

**Settings → Alerts & digests**:

1. Add a **delivery channel** (email, Telegram, ntfy, Discord, Slack or a webhook) and send a test message.
2. Turn on **📑 New reports & guidance** to hear as soon as an agency or vendor publishes an advisory or a report.
3. Add a **CVE alert** (for example: CVSS 9+, or anything added to CISA KEV).
4. Create a **digest**: a morning briefing of the last 24 hours, with new reports, the threat actors in the news and
   critical CVEs. With an AI provider configured (Settings → AI — a local model works) it starts with a short write-up.

## 5. Read on your phone (optional)

The web app works on phones. For a native app, create an app password in **Settings → Mobile apps** and add a
*FreshRSS / Google Reader* account in Reeder, NetNewsWire, Read You, FocusReader or Fluent Reader.

Next: the [User guide](02_User_guide.md) covers every feature in detail.
