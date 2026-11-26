# User guide

*A simple, plain-language guide to what Eye of Sauron does and how to use it.*
*Written for version 1.4. This guide is updated with every release. For detailed setup, administration and troubleshooting, see the [administrator docs](../admins/02_Operations.md).*

---

## What is Eye of Sauron?

Eye of Sauron collects cyber-security news and intelligence from many places into **one screen**, so you don't have to visit dozens of websites every day.

It can follow:
- **news sites and blogs** (RSS feeds, or any website, even one without a feed);
- **YouTube channels**;
- **Telegram channels**;
- **X (Twitter) accounts**;
- **AI research papers** (Hugging Face);
- **official vulnerability (CVE) data** from NIST and CISA.

It then helps you **sort, track, summarise and share** what matters, and can **alert you** when something important happens.

It runs on your own computer or server ("self-hosted"), so your data stays with you.

---

## The eight screens

Use the buttons at the top to switch between them (on a phone, swipe the tab bar sideways; press **Ctrl+K** / **⌘K**
anywhere to jump straight to a saved site):

| Screen | What it's for |
|---|---|
| 📰 **Articles** | Reading articles, like an email inbox for news. Includes the 🎭 Threat actors filter. |
| 📊 **Dashboards** | Charts and numbers: what's trending, which threats are active, CVE tracking, MITRE ATT&CK / ATLAS matrices. |
| 📺 **Videos** | YouTube channels and saved videos as a library, split into categories by topic; videos play inside the app. |
| 📦 **Repos** | GitHub (and GitLab) projects you follow, plus gists, GitHub Docs pages and websites, in your own folders. Shown inside 🔗 Resources (📦 Repos) by default; it can be its own tab again. |
| 🔗 **Resources** | Your bookmarks: websites, training platforms, labs, cheat sheets and tools, sorted into topics, with a ★ Launchpad. |
| 👥 **Socials** | Posts from social media accounts you follow (Mastodon, Bluesky, Reddit, X through a bridge…). |
| 🎙 **Podcasts** | Podcast shows and episodes, with a built-in player. |
| 🌍 **Threat Map** | A world map of where threats in your news are happening, plus links to live attack maps. |

---

## 1. Getting started

1. **Log in.** On the very first start a password is created for you; your administrator (or the setup instructions) tells you where to find it.
2. **Change your password:** **⚙ Settings → Account**.
3. **Add your first sources:** press **+ Add feed**, or import a ready-made list in **Settings → Feeds → Import OPML** (a starter list of security news sites is included).

---

## 2. Adding things to follow

Press **+ Add feed** and paste one of these:

| You paste… | Eye of Sauron… |
|---|---|
| A website or blog address | Finds its feed automatically. If it has none, it offers to "scrape" the page and shows you a preview first. |
| A YouTube channel link or @handle | Follows the channel and brings in all of its videos (with a YouTube API key); new videos appear in the 📺 Videos tab. |
| A link to one YouTube video | Asks whether to add just that video to the Library or follow its whole channel. |
| A Telegram link (`t.me/…`) | Follows the channel. Private channels need your Telegram account connected (Settings → Integrations). |
| An X profile link | Follows the account. This needs a little setup first (Settings → Integrations → X). |
| `huggingface.co/papers` | Follows the daily AI research papers. |
| The senders of an email newsletter (choose Type → *Email newsletter*) | Reads those emails from your mailbox and turns each one into an article. Set the mailbox up first in Settings → Integrations → Email newsletters. |

You'll always see a **preview** before subscribing.

**Folders:** to keep things tidy, drag a feed onto a folder in the left sidebar.

**Moving to another Eye of Sauron (or a second copy):** use **Settings → Feeds → Export OPML** and **Import OPML**. The file remembers what each feed is, so article feeds, podcasts, YouTube channels and accounts land in their own tabs with their settings. Imported a file from an older version and podcasts or accounts ended up in Articles? Export again from the first app and import that file: the feeds move to the right tabs. Files from other feed readers work too; podcasts are recognised after their first update.

**On a tablet:** Settings and other windows fit the screen and scroll inside; the ⚙ next to a feed sits after its count.

**Changing many feeds at once:** open **Settings → Feeds** and tick the feeds you want (Shift+click ticks a range; the box at the top ticks every feed shown). A bar appears where you can move them to a folder, change how often they update, switch them on or off, fetch them now, check them, or delete them. The filter box and the *Failing* / *Disabled* menu help you find the right feeds first.

**Fixing broken feeds:** a feed with ⚠ has stopped working. In **Settings → Feeds**, click **🩺 Check** next to it, or **🩺 Troubleshoot failing feeds** to check them all. For each one you see what went wrong in plain words:
- **The feed has moved:** a working address was found. Click **Use this address** to switch; your old articles stay.
- **Working again:** the problem was temporary. Click **Reset & fetch now**.
- **The site blocks automated feed readers:** the site only lets web browsers in. Eye of Sauron won't pretend to be a browser, so look for the same news elsewhere or disable the feed.
- **The address no longer exists** / **the domain is gone:** the site stopped publishing it. Disable or delete the feed, or add the site as a website source.

**Feed settings:** click the **⚙** next to any feed to change its name, how often it updates and how far back it keeps items. The window adapts to what you follow: an article feed, a podcast show (episodes), a YouTube channel (videos) or an account (posts). **One setting covers history:** *Keep & fetch … from* is both how long items are kept and how far back **⇣ Load older …** goes. Make it longer and press Save: the app offers to load the older items straight away.

**Newsletters that only come by email (for example CISA's email updates):**
1. Create a mailbox just for newsletters (or use one you have) and subscribe it to the newsletters.
2. In **Settings → Integrations → Email newsletters**, enter the mail server (for Gmail: `imap.gmail.com`), your address and an *app password* (Gmail, Outlook.com and iCloud make you create one in your account's security settings; your normal password won't work).
3. Press **+ Add feed**, choose **Type → Email newsletter**, and type who the emails come from, for example `cisa.gov` (a whole domain) or `alerts@example.com`. Add `subject: Advisory` at the end to keep only emails whose subject contains that word.

Eye of Sauron only *reads* the mailbox: it never marks emails as read, moves or deletes them. Tracking pixels are removed.

**Feeds in another language (CERT-FR, JPCERT…):** in the feed's **⚙** settings, tick **Translate titles**. Your AI provider (Settings → AI) translates new titles, and the original stays visible under the translated one. Untick it to get the original titles back.

**How often feeds are checked:** feeds that use the default interval learn their own pace. A blog that posts once a week is checked every few hours instead of every hour (never more often than your default, at most every 12 hours). You can turn this off in **Settings → Appearance & reading → Check quiet feeds less often**; a feed with its own interval always keeps it.

---

## 3. Reading

- **Sidebar views:** *Unread*, *Read*, *Starred* and *Today*, plus your folders and feeds.
- **How much your feeds keep:** in **Settings → Feeds**, press **🗓️ Keep feeds…**. Choose which feeds — *Article feeds*, *Podcasts*, *YouTube channels*, *Accounts* or *All feeds together* (it starts on the tab you are looking at) — optionally one folder, and how far back to keep (for example *Last year*, *Everything*, or *Custom…* 18 months). Before anything is removed it tells you how many items will go, and the feeds stay trimmed to that from then on. Tick **Also fetch older items back to this date** to fill in history at the same time (it runs in the background; you can stop it). Starred items, items you filed by hand and videos in your video groups always stay.
- **Dates** are shown day first: dd/mm/yyyy (for example 13/11/2026), with times in 24-hour format.
- **Read articles move to Read:** once you have read an article it leaves your feeds, folders and collections (it stays on screen until you open the next one) and waits in **Read** at the top of the sidebar. Changed your mind? Mark it unread in **Read** and it goes back to its feeds and collections. To keep read articles in place instead, untick **Hide read articles** in **Settings → Appearance & reading**.
- **Opening an article:** click an article in the middle list to read it on the right.
- **Article buttons:**
  - **★ Star** keeps it forever and finds it later.
  - **Mark read / unread**.
  - **📁 File into…** puts it in a *collection* (e.g. "Ransomware").
  - **📣 Share** turns it into social posts.
  - **✨ Summarize** gets a short AI summary.
  - **🔖 Save…** keeps it for later: send it to **Wallabag** or **Linkwarden**, create a note in **Obsidian**, or **download it as a Markdown file**. Set the services up in **Settings → Integrations → Read later** (Markdown download always works).
  - **Open original ↗** goes to the website.
- **In the list** you see each site's little logo and how long an article takes to read ("4 min"). Both can be switched off in **Settings → Appearance & reading**.
- **Highlight words:** in **Settings → Appearance & reading → Highlight these words**, write the names you care about (your company, products you use, suppliers), one per line. They are marked in yellow in the list and in articles.
- **Pictures and privacy:** pictures in articles load through your Eye of Sauron server, so the websites and their trackers don't see your device or IP address. You can switch this off (**Load images through this server**) or hide pictures altogether (**Load remote images**).
- **Search:** use the search box at the top. It searches titles and full text.
- **Pick your own dates:** in the date menu above the list choose **📅 Custom range…** and set *From* and *To* (or use a quick choice such as *Last 30 days*). Leave one end empty for "everything since" or "everything until" a date. **✎** next to the menu changes the dates. Videos and Podcasts have it at the bottom of their **Sort** menu (**✕ Clear custom range** removes it; Sort is outlined while a range is on), Accounts has a **📅** button in its toolbar, Dashboards have **📅 Custom range…** in *Range* (it applies to every widget), and the Threat Map has it in *Period*.
- **A whole collection folder at once:** in **Collections**, click a folder's name (for example **ATT&CK**, **ATLAS**, **AI** or **CVEs**) to see every article in all of its collections together, with the same filters and sorting as any other list. The small **▾** arrow still opens and closes the folder.
- **Layout:** drag the edges between the three panes to make them wider or narrower.
- **Several at once:** click **☑ Select** above the list (or Ctrl/Cmd+click an article, or press `x`), tick the articles you want, then use the bar that appears: **Read**, **Unread**, **Star**, **Unstar**, or **📁 Collection…** to file them or take them out of a collection. Shift+click ticks everything between two articles, **Select all** ticks every article loaded in the list, and **Done** (or `Esc`) leaves select mode.

**Articles that show only a sentence or two:** some sites send just a summary in their feed. Eye of Sauron then reads the full article from the site, automatically when you open it, or with **📄 Full article**. A few sites don't allow feed readers; for those you'll see "Only a summary is available" and can use **Open original ↗**. You can switch this per feed in its ⚙ settings (*Full article text*).

**Keyboard shortcuts:**

| Key | Action |
|---|---|
| `j` / `k` | next / previous article |
| `s` | star |
| `m` | read / unread |
| `x` | select / unselect the article (starts select mode); `Esc` leaves it |
| `o` | open the original |
| `/` | search |
| `d` | switch between Reader and Dashboards |

---

## 4. Letting it sort for you (rules)

A **rule** watches new articles for words you choose and does something automatically.

**Example:** *"If an article mentions **LockBit** or **ransomware**, file it under **Ransomware** and star it."*

Set rules up in **Settings → Rules**. A rule can:
- file the article into a collection;
- star it, or mark it read;
- send it somewhere automatically (a webhook, a social media draft, or an **instant alert** to your phone or email);
- **summarise it with AI**.

**Ready-made collections:** in **Settings → Rules → Ready-made collections**, tick the packs you want and click **Install / update**. Installed packs can be ticked again to add rules from newer versions, or **removed** (their collections and rules are deleted; the articles stay). Existing articles are filed into them too, which takes a minute or two. The packs are:
- **Core threats:** ransomware, zero-days, nation-state groups, phishing, breaches, malware, supply chain.
- **OT / ICS:** attacks on industrial systems, OT vulnerabilities, AI in OT, and OT defence, forensics & engineering.
- **Security practice:** offensive security (pentesting, red teaming), defensive security (SOC, incident response, detection, threat hunting), threat intelligence, and *Threat advisories*: advisories, alerts, guidance and threat reports from governments, CERTs, vendors and research teams (the **Advisories** folder plus matching headlines from other feeds), without CVE listings.
- **AI:** offensive AI, defensive AI, AI security (attacks on AI systems) and AI news & tools.
- **MITRE ATT&CK tactics:** one collection per stage of an attack, from reconnaissance to impact.
- **OWASP Top 10 (2025):** one collection per category.
- **CVEs:** articles that mention a CVE, by severity (Critical, High, Medium, Low), whether it is actively exploited or used by ransomware (CISA's KEV list), and the kind of flaw or target the OWASP list doesn't cover: remote code execution, privilege escalation, memory corruption, denial of service, edge devices & remote access, operating systems & browsers, virtualization & cloud, email servers, and AI/ML. They need the CVE data (the CVE tab downloads it).
- **Blockchain & crypto:** crypto hacks and thefts, and crypto news. Everything in a folder called **Blockchain & Crypto** counts as crypto news, and its incident write-ups (hacks, exploits, drains) are filed under hacks too.

Grouped collections, such as *ATT&CK: …*, appear under one heading in the sidebar. Click the heading to open or close the group.

**Smarter rules:** a rule can also require a word from a **second list**, for example *OT words* **and** *attack words*. Tick **Main words must be in the title** to keep it focused on articles that are really about the topic. Or set **Search in → Title and opening lines**: the rule then looks at the headline and the first few sentences only, so a word an article mentions in passing further down doesn't file it. The ready-made threat collections (APT & Nation-State, Ransomware, Malware, Phishing…) work this way. For example, an article about Nvidia's CEO that mentions a "Chinese espionage case" deep in the text is no longer filed under APT & Nation-State. If you changed one of those rules yourself, your version is kept. It can also match only articles that mention a CVE of a chosen **severity** or **OWASP category**. If you leave the words empty, the rule matches everything in the folder or feed you chose.

**Topics** work automatically in the background. Every article and video is tagged with topics such as *Malware*, *Cloud* or *AI security*. You can edit topics in **Videos → Topics…**.

---

## 5. Dashboards and CVE tracking

**📊 Dashboards** show what's going on at a glance: trending threat actors, ransomware groups, countries, topics, and more.
- **Drill down:** click any bar, slice or number to see the articles behind it.
- **Templates:** start from a ready-made template (*Threat landscape*, *Ransomware tracker*, *CVE tracker*…).
- **Customise:** click **✎ Edit**, then **+ Add widget**.
  - **Data:** *news articles*, *CVEs*, or *news articles + CVEs* side by side (two numbers, two lines on one chart, or one list of the latest of both).
  - **Chart style:** pick from pictures: big number, lines, area, stacked area, bars, stacked bars, 100% stacked, horizontal bars, columns, donut, pie, table or list.
  - **Filters:** choose **All must match** (narrow) or **Any can match** (broad, a partial match is enough). Boxes such as *Mentions…* and *In collections…* also let you pick *any of these* or *all of these*.
  - **Size:** drag a widget's right edge or bottom edge. It takes exactly the size you drag to, and keeps it when you let go. The *Width* menu in the editor has quick presets too.

**CVE tracking** downloads official vulnerability data (from NIST and CISA's "actively exploited" list) and lets you:
- see how many new CVEs there are, and how severe;
- filter by **device type**, such as edge devices (firewalls and VPNs);
- filter by **weakness type**, such as remote code execution, the OWASP Top 10 or AI;
- see which vulnerabilities are **actively exploited**.

Turn it on in **Settings → CVE tracking**.

---

### Tracking OT / ICS threat actors

Eye of Sauron knows the industrial-control-system threat groups and **all their aliases**.

**Why aliases matter:** security companies give the same group different names.
- **VOLTZITE** (Dragos) is **Volt Typhoon** (Microsoft), **Vanguard Panda** (CrowdStrike) and **UNC3236** (Mandiant).
- **ELECTRUM** is Dragos's name for **Sandworm** / **APT44**.
- **BAUXITE** is **CyberAv3ngers** / **Storm-0784**.

An article counts for the group whichever name it uses.

**Using the OT dashboards:** create them from **Dashboards → + New dashboard… → template**:

| Dashboard | Shows |
|---|---|
| **OT threat actors — activity** | Who is active right now, trends per group, latest coverage |
| **OT attacks — locations & targets** | Countries, sectors and technologies mentioned alongside each group |
| **OT attacks — types & malware** | How they attack (wipers, PLC/HMI tampering, edge exploitation…) and which ICS malware appears |
| **OT threat actors — history** | Month-by-month history over the years, with a timeline per group |

**Editing the lists:** see or edit the groups and aliases in **Settings → Watchlists & entities → OT / ICS threat actors**. For example, add a new alias the day a vendor renames a group.

**Better history:** follow OT-focused sources (Dragos, Claroty, Nozomi, Darktrace, Unit 42, Google Threat Intelligence…), set them to **Keep forever**, and use **⇣ Load older articles**.

---

### MITRE ATT&CK threat groups and techniques

Eye of Sauron keeps a copy of **MITRE ATT&CK**, the public catalogue of threat groups (APT28, Lazarus Group…) and the techniques they use.
- **Two watchlists:** *MITRE ATT&CK groups* (every group with all its aliases, e.g. *APT28 = Fancy Bear = Forest Blizzard*) and *MITRE ATT&CK techniques*. Dashboards and filters can use both like any watchlist.
- **Always up to date:** it checks MITRE for a new release **weekly** by default. You can change this to daily or off, or click **⟳ Sync now**, in **Settings → Watchlists & entities → MITRE ATT&CK**.
- **What changed:** the same card lists new, updated and removed groups and techniques after each update.
- **Looking a group up:** the card has a search box. Open a group to see its aliases and the techniques MITRE has seen it use.
- **ATT&CK collections:** new technique names are added to the *ATT&CK: …* collections automatically.

### OT sectors

The **OT sectors & industries** dashboard shows which industries appear in OT/ICS news, and which groups are reported against each one:
- **Industries covered:** energy and the grid, water, manufacturing, oil & gas, transport, and more.
- **Example question it answers:** "Who is going after water utilities?"


### Time ranges and rearranging

**Time ranges:** every widget has its own period: use the small menu in the widget's corner, and it is saved. To compare everything over the same period for a moment, pick a period in **Range** at the top: a green banner shows that all widgets are synced, and **↺ Reset** puts each widget back on its own range (reloading the page does too).

**Rearranging:** press **✎ Edit**, then drag a widget by its title onto another widget to move it, or drag a dashboard's tab onto another tab to change their order.

---

## 6. The Threat Map

**🌍 Threat Map** colours each country by how many of your articles mention it together with a threat.

Use the menus at the top, from left to right:

1. **Category:** threat actors, ransomware, OT/ICS groups, all OT news, malware, or everything.
2. **Actor / family** (optional): pick one group, such as *ShinyHunters*, *Qilin* or *VOLTZITE*. Only groups mentioned in the chosen period are listed, with their article counts.
3. **Attack type** (optional): pick one, such as *Ransomware*, *Data breach*, *DDoS* or *Phishing*.
4. **Period:** from 7 days to all time.

The line under the menus says what you're looking at, for example: *"Qilin — 8 articles in the last 90 days, mentioning 9 countries and 12 sectors."* **Clear focus** goes back to the whole category.

**Exploring:**
- **Countries** (map and list) and **Sectors targeted** (list) show counts for your selection.
- **Click a country** to see which sectors were mentioned there, plus the articles.
- **Click a sector** to see which countries were mentioned with it, plus the articles.
- **Click an article** to read it.

**What the colours mean:** yellow = a few articles, then orange, red, crimson and **purple = the most**. Grey means none. The legend shows the exact numbers for each colour.

**Keep in mind:** the map shows what your sources are *reporting*, not live attack traffic. A country counts when it is mentioned in the same article as the threat. That article might name it as a victim, or only say who was blamed, so read the articles before drawing conclusions.

**Live attack maps:** for vendor sensor telemetry, use the cards below the map. They open the vendors' own live maps (Kaspersky, Check Point, Fortinet and others) in a new tab.

---

## 7. Videos and social accounts

**📺 Videos** shows your YouTube videos, **split into categories by topic** (Malware analysis, Cloud, Bug bounty…). Each topic is a shelf; **Show all →** opens the whole topic, and **▦ Grid** shows everything in one grid instead.
- **Add channels or a video:** **+ Add channels or video**. Paste one link per line to add several channels at once.
- **Remove a channel:** pick it in the channel menu, then click **🗑 Remove channel**. Its videos are deleted too.
  - A **channel** link brings in **all of that channel's videos**, not just the newest ones, plus new uploads as they appear. This needs a free YouTube API key (see the tip); without one, YouTube only offers the latest 15.
  - A link to **one video** asks whether to add **just that video** or follow its whole channel. Single videos go into *Saved YouTube videos*.
  - **⇣ Load whole channel** (shown when you pick a channel) fetches the rest of an older channel.
- **Filters:** channels (tick **several**; a channel includes its playlists and the single videos you saved from it), topics (the topic dropdown lets you tick **several topics** and choose *any of these* or *all of these*; the topic buttons pick one), length (short / medium / long), watched or starred, and search.
- **Sorting:** by **date added** (newest first is the default, so what you just added comes first, or oldest first), by **date published** on YouTube (newest or oldest first), most viewed, longest or shortest.
- **Only 15 videos from a channel or playlist?** YouTube's public feed lists only the 15 newest. Add a free YouTube Data API key in **Settings → Integrations** (the page explains how): the app then offers to load **every** video of all your channels and playlists. Later, use **⇣ Load whole channel** (pick the channel) or **⇣ Load whole playlist** (open the playlist).
- **Videos and articles are kept apart:** YouTube videos appear only in **📺 Videos**, never in the Articles tab's lists. Pasting a YouTube channel's feed address into + Add feed adds it as a channel.
- **New uploads arrive automatically:** each channel is checked every hour (change it per channel in its ⚙ settings), so new videos show up without doing anything. The "latest 15" limit only affects older videos when you first add a channel.
- **No size limit:** with an API key, a channel or playlist loads completely, however big (up to 50,000 videos per load).
- **⟳ in Videos** checks your channels for new videos; **+ Add feed** is only in the Articles tab. Channels are kept together in a **YouTube** folder in the Articles tab.
- **Adding:** in **+ Add channels or video** choose what to add from each channel (**its videos**, **its playlists**, or **both**) and **how far back** (latest only, last day/week/month, 3 or 6 months, a year, 2 years, or everything). With one channel and playlists chosen, you pick which of its playlists to add.
- **Playlists inside groups:** dropping a playlist on a group *moves* it there: it disappears from the main page and appears as a card inside the group. **↩ Move out of group** brings it back. Inside a group, switch between **🗂 Playlists as cards** and **▦ All videos** (everything in one grid).
- **Your own order:** drag cards on the Playlists & groups page (or inside a group) to reorder them; they stay where you put them. Drop on the *middle* of a group to move a playlist in, on a card's *edge* to place it before/after.
- **Starred videos:** press ☆ on a video, then pick **★ Starred** in the **Status** drop-down (it shows how many you have).
- **Cleaning up:** **☑ Select** → tick playlists/groups → **🗑 Delete…**.
- **Adding just a playlist:** paste the playlist link (or the link of a video you're watching in it) into **+ Add channels or video**; only that playlist is added, not the channel.
- **Watched videos:** press **✓** on a video (or play it) and it leaves your library view; pick **✓ Watched** in the **Status** drop-down to see them, and press **↩** there to bring one back. Turn this off with *Hide watched videos* in Settings → Appearance & reading.
- **Videos toolbar:** **＋** (left), search, **Channels ▾**, **Topics ▾**, **Length**, **Status** (*all / Unwatched / ✓ Watched / ★ Starred*), **Sort** (date added, published, views, length, and at the bottom **🕘 Last 24 hours** - only videos published in the past day, counted from now each time the list loads - and **📅 Custom range…** to show only videos published between two dates; **✕ Show any date** / **✕ Clear custom range** removes either; the Sort box is outlined while one is on), **View** (Grid or List), then **🏷️ By topic** and **🗂️ Playlists & groups**. These two switch on and off: click one to open it, click it again to go back to the view you were in (all videos or By topic). Switching between them, and turning **🏷️ Tags** on or off, is instant: each view is kept in memory and quietly refreshed in the background.
- **Sort** offers date added, published date, views and length (the topic view is the 🏷 By topic tab).
- **Adding a playlist always brings every video in it.** The retention choice is for a channel's videos only. Ticking just *Follow the channel* brings its new uploads from now on, not its old videos.
- **🏷 By topic** (next to All videos) shows a shelf per topic. *Show all →* on a shelf opens that topic; click **By topic** again to get the shelves back.
- **Every video has a topic.** If no topic's keywords fit a video, it gets its channel's usual topic; if the channel has none, it goes under **General**.
- **＋ (top left, in Articles)** adds a feed. Pick **Keep** to say how long its articles stay, and tick **Also download older items** to fetch older ones from that period too. **＋ in the Videos toolbar** adds channels, playlists and videos.
- **Your own keep time frame:** when adding a feed, podcast, account or YouTube channel, choose **Custom…** under *Keep* and type a number with *days*, *weeks*, *months* or *years* (for example *18 months*). The app shows what that means next to it ("= 540 days"). Anything from 1 day to 100 years works.
- **See a channel's or feed's retention:** Videos → Channels ▾ → ⚙ shows *Retention… (1 year)*; Articles → ⚙ next to a feed shows *Retention* at the top.
- **Topics ▾ → ✎ Edit all** lists every topic with its color and keywords to edit in one place.
- **Retention** is shown in days with years/months, e.g. *365 days (1 year)*; typing a custom number shows what it means (*= 3 years*).
- **Socials** (the 👥 tab, called *Accounts* before 2026-11-23): **＋** adds anything - paste profile links, subreddits (reddit.com/r/homelab) or single posts, one per line; the dialog shows what each line is. Use **Accounts ▾ → ⚙** for an account's settings (retention, refresh, name…) or to remove it, and **Platforms ▾ → ⚙** to change or remove all accounts of a platform.
- **Subreddits** bring in every new post, checked every 30 minutes.
- **Single posts** (a link to one post) are shown so you can read them right here: who wrote it (name, handle, picture), when, the post's picture and its text. Long posts start as a short preview - press **Show more ▾** (above the text) for all of it. While you read, **Show less ▴** stays at the top of the screen, just under the search bar, so you can fold the post from anywhere in it.
- **"⚠ LinkedIn only shows this post to signed-in members"** on a card means the site showed its sign-in page instead of the post (or the post was deleted). The card is called *LinkedIn post* and shows the day it was posted. Nothing is ever done to get around that: open the post, copy its text and press **✎ Paste the post's text**. **↻** tries the site again.
- **No duplicates:** a post that's already in Socials - one you saved, or one from an account you follow - can't be added again, even from a different-looking link (twitter.com instead of x.com, a LinkedIn share link…). The ＋ window marks it **✓ already in Socials** and skips it. If you deleted a post, you can add it again.
- **🏷️ Tags** shows every post's topics or folds them behind each post's 🏷️ button. Switching it just changes the tags in place - the page doesn't reload or jump.
- **Delete a post:** press **🗑** under it (on the cards and in ☰ Read). It asks first. A post from an account you follow won't come back when the account is checked again; a post you saved yourself can be added again by pasting its link. To remove all of an account's posts, remove the account (**Accounts ▾ → ⚙ → 🗑 Remove**).
- **Pictures:** click a saved post's picture to see it big, right here (it doesn't open the post's site). Click the picture again for its actual size; press Esc, ✕ or click the dark area to close. **Open post ↗** is still there when you want the original.
- **Make posts wider or narrower:** point at a post's right edge until a small bar appears, then drag it. All posts in the view change together (the ☰ Read view has its own width). Your width is remembered; double-click the edge to go back to the automatic width.
- **＋ Follow** under a saved post adds its author to your accounts. If that isn't possible - LinkedIn has no feed for personal profiles, and X needs your bridge or an X API token - pressing it tells you why.
- Before you add a post, the ＋ window shows which outside site each post link will ask (for example *publish.twitter.com* for X, *www.linkedin.com* for LinkedIn). The app only uses official or public ways and never logs in for you.
- If a site only hands over the start of a post (X does this for long posts), the card says so: press **✎ Paste the full text**, copy the post's text from the site, paste it and save. **✎** on any saved post does the same, and **↻** reads the post again from the site (text you pasted is kept).
- **Socials → ☰ Read** shows whole posts one after another as you scroll. Click a Reddit post's title (or 💬 Thread) to read its comments; photos and videos show in the post.
- **Books → ⇩ Export** saves your list as a Markdown table or a CSV for a spreadsheet. **View: By topic** groups books by topic. A book with missing details or a wrong title: **✎** to edit it, **↻** to look it up again later.
- **Follow a channel from one of its videos:** click the channel name under the video (it shows ＋ when you don't follow it yet) and pick what to download. Clicking a channel you already follow shows its videos.
- **Channel groups:** in Videos → Channels ▾ tick channels → *🗂 Group these…* (or ⚙ → *Add to group…*). Pick the group at the top of the list to see all its channels together.
- **MITRE ATLAS (AI attacks):** Articles → the **ATLAS: …** collections sort articles by MITRE ATLAS tactic - attacks on and with AI (prompt injection, jailbreaks, poisoned models, deepfakes, AI-written malware…). They update themselves from MITRE's data like the ATT&CK ones (Settings → Watchlists → MITRE ATT&CK shows the ATLAS release; **⟳ Sync now** checks both).
- **Techniques on articles:** a tactic tag such as **ATT&CK: Execution 2 ▾** shows how many techniques of that tactic the article names. **Hover** to read them, **click** for a list - click a technique there to see every article that names it, or ↗ to open MITRE's page. Techniques that don't belong to one of the article's tactic tags appear as small square chips such as `T1566 Phishing` (grey = ATT&CK, violet = ATLAS); click one the same way. Open an **ATT&CK: …** or **ATLAS: …** collection and a **Techniques in …** strip above the list shows that tactic's techniques with article counts - click one to drill down (click the strip's title to fold it away).
- **Podcast player:** the bar at the bottom stays while you use other tabs and no longer hides the bottom of them. **Click the episode title on the bar** to jump to that episode in Podcasts with its description opened. The grey bar holds **↺ 10** (replay the last 10 seconds), **▶ / ⏸** (play / pause) and **10 ↻** (skip 10 seconds ahead), then the time, the seek bar (drag it to jump), **🔊** (mute; on big screens a volume slider sits next to it) and **⋮** for **playback speed** (0.75× to 2×, remembered) and **Download audio**. The skip buttons on headphones and the phone's lock screen work too.
- **Tactics, techniques and sub-techniques follow MITRE exactly:** the *ATT&CK* and *ATLAS* groups in the sidebar list the
  tactics of MITRE's current matrices, in matrix order (ATT&CK has **Stealth** and **Defense Impairment**; the old *Defense
  evasion* is gone). An article is in a tactic's collection only because it names one of that tactic's techniques or
  sub-techniques, or the tactic itself. Click a tactic tag on an article to see why: the techniques it names, each with the
  sub-techniques it names underneath (ⓘ = its page, ↗ = MITRE's page, ✕ = wrong match). If you remove a tactic tag from an
  article by hand it stays removed.
- **Sub-techniques where the article supports one:** when an article names a technique and its text also says which variant
  (for example *social engineering* + "impersonating", *phishing* + "malicious link", *valid accounts* + "cloud accounts"), the
  sub-technique is shown under the technique. An article that names no variant shows the technique alone - that is expected.
  Wrong one? ✕ next to the sub-technique removes it from that article.
- **Recolour many collections in one go:** Settings → Folders & collections → *Colour several at once*: pick a group (or tick
  collections), choose a colour, **Apply**.
- **All videos and podcasts about a technique:** on a technique's or entity's page (from the ▦ matrix, a Mentions chip or ⓘ),
  **▶ List these n videos** and **🎙 List these n podcast episodes** open the Videos / Podcasts tab showing only those, for the
  period chosen on the page. Press **×** on the *Mentions: …* chip there to see everything again.
- **Filter by threat actor:** click **🎭 Threat actors** above the article list. It lists every tracked actor that your items
  mention (pick the period at the top; search by any name - *Fancy Bear*, *VOLTZITE*, *Octo Tempest*). **📰** lists its articles,
  **▶** / **🎙** open its videos and podcast episodes, and the name opens its page. An actor that vendors call by different names
  (APT28 / Fancy Bear / Forest Blizzard) is one entry.
- **Videos and podcasts about what an article covers:** when an article has them, the reader's toolbar shows **▶ Videos n** and
  **🎙 Podcasts n**. They list the videos / episodes that name the same threat actor, malware, CVE or product, with the reason
  next to each; **Open all n in Videos →** shows them together in the Videos (or Podcasts) tab.
- **Articles means articles:** the Articles tab lists and counts articles only. Videos are in **Videos**, podcast episodes in
  **Podcasts**, account posts in **Socials**; their folders are not shown in the Articles sidebar. To get from an article to
  related videos or episodes use the **▶ Videos** / **🎙 Podcasts** buttons in the reader, or a threat actor's / technique's page.
- **Feeds by kind:** Settings → Feeds has tabs for 📰 Article feeds, 🎙 Podcasts, ▶ YouTube and 💬 Socials, so the list (and
  "select all") covers one kind at a time. **🗓️ Keep feeds…** works on the kind you are looking at (or *All feeds together*):
  how far back article feeds, podcasts, YouTube channels and accounts keep items, with a count before anything is removed.
- **Reports & guidance:** advisories, guidance and threat reports from government agencies, CERTs and security vendors'
  research teams go straight into your collections: advisories into **Threat advisories**, threat reports into **Threat
  intelligence**, guidance into **Defensive security**. To be told as soon as one is published: Settings → Alerts & digests
  → **📑 New reports & guidance**. Digests can include them too, with the threat actors most in the news.
- **Hide the sidebar:** press the panel button at the far left of the top bar (or the `[` key) to make room for the list
  and the article; press it again to bring the sidebar back. On a computer or tablet the app remembers your choice.
- **Every name of a threat actor:** an actor's page lists all the names it goes by (APT40, for example, also appears as
  Leviathan, Kryptonite Panda, Gadolinium, Gingham Typhoon, TEMP.Periscope, BRONZE MOHAWK, TA423…) from MITRE ATT&CK, MITRE
  ATLAS, the open MISP list, Microsoft and other vendors. Names that are also ordinary words (like "Leviathan") are shown
  but not searched for on their own, so articles about something else aren't tagged.
- **No ads inside articles:** sponsor lines, "follow us on…" and newsletter boxes, "Buy now" / "Try it free" links and
  "The post … appeared first on …" footers that publishers put into their feeds are removed, so the reader shows the article only.
  It learns per source: a promo line that keeps appearing under a site's articles is recognised after about three articles.
  Some things go straight away, even the first time: paid sponsor boxes inside an article, "we may earn a commission"
  notices, "you're out of free articles" paywall text, "listen to this article" players, and a site's own product plug at
  the very end. Sponsored articles keep their text, and tables or lists of products are never cut. This is always on;
  there is no setting for it.
- **Same story, many sources:** when several sites report the same story, the list shows it once with a **🧩 +5 sources**
  button. Click it to see the other sources and read any of them; **✓ Mark all read** clears the whole story. It also catches
  re-worded headlines ("Hackers spy on Bulgarian government…" and "Bulgaria discovers massive government breach…") by
  comparing the first lines of the articles. Two articles about different CVE numbers are never grouped. Turn it off or make
  it stricter / looser in **Settings → Appearance & reading → Smart features**.
- **Where an article comes from:** every article in the list shows its feed and its 📁 folder, and an open article says
  *From (feed) in (folder)*. Click the feed or the folder to see everything from it.
- **Pages for the things articles mention:** open an article and click a chip in the **Mentions** row (a threat actor, malware,
  vendor, country…). Its page shows how often it was mentioned over time, the latest articles, videos, podcast episodes and posts
  about it, and what it is usually seen together with. Techniques and MITRE groups also show MITRE's description.
- **Technique matrix:** click **▦** next to *ATT&CK* or *ATLAS* in the sidebar. Every technique your articles name is laid out by
  tactic; darker = more articles. Click one for its page. **⬇ Navigator layer** saves the picture for MITRE's ATT&CK Navigator.
  The period you pick (7 days … all time) is used by the matrix *and* by every page you open from it, so the numbers always agree; change it in either place. **← Matrix** on a page takes you back.
  On a page, **▶ Open in Videos** and **🎙 Open in Podcasts** take you to that exact video or episode inside the app. A technique's page also shows which of its **sub-techniques** your articles name, with counts.
- **A technique tag is wrong?** Click the tactic tag, then **✕** next to the technique. Choose *Remove it from this article*, or
  *Stop matching "…" everywhere* when a phrase keeps causing wrong tags. You can undo the second one in Settings → Appearance & reading.
- **Tags fold away:** articles, videos and account posts show a small **🏷️ 10 ▸** button instead of all their tags. Click it to see that item's tags, click again to hide them. Want them always visible? Press **🏷️ Tags** in the tab's toolbar (press again to fold them).
- **Public threat data on the dashboards:** CVE tracker, Ransomware tracker and the new Internet threats tab start with ready-made panels (pressure index, exploited bugs, ransomware claims, attacking networks and ports). Open **ℹ️ How to read it** under any panel for a plain explanation and the source. They fill in by themselves - "Collecting…" just means the first download is still running.
- **★ Favourite channels:** click ☆ beside a channel in Videos → Channels ▾ (or the ☆ before a channel's name under any video) - it turns gold ★. Pick **★ Favourite channels** at the top of Channels ▾ to see only their videos. Tick several channels → *★ Favourite these* (or *☆ Unfavourite these*) to do many at once. The ☆ in a video's button row stars the video, not the channel.
- **YouTube and Podcasts in the Articles sidebar:** open the *YouTube* or *Podcasts* folder in the Articles sidebar to see every channel or show by name. Click one to read its items in the reader; ↗ opens it in Videos or Podcasts. They don't add to your article counts or appear in All / Unread.
- **Podcast player:** ▶ Play opens a player bar at the bottom of the window. It keeps playing while you browse other tabs; ✕ on the bar stops it.
- **"Open in Articles" under a video** opens that same video in the article reader (bigger text, notes, highlights, AI tools). Nothing is copied: the video stays in its channel's feed in Videos (or *Saved YouTube videos* for single videos you added). Video feeds don't appear in the Articles sidebar - to find it again from Articles, ★ star it (Starred), add it to a collection, or search.
- **🎙 Podcasts:** ＋ → paste podcast links (Apple Podcasts, Spotify show, or a feed) one per line, or type a show's name and press ＋ Add on the right result. ▶ Play plays the episode here and remembers where you stopped; finished episodes are marked played.
- **Podcast topics & categories:** each episode shows its topics (click one to filter) and, for shows like Darknet Diaries, the show's own 📂 categories. **View** switches between Comfortable, Compact and Grid. Each episode links to its **Official page** and **YouTube**.
- **▶ YouTube on an episode** opens that episode's own video when the show is on YouTube (found automatically). *🔎 YouTube* means it isn't matched yet: it searches the show's channel. Wrong or missing channel? Podcasts → Shows ▾ → ⚙ beside the show → **▶ YouTube channel…** → paste the right channel or playlist link (or *No YouTube*).
- **★ Favourite topics:** in Videos → Topics ▾ click ☆ beside a topic; pick **★ Favourite topics** at the top to see videos from any of them. Tick several topics → *★ Favourite these*. Topics are picked only from this dropdown now (the row of topic buttons was removed).
- **Socials topics:** like Videos, the Socials page has no row of topic buttons any more - pick topics in **All topics ▾**; *Show all →* on a topic picks it there.
- **Topics menu:** ⚙ next to a topic → Edit or Delete; ＋ next to *All topics* → new topic; tick several → *Delete these topics*.
- **Channels menu:** ⚙ next to a channel → Retention (how far back to keep), Load whole channel, Remove; tick several → Retention / Remove for all of them.
- **Adding videos:** paste links (videos, playlists, channels). The app shows what each link is; tick what you want - just the video, the playlist, follow the channel, the channel's videos or playlists - and pick the retention.
- **Topics cover almost everything:** news shows, careers, certifications (CompTIA, CCNA, OSCP…), leadership, AppSec, identity & passwords, Windows, explainers, gear, breaches, crypto and podcasts each have a topic. A video's channel name counts too. Click several topic names to see videos from any of them.
- **Precise topics:** a video is in a topic only if its **title** contains one of the topic's words, so a topic shows what it says. Pick several topics with *all* to narrow further.
- **Searching videos:** the search box looks in titles, channel names and descriptions; every word you type must appear. "homelab" also finds "Home Lab". If nothing shows because a channel, topic or Starred filter is on, press **Clear filters and search all videos**.
- **Topics:** click several topic names under the toolbar to combine them; click a name again to remove it, or **All topics** to clear. The **Topics** menu has a search box. A new topic appears once its videos are tagged (a ⏳ note shows while that runs).
- **Getting older videos:** tick a channel (or none for all channels) → **🗓 Keep…** → choose how far back, e.g. *Last 2 years* or *Everything*. Videos older than that are removed, and the missing ones inside it are loaded in the background (needs the free YouTube API key). There is no 50-video limit.
- **Making channels smaller:** tick one channel → **🗓 Keep…** → e.g. *Last 3 months*, or **Custom…** to type your own (for example 18 months or 2 years). With no channel ticked, or several, the button changes to **Keep… (all channels)** or **Keep… (ticked)** and does them all at once. Older videos are removed now and as they age (starred videos and videos in your groups stay). Choose *Everything* to lift the limit again.
- **YouTube having a bad moment?** YouTube's public feed sometimes reports a channel as missing for a few minutes. With an API key, the app quietly uses the API instead; without one it tries again later, so nothing needs doing.
- **Watching:** click a video's picture or title and it plays **inside the app**, in a window over the page. **⏮ / ⏭** go to the previous / next video on the page (in a playlist, in the playlist's order), **↗ YouTube** opens it on YouTube, **✕** or Esc closes it (the video stops). Want YouTube in a new tab instead? Ctrl-click (⌘-click on a Mac) the title.
- **One copy of each video:** a video that is in a channel *and* in some of its playlists is stored once and shown in each of them - no duplicates. Adding a playlist or channel that overlaps what you have only adds the videos you don't have yet.
- **Sort a channel's videos into its playlists:** added a channel but not its playlists? **Channels ▾ → ⚙ beside the channel → ☰ Sort into its playlists…** shows the channel's playlists (all ticked). Untick any you don't want, keep *Put them in a group named after the channel* if you like, and click **Sort into playlists**. The videos you already have go into their playlists in the channel's order; only missing videos are downloaded. Needs the free YouTube API key.
- **Doing something to many videos at once:** click **☑ Select** in the toolbar (in the video grid and in By topic). Tick videos - or click their pictures, or **Select all shown** - and use the bar at the bottom: **🗂️ Add to group…** (one of yours or a new one), **▶ Add to playlist…** (it also shows in that playlist; your library only, YouTube isn't changed), **✓ Watched / ↩ Unwatched**, **★ Star / ☆ Unstar**, **🗑️ Remove…** (for good). **Done** (or **✓ Done selecting**) turns it off. On a phone the bar is one row: swipe it sideways for more actions. Playlists & groups has its own ☑ Select for cards.
- **Removing:** **🗑** on a video removes it for good (it won't come back on updates, from any playlist or channel). In a playlist, **🗑 Delete playlist** removes the playlist and its videos - except videos the channel or another playlist you follow also has, which stay.
- **Playlists & groups:** click **🗂 Playlists & groups** to see each playlist you follow, and your own groups, as cards. Click a card to see its videos in order.
  - **Make a group** (a series, a course, "watch later"…): click **＋** on any video card → **New group…**, or **+ New group** in the Playlists & groups view. Add more videos the same way.
  - A video in a playlist or group shows a small badge (▶ playlist, 🗂 group); click it to open that group.
  - In your own groups you can rename, delete (the videos stay) and remove single videos (✕).
  - **Renaming:** click **✎** on any playlist or group card (next to ＋), or **✎ Rename** inside an open playlist or group. A playlist keeps your name when it refreshes from YouTube; rename it to nothing (empty) to get YouTube's name back.
- **All** at the top of the channel and topic lists means no filter; tick single channels or topics to narrow it down.
- **Watching:** click a video to watch it on YouTube; it's then marked as watched.
- **Topic numbers** follow the filters you've set (channel, length, watched, search), so they always match what you see when you click a topic.
- **Videos are kept** until you remove the channel. The 90-day limit for news doesn't apply to YouTube channels.
- **Categories:** videos that match no topic are under *Other*. Add or edit topics with **Topics…** to sort them better.

**Tip:** add a free YouTube API key in **Settings → Integrations** for whole channels, video lengths and view counts.

**👥 Socials** works the same way for **social media accounts**: their posts appear as cards, split into categories by topic.
- **Add accounts:** **+ Add accounts**, then paste profile links, one per line.
  - **Work straight away:** Bluesky, Mastodon (and other fediverse servers) and Reddit users or subreddits. Telegram public channels too.
  - **X (Twitter):** needs a bridge or the paid X API (**Settings → Integrations → X**).
  - **LinkedIn, Instagram, Facebook, Threads, TikTok:** these sites offer no feeds and forbid scraping. Run a feed bridge such as RSSHub or RSS-Bridge, paste the feed link it gives you for the profile, and choose the platform.
- **Filters:** platform, account, several topics (any or all), unread or starred, and search. **▦ All posts** shows one grid instead of topic shelves.
- **Remove an account:** pick it, then click **🗑 Remove account**.
- Posts also appear in the reader under the **Social Accounts** folder.

---

## 7a. GitHub repos (📦 Repos)

Keep the GitHub projects you care about in one place. Press **＋** (*Add from GitHub*), paste one per line and press **＋ Add**:

| Paste | You get |
|---|---|
| `https://github.com/SpecterOps` (an owner) | Every public repo of that person or organisation (up to 500). |
| `https://github.com/projectdiscovery/nuclei` (a repo, or any page inside it: a file, a folder, the README) | That repo, plus its new versions in **🚀 Releases**. |
| `https://gitlab.com/<group>/<project>` (any page inside a GitLab project) | That GitLab project (🦊), with its releases. |
| `https://swisskyrepo.github.io/InternalAllTheThings/…` (a GitHub Pages website) | The repo the website is built from, if it is public. |
| `topic:homelab` or `https://github.com/topics/homelab` | The 100 most-starred repos GitHub tags with that topic. |
| `stars:octocat` or `https://github.com/octocat?tab=stars` | Everything that person starred (up to 500). |

- **Also follow the owner:** tick this in the ＋ dialog to add the repo *and* everything its owner publishes. Leave it off (the default) to add only the repo.
- **Website links:** `name.github.io` adds the repo the website is built from (`name/name.github.io`); a blog post on it adds that same repo; `name.github.io/project/…` adds `name/project`. The line tells you which repo it picked. Wiki links (`…/wiki`) add the repo.
- **Big pastes:** up to 200 lines at a time. Everything is saved at once and checked in the background; the window shows how far it has got and each line updates when it's done. You can close it and keep working.
- **Why a limit of 200?** It keeps one paste reviewable and stops a runaway script from filling the list; a free GitHub account (no token) only checks 60 links an hour anyway, so a big paste finishes over a few hours by itself. With a token it's done in minutes.
- **When GitHub's free limit runs out:** the line is still saved (⏳) and finishes by itself after the time shown. Nothing to paste again. Each pasted repo uses one of the 60 free requests an hour (none if it's already in your Repos).
- **Every line gets an answer:** *Added*, *Already here*, *No public repo* (it doesn't exist, was deleted or renamed, or is private), *a website, not a repo*, *Gists aren't supported yet*, or GitHub's limit with the time to try again.
- **Gists, docs and websites:** paste gist links (gist.github.com/…) and GitHub Docs pages (docs.github.com/…) like repos. They get their own cards (🧾 Gist, 📄 GitHub Docs, 🌐 Website), can go in folders and be starred, and **Type** in the filters shows only one kind. Docs pages are never downloaded: the title comes from the link.
- **Profile links ask first:** for a `github.com/<name>` line you choose *Follow all repos* (everything they publish, up to 500 - e.g. OWASP, Elastic), *Profile link only* (a 👤 card linking to the profile) or *Skip*; several at once get "for all of them" buttons.
- **Removing an owner:** ⚙ Sources → ✕. If some of its repos are in your folders you can choose *Remove it and its repos* or *Remove it, keep its repos*. Repos you pasted yourself or starred always stay.
- **📁 Folders:** Repos opens on your folders. Click a folder to see its repos (with all the filters); **← All folders** goes back. Make one with **＋ New folder**; **⋯** on a folder renames it, changes its emoji or colour, moves it, or deletes it (its repos stay). Put a repo in folders with **📁** on its card (a repo can be in several), tick many with **☑ Select** and use **Add to folder** / **Remove from folder**, or choose *Put them in* when adding. A repo in a folder stays even if you remove the owner or topic it came from.
- **Each card** shows what the repo is, its language, ★ stars, forks, licence, when it was last updated, GitHub's own tags (click one, e.g. **#homelab**, to see every repo with it) and your topics (click one to see that topic's repos). **archived** means the owner stopped maintaining it; **fork** means it's a copy of another repo.
- **Tabs:** under the search bar, **📁 Folders**, **▦ All repos**, **🏷️ By topic**, **👤 By owner**, **💻 By language** (press **Show all ›** on a shelf to open it) and **🚀 Releases**. On a phone they're behind **☰ Filters**.
- **Filters:** search, **Topics**, **Language**, **Type**, **Stars** (minimum), **★ Starred**, **Hide archived**, **Hide forks**. **Clear filters** resets them.
- **Sort** (★ most stars, 🕒 recently updated, 🆕 newest on GitHub, 📥 recently added here, A–Z) also holds **📅 Custom range…**: only repos last updated between two dates. **✕ Clear custom range** removes it; Sort is outlined while a range is on.
- **🗑 on a card** removes that repo (or gist / link) from Repos and from every folder. If it came from an owner, topic or stars list, it stays removed when the list is checked again; paste its link again to bring it back.
- **★ on a card** keeps that repo here even if you unfollow the owner, topic or stars list it came from.
- **⚙ Sources** lists what you follow: **Show** (only its repos), **⟳** (check now), **✕** (unfollow; its repos go unless you starred them or another source lists them). Problems show as ⚠ with the reason.
- **How often:** everything is checked twice a day in the background, and **⟳** at the top checks all now.
- **GitHub's limit:** without an account GitHub allows 60 requests an hour, which is plenty for a handful of sources (an owner with 300 repos takes about 4). If you follow a lot, create a free **read-only token** on GitHub (*Settings → Developer settings → Fine-grained tokens*, "Public repositories (read-only)", no other permissions) and paste it in **⚙ Sources → GitHub token**. That raises the limit to 5,000. The token is stored encrypted and never shown again. When the limit is reached the app simply waits and carries on after GitHub's reset.

---

## 7b. Resources (🔗 your websites, training and tools)

Everything you'd normally keep in browser bookmarks - training platforms, labs, cheat sheets, tools, docs - sorted so you
can find it quickly.

- **Bring your bookmarks in:** press **⇪ Import bookmarks** and choose your browser's export file.
  - *Chrome / Edge / Brave:* Bookmarks manager (Ctrl+Shift+O) → ⋮ (top right) → **Export bookmarks**.
  - *Firefox:* Bookmarks → Manage bookmarks → **Import and Backup** → **Export Bookmarks to HTML**.
  Your folder names help the sorting, links you already have are skipped, and the file never leaves the app.
  **Before anything is imported you see your folders** with how many links each holds: untick the ones you don't want
  (personal, business, shopping…) - unticking a folder leaves out everything inside it.
  Leave **Keep my folders and subfolders** ticked and your folders are rebuilt in Resources exactly as they are in
  your browser. A link you saved in two folders shows up in both.
- **Pick how to see your links** with the buttons under the header: **🌳 Folders**, **🗺 Map**, **🗂 Categories** or
  **☰ All links**. A search, type, status, category or ★ filter always shows the matching links as a list; press
  🌳 Folders to go back to your folders (it clears those filters).
- **🌳 Folder tree** (the first view): press ▸ to open a folder, *Open all* / *Close all*, or type in *Find* to
  narrow it down. The **⋯** next to a folder adds a subfolder, renames, moves it somewhere else, shows its links as a
  list, or deletes it (you choose: keep the links, or delete links that are only in that folder). The **⋯** next to a
  link moves it to another folder, *also* puts it in another folder, takes it out of this one, or **🗑 deletes it**
  (that removes it from Resources and from every folder it's in; to only remove it from one folder, use *Take out*).
- **🧠 Mind map:** your folders as bubbles around a centre (pick it under *Centre*: Everything or any folder). Solid
  lines go to subfolders; **dashed lines mean "goes well with"** - topics that help each other, each with a short note
  on why. Dashed bubbles on the outside are connected folders from elsewhere. Click a bubble to see its subfolders (click one to jump to it) and its links; the **🧠 number** next to
  its title opens its connections in a popup, double-click to put it in the middle. **Scroll the mouse wheel to zoom** in and out (around the pointer)
  and **click and drag to move** the map; on the keyboard, click the map and use the arrow keys, + / − and 0 (fit).
  **Fit** shows the whole map centred again. Connect two folders with
  **🧠 Goes well with…** (on the map, or in a folder's ⋯ in the tree); ✎ changes the note, ✕ removes the connection.
- **📦 Repos** (a view button in Resources): your whole Repos screen lives here now - repo folders, all repos, by topic /
  owner / language, releases, adding and following. The number on the button is new releases since you last looked.
  The Repos tab at the top is hidden; **Show Repos as its own tab too** (in the 📦 view) brings it back. Searching in
  Resources lists matching repos first, and Ctrl+K finds repos as well.
- **Change a link from the mind map:** press **⋯** next to a link (or repo) in the side panel. **📁 Folders…** lists
  every folder with a tick where it is now - tick more to put it in several topics, untick to take it out; **− Take out
  of …** removes it from just this topic; ✎ Edit changes its title, description and notes; 🗑 Delete removes it from
  Resources entirely (from every folder). The same 📁 Folders… is in a link's ⋯ in the folder tree.
- **Adding links:** **＋** (top) or **＋ Add… → ＋ New links…** on a topic. Leave **Put them in** on *✨ Sort into topics
  automatically* and each new link goes where it fits (next to links from the same site, by its title and description,
  its category and type) - you'll see *→ 📁 folder* after each one. With **📖 Read each page** ticked the app reads each
  new page's own title and description (it contacts those websites; up to 20 at a time) to name, describe and sort it.
  **＋ Add… → 🔗 Links already in Resources…** puts existing links in a topic too; **📦 Repos…** links repos.
- **Ctrl+K (⌘K on a Mac), from any tab:** type a few letters - a name, an address or a short form like *htb*,
  *thm*, *otw* - and press Enter to open that one site. It also finds folders and app tabs. Ctrl+Enter shows the
  link in Resources instead. With nothing typed it lists your favourites and recently opened links.
- **★ Launchpad:** the first view button - big tiles of your ★ favourites and your most opened links; each opens one
  site. Use **Copy** to grab its address (`…/#launchpad`) and set it as your browser's home page. Star a link with ☆
  in *All links*, or **⋯ → ★ Add to favourites** in the folder tree.
- **📦 Repos under topics:** repos from the Repos tab show under the topics they belong to - in the mind-map panel
  (after the links), in the tree and on the map. **📦 Link repos…** (a folder's ⋯, or the mind-map panel) lets you
  tick more on or off; ✕ next to a repo in the tree takes it off that folder (the repo stays in the Repos tab).
- **Find any link and jump to it:** type in **Find any resource…** at the top (works from every view). Each result
  has a **📍** button: *In its folder* (opens the tree at it), *On the map*, *In the mind map* or *In its category* -
  the link is scrolled to and highlighted for a few seconds. In the tree, a link's **⋯** menu has the same choices.
- **What it's for:** each link can carry a short description of what it is and what you'll get out of it. It shows
  under the link (untick **📝 What it's for** in the tree to hide it), search finds it, and ✎ Edit changes it - your
  own notes stay separate.
- **Top-level topics:** Learn & Practice, Daily Check & News, Offensive Security, Web & App Security, Defensive
  Security & SOC, DFIR & Malware Analysis, Threat Intelligence & OSINT, OT/ICS Security, Privacy, Identity &
  Encryption, GRC, Cloud, Linux / Windows / Virtualisation, Networking, Home Lab, AI, Tools, Community / People / Media
  and Personal & Business.
- **🎓 Learn & Practice** (first folder) holds everything for learning: hands-on platforms (HTB, TryHackMe, LetsDefend,
  BTLO…), wargames & CTFs (OverTheWire, UnderTheWire, picoCTF…), vulnerable machines, scripting (Python, PowerShell,
  Bash, Git), courses by topic, certifications, careers & roadmaps, cheat sheets, home-lab guides and non-cyber learning.
- **🗺 Map:** the same folders as a sitemap - boxes branching left to right. **Click a folder's name to go into it**
  (it becomes the centre), press its **⤢ double arrow to expand it right there like a tree** (⤡ closes it), and use the buttons at the top
  (🏠 All › Cyber › …) to go back up.
- **Change many at once:** **☑ Select**, tick links (or *Tick all shown*), then *Add to category*, *Remove from category*,
  *★ Favourite*, *☆ Unfavourite* or *🗑 Delete*.
- **Or paste links:** **＋** → one per line (an address, `Title | address`, or Markdown `[Title](address)`).
- **Categories:** offensive, red teaming, defensive, blue team & SOC, purple, threat intel, malware analysis, DFIR, malware
  development, scripting, coding, AppSec, cloud, networking, Linux, OT/ICS, OSINT, privacy, hardware, homelab, certs &
  careers, GRC and news. A link can be in up to three. **⚙ Categories** renames, recolours, reorders, deletes (links stay)
  or adds your own.
- **Types:** courses, training platforms, labs, CTFs, cheat sheets, docs, tools, repos, blogs, videos, people. **Type →
  🎓 Training** shows every course, platform, lab, CTF and cheat sheet at once - pick a category too (e.g. DFIR) for
  "DFIR training".
- **On each link:** ★ favourite (they sit in the **Quick** bar at the top with your recently opened links), a status
  (📌 to do, ▶ in progress, ✅ done), ✎ to change the title, type, notes and categories, 🗑 to delete. What you change
  yourself stays: **↻ Sort again** only re-sorts the links you haven't touched.

---

## 8. AI summaries (optional)

Eye of Sauron can use an AI service to summarise articles and write briefings.

1. Go to **Settings → AI** and choose a provider:
   - **Claude**, **OpenAI** or **Gemini** (you need an account and an API key from that company);
   - a **local AI** on your own machine (e.g. Ollama): free, and nothing leaves your network.
2. Press **Test connection**.
3. Set a **daily limit** so costs can't run away.

Then press **✨ Summarize** on any article, or tick **AI summary** on a rule.

**Remember:** AI summaries can be wrong. Check the original article before acting on them.

---

## 9. Alerts and daily briefings

Set these up in **Settings → Alerts & digests**.

**Step 1: choose where messages go.**
- **Options:** email, Telegram, phone push notifications (ntfy), Discord, Slack, or a webhook.
- **Check it works:** press **Test**.

**Step 2: choose what you want to hear about.**
- **CVE alerts:** for example, "tell me immediately about any new critical vulnerability in Fortinet, Ivanti or Cisco devices", or "…anything newly added to CISA's exploited list".
- **Rule alerts:** on any rule, choose **Instant alert to** to be told the moment a matching article arrives.
- **Digests:** a briefing at a time you choose, for example "every weekday at 7:30".
  - It lists the important articles and new CVEs since the last one.
  - It can start with a short AI-written overview.
  - Use **Preview** to see one before it's sent.

You won't get the same alert twice, and old vulnerabilities won't flood you when you first set this up.

---


## 11. On your phone

- **In the browser:** open your Eye of Sauron address on your phone. The layout adapts to phones, tablets and
  computers, upright or sideways:
  - **Top bar:** on a phone or small tablet it has two rows. Search, ⟳ and ⚙ sit on top; the tabs sit below - **swipe
    the tab bar sideways** to reach them all. On laptops and tablets held sideways the tabs show icons; hover or
    long-press for their names.
  - **☰ Filters:** on a phone, each tab's drop-downs and ticks fold behind **☰ Filters** next to the search box, so the
    list starts near the top of the screen. Tap it again to fold them away.
  - Everything you tap is finger-sized, and windows such as Settings fit the screen and scroll inside. Settings' section
    list scrolls sideways.
- **With an RSS app** such as Reeder, NetNewsWire, FeedMe or Read You:
  1. Create an **app password** in **Settings → Mobile apps**.
  2. In the app, add a **FreshRSS** account using that password.
  3. Read and unread status stays in sync.

When you're away from home, use a secure connection (HTTPS, or a VPN such as Tailscale).

---

## 12. Keeping your account safe

- **Password:** use a long, unique password, and never share it.
- **Apps and devices:** give each phone app and automation its own app password or API token, so you can revoke just that one if a device is lost.
- **Connected accounts and keys:** all stored keys (social accounts, AI keys, bot tokens) are encrypted, and they're never shown again after you save them.
- **Being nagged to change your password?** If Eye of Sauron says you are still using the first-run password, change it in **Settings → Account**.

---

## Quick answers

**An article list is empty or a feed shows ⚠.**
Go to **Settings → Feeds** and click **🩺 Check** next to the feed. It explains what's wrong and, if the feed has moved, offers the new address. The feed's ⚙ *Health* section shows the last error too.

**How long are articles kept?**
By default 90 days, but **starred** articles are kept forever. You can change this per feed or globally in **Settings → Appearance & reading**.

**Can I get older articles?**
Yes. A feed only shows its newest items, so the app looks the history up for you. Set how far back in **⚙ → Keep & fetch … from** (for example *2 years* or *Keep forever*) and press **⇣ Load older articles** (or *episodes* / *videos*). For many feeds at once use **Settings → Feeds → 🗓️ Keep feeds…** with **Also fetch older items back to this date** ticked. Leave *Where to look* on *Automatic*.

**Why is "keep" and "how far back" one setting?**
Because they have to agree: fetching five years of history into a feed that keeps two years would just have the clean-up delete three of them again. So the feed's Keep setting is also the limit for loading older items.

**Can I get older podcast episodes?**
Yes. Many shows only list their latest 100–300 episodes in their feed. Open the show's **⚙ Settings** (Podcasts → Shows, or the show's menu), set **Keep & fetch episodes from** (*Keep forever* for everything) and press **⇣ Load older episodes**. The app reads the show's whole feed again, then its older pages if the host has them, then old copies of the feed saved by the Internet Archive. A higher *Effort* reaches further back. Very old episodes sometimes point to audio files the show no longer hosts; those won't play.
- It first tries the website's own older pages.
- If the site has none, it reads old copies of the feed saved by the Internet Archive (web.archive.org), which has most public feeds going back years.
- Keep **Keep them** ticked, or the app's clean-up may delete what it just fetched.
- It runs in the background and can take a while for many feeds. Very small or brand-new blogs are often not archived, so nothing older exists for them.

**Is my data sent anywhere?**
Only when you choose to:
- to AI providers when you summarise or translate titles;
- to Wallabag or Linkwarden when you save an article there;
- to your social accounts when you publish;
- to your channels when you set up alerts.

Everything else stays on your server.

**I was signed out after an update.**
That's expected once: the sign-in cookie got a new name when the app's old working name ("feedwarden") was retired. Sign in again; your API tokens and app passwords keep working.

**Who can see what's on the server?**
Only people who can log in. Eye of Sauron is single-user: one admin account, plus the app passwords and tokens you create.

---

*Found something confusing or out of date? This guide lives at `docs/users/02_User_guide.md` and is updated with every release; contributions are welcome (see [CONTRIBUTING.md](../CONTRIBUTING.md)).*

## Social accounts

**Following people on LinkedIn, X, Instagram…** (👥 Socials → ＋): paste their normal profile link. X, Instagram, Threads, TikTok, Facebook pages and LinkedIn *company* pages work through the RSSHub bridge (set up once in Settings → Integrations → X). LinkedIn *personal* profiles can't be followed by any app; save their posts with **＋ Add post** instead.

**Saving one post** (👥 Socials → ＋): paste the link. X, Reddit, Bluesky, Mastodon, TikTok and Threads posts are read automatically. For LinkedIn, Instagram and Facebook, also paste the post's text (open the post, select the text, copy). Press ✨ on a post for an AI summary.
