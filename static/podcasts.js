/* 🎙 Podcasts tab: shows followed by their open RSS feeds; episodes play in the app (the show's own audio files).
 * Same rules as app.js: DOM built with h()/textContent only, links via safeUrl. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, safeColor, relTime, fullDate, store } = FW;
  const $ = (sel) => document.querySelector(sel);
  const DEFAULTS = { view: "episodes", feed_ids: [], topic_ids: [], q: "", state: "all", sort: "newest", layout: "comfortable", category: "" };
  const KEEP = [["0", "Every episode (keep forever)"], ["365", "Last year"], ["180", "Last 6 months"], ["90", "Last 90 days"], ["30", "Last 30 days"]];
  const fmtDur = (s) => (!s ? "" : s >= 3600 ? `${Math.floor(s / 3600)} h ${String(Math.floor(s % 3600 / 60)).padStart(2, "0")} min` : `${Math.round(s / 60)} min`);
  const posKey = (id) => `fw-pod-pos-${id}`;

  const view = {
    meta: null, topics: [], items: [], total: 0,
    filters: (() => { const f = { ...DEFAULTS, ...(store.get("fw-podcast-filters") || {}) }; f.dates = FW.dateRange.clean(f.dates); return f; })(),

    show() {
      // one load at a time: start-up restoring the tab and a click on it no longer build the view twice
      if (this.showing) return this.showing;
      this.showing = (async () => {
        const el = $("#podcastsView");
        if (!this.meta) fill(el, h("p", { class: "muted lib-pad", text: "Loading podcasts…" }));
        await this.loadMeta();
        this.renderShell();
        await this.reload();
      })().finally(() => { this.showing = null; });
      return this.showing;
    },
    hide() { /* the docked player keeps playing in other tabs; ✕ on it stops it */ },

    /** The docked player (outside #podcastsView, so list refreshes and tab switches never cut playback). */
    play(e, onEnded) {
      const audioUrl = safeUrl(e.audio_url);
      if (!audioUrl) return;
      let dock = document.getElementById("podDock");
      if (!dock) {
        dock = h("div", { id: "podDock", class: "pod-dock", role: "region", "aria-label": "Podcast player" });
        document.body.append(dock);
      }
      const old = dock.querySelector("audio");
      if (old) { old.pause(); old.removeAttribute("src"); old.load(); }
      const audio = h("audio", { controls: true, preload: "metadata", src: audioUrl });
      let saved = 0;
      try { saved = Number(localStorage.getItem(posKey(e.id)) || 0); } catch { /* storage off */ }
      audio.addEventListener("loadedmetadata", () => { if (saved > 5 && saved < (audio.duration || 1e9) - 10) audio.currentTime = saved; });
      let lastSaved = -1;
      audio.addEventListener("timeupdate", () => {
        const t = Math.floor(audio.currentTime);
        if (t !== lastSaved && t % 10 === 0) { lastSaved = t; try { localStorage.setItem(posKey(e.id), String(t)); } catch { /* storage off */ } }
      });
      audio.addEventListener("ended", () => {
        try { localStorage.removeItem(posKey(e.id)); } catch { /* storage off */ }
        if (onEnded) onEnded();
      });
      const close = () => { audio.pause(); if (this.dockSize) this.dockSize.disconnect(); dock.remove(); document.body.classList.remove("has-pod-dock"); };
      // ⏪ / ⏩ 10 seconds: replay a part you missed, or skip ahead (also from headphones / the lock screen)
      const skip = (secs) => {
        const end = Number.isFinite(audio.duration) ? audio.duration : Infinity;
        audio.currentTime = Math.min(Math.max(0, (audio.currentTime || 0) + secs), Math.max(0, end - 0.5));
      };
      const skipBtn = (secs) => h("button", { type: "button", class: "icon-btn pod-skip", text: secs < 0 ? "↺ 10" : "10 ↻",
        title: secs < 0 ? "Back 10 seconds" : "Forward 10 seconds", "aria-label": secs < 0 ? "Back 10 seconds" : "Forward 10 seconds",
        onclick: () => skip(secs) });
      if ("mediaSession" in navigator) {
        try {
          navigator.mediaSession.setActionHandler("seekbackward", (d) => skip(-((d && d.seekOffset) || 10)));
          navigator.mediaSession.setActionHandler("seekforward", (d) => skip((d && d.seekOffset) || 10));
        } catch { /* not supported by this browser */ }
      }
      fill(dock,
        safeUrl(e.image) ? h("img", { class: "pod-dock-art", src: safeUrl(e.image), alt: "", referrerpolicy: "no-referrer" }) : h("span", { class: "pod-dock-art pod-noart", text: "🎙" }),
        h("div", { class: "pod-dock-info" },
          h("button", { type: "button", class: "pod-dock-title", title: `${e.title}\nClick: open this episode in Podcasts`, text: e.title, onclick: () => this.goTo(e) }),
          h("span", { class: "muted small", text: e.show || "" })),
        h("div", { class: "pod-dock-controls" }, skipBtn(-10), audio, skipBtn(10)),
        h("button", { type: "button", class: "icon-btn", text: "✕", title: "Stop and close the player", "aria-label": "Stop and close the player", onclick: close }));
      document.body.classList.add("has-pod-dock");
      // the app ends where the player starts, so the player never covers the bottom of a list (its height can wrap on phones)
      const fit = () => document.documentElement.style.setProperty("--pod-dock-h", `${Math.ceil(dock.getBoundingClientRect().height)}px`);
      fit();
      if (this.dockSize) this.dockSize.disconnect();
      if (window.ResizeObserver) { this.dockSize = new ResizeObserver(fit); this.dockSize.observe(dock); }
      audio.play().catch(() => { /* the browser may want a click on the player */ });
    },

    /** The player's title: open Podcasts on that episode, with its description unfolded. */
    async goTo(e) {
      if (FW.currentMode && FW.currentMode() !== "podcasts") $("#modePodcasts").click();
      if (this.showing) await this.showing;
      else if (!this.meta || !$("#podList")) await this.show();
      const f = this.filters;
      const find = () => { const list = $("#podList"); return list ? list.querySelector(`[data-ep="${Number(e.id)}"]`) : null; };
      let row = f.view === "episodes" ? find() : null;
      if (!row) {  // not in the list as filtered now: show just this episode (its show + its title in the search box)
        this.mention = null;
        Object.assign(f, { feed_ids: e.feed_id ? [String(e.feed_id)] : [], q: String(e.title || "").slice(0, 200), state: "all", category: "", topic_ids: [], view: "episodes" });
        this.save();
        this.renderShell();
        await this.reload();
        row = find();
      }
      if (!row) { toast("That episode isn't in your library any more", true); return; }
      const desc = row.querySelector("details.pod-desc");
      const snippet = row.querySelector(".pod-snippet");
      if (desc) desc.open = true;
      else if (snippet && e.summary) snippet.replaceWith(h("details", { class: "pod-desc", open: true }, h("summary", { text: "Description" }), h("p", { text: e.summary })));
      row.classList.add("pod-ep-focus");
      row.scrollIntoView({ block: "center", behavior: "smooth" });
      setTimeout(() => row.classList.remove("pod-ep-focus"), 2500);
    },
    save() { store.set("fw-podcast-filters", this.filters); },
    async loadMeta() {
      const [meta, lib] = await Promise.all([api("GET", "/podcasts/meta").catch(() => ({ shows: [] })), api("GET", "/library/meta").catch(() => null)]);
      this.meta = meta;
      this.topics = (lib && lib.topics) || [];
      const known = new Set(meta.shows.map((s) => String(s.feed_id)));
      this.filters.feed_ids = this.filters.feed_ids.filter((id) => known.has(String(id)));
    },
    async refreshAll() { await this.loadMeta(); this.renderShell(); await this.reload(); },

    renderShell() {
      const el = $("#podcastsView");
      const f = this.filters;
      const m = this.meta;
      const select = (key, label, options) => h("select", { "aria-label": label, onchange: (e) => { f[key] = e.target.value; this.save(); this.reload(); } },
        options.map(([v, l]) => h("option", { value: v, text: l, selected: f[key] === v })));
      const search = h("input", { type: "search", placeholder: "Search episodes & shows…", maxlength: 200, value: f.q, "aria-label": "Search episodes" });
      let timer = null;
      search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); this.save(); this.reload(); }, 300); });
      const tab = (v, label) => h("button", { type: "button", class: `btn small${f.view === v ? " primary" : ""}`, "aria-pressed": String(f.view === v), text: label,
        onclick: () => { f.view = v; this.save(); this.renderShell(); this.reload(); } });
      const byId = (id) => m.shows.find((s) => String(s.feed_id) === String(id));
      const picker = FW.sources && FW.sources.multiPicker;
      fill(el,
        h("div", { class: "studio-header lib-header" },
          h("h2", { text: "🎙 Podcasts" }),
          h("button", { type: "button", class: "btn small primary lib-add-plus", text: "＋", title: "Add podcasts (feed, Apple Podcasts or Spotify link, or search by name)",
            "aria-label": "Add podcasts", onclick: () => this.openAdd() }),
          search,
          picker ? picker({
            items: m.shows.map((s) => ({ id: String(s.feed_id), name: s.title, count: s.episodes,
              hint: `${s.unplayed} unplayed · keeps ${FW.fmtRetention ? FW.fmtRetention(s.keeps, true) : s.keeps}${s.error_count ? ` · ⚠ ${s.last_error || "failing"}` : ""}` })),
            selected: f.feed_ids, noun: "show", allLabel: `All shows (${m.shows.length})`, search: true,
            onAdd: () => this.openAdd(), addTitle: "Add podcasts",
            itemMenu: (item) => {
              const s = byId(item.id);
              return [["⚙ Settings…", () => this.openSettings(s)], ["▶ YouTube channel…", () => this.openYouTube(s)], ["🗑️ Remove", () => this.remove(s), true]];
            },
            onChange: (ids) => { f.feed_ids = ids; f.category = ""; this.save(); this.renderShell(); this.reload(); } }) : null,
          FW.sources && FW.sources.topicPicker ? FW.sources.topicPicker({ topics: this.topics.filter((t) => t.enabled), selected: f.topic_ids,
            onChange: (ids) => { f.topic_ids = ids; this.save(); this.reload(); } }) : null,
          select("state", "Show", [["all", "All episodes"], ["unplayed", "Unplayed"], ["played", "Played"], ["starred", "★ Starred"]]),
          select("sort", "Sort", [["newest", "📅 Newest"], ["oldest", "📅 Oldest"], ["longest", "Longest"], ["shortest", "Shortest"]]),
          FW.dateRange.button({ value: f.dates, title: "Show only episodes published between two dates",
            onChange: (r) => { f.dates = r; this.save(); this.renderShell(); this.reload(); } }),
          (() => {  // how episodes are laid out (more on screen with Compact / Grid)
            const s = h("select", { "aria-label": "View", onchange: (e) => { f.layout = e.target.value; this.save(); this.reload(); } },
              [["comfortable", "☰ View: Comfortable"], ["compact", "≡ View: Compact"], ["grid", "▦ View: Grid"]]
                .map(([v, l]) => h("option", { value: v, text: l, selected: (f.layout || "comfortable") === v })));
            return s;
          })(),
          this.categorySelect(),
          h("span", { class: "lib-view", role: "group", "aria-label": "View" }, tab("episodes", "🎧 Episodes"), tab("shows", "🗂️ Shows"))),
        h("div", { id: "podCount", class: "muted small lib-pad" }),
        h("div", { id: "podList", class: "pod-list" }, Array.from({ length: 6 }, () => h("div", { class: "skeleton-row", "aria-hidden": "true" },
          h("span", { class: "sk sk-meta" }), h("span", { class: "sk sk-title" }), h("span", { class: "sk sk-line" })))),
        h("div", { class: "lib-more" }, h("button", { id: "podMore", type: "button", class: "btn", text: "Load more", hidden: true, onclick: () => this.loadMore() })));
      if (!m.shows.length) {
        $("#podList").replaceWith(h("div", { class: "card lib-empty" },
          h("h3", { text: "No podcasts yet" }),
          h("p", { class: "muted", text: "Click ＋ and paste a podcast's feed, an Apple Podcasts or Spotify link - or search for a show by name. Episodes play right here." })));
      }
    },

    /** 📂 the shows' own categories (e.g. Darknet Diaries' list) - only shown when the chosen shows have some. */
    categorySelect() {
      const f = this.filters;
      const sel = h("select", { "aria-label": "Show categories", hidden: true, onchange: (e) => { f.category = e.target.value; this.save(); this.reload(); } });
      const p = new URLSearchParams();
      if (f.feed_ids.length) p.set("feed_ids", f.feed_ids.join(","));
      api("GET", `/podcasts/categories?${p}`).then((res) => {
        const cats = res.categories || [];
        if (f.category && !cats.some((c) => c.name === f.category)) cats.unshift({ name: f.category, episodes: 0 });
        fill(sel, h("option", { value: "", text: `📂 All categories${cats.length ? ` (${cats.length})` : ""}` }),
          cats.map((c) => h("option", { value: c.name, text: `📂 ${c.name} (${c.episodes})`, selected: f.category === c.name })));
        sel.hidden = !cats.length;
      }).catch(() => {});
      return sel;
    },

    query(offset) {
      const f = this.filters;
      const p = new URLSearchParams({ state: f.state, sort: f.sort, limit: f.layout === "comfortable" ? "40" : "80", offset: String(offset) });
      if (f.category) p.set("category", f.category);
      if (f.feed_ids.length) p.set("feed_ids", f.feed_ids.join(","));
      if (f.topic_ids.length) p.set("topic_ids", f.topic_ids.join(","));
      if (f.q) p.set("q", f.q);
      FW.dateRange.addParams(p, f.dates);
      if (this.mention && this.mention.article) p.set("related_to", String(this.mention.article));
      else if (this.mention) { p.set("entity_id", String(this.mention.id)); p.set("days", String(this.mention.days || 0)); }
      return `/podcasts/episodes?${p}`;
    },

    /** "List these podcasts" on an entity / technique page: every episode that mentions it, for the page's period. */
    mention: null,  // { id, name, days }
    async listEntity(entity) {
      this.mention = entity.article ? { article: Number(entity.article), name: String(entity.name || "") }
        : { id: Number(entity.id), name: String(entity.name || ""), days: Number(entity.days) || 0 };
      if (FW.currentMode && FW.currentMode() !== "podcasts") $("#modePodcasts").click();
      if (this.showing) await this.showing;
      else if (!this.meta || !$("#podList")) await this.show();
      Object.assign(this.filters, { feed_ids: [], q: "", state: "all", category: "", topic_ids: [], sort: "newest", view: "episodes" });
      this.save();
      this.renderShell();
      await this.reload();
    },
    /** "Open all in Podcasts" on an article's related episodes. */
    async listRelated(article) {
      await this.listEntity({ article: Number(article.id), name: String(article.title || "").slice(0, 90) });
    },
    mentionChip() {
      const m = this.mention;
      if (!m) return null;
      const period = m.days ? (m.days === 365 ? "in the last year" : `in the last ${m.days} days`) : "all time";
      if (m.article) return h("span", { class: "chip mention-filter", title: `Only episodes that name the same actors, malware or techniques as the article “${m.name}”` },
        `Related to the article: ${m.name}`,
        h("button", { type: "button", "aria-label": "Show all episodes again", title: "Show all episodes again", text: "×",
          onclick: () => { this.mention = null; this.reload(); } }));
      return h("span", { class: "chip mention-filter", title: `Only episodes that mention ${m.name} (${period})` }, `Mentions: ${m.name} · ${period}`,
        h("button", { type: "button", "aria-label": "Show all episodes again", title: "Show all episodes again", text: "×",
          onclick: () => { this.mention = null; this.reload(); } }));
    },

    async reload() {
      const list = $("#podList");
      if (!list) return;
      if (this.filters.view === "shows") { this.renderShows(list); return; }
      const q = this.query(0);
      const res = await guarded(() => api("GET", q));
      if (!res || this.query(0) !== q || this.filters.view !== "episodes") return;
      this.items = res.items; this.total = res.total;
      list.className = `pod-list layout-${this.filters.layout || "comfortable"}`;
      fill(list, this.items.length ? this.items.map((e) => this.episode(e)) : h("p", { class: "muted lib-pad", text: "No episodes match." }));
      fill($("#podCount"), `${this.total.toLocaleString()} episode${this.total === 1 ? "" : "s"} `, this.mentionChip());
      $("#podMore").hidden = this.items.length >= this.total;
    },
    async loadMore() {
      const res = await guarded(() => api("GET", this.query(this.items.length)));
      if (!res) return;
      this.items = this.items.concat(res.items);
      $("#podList").append(...res.items.map((e) => this.episode(e)));
      $("#podMore").hidden = this.items.length >= this.total;
    },

    renderShows(list) {
      list.className = "pod-shows";
      $("#podMore").hidden = true;
      $("#podCount").textContent = `${this.meta.shows.length} show${this.meta.shows.length === 1 ? "" : "s"}`;
      fill(list, this.meta.shows.map((s) => h("button", { type: "button", class: "pod-show", title: `Episodes of ${s.title}`,
        onclick: () => { this.filters.feed_ids = [String(s.feed_id)]; this.filters.view = "episodes"; this.save(); this.renderShell(); this.reload(); } },
        safeUrl(s.artwork) ? h("img", { src: safeUrl(s.artwork), alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "pod-noart", text: "🎙" }),
        h("strong", { text: s.title }),
        h("span", { class: "muted small", text: `${s.episodes} episodes · ${s.unplayed} unplayed` }))));
    },

    async mark(e, change, done) {
      const action = "is_read" in change ? (change.is_read ? "read" : "unread") : (change.is_starred ? "star" : "unstar");
      if (await guarded(() => api("POST", "/articles/bulk", { ids: [e.id], action }))) { Object.assign(e, change); if (done) done(); }
    },

    /** One episode: art, show, title, date · length, ▶ play (the show's own audio file), ✓ played, ★, notes. */
    episode(e) {
      const topicsById = Object.fromEntries(this.topics.map((t) => [t.id, t]));
      const audioUrl = safeUrl(e.audio_url);
      const art = safeUrl(e.image);
      const played = h("button", { type: "button", class: `icon-btn${e.is_read ? " on" : ""}`, text: e.is_read ? "↩" : "✓",
        title: e.is_read ? "Mark unplayed" : "Mark played", "aria-label": e.is_read ? "Mark unplayed" : "Mark played",
        onclick: () => this.mark(e, { is_read: !e.is_read }, () => { played.textContent = e.is_read ? "↩" : "✓"; played.classList.toggle("on", e.is_read); row.classList.toggle("played", e.is_read); }) });
      const star = h("button", { type: "button", class: `icon-btn${e.is_starred ? " on" : ""}`, text: e.is_starred ? "★" : "☆", title: "Star", "aria-label": "Star",
        onclick: () => this.mark(e, { is_starred: !e.is_starred }, () => { star.textContent = e.is_starred ? "★" : "☆"; star.classList.toggle("on", e.is_starred); }) });
      const play = h("button", { type: "button", class: "btn small primary", text: "▶ Play", disabled: !audioUrl, title: "Play in the player docked at the bottom",
        onclick: () => this.play(e, () => {   // finished: mark it played
          if (!e.is_read) this.mark(e, { is_read: true }, () => { played.textContent = "↩"; played.classList.add("on"); row.classList.add("played"); });
        }) });
      let resume = 0;
      try { resume = Number(localStorage.getItem(posKey(e.id)) || 0); } catch { /* storage off */ }
      const topics = (e.topics || []).map((id) => topicsById[id]).filter(Boolean);
      const link = safeUrl(e.url);
      const row = h("article", { class: `pod-ep${e.is_read ? " played" : ""}`, "data-ep": String(e.id) },
        art ? h("img", { class: "pod-art", src: art, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "pod-art pod-noart", text: "🎙" }),
        h("div", { class: "pod-body" },
          h("div", { class: "muted small" }, h("strong", { text: e.show }), ` · ${relTime(e.published)}`, e.duration_s ? ` · ${fmtDur(e.duration_s)}` : "",
            resume > 5 ? ` · ⏸ ${fmtDur(resume) || `${resume} s`} in` : ""),
          h("div", { class: "pod-title", title: fullDate(e.published), text: e.title }),
          e.summary ? (this.filters.layout === "comfortable"
            ? h("details", { class: "pod-desc" }, h("summary", { text: "Description" }), h("p", { text: e.summary }))
            : h("p", { class: "pod-snippet", title: e.summary, text: e.summary })) : null,
          (e.categories || []).length ? h("div", { class: "lib-topics" }, e.categories.map((c) => h("button", { type: "button", class: "topic-tag pod-topic pod-cat",
            title: `Every episode the show files under “${c}”`, text: `📂 ${c}`,
            onclick: () => { this.filters.category = c; this.filters.view = "episodes"; this.save(); this.renderShell(); this.reload(); } }))) : null,
          topics.length ? h("div", { class: "lib-topics" }, topics.map((t) => h("button", { type: "button", class: "topic-tag pod-topic",
            title: `Show every episode about ${t.name}`, onclick: () => { this.filters.topic_ids = [String(t.id)]; this.filters.view = "episodes"; this.save(); this.renderShell(); this.reload(); } },
            h("span", { class: "dot", style: { background: safeColor(t.color) } }), t.name))) : null,
          h("div", { class: "lib-actions" }, play, played, star,
            (link || safeUrl(e.show_site)) ? h("a", { class: "btn small", href: link || safeUrl(e.show_site), target: "_blank", rel: "noopener noreferrer",
              text: "🌐 Official page ↗", title: link ? "The episode on the show's own website" : "The show's website" }) : null,
            // the episode on YouTube: its own video when the show's channel is in Videos, else a YouTube search
            safeUrl(e.youtube_url)
              ? h("a", { class: "btn small", href: safeUrl(e.youtube_url), target: "_blank", rel: "noopener noreferrer", text: "▶ YouTube ↗", title: "This episode's video on YouTube" })
              : h("a", { class: "btn small", target: "_blank", rel: "noopener noreferrer", text: "🔎 YouTube ↗",
                title: "Not matched to a video yet: search for it on YouTube (in the show's channel when known)",
                href: safeUrl(e.youtube_search) || `https://www.youtube.com/results?search_query=${encodeURIComponent(`${e.show} ${e.title}`.slice(0, 200))}` }))));
      return row;
    },

    openSettings(s) {
      if (!FW.feeds || !FW.feeds.openFeedEditor) return;
      $("#feedDialog").addEventListener("close", () => { if (FW.currentMode() === "podcasts") this.refreshAll(); }, { once: true });
      FW.feeds.openFeedEditor(s.feed_id);
    },

    /** ▶ YouTube channel…: what was found for the show (and how many episodes are linked), set it by hand, or look again. */
    openYouTube(s) {
      const dlg = $("#sourceDialog");
      const y = s.youtube || { sources: [], how: null, linked: 0 };
      const HOW = { site: "found on the show's website", feed: "found in the show's feed", videos: "a channel you follow in Videos",
        search: "found by a YouTube search (close name match)", manual: "set by you", none: "not found" };
      const url = h("input", { type: "url", maxlength: 500, placeholder: "https://www.youtube.com/@channel or …/playlist?list=…", "aria-label": "YouTube channel or playlist link" });
      const msg = h("p", { class: "muted small", role: "status" });
      const send = async (method, path, body, ok) => {
        const r = await guarded(() => api(method, path, body), ok);
        if (r) { dlg.close(); await this.refreshAll(); }
      };
      fill(dlg, h("form", { method: "dialog", class: "dialog-form", onsubmit: (e) => {
          e.preventDefault();
          send("PUT", `/podcasts/${s.feed_id}/youtube`, { url: url.value.trim() }, "Saved - matching episodes in the background (refresh in a minute)");
        } },
        h("h3", { text: `▶ YouTube for ${s.title}` }),
        h("p", { class: "small", text: y.sources.length ? `Episodes are matched to videos on:` : (y.how ? "No YouTube channel or playlist for this show yet." : "Not looked up yet - it happens on the show's next check (needs the YouTube API key).") }),
        y.sources.length ? h("ul", { class: "small" }, y.sources.map((x) => h("li", null,
          h("a", { href: safeUrl(x.url), target: "_blank", rel: "noopener noreferrer", text: `${x.kind === "playlist" ? "Playlist" : "Channel"}: ${x.title || x.id} ↗` })))) : null,
        y.how ? h("p", { class: "muted small", text: `${HOW[y.how] || y.how} · ${y.linked.toLocaleString()} of ${s.episodes.toLocaleString()} episodes linked to their video` }) : null,
        h("label", { class: "small", text: "Use this channel or playlist instead:" }), url, msg,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "✕ Close", onclick: () => dlg.close() }),
          h("button", { type: "button", class: "btn", text: "🚫 No YouTube", title: "This show isn't on YouTube: episodes keep a YouTube search",
            onclick: () => send("PUT", `/podcasts/${s.feed_id}/youtube`, { url: null }, "Saved") }),
          h("button", { type: "button", class: "btn", text: "🔎 Find again", title: "Look for the show's channel again and re-match its episodes",
            onclick: () => send("POST", `/podcasts/${s.feed_id}/youtube/find`, null, "Looking in the background - refresh in a minute") }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
      if (!dlg.open) dlg.showModal();
    },

    async remove(s) {
      if (!window.confirm(`Unfollow “${s.title}” and delete its ${s.episodes} episode(s)? This cannot be undone.`)) return;
      if (await guarded(() => api("DELETE", `/podcasts/${s.feed_id}`), `Removed ${s.title}`)) {
        this.filters.feed_ids = this.filters.feed_ids.filter((id) => String(id) !== String(s.feed_id));
        this.save(); FW.loadSidebar(); await this.refreshAll();
      }
    },

    /** ＋ Add: paste feeds / Apple / Spotify links (one per line), or find a show by name and pick it. */
    openAdd() {
      const dlg = $("#sourceDialog");
      const links = h("textarea", { rows: 4, maxlength: 20000, "aria-label": "Podcast links, one per line",
        placeholder: "Links, one per line:\nhttps://podcasts.apple.com/…/id1296350485\nhttps://open.spotify.com/show/…\nhttps://feeds.example.com/podcast.xml" });
      const find = h("input", { type: "search", maxlength: 200, placeholder: "…or find a show by name (e.g. Darknet Diaries)", "aria-label": "Find a show by name" });
      const results = h("ul", { class: "pod-results" });
      const keep = FW.keepPicker({ choices: KEEP, selected: "0" });
      const log = h("ol", { class: "batch-list small" });
      const err = h("p", { class: "error" });
      const days = () => keep.days();
      const addOne = async (input, label) => {
        if (Number.isNaN(days())) { err.textContent = "Custom keep time frame must be 1 day to 100 years."; return false; }
        err.textContent = "";
        const li = h("li", null, h("code", { text: label }), " — ", h("span", { class: "muted", text: "adding…" }));
        log.append(li);
        const status = li.lastChild;
        try {
          const r = await api("POST", "/podcasts", { input, retention_days: days() });
          status.className = "status-ok";
          status.textContent = r.moved ? `✓ ${r.title} - moved here from Articles (${r.episodes_filled} saved episodes ready to play)` : `✓ ${r.title} - episodes arrive in a few seconds`;
          return true;
        } catch (ex) { status.className = /already/.test(ex.message) ? "muted" : "status-err"; status.textContent = ex.message; return false; }
      };
      let timer = null;
      find.addEventListener("input", () => {
        clearTimeout(timer);
        const q = find.value.trim();
        if (q.length < 2) { fill(results); return; }
        timer = setTimeout(async () => {
          fill(results, h("li", { class: "muted small", text: "Searching…" }));
          const res = await api("GET", `/podcasts/search?q=${encodeURIComponent(q)}`).catch((ex) => ({ results: [], error: ex.message }));
          if (find.value.trim() !== q) return;
          fill(results, res.results.length ? res.results.map((s) => h("li", { class: "pod-result" },
            safeUrl(s.artwork) ? h("img", { src: safeUrl(s.artwork), alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "pod-noart", text: "🎙" }),
            h("span", null, h("strong", { text: s.title }), h("span", { class: "muted small", text: ` — ${[s.author, s.genre, s.episodes ? `${s.episodes} episodes` : null].filter(Boolean).join(" · ")}` })),
            h("button", { type: "button", class: "btn small", text: "＋ Add", onclick: async (ev) => {
              const btn = ev.currentTarget;   // currentTarget is gone after the await
              btn.disabled = true;
              if (await addOne(s.feed_url, s.title)) { btn.textContent = "✓ Added"; this.refreshAll(); } else btn.disabled = false;
            } })))
            : h("li", { class: "muted small", text: res.error || "No shows found." }));
        }, 400);
      });
      const go = async (ev) => {
        ev.preventDefault();
        const lines = [...new Set(links.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))];
        if (!lines.length) { err.textContent = "Paste a link above, or find a show by name and press its ＋ Add."; return; }
        if (lines.length > 30) { err.textContent = "Up to 30 at a time, please."; return; }
        err.textContent = "";
        for (const line of lines) await addOne(line, line);
        links.value = "";
        this.refreshAll();
        setTimeout(() => { if (FW.currentMode() === "podcasts") this.refreshAll(); }, 5000);
      };
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: "＋ Add podcasts" }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        links, find, results,
        h("div", { class: "grid-form" }, h("label", { text: "Keep" }), keep.el),
        h("ul", { class: "small src-notes" },
          h("li", { text: "Episodes come from each show's own open feed and play here - no account needed." }),
          h("li", { text: "Spotify links: the show's name is looked up in Apple's podcast directory to find its feed. Spotify-exclusive shows have no open feed." })),
        log, err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Close", onclick: () => { dlg.close(); this.refreshAll(); } }),
          h("button", { type: "submit", class: "btn primary", text: "Add links" }))));
      if (!dlg.open) dlg.showModal();
      links.focus();
    },
  };

  FW.podcasts = view;
})();
