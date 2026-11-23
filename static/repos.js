/* 📦 Repos tab: GitHub owners, repositories, topics and stars you follow - repo cards, shelves by topic / owner /
 * language, releases, and the sources you follow. Same rules as app.js: DOM built with h()/textContent only,
 * links only through safeUrl, colours through safeColor. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, safeColor, store, relTime, fmtDate } = FW;
  const $ = (sel) => document.querySelector(sel);
  const DEFAULTS = { view: "folders", folder_id: "", kind: "", q: "", topic_ids: [], language: "", owner: "", source_id: "", gh_topic: "", min_stars: 0,
    starred: false, hide_archived: false, hide_forks: false, sort: "stars", dates: null };
  // the inner tabs (like Podcasts' 🎧 Episodes / 🗂️ Shows)
  const VIEWS = [["folders", "📁 Folders"], ["grid", "▦ All repos"], ["topic", "🏷️ By topic"], ["owner", "👤 By owner"],
    ["language", "💻 By language"], ["releases", "🚀 Releases"]];
  const SORTS = [["stars", "★ Sort: Most stars"], ["pushed", "🕒 Sort: Recently updated"], ["created", "🆕 Sort: Newest on GitHub"],
    ["added", "📥 Sort: Recently added here"], ["name", "Sort: A–Z"]];
  const STARS = [[0, "Stars"], [10, "10+ stars"], [100, "100+ stars"], [1000, "1k+ stars"], [10000, "10k+ stars"]];
  const KIND = { owner: "👤 Owner", repo: "📦 Repo", topic: "# Topic", stars: "★ Stars", gist: "🧾 Gist", doc: "📄 Doc / site", gitlab: "🦊 GitLab" };
  const TYPES = [["", "Type"], ["repo", "📦 Repos"], ["gist", "🧾 Gists"], ["doc", "📄 Docs & websites"]];
  const PAGE = 60;
  const fmtNum = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(n >= 1e4 ? 0 : 1)}k` : String(n || 0));

  const view = {
    meta: null,
    folders: null,
    selecting: false,
    selected: new Set(),
    items: [],
    total: 0,
    poll: null,
    filters: (() => {
      const f = { ...DEFAULTS, ...(store.get("fw-repos-filters") || {}) };
      if (!store.get("fw-repos-folders-default")) { f.view = "folders"; f.folder_id = ""; store.set("fw-repos-folders-default", true); }  // once: Folders is the new start page
      if (!VIEWS.some(([v]) => v === f.view)) f.view = "folders";
      f.folder_id = f.folder_id === undefined || f.folder_id === null ? "" : String(f.folder_id);
      if (!SORTS.some(([v]) => v === f.sort)) f.sort = "stars";
      return f;
    })(),

    async show() {
      const el = $("#reposView");
      if (!this.meta) fill(el, h("p", { class: "muted lib-pad", text: "Loading repos…" }));
      await Promise.all([this.loadMeta(), this.loadFolders()]);
      this.renderShell();
      await this.reload();
      this.watch();
    },
    async loadFolders() {
      this.folders = await api("GET", "/repos/folders").catch(() => ({ folders: [], unfiled: 0, unfiled_peek: [] }));
    },
    folderName(id) {
      if (String(id) === "0") return "Not in a folder";
      const f = (this.folders ? this.folders.folders : []).find((x) => String(x.id) === String(id));
      return f ? `${f.emoji} ${f.name}` : "a folder";
    },
    hide() { clearTimeout(this.poll); this.poll = null; },
    save() { store.set("fw-repos-filters", this.filters); },
    async loadMeta() {
      this.meta = await api("GET", "/repos/meta").catch((ex) => ({ missing: ex.message === "Not Found", total: 0, starred: 0, archived: 0, forks: 0, releases: 0, languages: [],
        owners: [], topics: [], untagged: 0, sources: [], token_set: false, rate: {} }));
    },
    async refreshAll() { await Promise.all([this.loadMeta(), this.loadFolders()]); this.renderShell(); await this.reload(); },
    /** While a newly added source is still being fetched, look again every few seconds (up to ~3 minutes). */
    watch(rounds = 45) {
      clearTimeout(this.poll);
      const pending = (this.meta.sources || []).some((s) => !s.last_fetch && !s.last_error);
      if (!pending || rounds <= 0) return;
      this.poll = setTimeout(async () => {
        if (FW.currentMode() !== "repos") return;
        const before = this.meta.total;
        await this.loadMeta();
        if (this.meta.total !== before || !(this.meta.sources || []).some((s) => !s.last_fetch && !s.last_error)) { this.renderShell(); await this.reload(); }
        this.watch(rounds - 1);
      }, 4000);
    },

    params(extra = {}) {
      const f = this.filters;
      const p = new URLSearchParams();
      if (f.q) p.set("q", f.q);
      if (f.topic_ids.length) p.set("topic_ids", f.topic_ids.join(","));
      if (f.language) p.set("language", f.language);
      if (f.owner) p.set("owner", f.owner);
      if (f.source_id) p.set("source_id", f.source_id);
      if (f.folder_id !== "") p.set("folder_id", f.folder_id);
      if (f.kind) p.set("kind", f.kind);
      if (f.gh_topic) p.set("gh_topic", f.gh_topic);
      if (f.min_stars) p.set("min_stars", f.min_stars);
      if (f.starred) p.set("starred", "true");
      if (f.hide_archived) p.set("hide_archived", "true");
      if (f.hide_forks) p.set("hide_forks", "true");
      p.set("sort", f.sort);
      if (FW.dateRange) FW.dateRange.addParams(p, f.dates);
      for (const [k, v] of Object.entries(extra)) p.set(k, v);
      return p;
    },
    set(changes, rerenderShell = true) {
      Object.assign(this.filters, changes);
      this.save();
      if (rerenderShell) this.renderShell();
      this.reload();
    },

    renderShell() {
      const el = $("#reposView");
      const f = this.filters;
      const m = this.meta;
      const search = h("input", { type: "search", placeholder: "Search names, descriptions, GitHub topics…", maxlength: 200, value: f.q, "aria-label": "Search repos" });
      let timer = null;
      search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); this.save(); this.reload(); }, 300); });
      const select = (label, options, value, onchange) => h("select", { "aria-label": label, onchange: (e) => onchange(e.target.value) },
        options.map(([v, l]) => h("option", { value: String(v), text: l, selected: String(value) === String(v) })));
      const tick = (label, key, title) => h("label", { class: "repo-tick", title },
        h("input", { type: "checkbox", checked: Boolean(f[key]), onchange: (e) => this.set({ [key]: e.target.checked }, false) }), ` ${label}`);
      const topicPicker = FW.sources && FW.sources.topicPicker ? FW.sources.topicPicker({
        topics: [...m.topics.filter((t) => t.enabled).map((t) => ({ ...t, count: t.repos })), { id: 0, name: "No topic", color: "#6b7280", count: m.untagged }],
        selected: f.topic_ids, buttonLabel: "Topics", onChange: (ids) => this.set({ topic_ids: ids }, false) }) : null;
      // Sort, with 📅 Custom range… at the bottom (like Videos / Podcasts): a date filter, not a sort - the sort stays as it was
      const sortSel = h("select", { "aria-label": "Sort", title: "Sort" },
        SORTS.map(([v, l]) => h("option", { value: v, text: l, selected: f.sort === v })),
        FW.dateRange ? [h("hr"),
          h("option", { value: "custom-range", text: f.dates ? `📅 Custom range: ${FW.dateRange.label(f.dates)}…` : "📅 Custom range…" }),
          f.dates ? h("option", { value: "clear-range", text: "✕ Clear custom range" }) : null] : null);
      sortSel.addEventListener("change", async () => {
        const pick = sortSel.value;
        if (pick === "custom-range" || pick === "clear-range") {
          sortSel.value = f.sort;
          const r = pick === "clear-range" ? null : await FW.dateRange.pick(f.dates);
          if (r === undefined) return;  // cancelled
          this.set({ dates: r });
        } else {
          this.set({ sort: pick }, false);
        }
      });
      if (f.dates) { sortSel.classList.add("on"); sortSel.title = `Sort - showing only repos last updated ${FW.dateRange.label(f.dates)}`; }
      const tab = (v, label) => h("button", { type: "button", class: `btn small${f.view === v ? " primary" : ""}`, "aria-pressed": String(f.view === v), text: label,
        onclick: () => { if (f.view !== v) this.set({ view: v }); } });
      const chips = [];
      const chip = (text, clear) => chips.push(h("button", { type: "button", class: "btn small repo-chip-on", text: `${text} ✕`, title: "Remove this filter", onclick: clear }));
      if (f.folder_id !== "") chip(`📁 ${this.folderName(f.folder_id).replace(/^\S+\s/, "")}`, () => this.set({ folder_id: "" }));
      if (f.owner) chip(`👤 ${f.owner}`, () => this.set({ owner: "" }));
      if (f.gh_topic) chip(`#${f.gh_topic}`, () => this.set({ gh_topic: "" }));
      if (f.source_id) {
        const s = m.sources.find((x) => String(x.id) === String(f.source_id));
        chip(`From ${s ? s.title || s.value : "a source"}`, () => this.set({ source_id: "" }));
      }
      const anyFilter = f.kind || f.q || f.topic_ids.length || f.language || f.owner || f.source_id || f.gh_topic || f.min_stars || f.starred || f.hide_archived || f.hide_forks || f.dates;
      const errors = m.sources.filter((s) => s.last_error).length;
      fill(el,
        h("div", { class: "studio-header lib-header" },
          h("h2", { text: "📦 Repos" }),
          h("button", { type: "button", class: "btn small primary lib-add-plus", text: "＋", title: "Add GitHub repos (or owners, topics, stars)", "aria-label": "Add GitHub repos", onclick: () => this.openAdd() }),
          search, topicPicker,
          select("Language", [["", "Language"], ...m.languages.map((l) => [l.name, `${l.name} (${l.count})`])], f.language, (v) => this.set({ language: v }, false)),
          sortSel,
          h("button", { type: "button", class: `btn small${errors ? " repo-warn" : ""}`, text: `⚙ Sources${errors ? ` ⚠ ${errors}` : ""}`,
            title: `What you added (${m.sources.length}${errors ? `, ${errors} with a problem` : ""}), check now, and the optional GitHub token`, onclick: () => this.openSources() }),
          h("span", { class: "lib-view repo-views", role: "group", "aria-label": "View" }, VIEWS.map(([v, l]) => tab(v, l)))),
        f.view === "releases" ? null : h("div", { class: "repo-filters lib-pad" },
          select("Type", TYPES.map(([v, l]) => [v, v && this.meta.kinds ? `${l} (${(this.meta.kinds[v] || 0).toLocaleString()})` : l]), f.kind, (v) => this.set({ kind: v }, false)),
          select("Minimum stars", STARS, f.min_stars, (v) => this.set({ min_stars: Number(v) }, false)),
          tick("★ Starred", "starred", "Only repos you starred here"),
          tick("Hide archived", "hide_archived", "Hide read-only (archived) repos"),
          tick("Hide forks", "hide_forks", "Hide copies of other repos"),
          ...chips,
          anyFilter ? h("button", { type: "button", class: "btn small", text: "Clear filters", onclick: () => this.set({ ...DEFAULTS, view: f.view, sort: f.sort, folder_id: f.folder_id }) }) : null,
          f.view === "folders" && f.folder_id !== "" ? h("button", { type: "button", class: "btn small", text: "← All folders", onclick: () => this.set({ folder_id: "" }) }) : null,
          f.view === "folders" && f.folder_id === "" ? null : h("button", { type: "button", class: `btn small${this.selecting ? " primary" : ""}`, "aria-pressed": String(this.selecting),
            text: this.selecting ? "☑ Selecting…" : "☑ Select", title: "Tick repos to add them to a folder or take them out",
            onclick: () => { this.selecting = !this.selecting; this.selected.clear(); this.renderShell(); this.reload(); } })),
        this.selecting ? h("div", { id: "repoSelBar", class: "repo-sel-bar lib-pad" }) : null,
        h("div", { id: "repoCount", class: "muted small lib-pad", "aria-live": "polite" }),
        h("div", { id: "repoBody" }),
        h("div", { class: "lib-more" }, h("button", { id: "repoMore", type: "button", class: "btn", text: "Load more", hidden: true, onclick: () => this.loadMore() })));
      if (m.missing) {  // the page files are newer than the running server (it needs a restart)
        $("#repoBody").replaceWith(h("div", { class: "card lib-empty" }, h("h3", { text: "Restart needed" }),
          h("p", { class: "muted", text: "The server running this app doesn't have the Repos tab yet. Restart the app, then reload this page." })));
      } else if (!m.sources.length && !m.total) {
        $("#repoBody").replaceWith(h("div", { class: "card lib-empty" },
          h("h3", { text: "Add your first GitHub repos" }),
          h("p", { class: "muted", text: "Click ＋ and paste repo links, one per line (any page inside a repo works). You can also add an owner (github.com/SpecterOps) to get all their repos, a GitHub topic (topic:homelab) or someone's stars (stars:octocat). Repos are filed into your topics and refreshed twice a day." }),
          h("button", { type: "button", class: "btn primary", text: "＋ Add from GitHub", onclick: () => this.openAdd() })));
      }
    },

    async reload() {
      const body = $("#repoBody");
      if (!body) return;
      const f = this.filters;
      const count = $("#repoCount");
      const more = $("#repoMore");
      if (more) more.hidden = true;
      try {
        if (f.view === "folders" && f.folder_id === "") {
          if (!this.folders) await this.loadFolders();
          this.renderFolders(body, count);
          return;
        }
        if (f.view === "releases") {
          const p = new URLSearchParams({ limit: "100" });
          if (f.q) p.set("q", f.q);
          if (FW.dateRange) FW.dateRange.addParams(p, f.dates);
          const data = await api("GET", `/repos/releases?${p}`);
          count.textContent = `${data.total.toLocaleString()} release(s) from the repos you added one by one`;
          this.renderReleases(body, data.items);
          return;
        }
        if (f.view === "topic" || f.view === "owner" || f.view === "language") {
          const data = await api("GET", `/repos/shelves?${this.params({ by: f.view, per: "8" })}`);
          count.textContent = `${data.repos.toLocaleString()} repo(s) on ${data.shelves.length.toLocaleString()} shelf/shelves`;
          this.renderShelves(body, data);
          return;
        }
        const data = await api("GET", `/repos?${this.params({ limit: String(PAGE), offset: "0" })}`);
        this.items = data.items;
        this.total = data.total;
        count.textContent = `${data.total.toLocaleString()} repo(s)${f.folder_id !== "" ? ` in ${this.folderName(f.folder_id)}` : ""}`;
        this.renderSelBar();
        fill(body, data.items.length ? h("div", { class: "repo-grid" }, data.items.map((r) => this.card(r)))
          : h("p", { class: "muted lib-pad", text: this.meta.total ? "No repos match these filters." : "" }));
        if (more) more.hidden = this.items.length >= this.total;
      } catch (err) {
        fill(body, h("p", { class: "error lib-pad", text: err.message }));
      }
    },

    async loadMore() {
      const data = await guarded(() => api("GET", `/repos?${this.params({ limit: String(PAGE), offset: String(this.items.length) })}`));
      if (!data) return;
      this.items.push(...data.items);
      const grid = $("#repoBody .repo-grid");
      if (grid) grid.append(...data.items.map((r) => this.card(r)));
      $("#repoMore").hidden = this.items.length >= data.total;
    },

    card(r) {
      const topicInfo = new Map(this.meta.topics.map((t) => [t.id, t]));
      const star = h("button", { type: "button", class: `icon-btn repo-star${r.starred ? " on" : ""}`, text: r.starred ? "★" : "☆",
        title: r.starred ? "Starred here (kept even if you remove the source it came from) - click to unstar" : "Star (keep it here)",
        "aria-label": r.starred ? `Unstar ${r.full_name}` : `Star ${r.full_name}`, "aria-pressed": String(r.starred),
        onclick: async () => {
          const res = await guarded(() => api("PATCH", `/repos/${r.id}`, { starred: !r.starred }));
          if (!res) return;
          r.starred = res.starred;
          star.textContent = r.starred ? "★" : "☆";
          star.classList.toggle("on", r.starred);
          star.setAttribute("aria-pressed", String(r.starred));
          this.loadMeta();
        } });
      const avatar = safeUrl(r.owner_avatar) ? h("img", { class: "repo-avatar", src: safeUrl(r.owner_avatar), alt: "", loading: "lazy", referrerpolicy: "no-referrer", width: 28, height: 28 })
        : h("span", { class: "repo-avatar repo-avatar-none", text: (r.owner || "?").slice(0, 1).toUpperCase() });
      const isRepo = !r.kind || r.kind === "repo";
      const facts = [
        r.kind === "gist" ? h("span", { class: "repo-badge repo-kind", text: "🧾 Gist" }) : null,
        /^https:\/\/gitlab\.com\//.test(r.url || "") ? h("span", { class: "repo-badge repo-kind", text: "🦊 GitLab" }) : null,
        r.kind === "doc" ? h("span", { class: "repo-badge repo-kind", text: r.owner === "github-docs" ? "📄 GitHub Docs" : /^https:\/\/github\.com\//.test(r.url || "") ? "👤 Profile" : "🌐 Website" }) : null,
        r.language ? h("span", { class: "repo-fact", text: `💻 ${r.language}` }) : null,
        isRepo ? h("span", { class: "repo-fact", title: `${(r.stars || 0).toLocaleString()} stars on GitHub`, text: `★ ${fmtNum(r.stars)}` }) : null,
        isRepo ? h("span", { class: "repo-fact", title: `${(r.forks || 0).toLocaleString()} forks`, text: `⑂ ${fmtNum(r.forks)}` }) : null,
        r.kind === "gist" && r.open_issues ? h("span", { class: "repo-fact", text: `💬 ${r.open_issues}` }) : null,
        r.license ? h("span", { class: "repo-fact", title: "Licence", text: `⚖ ${r.license}` }) : null,
        r.archived ? h("span", { class: "repo-badge", title: "Archived: read-only, no longer maintained", text: "archived" }) : null,
        r.is_fork ? h("span", { class: "repo-badge", title: "A fork (copy) of another repo", text: "fork" }) : null,
      ];
      const ours = (r.topics || []).map((id) => topicInfo.get(id)).filter(Boolean).map((t) =>
        h("button", { type: "button", class: "repo-topic", style: `--c:${safeColor(t.color)}`, text: t.name, title: `Show ${t.name} repos`,
          onclick: () => this.set({ topic_ids: [t.id], view: "grid" }) }));
      const tags = (r.gh_topics || []).slice(0, 8).map((t) =>
        h("button", { type: "button", class: "repo-tag", text: `#${t}`, title: `Show repos tagged ${t} on GitHub`, onclick: () => this.set({ gh_topic: t, view: "grid" }) }));
      const home = safeUrl(r.homepage);
      const folderInfo = new Map((this.folders ? this.folders.folders : []).map((x) => [x.id, x]));
      const inFolders = (r.folders || []).map((id) => folderInfo.get(id)).filter(Boolean);
      const del = h("button", { type: "button", class: "icon-btn repo-del", text: "🗑", title: "Remove from Repos", "aria-label": `Remove ${r.full_name} from Repos`,
        onclick: async () => {
          const what = !r.kind || r.kind === "repo" ? "repo" : r.kind === "gist" ? "gist" : "link";
          if (!window.confirm(`Remove the ${what} “${r.name}” from Repos?\n\nIt's taken out of every folder. If an owner, topic or stars list also brings it in, it won't come back from there (paste it again any time to re-add it).`)) return;
          const res = await guarded(() => api("DELETE", `/repos/${r.id}`));
          if (!res) return;
          toast(`Removed ${r.name}${res.hidden ? " - it won't come back from your lists" : ""}`);
          await this.refreshAll();
        } });
      const fbtn = h("button", { type: "button", class: `icon-btn repo-fbtn${inFolders.length ? " on" : ""}`, text: "📁",
        title: inFolders.length ? `In ${inFolders.map((x) => x.name).join(", ")} - change folders` : "Put in a folder",
        "aria-label": `Folders for ${r.full_name}`, onclick: () => this.openFolderPicker(r) });
      const tickBox = this.selecting ? h("input", { type: "checkbox", class: "repo-check", checked: this.selected.has(r.id), "aria-label": `Select ${r.full_name}`,
        onchange: (e) => { if (e.target.checked) this.selected.add(r.id); else this.selected.delete(r.id); this.renderSelBar(); } }) : null;
      return h("article", { class: `repo-card${r.archived ? " archived" : ""}${this.selecting && this.selected.has(r.id) ? " picked" : ""}` },
        h("div", { class: "repo-head" }, tickBox, avatar,
          h("div", { class: "repo-title" },
            isRepo ? h("a", { href: safeUrl(r.url), target: "_blank", rel: "noopener noreferrer", class: "repo-name", title: `Open ${r.full_name}` },
              h("span", { class: "muted", text: `${r.owner}/` }), h("strong", { text: r.name }))
              : h("a", { href: safeUrl(r.url), target: "_blank", rel: "noopener noreferrer", class: "repo-name", title: r.url }, h("strong", { text: r.name })),
            h("button", { type: "button", class: "repo-owner-btn muted small", text: `👤 ${r.owner}`, title: `Show only ${r.owner}'s repos`, onclick: () => this.set({ owner: r.owner, view: "grid" }) })),
          fbtn, star, del),
        inFolders.length ? h("div", { class: "repo-fchips" }, inFolders.map((x) => h("button", { type: "button", class: "repo-fchip", style: `--c:${safeColor(x.color)}`,
          text: `${x.emoji} ${x.name}`, title: `Open the ${x.name} folder`, onclick: () => this.set({ view: "folders", folder_id: String(x.id) }) }))) : null,
        r.description ? h("p", { class: "repo-desc", text: r.description }) : h("p", { class: "repo-desc muted", text: "No description." }),
        h("div", { class: "repo-facts" }, facts),
        ours.length ? h("div", { class: "repo-topics" }, ours) : null,
        tags.length ? h("div", { class: "repo-tags" }, tags) : null,
        h("div", { class: "repo-foot muted small" },
          h("span", { title: r.pushed_ts ? `Last change ${fmtDate(r.pushed_ts)}` : "", text: r.pushed_ts ? `Updated ${relTime(r.pushed_ts)}` : r.kind === "doc" ? "Saved link" : "" }),
          home ? h("a", { href: home, target: "_blank", rel: "noopener noreferrer nofollow", text: "🌐 Website ↗", title: home }) : null));
    },

    /** 📁 Folders view: your folders as tiles (count + a peek at their top repos), Not in a folder, and ＋ New folder. */
    renderFolders(body, count) {
      const data = this.folders || { folders: [], unfiled: 0, unfiled_peek: [] };
      const list = data.folders;
      count.textContent = `${list.length} folder(s) · ${(this.meta.total || 0).toLocaleString()} repo(s), ${data.unfiled.toLocaleString()} not in a folder`;
      const peek = (items) => h("ul", { class: "repo-folder-peek small" }, items.map((p) => h("li", null,
        safeUrl(p.owner_avatar) ? h("img", { src: safeUrl(p.owner_avatar), alt: "", loading: "lazy", referrerpolicy: "no-referrer", width: 16, height: 16 }) : null,
        h("span", { text: p.full_name }))));
      const tile = (f, idx) => {
        const open = () => this.set({ folder_id: String(f.id) });
        const menu = h("details", { class: "repo-folder-menu" },
          h("summary", { class: "icon-btn", text: "⋯", title: "Folder options", "aria-label": `Options for ${f.name}` }),
          h("div", { class: "repo-folder-menu-list", role: "menu" },
            h("button", { type: "button", role: "menuitem", class: "btn small", text: "✎ Rename, emoji, colour", onclick: () => this.editFolder(f) }),
            idx > 0 ? h("button", { type: "button", role: "menuitem", class: "btn small", text: "← Move earlier", onclick: () => this.moveFolder(f.id, -1) }) : null,
            idx < list.length - 1 ? h("button", { type: "button", role: "menuitem", class: "btn small", text: "→ Move later", onclick: () => this.moveFolder(f.id, 1) }) : null,
            h("button", { type: "button", role: "menuitem", class: "btn small danger", text: "🗑 Delete folder", onclick: () => this.deleteFolder(f) })));
        return h("article", { class: "repo-folder", style: `--c:${safeColor(f.color)}` },
          h("div", { class: "repo-folder-head" },
            h("button", { type: "button", class: "repo-folder-open", onclick: open, title: `Open ${f.name}` },
              h("span", { class: "repo-folder-emoji", text: f.emoji }), h("strong", { text: f.name }),
              h("span", { class: "muted small", text: ` ${f.repos.toLocaleString()} repo(s)` })),
            menu),
          f.peek.length ? peek(f.peek) : h("p", { class: "muted small", text: "Empty - use 📁 on a repo, or ☑ Select in All repos." }),
          f.repos > f.peek.length ? h("button", { type: "button", class: "btn small", text: `Open all ${f.repos.toLocaleString()} ›`, onclick: open }) : null);
      };
      fill(body, h("div", { class: "repo-folders" },
        list.map(tile),
        h("article", { class: "repo-folder repo-folder-unfiled", style: "--c:#6b7280" },
          h("div", { class: "repo-folder-head" },
            h("button", { type: "button", class: "repo-folder-open", onclick: () => this.set({ folder_id: "0" }), title: "Repos that aren't in any folder" },
              h("span", { class: "repo-folder-emoji", text: "🗂️" }), h("strong", { text: "Not in a folder" }),
              h("span", { class: "muted small", text: ` ${data.unfiled.toLocaleString()} repo(s)` }))),
          data.unfiled_peek.length ? peek(data.unfiled_peek) : h("p", { class: "muted small", text: "Every repo is in a folder." })),
        h("button", { type: "button", class: "repo-folder repo-folder-new", onclick: () => this.editFolder(null) },
          h("span", { class: "repo-folder-emoji", text: "＋" }), h("strong", { text: "New folder" }))));
    },

    /** Create (folder = null) or edit a folder: name, emoji, colour. Resolves to the saved folder or null. */
    editFolder(folder) {
      return new Promise((resolve) => {
        const name = h("input", { type: "text", maxlength: 60, value: folder ? folder.name : "", required: true, "aria-label": "Folder name", placeholder: "e.g. Red team tools" });
        const emoji = h("input", { type: "text", maxlength: 8, value: folder ? folder.emoji : "📁", "aria-label": "Emoji", class: "repo-emoji-input" });
        const color = h("input", { type: "color", value: folder ? folder.color : "#64748b", "aria-label": "Colour" });
        const err = h("p", { class: "error small" });
        let saved = null;
        const dlg = h("dialog", { class: "range-dialog", "aria-label": folder ? "Edit folder" : "New folder" },
          h("form", { method: "dialog", class: "form", onsubmit: async (e) => {
            e.preventDefault();
            const body = { name: name.value.trim(), emoji: emoji.value.trim() || "📁", color: color.value };
            try {
              saved = folder ? await api("PATCH", `/repos/folders/${folder.id}`, body) : await api("POST", "/repos/folders", body);
              dlg.close();
            } catch (ex) { err.textContent = ex.message; }
          } },
            h("h3", { text: folder ? "✎ Edit folder" : "📁 New folder" }),
            h("label", null, "Name ", name), h("label", null, "Emoji ", emoji), h("label", null, "Colour ", color), err,
            h("div", { class: "form-actions" },
              h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
              h("button", { type: "submit", class: "btn primary", text: folder ? "Save" : "Create" }))));
        dlg.addEventListener("close", async () => {
          dlg.remove();
          if (saved) { await this.loadFolders(); if (FW.currentMode() === "repos") { this.renderShell(); await this.reload(); } }
          resolve(saved);
        });
        document.body.append(dlg);
        dlg.showModal();
        name.focus();
      });
    },
    async moveFolder(id, dir) {
      const ids = this.folders.folders.map((x) => x.id);
      const i = ids.indexOf(id), j = i + dir;
      if (i < 0 || j < 0 || j >= ids.length) return;
      [ids[i], ids[j]] = [ids[j], ids[i]];
      if (await guarded(() => api("POST", "/repos/folders/reorder", { ids }))) { await this.loadFolders(); this.reload(); }
    },
    async deleteFolder(f) {
      if (!window.confirm(`Delete the folder “${f.name}”? Its ${f.repos} repo(s) stay in Repos (and in any other folder).`)) return;
      if (await guarded(() => api("DELETE", `/repos/folders/${f.id}`), `Deleted ${f.name} - its repos are still in Repos`)) {
        if (String(this.filters.folder_id) === String(f.id)) this.filters.folder_id = "";
        await this.refreshAll();
      }
    },

    /** 📁 on a card: tick the folders this repo belongs in (or make a new one). */
    openFolderPicker(r) {
      const list = this.folders ? this.folders.folders : [];
      const ticks = list.map((x) => ({ x, box: h("input", { type: "checkbox", checked: (r.folders || []).includes(x.id) }) }));
      const err = h("p", { class: "error small" });
      const dlg = h("dialog", { class: "range-dialog", "aria-label": `Folders for ${r.full_name}` });
      const save = async () => {
        const ids = ticks.filter((t) => t.box.checked).map((t) => t.x.id);
        try {
          const res = await api("PUT", `/repos/${r.id}/folders`, { folder_ids: ids });
          r.folders = res.folders;
          dlg.close();
          if (!res.still_here) toast(`${r.full_name} left Repos: no source lists it any more and it's in no folder`);
          await this.loadFolders();
          this.renderShell();
          await this.reload();
        } catch (ex) { err.textContent = ex.message; }
      };
      fill(dlg, h("div", { class: "form" },
        h("h3", { text: `📁 ${r.full_name}` }),
        list.length ? h("ul", { class: "repo-folder-ticks" }, ticks.map((t) => h("li", null, h("label", null, t.box, ` ${t.x.emoji} ${t.x.name}`))))
          : h("p", { class: "muted small", text: "No folders yet." }),
        h("button", { type: "button", class: "btn small", text: "＋ New folder…", onclick: async () => {
          const made = await this.editFolder(null);
          if (made) { r.folders = [...(r.folders || []).filter((id) => ticks.some((t) => t.x.id === id && t.box.checked)), made.id]; dlg.close(); this.openFolderPicker(r); }
        } }),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "button", class: "btn primary", text: "Save", onclick: save }))));
      dlg.addEventListener("close", () => dlg.remove());
      document.body.append(dlg);
      dlg.showModal();
    },

    /** ☑ Select: the bar under the filters - add the ticked repos to a folder, or take them out of one. */
    renderSelBar() {
      const bar = $("#repoSelBar");
      if (!bar) return;
      const list = this.folders ? this.folders.folders : [];
      const open = this.filters.folder_id && this.filters.folder_id !== "0" ? this.filters.folder_id : "";
      const sel = h("select", { "aria-label": "Folder" }, list.map((x) => h("option", { value: String(x.id), text: `${x.emoji} ${x.name}`, selected: String(x.id) === String(open) })));
      const n = this.selected.size;
      const run = async (action) => {
        if (!n) { toast("Tick some repos first", true); return; }
        if (!sel.value) { toast("Create a folder first", true); return; }
        const res = await guarded(() => api("POST", `/repos/folders/${sel.value}/items`, { repo_ids: [...this.selected], action }));
        if (!res) return;
        toast(`${action === "add" ? "Added" : "Took out"} ${res.changed} repo(s) ${action === "add" ? "to" : "of"} ${sel.selectedOptions[0].text}`);
        this.selected.clear();
        await this.loadFolders();
        this.renderShell();
        await this.reload();
      };
      fill(bar,
        h("strong", { text: `${n} selected` }),
        h("button", { type: "button", class: "btn small", text: "Tick all shown", onclick: () => { this.items.forEach((r) => this.selected.add(r.id)); this.reload(); } }),
        n ? h("button", { type: "button", class: "btn small", text: "Untick all", onclick: () => { this.selected.clear(); this.reload(); } }) : null,
        list.length ? sel : h("span", { class: "muted small", text: "No folders yet" }),
        h("button", { type: "button", class: "btn small primary", text: "＋ Add to folder", disabled: !list.length, onclick: () => run("add") }),
        h("button", { type: "button", class: "btn small", text: "− Remove from folder", disabled: !list.length, onclick: () => run("remove") }),
        h("button", { type: "button", class: "btn small", text: "📁 New folder…", onclick: async () => { if (await this.editFolder(null)) this.renderSelBar(); } }));
    },

    renderShelves(body, data) {
      const f = this.filters;
      if (!data.shelves.length) { fill(body, h("p", { class: "muted lib-pad", text: this.meta.total ? "No repos match these filters." : "" })); return; }
      fill(body, data.shelves.map((s) => {
        const showAll = () => {
          const change = { view: "grid" };
          if (data.by === "topic") change.topic_ids = [s.key];
          else if (data.by === "owner") change.owner = String(s.key);
          else change.language = String(s.key);
          this.set(change);
        };
        return h("section", { class: "repo-shelf" },
          h("div", { class: "repo-shelf-head" },
            s.color ? h("span", { class: "repo-dot", style: `--c:${safeColor(s.color)}` }) : null,
            h("h3", { text: s.label }), h("span", { class: "muted small", text: `${s.total.toLocaleString()} repo(s)` }),
            s.total > s.items.length ? h("button", { type: "button", class: "btn small", text: "Show all ›", onclick: showAll }) : null),
          h("div", { class: "repo-grid" }, s.items.map((r) => this.card(r))));
      }));
      void f;
    },

    renderReleases(body, items) {
      if (!items.length) {
        fill(body, h("div", { class: "card lib-empty" }, h("h3", { text: "No releases yet" }),
          h("p", { class: "muted", text: "Releases are collected for repos you add one by one (＋ → a repo link such as github.com/projectdiscovery/nuclei). New versions then show up here with their dates." })));
        return;
      }
      fill(body, h("ol", { class: "repo-releases" }, items.map((x) => h("li", { class: "repo-release" },
        h("span", { class: "muted small repo-rel-date", title: fmtDate(x.published_ts), text: fmtDate(x.published_ts) }),
        h("div", null,
          h("div", null,
            h("a", { href: safeUrl(x.url), target: "_blank", rel: "noopener noreferrer", class: "repo-rel-title", text: x.title || x.tag }),
            h("span", { class: "muted small", text: ` · ${x.full_name}${x.title && x.title !== x.tag ? ` · ${x.tag}` : ""}` })),
          x.summary ? h("p", { class: "muted small repo-rel-sum", text: x.summary }) : null)))));
    },

    /** ＋ Add: paste up to 200 repos, owners, topic:<name> or stars:<user>, one per line. Every valid line is saved at
     *  once; the background sync then checks them with GitHub (paced to its hourly limit) and each line updates as it
     *  finishes: added / already here / doesn't exist / a website / waiting for GitHub's limit. */
    openAdd() {
      const MAX_LINES = 200;
      const dlg = $("#sourceDialog");
      const box = h("textarea", { rows: 7, maxlength: 100000, "aria-label": "GitHub links, one per line",
        placeholder: "One per line (up to 200) - any page inside a repo works:\nhttps://github.com/projectdiscovery/nuclei        (a repo)\nhttps://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/README.md\nhttps://github.com/SpecterOps                      (an owner: all their repos)\ntopic:homelab                                      (top repos of a GitHub topic)\nstars:octocat                                      (everything someone starred)" });
      const count = h("span", { class: "muted small", text: "" });
      const owner = h("input", { type: "checkbox" });
      const openFolder = this.filters.folder_id && this.filters.folder_id !== "0" ? this.filters.folder_id : "";
      const folderSel = h("select", { "aria-label": "Put the new repos in a folder" }, h("option", { value: "", text: "No folder" }),
        (this.folders ? this.folders.folders : []).map((x) => h("option", { value: String(x.id), text: `${x.emoji} ${x.name}`, selected: String(x.id) === String(openFolder) })));
      const progress = h("p", { class: "small", "aria-live": "polite" });
      const log = h("ol", { class: "batch-list small" });
      const err = h("p", { class: "error" });
      const NOUN = { repo: "repo", owner: "owner", topic: "topic", stars: "stars list", gist: "gist", doc: "link", gitlab: "GitLab project" };
      const hhmm = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const linesOf = () => [...new Set(box.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))];
      box.addEventListener("input", () => {
        const n = linesOf().length;
        count.textContent = n ? `${n} line(s)${n > MAX_LINES ? ` - up to ${MAX_LINES} at a time` : ""}` : "";
        count.className = n > MAX_LINES ? "error small" : "muted small";
      });
      const rows = new Map();   // source id → {status element, row data}
      const label = (r) => r.kind === "repo" ? `repo ${r.value}${r.note ? ` (${r.note})` : ""}` : r.kind === "owner" ? `owner ${r.value}`
        : r.kind === "topic" ? `topic ${r.value}` : r.kind === "gist" ? `gist ${r.value.slice(0, 12)}…`
          : r.kind === "doc" ? `link ${r.value.replace(/^https:\/\//, "").slice(0, 70)}${r.note ? ` (${r.note})` : ""}`
            : r.kind === "gitlab" ? `GitLab project ${r.value}` : `${r.value}'s stars`;
      const show = (el, cls, text) => { el.className = cls; el.textContent = text; };
      const stateText = (row, st) => {
        const r = row.data;
        if (st.state === "done") {
          const n = ["owner", "topic", "stars"].includes(st.kind) ? ` - ${st.repos.toLocaleString()} repo(s)` : "";
          return ["status-ok", `✓ Added ${label({ ...r, value: st.value })}${n}`];
        }
        if (st.state === "error") return ["status-err", `⚠ ${st.error}`];
        if (st.state === "waiting") return ["muted", `⏳ Saved ${label({ ...r, value: st.value })} - GitHub's free hourly limit is used up, so it finishes by itself after ${hhmm(st.until)}.`];
        return ["muted", `checking ${label({ ...r, value: st.value })} with GitHub…`];
      };
      let poll = null;
      const watchRows = async (rounds = 400) => {
        clearTimeout(poll);
        const ids = [...rows.keys()];
        if (!ids.length || !dlg.open) return;
        let st;
        try { st = await api("GET", `/repos/sources/status?ids=${ids.join(",")}`); } catch { st = null; }
        if (st) {
          const tally = { done: 0, error: 0, waiting: 0, queued: 0 };
          let until = 0;
          for (const it of st.items) {
            const row = rows.get(it.id);
            if (!row) continue;
            tally[it.state] += 1;
            if (it.state === "waiting") until = Math.max(until, it.until || 0);
            const [cls, text] = stateText(row, it);
            show(row.el, cls, text + row.extra);
          }
          const total = st.items.length;
          progress.textContent = `Checked ${(tally.done + tally.error).toLocaleString()} of ${total.toLocaleString()}`
            + (tally.waiting ? ` · ${tally.waiting} waiting for GitHub's hourly limit (finish by themselves after ${hhmm(until)})` : "")
            + (tally.error ? ` · ${tally.error} problem(s)` : "") + (tally.queued ? " · checking…" : " · done.");
          if (!tally.queued) { this.refreshAll(); return; }
          if (rounds % 5 === 0) this.loadMeta().then(() => { if (FW.currentMode() === "repos") this.reload(); });
        }
        if (rounds > 0) poll = setTimeout(() => watchRows(rounds - 1), 3000);
      };
      // a bare profile link would follow every repo that account publishes (up to 500): ask, per link or for all of them
      const asks = [];
      const askAll = h("div", { class: "repo-ask-all", hidden: true });
      const decide = async (r, el, mode) => {
        if (mode === "skip") { show(el, "muted", "Skipped."); return; }
        show(el, "muted", mode === "follow" ? "following…" : "saving the profile…");
        try {
          const res = await api("POST", "/repos/sources/batch", { lines: [r.line], owner_mode: mode, ...(folderSel.value ? { folder_id: Number(folderSel.value) } : {}) });
          const x = res.results[0];
          if (x.status === "queued") { rows.set(x.id, { el, data: x, extra: "" }); show(el, "muted", `saved - ${label(x)}…`); watchRows(); }
          else if (x.status === "exists") show(el, "muted", `Already in your Repos: ${NOUN[x.kind]} ${x.value}.`);
          else show(el, "status-err", x.detail || x.status);
        } catch (ex) { show(el, "status-err", ex.message); }
      };
      const askRow = (r, el) => {
        el.className = "repo-ask";
        fill(el, h("span", { class: "small", text: `${r.value} is a profile - follow every repo it publishes (up to 500), or just save the profile? ` }),
          h("button", { type: "button", class: "btn small", text: "Follow all repos", onclick: () => decide(r, el, "follow") }),
          h("button", { type: "button", class: "btn small primary", text: "Profile link only", onclick: () => decide(r, el, "profile") }),
          h("button", { type: "button", class: "btn small", text: "Skip", onclick: () => decide(r, el, "skip") }));
      };
      const decideAll = async (mode) => {
        askAll.hidden = true;
        for (const { r, el } of asks.splice(0)) await decide(r, el, mode);
      };
      const go = async (ev) => {
        ev.preventDefault();
        const lines = linesOf();
        if (!lines.length) { err.textContent = "Paste at least one line."; return; }
        if (lines.length > MAX_LINES) { err.textContent = `Up to ${MAX_LINES} lines at a time, please (${lines.length} pasted).`; return; }
        err.textContent = "";
        const submit = ev.submitter || dlg.querySelector("button[type=submit]");
        if (submit) submit.disabled = true;
        let res;
        try { res = await api("POST", "/repos/sources/batch", { lines, follow_owner: owner.checked, ...(folderSel.value ? { folder_id: Number(folderSel.value) } : {}) }); }
        catch (ex) {
          err.textContent = ex.message === "Not Found" ? "The app hasn't finished installing this - restart it, then try again." : ex.message;
          if (submit) submit.disabled = false;
          return;
        } finally { if (submit) submit.disabled = false; }
        box.value = "";
        count.textContent = "";
        for (const r of res.results) {
          const el = h("span", { class: "muted" });
          log.append(h("li", null, h("code", { text: r.line }), " — ", el));
          const own = r.owner ? (r.owner.status === "queued" ? ` · also following owner ${r.owner.value}` : r.owner.status === "exists" ? ` · owner ${r.owner.value} already followed` : "") : "";
          if (r.status === "invalid" || r.status === "full") show(el, "status-err", r.detail);
          else if (r.status === "duplicate") show(el, "muted", "Listed twice in this paste.");
          else if (r.status === "exists") show(el, "muted", `Already in your Repos: ${NOUN[r.kind]} ${r.value}.${own}`);
          else if (r.status === "ask") { asks.push({ r, el }); askRow(r, el); }
          else { rows.set(r.id, { el, data: r, extra: own }); show(el, "muted", `saved - checking ${label(r)} with GitHub…${own}`); }
        }
        progress.textContent = res.queued ? `Saved ${res.queued} line(s). GitHub checks them in the background…` : asks.length ? "" : "Nothing new to add.";
        if (asks.length > 1) {
          fill(askAll, h("span", { class: "small", text: `${asks.length} profile links: ` }),
            h("button", { type: "button", class: "btn small", text: "Follow all their repos (every one)", onclick: () => decideAll("follow") }),
            h("button", { type: "button", class: "btn small primary", text: "Save them as profile links", onclick: () => decideAll("profile") }),
            h("button", { type: "button", class: "btn small", text: "Skip them", onclick: () => decideAll("skip") }));
          askAll.hidden = false;
        }
        if (rows.size) watchRows();
      };
      dlg.addEventListener("close", () => clearTimeout(poll), { once: true });
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: "＋ Add from GitHub" }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        box, count,
        h("label", { class: "repo-tick", title: "Off: only the repo you pasted is added. On: its owner is followed too, so all their public repos appear (up to 500)." },
          owner, " Also follow the owner (all their public repos)"),
        h("label", { class: "repo-tick", title: "The repos these lines bring in go into this folder" }, "📁 Put them in ", folderSel),
        h("ul", { class: "small src-notes" },
          h("li", { text: "Up to 200 lines at a time. Everything is saved straight away and checked with GitHub in the background - you can close this window." }),
          h("li", { text: "A repo link (any page inside it - a file, a folder, the README, the wiki) adds just that repo, and its new versions show in 🚀 Releases. A <name>.github.io website adds the repo it is built from." }),
          h("li", { text: "Gists (gist.github.com/…), GitHub Docs pages (docs.github.com/…) and GitLab projects (gitlab.com/<group>/<project>) are saved too. A <name>.github.io website with no public repo behind it is saved as a website link." }),
          h("li", { text: "A profile link (github.com/<name>): you're asked each time whether to follow every repo they publish (up to 500) or just save the profile as a link. topic:<name> adds the 100 most-starred repos with that GitHub topic; stars:<user> adds what they starred." }),
          h("li", { text: "Without a GitHub token GitHub allows 60 requests an hour (each new repo uses one); lines past that wait and finish by themselves after GitHub's reset. A free read-only token (⚙ Sources) allows 5,000." })),
        progress, askAll, log, err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "＋ Add" }))));
      if (!dlg.open) dlg.showModal();
      box.focus();
    },

    /** ⚙ Sources: what you follow (refresh, unfollow, filter by it), GitHub's request budget and the optional token. */
    async openSources() {
      const dlg = $("#sourceDialog");
      await this.loadMeta();
      const m = this.meta;
      const rate = m.rate || {};
      const budget = rate.remaining === null || rate.remaining === undefined ? "not used yet since the app started"
        : `${rate.remaining.toLocaleString()} of ${(rate.limit || 0).toLocaleString()} requests left this hour${rate.reset ? ` (resets ${new Date(rate.reset * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })})` : ""}`;
      const rows = m.sources.map((s) => h("li", { class: "repo-src" },
        h("span", { class: "repo-src-kind small", text: KIND[s.kind] || s.kind }),
        h("span", { class: "repo-src-main" },
          h("a", { href: safeUrl(s.url), target: "_blank", rel: "noopener noreferrer", text: s.title || s.value }),
          h("span", { class: "muted small", text: ` · ${s.last_fetch ? `${s.repo_count.toLocaleString()} repo(s), checked ${relTime(s.last_fetch)}`
            : s.last_error ? "not fetched yet"
              : s.next_fetch && s.next_fetch * 1000 > Date.now() ? `⏳ waiting for GitHub's hourly limit - finishes by itself after ${new Date(s.next_fetch * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
                : "fetching…"}` }),
          s.note ? h("span", { class: "muted small repo-src-err", text: `From ${s.origin || "a website link"}: ${s.note}` }) : null,
          s.last_error ? h("span", { class: "error small repo-src-err", text: `⚠ ${s.last_error}` }) : null),
        h("span", { class: "repo-src-actions" },
          h("button", { type: "button", class: "btn small", text: "Show", title: "Show only this source's repos", onclick: () => { dlg.close(); this.set({ ...DEFAULTS, source_id: String(s.id), view: "grid", sort: this.filters.sort }); } }),
          h("button", { type: "button", class: "btn small", text: "⟳", title: "Check now", "aria-label": `Check ${s.title || s.value} now`,
            onclick: async () => { if (await guarded(() => api("POST", `/repos/sources/${s.id}/refresh`), "Checking in the background…")) this.watchSoon(); } }),
          h("button", { type: "button", class: "btn small danger", text: "✕", title: "Remove", "aria-label": `Remove ${s.title || s.value}`,
            onclick: async () => {
              const info = await guarded(() => api("GET", `/repos/sources/${s.id}/only`));
              if (!info) return;
              const choice = await this.askRemove(s, info);
              if (!choice) return;
              const r = await guarded(() => api("DELETE", `/repos/sources/${s.id}${choice === "all" ? "?with_repos=true" : ""}`));
              if (r) { toast(`Removed - ${r.repos_removed} repo(s) went with it${r.kept_in_folders && choice !== "all" ? `; ${r.kept_in_folders} stay because they're in your folders` : ""}`); if (String(this.filters.source_id) === String(s.id)) this.filters.source_id = ""; await this.refreshAll(); this.openSources(); }
            } }))));
      const token = h("input", { type: "password", autocomplete: "off", spellcheck: "false", maxlength: 300, placeholder: m.token_set ? "A token is saved - paste a new one to replace it" : "github_pat_… or ghp_…", "aria-label": "GitHub token" });
      const tokenMsg = h("p", { class: "small", "aria-live": "polite" });
      const saveToken = async (clear) => {
        tokenMsg.className = "small";
        tokenMsg.textContent = clear ? "Removing…" : "Checking the token with GitHub…";
        try {
          const r = await api("PUT", "/repos/token", clear ? { clear: true } : { token: token.value.trim() });
          token.value = "";
          tokenMsg.className = "small status-ok";
          tokenMsg.textContent = r.token_set ? `✓ Saved - GitHub now allows ${(r.limit || 5000).toLocaleString()} requests an hour.` : "✓ Removed.";
          await this.loadMeta();
        } catch (ex) { tokenMsg.className = "small status-err"; tokenMsg.textContent = ex.message; }
      };
      fill(dlg, h("div", { class: "form source-wizard" },
        h("div", { class: "sd-head" }, h("h3", { text: "⚙ GitHub sources" }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        rows.length ? h("ul", { class: "repo-srcs" }, rows) : h("p", { class: "muted", text: "Nothing added from GitHub yet - use ＋." }),
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "＋ Add more", onclick: () => this.openAdd() }),
          rows.length ? h("button", { type: "button", class: "btn", text: "⟳ Check all now", onclick: async () => { if (await guarded(() => api("POST", "/repos/refresh"), "Checking all sources in the background…")) this.watchSoon(); } }) : null),
        h("h4", { text: "GitHub token (optional)" }),
        h("p", { class: "muted small", text: `GitHub's budget: ${budget}. Without a token GitHub allows 60 requests an hour; a token raises it to 5,000. Create a fine-grained token with “Public repositories (read-only)” and no other permissions, then paste it here. It is stored encrypted and never shown again.` }),
        h("p", { class: "small" }, h("a", { href: "https://github.com/settings/personal-access-tokens/new", target: "_blank", rel: "noopener noreferrer", text: "Create a token on GitHub ↗" }),
          h("span", { class: "muted", text: m.token_set ? " · a token is saved" : " · no token saved" })),
        token, tokenMsg,
        h("div", { class: "form-actions" },
          m.token_set ? h("button", { type: "button", class: "btn danger", text: "Remove token", onclick: () => saveToken(true) }) : null,
          h("button", { type: "button", class: "btn primary", text: "Save token", onclick: () => { if (token.value.trim()) saveToken(false); else { tokenMsg.className = "small status-err"; tokenMsg.textContent = "Paste a token first."; } } }))));
      if (!dlg.open) dlg.showModal();
    },
    /** Removing a source: when folders would keep some of its repos, ask whether those should go too. → "all" | "source" | null */
    askRemove(s, info) {
      return new Promise((resolve) => {
        let choice = null;
        const name = s.title || s.value;
        const kept = info.only_here_in_folders;
        const dlg = h("dialog", { class: "range-dialog", "aria-label": `Remove ${name}` },
          h("div", { class: "form" },
            h("h3", { text: `Remove “${name}”?` }),
            h("p", { class: "small", text: `It lists ${info.repos.toLocaleString()} repo(s); ${info.only_here.toLocaleString()} of them come only from it (not starred, not added any other way).` }),
            kept ? h("p", { class: "small muted", text: `${kept.toLocaleString()} of those are in your folders, so they'd normally stay.` }) : null,
            h("div", { class: "form-actions repo-remove-actions" },
              h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
              kept ? h("button", { type: "button", class: "btn", text: "Remove it, keep its repos", onclick: () => { choice = "source"; dlg.close(); } }) : null,
              h("button", { type: "button", class: "btn danger", text: kept ? `Remove it and its ${info.only_here.toLocaleString()} repo(s)` : "Remove",
                onclick: () => { choice = kept ? "all" : "source"; dlg.close(); } }))));
        dlg.addEventListener("close", () => { dlg.remove(); resolve(choice); });
        document.body.append(dlg);
        dlg.showModal();
      });
    },
    watchSoon() { setTimeout(async () => { await this.loadMeta(); if (FW.currentMode() === "repos") { this.renderShell(); await this.reload(); } }, 5000); },
  };

  FW.repos = view;
})();
