/* 🔗 Resources tab: your websites, training platforms, courses, labs, cheat sheets, tools and docs, sorted into
 * categories and types - imported from your browser's bookmark export or pasted. Same rules as app.js: DOM built with
 * h()/textContent only, links only through safeUrl, colours through safeColor. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, safeColor, store, relTime } = FW;
  const $ = (sel) => document.querySelector(sel);
  const DEFAULTS = { view: "tree", category_id: "", kind: "", training: false, status: "", favourite: false, q: "", sort: "title" };
  const SORTS = [["title", "A–Z"], ["added", "📥 Recently added"], ["opened", "🕒 Recently opened"], ["popular", "🔥 Most opened"], ["host", "Website"]];
  const STATUS = [["", "Any status"], ["todo", "📌 To do"], ["doing", "▶ In progress"], ["done", "✅ Done"]];
  const PAGE = 100;

  const view = {
    meta: null,
    items: [],
    total: 0,
    selecting: false,
    selected: new Set(),
    filters: (() => {
      const saved = store.get("fw-resources-filters") || {};
      // Saved before folders existed (no v: 2): open on your folder tree once, whatever view was remembered.
      const f = saved.v === 2 ? { ...DEFAULTS, ...saved } : { ...DEFAULTS, sort: saved.sort || DEFAULTS.sort };
      f.v = 2;
      if (!["launch", "tree", "map", "mind", "repos", "categories", "list"].includes(f.view)) f.view = "tree";
      f.category_id = f.category_id === undefined || f.category_id === null ? "" : String(f.category_id);
      return f;
    })(),

    async show() {
      const el = $("#resourcesView");
      if (!this.meta) fill(el, h("p", { class: "muted lib-pad", text: "Loading resources…" }));
      await this.loadMeta();
      this.renderShell();
      await this.reload();
    },
    hide() { this.unmountRepos(); },
    save() { store.set("fw-resources-filters", this.filters); },
    async loadMeta() {
      this.meta = await api("GET", "/resources/meta").catch((ex) => ({ missing: ex.message === "Not Found", total: 0, training: 0, uncategorised: 0,
        kinds: {}, kind_labels: {}, categories: [], favourites: [], recent: [] }));
    },
    async refreshAll() { await this.loadMeta(); this.renderShell(); await this.reload(); },
    set(changes, shell = true) {
      if (changes.view && changes.view !== "list") this.folderFilter = null;
      if (["launch", "tree", "map", "mind", "repos"].includes(changes.view)) {
        Object.assign(changes, { q: "", kind: "", training: false, status: "", favourite: false, category_id: "" });
      }
      Object.assign(this.filters, changes); this.save(); if (shell) this.renderShell(); this.reload();
    },
    /** The view actually on screen: any filter or search shows the matching links as a list. */
    shownView() {
      const f = this.filters;
      if (f.view === "categories") return f.category_id === "" && !f.q ? "categories" : "list";
      if (["launch", "tree", "map", "mind", "repos"].includes(f.view)) return f.category_id === "" && !f.q && !f.kind && !f.training && !f.status && !f.favourite ? f.view : "list";
      return "list";
    },
    catName(id) {
      if (String(id) === "0") return "Not in a category";
      const c = this.meta.categories.find((x) => String(x.id) === String(id));
      return c ? `${c.emoji} ${c.name}` : "a category";
    },
    kindLabel(k) { return (this.meta.kind_labels || {})[k] || k; },

    /** A 📦 repo from the Repos tab: opens on GitHub (or wherever it lives) in a new tab. */
    repoLink(rp, cls = "res-tree-title") {
      return h("a", { href: safeUrl(rp.url), target: "_blank", rel: "noopener noreferrer", class: cls, title: rp.description || rp.url, text: `📦 ${rp.title}` });
    },
    /** Opening a link counts it (for Recently opened / Most opened) and opens it in a new tab. */
    link(r, cls = "res-title") {
      return h("a", { href: safeUrl(r.url), target: "_blank", rel: "noopener noreferrer", class: cls, title: r.url, text: r.title,
        onclick: () => { api("POST", `/resources/${r.id}/opened`).catch(() => {}); } });
    },

    renderShell() {
      this.unmountRepos();
      const el = $("#resourcesView");
      const f = this.filters;
      const m = this.meta;
      const search = h("input", { type: "search", placeholder: "Find any resource: title, address, notes, folder…", maxlength: 200, value: f.q, "aria-label": "Search resources" });
      let timer = null;
      search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { this.set({ q: search.value.trim(), view: search.value.trim() ? "list" : f.view }, false); }, 300); });
      const select = (label, options, value, onchange) => h("select", { "aria-label": label, onchange: (e) => onchange(e.target.value) },
        options.map(([v, l]) => h("option", { value: String(v), text: l, selected: String(value) === String(v) })));
      const kinds = [["", "All types"], ["training", `🎓 Training (${(m.training || 0).toLocaleString()})`],
        ...Object.entries(m.kind_labels || {}).map(([k, l]) => [k, `${l} (${(m.kinds[k] || 0).toLocaleString()})`])];
      const kindValue = f.training ? "training" : f.kind;
      const chips = [];
      if (f.category_id !== "") chips.push(h("button", { type: "button", class: "btn small repo-chip-on", text: `${this.catName(f.category_id)} ✕`, onclick: () => this.set({ category_id: "" }) }));
      if (this.folderFilter && f.view === "list") chips.push(h("button", { type: "button", class: "btn small repo-chip-on", text: `📁 ${this.tree ? this.folderPath(this.folderFilter) : "a folder"} ✕`,
        onclick: () => { this.folderFilter = null; this.renderShell(); this.reload(); } }));
      const anyFilter = f.q || f.kind || f.training || f.status || f.favourite || f.category_id !== "";
      const quick = [...m.favourites.map((r) => ({ r, star: true })), ...m.recent.filter((r) => !r.favourite).map((r) => ({ r, star: false }))].slice(0, 24);
      fill(el,
        h("div", { class: "studio-header lib-header" },
          h("h2", { text: "🔗 Resources" }),
          h("button", { type: "button", class: "btn small primary lib-add-plus", text: "＋", title: "Add links", "aria-label": "Add links", onclick: () => this.openAdd(null) }),
          h("button", { type: "button", class: "btn small", text: "⇪ Import bookmarks", title: "Import your browser's bookmark export (HTML)", onclick: () => this.openImport() }),
          search,
          select("Type", kinds, kindValue, (v) => this.set(v === "training" ? { training: true, kind: "", view: "list" } : { training: false, kind: v, view: v ? "list" : f.view })),
          select("Status", STATUS, f.status, (v) => this.set({ status: v, view: v ? "list" : f.view })),
          select("Sort", SORTS, f.sort, (v) => this.set({ sort: v }, false)),
          h("button", { type: "button", class: "btn small", text: "⚙ Categories", title: "Rename, recolour, reorder, add or delete categories", onclick: () => this.openCategories() })),
        h("div", { class: "res-views lib-pad", role: "tablist", "aria-label": "How to show your links" },
          [["launch", "★ Launchpad"], ["tree", "🌳 Folders"], ["map", "🗺 Map"], ["mind", "🧠 Mind map"], ["repos", "📦 Repos"], ["categories", "🗂 Categories"], ["list", "☰ All links"]].map(([v, label]) => {
            const on = this.shownView() === v;
            return h("button", { type: "button", role: "tab", class: `btn small${on ? " primary" : ""}`, "aria-selected": String(on), text: label,
              "data-view": v, onclick: () => this.set({ view: v }) },
              v === "repos" ? h("span", { class: "res-badge-new", id: "resReposBadge", hidden: true }) : null);
          })),
        h("div", { class: "repo-filters lib-pad" },
          h("label", { class: "repo-tick" }, h("input", { type: "checkbox", checked: f.favourite, onchange: (e) => this.set({ favourite: e.target.checked, view: e.target.checked ? "list" : f.view }) }), " ★ Favourites"),
          ...chips,
          f.view === "list" && f.category_id !== "" ? h("button", { type: "button", class: "btn small", text: "← All categories", onclick: () => this.set({ category_id: "", view: "categories" }) }) : null,
          anyFilter ? h("button", { type: "button", class: "btn small", text: "Clear filters", onclick: () => this.set({ ...DEFAULTS, sort: f.sort }) }) : null,
          this.listing() ? h("button", { type: "button", class: `btn small${this.selecting ? " primary" : ""}`, "aria-pressed": String(this.selecting),
            text: this.selecting ? "☑ Selecting…" : "☑ Select", title: "Tick links to change many at once",
            onclick: () => { this.selecting = !this.selecting; this.selected.clear(); this.renderShell(); this.reload(); } }) : null,
          h("button", { type: "button", class: "btn small", text: "↻ Sort again", title: "Re-sort every link whose categories you haven't changed yourself", onclick: async () => {
            const r = await guarded(() => api("POST", "/resources/reclassify"));
            if (r) { toast(`Sorted ${r.sorted.toLocaleString()} link(s) again`); this.refreshAll(); }
          } })),
        quick.length ? h("div", { class: "res-quick", "aria-label": "Favourites and recently opened" },
          h("span", { class: "muted small", text: "Quick:" }),
          quick.map(({ r, star }) => { const a = this.link(r, "res-quick-item"); a.textContent = `${star ? "★ " : ""}${r.title}`; return a; })) : null,
        this.selecting && this.listing() ? h("div", { id: "resSelBar", class: "repo-sel-bar lib-pad" }) : null,
        h("div", { id: "resCount", class: "muted small lib-pad", "aria-live": "polite" }),
        h("div", { id: "resBody" }),
        h("div", { class: "lib-more" }, h("button", { id: "resMore", type: "button", class: "btn", text: "Load more", hidden: true, onclick: () => this.loadMore() })));
      this.updateReposBadge();
      if (m.missing) {
        $("#resBody").replaceWith(h("div", { class: "card lib-empty" }, h("h3", { text: "Restart needed" }),
          h("p", { class: "muted", text: "The server running this app doesn't have the Resources tab yet. Restart the app, then reload this page." })));
      } else if (!m.total) {
        $("#resBody").replaceWith(h("div", { class: "card lib-empty" },
          h("h3", { text: "Your resources in one place" }),
          h("p", { class: "muted", text: "Import your browser's bookmarks (Chrome / Edge: Bookmarks manager → ⋮ → Export bookmarks; Firefox: Library → Import and Backup → Export Bookmarks to HTML) or paste links with ＋. Everything is sorted into categories - offensive, defensive, DFIR, threat intel, malware analysis, scripting… - and types (courses, labs, CTFs, cheat sheets, tools), and you can change any of it." }),
          h("div", { class: "form-actions" },
            h("button", { type: "button", class: "btn primary", text: "⇪ Import bookmarks", onclick: () => this.openImport() }),
            h("button", { type: "button", class: "btn", text: "＋ Paste links", onclick: () => this.openAdd() }))));
      }
    },

    params(extra = {}) {
      const f = this.filters;
      const p = new URLSearchParams({ sort: f.sort });
      if (f.q) p.set("q", f.q);
      if (f.category_id !== "") p.set("category_id", f.category_id);
      if (this.folderFilter && f.view === "list") { p.set("folder_id", String(this.folderFilter)); p.set("include_sub", "true"); }
      if (f.kind) p.set("kind", f.kind);
      if (f.training) p.set("training", "true");
      if (f.status) p.set("status", f.status);
      if (f.favourite) p.set("favourite", "true");
      for (const [k, v] of Object.entries(extra)) p.set(k, v);
      return p;
    },

    async reload() {
      const body = $("#resBody");
      if (!body || this.meta.missing) return;
      const f = this.filters;
      const more = $("#resMore");
      if (more) more.hidden = true;
      if (f.view === "categories" && f.category_id === "" && !f.q) { this.renderCategories(body); return; }
      if (f.view === "repos" && f.category_id === "" && !f.q && !f.kind && !f.training && !f.status && !f.favourite) {
        this.mountRepos(body);
        return;
      }
      this.unmountRepos();
      if (f.view === "launch" && f.category_id === "" && !f.q && !f.kind && !f.training && !f.status && !f.favourite) {
        await this.renderLaunchpad(body);
        return;
      }
      if ((f.view === "tree" || f.view === "map" || f.view === "mind") && f.category_id === "" && !f.q && !f.kind && !f.training && !f.status && !f.favourite) {
        await this.loadTree();
        if (f.view === "tree") this.renderTree(body); else if (f.view === "map") this.renderMap(body); else await this.renderMind(body);
        return;
      }
      try {
        await this.loadTree().catch(() => {});
        const data = await api("GET", `/resources?${this.params({ limit: String(PAGE), offset: "0" })}`);
        this.items = data.items;
        this.total = data.total;
        $("#resCount").textContent = `${data.total.toLocaleString()} link(s)${f.category_id !== "" ? ` in ${this.catName(f.category_id)}` : ""}`;
        let repoHits = null;
        if (f.q && !f.kind && !f.training && !f.status && f.category_id === "") {
          const rr = await api("GET", `/resources/repo-search?${new URLSearchParams({ q: f.q })}`).catch(() => ({ items: [] }));
          if (rr.items.length) {
            const term = f.q;
            repoHits = h("div", { class: "res-repo-hits lib-pad" },
              h("strong", { class: "small", text: `📦 Repos (${rr.items.length >= 40 ? "40+" : rr.items.length})` }),
              h("ul", { class: "res-repo-hit-list" }, rr.items.slice(0, 6).map((rp) => h("li", null, this.repoLink(rp),
                rp.description ? h("span", { class: "muted small", text: ` - ${rp.description.slice(0, 90)}` }) : null))),
              h("button", { type: "button", class: "btn small", text: "Show them in 📦 Repos", onclick: () => { this.reposQuery = term; this.set({ view: "repos" }); } }));
          }
        }
        fill(body, repoHits, data.items.length ? h("ul", { class: "res-list" }, data.items.map((r) => this.row(r)))
          : h("p", { class: "muted lib-pad", text: this.meta.total ? "Nothing else matches these filters." : "" }));
        if (more) more.hidden = this.items.length >= this.total;
        this.renderSelBar();
      } catch (err) { fill(body, h("p", { class: "error lib-pad", text: err.message })); }
    },

    async loadMore() {
      const data = await guarded(() => api("GET", `/resources?${this.params({ limit: String(PAGE), offset: String(this.items.length) })}`));
      if (!data) return;
      this.items.push(...data.items);
      const list = $("#resBody .res-list");
      if (list) list.append(...data.items.map((r) => this.row(r)));
      $("#resMore").hidden = this.items.length >= data.total;
    },

    // ---------------------------------------------------------------- 🌳 folder tree and 🗺 map
    tree: null,
    async loadTree(force = false) {
      if (this.tree && !force) return;
      const [t, rl] = await Promise.all([api("GET", "/resources/tree"), api("GET", "/resources/repos").catch(() => ({ links: [], repos: [] }))]);
      const repoById = new Map(rl.repos.map((r) => [r.id, r]));
      const reposBy = new Map();
      for (const [fid, rid] of rl.links) { if (!repoById.has(rid)) continue; if (!reposBy.has(fid)) reposBy.set(fid, []); reposBy.get(fid).push(repoById.get(rid)); }
      const kids = new Map(), byFolder = new Map(), folder = new Map();
      for (const f of t.folders) { folder.set(f.id, f); if (!kids.has(f.parent_id ?? 0)) kids.set(f.parent_id ?? 0, []); kids.get(f.parent_id ?? 0).push(f); }
      for (const list of kids.values()) list.sort((a, b) => a.position - b.position || a.name.localeCompare(b.name));
      const unfiled = [];
      for (const it of t.items) {
        if (!it.folders.length) unfiled.push(it);
        for (const fid of it.folders) { if (!byFolder.has(fid)) byFolder.set(fid, []); byFolder.get(fid).push(it); }
      }
      this.tree = { ...t, kids, byFolder, folder, unfiled, reposBy, repoCount: rl.links.length };
    },
    openState() { try { return new Set(store.get("fw-res-open") || []); } catch { return new Set(); } },
    saveOpen(set) { store.set("fw-res-open", [...set].slice(0, 2000)); },
    folderPath(fid) {
      const parts = [];
      let f = this.tree && this.tree.folder.get(fid);
      while (f) { parts.unshift(f.name); f = f.parent_id ? this.tree.folder.get(f.parent_id) : null; }
      return parts.join(" / ");
    },
    /** A select of every folder, indented like the tree. */
    folderSelect(label, { top = false, exclude = null } = {}) {
      const opts = [];
      const skip = new Set();
      if (exclude) { const walk = (id) => { skip.add(id); (this.tree.kids.get(id) || []).forEach((c) => walk(c.id)); }; walk(exclude); }
      const walk = (pid, depth) => (this.tree.kids.get(pid) || []).forEach((f) => {
        if (skip.has(f.id)) return;
        opts.push(h("option", { value: String(f.id), text: `${"  ".repeat(depth)}${depth ? "└ " : ""}📁 ${f.name}` }));
        walk(f.id, depth + 1);
      });
      walk(0, 0);
      return h("select", { "aria-label": label }, top ? h("option", { value: "0", text: "⬆ Top level" }) : null, opts);
    },
    async renderTree(body) {
      const t = this.tree;
      const open = this.openState();
      const filter = h("input", { type: "search", placeholder: "Find in the tree…", "aria-label": "Find in the tree", maxlength: 100 });
      const box = h("div", { class: `res-tree${store.get("fw-res-sum", true) === false ? " res-hide-sum" : ""}`, role: "tree" });
      const linkRow = (it, fid) => {
        const menu = h("details", { class: "repo-folder-menu" }, h("summary", { class: "icon-btn", text: "⋯", "aria-label": `Options for ${it.title}` }),
          h("div", { class: "repo-folder-menu-list", role: "menu" },
            h("button", { type: "button", class: "btn small", text: "📁 Folders… (put it in several)", onclick: () => this.placeIn({ type: "link", item: it }) }),
            h("button", { type: "button", class: "btn small", text: "⇢ Move to folder…", onclick: () => this.fileLinks([it.id], fid ? "move" : "add", fid) }),
            h("button", { type: "button", class: "btn small", text: "＋ Also put in folder…", onclick: () => this.fileLinks([it.id], "add", null) }),
            h("button", { type: "button", class: "btn small", text: it.favourite ? "☆ Remove from favourites" : "★ Add to favourites (Launchpad)", onclick: async () => {
              const res = await guarded(() => api("PATCH", `/resources/${it.id}`, { favourite: !it.favourite }), it.favourite ? "Removed from favourites" : "Added to favourites and the Launchpad");
              if (res) { this.tree = null; await this.loadMeta(); this.renderShellKeep(); this.reload(); }
            } }),
            h("button", { type: "button", class: "btn small", text: "🗺 Show on the map", onclick: () => this.locate(it, "map", fid) }),
            h("button", { type: "button", class: "btn small", text: "🧠 Show in the mind map", onclick: () => this.locate(it, "mind", fid) }),
            h("button", { type: "button", class: "btn small", text: "🗂 Show in its category", disabled: !(it.categories || []).length, onclick: () => this.locate(it, "cat") }),
            fid ? h("button", { type: "button", class: "btn small", text: "− Take out of this folder", onclick: async () => {
              if (await guarded(() => api("POST", `/resources/folders/${fid}/items`, { resource_ids: [it.id], action: "remove" }))) { this.tree = null; this.reload(); }
            } }) : null,
            h("button", { type: "button", class: "btn small", text: "✎ Edit…", onclick: async () => {
              const full = (await api("GET", `/resources?q=${encodeURIComponent(it.url.slice(0, 190))}&limit=5`)).items.find((x) => x.id === it.id);
              if (full) this.openEdit(full);
            } }),
            h("button", { type: "button", class: "btn small danger", text: "🗑 Delete link…", onclick: async () => {
              const n = (it.folders || []).length;
              const where = n > 1 ? `It's in ${n} folders - it goes from all of them.` : "It's removed from Resources entirely, not just from this folder.";
              if (!window.confirm(`Delete “${it.title}”?\n\n${where}\nThis can't be undone (use “− Take out of this folder” to only take it out of here).`)) return;
              if (await guarded(() => api("DELETE", `/resources/${it.id}`), "Link deleted")) this.refreshTreeAll();
            } })));
        return h("li", { class: "res-tree-link", role: "treeitem", "data-rid": String(it.id), "data-text": `${it.title} ${it.url} ${it.summary || ""}`.toLowerCase(), title: it.summary || null },
          h("span", { class: "res-tree-dot", text: it.favourite ? "★" : "•" }), this.link(it, "res-tree-title"),
          h("span", { class: "muted small", text: ` ${it.host}` }), menu,
          it.summary ? h("div", { class: "res-tree-sum muted small", text: it.summary }) : null);
      };
      const folderNode = (f, depth) => {
        const isOpen = open.has(f.id);
        const childBox = h("ul", { class: "res-tree-kids", role: "group", hidden: !isOpen });
        let built = false;
        const build = () => {
          if (built) return;
          built = true;
          fill(childBox, (t.kids.get(f.id) || []).map((c) => folderNode(c, depth + 1)), (t.byFolder.get(f.id) || []).map((it) => linkRow(it, f.id)),
            (t.reposBy.get(f.id) || []).map((rp) => h("li", { class: "res-tree-link res-tree-repo", role: "treeitem", "data-text": `${rp.title} ${rp.description}`.toLowerCase(), title: rp.description || null },
              h("span", { class: "res-tree-dot", text: "•" }), this.repoLink(rp),
              h("span", { class: "muted small", text: rp.kind === "repo" ? ` ${rp.language || "repo"}${rp.stars ? ` · ★${rp.stars.toLocaleString()}` : ""}` : ` ${rp.kind}` }),
              h("button", { type: "button", class: "icon-btn res-repo-unlink", text: "✕", title: `Take ${rp.title} off this folder`, "aria-label": `Take ${rp.title} off ${f.name}`,
                onclick: async () => {
                  if (await guarded(() => api("POST", `/resources/folders/${f.id}/repos`, { repo_ids: [rp.id], action: "remove" }), "Repo taken off this folder")) { this.tree = null; this.reload(); }
                } }))));
        };
        if (isOpen) build();
        const caret = h("button", { type: "button", class: "res-tree-caret", text: isOpen ? "▾" : "▸", "aria-expanded": String(isOpen), "aria-label": `Open ${f.name}`,
          onclick: () => {
            const nowOpen = childBox.hidden;
            if (nowOpen) build();
            childBox.hidden = !nowOpen;
            caret.textContent = nowOpen ? "▾" : "▸";
            caret.setAttribute("aria-expanded", String(nowOpen));
            if (nowOpen) open.add(f.id); else open.delete(f.id);
            this.saveOpen(open);
          } });
        const menu = h("details", { class: "repo-folder-menu" }, h("summary", { class: "icon-btn", text: "⋯", "aria-label": `Options for ${f.name}` }),
          h("div", { class: "repo-folder-menu-list", role: "menu" },
            h("button", { type: "button", class: "btn small", text: "＋ New subfolder", onclick: () => this.newFolder(f.id) }),
            h("button", { type: "button", class: "btn small", text: "✎ Rename", onclick: () => this.renameFolder(f) }),
            h("button", { type: "button", class: "btn small", text: "⇢ Move folder…", onclick: () => this.moveFolder(f) }),
            h("button", { type: "button", class: "btn small", text: "☰ Show its links as a list", onclick: () => this.showFolderList(f) }),
            h("button", { type: "button", class: "btn small", text: "🧠 Goes well with…", onclick: () => this.addRelation(f.id) }),
            h("button", { type: "button", class: "btn small", text: "＋ Add new links here…", onclick: () => this.openAdd(f.id) }),
            h("button", { type: "button", class: "btn small", text: "🔗 Add links already in Resources…", onclick: () => this.pickLinks(f.id) }),
            h("button", { type: "button", class: "btn small", text: "📦 Link repos…", onclick: () => this.linkRepos(f.id) }),
            h("button", { type: "button", class: "btn small danger", text: "🗑 Delete folder…", onclick: () => this.deleteFolder(f) })));
        return h("li", { class: "res-tree-folder", role: "treeitem", "aria-expanded": String(isOpen), "data-id": String(f.id), "data-text": f.name.toLowerCase() },
          h("div", { class: "res-tree-row" }, caret, h("span", { class: "res-tree-name", text: `📁 ${f.name}` }),
            h("span", { class: "muted small", text: ` ${f.total.toLocaleString()}` }),
            (t.reposBy.get(f.id) || []).length ? h("span", { class: "muted small", title: "Repos linked here", text: ` · 📦 ${(t.reposBy.get(f.id) || []).length}` }) : null, menu),
          childBox);
      };
      const roots = t.kids.get(0) || [];
      const unfiledNode = t.unfiled.length ? h("li", { class: "res-tree-folder" },
        h("details", null, h("summary", { class: "res-tree-row" }, h("span", { class: "res-tree-name", text: `🗂️ Not in a folder` }),
          h("span", { class: "muted small", text: ` ${t.unfiled.length.toLocaleString()}` })),
          h("ul", { class: "res-tree-kids" }, t.unfiled.slice(0, 500).map((it) => linkRow(it, null))))) : null;
      fill(box, h("ul", { class: "res-tree-root" }, roots.map((f) => folderNode(f, 0)), unfiledNode));
      // find: open the folders on the way to every match, hide what doesn't match
      let timer = null;
      filter.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => {
        const q = filter.value.trim().toLowerCase();
        if (!q) { this.renderTree(body); return; }
        const hit = new Set();
        for (const it of t.items) if (`${it.title} ${it.url}`.toLowerCase().includes(q)) it.folders.forEach((fid) => { let f = t.folder.get(fid); while (f) { hit.add(f.id); f = f.parent_id ? t.folder.get(f.parent_id) : null; } });
        for (const f of t.folders) if (f.name.toLowerCase().includes(q)) { let p = f; while (p) { hit.add(p.id); p = p.parent_id ? t.folder.get(p.parent_id) : null; } }
        const o = new Set(hit);
        this.saveOpen(o);
        this.renderTree(body).then(() => {
          $("#resTreeFind").value = filter.value;
          body.querySelectorAll(".res-tree-folder[data-id]").forEach((li) => { li.hidden = !hit.has(Number(li.dataset.id)); });
          body.querySelectorAll(".res-tree-link").forEach((li) => { li.hidden = !li.dataset.text.includes(q); });
          $("#resTreeFind").focus();
        });
      }, 350); });
      filter.id = "resTreeFind";
      $("#resCount").textContent = `${t.items.length.toLocaleString()} link(s) in ${t.folders.length.toLocaleString()} folder(s)${t.unfiled.length ? ` · ${t.unfiled.length.toLocaleString()} not in a folder` : ""}`;
      fill(body,
        h("div", { class: "res-tree-tools lib-pad" }, filter,
          h("button", { type: "button", class: "btn small", text: "▾ Open all", onclick: () => { this.saveOpen(new Set(t.folders.map((f) => f.id))); this.renderTree(body); } }),
          h("button", { type: "button", class: "btn small", text: "▸ Close all", onclick: () => { this.saveOpen(new Set()); this.renderTree(body); } }),
          h("label", { class: "repo-tick", title: "Show what each link is for under it" }, h("input", { type: "checkbox", checked: store.get("fw-res-sum", true) !== false,
            onchange: (e) => { store.set("fw-res-sum", e.target.checked); box.classList.toggle("res-hide-sum", !e.target.checked); } }), " 📝 What it's for"),
          h("button", { type: "button", class: "btn small", text: "＋ New folder", onclick: () => this.newFolder(null) })),
        t.folders.length || t.unfiled.length ? box : h("div", { class: "card lib-empty" }, h("h3", { text: "No folders yet" }),
          h("p", { class: "muted", text: "Import your bookmarks (⇪) with “Keep my folders and subfolders” ticked, or make folders with ＋ New folder." })));
    },

    /** 🗺 Map: your folders as a sitemap - boxes branching left to right; click a box to open it, ⤢ to make it the centre. */
    renderMap(body) {
      const t = this.tree;
      const focus = this.mapFocus && t.folder.get(this.mapFocus) ? this.mapFocus : 0;
      const open = this.mapOpen || (this.mapOpen = new Set());
      const crumbs = [];
      let f = focus ? t.folder.get(focus) : null;
      while (f) { crumbs.unshift(f); f = f.parent_id ? t.folder.get(f.parent_id) : null; }
      const node = (fo) => {
        const kids = t.kids.get(fo.id) || [];
        const links = t.byFolder.get(fo.id) || [];
        const repos = t.reposBy.get(fo.id) || [];
        const isOpen = open.has(fo.id);
        const li = h("li", null,
          // Click the name = go into the folder; the arrow = open / close it here.
          h("div", { class: "res-node", tabindex: "0", role: "button", title: `Go into ${fo.name} (${fo.total} link(s))`,
            onclick: () => { this.mapFocus = fo.id; this.renderMap(body); },
            onkeydown: (e) => { if (e.key === "Enter") e.currentTarget.click(); } },
            h("strong", { text: fo.name }), h("span", { class: "muted small", text: ` ${fo.total}` }),
            kids.length || links.length || repos.length ? h("button", { type: "button", class: `res-node-focus${isOpen ? " open" : ""}`, text: isOpen ? "⤡" : "⤢",
              title: `${isOpen ? "Close" : "Open"} ${fo.name} here`, "aria-label": `${isOpen ? "Close" : "Open"} ${fo.name}`, "aria-expanded": String(isOpen),
              onclick: (e) => { e.stopPropagation(); if (isOpen) open.delete(fo.id); else open.add(fo.id); this.renderMap(body); } }) : null),
          isOpen && (kids.length || links.length || repos.length) ? h("ul", null, kids.map(node),
            repos.map((rp) => h("li", null, h("div", { class: "res-leaf res-leaf-repo", title: rp.description || null }, this.repoLink(rp, "res-leaf-link")))),
            links.slice(0, 60).map((it) => h("li", null, h("div", { class: "res-leaf", "data-rid": String(it.id), title: it.summary || null }, this.link(it, "res-leaf-link")))),
            links.length > 60 ? h("li", null, h("div", { class: "res-leaf muted", text: `…and ${links.length - 60} more` })) : null) : null);
        return li;
      };
      // Focused: the folder itself is the root box, and its subfolders + links branch straight out of it.
      const roots = t.kids.get(focus) || [];
      const rootLinks = (focus ? t.byFolder.get(focus) || [] : []).slice().sort((a, b) => (b.id === this.mapLocate) - (a.id === this.mapLocate));
      $("#resCount").textContent = `Map of ${t.folders.length.toLocaleString()} folder(s) - click a name to go into it, ⤢ to expand it here like a tree`;
      fill(body,
        h("div", { class: "res-tree-tools lib-pad" },
          h("button", { type: "button", class: "btn small", text: "🏠 All", onclick: () => { this.mapFocus = 0; this.renderMap(body); } }),
          crumbs.map((c) => h("button", { type: "button", class: "btn small", text: `› ${c.name}`, onclick: () => { this.mapFocus = c.id; this.renderMap(body); } })),
          h("button", { type: "button", class: "btn small", text: "▾ Open this level", onclick: () => { roots.forEach((r) => open.add(r.id)); this.renderMap(body); } }),
          h("button", { type: "button", class: "btn small", text: "▸ Close all", onclick: () => { open.clear(); this.renderMap(body); } }),
          focus ? this.addMenu(focus, `＋ Add to ${t.folder.get(focus).name}…`) : null),
        h("div", { class: "res-map" }, h("div", { class: "res-map-root" },
          h("div", { class: "res-node res-node-root", text: focus ? `📁 ${this.folderPath(focus)} · ${t.folder.get(focus).total}` : "🔗 Resources" }),
          h("ul", null, roots.map(node),
            (focus ? t.reposBy.get(focus) || [] : []).map((rp) => h("li", null, h("div", { class: "res-leaf res-leaf-repo", title: rp.description || null }, this.repoLink(rp, "res-leaf-link")))),
            rootLinks.slice(0, 60).map((it) => h("li", null, h("div", { class: "res-leaf", "data-rid": String(it.id), title: it.summary || null }, this.link(it, "res-leaf-link")))),
            rootLinks.length > 60 ? h("li", null, h("div", { class: "res-leaf muted", text: `…and ${rootLinks.length - 60} more` })) : null))));
    },

    /** ⋯ for one link or repo in the mind-map panel: choose its folders (several), take it out of this one, edit, delete. */
    itemMenu({ type, item, fid }) {
      const t = this.tree;
      const here = fid ? t.folder.get(fid) : null;
      const close = (e) => { const d = e.target.closest("details"); if (d) d.open = false; };
      const after = async () => { this.tree = null; await this.loadTree(); this.mindSel = fid; this.reload(); };
      const rows = type === "link" ? [
        h("button", { type: "button", class: "btn small", text: "📁 Folders… (put it in several)", onclick: (e) => { close(e); this.placeIn({ type, item }); } }),
        here ? h("button", { type: "button", class: "btn small", text: `− Take out of ${here.name}`, onclick: async (e) => {
          close(e);
          if (await guarded(() => api("POST", `/resources/folders/${fid}/items`, { resource_ids: [item.id], action: "remove" }), `Taken out of ${here.name}`)) await after();
        } }) : null,
        h("button", { type: "button", class: "btn small", text: "✎ Edit title, description, notes…", onclick: async (e) => {
          close(e);
          const full = (await api("GET", `/resources?q=${encodeURIComponent(item.url.slice(0, 190))}&limit=5`)).items.find((x) => x.id === item.id);
          if (full) this.openEdit(full);
        } }),
        h("button", { type: "button", class: "btn small", text: "📍 Show in the folder tree", onclick: (e) => { close(e); this.locate(item, "tree", fid); } }),
        h("button", { type: "button", class: "btn small danger", text: "🗑 Delete link…", onclick: async (e) => {
          close(e);
          const n = (item.folders || []).length;
          if (!window.confirm(`Delete “${item.title}”?\n\nIt goes from Resources entirely${n > 1 ? ` - from all ${n} folders it's in` : ""}. This can't be undone.\nTo only remove it from ${here ? here.name : "this folder"}, use “Take out” instead.`)) return;
          if (await guarded(() => api("DELETE", `/resources/${item.id}`), "Link deleted")) await after();
        } }),
      ] : [
        h("button", { type: "button", class: "btn small", text: "📁 Folders… (show it under several)", onclick: (e) => { close(e); this.placeIn({ type, item }); } }),
        here ? h("button", { type: "button", class: "btn small", text: `− Take off ${here.name}`, onclick: async (e) => {
          close(e);
          if (await guarded(() => api("POST", `/resources/folders/${fid}/repos`, { repo_ids: [item.id], action: "remove" }), `Taken off ${here.name} (still in Repos)`)) await after();
        } }) : null,
      ];
      return h("details", { class: "repo-folder-menu mm-item-menu" },
        h("summary", { class: "icon-btn", text: "⋯", title: "Edit, move or remove", "aria-label": `Options for ${item.title}` }),
        h("div", { class: "repo-folder-menu-list", role: "menu" }, rows));
    },
    /** 📁 Folders…: every folder with a tick where this link (or repo) is now - tick more to add it there, untick to take it out. */
    async placeIn({ type, item }) {
      await this.loadTree();
      const t = this.tree;
      const now = new Set(type === "link" ? (t.items.find((x) => x.id === item.id) || item).folders || []
        : [...t.reposBy.entries()].filter(([, rs]) => rs.some((r) => r.id === item.id)).map(([f]) => f));
      const chosen = new Set(now);
      const find = h("input", { type: "search", maxlength: 100, placeholder: "Find a folder…", "aria-label": "Find a folder" });
      const list = h("ul", { class: "res-cat-list res-place-list" });
      const count = h("p", { class: "muted small" });
      const err = h("p", { class: "error small" });
      const rows = [];
      const walk = (pid, depth) => (t.kids.get(pid) || []).forEach((f) => {
        const box = h("input", { type: "checkbox", checked: chosen.has(f.id), onchange: (e) => { if (e.target.checked) chosen.add(f.id); else chosen.delete(f.id); tally(); } });
        const li = h("li", { "data-text": this.folderPath(f.id).toLowerCase(), style: { "padding-left": `${depth * 16}px` } },
          h("label", null, box, ` 📁 ${f.name}`, now.has(f.id) ? h("span", { class: "muted small", text: " · here now" }) : null));
        rows.push(li);
        walk(f.id, depth + 1);
      });
      walk(0, 0);
      fill(list, rows);
      const tally = () => { count.textContent = `In ${chosen.size} folder(s)${chosen.size ? "" : " - it will show under “Not in a folder”"}`; };
      tally();
      find.addEventListener("input", () => {
        const q = find.value.trim().toLowerCase();
        rows.forEach((li) => { li.hidden = !!q && !li.dataset.text.includes(q); });
      });
      this.dialog("Choose folders", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        const add = [...chosen].filter((f) => !now.has(f));
        const remove = [...now].filter((f) => !chosen.has(f));
        try {
          for (const f of add) await api("POST", type === "link" ? `/resources/folders/${f}/items` : `/resources/folders/${f}/repos`,
            type === "link" ? { resource_ids: [item.id], action: "add" } : { repo_ids: [item.id] });
          for (const f of remove) await api("POST", type === "link" ? `/resources/folders/${f}/items` : `/resources/folders/${f}/repos`,
            type === "link" ? { resource_ids: [item.id], action: "remove" } : { repo_ids: [item.id], action: "remove" });
          dlg.close();
          if (add.length || remove.length) toast(`Added to ${add.length}, taken out of ${remove.length} folder(s)`);
          this.tree = null; this.reload();
        } catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: `📁 Folders for ${type === "repo" ? "📦 " : ""}${item.title}` }),
        h("p", { class: "muted small", text: type === "repo" ? "Tick every topic it should show under. The repo itself stays in the Repos tab."
          : "Tick every topic it belongs to - it's one link, shown in each (edits and ★ apply everywhere)." }),
        find, list, count, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
      find.focus();
    },
    /** ＋ Add… for one folder: new links (pasted), links already in Resources, or repos from the Repos tab. */
    addMenu(fid, label = "＋ Add…") {
      return h("details", { class: "repo-folder-menu res-add-menu" },
        h("summary", { class: "btn small", text: label, title: "Add links or repos to this folder" }),
        h("div", { class: "repo-folder-menu-list", role: "menu" },
          h("button", { type: "button", class: "btn small", text: "＋ New links…", onclick: (e) => { e.target.closest("details").open = false; this.openAdd(fid); } }),
          h("button", { type: "button", class: "btn small", text: "🔗 Links already in Resources…", onclick: (e) => { e.target.closest("details").open = false; this.pickLinks(fid); } }),
          h("button", { type: "button", class: "btn small", text: "📦 Repos…", onclick: (e) => { e.target.closest("details").open = false; this.linkRepos(fid); } })));
    },
    /** Tick links that are already in Resources to also put them in this folder (they stay where they are too). */
    async pickLinks(fid) {
      await this.loadTree();
      const t = this.tree;
      const here = new Set((t.byFolder.get(fid) || []).map((r) => r.id));
      const chosen = new Set();
      const q = h("input", { type: "search", maxlength: 200, placeholder: "Find links by title, address, notes…", "aria-label": "Find links" });
      const list = h("ul", { class: "res-cat-list res-repo-pick" });
      const err = h("p", { class: "error small" });
      let timer = null, seq = 0;
      const search = async () => {
        const mine = ++seq;
        const term = q.value.trim();
        if (!term) { fill(list, h("li", { class: "muted small", text: "Type to find links to add here." })); return; }
        const res = await api("GET", `/resources?${new URLSearchParams({ q: term, limit: "40", sort: "popular" })}`).catch(() => ({ items: [] }));
        if (mine !== seq) return;
        fill(list, res.items.length ? res.items.map((r) => {
          const inHere = here.has(r.id);
          const box = h("input", { type: "checkbox", checked: inHere || chosen.has(r.id), disabled: inHere,
            onchange: (e) => { if (e.target.checked) chosen.add(r.id); else chosen.delete(r.id); } });
          return h("li", null, h("label", null, box, ` ${r.title}`, h("span", { class: "muted small", text: inHere ? " - already here" : ` - ${this.whereIs(r) || r.host}` })));
        }) : h("li", { class: "muted small", text: "Nothing matches." }));
      };
      q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 200); });
      this.dialog("Add links here", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        if (!chosen.size) { dlg.close(); return; }
        try {
          await api("POST", `/resources/folders/${fid}/items`, { resource_ids: [...chosen], action: "add" });
          dlg.close(); toast(`Added ${chosen.size} link(s) to ${t.folder.get(fid).name}`); this.tree = null; this.reload();
        } catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: `🔗 Add links to ${t.folder.get(fid).name}` }),
        h("p", { class: "muted small", text: "They also stay in the folders they're in now." }), q, list, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Add" }))));
      q.focus();
      search();
    },
    /** 📦 Link repos…: tick repos from the Repos tab to show them under this folder (a repo can sit under several topics). */
    async linkRepos(fid) {
      await this.loadTree();
      const t = this.tree;
      const linked = new Set((t.reposBy.get(fid) || []).map((r) => r.id));
      const chosen = new Set(linked);
      const q = h("input", { type: "search", maxlength: 100, placeholder: "Find a repo by name or description…", "aria-label": "Find repos" });
      const list = h("ul", { class: "res-cat-list res-repo-pick" });
      const err = h("p", { class: "error small" });
      const known = new Map((t.reposBy.get(fid) || []).map((r) => [r.id, r]));
      const draw = (items) => fill(list, items.length ? items.map((rp) => {
        known.set(rp.id, rp);
        const box = h("input", { type: "checkbox", checked: chosen.has(rp.id), onchange: (e) => { if (e.target.checked) chosen.add(rp.id); else chosen.delete(rp.id); } });
        return h("li", null, h("label", null, box, ` 📦 ${rp.title}`, rp.description ? h("span", { class: "muted small", text: ` - ${rp.description.slice(0, 90)}` }) : null));
      }) : h("li", { class: "muted small", text: "No repos match. Add repos in the Repos tab first." }));
      let timer = null, seq = 0;
      const search = async () => {
        const mine = ++seq;
        const res = await api("GET", `/resources/repo-search?${new URLSearchParams({ q: q.value.trim() })}`).catch(() => ({ items: [] }));
        if (mine !== seq) return;
        const mineFirst = [...(t.reposBy.get(fid) || []).filter((r) => !q.value.trim() || `${r.title} ${r.description}`.toLowerCase().includes(q.value.trim().toLowerCase())),
          ...res.items.filter((r) => !linked.has(r.id))];
        draw(mineFirst);
      };
      q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 200); });
      this.dialog("Link repos", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        const add = [...chosen].filter((id) => !linked.has(id));
        const remove = [...linked].filter((id) => !chosen.has(id));
        try {
          if (add.length) await api("POST", `/resources/folders/${fid}/repos`, { repo_ids: add });
          if (remove.length) await api("POST", `/resources/folders/${fid}/repos`, { repo_ids: remove, action: "remove" });
          dlg.close();
          if (add.length || remove.length) toast(`Linked ${add.length}, took off ${remove.length}`);
          this.tree = null; this.reload();
        } catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: `📦 Repos for ${t.folder.get(fid).name}` }),
        h("p", { class: "muted small", text: "Repos come from the Repos tab. Ticked ones show under this topic in the tree, map and mind map." }),
        q, list, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
      q.focus();
      search();
    },

    /* ===================================================================== 📦 Repos inside Resources */
    reposCombined() { return store.get("fw-repos-in-resources", true) !== false; },
    /** The top Repos tab is hidden while Repos lives in Resources (one click brings it back). */
    applyReposTab() {
      const b = document.getElementById("modeRepos");
      if (b) b.hidden = this.reposCombined();
    },
    /** Show the Repos screen (the Repos tab's own section) inside Resources' 📦 Repos view. */
    mountRepos(body) {
      const rv = document.getElementById("reposView");
      if (!rv || !FW.repos) { fill(body, h("p", { class: "muted lib-pad", text: "Repos isn't available in this app." })); return; }
      if (!this.reposHome) this.reposHome = { parent: rv.parentNode };
      const combined = this.reposCombined();
      $("#resCount").textContent = "Your GitHub repos, owners, topics, stars and releases - the Repos screen, here in Resources";
      const note = h("p", { class: "muted small res-repos-note lib-pad" },
        combined ? "📦 Repos lives here in Resources now (its own tab is hidden). " : "📦 Repos also has its own tab at the top. ",
        h("button", { type: "button", class: "btn small", text: combined ? "Show Repos as its own tab too" : "Keep Repos only in Resources",
          onclick: () => { store.set("fw-repos-in-resources", !combined); this.applyReposTab(); this.unmountRepos(); this.reload(); } }));
      fill(body, note, rv);                                  // moves the Repos section in here
      rv.hidden = false;
      rv.classList.add("res-embedded");
      this.reposMounted = true;
      store.set("fw-res-releases-seen", Math.floor(Date.now() / 1000));
      this.updateReposBadge(0);
      if (this.reposQuery) {                                 // "Show them in 📦 Repos" / Ctrl+Enter: open on that search
        Object.assign(FW.repos.filters, { q: this.reposQuery, view: "grid" });
        if (FW.repos.save) FW.repos.save();
        this.reposQuery = null;
      }
      FW.repos.show();
    },
    /** Put the Repos section back where the page keeps it (before Resources redraws, or when leaving the view / tab). */
    unmountRepos() {
      if (!this.reposMounted) return;
      this.reposMounted = false;
      const rv = document.getElementById("reposView");
      if (FW.repos) FW.repos.hide();
      if (!rv || !this.reposHome) return;
      const anchor = document.getElementById("resourcesView");
      this.reposHome.parent.insertBefore(rv, anchor && anchor.parentNode === this.reposHome.parent ? anchor : null);
      rv.classList.remove("res-embedded");
      rv.hidden = !document.getElementById("app").classList.contains("mode-repos");
    },
    /** New releases since you last opened 📦 Repos, as a small count on its button. */
    async updateReposBadge(n) {
      const set = (k) => { const b = document.getElementById("resReposBadge"); if (b) { b.hidden = !k; b.textContent = k > 99 ? "99+" : String(k); b.title = `${k} new release(s)`; } };
      if (typeof n === "number") { set(n); return; }
      const seen = store.get("fw-res-releases-seen", 0) || Math.floor(Date.now() / 1000) - 7 * 86400;
      const r = await api("GET", `/repos/releases?${new URLSearchParams({ since: String(seen), limit: "1" })}`).catch(() => null);
      if (r && this.filters.view !== "repos") set(r.total || 0);
    },

    /* ===================================================================== ★ Launchpad + Ctrl+K launcher */
    /** One tile: opens ONE site in a new tab (and counts it); the colour and emoji come from its first category. */
    tile(r) {
      const cats = new Map(((this.meta && this.meta.categories) || []).map((c) => [c.id, c]));
      const c = (r.categories || []).map((id) => cats.get(id)).find(Boolean);
      return h("a", { class: "res-pad-tile", href: safeUrl(r.url), target: "_blank", rel: "noopener noreferrer", title: r.summary || r.url,
        style: { "--c": c ? safeColor(c.color) : "#6b7280" }, onclick: () => { api("POST", `/resources/${r.id}/opened`).catch(() => {}); } },
        h("span", { class: "res-pad-icon", "aria-hidden": "true", text: c ? c.emoji : (r.host || "?").replace(/^www\./, "").charAt(0).toUpperCase() }),
        h("span", { class: "res-pad-title", text: r.title }),
        h("span", { class: "res-pad-host muted small", text: r.host }));
    },
    async renderLaunchpad(body) {
      const [fav, pop] = await Promise.all([api("GET", "/resources?favourite=true&sort=popular&limit=200"), api("GET", "/resources?sort=popular&limit=40")]);
      const favIds = new Set(fav.items.map((r) => r.id));
      const most = pop.items.filter((r) => r.open_count > 0 && !favIds.has(r.id)).slice(0, 12);
      const home = `${location.origin}/#launchpad`;
      $("#resCount").textContent = `${fav.total.toLocaleString()} favourite(s) · Ctrl+K anywhere in the app opens any resource`;
      fill(body, h("div", { class: "res-pad-wrap lib-pad" },
        h("p", { class: "res-pad-home small muted" }, "Your browser's home page: ", h("code", { text: home }),
          h("button", { type: "button", class: "btn small", text: "Copy", onclick: async () => {
            try { await navigator.clipboard.writeText(home); toast("Copied - paste it as your browser's home page"); } catch { toast("Select the address and copy it", true); }
          } })),
        fav.items.length ? h("div", { class: "res-pad", role: "list", "aria-label": "Favourites" }, fav.items.map((r) => h("div", { role: "listitem" }, this.tile(r))))
          : h("div", { class: "card lib-empty" }, h("h3", { text: "Pin your go-to sites here" }),
            h("p", { class: "muted", text: "Press ☆ on a link (in All links), or ⋯ → ★ Add to favourites in the folder tree. Each tile opens one site." })),
        most.length ? h("h3", { class: "res-pad-h", text: "🔥 Most opened" }) : null,
        most.length ? h("div", { class: "res-pad res-pad-small", role: "list", "aria-label": "Most opened" }, most.map((r) => h("div", { role: "listitem" }, this.tile(r)))) : null));
    },
    /** Make the Resources tab the one on screen (from any other tab), then run fn. */
    async inResources(fn) {
      const rv = document.getElementById("resourcesView");
      if (rv && rv.hidden) {
        document.getElementById("modeResources")?.click();
        for (let i = 0; i < 40 && (!this.meta || !$("#resBody")); i++) await new Promise((r) => setTimeout(r, 100));
        await new Promise((r) => setTimeout(r, 250));
      }
      await fn();
    },
    /** Open a folder in the tree: its parents opened, the folder scrolled to and highlighted. */
    async openFolder(fid) {
      await this.loadTree();
      const open = this.openState();
      for (let f = this.tree.folder.get(fid); f; f = f.parent_id ? this.tree.folder.get(f.parent_id) : null) open.add(f.id);
      this.saveOpen(open);
      this.folderFilter = null;
      Object.assign(this.filters, { view: "tree", q: "", kind: "", training: false, status: "", favourite: false, category_id: "" });
      this.save(); this.renderShell(); await this.reload();
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      const row = document.querySelector(`#resBody .res-tree-folder[data-id="${fid}"] > .res-tree-row`);
      if (row) { row.classList.add("res-located"); row.scrollIntoView({ block: "center", behavior: "smooth" }); setTimeout(() => row.classList.remove("res-located"), 4500); }
    },
    /** ⌘/Ctrl+K: type a few letters ("htb") and press Enter to open that one site - works from every tab. */
    async openLauncher() {
      const already = document.querySelector("dialog.res-launcher[open]");
      if (already) { already.querySelector("input").focus(); return; }
      if (!this.meta) await this.loadMeta();
      if (!this.tree) this.loadTree().catch(() => {});        // folders join the results once they arrive
      const input = h("input", { type: "search", maxlength: 120, placeholder: "Open a resource, folder or tab… (e.g. htb)", "aria-label": "Search resources, folders and tabs",
        role: "combobox", "aria-expanded": "true", "aria-controls": "resLaunchList", autocomplete: "off" });
      const list = h("ul", { id: "resLaunchList", class: "res-launch-list", role: "listbox", "aria-label": "Results" });
      const hint = h("p", { class: "muted small res-launch-hint", text: "↑ ↓ to choose · Enter opens · Ctrl+Enter shows it in Resources · Esc closes" });
      let items = [], active = 0, seq = 0;
      const tabs = () => [...document.querySelectorAll(".mode-switch > button[id^='mode']")].map((b) => ({ type: "tab", id: b.id, label: (b.title || b.textContent).split(":")[0].trim(), icon: b.textContent.trim().split(" ")[0] }));
      const draw = () => {
        fill(list, items.length ? items.map((it, i) => {
          const sub = it.type === "res" ? (it.r.summary || it.r.host) : it.type === "folder" ? `Folder · ${it.path}` : it.type === "repo" ? `Repo${it.rp.description ? ` · ${it.rp.description}` : ""}` : "Tab";
          return h("li", { id: `resLaunch${i}`, role: "option", class: `res-launch-item${i === active ? " active" : ""}`, "aria-selected": String(i === active),
            onclick: (e) => run(it, e.ctrlKey || e.metaKey), onmousemove: () => { if (active !== i) { active = i; mark(); } } },
            h("span", { class: "res-launch-icon", "aria-hidden": "true", text: it.type === "res" ? (it.r.favourite ? "★" : "🔗") : it.type === "folder" ? "📁" : it.type === "repo" ? "📦" : it.icon }),
            h("span", { class: "res-launch-text" }, h("strong", { text: it.type === "res" ? it.r.title : it.label }), h("span", { class: "muted small", text: sub })));
        }) : h("li", { class: "muted small res-launch-empty", text: "Nothing matches - try another word." }));
        mark();
      };
      const mark = () => {
        [...list.children].forEach((li, i) => { li.classList.toggle("active", i === active); li.setAttribute("aria-selected", String(i === active)); });
        input.setAttribute("aria-activedescendant", items.length ? `resLaunch${active}` : "");
        const el = list.children[active];
        if (el && el.scrollIntoView) el.scrollIntoView({ block: "nearest" });
      };
      const search = async () => {
        const q = input.value.trim();
        const mine = ++seq;
        if (!q) {
          const seen = new Set();
          items = [...this.meta.favourites, ...this.meta.recent].filter((r) => !seen.has(r.id) && seen.add(r.id)).slice(0, 12).map((r) => ({ type: "res", r }));
          active = 0; draw(); return;
        }
        const ql = q.toLowerCase();
        const words = ql.split(/\s+/).filter(Boolean);
        const hit = (txt) => words.every((w) => txt.toLowerCase().includes(w));
        const data = await api("GET", `/resources?${new URLSearchParams({ q, limit: "30", sort: "popular" })}`).catch(() => ({ items: [] }));
        if (mine !== seq) return;                               // a newer keystroke won
        // Short forms match a site's name letter by letter: "htb" → hackthebox, "thm" → tryhackme, "otw" → overthewire.
        const core = (host) => {                              // the site's own name: "hackthebox" in academy.hackthebox.com
          const parts = (host || "").toLowerCase().split(".");
          const cut = parts.length > 2 && /^(com|net|org|gov|edu|co|ac)$/.test(parts[parts.length - 2]) ? 3 : 2;
          return parts.length >= cut ? parts[parts.length - cut] : parts[0] || "";
        };
        const initials = (host) => {                          // 0 = no match; otherwise how many letters the match spans (tighter = better)
          const c = core(host);
          if (!/^[a-z0-9]+$/.test(ql) || ql.length < 2 || c[0] !== ql[0]) return 0;
          let i = 0, end = 0;
          for (let k = 0; k < c.length && i < ql.length; k++) if (c[k] === ql[i]) { i++; end = k; }
          return i === ql.length ? end + 1 : 0;
        };
        const tight = (host) => { const span = initials(host); return span ? 2.5 + 1 / span : 0; };
        const score = (r) => (r.favourite ? 4 : 0) + (core(r.host).startsWith(ql) ? 3 : 0) + tight(r.host)
          + (r.title.toLowerCase().startsWith(ql) ? 2 : 0) + Math.min(r.open_count || 0, 5) / 5;
        const pool = new Map(data.items.map((r) => [r.id, r]));
        if (this.tree && !q.includes(" ")) for (const r of this.tree.items) if (!pool.has(r.id) && initials(r.host)) pool.set(r.id, r);
        const res = [...pool.values()].sort((a, b) => score(b) - score(a)).slice(0, 8).map((r) => ({ type: "res", r }));
        const folders = this.tree ? this.tree.folders.filter((f) => hit(f.name)).slice(0, 4).map((f) => ({ type: "folder", fid: f.id, label: f.name, path: this.folderPath(f.id) })) : [];
        const tabHits = tabs().filter((t) => hit(t.label)).slice(0, 3);
        const rr = await api("GET", `/resources/repo-search?${new URLSearchParams({ q })}`).catch(() => ({ items: [] }));
        if (mine !== seq) return;
        const repoHits = rr.items.slice(0, 4).map((rp) => ({ type: "repo", rp, label: rp.title }));
        items = [...res, ...repoHits, ...folders, ...tabHits];
        active = 0; draw();
      };
      let timer = null;
      input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 120); });
      input.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); if (items.length) { active = (active + 1) % items.length; mark(); } }
        else if (e.key === "ArrowUp") { e.preventDefault(); if (items.length) { active = (active - 1 + items.length) % items.length; mark(); } }
        else if (e.key === "Enter") { e.preventDefault(); if (items[active]) run(items[active], e.ctrlKey || e.metaKey); }
      });
      const run = async (it, show) => {
        dlg.close();
        if (it.type === "res" && !show) {
          api("POST", `/resources/${it.r.id}/opened`).catch(() => {});
          window.open(safeUrl(it.r.url), "_blank", "noopener,noreferrer");
        } else if (it.type === "res") {
          await this.inResources(() => this.locate(it.r, "tree"));
        } else if (it.type === "repo" && !show) {
          window.open(safeUrl(it.rp.url), "_blank", "noopener,noreferrer");
        } else if (it.type === "repo") {
          await this.inResources(async () => { this.reposQuery = it.rp.title; this.set({ view: "repos" }); });
        } else if (it.type === "folder") {
          await this.inResources(() => this.openFolder(it.fid));
        } else {
          document.getElementById(it.id)?.click();
        }
      };
      const dlg = this.dialog("Open a resource", () => h("div", { class: "res-launch" }, input, list, hint));
      dlg.classList.add("res-launcher");
      input.focus();
      search();
    },

    /* ===================================================================== 🧠 mind map
       Folders as a radial map around a centre (Everything, or one folder): ring 1 = its subfolders, ring 2 = theirs.
       Solid lines = inside; dashed lines = "goes well with" (your connections, with a note on why). Connected folders
       outside the centre's branch show as dashed bubbles on the outer ring. Click a bubble for its links and connections. */
    relations: null,
    async loadRelations(force = false) {
      if (this.relations && !force) return;
      this.relations = (await api("GET", "/resources/relations")).relations;
    },
    relationsOf(fid) { return (this.relations || []).filter((r) => r.a === fid || r.b === fid).map((r) => ({ ...r, other: r.a === fid ? r.b : r.a })); },
    async renderMind(body) {
      await this.loadRelations();
      const t = this.tree;
      const NS = "http://www.w3.org/2000/svg";
      const svg = (tag, attrs = {}, ...kids) => {
        const el = document.createElementNS(NS, tag);
        for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
        kids.flat().forEach((c) => c && el.append(c instanceof Node ? c : document.createTextNode(String(c))));
        return el;
      };
      if (this.mindFocus && !t.folder.get(this.mindFocus)) this.mindFocus = 0;
      const focus = this.mindFocus || 0;
      const deep = this.mindDeep !== false;
      const ring1 = t.kids.get(focus) || [];
      const PAL = ["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4", "#ec4899", "#84cc16", "#f97316", "#14b8a6", "#a855f7", "#64748b"];
      // Angles: each ring-1 branch gets a slice sized by how many ring-2 bubbles it shows.
      const kidsOf = (id) => (deep ? (t.kids.get(id) || []) : []);
      const weight = (f) => Math.max(deep ? 3 : 1, kidsOf(f.id).length);   // a minimum slice keeps small branches readable
      const totalW = ring1.reduce((s, f) => s + weight(f), 0) || 1;
      const n2 = ring1.reduce((s, f) => s + kidsOf(f.id).length, 0);
      const R1 = Math.max(170, Math.min(300, 60 + ring1.length * 14));
      const R2 = R1 + Math.max(170, Math.min(330, 90 + n2 * 2.2));
      const R3 = R2 + 150;
      const W = (R3 + 240) * 2, H = W;
      const cx = W / 2, cy = H / 2;
      const pos = new Map();          // folder id → {x, y, a, ring, color}
      pos.set(focus, { x: cx, y: cy, a: 0, ring: 0, color: "var(--accent)" });
      let acc = -Math.PI / 2;
      ring1.forEach((f, i) => {
        const span = (weight(f) / totalW) * Math.PI * 2;
        const a = acc + span / 2;
        const color = PAL[i % PAL.length];
        pos.set(f.id, { x: cx + R1 * Math.cos(a), y: cy + R1 * Math.sin(a), a, ring: 1, color, parent: focus });
        const kids = kidsOf(f.id);
        kids.forEach((k, j) => {
          const ka = acc + (span * (j + 0.5)) / kids.length;
          pos.set(k.id, { x: cx + R2 * Math.cos(ka), y: cy + R2 * Math.sin(ka), a: ka, ring: 2, color, parent: f.id });
        });
        acc += span;
      });
      // Connected folders outside this view: a dashed bubble on the outer ring, next to the first bubble it connects to.
      const outside = new Map();
      for (const r of this.relations) {
        const inA = pos.has(r.a), inB = pos.has(r.b);
        if (inA === inB) continue;
        const [inside, other] = inA ? [r.a, r.b] : [r.b, r.a];
        if (!t.folder.get(other) || other === focus) continue;
        if (!outside.has(other)) outside.set(other, []);
        outside.get(other).push(pos.get(inside).a);
      }
      const used = [];
      for (const [fid, angles] of outside) {
        let a = Math.atan2(angles.reduce((s, x) => s + Math.sin(x), 0), angles.reduce((s, x) => s + Math.cos(x), 0));
        for (let tries = 0; tries < 40 && used.some((u) => Math.abs(Math.atan2(Math.sin(u - a), Math.cos(u - a))) < 0.11); tries++) a += 0.11;
        used.push(a);
        pos.set(fid, { x: cx + R3 * Math.cos(a), y: cy + R3 * Math.sin(a), a, ring: 3, color: "var(--muted)" });
      }
      const short = (s, n = 26) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
      const curve = (p, q, bend) => {
        const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
        const qx = mx + (cx - mx) * bend, qy = my + (cy - my) * bend;
        return `M${p.x.toFixed(1)},${p.y.toFixed(1)} Q${qx.toFixed(1)},${qy.toFixed(1)} ${q.x.toFixed(1)},${q.y.toFixed(1)}`;
      };
      const treeLines = svg("g", { class: "mm-tree" });
      const relLines = svg("g", { class: "mm-rel" });
      const nodes = svg("g", { class: "mm-nodes" });
      for (const [fid, p] of pos) if (p.parent !== undefined && pos.has(p.parent)) {
        treeLines.append(svg("path", { d: curve(pos.get(p.parent), p, 0.15), stroke: p.color, "data-a": p.parent, "data-b": fid }));
      }
      for (const r of this.relations) {
        if (!pos.has(r.a) || !pos.has(r.b)) continue;
        relLines.append(svg("path", { d: curve(pos.get(r.a), pos.get(r.b), 0.45), "data-a": r.a, "data-b": r.b },
          svg("title", {}, `${t.folder.get(r.a).name} ↔ ${t.folder.get(r.b).name}${r.note ? `: ${r.note}` : ""}`)));
      }
      const select = (fid) => { this.mindSel = fid; drawPanel(); highlight(fid); };
      const highlight = (fid) => {
        box.querySelectorAll(".mm-on").forEach((el) => el.classList.remove("mm-on"));
        if (!fid) return;
        box.querySelectorAll(`[data-a="${fid}"], [data-b="${fid}"], [data-id="${fid}"]`).forEach((el) => el.classList.add("mm-on"));
      };
      for (const [fid, p] of pos) {
        const f = fid ? t.folder.get(fid) : null;
        const name = f ? f.name : "Everything";
        const total = f ? f.total : t.items.length;
        const rad = p.ring === 0 ? 34 : p.ring === 1 ? Math.min(26, 11 + Math.sqrt(total) * 1.2) : Math.min(16, 6 + Math.sqrt(total) * 0.9);
        const right = Math.cos(p.a) >= 0;
        const lx = p.ring === 0 ? p.x : p.x + (right ? rad + 6 : -rad - 6);
        const ly = p.ring === 0 ? p.y + rad + 18 : p.y + 4;
        const rels = this.relationsOf(fid).length;
        const g = svg("g", { class: `mm-node mm-r${p.ring}`, tabindex: "0", role: "button", "data-id": fid,
          "aria-label": `${name}: ${total} link(s)${rels ? `, ${rels} connection(s)` : ""}` },
          svg("circle", { cx: p.x.toFixed(1), cy: p.y.toFixed(1), r: rad.toFixed(1), fill: p.color, stroke: p.color }),
          svg("text", { x: lx.toFixed(1), y: ly.toFixed(1), "text-anchor": p.ring === 0 ? "middle" : right ? "start" : "end" },
            `${p.ring === 3 && f && f.parent_id ? `${short(t.folder.get(f.parent_id).name, 14)} › ` : ""}${short(name, p.ring === 0 ? 40 : 26)}`),
          p.ring !== 3 ? svg("text", { x: p.x.toFixed(1), y: (p.y + 4).toFixed(1), "text-anchor": "middle", class: "mm-count" }, total > 999 ? `${Math.round(total / 100) / 10}k` : String(total)) : null,
          svg("title", {}, `${f ? this.folderPath(fid) : "Everything"} · ${total} link(s)${rels ? ` · ${rels} connection(s)` : ""}`));
        g.addEventListener("click", () => { if (!this.mmDragged) select(fid); });
        g.addEventListener("dblclick", () => { if (fid !== focus && (t.kids.get(fid) || []).length) { this.mindFocus = fid; this.mindSel = fid; this.renderMind(body); } });
        g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(fid); } });
        g.addEventListener("mouseenter", () => highlight(fid));
        g.addEventListener("mouseleave", () => highlight(this.mindSel));
        nodes.append(g);
      }
      // Camera: the SVG fills the canvas and the view (x, y, w, h in map units) is its viewBox. Wheel = zoom at the
      // pointer, drag = pan, arrows / + / - / 0 on the canvas. The view is kept while you stay on the same centre.
      const map = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "mm-svg", role: "img", "aria-label": "Mind map of your folders" }, treeLines, relLines, nodes);
      const canvas = h("div", { class: "mm-canvas", tabindex: "0", "aria-label": "Mind map: scroll to zoom, drag or use the arrow keys to move, 0 to fit" }, map);
      const panel = h("aside", { class: "mm-panel card", "aria-live": "polite" });
      const box = h("div", { class: "mm-wrap" }, canvas, panel);
      const key = `${focus}:${deep}:${W}`;
      let view = this.mindView && this.mindView.key === key ? { ...this.mindView } : null;
      const apply = () => {
        map.setAttribute("viewBox", `${view.x.toFixed(1)} ${view.y.toFixed(1)} ${view.w.toFixed(1)} ${view.h.toFixed(1)}`);
        this.mindView = { ...view, key };
      };
      const size = () => [canvas.clientWidth || 800, canvas.clientHeight || 600];
      const fit = () => {
        const [cw, ch] = size();
        const k = Math.max(W / cw, H / ch) * 1.04;              // map units per screen pixel: the whole map, centred
        view = { x: cx - (cw * k) / 2, y: cy - (ch * k) / 2, w: cw * k, h: ch * k };
        apply();
      };
      const zoomAt = (factor, px, py) => {                    // px, py (map units) stay under the pointer
        const nw = Math.max(W * 0.06, Math.min(W * 4, view.w * factor));
        const f = nw / view.w;
        view = { x: px - (px - view.x) * f, y: py - (py - view.y) * f, w: view.w * f, h: view.h * f };
        apply();
      };
      const toMap = (clientX, clientY) => {
        const r = canvas.getBoundingClientRect();
        return [view.x + ((clientX - r.left) / r.width) * view.w, view.y + ((clientY - r.top) / r.height) * view.h];
      };
      const zoomCentre = (factor) => zoomAt(factor, view.x + view.w / 2, view.y + view.h / 2);
      canvas.addEventListener("wheel", (e) => {
        e.preventDefault();
        const [px, py] = toMap(e.clientX, e.clientY);
        const d = Math.max(-1, Math.min(1, e.deltaY / (e.deltaMode ? 3 : 100)));
        zoomAt(Math.exp(d * 0.18), px, py);
      }, { passive: false });
      let drag = null;
      canvas.addEventListener("pointerdown", (e) => {
        if (e.button !== 0) return;
        drag = { id: e.pointerId, sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: false };
        this.mmDragged = false;
      });
      canvas.addEventListener("pointermove", (e) => {
        if (!drag || e.pointerId !== drag.id) return;
        const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
        if (!drag.moved && Math.hypot(dx, dy) < 5) return;          // still a click, not a drag
        if (!drag.moved) { drag.moved = true; this.mmDragged = true; canvas.setPointerCapture(e.pointerId); canvas.classList.add("dragging"); }
        const k = view.w / size()[0];
        view = { ...view, x: drag.vx - dx * k, y: drag.vy - dy * k };
        apply();
      });
      const endDrag = (e) => {
        if (!drag || e.pointerId !== drag.id) return;
        canvas.classList.remove("dragging");
        if (drag.moved) setTimeout(() => { this.mmDragged = false; }, 0);   // swallow the click that ends a drag
        drag = null;
      };
      canvas.addEventListener("pointerup", endDrag);
      canvas.addEventListener("pointercancel", endDrag);
      canvas.addEventListener("keydown", (e) => {
        if (e.target !== canvas) return;
        const step = 0.12;
        const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
        if (moves[e.key]) { e.preventDefault(); view = { ...view, x: view.x + moves[e.key][0] * view.w, y: view.y + moves[e.key][1] * view.h }; apply(); }
        else if (e.key === "+" || e.key === "=") { e.preventDefault(); zoomCentre(1 / 1.25); }
        else if (e.key === "-" || e.key === "_") { e.preventDefault(); zoomCentre(1.25); }
        else if (e.key === "0") { e.preventDefault(); fit(); }
      });
      if (this.mmResize) this.mmResize.disconnect();
      this.mmResize = new ResizeObserver(() => {             // same scale and centre when the window changes size
        if (!view || !canvas.isConnected) return;
        const [cw, ch] = size();
        const k = view.w / (this.mmLastW || cw);
        const mx = view.x + view.w / 2, my = view.y + view.h / 2;
        view = { x: mx - (cw * k) / 2, y: my - (ch * k) / 2, w: cw * k, h: ch * k };
        this.mmLastW = cw;
        apply();
      });
      const drawPanel = () => {
        const fid = this.mindSel ?? focus;
        const f = fid ? t.folder.get(fid) : null;
        if (fid && !f) { fill(panel, h("p", { class: "muted", text: "Click a bubble." })); return; }
        const rels = this.relationsOf(fid);
        const links = (f ? (t.byFolder.get(fid) || []) : []).slice().sort((a, b) => (b.id === this.mindLocate) - (a.id === this.mindLocate));
        const subs = t.kids.get(fid || 0) || [];
        const jump = (other) => {                                // select a folder on the map (re-centre if it isn't drawn)
          if (pos.has(other)) select(other); else { this.mindFocus = t.folder.get(other).parent_id || 0; this.mindSel = other; this.renderMind(body); }
        };
        // 🧠 "Goes well with" lives in a closable popup, opened from the button next to the title
        const openConnections = () => {
          const dlg = this.dialog(`${f.name} goes well with`, (d) => {
            const draw = () => {
              const now = this.relationsOf(fid);
              return h("div", { class: "form mm-conn" },
                h("div", { class: "mm-conn-head" },
                  h("h3", { text: `🧠 ${f.name} goes well with (${now.length})` }),
                  h("button", { type: "button", class: "icon-btn", text: "✕", title: "Close", "aria-label": "Close", onclick: () => d.close() })),
                now.length ? h("ul", { class: "mm-rels" }, now.map((r) => h("li", null,
                  h("button", { type: "button", class: "linklike", text: `↔ ${this.folderPath(r.other)}`, title: "Show it on the map",
                    onclick: () => { d.close(); jump(r.other); } }),
                  r.note ? h("span", { class: "muted small mm-note", text: r.note }) : null,
                  h("span", { class: "mm-conn-tools" },
                    h("button", { type: "button", class: "icon-btn", text: "✎", title: "Change the note", "aria-label": `Change the note for ${this.folderPath(r.other)}`,
                      onclick: () => { d.close(); this.editRelation(r); } }),
                    h("button", { type: "button", class: "icon-btn danger", text: "🗑", title: "Remove this connection", "aria-label": `Remove the connection to ${this.folderPath(r.other)}`,
                      onclick: async () => {
                        if (!window.confirm(`Remove the connection between ${t.folder.get(r.a).name} and ${t.folder.get(r.b).name}?`)) return;
                        if (await guarded(() => api("DELETE", `/resources/relations/${r.id}`), "Connection removed")) {
                          await this.loadRelations(true); fill(d, draw()); this.renderMind(body);
                        }
                      } }))))) : h("p", { class: "muted small", text: "Nothing yet - connect topics that help each other (e.g. Python ↔ Malware analysis)." }),
                h("div", { class: "form-actions" },
                  h("button", { type: "button", class: "btn", text: "Close", onclick: () => d.close() }),
                  h("button", { type: "button", class: "btn primary", text: "＋ Connect a folder", onclick: () => { d.close(); this.addRelation(fid); } })));
            };
            return draw();
          });
          return dlg;
        };
        fill(panel,
          h("div", { class: "mm-panel-head" },
            h("h3", { text: f ? `📁 ${f.name}` : "🔗 Everything" }),
            f ? h("button", { type: "button", class: `btn small${rels.length ? " primary" : ""}`, text: `🧠 ${rels.length}`,
              title: rels.length ? `Goes well with ${rels.length} folder(s) - show them` : "No connections yet - add one",
              "aria-label": `Goes well with: ${rels.length} connection(s)`, onclick: openConnections }) : null),
          f ? h("p", { class: "muted small", text: `${this.folderPath(fid)} · ${f.total.toLocaleString()} link(s)` }) : h("p", { class: "muted small", text: `${t.items.length.toLocaleString()} link(s) in ${t.folders.length} folder(s) · ${this.relations.length} connection(s)` }),
          h("div", { class: "form-actions mm-actions" },
            f && fid !== focus && subs.length ? h("button", { type: "button", class: "btn small", text: "⤢ Centre here", onclick: () => { this.mindFocus = fid; this.renderMind(body); } }) : null,
            f ? h("button", { type: "button", class: "btn small", text: "☰ Its links", onclick: () => this.showFolderList(f) }) : null,
            f ? this.addMenu(fid) : null),
          subs.length ? h("h4", { text: `Subfolders (${subs.length})` }) : null,
          subs.length ? h("ul", { class: "mm-subs" }, subs.map((sf) => h("li", null,
            h("button", { type: "button", class: "linklike", text: `📁 ${sf.name}`, title: `Show ${sf.name}`, onclick: () => jump(sf.id) }),
            h("span", { class: "muted small", text: ` ${sf.total.toLocaleString()} link(s)${(t.kids.get(sf.id) || []).length ? ` · ${(t.kids.get(sf.id) || []).length} subfolder(s)` : ""}` })))) : null,
          links.length ? h("h4", { text: `Links here (${links.length})` }) : null,
          links.length ? h("ul", { class: "mm-links mm-editable" }, links.slice(0, 40).map((it) => h("li", { "data-rid": String(it.id) },
            h("div", { class: "mm-item-row" }, this.link(it, "res-tree-title"), this.itemMenu({ type: "link", item: it, fid })),
            it.summary ? h("div", { class: "muted small", text: it.summary }) : null))) : null,
          links.length > 40 ? h("p", { class: "muted small", text: `…and ${links.length - 40} more - ☰ Its links shows them all.` }) : null,
          ...(() => {                                            // 📦 repos from the Repos tab linked to this topic
            const rps = f ? t.reposBy.get(fid) || [] : [];
            if (!rps.length) return [];
            return [h("h4", { text: `Repos (${rps.length})` }),
              h("ul", { class: "mm-links mm-repos mm-editable" }, rps.map((rp) => h("li", null,
                h("div", { class: "mm-item-row" }, this.repoLink(rp), this.itemMenu({ type: "repo", item: rp, fid })),
                rp.description ? h("div", { class: "muted small", text: rp.description }) : null)))];
          })());
      };
      const centre = this.folderSelect("Centre the mind map on");
      centre.prepend(h("option", { value: "0", text: "🔗 Everything" }));
      centre.value = String(focus);
      centre.addEventListener("change", () => { this.mindFocus = Number(centre.value); this.mindSel = null; this.renderMind(body); });
      $("#resCount").textContent = `${(pos.size - 1 - outside.size).toLocaleString()} folder(s) on the map · ${relLines.childNodes.length} connection(s) drawn · ${this.relations.length} in all`;
      fill(body,
        h("div", { class: "res-tree-tools lib-pad" },
          h("label", { class: "small" }, "Centre: ", centre),
          focus ? h("button", { type: "button", class: "btn small", text: "⬆ Up a level", onclick: () => { this.mindFocus = t.folder.get(focus).parent_id || 0; this.mindSel = null; this.renderMind(body); } }) : null,
          h("label", { class: "repo-tick" }, h("input", { type: "checkbox", checked: deep, onchange: (e) => { this.mindDeep = e.target.checked; this.renderMind(body); } }), " Show subfolders"),
          h("span", { class: "mm-zoom" },
            h("button", { type: "button", class: "btn small", text: "−", title: "Zoom out", "aria-label": "Zoom out", onclick: () => zoomCentre(1.25) }),
            h("button", { type: "button", class: "btn small", text: "＋", title: "Zoom in", "aria-label": "Zoom in", onclick: () => zoomCentre(1 / 1.25) }),
            h("button", { type: "button", class: "btn small", text: "Fit", title: "Show the whole map, centred (key 0)", onclick: () => fit() })),
          h("span", { class: "muted small mm-legend", text: "Scroll to zoom · drag to move · click a bubble, double-click to centre · — inside  ┄ goes well with  ◌ elsewhere" })),
        box);
      drawPanel();
      if (this.mindSel) highlight(this.mindSel);
      requestAnimationFrame(() => {                           // start with the whole map centred (or where you left it)
        this.mmLastW = size()[0];
        if (view) apply(); else fit();
        this.mmResize.observe(canvas);
      });
    },
    addRelation(fid) {
      const load = this.loadTree();
      const go = async () => {
        await load;
        await this.loadRelations();
        const sel = this.folderSelect("Goes well with", { exclude: null });
        [...sel.options].forEach((o) => { if (Number(o.value) === fid) o.disabled = true; });
        const note = h("input", { type: "text", maxlength: 300, placeholder: "Why? e.g. automate malware triage with Python", "aria-label": "Why they go together" });
        const err = h("p", { class: "error small" });
        this.dialog("Goes well with", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
          e.preventDefault();
          try {
            await api("POST", "/resources/relations", { a: fid, b: Number(sel.value), note: note.value.trim() });
            dlg.close(); await this.loadRelations(true); toast("Connected"); this.mindSel = fid; this.reload();
          } catch (ex) { err.textContent = ex.message; }
        } }, h("h3", { text: `🧠 ${this.tree.folder.get(fid).name} goes well with…` }),
          h("label", null, "Folder", sel), h("label", null, "Why (optional)", note), err,
          h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
            h("button", { type: "submit", class: "btn primary", text: "Connect" }))));
      };
      go();
    },
    editRelation(r) {
      const note = h("input", { type: "text", maxlength: 300, value: r.note || "", "aria-label": "Why they go together" });
      const err = h("p", { class: "error small" });
      this.dialog("Change the note", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try { await api("PATCH", `/resources/relations/${r.id}`, { note: note.value.trim() }); dlg.close(); await this.loadRelations(true); this.reload(); } catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: `✎ ${this.tree.folder.get(r.a).name} ↔ ${this.tree.folder.get(r.b).name}` }), note, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
    },

    newFolder(parentId) {
      const name = h("input", { type: "text", maxlength: 120, required: true, "aria-label": "Folder name", placeholder: "e.g. Exam prep" });
      const err = h("p", { class: "error small" });
      this.dialog("New folder", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try { await api("POST", "/resources/folders", { name: name.value.trim(), ...(parentId ? { parent_id: parentId } : {}) }); dlg.close(); this.tree = null; this.reload(); }
        catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: parentId ? `📁 New folder in ${this.folderPath(parentId)}` : "📁 New folder" }), name, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Create" }))));
      name.focus();
    },
    renameFolder(f) {
      const name = h("input", { type: "text", maxlength: 120, value: f.name, required: true, "aria-label": "Folder name" });
      const err = h("p", { class: "error small" });
      this.dialog("Rename folder", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try { await api("PATCH", `/resources/folders/${f.id}`, { name: name.value.trim() }); dlg.close(); this.tree = null; this.reload(); }
        catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: "✎ Rename folder" }), name, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
      name.select();
    },
    moveFolder(f) {
      const sel = this.folderSelect("Move into", { top: true, exclude: f.id });
      sel.value = String(f.parent_id || 0);
      const err = h("p", { class: "error small" });
      this.dialog("Move folder", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try { await api("PATCH", `/resources/folders/${f.id}`, { parent_id: Number(sel.value) }); dlg.close(); this.tree = null; this.reload(); }
        catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: `⇢ Move “${f.name}” into…` }), sel, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Move" }))));
    },
    deleteFolder(f) {
      this.dialog("Delete folder", (dlg) => h("div", { class: "form" },
        h("h3", { text: `🗑 Delete “${f.name}”?` }),
        h("p", { class: "small", text: `It holds ${f.total.toLocaleString()} link(s), counting its subfolders, which go with it.` }),
        h("div", { class: "form-actions repo-remove-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "button", class: "btn", text: "Delete the folder, keep its links", onclick: async () => {
            if (await guarded(() => api("DELETE", `/resources/folders/${f.id}`), "Folder deleted - its links are kept")) { dlg.close(); this.refreshTreeAll(); }
          } }),
          h("button", { type: "button", class: "btn danger", text: "Delete the folder and its links", onclick: async () => {
            const r = await guarded(() => api("DELETE", `/resources/folders/${f.id}?with_links=true`));
            if (r) { toast(`Deleted ${r.folders} folder(s) and ${r.links_deleted} link(s) (links also in other folders were kept)`); dlg.close(); this.refreshTreeAll(); }
          } }))));
    },
    showFolderList(f) { this.folderFilter = f.id; this.set({ view: "list", category_id: "" }); },
    /** 📍 Jump to one link in a view: "tree" (its folder opened), "map" (its folder as the centre), "mind" (its folder
        selected, the link first in the panel) or "cat" (its category's list). It is scrolled to and highlighted. */
    async locate(r, where, inFolder = null) {
      await this.loadTree();
      const t = this.tree;
      const topName = (id) => { let f = t.folder.get(id); while (f && f.parent_id) f = t.folder.get(f.parent_id); return f ? f.name : ""; };
      const fids = (r.folders || []).filter((id) => t.folder.has(id));
      const fid = inFolder && t.folder.has(inFolder) ? inFolder : (fids.find((id) => topName(id) !== "Learn & Practice") ?? fids[0]);
      const clear = { q: "", kind: "", training: false, status: "", favourite: false, category_id: "" };
      this.folderFilter = null;
      document.querySelectorAll("details.res-locate[open], .res-tree details[open]").forEach((d) => d.removeAttribute("open"));
      if (where === "cat") {
        const cid = (r.categories || [])[0];
        if (!cid) { toast("This link isn't in a category yet", true); return; }
        Object.assign(this.filters, clear, { view: "list", category_id: String(cid) });
      } else {
        if (fid === undefined) { toast("This link isn't in a folder yet", true); return; }
        if (where === "tree") {
          const open = this.openState();
          for (let f = t.folder.get(fid); f; f = f.parent_id ? t.folder.get(f.parent_id) : null) open.add(f.id);
          this.saveOpen(open);
        }
        if (where === "map") { this.mapFocus = fid; this.mapLocate = r.id; }
        if (where === "mind") { this.mindFocus = t.folder.get(fid).parent_id || 0; this.mindSel = fid; this.mindLocate = r.id; this.mindView = null; }
        Object.assign(this.filters, clear, { view: where });
      }
      this.save();
      this.renderShell();
      await this.reload();
      if (where === "cat") {
        for (let i = 0; i < 30 && !$(`#resBody [data-rid="${r.id}"]`) && this.items.length < this.total; i++) await this.loadMore();
      }
      await new Promise((res) => requestAnimationFrame(() => requestAnimationFrame(res)));
      const el = document.querySelector(`#resBody [data-rid="${r.id}"]`);
      if (!el) { toast("Opened - the link is in this view", false); return; }
      el.classList.add("res-located");
      el.scrollIntoView({ block: "center", behavior: "smooth" });
      setTimeout(() => el.classList.remove("res-located"), 4500);
    },
    /** The folder a link is in now (a topic folder before its Learn & Practice copy), as a path - "" if unknown. */
    whereIs(r) {
      const t = this.tree;
      if (!t) return "";
      const fids = (r.folders || []).filter((id) => t.folder.has(id));
      if (!fids.length) return "";
      const top = (id) => { let f = t.folder.get(id); while (f && f.parent_id) f = t.folder.get(f.parent_id); return f ? f.name : ""; };
      const fid = fids.find((id) => top(id) !== "Learn & Practice") ?? fids[0];
      return this.folderPath(fid).replace(/ \/ /g, " › ") + (fids.length > 1 ? ` (+${fids.length - 1})` : "");
    },
    async refreshTreeAll() { this.tree = null; this.relations = null; await this.refreshAll(); },
    /** Put links in a folder: "move" takes them out of ``fromId``, "add" keeps them where they are too. */
    async fileLinks(ids, action, fromId) {
      await this.loadTree();
      const sel = this.folderSelect("Folder");
      const err = h("p", { class: "error small" });
      this.dialog("Choose a folder", (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try {
          await api("POST", `/resources/folders/${sel.value}/items`, { resource_ids: ids, action: action === "move" && fromId ? "move" : "add", ...(action === "move" && fromId ? { from_folder_id: fromId } : {}) });
          dlg.close(); this.tree = null; this.reload();
        } catch (ex) { err.textContent = ex.message; }
      } }, h("h3", { text: action === "move" && fromId ? "⇢ Move to folder" : "＋ Put in folder" }), sel, err,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: action === "move" && fromId ? "Move" : "Add" }))));
    },

    renderCategories(body) {
      const m = this.meta;
      $("#resCount").textContent = `${m.total.toLocaleString()} link(s) in ${m.categories.length} categories · ${m.training.toLocaleString()} training · ${m.uncategorised.toLocaleString()} not in a category`;
      const tile = (c) => h("button", { type: "button", class: "repo-folder res-cat", style: { "--c": safeColor(c.color) }, title: `Open ${c.name}`,
        onclick: () => this.set({ category_id: String(c.id), view: "list" }) },
        h("div", { class: "repo-folder-head" }, h("span", { class: "repo-folder-emoji", text: c.emoji }), h("strong", { text: c.name })),
        h("span", { class: "muted small", text: `${c.count.toLocaleString()} link(s)` }));
      const cats = m.categories.filter((c) => c.count > 0);
      const empty = m.categories.filter((c) => c.count === 0);
      fill(body, h("div", { class: "repo-folders" },
        cats.map(tile),
        m.uncategorised ? h("button", { type: "button", class: "repo-folder res-cat", style: { "--c": "#6b7280" }, onclick: () => this.set({ category_id: "0", view: "list" }) },
          h("div", { class: "repo-folder-head" }, h("span", { class: "repo-folder-emoji", text: "🗂️" }), h("strong", { text: "Not in a category" })),
          h("span", { class: "muted small", text: `${m.uncategorised.toLocaleString()} link(s)` })) : null,
        empty.length ? h("p", { class: "muted small res-empty-cats", text: `Empty categories: ${empty.map((c) => `${c.emoji} ${c.name}`).join(", ")}` }) : null));
    },

    row(r) {
      const cats = new Map(this.meta.categories.map((c) => [c.id, c]));
      const mine = (r.categories || []).map((id) => cats.get(id)).filter(Boolean);
      const first = mine[0];
      const star = h("button", { type: "button", class: `icon-btn repo-star${r.favourite ? " on" : ""}`, text: r.favourite ? "★" : "☆",
        "aria-label": r.favourite ? `Remove ${r.title} from favourites` : `Add ${r.title} to favourites`, "aria-pressed": String(r.favourite),
        onclick: async () => {
          const res = await guarded(() => api("PATCH", `/resources/${r.id}`, { favourite: !r.favourite }));
          if (res) { r.favourite = res.favourite; star.textContent = r.favourite ? "★" : "☆"; star.classList.toggle("on", r.favourite); this.loadMeta().then(() => this.renderShellKeep()); }
        } });
      const status = h("select", { "aria-label": `Status of ${r.title}`, class: "small", onchange: async (e) => {
        const res = await guarded(() => api("PATCH", `/resources/${r.id}`, { status: e.target.value }));
        if (res) r.status = res.status;
      } }, [["", "—"], ["todo", "📌 To do"], ["doing", "▶ In progress"], ["done", "✅ Done"]].map(([v, l]) => h("option", { value: v, text: l, selected: (r.status || "") === v })));
      const tick = this.selecting ? h("input", { type: "checkbox", class: "repo-check", checked: this.selected.has(r.id), "aria-label": `Select ${r.title}`,
        onchange: (e) => { if (e.target.checked) this.selected.add(r.id); else this.selected.delete(r.id); e.target.closest(".res-row").classList.toggle("picked", e.target.checked); this.renderSelBar(); } }) : null;
      const locate = h("details", { class: "repo-folder-menu res-locate" },
        h("summary", { class: "icon-btn", text: "📍", title: "Show this link in its folder, the map, the mind map or its category",
          "aria-label": `Show ${r.title} in folders, map, mind map or category` }),
        h("div", { class: "repo-folder-menu-list", role: "menu" },
          h("button", { type: "button", class: "btn small", text: "🌳 In its folder", disabled: !(r.folders || []).length, onclick: () => this.locate(r, "tree") }),
          h("button", { type: "button", class: "btn small", text: "🗺 On the map", disabled: !(r.folders || []).length, onclick: () => this.locate(r, "map") }),
          h("button", { type: "button", class: "btn small", text: "🧠 In the mind map", disabled: !(r.folders || []).length, onclick: () => this.locate(r, "mind") }),
          h("button", { type: "button", class: "btn small", text: "🗂 In its category", disabled: !(r.categories || []).length, onclick: () => this.locate(r, "cat") })));
      return h("li", { class: `res-row${this.selecting && this.selected.has(r.id) ? " picked" : ""}`, "data-rid": String(r.id) }, tick,
        h("span", { class: "repo-avatar repo-avatar-none res-badge", style: first ? { background: `color-mix(in srgb, ${safeColor(first.color)} 25%, transparent)` } : null, text: first ? first.emoji : "🔗" }),
        h("div", { class: "res-main" },
          this.link(r),
          h("div", { class: "res-meta muted small" },
            h("span", { text: r.host }), h("span", { class: "repo-badge", text: this.kindLabel(r.kind) }),
            this.whereIs(r) ? h("span", { title: "Folder", text: `📁 ${this.whereIs(r)}` }) : r.trail ? h("span", { title: "Bookmark folder", text: `📁 ${r.trail}` }) : null,
            r.last_opened ? h("span", { text: `opened ${relTime(r.last_opened)}` }) : null),
          mine.length ? h("div", { class: "repo-fchips" }, mine.map((c) => h("button", { type: "button", class: "repo-fchip", style: { "--c": safeColor(c.color) },
            text: `${c.emoji} ${c.name}`, onclick: () => this.set({ category_id: String(c.id), view: "list" }) }))) : null,
          r.summary ? h("p", { class: "res-summary small", text: r.summary }) : null,
          r.notes ? h("p", { class: "res-notes small", text: r.notes }) : null),
        h("span", { class: "res-actions" }, locate, star, status,
          h("button", { type: "button", class: "icon-btn", text: "✎", title: "Edit", "aria-label": `Edit ${r.title}`, onclick: () => this.openEdit(r) }),
          h("button", { type: "button", class: "icon-btn", text: "🗑", title: "Delete", "aria-label": `Delete ${r.title}`, onclick: async () => {
            if (!window.confirm(`Delete “${r.title}”?`)) return;
            if (await guarded(() => api("DELETE", `/resources/${r.id}`), "Deleted")) this.refreshAll();
          } })));
    },
    /** The list is showing (not the category tiles) - selecting only makes sense there. */
    listing() {
      const f = this.filters;
      if (f.view === "categories" && f.category_id === "" && !f.q) return false;
      if (["launch", "tree", "map", "mind", "repos"].includes(f.view) && f.category_id === "" && !f.q && !f.kind && !f.training && !f.status && !f.favourite) return false;
      return true;
    },

    /** ☑ Select: the bar under the filters - change the ticked links all at once. */
    renderSelBar() {
      const bar = $("#resSelBar");
      if (!bar) return;
      const n = this.selected.size;
      const cat = h("select", { "aria-label": "Category" }, this.meta.categories.map((c) => h("option", { value: String(c.id), text: `${c.emoji} ${c.name}`,
        selected: String(c.id) === String(this.filters.category_id) })));
      const run = async (action, needsCategory = false) => {
        if (!n) { toast("Tick some links first", true); return; }
        if (action === "delete" && !window.confirm(`Delete ${n} link(s)? This can't be undone.`)) return;
        const body = { ids: [...this.selected], action, ...(needsCategory ? { category_id: Number(cat.value) } : {}) };
        const res = await guarded(() => api("POST", "/resources/bulk", body));
        if (!res) return;
        const label = { add: `Added ${res.changed} to ${cat.selectedOptions[0] ? cat.selectedOptions[0].text : "the category"}`,
          remove: `Took ${res.changed} out of ${cat.selectedOptions[0] ? cat.selectedOptions[0].text : "the category"}`,
          favourite: `★ ${res.changed} favourite(s)`, unfavourite: `Removed ${res.changed} from favourites`, delete: `Deleted ${res.changed} link(s)` }[action];
        toast(label);
        this.selected.clear();
        await this.refreshAll();
      };
      fill(bar,
        h("strong", { text: `${n} selected` }),
        h("button", { type: "button", class: "btn small", text: "Tick all shown", onclick: () => { this.items.forEach((r) => this.selected.add(r.id)); this.reload(); } }),
        n ? h("button", { type: "button", class: "btn small", text: "Untick all", onclick: () => { this.selected.clear(); this.reload(); } }) : null,
        this.meta.categories.length ? cat : null,
        h("button", { type: "button", class: "btn small primary", text: "＋ Add to category", disabled: !this.meta.categories.length, onclick: () => run("add", true) }),
        h("button", { type: "button", class: "btn small", text: "− Remove from category", disabled: !this.meta.categories.length, onclick: () => run("remove", true) }),
        h("button", { type: "button", class: "btn small", text: "★ Favourite", onclick: () => run("favourite") }),
        h("button", { type: "button", class: "btn small", text: "☆ Unfavourite", onclick: () => run("unfavourite") }),
        h("button", { type: "button", class: "btn small danger", text: "🗑 Delete", onclick: () => run("delete") }));
    },

    renderShellKeep() { /* the quick bar shows favourites: redraw the header without losing the list */
      const keep = $("#resBody");
      const count = $("#resCount") ? $("#resCount").textContent : "";
      this.renderShell();
      if (keep && $("#resBody")) { $("#resBody").replaceWith(keep); $("#resCount").textContent = count; }
    },

    dialog(label, build) {
      const dlg = h("dialog", { class: "range-dialog res-dialog", "aria-label": label });
      fill(dlg, build(dlg));
      dlg.addEventListener("close", () => dlg.remove());
      document.body.append(dlg);
      dlg.showModal();
      return dlg;
    },
    catSelect(withNone = true) {
      return h("select", { "aria-label": "Category" }, withNone ? h("option", { value: "", text: "Sort automatically" }) : null,
        this.meta.categories.map((c) => h("option", { value: String(c.id), text: `${c.emoji} ${c.name}` })));
    },

    openEdit(r) {
      const title = h("input", { type: "text", maxlength: 300, value: r.title, "aria-label": "Title" });
      const kind = h("select", { "aria-label": "Type" }, Object.entries(this.meta.kind_labels).map(([k, l]) => h("option", { value: k, text: l, selected: r.kind === k })));
      const summary = h("textarea", { rows: 2, maxlength: 600, "aria-label": "What it's for", placeholder: "What it's for and what you get out of it" });
      summary.value = r.summary || "";
      const notes = h("textarea", { rows: 3, maxlength: 4000, "aria-label": "Notes", placeholder: "Your notes (where you got to, logins to remember…)" });
      notes.value = r.notes || "";
      const ticks = this.meta.categories.map((c) => ({ c, box: h("input", { type: "checkbox", checked: (r.categories || []).includes(c.id) }) }));
      const err = h("p", { class: "error small" });
      this.dialog(`Edit ${r.title}`, (dlg) => h("form", { class: "form", onsubmit: async (e) => {
        e.preventDefault();
        try {
          await api("PATCH", `/resources/${r.id}`, { title: title.value.trim() || r.title, kind: kind.value, summary: summary.value.trim(), notes: notes.value,
            category_ids: ticks.filter((t) => t.box.checked).map((t) => t.c.id) });
          dlg.close();
          this.refreshAll();
        } catch (ex) { err.textContent = ex.message; }
      } },
        h("h3", { text: "✎ Edit link" }),
        h("label", null, "Title ", title), h("label", null, "Type ", kind),
        h("label", null, "What it's for ", summary), h("label", null, "Your notes ", notes),
        h("p", { class: "small", text: "Categories (your choice is kept - automatic sorting won't change it):" }),
        h("ul", { class: "repo-folder-ticks res-cat-ticks" }, ticks.map((t) => h("li", null, h("label", null, t.box, ` ${t.c.emoji} ${t.c.name}`)))),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
    },

    async openAdd(folderId = null) {
      await this.loadTree().catch(() => {});
      const box = h("textarea", { rows: 7, maxlength: 200000, "aria-label": "Links, one per line",
        placeholder: "One per line:\nhttps://www.hackthebox.com\nTryHackMe | https://tryhackme.com\n[GTFOBins](https://gtfobins.github.io)" });
      const cat = this.catSelect();
      const where = this.tree ? this.folderSelect("Put them in") : h("select", { "aria-label": "Put them in" });
      where.prepend(h("option", { value: "", text: "✨ Sort into topics automatically" }));
      where.value = folderId ? String(folderId) : "";
      const read = h("input", { type: "checkbox", checked: store.get("fw-res-readpages", true) !== false,
        onchange: (e) => store.set("fw-res-readpages", e.target.checked) });
      const log = h("ol", { class: "batch-list small" });
      const err = h("p", { class: "error small" });
      this.dialog("Add links", (dlg) => h("form", { class: "form source-wizard", onsubmit: async (e) => {
        e.preventDefault();
        const lines = box.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        if (!lines.length) { err.textContent = "Paste at least one link."; return; }
        if (lines.length > 500) { err.textContent = "Up to 500 lines at a time, please."; return; }
        err.textContent = "";
        try {
          if (read.checked && lines.length) err.textContent = "Reading the pages…";
          const r = await api("POST", "/resources/batch", { lines, read_pages: read.checked, auto_file: !where.value,
            ...(where.value ? { folder_id: Number(where.value) } : {}), ...(cat.value ? { category_id: Number(cat.value) } : {}) });
          err.textContent = "";
          fill(log, r.results.map((x) => h("li", { class: x.status === "added" ? "status-ok" : x.status === "duplicate" ? "muted" : "status-err",
            text: `${x.status === "added" ? `✓ ${x.title} · ${this.kindLabel(x.kind)}${(x.folders || []).length ? ` → 📁 ${x.folders.join(" + ")}` : " → not filed yet"}`
              : x.status === "duplicate" ? (where.value ? "Already here - also put in this folder" : "Already here") : x.detail} — ${x.line}` })));
          box.value = "";
          toast(`Added ${r.added} link(s)${r.duplicates ? `, ${r.duplicates} already here` : ""}${r.pages_read ? ` · read ${r.pages_read} page(s)` : ""}`);
          this.tree = null;
          this.refreshAll();
        } catch (ex) { err.textContent = ex.message; }
      } },
        h("div", { class: "sd-head" }, h("h3", { text: "＋ Add links" }), h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        box,
        h("label", { class: "res-add-where" }, "Put them in ", where),
        h("label", { class: "repo-tick" }, read, " 📖 Read each page to name, describe and sort it (contacts those websites; up to 20 links)"),
        h("label", { class: "repo-tick" }, "Category ", cat),
        h("p", { class: "muted small", text: "✨ Automatic: each link goes into the topics that fit it - next to other links from the same site, by its title and the page's own description, its category and its type (training also goes under Learn & Practice). It then shows in the tree, map and mind map. You can move it any time." }),
        log, err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "＋ Add" }))));
      box.focus();
    },

    /** ⇪ Import: 1. choose the bookmark file, 2. tick the folders to bring in (leave out personal, shopping…), 3. import. */
    openImport() {
      const file = h("input", { type: "file", accept: ".html,.htm,.txt,text/html,text/plain", "aria-label": "Bookmark file" });
      const cat = this.catSelect();
      const step = h("div", { class: "small" });
      const out = h("div", { class: "small", "aria-live": "polite" });
      const err = h("p", { class: "error small" });
      let html = null;
      let boxes = [];
      const go = h("button", { type: "submit", class: "btn primary", text: "Next: choose folders ›" });
      const keepFolders = h("input", { type: "checkbox", checked: true });
      const readFile = async () => {
        const f = file.files && file.files[0];
        if (!f) { err.textContent = "Choose your bookmark file first."; return null; }
        if (f.size > 5 * 1024 * 1024) { err.textContent = "That file is too big (5 MB at most)."; return null; }
        return f.text();
      };
      const showFolders = (pv) => {
        boxes = pv.folders.map((fo) => ({ fo, box: h("input", { type: "checkbox", checked: true }) }));
        // ticking or unticking a folder does the same to everything inside it
        // unticking a folder unticks everything inside it; ticking one ticks the folders it sits in
        boxes.forEach(({ fo, box }) => box.addEventListener("change", () => {
          if (box.checked) boxes.filter((b) => fo.path.startsWith(b.fo.path + " / ")).forEach((b) => { b.box.checked = true; });
          else boxes.filter((b) => b.fo.path.startsWith(fo.path + " / ")).forEach((b) => { b.box.checked = false; });
          count();
        }));
        const total = h("strong");
        const inFolders = pv.folders.filter((fo) => fo.depth === 0).reduce((n, fo) => n + fo.count, 0);
        const count = () => {
          const off = boxes.filter((b) => !b.box.checked).map((b) => b.fo);
          const top = off.filter((fo) => !off.some((o) => fo.path.startsWith(o.path + " / ")));   // an unticked folder covers its children
          const kept = pv.no_folder + inFolders - top.reduce((n, fo) => n + fo.count, 0);
          total.textContent = `${kept.toLocaleString()} of ${pv.found.toLocaleString()} link(s) will be imported`;
        };
        fill(step,
          h("p", null, `Found ${pv.found.toLocaleString()} link(s) in ${pv.folders.length} folder(s). Untick what you don't want (personal, shopping, work…) - only the ticked folders are imported.`),
          h("div", { class: "res-cat-row" },
            h("button", { type: "button", class: "btn small", text: "Tick all", onclick: () => { boxes.forEach((b) => { b.box.checked = true; }); count(); } }),
            h("button", { type: "button", class: "btn small", text: "Untick all", onclick: () => { boxes.forEach((b) => { b.box.checked = false; }); count(); } }), total),
          h("ul", { class: "res-cat-list res-import-folders" }, boxes.map(({ fo, box }) => h("li", { style: { "padding-left": `${fo.depth * 18}px` } },
            h("label", null, box, ` 📁 ${fo.name} `, h("span", { class: "muted", text: `(${fo.count.toLocaleString()})` }))))),
          pv.no_folder ? h("p", { class: "muted", text: `${pv.no_folder} link(s) aren't in any folder - they're always imported (delete them afterwards if you like).` }) : null);
        count();
        go.textContent = "⇪ Import ticked folders";
      };
      this.dialog("Import bookmarks", (dlg) => h("form", { class: "form source-wizard", onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = "";
        try {
          if (html === null) {                                   // step 1 → 2: list the folders (nothing saved yet)
            const text = await readFile();
            if (text === null) return;
            fill(out, h("p", { class: "muted", text: "Reading the folders…" }));
            const pv = await api("POST", "/resources/import", { html: text, preview: true });
            html = text;
            file.disabled = true;
            fill(out);
            showFolders(pv);
            return;
          }
          const skip = boxes.filter((b) => !b.box.checked).map((b) => b.fo.path)
            .filter((path, _, all) => !all.some((o) => o !== path && path.startsWith(o + " / ")));   // a skipped parent covers its children
          go.disabled = true;
          fill(out, h("p", { class: "muted", text: "Importing and sorting…" }));
          const r = await api("POST", "/resources/import", { html, skip_folders: skip, make_folders: keepFolders.checked, ...(cat.value ? { category_id: Number(cat.value) } : {}) });
          fill(step);
          this.tree = null;
          fill(out, h("p", { class: "status-ok", text: `✓ ${r.added.toLocaleString()} link(s) added${r.folders_made ? ` in ${r.folders_made.toLocaleString()} folder(s)` : ""}, ${(r.duplicates || 0).toLocaleString()} already here, ${(r.left_out || 0).toLocaleString()} left out with their folders, ${(r.invalid || 0).toLocaleString()} without a web link.` }),
            h("p", { class: "muted", text: "Have a look through the categories - anything you move by hand stays where you put it." }));
          go.hidden = true;
          this.refreshAll();
        } catch (ex) { fill(out); err.textContent = ex.message; go.disabled = false; }
      } },
        h("div", { class: "sd-head" }, h("h3", { text: "⇪ Import bookmarks" }), h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        h("ol", { class: "small src-notes" },
          h("li", { text: "Chrome / Edge / Brave: open the Bookmarks manager (Ctrl+Shift+O) → ⋮ (top right) → Export bookmarks → save the .html file." }),
          h("li", { text: "Firefox: Bookmarks → Manage bookmarks (Ctrl+Shift+O) → Import and Backup → Export Bookmarks to HTML." }),
          h("li", { text: "Choose that file, then tick only the folders you want here. Your folder names help the sorting; links you already have are skipped." })),
        file,
        h("label", { class: "repo-tick", title: "Your bookmark folders and subfolders are made here too, and each link goes into its folder (a link bookmarked in two folders goes into both)" },
          keepFolders, " Keep my folders and subfolders"),
        h("label", { class: "repo-tick" }, "Also put them all in category ", cat),
        h("p", { class: "muted small", text: "The file goes only to this app - nothing is sent anywhere else, and no page is visited." }),
        step, out, err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }), go)));
    },

    /** ⚙ Categories: rename, emoji, colour, move, delete (links stay), add your own. */
    async openCategories() {
      await this.loadMeta();
      const draw = (dlg) => {
        const list = this.meta.categories;
        const rows = list.map((c, i) => {
          const name = h("input", { type: "text", maxlength: 60, value: c.name, "aria-label": "Category name" });
          const emoji = h("input", { type: "text", maxlength: 8, value: c.emoji, class: "repo-emoji-input", "aria-label": "Emoji" });
          const color = h("input", { type: "color", value: safeColor(c.color), "aria-label": "Colour" });
          const saveRow = async () => {
            if (await guarded(() => api("PATCH", `/resources/categories/${c.id}`, { name: name.value.trim() || c.name, emoji: emoji.value.trim() || c.emoji, color: color.value }), "Saved")) {
              await this.loadMeta();
            }
          };
          const move = async (d) => {
            const ids = list.map((x) => x.id);
            const j = i + d;
            if (j < 0 || j >= ids.length) return;
            [ids[i], ids[j]] = [ids[j], ids[i]];
            if (await guarded(() => api("POST", "/resources/categories/reorder", { ids }))) { await this.loadMeta(); fill(dlg, draw(dlg)); }
          };
          return h("li", { class: "res-cat-row" }, emoji, name, color,
            h("span", { class: "muted small", text: `${c.count}` }),
            h("button", { type: "button", class: "btn small", text: "Save", onclick: saveRow }),
            h("button", { type: "button", class: "btn small", text: "↑", disabled: i === 0, "aria-label": `Move ${c.name} up`, onclick: () => move(-1) }),
            h("button", { type: "button", class: "btn small", text: "↓", disabled: i === list.length - 1, "aria-label": `Move ${c.name} down`, onclick: () => move(1) }),
            h("button", { type: "button", class: "btn small danger", text: "🗑", "aria-label": `Delete ${c.name}`, onclick: async () => {
              if (!window.confirm(`Delete the category “${c.name}”? Its ${c.count} link(s) stay (in their other categories, or not in a category).`)) return;
              if (await guarded(() => api("DELETE", `/resources/categories/${c.id}`), "Category deleted")) { await this.loadMeta(); fill(dlg, draw(dlg)); }
            } }));
        });
        const newName = h("input", { type: "text", maxlength: 60, placeholder: "New category, e.g. Exam prep", "aria-label": "New category name" });
        return h("div", { class: "form" },
          h("div", { class: "sd-head" }, h("h3", { text: "⚙ Categories" }), h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
          h("ul", { class: "res-cat-list" }, rows),
          h("div", { class: "res-cat-row" }, newName, h("button", { type: "button", class: "btn small primary", text: "＋ Add category", onclick: async () => {
            if (!newName.value.trim()) return;
            if (await guarded(() => api("POST", "/resources/categories", { name: newName.value.trim() }), "Category added")) { await this.loadMeta(); fill(dlg, draw(dlg)); }
          } })));
      };
      const dlg = this.dialog("Categories", (d) => draw(d));
      dlg.addEventListener("close", () => this.refreshAll());
    },
  };

  FW.resources = view;

  // ⌘/Ctrl+K from any tab opens the launcher.
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      view.openLauncher().catch(() => {});
    }
  });

  // http://<app>/#launchpad opens straight on the ★ Launchpad (for the browser's home page). The app restores its last tab
  // while it starts, so keep the Resources tab in front for a few seconds - unless you click another tab yourself.
  const openLaunchpadFromHash = () => {
    if (location.hash !== "#launchpad") return;
    Object.assign(view.filters, { view: "launch", q: "", kind: "", training: false, status: "", favourite: false, category_id: "" });
    view.save();
    let userTook = false;
    const bar = document.querySelector(".mode-switch");
    if (bar) bar.addEventListener("click", (e) => { if (e.isTrusted) userTook = true; }, { capture: true });
    const until = Date.now() + 8000;
    const tick = () => {
      if (userTook || Date.now() > until) return;
      const rv = document.getElementById("resourcesView");
      if (rv && rv.hidden) document.getElementById("modeResources")?.click();
      else if (rv && view.meta && view.filters.view === "launch" && !document.querySelector("#resBody .res-pad-wrap")) view.set({ view: "launch" });
      setTimeout(tick, 250);
    };
    tick();
  };
  window.addEventListener("hashchange", openLaunchpadFromHash);
  openLaunchpadFromHash();

  // 📦 Repos lives in Resources: hide its top tab, and whenever the app switches to Repos (restoring it as the last tab -
  // however late that lands on a slow phone - or code calling setMode("repos")), show Resources › 📦 Repos instead.
  // Hooked to the moment the mode is applied (#app's class), not to a timer.
  view.applyReposTab();
  const appEl = document.getElementById("app");
  const toReposView = () => {
    if (!view.reposCombined() || !appEl || !appEl.classList.contains("mode-repos")) return;
    if (document.querySelector("#resourcesView #reposView")) return;
    Object.assign(view.filters, { view: "repos", q: "", kind: "", training: false, status: "", favourite: false, category_id: "" });
    view.save();
    document.getElementById("modeResources")?.click();
  };
  if (appEl) new MutationObserver(toReposView).observe(appEl, { attributes: true, attributeFilter: ["class"] });
  toReposView();
})();
