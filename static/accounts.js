/* 👥 Socials tab (internally "accounts"): posts from followed social accounts and communities (X, Telegram, Bluesky, Mastodon, Reddit users
 * and subreddits, bridged LinkedIn / Instagram ...), split into categories by topic like the Videos tab.
 * Same rules as app.js: DOM built with h()/textContent only, links via safeUrl, no inline script/style. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, safeColor, relTime, fullDate, store } = FW;
  const $ = (sel) => document.querySelector(sel);
  const DEFAULTS = { feed_ids: [], platforms: [], topic_id: "", topic_ids: [], topic_match: "any", q: "", state: "all", sort: "newest", view: "topics" };
  const BRIDGE_PLATFORMS = [["linkedin", "LinkedIn"], ["instagram", "Instagram"], ["facebook", "Facebook"], ["threads", "Threads"],
    ["tiktok", "TikTok"], ["x", "X"], ["mastodon", "Mastodon"], ["other", "Other"]];
  const KEEP_CHOICES = [["", "Default (global setting)"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["180", "Last 6 months"],
    ["365", "Last year"], ["730", "Last 2 years"], ["1825", "Last 5 years"], ["0", "Everything (keep forever)"]];
  const REFRESH_CHOICES = [["", "Don't change"], ["default", "Default"], ["15", "Every 15 minutes"], ["30", "Every 30 minutes"],
    ["60", "Every hour"], ["180", "Every 3 hours"], ["360", "Every 6 hours"], ["1440", "Once a day"]];
  const keepText = (d) => (FW.fmtRetention ? FW.fmtRetention(d, true) : `${d} days`);

  /** Saved filters from before several accounts / platforms could be picked: one account → a list of one. */
  function loadFilters() {
    const f = { ...DEFAULTS, ...(store.get("fw-accounts-filters") || {}) };
    if (!Array.isArray(f.feed_ids)) f.feed_ids = [];
    if (!Array.isArray(f.platforms)) f.platforms = [];
    if (f.feed_id) f.feed_ids = [String(f.feed_id)];
    if (f.platform) f.platforms = [String(f.platform)];
    delete f.feed_id; delete f.platform;
    if (f.topic_id !== "" && f.topic_id != null && !(f.topic_ids || []).length) f.topic_ids = [String(f.topic_id)];  // saved by a topic chip
    f.topic_id = "";
    f.topic_match = "any";
    f.dates = FW.dateRange.clean(f.dates);  // 📅 custom from / to range
    return f;
  }

  const view = {
    meta: null,
    topics: [],
    filters: loadFilters(),
    offset: 0,

    async show() {
      const el = $("#accountsView");
      if (this.meta && el.childElementCount > 1) { await this.reload(); return; }  // coming back: refresh in place
      if (!this.meta) fill(el, h("p", { class: "muted lib-pad", text: "Loading accounts…" }));
      await this.loadMeta();
      this.renderShell();
      await this.reload();
    },
    hide() { /* nothing to tear down */ },
    save() { store.set("fw-accounts-filters", this.filters); },

    async loadMeta() {
      const [meta, lib] = await Promise.all([api("GET", "/accounts/meta").catch(() => null), api("GET", "/library/meta").catch(() => null)]);
      this.meta = meta || { accounts: [], platforms: [], labels: {}, icons: {} };
      this.topics = (lib && lib.topics) || [];
      const known = new Set(this.meta.accounts.map((a) => String(a.feed_id)));
      this.filters.feed_ids = this.filters.feed_ids.filter((id) => known.has(String(id)));  // removed accounts drop out
    },
    async refreshAll() { await this.loadMeta(); this.renderShell(); await this.reload(); },

    icon(p) { return (this.meta.icons || {})[p] || "◎"; },
    label(p) { return (this.meta.labels || {})[p] || p; },
    accountsOf(platform) { return this.meta.accounts.filter((a) => a.platform === platform); },

    renderShell() {
      const el = $("#accountsView");
      const f = this.filters;
      const m = this.meta;
      const set = (key) => (e) => { f[key] = e.target.value; this.save(); this.renderShell(); this.reload(); };
      const select = (key, label, options) => h("select", { "aria-label": label, onchange: set(key) },
        options.map(([v, l]) => h("option", { value: v, text: l, selected: String(f[key]) === String(v) })));
      const search = h("input", { type: "search", placeholder: "Search posts & accounts…", maxlength: 200, value: f.q, "aria-label": "Search posts" });
      let timer = null;
      search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); this.save(); this.reload(); }, 300); });
      const viewBtn = (v, label) => h("button", { type: "button", class: `btn small${f.view === v ? " primary" : ""}`, "aria-pressed": String(f.view === v), text: label,
        onclick: () => { f.view = v; if (v === "topics") { f.topic_id = ""; f.topic_ids = []; } this.save(); this.renderShell(); this.reload(); } });
      const picker = FW.sources && FW.sources.multiPicker;
      const byId = (id) => m.accounts.find((a) => String(a.feed_id) === String(id));
      // Platforms ▾: ⚙ per platform → settings for all its accounts / remove the platform
      const platforms = picker ? picker({
        items: m.platforms.map((p) => ({ id: p.id, name: `${p.icon} ${p.label}`, count: p.accounts })),
        selected: f.platforms, noun: "platform", allLabel: `All platforms (${m.platforms.length})`,
        itemMenu: (item) => {
          const list = this.accountsOf(item.id);
          const name = this.label(item.id);
          return [[`⚙ Settings for its ${list.length} account${list.length === 1 ? "" : "s"}…`, () => this.openGroupSettings(list, name)],
            [`🗑️ Remove ${name} (${list.length} account${list.length === 1 ? "" : "s"})`, () => this.removeAccounts(list, name), true]];
        },
        onChange: (ids) => { f.platforms = ids; this.save(); this.reload(); } }) : null;
      // Accounts ▾: ⚙ per account → its full settings (like a feed in Articles) / remove; tick several → together
      const accounts = picker ? picker({
        items: m.accounts.map((a) => ({ id: String(a.feed_id), name: `${this.icon(a.platform)} ${a.title}`, count: a.posts,
          hint: `${this.label(a.platform)} · keeps ${keepText(a.keeps)}${a.error_count ? ` · ⚠ ${a.last_error || "failing"}` : ""}` })),
        selected: f.feed_ids, noun: "account", allLabel: `All accounts (${m.accounts.length})`, search: true,
        onAdd: () => this.openAdd(), addTitle: "Add accounts, subreddits or posts",
        itemMenu: (item) => {
          const a = byId(item.id);
          return [[`⚙ Settings… (keeps ${keepText(a.keeps)})`, () => this.openSettings(a)], ["🗑️ Remove", () => this.removeAccounts([a], a.title), true]];
        },
        bulkActions: (ids) => {
          const list = ids.map(byId).filter(Boolean);
          return list.length >= 2 ? [["⚙ Settings for these…", () => this.openGroupSettings(list, `${list.length} accounts`)],
            ["🗑️ Remove these", () => this.removeAccounts(list, `${list.length} accounts`), true]] : [];
        },
        onChange: (ids) => { f.feed_ids = ids; this.save(); this.reload(); } }) : null;
      const failing = f.feed_ids.map(byId).filter((a) => a && a.error_count);
      // 🏷️ Tags: only this button and the cards' tag rows change - nothing is reloaded and the page doesn't jump
      let tagsEl = null;
      const tagsBtn = () => (tagsEl = FW.tagsToggle("accounts", () => { tagsEl.replaceWith(tagsBtn()); this.redrawTags(); }));
      fill(el,
        h("div", { class: "studio-header lib-header" },
          h("h2", { text: "👥 Socials" }),
          h("button", { type: "button", class: "btn small primary lib-add-plus", text: "＋", title: "Add accounts, subreddits or single posts",
            "aria-label": "Add accounts, subreddits or single posts", onclick: () => this.openAdd() }),
          search, platforms, accounts,
          FW.sources && FW.sources.topicPicker ? FW.sources.topicPicker({
            topics: [...this.topics.filter((t) => t.enabled), { id: 0, name: "Other (no topic)", color: "#6b7280" }],
            selected: f.topic_ids || [],
            onChange: (ids) => { f.topic_ids = ids; f.topic_match = "any"; f.topic_id = ""; if (ids.length) f.view = "grid"; this.save(); this.reload(); } }) : null,
          select("state", "Show", [["all", "All posts"], ["unread", "Unread"], ["starred", "★ Starred"]]),
          select("sort", "Sort", [["newest", "📅 Date — newest"], ["oldest", "📅 Date — oldest"]]),
          FW.dateRange.button({ value: f.dates, title: "Show only posts published between two dates",
            onChange: (r) => { f.dates = r; this.save(); this.renderShell(); this.reload(); } }),
          h("span", { class: "lib-view", role: "group", "aria-label": "View" }, viewBtn("topics", "▤ By topic"), viewBtn("grid", "▦ All posts"),
            viewBtn("read", "☰ Read")),
          tagsBtn()),
        failing.length ? h("p", { class: "error small lib-pad", text: failing.map((a) => `⚠ ${a.title}: ${a.last_error || "the feed is failing"}`).join(" · ") + " — open ⚙ Settings next to the account (Accounts ▾)." }) : null,
        h("div", { id: "accCount", class: "muted small lib-pad" }),
        h("div", { id: "accGrid", class: "lib-grid" }),
        h("div", { class: "lib-more" }, h("button", { id: "accMore", type: "button", class: "btn", text: "Load more", hidden: true, onclick: () => this.loadMore() })));
      // the header (search, filters) stays at the top: an opened post's Show less sticks just below it
      const head = el.querySelector(".studio-header");
      if (this.headWatch) this.headWatch.disconnect();
      if (head && "ResizeObserver" in window) {
        this.headWatch = new ResizeObserver(() => el.style.setProperty("--acc-head-h", `${head.offsetHeight}px`));
        this.headWatch.observe(head);
      }
      if (!m.accounts.length) {
        $("#accGrid").replaceWith(h("div", { class: "card lib-empty" },
          h("h3", { text: "No social accounts yet" }),
          h("p", { class: "muted", text: "Click ＋ and paste links, one per line: profiles (X, Bluesky, Mastodon, Telegram, Instagram…), subreddits (reddit.com/r/homelab) or single posts. The app recognises each link. Posts are sorted into topics automatically." })));
      }
    },

    params(extra = {}) {
      const f = this.filters;
      const p = new URLSearchParams();
      if (f.feed_ids.length) p.set("feed_ids", f.feed_ids.join(","));
      if (f.platforms.length) p.set("platforms", f.platforms.join(","));
      if (f.q) p.set("q", f.q);
      FW.dateRange.addParams(p, f.dates);
      p.set("state", f.state);
      for (const [k, v] of Object.entries(extra)) p.set(k, v);
      return p;
    },

    async reload() {
      const grid = $("#accGrid");
      if (!grid) return;
      this.offset = 0;
      const f = this.filters;
      if (f.view === "topics" && f.topic_id === "" && !(f.topic_ids || []).length) {
        const q = this.params({ per: 12 }).toString();
        const data = await api("GET", `/accounts/shelves?${q}`).catch((e) => { toast(e.message, true); return null; });
        if (!data || !grid.isConnected || f.view !== "topics" || this.params({ per: 12 }).toString() !== q) return;  // a newer view / filter won
        grid.className = "lib-grid shelves";
        this.applyWidth();
        $("#accMore").hidden = true;
        $("#accCount").textContent = data.shelves.length ? `${data.shelves.length} categories` : "No posts yet.";
        fill(grid, data.shelves.map((s) => h("section", { class: "lib-shelf" },
          h("div", { class: "lib-shelf-head" }, h("span", { class: "dot", style: { background: safeColor(s.topic.color) } }),
            h("h3", { text: s.topic.name }), h("span", { class: "muted small", text: `${s.total} posts` }), h("span", { class: "spacer" }),
            h("button", { type: "button", class: "btn small", text: "Show all →", onclick: () => { f.topic_ids = [String(s.topic.id)]; f.topic_id = ""; f.view = "grid"; this.save(); this.renderShell(); this.reload(); } })),
          h("div", { class: "lib-shelf-row" }, s.items.map((p) => this.card(p))))));
        return;
      }
      grid.className = f.view === "read" ? "acc-read" : "lib-grid";
      this.applyWidth();
      // placeholders of the same size while the posts load (no empty flash, no jump)
      fill(grid, Array.from({ length: 6 }, () => h("div", { class: "skeleton-card", "aria-hidden": "true" })));
      grid.dataset.skeleton = "1";
      this.loadingMore = false;
      await this.loadMore();
      this.watchScroll();
    },

    /** ☰ Read: load the next posts as you near the end (continuous scroll, like the platform itself). */
    watchScroll() {
      if (this.observer) this.observer.disconnect();
      const more = $("#accMore");
      if (!more || this.filters.view !== "read" || !("IntersectionObserver" in window)) return;
      this.observer = new IntersectionObserver((seen) => {
        if (seen.some((e) => e.isIntersecting) && !more.hidden && !this.loadingMore) this.loadMore();
      }, { rootMargin: "800px 0px" });
      this.observer.observe(more);
    },

    async loadMore() {
      const f = this.filters;
      const reading = f.view === "read";
      if (this.loadingMore) return;
      this.loadingMore = true;
      const extra = { sort: f.sort, limit: reading ? 20 : 40, offset: this.offset };
      if (reading) extra.full = "true";
      if (f.topic_id !== "") extra.topic_id = f.topic_id;
      if ((f.topic_ids || []).length) { extra.topic_ids = f.topic_ids.join(","); extra.topic_match = "any"; }
      const data = await api("GET", `/accounts/posts?${this.params(extra)}`).catch((e) => { toast(e.message, true); return null; });
      this.loadingMore = false;
      const g0 = $("#accGrid");
      if (!data && g0 && g0.dataset.skeleton) { fill(g0); delete g0.dataset.skeleton; }
      if (!data) return;
      const grid = $("#accGrid");
      if (!grid || (f.view === "read") !== reading) return;  // switched view meanwhile
      if (grid.dataset.skeleton) { fill(grid); delete grid.dataset.skeleton; }  // placeholders out, posts in
      grid.append(...data.items.map((p) => (reading ? this.readCard(p) : this.card(p))));
      this.offset += data.items.length;
      this.total = data.total;
      $("#accCount").textContent = `${data.total} post${data.total === 1 ? "" : "s"}`;
      $("#accMore").hidden = this.offset >= data.total;
    },

    /** The posts' width you dragged (one for the card views, one for ☰ Read); 0 = the automatic width. */
    widthKey() { return this.filters.view === "read" ? "fw-accounts-read-width" : "fw-accounts-card-width"; },
    applyWidth() {
      const grid = $("#accGrid");
      if (!grid) return;
      const w = Number(store.get(this.widthKey(), 0)) || 0;
      grid.classList.toggle("acc-sized", w > 0);
      if (w > 0) grid.style.setProperty("--acc-w", `${w}px`); else grid.style.removeProperty("--acc-w");
    },

    /** A handle on the post's right edge: drag to make the posts wider or narrower, double-click for the automatic width. */
    widthHandle(el) {
      const handle = h("div", { class: "acc-resize", title: "Drag to change the width of the posts (double-click: automatic width)",
        "aria-label": "Width of the posts" });
      if (!FW.makeResizer) return null;
      const reading = () => this.filters.view === "read";
      const max = () => Math.max(260, ($("#accountsView") || document.body).clientWidth - 24);
      let base = 0;   // the width when the drag started
      FW.makeResizer(handle, {
        min: 220, step: 40, getMax: max,
        get: () => (base = Math.round(((reading() && $("#accGrid")) || el).getBoundingClientRect().width)),  // ☰ Read: the column
        onChange: (px) => {
          const g = $("#accGrid");
          if (!g) return;
          // the ☰ Read column is centred: it grows on both sides, so twice the move keeps its edge under the pointer
          const w = reading() ? Math.round(Math.max(220, Math.min(max(), base + 2 * (px - base)))) : px;
          g.classList.add("acc-sized");
          g.style.setProperty("--acc-w", `${w}px`);
        },
        onCommit: () => store.set(this.widthKey(), Math.round(((reading() && $("#accGrid")) || el).getBoundingClientRect().width)),
        onReset: () => { store.set(this.widthKey(), 0); this.applyWidth(); },
      });
      return handle;
    },

    /** A post's picture, big, inside the app (not the platform's page). Click it for actual size; Esc, ✕ or the dark
     *  area around it closes it. */
    openPhoto(src) {
      const ok = this.imgSrc(src);
      if (!ok) return;
      let dlg = document.getElementById("accPhoto");
      if (!dlg) {
        dlg = h("dialog", { id: "accPhoto", class: "acc-lightbox", "aria-label": "Picture" });
        dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
        dlg.addEventListener("close", () => { dlg.classList.remove("actual"); fill(dlg); });
        document.body.append(dlg);
      }
      const img = h("img", { src: ok, alt: "", referrerpolicy: "no-referrer", title: "Click for actual size",
        onclick: () => { dlg.classList.toggle("actual"); img.title = dlg.classList.contains("actual") ? "Click to fit the screen" : "Click for actual size"; } });
      fill(dlg, h("button", { type: "button", class: "icon-btn acc-lightbox-close", "aria-label": "Close", title: "Close (Esc)", text: "✕", onclick: () => dlg.close() }), img);
      dlg.classList.remove("actual");
      if (!dlg.open) dlg.showModal();
    },

    /** Pictures inside a saved post's text open in the viewer too. */
    zoomable(root) {
      for (const img of root.querySelectorAll("img")) {
        if (img.closest("a")) continue;   // a picture that is a link keeps its link
        img.classList.add("acc-zoom");
        img.title = "Open the picture";
        img.addEventListener("click", () => this.openPhoto(img.getAttribute("src")));
      }
    },

    /** A picture address the page may load: https from the platform, or our own signed image proxy. */
    imgSrc(u) {
      return safeUrl(u) || (typeof u === "string" && /^\/api\/v1\/img\?u=[^"'<>\s]+&s=[0-9a-f]{32}$/.test(u) ? u : null);
    },

    /** Who wrote it: the profile picture (or their initial), name and handle - for single saved posts. */
    authorHead(p) {
      const name = p.author || p.handle || (p.saved ? `${this.label(p.platform)} post` : p.feed_title) || "";  // not "Saved LinkedIn posts"
      const avatar = this.imgSrc(p.avatar);
      return [
        avatar ? h("img", { class: "acc-avatar", src: avatar, alt: "", loading: "lazy", referrerpolicy: "no-referrer" })
          : h("span", { class: "acc-avatar acc-initial", "aria-hidden": "true", text: (name.replace(/^[@#]/, "")[0] || "?").toUpperCase() }),
        h("span", { class: "acc-who" },
          h("span", { class: "acc-name", text: name }),
          p.handle && p.handle !== name ? h("span", { class: "acc-handle muted small", text: p.handle }) : null),
      ];
    },

    /** 🗑 Delete one post for good (asks first). It doesn't come back when its account is checked again; a saved post can be
     *  added again by pasting its link. */
    async deletePost(p, el) {
      const back = p.saved ? "You can add it again by pasting its link." : "It won't come back when the account is checked again.";
      if (!window.confirm(`Delete this post${p.is_starred ? " (it's starred)" : ""}? ${back}`)) return;
      if (!(await guarded(() => api("DELETE", `/accounts/posts/${p.id}`)))) return;
      const shelf = el.closest(".lib-shelf");
      el.remove();
      if (shelf && !shelf.querySelector(".acc-card")) shelf.remove();
      if (this.filters.view !== "topics" && typeof this.total === "number") {
        this.total -= 1;
        this.offset = Math.max(0, this.offset - 1);   // "Load more" carries on from the right place
        const count = $("#accCount");
        if (count) count.textContent = `${this.total} post${this.total === 1 ? "" : "s"}`;
      }
      toast("Post deleted");
      this.loadMeta().catch(() => {});   // post counts in Accounts ▾
    },

    cardPosts: new WeakMap(),   // card element → its post (to redraw a card's tags in place)

    /** A post's topics: folded behind 🏷️ n, or shown on every card when the tab's 🏷️ Tags toggle is on. */
    tagArea(p) {
      const topics = (p.topics || []).map((id) => this.topics.find((t) => t.id === id)).filter(Boolean);
      return FW.tagFold("accounts", topics.length, () => h("div", { class: "lib-topics" },
        topics.map((t) => h("span", { class: "topic-tag", style: { "border-color": safeColor(t.color) }, text: t.name }))));
    },

    /** 🏷️ Tags turned on / off: swap each card's tag row where it is (no reload, the scroll position stays). */
    redrawTags() {
      for (const el of document.querySelectorAll("#accGrid .acc-card, #accGrid .acc-post")) {
        const p = this.cardPosts.get(el);
        const old = p && el.querySelector(".tag-fold, .lib-topics");
        if (!old) continue;
        const next = this.tagArea(p);
        if (next) old.replaceWith(next); else old.remove();
      }
    },

    /** "@karpathy" / "u/someone" read well on a button; "in/jane-doe" doesn't - then the person's name. */
    followName(p) { return /^(@|u\/)/.test(p.handle || "") ? p.handle : (p.author || p.handle); },

    /** ＋ Follow the author of a saved post (adds their account to this tab), or say plainly why that can't be done. */
    followControl(f, who) {
      if (!f) return null;
      const label = who || "this account";
      if (f.followed) return h("span", { class: "acc-follow muted small", text: `✓ Following ${label}` });
      const box = h("span", { class: "acc-follow" });
      const note = h("span", { class: "small muted acc-follow-note", hidden: true });
      const btn = h("button", { type: "button", class: "btn small", text: `＋ Follow ${label}`,
        title: f.possible ? `Follow ${label} in the Accounts tab` : (f.reason || "This account can't be followed here"),
        onclick: async () => {
          if (!f.possible) { note.textContent = f.reason || "This account can't be followed here."; note.hidden = !note.hidden; return; }
          btn.disabled = true;
          btn.textContent = "Following…";
          try {
            const res = await api("POST", "/accounts", { input: f.url });
            f.followed = true;
            fill(box, h("span", { class: "muted small", text: `✓ Following ${label}` }));
            toast(`Following ${res.title || label}${f.note ? ` — ${f.note}` : ""}`);
            FW.loadSidebar();
            this.loadMeta().catch(() => {});
          } catch (err) {
            const already = /already/i.test(err.message);
            if (already) { f.followed = true; fill(box, h("span", { class: "muted small", text: `✓ Following ${label}` })); return; }
            btn.disabled = false;
            btn.textContent = `＋ Follow ${label}`;
            const down = f.platform === "x" && /ConnectError|connect|timed? ?out|reach/i.test(err.message);
            note.textContent = down ? "Your X bridge (RSSHub, Settings → Integrations → X) isn't answering. Start it — or add an X API bearer token there — and try again."
              : `Couldn't follow: ${err.message}`;
            note.hidden = false;
          }
        } });
      box.append(btn, note);
      return box;
    },

    /** Paste the post's text yourself (the platform handed over only the start of it, or nothing). */
    pasteBox(p, card) {
      const area = h("textarea", { rows: 6, maxlength: 20000, "aria-label": "The post's full text",
        placeholder: "Open the post, copy all of its text and paste it here. It is stored as you paste it." });
      const err = h("p", { class: "error small" });
      const box = h("div", { class: "acc-paste" }, area, err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn small", text: "Cancel", onclick: () => box.remove() }),
          h("button", { type: "button", class: "btn small primary", text: "Save text",
            onclick: async () => {
              if (!area.value.trim()) { err.textContent = "Paste the post's text first."; return; }
              try {
                const d = await api("PUT", `/accounts/posts/${p.id}/text`, { text: area.value });
                card.replaceWith(this.renderAgain(p, d));
                toast("Post text saved");
              } catch (ex) { err.textContent = ex.message; }
            } })));
      return box;
    },

    renderAgain(p, detail) {
      const next = { ...p, ...detail };
      delete next.html;
      return this.filters.view === "read" ? this.readCard({ ...next, html: detail.html }) : this.card(next);
    },

    card(p) {
      const link = safeUrl(p.url);
      const text = (p.text || "").trim();
      const rawTitle = (p.title || "").trim();
      const title = /^\(?untitled\)?$/i.test(rawTitle) ? "" : rawTitle;  // Mastodon/Bluesky posts have no titles
      const same = text && title && text.toLowerCase().startsWith(title.slice(0, 60).toLowerCase());
      const saved = Boolean(p.saved);
      const image = saved ? this.imgSrc(p.image) : null;
      // collapsed to a short preview; "Show more" opens the whole post (its paragraphs and links)
      const long = saved ? (p.text_len > 320 || text.split("\n").length > 6) : text.length >= 360;
      const preview = text ? h("p", { class: `acc-text${long ? " acc-clamp" : ""}`, text: saved ? text : (text.length > 360 ? `${text.slice(0, 360)}…` : text) }) : null;
      let full = null;
      const more = long ? h("button", { type: "button", class: "link-btn acc-more", text: "Show more ▾", "aria-expanded": "false",
        onclick: async () => {
          const opening = more.getAttribute("aria-expanded") !== "true";
          if (opening && !full) {
            more.disabled = true;
            more.textContent = "Loading…";
            try {
              const d = saved ? await api("GET", `/accounts/posts/${p.id}`) : await api("GET", `/articles/${p.id}`);
              full = h("div", { class: "acc-full" }, FW.buildContent ? FW.buildContent(saved ? d.html : d.content_html) : h("p", { class: "acc-text", text: d.text || text }));
            } catch (err) { toast(err.message, true); }
            more.disabled = false;
          }
          if (opening && full) { preview.replaceWith(full); more.textContent = "Show less ▴"; more.setAttribute("aria-expanded", "true"); }
          else if (!opening && full) {
            full.replaceWith(preview);
            more.textContent = "Show more ▾";
            more.setAttribute("aria-expanded", "false");
            if (card.getBoundingClientRect().top < 0) card.scrollIntoView({ block: "start" });
          } else more.textContent = "Show more ▾";
        } }) : null;
      const missing = saved && p.source === "unavailable";   // the site showed a sign-in page / nothing instead of the post
      const trunc = saved && (p.truncated || missing) ? h("p", { class: "acc-trunc small" },
        h("span", { text: missing ? `⚠ ${this.label(p.platform)} only shows this post to signed-in members (or it was deleted), so the app can't read it — it never signs in for you. Open the post ↗, copy its text and paste it here. `
          : `⚠ ${this.label(p.platform)} only hands over the start of this post. ` }),
        h("button", { type: "button", class: "link-btn", text: missing ? "✎ Paste the post's text" : "✎ Paste the full text", onclick: (e) => { const el = e.currentTarget.closest("article") || card; if (!el.querySelector(".acc-paste")) trunc.after(this.pasteBox(p, el)); } })) : null;
      const follow = saved ? this.followControl(p.follow, this.followName(p)) : null;
      const open = () => {
        if (!p.is_read) { api("POST", "/articles/bulk", { ids: [p.id], action: "read" }).catch(() => {}); p.is_read = true; card.classList.add("watched"); }
      };
      const star = h("button", { type: "button", class: `icon-btn${p.is_starred ? " on" : ""}`, title: "Star", "aria-label": "Star", text: p.is_starred ? "★" : "☆",
        onclick: async () => {
          const on = !p.is_starred;
          if (await guarded(() => api("POST", "/articles/bulk", { ids: [p.id], action: on ? "star" : "unstar" }))) { p.is_starred = on; star.textContent = on ? "★" : "☆"; star.classList.toggle("on", on); }
        } });
      const summary = h("div", { class: "acc-summary", hidden: true });
      const savedActions = saved ? [
        h("button", { type: "button", class: "icon-btn", title: `Read this post again from ${this.label(p.platform)}`, "aria-label": "Read the post again", text: "↻",
          onclick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            try { const d = await api("POST", `/accounts/posts/${p.id}/refresh`); (btn.closest("article") || card).replaceWith(this.renderAgain(p, d)); toast("Post read again"); }
            catch (err) { toast(err.message, true); btn.disabled = false; }
          } }),
        h("button", { type: "button", class: "icon-btn", title: "Paste the post's text yourself", "aria-label": "Paste the post's text", text: "✎",
          onclick: (e) => {
            const el = e.currentTarget.closest("article") || card;  // the ☰ Read card reuses these buttons
            if (!el.querySelector(".acc-paste")) (el.querySelector(".lib-actions") || el).before(this.pasteBox(p, el));
          } }),
      ] : [];
      const card = h("article", { class: `lib-card acc-card${p.is_read ? " watched" : ""}${saved ? " acc-saved" : ""}` },
        h("div", { class: "lib-body" },
          h("div", { class: "acc-head" },
            h("span", { class: `acc-badge p-${p.platform}`, title: this.label(p.platform), text: this.icon(p.platform) }),
            ...(saved ? this.authorHead(p) : [h("span", { class: "acc-name", text: p.feed_title })]),
            h("span", { class: "muted small acc-date", title: fullDate(p.published), text: relTime(p.published) })),
          title && !same && !saved ? h("div", { class: "lib-title acc-title", text: title }) : null,
          image ? h("button", { type: "button", class: "acc-thumb", title: "Open the picture", "aria-label": "Open the picture", onclick: () => this.openPhoto(image) },
            h("img", { src: image, alt: "", loading: "lazy", referrerpolicy: "no-referrer" })) : null,
          more, preview, trunc, follow,
          this.tagArea(p),
          summary,
          h("div", { class: "lib-actions" }, star, ...savedActions,
            h("button", { type: "button", class: "icon-btn", title: "Summarise with AI (Settings → AI)", "aria-label": "Summarise with AI", text: "✨",
              onclick: async () => {
                summary.hidden = false;
                fill(summary, h("span", { class: "muted small", text: "✨ Summarising…" }));
                try {
                  const r = await api("POST", `/articles/${p.id}/summary`, { force: false });
                  fill(summary, h("strong", { class: "small", text: "✨ Summary" }), h("p", { class: "small", text: r.summary || "" }));
                } catch (err) {
                  fill(summary, h("span", { class: "error small", text: err.message }),
                    /Settings → AI|configured|API key|provider/i.test(err.message) ? h("button", { type: "button", class: "btn small", text: "Open Settings → AI", onclick: () => FW.openSettings("ai") }) : null);
                }
              } }),
            h("button", { type: "button", class: "icon-btn", title: "Open in Articles", "aria-label": "Open in Articles", text: "📰", onclick: () => { open(); FW.openArticleInReader(p.id); } }),
            h("button", { type: "button", class: "icon-btn acc-del", title: "Delete this post", "aria-label": "Delete this post", text: "🗑",
              onclick: (e) => this.deletePost(p, e.currentTarget.closest("article") || card) }),
            link ? h("a", { class: "btn small", href: link, target: "_blank", rel: "noopener noreferrer", text: "Open post ↗", onclick: open }) : null)));
      card.append(this.widthHandle(card) || "");
      this.cardPosts.set(card, p);
      return card;
    },

    /** Photos (full size), a Reddit video (the browser tries Reddit's files in turn) or a gallery link. */
    mediaBlock(list) {
      const okHost = (u, hosts) => { try { const x = new URL(u); return x.protocol === "https:" && hosts.includes(x.hostname); } catch { return false; } };
      const IMG_HOSTS = ["i.redd.it", "preview.redd.it", "external-preview.redd.it", "i.imgur.com"];
      const items = (list || []).map((m) => {
        if (m.type === "image" && okHost(m.src, IMG_HOSTS)) {
          return h("a", { href: m.src, target: "_blank", rel: "noopener noreferrer", class: "acc-photo" },
            h("img", { src: m.src, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }));
        }
        if (m.type === "video" && (m.sources || []).every((s) => okHost(s, ["v.redd.it"]))) {
          const poster = m.poster && okHost(m.poster, IMG_HOSTS) ? m.poster : undefined;
          const video = h("video", { controls: true, preload: "none", playsinline: true, poster },
            m.sources.map((s) => h("source", { src: s, type: s.endsWith(".m3u8") ? "application/vnd.apple.mpegurl" : "video/mp4" })));
          return h("div", { class: "acc-video" }, video,
            h("a", { class: "muted small", href: safeUrl(m.page), target: "_blank", rel: "noopener noreferrer", text: "No sound or won't play? Open the video on Reddit ↗" }));
        }
        if (m.type === "gallery" && okHost(m.href, ["www.reddit.com", "reddit.com"])) {
          const poster = m.poster && okHost(m.poster, IMG_HOSTS) ? m.poster : null;
          return h("a", { class: "acc-gallery", href: m.href, target: "_blank", rel: "noopener noreferrer" },
            poster ? h("img", { src: poster, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : null,
            h("span", { text: "🖼️ Gallery — view all its pictures on Reddit ↗" }));
        }
        return null;
      }).filter(Boolean);
      return items.length ? h("div", { class: "acc-media" }, items) : null;
    },

    /** ☰ Read: one post in full - its text, links, photos and video - like reading it on the platform. */
    readCard(p) {
      const card = this.card(p);   // reuse the actions (★, ✨, 📰, open) of the normal card
      const actions = card.querySelector(".lib-actions");
      const topics = card.querySelector(".tag-fold, .lib-topics");
      const summary = card.querySelector(".acc-summary");
      const extras = [card.querySelector(".acc-trunc"), card.querySelector(".acc-follow")];  // saved posts: shortened note, ＋ Follow
      const link = safeUrl(p.url);
      const rawTitle = (p.title || "").trim();
      const title = /^\(?untitled\)?$/i.test(rawTitle) || p.saved ? "" : rawTitle;  // a saved post's title is its first line
      const content = FW.buildContent ? FW.buildContent(p.thread ? (p.body || "") : (p.html || "")) : h("p", { text: p.text || "" });
      if (p.thread && !p.body) content.replaceChildren();   // a link / photo post: the media says it all
      if (p.saved) this.zoomable(content);
      const open = () => this.openThread(p);
      if (p.thread && actions) actions.prepend(h("button", { type: "button", class: "btn small", text: "💬 Thread", title: "Read the comments", onclick: open }));
      const post = h("article", { class: `acc-post${p.is_read ? " watched" : ""}` },
        h("div", { class: "acc-head" },
          h("span", { class: `acc-badge p-${p.platform}`, title: this.label(p.platform), text: this.icon(p.platform) }),
          ...(p.saved ? this.authorHead(p) : [h("span", { class: "acc-name", text: p.feed_title }),
            p.author ? h("span", { class: "muted small", text: p.author }) : null]),
          h("span", { class: "muted small acc-date", title: fullDate(p.published), text: relTime(p.published) })),
        title ? (p.thread ? h("button", { type: "button", class: "acc-post-title link-btn", text: title, onclick: open })
          : link ? h("a", { class: "acc-post-title", href: link, target: "_blank", rel: "noopener noreferrer", text: title }) : h("div", { class: "acc-post-title", text: title })) : null,
        p.thread ? this.mediaBlock(p.media) : null,
        content, ...extras, topics, summary, actions);
      post.append(this.widthHandle(post) || "");
      this.cardPosts.set(post, p);
      return post;
    },

    /** A Reddit post with its comments (from the post's public feed). */
    async openThread(p) {
      const dlg = $("#feedDialog");
      fill(dlg, h("p", { class: "muted", text: "Loading the thread…" }));
      if (!dlg.open) dlg.showModal();
      if (!p.is_read) { api("POST", "/articles/bulk", { ids: [p.id], action: "read" }).catch(() => {}); p.is_read = true; }
      let t;
      try { t = await api("GET", `/accounts/posts/${p.id}/thread`); } catch (err) {
        fill(dlg, h("div", { class: "form" }, h("p", { class: "error", text: err.message }),
          h("div", { class: "form-actions" }, safeUrl(p.url) ? h("a", { class: "btn", href: safeUrl(p.url), target: "_blank", rel: "noopener noreferrer", text: "Open on Reddit ↗" }) : null,
            h("button", { type: "button", class: "btn primary", text: "Close", onclick: () => dlg.close() }))));
        return;
      }
      const post = t.post;
      fill(dlg, h("div", { class: "acc-thread" },
        h("div", { class: "sd-head" },
          h("div", null, h("h3", { text: post.title || p.title }),
            h("div", { class: "muted small", text: [post.author, post.published ? fullDate(post.published) : null, `${t.comments.length} comment${t.comments.length === 1 ? "" : "s"}`].filter(Boolean).join(" · ") })),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        this.mediaBlock(post.media),
        post.body && FW.buildContent ? FW.buildContent(post.body) : null,
        h("div", { class: "acc-comments" },
          t.comments.length ? t.comments.map((c) => h("div", { class: "acc-comment" },
            h("div", { class: "muted small" }, h("strong", { text: c.author || "someone" }), c.published ? ` · ${relTime(c.published)}` : ""),
            FW.buildContent ? FW.buildContent(c.html) : h("p", { text: "" })))
            : h("p", { class: "muted", text: "No comments yet." })),
        h("p", { class: "muted small", text: "Comments come from the thread's public feed, in its order and without the nesting. To reply, or for very long threads, open it on Reddit." }),
        h("div", { class: "form-actions" },
          h("a", { class: "btn", href: safeUrl(post.link), target: "_blank", rel: "noopener noreferrer", text: "Open on Reddit ↗" }),
          h("button", { type: "button", class: "btn primary", text: "Close", onclick: () => dlg.close() }))));
    },

    /** One account's full settings - the same dialog as a feed in Articles (name, refresh, retention, history…). */
    openSettings(account) {
      if (!FW.feeds || !FW.feeds.openFeedEditor) return;
      const dlg = $("#feedDialog");
      dlg.addEventListener("close", () => { if (FW.currentMode() === "accounts") this.refreshAll(); }, { once: true });
      FW.feeds.openFeedEditor(account.feed_id);
    },

    /** Retention and refresh for several accounts at once (a whole platform, or the ticked ones). */
    openGroupSettings(list, name) {
      if (!list.length) return;
      const dlg = $("#sourceDialog");
      const keeps = [...new Set(list.map((a) => a.keeps))];
      const keep = h("select", { "aria-label": "Keep (retention)" }, h("option", { value: "same", text: "Don't change" }),
        KEEP_CHOICES.filter(([v]) => v !== "").map(([v, l]) => h("option", { value: v, text: l })));
      const refresh = h("select", { "aria-label": "Refresh" }, REFRESH_CHOICES.map(([v, l]) => h("option", { value: v, text: l })));
      const err = h("p", { class: "error" });
      const ids = list.map((a) => a.feed_id);
      const go = async (e) => {
        e.preventDefault();
        err.textContent = "";
        const jobs = [];
        if (keep.value !== "same") {
          const days = Number(keep.value);
          const dry = await api("POST", "/feeds/keep", { scope: "feeds", feed_ids: ids, days, dry_run: true }).catch((ex) => { err.textContent = ex.message; return null; });
          if (!dry) return;
          if (dry.removed && !window.confirm(`Keep the ${KEEP_CHOICES.find(([v]) => v === keep.value)[1].toLowerCase()} for ${name}? ${dry.removed} older post(s) will be removed (starred ones stay).`)) return;
          jobs.push(api("POST", "/feeds/keep", { scope: "feeds", feed_ids: ids, days }));
        }
        if (refresh.value) jobs.push(api("POST", "/feeds/bulk", { ids, action: "set_refresh", refresh_minutes: refresh.value === "default" ? null : Number(refresh.value) }));
        if (!jobs.length) { dlg.close(); return; }
        try { await Promise.all(jobs); } catch (ex) { err.textContent = ex.message; return; }
        dlg.close();
        toast(`Saved for ${name}`);
        this.refreshAll();
      };
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: `⚙ ${name}` }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        h("p", { class: "muted small", text: `${list.length} account${list.length === 1 ? "" : "s"}: ${list.slice(0, 8).map((a) => a.title).join(", ")}${list.length > 8 ? "…" : ""}` }),
        h("div", { class: "grid-form" },
          h("label", { text: "Currently keeps" }), h("strong", { class: "keep-now", text: keeps.length === 1 ? (FW.fmtRetention ? FW.fmtRetention(keeps[0]) : `${keeps[0]} days`) : `mixed (${keeps.map(keepText).join(", ")})` }),
          h("label", { text: "Keep (retention)" }), keep,
          h("label", { text: "Check for new posts" }), refresh),
        h("ul", { class: "small src-notes" },
          h("li", { text: "Each account's own settings (name, address, history, health) are under ⚙ Settings next to it in Accounts ▾." }),
          h("li", { text: "Starred posts are always kept." })),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Apply" }))));
      if (!dlg.open) dlg.showModal();
    },

    async removeAccounts(list, name) {
      if (!list.length) return;
      const posts = list.reduce((n, a) => n + (a.posts || 0), 0);
      if (!window.confirm(`Stop following ${list.length === 1 ? `“${list[0].title}”` : `${name} (${list.length} accounts)`} and delete ${posts} post(s)? Starred posts go too. This cannot be undone.`)) return;
      const ok = list.length === 1
        ? await guarded(() => api("DELETE", `/accounts/${list[0].feed_id}`))
        : await guarded(() => api("POST", "/feeds/bulk", { ids: list.map((a) => a.feed_id), action: "delete" }));
      if (!ok) return;
      toast(`Removed ${list.length === 1 ? list[0].title : name}`);
      const gone = new Set(list.map((a) => String(a.feed_id)));
      this.filters.feed_ids = this.filters.feed_ids.filter((id) => !gone.has(String(id)));
      this.save();
      FW.loadSidebar();
      await this.refreshAll();
    },

    /** One ＋ for everything: paste profiles, subreddits and single posts; each line is recognised as you type. */
    openAdd() {
      const dlg = $("#sourceDialog");
      const box = h("textarea", { rows: 6, maxlength: 20000, "aria-label": "Links, one per line",
        placeholder: "Paste links, one per line — profiles, subreddits or single posts:\nhttps://www.reddit.com/r/homelab\nhttps://x.com/vxunderground\nhttps://bsky.app/profile/troyhunt.com\n@GossiTheDog@cyberplace.social\nhttps://t.me/somechannel\nhttps://www.linkedin.com/posts/…   (a single post)" });
      const list = h("ul", { class: "acc-detected small" });
      const g = Number(FW.state.settings.retention_days ?? 90);
      const keep = FW.keepPicker({ choices: KEEP_CHOICES.map(([v, l]) => [v, v === "" ? `Default (global setting: ${keepText(g)})` : l]) });
      const platform = h("select", { "aria-label": "Platform for bridge feed links" }, h("option", { value: "", text: "Detect automatically" }),
        BRIDGE_PLATFORMS.map(([v, l]) => h("option", { value: v, text: l })));
      const err = h("p", { class: "error" });
      const seen = new Map();   // line -> {info, text: textarea|null, row}
      const ICON = { post: "📝 post", community: "👥 subreddit", account: "👤 account", unknown: "❓" };
      let timer = null;
      const describe = async () => {
        const lines = [...new Set(box.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))].slice(0, 50);
        for (const key of [...seen.keys()]) if (!lines.includes(key)) seen.delete(key);
        for (const line of lines) {
          if (seen.has(line)) continue;
          const entry = { info: null, text: null, row: h("li", null, h("span", { class: "muted", text: "…" }), " ", h("code", { text: line })) };
          seen.set(line, entry);
          api("POST", "/accounts/recognize", { input: line }).then((info) => {
            entry.info = info;
            if (info.exists) {  // the same post (any link form) is already here: say so, and it is skipped
              entry.text = null;
              fill(entry.row, h("strong", { class: "muted", text: `✓ already in Socials (in “${info.exists.where}”) — skipped` }), " ", h("code", { text: line }));
              return;
            }
            const what = info.kind === "unknown" ? `❓ ${info.error || "not recognised"}` : `${ICON[info.kind]} · ${info.label}${info.handle && info.kind !== "post" ? ` · ${info.handle}` : ""}`;
            entry.text = info.needs_text ? h("textarea", { rows: 3, maxlength: 20000, "aria-label": "Post text",
              placeholder: `Optional: paste the post's text. The app first reads ${info.label}'s public preview (often the whole post, its author and picture); if ${info.label} hides it behind a login, your pasted text is used.` }) : null;
            const contacts = info.kind === "post" && (info.contacts || []).length
              ? h("span", { class: "muted small acc-contacts", text: `Contacts: ${info.contacts.join(", ")}` })
              : info.kind === "post" ? h("span", { class: "muted small acc-contacts", text: "Contacts no outside site: paste the post's text below." }) : null;
            fill(entry.row, h("strong", { class: info.kind === "unknown" ? "status-err" : "", text: what }), " ", h("code", { text: line }), contacts, entry.text);
          }).catch(() => { fill(entry.row, h("span", { class: "muted", text: "will be checked when added" }), " ", h("code", { text: line })); });
        }
        fill(list, lines.map((l) => seen.get(l).row));
      };
      box.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(describe, 350); });
      const go = (e) => {
        e.preventDefault();
        const lines = [...new Set(box.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))];
        if (!lines.length) { err.textContent = "Paste at least one link."; return; }
        if (lines.length > 50) { err.textContent = "Up to 50 at a time, please."; return; }
        const items = lines.map((line) => {
          const s = seen.get(line);
          return { line, kind: s && s.info ? s.info.kind : null, text: s && s.text ? s.text.value.trim() : "", exists: s && s.info ? s.info.exists : null };
        });
        const days = keep.days();
        if (Number.isNaN(days)) { err.textContent = "Custom keep time frame must be 1 day to 100 years."; return; }
        this.addBatch(items, { platform: platform.value || null, retention_days: days });
      };
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: "＋ Add accounts, subreddits or posts" }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        box, list,
        h("div", { class: "grid-form" },
          h("label", { text: "Keep (retention)" }), keep.el,
          h("label", { text: "Bridge feed links are" }), platform),
        h("ul", { class: "small src-notes" },
          h("li", { text: "Subreddits (reddit.com/r/…) bring in every new post as it's submitted, checked every 30 minutes." }),
          h("li", { text: "Bluesky, Mastodon, Reddit and public Telegram channels work straight away. X, Instagram, Threads, TikTok, Facebook and LinkedIn company pages go through your RSSHub bridge (Settings → Integrations → X)." }),
          h("li", { text: "A link to one post saves just that post — its text, author, date and picture — so you can read it here. Each post link shows which outside site is asked (only official or public ways: X's embed, Bluesky's public API, the page's public link preview…). The app never logs in or gets around a login wall: if a site won't hand the post over, paste its text." }),
          h("li", { text: "Pictures load through this server when “Load images through this server” is on (Settings → Reading), otherwise straight from the platform's image server." })),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Add" }))));
      if (!dlg.open) dlg.showModal();
      box.focus();
    },

    async addBatch(items, opts) {
      const dlg = $("#sourceDialog");
      const rows = items.map((it) => ({ ...it, status: h("span", { class: "muted", text: "waiting" }) }));
      const done = h("button", { type: "button", class: "btn primary", text: "Close", disabled: true, onclick: () => dlg.close() });
      const summary = h("p", { class: "small" });
      fill(dlg, h("div", { class: "form source-wizard" },
        h("div", { class: "sd-head" }, h("h3", { text: `Adding ${items.length} link${items.length > 1 ? "s" : ""}` })),
        h("ol", { class: "batch-list small acc-batch" }, rows.map((r) => h("li", null, h("code", { text: r.line }), " — ", r.status))),
        summary, h("div", { class: "form-actions" }, done)));
      let accounts = 0, posts = 0;
      for (const r of rows) {
        const set = (cls, text) => { r.status.className = cls; r.status.textContent = text; };
        if (r.exists) { set("muted", `already in Socials (in “${r.exists.where}”) — skipped`); continue; }
        set("muted", "adding…");
        const call = r.kind === "post"
          ? () => api("POST", "/accounts/posts", { url: r.line, ...(r.text ? { text: r.text } : {}) })
          : () => api("POST", "/accounts", { input: r.line, ...(opts.platform ? { platform: opts.platform } : {}),
            ...(opts.retention_days !== null ? { retention_days: opts.retention_days } : {}) });
        let res = null;
        for (let attempt = 0; attempt < 2 && !res; attempt += 1) {
          try { res = await call(); } catch (err) {
            if (attempt === 0 && /too many|rate/i.test(err.message)) { set("muted", "waiting (rate limit)…"); await new Promise((ok) => setTimeout(ok, 30000)); continue; }
            const already = /already (subscribed|saved)/i.test(err.message);
            set(already ? "muted" : "status-err", already ? "already there" : `✗ ${err.message}`);
            break;
          }
        }
        if (!res) continue;
        if (r.kind === "post") {
          posts += 1;
          set("status-ok", `✓ post saved: ${(res.title || "").slice(0, 80)}${res.truncated ? " — only its start was available; paste the rest on its card (✎)" : ""}`);
          const follow = res.follow && !res.follow.followed ? this.followControl(res.follow, this.followName(res)) : null;
          if (follow) r.status.after(" ", follow);
        }
        else { accounts += 1; set("status-ok", `✓ ${this.label(res.platform)}: ${res.title}`); }
      }
      summary.textContent = `${accounts} account(s) and ${posts} post(s) added. New accounts' posts appear in a few seconds.`;
      done.disabled = false;
      FW.loadSidebar();
      await this.refreshAll();
      setTimeout(async () => { if (FW.currentMode() === "accounts") await this.refreshAll(); }, 5000);
    },
  };

  FW.accounts = view;
})();
