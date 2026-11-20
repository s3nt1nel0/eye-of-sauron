"use strict";
/*
 * Eye of Sauron web UI - dependency-free.
 * Security notes:
 *  - All dynamic text is inserted with textContent / createTextNode, never innerHTML.
 *  - The single exception is article content, which the server sanitises with an
 *    allow-list (nh3) before storage and again on output; a strict CSP
 *    (script-src 'self', no inline) backs that up.
 *  - Every state-changing request carries the per-session CSRF token header.
 */
(function () {
  // ======================================================================= helpers
  const $ = (sel, root = document) => root.querySelector(sel);

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") el.className = value;
        else if (key === "text") el.textContent = value;
        else if (key === "dataset") Object.assign(el.dataset, value);
        else if (key === "style") for (const [p, v] of Object.entries(value)) el.style.setProperty(p, v);
        else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
        else if (key === "value") el.value = value;
        else if (key === "checked") el.checked = Boolean(value);
        else if (value === true) el.setAttribute(key, "");
        else el.setAttribute(key, String(value));
      }
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  /** Replace an element's children; arrays are flattened (replaceChildren would stringify them). */
  function fill(el, ...children) {
    el.replaceChildren();
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  /** Only http(s) URLs may become links (server enforces this too). */
  function safeUrl(url) {
    return typeof url === "string" && /^https?:\/\//i.test(url) ? url : null;
  }

  /** Only #rrggbb colours reach style properties. */
  function safeColor(c) {
    return typeof c === "string" && /^#[0-9a-f]{6}$/i.test(c) ? c : "#6b7280";
  }

  const store = {
    get(key, fallback) {
      try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch (_) { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* ignore */ }
    },
  };

  let toastTimer = null;
  function toast(message, isError = false) {
    const el = $("#toast");
    el.textContent = message;
    el.classList.toggle("err", isError);
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), isError ? 5000 : 2500);
  }

  function relTime(ts) {
    if (!ts) return "";
    const diff = Math.floor(Date.now() / 1000) - ts;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}d ago`;
    return fmtDate(ts);
  }
  // Dates are always shown as dd/mm/yyyy, times as 24-hour HH:MM (local time).
  const pad2 = (n) => String(n).padStart(2, "0");
  /** A retention in days for people: "365 days (1 year)", "400 days (1 year 35 days)", "90 days (3 months)",
   *  "14 days", "forever". short: just the human part ("1 year"). */
  function fmtRetention(days, short = false) {
    if (days === null || days === undefined || days === "") return "not set";
    const d = Number(days);
    if (!Number.isFinite(d)) return "not set";
    if (d === 0) return short ? "everything" : "forever";
    const plural = (n, w) => `${n.toLocaleString()} ${w}${n === 1 ? "" : "s"}`;
    const years = Math.floor(d / 365), rest = d % 365, parts = [];
    if (years) parts.push(plural(years, "year"));
    if (rest) parts.push(rest % 30 === 0 ? plural(rest / 30, "month") : plural(rest, "day"));
    const human = parts.join(" ");
    const plain = plural(d, "day");
    if (short) return human;
    return human === plain ? plain : `${plain} (${human})`;
  }

  function fmtDate(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}/${d.getFullYear()}`;
  }
  function fullDate(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    return `${fmtDate(ts)} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }

  // Refresh intervals in minutes (server accepts any value from 5 to 10080).
  const REFRESH_CHOICES = [
    5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 360, 480, 720, 1440, 2880, 4320, 10080,
  ];

  function fmtMinutes(m) {
    if (m < 60) return `Every ${m} minutes`;
    if (m === 60) return "Hourly";
    if (m === 1440) return "Daily";
    if (m === 10080) return "Weekly";
    if (m % 1440 === 0) return `Every ${m / 1440} days`;
    if (m % 60 === 0) return `Every ${m / 60} hours`;
    return `Every ${Math.floor(m / 60)}h ${m % 60}m`;
  }

  /**
   * Interval picker: preset list + "Custom…" (number of minutes).
   * withDefault=true adds a "use global default" option (value null).
   * Returns { el, value() } - value() is a number, null (default) or NaN (invalid custom).
   */
  function refreshPicker(selected, withDefault, label) {
    const select = h("select", { "aria-label": label || "Refresh interval" });
    if (withDefault) {
      select.append(h("option", { value: "", text: `Default (${fmtMinutes(state.settings.default_refresh_minutes || 60).toLowerCase()})` }));
    }
    const choices = REFRESH_CHOICES.slice();
    if (selected && !choices.includes(selected)) choices.push(selected);
    choices.sort((a, b) => a - b);
    for (const m of choices) select.append(h("option", { value: m, text: fmtMinutes(m), selected: m === selected }));
    select.append(h("option", { value: "custom", text: "Custom…" }));
    const custom = h("input", { type: "number", min: 5, max: 10080, step: 1, placeholder: "minutes", class: "custom-minutes", hidden: true, "aria-label": "Custom interval in minutes" });
    select.addEventListener("change", () => {
      custom.hidden = select.value !== "custom";
      if (!custom.hidden) custom.focus();
    });
    const el = h("span", { class: "refresh-picker" }, select, custom);
    return {
      el,
      select,
      custom,
      value() {
        if (select.value === "") return null;
        const n = Number(select.value === "custom" ? custom.value : select.value);
        return Number.isInteger(n) && n >= 5 && n <= 10080 ? n : NaN;
      },
    };
  }

  // ======================================================================= API
  let CSRF = null;

  function errorMessage(data, fallback) {
    if (!data || data.detail === undefined) return fallback;
    const d = data.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return d.map((e) => `${(e.loc || []).slice(1).join(".") || "input"}: ${e.msg}`).join("; ");
    if (typeof d === "object") return Object.entries(d).map(([k, v]) => `${k}: ${v}`).join("; ");
    return fallback;
  }

  async function api(method, path, body, opts = {}) {
    const headers = { Accept: "application/json" };
    const init = { method, headers, credentials: "same-origin" };
    if (opts.signal) init.signal = opts.signal;  // a newer request for the same place cancels this one
    if (body !== undefined) {
      if (opts.raw) {
        headers["Content-Type"] = opts.contentType || "application/octet-stream";
        init.body = body;
      } else {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
    }
    if (method !== "GET" && CSRF) headers["X-CSRF-Token"] = CSRF;
    const res = await fetch(`/api/v1${path}`, init);
    if (res.status === 401) {
      window.location.replace("/login");
      throw new Error("Session expired");
    }
    if (opts.blob && res.ok) return res.blob();
    let data = null;
    if ((res.headers.get("content-type") || "").includes("application/json")) data = await res.json();
    if (!res.ok) throw new Error(errorMessage(data, `Request failed (${res.status})`));
    return data;
  }

  async function guarded(fn, okMessage) {
    try {
      const result = await fn();
      if (okMessage) toast(okMessage);
      return result;
    } catch (err) {
      if (err && err.name === "AbortError") return undefined;  // replaced by a newer request
      toast(err.message || "Something went wrong", true);
      return undefined;
    }
  }

  // ======================================================================= state
  const state = {
    settings: {},
    sidebar: { folders: [], feeds: [], tags: [], counts: {} },
    view: { type: "unread", id: null },
    q: "",
    articles: [],
    total: 0,
    selectedId: null,
    selecting: false,          // multi-select mode in the article list
    checked: new Set(),        // ids of ticked articles
    lastChecked: null,         // anchor for Shift+click ranges
    current: null,
    loading: false,
    lastTotal: null,
    collapsed: new Set(store.get("fw-collapsed", [])),
  };

  // ======================================================================= settings / theme
  // ---------------------------------------------------------------- tab order (drag the tabs, or Settings → Arrange tabs…)
  const TAB_IDS = { reader: "modeReader", dashboard: "modeDash", library: "modeLibrary", accounts: "modeAccounts",
    podcasts: "modePodcasts", repos: "modeRepos", threatmap: "modeThreatmap" };
  const tabBar = () => document.querySelector(".mode-switch");
  const tabKeys = () => [...(tabBar() ? tabBar().children : [])].map((b) => b.dataset.tab).filter(Boolean);
  function applyTabOrder() {
    const bar = tabBar();
    if (!bar) return;
    for (const [key, id] of Object.entries(TAB_IDS)) { const b = document.getElementById(id); if (b) b.dataset.tab = key; }
    const buttons = new Map([...bar.children].filter((b) => b.dataset.tab).map((b) => [b.dataset.tab, b]));
    const want = (state.settings.tab_order || []).filter((k) => buttons.has(k));
    const order = [...want, ...[...buttons.keys()].filter((k) => !want.includes(k))];
    if (order.join() !== tabKeys().join()) order.forEach((k) => bar.append(buttons.get(k)));
  }
  async function saveTabOrder(order) {
    const res = await guarded(() => api("PATCH", "/settings", { tab_order: order }));
    if (res) state.settings = res;
    applyTabOrder();
  }
  /** Drag a tab left or right to move it (mouse / pen); Alt+Shift+←/→ moves the focused tab (keyboard). */
  function setupTabDrag() {
    const bar = tabBar();
    if (!bar || bar.dataset.dragReady) return;
    bar.dataset.dragReady = "1";
    let dragged = null;
    for (const b of bar.children) {
      if (!b.dataset.tab) continue;
      b.draggable = true;
      b.addEventListener("dragstart", (e) => { dragged = b; b.classList.add("tab-dragging"); e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", b.dataset.tab); });
      b.addEventListener("dragend", () => { if (dragged) dragged.classList.remove("tab-dragging"); dragged = null; });
      b.addEventListener("keydown", (e) => {
        if (!e.altKey || !e.shiftKey || (e.key !== "ArrowLeft" && e.key !== "ArrowRight")) return;
        e.preventDefault();
        const order = tabKeys();
        const i = order.indexOf(b.dataset.tab), j = i + (e.key === "ArrowLeft" ? -1 : 1);
        if (j < 0 || j >= order.length) return;
        [order[i], order[j]] = [order[j], order[i]];
        saveTabOrder(order).then(() => b.focus());
      });
    }
    bar.addEventListener("dragover", (e) => {
      if (!dragged) return;
      e.preventDefault();
      const over = e.target.closest(".mode-switch > button");
      if (!over || over === dragged) return;
      const r = over.getBoundingClientRect();
      bar.insertBefore(dragged, e.clientX > r.left + r.width / 2 ? over.nextSibling : over);
    });
    bar.addEventListener("drop", (e) => {
      if (!dragged) return;
      e.preventDefault();
      saveTabOrder(tabKeys());
    });
  }
  /** Settings → Arrange tabs…: ↑ / ↓ for each tab (works on phones and tablets too), Reset = built-in order. */
  function openArrangeTabs() {
    const labels = Object.fromEntries([...(tabBar() ? tabBar().children : [])].filter((b) => b.dataset.tab).map((b) => [b.dataset.tab, b.textContent.trim()]));
    let order = tabKeys();
    const list = h("ol", { class: "tab-arrange" });
    const draw = () => fill(list, order.map((k, i) => h("li", null,
      h("span", { text: labels[k] || k }),
      h("span", { class: "tab-arrange-btns" },
        h("button", { type: "button", class: "btn small", text: "↑", disabled: i === 0, "aria-label": `Move ${labels[k]} earlier`, onclick: () => { [order[i - 1], order[i]] = [order[i], order[i - 1]]; draw(); } }),
        h("button", { type: "button", class: "btn small", text: "↓", disabled: i === order.length - 1, "aria-label": `Move ${labels[k]} later`, onclick: () => { [order[i + 1], order[i]] = [order[i], order[i + 1]]; draw(); } })))));
    draw();
    const dlg = h("dialog", { class: "range-dialog", "aria-label": "Arrange tabs" },
      h("div", { class: "form" },
        h("h3", { text: "⇄ Arrange tabs" }),
        h("p", { class: "muted small", text: "The order of the tabs at the top. On a computer you can also drag a tab left or right." }),
        list,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Reset", title: "Back to the built-in order", onclick: async () => { await saveTabOrder([]); dlg.close(); toast("Tabs back in the built-in order"); } }),
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "button", class: "btn primary", text: "Save", onclick: async () => { await saveTabOrder(order); dlg.close(); toast("Tab order saved"); } }))));
    dlg.addEventListener("close", () => dlg.remove());
    document.body.append(dlg);
    dlg.showModal();
  }

  function applySettings() {
    applyTabOrder();
    setupTabDrag();
    const s = state.settings;
    const root = document.documentElement;
    if (s.theme === "dark" || s.theme === "light") root.dataset.theme = s.theme;
    else delete root.dataset.theme;
    store.set("fw-theme", s.theme || "system");
    root.dataset.density = s.density || "comfortable";
    root.dataset.font = s.font_size || "medium";
    root.style.setProperty("--accent", safeColor(s.accent_color));
    $("#app").classList.toggle("layout-list", s.layout === "list");
    $("#sortSelect").value = s.sort || "newest";
  }

  // ======================================================================= sidebar
  function viewEquals(a, b) { return a.type === b.type && (a.id ?? null) === (b.id ?? null); }

  function sideItem({ label, count, icon, view, extraClass, dot, title, warn }) {
    const active = view && viewEquals(view, state.view);
    return h("button", {
      type: "button",
      class: `side-item ${active ? "active" : ""} ${extraClass || ""}`,
      title: title || label,
      onclick: () => view && selectView(view),
    },
    dot ? h("span", { class: "dot", style: { "--dot": safeColor(dot) } }) : h("span", { class: "ico", text: icon || "" }),
    h("span", { class: "label", text: label }),
    warn ? h("span", { class: "warn", title: warn, text: "⚠" }) : null,
    count ? h("span", { class: "count", text: count }) : null);
  }

  function renderSidebar() {
    const { folders, feeds, tags, counts } = state.sidebar;
    const side = $("#sidebar");
    fill(side, );

    side.append(h("div", { class: "side-section" },
      sideItem({ label: "All articles", icon: "≡", count: counts.total, view: { type: "all" } }),
      sideItem({ label: "Unread", icon: "●", count: counts.unread, view: { type: "unread" } }),
      sideItem({ label: "Read", icon: "○", count: Math.max(0, (counts.total || 0) - (counts.unread || 0)) || "", view: { type: "read" } }),
      sideItem({ label: "Starred", icon: "★", count: counts.starred, view: { type: "starred" } }),
      sideItem({ label: "Today", icon: "◷", view: { type: "today" } }),
    ));

    const tagSection = h("div", { class: "side-section" },
      h("div", { class: "side-head" }, h("span", { text: "Collections" }),
        h("button", { class: "icon-btn", type: "button", title: "New collection", "aria-label": "New collection", onclick: quickAddTag, text: "+" })));
    if (!tags.length) {
      tagSection.append(h("div", { class: "muted", style: { padding: "2px 10px" } },
        "No collections yet. ",
        h("a", { href: "#", onclick: (e) => { e.preventDefault(); openSettings("rules"); }, text: "Install the starter pack" })));
    }
    // "OT/ICS: Attacks" style names are grouped under a collapsible "OT/ICS" heading (closed by default).
    const groups = new Map();
    for (const t of tags) {
      const m = /^([^:]{1,30}):\s+(.+)$/.exec(t.name);
      const key = m ? m[1] : "";
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push({ t, label: m ? m[2] : t.name });
    }
    const tagItem = ({ t, label }, child) => sideItem({ label, dot: t.color, count: t.unread || "", view: { type: "tag", id: t.id },
      title: `${t.name} — ${t.total} articles`, extraClass: child ? "child" : "" });
    for (const { t, label } of groups.get("") || []) tagSection.append(tagItem({ t, label }, false));
    for (const [key, items] of groups) {
      if (!key) continue;
      if (items.length === 1) { tagSection.append(tagItem({ t: items[0].t, label: items[0].t.name }, false)); continue; }
      const openKey = `tags-open:${key}`;
      const wrap = h("div", { class: state.collapsed.has(openKey) ? "" : "collapsed" });
      const unread = items.reduce((n, x) => n + (x.t.unread || 0), 0);
      const total = items.reduce((n, x) => n + (x.t.total || 0), 0);
      // The heading opens every article in the folder's collections (filters, sort and dates apply as for any list);
      // the ▾ caret opens / closes the folder.
      const head = sideItem({ label: key, count: unread || "", view: { type: "taggroup", id: key, ids: items.map((x) => x.t.id) },
        title: `${key}: all ${items.length} collections (${total} articles). ▾ shows them one by one` });
      const caret = h("span", { class: "caret", text: "▾", title: "Show / hide the collections in this folder", role: "button",
        tabindex: "0", "aria-label": `Show or hide the collections in ${key}` });
      const toggle = (e) => {
        e.stopPropagation(); e.preventDefault();
        wrap.classList.toggle("collapsed");
        if (wrap.classList.contains("collapsed")) state.collapsed.delete(openKey); else state.collapsed.add(openKey);
        store.set("fw-collapsed", [...state.collapsed]);
      };
      caret.addEventListener("click", toggle);
      caret.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") toggle(e); });
      head.firstChild.replaceWith(caret);
      const matrixBtn = key === "ATT&CK" || key === "ATLAS" ? h("button", { type: "button", class: "feed-gear matrix-btn", text: "▦",
        title: `${key} technique matrix: every technique by tactic, coloured by how many articles name it`, "aria-label": `${key} technique matrix`,
        onclick: (e) => { e.stopPropagation(); window.FW.intel.matrix(key === "ATLAS" ? "atlas" : "attack"); } }) : null;
      wrap.append(matrixBtn ? h("div", { class: "side-row matrix-row" }, head, matrixBtn) : head, h("div", { class: "children" }, items.map((x) => tagItem(x, true))));
      tagSection.append(wrap);
    }
    side.append(tagSection);

    const folderSection = h("div", { class: "side-section" },
      h("div", { class: "side-head" }, h("span", { text: "Feeds" }),
        h("button", { class: "icon-btn", type: "button", title: "New folder", "aria-label": "New folder", onclick: quickAddFolder, text: "+" })));

    const dnd = state.settings.sidebar_drag_drop !== false;
    const unfiledZone = h("div", { class: "drop-unfiled", hidden: true, text: "Drop here to remove from folder" });

    const feedItem = (f, child) => {
      const item = sideItem({
        label: f.title || f.url, icon: "◦", count: f.unread || "", view: { type: "feed", id: f.id },
        extraClass: `${child ? "child" : ""} ${f.enabled ? "" : "disabled"}`,
        warn: f.error_count ? `Last error: ${f.last_error || "unknown"}` : null,
      });
      const openEditor = () => window.FW.feeds && window.FW.feeds.openFeedEditor(f.id);
      item.addEventListener("contextmenu", (e) => { e.preventDefault(); openEditor(); });
      item.addEventListener("dblclick", (e) => { e.preventDefault(); openEditor(); });
      const gear = h("button", { type: "button", class: "feed-gear", title: "Feed settings", "aria-label": `Settings for ${f.title || f.url}`, text: "⚙",
        onclick: (e) => { e.stopPropagation(); openEditor(); } });
      const row = h("div", { class: "side-row" }, item, gear);
      if (dnd) {
        item.draggable = true;
        item.title = `${f.title || f.url} — drag onto a folder to move it`;
        item.addEventListener("dragstart", (e) => {
          e.dataTransfer.setData(DRAG_TYPE, String(f.id));
          e.dataTransfer.effectAllowed = "move";
          item.classList.add("dragging");
          unfiledZone.hidden = f.folder_id === null;
        });
        item.addEventListener("dragend", () => {
          item.classList.remove("dragging");
          unfiledZone.hidden = true;
          for (const el of side.querySelectorAll(".drop-target")) el.classList.remove("drop-target");
        });
      }
      return row;
    };
    if (dnd) makeDropTarget(unfiledZone, null);

    /** A YouTube channel / podcast show in the sidebar: click lists its items here; ↗ opens it in its own tab.
     *  No count, no feed editor, no drag (they're managed in Videos / Podcasts). */
    const mediaItem = (f, child) => {
      const tab = f.section === "podcasts" ? "Podcasts" : "Videos";
      const item = sideItem({
        label: f.title || f.url, icon: f.section === "podcasts" ? "🎙" : "▸", count: "", view: { type: "feed", id: f.id },
        extraClass: `${child ? "child" : ""} ${f.enabled ? "" : "disabled"} media-feed`,
        warn: f.error_count ? `Last error: ${f.last_error || "unknown"}` : null,
      });
      const open = h("button", { type: "button", class: "feed-gear", title: `Open in ${tab}`, "aria-label": `Open ${f.title || f.url} in ${tab}`, text: "↗",
        onclick: (e) => {
          e.stopPropagation();
          if (f.section === "podcasts") {
            const pod = window.FW && window.FW.podcasts;
            if (pod) { pod.filters.feed_ids = [String(f.id)]; pod.filters.view = "episodes"; pod.filters.category = ""; pod.save(); }
            setMode("podcasts");
          } else {
            const lib = window.FW && window.FW.library;
            const c = lib && lib.meta && (lib.meta.channels || []).find((x) => x.feeds.some((fd) => fd.id === f.id));
            if (lib && c) { lib.filters.channels = [c.key]; lib.save(); }
            setMode("library");
          }
        } });
      return h("div", { class: "side-row" }, item, open);
    };

    for (const folder of folders) {
      // a folder that only holds YouTube channels, podcast shows or accounts belongs to their tabs, not to Articles
      if (!folder.article_feeds && folder.other_feeds) continue;
      const children = feeds.filter((f) => f.folder_id === folder.id);
      const unread = children.reduce((n, f) => n + (f.unread || 0), 0);
      const key = `folder-${folder.id}`;
      const wrap = h("div", { class: state.collapsed.has(key) ? "collapsed" : "" });
      const head = sideItem({ label: folder.name, count: unread || "", view: { type: "folder", id: folder.id } });
      const caret = h("span", { class: "caret", text: "▾", title: "Collapse / expand" });
      caret.addEventListener("click", (e) => {
        e.stopPropagation();
        wrap.classList.toggle("collapsed");
        if (wrap.classList.contains("collapsed")) state.collapsed.add(key); else state.collapsed.delete(key);
        store.set("fw-collapsed", [...state.collapsed]);
      });
      head.firstChild.replaceWith(caret);
      if (dnd) makeDropTarget(head, folder.id);
      wrap.append(head, h("div", { class: "children" }, children.map((f) => feedItem(f, true))));
      folderSection.append(wrap);
    }
    const unfiled = feeds.filter((f) => f.folder_id === null);
    for (const f of unfiled) folderSection.append(feedItem(f, false));
    if (!feeds.length) {
      folderSection.append(h("div", { class: "muted", style: { padding: "2px 10px" } }, "No feeds yet — click “+ Add feed”."));
    }
    folderSection.append(unfiledZone);
    side.append(folderSection);
  }

  // ----------------------------------------------------------------- drag & drop (sidebar)
  // Only drags that carry our private type are accepted; text/links dragged in from
  // other pages are ignored, and the feed id is checked against the known feed list.
  const DRAG_TYPE = "application/x-eos-feed";

  function makeDropTarget(el, folderId) {
    const accepts = (e) => Array.from(e.dataTransfer.types || []).includes(DRAG_TYPE);
    el.addEventListener("dragover", (e) => {
      if (!accepts(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
    });
    el.addEventListener("dragenter", (e) => { if (accepts(e)) el.classList.add("drop-target"); });
    el.addEventListener("dragleave", (e) => { if (!el.contains(e.relatedTarget)) el.classList.remove("drop-target"); });
    el.addEventListener("drop", (e) => {
      if (!accepts(e)) return;
      e.preventDefault();
      el.classList.remove("drop-target");
      const feedId = Number.parseInt(e.dataTransfer.getData(DRAG_TYPE), 10);
      moveFeedToFolder(feedId, folderId);
    });
  }

  async function moveFeedToFolder(feedId, folderId) {
    const feed = state.sidebar.feeds.find((f) => f.id === feedId);
    if (!feed || feed.folder_id === folderId) return;
    const body = folderId === null ? { clear_folder: true } : { folder_id: folderId };
    const target = folderId === null ? "Unfiled" : (state.sidebar.folders.find((f) => f.id === folderId) || {}).name;
    if (await guarded(() => api("PATCH", `/feeds/${feedId}`, body), `Moved “${feed.title || feed.url}” to ${target}`)) {
      if (folderId !== null) { state.collapsed.delete(`folder-${folderId}`); store.set("fw-collapsed", [...state.collapsed]); }
      loadSidebar();
    }
  }

  async function loadSidebar() {
    const data = await guarded(() => api("GET", "/sidebar"));
    if (!data) return;
    state.sidebar = data;
    if (state.lastTotal !== null && data.counts.total > state.lastTotal) $("#newBanner").hidden = false;
    state.lastTotal = data.counts.total;
    renderSidebar();
    updateViewTitle();
  }

  async function quickAddFolder() {
    const name = (window.prompt("New folder name") || "").trim();
    if (!name) return;
    if (await guarded(() => api("POST", "/folders", { name }), "Folder created")) loadSidebar();
  }

  async function quickAddTag() {
    const name = (window.prompt("New collection name (e.g. Ransomware)") || "").trim();
    if (!name) return;
    if (await guarded(() => api("POST", "/tags", { name, color: "#6366f1" }), "Collection created")) loadSidebar();
  }

  // ======================================================================= article list
  function viewLabel() {
    const v = state.view;
    const sb = state.sidebar;
    switch (v.type) {
      case "all": return "All articles";
      case "unread": return "Unread";
      case "read": return "Read";
      case "starred": return "Starred";
      case "today": return "Today";
      case "feed": return (sb.feeds.find((f) => f.id === v.id) || (sb.media_feeds || []).find((f) => f.id === v.id) || {}).title || "Feed";
      case "folder": return (sb.folders.find((f) => f.id === v.id) || {}).name || "Folder";
      case "tag": return (sb.tags.find((t) => t.id === v.id) || {}).name || "Collection";
      case "taggroup": return `${v.id} (all collections)`;
      case "ttp": return `${v.id.startsWith("AML.") ? "ATLAS" : "ATT&CK"} technique: ${v.name || ""} (${v.id})`;
      case "entity": return `Mentions: ${v.name || ""}`;
      default: return "";
    }
  }

  function updateViewTitle() {
    $("#viewTitle").textContent = state.q ? `Search: “${state.q}”` : viewLabel();
    $("#feedSettingsBtn").hidden = state.view.type !== "feed" || Boolean(state.q);
    $("#viewCount").textContent = state.total ? `${state.total} article${state.total === 1 ? "" : "s"}` : "";
  }

  /** Read articles are hidden here (they stay in the Read view, Starred and search results). */
  function hidesRead() {
    const t = state.view.type;
    return state.settings.hide_read !== false && !state.q && t !== "read" && t !== "starred";
  }

  /** Does this article still belong in the current list? (Read view: read ones; hide-read views: unread ones.) */
  function belongsHere(a) {
    if (state.view.type === "read" && !state.q) return Boolean(a.is_read);
    if (hidesRead()) return !a.is_read;
    return true;
  }

  function buildQuery(offset) {
    const p = new URLSearchParams();
    const v = state.view;
    if (v.type === "feed") p.set("feed_id", v.id);
    if (v.type === "folder") p.set("folder_id", v.id);
    if (v.type === "tag") p.set("tag_id", v.id);
    if (v.type === "taggroup") p.set("tag_ids", v.ids.join(","));
    if (v.type === "ttp") p.set("technique", v.id);
    if (v.type === "entity") p.set("entity_id", v.id);
    if (v.type === "starred") p.set("starred", "true");
    if (v.type === "read") p.set("read", "true");
    else if (v.type === "unread" || hidesRead()) p.set("unread", "true");
    const now = Math.floor(Date.now() / 1000);
    if (v.type === "today") {
      const start = new Date(); start.setHours(0, 0, 0, 0);
      p.set("since", Math.floor(start.getTime() / 1000));
    } else if ($("#rangeSelect").value === "custom") {
      addRangeParams(p, state.range);
    } else if ($("#rangeSelect").value) {
      p.set("since", now - Number($("#rangeSelect").value));
    }
    if (state.q) p.set("q", state.q);
    p.set("sort", $("#sortSelect").value);
    p.set("limit", state.settings.page_size || 50);
    p.set("offset", offset);
    return p.toString();
  }

  let listSeq = 0;
  let listCtl = null;
  /** Skeleton rows of the same height as articles, for the very first load (later loads keep the old list, dimmed). */
  function listSkeleton(list) {
    if (list.querySelector(".article-item, .empty")) return;
    fill(list, Array.from({ length: 8 }, () => h("div", { class: "skeleton-row", "aria-hidden": "true" },
      h("span", { class: "sk sk-meta" }), h("span", { class: "sk sk-title" }), h("span", { class: "sk sk-line" }))));
  }
  async function loadArticles(append = false) {
    if (append && state.loading) return;            // "Load more" waits; a new view never does
    const mine = append ? listSeq : ++listSeq;      // switching views cancels the older request instead of dropping the new one
    if (!append) {
      if (listCtl) listCtl.abort();
      listCtl = new AbortController();
    }
    const signal = append ? undefined : listCtl.signal;
    state.loading = true;
    const list = $("#articleList");
    list.classList.add("is-loading");
    list.setAttribute("aria-busy", "true");
    if (!append) listSkeleton(list);
    const offset = append ? state.articles.filter(belongsHere).length : 0;
    try {
      const data = await api("GET", `/articles?${buildQuery(offset)}`, undefined, { signal });
      if (mine !== listSeq) return;                 // a newer view or filter won
      state.articles = append ? state.articles.concat(data.items) : data.items;
      state.total = data.total;
      if (!append && state.checked.size) {
        // Keep ticks only on articles that are still listed (e.g. after "Unread only" hides some).
        const listed = new Set(state.articles.map((a) => a.id));
        for (const id of [...state.checked]) if (!listed.has(id)) state.checked.delete(id);
        renderBulkBar();
      }
      if (!append) {
        $("#articleList").scrollTop = 0;
        $("#newBanner").hidden = true;
      }
      renderList();
      updateViewTitle();
    } catch (err) {
      if (err.name !== "AbortError" && mine === listSeq) toast(err.message, true);
    } finally {
      if (mine === listSeq) {
        state.loading = false;
        list.classList.remove("is-loading");
        list.removeAttribute("aria-busy");
      }
    }
  }

  /** The techniques an article names that belong to one of its tactic collections ("ATT&CK: Execution", "ATLAS: Execution"). */
  function ttpsOfTag(tag, ttps) {
    const m = /^(ATT&CK|ATLAS): (.+)$/.exec(tag.name || "");
    if (!m || !ttps || !ttps.length) return [];
    const fw = m[1] === "ATLAS" ? "atlas" : "attack";
    const want = m[2].toLowerCase();
    return ttps.filter((t) => t.framework === fw && (t.tactics || []).some((x) => x.toLowerCase() === want));
  }

  /** The tactic itself, when the article names it directly ("lateral movement", TA0008) - from a.ttp_tactics. */
  function tacticNamed(tag, named) {
    const m = /^(ATT&CK|ATLAS): (.+)$/.exec(tag.name || "");
    if (!m || !named || !named.length) return null;
    const fw = m[1] === "ATLAS" ? "atlas" : "attack";
    return named.find((t) => t.framework === fw && t.name.toLowerCase() === m[2].toLowerCase()) || null;
  }

  /** Click on a tactic tag: the article's techniques of that tactic (click one = every article naming it, ↗ = MITRE's page). */
  function ttpPopover(anchor, tag, ttps, aid, named) {
    const open = document.querySelector(".ttp-pop");
    if (open) { open.remove(); if (open.anchor === anchor) return; }
    const pop = h("div", { class: "ttp-pop", role: "dialog", "aria-label": `Techniques of ${tag.name} named in this article` },
      h("div", { class: "ttp-pop-head" }, h("strong", { text: tag.name }), h("span", { class: "muted small", text: ` · ${ttps.length} technique${ttps.length === 1 ? "" : "s"} named in this article` })),
      named ? h("div", { class: "muted small ttp-pop-named", text: ttps.length
        ? `The article also names the tactic itself (${named.id}).`
        : `The article names the tactic itself (${named.id}) but none of its techniques.` }) : null,
      ttps.map((t) => [h("div", { class: "ttp-pop-row" },
        h("button", { type: "button", class: "ttp-pop-item", title: "Every article that names this technique",
          onclick: (e) => { e.stopPropagation(); pop.remove(); selectView({ type: "ttp", id: t.id, name: t.name }); } },
          h("code", { text: t.id }), h("span", { text: t.name })),
        h("button", { type: "button", class: "ttp-pop-x", title: `About ${t.id}: mentions over time, groups that use it, latest items`, "aria-label": `About ${t.id}`, text: "ⓘ",
          onclick: (e) => { e.stopPropagation(); pop.remove(); window.FW.intel.techniquePage(t.id); } }),
        h("a", { class: "ttp-pop-link", href: safeUrl(t.url), target: "_blank", rel: "noopener noreferrer", title: `Open ${t.id} on MITRE's site`,
          "aria-label": `Open ${t.id} on MITRE's site`, text: "↗", onclick: (e) => e.stopPropagation() }),
        aid ? h("button", { type: "button", class: "ttp-pop-x no", title: "Not this technique? Remove it from this article, or stop matching the name", "aria-label": `${t.id} is wrong for this article`, text: "✕",
          onclick: (e) => { e.stopPropagation(); pop.remove(); notThisTechnique(aid, t); } }) : null),
        (t.subs || []).map((s) => h("div", { class: "ttp-pop-row ttp-pop-sub" },
          h("button", { type: "button", class: "ttp-pop-item", title: "Sub-technique named in this article - click for every article that names it",
            onclick: (e) => { e.stopPropagation(); pop.remove(); selectView({ type: "ttp", id: s.id, name: s.name }); } },
            h("code", { text: `.${String(s.id).split(".").pop()}` }), h("span", { text: s.name })),
          h("button", { type: "button", class: "ttp-pop-x", title: `About ${s.id}`, "aria-label": `About ${s.id}`, text: "ⓘ",
            onclick: (e) => { e.stopPropagation(); pop.remove(); window.FW.intel.techniquePage(s.id); } }),
          h("a", { class: "ttp-pop-link", href: safeUrl(s.url), target: "_blank", rel: "noopener noreferrer", title: `Open ${s.id} on MITRE's site`,
            "aria-label": `Open ${s.id} on MITRE's site`, text: "↗", onclick: (e) => e.stopPropagation() }),
          aid ? h("button", { type: "button", class: "ttp-pop-x no", title: "Not this sub-technique? Remove it from this article (the technique stays)", "aria-label": `${s.id} is wrong for this article`, text: "✕",
            onclick: (e) => { e.stopPropagation(); pop.remove(); notThisTechnique(aid, s); } }) : null))]),
      h("div", { class: "muted small ttp-pop-foot", text: "Click a technique to list every article that names it · ⓘ its page · ✕ wrong match" }));
    pop.anchor = anchor;
    pop.addEventListener("click", (e) => e.stopPropagation());
    document.body.append(pop);
    const r = anchor.getBoundingClientRect();
    const w = pop.offsetWidth, ht = pop.offsetHeight;
    pop.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - w - 8))}px`;
    pop.style.top = `${r.bottom + ht + 8 > window.innerHeight ? Math.max(8, r.top - ht - 4) : r.bottom + 4}px`;
    const close = (e) => {
      if (e.type === "keydown" && e.key !== "Escape") return;
      if (e.type === "click" && (pop.contains(e.target) || anchor.contains(e.target))) return;
      pop.remove();
      document.removeEventListener("click", close); document.removeEventListener("keydown", close); document.removeEventListener("scroll", close, true);
    };
    setTimeout(() => { document.addEventListener("click", close); document.addEventListener("keydown", close); document.addEventListener("scroll", close, true); }, 0);
  }

  /** After "not this technique": drop it from the loaded copies of the article and redraw. */
  function notThisTechnique(aid, t) {
    window.FW.intel.notThis(aid, t, () => {
      for (const a of [findArticle(aid), state.current && state.current.id === aid ? state.current : null]) {
        if (a && a.ttps) a.ttps = a.ttps.filter((x) => x.id !== t.id).map((x) => ({ ...x, subs: (x.subs || []).filter((s) => s.id !== t.id) }));
      }
      renderList();
      renderReader();
    });
  }

  function chip(tag, onRemove, ttps, aid, named) {
    const own = ttpsOfTag(tag, ttps);
    const tactic = tacticNamed(tag, named);
    const isTactic = /^(ATT&CK|ATLAS): /.test(tag.name || "");
    const filed = tag.source !== "rule" ? "Filed manually" : isTactic ? "Filed from the techniques this article names" : "Filed by rule";
    if (!own.length && !tactic) {
      return h("span", { class: "chip", style: { "--chip": safeColor(tag.color) }, title: filed },
        tag.name,
        onRemove ? h("button", { type: "button", "aria-label": `Remove ${tag.name}`, onclick: onRemove, text: "×" }) : null);
    }
    return h("span", { class: "chip has-ttps", style: { "--chip": safeColor(tag.color) } },
      h("button", { type: "button", class: "chip-ttps", "aria-haspopup": "dialog",
        title: own.length
          ? `${filed}. Techniques named in this article:\n${own.map((t) => [`${t.id}  ${t.name}`, ...(t.subs || []).map((s) => `   ${s.id}  ${s.name}`)].join("\n")).join("\n")}\nClick for the list`
          : `${filed}. It names the tactic itself (${tactic.id}), no specific technique.`,
        onclick: (e) => { e.stopPropagation(); ttpPopover(e.currentTarget, tag, own, aid, tactic); } },
        tag.name, h("span", { class: "chip-n", text: `${own.length || "TA"} ▾` })),
      onRemove ? h("button", { type: "button", "aria-label": `Remove ${tag.name}`, onclick: onRemove, text: "×" }) : null);
  }

  /** Tags take a lot of room: by default an item shows a small "🏷️ n" button that unfolds its tags; the tab's
   *  🏷️ Tags toggle shows them on every item. `build` returns the tag elements (called only when they are shown). */
  const tagsOpen = (area) => store.get(`fw-tags-open:${area}`, false) === true;
  function tagFold(area, count, build) {
    if (!count) return null;
    if (tagsOpen(area)) return build(false);
    const body = h("div", { class: "tag-fold-body", hidden: true });
    const btn = h("button", { type: "button", class: "tag-fold-btn", "aria-expanded": "false", title: `Show the ${count} tag${count === 1 ? "" : "s"} of this item`,
      text: `🏷️ ${count} ▸`, onclick: (e) => {
        e.stopPropagation();
        const open = btn.getAttribute("aria-expanded") !== "true";
        btn.setAttribute("aria-expanded", String(open));
        btn.textContent = `🏷️ ${count} ${open ? "▾" : "▸"}`;
        btn.title = open ? "Hide the tags" : `Show the ${count} tag${count === 1 ? "" : "s"} of this item`;
        fill(body, open ? build(true) : null);
        body.hidden = !open;
      } });
    return h("div", { class: "tag-fold" }, btn, body);
  }
  /** The tab's toggle: tags on every item, or folded behind each item's 🏷️ button. */
  function tagsToggle(area, rerender, cls) {
    const on = tagsOpen(area);
    return h("button", { type: "button", class: `${cls || "btn small"}${on ? " primary" : ""}`, "aria-pressed": String(on), text: "🏷️ Tags",
      title: on ? "Tags are shown on every item - click to fold them away" : "Tags are folded behind each item's 🏷️ button - click to show them on every item",
      onclick: () => { store.set(`fw-tags-open:${area}`, !on); rerender(); } });
  }

  /** Techniques that none of the article's tactic tags covers (they get their own chips). */
  function looseTtps(a) {
    return (a.ttps || []).filter((t) => !(a.tags || []).some((tag) => ttpsOfTag(tag, [t]).length));
  }

  /** A technique named in an article (MITRE ATT&CK or ATLAS). Click: every article that names it. */
  function ttpChip(t, count) {
    const tactics = (t.tactics || []).join(", ");
    return h("button", {
      type: "button", class: `chip ttp ${t.framework === "atlas" || String(t.id).startsWith("AML.") ? "atlas" : ""}`,
      title: `${String(t.id).startsWith("AML.") ? "MITRE ATLAS" : "MITRE ATT&CK"} technique ${t.id}${(t.also || []).length ? ` (also ${t.also.join(", ")})` : ""}${tactics ? `\nTactic: ${tactics}` : ""}${(t.subs || []).length ? `\nSub-techniques named: ${t.subs.map((s) => `${s.id} ${s.name}`).join(", ")}` : ""}\nClick: all articles that name it`,
      onclick: (e) => { e.stopPropagation(); selectView({ type: "ttp", id: t.id, name: t.name }); },
    }, h("code", { text: t.id }), t.name, count != null ? h("span", { class: "n", text: String(count) }) : null);
  }

  function ttpRow(ttps, max) {
    if (!ttps || !ttps.length) return null;
    const shown = max ? ttps.slice(0, max) : ttps;
    return h("div", { class: "ttp-row" }, h("span", { class: "ttp-label", text: "Techniques" }), shown.map((t) => ttpChip(t)),
      ttps.length > shown.length ? h("span", { class: "chip ttp-more", title: ttps.slice(shown.length).map((t) => `${t.id} ${t.name}`).join("\n"), text: `+${ttps.length - shown.length}` }) : null);
  }


  /** Above the list of an "ATT&CK: <tactic>" / "ATLAS: <tactic>" collection: that tactic's techniques, most-mentioned first. */
  let ttpStripKey = "";
  async function renderTtpStrip() {
    const strip = $("#ttpStrip");
    if (!strip) return;
    const v = state.view;
    const tag = v.type === "tag" && !state.q ? (state.sidebar.tags || []).find((t) => t.id === v.id) : null;
    const m = tag ? /^(ATT&CK|ATLAS): (.+)$/.exec(tag.name) : null;
    const key = m ? tag.name : "";
    if (key === ttpStripKey) return;
    if (v.type === "ttp" || v.type === "entity") {  // a technique's / entity's own list: its page (and the matrix)
      ttpStripKey = `${v.type}:${v.id}`;
      fill(strip, h("div", { class: "strip-tools" },
        h("button", { type: "button", class: "btn small", text: `ⓘ About ${v.name || v.id}`, title: "Mentions over time, latest items in every tab, what it is seen with",
          onclick: () => (v.type === "ttp" ? window.FW.intel.techniquePage(v.id) : window.FW.intel.entityPage(v.id)) }),
        v.type === "ttp" ? h("button", { type: "button", class: "btn small", text: "▦ Matrix", title: "All techniques by tactic, coloured by how many articles name them",
          onclick: () => window.FW.intel.matrix(String(v.id).startsWith("AML.") ? "atlas" : "attack") }) : null));
      strip.hidden = false;
      return;
    }
    ttpStripKey = key;
    strip.hidden = true;
    fill(strip);
    if (!m) return;
    const fw = m[1] === "ATLAS" ? "atlas" : "attack";
    const data = await api("GET", `/attack/techniques?framework=${fw}&tactic=${encodeURIComponent(m[2])}`).catch(() => null);
    if (ttpStripKey !== key || !data || !data.items.length) return;
    const open = store.get("fw-ttp-strip", true) !== false;
    const box = h("details", { open, ontoggle: (e) => store.set("fw-ttp-strip", e.currentTarget.open) },
      h("summary", { text: `Techniques in ${m[2]} (${data.items.length}) - click one to see every article that names it` }),
      h("div", { class: "chips" }, data.items.map((t) => ttpChip({ ...t, framework: fw }, t.articles)),
        h("button", { type: "button", class: "btn small", text: "▦ Matrix", title: "All techniques by tactic, coloured by how many articles name them",
          onclick: () => window.FW.intel.matrix(fw) })));
    fill(strip, box);
    strip.hidden = false;
  }

  /** "+n sources" under the first article of a story: unfolds the other sources (click one to read it). */
  const storyOpen = new Set();
  const storyCache = new Map();  // story id -> its articles
  function storyFold(a) {
    if (state.settings.story_grouping === false || state.selecting || !a.story_id || (a.story_count || 1) < 2) return null;
    const sid = a.story_id;
    const open = storyOpen.has(sid);
    const n = a.story_count - 1;
    const btn = h("button", { type: "button", class: "story-btn", "aria-expanded": String(open),
      title: open ? "Hide the other sources" : `${n} more source${n === 1 ? "" : "s"} report${n === 1 ? "s" : ""} the same story - click to see them`,
      text: `🧩 +${n} source${n === 1 ? "" : "s"} ${open ? "▾" : "▸"}`,
      onclick: async (e) => {
        e.stopPropagation();
        if (storyOpen.has(sid)) storyOpen.delete(sid);
        else {
          storyOpen.add(sid);
          if (!storyCache.has(sid)) {
            const data = await guarded(() => api("GET", `/articles/${a.id}/story`));
            if (!data) { storyOpen.delete(sid); return; }
            storyCache.set(sid, data.items);
          }
        }
        renderList();
      } });
    if (!open) return h("div", { class: "story-fold" }, btn);
    const others = (storyCache.get(sid) || []).filter((m) => m.id !== a.id);
    const unread = others.filter((m) => !m.is_read).map((m) => m.id).concat(a.is_read ? [] : [a.id]);
    return h("div", { class: "story-fold" }, btn,
      h("div", { class: "story-body" },
        others.map((m) => h("button", { type: "button", class: `story-row${m.is_read ? " read" : ""}${m.id === state.selectedId ? " current" : ""}`, title: "Read this source",
          onclick: (e) => { e.stopPropagation(); if (state.settings.mark_read_on_open) m.is_read = 1; openArticle(m.id); } },
          h("span", { class: "story-meta", text: `${m.feed_title} · ${relTime(m.sort_ts)}` }), h("span", { class: "story-title", text: m.title }))),
        unread.length ? h("div", { class: "story-tools" },
          h("button", { type: "button", class: "btn small", text: `✓ Mark all ${unread.length} read`, title: "Mark every source of this story as read",
            onclick: async (e) => {
              e.stopPropagation();
              const res = await guarded(() => api("POST", "/articles/mark-read", { ids: unread }));
              if (!res) return;
              for (const m of storyCache.get(sid) || []) m.is_read = 1;
              for (const id of unread) patchLocal(id, { is_read: 1 });
              renderList(); renderReader(); loadSidebar();
            } })) : null));
  }

  function siteIcon(feedId, version) {
    const img = h("img", { class: "site-icon", alt: "", width: 16, height: 16, loading: "lazy", decoding: "async",
      src: `/api/v1/feeds/${Number(feedId)}/icon?v=${Number(version) || 0}` });
    img.addEventListener("error", () => img.remove());
    return img;
  }

  function renderList() {
    renderTtpStrip();
    const list = $("#articleList");
    fill(list, );
    if (!state.articles.length) {
      const hasFeeds = state.sidebar.feeds.length > 0;
      list.append(h("div", { class: "empty" },
        h("span", { class: "big", text: hasFeeds ? "✓" : "📡" }),
        hasFeeds ? "Nothing here. You're all caught up." : "Add your first feed to get started."));
    }
    list.classList.toggle("selecting", state.selecting);
    // Same story from several sources: the first one listed leads, the others fold under its "+n sources" button.
    const folded = new Set();
    if (state.settings.story_grouping !== false && !state.selecting) {
      const leads = new Set();
      for (const a of state.articles) {
        if (!a.story_id || (a.story_count || 1) < 2) continue;
        if (leads.has(a.story_id)) { if (a.id !== state.selectedId) folded.add(a.id); } else leads.add(a.story_id);
      }
    }
    for (const a of state.articles) {
      if (folded.has(a.id)) continue;
      const ticked = state.checked.has(a.id);
      const item = h("div", {
        class: `article-item ${a.is_read ? "" : "unread"} ${a.id === state.selectedId ? "selected" : ""} ${ticked ? "checked" : ""}`,
        role: "listitem", tabindex: "0", dataset: { id: a.id },
        onclick: (e) => {
          // In select mode a click ticks; Ctrl/Cmd+click starts select mode from anywhere.
          if (state.selecting || e.ctrlKey || e.metaKey) { e.preventDefault(); toggleChecked(a.id, e.shiftKey); }
          else if (e.shiftKey && state.selectedId) { e.preventDefault(); toggleChecked(state.selectedId, false); toggleChecked(a.id, true); }
          else openArticle(a.id);
        },
        onkeydown: (e) => {
          if (e.key === "Enter") openArticle(a.id);
          else if (e.key === " " && state.selecting) { e.preventDefault(); toggleChecked(a.id, e.shiftKey); }
        },
      },
      state.selecting ? h("input", {
        type: "checkbox", class: "pick", checked: ticked, tabindex: "-1", "aria-label": `Select “${a.title}”`,
        onclick: (e) => { e.stopPropagation(); toggleChecked(a.id, e.shiftKey); },
      }) : null,
      h("div", { class: "meta" },
        state.settings.show_site_icons !== false && a.icon_v ? siteIcon(a.feed_id, a.icon_v) : null,
        h("span", { class: "feed", text: a.feed_title }),
        state.settings.show_reading_time !== false && a.read_minutes ? h("span", { class: "read-time", title: "Reading time", text: `${a.read_minutes} min` }) : null,
        h("span", { class: "time", title: fullDate(a.sort_ts), text: relTime(a.sort_ts) })),
      h("div", { class: "title" }, marked(a.title)),
      state.settings.show_snippets && a.snippet ? h("div", { class: "snippet" }, marked(a.snippet)) : null,
      storyFold(a),
      tagFold("articles", (a.tags || []).length + looseTtps(a).length, (single) => [
        a.tags && a.tags.length ? h("div", { class: "chips" }, a.tags.map((t) => chip(t, null, a.ttps, a.id, a.ttp_tactics))) : null,
        ttpRow(looseTtps(a), single ? 0 : 3)]),
      h("button", {
        type: "button", class: `icon-btn star ${a.is_starred ? "on" : ""}`, title: "Star (s)",
        "aria-label": a.is_starred ? "Unstar" : "Star", text: a.is_starred ? "★" : "☆",
        onclick: (e) => { e.stopPropagation(); toggleStar(a.id); },
      }));
      list.append(item);
    }
    $("#loadMoreBtn").hidden = state.articles.length >= state.total;
  }

  // ======================================================================= multi-select (bulk actions)
  function setSelecting(on) {
    state.selecting = on;
    if (!on) { state.checked.clear(); state.lastChecked = null; }
    const btn = $("#selectModeBtn");
    btn.setAttribute("aria-pressed", String(on));
    btn.classList.toggle("primary", on);
    renderBulkBar();
    renderList();
  }

  /** Tick/untick one article; with ``range`` (Shift) tick everything between the last ticked one and this. */
  function toggleChecked(id, range) {
    if (!state.selecting) { state.selecting = true; $("#selectModeBtn").setAttribute("aria-pressed", "true"); $("#selectModeBtn").classList.add("primary"); }
    const ids = state.articles.map((a) => a.id);
    if (range && state.lastChecked !== null && ids.includes(state.lastChecked)) {
      const [i, j] = [ids.indexOf(state.lastChecked), ids.indexOf(id)].sort((x, y) => x - y);
      for (const x of ids.slice(i, j + 1)) state.checked.add(x);
    } else if (state.checked.has(id)) {
      state.checked.delete(id);
    } else {
      state.checked.add(id);
    }
    state.lastChecked = id;
    renderBulkBar();
    renderList();
  }

  function renderBulkBar() {
    const bar = $("#bulkBar");
    bar.hidden = !state.selecting;
    if (!state.selecting) { fill(bar); return; }
    const n = state.checked.size;
    const none = n === 0;
    const act = (label, title, action) => h("button", { type: "button", class: "btn small", text: label, title, disabled: none, onclick: () => bulkAction(action) });
    const tags = state.sidebar.tags || [];
    const coll = h("select", { "aria-label": "Collections", disabled: none || !tags.length, title: tags.length ? "File in, or remove from, a collection" : "No collections yet" },
      h("option", { value: "", text: "📁 Collection…" }),
      tags.length ? h("optgroup", { label: "Add to" }, tags.map((t) => h("option", { value: `add_tag:${t.id}`, text: t.name }))) : null,
      tags.length ? h("optgroup", { label: "Remove from" }, tags.map((t) => h("option", { value: `remove_tag:${t.id}`, text: t.name }))) : null);
    coll.addEventListener("change", () => {
      const [action, tagId] = coll.value.split(":");
      coll.value = "";
      if (action) bulkAction(action, Number(tagId));
    });
    const allLoaded = state.articles.length > 0 && state.articles.every((a) => state.checked.has(a.id));
    fill(bar,
      h("span", { class: "bulk-count", "aria-live": "polite", text: none ? "Tick articles (Shift+click for a range)" : `${n} selected` }),
      h("button", { type: "button", class: "btn small", text: allLoaded ? "Select none" : `Select all ${state.articles.length}`,
        title: "All articles currently loaded in the list", onclick: () => {
          if (allLoaded) state.checked.clear(); else for (const a of state.articles) state.checked.add(a.id);
          renderBulkBar(); renderList();
        } }),
      h("span", { class: "bulk-sep" }),
      act("✓ Read", "Mark the selected articles as read", "read"),
      act("○ Unread", "Mark the selected articles as unread", "unread"),
      act("★ Star", "Star the selected articles", "star"),
      act("☆ Unstar", "Remove the star from the selected articles", "unstar"),
      coll,
      h("span", { class: "spacer" }),
      h("button", { type: "button", class: "btn small", text: "✕ Done", title: "Leave select mode (Esc)", onclick: () => setSelecting(false) }));
  }

  const BULK_DONE = { read: "marked read", unread: "marked unread", star: "starred", unstar: "unstarred", add_tag: "filed", remove_tag: "removed from the collection" };

  async function bulkAction(action, tagId) {
    const ids = [...state.checked];
    if (!ids.length) return;
    const body = { ids: ids.slice(0, 1000), action };
    if (tagId) body.tag_id = tagId;
    const res = await guarded(() => api("POST", "/articles/bulk", body));
    if (!res) return;
    const changes = { read: { is_read: true }, unread: { is_read: false }, star: { is_starred: true }, unstar: { is_starred: false } }[action];
    if (changes) for (const id of ids) patchLocal(id, changes);
    if (action === "read" || action === "unread") {
      // e.g. marked unread in the Read view: they go back to their feeds/collections and leave this list
      const before = state.articles.length;
      state.articles = state.articles.filter((a) => belongsHere(a) || (state.current && a.id === state.current.id));
      state.total = Math.max(0, state.total - (before - state.articles.length));
      for (const id of ids) if (!findArticle(id)) state.checked.delete(id);
      updateViewTitle();
      renderBulkBar();
    }
    toast(`${ids.length} article${ids.length === 1 ? "" : "s"} ${BULK_DONE[action]}${ids.length > 1000 ? " (first 1,000)" : ""}`);
    if (state.current && ids.includes(state.current.id)) {
      if (changes) renderReader(); else refreshCurrent();
    }
    loadSidebar();
    if (changes) renderList(); else loadArticles();  // collections: reload to show the new chips
  }

  function selectView(view) {
    if (state.selecting) setSelecting(false);
    state.view = view;
    state.q = "";
    $("#search").value = "";
    $("#rangeSelect").disabled = view.type === "today";
    $("#app").classList.remove("show-sidebar", "show-reader"); syncSidebarButton();
    renderSidebar();
    loadArticles();
  }

  // ======================================================================= reader
  function findArticle(id) { return state.articles.find((a) => a.id === id); }

  function patchLocal(id, changes) {
    const a = findArticle(id);
    if (a) Object.assign(a, changes);
    if (state.current && state.current.id === id) Object.assign(state.current, changes);
  }

  async function setRead(id, isRead) {
    const res = await guarded(() => api("PATCH", `/articles/${id}`, { is_read: isRead }));
    if (!res) return;
    patchLocal(id, { is_read: res.is_read });
    renderList();
    if (state.current && state.current.id === id) renderReader();
    loadSidebar();
  }

  async function toggleStar(id) {
    const a = findArticle(id) || state.current;
    if (!a) return;
    const res = await guarded(() => api("PATCH", `/articles/${id}`, { is_starred: !a.is_starred }));
    if (!res) return;
    patchLocal(id, { is_starred: res.is_starred });
    renderList();
    if (state.current && state.current.id === id) renderReader();
    loadSidebar();
  }

  /** Drop the article you just left if it no longer belongs here: read in a hide-read view, or marked unread in
   *  the Read view (it is back in its feeds and collections). It stays on screen while you are reading it. */
  function pruneLeftArticle(nextId) {
    const prev = state.selectedId;
    if (prev == null || prev === nextId) return;
    const a = findArticle(prev);
    if (!a || belongsHere(a)) return;
    state.articles = state.articles.filter((x) => x.id !== prev);
    state.total = Math.max(0, state.total - 1);
    state.checked.delete(prev);
    updateViewTitle();
  }

  let openSeq = 0;
  async function openArticle(id) {
    pruneLeftArticle(id);
    state.selectedId = id;
    renderList();
    const mine = ++openSeq;
    const reader = $("#reader");
    reader.classList.add("is-loading");
    const article = await guarded(() => api("GET", `/articles/${id}`));
    if (mine !== openSeq) return;                   // j / k pressed again: a newer article is on its way
    reader.classList.remove("is-loading");
    if (!article) return;
    state.current = article;
    $("#app").classList.add("show-reader");
    renderReader();
    $("#reader").scrollTop = 0;
    if (!article.is_read && state.settings.mark_read_on_open) setRead(id, true);
    const el = $(`.article-item[data-id="${Number(id)}"]`);
    if (el) el.scrollIntoView({ block: "nearest" });
  }

  async function addTag(articleId, tagId) {
    if (await guarded(() => api("POST", `/articles/${articleId}/tags/${tagId}`), "Filed")) refreshCurrent();
  }

  async function removeTag(articleId, tagId) {
    if (await guarded(() => api("DELETE", `/articles/${articleId}/tags/${tagId}`))) refreshCurrent();
  }

  async function refreshCurrent() {
    if (!state.current) return;
    const article = await guarded(() => api("GET", `/articles/${state.current.id}`));
    if (!article) return;
    state.current = article;
    patchLocal(article.id, { tags: article.tags });
    renderReader();
    renderList();
    loadSidebar();
  }

  /** Settings → Appearance & reading: technique names you muted with "Stop matching … everywhere" (✕ brings one back). */
  async function renderMutedNames() {
    const data = await api("GET", "/attack/muted").catch(() => null);
    const box = $("#mutedNames");
    if (!box || !data) return;
    fill(box, data.items.length ? [
      h("div", { class: "hint", text: "Technique names you told the matcher to ignore - click ✕ to use one again:" }),
      h("div", { class: "muted-names" }, data.items.map((m) => h("span", { class: "chip", title: m.technique_name }, `${m.name} (${m.technique})`,
        h("button", { type: "button", "aria-label": `Use “${m.name}” again`, title: "Use this name again", text: "×",
          onclick: async () => {
            if (await guarded(() => api("POST", "/attack/muted/restore", { technique: m.technique, name: m.name }), "Restored - articles are being re-checked")) renderMutedNames();
          } }))))] : null);
  }

  function renderReader() {
    const reader = $("#reader");
    fill(reader, );
    const a = state.current;
    if (!a) {
      reader.append(h("div", { class: "empty" },
        h("span", { class: "big", text: "📰" }), "Select an article to read.",
        h("p", { class: "muted" }, "Shortcuts: ", h("kbd", { text: "j" }), " / ", h("kbd", { text: "k" }), " next/prev · ",
          h("kbd", { text: "s" }), " star · ", h("kbd", { text: "m" }), " read/unread · ", h("kbd", { text: "o" }), " open original · ",
          h("kbd", { text: "/" }), " search")));
      return;
    }
    const url = safeUrl(a.url);
    const existing = new Set((a.tags || []).map((t) => t.id));
    const tagSelect = h("select", { "aria-label": "File into collection" },
      h("option", { value: "", text: "📁 File into…" }),
      state.sidebar.tags.filter((t) => !existing.has(t.id)).map((t) => h("option", { value: t.id, text: t.name })));
    tagSelect.addEventListener("change", () => { if (tagSelect.value) addTag(a.id, Number(tagSelect.value)); });

    reader.append(
      h("div", { class: "reader-toolbar" },
        h("button", { type: "button", class: "icon-btn back-btn", "aria-label": "Back to list", text: "←", onclick: () => $("#app").classList.remove("show-reader") }),
        h("button", { type: "button", class: "btn", onclick: () => toggleStar(a.id) }, h("span", { class: `star ${a.is_starred ? "on" : ""}`, text: a.is_starred ? "★ " : "☆ " }), a.is_starred ? "Starred" : "Star"),
        h("button", { type: "button", class: "btn", onclick: () => setRead(a.id, !a.is_read), text: a.is_read ? "Mark unread" : "Mark read" }),
        tagSelect,
        h("button", { type: "button", class: "btn", title: "Summarise this article with your AI provider (Settings → AI)", text: "✨ Summarize",
          onclick: () => window.FW.ai && window.FW.ai.summarize(a.id, false) }),
        a.related && a.related.videos ? h("button", { type: "button", class: "btn related-btn", text: `▶ Videos ${a.related.videos}`,
          title: `${a.related.videos} video${a.related.videos === 1 ? "" : "s"} name the same threat actors, malware or techniques as this article`,
          onclick: () => window.FW.intel.related(a, "videos") }) : null,
        a.related && a.related.podcasts ? h("button", { type: "button", class: "btn related-btn", text: `🎙 Podcasts ${a.related.podcasts}`,
          title: `${a.related.podcasts} podcast episode${a.related.podcasts === 1 ? "" : "s"} name the same threat actors, malware or techniques as this article`,
          onclick: () => window.FW.intel.related(a, "podcasts") }) : null,
        a.full_text_possible && a.url && a.fulltext !== 1 ? h("button", { type: "button", class: "btn", title: "Fetch the full article from the site (for feeds that only send a summary)",
          text: "📄 Full article", onclick: () => maybeLoadFullText(a, true) }) : null,
        readLaterMenu(a),
        h("span", { class: "spacer" }),
        url ? h("a", { class: "btn", href: url, target: "_blank", rel: "noopener noreferrer", text: "Open original ↗" }) : null),
      h("article", { class: "reader-inner" },
        h("h1", null, url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, marked(a.title)) : marked(a.title)),
        a.title_original && a.title_original !== a.title ? h("div", { class: "orig-title", title: "Original title (translated by your AI provider)", text: `🌐 ${a.title_original}` }) : null,
        h("div", { class: "byline" },
          h("span", { text: a.feed_title }),
          a.author ? h("span", { text: `by ${a.author}` }) : null,
          h("span", { text: fullDate(a.published || a.fetched_at) }),
          state.settings.show_reading_time !== false && a.read_minutes ? h("span", { text: `${a.read_minutes} min read` }) : null),
        a.tags && a.tags.length ? h("div", { class: "chips" }, a.tags.map((t) => chip(t, () => removeTag(a.id, t.id), a.ttps, a.id, a.ttp_tactics))) : null,
        looseTtps(a).length ? h("div", { class: "ttp-row" }, h("span", { class: "ttp-label", text: "Other techniques named" }),
          looseTtps(a).map((t) => [ttpChip(t), h("a", { class: "chip ttp-link", href: safeUrl(t.url), target: "_blank", rel: "noopener noreferrer",
            title: `Open ${t.id} on MITRE's site`, "aria-label": `Open ${t.id} on MITRE's site`, text: "↗" }),
            h("button", { type: "button", class: "chip ttp-x", title: "Not this technique? Remove it from this article, or stop matching the name",
              "aria-label": `${t.id} is wrong for this article`, text: "✕", onclick: () => notThisTechnique(a.id, t) })])) : null,
        a.entities && a.entities.length ? h("div", { class: "mention-row" }, h("span", { class: "ttp-label", text: "Mentions" }),
          a.entities.map((e) => h("button", { type: "button", class: "chip intel-chip", title: `${e.watchlist} · open its page`, text: e.name,
            onclick: () => window.FW.intel.entityPage(e.id) }))) : null,
        h("div", { id: "aiSummary", class: "ai-summary", hidden: true }),
        h("div", { id: "fullTextNote", class: "fulltext-note", hidden: true }),
        buildContent(a.content_html)));
    if (window.FW.ai) window.FW.ai.loadCached(a.id);
    maybeLoadFullText(a);
  }

  // ----------------------------------------------------------------------- read later (Wallabag / Linkwarden / Obsidian / Markdown)
  let readLater = null;
  async function loadReadLater() {
    try { readLater = await api("GET", "/readlater"); } catch (_) { readLater = { wallabag: false, linkwarden: false, obsidian: null }; }
    if (state.current) renderReader();
  }
  function articleMarkdown(a) {
    const text = ($("#reader .content") || {}).textContent || "";
    const tags = (a.tags || []).map((t) => `#${t.name.replace(/\s+/g, "-")}`).join(" ");
    return [`# ${a.title}`, "", `- Source: ${a.feed_title}`, a.url ? `- Link: ${a.url}` : null,
      `- Published: ${fullDate(a.published || a.fetched_at)}`, tags ? `- Tags: ${tags}` : null, "", text.trim().slice(0, 6000)]
      .filter((l) => l !== null).join("\n");
  }
  function fileName(title) {
    return (title || "article").replace(/[\\/:*?"<>|#^[\]]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 100) || "article";
  }
  function clickHidden(href, download) {
    const link = h("a", { href, download: download || null, hidden: true });
    document.body.append(link);
    link.click();
    link.remove();
  }
  function readLaterMenu(a) {
    const sel = h("select", { class: "readlater", "aria-label": "Save for later", title: "Save this article for later" },
      h("option", { value: "", text: "🔖 Save…" }));
    const rl = readLater || {};
    const url = safeUrl(a.url);
    if (rl.wallabag && url) sel.append(h("option", { value: "wallabag", text: "Wallabag" }));
    if (rl.linkwarden && url) sel.append(h("option", { value: "linkwarden", text: "Linkwarden" }));
    if (rl.obsidian) sel.append(h("option", { value: "obsidian", text: `Obsidian (${rl.obsidian.vault})` }));
    sel.append(h("option", { value: "markdown", text: "Download as Markdown" }));
    sel.addEventListener("change", async () => {
      const choice = sel.value;
      sel.value = "";
      if (choice === "wallabag" || choice === "linkwarden") {
        await guarded(() => api("POST", `/articles/${a.id}/save`, { service: choice }), `Saved to ${choice === "wallabag" ? "Wallabag" : "Linkwarden"}`);
      } else if (choice === "obsidian" && rl.obsidian) {
        const path = [rl.obsidian.folder, fileName(a.title)].filter(Boolean).join("/");
        clickHidden(`obsidian://new?vault=${encodeURIComponent(rl.obsidian.vault)}&file=${encodeURIComponent(path)}&content=${encodeURIComponent(articleMarkdown(a))}`);
      } else if (choice === "markdown") {
        const href = URL.createObjectURL(new Blob([articleMarkdown(a)], { type: "text/markdown" }));
        clickHidden(href, `${fileName(a.title)}.md`);
        setTimeout(() => URL.revokeObjectURL(href), 5000);
      }
    });
    return sel;
  }

  /** Feeds that only publish a summary: fetch the article page once and show the full text (if the site allows). */
  async function maybeLoadFullText(a, force = false) {
    const note = $("#fullTextNote");
    if (!note || !a.full_text_possible || !a.url) return;
    const short = (a.text_length || 0) < 700;
    const auto = a.full_text_mode === "always" || (a.full_text_mode === "auto" && short);
    if (!force && (a.fulltext !== null || !auto)) {
      if (a.fulltext === -1 && short) {
        fill(note, "Only a summary is available here — this site doesn't share its articles with feed readers. ",
          h("button", { type: "button", class: "link-btn", text: "Try again", onclick: () => maybeLoadFullText(a, true) }));
        note.hidden = false;
      }
      return;
    }
    fill(note, "Loading the full article from the site…");
    note.hidden = false;
    let res = null;
    try { res = await api("POST", `/articles/${a.id}/fulltext`, { force }); } catch (err) { res = { ok: false, reason: err.message }; }
    if (!state.current || state.current.id !== a.id) return;  // the reader moved on
    if (res && res.ok) {
      const scroll = $("#reader").scrollTop;
      await refreshCurrent();
      $("#reader").scrollTop = scroll;
      return;
    }
    fill(note, `Only a summary is available — ${res && res.reason ? res.reason : "the full article couldn't be loaded"}. Use “Open original ↗”. `,
      h("button", { type: "button", class: "link-btn", text: "Try again", onclick: () => maybeLoadFullText(a, true) }));
  }

  function buildContent(sanitizedHtml) {
    const div = h("div", { class: "content" });
    // Server-sanitised (allow-list) HTML; parsed in an inert document first.
    const doc = new DOMParser().parseFromString(sanitizedHtml || "", "text/html");
    for (const a of doc.querySelectorAll("a")) {
      if (!safeUrl(a.getAttribute("href")) && !/^mailto:/i.test(a.getAttribute("href") || "")) a.removeAttribute("href");
      a.setAttribute("target", "_blank");
      a.setAttribute("rel", "noopener noreferrer nofollow");
    }
    for (const img of doc.querySelectorAll("img")) {
      const src = img.getAttribute("src") || "";
      // http(s) from the publisher, or our own signed image proxy (Settings → Load images through this server)
      if (!safeUrl(src) && !/^\/api\/v1\/img\?u=[^"'<>\s]+&s=[0-9a-f]{32}$/.test(src)) { img.remove(); continue; }
      img.setAttribute("loading", "lazy");
      img.setAttribute("referrerpolicy", "no-referrer");
    }
    div.append(...doc.body.childNodes);
    highlightTree(div);
    if (!div.childNodes.length) div.append(h("p", { class: "muted", text: "No content in feed — open the original article." }));
    return div;
  }

  // ======================================================================= add feed
  function fillFolderSelect(select, selected) {
    fill(select, h("option", { value: "", text: "— No folder —" }),
      state.sidebar.folders.map((f) => h("option", { value: f.id, text: f.name, selected: f.id === selected })));
  }

  let addFeedPicker = null;
  let addFeedKeep = null;
  const ADD_KEEP = [["", "Default"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["180", "Last 6 months"], ["365", "Last year"],
    ["730", "Last 2 years"], ["1825", "Last 5 years"], ["0", "Everything (keep forever)"]];

  function openAddFeed() {
    const dlg = $("#addFeedDialog");
    $("#addFeedForm").reset();
    $("#addFeedError").textContent = "";
    fillFolderSelect($("#addFeedFolder"), state.view.type === "folder" ? state.view.id : null);
    addFeedPicker = refreshPicker(null, true);
    fill($("#addFeedRefresh"), addFeedPicker.el);
    const g = Number(state.settings.retention_days ?? 90);  // what "Default" means right now
    addFeedKeep = keepPicker({ choices: ADD_KEEP.map(([v, l]) => [v, v === "" ? `Default (global setting: ${fmtRetention(g, true)})` : l]) });
    fill($("#addFeedKeep"), addFeedKeep.el);
    dlg.showModal();
  }

  async function submitAddFeed(e) {
    e.preventDefault();
    const form = e.target;
    const raw = form.url.value.trim();
    const kind = window.FW.sources ? window.FW.sources.detectKind(raw, form.kind.value) : null;
    const body = { url: raw };
    if (form.title.value.trim()) body.title = form.title.value.trim();
    if (form.folder_id.value) body.folder_id = Number(form.folder_id.value);
    const interval = addFeedPicker ? addFeedPicker.value() : null;
    if (Number.isNaN(interval)) { $("#addFeedError").textContent = "Custom interval must be 5–10080 minutes."; return; }
    if (interval !== null) body.refresh_minutes = interval;
    const keepDays = addFeedKeep ? addFeedKeep.days() : null;
    if (Number.isNaN(keepDays)) { $("#addFeedError").textContent = "Custom keep time frame must be 1 day to 100 years."; return; }
    if (keepDays !== null) body.retention_days = keepDays;
    const loadOlder = form.load_older.checked;
    const submitBtn = form.querySelector("button[type=submit]");
    if (kind) {  // YouTube / X / Telegram / HF papers: resolve and preview in the source wizard
      $("#addFeedDialog").close();
      const base = { folder_id: body.folder_id ?? null, retention_days: keepDays, load_older: loadOlder };
      if (interval !== null) base.refresh_minutes = interval;
      window.FW.sources.openSourceWizard(raw, base, { kind });
      return;
    }
    if (raw.startsWith("@")) { $("#addFeedError").textContent = "For an @handle, choose its type (YouTube, X or Telegram)."; return; }
    if (!/^https?:\/\//i.test(raw)) body.url = `https://${raw}`;
    try {
      // Smooth path: if the URL is a normal web page, look for its real feed or offer website scraping.
      submitBtn.disabled = true;
      $("#addFeedError").textContent = "Checking the address…";
      const found = await api("POST", "/scrape/discover", { url: body.url }).catch(() => null);
      $("#addFeedError").textContent = "";
      if (found && !found.is_feed && window.FW.feeds) {
        $("#addFeedDialog").close();
        window.FW.feeds.openScrapeWizard(found, body);
        return;
      }
      const feed = await api("POST", "/feeds", body);
      $("#addFeedDialog").close();
      if (loadOlder && feed && feed.id) {  // older items inside the chosen time frame (in the background)
        await api("POST", `/feeds/${feed.id}/backfill`, { method: "auto", max_pages: 100, ...(keepDays === null ? {} : { keep_days: keepDays }) })
          .then(() => toast("Subscribed — fetching articles, older ones load in the background…"))
          .catch((ex) => toast(`Subscribed. Older articles: ${ex.message}`));
      } else toast("Subscribed — fetching articles…");
      await loadSidebar();
      setTimeout(() => { loadSidebar(); loadArticles(); }, 4000);
    } catch (err) {
      $("#addFeedError").textContent = err.message;
    } finally {
      submitBtn.disabled = false;
    }
  }

  // ======================================================================= settings dialog
  const PANELS = {
    general: ["Appearance & reading", renderGeneralPanel],
    feeds: ["Feeds", renderFeedsPanel],
    organise: ["Folders & collections", renderOrganisePanel],
    rules: ["Rules & auto-filing", renderRulesPanel],
    watchlists: ["Watchlists & entities", (p) => renderWatchlistsPanel(p)],
    cves: ["CVE tracking", (p) => window.FW.cve && window.FW.cve.renderPanel(p)],
    webhooks: ["Webhooks", renderWebhooksPanel],
    api: ["API tokens", renderApiPanel],
    integrations: ["Integrations", (p) => window.FW.sources && window.FW.sources.integrationsPanel(p)],
    ai: ["AI", (p) => window.FW.ai && window.FW.ai.settingsPanel(p)],
    alerting: ["Alerts & digests", (p) => window.FW.ai && window.FW.ai.alertsPanel(p)],
    mobile: ["Mobile apps", (p) => window.FW.feeds && window.FW.feeds.mobilePanel(p)],
    account: ["Account", renderAccountPanel],
    about: ["About", renderAboutPanel],
  };
  let activePanel = "general";

  function openSettings(panel = "general") {
    activePanel = panel;
    const nav = $("#settingsNav");
    fill(nav, ...Object.entries(PANELS).map(([key, [label]]) =>
      h("button", { type: "button", class: key === activePanel ? "active" : "", text: label, onclick: () => openSettings(key) })));
    $("#settingsTitle").textContent = PANELS[activePanel][0];
    const dlg = $("#settingsDialog");
    if (!dlg.open) dlg.showModal();
    PANELS[activePanel][1]($("#settingsPanel"));
  }

  const rerender = () => openSettings(activePanel);

  async function saveSetting(key, value) {
    const res = await guarded(() => api("PATCH", "/settings", { [key]: value }), "Saved");
    if (res) {
      state.settings = res;
      applySettings();
      if (key === "hide_read" || key === "story_grouping" || key === "story_match") loadArticles();
      if (key === "entity_chips" || key === "related_media" || key === "image_proxy" || key === "load_images") refreshCurrent();
      renderList();
      renderSidebar();
    }
  }

  function settingRow(label, control, hint) {
    return [h("label", { text: label, for: control.id || null }), control, hint ? h("div", { class: "hint", text: hint }) : null];
  }

  function selectControl(key, options) {
    const sel = h("select", { id: `set-${key}` }, options.map(([v, l]) => h("option", { value: v, text: l, selected: String(state.settings[key]) === String(v) })));
    sel.addEventListener("change", () => {
      const raw = sel.value;
      saveSetting(key, /^\d+$/.test(raw) ? Number(raw) : raw);
    });
    return sel;
  }

  function checkControl(key) {
    const cb = h("input", { type: "checkbox", id: `set-${key}`, checked: state.settings[key] });
    cb.addEventListener("change", () => saveSetting(key, cb.checked));
    return cb;
  }

  function numberControl(key, min, max) {
    const inp = h("input", { type: "number", id: `set-${key}`, min, max, value: state.settings[key] });
    inp.addEventListener("change", () => {
      const n = Number(inp.value);
      if (Number.isInteger(n)) saveSetting(key, n);
    });
    return inp;
  }

  function highlightControl() {
    const box = h("textarea", { id: "set-highlight_terms", rows: 4, maxlength: 3200, spellcheck: "false", placeholder: "Acme Corp\nFortiGate\nour-domain.com" });
    box.value = (state.settings.highlight_terms || []).join("\n");
    box.addEventListener("change", async () => {
      const terms = box.value.split("\n").map((s) => s.trim()).filter((s) => s.length >= 2).slice(0, 50);
      await saveSetting("highlight_terms", terms);
      if (state.current) renderReader();
    });
    return box;
  }

  /** The user's highlight words as one regex (escaped; longest first), cached until the list changes. */
  let hlCache = { key: null, re: null };
  function highlightRegex() {
    const terms = (state.settings.highlight_terms || []).filter((s) => typeof s === "string" && s.length >= 2);
    const key = terms.join("\u0000");
    if (hlCache.key !== key) {
      const esc = terms.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).sort((a, b) => b.length - a.length);
      hlCache = { key, re: esc.length ? new RegExp(`(${esc.join("|")})`, "gi") : null };
    }
    return hlCache.re;
  }
  /** Text with highlight words wrapped in <mark> elements (built as nodes - never HTML). */
  function marked(text) {
    const re = highlightRegex();
    if (!re || !text) return text;
    const s = String(text);
    const out = [];
    let last = 0;
    for (const m of s.matchAll(re)) {
      if (m.index > last) out.push(s.slice(last, m.index));
      out.push(h("mark", { class: "hl", text: m[0] }));
      last = m.index + m[0].length;
    }
    if (!out.length) return s;
    if (last < s.length) out.push(s.slice(last));
    return out;
  }
  function highlightTree(root) {
    const re = highlightRegex();
    if (!re) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) { re.lastIndex = 0; if (re.test(walker.currentNode.nodeValue)) nodes.push(walker.currentNode); }
    for (const node of nodes) {
      const parts = marked(node.nodeValue);
      if (Array.isArray(parts)) node.replaceWith(...parts.map((x) => (x instanceof Node ? x : document.createTextNode(x))));
    }
  }

  function defaultIntervalControl() {
    const picker = refreshPicker(state.settings.default_refresh_minutes, false, "Default refresh interval");
    const save = () => {
      const v = picker.value();
      if (Number.isNaN(v) || v === null) return;
      saveSetting("default_refresh_minutes", v);
    };
    picker.select.addEventListener("change", () => { if (picker.select.value !== "custom") save(); });
    picker.custom.addEventListener("change", save);
    return picker.el;
  }

  function bulkIntervalBar(onDone) {
    const scope = h("select", { "aria-label": "Apply to" },
      h("option", { value: "all", text: "All feeds" }),
      h("option", { value: "unfiled", text: "Unfiled feeds" }),
      state.sidebar.folders.map((f) => h("option", { value: `folder:${f.id}`, text: `Folder: ${f.name}` })));
    const picker = refreshPicker(null, true, "Interval to apply");
    const apply = async () => {
      const minutes = picker.value();
      if (Number.isNaN(minutes)) { toast("Custom interval must be 5–10080 minutes", true); return; }
      const [kind, id] = scope.value.split(":");
      const body = { scope: kind, refresh_minutes: minutes };
      if (kind === "folder") body.folder_id = Number(id);
      const res = await guarded(() => api("POST", "/feeds/bulk-interval", body));
      if (res) { toast(`Updated ${res.updated} feed(s)`); onDone(); }
    };
    return h("div", { class: "row-form card" },
      h("strong", { text: "Set refresh interval for" }), scope, h("span", { text: "to" }), picker.el,
      h("button", { type: "button", class: "btn", text: "Apply", onclick: apply }));
  }

  function renderGeneralPanel(panel) {
    const color = h("input", { type: "color", id: "set-accent_color", value: safeColor(state.settings.accent_color) });
    color.addEventListener("change", () => saveSetting("accent_color", color.value));
    fill(panel, 
      h("div", { class: "panel-section" }, h("h4", { text: "Appearance" }),
        h("div", { class: "grid-form" },
          settingRow("Theme", selectControl("theme", [["system", "Follow system"], ["dark", "Dark"], ["light", "Light"]])),
          settingRow("Accent colour", color),
          settingRow("Layout", selectControl("layout", [["three-pane", "Three panes (list + reader)"], ["list", "List only (reader replaces list)"]])),
          settingRow("Density", selectControl("density", [["comfortable", "Comfortable"], ["compact", "Compact"]])),
          settingRow("Text size", selectControl("font_size", [["small", "Small"], ["medium", "Medium"], ["large", "Large"]])),
          settingRow("Show snippets in list", checkControl("show_snippets")),
          settingRow("Order of the tabs at the top", h("button", { type: "button", class: "btn small", text: "⇄ Arrange tabs…", onclick: () => openArrangeTabs() }),
            "Or drag a tab left or right at the top (Alt+Shift+← / → moves the focused tab)."),
          settingRow("Drag feeds between folders in the sidebar", checkControl("sidebar_drag_drop"), "Drag a feed onto a folder to move it. Turn off if it gets in the way — folders can still be changed under Settings → Feeds."))),
      h("div", { class: "panel-section" }, h("h4", { text: "Reading" }),
        h("div", { class: "grid-form" },
          settingRow("Start view", selectControl("default_view", [["unread", "Unread"], ["read", "Read"], ["all", "All articles"], ["starred", "Starred"], ["today", "Today"]])),
          settingRow("Default sort", selectControl("sort", [["newest", "Newest first"], ["oldest", "Oldest first"]])),
          settingRow("Articles per page", numberControl("page_size", 10, 200)),
          settingRow("Mark read when opened", checkControl("mark_read_on_open")),
          settingRow("Hide watched videos", checkControl("hide_watched"), "Watched videos leave Videos (By topic and Grid) and wait in the ✓ Watched tab; mark one unwatched to bring it back."),
          settingRow("Hide read articles", checkControl("hide_read"), "Read articles leave your feeds, folders and collections and are kept in the Read view (Starred and search still show them)."),
          settingRow("Load remote images", checkControl("load_images"), "Show the pictures in articles. Turn off for text only."),
          settingRow("Load images through this server", checkControl("image_proxy"), "Article pictures are fetched by Eye of Sauron and passed on, so publishers and their trackers see the server, not your device or IP address."),
          settingRow("Show reading time", checkControl("show_reading_time"), "“4 min” next to each article in the list (about 200 words a minute)."),
          settingRow("Show site icons", checkControl("show_site_icons"), "Each site's little logo in front of its name in the list. Icons are fetched once in the background and kept on the server."),
          settingRow("Highlight these words", highlightControl(), "One word or phrase per line (up to 50) — your company, products, suppliers, people. They are marked in the article list and the reader."))),
      h("div", { class: "panel-section" }, h("h4", { text: "Smart features" }),
        h("div", { class: "grid-form" },
          settingRow("Group articles about the same story", checkControl("story_grouping"), "When several sources report the same story, the list shows one article with a 🧩 +n sources button for the others."),
          settingRow("How alike titles must be", selectControl("story_match", [["strict", "Strict (nearly identical)"], ["normal", "Normal"], ["loose", "Loose (groups more)"]]), "Changing this regroups your stored articles in the background (a minute or two)."),
          settingRow("Related videos and podcasts in the reader", checkControl("related_media"), "▶ Videos and 🎙 Podcasts buttons on an article: the videos and episodes that name the same threat actors, malware or techniques."),
          settingRow("Show who and what an article mentions", checkControl("entity_chips"), "Chips in the reader for threat actors, malware, vendors, countries… Click one for its page: mentions over time and the latest items in every tab."),
          settingRow("Recognise techniques by everyday terms", checkControl("ttp_everyday_terms"), "Also tag ATT&CK techniques from the words news really uses (DDoS, ClickFix, MFA fatigue, supply chain attack). Off = official MITRE names and IDs only."),
          settingRow("Period for the matrix and entity pages", selectControl("matrix_days", [[7, "Last 7 days"], [30, "Last 30 days"], [90, "Last 90 days"], [365, "Last year"], [0, "All time"]]), "The ▦ matrix (next to ATT&CK / ATLAS in the sidebar) and the pages it opens count articles from this period. You can also change it on the matrix or a page; both always use the same one.")),
        h("div", { id: "mutedNames" })),
      h("div", { class: "panel-section" }, h("h4", { text: "Updates & storage" }),
        h("div", { class: "grid-form" },
          settingRow("Default refresh interval", defaultIntervalControl(), "Feeds without their own interval use this (5 minutes to 7 days). Failing feeds back off automatically."),
          settingRow("Check quiet feeds less often", checkControl("adaptive_refresh"), "Feeds that use the default interval learn their own pace: one that posts every few days is checked every few hours (at most every 12 hours), never more often than the default. Feeds with their own interval keep it."),
          settingRow("Keep articles for (days)", numberControl("retention_days", 0, 3650), "0 = keep forever. Starred and manually-filed articles are always kept. Each feed can override this (⚙ next to the feed); feeds whose history you loaded keep everything."),
          settingRow("Keep feeds", h("button", { type: "button", class: "btn small", text: "🗓️ Keep feeds…", onclick: () => FW.feedtools.openKeepFeeds({ type: "all" }) }), "How far back feeds keep items — article feeds, podcasts, YouTube or accounts, or all together — with a count before anything is removed, and an option to fetch older items back to that date."),
          settingRow("Max articles per feed", numberControl("max_articles_per_feed", 0, 100000), "0 = unlimited."))),
    );
    renderMutedNames();
  }

  async function renderFeedsPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const feeds = await guarded(() => api("GET", "/feeds"));
    if (!feeds) return;
    const fileInput = h("input", { type: "file", accept: ".opml,.xml,text/xml,application/xml", hidden: true });
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files[0];
      if (!file) return;
      if (file.size > 5 * 1024 * 1024) { toast("OPML file too large (max 5 MB)", true); return; }
      const text = await file.text();
      const res = await guarded(() => api("POST", "/opml/import", text, { raw: true, contentType: "text/xml" }));
      if (res) {
        const t = res.by_type || {};
        const parts = [["articles", "article feeds"], ["podcasts", "podcasts"], ["videos", "YouTube channels"], ["accounts", "accounts"]]
          .filter(([k]) => t[k]).map(([k, label]) => `${t[k]} ${label}`);
        toast(`Imported ${res.added} feeds${parts.length ? ` (${parts.join(", ")})` : ""} · ${res.skipped} already present` +
          `${res.updated ? ` (${res.updated} moved to the right tab)` : ""}${res.invalid ? ` · ${res.invalid} invalid` : ""}`);
        await loadSidebar();
        rerender();
      }
    });

    const onChanged = async (soft) => { await loadSidebar(); if (!soft) { loadArticles(); rerender(); } };

    fill(panel, 
      h("div", { class: "panel-section" },
        h("div", { class: "row-form" },
          h("button", { type: "button", class: "btn primary", text: "+ Add feed", onclick: () => { $("#settingsDialog").close(); openAddFeed(); } }),
          h("button", { type: "button", class: "btn", text: "⟳ Refresh all", onclick: refreshAll }),
          h("button", { type: "button", class: "btn", text: "Import OPML", onclick: () => fileInput.click() }),
          h("button", { type: "button", class: "btn", text: "Export OPML", onclick: exportOpml }),
          fileInput)),
      feeds.length ? bulkIntervalBar(rerender) : null,
      feeds.length
        ? window.FW.feedtools.manager(feeds, onChanged)
        : h("p", { class: "muted", text: "No feeds yet. Add one, or import an OPML file (a starter list of security feeds ships in examples/)." }),
    );
  }

  async function exportOpml() {
    const blob = await guarded(() => api("GET", "/opml/export", undefined, { blob: true }));
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: "eye-of-sauron.opml" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function renderOrganisePanel(panel) {
    const { folders, tags } = state.sidebar;
    const newFolder = h("input", { type: "text", maxlength: 100, placeholder: "New folder name" });
    const newTag = h("input", { type: "text", maxlength: 100, placeholder: "New collection, e.g. Ransomware" });
    const newColor = h("input", { type: "color", value: "#6366f1", "aria-label": "Colour" });

    const after = async () => { await loadSidebar(); rerender(); };

    // ---- colour several collections at once: tick them (or pick a group), choose a colour, apply
    const bulkBoxes = new Map();   // tag id -> its checkbox
    const bulkColor = h("input", { type: "color", value: "#6366f1", "aria-label": "Colour for the selected collections" });
    const bulkApply = h("button", { type: "button", class: "btn small primary", text: "Apply to 0 selected", disabled: true, onclick: async () => {
      const ids = [...bulkBoxes].filter(([, box]) => box.checked).map(([id]) => id);
      if (!ids.length) return;
      const res = await guarded(() => api("POST", "/tags/colors", { ids, color: bulkColor.value }));
      if (res) { toast(`Colour changed for ${res.updated} collection${res.updated === 1 ? "" : "s"}`); after(); }
    } });
    function bulkCount() {
      const n = [...bulkBoxes.values()].filter((box) => box.checked).length;
      bulkApply.textContent = `Apply to ${n} selected`;
      bulkApply.disabled = !n;
    }
    const groupOf = (t) => (t.name.includes(": ") ? t.name.split(": ")[0] : "");
    const groupNames = [...new Set(tags.map(groupOf).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const bulkGroup = h("select", { "aria-label": "Select a group of collections", title: "Tick every collection of a group" },
      h("option", { value: "", text: "Select a group…" }), h("option", { value: "*", text: `All collections (${tags.length})` }),
      groupNames.map((g) => h("option", { value: g, text: `${g} (${tags.filter((t) => groupOf(t) === g).length})` })),
      tags.some((t) => !groupOf(t)) ? h("option", { value: "-", text: `Without a group (${tags.filter((t) => !groupOf(t)).length})` }) : null);
    bulkGroup.addEventListener("change", () => {
      const g = bulkGroup.value;
      if (!g) return;
      for (const t of tags) if (g === "*" || (g === "-" ? !groupOf(t) : groupOf(t) === g)) bulkBoxes.get(t.id).checked = true;
      bulkGroup.value = "";
      bulkCount();
    });
    const bulkBar = h("div", { class: "row-form bulk-colors", style: { "margin-top": "10px" } },
      h("strong", { class: "small", text: "Colour several at once:" }), bulkGroup,
      h("button", { type: "button", class: "btn small", text: "Clear", title: "Untick every collection", onclick: () => { for (const box of bulkBoxes.values()) box.checked = false; bulkCount(); } }),
      bulkColor, bulkApply,
      h("span", { class: "muted small", text: "Tick collections below or pick a group, choose a colour, then Apply." }));

    fill(panel, 
      h("div", { class: "panel-section" }, h("h4", { text: "Folders (group your feeds)" }),
        h("form", { class: "row-form", onsubmit: async (e) => {
          e.preventDefault();
          if (newFolder.value.trim() && await guarded(() => api("POST", "/folders", { name: newFolder.value.trim() }), "Folder created")) after();
        } }, newFolder, h("button", { type: "submit", class: "btn primary", text: "Add" })),
        h("div", { style: { "margin-top": "10px" } }, folders.map((f) => {
          const name = h("input", { type: "text", value: f.name, maxlength: 100, "aria-label": "Folder name" });
          return h("div", { class: "row-form", style: { "margin-bottom": "6px" } }, name,
            h("button", { type: "button", class: "btn small", text: "Rename", onclick: async () => {
              if (await guarded(() => api("PATCH", `/folders/${f.id}`, { name: name.value.trim() }), "Renamed")) after();
            } }),
            h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
              if (window.confirm(`Delete folder “${f.name}”? Its feeds are kept (unfiled).`) && await guarded(() => api("DELETE", `/folders/${f.id}`), "Deleted")) after();
            } }));
        }))),
      h("div", { class: "panel-section" }, h("h4", { text: "Collections (categorise articles: Ransomware, Advisories, APT…)" }),
        h("form", { class: "row-form", onsubmit: async (e) => {
          e.preventDefault();
          if (newTag.value.trim() && await guarded(() => api("POST", "/tags", { name: newTag.value.trim(), color: newColor.value }), "Collection created")) after();
        } }, newColor, newTag, h("button", { type: "submit", class: "btn primary", text: "Add" })),
        bulkBar,
        h("div", { style: { "margin-top": "10px" } }, tags.map((t) => {
          const name = h("input", { type: "text", value: t.name, maxlength: 100, "aria-label": "Collection name" });
          const color = h("input", { type: "color", value: safeColor(t.color), "aria-label": "Colour" });
          const pick = h("input", { type: "checkbox", "aria-label": `Select ${t.name} for a colour change`, title: "Select for “Colour several at once”", onchange: bulkCount });
          bulkBoxes.set(t.id, pick);
          return h("div", { class: "row-form", style: { "margin-bottom": "6px" } }, pick, color, name,
            h("span", { class: "muted", text: `${t.total} articles` }),
            h("button", { type: "button", class: "btn small", text: "Save", onclick: async () => {
              if (await guarded(() => api("PATCH", `/tags/${t.id}`, { name: name.value.trim(), color: color.value }), "Saved")) after();
            } }),
            h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
              if (window.confirm(`Delete collection “${t.name}”? Articles are not deleted.`) && await guarded(() => api("DELETE", `/tags/${t.id}`), "Deleted")) after();
            } }));
        }))),
    );
  }

  const splitKeywords = (s) => s.split(",").map((k) => k.trim()).filter(Boolean).slice(0, 100);

  /** Ready-made collection packs: tick, install; new rules are back-filled over stored articles in the background. */
  async function packsCard() {
    const data = await api("GET", "/rules/packs").catch(() => null);
    if (!data) return null;
    const boxes = [];
    const rows = data.packs.map((p) => {
      const total = p.collections.length;
      const state = !p.installed ? "Not installed"
        : p.installed < total ? `${p.installed} of ${total} installed`
          : p.rules_missing ? `Installed · ${p.rules_missing} new rule(s) to add` : "✓ Installed";
      const id = `pack-${p.slug}`;
      const box = h("input", { type: "checkbox", id, value: p.slug, "aria-label": p.title });
      boxes.push(box);
      return h("div", { class: `pack-row ${p.installed === total && !p.rules_missing ? "done" : ""}` }, box,
        h("div", null,
          h("label", { for: id }, h("strong", { text: p.title }), h("span", { class: "muted small", text: ` · ${total} collections · ${state}` })),
          h("div", { class: "muted small", text: p.description }),
          h("details", null, h("summary", { class: "small", text: "Show collections" }), h("div", { class: "small pack-list", text: p.collections.join(" · ") }))));
    });
    const picked = () => boxes.filter((b) => b.checked).map((b) => b.value);
    const status = h("p", { class: "muted small", text: data.backfill && data.backfill.running ? "⏳ Filing existing articles into the new collections…" : "" });
    const install = h("button", { type: "button", class: "btn primary", text: "Install / update selected", onclick: async () => {
      const slugs = picked();
      if (!slugs.length) { toast("Tick at least one pack", true); return; }
      const res = await guarded(() => api("POST", "/rules/packs", { slugs }));
      if (!res) return;
      toast(res.rules_created ? `Added ${res.collections_created} collections and ${res.rules_created} rules${res.backfill_started ? " - filing existing articles in the background" : ""}`
        : "Already up to date - nothing to add");
      await loadSidebar(); rerender();
    } });
    const remove = h("button", { type: "button", class: "btn danger", text: "Remove selected", onclick: async () => {
      const slugs = picked();
      if (!slugs.length) { toast("Tick at least one pack", true); return; }
      const names = data.packs.filter((p) => slugs.includes(p.slug)).map((p) => p.title).join(", ");
      if (!window.confirm(`Remove ${names}?\n\nIts collections and their rules are deleted. Articles stay, but they are no longer filed in those collections (manual filings too).`)) return;
      const res = await guarded(() => api("POST", "/rules/packs/remove", { slugs }));
      if (!res) return;
      toast(`Removed ${res.collections_removed} collections and ${res.rules_removed} rules`);
      await loadSidebar(); rerender();
    } });
    const all = h("button", { type: "button", class: "btn small", text: "Select all", onclick: () => { const on = boxes.some((b) => !b.checked); boxes.forEach((b) => { b.checked = on; }); all.textContent = on ? "Select none" : "Select all"; } });
    return h("div", { class: "card packs-card" },
      h("div", { class: "card-head" }, h("strong", { text: "Ready-made collections" }), h("div", { class: "actions" }, all, remove, install)),
      h("p", { class: "muted small", text: "Tick packs, then install them (or update them with rules added in newer versions) or remove them. Installing never overwrites collections or rules you edited. After installing, existing articles are filed too (a minute or two)." }),
      h("div", { class: "pack-grid" }, rows), status);
  }

  async function renderRulesPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const [rules, hooks, alertChannels] = await Promise.all([guarded(() => api("GET", "/rules")), guarded(() => api("GET", "/webhooks")),
      api("GET", "/delivery-channels").catch(() => [])]);
    if (!rules) return;
    const { feeds, folders, tags } = state.sidebar;
    const cveCats = (((await api("GET", "/cves/meta").catch(() => null)) || {}).categories || []).filter((c) => c.enabled);
    const cveCatName = (slug) => ({ kev: "Actively exploited (CISA KEV)", "kev-ransomware": "Used by ransomware (CISA KEV)" })[slug]
      || (cveCats.find((c) => c.slug === slug) || {}).name || slug;
    const nameOf = (list, id, key = "name") => (list.find((x) => x.id === id) || {})[key] || "?";

    function editor(rule) {
      const r = rule || { name: "", keywords: [], exclude_keywords: [], require_keywords: [], cve_severity: null, cve_owasp: null, cve_category: null, keywords_in_title: false, match_in: "title_content", feed_id: null, folder_id: null, tag_id: null, webhook_id: null, social_channel_id: null, alert_channel_id: null, ai_summarize: false, star: false, mark_read: false, enabled: true };
      const f = {
        name: h("input", { type: "text", maxlength: 100, value: r.name, required: true }),
        keywords: h("input", { type: "text", value: r.keywords.join(", "), placeholder: "lockbit, ransomware, extortion (empty = everything in “Apply to”)" }),
        require: h("input", { type: "text", value: (r.require_keywords || []).join(", "), placeholder: "optional, e.g. attack, breach, compromise" }),
        inTitle: h("input", { type: "checkbox", checked: Boolean(r.keywords_in_title) }),
        cve: h("select", null, h("option", { value: "", text: "— no CVE condition —" }),
          h("optgroup", { label: "Names a CVE with severity" }, ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => h("option", { value: `sev:${v}`, text: v[0] + v.slice(1).toLowerCase(), selected: r.cve_severity === v }))),
          ["2025", "2021"].map((ed) => h("optgroup", { label: `Names a CVE in OWASP Top 10 ${ed}` },
            Array.from({ length: 10 }, (_, i) => `A${String(i + 1).padStart(2, "0")}`).map((code) => h("option", { value: `owasp:${ed}:${code}`, text: `${code} (${ed})`, selected: r.cve_owasp === `${ed}:${code}` })))),
          h("optgroup", { label: "Names a CVE that is…" }, ["kev", "kev-ransomware"].map((s) => h("option", { value: `cat:${s}`, text: cveCatName(s), selected: r.cve_category === s }))),
          h("optgroup", { label: "Names a CVE in the CVE category" }, cveCats.map((c) => h("option", { value: `cat:${c.slug}`, text: c.name, selected: r.cve_category === c.slug })))),
        exclude: h("input", { type: "text", value: r.exclude_keywords.join(", "), placeholder: "optional, e.g. webinar, sponsored" }),
        match: h("select", null, h("option", { value: "title_content", text: "Title and content", selected: r.match_in === "title_content" }), h("option", { value: "title", text: "Title only", selected: r.match_in === "title" })),
        scope: h("select", null, h("option", { value: "", text: "All feeds" }),
          h("optgroup", { label: "Folder" }, folders.map((x) => h("option", { value: `folder:${x.id}`, text: x.name, selected: r.folder_id === x.id }))),
          h("optgroup", { label: "Feed" }, feeds.map((x) => h("option", { value: `feed:${x.id}`, text: x.title, selected: r.feed_id === x.id })))),
        tag: h("select", null, h("option", { value: "", text: "— none —" }), tags.map((x) => h("option", { value: x.id, text: x.name, selected: r.tag_id === x.id }))),
        hook: h("select", null, h("option", { value: "", text: "— none —" }), (hooks || []).map((x) => h("option", { value: x.id, text: x.name, selected: r.webhook_id === x.id }))),
        alert: h("select", null, h("option", { value: "", text: "— none —" }), (alertChannels || []).map((x) => h("option", { value: x.id, text: `${x.name} (${x.kind})`, selected: r.alert_channel_id === x.id }))),
        summarize: h("input", { type: "checkbox", checked: r.ai_summarize }),
        star: h("input", { type: "checkbox", checked: r.star }),
        read: h("input", { type: "checkbox", checked: r.mark_read }),
        enabled: h("input", { type: "checkbox", checked: r.enabled }),
      };
      const err = h("p", { class: "error" });
      const form = h("form", { class: "card" },
        h("div", { class: "grid-form" },
          settingRow("Rule name", f.name),
          settingRow("Match any of (comma-separated)", f.keywords, "Whole-word, case-insensitive literal matching. Leave empty to match every article in “Apply to” (or every article meeting the CVE condition)."),
          settingRow("Main words must be in the title", f.inTitle, "Keeps a collection focused: e.g. “OT” must be in the headline, while the second list may match anywhere in the article."),
          settingRow("…and also one of", f.require, "Optional second list: the article must contain one word from each list, e.g. OT terms AND attack terms."),
          settingRow("CVE condition", f.cve, "Only articles that name a CVE (CVE-YYYY-NNNN) with this severity, whose weakness (CWE) maps to this OWASP category, that is in CISA KEV, or that falls in this CVE category (Settings → CVE tracking). Uses the CVE data from the CVE tab."),
          settingRow("…but not if it contains", f.exclude),
          settingRow("Search in", f.match),
          settingRow("Apply to", f.scope),
          settingRow("File into collection", f.tag),
          settingRow("Send to webhook", f.hook),
          settingRow("Instant alert to", f.alert, "Sends each new matching article to this channel (Settings → Alerts & digests). Several matches at once are combined."),
          settingRow("AI summary", f.summarize, "Summarise each new matching article with the AI provider (Settings → AI). Included in the alert when both are set."),
          settingRow("Star it", f.star),
          settingRow("Mark as read (mute)", f.read),
          settingRow("Enabled", f.enabled)),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: rerender }),
          h("button", { type: "submit", class: "btn primary", text: rule ? "Save rule" : "Create rule" })));
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const [scopeType, scopeId] = f.scope.value.split(":");
        const body = {
          name: f.name.value.trim(), keywords: splitKeywords(f.keywords.value), exclude_keywords: splitKeywords(f.exclude.value),
          require_keywords: splitKeywords(f.require.value),
          keywords_in_title: f.inTitle.checked,
          cve_severity: f.cve.value.startsWith("sev:") ? f.cve.value.slice(4) : null,
          cve_owasp: f.cve.value.startsWith("owasp:") ? f.cve.value.slice(6) : null,
          cve_category: f.cve.value.startsWith("cat:") ? f.cve.value.slice(4) : null,
          match_in: f.match.value,
          feed_id: scopeType === "feed" ? Number(scopeId) : null,
          folder_id: scopeType === "folder" ? Number(scopeId) : null,
          tag_id: f.tag.value ? Number(f.tag.value) : null,
          webhook_id: f.hook.value ? Number(f.hook.value) : null,
          alert_channel_id: f.alert.value ? Number(f.alert.value) : null,
          ai_summarize: f.summarize.checked,
          star: f.star.checked, mark_read: f.read.checked, enabled: f.enabled.checked,
        };
        try {
          await api(rule ? "PUT" : "POST", rule ? `/rules/${rule.id}` : "/rules", body);
          toast("Rule saved — applies to new articles. Use “Apply to existing” to back-fill.");
          rerender();
        } catch (ex) { err.textContent = ex.message; }
      });
      return form;
    }

    const list = h("div");
    const cards = rules.map((r) => h("div", { class: "card", "data-search": `${r.name} ${r.keywords.join(" ")} ${nameOf(tags, r.tag_id)}`.toLowerCase() },
      h("div", { class: "card-head" },
        h("strong", { text: `${r.enabled ? "" : "⏸ "}${r.name}` }),
        h("div", { class: "actions" },
          h("button", { type: "button", class: "btn small", text: "Edit", onclick: (e) => e.target.closest(".card").replaceWith(editor(r)) }),
          h("button", { type: "button", class: "btn small", text: "Apply to existing", onclick: async () => {
            const res = await guarded(() => api("POST", `/rules/${r.id}/apply`));
            if (res) { toast(`Scanned ${res.scanned} articles, filed ${res.newly_filed}`); loadSidebar(); loadArticles(); }
          } }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
            if (window.confirm(`Delete rule “${r.name}”?`) && await guarded(() => api("DELETE", `/rules/${r.id}`), "Rule deleted")) rerender();
          } }))),
      h("div", null, r.keywords.length ? r.keywords.map((k) => h("span", { class: "kw", text: k })) : h("span", { class: "muted", text: "(any article in scope) " }),
        (r.require_keywords || []).length ? [h("span", { class: "muted", text: " AND one of " }), r.require_keywords.map((k) => h("span", { class: "kw req", text: k }))] : null,
        r.exclude_keywords.map((k) => h("span", { class: "kw neg", text: k }))),
      h("div", { class: "muted" },
        [
          r.feed_id ? `Feed: ${nameOf(feeds, r.feed_id, "title")}` : r.folder_id ? `Folder: ${nameOf(folders, r.folder_id)}` : "All feeds",
          r.match_in === "title" ? "title only" : "title + content",
          r.keywords_in_title ? "main words in title" : null,
          r.cve_severity ? `names a ${r.cve_severity.toLowerCase()} CVE` : null,
          r.cve_owasp ? `names a CVE in OWASP ${r.cve_owasp.replace(":", " ")}` : null,
          r.cve_category ? `names a CVE: ${cveCatName(r.cve_category)}` : null,
          r.tag_id ? `→ ${nameOf(tags, r.tag_id)}` : null,
          r.star ? "★ star" : null, r.mark_read ? "mark read" : null,
          r.webhook_id ? `→ webhook ${nameOf(hooks || [], r.webhook_id)}` : null,
        ].filter(Boolean).join(" · "))));
    list.append(...cards);
    const ruleFilter = h("input", { type: "search", placeholder: `Filter ${rules.length} rules…`, "aria-label": "Filter rules" });
    ruleFilter.addEventListener("input", () => {
      const q = ruleFilter.value.trim().toLowerCase();
      for (const c of cards) c.hidden = Boolean(q) && !c.dataset.search.includes(q);
    });

    fill(panel, 
      h("p", { class: "muted", text: "Rules run on every new article: they file it into collections, star it, mute it, or push it to a webhook for automation." }),
      h("div", { class: "row-form", style: { "margin-bottom": "14px" } },
        h("button", { type: "button", class: "btn primary", text: "+ New rule", onclick: () => list.prepend(editor(null)) }),
        ruleFilter),
      await packsCard(),
      rules.length ? list : h("div", null, list, h("p", { class: "muted", text: "No rules yet. Install a ready-made pack above, or create your own rule." })),
    );
  }

  async function renderWebhooksPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const hooks = await guarded(() => api("GET", "/webhooks"));
    if (!hooks) return;
    const name = h("input", { type: "text", maxlength: 100, placeholder: "Name (e.g. n8n triage)", required: true });
    const url = h("input", { type: "url", maxlength: 2048, placeholder: "https://automation.example/webhook/…", required: true });
    const secret = h("input", { type: "text", maxlength: 200, placeholder: "Signing secret (optional, ≥16 chars)" });
    const gen = h("button", { type: "button", class: "btn small", text: "Generate", onclick: () => {
      const bytes = new Uint8Array(32); crypto.getRandomValues(bytes);
      secret.value = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    } });

    fill(panel, 
      h("p", { class: "muted" }, "Webhooks receive a JSON POST when a rule with a webhook action matches. With a secret, requests are signed: ",
        h("code", { text: "X-EOS-Signature: sha256=HMAC(secret, timestamp + \".\" + body)" }), "."),
      h("form", { class: "card", onsubmit: async (e) => {
        e.preventDefault();
        const body = { name: name.value.trim(), url: url.value.trim() };
        if (secret.value.trim()) body.secret = secret.value.trim();
        if (await guarded(() => api("POST", "/webhooks", body), "Webhook added")) rerender();
      } },
      h("div", { class: "row-form" }, name, url),
      h("div", { class: "row-form", style: { "margin-top": "8px" } }, secret, gen, h("button", { type: "submit", class: "btn primary", text: "Add webhook" }))),
      hooks.map((w) => h("div", { class: "card" },
        h("div", { class: "card-head" },
          h("strong", { text: `${w.enabled ? "" : "⏸ "}${w.name}` }),
          h("div", { class: "actions" },
            h("button", { type: "button", class: "btn small", text: "Send test", onclick: async () => {
              const r = await guarded(() => api("POST", `/webhooks/${w.id}/test`));
              if (r) { toast(r.ok ? "Delivered" : `Failed: ${r.message}`, !r.ok); rerender(); }
            } }),
            h("button", { type: "button", class: "btn small", text: w.enabled ? "Disable" : "Enable", onclick: async () => {
              if (await guarded(() => api("PATCH", `/webhooks/${w.id}`, { enabled: !w.enabled }))) rerender();
            } }),
            h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
              if (window.confirm(`Delete webhook “${w.name}”?`) && await guarded(() => api("DELETE", `/webhooks/${w.id}`), "Deleted")) rerender();
            } }))),
        h("div", { class: "muted", text: w.url }),
        h("div", { class: "muted" },
          w.has_secret ? "🔒 signed" : "unsigned",
          w.last_sent ? ` · last sent ${relTime(w.last_sent)} · ` : "",
          w.last_sent ? h("span", { class: w.last_error ? "status-err" : "status-ok", text: w.last_error || `HTTP ${w.last_status}` }) : ""))),
    );
  }

  async function renderApiPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const tokens = await guarded(() => api("GET", "/tokens"));
    if (!tokens) return;
    const name = h("input", { type: "text", maxlength: 64, placeholder: "Token name (e.g. home-assistant)", required: true });
    const scope = h("select", null, h("option", { value: "read", text: "Read only" }), h("option", { value: "write", text: "Read + write" }));
    const expiry = h("select", null, [[30, "30 days"], [90, "90 days"], [365, "1 year"], ["", "Never expires"]].map(([v, l]) => h("option", { value: v, text: l, selected: v === 90 })));
    const reveal = h("div");
    const origin = window.location.origin;

    fill(panel, 
      h("p", { class: "muted" }, "Tokens let scripts and automation tools use the REST API. They cannot manage tokens, webhooks, settings or your password. The OpenAPI schema (login required) is at ",
        h("a", { href: "/api/v1/openapi.json", target: "_blank", rel: "noopener noreferrer", text: "/api/v1/openapi.json" }), "."),
      h("form", { class: "row-form card", onsubmit: async (e) => {
        e.preventDefault();
        const body = { name: name.value.trim(), scope: scope.value, expires_days: expiry.value ? Number(expiry.value) : null };
        const res = await guarded(() => api("POST", "/tokens", body));
        if (!res) return;
        await renderApiPanel(panel);
        const box = h("div", { class: "secret-box", text: res.token });
        panel.prepend(h("div", { class: "card" },
          h("strong", { text: "Copy your new token now — it will not be shown again." }), box,
          h("div", { class: "row-form", style: { "margin-top": "8px" } },
            h("button", { type: "button", class: "btn small", text: "Copy", onclick: async () => {
              try { await navigator.clipboard.writeText(res.token); toast("Copied"); } catch (_) { toast("Copy failed — select the text manually", true); }
            } }))));
      } }, name, scope, expiry, h("button", { type: "submit", class: "btn primary", text: "Create token" })),
      reveal,
      tokens.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Name", "Prefix", "Scope", "Created", "Last used", "Expires", ""].map((t) => h("th", { text: t })))),
        h("tbody", null, tokens.map((t) => h("tr", null,
          h("td", { text: t.name }), h("td", null, h("code", { text: `${t.prefix}…` })), h("td", { text: t.scopes }),
          h("td", { text: relTime(t.created_at) }), h("td", { text: t.last_used ? relTime(t.last_used) : "never" }),
          h("td", { text: t.expires_at ? fmtDate(t.expires_at) : "never" }),
          h("td", null, h("button", { type: "button", class: "btn small danger", text: "Revoke", onclick: async () => {
            if (window.confirm(`Revoke token “${t.name}”?`) && await guarded(() => api("DELETE", `/tokens/${t.id}`), "Revoked")) renderApiPanel(panel);
          } }))))))) : null,
      h("div", { class: "panel-section", style: { "margin-top": "20px" } }, h("h4", { text: "Examples" }),
        h("code", { class: "block", text:
`# Latest unread ransomware-collection articles
curl -H "Authorization: Bearer $FW_TOKEN" "${origin}/api/v1/articles?unread=true&tag_id=1&limit=20"

# Search
curl -H "Authorization: Bearer $FW_TOKEN" "${origin}/api/v1/articles?q=CVE-2026&since=$(date -d '-1 day' +%s)"

# Add a feed (write scope)
curl -X POST -H "Authorization: Bearer $FW_TOKEN" -H "Content-Type: application/json" \\
     -d '{"url":"https://example.com/feed.xml"}' "${origin}/api/v1/feeds"` })),
    );
  }

  async function renderAboutPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const info = await guarded(() => api("GET", "/about"));
    if (!info) return;
    const src = safeUrl(info.source_url);
    fill(panel,
      h("div", { class: "panel-section" },
        h("h4", { text: `${info.name} ${info.version}` }),
        h("p", { text: "A self-hosted, security-focused aggregator for cyber-security news, threat intel, CVEs, videos and social channels." }),
        h("p", null, "Free software under the ", h("a", { href: safeUrl(info.license_url), target: "_blank", rel: "noopener noreferrer", text: "GNU Affero General Public License v3.0 or later" }),
          ". You may use, study, share and modify it; if you run a modified version for other people over a network, you must offer them its source code."),
        h("p", null, "Source code: ", src ? h("a", { href: src, target: "_blank", rel: "noopener noreferrer", text: src })
          : h("span", { class: "muted", text: "not configured — set EOS_SOURCE_URL to your repository (required if you run a modified version for others)." })),
        h("p", { class: "muted small", text: "Provided without any warranty. See the LICENSE file for the full terms." })));
  }

  function renderAccountPanel(panel) {
    const current = h("input", { type: "password", autocomplete: "current-password", maxlength: 256, required: true });
    const next = h("input", { type: "password", autocomplete: "new-password", minlength: 12, maxlength: 256, required: true });
    const confirmPw = h("input", { type: "password", autocomplete: "new-password", minlength: 12, maxlength: 256, required: true });
    const err = h("p", { class: "error" });
    fill(panel, 
      h("div", { class: "panel-section" }, h("h4", { text: "Change password" }),
        h("form", { class: "grid-form", onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          if (next.value !== confirmPw.value) { err.textContent = "New passwords do not match."; return; }
          try {
            await api("POST", "/auth/password", { current_password: current.value, new_password: next.value });
            toast("Password changed. Other sessions were signed out.");
            current.value = next.value = confirmPw.value = "";
          } catch (ex) { err.textContent = ex.message; }
        } },
        ...settingRow("Current password", current),
        ...settingRow("New password", next, "At least 12 characters. A passphrase is best."),
        ...settingRow("Confirm new password", confirmPw),
        h("span"), h("div", null, err, h("button", { type: "submit", class: "btn primary", text: "Update password" })))),
      h("div", { class: "panel-section" }, h("h4", { text: "Session" }),
        h("button", { type: "button", class: "btn danger", text: "Sign out", onclick: logout })),
    );
  }

  async function logout() {
    try { await api("POST", "/auth/logout"); } catch (_) { /* ignore */ }
    window.location.replace("/login");
  }

  // ======================================================================= actions
  /** ⟳ refreshes the section you are in: Reader feeds, YouTube channels (Videos) or social accounts (Accounts). */
  async function refreshAll() {
    const mode = currentMode();
    if (mode === "repos") {  // GitHub sources have their own refresh (paced to GitHub's hourly limit)
      const r = await guarded(() => api("POST", "/repos/refresh"));
      if (r) { toast(`Checking ${r.sources} GitHub source(s) in the background…`); if (window.FW.repos) window.FW.repos.watchSoon(); }
      return;
    }
    const section = mode === "library" ? "videos" : mode === "accounts" ? "accounts" : mode === "reader" ? "reader" : "all";
    const res = await guarded(() => api("POST", `/feeds/refresh?section=${section}`));
    if (!res) return;
    const what = { videos: "YouTube channels", accounts: "social accounts", reader: "feeds", all: "feeds" }[section];
    toast(`Checking ${res.queued} ${what} for new ${section === "videos" ? "videos" : "posts"}…`);
    const after = () => {
      loadSidebar();
      if (section === "videos" && window.FW.library && currentMode() === "library") window.FW.library.loadMeta().then(() => { window.FW.library.renderShell(); window.FW.library.reload(); });
      if (section === "accounts" && window.FW.accounts && currentMode() === "accounts") window.FW.accounts.loadMeta().then(() => { window.FW.accounts.renderShell(); window.FW.accounts.reload(); });
    };
    setTimeout(after, 6000);
    setTimeout(after, 20000);
  }

  async function markAllRead() {
    const v = state.view;
    const body = { before: Math.floor(Date.now() / 1000) };
    if (v.type === "ttp" || v.type === "entity") { toast("Mark read isn't available in this view: use ☑ Select", true); return; }
    if (v.type === "feed") body.feed_id = v.id;
    else if (v.type === "folder") body.folder_id = v.id;
    else if (v.type === "tag") body.tag_id = v.id;
    else if (v.type === "taggroup") body.tag_ids = v.ids;
    else if (v.type === "starred") body.starred = true;
    else body.all = true;
    if (!window.confirm(`Mark everything in “${viewLabel()}” as read?`)) return;
    const res = await guarded(() => api("POST", "/articles/mark-read", body));
    if (res) { toast(`Marked ${res.updated} as read`); loadSidebar(); loadArticles(); }
  }

  function move(delta) {
    if (!state.articles.length) return;
    let idx = state.articles.findIndex((a) => a.id === state.selectedId);
    idx = idx === -1 ? 0 : Math.min(Math.max(idx + delta, 0), state.articles.length - 1);
    // skip articles folded under another source of the same story (they have no row of their own)
    const shown = (i) => Boolean(document.querySelector(`.article-item[data-id="${Number(state.articles[i].id)}"]`));
    while (!shown(idx) && idx + delta >= 0 && idx + delta < state.articles.length) idx += delta;
    openArticle(state.articles[idx].id);
    if (idx >= state.articles.length - 3 && state.articles.length < state.total) loadArticles(true);
  }


  // ======================================================================= resizable panes & drawer
  /**
   * Drag (pointer) or keyboard (arrow keys) resizing with limits. `getMax` may depend on the window.
   * onChange(px) applies the size live; onCommit(px) persists it; double-click resets.
   */
  function makeResizer(handle, { get, min, getMax, onChange, onCommit, onReset, edge = "right", step = 16 }) {
    handle.setAttribute("role", "separator");
    handle.setAttribute("tabindex", "0");
    handle.setAttribute("aria-orientation", "vertical");
    const clamp = (v) => Math.round(Math.max(min, Math.min(getMax(), v)));
    handle.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const startX = e.clientX;
      const start = get();
      try { handle.setPointerCapture(e.pointerId); } catch (_) { /* window listeners below still track the drag */ }
      document.body.classList.add("is-resizing");
      const move = (ev) => {
        const dx = ev.clientX - startX;
        onChange(clamp(edge === "left" ? start - dx : start + dx));
      };
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", up);
        document.body.classList.remove("is-resizing");
        onCommit(get());
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", up);
    });
    handle.addEventListener("keydown", (e) => {
      const grow = edge === "left" ? "ArrowLeft" : "ArrowRight";
      const shrink = edge === "left" ? "ArrowRight" : "ArrowLeft";
      if (e.key !== grow && e.key !== shrink) return;
      e.preventDefault();
      const v = clamp(get() + (e.key === grow ? step : -step));
      onChange(v);
      onCommit(v);
    });
    handle.addEventListener("dblclick", () => { onReset(); });
  }

  // Reader panes: sidebar (feeds, folders, collections) and article list.
  // Limits: sidebar up to 440 px (a medium feed name fits on one line); list up to 820 px (a full average
  // headline fits without wrapping); the reader always keeps at least 360 px.
  const PANE = { side: { key: "fw-side-w", def: 260, min: 200, max: 440 }, list: { key: "fw-list-w", def: 400, min: 300, max: 820 } };

  function paneWidth(which) {
    const v = Number(store.get(PANE[which].key, 0));
    return v ? v : null;
  }

  function applyPaneWidths() {
    const app = $("#app");
    const side = paneWidth("side");
    const list = paneWidth("list");
    if (side) app.style.setProperty("--side-w", `${side}px`); else app.style.removeProperty("--side-w");
    if (list) app.style.setProperty("--list-w", `${list}px`); else app.style.removeProperty("--list-w");
  }

  function setupPaneResizers() {
    const app = $("#app");
    const current = (sel) => Math.round($(sel).getBoundingClientRect().width);
    makeResizer($("#sideResizer"), {
      get: () => current("#sidebar"), min: PANE.side.min,
      getMax: () => Math.min(PANE.side.max, window.innerWidth - current("#listPane") - 360),
      onChange: (px) => app.style.setProperty("--side-w", `${px}px`),
      onCommit: (px) => store.set(PANE.side.key, px),
      onReset: () => { store.set(PANE.side.key, 0); applyPaneWidths(); },
    });
    makeResizer($("#listResizer"), {
      get: () => current("#listPane"), min: PANE.list.min,
      getMax: () => Math.min(PANE.list.max, window.innerWidth - current("#sidebar") - 360),
      onChange: (px) => app.style.setProperty("--list-w", `${px}px`),
      onCommit: (px) => store.set(PANE.list.key, px),
      onReset: () => { store.set(PANE.list.key, 0); applyPaneWidths(); },
    });
    applyPaneWidths();
  }

  // Side drawer (dashboard drill-downs, CVE details): wide by default, resizable from its left edge.
  const DRAWER_KEY = "fw-drawer-w";
  const drawerDefault = () => Math.min(1100, Math.round(window.innerWidth * 0.92));
  const drawerMax = () => Math.max(360, window.innerWidth - 24);

  function enhanceDrawer(drawer) {
    const saved = Number(store.get(DRAWER_KEY, 0));
    const width = Math.max(360, Math.min(drawerMax(), saved || drawerDefault()));
    drawer.style.width = `${width}px`;
    if (drawer.querySelector(":scope > .drawer-resizer")) return;
    const handle = h("div", { class: "drawer-resizer", title: "Drag to resize (double-click to reset)", "aria-label": "Resize panel" });
    drawer.prepend(handle);
    makeResizer(handle, {
      edge: "left", step: 40, min: 360, getMax: drawerMax,
      get: () => Math.round(drawer.getBoundingClientRect().width),
      onChange: (px) => { drawer.style.width = `${px}px`; },
      onCommit: (px) => store.set(DRAWER_KEY, px),
      onReset: () => { store.set(DRAWER_KEY, 0); drawer.style.width = `${drawerDefault()}px`; },
    });
  }

  // ======================================================================= mode switch
  function currentMode() {
    const cl = $("#app").classList;
    return cl.contains("mode-dashboard") ? "dashboard" : cl.contains("mode-library") ? "library" : cl.contains("mode-accounts") ? "accounts" : cl.contains("mode-podcasts") ? "podcasts" : cl.contains("mode-threatmap") ? "threatmap" : "reader";
  }

  // ----------------------------------------------------------------------- sidebar show / hide
  /** Phones: the sidebar slides over the list. Wider screens: its column collapses and the choice is remembered. */
  const narrow = () => window.matchMedia("(max-width: 860px)").matches;
  function sidebarOpen() {
    const app = $("#app");
    return narrow() ? app.classList.contains("show-sidebar") : !app.classList.contains("sidebar-collapsed");
  }
  function syncSidebarButton() {
    const open = sidebarOpen();
    const btn = $("#menuBtn");
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-label", open ? "Hide sidebar" : "Show sidebar");
    btn.title = `${open ? "Hide" : "Show"} sidebar ( [ )`;
  }
  function toggleSidebar() {
    const app = $("#app");
    if (narrow()) app.classList.toggle("show-sidebar");
    else {
      const collapsed = app.classList.toggle("sidebar-collapsed");
      store.set("fw-sidebar-collapsed", collapsed);
    }
    syncSidebarButton();
  }
  function restoreSidebar() {
    $("#app").classList.toggle("sidebar-collapsed", Boolean(store.get("fw-sidebar-collapsed", false)));
    syncSidebarButton();
  }

  function setMode(mode, persist = true) {
    if (!["reader", "dashboard", "library", "accounts", "podcasts", "repos", "threatmap"].includes(mode)) mode = "reader";
    const app = $("#app");
    app.classList.toggle("mode-dashboard", mode === "dashboard");
    app.classList.toggle("mode-library", mode === "library");
    app.classList.toggle("mode-accounts", mode === "accounts");
    app.classList.toggle("mode-podcasts", mode === "podcasts");
    app.classList.toggle("mode-repos", mode === "repos");
    app.classList.toggle("mode-threatmap", mode === "threatmap");
    $("#dashboardView").hidden = mode !== "dashboard";
    $("#libraryView").hidden = mode !== "library";
    $("#accountsView").hidden = mode !== "accounts";
    $("#podcastsView").hidden = mode !== "podcasts";
    $("#reposView").hidden = mode !== "repos";
    $("#threatmapView").hidden = mode !== "threatmap";
    $("#modeThreatmap").setAttribute("aria-pressed", String(mode === "threatmap"));
    const tmap = window.FW && window.FW.threatmap;
    if (tmap) { if (mode === "threatmap") tmap.show(); else tmap.hide(); }
    $("#modeLibrary").setAttribute("aria-pressed", String(mode === "library"));
    const lib = window.FW && window.FW.library;
    if (lib) { if (mode === "library") lib.show(); else lib.hide(); }
    $("#modeAccounts").setAttribute("aria-pressed", String(mode === "accounts"));
    $("#modePodcasts").setAttribute("aria-pressed", String(mode === "podcasts"));
    const pod = window.FW && window.FW.podcasts;
    if (pod) { if (mode === "podcasts") pod.show(); else pod.hide(); }
    $("#modeRepos").setAttribute("aria-pressed", String(mode === "repos"));
    const repos = window.FW && window.FW.repos;
    if (repos) { if (mode === "repos") repos.show(); else repos.hide(); }
    // ＋ (add a feed) belongs to Articles; Videos and Accounts have their own ＋ in their toolbar. ⟳ follows the section.
    $("#addFeedBtn").hidden = mode !== "reader";
    const refreshTitle = { library: "Check subscribed channels for new videos", accounts: "Check followed accounts for new posts", reader: "Refresh all article feeds (r)",
      repos: "Check the GitHub owners, repos and topics you follow" }[mode] || "Refresh everything";
    $("#refreshBtn").title = refreshTitle;
    $("#refreshBtn").setAttribute("aria-label", refreshTitle);
    const acc = window.FW && window.FW.accounts;
    if (acc) { if (mode === "accounts") acc.show(); else acc.hide(); }
    $("#modeReader").setAttribute("aria-pressed", String(mode === "reader"));
    $("#modeDash").setAttribute("aria-pressed", String(mode === "dashboard"));
    const board = window.FW && window.FW.dashboard;
    if (board) { if (mode === "dashboard") board.show(); else board.hide(); }
    // a short fade on the view that appears (no flash of an empty page while it refreshes in place)
    const shown = { dashboard: "#dashboardView", library: "#libraryView", accounts: "#accountsView", podcasts: "#podcastsView", repos: "#reposView", threatmap: "#threatmapView" }[mode];
    const fadeEls = shown ? [$(shown)] : [$(".sidebar"), $(".list-pane"), $("#reader")];
    for (const el of fadeEls) { if (!el) continue; el.classList.remove("view-fade"); void el.offsetWidth; el.classList.add("view-fade"); }
    if (persist && state.settings.ui_mode !== mode) {
      state.settings.ui_mode = mode;
      api("PATCH", "/settings", { ui_mode: mode }).catch(() => { /* non-critical */ });
    }
  }

  async function openArticleInReader(id) {
    setMode("reader");
    await openArticle(id);
  }

  // ======================================================================= MITRE ATT&CK card
  /** Sync status + schedule + "Sync now" + last change report + a searchable list of the groups. */
  async function attackCard(reload) {
    const st = await api("GET", "/attack/status").catch(() => null);
    if (!st) return null;
    const schedule = h("select", { "aria-label": "Check for updates" },
      [["weekly", "Weekly"], ["daily", "Daily"], ["off", "Off (manual only)"]].map(([v, l]) => h("option", { value: v, text: l, selected: st.schedule === v })));
    schedule.addEventListener("change", () => saveSetting("attack_sync", schedule.value));
    const syncBtn = h("button", { type: "button", class: "btn small primary", text: st.running ? "Syncing…" : "⟳ Sync now", disabled: st.running, onclick: async () => {
      if (await guarded(() => api("POST", "/attack/sync"), "Checking MITRE ATT&CK in the background…")) {
        syncBtn.disabled = true; syncBtn.textContent = "Syncing…";
        const poll = setInterval(async () => {
          const s2 = await api("GET", "/attack/status").catch(() => null);
          if (s2 && !s2.running && !(s2.atlas && s2.atlas.running)) { clearInterval(poll); reload(); }
        }, 3000);
      }
    } });
    const versions = Object.entries(st.versions).filter(([, v]) => v).map(([d, v]) => `${d.replace("-attack", "")} v${v}`).join(" · ");
    const res = st.last_result;
    const upd = st.last_update && st.last_update.report;
    const listOf = (label, items) => items && items.length ? h("details", null, h("summary", { text: `${label} (${items.length})` }), h("div", { class: "small pack-list", text: items.join(" · ") })) : null;
    const q = h("input", { type: "search", placeholder: "Find a group, alias or G-ID (e.g. Fancy Bear)…", "aria-label": "Find an ATT&CK group" });
    const results = h("div", { class: "attack-groups" });
    let timer = null;
    const search = async () => {
      const data = await api("GET", `/attack/groups?limit=30&q=${encodeURIComponent(q.value.trim())}`).catch(() => null);
      if (!data) return;
      fill(results, data.items.length ? data.items.map((g) => h("details", { class: "attack-group", "data-id": g.id },
        h("summary", null, h("strong", { text: g.name }), h("span", { class: "muted small", text: ` ${g.id} · ${g.techniques} techniques` })),
        h("div", { class: "small muted", text: g.aliases.length ? `Also known as: ${g.aliases.join(", ")}` : "No aliases listed" }),
        h("div", { class: "small" }, h("a", { href: safeUrl(g.url), target: "_blank", rel: "noopener noreferrer", text: "Open on attack.mitre.org ↗" })),
        h("div", { class: "small attack-ttps", text: "Loading techniques…" }))) : h("p", { class: "muted small", text: "No matching groups." }));
      for (const d of results.querySelectorAll("details.attack-group")) {
        d.addEventListener("toggle", async () => {
          const box = d.querySelector(".attack-ttps");
          if (!d.open || box.dataset.loaded) return;
          const g = await api("GET", `/attack/groups/${encodeURIComponent(d.dataset.id)}`).catch(() => null);
          box.dataset.loaded = "1";
          box.textContent = g ? (g.techniques.length ? g.techniques.map((t) => `${t.id} ${t.name}`).join(" · ") : "No techniques recorded.") : "Could not load.";
        });
      }
    };
    q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 300); });
    if (st.counts.groups) search();
    return h("div", { class: "card attack-card" },
      h("div", { class: "card-head" }, h("strong", { text: "🛡️ MITRE ATT&CK" }), h("div", { class: "actions" }, h("span", { class: "muted small", text: "Check for updates" }), schedule, syncBtn)),
      h("p", { class: "muted small", text: "Threat groups and techniques (TTPs) from MITRE ATT&CK - and AI attack techniques from MITRE ATLAS - kept up to date automatically. Groups and their aliases fill the “MITRE ATT&CK groups” watchlist, techniques the “MITRE ATT&CK techniques” watchlist, and new technique names flow into the ATT&CK collections." }),
      h("p", { class: "small" },
        st.counts.groups ? `${st.counts.groups} groups · ${st.counts.techniques} techniques · ${st.counts.relationships} group→technique links${versions ? ` · ${versions}` : ""}` : "Not synced yet — click Sync now.",
        st.checked_at ? h("span", { class: "muted", text: ` · checked ${relTime(st.checked_at)}${st.next_check ? `, next ${fmtDate(st.next_check)}` : ""}` }) : null),
      st.atlas ? h("p", { class: "small" },
        h("strong", { text: "MITRE ATLAS (AI): " }),
        st.atlas.techniques ? `${st.atlas.techniques} techniques · release ${st.atlas.version || "?"}` : "not synced yet — click Sync now.",
        st.atlas.checked_at ? h("span", { class: "muted", text: ` · checked ${relTime(st.atlas.checked_at)}` }) : null,
        st.atlas.techniques && !st.atlas.collections ? h("span", { class: "muted", text: " · install the “MITRE ATLAS tactics (AI)” pack under Rules for its collections" }) : null,
        st.atlas.last_result && st.atlas.last_result.status === "error" ? h("span", { class: "error", text: ` · last check failed: ${st.atlas.last_result.error}` }) : null) : null,
      st.running || (st.atlas && st.atlas.running) ? h("p", { class: "muted small", text: `⏳ ${st.phase || (st.atlas && st.atlas.phase) || "Working"}…` }) : null,
      res && res.status === "error" ? h("p", { class: "error small", text: `Last check failed: ${res.error}` }) : null,
      res && res.status === "up to date" ? h("p", { class: "muted small", text: "Last check: already up to date." }) : null,
      upd ? h("div", { class: "small" },
        h("div", { class: "muted", text: upd.first_sync ? `First sync ${relTime(st.last_update.finished)}.` : `Last update ${relTime(st.last_update.finished)}: ${upd.groups_added.length} new groups, ${upd.groups_updated.length} updated, ${upd.techniques_added.length} new techniques.` }),
        listOf("New groups", upd.groups_added), listOf("Updated groups", upd.groups_updated), listOf("Removed groups", upd.groups_removed),
        listOf("New techniques", upd.techniques_added), listOf("Removed techniques", upd.techniques_removed)) : null,
      st.counts.groups ? h("div", { class: "attack-search" }, q, results) : null);
  }

  // ======================================================================= watchlists panel
  async function renderWatchlistsPanel(panel, selectedId) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const [lists, status] = await Promise.all([guarded(() => api("GET", "/watchlists")), guarded(() => api("GET", "/watchlists/status"))]);
    if (!lists) return;
    const current = selectedId || (lists[0] && lists[0].id);
    const detailBox = h("div", { class: "wl-detail" });
    const newName = h("input", { type: "text", maxlength: 100, placeholder: "New watchlist, e.g. My organisations" });

    const listNav = h("div", { class: "wl-list" },
      lists.map((w) => h("button", {
        type: "button", class: w.id === current ? "active" : "",
        onclick: () => renderWatchlistsPanel(panel, w.id),
      }, h("span", { text: w.name }), h("span", { class: "count", text: w.entity_count }))),
      h("form", { class: "row-form", style: { "margin-top": "10px" }, onsubmit: async (e) => {
        e.preventDefault();
        const name = newName.value.trim();
        if (!name) return;
        const res = await guarded(() => api("POST", "/watchlists", { name }), "Watchlist created");
        if (res) renderWatchlistsPanel(panel, res.id);
      } }, newName, h("button", { type: "submit", class: "btn small primary", text: "Add" })));

    fill(panel, 
      h("p", { class: "muted" },
        "Watchlists power the dashboards: every article is scanned for these names and aliases (whole words; punctuation ignored). ",
        "ALL-CAPS aliases like US are case-sensitive; prefix an alias with = to force case-sensitivity (e.g. =Polish). Counts are article mentions, not verified incidents."),
      h("div", { class: "row-form", style: { "margin-bottom": "12px" } },
        h("button", { type: "button", class: "btn small", text: "Re-index all articles", onclick: async () => {
          if (await guarded(() => api("POST", "/watchlists/reindex"), "Re-indexing in the background…")) renderWatchlistsPanel(panel, current);
        } }),
        status && status.indexing ? h("span", { class: "muted", text: "⏳ Indexing in progress…" }) : null),
      await attackCard(() => renderWatchlistsPanel(panel, current)),
      h("div", { class: "wl-layout" }, listNav, detailBox));

    if (!current) { detailBox.append(h("p", { class: "muted", text: "No watchlists yet." })); return; }
    const wl = await guarded(() => api("GET", `/watchlists/${current}`));
    if (!wl) return;
    const wlName = h("input", { type: "text", value: wl.name, maxlength: 100, "aria-label": "Watchlist name" });
    const wlDesc = h("input", { type: "text", value: wl.description, maxlength: 300, placeholder: "Description", "aria-label": "Description" });
    const entName = h("input", { type: "text", maxlength: 100, placeholder: "Entity name, e.g. Acme Corp" });
    const entAliases = h("input", { type: "text", placeholder: "Aliases, comma-separated (optional)" });
    const filter = h("input", { type: "search", placeholder: "Filter entities…", "aria-label": "Filter entities" });
    const reload = () => renderWatchlistsPanel(panel, current);

    const rows = wl.entities.map((ent) => {
      const name = h("input", { type: "text", value: ent.name, maxlength: 100, "aria-label": "Entity name" });
      const aliases = h("input", { type: "text", value: ent.aliases.join(", "), "aria-label": "Aliases" });
      return h("tr", { dataset: { search: `${ent.name} ${ent.aliases.join(" ")}`.toLowerCase() } },
        h("td", null, name), h("td", null, aliases), h("td", { class: "num", text: ent.mentions }),
        h("td", null, h("div", { class: "actions" },
          h("button", { type: "button", class: "btn small", text: "Save", onclick: async () => {
            const body = { name: name.value.trim(), aliases: splitKeywords(aliases.value) };
            if (await guarded(() => api("PATCH", `/entities/${ent.id}`, body), "Saved — re-indexing")) reload();
          } }),
          h("button", { type: "button", class: "btn small danger", text: "✕", "aria-label": `Delete ${ent.name}`, onclick: async () => {
            if (window.confirm(`Delete “${ent.name}”?`) && await guarded(() => api("DELETE", `/entities/${ent.id}`))) reload();
          } }))));
    });
    const tbody = h("tbody", null, rows);
    filter.addEventListener("input", () => {
      const needle = filter.value.trim().toLowerCase();
      for (const tr of tbody.children) tr.hidden = needle && !tr.dataset.search.includes(needle);
    });

    detailBox.append(
      h("div", { class: "row-form" }, wlName, wlDesc,
        h("button", { type: "button", class: "btn small", text: "Save", onclick: async () => {
          if (await guarded(() => api("PATCH", `/watchlists/${wl.id}`, { name: wlName.value.trim(), description: wlDesc.value.trim() }), "Saved")) reload();
        } }),
        h("button", { type: "button", class: "btn small danger", text: "Delete list", onclick: async () => {
          if (window.confirm(`Delete watchlist “${wl.name}” and all its entities? Dashboard widgets using it will show no data.`)
            && await guarded(() => api("DELETE", `/watchlists/${wl.id}`), "Deleted")) renderWatchlistsPanel(panel);
        } })),
      h("form", { class: "row-form card", style: { "margin-top": "10px" }, onsubmit: async (e) => {
        e.preventDefault();
        if (!entName.value.trim()) return;
        const body = { name: entName.value.trim(), aliases: splitKeywords(entAliases.value) };
        if (await guarded(() => api("POST", `/watchlists/${wl.id}/entities`, body), "Entity added — indexing")) reload();
      } }, entName, entAliases, h("button", { type: "submit", class: "btn primary small", text: "Add entity" })),
      h("div", { class: "row-form", style: { margin: "8px 0" } }, filter, h("span", { class: "muted", text: `${wl.entities.length} entities` })),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Name", "Aliases", "Mentions", ""].map((t) => h("th", { text: t })))),
        tbody)));
  }

  // ======================================================================= wiring
  function bindEvents() {
    let searchTimer = null;
    $("#modeReader").addEventListener("click", () => setMode("reader"));
    $("#modeDash").addEventListener("click", () => setMode("dashboard"));
    $("#modeLibrary").addEventListener("click", () => setMode("library"));
    $("#modeAccounts").addEventListener("click", () => setMode("accounts"));
    $("#modePodcasts").addEventListener("click", () => setMode("podcasts"));
    $("#modeRepos").addEventListener("click", () => setMode("repos"));
    $("#modeThreatmap").addEventListener("click", () => setMode("threatmap"));
    $("#search").addEventListener("input", (e) => {
      if (currentMode() !== "reader") setMode("reader");
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { state.q = e.target.value.trim().slice(0, 200); loadArticles(); }, 300);
    });
    // Date range: presets, or 📅 Custom range… (from / to). The custom range is remembered.
    const rangeSel = $("#rangeSelect");
    const customOpt = rangeSel.querySelector('option[value="custom"]');
    const showCustom = () => { if (customOpt) customOpt.textContent = state.range ? `📅 ${rangeLabel(state.range)}` : "📅 Custom range…"; };
    state.range = cleanRange(store.get("fw-art-range", null));
    if (state.range && customOpt) { rangeSel.value = "custom"; showCustom(); }
    // a select fires no change when the same entry is picked again: a small ✎ button edits the custom range
    const editRange = h("button", { type: "button", class: "icon-btn", text: "✎", title: "Change the dates", "aria-label": "Change the custom date range",
      onclick: () => rangeSel.dispatchEvent(new Event("change")) });
    const syncEdit = () => { editRange.hidden = rangeSel.value !== "custom"; };
    rangeSel.after(editRange);
    syncEdit();
    let lastRange = rangeSel.value;
    rangeSel.addEventListener("change", async () => {
      if (rangeSel.value === "custom") {
        const r = await pickDateRange(state.range);
        if (r === undefined) { rangeSel.value = lastRange; syncEdit(); return; }   // cancelled: keep what was there
        state.range = r;
        store.set("fw-art-range", r);
        if (!r) rangeSel.value = "";
        showCustom();
      }
      lastRange = rangeSel.value;
      syncEdit();
      loadArticles();
    });

    $("#actorsBtn").addEventListener("click", () => window.FW.intel.actors());
    $("#sortSelect").addEventListener("change", () => loadArticles());
    $("#markAllBtn").addEventListener("click", markAllRead);
    $("#selectModeBtn").addEventListener("click", () => setSelecting(!state.selecting));
    const drawTagsToggle = () => $("#tagsToggleSlot").replaceChildren(tagsToggle("articles", () => { drawTagsToggle(); renderList(); }, "btn"));
    drawTagsToggle();
    $("#loadMoreBtn").addEventListener("click", () => loadArticles(true));
    $("#newBannerBtn").addEventListener("click", () => loadArticles());
    $("#refreshBtn").addEventListener("click", refreshAll);
    $("#addFeedBtn").addEventListener("click", openAddFeed);
    $("#feedSettingsBtn").addEventListener("click", () => {
      if (state.view.type === "feed" && window.FW.feeds) window.FW.feeds.openFeedEditor(state.view.id);
    });
    $("#settingsBtn").addEventListener("click", () => openSettings("general"));
    $("#menuBtn").addEventListener("click", toggleSidebar);
    window.matchMedia("(max-width: 860px)").addEventListener("change", syncSidebarButton);
    $("#addFeedForm").addEventListener("submit", submitAddFeed);
    for (const btn of document.querySelectorAll("[data-close]")) {
      btn.addEventListener("click", () => btn.closest("dialog").close());
    }
    $("#settingsDialog").addEventListener("close", () => { loadSidebar(); });
    $("#articleList").addEventListener("scroll", (e) => {
      const el = e.target;
      if (el.scrollTop + el.clientHeight > el.scrollHeight - 200 && state.articles.length < state.total) loadArticles(true);
    });

    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = (e.target.tagName || "").toLowerCase();
      if (["input", "textarea", "select"].includes(tag) || document.querySelector("dialog[open]")) {
        if (e.key === "Escape" && tag === "input" && e.target.id === "search") e.target.blur();
        return;
      }
      if (e.key === "d") { setMode(currentMode() === "dashboard" ? "reader" : "dashboard"); return; }
      if (e.key === "[" && currentMode() === "reader") { toggleSidebar(); return; }
      if (currentMode() !== "reader") {
        if (e.key === "Escape" && window.FW.dashboard) window.FW.dashboard.closeDrawer();
        return;
      }
      const id = state.current && state.current.id;
      switch (e.key) {
        case "j": move(1); break;
        case "k": move(-1); break;
        case "s": if (id) toggleStar(id); break;
        case "m": if (id) setRead(id, !state.current.is_read); break;
        case "o": case "v": {
          const url = state.current && safeUrl(state.current.url);
          if (url) window.open(url, "_blank", "noopener,noreferrer");
          break;
        }
        case "r": refreshAll(); break;
        case "/": e.preventDefault(); $("#search").focus(); break;
        case "x": {  // tick the focused or open article (starts select mode)
          const focused = document.activeElement && document.activeElement.closest && document.activeElement.closest(".article-item");
          const target = focused ? Number(focused.dataset.id) : (state.selectedId || id);
          if (target) toggleChecked(target, e.shiftKey);
          break;
        }
        case "Escape":
          if (state.selecting) { setSelecting(false); break; }
          $("#app").classList.remove("show-reader", "show-sidebar"); syncSidebarButton();
          break;
        default: return;
      }
    });
  }

  async function init() {
    let me;
    try {
      me = await api("GET", "/auth/me");
    } catch (_) {
      return; // api() already redirected on 401
    }
    CSRF = me.csrf_token;
    bindEvents();
    setupPaneResizers();
    restoreSidebar();
    if (me.initial_password_pending) {
      // The generated first-run password is still in use (OWASP: change default credentials).
      const bar = h("div", { class: "security-banner", role: "alert" },
        "⚠ You are still using the generated first-run password. ",
        h("button", { type: "button", class: "btn small", text: "Change it now", onclick: () => openSettings("account") }));
      document.body.prepend(bar);
    }
    state.settings = (await guarded(() => api("GET", "/settings"))) || {};
    loadReadLater();
    applySettings();
    await loadSidebar();
    const dv = state.settings.default_view || "unread";
    selectView({ type: dv });
    renderReader();
    setMode(state.settings.ui_mode || "reader", false);
    setInterval(loadSidebar, 60_000);
  }

  // Shared helpers for charts.js / dashboard.js (same origin, loaded after this file).
  // ======================================================== custom date range (every tab)
  /** A range is {from: "YYYY-MM-DD" | "", to: "YYYY-MM-DD" | ""} in local time; either end may be empty (open). */
  const ISO_DAY = /^\d{4}-\d{2}-\d{2}$/;
  function cleanRange(r) {
    if (!r || typeof r !== "object") return null;
    const from = ISO_DAY.test(r.from || "") ? r.from : "";
    const to = ISO_DAY.test(r.to || "") ? r.to : "";
    return from || to ? { from, to } : null;
  }
  const dayStart = (iso) => { const [y, m, d] = iso.split("-").map(Number); return Math.floor(new Date(y, m - 1, d).getTime() / 1000); };
  /** {since, until} in unix seconds: from the start of "from" up to the end of "to" (local days). */
  function rangeTimes(r) {
    const c = cleanRange(r);
    if (!c) return {};
    const out = {};
    if (c.from) out.since = dayStart(c.from);
    if (c.to) { const [y, m, d] = c.to.split("-").map(Number); out.until = Math.floor(new Date(y, m - 1, d + 1).getTime() / 1000); }
    return out;
  }
  function addRangeParams(p, r) {
    const t = rangeTimes(r);
    if (t.since != null) p.set("since", String(t.since));
    if (t.until != null) p.set("until", String(t.until));
    return p;
  }
  const shortDay = (iso) => { const [y, m, d] = iso.split("-").map(Number); return new Date(y, m - 1, d).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }); };
  function rangeLabel(r) {
    const c = cleanRange(r);
    if (!c) return "Any date";
    if (c.from && c.to) return c.from === c.to ? shortDay(c.from) : `${shortDay(c.from)} – ${shortDay(c.to)}`;
    return c.from ? `From ${shortDay(c.from)}` : `Until ${shortDay(c.to)}`;
  }
  const isoOf = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  /** Ask for a from / to range. Resolves to the new range, null for "clear", or undefined when cancelled. */
  function pickDateRange(current, title = "Custom date range") {
    const c = cleanRange(current) || { from: "", to: "" };
    return new Promise((resolve) => {
      const today = isoOf(new Date());
      const from = h("input", { type: "date", value: c.from, max: today, "aria-label": "From" });
      const to = h("input", { type: "date", value: c.to, max: today, "aria-label": "To" });
      const err = h("p", { class: "muted small", role: "alert" });
      let result;
      const preset = (days) => { const d = new Date(); d.setDate(d.getDate() - days + 1); from.value = isoOf(d); to.value = today; };
      const dlg = h("dialog", { class: "dialog range-dialog", "aria-label": title },
        h("form", { class: "form", method: "dialog" },
          h("h3", { text: `📅 ${title}` }),
          h("div", { class: "range-row" }, h("label", {}, "From", from), h("label", {}, "To", to)),
          h("div", { class: "range-presets" },
            [[7, "Last 7 days"], [30, "Last 30 days"], [90, "Last 90 days"], [365, "Last year"]].map(([d, l]) =>
              h("button", { type: "button", class: "btn small", text: l, onclick: () => preset(d) })),
            h("button", { type: "button", class: "btn small", text: "This year", onclick: () => { from.value = `${new Date().getFullYear()}-01-01`; to.value = today; } })),
          h("p", { class: "muted small", text: "Leave one end empty for an open range (everything since / until a date)." }),
          err,
          h("div", { class: "form-actions" },
            h("button", { type: "button", class: "btn", text: "Clear dates", onclick: () => { result = null; dlg.close(); } }),
            h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
            h("button", { type: "submit", class: "btn primary", text: "Apply", onclick: (e) => {
              const r = cleanRange({ from: from.value, to: to.value });
              if (r && r.from && r.to && r.to < r.from) { e.preventDefault(); err.textContent = "The end date is before the start date."; return; }
              result = r;
            } }))));
      dlg.addEventListener("close", () => { dlg.remove(); resolve(result); });
      document.body.append(dlg);
      dlg.showModal();
      from.focus();
    });
  }
  /** A "📅 <range>" button that opens the picker; onChange(range|null) runs when it changes. */
  function dateRangeButton({ value, onChange, title }) {
    const c = cleanRange(value);
    return h("button", { type: "button", class: `btn small date-range-btn ${c ? "on" : ""}`, text: `📅 ${rangeLabel(c)}`,
      title: title || "Show only items published between two dates", "aria-label": `Date range: ${rangeLabel(c)}`,
      onclick: async () => { const r = await pickDateRange(c); if (r !== undefined) onChange(r); } });
  }
  const dateRange = { clean: cleanRange, times: rangeTimes, addParams: addRangeParams, label: rangeLabel, pick: pickDateRange, button: dateRangeButton };

  /** "Keep (retention)" select for add dialogs: fixed choices plus Custom… (a number + days / weeks / months / years).
   *  choices: [[value, label]] with "" = the default (null), "0" = keep forever. days(): null = default, 0 = forever,
   *  N = days, NaN = an invalid custom value. */
  const KEEP_UNITS = { days: 1, weeks: 7, months: 30, years: 365 };
  const KEEP_MAX_DAYS = 36500;
  function keepPicker({ choices, selected = "", label = "Keep (retention)" }) {
    const select = h("select", { "aria-label": label },
      choices.map(([v, l]) => h("option", { value: String(v), text: l, selected: String(selected) === String(v) })),
      h("option", { value: "custom", text: "Custom…" }));
    const amount = h("input", { type: "number", min: 1, max: KEEP_MAX_DAYS, step: 1, value: 3, class: "custom-minutes", "aria-label": "How many" });
    const unit = h("select", { "aria-label": "Unit" }, Object.keys(KEEP_UNITS).map((u) => h("option", { value: u, text: u, selected: u === "years" })));
    const said = h("span", { class: "muted small custom-said" });
    const custom = h("span", { class: "tf-custom", hidden: true }, amount, unit, said);
    const days = () => {
      if (select.value === "") return null;
      if (select.value !== "custom") return Number(select.value);
      const n = Number(amount.value), d = n * KEEP_UNITS[unit.value];
      return Number.isInteger(n) && n >= 1 && d <= KEEP_MAX_DAYS ? d : NaN;
    };
    const say = () => {
      const d = days();
      said.textContent = Number.isNaN(d) ? "1 day to 100 years" : `= ${fmtRetention(d)}`;
      said.classList.toggle("error", Number.isNaN(d));
    };
    select.addEventListener("change", () => { custom.hidden = select.value !== "custom"; if (!custom.hidden) { say(); amount.focus(); } });
    amount.addEventListener("input", say);
    unit.addEventListener("change", say);
    const describe = () => {
      const d = days();
      return select.value === "custom" ? (Number.isNaN(d) ? "an invalid time frame" : `the last ${fmtRetention(d, true)}`)
        : select.selectedOptions[0].text.toLowerCase();
    };
    return { el: h("span", { class: "tf-picker" }, select, custom), select, days, describe };
  }

  window.FW = {
    dateRange, keepPicker,
    api, h, fill, toast, guarded, safeUrl, safeColor, relTime, fullDate, fmtDate, fmtRetention, store, state,
    openArticleInReader, setMode, openSettings, currentMode, fmtMinutes, makeResizer, enhanceDrawer, buildContent,
    refreshPicker, fillFolderSelect, selectView: (v) => selectView(v), loadArticles: () => loadArticles(),
    loadSidebar: () => loadSidebar(), tagFold, tagsToggle, loadReadLater: () => loadReadLater(), marked,
  };

  init();
})();
