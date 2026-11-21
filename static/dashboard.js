"use strict";
/*
 * Eye of Sauron dashboards - the second interface.
 * Customisable dashboards made of widgets (KPI, trend, breakdown, article list),
 * each backed by POST /api/v1/analytics/query. Click any bar, slice, legend entry,
 * data point or KPI to drill into the matching articles.
 * All dynamic text is rendered with textContent (via FW.h / charts.js).
 */
(function () {
  const FW = window.FW;
  const C = window.FWCharts;
  if (!FW || !C) return;
  const { h, api, toast, guarded, fill, safeUrl } = FW;
  const $ = (sel) => document.querySelector(sel);

  const RANGE_CHOICES = [[0, "Each widget's own"], [1, "Last 24 hours"], [7, "Last 7 days"], [30, "Last 30 days"],
    [90, "Last 90 days"], [180, "Last 6 months"], [365, "Last year"]];
  const DAY_CHOICES = [1, 3, 7, 14, 30, 60, 90, 180, 365, 730];
  const GROUPS = { tag: "Collection", feed: "Feed", folder: "Folder", watchlist: "Watchlist entities" };

  const st = {
    dashboards: [],
    current: null,
    templates: [],
    meta: { watchlists: [], entities: [] },
    cveMeta: null,
    range: 0,  // top "Range": 0 = each widget's own; otherwise a temporary sync for all widgets (not remembered)
    custom: null,  // 📅 custom from / to range for all widgets ({from, to}); st.range then holds its length in days
    dragWidget: null, dragDash: null,
    edit: false,
    timer: null,
    visible: false,
    cards: new Map(), // widget id -> {w, body, result, tableMode}
    resizeObs: null,
  };

  const tzOffset = () => -new Date().getTimezoneOffset();
  const root = () => $("#dashboardView");
  const randomId = () => {
    const b = new Uint8Array(4);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));

  // ===================================================================== data
  async function loadMeta() {
    const [watchlists, entities, templates] = await Promise.all([
      guarded(() => api("GET", "/watchlists")),
      guarded(() => api("GET", "/entities")),
      st.templates.length ? Promise.resolve(st.templates) : guarded(() => api("GET", "/dashboard-templates")),
    ]);
    st.cveMeta = FW.cve ? await FW.cve.meta(true).catch(() => null) : null;
    st.meta.watchlists = watchlists || [];
    st.meta.entities = entities || [];
    st.templates = templates || [];
  }

  async function loadList() {
    st.dashboards = (await guarded(() => api("GET", "/dashboards"))) || [];
  }

  async function openDashboard(id) {
    const d = await guarded(() => api("GET", `/dashboards/${id}`));
    if (!d) return;
    st.current = d;
    FW.store.set("fw-dash-last", id);
    render();
  }

  async function saveCurrent(okMsg) {
    const d = st.current;
    const res = await guarded(() => api("PUT", `/dashboards/${d.id}`, { name: d.name, position: d.position, widgets: d.widgets }), okMsg);
    if (res) {
      st.current = res;
      await loadList();
      render();
    }
    return res;
  }

  // ===================================================================== naming helpers
  const nameOf = {
    watchlist: (id) => (st.meta.watchlists.find((w) => w.id === id) || {}).name || `#${id}`,
    entity: (id) => (st.meta.entities.find((e) => e.id === id) || {}).name || `#${id}`,
    tag: (id) => (FW.state.sidebar.tags.find((t) => t.id === id) || {}).name || `#${id}`,
    feed: (id) => ([...FW.state.sidebar.feeds, ...(FW.state.sidebar.media_feeds || []), ...(FW.state.sidebar.account_feeds || [])].find((f) => f.id === id) || {}).title || `#${id}`,
    folder: (id) => (FW.state.sidebar.folders.find((f) => f.id === id) || {}).name || `#${id}`,
  };

  function periodLabel(days) {
    if (days === 1) return "Last 24 hours";
    if (days % 365 === 0) return days === 365 ? "Last year" : `Last ${days / 365} years`;
    return `Last ${days} days`;
  }

  function describeCve(q) {
    const f = q.filters || {};
    const parts = [periodLabel(q.days) + (q.date_field === "kev_added" ? " (added to KEV)" : q.date_field === "modified" ? " (modified)" : "")];
    if (f.severities && f.severities.length) parts.push(f.severities.map((x) => FW.cve.SEV_LABEL[x] || x).join("/"));
    if (f.min_score !== null && f.min_score !== undefined) parts.push(`CVSS ≥ ${f.min_score}`);
    const catName = (slug) => ((st.cveMeta && st.cveMeta.categories.find((c) => c.slug === slug)) || {}).name || slug;
    if (f.categories && f.categories.length) parts.push(f.categories.slice(0, 2).map(catName).join(", ") + (f.categories.length > 2 ? ` +${f.categories.length - 2}` : ""));
    if (f.exclude_categories && f.exclude_categories.length) parts.push(`not ${f.exclude_categories.slice(0, 2).map(catName).join(", ")}`);
    if (f.owasp && f.owasp.length) parts.push(`OWASP ${f.owasp.join(", ")}`);
    if (f.vendors && f.vendors.length) parts.push(`vendors: ${f.vendors.slice(0, 2).join(", ")}${f.vendors.length > 2 ? "…" : ""}`);
    if (f.cwe_ids && f.cwe_ids.length) parts.push(`CWE-${f.cwe_ids.slice(0, 3).join(", CWE-")}`);
    if (f.require_categories && f.require_categories.length) parts.push(f.require_categories.slice(0, 2).map(catName).join(" and ") + (f.require_categories.length > 2 ? ` +${f.require_categories.length - 2}` : ""));
    if (f.kev_only) parts.push("CISA KEV");
    if (f.exploited_only) parts.push("exploited");
    if (f.ransomware_only) parts.push("ransomware use");
    if (f.q) parts.push(`“${f.q}”`);
    if (f.match === "any" && parts.length > 2) return `${parts[0]} · any of: ${parts.slice(1).join(" / ")}`;
    return parts.join(" · ");
  }

  function describeArticles(f) {
    const parts = [];
    const list = (ids, fn, max = 2, joiner = ", ") => ids.slice(0, max).map(fn).join(joiner) + (ids.length > max ? ` +${ids.length - max}` : "");
    if (f.watchlist_ids && f.watchlist_ids.length) parts.push(`mentions ${list(f.watchlist_ids, nameOf.watchlist)}`);
    if (f.entity_ids && f.entity_ids.length) parts.push(`mentions ${list(f.entity_ids, nameOf.entity, 2, " or ")}`);
    if (f.require_entity_ids && f.require_entity_ids.length) parts.push(`mentions ${list(f.require_entity_ids, nameOf.entity, 2, " and ")}`);
    if (f.tag_ids && f.tag_ids.length) parts.push(`in ${list(f.tag_ids, nameOf.tag, 2, " or ")}`);
    if (f.require_tag_ids && f.require_tag_ids.length) parts.push(`in ${list(f.require_tag_ids, nameOf.tag, 2, " and ")}`);
    if (f.feed_ids && f.feed_ids.length) parts.push(`feeds: ${list(f.feed_ids, nameOf.feed)}`);
    if (f.folder_ids && f.folder_ids.length) parts.push(`folders: ${list(f.folder_ids, nameOf.folder)}`);
    if (f.q) parts.push(`“${f.q}”`);
    const joined = f.match === "any" && parts.length > 1 ? `any of: ${parts.join(" / ")}` : parts.join(" · ");
    const always = [];
    if (f.exclude_entity_ids && f.exclude_entity_ids.length) always.push(`not ${list(f.exclude_entity_ids, nameOf.entity)}`);
    if (f.starred) always.push("starred");
    if (f.unread) always.push("unread");
    return [joined, ...always].filter(Boolean).join(" · ");
  }

  function describe(q) {
    if (q.dataset === "observatory") return "🔭 Public threat data · updated automatically";
    if (q.dataset === "cves") return describeCve(q);
    if (q.dataset === "combined") {
      const news = describeArticles(q.articles || {});
      const cves = describeCve({ days: q.days, date_field: q.date_field, filters: q.cves || {} }).split(" · ").slice(1).join(" · ");
      return [periodLabel(q.days), `news${news ? `: ${news}` : ""}`, `CVEs${cves ? `: ${cves}` : ""}`].join(" · ");
    }
    const rest = describeArticles(q.filters || {});
    return [periodLabel(q.days), rest].filter(Boolean).join(" · ");
  }

  const autoBucket = (days) => (days <= 45 ? "day" : days <= 200 ? "week" : "month");

  function effectiveQuery(w) {
    const q = clone(w.query);
    q.tz_offset_minutes = tzOffset();
    if (st.range) {
      q.days = st.range;
      if (q.type === "timeseries") q.bucket = autoBucket(st.range);
    }
    if (st.custom && q.dataset !== "observatory") {  // ready-made 🔭 panels have fixed periods
      const t = FW.dateRange.times(st.custom);
      q.until_ts = t.until != null ? t.until : Math.floor(Date.now() / 1000) + 1;
    }
    return q;
  }

  /** Change one widget's own time range (saved with the widget). */
  async function setWidgetRange(idx, days) {
    const w = clone(st.current.widgets[idx]);
    w.query.days = days;
    if (w.query.type === "timeseries") w.query.bucket = autoBucket(days);
    // titles from the templates end in the period ("Articles · 7 days", "… · 30d"): keep that part true
    w.title = w.title.replace(/ · \d+ ?(?:d|days?)$/, ` · ${days === 1 ? "24h" : days % 365 === 0 ? `${days / 365}y` : `${days}d`}`);
    const widgets = st.current.widgets.slice();
    widgets[idx] = w;
    const res = await guarded(() => api("PUT", `/dashboards/${st.current.id}`, { name: st.current.name, position: st.current.position, widgets }));
    if (res) { st.current = res; renderGrid(); }
  }

  function setSync(days) {
    st.range = days;
    st.custom = null;
    render();
  }

  /** 📅 one custom from / to range for every widget: its length becomes the widgets' period, its end their window end. */
  async function pickCustom() {
    const r = await FW.dateRange.pick(st.custom, "Date range for all widgets");
    if (r === undefined) { render(); return; }
    if (!r) { setSync(0); return; }
    const t = FW.dateRange.times(r);
    const until = t.until != null ? t.until : Math.floor(Date.now() / 1000) + 1;
    const since = t.since != null ? t.since : until - 3650 * 86400;
    st.custom = r;
    st.range = Math.min(3650, Math.max(1, Math.round((until - since) / 86400)));
    render();
  }
  const syncLabel = () => (st.custom ? FW.dateRange.label(st.custom) : periodLabel(st.range).toLowerCase());

  // ===================================================================== rendering
  function render() {
    const view = root();
    fill(view, );
    st.cards.clear();

    const tabs = h("div", { class: "dash-tabs", role: "tablist" },
      st.dashboards.map((d) => h("button", {
        type: "button", role: "tab", class: st.current && st.current.id === d.id ? "active" : "",
        "aria-selected": String(Boolean(st.current && st.current.id === d.id)),
        onclick: () => openDashboard(d.id), text: d.name,
      })));

    const newSel = h("select", { "aria-label": "New dashboard", class: "new-dash" },
      h("option", { value: "", text: "+ New dashboard…" }),
      h("option", { value: "blank", text: "Blank dashboard" }),
      h("optgroup", { label: "From template" }, st.templates.map((t) => h("option", { value: `tpl:${t.key}`, text: t.name }))));
    newSel.addEventListener("change", () => { const v = newSel.value; newSel.value = ""; if (v) createDashboard(v); });

    const rangeSel = h("select", { "aria-label": "Time range for all widgets", title: "Show every widget over the same period for now (each widget keeps its own range)" },
      RANGE_CHOICES.map(([v, l]) => h("option", { value: v, text: v ? `All: ${l.toLowerCase()}` : l, selected: !st.custom && v === st.range })),
      h("option", { value: "custom", text: st.custom ? `📅 All: ${FW.dateRange.label(st.custom)}` : "📅 Custom range…", selected: Boolean(st.custom) }));
    rangeSel.addEventListener("change", () => (rangeSel.value === "custom" ? pickCustom() : setSync(Number(rangeSel.value))));

    const tools = h("div", { class: "dash-tools" },
      h("label", { class: "muted", text: "Range" }), rangeSel,
      st.range ? h("button", { type: "button", class: "btn small", text: "↺ Reset", title: "Back to each widget's own time range", onclick: () => setSync(0) }) : null,
      h("button", { type: "button", class: "icon-btn", title: "Reload data", "aria-label": "Reload data", text: "⟳", onclick: () => renderGrid() }),
      st.current ? h("button", { type: "button", class: `btn ${st.edit ? "primary" : ""}`, text: st.edit ? "✓ Done" : "✎ Edit", onclick: () => { st.edit = !st.edit; render(); } }) : null,
      newSel);

    view.append(h("div", { class: "dash-header" }, tabs, tools));
    if (st.current && st.edit) tabs.querySelectorAll("button[role=tab]").forEach((b, i) => dashTabDrag(b, st.dashboards[i]));
    if (st.range && st.current) {
      view.append(h("div", { class: "dash-sync", role: "status" },
        h("span", { text: `🔗 All widgets show ${syncLabel()} for now. Their own ranges are unchanged.` }),
        st.custom ? h("button", { type: "button", class: "btn small", text: "📅 Change dates", onclick: () => pickCustom() }) : null,
        h("button", { type: "button", class: "btn small", text: "↺ Back to each widget's own range", onclick: () => setSync(0) })));
    }

    if (st.current && st.edit) {
      view.append(h("div", { class: "dash-editbar" },
        h("button", { type: "button", class: "btn primary", text: "+ Add widget", onclick: () => openEditor(null) }),
        h("button", { type: "button", class: "btn", text: "Rename", onclick: renameDashboard }),
        h("button", { type: "button", class: "btn", text: "Set as start dashboard", onclick: setDefault }),
        h("button", { type: "button", class: "btn", text: "Move left", onclick: () => moveDashboard(-1) }),
        h("button", { type: "button", class: "btn", text: "Move right", onclick: () => moveDashboard(1) }),
        h("button", { type: "button", class: "btn danger", text: "Delete dashboard", onclick: deleteDashboard }),
        h("span", { class: "muted", text: "Tip: drag a widget by its title bar to move it, and drag a tab to reorder dashboards (◀ ▶ work too)." })));
    }

    view.append(h("div", { id: "dashNotice", class: "dash-notice", hidden: true }));

    if (!st.current) {
      view.append(gallery());
      return;
    }
    view.append(h("div", { id: "dashGrid", class: "dash-grid" }));
    renderGrid();
  }

  function gallery() {
    return h("div", { class: "gallery" },
      h("h2", { text: "Create your first dashboard" }),
      h("p", { class: "muted", text: "Start from a template and customise it, or build one from scratch. Widgets count articles that match your filters; watchlist groups count articles that mention an entity." }),
      h("div", { class: "gallery-grid" },
        st.templates.map((t) => h("button", { type: "button", class: "gallery-card", onclick: () => createDashboard(`tpl:${t.key}`) },
          h("strong", { text: t.name }), h("span", { class: "muted", text: t.description }))),
        h("button", { type: "button", class: "gallery-card", onclick: () => createDashboard("blank") },
          h("strong", { text: "Blank dashboard" }), h("span", { class: "muted", text: "Add your own widgets and filters." }))));
  }

  function renderGrid() {
    const grid = $("#dashGrid");
    if (!grid || !st.current) return;
    fill(grid, );
    st.cards.clear();
    const widgets = st.current.widgets;
    if (!widgets.length) {
      grid.append(h("div", { class: "chart-empty wide" }, "This dashboard is empty. ",
        h("button", { type: "button", class: "btn primary", text: "+ Add widget", onclick: () => { st.edit = true; openEditor(null); } })));
      return;
    }
    widgets.forEach((w, idx) => grid.append(card(w, idx)));
    observeResize(grid);
  }

  function card(w, idx) {
    const body = h("div", { class: "widget-body" }, h("div", { class: "chart-loading", text: "Loading…" }));
    const entry = { w, body, result: null, tableMode: false };
    st.cards.set(w.id, entry);
    const canTable = w.query.type === "timeseries" || (w.query.type === "breakdown" && w.chart !== "table");
    const isCve = w.query.dataset === "cves" || w.query.dataset === "combined";
    const q = effectiveQuery(w);
    const own = typeof w.query.days === "number" ? w.query.days : null;
    const rangeSel = own === null ? null : h("select", {
      class: "widget-range", "aria-label": `Time range for ${w.title}`, disabled: Boolean(st.range),
      title: st.range ? `Synced to the top Range (${syncLabel()}). This widget's own range: ${periodLabel(own).toLowerCase()} - press ↺ Reset to go back.`
        : "This widget's time range (saved with the widget)",
    }, [...new Set([...DAY_CHOICES, own, st.range || own])].sort((a, b) => a - b).map((d) => h("option", { value: d, text: periodLabel(d), selected: d === (st.range || own) })));
    if (rangeSel) rangeSel.addEventListener("change", () => setWidgetRange(idx, Number(rangeSel.value)));
    const actions = h("div", { class: "widget-actions" },
      rangeSel,
      canTable ? h("button", { type: "button", class: "icon-btn small", title: "Toggle table view", "aria-label": "Toggle table view", text: "▦",
        onclick: () => { entry.tableMode = !entry.tableMode; draw(entry); } }) : null,
      st.edit ? [
        h("button", { type: "button", class: "icon-btn small", title: "Move left", "aria-label": "Move widget left", text: "◀", onclick: () => moveWidget(idx, -1) }),
        h("button", { type: "button", class: "icon-btn small", title: "Move right", "aria-label": "Move widget right", text: "▶", onclick: () => moveWidget(idx, 1) }),
        w.query.dataset === "observatory" ? null : h("button", { type: "button", class: "icon-btn small", title: "Edit", "aria-label": "Edit widget", text: "✎", onclick: () => openEditor(idx) }),
        w.query.dataset === "observatory" ? null : h("button", { type: "button", class: "icon-btn small", title: "Duplicate", "aria-label": "Duplicate widget", text: "⧉", onclick: () => duplicateWidget(idx) }),
        h("button", { type: "button", class: "icon-btn small danger", title: "Remove", "aria-label": "Remove widget", text: "✕", onclick: () => removeWidget(idx) }),
      ] : null);
    if (w.height) { body.style.height = `${w.height}px`; body.style.maxHeight = "none"; body.classList.add("fixed-height"); }
    const head = h("header", { class: "widget-head" },
      h("div", { class: "widget-titles" }, h("h3", { text: w.title }), h("div", { class: "widget-sub", text: describe(q) })),
      actions);
    const section = h("section", { class: `widget type-${w.query.type}${isCve ? " dataset-cves" : ""}` }, head, body);
    if (st.edit) widgetDrag(section, head, idx);
    section.style.setProperty("--w", String(widthOf(w)));  // width as % of the row (CSS flex-basis)
    section.classList.toggle("wide", widthOf(w) > 55);      // narrow screens: wide widgets take the full row
    if (st.edit) addResizeHandles(section, body, w, idx);
    loadWidget(entry);
    return section;
  }

  // ===================================================================== drag-resizing widgets (edit mode)
  /** Free-form: the right edge sets the width (% of the row) and the bottom edge the height (px), exactly where
   *  you drag them - no snapping. The widget follows the pointer and the size is saved when you let go.
   *  Arrow keys on a focused handle: ±5% width / ±20 px height. Double-click bottom/corner: automatic height. */
  function addResizeHandles(section, body, w, idx) {
    const handles = [["e", "Drag to change width (double-click the corner to reset the height)"], ["s", "Drag to change height (double-click: automatic)"],
      ["se", "Drag to resize (double-click: automatic height)"]];
    for (const [dir, title] of handles) {
      const el = h("div", { class: `widget-resize rz-${dir}`, title, role: "separator", tabindex: "0", "aria-label": title });
      el.addEventListener("pointerdown", (e) => startResize(e, dir, section, body, w, idx, el));
      el.addEventListener("keydown", (e) => keyResize(e, dir, w, idx));
      if (dir !== "e") el.addEventListener("dblclick", () => commitResize(idx, widthOf(w), null));
      section.append(el);
    }
  }

  function startResize(e, dir, section, body, w, idx, handle) {
    if (e.button !== 0) return;
    e.preventDefault();
    const grid = section.parentElement;
    const gap = parseFloat(getComputedStyle(grid).columnGap) || 14;
    const gridW = grid.clientWidth;
    const rect = section.getBoundingClientRect();
    const bodyH = body.getBoundingClientRect().height;
    const startX = e.clientX;
    const startY = e.clientY;
    const startPct = widthOf(w);
    let pct = startPct;
    let height = w.height || null;
    const sizeLabel = h("div", { class: "resize-readout" });
    section.append(sizeLabel);
    try { handle.setPointerCapture(e.pointerId); } catch (_) { /* window listeners below still track the drag */ }
    section.classList.add("resizing");
    document.body.classList.add("is-resizing");
    const readout = () => { sizeLabel.textContent = `${Math.round(pct)}% wide${height ? ` · ${height}px tall` : ""}`; };
    readout();
    const move = (ev) => {
      if (dir !== "s") {
        // Width in % of the row, inverting the flex-basis formula used in CSS (exact pixel tracking, no steps).
        const px = rect.width + (ev.clientX - startX);
        pct = Math.max(15, Math.min(100, ((px + gap) / (gridW + gap)) * 100));
        section.style.setProperty("--w", pct.toFixed(2));
      }
      if (dir !== "e") {
        height = Math.round(Math.max(120, Math.min(1400, bodyH + (ev.clientY - startY))));
        body.style.height = `${height}px`;
        body.style.maxHeight = "none";
      }
      readout();
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
      section.classList.remove("resizing");
      document.body.classList.remove("is-resizing");
      sizeLabel.remove();
      const newPct = Math.round(pct * 10) / 10;
      if (Math.abs(newPct - startPct) >= 0.1 || height !== (w.height || null)) commitResize(idx, newPct, height);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);
  }

  function keyResize(e, dir, w, idx) {
    let pct = widthOf(w);
    let height = w.height || null;
    if (dir !== "s" && (e.key === "ArrowRight" || e.key === "ArrowLeft")) {
      pct = Math.max(15, Math.min(100, pct + (e.key === "ArrowRight" ? 5 : -5)));
    } else if (dir !== "e" && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      height = Math.max(120, Math.min(1400, (w.height || 300) + (e.key === "ArrowDown" ? 20 : -20)));
    } else return;
    e.preventDefault();
    commitResize(idx, pct, height);
  }

  function commitResize(idx, pct, height) {
    const w = st.current.widgets[idx];
    if (!w) return;
    w.width = pct;
    w.size = sizeFor(pct);
    if (height) w.height = height; else delete w.height;
    saveCurrent();
  }

  async function loadWidget(entry) {
    try {
      const q = effectiveQuery(entry.w);
      if (entry.sort) q.sort = entry.sort;
      entry.result = await api("POST", "/analytics/query", q);
      if (entry.result.indexing) showNotice("⏳ Indexing entity mentions in the background — numbers will grow as it completes.");
      draw(entry);
    } catch (err) {
      fill(entry.body, h("div", { class: "chart-empty error", text: err.message }));
    }
  }

  function showNotice(text) {
    const n = $("#dashNotice");
    if (n) { n.textContent = text; n.hidden = false; }
  }

  function draw(entry) {
    const { w, body, result } = entry;
    if (!result) return;
    if (result.dataset === "observatory") { obsPanel(body, result, w); return; }
    const pick = (item) => drill(w, { item });
    const countLabel = result.dataset === "cves" ? "CVEs" : "Articles";
    if (result.type === "cves") {
      FW.cve.cveTable(body, result.items, {
        sort: entry.sort || w.query.sort || "newest", dateField: w.query.date_field, compact: w.size !== "xl",
        onSort: (key) => { entry.sort = key; loadWidget(entry); },
      });
      if (result.total > result.items.length) {
        body.append(h("button", { type: "button", class: "link-btn small more-link", text: `Showing ${result.items.length} of ${result.total.toLocaleString()} — open all`,
          onclick: () => drill(w, {}) }));
      }
      return;
    }
    if (result.type === "kpi_pair") {
      C.kpiPair(body, result.items, (item) => drillCombined(w, { key: item.key }));
      return;
    }
    if (result.type === "mixed") {
      mixedList(body, result.items);
      return;
    }
    if (result.dataset === "combined" && result.type === "timeseries") {
      if (entry.tableMode) { C.seriesTable(body, result.buckets, result.series, result.bucket); return; }
      C.timeChart(body, {
        buckets: result.buckets, series: result.series, bucket: result.bucket, kind: w.chart,
        height: w.height ? Math.max(100, w.height - 50) : 230,
        onPick: (i) => drillCombined(w, { bucket: result.buckets[i], bucketType: result.bucket, counts: result.series.map((x) => x.values[i]) }),
        onSeries: (item) => drillCombined(w, { key: item.key }),
      });
      return;
    }
    if (result.type === "kpi") {
      C.kpi(body, result, () => drill(w, {}));
    } else if (result.type === "timeseries") {
      if (entry.tableMode) { C.seriesTable(body, result.buckets, result.series, result.bucket); return; }
      C.timeChart(body, {
        buckets: result.buckets, series: result.series, bucket: result.bucket, kind: w.chart,
        height: w.height ? Math.max(100, w.height - 50) : (w.size === "s" ? 160 : 230),
        onPick: (i) => drill(w, { bucket: result.buckets[i], bucketType: result.bucket }),
        onSeries: result.group_by && result.group_by !== "none" ? pick : null,
      });
    } else if (result.type === "breakdown") {
      if (entry.tableMode || w.chart === "table") C.table(body, result.items, pick, countLabel);
      else if (w.chart === "donut") C.donut(body, result.items, pick);
      else if (w.chart === "pie") C.donut(body, result.items, pick, true);
      else if (w.chart === "bar") C.columns(body, result.items, pick, w.height ? Math.max(120, w.height - 30) : 240);
      else C.hbar(body, result.items, pick);
    } else {
      articleList(body, result.items);
    }
  }

  /** 🔭 A ready-made panel: blocks (stats, charts, bars, tables) + "How to read it" + sources. */
  function obsPanel(body, r, w) {
    fill(body);
    const fmtTs = (ts) => (ts ? FW.relTime(ts) : "");
    for (const b of r.blocks || []) {
      if (b.title) body.append(h("div", { class: "obs-sub", text: b.title }));
      if (b.kind === "note") body.append(h("div", { class: "chart-empty", text: b.text }));
      else if (b.kind === "stats") {
        body.append(h("div", { class: "obs-stats" }, b.items.map((s) => h("div", { class: `obs-stat${s.tone ? ` tone-${s.tone}` : ""}` },
          h("div", { class: "obs-value", text: s.value }), h("div", { class: "obs-label", text: s.label }),
          s.sub ? h("div", { class: "obs-delta", text: s.sub }) : null))));
      } else if (b.kind === "chart") {
        const host = h("div", { class: "obs-chart" });
        body.append(host);
        requestAnimationFrame(() => C.timeChart(host, { buckets: b.buckets, series: b.series, bucket: b.bucket, kind: b.chart,
          height: b.height || 200, onPick: null, onSeries: null }));
      } else if (b.kind === "hbar") {
        const host = h("div"); body.append(host); C.hbar(host, b.items, null);
      } else if (b.kind === "columns") {
        const host = h("div"); body.append(host);
        requestAnimationFrame(() => C.columns(host, b.items, null, 210));
      } else if (b.kind === "table") body.append(obsTable(b));
    }
    if (r.note) body.append(h("div", { class: "muted small obs-note", text: r.note }));
    body.append(h("details", { class: "obs-how" }, h("summary", { text: "ℹ️ How to read it" }), h("p", { text: r.how || "" }),
      h("p", { class: "muted small" }, "Source: ", ...(r.sources || []).flatMap((s, i) => [i ? " · " : "",
        safeUrl(s.url) ? h("a", { href: safeUrl(s.url), target: "_blank", rel: "noopener noreferrer", text: s.name }) : s.name]),
        r.updated ? ` · updated ${fmtTs(r.updated)}` : "")));
  }

  function obsTable(b) {
    const wrap = h("div", { class: "obs-table" });
    const numeric = new Set(b.numeric || []);
    const tbody = h("tbody");
    const rows = b.rows.map((row) => {
      const tr = h("tr", null, row.map((cell, i) => {
        if (i === b.link_col) {
          const u = safeUrl(cell);
          return h("td", null, u ? h("a", { href: u, target: "_blank", rel: "noopener noreferrer", text: "↗", title: "Open on the source site" }) : "");
        }
        return h("td", { class: numeric.has(i) ? "num" : "", text: typeof cell === "number" ? cell.toLocaleString() : String(cell ?? "") });
      }));
      tr.dataset.search = row.filter((c, i) => i !== b.link_col).join(" ").toLowerCase();
      return tr;
    });
    fill(tbody, rows);
    const count = h("span", { class: "muted small", text: `${rows.length} rows` });
    const search = b.search ? h("input", { type: "search", class: "obs-search", placeholder: "Search…", "aria-label": "Search this table",
      oninput: (e) => {
        const q = e.target.value.trim().toLowerCase();
        let n = 0;
        for (const tr of rows) { const show = !q || tr.dataset.search.includes(q); tr.hidden = !show; if (show) n++; }
        count.textContent = `${n} of ${rows.length} rows`;
      } }) : null;
    wrap.append(...(search ? [h("div", { class: "obs-tools" }, search, count)] : []),
      h("div", { class: "obs-scroll" }, h("table", { class: "data compact" },
        h("thead", null, h("tr", null, b.columns.map((c, i) => h("th", { class: numeric.has(i) ? "num" : "", text: c })))), tbody)));
    return wrap;
  }

  /** Combined widgets: latest articles and CVEs in one list, newest first. */
  function mixedList(body, items) {
    fill(body);
    if (!items.length) { body.append(h("div", { class: "chart-empty", text: "No matching articles or CVEs in this period." })); return; }
    body.append(h("ul", { class: "dash-articles mixed" }, items.map((it) => {
      if (it.kind === "article") {
        const li = articleRow(it);
        li.prepend(h("span", { class: "mix-kind k-article", text: "News" }));
        return li;
      }
      const sev = it.severity ? FW.cve.SEV_LABEL[it.severity] || it.severity : "Unscored";
      return h("li", null,
        h("span", { class: "mix-kind k-cve", text: "CVE" }),
        h("button", { type: "button", class: "link-btn title", text: `${it.id}${it.kev ? " · KEV" : ""}`, title: "Show CVE details",
          onclick: () => FW.cve.openCve(it.id) }),
        h("div", { class: "muted" },
          h("span", { text: `${sev}${it.score != null ? ` ${it.score}` : ""}` }), " · ",
          h("span", { text: FW.relTime(it.ts), title: FW.fullDate(it.ts) }), " · ",
          h("span", { class: "mix-desc", text: (it.description || "").slice(0, 160) })));
    })));
  }

  /** Drill-down for combined widgets: open the article side or the CVE side with that side's own filters. */
  function drillCombined(w, { key, bucket, bucketType, counts }) {
    const q = effectiveQuery(w);
    const asArticles = { title: `${w.title} — news articles`, query: { dataset: "articles", type: "articles", days: q.days, filters: q.articles || {} } };
    const asCves = { title: `${w.title} — CVEs`, query: { dataset: "cves", type: "cves", days: q.days, date_field: q.date_field, sort: "newest", filters: q.cves || {} } };
    if (key === "articles") { drill(asArticles, { bucket, bucketType }); return; }
    if (key === "cves") { drillCve(asCves, { bucket, bucketType }); return; }
    // A click on a date: let the reader choose which side to open.
    const [nArt, nCve] = counts || [];
    openDrawer(`${w.title} — ${C.fmtBucket(bucket, bucketType, true)}`, h("div", { class: "row-form" },
      h("button", { type: "button", class: "btn", text: `News articles (${(nArt ?? 0).toLocaleString()})`, onclick: () => drill(asArticles, { bucket, bucketType }) }),
      h("button", { type: "button", class: "btn", text: `CVEs (${(nCve ?? 0).toLocaleString()})`, onclick: () => drillCve(asCves, { bucket, bucketType }) })));
  }

  function articleList(body, items) {
    fill(body, );
    if (!items.length) { body.append(h("div", { class: "chart-empty", text: "No matching articles in this period." })); return; }
    body.append(h("ul", { class: "dash-articles" }, items.map((a) => articleRow(a))));
  }

  function articleRow(a) {
    const url = FW.safeUrl(a.url);
    return h("li", { class: a.is_read ? "" : "unread" },
      h("button", { type: "button", class: "link-btn title", text: a.title, title: "Open in Articles",
        onclick: () => { closeDrawer(); FW.openArticleInReader(a.id); } }),
      h("div", { class: "muted" },
        h("span", { text: a.feed_title }), " · ", h("span", { text: FW.relTime(a.sort_ts), title: FW.fullDate(a.sort_ts) }),
        a.is_starred ? " · ★" : "",
        url ? [" · ", h("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: "original ↗" })] : null));
  }

  function observeResize(grid) {
    if (st.resizeObs) st.resizeObs.disconnect();
    let timer = null;
    let lastWidth = grid.clientWidth;
    st.resizeObs = new ResizeObserver(() => {
      if (Math.abs(grid.clientWidth - lastWidth) < 8) return;
      lastWidth = grid.clientWidth;
      clearTimeout(timer);
      timer = setTimeout(() => {
        for (const entry of st.cards.values()) if (entry.result && entry.result.type === "timeseries") draw(entry);
      }, 150);
    });
    st.resizeObs.observe(grid);
  }

  // ===================================================================== drill-down
  function bucketWindow(q, bucket, bucketType) {
    const [y, m, d] = bucket.split("-").map(Number);
    const startUtc = Date.UTC(y, m - 1, d) / 1000 - q.tz_offset_minutes * 60;
    let endDate;
    if (bucketType === "day") endDate = Date.UTC(y, m - 1, d + 1);
    else if (bucketType === "week") endDate = Date.UTC(y, m - 1, d + 7);
    else endDate = Date.UTC(y, m, 1);
    const endUtc = endDate / 1000 - q.tz_offset_minutes * 60;
    return { until_ts: endUtc, days: Math.max(1, Math.round((endUtc - startUtc) / 86400)) };
  }

  async function drillCve(w, { item, bucket, bucketType }) {
    const q = effectiveQuery(w);
    const filters = clone(q.filters || {});
    let title = w.title;
    if (item) {
      // The clicked bar/slice is a "focus": always ANDed on top of the widget's filters, even in "any" mode.
      title = `${w.title} — ${item.label}`;
      const gb = q.group_by;
      if (gb === "severity") filters.focus = { severity: item.key };
      else if (gb === "category") filters.focus = { category: item.key };
      else if (gb === "cwe") filters.focus = { cwe_id: item.key };
      else if (gb === "vendor") filters.focus = { vendor: item.key };
      else if (gb === "owasp2021" || gb === "owasp2025") filters.focus = { owasp: item.key, owasp_edition: gb.slice(5) };
      else if (gb === "kev") filters.focus = { kev: item.key === 1 };
    }
    const query = { dataset: "cves", type: "cves", days: q.days, date_field: q.date_field || "published", sort: q.sort || "newest",
      limit: 100, offset: 0, tz_offset_minutes: q.tz_offset_minutes, filters };
    if (bucket) {
      Object.assign(query, bucketWindow(q, bucket, bucketType));
      title = `${title} — ${C.fmtBucket(bucket, bucketType, true)}`;
    }
    const holder = h("div");
    const sortSel = h("select", { "aria-label": "Sort CVEs" }, FW.cve.SORTS.map(([v, l]) => h("option", { value: v, text: l, selected: v === query.sort })));
    let items = [];
    const load = async (append) => {
      try {
        const res = await api("POST", "/analytics/query", query);
        items = append ? items.concat(res.items) : res.items;
        FW.cve.cveTable(holder, items, { sort: query.sort, dateField: query.date_field, onSort: (k) => { query.sort = k; sortSel.value = k; query.offset = 0; load(false); } });
        const more = items.length < res.total
          ? h("button", { type: "button", class: "btn small", text: `Load more (${items.length.toLocaleString()} of ${res.total.toLocaleString()})`,
            onclick: () => { query.offset = items.length; load(true); } })
          : null;
        openDrawer(title, h("div", null, h("div", { class: "row-form", style: { "margin-bottom": "8px" } }, "Sort: ", sortSel), holder, more),
          `${res.total.toLocaleString()} CVE(s).`);
      } catch (err) {
        openDrawer(title, h("div", { class: "chart-empty error", text: err.message }));
      }
    };
    sortSel.addEventListener("change", () => { query.sort = sortSel.value; query.offset = 0; load(false); });
    openDrawer(title, h("div", { class: "chart-loading", text: "Loading…" }));
    load(false);
  }

  async function drill(w, { item, bucket, bucketType }) {
    if (w.query.dataset === "cves") { drillCve(w, { item, bucket, bucketType }); return; }
    const q = effectiveQuery(w);
    const filters = clone(q.filters || {});
    let title = w.title;
    if (item) {
      // The clicked bar/slice/series is a "focus": always ANDed on top of the widget's filters, even in "any" mode.
      title = `${w.title} — ${item.label}`;
      const gb = q.group_by;
      if (gb === "watchlist") filters.focus = { entity_id: item.key };
      else if (gb === "tag") filters.focus = { tag_id: item.key };
      else if (gb === "feed") filters.focus = { feed_id: item.key };
      else if (gb === "folder") {
        if (item.key === null) { toast("Unfiled feeds cannot be drilled into here — use the reader view.", true); return; }
        filters.focus = { folder_id: item.key };
      }
    }
    const query = { type: "articles", days: q.days, limit: 50, tz_offset_minutes: q.tz_offset_minutes, filters };
    if (bucket) {
      const [y, m, d] = bucket.split("-").map(Number);
      const startUtc = Date.UTC(y, m - 1, d) / 1000 - q.tz_offset_minutes * 60;
      let endDate;
      if (bucketType === "day") endDate = Date.UTC(y, m - 1, d + 1);
      else if (bucketType === "week") endDate = Date.UTC(y, m - 1, d + 7);
      else endDate = Date.UTC(y, m, 1);
      const endUtc = endDate / 1000 - q.tz_offset_minutes * 60;
      query.until_ts = endUtc;
      query.days = Math.max(1, Math.round((endUtc - startUtc) / 86400));
      title = `${title} — ${C.fmtBucket(bucket, bucketType, true)}`;
    }
    openDrawer(title, h("div", { class: "chart-loading", text: "Loading…" }));
    try {
      const res = await api("POST", "/analytics/query", query);
      const list = h("div");
      articleList(list, res.items);
      openDrawer(title, list, res.items.length >= 50 ? "Showing the 50 most recent matches." : `${res.items.length} article(s).`);
    } catch (err) {
      openDrawer(title, h("div", { class: "chart-empty error", text: err.message }));
    }
  }

  function openDrawer(title, content, footer) {
    const d = $("#drawer");
    fill(d, 
      h("div", { class: "drawer-head" }, h("h3", { text: title }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: closeDrawer })),
      h("div", { class: "drawer-body" }, content),
      footer ? h("div", { class: "drawer-foot muted", text: footer }) : null);
    if (FW.enhanceDrawer) FW.enhanceDrawer(d);
    d.hidden = false;
  }

  function closeDrawer() {
    const d = $("#drawer");
    if (d) d.hidden = true;
  }

  // ===================================================================== dashboard actions
  async function createDashboard(value) {
    let res;
    if (value === "blank") {
      const name = (window.prompt("Dashboard name") || "").trim();
      if (!name) return;
      res = await guarded(() => api("POST", "/dashboards", { name, position: st.dashboards.length, widgets: [] }), "Dashboard created");
      if (res) st.edit = true;
    } else {
      res = await guarded(() => api("POST", `/dashboard-templates/${value.slice(4)}`), "Dashboard created from template");
    }
    if (!res) return;
    await loadList();
    st.current = res;
    FW.store.set("fw-dash-last", res.id);
    render();
  }

  async function renameDashboard() {
    const name = (window.prompt("Rename dashboard", st.current.name) || "").trim();
    if (!name || name === st.current.name) return;
    st.current.name = name;
    await saveCurrent("Renamed");
  }

  async function deleteDashboard() {
    if (!window.confirm(`Delete dashboard “${st.current.name}”? This cannot be undone.`)) return;
    if (!(await guarded(() => api("DELETE", `/dashboards/${st.current.id}`), "Dashboard deleted"))) return;
    st.current = null;
    st.edit = false;
    await loadList();
    if (st.dashboards.length) await openDashboard(st.dashboards[0].id);
    else render();
  }

  async function setDefault() {
    if (await guarded(() => api("PATCH", "/settings", { default_dashboard_id: st.current.id }), "This dashboard opens first now")) {
      FW.state.settings.default_dashboard_id = st.current.id;
    }
  }

  async function moveDashboard(delta) {
    const list = st.dashboards.slice();
    const i = list.findIndex((d) => d.id === st.current.id);
    const j = i + delta;
    if (j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    // Persist new positions for the two swapped dashboards.
    for (const [pos, d] of [[i, list[i]], [j, list[j]]]) {
      const full = d.id === st.current.id ? st.current : await guarded(() => api("GET", `/dashboards/${d.id}`));
      if (!full) return;
      await guarded(() => api("PUT", `/dashboards/${d.id}`, { name: full.name, position: pos, widgets: full.widgets }));
    }
    await loadList();
    await openDashboard(st.current.id);
  }

  // ===================================================================== drag to reorder (edit mode)
  /** Widgets: drag by the title bar, drop on another widget to put it there. */
  function widgetDrag(section, head, idx) {
    head.draggable = true;
    head.classList.add("drag-handle");
    head.title = "Drag to move this widget";
    head.addEventListener("dragstart", (e) => {
      if (e.target.closest && e.target.closest("button, select, input")) { e.preventDefault(); return; }
      st.dragWidget = idx;
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", String(idx));
      e.dataTransfer.setDragImage(section, 20, 20);
      section.classList.add("dragging");
    });
    head.addEventListener("dragend", () => { st.dragWidget = null; section.classList.remove("dragging"); clearDropMarks(); });
    section.addEventListener("dragover", (e) => {
      if (st.dragWidget === null || st.dragWidget === idx) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      const r = section.getBoundingClientRect();
      const after = e.clientX > r.left + r.width / 2;
      clearDropMarks();
      section.classList.add(after ? "drop-after" : "drop-before");
    });
    section.addEventListener("dragleave", (e) => { if (!section.contains(e.relatedTarget)) section.classList.remove("drop-before", "drop-after"); });
    section.addEventListener("drop", (e) => {
      if (st.dragWidget === null || st.dragWidget === idx) return;
      e.preventDefault();
      const after = section.classList.contains("drop-after");
      const from = st.dragWidget;
      st.dragWidget = null;
      clearDropMarks();
      moveWidgetTo(from, idx + (after ? 1 : 0));
    });
  }

  function clearDropMarks() {
    document.querySelectorAll(".drop-before, .drop-after, .tab-drop").forEach((el) => el.classList.remove("drop-before", "drop-after", "tab-drop"));
  }

  function moveWidgetTo(from, to) {
    const ws = st.current.widgets;
    const [w] = ws.splice(from, 1);
    ws.splice(to > from ? to - 1 : to, 0, w);
    saveCurrent("Widget moved");
  }

  /** Dashboard tabs (edit mode): drag a tab onto another to reorder. */
  function dashTabDrag(btn, d) {
    if (!d) return;
    btn.draggable = true;
    btn.title = "Drag to reorder dashboards";
    btn.addEventListener("dragstart", (e) => { st.dragDash = d.id; e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", d.name); });
    btn.addEventListener("dragend", () => { st.dragDash = null; clearDropMarks(); });
    btn.addEventListener("dragover", (e) => { if (st.dragDash && st.dragDash !== d.id) { e.preventDefault(); clearDropMarks(); btn.classList.add("tab-drop"); } });
    btn.addEventListener("dragleave", () => btn.classList.remove("tab-drop"));
    btn.addEventListener("drop", (e) => {
      if (!st.dragDash || st.dragDash === d.id) return;
      e.preventDefault();
      const from = st.dragDash;
      st.dragDash = null;
      clearDropMarks();
      reorderDashboards(from, d.id);
    });
  }

  async function reorderDashboards(fromId, toId) {
    const list = st.dashboards.slice();
    const i = list.findIndex((x) => x.id === fromId);
    const j = list.findIndex((x) => x.id === toId);
    if (i < 0 || j < 0) return;
    const [moved] = list.splice(i, 1);
    list.splice(j, 0, moved);
    for (const [pos, d] of list.entries()) {
      if (d.position === pos) continue;
      const full = st.current && d.id === st.current.id ? st.current : await guarded(() => api("GET", `/dashboards/${d.id}`));
      if (!full) return;
      if (!await guarded(() => api("PUT", `/dashboards/${d.id}`, { name: full.name, position: pos, widgets: full.widgets }))) return;
    }
    toast("Dashboards reordered");
    await loadList();
    await openDashboard(st.current.id);
  }

  function moveWidget(idx, delta) {
    const ws = st.current.widgets;
    const j = idx + delta;
    if (j < 0 || j >= ws.length) return;
    [ws[idx], ws[j]] = [ws[j], ws[idx]];
    saveCurrent();
  }

  function duplicateWidget(idx) {
    const copy = clone(st.current.widgets[idx]);
    copy.id = randomId();
    copy.title = `${copy.title} (copy)`.slice(0, 100);
    st.current.widgets.splice(idx + 1, 0, copy);
    saveCurrent("Duplicated");
  }

  function removeWidget(idx) {
    if (!window.confirm(`Remove widget “${st.current.widgets[idx].title}”?`)) return;
    st.current.widgets.splice(idx, 1);
    saveCurrent("Removed");
  }

  // ===================================================================== widget editor
  function multiSelect(options, selected, label, withFilter) {
    const sel = h("select", { multiple: true, size: 6, "aria-label": label });
    const groups = new Map();
    for (const o of options) {
      const opt = h("option", { value: o.value, text: o.label, selected: selected.includes(o.value) });
      if (o.group) {
        if (!groups.has(o.group)) { const g = h("optgroup", { label: o.group }); groups.set(o.group, g); sel.append(g); }
        groups.get(o.group).append(opt);
      } else sel.append(opt);
    }
    const parts = [sel];
    if (withFilter) {
      const filter = h("input", { type: "search", placeholder: "Filter…", "aria-label": `Filter ${label}` });
      filter.addEventListener("input", () => {
        const needle = filter.value.trim().toLowerCase();
        for (const opt of sel.querySelectorAll("option")) opt.hidden = Boolean(needle) && !opt.textContent.toLowerCase().includes(needle) && !opt.selected;
      });
      parts.unshift(filter);
    }
    const clear = h("button", { type: "button", class: "btn small", text: "Clear", onclick: () => { for (const o of sel.options) o.selected = false; } });
    return {
      el: h("div", { class: "multi" }, parts, h("div", { class: "multi-foot" }, h("span", { class: "muted", text: "Ctrl/⌘-click to pick several" }), clear)),
      values: () => Array.from(sel.selectedOptions, (o) => Number(o.value)),
      strValues: () => Array.from(sel.selectedOptions, (o) => o.value),
      select: sel,
    };
  }

  function field(label, control, hint) {
    return h("div", { class: "wf-row" }, h("label", { text: label }), h("div", null, control, hint ? h("div", { class: "hint", text: hint }) : null));
  }

  /** Two-option radio group; value() returns the chosen value. */
  function choice(name, options, current) {
    const id = `${name}-${randomId()}`;
    const inputs = options.map(([v]) => h("input", { type: "radio", name: id, value: v, checked: v === current }));
    return {
      el: h("div", { class: "wf-choice", role: "radiogroup" }, options.map(([, l, hint], i) => h("label", { class: "toggle", title: hint || "" }, inputs[i], ` ${l}`))),
      value: () => (inputs.find((i) => i.checked) || inputs[0]).value,
      inputs,
    };
  }

  const MATCH_OPTIONS = [["all", "All must match", "Narrow: an item has to satisfy every filter you set"],
    ["any", "Any can match (partial)", "Broad: satisfying one of the filters is enough"]];

  // ---- chart styles: one picker for widget type + chart ----------------------------------------
  // Tiny static icons (fixed path data, no user input) drawn as SVG.
  const ICONS = {
    number: "M4 17V7l-2 2M9 7h4l-4 10h4M16 7h3a1.5 1.5 0 010 5h-2 2a1.5 1.5 0 010 5h-3",
    line: "M2 17l5-6 4 3 6-8 5 4",
    area: "M2 17l5-6 4 3 6-8 5 4V20H2z",
    stackedarea: "M2 20V14l5-3 5 2 5-4 5 2V20zM2 14V9l5-3 5 2 5-5 5 2v8",
    bar: "M3 20V12h3v8M9 20V6h3v14M15 20V10h3v10",
    stacked: "M3 20v-5h3v5M3 15v-4h3v4M9 20v-8h3v8M9 12V6h3v6M15 20v-6h3v6M15 14v-5h3v5",
    percent: "M3 20V4h3v16M3 11h3M9 20V4h3v16M9 14h3M15 20V4h3v16M15 8h3",
    hbar: "M3 5h14v3H3zM3 10.5h10v3H3zM3 16h6v3H3z",
    column: "M3 20V8h4v12M9 20V4h4v16M15 20v-8h4v8",
    donut: "M12 3a9 9 0 109 9h-4a5 5 0 11-5-5z",
    pie: "M12 3a9 9 0 109 9h-9z",
    table: "M3 5h18v14H3zM3 10h18M3 15h18M10 5v14",
    list: "M4 6h2M9 6h11M4 12h2M9 12h11M4 18h2M9 18h11",
  };
  function icon(name) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", "style-icon");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", ICONS[name] || ICONS.list);
    svg.append(p);
    return svg;
  }

  const TIME_STYLES = [["line", "Lines"], ["area", "Area"], ["stackedarea", "Stacked area"], ["bar", "Bars (total)"], ["stacked", "Stacked bars"], ["percent", "100% stacked"]];
  const STYLE_GROUPS = {
    articles: [
      ["Single number", [{ type: "kpi", chart: "number", label: "Big number", icon: "number" }]],
      ["Over time", TIME_STYLES.map(([c, l]) => ({ type: "timeseries", chart: c, label: l, icon: c }))],
      ["Ranking / breakdown", [{ type: "breakdown", chart: "hbar", label: "Horizontal bars", icon: "hbar" }, { type: "breakdown", chart: "bar", label: "Columns", icon: "column" },
        { type: "breakdown", chart: "donut", label: "Donut", icon: "donut" }, { type: "breakdown", chart: "pie", label: "Pie", icon: "pie" },
        { type: "breakdown", chart: "table", label: "Table", icon: "table" }]],
      ["List", [{ type: "articles", chart: "list", label: "Article list", icon: "list" }]],
    ],
  };
  STYLE_GROUPS.cves = STYLE_GROUPS.articles.map(([g, items]) => [g, g === "List" ? [{ type: "cves", chart: "cvelist", label: "CVE table", icon: "table" }] : items]);
  STYLE_GROUPS.combined = [
    ["Side by side", [{ type: "kpi", chart: "number", label: "Two numbers", icon: "number" }]],
    ["Over time", TIME_STYLES.map(([c, l]) => ({ type: "timeseries", chart: c, label: l, icon: c }))],
    ["List", [{ type: "mixed", chart: "list", label: "Latest news + CVEs", icon: "list" }]],
  ];

  function stylePicker(dataset, type, chart, onChange) {
    const name = `style-${randomId()}`;
    let current = { type, chart };
    const groups = STYLE_GROUPS[dataset];
    const all = groups.flatMap(([, items]) => items);
    if (!all.some((s) => s.type === type && s.chart === chart)) current = { type: all[0].type, chart: all[0].chart };
    const el = h("div", { class: "style-picker", role: "radiogroup", "aria-label": "Chart style" },
      groups.map(([g, items]) => h("div", { class: "style-group" },
        h("div", { class: "style-group-label", text: g }),
        h("div", { class: "style-tiles" }, items.map((s) => {
          const input = h("input", { type: "radio", name, value: `${s.type}:${s.chart}`, checked: s.type === current.type && s.chart === current.chart });
          input.addEventListener("change", () => { current = { type: s.type, chart: s.chart }; onChange(current); });
          return h("label", { class: "style-tile", title: s.label }, input, icon(s.icon), h("span", { text: s.label }));
        })))));
    return { el, value: () => current };
  }

  // ---- width -------------------------------------------------------------------------------------
  const WIDTH_PRESETS = [[25, "Quarter (25%)"], [33.3, "Third (33%)"], [50, "Half (50%)"], [66.7, "Two thirds (67%)"], [75, "Three quarters (75%)"], [100, "Full width"]];
  const widthOf = (w) => w.width || { s: 25, m: 50, l: 75, xl: 100 }[w.size] || 50;
  const sizeFor = (pct) => (pct <= 37 ? "s" : pct <= 62 ? "m" : pct <= 87 ? "l" : "xl");
  function widthPicker(w) {
    const cur = widthOf(w);
    const preset = WIDTH_PRESETS.find(([v]) => Math.abs(v - cur) < 0.5);
    const sel = h("select", { "aria-label": "Width" }, WIDTH_PRESETS.map(([v, l]) => h("option", { value: v, text: l, selected: preset && preset[0] === v })),
      preset ? null : h("option", { value: cur, text: `Custom (${Math.round(cur)}%)`, selected: true }));
    return { el: sel, value: () => Number(sel.value) };
  }

  // ---- filters: news articles ---------------------------------------------------------------------
  function articleFilters(f0) {
    const f = Object.assign({ tag_ids: [], require_tag_ids: [], feed_ids: [], folder_ids: [], entity_ids: [], require_entity_ids: [], watchlist_ids: [],
      exclude_entity_ids: [], q: "", starred: false, unread: false, match: "all" }, f0 || {});
    const sb = FW.state.sidebar;
    const wlName = new Map(st.meta.watchlists.map((x) => [x.id, x.name]));
    const entityOptions = st.meta.entities.map((e) => ({ value: e.id, label: e.name, group: wlName.get(e.watchlist_id) || "Other" }));
    const entMode = choice("ent", [["any", "any of these"], ["all", "all of these (max 20)"]], f.require_entity_ids.length ? "all" : "any");
    const tagMode = choice("tag", [["any", "any of these"], ["all", "all of these (max 20)"]], f.require_tag_ids.length ? "all" : "any");
    const match = choice("match", MATCH_OPTIONS, f.match || "all");
    const mWatch = multiSelect(st.meta.watchlists.map((x) => ({ value: x.id, label: x.name })), f.watchlist_ids, "Watchlists");
    const mEnt = multiSelect(entityOptions, f.require_entity_ids.length ? f.require_entity_ids : f.entity_ids, "Entities", true);
    const mExcl = multiSelect(entityOptions, f.exclude_entity_ids, "Excluded entities", true);
    const mTags = multiSelect(sb.tags.map((t) => ({ value: t.id, label: t.name })), f.require_tag_ids.length ? f.require_tag_ids : f.tag_ids, "Collections");
    const mFeeds = multiSelect(sb.feeds.map((x) => ({ value: x.id, label: x.title })), f.feed_ids, "Feeds", true);
    const mFolders = multiSelect(sb.folders.map((x) => ({ value: x.id, label: x.name })), f.folder_ids, "Folders");
    const search = h("input", { type: "text", maxlength: 200, value: f.q || "", placeholder: "e.g. CVE-2026 or zero-day" });
    const starred = h("input", { type: "checkbox", checked: f.starred });
    const unread = h("input", { type: "checkbox", checked: f.unread });
    return {
      el: (legend) => h("fieldset", null, h("legend", { text: legend || "Filters" }),
        field("Combine filters", match.el, "Exclusions, “only starred” and “only unread” always apply."),
        field("Mentions any of these watchlists", mWatch.el),
        field("Mentions…", h("div", null, entMode.el, mEnt.el)),
        field("…but none of these entities", mExcl.el),
        field("In collections…", h("div", null, tagMode.el, mTags.el)),
        field("From these feeds", mFeeds.el),
        field("From these folders", mFolders.el),
        field("Keyword search", search, "Full-text search over titles and content."),
        field("Only starred", starred), field("Only unread", unread)),
      values() {
        const ents = mEnt.values();
        const tags = mTags.values();
        const entAll = entMode.value() === "all";
        const tagAll = tagMode.value() === "all";
        if (entAll && ents.length > 20) throw new Error("“All of these” entities: pick at most 20.");
        if (tagAll && tags.length > 20) throw new Error("“All of these” collections: pick at most 20.");
        const out = {
          watchlist_ids: mWatch.values(), entity_ids: entAll ? [] : ents, require_entity_ids: entAll ? ents : [],
          exclude_entity_ids: mExcl.values(), tag_ids: tagAll ? [] : tags, require_tag_ids: tagAll ? tags : [],
          feed_ids: mFeeds.values(), folder_ids: mFolders.values(), starred: starred.checked, unread: unread.checked, match: match.value(),
        };
        if (search.value.trim()) out.q = search.value.trim();
        return out;
      },
    };
  }

  // ---- filters: CVEs -------------------------------------------------------------------------------
  function cveFilters(f0) {
    const meta = st.cveMeta || { categories: [], vendors: [], owasp: {}, cwes: [] };
    const f = Object.assign({ severities: [], categories: [], require_categories: [], exclude_categories: [], vendors: [], cwe_ids: [], owasp: [], owasp_edition: "2021",
      kev_only: false, exploited_only: false, ransomware_only: false, q: "", min_score: null, match: "all" }, f0 || {});
    const match = choice("cmatch", MATCH_OPTIONS, f.match || "all");
    const sevBoxes = Object.entries(FW.cve.SEV_LABEL).map(([v, l]) => ({ v, cb: h("input", { type: "checkbox", checked: f.severities.includes(v) }), l }));
    const minScore = h("input", { type: "number", min: 0, max: 10, step: 0.1, value: f.min_score ?? "", placeholder: "any" });
    const catOptions = meta.categories.map((c) => ({ value: c.slug, label: `${c.name} (${c.cve_count})` }));
    const catMode = choice("cat", [["any", "any of these"], ["all", "all of these (max 10)"]], f.require_categories.length ? "all" : "any");
    const mCats = multiSelect(catOptions, f.require_categories.length ? f.require_categories : f.categories, "Categories");
    const mExcl = multiSelect(catOptions, f.exclude_categories, "Excluded categories");
    const edition = h("select", null, ["2021", "2025"].map((e) => h("option", { value: e, text: `OWASP Top 10 ${e}`, selected: e === f.owasp_edition })));
    const owaspBox = h("div");
    let mOwasp = null;
    const buildOwasp = () => {
      mOwasp = multiSelect((meta.owasp[edition.value] || []).map((o) => ({ value: o.code, label: `${o.code} ${o.name}` })), f.owasp, "OWASP categories");
      fill(owaspBox, mOwasp.el);
    };
    buildOwasp();
    edition.addEventListener("change", () => { f.owasp = []; buildOwasp(); });
    const mVendors = multiSelect(meta.vendors.map((v) => ({ value: v.key, label: `${v.label} (${v.count})` })), f.vendors, "Vendors", true);
    const mCwes = multiSelect(meta.cwes.map((c) => ({ value: c.id, label: `CWE-${c.id} ${c.name || ""} (${c.count})` })), f.cwe_ids, "Weaknesses", true);
    const kev = h("input", { type: "checkbox", checked: f.kev_only });
    const exploited = h("input", { type: "checkbox", checked: f.exploited_only });
    const ransomware = h("input", { type: "checkbox", checked: f.ransomware_only });
    const search = h("input", { type: "text", maxlength: 200, value: f.q || "", placeholder: "e.g. Fortinet or CVE-2026-1234" });
    return {
      catOptions,
      el: (legend) => h("fieldset", null, h("legend", { text: legend || "Filters" }),
        field("Combine filters", match.el, "Excluded categories always apply."),
        field("Severity", h("div", { class: "sev-boxes" }, sevBoxes.map((b) => h("label", { class: "toggle" }, b.cb, ` ${b.l}`)))),
        field("Minimum CVSS", minScore),
        field("In categories…", h("div", null, catMode.el, mCats.el), "Edge devices, RCE, AI/ML… (edit in Settings → CVE tracking)"),
        field("…but none of these", mExcl.el),
        field("OWASP Top 10", h("div", null, edition, owaspBox)),
        field("Vendors", mVendors.el),
        field("Weaknesses (CWE)", mCwes.el),
        field("Only CISA KEV", kev), field("Only exploited (KEV or SSVC active)", exploited), field("Only known ransomware use", ransomware),
        field("Keyword / CVE ID", search)),
      values() {
        const cats = mCats.strValues();
        const catAll = catMode.value() === "all";
        if (catAll && cats.length > 10) throw new Error("“All of these” categories: pick at most 10.");
        const out = {
          severities: sevBoxes.filter((b) => b.cb.checked).map((b) => b.v), categories: catAll ? [] : cats, require_categories: catAll ? cats : [],
          exclude_categories: mExcl.strValues(), owasp_edition: edition.value, owasp: mOwasp.strValues(), vendors: mVendors.strValues(),
          cwe_ids: mCwes.values(), kev_only: kev.checked, exploited_only: exploited.checked, ransomware_only: ransomware.checked, match: match.value(),
        };
        if (minScore.value !== "") out.min_score = Number(minScore.value);
        if (search.value.trim()) out.q = search.value.trim();
        return out;
      },
    };
  }

  // ---- shared dialog plumbing ----------------------------------------------------------------------
  function datasetSwitch(current, idx) {
    const sel = h("select", { "aria-label": "Data source" },
      h("option", { value: "articles", text: "News articles (mentions, collections, feeds)", selected: current === "articles" }),
      h("option", { value: "cves", text: "CVEs (NVD · CISA KEV · CWE/OWASP)", selected: current === "cves" }),
      h("option", { value: "combined", text: "News articles + CVEs (side by side)", selected: current === "combined" }));
    sel.addEventListener("change", () => openEditor(idx, sel.value));
    return h("fieldset", null, h("legend", { text: "Data source" }), field("Data", sel));
  }

  function showEditor(form, focusEl) {
    const dlg = $("#widgetDialog");
    fill(dlg, form);
    if (!dlg.open) dlg.showModal();
    focusEl.focus();
  }

  async function saveWidget(idx, widget, err, existing) {
    const before = clone(st.current.widgets);
    if (existing) st.current.widgets[idx] = widget; else st.current.widgets.push(widget);
    const res = await api("PUT", `/dashboards/${st.current.id}`, { name: st.current.name, position: st.current.position, widgets: st.current.widgets })
      .catch((ex) => { err.textContent = ex.message; return null; });
    if (!res) { st.current.widgets = before; return; }
    st.current = res;
    $("#widgetDialog").close();
    toast(existing ? "Widget saved" : "Widget added");
    await loadList();
    render();
  }

  function editorForm(existing, idx, dataset, sections, onSubmit) {
    const err = h("p", { class: "error" });
    const form = h("form", { class: "widget-form" },
      h("div", { class: "wf-head" }, h("h3", { text: existing ? "Edit widget" : "Add widget" }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => $("#widgetDialog").close() })),
      h("div", { class: "wf-body" }, existing ? null : datasetSwitch(dataset, idx), sections),
      err,
      h("div", { class: "form-actions wf-foot" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => $("#widgetDialog").close() }),
        h("button", { type: "submit", class: "btn primary", text: existing ? "Save widget" : "Add widget" })));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      err.textContent = "";
      try { onSubmit(err); } catch (ex) { err.textContent = ex.message; }
    });
    return form;
  }

  const sizing = (w, width) => ({ size: sizeFor(width), width, ...(w.height ? { height: w.height } : {}) });
  const daysSelect = (q) => h("select", null, [...new Set([...DAY_CHOICES, q.days])].sort((a, b) => a - b).map((d) => h("option", { value: d, text: periodLabel(d), selected: d === q.days })));
  const bucketSelect = (q) => h("select", null, [["day", "Daily"], ["week", "Weekly"], ["month", "Monthly"]].map(([v, l]) => h("option", { value: v, text: l, selected: v === q.bucket })));

  // ---- editor: news articles -------------------------------------------------------------------------
  function openEditor(idx, forceDataset) {
    const existing = idx === null ? null : st.current.widgets[idx];
    const dataset = forceDataset || (existing ? existing.query.dataset || "articles" : "articles");
    if (dataset === "cves") { openCveEditor(idx); return; }
    if (dataset === "combined") { openCombinedEditor(idx); return; }
    const w = existing && (existing.query.dataset || "articles") === "articles" ? clone(existing) : {
      id: randomId(), title: "", size: "m", chart: "hbar",
      query: { type: "breakdown", days: 30, bucket: "day", group_by: "watchlist", group_watchlist_id: (st.meta.watchlists[0] || {}).id || null, group_entity_ids: [], limit: 10, filters: {} },
    };
    const q = w.query;
    const title = h("input", { type: "text", maxlength: 100, required: true, value: w.title, placeholder: "e.g. Ransomware groups hitting healthcare" });
    const width = widthPicker(w);
    const days = daysSelect(q);
    const bucket = bucketSelect(q);
    const groupBy = h("select");
    const groupWl = h("select", null, st.meta.watchlists.map((x) => h("option", { value: x.id, text: x.name, selected: x.id === q.group_watchlist_id })));
    const limit = h("input", { type: "number", min: 1, max: 50, value: q.limit || 10 });
    let groupEntities = null;
    const groupEntitiesBox = h("div");
    const buildGroupEntities = () => {
      const wid = Number(groupWl.value);
      groupEntities = multiSelect(st.meta.entities.filter((e) => e.watchlist_id === wid).map((e) => ({ value: e.id, label: e.name })), (q.group_entity_ids || []), "Only these entities", true);
      fill(groupEntitiesBox, groupEntities.el);
    };
    buildGroupEntities();
    groupWl.addEventListener("change", () => { q.group_entity_ids = []; buildGroupEntities(); });
    const filters = articleFilters(q.filters);
    const rows = {
      bucket: field("Group dates by", bucket),
      groupBy: field("Split / group by", groupBy, "Watchlist entities = threat actors, ransomware groups, countries, sectors…"),
      groupWl: field("Watchlist", groupWl), groupEnt: field("Only these entities", groupEntitiesBox, "Optional. Leave empty for the top N automatically."),
      limit: field("Top N / how many", limit),
    };
    const sync = () => {
      const t = style.value().type;
      const groupOptions = t === "timeseries" ? [["none", "Nothing (single total)"], ...Object.entries(GROUPS)] : Object.entries(GROUPS);
      const prevGroup = groupBy.value || q.group_by;
      fill(groupBy, ...groupOptions.map(([v, l]) => h("option", { value: v, text: l, selected: v === prevGroup })));
      const grouped = t === "timeseries" || t === "breakdown";
      rows.bucket.hidden = t !== "timeseries";
      rows.groupBy.hidden = !grouped;
      rows.groupWl.hidden = !grouped || groupBy.value !== "watchlist";
      rows.groupEnt.hidden = rows.groupWl.hidden;
      rows.limit.hidden = !(t === "breakdown" || t === "articles" || (t === "timeseries" && groupBy.value !== "none"));
      limit.max = t === "timeseries" ? 8 : 50;
      if (Number(limit.value) > Number(limit.max)) limit.value = limit.max;  // e.g. a trend shows at most 8 series
    };
    const style = stylePicker("articles", q.type, w.chart, sync);
    groupBy.addEventListener("change", sync);
    const form = editorForm(existing, idx, "articles", [
      h("fieldset", null, h("legend", { text: "What to show" }),
        field("Title", title), field("Chart style", style.el), field("Width", width.el, "Or drag the widget's edge in Edit mode."),
        field("Period", days, "Saved with the widget (also changeable from the menu on the widget). The Range menu at the top can show all widgets over one period for a while; ↺ Reset goes back to this."),
        rows.bucket, rows.groupBy, rows.groupWl, rows.groupEnt, rows.limit),
      filters.el("Filters"),
    ], (err) => {
      const { type: t, chart } = style.value();
      const gb = (t === "timeseries" || t === "breakdown") ? groupBy.value : "none";
      if (t === "breakdown" && gb === "none") throw new Error("A ranking needs something to split by.");
      const widget = {
        id: w.id, title: title.value.trim(), chart, ...sizing(w, width.value()),
        query: {
          type: t, days: Number(days.value), bucket: bucket.value, group_by: gb,
          group_watchlist_id: gb === "watchlist" ? Number(groupWl.value) : null,
          group_entity_ids: gb === "watchlist" ? groupEntities.values() : [],
          limit: Math.min(Number(limit.value) || 10, t === "timeseries" ? 8 : 50), filters: filters.values(),
        },
      };
      saveWidget(idx, widget, err, existing);
    });
    showEditor(form, title);
    sync();
  }

  // ---- editor: CVEs ------------------------------------------------------------------------------------
  const CVE_GROUPS = { severity: "Severity", category: "Category", owasp2021: "OWASP Top 10 (2021)", owasp2025: "OWASP Top 10 (2025)",
    vendor: "Vendor", cwe: "Weakness (CWE)", kev: "In CISA KEV" };
  const dateFieldSelect = (value) => h("select", null, [["published", "Published date"], ["modified", "Last modified"], ["kev_added", "Date added to CISA KEV"]]
    .map(([v, l]) => h("option", { value: v, text: l, selected: v === (value || "published") })));

  function openCveEditor(idx) {
    const existing = idx === null ? null : st.current.widgets[idx];
    const w = existing && existing.query.dataset === "cves" ? clone(existing) : {
      id: randomId(), title: "", size: "m", chart: "stacked",
      query: { dataset: "cves", type: "timeseries", days: 30, bucket: "day", group_by: "severity", date_field: "published", sort: "newest", limit: 6, filters: {} },
    };
    const q = w.query;
    const title = h("input", { type: "text", maxlength: 100, required: true, value: w.title, placeholder: "e.g. Critical edge-device CVEs" });
    const width = widthPicker(w);
    const days = daysSelect(q);
    const dateField = dateFieldSelect(q.date_field);
    const bucket = bucketSelect(q);
    const groupBy = h("select");
    const sort = h("select", null, FW.cve.SORTS.map(([v, l]) => h("option", { value: v, text: l, selected: v === (q.sort || "newest") })));
    const limit = h("input", { type: "number", min: 1, max: 200, value: q.limit || 10 });
    const filters = cveFilters(q.filters);
    const groupCats = multiSelect(filters.catOptions, q.group_categories || [], "Only these categories");
    const rows = { bucket: field("Group dates by", bucket), groupBy: field("Split / group by", groupBy),
      groupCats: field("Only these categories", groupCats.el, "Optional: pick the series/bars to compare."),
      sort: field("Sort", sort), limit: field("How many", limit) };
    const sync = () => {
      const t = style.value().type;
      const opts = t === "timeseries" ? [["none", "Nothing (single total)"], ...Object.entries(CVE_GROUPS)] : Object.entries(CVE_GROUPS);
      const prev = groupBy.value || q.group_by;
      fill(groupBy, ...opts.map(([v, l]) => h("option", { value: v, text: l, selected: v === prev })));
      const grouped = t === "timeseries" || t === "breakdown";
      rows.bucket.hidden = t !== "timeseries";
      rows.groupBy.hidden = !grouped;
      rows.groupCats.hidden = !grouped || groupBy.value !== "category";
      rows.sort.hidden = t !== "cves";
      rows.limit.hidden = t === "kpi" || (t === "timeseries" && groupBy.value === "none");
      limit.max = t === "cves" ? 200 : t === "timeseries" ? 8 : 50;
      if (Number(limit.value) > Number(limit.max)) limit.value = limit.max;
    };
    const style = stylePicker("cves", q.type, w.chart, sync);
    groupBy.addEventListener("change", sync);
    const form = editorForm(existing, idx, "cves", [
      h("fieldset", null, h("legend", { text: "What to show" }),
        field("Title", title), field("Chart style", style.el), field("Width", width.el, "Or drag the widget's edge in Edit mode."),
        field("Period", days), field("Date used", dateField),
        rows.bucket, rows.groupBy, rows.groupCats, rows.sort, rows.limit),
      filters.el("Filters"),
    ], (err) => {
      const { type: t, chart } = style.value();
      const gb = (t === "timeseries" || t === "breakdown") ? groupBy.value : "none";
      if (t === "breakdown" && gb === "none") throw new Error("A ranking needs something to split by.");
      const max = t === "cves" ? 200 : t === "timeseries" ? 8 : 50;
      const widget = {
        id: w.id, title: title.value.trim(), chart, ...sizing(w, width.value()),
        query: { dataset: "cves", type: t, days: Number(days.value), bucket: bucket.value, group_by: gb, date_field: dateField.value,
          sort: sort.value, limit: Math.min(Number(limit.value) || 10, max), group_categories: gb === "category" ? groupCats.strValues() : [], filters: filters.values() },
      };
      saveWidget(idx, widget, err, existing);
    });
    showEditor(form, title);
    sync();
  }

  // ---- editor: news articles + CVEs --------------------------------------------------------------------
  function openCombinedEditor(idx) {
    const existing = idx === null ? null : st.current.widgets[idx];
    const w = existing && existing.query.dataset === "combined" ? clone(existing) : {
      id: randomId(), title: "", size: "m", chart: "line",
      query: { dataset: "combined", type: "timeseries", days: 30, bucket: "day", limit: 20, date_field: "published", articles: {}, cves: {} },
    };
    const q = w.query;
    const title = h("input", { type: "text", maxlength: 100, required: true, value: w.title, placeholder: "e.g. Fortinet: news coverage vs. new CVEs" });
    const width = widthPicker(w);
    const days = daysSelect(q);
    const bucket = bucketSelect(q);
    const dateField = dateFieldSelect(q.date_field);
    const limit = h("input", { type: "number", min: 1, max: 100, value: q.limit || 20 });
    const news = articleFilters(q.articles);
    const vulns = cveFilters(q.cves);
    const rows = { bucket: field("Group dates by", bucket), limit: field("How many items", limit) };
    const sync = () => {
      const t = style.value().type;
      rows.bucket.hidden = t !== "timeseries";
      rows.limit.hidden = t !== "mixed";
    };
    const style = stylePicker("combined", q.type, w.chart, sync);
    const form = editorForm(existing, idx, "combined", [
      h("fieldset", null, h("legend", { text: "What to show" }),
        h("p", { class: "muted small", text: "Compare news coverage with CVE volume: two numbers, two lines on one chart, or one list of the latest items from both. Each side has its own filters below." }),
        field("Title", title), field("Chart style", style.el), field("Width", width.el, "Or drag the widget's edge in Edit mode."),
        field("Period", days, "Saved with the widget. The Range menu at the top can override it for a while (↺ Reset goes back)."), field("CVE date used", dateField), rows.bucket, rows.limit),
      news.el("News article filters"),
      vulns.el("CVE filters"),
    ], (err) => {
      const { type: t, chart } = style.value();
      const widget = {
        id: w.id, title: title.value.trim(), chart, ...sizing(w, width.value()),
        query: { dataset: "combined", type: t, days: Number(days.value), bucket: bucket.value, date_field: dateField.value,
          limit: Math.min(Number(limit.value) || 20, 100), articles: news.values(), cves: vulns.values() },
      };
      saveWidget(idx, widget, err, existing);
    });
    showEditor(form, title);
    sync();
  }

  // ===================================================================== lifecycle
  async function show() {
    st.visible = true;
    if (st.current && st.cards.size && root().childElementCount) {  // coming back: refresh the widgets in place
      st.cards.forEach((entry) => loadWidget(entry));
      return;
    }
    if (!root().childElementCount) fill(root(), h("p", { class: "muted lib-pad", text: "Loading dashboards…" }));  // never a blank page
    await loadMeta();
    await loadList();
    if (!st.current || !st.dashboards.some((d) => d.id === st.current.id)) {
      const preferred = [FW.state.settings.default_dashboard_id, Number(FW.store.get("fw-dash-last", 0))];
      const id = preferred.find((p) => p && st.dashboards.some((d) => d.id === p)) || (st.dashboards[0] || {}).id;
      if (id) { await openDashboard(id); } else { st.current = null; render(); }
    } else {
      render();
    }
    clearInterval(st.timer);
    st.timer = setInterval(() => {
      if (st.visible && !document.querySelector("dialog[open]") && !document.hidden) renderGrid();
    }, 5 * 60 * 1000);
  }

  function hide() {
    st.visible = false;
    clearInterval(st.timer);
    closeDrawer();
  }

  FW.dashboard = { show, hide, closeDrawer };
  const view = root();
  if (view && !view.hidden) show();
})();
