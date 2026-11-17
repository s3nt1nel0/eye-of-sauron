/* Settings → Feeds: the feed table with multi-select + bulk actions, and the feed troubleshooter.
 * Same rules as app.js: DOM built with h()/textContent only, no inline script/style, links via safeUrl. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, relTime, fullDate, refreshPicker, fillFolderSelect, state } = FW;
  const $ = (sel) => document.querySelector(sel);

  const VERDICT_ICON = {
    working: "✓", moved: "↪", blocked: "⛔", not_feed: "▢", gone: "✗", dns: "✗", server: "⚠", network: "⚠",
    unsafe: "⛔", broken: "⚠", skipped: "–",
  };
  const VERDICT_CLASS = { working: "ok", moved: "ok", skipped: "muted" };
  const HOW = {
    redirect: "the old address forwards here",
    declared: "linked from the site's own pages",
    alternative: "same feed over HTTPS / without extras",
    guess: "found at a common feed path - may be the whole site's feed",
  };
  const fmtDate = (ts) => (ts ? FW.fmtDate(ts) : "no dates");

  // ===================================================================== troubleshooter report
  function reportCard(rep, onChanged) {
    const feedId = rep.feed_id;
    const card = h("div", { class: `card doctor-card verdict-${rep.verdict}` });
    const after = async (msg) => { toast(msg); await onChanged(); };
    const useUrl = async (url) => {
      const res = await guarded(() => api("PATCH", `/feeds/${feedId}`, { url }));
      if (!res) return;
      const r = await guarded(() => api("POST", `/feeds/${feedId}/refresh`));
      card.classList.add("fixed");
      fill(card, h("p", { class: "status-ok", text: r && r.ok ? `✓ Switched to ${url} - ${r.new} new article(s).` : `Switched to ${url}${r && r.error ? `, but the first fetch failed: ${r.error}` : ""}.` }));
      await onChanged(true);
    };
    const actions = h("div", { class: "actions" },
      rep.verdict === "working" ? h("button", { type: "button", class: "btn small primary", text: "Reset & fetch now", onclick: async () => {
        await guarded(() => api("POST", "/feeds/bulk", { ids: [feedId], action: "reset_errors" }));
        const r = await guarded(() => api("POST", `/feeds/${feedId}/refresh`));
        if (r) after(r.ok ? `Fetched: ${r.new} new article(s)` : `Still failing: ${r.error}`);
      } }) : null,
      h("button", { type: "button", class: "btn small", text: "⚙ Edit feed", onclick: () => { $("#settingsDialog").close(); FW.feeds.openFeedEditor(feedId); } }),
      h("button", { type: "button", class: "btn small", text: "Disable", onclick: async () => {
        if (await guarded(() => api("POST", "/feeds/bulk", { ids: [feedId], action: "disable" }))) { card.classList.add("fixed"); after("Feed disabled - its articles are kept"); }
      } }),
      h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
        if (!window.confirm(`Unsubscribe from “${rep.title || rep.url}” and delete its articles?`)) return;
        if (await guarded(() => api("DELETE", `/feeds/${feedId}`))) { card.remove(); after("Feed deleted"); }
      } }));
    // h() skips null children; native append() would print "null", so build through h() and move the nodes.
    card.append(...h("div", null,
      h("div", { class: "card-head" },
        h("div", null,
          h("strong", { text: `${VERDICT_ICON[rep.verdict] || "?"} ${rep.title || rep.url}` }),
          h("div", { class: "url muted small", text: rep.url || "" })),
        actions),
      h("p", { class: `doctor-summary ${VERDICT_CLASS[rep.verdict] || "bad"}`, text: rep.summary }),
      rep.suggestions && rep.suggestions.length
        ? h("div", { class: "doctor-suggestions" },
          h("div", { class: "small muted", text: rep.suggestions.length > 1 ? "Working addresses found (newest first):" : "Working address found:" }),
          rep.suggestions.map((s) => h("div", { class: "doctor-sug" },
            h("div", null,
              h("a", { href: safeUrl(s.url), target: "_blank", rel: "noopener noreferrer", text: s.url }),
              h("div", { class: "small muted", text: `${s.title ? `${s.title} · ` : ""}${s.items} items · newest ${fmtDate(s.newest)} · ${HOW[s.how] || ""}` })),
            h("button", { type: "button", class: "btn small primary", text: "Use this address", onclick: () => useUrl(s.url) }))))
        : null,
      rep.advice && rep.advice.length ? h("ul", { class: "doctor-advice" }, rep.advice.map((a) => h("li", { text: a }))) : null,
      rep.steps && rep.steps.length
        ? h("details", { class: "doctor-steps" }, h("summary", { text: `What was checked (${rep.steps.length} steps)` }),
          h("ol", null, rep.steps.map((st) => h("li", { class: st.ok ? "status-ok" : st.ok === false ? "status-err" : "" },
            h("strong", { text: `${st.step}: ` }), h("span", { text: st.detail })))))
        : null).childNodes);
    return card;
  }

  /** Background run over many feeds, with live progress; results render as report cards. */
  function doctorPanel(onChanged) {
    const box = h("div", { class: "doctor-panel" });
    let timer = null;
    const shown = new Set();
    const results = h("div", { class: "doctor-results" });
    const progress = h("div", { class: "doctor-progress muted" });
    const cancel = h("button", { type: "button", class: "btn small", text: "Stop", onclick: () => api("POST", "/feeds/diagnose/cancel").catch(() => {}) });
    const counts = h("div", { class: "doctor-counts small" });

    function summarise(list) {
      const by = {};
      for (const r of list) by[r.verdict] = (by[r.verdict] || 0) + 1;
      const label = { moved: "fixable (new address found)", working: "working again", blocked: "blocked by bot protection", gone: "gone (404)", dns: "domain gone",
        not_feed: "no longer a feed", server: "server errors", network: "unreachable", broken: "malformed", unsafe: "blocked address", skipped: "skipped" };
      fill(counts, Object.entries(by).sort((a, b) => b[1] - a[1]).map(([k, n]) => h("span", { class: `doctor-chip verdict-${k}`, text: `${n} ${label[k] || k}` })));
    }

    async function poll() {
      const st = await api("GET", "/feeds/diagnose").catch(() => null);
      if (!st) return;
      for (const r of st.results || []) {
        if (shown.has(r.feed_id)) continue;
        shown.add(r.feed_id);
        // Fixable first, then everything else in arrival order.
        const card = reportCard(r, onChanged);
        if (r.verdict === "moved" || r.verdict === "working") results.prepend(card); else results.append(card);
      }
      summarise(st.results || []);
      if (st.running) {
        fill(progress, `Checking ${st.done + 1} of ${st.total}${st.current ? `: ${st.current}` : ""}… `, cancel);
        timer = setTimeout(poll, 2000);
      } else {
        fill(progress, st.total ? `Checked ${st.done} of ${st.total} feed(s)${st.finished ? ` · ${relTime(st.finished)}` : ""}.` : "");
        timer = null;
      }
    }

    box.start = async (ids) => {
      const res = await guarded(() => api("POST", "/feeds/diagnose", ids ? { ids } : {}));
      if (!res) return;
      if (!res.started) { toast("No failing feeds to check"); return; }
      shown.clear(); fill(results); fill(counts);
      box.hidden = false;
      box.scrollIntoView({ behavior: "smooth", block: "start" });
      if (!timer) poll();
    };
    box.resume = () => { if (!timer) poll(); };
    box.append(
      h("div", { class: "panel-section-head" }, h("h4", { text: "🩺 Troubleshooter results" })),
      h("p", { class: "muted small", text: "Each feed is checked: does the domain still exist, what the address returns now, and whether the site publishes a working feed elsewhere (redirects, HTTPS, links on its pages, common feed paths). It never disguises itself or gets around bot checks." }),
      progress, counts, results);
    box.hidden = true;
    return box;
  }

  async function diagnoseOne(feed, host, onChanged) {
    const placeholder = h("div", { class: "card muted", text: `🩺 Checking “${feed.title || feed.url}”…` });
    host.prepend(placeholder);
    host.hidden = false;
    placeholder.scrollIntoView({ behavior: "smooth", block: "nearest" });
    const rep = await guarded(() => api("POST", `/feeds/${feed.id}/diagnose`));
    placeholder.replaceWith(rep ? reportCard(rep, onChanged) : h("p", { class: "error", text: "Check failed." }));
  }


  // ===================================================================== keep articles to a time frame
  /** "Keep articles from…": scale Reader feeds back (all, a folder, or the ticked feeds), with a live preview. */
  function openKeepArticles({ feedIds = [], onDone = () => {} } = {}) {
    const dlg = $("#sourceDialog");
    const frame = FW.sources.timeFramePicker({ label: "Keep articles from", selected: 365, everythingText: "Everything (no limit)" });
    const scope = h("select", { "aria-label": "Which feeds" },
      feedIds.length ? h("option", { value: "feeds", text: `The ${feedIds.length} ticked feed${feedIds.length === 1 ? "" : "s"}` }) : null,
      h("option", { value: "all", text: "All article feeds" }),
      state.sidebar.folders.length ? h("optgroup", { label: "A folder" },
        state.sidebar.folders.map((f) => h("option", { value: `folder:${f.id}`, text: f.name }))) : null);
    const preview = h("p", { class: "keep-preview", "aria-live": "polite" });
    const err = h("p", { class: "error" });
    const body = (dry) => {
      const days = frame.days();
      if (Number.isNaN(days)) return null;
      const b = { days, dry_run: dry };
      if (scope.value === "feeds") Object.assign(b, { scope: "feeds", feed_ids: feedIds });
      else if (scope.value.startsWith("folder:")) Object.assign(b, { scope: "folder", folder_id: Number(scope.value.slice(7)) });
      else b.scope = "all";
      return b;
    };
    let seq = 0;
    const update = async () => {
      const b = body(true);
      err.textContent = "";
      if (!b) { preview.textContent = "Custom time frame: enter a whole number from 1 to 100."; return; }
      if (!b.days) { preview.textContent = "Nothing is removed; these feeds keep every article from now on."; return; }
      const mine = ++seq;
      preview.textContent = "Counting…";
      const r = await api("POST", "/feeds/keep", b).catch((e) => ({ error: e.message }));
      if (mine !== seq) return;
      if (r.error) { preview.textContent = ""; err.textContent = r.error; return; }
      const left = r.skipped ? ` ${r.skipped} podcast, video or account feed${r.skipped === 1 ? " is" : "s are"} left untouched.` : "";
      preview.textContent = (r.removed
        ? `Removes ${r.removed.toLocaleString()} article${r.removed === 1 ? "" : "s"} published before ${FW.fmtDate(Math.floor(Date.now() / 1000) - b.days * 86400)} (the oldest from ${FW.fmtDate(r.oldest)}) in ${r.feeds} article feed${r.feeds === 1 ? "" : "s"}.`
        : `Nothing older than that in ${r.feeds} article feed${r.feeds === 1 ? "" : "s"}; they are kept trimmed from now on.`) + left;
    };
    frame.select.addEventListener("change", update);
    frame.el.addEventListener("input", () => { clearTimeout(frame.t); frame.t = setTimeout(update, 400); });
    scope.addEventListener("change", update);
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: async (e) => {
      e.preventDefault();
      const b = body(false);
      if (!b) { err.textContent = "Custom time frame: enter a whole number from 1 to 100."; return; }
      if (b.days && !window.confirm(`${preview.textContent}\n\nStarred and hand-filed articles are kept. Removed articles cannot be brought back. Continue?`)) return;
      const r = await guarded(() => api("POST", "/feeds/keep", b));
      if (!r) return;
      dlg.close();
      toast(b.days ? `Removed ${r.removed.toLocaleString()} older article${r.removed === 1 ? "" : "s"} — keeping the ${frame.describe()} from now on`
        : `${r.feeds} feed${r.feeds === 1 ? "" : "s"} now keep every article`);
      FW.loadSidebar(); FW.loadArticles();
      onDone();
    } },
      h("div", { class: "sd-head" }, h("h3", { text: "🗓️ Keep articles from…" }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("div", { class: "grid-form" },
        h("label", { text: "Feeds" }), scope,
        h("label", { text: "Keep articles published in" }), frame.el),
      preview,
      h("ul", { class: "small src-notes" },
        h("li", { text: "Older articles are removed now, and new ones drop off as they pass the limit, so the feeds stay this size." }),
        h("li", { text: "Starred articles and articles you filed into a collection by hand are always kept." }),
        h("li", { text: "Podcast shows, YouTube channels and accounts among the ticked feeds are never touched here. YouTube channels have their own 🗓️ Keep… in the Videos tab." })),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "submit", class: "btn primary", text: "Apply" }))));
    if (!dlg.open) dlg.showModal();
    update();
  }

  // ===================================================================== feed table with multi-select
  /**
   * feeds: rows from GET /feeds. onChanged(soft): reload sidebar (+ re-render the panel unless soft).
   */
  function manager(feeds, onChanged) {
    const selected = new Set();
    let lastClicked = null;
    const failing = feeds.filter((f) => f.error_count > 0);
    // what a feed delivers: articles, podcast episodes, videos or account posts - shown apart, one kind at a time
    const typeOf = (f) => (f.kind === "podcast" ? "podcasts" : f.kind === "youtube" ? "videos" : f.social_platform ? "accounts" : "articles");
    const TYPES = [["articles", "📰 Article feeds"], ["podcasts", "🎙 Podcasts"], ["videos", "▶ YouTube"], ["accounts", "💬 Accounts"]];
    const typeCount = Object.fromEntries(TYPES.map(([t]) => [t, feeds.filter((f) => typeOf(f) === t).length]));
    const remembered = FW.store ? FW.store.get("fw-feed-type", "articles") : "articles";
    const filters = { q: "", status: "all", folder: "any", type: remembered === "all" || typeCount[remembered] ? remembered : "articles" };

    const single = h("div", { class: "doctor-results" });
    single.hidden = true;
    const doctor = doctorPanel(onChanged);

    // ---- filters
    const search = h("input", { type: "search", placeholder: "Filter feeds…", "aria-label": "Filter feeds" });
    const status = h("select", { "aria-label": "Status" },
      [["all", `All (${feeds.length})`], ["failing", `Failing (${failing.length})`], ["disabled", `Disabled (${feeds.filter((f) => !f.enabled).length})`], ["ok", "Working"]]
        .map(([v, l]) => h("option", { value: v, text: l })));
    const folderFilter = h("select", { "aria-label": "Folder" }, h("option", { value: "any", text: "Any folder" }), h("option", { value: "none", text: "No folder" }),
      state.sidebar.folders.map((f) => h("option", { value: String(f.id), text: f.name })));

    const typeTabs = h("div", { class: "seg feed-types", role: "tablist", "aria-label": "Kind of feed" });
    const drawTypes = () => fill(typeTabs, [...TYPES.filter(([t]) => typeCount[t]), ["all", "All together"]].map(([t, label]) =>
      h("button", { type: "button", role: "tab", class: `btn small${filters.type === t ? " primary" : ""}`, "aria-selected": String(filters.type === t),
        text: `${label} (${t === "all" ? feeds.length : typeCount[t]})`,
        onclick: () => { filters.type = t; if (FW.store) FW.store.set("fw-feed-type", t); selected.clear(); drawTypes(); render(); } })));

    const visible = () => feeds.filter((f) => {
      if (filters.type !== "all" && typeOf(f) !== filters.type) return false;
      if (filters.status === "failing" && !f.error_count) return false;
      if (filters.status === "disabled" && f.enabled) return false;
      if (filters.status === "ok" && (f.error_count || !f.enabled)) return false;
      if (filters.folder === "none" && f.folder_id !== null) return false;
      if (filters.folder !== "any" && filters.folder !== "none" && f.folder_id !== Number(filters.folder)) return false;
      if (filters.q) {
        const q = filters.q.toLowerCase();
        if (!`${f.title} ${f.url}`.toLowerCase().includes(q)) return false;
      }
      return true;
    });

    // ---- bulk bar
    const count = h("strong");
    const moveTo = h("select", { "aria-label": "Move to folder" }); fillFolderSelect(moveTo, null);
    const picker = refreshPicker(null, true, "Refresh interval for the selected feeds");
    const ids = () => [...selected];
    const bulk = async (action, extra = {}, confirmText = null) => {
      if (!selected.size) return;
      if (confirmText && !window.confirm(confirmText)) return;
      const res = await guarded(() => api("POST", "/feeds/bulk", { ids: ids(), action, ...extra }));
      if (res) { toast(`${res.updated} feed(s) updated`); selected.clear(); await onChanged(); }
    };
    const bar = h("div", { class: "bulk-bar feed-bulk", role: "toolbar", "aria-label": "Selected feeds" },
      count,
      h("span", { class: "bulk-group" }, h("span", { class: "muted", text: "Folder" }), moveTo,
        h("button", { type: "button", class: "btn small", text: "Move", onclick: () => bulk("move", { folder_id: moveTo.value ? Number(moveTo.value) : null }) })),
      h("span", { class: "bulk-group" }, h("span", { class: "muted", text: "Refresh" }), picker.el,
        h("button", { type: "button", class: "btn small", text: "Set", onclick: () => {
          const m = picker.value();
          if (Number.isNaN(m)) { toast("Custom interval must be 5–10080 minutes", true); return; }
          bulk("set_refresh", { refresh_minutes: m });
        } })),
      h("span", { class: "bulk-group" },
        h("button", { type: "button", class: "btn small", text: "Enable", onclick: () => bulk("enable") }),
        h("button", { type: "button", class: "btn small", text: "Disable", onclick: () => bulk("disable") }),
        h("button", { type: "button", class: "btn small", text: "⟳ Fetch now", onclick: () => bulk("fetch_now") }),
        h("button", { type: "button", class: "btn small", text: "Reset errors", title: "Clear the error counter and retry at once", onclick: () => bulk("reset_errors") }),
        h("button", { type: "button", class: "btn small", text: "🩺 Check", title: "Troubleshoot the selected feeds", onclick: () => doctor.start(ids()) }),
        h("button", { type: "button", class: "btn small", text: "🗓️ Keep…", title: "Keep only articles from a time frame in the selected feeds",
          onclick: () => openKeepArticles({ feedIds: ids(), onDone: () => onChanged() }) }),
        h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => bulk("delete", {}, `Unsubscribe from ${selected.size} feed(s) and delete their articles? This cannot be undone.`) })),
      h("button", { type: "button", class: "btn small", text: "Clear", onclick: () => { selected.clear(); render(); } }));

    // ---- table
    const tbody = h("tbody");
    const allBox = h("input", { type: "checkbox", "aria-label": "Select all shown feeds" });
    allBox.addEventListener("change", () => {
      for (const f of visible()) { if (allBox.checked) selected.add(f.id); else selected.delete(f.id); }
      render();
    });

    function row(f, list) {
      const pick = h("input", { type: "checkbox", checked: selected.has(f.id), "aria-label": `Select ${f.title}` });
      pick.addEventListener("click", (e) => {
        const on = pick.checked;
        if (e.shiftKey && lastClicked !== null) {
          const a = list.findIndex((x) => x.id === lastClicked);
          const b = list.findIndex((x) => x.id === f.id);
          if (a >= 0 && b >= 0) for (const x of list.slice(Math.min(a, b), Math.max(a, b) + 1)) { if (on) selected.add(x.id); else selected.delete(x.id); }
        }
        if (on) selected.add(f.id); else selected.delete(f.id);
        lastClicked = f.id;
        render();
      });
      const title = h("input", { type: "text", value: f.title, maxlength: 300, "aria-label": "Title" });
      const folder = h("select", { "aria-label": "Folder" }); fillFolderSelect(folder, f.folder_id);
      const refresh = refreshPicker(f.refresh_minutes, true);
      const enabled = h("input", { type: "checkbox", checked: f.enabled, "aria-label": "Enabled" });
      const save = async () => {
        const body = { title: title.value.trim(), enabled: enabled.checked };
        if (folder.value) body.folder_id = Number(folder.value); else body.clear_folder = true;
        const interval = refresh.value();
        if (Number.isNaN(interval)) { toast("Custom interval must be 5–10080 minutes", true); return; }
        if (interval === null) body.use_default_refresh = true; else body.refresh_minutes = interval;
        if (await guarded(() => api("PATCH", `/feeds/${f.id}`, body), "Feed saved")) onChanged(true);
      };
      const statusCell = f.error_count
        ? h("div", null,
          h("span", { class: "status-err", title: f.last_error || "", text: `⚠ ${f.error_count} error${f.error_count > 1 ? "s" : ""}` }),
          h("div", { class: "small muted err-text", text: f.last_error || "" }),
          h("button", { type: "button", class: "btn small", text: "🩺 Check", title: "Find out why it fails and look for a working address", onclick: () => diagnoseOne(f, single, onChanged) }))
        : h("span", { class: "status-ok", title: `Last fetched ${fullDate(f.last_fetched)}`, text: f.last_fetched ? `✓ ${relTime(f.last_fetched)}` : "pending" });
      return h("tr", { class: selected.has(f.id) ? "checked" : "" },
        h("td", { class: "pick-cell" }, pick),
        h("td", null, title, h("div", { class: "url", title: f.url }, filters.type === "all" ? h("span", { class: "feed-kind", text: `${TYPES.find(([t]) => t === typeOf(f))[1]} · ` }) : null, f.url)),
        h("td", null, folder), h("td", null, refresh.el), h("td", null, enabled), h("td", null, statusCell),
        h("td", null, h("div", { class: "actions" },
          h("button", { type: "button", class: "btn small", text: "Save", onclick: save }),
          h("button", { type: "button", class: "btn small", text: "⚙", title: "All settings for this feed", onclick: () => { $("#settingsDialog").close(); FW.feeds.openFeedEditor(f.id); } }),
          h("button", { type: "button", class: "btn small", text: "Fetch", onclick: async () => {
            const r = await guarded(() => api("POST", `/feeds/${f.id}/refresh`));
            if (r) { toast(r.ok ? `${r.new} new article(s)` : `Failed: ${r.error}`, !r.ok); onChanged(true); }
          } }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
            if (!window.confirm(`Unsubscribe from “${f.title}” and delete its articles?`)) return;
            if (await guarded(() => api("DELETE", `/feeds/${f.id}`), "Feed deleted")) onChanged();
          } }))));
    }

    function render() {
      const list = visible();
      fill(tbody, list.map((f) => row(f, list)));
      const shownSelected = list.filter((f) => selected.has(f.id)).length;
      allBox.checked = list.length > 0 && shownSelected === list.length;
      allBox.indeterminate = shownSelected > 0 && shownSelected < list.length;
      count.textContent = `${selected.size} selected`;
      bar.hidden = selected.size === 0;
    }

    search.addEventListener("input", () => { filters.q = search.value.trim(); render(); });
    status.addEventListener("change", () => { filters.status = status.value; render(); });
    folderFilter.addEventListener("change", () => { filters.folder = folderFilter.value; render(); });
    drawTypes();
    render();
    doctor.resume();  // a run started earlier keeps going server-side; show it again

    return h("div", { class: "feed-manager" },
      typeTabs,
      h("div", { class: "row-form feed-filters" }, search, status, folderFilter,
        h("button", { type: "button", class: "btn", text: "🗓️ Keep articles from…", title: "Scale your feeds back: remove articles older than a time frame (all feeds, a folder, or the ticked ones)",
          onclick: () => openKeepArticles({ feedIds: ids(), onDone: () => onChanged() }) }),
        failing.length ? h("button", { type: "button", class: "btn", text: `🩺 Troubleshoot failing feeds (${failing.length})`, onclick: () => doctor.start(null) }) : null),
      h("p", { class: "muted small", text: "Tick feeds (Shift+click for a range, or the header box for all shown) to move them to a folder, change the refresh interval, enable, disable, fetch, check or delete them together." }),
      bar,
      single,
      doctor,
      h("div", { class: "table-wrap" }, h("table", { class: "data feed-table" },
        h("thead", null, h("tr", null, h("th", { class: "pick-cell" }, allBox), ["Feed", "Folder", "Refresh", "On", "Status", ""].map((t) => h("th", { text: t })))),
        tbody)));
  }

  FW.feedtools = { manager, reportCard, openKeepArticles };
})();
