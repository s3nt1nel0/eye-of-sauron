/* Feed editor (opened from the sidebar ⚙ / right-click / list header) and history tools:
 * per-feed retention and "fetch older articles" (one feed, or all feeds at once).
 * Same rules as app.js: textContent only, links via safeUrl, no inline script/style. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, relTime, fullDate } = FW;
  const $ = (sel) => document.querySelector(sel);

  const RETENTION_CHOICES = [[30, "30 days"], [90, "90 days"], [180, "6 months"], [365, "1 year"], [730, "2 years"], [1095, "3 years"],
    [1825, "5 years"], [3650, "10 years"]];
  const CAP_CHOICES = [[200, "200"], [1000, "1,000"], [5000, "5,000"], [20000, "20,000"]];
  const fmtDays = (d) => FW.fmtRetention(d);  // "365 days (1 year)"
  const fmtDate = (ts) => (ts ? FW.fmtDate(ts) : "—");

  // ===================================================================== fetching older articles (shared)
  const METHOD = {
    paged: "WordPress ?paged=N", page: "?page=N", blogger: "Blogger pages", ghost: "Ghost pages", rfc5005: "RFC 5005 archive",
    wayback: "Internet Archive", "youtube-api": "YouTube Data API", "hf-daily": "one day per page",
    "telegram-web": "Telegram web preview", "telegram-account": "Telegram account",
  };
  // ONE history setting: how long a feed keeps items is also how far back older items are fetched (0 = everything).
  const WINDOW_CHOICES = [["", "Each feed's own “Keep” setting"], [90, "90 days"], [180, "6 months"], [365, "1 year"], [730, "2 years"],
    [1825, "5 years"], [3650, "10 years"], [0, "Everything (keep forever)"]];

  /** Where to look / effort (and, for many feeds, the keep & fetch-back window), shared by the feed editor and the
   *  all-feeds card. body(keepDays) sends keep_days: the feeds keep that window and are fetched back to it. */
  function backfillControls({ pagesDefault = 20, pagesLabel = "pages", withWindow = false, podcast = false } = {}) {
    const method = h("select", { "aria-label": "Where to look" }, [
      ["auto", podcast ? "Automatic (the show's feed and its older pages, then Internet Archive)" : "Automatic (site first, then Internet Archive)"],
      ["paged", podcast ? "The show's own feed and older pages only" : "The site's own older pages only"], ["wayback", "Internet Archive only"],
    ].map(([v, l]) => h("option", { value: v, text: l })));
    const window_ = withWindow ? h("select", { "aria-label": "Keep and fetch back" }, WINDOW_CHOICES.map(([v, l]) => h("option", { value: v, text: l }))) : null;
    const pages = h("select", { "aria-label": "Effort" }, [[10, `up to 10 ${pagesLabel}`], [20, `up to 20 ${pagesLabel}`], [30, `up to 30 ${pagesLabel}`], [60, `up to 60 ${pagesLabel}`], [100, `up to 100 ${pagesLabel}`], [200, `up to 200 ${pagesLabel}`]]
      .map(([v, l]) => h("option", { value: v, text: l, selected: v === pagesDefault })));
    return {
      method, pages, window: window_,
      body(keepDays) {
        const b = { method: method.value, max_pages: Number(pages.value) };
        const k = keepDays !== undefined ? keepDays : (window_ && window_.value !== "" ? Number(window_.value) : null);
        if (k !== null && k !== undefined && Number.isInteger(k) && k >= 0) b.keep_days = k;
        return b;
      },
    };
  }

  /** What a feed holds, in words: articles, podcast episodes, videos or account posts. */
  function feedNoun(f) {
    if (f.kind === "podcast") return { one: "episode", many: "episodes", Many: "Episodes", unread: "Unplayed", read: "played", feed: "show", Feed: "Show" };
    if (f.kind === "youtube") return { one: "video", many: "videos", Many: "Videos", unread: "Unwatched", read: "watched", feed: "channel", Feed: "Channel" };
    if (f.social_platform) return { one: "post", many: "posts", Many: "Posts", unread: "Unread", read: "read", feed: "account", Feed: "Account" };
    return { one: "article", many: "articles", Many: "Articles", unread: "Unread", read: "read", feed: "feed", Feed: "Feed" };
  }
  const PODCAST_HINT = "Shows usually list their latest 100–300 episodes in their feed. Loading older episodes reads the whole feed again, then the show's own older pages (when its host offers them), then old copies of the feed saved by the Internet Archive (web.archive.org). Each page or saved copy is one request; it runs in the background.";

  function describeBackfill(b) {
    const how = b.method ? ` via ${METHOD[b.method] || b.method}` : "";
    const reached = b.reached ? `, back to ${fmtDate(b.reached)}` : "";
    if (b.state === "running") return `⏳ Fetching older articles${how} — ${b.pages || 0} page(s), ${(b.new || 0).toLocaleString()} older article(s) so far${reached}…`;
    if (b.state === "done") return `✓ Done${how}: ${(b.new || 0).toLocaleString()} older article(s) from ${b.pages || 0} page(s)${reached}.${b.note ? ` ${b.note}` : ""}`;
    if (b.state === "error") return `✗ ${b.error}`;
    if (b.state === "cancelled") return `Stopped after ${(b.new || 0).toLocaleString()} article(s).`;
    return "";
  }

  /** Select with "Use global (…)", fixed choices and Custom…; value(): null = global, 0 = forever/unlimited. */
  function overridePicker(current, globalValue, choices, zeroLabel, unit, max, fmt = null) {
    const sel = h("select");
    const describe = (v) => (fmt ? fmt(v, true) : `${v.toLocaleString()} ${unit}`);
    sel.append(h("option", { value: "", text: `Use global setting (${globalValue === 0 ? zeroLabel.toLowerCase() : describe(globalValue)})` }));
    sel.append(h("option", { value: "0", text: zeroLabel, selected: current === 0 }));
    const values = choices.map(([v]) => v);
    for (const [v, l] of choices) sel.append(h("option", { value: v, text: l, selected: current === v }));
    const isCustom = current !== null && current !== undefined && current !== 0 && !values.includes(current);
    sel.append(h("option", { value: "custom", text: "Custom…", selected: isCustom }));
    if (current === null || current === undefined) sel.value = "";
    const custom = h("input", { type: "number", min: 1, max, value: isCustom ? current : "", hidden: !isCustom, placeholder: unit, class: "custom-minutes" });
    // the custom number in words next to it: "1095 days" → "= 3 years"
    const said = h("span", { class: "muted small custom-said", hidden: !isCustom || !fmt });
    const say = () => { const n = Number(custom.value); said.textContent = fmt && Number.isInteger(n) && n > 0 ? `= ${fmt(n, true)}` : ""; };
    custom.addEventListener("input", say); say();
    sel.addEventListener("change", () => { custom.hidden = sel.value !== "custom"; said.hidden = custom.hidden || !fmt; if (!custom.hidden) custom.focus(); });
    return {
      el: h("span", { class: "refresh-picker" }, sel, custom, said),
      value() {
        if (sel.value === "") return null;
        const n = Number(sel.value === "custom" ? custom.value : sel.value);
        return Number.isInteger(n) && n >= 0 && n <= max ? n : NaN;
      },
    };
  }

  async function openFeedEditor(feedId) {
    const dlg = $("#feedDialog");
    fill(dlg, h("p", { class: "muted", text: "Loading…" }));
    if (!dlg.open) dlg.showModal();
    let f;
    try { f = await api("GET", `/feeds/${feedId}/details`); } catch (err) { fill(dlg, h("p", { class: "error", text: err.message })); return; }
    const settings = FW.state.settings;
    const site = safeUrl(f.site_url);
    const title = h("input", { type: "text", maxlength: 300, value: f.title, placeholder: "Feed title" });
    const url = h("input", { type: "url", maxlength: 2048, value: f.url, required: true });
    const folder = h("select", { "aria-label": "Folder" });
    FW.fillFolderSelect(folder, f.folder_id);
    const refresh = FW.refreshPicker(f.refresh_minutes, true);
    const enabled = h("input", { type: "checkbox", checked: f.enabled });
    const translate = h("input", { type: "checkbox", checked: Boolean(f.translate_titles) });
    const adaptiveNote = f.refresh_minutes ? null : f.effective.adaptive
      ? `Default interval, adapted to how often this feed posts — currently ${FW.fmtMinutes(f.effective.refresh_minutes).toLowerCase()} (Settings → Appearance & reading → Check quiet feeds less often).`
      : null;
    const isArticles = ["rss", "html", null, undefined].includes(f.kind) && !f.social_platform;
    const N = feedNoun(f);
    const media = f.kind === "podcast" || f.kind === "youtube";   // podcasts and videos live in their own tabs
    const sourceKind = ["youtube", "hfpapers", "x", "telegram"].includes(f.kind || "");
    const canHistory = !["html", "json", "x"].includes(f.kind || "rss");
    const fullText = isArticles ? h("select", { "aria-label": "Full article text" },
      [["auto", "Automatic — when the feed sends only a summary"], ["always", "Always fetch the article page"], ["never", "Never (show what the feed sends)"]]
        .map(([v, l]) => h("option", { value: v, text: l, selected: (f.full_text || "auto") === v }))) : null;
    const keep = overridePicker(f.retention_days, Number(settings.retention_days ?? 90), RETENTION_CHOICES, "Keep forever", "days", 36500, FW.fmtRetention);
    // a count cap only makes sense for article feeds; podcasts and videos are kept by time alone
    const cap = media ? null : overridePicker(f.max_articles, Number(settings.max_articles_per_feed ?? 0), CAP_CHOICES, "Unlimited", N.many, 1000000);
    const err = h("p", { class: "error" });
    const s = f.stats;
    const scrapeEditor = (f.kind === "html" || f.kind === "json") && f.scrape ? rulesEditor(f.scrape, () => url.value.trim()) : null;
    const sourceEditor = FW.sources ? FW.sources.sourceEditor(f) : null;
    if (sourceEditor) url.readOnly = true;
    const reload = () => openFeedEditor(feedId);

    const save = async (e) => {
      e.preventDefault();
      err.textContent = "";
      const interval = refresh.value();
      const days = keep.value();
      const max = cap ? cap.value() : (f.max_articles ?? null);
      if (Number.isNaN(interval)) { err.textContent = "Custom refresh interval must be 5–10080 minutes."; return; }
      if (Number.isNaN(days) || Number.isNaN(max)) { err.textContent = "Custom retention values must be whole numbers."; return; }
      const body = { title: title.value.trim(), enabled: enabled.checked };
      if (translate.checked !== Boolean(f.translate_titles)) body.translate_titles = translate.checked;
      if (fullText) body.full_text = fullText.value;
      if (!sourceEditor && url.value.trim() !== f.url) body.url = url.value.trim();
      if (sourceEditor && sourceEditor.value()) body.source = sourceEditor.value();
      if (!media) { if (folder.value) body.folder_id = Number(folder.value); else body.clear_folder = true; }
      if (interval === null) body.use_default_refresh = true; else body.refresh_minutes = interval;
      if (scrapeEditor) {
        const rules = scrapeEditor.value();
        if (!rules.items) { err.textContent = "The items selector is required."; return; }
        body.scrape = rules;
      }
      try {
        await api("PATCH", `/feeds/${feedId}`, body);
        await api("PUT", `/feeds/${feedId}/retention`, { retention_days: days, max_articles: max });
        toast(`${N.Feed} saved`);
        FW.loadSidebar();
        // one setting: a longer time frame also means "go and get the older items" - offer it right away
        const before = f.effective.retention_days, after = days === null ? Number(settings.retention_days ?? 0) : days;
        const longer = canHistory && before !== 0 && (after === 0 || after > before);
        if (longer && window.confirm(`Keep ${after === 0 ? "everything" : fmtDays(after)} now. Load older ${N.many} back to ${after === 0 ? "the very first one" : "that date"}?`)) {
          await startBackfill(after);
          return;
        }
        reload();
      } catch (ex) { err.textContent = ex.message; }
    };

    const bf = backfillControls({ podcast: f.kind === "podcast" });
    const backfillStatus = h("div", { class: "muted small", "aria-live": "polite" });
    const showBackfill = (b) => {
      backfillStatus.textContent = b && b.feed_id === feedId && !b.bulk ? describeBackfill(b)
        : b && b.bulk && b.state === "running" ? "⏳ An all-feeds back-fill is running (Settings → Feeds)." : "";
    };
    showBackfill(f.backfill);
    const pollBackfill = async () => {
      const st = await api("GET", "/history/status").catch(() => null);
      if (!st || !dlg.open) return;
      showBackfill(st.backfill);
      if (st.backfill.state === "running") setTimeout(pollBackfill, 1500);
      else { FW.loadSidebar(); FW.loadArticles(); }
    };
    const startBackfill = async (keepDays) => {
      // fetch back as far as the Keep setting says (the value in the picker, even before Save)
      const chosen = Number.isInteger(keepDays) ? keepDays : keep.value();
      const body = bf.body(Number.isInteger(chosen) ? chosen : undefined);
      if (await guarded(() => api("POST", `/feeds/${feedId}/backfill`, body))) {
        backfillStatus.textContent = "⏳ Starting…";
        setTimeout(pollBackfill, 800);
      }
    };

    const ruleRows = f.rules.map((r) => h("li", { class: r.enabled ? "" : "muted" },
      h("strong", { text: r.name }), ` — ${r.scope}: `, r.keywords.join(", "),
      " → ", [r.collection ? `📁 ${r.collection}` : null, r.star ? "★" : null, r.mark_read ? "mute" : null,
        r.webhook ? "webhook" : null, r.social ? "social draft" : null].filter(Boolean).join(", ") || "—",
      r.enabled ? "" : " (disabled)"));

    fill(dlg, h("form", { class: "form feed-editor", onsubmit: save },
      h("div", { class: "sd-head" },
        h("div", null, h("h3", { text: `⚙ ${f.title}` }),
          h("div", { class: "muted small" }, site ? h("a", { href: site, target: "_blank", rel: "noopener noreferrer", text: f.site_url }) : f.url)),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("div", { class: "fe-stats" },
        stat(N.Many, s.total.toLocaleString()), stat(N.unread, s.unread.toLocaleString()), stat("Starred", s.starred.toLocaleString()),
        stat("Last 30 days", s.last_30d.toLocaleString()), stat("Oldest", fmtDate(s.oldest)), stat("Newest", fmtDate(s.newest)),
        stat("Keeps", `${fmtDays(f.effective.retention_days)}${f.retention_days === null || f.retention_days === undefined ? " (global)" : ""}`)),
      h("fieldset", null, h("legend", { text: N.Feed }),
        h("div", { class: "grid-form" },
          h("label", { text: "Title" }), title,
          h("label", { text: sourceEditor ? "Address" : "Feed URL" }), url,
          media ? null : h("label", { text: "Folder" }), media ? null : folder,
          h("label", { text: "Refresh every" }), refresh.el,
          adaptiveNote ? h("div", { class: "hint", text: adaptiveNote }) : null,
          h("label", { text: "Enabled" }), enabled,
          h("label", { text: "Translate titles" }), translate,
          h("div", { class: "hint", text: `For ${N.feed}s in another language (CERT-FR, JPCERT…): ${N.one} titles are translated by your AI provider (Settings → AI, into its language setting). The original title stays visible under the translation. Turning this off puts the original titles back.` }),
          fullText ? h("label", { text: "Full article text" }) : null, fullText,
          fullText ? h("div", { class: "hint", text: "Many sites put only a sentence or two in their feed. The full text is then read from the article page (if the site allows feed readers; some refuse, and those keep the summary)." }) : null)),
      sourceEditor ? sourceEditor.el : null,
      scrapeEditor ? h("fieldset", null, h("legend", { text: `Scraping rules (${f.kind === "json" ? "JSON API" : "web page"})` }),
        h("p", { class: "muted small", text: "This feed is built by scraping. If the site changes its layout and nothing matches, the feed shows an error — adjust the selectors and use ▶ Test rules." }),
        scrapeEditor.el) : null,
      h("fieldset", null, h("legend", { text: "History" }),
        h("div", { class: "grid-form" },
          h("label", { text: `Keep & fetch ${N.many} from` }), keep.el,
          h("div", { class: "hint", text: `One setting: ${N.many} older than this are removed, and loading older ${N.many} goes back exactly this far. Currently: ${fmtDays(f.effective.retention_days)}. Starred and hand-filed ${N.many} are always kept.` }),
          cap ? h("label", { text: `At most` }) : null, cap ? cap.el : null,
          cap ? h("div", { class: "hint", text: `A count limit on top of the time frame (the newest stay). Currently: ${f.effective.max_articles ? f.effective.max_articles.toLocaleString() : "no limit"}.` }) : null,
          canHistory ? h("label", { text: `Older ${N.many}` }) : null,
          canHistory ? h("div", null,
            h("div", { class: "row-form bf-row" }, sourceKind ? null : bf.method, bf.pages),
            h("div", { class: "row-form" },
              h("button", { type: "button", class: "btn small", text: `⇣ Load older ${N.many}`, title: `Back to the Keep setting above (${fmtDays(f.effective.retention_days)} now)`, onclick: () => startBackfill() }),
              h("button", { type: "button", class: "btn small", text: "Stop", onclick: () => api("POST", "/history/cancel", {}) })),
            backfillStatus) : null,
          canHistory ? h("div", { class: "hint", text: f.kind === "podcast" ? PODCAST_HINT : (FW.sources && FW.sources.BACKFILL_HINT[f.kind]) || "Feeds only list their latest items. Automatic tries the site's own older pages (archive links, WordPress, Blogger, Ghost, ?page=N) and otherwise reads old copies of this feed saved by the Internet Archive (web.archive.org), which reaches back years for most public feeds. Each page or saved copy is one request; it runs in the background." })
            : h("div", { class: "hint", text: "Scraped web pages and X only show what is there now: there are no older pages to load." }))),
      h("fieldset", null, h("legend", { text: "Health" }),
        h("div", { class: "grid-form" },
          h("label", { text: "Last fetched" }), h("span", { text: f.last_fetched ? `${relTime(f.last_fetched)} (${fullDate(f.last_fetched)})` : "never" }),
          h("label", { text: "Next fetch" }), h("span", { text: f.next_fetch ? fullDate(f.next_fetch) : "as soon as possible" }),
          h("label", { text: "Status" }), f.error_count
            ? h("span", { class: "status-err", text: `⚠ ${f.error_count} consecutive error(s): ${f.last_error || "unknown"}` })
            : h("span", { class: "status-ok", text: "✓ OK" }),
          h("label", { text: "Subscribed" }), h("span", { text: fullDate(f.created_at) }))),
      media ? null : h("fieldset", null, h("legend", { text: `Rules that apply (${f.rules.length})` }),
        f.rules.length ? h("ul", { class: "small fe-rules" }, ruleRows) : h("p", { class: "muted small", text: `No rules apply to this ${N.feed}.` }),
        h("button", { type: "button", class: "btn small", text: "Manage rules…", onclick: () => { dlg.close(); FW.openSettings("rules"); } })),
      err,
      h("div", { class: "form-actions fe-foot" },
        h("button", { type: "button", class: "btn danger", text: `Delete ${N.feed}`, onclick: async () => {
          if (!window.confirm(`Unsubscribe from “${f.title}” and delete its ${s.total} ${s.total === 1 ? N.one : N.many}?`)) return;
          if (await guarded(() => api("DELETE", `/feeds/${feedId}`), `${N.Feed} deleted`)) { dlg.close(); FW.loadSidebar(); if (!media) FW.selectView({ type: "unread" }); }
        } }),
        h("span", { class: "spacer" }),
        h("button", { type: "button", class: "btn", text: `Mark all ${N.read}`, onclick: async () => {
          if (await guarded(() => api("POST", "/articles/mark-read", { feed_id: feedId }), "Marked read")) { FW.loadSidebar(); FW.loadArticles(); reload(); }
        } }),
        h("button", { type: "button", class: "btn", text: "⟳ Refresh now", onclick: async () => {
          const r = await guarded(() => api("POST", `/feeds/${feedId}/refresh`));
          if (r) { toast(r.ok ? `${r.new} new ${r.new === 1 ? N.one : N.many}` : `Failed: ${r.error}`, !r.ok); FW.loadSidebar(); FW.loadArticles(); reload(); }
        } }),
        h("button", { type: "submit", class: "btn primary", text: "Save" }))));
    if (f.backfill && f.backfill.state === "running") setTimeout(pollBackfill, 1000);
  }

  function stat(label, value) {
    return h("div", { class: "fe-stat" }, h("div", { class: "fe-stat-v", text: value }), h("div", { class: "muted small", text: label }));
  }

  // ===================================================================== fetch older articles for all feeds
  function backfillAllCard(folders, onDone) {
    const bf = backfillControls({ pagesDefault: 30, pagesLabel: "pages per feed", withWindow: true });
    const folder = h("select", { "aria-label": "Which feeds" }, [h("option", { value: "", text: "All feeds" })]
      .concat(folders.map((f) => h("option", { value: f.id, text: `Folder: ${f.name}` }))));
    const missing = h("input", { type: "checkbox", checked: true });
    const progress = h("div", { class: "muted small", "aria-live": "polite" });
    const summary = h("div");
    const show = (j) => {
      fill(summary);
      if (!j || j.state === "idle" || !j.bulk) {
        progress.textContent = j && j.state === "running" ? "⏳ A single-feed back-fill is running…" : "";
        return;
      }
      const head = `${(j.new_total || 0).toLocaleString()} older article(s) so far`;
      if (j.state === "running") {
        progress.textContent = `⏳ Feed ${j.current || 0} of ${j.total} — ${j.feed_title || ""}${j.method ? ` (${METHOD[j.method] || j.method})` : ""}: ${(j.new || 0).toLocaleString()} from this feed. ${head}.`;
      } else if (j.state === "error") {
        progress.textContent = `✗ ${j.error}`;
      } else {
        progress.textContent = `${j.state === "cancelled" ? "Stopped" : "✓ Finished"}: ${(j.new_total || 0).toLocaleString()} older article(s) from ${j.done || 0} of ${j.total} feed(s)${j.failed ? `; ${j.failed} feed(s) had nothing to offer or failed` : ""}.`;
      }
      const results = j.results || [];
      if (!results.length) return;
      const got = results.filter((r) => r.new).sort((x, y) => y.new - x.new);
      const failed = results.filter((r) => r.error);
      fill(summary, h("details", { class: "small" },
        h("summary", { text: `Per feed (${got.length} gained articles, ${failed.length} without)` }),
        h("ul", { class: "small" }, got.map((r) => h("li", { text: `${r.title}: ${r.new.toLocaleString()} via ${METHOD[r.method] || r.method || "—"}` }))
          .concat(failed.map((r) => h("li", { class: "muted", text: `${r.title}: ${r.error}` }))))));
    };
    const poll = async () => {
      const st = await api("GET", "/history/status").catch(() => null);
      if (!st || !document.body.contains(progress)) return;
      show(st.backfill);
      if (st.backfill.state === "running") setTimeout(poll, 2000);
      else if (st.backfill.bulk && onDone) onDone();
    };
    api("GET", "/history/status").then((st) => { show(st.backfill); if (st.backfill.state === "running") setTimeout(poll, 2000); }).catch(() => {});
    const start = async () => {
      const body = { ...bf.body(), only_missing: missing.checked };
      if (folder.value) body.folder_id = Number(folder.value);
      const r = await guarded(() => api("POST", "/history/backfill-all", body));
      if (!r) return;
      if (!r.started) { progress.textContent = "Nothing to do: every selected feed already has history back to that date."; return; }
      progress.textContent = `⏳ Starting on ${r.feeds} feed(s)…`;
      setTimeout(poll, 1000);
    };
    return h("div", { class: "card" },
      h("h4", { text: "Fetch older articles for all feeds" }),
      h("p", { class: "muted small", text: "Feeds only list their newest items, so history has to be looked up feed by feed: first on the site itself (archive links, WordPress, Blogger, Ghost or ?page=N paging), then in old copies of the feed saved by the Internet Archive (web.archive.org). It runs in the background, one feed after another, with pauses between requests — a full run over many feeds can take an hour or more. Scraped web pages and X feeds are skipped." }),
      h("div", { class: "grid-form" },
        h("label", { text: "Feeds" }), folder,
        h("label", { text: "Keep & fetch back" }), bf.window,
        h("div", { class: "hint", text: "One setting: the feeds keep this time frame and older articles are fetched back to it. “Each feed's own” uses every feed's Keep setting as it is." }),
        h("label", { text: "Where to look" }), bf.method,
        h("label", { text: "Effort" }), bf.pages,
        h("label", { text: "Options" }), h("div", { class: "fe-opts" },
          h("label", { class: "toggle", title: "Skips feeds whose articles already reach back to the chosen date." }, missing, " Only feeds missing that history"))),
      progress, summary,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Stop", onclick: () => api("POST", "/history/cancel", {}) }),
        h("button", { type: "button", class: "btn primary", text: "⇣ Start", onclick: start })));
  }

  // ===================================================================== website scraping
  const FIELD_HELP = {
    items: "CSS selector matching ONE element per article, e.g. article, div.post, li.news-item",
    title: "Relative to the item. Empty = the item's text. e.g. h2, .title",
    link: "e.g. h2 a @href (an @attribute reads an attribute). Empty = first link in the item",
    content: "Summary / body, e.g. p, .excerpt",
    date: "e.g. time (uses its datetime attribute), .date, span.posted",
    author: "e.g. .author",
    image: "e.g. img @src",
    date_format: "Only if dates are not recognised automatically, e.g. %d %B %Y",
  };
  const JSON_HELP = {
    items: "Dotted path to the list, e.g. data.articles or results[0].items",
    title: "Path inside each item, e.g. title  (combine: title & \" - \" & source)",
    link: "e.g. url or links[0].href",
    content: "e.g. summary", date: "e.g. published_at", author: "e.g. author.name", image: "e.g. image.url",
    date_format: "Only if needed, e.g. %Y-%m-%dT%H:%M:%S",
  };

  function rulesEditor(initial, getUrl) {
    const r = Object.assign({ mode: "html", items: "", title: "", link: "", content: "", date: "", author: "", image: "", date_format: "" }, initial || {});
    const mode = h("select", null, h("option", { value: "html", text: "Web page (HTML + CSS selectors)", selected: r.mode === "html" }),
      h("option", { value: "json", text: "JSON API (dotted paths)", selected: r.mode === "json" }));
    const inputs = {};
    const rows = h("div", { class: "grid-form" });
    const preview = h("div", { class: "scrape-preview" });
    const build = () => {
      const help = mode.value === "json" ? JSON_HELP : FIELD_HELP;
      const els = [];
      for (const key of ["items", "title", "link", "content", "date", "author", "image", "date_format"]) {
        inputs[key] = inputs[key] || h("input", { type: "text", maxlength: key === "date_format" ? 60 : 300, value: r[key] || "", spellcheck: "false", class: "mono" });
        els.push(h("label", { text: key === "items" ? "Items *" : key.replace("_", " ").replace(/^./, (c) => c.toUpperCase()) }), inputs[key],
          h("div", { class: "hint", text: help[key] }));
      }
      fill(rows, els);
    };
    mode.addEventListener("change", build);
    build();
    const value = () => {
      const out = { mode: mode.value };
      for (const [k, el] of Object.entries(inputs)) out[k] = el.value.trim();
      return out;
    };
    const test = async () => {
      fill(preview, h("p", { class: "muted", text: "Testing against the live page…" }));
      try {
        const res = await api("POST", "/scrape/preview", { url: getUrl(), scrape: value() });
        showPreview(preview, res.items, res.count, res.warnings);
      } catch (err) { fill(preview, h("p", { class: "error", text: err.message })); }
    };
    const el = h("div", { class: "scrape-editor" },
      h("div", { class: "row-form" }, mode, h("button", { type: "button", class: "btn small", text: "▶ Test rules", onclick: test })),
      rows, preview);
    return { el, value, test, preview };
  }

  function showPreview(host, items, count, warnings) {
    fill(host,
      h("div", { class: "muted small", text: `${count} item(s) matched${count > items.length ? ` — showing ${items.length}` : ""}.` }),
      (warnings || []).map((w) => h("p", { class: "hint warn-text", text: `⚠ ${w}` })),
      items.length ? h("ol", { class: "scrape-items" }, items.map((it) => {
        const link = safeUrl(it.link);
        return h("li", null,
          link ? h("a", { href: link, target: "_blank", rel: "noopener noreferrer", text: it.title || it.link }) : h("strong", { text: it.title }),
          h("div", { class: "muted small", text: [it.published ? fmtDate(it.published) : "no date", it.author].filter(Boolean).join(" · ") }),
          it.summary ? h("div", { class: "small", text: it.summary }) : null);
      })) : null);
  }

  /** Shown when "Add feed" points at a normal web page: offer its real feeds first, otherwise scraping rules. */
  function openScrapeWizard(found, base) {
    const dlg = $("#feedDialog");
    const url = h("input", { type: "url", value: found.page_url || base.url, maxlength: 2048 });
    const editor = rulesEditor(found.suggestion, () => url.value.trim());
    if (found.preview && found.preview.length) showPreview(editor.preview, found.preview, found.preview.length, []);
    const err = h("p", { class: "error" });
    const subscribe = async (payload, msg) => {
      try {
        await api("POST", "/feeds", payload);
        dlg.close();
        toast(msg);
        await FW.loadSidebar();
        setTimeout(() => { FW.loadSidebar(); FW.loadArticles(); }, 4000);
      } catch (ex) { err.textContent = ex.message; }
    };
    fill(dlg, h("div", { class: "form" },
      h("div", { class: "sd-head" }, h("div", null, h("h3", { text: "This address is a web page, not a feed" }),
        h("div", { class: "muted small", text: base.url })),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      found.feeds.length ? h("fieldset", null, h("legend", { text: "✓ Feeds found on this site (best option)" }),
        found.feeds.map((f) => h("div", { class: "card-head found-feed" },
          h("div", null, h("strong", { text: f.title || f.url }), h("div", { class: "muted small", text: `${f.url} · ${f.type || "feed"} · ${f.items} items` })),
          h("button", { type: "button", class: "btn small primary", text: "Subscribe",
            onclick: () => subscribe({ ...base, url: f.url }, "Subscribed — fetching articles…") })))) : null,
      h("fieldset", null, h("legend", { text: found.feeds.length ? "…or scrape the page itself" : "Create a feed by scraping the page" }),
        found.hint ? h("p", { class: "hint warn-text", text: found.hint }) : null,
        found.suggestion ? h("p", { class: "muted small", text: "Rules were suggested automatically from the page structure — check the preview, adjust if needed." })
          : h("p", { class: "muted small", text: "No repeating article list was detected automatically. Enter a CSS selector for one article (browser: right-click an article → Inspect)." }),
        h("div", { class: "grid-form" }, h("label", { text: "Page URL" }), url),
        editor.el),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "button", class: "btn primary", text: "Subscribe to scraped feed", onclick: () => {
          const rules = editor.value();
          if (!rules.items) { err.textContent = "The items selector is required."; return; }
          subscribe({ ...base, url: url.value.trim(), scrape: rules }, "Scraped feed added — fetching…");
        } }))));
    if (!dlg.open) dlg.showModal();
  }


  // ===================================================================== mobile apps (Google Reader API)
  async function mobilePanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    let apps;
    try { apps = await api("GET", "/reader-apps"); } catch (err) { fill(panel, h("p", { class: "error", text: err.message })); return; }
    const origin = window.location.origin;
    const rerender = () => mobilePanel(panel);
    const name = h("input", { type: "text", maxlength: 60, placeholder: "Device / app, e.g. iPhone – Reeder", required: true });
    const reveal = h("div");
    const copyBtn = (text) => h("button", { type: "button", class: "btn small", text: "Copy", onclick: async () => {
      try { await navigator.clipboard.writeText(text); toast("Copied"); } catch (_) { toast("Copy failed — select the text", true); }
    } });
    const row = (label, value) => [h("label", { text: label }), h("div", { class: "row-form" }, h("code", { class: "secret-box small", text: value }), copyBtn(value))];
    const httpsWarn = window.location.protocol !== "https:"
      ? h("p", { class: "hint warn-text", text: "⚠ This page is served over plain HTTP. Only use mobile apps on your home network, or put Eye of Sauron behind HTTPS / Tailscale before connecting from outside (see the guide, “Using it from your phone”)." })
      : null;
    fill(panel,
      h("p", { class: "muted", text: "Connect native RSS apps — Reeder, NetNewsWire, FeedMe, Read You, FocusReader, Fluent Reader, News+ and others — through the Google Reader API (the same protocol FreshRSS uses). Read/unread, stars, folders and subscriptions stay in sync." }),
      httpsWarn,
      h("div", { class: "panel-section" }, h("h4", { text: "How to connect" }),
        h("ol", { class: "small mobile-steps" },
          h("li", { text: "Create an app password below (one per device — never use your main password in an app)." }),
          h("li", { text: "In the app, add an account of type “FreshRSS” (preferred) or “Google Reader API”." }),
          h("li", null, "Server: ", h("code", { text: origin }), " — if the app asks for the full API address use ", h("code", { text: `${origin}/api/greader.php` }), "."),
          h("li", { text: "Username: your Eye of Sauron username. Password: the app password." }))),
      h("form", { class: "row-form card", onsubmit: async (e) => {
        e.preventDefault();
        const res = await guarded(() => api("POST", "/reader-apps", { name: name.value.trim() }));
        if (!res) return;
        await mobilePanel(panel);
        panel.prepend(h("div", { class: "card" },
          h("strong", { text: `App password for “${res.name}” — copy it now, it will not be shown again.` }),
          h("div", { class: "grid-form", style: { "margin-top": "8px" } },
            row("Server", origin), row("API address", `${origin}/api/greader.php`), row("Username", res.username), row("App password", res.password))));
      } }, name, h("button", { type: "submit", class: "btn primary", text: "Create app password" })),
      reveal,
      apps.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["App / device", "Created", "Last sign-in", "Active sessions", ""].map((t) => h("th", { text: t })))),
        h("tbody", null, apps.map((a) => h("tr", null,
          h("td", { text: a.name }), h("td", { text: relTime(a.created_at) }), h("td", { text: a.last_used ? relTime(a.last_used) : "never" }),
          h("td", { text: String(a.devices) }),
          h("td", null, h("button", { type: "button", class: "btn small danger", text: "Revoke", onclick: async () => {
            if (window.confirm(`Revoke “${a.name}”? The app is signed out immediately.`) && await guarded(() => api("DELETE", `/reader-apps/${a.id}`), "Revoked")) rerender();
          } }))))))) : h("p", { class: "muted", text: "No app passwords yet." }),
      h("p", { class: "muted small", text: "App passwords only work for the reader API: an app can read articles, change read/starred state and manage subscriptions/folders, but cannot reach settings, tokens, webhooks, social accounts or the REST API." }));
  }

  FW.feeds = { openFeedEditor, backfillAllCard, backfillControls, openScrapeWizard, rulesEditor, mobilePanel };
})();
