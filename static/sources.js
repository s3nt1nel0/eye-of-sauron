/* Stage-2 sources: add YouTube / X / Telegram / Hugging Face Papers, Integrations settings
 * (API keys, X bridge, Telegram account login) and the YouTube library view.
 * Same rules as app.js: textContent only, links via safeUrl, colours via safeColor, no inline script. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, safeColor, relTime } = FW;
  const $ = (sel) => document.querySelector(sel);

  const KIND_LABEL = { youtube: "YouTube", hfpapers: "Hugging Face Daily Papers", x: "X (Twitter)", telegram: "Telegram", email: "Email newsletter" };
  const KIND_ICON = { youtube: "▶", hfpapers: "📄", x: "𝕏", telegram: "✈", email: "✉" };
  const SOURCE_RE = /^(?:https?:\/\/)?(?:www\.|m\.|mobile\.)?(?:youtube\.com\/|youtu\.be\/|t\.me\/|telegram\.me\/|x\.com\/|twitter\.com\/|huggingface\.co\/papers|hf\.co\/papers)/i;

  /** Kind for an input, or null for websites/RSS. `hint` comes from the Add-feed type picker. */
  function detectKind(text, hint) {
    if (hint && hint !== "auto" && hint !== "rss") return hint;
    if (hint === "rss") return null;
    if (SOURCE_RE.test(text.trim())) return "auto";
    return null;
  }

  // ======================================================================= single YouTube videos
  const VIDEO_RE = /(?:youtube\.com\/(?:watch\?(?:.*&)?v=|shorts\/|live\/|embed\/)|youtu\.be\/)[A-Za-z0-9_-]{11}/i;
  // A playlist link, or a link to a video played inside a playlist (…watch?v=…&list=…). "RD…" lists are YouTube's
  // automatic mixes, not playlists anyone made: those stay single videos.
  const PLAYLIST_RE = /youtube\.com\/(?:playlist|watch)\?(?:.*&)?list=(?!RD)[A-Za-z0-9_-]{12,64}/i;
  const isPlaylistLink = (text) => PLAYLIST_RE.test(text.trim());
  const isVideoLink = (text) => VIDEO_RE.test(text.trim()) && !isPlaylistLink(text);
  /** A video played inside a playlist: it can mean "this video" or "the whole playlist" - the user picks. */
  const isVideoInPlaylist = (text) => VIDEO_RE.test(text.trim()) && isPlaylistLink(text);

  /** A link to one video: add just that video (default) or subscribe to its whole channel. */
  async function chooseVideoOrChannel(input, base) {
    const dlg = $("#sourceDialog");
    // 📁 optionally straight into one of your groups (or a new one)
    const groupList = await api("GET", "/library/groups").then((r) => r.groups.filter((g) => String(g.id).startsWith("g:"))).catch(() => []);
    const groupSel = h("select", { "aria-label": "Put the video in a group" }, h("option", { value: "", text: "No group" }),
      groupList.map((g) => h("option", { value: g.id, text: g.name })), h("option", { value: "new", text: "＋ New group…" }));
    const groupName = h("input", { type: "text", maxlength: 100, placeholder: "New group name", "aria-label": "New group name", hidden: true });
    groupSel.addEventListener("change", () => { groupName.hidden = groupSel.value !== "new"; if (!groupName.hidden) groupName.focus(); });
    const addVideo = async () => {
      let group = groupSel.value || null, groupLabel = "";
      if (group === "new") {
        if (!groupName.value.trim()) { groupName.focus(); toast("Type a name for the new group", true); return; }
        try { const g = await api("POST", "/library/groups", { name: groupName.value.trim() }); group = g.id; groupLabel = groupName.value.trim(); }
        catch (ex) { toast(ex.message, true); return; }
      } else if (group) groupLabel = (groupList.find((g) => g.id === group) || {}).name || "";
      fill(dlg, h("p", { class: "muted", text: "Adding the video…" }));
      try {
        const r = await api("POST", "/library/videos", { url: input });
        let inGroup = "";
        if (group && r.article_id) {
          const g = await api("POST", `/library/groups/${encodeURIComponent(group)}/videos`, { article_ids: [r.article_id] }).catch(() => null);
          if (g) inGroup = ` · in ${groupLabel}`;
        }
        dlg.close();
        toast((r.already ? `Already in your library: ${r.title}` : `Added to the library: ${r.title}`) + inGroup);
        FW.loadSidebar();
        if (FW.currentMode() === "library") { await library.loadMeta(); library.renderShell(); library.reload(); }
      } catch (err) {
        fill(dlg, h("div", { class: "form" }, h("h3", { text: "Couldn’t add that video" }), h("p", { class: "error", text: err.message }),
          h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }))));
      }
    };
    fill(dlg, h("div", { class: "form source-wizard" },
      h("div", { class: "sd-head" }, h("h3", null, h("span", { class: "src-badge k-youtube", text: "▶" }), " YouTube video"),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("p", { class: "muted", text: "This is a link to a single video. Add only this video to your library, or follow the whole channel it belongs to?" }),
      h("div", { class: "grid-form" }, h("label", { text: "Put the video in group" }), h("span", { class: "tf-picker" }, groupSel, groupName)),
      h("div", { class: "choice-cards" },
        h("button", { type: "button", class: "choice-card primary", onclick: addVideo },
          h("strong", { text: "▶ Add just this video" }), h("span", { class: "muted small", text: "It goes into “Saved YouTube videos” and is sorted into topics like the rest." })),
        isVideoInPlaylist(input) ? h("button", { type: "button", class: "choice-card", onclick: () => openSourceWizard(input, base, { kind: "youtube", skipVideoChoice: true }) },
          h("strong", { text: "▶ Follow the whole playlist" }), h("span", { class: "muted small", text: "Every video in the playlist this link came from, plus new ones added to it." })) : null,
        h("button", { type: "button", class: "choice-card", onclick: () => openSourceWizard(isVideoInPlaylist(input) ? input.replace(/[?&]list=[^&]*/, "") : input, base, { kind: "youtube", skipVideoChoice: true }) },
          h("strong", { text: "📺 Subscribe to the whole channel" }), h("span", { class: "muted small", text: "All of its videos (with a YouTube API key), plus new uploads as they appear." })))));
    if (!dlg.open) dlg.showModal();
  }

  // ======================================================================= add-source wizard
  async function openSourceWizard(input, base = {}, opts = {}) {
    if (!opts.skipVideoChoice && (!opts.kind || opts.kind === "auto" || opts.kind === "youtube") && (isVideoLink(input) || isVideoInPlaylist(input))) {
      chooseVideoOrChannel(input, base);
      return;
    }
    const dlg = $("#sourceDialog");
    fill(dlg, h("p", { class: "muted", text: "Looking up the source…" }));
    if (!dlg.open) dlg.showModal();
    let res;
    try {
      res = await api("POST", "/sources/resolve", { input, kind: opts.kind && opts.kind !== "auto" ? opts.kind : undefined, via: opts.via });
    } catch (err) {
      fill(dlg, h("div", { class: "form" },
        h("h3", { text: "Couldn’t add that source" }),
        h("p", { class: "error", text: err.message }),
        /Integrations/.test(err.message) ? h("p", null, h("button", { type: "button", class: "btn small", text: "Open Settings → Integrations", onclick: () => { dlg.close(); FW.openSettings("integrations"); } })) : null,
        h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }))));
      return;
    }
    const title = h("input", { type: "text", maxlength: 300, value: res.title || "", placeholder: "Title (optional)" });
    const folder = h("select", { "aria-label": "Folder" });
    FW.fillFolderSelect(folder, base.folder_id ?? null);
    const err = h("p", { class: "error" });
    let viaPicker = null;
    if (res.kind === "x" || res.kind === "telegram") {
      const options = res.kind === "x" ? [["bridge", "Bridge (RSSHub / Nitter / RSS-Bridge)"], ["api", "Official X API (paid)"]]
        : [["web", "Public web preview (no login)"], ["account", "My Telegram account"]];
      viaPicker = h("select", { "aria-label": "Read through", onchange: () => openSourceWizard(input, { ...base, folder_id: folder.value ? Number(folder.value) : null }, { kind: res.kind, via: viaPicker.value }) },
        options.map(([v, l]) => h("option", { value: v, text: l, selected: res.source.via === v })));
    }
    const subscribe = async (e) => {
      e.preventDefault();
      const body = { url: res.url, source: res.source, refresh_minutes: base.refresh_minutes ?? res.refresh_minutes };
      if (base.retention_days !== undefined && base.retention_days !== null) body.retention_days = base.retention_days;
      if (title.value.trim()) body.title = title.value.trim();
      if (folder.value && res.kind !== "youtube") body.folder_id = Number(folder.value);
      try {
        const feed = await api("POST", "/feeds", body);
        dlg.close();
        toast(feed.adopted ? `${feed.title} was already in Articles as a plain feed — it is now a YouTube channel, and its videos are in Videos.`
          : `${KIND_LABEL[res.kind]} source added — fetching…`);
        FW.loadSidebar();
        setTimeout(() => { FW.loadSidebar(); FW.loadArticles(); if (FW.currentMode() === "library") library.reload(); }, 4000);
        if (res.kind === "youtube" && opts.offerBackfill !== false) loadWholeChannel(feed.id, true);
        else if (base.load_older && feed.id) {  // Add feed → "also download older items" for X / Telegram / papers
          api("POST", `/feeds/${feed.id}/backfill`, { method: "auto", max_pages: 100, since_days: base.retention_days || null,
            keep_forever: base.retention_days === 0 }).catch((ex) => toast(`Older items: ${ex.message}`));
        }
      } catch (ex) { err.textContent = ex.message; }
    };
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: subscribe },
      h("div", { class: "sd-head" },
        h("h3", null, h("span", { class: `src-badge k-${res.kind}`, text: KIND_ICON[res.kind] }), ` Add ${KIND_LABEL[res.kind]} source`),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("div", { class: "grid-form" },
        h("label", { text: "Title" }), title,
        viaPicker ? h("label", { text: "Read through" }) : null, viaPicker,
        res.kind === "youtube" ? null : h("label", { text: "Folder" }), res.kind === "youtube" ? null : folder,
        h("label", { text: "Address" }), h("code", { class: "small", text: res.url })),
      res.notes.length ? h("ul", { class: "small src-notes" }, res.notes.map((n) => h("li", { text: n }))) : null,
      h("fieldset", null, h("legend", { text: res.preview.length
        ? (res.found && res.found > res.preview.length ? `${res.found} items found · latest ${res.preview.length} shown` : `${res.preview.length} item${res.preview.length === 1 ? "" : "s"} found`)
        : "Preview" }),
        res.preview.length ? h("ol", { class: "scrape-items" }, res.preview.map((p) => {
          const link = safeUrl(p.link);
          return h("li", null, link ? h("a", { href: link, target: "_blank", rel: "noopener noreferrer", text: p.title || "(untitled)" }) : h("span", { text: p.title || "(untitled)" }),
            p.summary ? h("div", { class: "muted small", text: p.summary }) : null);
        })) : h("p", { class: "muted small", text: res.kind === "x" && res.source.via === "api" ? "No preview for the X API (each post read costs API credits) — posts appear after the first fetch." : "Nothing to preview yet." })),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "submit", class: "btn primary", text: "Subscribe" }))));
  }

  // ----------------------------------------------------------------------- time frames (adding and scaling back)
  const TIME_FRAMES = [[1, "Last day"], [7, "Last week"], [30, "Last month"], [90, "Last 3 months"], [180, "Last 6 months"],
    [365, "Last year"], [730, "Last 2 years"], [0, "Everything"]];
  const UNIT_DAYS = { days: 1, weeks: 7, months: 30, years: 365 };
  /** A time-frame select with a "Custom…" choice (a number + days/weeks/months/years).
   *  Returns {el, select, days()}: days() = number of days, 0 = everything, null = "latest", NaN = invalid custom. */
  function timeFramePicker({ label, selected, everythingText, latest = false }) {
    const select = h("select", { "aria-label": label },
      latest ? h("option", { value: "latest", text: "Latest videos only (no history)", selected: selected === "latest" }) : null,
      TIME_FRAMES.map(([v, l]) => h("option", { value: String(v), text: v === 0 ? everythingText : l, selected: String(selected) === String(v) })),
      h("option", { value: "custom", text: "Custom…" }));
    const amount = h("input", { type: "number", min: 1, max: 100, step: 1, value: 4, class: "custom-minutes", "aria-label": "How many" });
    const unit = h("select", { "aria-label": "Unit" }, Object.keys(UNIT_DAYS).map((u) => h("option", { value: u, text: u, selected: u === "months" })));
    const custom = h("span", { class: "tf-custom", hidden: true }, amount, unit);
    select.addEventListener("change", () => { custom.hidden = select.value !== "custom"; if (!custom.hidden) amount.focus(); });
    const days = () => {
      if (select.value === "latest") return null;
      if (select.value !== "custom") return Number(select.value);
      const n = Number(amount.value);
      return Number.isInteger(n) && n >= 1 && n <= 100 ? Math.min(36500, n * UNIT_DAYS[unit.value]) : NaN;
    };
    const describe = () => select.value === "custom" ? `last ${amount.value} ${Number(amount.value) === 1 ? unit.value.replace(/s$/, "") : unit.value}`
      : select.selectedOptions[0].text.toLowerCase();
    return { el: h("span", { class: "tf-picker" }, select, custom), select, days, describe };
  }

  const ytKeySet = async () => {
    const st = await api("GET", "/integrations").catch(() => null);
    return Boolean(st && st.youtube.secrets_set.includes("api_key"));
  };

  /** Add one or many YouTube channels / playlists / single videos (one per line), choosing what to add from each
   *  channel (its videos, its playlists, or both) and how far back. */
  /** What a pasted line is: a single video, a video inside a playlist, a playlist, or a channel / @handle. */
  const lineKind = (l) => (isVideoInPlaylist(l) ? "video+playlist" : isVideoLink(l) ? "video" : isPlaylistLink(l) ? "playlist" : "channel");

  /** Add YouTube links (one per line). Each link is recognised; tick what to take from it and how far back. */
  async function openAddChannels(prefill = "") {
    const dlg = $("#sourceDialog");
    const hasKey = await ytKeySet();
    const box = h("textarea", { rows: 6, maxlength: 20000, "aria-label": "YouTube links, one per line",
      placeholder: "Paste links, one per line — videos, playlists, channels or @handles:\nhttps://www.youtube.com/watch?v=…\nhttps://www.youtube.com/playlist?list=…\n@NetworkChuck" });
    const detected = h("ul", { class: "small add-detected", "aria-live": "polite" });
    const tick = (label, hint, disabled = false) => {
      const input = h("input", { type: "checkbox", disabled });
      input.addEventListener("change", () => { input.dataset.touched = "1"; });
      return { input, row: h("label", { class: "add-opt", title: hint }, input, h("span", null, h("strong", { text: label }), h("span", { class: "muted small", text: ` — ${hint}` }))) };
    };
    const opt = {
      video: tick("The video", "just that video, nothing else"),
      playlist: tick("The playlist", "every video in it, plus new ones added to it"),
      follow: tick("Follow the channel", "its new uploads keep arriving"),
      chanVideos: tick("The channel's videos", hasKey ? "its back-catalogue (within the time frame below)" : "needs a free YouTube API key (Settings → Integrations)", !hasKey),
      chanPlaylists: tick("The channel's playlists", hasKey ? "all of its public playlists" : "needs a free YouTube API key (Settings → Integrations)", !hasKey),
    };
    const frame = timeFramePicker({ label: "Retention", selected: hasKey ? 365 : "latest", everythingText: "Everything (whole history)", latest: true });
    // 📁 put the added videos / playlists straight into one of your groups (or a new one)
    const groupList = await api("GET", "/library/groups").then((r) => r.groups.filter((g) => String(g.id).startsWith("g:"))).catch(() => []);
    const groupSel = h("select", { "aria-label": "Put them in a group" }, h("option", { value: "", text: "No group" }),
      groupList.map((g) => h("option", { value: g.id, text: g.name })), h("option", { value: "new", text: "＋ New group…" }));
    const groupName = h("input", { type: "text", maxlength: 100, placeholder: "New group name", "aria-label": "New group name", hidden: true });
    groupSel.addEventListener("change", () => { groupName.hidden = groupSel.value !== "new"; if (!groupName.hidden) groupName.focus(); });
    const err = h("p", { class: "error" });
    const lines = () => [...new Set(box.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean))];
    const refresh = () => {
      const ls = lines();
      const kinds = ls.map(lineKind);
      const has = (k) => kinds.some((x) => x === k || x.split("+").includes(k));
      const icon = { video: "▶ video", "video+playlist": "▶ video in a playlist", playlist: "☰ playlist", channel: "📺 channel" };
      fill(detected, ls.slice(0, 8).map((l, i) => h("li", null, h("span", { class: "tag-kind", text: icon[kinds[i]] }), " ", h("code", { text: l.length > 70 ? `${l.slice(0, 67)}…` : l }))),
        ls.length > 8 ? h("li", { class: "muted", text: `…and ${ls.length - 8} more` }) : null);
      opt.video.row.hidden = !has("video");
      opt.playlist.row.hidden = !has("playlist");
      // sensible defaults until you change a box yourself: a link gets what it points to; a channel link is followed
      const def = { video: has("video"), playlist: kinds.includes("playlist"), follow: has("channel"), chanVideos: has("channel") && hasKey, chanPlaylists: false };
      for (const [k, o] of Object.entries(opt)) if (!o.input.dataset.touched && !o.input.disabled) o.input.checked = def[k];
    };
    box.addEventListener("input", refresh);
    const go = async (e) => {
      e.preventDefault();
      const ls = lines();
      if (!ls.length) { err.textContent = "Paste at least one link or @handle."; return; }
      if (ls.length > 50) { err.textContent = "Up to 50 at a time, please."; return; }
      const days = frame.days();
      if (Number.isNaN(days)) { err.textContent = "Custom time frame: enter a whole number from 1 to 100."; return; }
      const o = Object.fromEntries(Object.entries(opt).map(([k, v]) => [k, v.input.checked && !v.row.hidden && !v.input.disabled]));
      if (!Object.values(o).some(Boolean)) { err.textContent = "Tick at least one thing to add."; return; }
      let group = groupSel.value || null;
      if (group === "new") {
        const name = groupName.value.trim();
        if (!name) { err.textContent = "Type a name for the new group."; return; }
        try { group = (await api("POST", "/library/groups", { name })).id; }
        catch (ex) { err.textContent = ex.message; return; }
      }
      const opts = { ...o, days, hasKey, group, groupLabel: group ? (groupList.find((g) => g.id === group) || { name: groupName.value.trim() }).name : "" };
      if (ls.length === 1 && o.chanPlaylists && lineKind(ls[0]) === "channel") {
        const picked = await pickPlaylists(ls[0], opts);  // choose which playlists of this one channel
        if (picked === null) return;
        opts.playlists = picked;
      }
      addChannelsBatch(ls, opts);
    };
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
      h("div", { class: "sd-head" },
        h("h3", { text: "Add YouTube videos, playlists or channels" }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      box, detected,
      h("div", { class: "add-opts" }, h("div", { class: "muted small", text: "Add:" }), Object.values(opt).map((o) => o.row)),
      h("div", { class: "grid-form" }, h("label", { text: "Retention (how far back)" }), frame.el,
        h("label", { text: "Put in group" }), h("span", { class: "tf-picker" }, groupSel, groupName)),
      h("ul", { class: "small src-notes" },
        h("li", { text: "The retention applies to the channel's videos: older ones are skipped and drop off as they age. Playlists are always added whole. Change it later with 🗓️ Retention in the channels menu." }),
        h("li", { text: "Put in group: single videos are added to the group, and a playlist moves into it whole. A followed channel isn't a group item - its videos stay under the channel." }),
        h("li", { text: "“The video” alone adds only that video: no channel, no other videos." }),
        hasKey ? null : h("li", { text: "Without a YouTube API key only the latest 15 videos of a channel or playlist exist — add a free key in Settings → Integrations." })),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "submit", class: "btn primary", text: "Add" }))));
    if (prefill) box.value = prefill;   // e.g. a channel picked from a video card: the usual choices appear for it
    if (!dlg.open) dlg.showModal();
    refresh();
    box.focus();
  }

  /** For one channel: list its playlists to tick (all ticked). Returns [{playlist_id, title}], [] for none, null = cancelled. */
  async function pickPlaylists(line, opts) {
    const dlg = $("#sourceDialog");
    fill(dlg, h("p", { class: "muted", text: "Looking up the channel's playlists…" }));
    let channelId = null;
    try {
      const res = await api("POST", "/sources/resolve", { input: line, kind: "youtube" });
      if (res.source.playlist_id) return [];  // the link is a playlist itself
      channelId = res.source.channel_id;
    } catch (err) { toast(err.message, true); openAddChannels(); return null; }
    let list = [];
    try { list = (await api("GET", `/library/youtube/playlists?channel_id=${encodeURIComponent(channelId)}`)).playlists; }
    catch (err) { toast(err.message, true); openAddChannels(); return null; }
    if (!list.length) { toast("This channel has no public playlists"); return []; }
    return new Promise((resolve) => {
      const boxes = list.map((p) => ({ p, box: h("input", { type: "checkbox", checked: true, "aria-label": p.title }) }));
      const all = h("input", { type: "checkbox", checked: true, "aria-label": "All playlists" });
      all.addEventListener("change", () => boxes.forEach((b) => { b.box.checked = all.checked; }));
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: (e) => { e.preventDefault(); resolve(boxes.filter((b) => b.box.checked).map((b) => b.p)); } },
        h("div", { class: "sd-head" }, h("h3", { text: `Playlists of this channel (${list.length})` })),
        h("label", { class: "tp-item tp-all" }, all, h("span", { text: "All playlists" })),
        h("div", { class: "tp-list pl-pick" }, boxes.map(({ p, box }) => h("label", { class: "tp-item" }, box,
          h("span", { class: "tp-name", text: p.title }), h("span", { class: "count", text: String(p.videos) })))),
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => { dlg.close(); resolve(null); } }),
          h("button", { type: "submit", class: "btn primary", text: "Add" }))));
    });
  }

  async function addChannelsBatch(lines, opts) {
    const dlg = $("#sourceDialog");
    const rows = lines.map((line) => ({ line, status: h("span", { class: "muted", text: "waiting" }) }));
    const done = h("button", { type: "button", class: "btn primary", text: "Close", disabled: true, onclick: () => dlg.close() });
    const summary = h("p", { class: "small" });
    fill(dlg, h("div", { class: "form source-wizard" },
      h("div", { class: "sd-head" }, h("h3", { text: `Adding ${lines.length} item${lines.length === 1 ? "" : "s"}` })),
      h("ol", { class: "batch-list small" }, rows.map((r) => h("li", null, h("code", { text: r.line }), " — ", r.status))),
      summary,
      h("div", { class: "form-actions" }, done)));
    const added = [];
    const call = async (method, path, body) => {
      try { return await api(method, path, body); } catch (err) {
        if (/too many|rate/i.test(err.message)) {  // lookups are rate-limited: wait and retry once
          await new Promise((r) => setTimeout(r, 30000));
          return api(method, path, body);
        }
        throw err;
      }
    };
    const subscribe = async (source, title) => {
      try {
        const feed = await call("POST", "/feeds", { url: "https://www.youtube.com/", source, title: title || undefined, refresh_minutes: 60 });
        added.push(feed.id);
        return "added";
      } catch (err) {
        if (/already/i.test(err.message)) return "already";
        throw err;
      }
    };
    const fill_ids = [];  // feeds whose older videos are downloaded (playlists, the channel's videos)
    const playlist_ids = [];  // playlists are kept whole - the time frame is for channels only
    const subscribeFill = async (source, title, download) => {
      const n = added.length;
      const r = await subscribe(source, title);
      if (added.length > n) {
        if (download) fill_ids.push(added[added.length - 1]);
        if (source.playlist_id) playlist_ids.push(added[added.length - 1]);
      }
      return r;
    };
    for (const r of rows) {
      const set = (cls, text) => { r.status.className = cls; r.status.textContent = text; };
      set("muted", "looking up…");
      try {
        const kind = lineKind(r.line);
        const parts = [];
        let title = "";
        if (kind.startsWith("video") && opts.video) {  // just this video
          const v = await call("POST", "/library/videos", { url: r.line });
          parts.push(v.already ? "video already there" : "video added"); title = v.title || "";
          if (opts.group && v.article_id) {
            const g = await call("POST", `/library/groups/${encodeURIComponent(opts.group)}/videos`, { article_ids: [v.article_id] }).catch(() => null);
            if (g) parts.push(`in ${opts.groupLabel}`);
          }
        }
        if ((kind === "playlist" || kind === "video+playlist") && opts.playlist) {
          const res = await call("POST", "/sources/resolve", { input: kind === "playlist" ? r.line : `https://www.youtube.com/playlist?list=${new URL(r.line).searchParams.get("list")}`, kind: "youtube" });
          const before = added.length;
          parts.push(`playlist ${await subscribeFill(res.source, res.title, true)}`); title = title || res.title || "";
          if (opts.group && added.length > before) {
            const g = await call("POST", `/library/groups/${encodeURIComponent(opts.group)}/videos`, { from_ref: `p:${added[added.length - 1]}` }).catch(() => null);
            if (g) parts.push(`moved into ${opts.groupLabel}`);
          }
        }
        if (opts.follow || opts.chanVideos || opts.chanPlaylists) {
          let channel;  // the channel itself, or the one the video / playlist belongs to
          if (kind === "channel") {
            const res = await call("POST", "/sources/resolve", { input: r.line, kind: "youtube" });
            channel = { source: res.source, title: res.title };
          } else {
            const own = await call("GET", `/library/youtube/owner?url=${encodeURIComponent(r.line)}`);
            channel = { source: { kind: "youtube", channel_id: own.channel_id }, title: own.title };
          }
          if (opts.follow || opts.chanVideos) parts.push(`channel ${await subscribeFill(channel.source, channel.title, opts.chanVideos)}`);
          if (opts.chanPlaylists && opts.hasKey && channel.source.channel_id) {
            const lists = opts.playlists || (await call("GET", `/library/youtube/playlists?channel_id=${encodeURIComponent(channel.source.channel_id)}`)).playlists;
            let n = 0;
            for (const p of lists) {
              set("muted", `adding playlists ${++n}/${lists.length}…`);
              await subscribeFill({ kind: "youtube", playlist_id: p.playlist_id }, p.title, true);
            }
            parts.push(`${lists.length} playlist${lists.length === 1 ? "" : "s"}`);
          }
          title = title || channel.title || "";
        }
        set("status-ok", `✓ ${title ? `${title} — ` : ""}${parts.join(", ").replace(/already/g, "already there") || "nothing to add"}`);
      } catch (err) { set("status-err", `✗ ${err.message}`); }
    }
    let note = "";
    if (added.length) {
      const channel_ids = added.filter((id) => !playlist_ids.includes(id));
      // playlists: every video, never trimmed by age; channels: the chosen time frame (now and as videos age).
      // load: false - downloading is done below, only for what was ticked (Follow alone = new uploads only).
      if (playlist_ids.length) await api("POST", "/library/keep", { feed_ids: playlist_ids, days: 0, load: false }).catch(() => {});
      if (channel_ids.length && opts.days !== null && opts.days !== 0) {
        await api("POST", "/library/keep", { feed_ids: channel_ids, days: opts.days, load: false }).catch(() => {});
      }
      if (opts.days !== null && opts.hasKey && fill_ids.length) {
        try {
          await api("POST", "/history/backfill-all", { feed_ids: fill_ids, max_pages: 1000, only_missing: false,
            keep_forever: opts.days === 0, since_days: opts.days || null, whole_playlists: true });
          note = " Their older videos are loading in the background.";
        } catch (err) { note = /running/.test(err.message) ? " Another history job is running — use ⇣ Load whole channel later." : ` History: ${err.message}`; }
      } else if (opts.days !== null && !opts.hasKey) {
        note = " Add a YouTube API key (Settings → Integrations) to load older videos.";
      }
    }
    summary.textContent = `${added.length} channel/playlist feed(s) added.${note}`;
    done.disabled = false;
    FW.loadSidebar();
    setTimeout(() => { if (FW.currentMode() === "library") { library.loadMeta().then(() => { library.renderShell(); library.reload(); }); } }, 4000);
  }

  /** Scale a channel or playlist back to a time frame ("keep only the last …"). feeds: [{id, title, type}] */
  /** "1 year", "90 days", "everything" - a retention in days (null = not known). */
  const keepLabel = (d) => FW.fmtRetention(d, true);

  function openKeepDialog(name, feeds, onDone) {
    const dlg = $("#sourceDialog");
    const current = [...new Set(feeds.map((f) => f.retention_days).filter((d) => d !== undefined && d !== null))];
    const now = current.length === 1 ? current[0] : null;   // one value for all of them (else "mixed")
    const known = TIME_FRAMES.some(([v]) => v === now);
    const frame = timeFramePicker({ label: "Keep videos from", selected: known ? now : 90, everythingText: "Everything (no limit)" });
    const nowText = !current.length ? "not set" : current.length > 1 ? `mixed (${current.map(keepLabel).join(", ")})` : FW.fmtRetention(now);
    const own = feeds.filter((f) => f.type === "channel");
    const lists = feeds.filter((f) => f.type === "playlist");
    const withLists = h("input", { type: "checkbox", checked: true });
    const err = h("p", { class: "error" });
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: async (e) => {
      e.preventDefault();
      const ids = [...own, ...(withLists.checked || !own.length ? lists : [])].map((f) => f.id);
      if (!ids.length) { err.textContent = "Nothing to scale back."; return; }
      const days = frame.days();
      if (Number.isNaN(days)) { err.textContent = "Custom time frame: enter a whole number from 1 to 100."; return; }
      if (days && !window.confirm(`Keep the ${frame.describe()} of “${name}”? Older videos are removed (starred ones and videos in your groups stay), and missing videos from inside that time frame are loaded.`)) return;
      const res = await guarded(() => api("POST", "/library/keep", { feed_ids: ids, days }));
      if (!res) return;
      dlg.close();
      const trimmed = res.removed ? `Removed ${res.removed} older video${res.removed === 1 ? "" : "s"}. ` : "";
      const fill = res.loading ? `Loading videos from the ${days ? frame.describe() : "whole history"} in the background — they appear as they arrive.`
        : res.busy ? "Another history job is running — use ⇣ Load whole channel later to fill the time frame."
        : "Add a YouTube API key (Settings → Integrations) to load older videos.";
      toast(`${trimmed}${fill}`);
      if (res.loading) watchHistoryJob(() => onDone());
      onDone();
    } },
      h("div", { class: "sd-head" }, h("h3", { text: `🗓️ Retention — ${name}` }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("div", { class: "grid-form" },
        h("label", { text: "Currently" }), h("strong", { class: "keep-now", text: nowText }),
        h("label", { text: "Keep videos published in" }), frame.el,
        own.length && lists.length ? h("label", { text: `Also ${own.length > 1 ? "their" : "its"} ${lists.length} playlist${lists.length === 1 ? "" : "s"}` }) : null,
        own.length && lists.length ? withLists : null),
      h("ul", { class: "small src-notes" },
        h("li", { text: "Shorter than now: older videos are removed, and new ones drop off as they pass the limit." }),
        h("li", { text: "Longer (or Everything): the older videos inside the time frame are loaded in the background (needs a free YouTube API key)." }),
        h("li", { text: "Starred videos and videos you put in your own groups are always kept; videos you removed with 🗑️ stay removed." })),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "submit", class: "btn primary", text: "Apply" }))));
    if (!dlg.open) dlg.showModal();
  }

  /** Poll the history job until it finishes, then refresh (Keep… loading older videos). */
  function watchHistoryJob(onFinish) {
    let ticks = 0;
    const poll = async () => {
      const st = await api("GET", "/history/status").catch(() => null);
      const b = st && st.backfill;
      if (b && b.state === "running" && ticks++ < 900) {
        setTimeout(poll, 4000);
        return;
      }
      if (b && b.state === "done") toast(`Loaded ${(b.new_total ?? b.new ?? 0).toLocaleString()} older video${(b.new_total ?? b.new) === 1 ? "" : "s"}`);
      onFinish();
    };
    setTimeout(poll, 4000);
  }

  /** With a key saved: load the complete back-catalogue of every channel and playlist already followed. */
  async function offerFullYouTubeHistory() {
    const meta = await api("GET", "/library/meta").catch(() => null);
    const ids = meta ? [...new Set(meta.channels.flatMap((c) => c.feeds.filter((fd) => fd.type !== "saved").map((fd) => fd.id)))] : [];
    if (!ids.length) return;
    if (!window.confirm(`Load every video of the ${ids.length} YouTube channels and playlists you follow? `
      + "Until now only their latest 15 videos could be fetched. This runs in the background (a few minutes) and uses part of the key's free daily quota.")) return;
    try {
      const res = await api("POST", "/history/backfill-all", { feed_ids: ids, max_pages: 1000, keep_forever: true, only_missing: false });
      toast(res.started ? `Loading the full history of ${res.feeds} channels and playlists — videos appear in Videos as they arrive.` : "Nothing to load.");
    } catch (err) {
      toast(/running/.test(err.message) ? "Another history job is running — try again from a channel's “⇣ Load whole channel” once it finishes." : err.message, true);
    }
  }

  /** Load a channel's entire back-catalogue (up to 10,000 videos) and keep it. Needs a YouTube Data API key;
   *  without one only the latest 15 videos exist (YouTube's channel feed), and we say so instead of scraping. */
  async function loadWholeChannel(feedId, automatic) {
    const st = await api("GET", "/integrations").catch(() => null);
    if (!st || !st.youtube.secrets_set.includes("api_key")) {
      toast(automatic ? "Added with its latest 15 videos — YouTube's feed lists no more. Add a free YouTube Data API key (Settings → Integrations) to load all of them."
        : "Loading every video needs a free YouTube Data API key — add one in Settings → Integrations (it then offers to load all your channels and playlists).", !automatic);
      return;
    }
    try {
      await api("POST", `/feeds/${feedId}/backfill`, { max_pages: 1000, keep_forever: true });
      toast("Loading the whole channel in the background — videos appear in the library as they arrive.");
    } catch (err) {
      toast(/running/.test(err.message) ? "Another history job is running — use “⇣ Load whole channel” in Videos once it finishes." : err.message, true);
    }
  }

  /** ☰ Sort a followed channel's videos into its playlists: list the channel's playlists (all ticked, the ones
   *  already followed marked), follow the ticked ones, and read each playlist whole. Videos the library already has
   *  are linked to the playlist in YouTube's order (never copied); only videos missing from the library are added.
   *  Optionally the playlists go into one group named after the channel. Needs a YouTube Data API key. */
  async function sortIntoPlaylists(channel, onDone) {
    const dlg = $("#sourceDialog");
    if (!(await ytKeySet())) {
      toast("Listing a channel's playlists needs a free YouTube Data API key — add one in Settings → Integrations.", true);
      return;
    }
    fill(dlg, h("p", { class: "muted", text: `Looking up the playlists of ${channel.title}…` }));
    if (!dlg.open) dlg.showModal();
    let list;
    try { list = (await api("GET", `/library/youtube/playlists?channel_id=${encodeURIComponent(channel.key)}`)).playlists; }
    catch (err) { dlg.close(); toast(err.message, true); return; }
    if (!list.length) { dlg.close(); toast(`${channel.title} has no public playlists`); return; }
    const followed = new Map(channel.feeds.filter((fd) => fd.playlist_id).map((fd) => [fd.playlist_id, fd]));
    const boxes = list.map((p) => ({ p, box: h("input", { type: "checkbox", checked: true, "aria-label": p.title }) }));
    const all = h("input", { type: "checkbox", checked: true, "aria-label": "All playlists" });
    all.addEventListener("change", () => boxes.forEach((b) => { b.box.checked = all.checked; }));
    const grouped = h("input", { type: "checkbox", checked: true });
    const status = h("p", { class: "small", "aria-live": "polite" });
    const go = h("button", { type: "submit", class: "btn primary", text: "Sort into playlists" });
    const run = async (e) => {
      e.preventDefault();
      const picked = boxes.filter((b) => b.box.checked).map((b) => b.p);
      if (!picked.length) { toast("Tick at least one playlist", true); return; }
      go.disabled = true;
      const feedIds = [];
      const added = [];
      let n = 0;
      for (const p of picked) {
        status.textContent = `Following playlists ${++n}/${picked.length}…`;
        const have = followed.get(p.playlist_id);
        if (have) { feedIds.push(have.id); continue; }
        try {
          const feed = await api("POST", "/feeds", { url: "https://www.youtube.com/", source: { kind: "youtube", playlist_id: p.playlist_id }, title: p.title, refresh_minutes: 60 });
          feedIds.push(feed.id); added.push(feed.id);
        } catch (err) { if (!/already/i.test(err.message)) toast(`${p.title}: ${err.message}`, true); }
      }
      // playlists are kept whole (never trimmed by age)
      if (added.length) await api("POST", "/library/keep", { feed_ids: added, days: 0, load: false }).catch(() => {});
      if (grouped.checked && feedIds.length) {
        status.textContent = `Putting them in the group “${channel.title}”…`;
        try {
          const groups = (await api("GET", "/library/groups")).groups;
          let g = groups.find((x) => String(x.id).startsWith("g:") && x.name.toLowerCase() === channel.title.toLowerCase());
          if (!g) g = await api("POST", "/library/groups", { name: channel.title.slice(0, 100) });
          const loose = new Set(groups.filter((x) => x.type === "playlist").map((x) => x.id));  // not in a group yet
          for (const fid of feedIds) {
            if (added.includes(fid) || loose.has(`p:${fid}`)) {
              await api("POST", `/library/groups/${encodeURIComponent(g.id)}/videos`, { from_ref: `p:${fid}` }).catch(() => {});
            }
          }
        } catch (err) { toast(`Group: ${err.message}`, true); }
      }
      let note = "";
      try {
        await api("POST", "/history/backfill-all", { feed_ids: feedIds, max_pages: 1000, only_missing: false, keep_forever: true,
          since_days: null, whole_playlists: true });
        note = "Each playlist is being read in the background: videos you already have are sorted into it in YouTube's order, missing ones are added.";
      } catch (err) {
        note = /running/.test(err.message) ? "Another history job is running — the playlists fill in at their next refresh (or run this again once it finishes)."
          : `Loading: ${err.message}`;
      }
      status.textContent = `${feedIds.length} playlist${feedIds.length === 1 ? "" : "s"} (${added.length} newly followed). ${note}`;
      go.textContent = "Done"; go.disabled = false; go.type = "button"; go.onclick = () => dlg.close();
      if (onDone) setTimeout(onDone, 3000);
    };
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: run },
      h("div", { class: "sd-head" }, h("h3", { text: `Sort ${channel.title} into its playlists (${list.length})` })),
      h("p", { class: "muted small", text: "Videos you already have are put into their playlists, in the channel's order. Nothing is copied: a video in several playlists is stored once and shown in each. Only videos you don't have yet are added." }),
      h("label", { class: "tp-item tp-all" }, all, h("span", { text: "All playlists" })),
      h("div", { class: "tp-list pl-pick" }, boxes.map(({ p, box }) => h("label", { class: "tp-item" }, box,
        h("span", { class: "tp-name", text: p.title }),
        followed.has(p.playlist_id) ? h("span", { class: "muted small", text: "followed" }) : null,
        h("span", { class: "count", text: String(p.videos) })))),
      h("label", { class: "tp-item" }, grouped, h("span", { text: `Put them in a group named “${channel.title}”` })),
      status,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Close", onclick: () => dlg.close() }), go)));
  }

  // ======================================================================= feed editor: source settings
  /** {el, value()} for the feed editor, or null for non-source feeds. */
  function sourceEditor(f) {
    const src = f.source;
    if (!src) return null;
    const rows = [];
    let value = () => null;
    if (src.kind === "x") {
      const via = h("select", null, [["bridge", "Bridge (RSSHub / Nitter / RSS-Bridge)"], ["api", "Official X API"]].map(([v, l]) => h("option", { value: v, text: l, selected: src.via === v })));
      const replies = h("input", { type: "checkbox", checked: src.include_replies });
      const reposts = h("input", { type: "checkbox", checked: src.include_reposts !== false });
      rows.push(h("label", { text: "Account" }), h("span", { text: `@${src.username}` }), h("label", { text: "Read through" }), via,
        h("label", { text: "Include replies" }), replies, h("label", { text: "Include reposts" }), reposts);
      value = () => ({ kind: "x", username: src.username, via: via.value, include_replies: replies.checked, include_reposts: reposts.checked });
    } else if (src.kind === "hfpapers") {
      const min = h("input", { type: "number", min: 0, max: 10000, value: src.min_upvotes || 0 });
      rows.push(h("label", { text: "Minimum upvotes" }), min, h("div", { class: "hint", text: "Only papers with at least this many upvotes on Hugging Face are added (0 = all)." }));
      value = () => ({ kind: "hfpapers", min_upvotes: Math.max(0, Math.min(10000, Number(min.value) || 0)) });
    } else if (src.kind === "telegram") {
      const via = h("select", { disabled: !src.channel }, [["web", "Public web preview"], ["account", "My Telegram account"]].map(([v, l]) => h("option", { value: v, text: l, selected: src.via === v })));
      rows.push(h("label", { text: "Chat" }), h("span", { text: src.channel ? `@${src.channel}` : `private chat ${src.chat_id}` }), h("label", { text: "Read through" }), via);
      value = () => (src.channel ? { kind: "telegram", channel: src.channel, via: via.value } : { ...src });
    } else if (src.kind === "email") {
      const senders = h("input", { type: "text", maxlength: 1500, value: (src.senders || []).join(", "), spellcheck: "false" });
      const folderIn = h("input", { type: "text", maxlength: 100, value: src.folder || "INBOX", spellcheck: "false" });
      const subject = h("input", { type: "text", maxlength: 100, value: src.subject_contains || "", placeholder: "(any subject)" });
      rows.push(h("label", { text: "Senders" }), senders,
        h("div", { class: "hint", text: "Addresses (alerts@example.com) or whole domains (example.com), separated by commas — up to 20." }),
        h("label", { text: "Mailbox folder" }), folderIn,
        h("label", { text: "Subject contains" }), subject);
      value = () => ({ kind: "email", senders: senders.value.split(/[\s,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean).slice(0, 20),
        folder: folderIn.value.trim() || "INBOX", subject_contains: subject.value.trim() || undefined });
    } else if (src.kind === "youtube") {
      const link = src.channel_id ? `https://www.youtube.com/channel/${src.channel_id}` : `https://www.youtube.com/playlist?list=${src.playlist_id}`;
      rows.push(h("label", { text: src.channel_id ? "Channel" : "Playlist" }), h("a", { href: link, target: "_blank", rel: "noopener noreferrer", text: src.channel_id || src.playlist_id }),
        h("div", { class: "hint", text: "New videos arrive through the channel’s RSS feed (latest 15). With a YouTube API key, “Fetch older articles” loads the back-catalogue (50 videos per page) and adds durations and view counts." }));
      value = () => null;
    }
    return {
      el: h("fieldset", null, h("legend", null, h("span", { class: `src-badge k-${src.kind}`, text: KIND_ICON[src.kind] }), ` ${KIND_LABEL[src.kind]} source`), h("div", { class: "grid-form" }, rows)),
      value,
    };
  }

  const BACKFILL_HINT = {
    youtube: "Loads older uploads through the YouTube Data API (needs an API key in Integrations). Each page is 50 videos.",
    hfpapers: "Each page is one earlier day of Hugging Face Daily Papers.",
    telegram: "Pages back through the channel history (about 20 posts per page on the web preview, 100 with your account).",
    x: "Not available for X: bridges only show recent posts and the official API charges per post read.",
  };

  // ======================================================================= Integrations settings panel
  async function integrationsPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    let st;
    try { st = await api("GET", "/integrations"); } catch (err) { fill(panel, h("p", { class: "error", text: err.message })); return; }
    const rerender = () => integrationsPanel(panel);
    const secretInput = (placeholder, pattern) => h("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder, pattern, maxlength: 600 });
    const setBadge = (on) => h("span", { class: on ? "status-ok" : "muted", text: on ? "✓ set" : "not set" });

    // --- YouTube
    const ytKey = secretInput("YouTube Data API v3 key", "[A-Za-z0-9_\\-]{20,100}");
    const ytSet = st.youtube.secrets_set.includes("api_key");
    const youtube = h("div", { class: "panel-section card" },
      h("h4", null, "▶ YouTube ", setBadge(ytSet)),
      h("p", { class: "muted small", text: "Channels and playlists work without a key (latest 15 videos via RSS). A free YouTube Data API key adds older videos, durations and view counts, and resolves @handles reliably." }),
      h("form", { class: "row-form", onsubmit: async (e) => {
        e.preventDefault();
        if (!(await guarded(() => api("PUT", "/integrations/youtube", { api_key: ytKey.value.trim() }), "YouTube key saved"))) return;
        await offerFullYouTubeHistory();
        rerender();
      } }, ytKey, h("button", { type: "submit", class: "btn primary small", text: ytSet ? "Replace key" : "Save key" }),
        ytSet ? h("button", { type: "button", class: "btn small danger", text: "Remove", onclick: async () => { if (await guarded(() => api("PUT", "/integrations/youtube", { clear: true }), "Removed")) rerender(); } }) : null),
      h("details", { class: "small" }, h("summary", { text: "How to get a key" }),
        h("ol", null, h("li", { text: "Google Cloud Console → create a project → APIs & Services → Library → enable “YouTube Data API v3”." }),
          h("li", { text: "Credentials → Create credentials → API key. Restrict it to the YouTube Data API v3." }),
          h("li", { text: "Paste it here. The free quota (10,000 units/day) covers thousands of videos a day." }))));

    // --- X
    const xc = st.x.config;
    const bridgeType = h("select", null, [["none", "No bridge"], ["rsshub", "RSSHub"], ["nitter", "Nitter"], ["rssbridge", "RSS-Bridge"], ["template", "Custom URL template"]]
      .map(([v, l]) => h("option", { value: v, text: l, selected: (xc.bridge_type || "none") === v })));
    const bridgeUrl = h("input", { type: "url", maxlength: 500, placeholder: "http://rsshub:1200", value: xc.bridge_url || "" });
    const bridgeTpl = h("input", { type: "text", maxlength: 600, placeholder: "https://bridge.lan/x/{username}.xml", value: xc.bridge_template || "" });
    const syncBridge = () => { bridgeUrl.hidden = ["none", "template"].includes(bridgeType.value); bridgeTpl.hidden = bridgeType.value !== "template"; };
    bridgeType.addEventListener("change", syncBridge);
    syncBridge();
    const xToken = secretInput("X API bearer token");
    const xSet = st.x.secrets_set.includes("bearer_token");
    const x = h("div", { class: "panel-section card" },
      h("h4", null, "𝕏 (Twitter)"),
      h("p", { class: "muted small", text: "X has no free read access. Use a self-hosted bridge (RSSHub, Nitter or RSS-Bridge — usually on your LAN) and/or the official X API. Eye of Sauron never scrapes x.com directly." }),
      h("form", { class: "grid-form", onsubmit: async (e) => {
        e.preventDefault();
        const body = { bridge_type: bridgeType.value };
        if (bridgeType.value === "template") body.bridge_template = bridgeTpl.value.trim();
        else if (bridgeType.value !== "none") body.bridge_url = bridgeUrl.value.trim();
        if (await guarded(() => api("PUT", "/integrations/x", body), "Bridge saved")) rerender();
      } },
        h("label", { text: "Bridge" }), h("div", { class: "row-form" }, bridgeType, bridgeUrl, bridgeTpl, h("button", { type: "submit", class: "btn small primary", text: "Save bridge" })),
        h("div", { class: "hint", text: "The bridge address may be a private/LAN address — it is the one exception to the SSRF guard, because only you can set it." })),
      h("form", { class: "grid-form", onsubmit: async (e) => {
        e.preventDefault();
        if (await guarded(() => api("PUT", "/integrations/x", { bearer_token: xToken.value.trim() }), "X API token saved")) rerender();
      } },
        h("label", null, "API token ", setBadge(xSet)), h("div", { class: "row-form" }, xToken, h("button", { type: "submit", class: "btn small primary", text: xSet ? "Replace" : "Save" }),
          xSet ? h("button", { type: "button", class: "btn small danger", text: "Remove", onclick: async () => { if (await guarded(() => api("PUT", "/integrations/x", { clear_bearer: true }), "Removed")) rerender(); } }) : null),
        h("div", { class: "hint", text: "App-only bearer token from the X developer portal. Reads are billed per post, so X API feeds refresh every 6 hours by default — change it per feed." })));

    // --- Telegram
    const tc = st.telegram.config;
    const telegram = h("div", { class: "panel-section card" }, h("h4", { text: "✈ Telegram" }));
    telegram.append(h("p", { class: "muted small", text: "Public channels with a web preview (t.me/s/…) work without logging in. Connect your own account to follow channels without a preview and private groups/channels you belong to." }));
    if (tc.account) {
      const dialogsBox = h("div");
      telegram.append(
        h("p", null, h("span", { class: "status-ok", text: "✓ Connected" }), ` as ${tc.account.name}${tc.account.username ? ` (@${tc.account.username})` : ""}`),
        h("div", { class: "row-form" },
          h("button", { type: "button", class: "btn small primary", text: "Add channels / groups from my account…", onclick: () => showDialogs(dialogsBox) }),
          h("button", { type: "button", class: "btn small danger", text: "Disconnect", onclick: async () => {
            if (window.confirm("Log this session out of Telegram and delete it? Feeds that read through your account will stop updating.") &&
              await guarded(() => api("POST", "/integrations/telegram/logout"), "Disconnected")) rerender();
          } })),
        dialogsBox);
    } else {
      telegram.append(telegramLogin(rerender));
    }
    telegram.append(h("p", { class: "muted small", text: "The session is equivalent to a logged-in device: it is stored encrypted, never shown again, and you can also end it from Telegram → Settings → Devices. Your phone number and login code are not stored." }));

    // --- Email newsletters (IMAP)
    const ic = st.imap.config;
    const imapSet = st.imap.secrets_set.includes("password");
    const imapHost = h("input", { type: "text", maxlength: 253, placeholder: "imap.gmail.com", value: ic.host || "", spellcheck: "false" });
    const imapPort = h("input", { type: "number", min: 1, max: 65535, value: ic.port || 993 });
    const imapUser = h("input", { type: "text", maxlength: 254, placeholder: "you@example.com", value: ic.username || "", autocomplete: "off", spellcheck: "false" });
    const imapPass = secretInput(imapSet ? "(saved — leave empty to keep)" : "App password");
    const mail = h("div", { class: "panel-section card" },
      h("h4", null, "✉ Email newsletters ", setBadge(imapSet)),
      h("p", { class: "muted small", text: "Follow publishers that send updates by email (CISA's email updates, vendor threat-intel mailers, newsletters). Point this at a mailbox — ideally one you use only for newsletters — then add a source with Add feed → Type → Email newsletter. Mail is read over TLS only and read-only: nothing is marked read, moved or deleted." }),
      h("form", { class: "grid-form", onsubmit: async (e) => {
        e.preventDefault();
        const body = { host: imapHost.value.trim(), port: Number(imapPort.value) || 993, username: imapUser.value.trim() };
        if (imapPass.value) body.password = imapPass.value;
        if (await guarded(() => api("PUT", "/integrations/imap", body), "Mailbox connected")) rerender();
      } },
        h("label", { text: "Mail server (IMAPS)" }), h("div", { class: "row-form" }, imapHost, imapPort),
        h("label", { text: "User name" }), imapUser,
        h("label", { text: "Password" }), imapPass,
        h("div", { class: "hint", text: "Gmail, Outlook.com and iCloud need an app password (not your normal one). A mail server on your own network must be listed in EOS_PRIVATE_ALLOWLIST." }),
        h("div", { class: "row-form" }, h("button", { type: "submit", class: "btn small primary", text: imapSet ? "Save & test" : "Connect" }),
          imapSet ? h("button", { type: "button", class: "btn small danger", text: "Remove", onclick: async () => { if (await guarded(() => api("PUT", "/integrations/imap", { clear: true }), "Removed")) rerender(); } }) : null)),
      ic.folders && ic.folders.length ? h("p", { class: "muted small", text: `Folders: ${ic.folders.slice(0, 30).join(", ")}${ic.folders.length > 30 ? "…" : ""}` }) : null);

    // --- Read later
    const rc = st.readlater.config;
    const rs = st.readlater.secrets_set;
    const wbUrl = h("input", { type: "url", maxlength: 300, placeholder: "https://wallabag.example.com", value: rc.wallabag_url || "" });
    const wbClient = h("input", { type: "text", maxlength: 200, placeholder: "Client ID", value: rc.wallabag_client_id || "", spellcheck: "false" });
    const wbSecret = secretInput(rs.includes("wallabag_client_secret") ? "Client secret (saved)" : "Client secret");
    const wbUser = h("input", { type: "text", maxlength: 200, placeholder: rs.includes("wallabag_username") ? "User name (saved)" : "User name", autocomplete: "off" });
    const wbPass = secretInput(rs.includes("wallabag_password") ? "Password (saved)" : "Password");
    const lwUrl = h("input", { type: "url", maxlength: 300, placeholder: "https://linkwarden.example.com", value: rc.linkwarden_url || "" });
    const lwToken = secretInput(rs.includes("linkwarden_token") ? "Access token (saved)" : "Access token");
    const obVault = h("input", { type: "text", maxlength: 100, placeholder: "Vault name", value: rc.obsidian_vault || "" });
    const obFolder = h("input", { type: "text", maxlength: 200, placeholder: "Folder in the vault (optional)", value: rc.obsidian_folder || "" });
    const saveRl = async (body, label) => {
      if (await guarded(() => api("PUT", "/integrations/readlater", body), label)) { if (FW.loadReadLater) FW.loadReadLater(); rerender(); }
    };
    const clearBtn = (which) => h("button", { type: "button", class: "btn small danger", text: "Remove", onclick: () => saveRl({ clear: which }, "Removed") });
    const readlater = h("div", { class: "panel-section card" },
      h("h4", { text: "🔖 Read later" }),
      h("p", { class: "muted small", text: "Adds a 🔖 Save… menu to the reader. Markdown download always works; Wallabag, Linkwarden and Obsidian appear once set up here. Self-hosted addresses on your network are allowed." }),
      h("form", { class: "grid-form", onsubmit: (e) => {
        e.preventDefault();
        const body = { wallabag_url: wbUrl.value.trim(), wallabag_client_id: wbClient.value.trim() };
        if (wbSecret.value) body.wallabag_client_secret = wbSecret.value;
        if (wbUser.value.trim()) body.wallabag_username = wbUser.value.trim();
        if (wbPass.value) body.wallabag_password = wbPass.value;
        saveRl(body, "Wallabag saved");
      } },
        h("label", { text: "Wallabag" }), h("div", { class: "row-form" }, wbUrl, wbClient),
        h("span"), h("div", { class: "row-form" }, wbSecret, wbUser, wbPass),
        h("div", { class: "hint", text: "Wallabag → API clients management → Create a new client: copy its Client ID and Client secret, and use your Wallabag user name and password." }),
        h("span"), h("div", { class: "row-form" }, h("button", { type: "submit", class: "btn small primary", text: "Save Wallabag" }), rc.wallabag_url ? clearBtn("wallabag") : null)),
      h("form", { class: "grid-form", onsubmit: (e) => {
        e.preventDefault();
        const body = { linkwarden_url: lwUrl.value.trim() };
        if (lwToken.value) body.linkwarden_token = lwToken.value.trim();
        saveRl(body, "Linkwarden saved");
      } },
        h("label", { text: "Linkwarden" }), h("div", { class: "row-form" }, lwUrl, lwToken),
        h("div", { class: "hint", text: "Linkwarden → Settings → Access Tokens → New access token." }),
        h("span"), h("div", { class: "row-form" }, h("button", { type: "submit", class: "btn small primary", text: "Save Linkwarden" }), rc.linkwarden_url ? clearBtn("linkwarden") : null)),
      h("form", { class: "grid-form", onsubmit: (e) => { e.preventDefault(); saveRl({ obsidian_vault: obVault.value.trim(), obsidian_folder: obFolder.value.trim() }, "Obsidian saved"); } },
        h("label", { text: "Obsidian" }), h("div", { class: "row-form" }, obVault, obFolder),
        h("div", { class: "hint", text: "Creates a note in the vault through Obsidian's obsidian:// link on this device (Obsidian must be installed here). Nothing is sent to a server." }),
        h("span"), h("div", { class: "row-form" }, h("button", { type: "submit", class: "btn small primary", text: "Save Obsidian" }), rc.obsidian_vault ? clearBtn("obsidian") : null)));

    fill(panel,
      h("p", { class: "muted", text: "Credentials for third-party sources. Secrets are encrypted at rest and never displayed again after saving." }),
      youtube, x, telegram, mail, readlater);
  }

  function telegramLogin(done) {
    const box = h("div");
    const apiId = h("input", { type: "number", min: 1, placeholder: "api_id", required: true });
    const apiHash = h("input", { type: "password", autocomplete: "off", placeholder: "api_hash (32 hex characters)", pattern: "[0-9a-f]{32}", required: true });
    const phone = h("input", { type: "tel", autocomplete: "off", placeholder: "+441234567890", pattern: "\\+[1-9][0-9]{6,14}", required: true });
    const err = h("p", { class: "error" });
    const step2 = (needsPassword) => {
      const input = needsPassword
        ? h("input", { type: "password", autocomplete: "off", placeholder: "Two-step verification password", required: true })
        : h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", placeholder: "Login code from Telegram", pattern: "[0-9]{4,8}", required: true });
      const err2 = h("p", { class: "error" });
      fill(box, h("form", { class: "row-form", onsubmit: async (e) => {
        e.preventDefault();
        err2.textContent = "";
        try {
          const res = needsPassword
            ? await api("POST", "/integrations/telegram/password", { password: input.value })
            : await api("POST", "/integrations/telegram/code", { code: input.value.trim() });
          input.value = "";
          if (res.needs_password) { step2(true); return; }
          toast("Telegram connected");
          done();
        } catch (ex) { err2.textContent = ex.message; }
      } }, input, h("button", { type: "submit", class: "btn small primary", text: "Verify" })), err2,
      h("p", { class: "muted small", text: needsPassword ? "Your account has two-step verification. The password is sent to Telegram once and never stored." : "Telegram sent a code to your Telegram app (or SMS). It expires after a few minutes." }));
      input.focus();
    };
    fill(box,
      h("ol", { class: "small" },
        h("li", null, "Create an app at ", h("a", { href: "https://my.telegram.org/apps", target: "_blank", rel: "noopener noreferrer", text: "my.telegram.org/apps" }), " (any name) and copy its api_id and api_hash."),
        h("li", { text: "Enter them with your phone number, then the code Telegram sends you." })),
      h("form", { class: "grid-form", onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = "";
        try {
          await api("POST", "/integrations/telegram/login", { api_id: Number(apiId.value), api_hash: apiHash.value.trim().toLowerCase(), phone: phone.value.trim() });
          step2(false);
        } catch (ex) { err.textContent = ex.message; }
      } },
        h("label", { text: "api_id" }), apiId, h("label", { text: "api_hash" }), apiHash, h("label", { text: "Phone" }), phone,
        h("span"), h("div", null, h("button", { type: "submit", class: "btn small primary", text: "Send login code" }))),
      err);
    return box;
  }

  async function showDialogs(box) {
    fill(box, h("p", { class: "muted small", text: "Loading your channels and groups…" }));
    let list;
    try { list = await api("GET", "/integrations/telegram/dialogs"); } catch (err) { fill(box, h("p", { class: "error", text: err.message })); return; }
    const filter = h("input", { type: "search", placeholder: "Filter…", maxlength: 100 });
    const body = h("tbody");
    const draw = () => {
      const q = filter.value.trim().toLowerCase();
      fill(body, list.filter((d) => !q || d.title.toLowerCase().includes(q) || (d.username || "").toLowerCase().includes(q)).slice(0, 300).map((d) =>
        h("tr", null, h("td", { text: d.title }), h("td", { class: "muted", text: d.type }), h("td", { class: "muted", text: d.username ? `@${d.username}` : "private" }),
          h("td", null, h("button", { type: "button", class: "btn small", text: "Add", onclick: () => {
            const settings = $("#settingsDialog");
            if (settings && settings.open) settings.close();
            openSourceWizard(d.username || String(d.chat_id), {}, { kind: "telegram", via: "account" });
          } })))));
    };
    filter.addEventListener("input", draw);
    draw();
    fill(box, filter, h("div", { class: "table-wrap tg-dialogs" }, h("table", { class: "data" }, body)));
  }

  /** Dropdown of tick boxes. opts: {items: [{id, name, color?, count?, hint?}], selected: [ids], noun: "topic",
   *  allLabel: "All topics", buttonLabel?: "Topics" (title when nothing is picked), match?: "any"|"all" (shows the any/all switch), search?: true, dataAttr?: "topic",
   *  onChange(selected, match)} */
  function multiPicker(opts) {
    const selected = new Set(opts.selected.map(String));
    let match = opts.match === "all" ? "all" : "any";
    const label = () => {
      if (!selected.size) return opts.buttonLabel || opts.allLabel;  // the closed dropdown's title
      const names = opts.items.filter((t) => selected.has(String(t.id))).map((t) => t.name);
      if (selected.size === 1) return names[0] || `1 ${opts.noun}`;
      return `${selected.size} ${opts.noun}s${opts.match !== undefined ? ` (${match})` : ""}`;
    };
    const summary = h("summary", { class: "btn small", "aria-label": `Filter by ${opts.noun}s`, text: `${label()} ▾` });
    let allBox = null;
    const changed = () => {
      summary.textContent = `${label()} ▾`;
      if (allBox) allBox.checked = selected.size === 0;  // "All" is ticked exactly when no single item is
      syncBulk();
      opts.onChange([...selected], match);
    };
    const modeBtn = (m, text) => h("button", { type: "button", class: `btn small${match === m ? " primary" : ""}`, "aria-pressed": String(match === m), text,
      onclick: (e) => { match = m; for (const b of e.target.parentNode.children) b.classList.toggle("primary", b === e.target); if (selected.size > 1) changed(); } });
    // optional management: a ⚙ menu per item (opts.itemMenu(item) -> [[label, fn, danger?]]), "+" next to "All",
    // and buttons for several ticked items (opts.bulkActions -> [[label, fn(ids), danger?]])
    const closeMenus = () => document.querySelectorAll(".tp-menu").forEach((m) => m.remove());
    const openMenu = (anchor, entries) => {
      closeMenus();
      const menu = h("div", { class: "tp-menu lib-group-menu", role: "menu" },
        entries.map(([text, fn, danger]) => h("button", { type: "button", role: "menuitem", class: danger ? "danger" : "", text,
          onclick: (e) => { e.preventDefault(); e.stopPropagation(); closeMenus(); fn(); } })));
      menu.addEventListener("click", (e) => e.stopPropagation());
      // floating, so the scrolling list can't clip it
      const r = anchor.getBoundingClientRect();
      menu.style.top = `${Math.round(r.bottom + 4)}px`;
      menu.style.left = `${Math.round(Math.max(8, r.right - 190))}px`;
      details.append(menu);
    };
    const rows = opts.items.map((t) => {
      const box = h("input", { type: "checkbox", checked: selected.has(String(t.id)), "aria-label": t.name });
      box.addEventListener("change", () => { if (box.checked) selected.add(String(t.id)); else selected.delete(String(t.id)); changed(); });
      const attrs = { class: "tp-item", title: t.hint || "" };
      if (opts.dataAttr) attrs[`data-${opts.dataAttr}`] = String(t.id);
      const gear = opts.itemMenu ? h("button", { type: "button", class: "tp-gear", title: `Options for ${t.name}`, "aria-label": `Options for ${t.name}`, text: "⚙",
        onclick: (e) => { e.preventDefault(); e.stopPropagation(); openMenu(e.currentTarget, opts.itemMenu(t)); } }) : null;
      const starOn = opts.star && opts.star.isOn(t);
      const star = starOn == null ? null : h("button", { type: "button", class: `tp-star${starOn ? " on" : ""}`, text: starOn ? "★" : "☆",
        title: starOn ? `Remove ${t.name} from favourites` : `Add ${t.name} to favourites`, "aria-label": starOn ? `Remove ${t.name} from favourites` : `Add ${t.name} to favourites`,
        "aria-pressed": String(Boolean(starOn)),
        onclick: async (e) => {
          e.preventDefault(); e.stopPropagation();
          const btn = e.currentTarget, on = !btn.classList.contains("on");
          if (await opts.star.toggle(t, on)) {
            btn.classList.toggle("on", on); btn.textContent = on ? "★" : "☆"; btn.setAttribute("aria-pressed", String(on));
            btn.title = on ? `Remove ${t.name} from favourites` : `Add ${t.name} to favourites`; btn.setAttribute("aria-label", btn.title);
          }
        } });
      const row = h("label", attrs, box, star,
        t.color ? h("span", { class: "dot", style: { background: safeColor(t.color) } }) : null, h("span", { class: "tp-name", text: t.name }),
        t.count != null ? h("span", { class: "count", text: String(t.count) }) : null, gear);
      row.dataset.search = t.name.toLowerCase();
      return row;
    });
    const bulkBar = h("div", { class: "tp-bulk" });
    const syncBulk = () => {
      if (!opts.bulkActions) return;
      const ids = [...selected];
      const actions = opts.bulkActions(ids);
      fill(bulkBar, actions.length ? [h("span", { class: "muted small", text: ids.length ? `${ids.length} ticked:` : "" }),
        actions.map(([text, fn, danger]) => h("button", { type: "button", class: `btn small${danger ? " danger" : ""}`, text,
          onclick: (e) => { e.preventDefault(); fn(ids); } }))] : []);
      bulkBar.hidden = !actions.length;
    };
    const find = opts.search ? h("input", { type: "search", class: "tp-search", placeholder: `Find a ${opts.noun}…`, "aria-label": `Find a ${opts.noun}` }) : null;
    if (find) find.addEventListener("input", () => { const q = find.value.trim().toLowerCase(); for (const r of rows) r.hidden = Boolean(q) && !r.dataset.search.includes(q); });
    // "All …" at the top: ticking it clears the individual choices (= no filter); ticking any item unticks it.
    allBox = h("input", { type: "checkbox", checked: selected.size === 0, "aria-label": opts.allLabel });
    allBox.addEventListener("change", () => {
      if (!allBox.checked && selected.size === 0) { allBox.checked = true; return; }  // nothing ticked already means all
      selected.clear(); rows.forEach((l) => { l.querySelector("input").checked = false; }); changed();
    });
    const allRow = h("label", { class: "tp-item tp-all" }, allBox, h("span", { class: "tp-name", text: opts.allLabel }),
      opts.onAdd ? h("button", { type: "button", class: "tp-add", title: opts.addTitle || `Add a ${opts.noun}`, "aria-label": opts.addTitle || `Add a ${opts.noun}`, text: "＋",
        onclick: (e) => { e.preventDefault(); e.stopPropagation(); details.open = false; opts.onAdd(); } }) : null);
    const details = h("details", { class: "topic-picker" }, summary,
      h("div", { class: "tp-panel" },
        find,
        allRow,
        opts.match !== undefined ? h("div", { class: "tp-mode", role: "group", "aria-label": "Match" }, modeBtn("any", "Any of these"), modeBtn("all", "All of these")) : null,
        h("div", { class: "tp-list" }, rows),
        bulkBar,
        h("div", { class: "tp-foot" },
          opts.editAll ? h("button", { type: "button", class: "btn small", text: opts.editAllLabel || "✎ Edit all",
            onclick: (e) => { e.preventDefault(); details.open = false; opts.editAll(); } }) : null,
          h("button", { type: "button", class: "btn small primary", text: "Done", onclick: () => { details.open = false; } }))));
    syncBulk();
    if (find) details.addEventListener("toggle", () => { if (details.open) find.focus(); });
    const outside = (e) => {
      if (!details.isConnected) { document.removeEventListener("click", outside); return; }  // header was redrawn
      if (details.open && !details.contains(e.target)) details.open = false;
      if (!e.target.closest || !e.target.closest(".tp-menu, .tp-gear")) closeMenus();
    };
    document.addEventListener("click", outside);
    return details;
  }

  /** Multi-topic filter: ticking several shows items from any of them. opts: {topics, selected, onChange, editAll?} */
  function topicPicker(opts) {
    return multiPicker({ items: opts.topics, selected: opts.selected, noun: "topic", allLabel: "All topics", buttonLabel: opts.buttonLabel,
      dataAttr: "topic", search: true, onChange: (ids) => opts.onChange(ids, "any"), itemMenu: opts.itemMenu, onAdd: opts.onAdd, star: opts.star,
      addTitle: opts.addTitle, bulkActions: opts.bulkActions, editAll: opts.editAll, editAllLabel: "✎ Edit all" });
  }

  // ======================================================================= YouTube library
  const fmtDuration = (s) => (s == null ? "" : s >= 3600 ? `${Math.floor(s / 3600)}:${String(Math.floor(s % 3600 / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`);
  const fmtViews = (n) => (n == null ? "" : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M views` : n >= 1e3 ? `${(n / 1e3).toFixed(n >= 1e4 ? 0 : 1)}K views` : `${n} views`);

  const library = {
    filters: (() => {
      const f = Object.assign({ channels: [], topic_ids: [], topic_match: "any", q: "", sort: "added", length: "any", state: "all", view: "topics" },
        FW.store.get("fw-library-filters", {}));
      if (f.topic_id) f.topic_ids = [String(f.topic_id)];  // saved by the single-topic version
      delete f.topic_id;
      if (!Array.isArray(f.topic_ids)) f.topic_ids = [];
      if (!Array.isArray(f.channels)) f.channels = [];
      if (f.v !== 2 && f.v !== 3) { if (f.sort === "newest") f.sort = "added"; f.v = 2; }  // once: just-added playlists show first
      if (f.v === 2) {  // once: "By topic" became Sort → Topic, "Grid" became View → Grid
        if (f.view === "topics") { f.view = "all"; f.sort = "topic"; } else if (f.view === "grid") { f.view = "all"; }
        f.layout = "grid";
        f.v = 3;
      }
      if (f.view === "starred" || f.view === "watched") { f.state = f.view; f.view = "all"; }  // those tabs became drop-down choices
      if (!["all", "topics", "groups"].includes(f.view)) f.view = "all";
      if (!["all", "topics"].includes(f.prev_view)) f.prev_view = "all";  // where switching a view off returns to
      if (!["grid", "list"].includes(f.layout)) f.layout = "grid";
      f.topic_match = "any";  // the any/all switch was removed: several topics = videos from any of them
      if (f.sort === "topic") f.sort = "added";  // Sort: Topic (shelves) was removed 2026-11-15
      f.dates = FW.dateRange.clean(f.dates);       // 📅 custom from / to range (null = any date)
      return f;
    })(),
    items: [], total: 0, meta: null, loading: false,
    /** The 🏷️ By topic tab: one shelf per topic (picking topics in the Topics menu shows them as a plain grid). */
    shelfMode() { return this.filters.view === "topics" && !this.filters.topic_ids.length && !this.mention; },

    /** "List these videos" on an entity / technique page: every video that mentions it (watched ones included),
     *  for the page's period. Stays until its ✕ is pressed; the other filters narrow it further. */
    mention: null,  // { id, name, days }
    async listEntity(entity) {
      this.mention = { id: Number(entity.id), name: String(entity.name || ""), days: Number(entity.days) || 0 };
      Object.assign(this.filters, { channels: [], topic_ids: [], q: "", length: "any", state: "all", sort: "newest", view: "all" });
      this.save();
      if (FW.currentMode() !== "library") FW.setMode("library");
      await this.show();
      this.renderShell();
      await this.reload();
    },
    /** "Open all in Videos" on an article's related videos: the Videos tab on exactly those. */
    async listRelated(article) {
      this.mention = { article: Number(article.id), name: String(article.title || "").slice(0, 90) };
      Object.assign(this.filters, { channels: [], topic_ids: [], q: "", length: "any", state: "all", sort: "newest", view: "all" });
      this.save();
      if (FW.currentMode() !== "library") FW.setMode("library");
      await this.show();
      this.renderShell();
      await this.reload();
    },
    mentionChip() {
      const m = this.mention;
      if (!m) return null;
      const period = m.days ? (m.days === 365 ? "in the last year" : `in the last ${m.days} days`) : "all time";
      if (m.article) return h("span", { class: "chip mention-filter", title: `Only videos that name the same actors, malware or techniques as the article “${m.name}”` },
        `Related to the article: ${m.name}`,
        h("button", { type: "button", "aria-label": "Show all videos again", title: "Show all videos again", text: "×",
          onclick: () => { this.mention = null; this.renderShell(); this.reload(); } }));
      return h("span", { class: "chip mention-filter", title: `Only videos that mention ${m.name} (${period})` }, `Mentions: ${m.name} · ${period}`,
        h("button", { type: "button", "aria-label": "Show all videos again", title: "Show all videos again", text: "×",
          onclick: () => { this.mention = null; this.renderShell(); this.reload(); } }));
    },

    /** One load at a time: a second call while one runs waits for the same one. */
    show() {
      if (!this.showing) this.showing = this._show().finally(() => { this.showing = null; });
      return this.showing;
    },
    async _show() {
      const view = $("#libraryView");
      if (this.meta && view.querySelector("#libGrid")) {  // coming back: refresh in place
        this.refreshStarCount();
        await this.reload();
        return;
      }
      if (!this.meta) fill(view, h("p", { class: "muted lib-pad", text: "Loading library…" }));
      await this.loadMeta();
      this.renderShell();
      await this.reload();
    },
    hide() { /* nothing to tear down */ },

    /** Open Videos on one video (from an entity page): the filters are replaced by its title, the card is outlined. */
    async goTo(v) {
      const find = () => { const g = $("#libGrid"); return g ? g.querySelector(`[data-video="${Number(v.id)}"]`) : null; };
      const states = v.is_read ? ["watched", "all"] : ["all", "watched"];  // watched videos are hidden from "All" by default
      let card = null;
      for (const state of states) {
        this.mention = null;
        Object.assign(this.filters, { channels: [], topic_ids: [], q: String(v.title || "").slice(0, 200), length: "any", state, sort: "added", view: "all" });
        this.save();
        if (FW.currentMode() !== "library") FW.setMode("library");
        await this.show();        // joins the load the tab switch started
        this.renderShell();       // the search box and tabs show the new filters
        await this.reload();
        card = find();
        if (card) break;
      }
      if (!card) { toast("That video isn't in your library any more", true); return; }
      card.classList.add("lib-card-focus");
      card.scrollIntoView({ block: "center", behavior: "smooth" });
      setTimeout(() => card.classList.remove("lib-card-focus"), 3000);
    },

    async loadMeta() {
      this.meta = await api("GET", "/library/meta").catch(() => ({ channels: [], topics: [] }));
      const f = this.filters;
      if (f.feed_id) {  // saved by the one-feed version: pick the channel that feed belongs to
        const c = this.meta.channels.find((x) => x.feeds.some((fd) => String(fd.id) === String(f.feed_id)));
        f.channels = c ? [c.key] : [];
        delete f.feed_id;
        this.save();
      }
      const known = new Set(["fav", ...this.meta.channels.map((c) => c.key), ...(this.meta.channel_groups || []).map((g) => `cg:${g.id}`)]);
      f.channels = f.channels.filter((k) => known.has(k));  // removed channels drop out of the filter
    },

    save() { FW.store.set("fw-library-filters", this.filters); },

    syncChips() {
      const ids = this.filters.topic_ids;
      for (const chip of document.querySelectorAll("#libraryView .topic-chip")) {
        const id = chip.dataset.topic || "";
        const on = id ? ids.includes(id) : !ids.length;
        chip.classList.toggle("active", on);
        chip.setAttribute("aria-pressed", String(on));
      }
    },

    /** "Load whole channel" / "Remove channel" act on one channel, so they appear when exactly one is picked. */
    channelButtons() {
      const f = this.filters;
      const channel = f.channels.length === 1 ? this.meta.channels.find((c) => c.key === f.channels[0]) : null;
      if (!channel) {
        // No channel or several ticked: scale back all of them (or the ticked ones) in one go.
        const picked = f.channels.length ? this.meta.channels.filter((c) => f.channels.includes(c.key)) : this.meta.channels;
        const feeds = picked.flatMap((c) => c.feeds.filter((fd) => fd.type !== "saved"));
        if (!feeds.length) return [];
        const label = f.channels.length ? `${picked.length} ticked channels` : `all ${picked.length} channels`;
        return [h("button", { type: "button", class: "btn small", text: f.channels.length ? "🗓️ Keep… (ticked)" : "🗓️ Keep… (all channels)",
          title: `Keep only videos from a time frame, for ${label} and their playlists`,
          onclick: () => openKeepDialog(label, feeds, async () => { await this.loadMeta(); this.renderShell(); this.reload(); }) })];
      }
      return [
        channel.feed_id ? h("button", { type: "button", class: "btn small", text: "⇣ Load whole channel",
          title: "Fetch every video this channel has published (needs a YouTube Data API key)", onclick: () => loadWholeChannel(channel.feed_id, false) }) : null,        channel.feeds.some((fd) => fd.type !== "saved") ? h("button", { type: "button", class: "btn small", text: "🗓️ Keep…",
          title: "Keep only videos from a time frame (last week, 3 months, a year…)",
          onclick: () => openKeepDialog(channel.title, channel.feeds.filter((fd) => fd.type !== "saved"), async () => { await this.loadMeta(); this.renderShell(); this.reload(); }) }) : null,
        h("button", { type: "button", class: "btn small danger", text: channel.saved ? "🗑️ Remove saved videos" : "🗑️ Remove channel",
          title: "Unsubscribe from this channel (and its playlists) and delete their videos", onclick: () => this.removeChannel(channel) }),
      ].filter(Boolean);
    },

    async removeChannels(chans) {
      const feeds = chans.flatMap((c) => (c.saved ? c.feeds : c.feeds.filter((fd) => fd.type !== "saved")));
      const videos = feeds.reduce((n, fd) => n + (fd.videos || 0), 0);
      if (!window.confirm(`Remove ${chans.length} channels and their ${videos.toLocaleString()} videos?\n\n${chans.map((c) => `• ${c.title}`).join("\n")}\n\nStarred videos are deleted too. It cannot be undone.`)) return;
      for (const fd of feeds) {
        try { await api("DELETE", `/feeds/${fd.id}`); } catch (err) { toast(err.message, true); break; }
      }
      toast(`Removed ${chans.length} channels`);
      this.filters.channels = [];
      this.save();
      FW.loadSidebar();
      await this.loadMeta();
      this.renderShell();
      await this.reload();
    },

    async removeChannel(channel) {
      // The channel's own feed and its playlists; single saved videos live in the shared "Saved YouTube videos"
      // feed (other channels' too), so they are only removed when that is all there is.
      const feeds = channel.saved ? channel.feeds : channel.feeds.filter((fd) => fd.type !== "saved");
      const list = feeds.map((fd) => `• ${fd.title} (${fd.type}, ${fd.videos} video${fd.videos === 1 ? "" : "s"})`).join("\n");
      const keepNote = !channel.saved && channel.feeds.some((fd) => fd.type === "saved") ? "\n\nSingle videos you saved from this channel are kept." : "";
      if (!window.confirm(`Remove “${channel.title}” from the library?\n\nThis unsubscribes from and deletes:\n${list}${keepNote}\n\nStarred videos are deleted too. It cannot be undone.`)) return;
      for (const fd of feeds) {
        try { await api("DELETE", `/feeds/${fd.id}`); } catch (err) { toast(err.message, true); return; }
      }
      toast(`Removed ${channel.title}`);
      this.filters.channels = [];
      this.save();
      FW.loadSidebar();
      await this.loadMeta();
      this.renderShell();
      await this.reload();
    },

    renderShell() {
      this.countsKey = null;  // a new toolbar needs its topic numbers filled in again
      const view = $("#libraryView");
      const f = this.filters;
      const m = this.meta;
      const set = (key) => (e) => {
        f[key] = e.target.value;
        this.save();
        this.reload();
      };
      const search = h("input", { type: "search", placeholder: "Search titles, channels & descriptions…", maxlength: 200, value: f.q, "aria-label": "Search videos" });
      let timer = null;
      search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value.trim(); this.save(); this.reload(); }, 300); });
      const select = (key, label, options) => h("select", { "aria-label": label, onchange: set(key) }, options.map(([v, l]) => h("option", { value: v, text: l, selected: String(f[key]) === String(v) })));
      // By topic / Playlists & groups switch on and off: clicking the one that is on goes back to the view you were in
      const viewBtn = (v, label, title) => h("button", { type: "button", class: `btn small${f.view === v ? " primary" : ""}`, "aria-pressed": String(f.view === v),
        title: f.view === v ? "Click again to go back" : title, text: label, "data-view": v, "data-hint": title,
        onclick: () => {
          if (f.view === v) { this.setView(f.prev_view && f.prev_view !== v ? f.prev_view : "all"); return; }  // off: back to the view you came from
          f.prev_view = f.view;
          if (v === "topics" && f.topic_ids.length) {  // By topic shows every topic: the Topics ▾ choice is cleared, so its label changes
            f.topic_ids = []; f.view = v; this.openGroup = null; this.save(); this.renderShell(); this.reload({ fromCache: true }); return;
          }
          this.setView(v);
        } });
      // 🏷️ Tags: only this button and the cards change
      let tagsEl = null;
      const tagsBtn = () => (tagsEl = FW.tagsToggle("videos", () => { tagsEl.replaceWith(tagsBtn()); this.redrawTags(); }));
      // Sort and View (Grid / List); choosing one leaves Playlists & groups
      const sortSel = h("select", { "aria-label": "Sort", title: "Sort" },
        [["added", "📅 Sort: Date added — newest"], ["added_oldest", "📅 Sort: Date added — oldest"],
          ["newest", "📅 Sort: Published — newest"], ["oldest", "📅 Sort: Published — oldest"],
          ["views", "Sort: Most viewed"], ["longest", "Sort: Longest"], ["shortest", "Sort: Shortest"]]
          .map(([v, l]) => h("option", { value: v, text: l, selected: f.sort === v })),
        // a date filter, not a sort: picking it opens the from / to picker and the sort stays as it was
        h("hr"),
        h("option", { value: "custom-range", text: f.dates ? `📅 Custom range: ${FW.dateRange.label(f.dates)}…` : "📅 Custom range…" }),
        f.dates ? h("option", { value: "clear-range", text: "✕ Clear custom range" }) : null);
      sortSel.addEventListener("change", async () => {
        const pick = sortSel.value;
        if (pick === "custom-range" || pick === "clear-range") {
          sortSel.value = f.sort;
          const r = pick === "clear-range" ? null : await FW.dateRange.pick(f.dates);
          if (r === undefined) return;  // cancelled
          f.dates = r;
        } else {
          f.sort = pick;
        }
        if (f.view === "groups") f.view = "all";
        this.openGroup = null; this.save(); this.renderShell(); this.reload();
      });
      if (f.dates) { sortSel.classList.add("on"); sortSel.title = `Sort - showing only videos published ${FW.dateRange.label(f.dates)}`; }
      const layoutSel = h("select", { "aria-label": "View", title: "How videos are laid out" },
        [["grid", "▦ View: Grid"], ["list", "☰ View: List"]].map(([v, l]) => h("option", { value: v, text: l, selected: f.layout === v })));
      layoutSel.addEventListener("change", () => { f.layout = layoutSel.value; if (f.view === "groups") f.view = "all"; this.openGroup = null; this.save(); this.renderShell(); this.reload(); });
      const refreshAll = async () => { await this.loadMeta(); this.renderShell(); this.reload(); };
      const chanOf = (key) => m.channels.find((c) => c.key === key);
      const feedsOf = (chans) => chans.flatMap((c) => c.feeds.filter((fd) => fd.type !== "saved"));
      fill(view,
        h("div", { class: "studio-header lib-header" },
          h("h2", { text: "📺 Videos" }),
          h("button", { type: "button", class: "btn small primary lib-add-plus", text: "＋", title: "Add channels, playlists or videos", "aria-label": "Add channels, playlists or videos", onclick: () => openAddChannels() }),
          search,
          multiPicker({ items: [
              { id: "fav", name: `★ Favourite channels (${m.channels.filter((c) => c.favorite).length})`,
                count: m.channels.reduce((n, c) => n + (c.favorite ? c.videos : 0), 0),
                hint: "Only videos from the channels you starred (☆ beside a channel, or on a video's channel name)" },
              ...(m.channel_groups || []).map((g) => ({ id: `cg:${g.id}`, name: `🗂️ ${g.name}`,
                count: g.channels.reduce((n, k) => n + ((chanOf(k) || {}).videos || 0), 0),
                hint: `Channel group: ${g.channels.map((k) => (chanOf(k) || { title: k }).title).join(", ") || "no channels yet"}` })),
              ...m.channels.map((c) => ({ id: c.key, name: c.title, count: c.videos,
                hint: c.feeds.map((fd) => `${fd.title} (${fd.type})`).join(", ") }))],
            selected: f.channels, noun: "channel", allLabel: `All channels (${m.channels.length})`, buttonLabel: "Channels", search: true,
            onAdd: () => openAddChannels(), addTitle: "Add channels or a video",
            star: { isOn: (item) => { const c = chanOf(item.id); return c ? c.favorite : null; },
              toggle: (item, on) => this.setFavorite([item.id], on) },
            itemMenu: (item) => {
              if (item.id === "fav") {
                const favs = m.channels.filter((c) => c.favorite);
                return favs.length ? [["☆ Clear all favourites", () => this.setFavorite(favs.map((c) => c.key), false, true), true]] : [];
              }
              if (item.id.startsWith("cg:")) {
                const g = (m.channel_groups || []).find((x) => `cg:${x.id}` === item.id);
                return [["☑ Channels…", () => this.editChannelGroup(g, refreshAll)], ["✎ Rename…", () => this.renameChannelGroup(g, refreshAll)],
                  g.channels.length ? ["★ Favourite its channels", () => this.setFavorite(g.channels, true, true)] : null,
                  g.channels.length ? ["☆ Unfavourite its channels", () => this.setFavorite(g.channels, false, true)] : null,
                  ["🗑️ Delete group", () => this.deleteChannelGroup(g, refreshAll), true]].filter(Boolean);
              }
              const c = chanOf(item.id);
              const own = feedsOf([c]);
              return [
                [c.favorite ? "☆ Remove from favourites" : "★ Add to favourites", () => this.setFavorite([c.key], !c.favorite, true)],
                ["🗂️ Add to group…", () => this.groupChannels([c], refreshAll)],
                own.length ? [`🗓️ Retention… (${keepLabel(c.retention_days)})`, () => openKeepDialog(c.title, own, refreshAll)] : null,
                c.feed_id ? ["⇣ Load whole channel", () => loadWholeChannel(c.feed_id, false)] : null,
                /^UC/.test(c.key) ? ["☰ Sort into its playlists…", () => sortIntoPlaylists(c, refreshAll)] : null,
                [c.saved ? "🗑️ Remove saved videos" : "🗑️ Remove channel", () => this.removeChannel(c), true],
              ].filter(Boolean);
            },
            bulkActions: (keys) => {
              const chans = keys.map(chanOf).filter(Boolean);
              const favBtns = chans.length ? [
                chans.some((c) => !c.favorite) ? [`★ Favourite${chans.length > 1 ? " these" : ""}`, () => this.setFavorite(chans.map((c) => c.key), true, true)] : null,
                chans.some((c) => c.favorite) ? [`☆ Unfavourite${chans.length > 1 ? " these" : ""}`, () => this.setFavorite(chans.map((c) => c.key), false, true)] : null,
              ].filter(Boolean) : [];
              if (chans.length === 1) return favBtns;
              if (chans.length >= 2) {
                return [...favBtns, ["🗂️ Group these…", () => this.groupChannels(chans, refreshAll)],
                  ["🗓️ Retention…", () => openKeepDialog(`${chans.length} channels`, feedsOf(chans), refreshAll)],
                  ["🗑️ Remove", () => this.removeChannels(chans), true]];
              }
              return chans.length ? [] : [["🗓️ Retention for all channels…", () => openKeepDialog(`all ${m.channels.length} channels`, feedsOf(m.channels), refreshAll)]];
            },
            // no full redraw here: that would close the dropdown while you tick several channels
            onChange: (keys) => { f.channels = keys; this.save(); this.reload(); } }),
          topicPicker({ topics: [
              { id: "fav", name: `★ Favourite topics (${m.topics.filter((t) => t.favorite).length})`,
                hint: "Videos from any of the topics you starred (☆ beside a topic)" },
              ...m.topics.map((t) => ({ ...t, count: t.videos, name: t.enabled ? t.name : `${t.name} (off)` }))], selected: f.topic_ids, match: f.topic_match, buttonLabel: "Topics",
            onAdd: () => openTopicEditor(null, refreshAll), addTitle: "Add a topic", editAll: () => openTopics(),
            star: { isOn: (item) => { const t = m.topics.find((x) => String(x.id) === String(item.id)); return t ? t.favorite : null; },
              toggle: (item, on) => this.setFavoriteTopics([Number(item.id)], on) },
            itemMenu: (t) => {
              if (t.id === "fav") {
                const favs = m.topics.filter((x) => x.favorite);
                return favs.length ? [["☆ Clear all favourite topics", () => this.setFavoriteTopics(favs.map((x) => x.id), false, true), true]] : [];
              }
              const topic = m.topics.find((x) => x.id === t.id);
              return [[topic.favorite ? "☆ Remove from favourites" : "★ Add to favourites", () => this.setFavoriteTopics([topic.id], !topic.favorite, true)],
                ["✎ Edit", () => openTopicEditor(topic, refreshAll)],
                ["🗑️ Delete", () => deleteTopics([topic], refreshAll), true]];
            },
            bulkActions: (ids) => {
              const picked = m.topics.filter((x) => ids.includes(String(x.id)));
              const fav = picked.length ? [
                picked.some((x) => !x.favorite) ? [`★ Favourite${picked.length > 1 ? " these" : ""}`, () => this.setFavoriteTopics(picked.map((x) => x.id), true, true)] : null,
                picked.some((x) => x.favorite) ? [`☆ Unfavourite${picked.length > 1 ? " these" : ""}`, () => this.setFavoriteTopics(picked.map((x) => x.id), false, true)] : null,
              ].filter(Boolean) : [];
              return picked.length >= 2 ? [...fav, ["🗑️ Delete these topics", () => deleteTopics(picked, refreshAll), true]] : fav;
            },
            onChange: (ids, match) => { f.topic_ids = ids; f.topic_match = match; this.save(); this.syncChips(); this.reload(); } }),
          select("length", "Length", [["any", "Length"], ["short", "Shorts (≤3 min)"], ["medium", "3–20 min"], ["long", "Over 20 min"]]),
          (() => {
            const s = h("select", { "aria-label": "Status", class: "lib-state", title: "Status: all, unwatched, watched or starred videos" },
              [["all", "Status"], ["unwatched", "Unwatched"], ["watched", "✓ Watched"], ["starred", "★ Starred"]]
                .map(([v, l]) => h("option", { value: v, text: l, selected: f.state === v })));
            s.addEventListener("change", () => {
              f.state = s.value;
              if (f.view === "groups") { f.view = "all"; this.openGroup = null; this.save(); this.renderShell(); this.reload(); return; }
              this.save(); this.reload();
            });
            return s;
          })(),
          sortSel, layoutSel,
          h("span", { class: "lib-view", role: "group", "aria-label": "Show" },
            viewBtn("topics", "🏷️ By topic", "Your videos sorted into a shelf per topic (the channel, length and watched filters apply)"),
            viewBtn("groups", "🗂️ Playlists & groups", "Playlists and your own groups, as cards")),
          tagsBtn(),
          h("span", { class: "spacer" })),
        // topics are picked in Topics ▾ (the row of topic buttons is gone)
        m.reclassifying ? h("div", { class: "muted small lib-pad", text: "⏳ Tagging videos with your topics…" }) : null,
        h("div", { id: "libCount", class: "muted small lib-pad" }),
        h("div", { id: "libGrid", class: `lib-grid${f.layout === "list" ? " layout-list" : ""}` }),
        h("div", { class: "lib-more" }, h("button", { id: "libMore", type: "button", class: "btn", text: "Load more", hidden: true, onclick: () => this.loadMore() })));
      this.refreshStarCount();
      if (!m.channels.length) {
        $("#libGrid").replaceWith(h("div", { class: "card lib-empty" },
          h("h3", { text: "No YouTube channels yet" }),
          h("p", { class: "muted", text: "Add channels (several at once, one per line) or a single video with the ＋ button (or paste a YouTube link into ＋ in the top bar). A channel brings in all of its videos (with a YouTube API key); a video link adds just that video. Videos are sorted into topics automatically — manage them from the ⚙ next to each topic in the topics menu." })));
      }
    },

    async refreshStarCount() {
      for (const [state, label] of [["starred", "★ Starred"], ["watched", "✓ Watched"]]) {
        const res = await api("GET", `/library/videos?state=${state}&limit=1`).catch(() => null);
        const opt = document.querySelector(`#libraryView select.lib-state option[value="${state}"]`);
        if (opt && res) opt.textContent = `${label} (${res.total.toLocaleString()})`;
      }
    },

    /** The Watched drop-down's choice; "All" hides watched videos unless Settings says otherwise. */
    stateNow() {
      const f = this.filters;
      if (f.state !== "all") return f.state;
      // watched videos wait under Watched ▾ → ✓ Watched (Settings: Hide watched videos); a search still finds them
      return FW.state.settings.hide_watched !== false && !f.q && !this.mention ? "unwatched" : "all";
    },
    hidesWatched() { return this.stateNow() === "unwatched" && this.filters.state === "all"; },
    /** The picked channels, with any picked channel group ("cg:3") opened up into its channels. */
    channelKeys() {
      const groups = (this.meta && this.meta.channel_groups) || [];
      const favs = ((this.meta && this.meta.channels) || []).filter((c) => c.favorite).map((c) => c.key);
      const keys = this.filters.channels.flatMap((k) => (k === "fav" ? (favs.length ? favs : ["feed:0"])   // no favourites yet: nothing matches
        : k.startsWith("cg:") ? (groups.find((g) => `cg:${g.id}` === k) || { channels: [] }).channels : [k]));
      return [...new Set(keys)].slice(0, 200);
    },

    /** The picked topics, with "★ Favourite topics" opened up into the starred ones (none starred: matches nothing). */
    topicIds() {
      const favs = ((this.meta && this.meta.topics) || []).filter((t) => t.favorite).map((t) => String(t.id));
      const ids = this.filters.topic_ids.flatMap((k) => (k === "fav" ? (favs.length ? favs : ["0"]) : [k]));
      return [...new Set(ids)].slice(0, 20);
    },

    /** ★ / ☆ topics; redraw rebuilds the header (menus), otherwise the open dropdown is updated in place. */
    async setFavoriteTopics(ids, on, redraw = false) {
      const res = await guarded(() => api("POST", "/library/favorite-topics", { topic_ids: ids.slice(0, 200), favorite: on }));
      if (!res) return false;
      const favs = new Set(res.favorites);
      for (const t of this.meta.topics) t.favorite = favs.has(t.id);
      const n = this.meta.topics.filter((t) => t.favorite).length;
      document.querySelectorAll("#libraryView .tp-item[data-topic='fav'] .tp-name").forEach((el) => { el.textContent = `★ Favourite topics (${n})`; });
      toast(on ? `★ ${ids.length === 1 ? "Topic added to" : `${ids.length} topics added to`} favourites`
        : `☆ ${ids.length === 1 ? "Topic removed from" : `${ids.length} topics removed from`} favourites`);
      if (redraw) this.renderShell();
      if (redraw || this.filters.topic_ids.includes("fav")) this.reload();
      return true;
    },

    query(offset) {
      const f = this.filters;
      const p = new URLSearchParams({ sort: f.sort, length: f.length, state: this.stateNow(), limit: "60", offset: String(offset) });
      if (f.channels.length) p.set("channels", this.channelKeys().join(","));
      if (f.topic_ids.length) { p.set("topic_ids", this.topicIds().join(",")); p.set("topic_match", f.topic_ids.includes("fav") ? "any" : f.topic_match); }
      if (f.q) p.set("q", f.q);
      FW.dateRange.addParams(p, f.dates);
      if (this.mention && this.mention.article) p.set("related_to", String(this.mention.article));
      else if (this.mention) { p.set("entity_id", String(this.mention.id)); p.set("days", String(this.mention.days || 0)); }
      return `/library/videos?${p}`;
    },

    /** Numbers next to topic names follow the channel / length / watched / search filters. */
    async refreshCounts(onlyIfChanged = false) {
      const f = this.filters;
      const p = new URLSearchParams({ length: f.length, state: this.stateNow() });
      if (f.channels.length) p.set("channels", this.channelKeys().join(","));
      if (f.q) p.set("q", f.q);
      FW.dateRange.addParams(p, f.dates);
      if (this.mention && this.mention.article) p.set("related_to", String(this.mention.article));
      else if (this.mention) { p.set("entity_id", String(this.mention.id)); p.set("days", String(this.mention.days || 0)); }
      if (onlyIfChanged && this.countsKey === String(p)) return;  // a view switch: same filters, same numbers
      this.countsKey = String(p);
      const res = await api("GET", `/library/topic-counts?${p}`).catch(() => null);
      if (!res) return;
      for (const el of document.querySelectorAll("#libraryView .topic-chip[data-topic], #libraryView .tp-item[data-topic]")) {
        const id = el.dataset.topic;
        if (!id || id === "fav") continue;
        const n = res.counts[id] || 0;
        const span = el.querySelector(".count");
        if (span) span.textContent = String(n);
        el.classList.toggle("empty", n === 0);
      }
    },

    // ------------------------------------------------------------------ smooth switching
    // Each view's answer is kept in memory (by its URL), so switching By topic / Playlists & groups / back, or turning
    // 🏷️ Tags on and off, draws at once from memory; the server is asked again in the background and the page only
    // redraws if something changed. The other views are fetched ahead of time once the current one is on screen.
    cache: new Map(),   // url -> {data, text}

    shelvesUrl() {
      const p = new URLSearchParams(this.query(0).split("?")[1]);
      ["limit", "offset", "topic_ids", "topic_match"].forEach((k) => p.delete(k));
      p.set("per", "12");
      return `/library/shelves?${p}`;
    },
    remember(url, data) {
      const text = JSON.stringify(data);
      const hit = this.cache.get(url);
      this.cache.delete(url);
      this.cache.set(url, { data, text });
      while (this.cache.size > 24) this.cache.delete(this.cache.keys().next().value);  // oldest first
      return !hit || hit.text !== text;  // true = new or changed
    },
    /** Draw from memory when allowed, then from the server (only if it differs from what is drawn). */
    async swr(url, { fromCache, revalidate = true, isCurrent, draw }) {
      const grid = $("#libGrid");
      const hit = fromCache ? this.cache.get(url) : null;
      if (hit) draw(hit.data, false);
      if (hit && !revalidate) return;
      if (!hit && grid && grid.children.length) grid.classList.add("is-loading");  // keep the old view, dimmed, until the new one is in
      const res = await guarded(() => api("GET", url));
      if (grid) grid.classList.remove("is-loading");
      if (!res) return;
      const changed = this.remember(url, res);
      if (!isCurrent()) return;                      // you switched again meanwhile: keep it for later, don't draw
      if (!hit || changed) draw(res, Boolean(hit));
    },
    /** Fetch the views you aren't on yet, quietly, so the first switch to them is instant too. */
    prefetch() {
      clearTimeout(this.prefetchTimer);
      this.prefetchTimer = setTimeout(() => {
        if (!$("#libGrid") || this.mention) return;
        const urls = [this.query(0), "/library/groups"];
        if (!this.filters.topic_ids.length) urls.push(this.shelvesUrl());
        for (const url of urls) {
          if (!this.cache.has(url)) api("GET", url).then((res) => this.remember(url, res)).catch(() => {});
        }
      }, 800);
    },
    /** By topic / Playlists & groups on or off: no toolbar rebuild, the content swaps in place. */
    setView(v) {
      this.filters.view = v;
      this.openGroup = null;
      this.save();
      for (const b of document.querySelectorAll("#libraryView .lib-view button[data-view]")) {
        const on = b.dataset.view === v;
        b.classList.toggle("primary", on);
        b.setAttribute("aria-pressed", String(on));
        b.title = on ? "Click again to go back" : b.dataset.hint;
      }
      this.reload({ fromCache: true });
    },
    /** 🏷️ Tags on / off: redraw what is on screen from memory, no server call. */
    redrawTags() {
      const y = window.scrollY;
      if (this.filters.view === "groups") this.reload({ fromCache: true });
      else if (this.shelfMode() && this.lastShelves) this.renderShelves(this.lastShelves);
      else this.renderGrid();
      window.scrollTo(0, y);
    },

    async reload({ fromCache = false } = {}) {
      if (!$("#libGrid")) return;
      if (this.filters.view === "groups") { await this.renderGroups(fromCache); this.prefetch(); return; }
      this.refreshCounts(fromCache);
      const grid0 = $("#libGrid");
      if (grid0 && !grid0.children.length) fill(grid0, Array.from({ length: 8 }, () => h("div", { class: "skeleton-card", "aria-hidden": "true" })));  // first load: placeholders, not a blank page
      if (this.shelfMode()) {
        const url = this.shelvesUrl();
        await this.swr(url, { fromCache, isCurrent: () => this.shelfMode() && this.filters.view === "topics" && this.shelvesUrl() === url,
          draw: (res) => this.renderShelves(res) });
        this.prefetch();
        return;
      }
      const q = this.query(0);
      await this.swr(q, { fromCache, isCurrent: () => this.filters.view !== "groups" && !this.shelfMode() && this.query(0) === q,
        draw: (res, again) => {
          if (again && this.items.length > res.items.length) return;  // you loaded more meanwhile: keep those
          this.items = res.items;
          this.total = res.total;
          this.renderGrid();
        } });
      this.prefetch();
    },

    async loadMore() {
      const res = await guarded(() => api("GET", this.query(this.items.length)));
      if (!res) return;
      this.items = this.items.concat(res.items);
      this.renderGrid();
    },

    /** One shelf per topic (most videos first), then "Other" for videos no topic matched. */
    renderShelves(res) {
      const grid = $("#libGrid");
      if (!grid) return;
      this.lastShelves = res;  // 🏷️ Tags redraws from this
      grid.className = `lib-grid${this.filters.layout === "list" ? " layout-list" : ""}`;  // coming back from Playlists & groups
      const topicsById = Object.fromEntries((this.meta.topics || []).map((t) => [t.id, t]));
      const showImages = FW.state.settings.load_images !== false;
      const shelves = res.shelves.concat(res.other.total ? [{ id: null, name: "Other (no topic matched)", color: "#8a8f98", total: res.other.total, items: res.other.items }] : []);
      const distinct = new Set(shelves.flatMap((s) => s.items.map((v) => v.id))).size;
      $("#libCount").textContent = shelves.length
        ? `${shelves.length} categor${shelves.length === 1 ? "y" : "ies"} · a video with several topics appears on each of their shelves`
        : "";
      if (!shelves.length) { fill(grid, this.noMatches()); $("#libMore").hidden = true; return; }
      $("#libMore").hidden = true;
      grid.classList.add("shelves");
      fill(grid, shelves.map((s) => h("section", { class: "lib-shelf" },
        h("header", { class: "lib-shelf-head" },
          h("span", { class: "dot", style: { background: safeColor(s.color) } }),
          h("h3", { text: s.name }), h("span", { class: "muted small", text: `${s.total.toLocaleString()} video${s.total === 1 ? "" : "s"}` }),
          h("span", { class: "spacer" }),
          s.id !== null && s.total > s.items.length ? h("button", { type: "button", class: "link-btn small", text: `Show all ${s.total.toLocaleString()} →`,
            onclick: () => { this.filters.topic_ids = [String(s.id)]; this.save(); this.renderShell(); this.reload(); } }) : null),
        h("div", { class: "lib-shelf-row" }, s.items.map((v) => this.card(v, topicsById, showImages))))));
      if (!distinct && !this.meta.channels.length) grid.classList.remove("shelves");
    },

    /** Filters besides the search box that narrow the results (shown when a search finds nothing). */
    activeFilters() {
      const f = this.filters;
      return [f.channels.length ? `${f.channels.length} channel${f.channels.length === 1 ? "" : "s"}` : null,
        f.topic_ids.length ? `${f.topic_ids.length} topic${f.topic_ids.length === 1 ? "" : "s"}` : null,
        f.length !== "any" ? "length" : null, f.dates ? `dates: ${FW.dateRange.label(f.dates)}` : null, this.stateNow() !== "all" ? (this.stateNow() === "starred" ? "starred only" : this.stateNow()) : null].filter(Boolean);
    },

    noMatches() {
      const active = this.activeFilters();
      if (this.filters.state === "watched" && !this.filters.q) return h("p", { class: "muted lib-pad", text: "No watched videos yet. Press ✓ on a video (or play it) and it shows here." });
      if (!active.length) return h("p", { class: "muted lib-pad", text: this.filters.q ? `No videos mention “${this.filters.q}” in their title, channel or description.` : "No videos." });
      return h("p", { class: "muted lib-pad" }, `Nothing matches with these filters on (${active.join(", ")}). `,
        h("button", { type: "button", class: "btn small", text: "Clear filters and search all videos", onclick: () => {
          const f = this.filters;
          f.channels = []; f.topic_ids = []; f.length = "any"; f.state = "all"; f.dates = null;
          this.save(); this.renderShell(); this.reload();
        } }));
    },

    renderGrid() {
      const grid = $("#libGrid");
      if (!grid) return;
      grid.className = `lib-grid${this.filters.layout === "list" ? " layout-list" : ""}`;  // no shelves / group-card styles left over
      const topicsById = Object.fromEntries((this.meta.topics || []).map((t) => [t.id, t]));
      const showImages = FW.state.settings.load_images !== false;
      fill($("#libCount"), `${this.total.toLocaleString()} video${this.total === 1 ? "" : "s"}${this.filters.q ? ` matching “${this.filters.q}”` : ""} `, this.mentionChip());
      fill(grid, this.items.length ? this.items.map((v) => this.card(v, topicsById, showImages)) : this.noMatches());
      $("#libMore").hidden = this.items.length >= this.total;
    },

    // ------------------------------------------------------------------ playlists & groups
    openGroup: null,  // "p:<feed id>" or "g:<id>" while one group is open

    async renderGroups(fromCache = false) {
      $("#libMore").hidden = true;
      if (this.openGroup) { await this.renderGroup(this.openGroup); return; }
      await this.swr("/library/groups", { fromCache, isCurrent: () => !this.openGroup && this.filters.view === "groups",  // you opened something else meanwhile
        draw: (res) => this.drawGroups(res) });
    },

    drawGroups(res) {
      const grid = $("#libGrid");
      if (!grid) return;
      const showImages = FW.state.settings.load_images !== false;
      $("#libCount").textContent = `${res.groups.length} playlist${res.groups.length === 1 ? "" : "s"} & groups · drag a playlist onto a group to move it there · the channel and topic filters don't apply here`;
      const newBtn = h("button", { type: "button", class: "lib-group-card lib-group-new", onclick: () => this.newGroup() },
        h("span", { class: "lib-group-plus", text: "+" }), h("strong", { text: "New group" }),
        h("span", { class: "muted small", text: "Collect videos and playlists into your own series, or drop a playlist here" }));
      this.dropTarget(newBtn, null);
      grid.className = "lib-grid lib-groups";
      const sel = this.groupSel || (this.groupSel = new Map());   // ref -> name, while "Select" is on
      for (const ref of [...sel.keys()]) if (!res.groups.some((g) => g.id === ref)) sel.delete(ref);
      const countEl = h("span", { class: "muted small" });
      const addSel = h("span", { class: "lib-add-wrap" }, h("button", { type: "button", class: "btn small primary", text: "＋ Add to group…",
        onclick: (e) => { if (sel.size) this.addAllToGroupMenu([...sel].map(([id, name]) => ({ id, name })), e.currentTarget); } }));
      const syncBar = () => {
        countEl.textContent = sel.size ? `${sel.size} selected` : "Tick playlists (or groups) to add them to a group";
        addSel.firstChild.disabled = !sel.size;
      };
      const selectBtn = h("button", { type: "button", class: `btn small${this.groupSelecting ? " active" : ""}`, text: this.groupSelecting ? "✓ Done" : "☑ Select",
        title: "Tick several playlists and add them to a group at once", onclick: () => {
          this.groupSelecting = !this.groupSelecting; if (!this.groupSelecting) sel.clear(); this.reload();
        } });
      const bar = h("div", { class: "lib-group-bar" }, selectBtn,
        this.groupSelecting ? [countEl, addSel,
          h("button", { type: "button", class: "btn small", text: "Select all playlists", onclick: () => {
            res.groups.filter((g) => g.type === "playlist").forEach((g) => sel.set(g.id, g.name)); this.reload();
          } }),
          h("button", { type: "button", class: "btn small", text: "Clear", onclick: () => { sel.clear(); this.reload(); } }),
          h("button", { type: "button", class: "btn small danger", text: "🗑️ Delete…", title: "Delete the ticked playlists and groups",
            onclick: () => this.deleteSelected(res.groups.filter((g) => sel.has(g.id))) })]
          : h("span", { class: "muted small", text: "Drag a card to reorder (it stays where you put it). Drop a playlist on the middle of a group to move it in, or use ＋ / Select." }));
      syncBar();
      fill(grid, bar, newBtn, res.groups.map((g) => {
        const tiles = g.thumbs.map((t) => {
          const src = safeUrl(t.thumbnail) || (t.video_id ? `https://i.ytimg.com/vi/${encodeURIComponent(t.video_id)}/mqdefault.jpg` : null);
          return showImages && src ? h("img", { src, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "lib-noimg", text: "▶" });
        });
        const picked = sel.has(g.id);
        const box = this.groupSelecting ? h("input", { type: "checkbox", class: "lib-group-check", checked: picked, "aria-label": `Select ${g.name}`,
          onclick: (e) => e.stopPropagation(), onchange: (e) => { if (e.target.checked) sel.set(g.id, g.name); else sel.delete(g.id); card.classList.toggle("picked", e.target.checked); syncBar(); } }) : null;
        const plus = h("span", { class: "lib-add-wrap lib-card-plus" }, h("button", { type: "button", class: "icon-btn", text: "＋",
          title: g.type === "playlist" ? "Move this playlist into a group" : "Add this group's videos to another group",
          "aria-label": `Add ${g.name} to a group`,
          onclick: (e) => { e.stopPropagation(); this.addAllToGroupMenu([{ id: g.id, name: g.name }], e.currentTarget); } }));
        const open = () => {
          if (this.groupSelecting) { box.checked = !box.checked; box.dispatchEvent(new Event("change")); return; }
          this.openGroup = g.id; this.reload();
        };
        // a div with role=button, so the ＋ button and tick box can sit inside it (no buttons inside buttons)
        const card = h("div", { class: `lib-group-card${picked ? " picked" : ""}`, role: "button", tabindex: "0", "aria-label": `Open ${g.name}`, draggable: "true",
          title: g.type === "playlist" ? "Drag onto one of your groups to move it there" : null, onclick: open,
          onkeydown: (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === card) { e.preventDefault(); open(); } } },
          h("span", { class: `lib-mosaic n${Math.max(1, tiles.length)}` }, tiles.length ? tiles : h("span", { class: "lib-noimg", text: "🗂️" })),
          box, plus, h("span", { class: "lib-card-edit" }, this.renameBtn(g.id, g.name)),
          h("span", { class: `lib-group-kind k-${g.type}`, text: g.type === "playlist" ? "▶ Playlist" : "🗂️ Group" }),
          h("strong", { class: "lib-group-name", text: g.name }),
          h("span", { class: "muted small", text: [g.playlists ? `${g.playlists} playlist${g.playlists === 1 ? "" : "s"}` : null, `${g.videos} video${g.videos === 1 ? "" : "s"}`, g.watched ? `${g.watched} watched` : null, g.channels.join(", ")].filter(Boolean).join(" · ") }));
        card.addEventListener("dragstart", (e) => {
          // dragging a ticked card takes every ticked one along
          this.dragging = sel.has(g.id) && sel.size > 1 ? [...sel].map(([id, name]) => ({ id, name })) : [{ id: g.id, name: g.name }];
          e.dataTransfer.effectAllowed = "copyMove";
          e.dataTransfer.setData("text/plain", g.name);  // Firefox needs some data to start a drag
          grid.classList.add("dragging");
        });
        card.addEventListener("dragend", () => { this.dragging = null; grid.classList.remove("dragging"); });
        this.cardDrop(card, g, res.groups.map((x) => x.id));
        return card;
      }));
    },

    /** Any card: dropping on its left/right half puts the dragged cards before/after it (saved order); dropping on
     *  the middle of a group card moves the dragged playlists into that group. */
    cardDrop(card, g, order) {
      const zone = (e) => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width;
        if (g.type === "group" && x > 0.25 && x < 0.75 && this.dragging.some((s) => s.id !== g.id)) return "into";
        return x < 0.5 ? "before" : "after";
      };
      const clear = () => card.classList.remove("drop-on", "drop-before", "drop-after");
      card.addEventListener("dragover", (e) => {
        if (!this.dragging || (this.dragging.length === 1 && this.dragging[0].id === g.id)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = zone(e) === "into" ? "copy" : "move";
        const z = zone(e);
        card.classList.toggle("drop-on", z === "into");
        card.classList.toggle("drop-before", z === "before");
        card.classList.toggle("drop-after", z === "after");
      });
      card.addEventListener("dragleave", (e) => { if (!card.contains(e.relatedTarget)) clear(); });
      card.addEventListener("drop", async (e) => {
        if (!this.dragging) return;
        e.preventDefault();
        const z = zone(e);
        clear();
        const srcs = this.dragging;
        this.dragging = null;
        if (z === "into") await this.copyIntoGroup(srcs, g);
        else await this.reorder(order, srcs.map((s) => s.id), g.id, z === "after");
      });
    },

    /** Put `moving` before/after `targetId` in `order` and save it. */
    async reorder(order, moving, targetId, after) {
      const mv = moving.filter((id) => order.includes(id) && id !== targetId);
      if (!mv.length) return;
      const rest = order.filter((id) => !mv.includes(id));
      let i = rest.indexOf(targetId);
      i = i < 0 ? rest.length : i + (after ? 1 : 0);
      rest.splice(i, 0, ...mv);
      if (await guarded(() => api("PUT", "/library/groups/order", { refs: rest }))) this.reload();
    },

    /** A group card (or "New group", group = null) that accepts dragged playlists/groups: their videos are added. */
    dropTarget(el, group) {
      const ok = () => this.dragging && (!group || this.dragging.some((s) => s.id !== group.id));
      el.addEventListener("dragover", (e) => { if (ok()) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; el.classList.add("drop-on"); } });
      el.addEventListener("dragleave", () => el.classList.remove("drop-on"));
      el.addEventListener("drop", async (e) => {
        el.classList.remove("drop-on");
        if (!ok()) return;
        e.preventDefault();
        const srcs = this.dragging;
        this.dragging = null;
        await this.copyIntoGroup(srcs, group);
      });
    },

    /** Add every video of some playlists/groups to one of your groups (group = null: create a new group first). */
    async copyIntoGroup(srcs, group) {
      let target = group;
      if (!target) {
        const name = (window.prompt("Name of the new group", srcs.length === 1 ? srcs[0].name : "") || "").trim();
        if (!name) return;
        target = await guarded(() => api("POST", "/library/groups", { name }));
        if (!target) return;
      }
      let added = 0, skipped = 0, moved = 0, done = 0;
      for (const src of srcs.filter((s) => s.id !== target.id)) {
        const r = await guarded(() => api("POST", `/library/groups/${target.id}/videos`, { from_ref: src.id }));
        if (!r) break;
        added += r.added; skipped += r.skipped; moved += r.moved || 0; done += 1;
      }
      if (!done) return;
      const one = srcs.find((s) => s.id !== target.id);
      const parts = [];
      if (moved) parts.push(`Moved ${moved === 1 && done === 1 ? `“${one.name}”` : `${moved} playlist${moved === 1 ? "" : "s"}`} into “${target.name}”`);
      if (added) parts.push(`added ${added} video${added === 1 ? "" : "s"}${skipped ? ` (${skipped} already there)` : ""}`);
      toast(parts.length ? parts.join(", ") : `Everything is already in “${target.name}”`);
      if (this.groupSel) this.groupSel.clear();
      this.groupSelecting = false;
      this.reload();
    },

    /** Menu: add all videos of some playlists/groups to one of your groups (no drag and drop needed). */
    async addAllToGroupMenu(srcs, anchor) {
      document.querySelectorAll(".lib-group-menu").forEach((m) => m.remove());
      const res = await api("GET", "/library/groups").catch(() => null);
      const ids = new Set(srcs.map((s) => s.id));
      const mine = res ? res.groups.filter((g) => g.type === "group" && !(ids.size === 1 && ids.has(g.id))) : [];
      const menu = h("div", { class: "lib-group-menu", role: "menu" },
        h("div", { class: "muted small", text: srcs.every((s) => s.id.startsWith("p:")) ? (srcs.length === 1 ? "Move this playlist into" : `Move ${srcs.length} playlists into`)
          : srcs.length === 1 ? "Add all its videos to" : `Add ${srcs.length} items to` }),
        mine.map((g) => h("button", { type: "button", role: "menuitem", text: g.name, onclick: (e) => { e.stopPropagation(); menu.remove(); this.copyIntoGroup(srcs, g); } })),
        h("button", { type: "button", role: "menuitem", class: "new", text: "+ New group…", onclick: (e) => { e.stopPropagation(); menu.remove(); this.copyIntoGroup(srcs, null); } }));
      menu.addEventListener("click", (e) => e.stopPropagation());  // don't open the card underneath
      anchor.parentNode.append(menu);
      const close = (e) => { if (!menu.contains(e.target) && e.target !== anchor) { menu.remove(); document.removeEventListener("click", close); } };
      setTimeout(() => document.addEventListener("click", close), 0);
    },

    async renderGroup(ref) {
      const grid = $("#libGrid");
      const allMode = ref.startsWith("g:") && this.groupMode === "all";   // a group: playlists as cards, or every video in one grid
      const scopeQ = allMode ? "&scope=all" : "";
      const res = await guarded(() => api("GET", `/library/groups/${encodeURIComponent(ref)}?limit=300${scopeQ}`));
      if (this.openGroup !== ref || this.filters.view !== "groups") return;  // you went back / elsewhere while it loaded
      if (!res) { this.openGroup = null; return; }
      const topicsById = Object.fromEntries((this.meta.topics || []).map((t) => [t.id, t]));
      const showImages = FW.state.settings.load_images !== false;
      const mine = res.type === "group";
      $("#libCount").textContent = "";
      const parent = res.in_group || null;
      const back = parent
        ? h("button", { type: "button", class: "btn small", text: `← ${parent.name}`, title: "Back to the group", onclick: () => { this.openGroup = parent.id; this.reload(); } })
        : h("button", { type: "button", class: "btn small", text: "← All playlists & groups", onclick: () => { this.openGroup = null; this.reload(); } });
      const feedId = res.type === "playlist" ? Number(ref.slice(2)) : null;
      const addAll = h("span", { class: "lib-add-wrap" }, h("button", { type: "button", class: "btn small",
        text: res.type === "playlist" ? (parent ? "＋ Move to another group…" : "＋ Move to group…") : "＋ Add to group…",
        title: res.type === "playlist" ? "Move this playlist into one of your groups (or drag its card onto a group)" : "Add this group's videos to another group",
        onclick: (e) => this.addAllToGroupMenu([{ id: ref, name: res.name }], e.currentTarget) }));
      const moveOut = parent ? h("button", { type: "button", class: "btn small", text: "↩ Move out of group",
        title: `Take this playlist out of “${parent.name}” and back to the main page`,
        onclick: () => this.movePlaylistOut(parent, { id: ref, name: res.name }, ref) }) : null;
      const actions = feedId ? [
        moveOut, addAll, this.renameBtn(ref, res.name, "btn small"),
        h("button", { type: "button", class: "btn small", text: "⇣ Load whole playlist",
          title: "Fetch every video in this playlist (YouTube's feed only lists the latest 15; needs a free YouTube Data API key)",
          onclick: () => loadWholeChannel(feedId, false) }),
        h("button", { type: "button", class: "btn small", text: "🗓️ Keep…", title: "Keep only videos from a time frame",
          onclick: () => openKeepDialog(res.name, [{ id: feedId, title: res.name, type: "playlist" }], () => this.reload()) }),
        h("button", { type: "button", class: "btn small danger", text: "🗑️ Delete playlist", onclick: async () => {
          if (!window.confirm(`Delete the playlist “${res.name}” and its ${res.total} video${res.total === 1 ? "" : "s"} from your library? It cannot be undone (you can add it again later).`)) return;
          const r = await guarded(() => api("DELETE", `/library/groups/${ref}`));
          if (r) { toast(`Deleted “${res.name}” (${r.videos_removed} videos)`); this.openGroup = null; await this.loadMeta(); this.reload(); }
        } })] : mine ? [
        addAll,
        this.renameBtn(ref, res.name, "btn small"),
        h("button", { type: "button", class: "btn small danger", text: "Delete group", onclick: async () => {
          if (window.confirm(`Delete the group “${res.name}”? Its videos stay in your library.`)
            && await guarded(() => api("DELETE", `/library/groups/${ref}`), "Group deleted")) { this.openGroup = null; this.reload(); }
        } })] : [];
      grid.className = "lib-grid";
      fill(grid,
        h("div", { class: "lib-group-head" }, back,
          h("h3", null, h("span", { class: `lib-group-kind k-${res.type}`, text: res.type === "playlist" ? "▶ Playlist" : "🗂️ Group" }), ` ${res.name}`),
          h("span", { class: "muted small", text: `${mine && (res.playlists || []).length ? `${res.playlists.length} playlist${res.playlists.length === 1 ? "" : "s"} · ` : ""}${res.total} video${res.total === 1 ? "" : "s"}${res.type === "playlist" ? " · in publishing order" : (res.playlists || []).length ? (allMode ? " in all" : " added by hand") : " · in the order you added them"}${res.type === "playlist" && res.total === 15 ? " · probably more: YouTube's feed stops at 15, use ⇣ Load whole playlist" : ""}` }),
          h("span", { class: "spacer" }), actions),
        mine && (res.playlists || []).length ? h("div", { class: "lib-group-bar" },
          h("span", { class: "lib-view", role: "group", "aria-label": "How to show this group" },
            h("button", { type: "button", class: `btn small${allMode ? "" : " primary"}`, "aria-pressed": String(!allMode), text: "🗂️ Playlists as cards",
              title: "Each playlist as its own card, then the videos you added one by one", onclick: () => { this.groupMode = "cards"; this.reload(); } }),
            h("button", { type: "button", class: `btn small${allMode ? " primary" : ""}`, "aria-pressed": String(allMode), text: "▦ All videos",
              title: "Every video in this group, from all its playlists, in one grid", onclick: () => { this.groupMode = "all"; this.reload(); } })),
          h("span", { class: "muted small", text: allMode ? `All ${res.total} videos from ${res.playlists.length} playlist${res.playlists.length === 1 ? "" : "s"} and the ones you added` : "" })) : null,
        mine && !allMode && (res.playlists || []).length ? [
          h("h4", { class: "lib-sub-head", text: `Playlists in this group (${res.playlists.length})` }),
          res.playlists.map((pl) => this.nestedPlaylistCard(pl, { id: ref, name: res.name }, showImages, res.playlists.map((x) => x.id))),
          h("h4", { class: "lib-sub-head", text: res.items.length ? `Videos you added (${res.total})` : "Videos you added" })] : null,
        res.items.length ? res.items.map((v, i) => {
          const card = this.card(v, topicsById, showImages, { number: i + 1, inGroup: mine && !allMode ? ref : null, inPlaylist: !mine });
          return card;
        }) : h("p", { class: "muted lib-pad", text: mine ? ((res.playlists || []).length ? "None yet: use ＋ on any video card to add single videos." : "Nothing here yet. Drag a playlist onto this group, or use ＋ on a video card to add it.") : "No videos in this playlist yet." }));
      // big playlists: load the rest a page at a time
      let shown = res.items.length;
      const more = $("#libMore").cloneNode(true);  // a copy without the grid's "Load more" listener
      $("#libMore").replaceWith(more);
      more.hidden = shown >= res.total;
      more.onclick = async () => {
        const next = await guarded(() => api("GET", `/library/groups/${encodeURIComponent(ref)}?offset=${shown}&limit=300${scopeQ}`));
        if (!next) return;
        grid.append(...next.items.map((v, i) => this.card(v, topicsById, showImages, { number: shown + i + 1, inGroup: mine && !allMode ? ref : null, inPlaylist: !mine })));
        shown += next.items.length;
        more.hidden = shown >= next.total;
      };
    },

    /** Delete ticked cards: playlists are unsubscribed with their videos; groups go, their videos and playlists stay. */
    async deleteSelected(items) {
      if (!items.length) { toast("Tick some playlists or groups first", true); return; }
      const lists = items.filter((g) => g.type === "playlist");
      const groups = items.filter((g) => g.type === "group");
      const videos = lists.reduce((n, g) => n + (g.videos || 0), 0);
      const lines = [
        lists.length ? `• ${lists.length} playlist${lists.length === 1 ? "" : "s"} and ${videos} video${videos === 1 ? "" : "s"} in them (removed from your library; starred ones too)` : null,
        groups.length ? `• ${groups.length} group${groups.length === 1 ? "" : "s"} (their videos and playlists stay; playlists go back to this page)` : null].filter(Boolean);
      if (!window.confirm(`Delete:\n${lines.join("\n")}\n\nThis cannot be undone (you can add a playlist again later).`)) return;
      let done = 0, removed = 0;
      for (const g of items) {
        const r = await guarded(() => api("DELETE", `/library/groups/${g.id}`));
        if (!r) break;
        done += 1; removed += r.videos_removed || 0;
      }
      toast(`Deleted ${done} item${done === 1 ? "" : "s"}${removed ? ` (${removed} videos removed)` : ""}`);
      if (this.groupSel) this.groupSel.clear();
      this.groupSelecting = false;
      await this.loadMeta();
      this.renderShell();
      this.reload();
    },

    /** A playlist card inside a group: opens the playlist; ↩ takes it back out to the main page. */
    /** ✎ Rename a playlist ("p:<feed>") or one of your groups ("g:<id>"). A playlist keeps your name when YouTube's
     *  feed refreshes (the feed's custom title); an empty name goes back to the name YouTube gives it. */
    async renameRef(ref, current) {
      const playlist = ref.startsWith("p:");
      const asked = window.prompt(playlist ? "Playlist name (leave empty to use YouTube's name again)" : "Group name", current);
      if (asked === null) return false;                 // cancelled
      const name = asked.trim().slice(0, playlist ? 300 : 100);
      if (name === current || (!name && !playlist)) return false;
      const ok = playlist
        ? await guarded(() => api("PATCH", `/feeds/${Number(ref.slice(2))}`, { title: name }), name ? "Renamed" : "YouTube's name comes back with the next refresh")
        : await guarded(() => api("PATCH", `/library/groups/${ref}`, { name }), "Renamed");
      if (!ok) return false;
      if (playlist && !name) await api("POST", `/feeds/${Number(ref.slice(2))}/refresh`).catch(() => null);  // fetch YouTube's name now
      this.cache.clear();                               // names are in the remembered views
      await this.loadMeta();                            // and in the Channels ▾ list
      this.reload();
      return true;
    },
    renameBtn(ref, name, cls = "icon-btn") {
      return h("button", { type: "button", class: cls, text: cls === "icon-btn" ? "✎" : "✎ Rename",
        title: ref.startsWith("p:") ? "Rename this playlist (your name stays when it refreshes)" : "Rename this group",
        "aria-label": `Rename ${name}`, onclick: (e) => { e.stopPropagation(); this.renameRef(ref, name); } });
    },

    nestedPlaylistCard(pl, group, showImages, order) {
      const tiles = pl.thumbs.map((t) => {
        const src = safeUrl(t.thumbnail) || (t.video_id ? `https://i.ytimg.com/vi/${encodeURIComponent(t.video_id)}/mqdefault.jpg` : null);
        return showImages && src ? h("img", { src, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "lib-noimg", text: "▶" });
      });
      const open = () => { this.openGroup = pl.id; this.reload(); };
      const card = h("div", { class: "lib-group-card lib-nested", role: "button", tabindex: "0", "aria-label": `Open ${pl.name}`, onclick: open,
        draggable: "true", title: "Drag to reorder the playlists in this group",
        onkeydown: (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === e.currentTarget) { e.preventDefault(); open(); } } },
        h("span", { class: `lib-mosaic n${Math.max(1, tiles.length)}` }, tiles.length ? tiles : h("span", { class: "lib-noimg", text: "▶" })),
        h("span", { class: "lib-card-edit solo" }, this.renameBtn(pl.id, pl.name)),
        h("span", { class: "lib-group-kind k-playlist", text: "▶ Playlist" }),
        h("strong", { class: "lib-group-name", text: pl.name }),
        h("span", { class: "muted small", text: [`${pl.videos} video${pl.videos === 1 ? "" : "s"}`, pl.watched ? `${pl.watched} watched` : null].filter(Boolean).join(" · ") }),
        h("button", { type: "button", class: "btn small lib-move-out", text: "↩ Move out of group", title: `Back to the main Playlists & groups page`,
          onclick: (e) => { e.stopPropagation(); this.movePlaylistOut(group, pl, group.id); } }));
      card.addEventListener("dragstart", (e) => { this.dragging = [{ id: pl.id, name: pl.name }]; e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", pl.name); });
      card.addEventListener("dragend", () => { this.dragging = null; });
      this.cardDrop(card, pl, order);
      return card;
    },

    async movePlaylistOut(group, pl, stayOn) {
      const r = await guarded(() => api("DELETE", `/library/groups/${group.id}/playlists/${pl.id.slice(2)}`));
      if (!r) return;
      toast(`“${pl.name}” is back on the Playlists & groups page`);
      this.openGroup = stayOn;
      this.reload();
    },

    async newGroup(addIds) {
      const name = (window.prompt("Name of the new group (e.g. “Linux course”, “Watch later”)") || "").trim();
      if (!name) return null;
      const g = await guarded(() => api("POST", "/library/groups", { name }));
      if (!g) return null;
      if (addIds && addIds.length) await guarded(() => api("POST", `/library/groups/${g.id}/videos`, { article_ids: addIds }));
      toast(addIds && addIds.length ? `Added to the new group “${g.name}”` : `Group “${g.name}” created`);
      if (this.filters.view === "groups") this.reload();
      return g;
    },

    /** Small menu on a video card: add it to one of your groups, or a new one. */
    async addToGroupMenu(v, anchor, refresh = () => {}) {
      document.querySelectorAll(".lib-group-menu").forEach((m) => m.remove());
      const res = await api("GET", "/library/groups").catch(() => null);
      const mine = res ? res.groups.filter((g) => g.type === "group") : [];
      const inIds = new Set((v.groups || []).map((g) => g.id));
      const menu = h("div", { class: "lib-group-menu", role: "menu" },
        h("div", { class: "muted small", text: "Add to group" }),
        mine.map((g) => h("button", { type: "button", role: "menuitem", class: inIds.has(g.id) ? "on" : "", disabled: inIds.has(g.id),
          text: `${inIds.has(g.id) ? "✓ " : ""}${g.name}`, onclick: async () => {
            menu.remove();
            if (await guarded(() => api("POST", `/library/groups/${g.id}/videos`, { article_ids: [v.id] }), `Added to “${g.name}”`)) {
              v.groups = [...(v.groups || []), { id: g.id, name: g.name }];
              refresh();
            }
          } })),
        h("button", { type: "button", role: "menuitem", class: "new", text: "+ New group…", onclick: async () => {
          menu.remove();
          const g = await this.newGroup([v.id]);
          if (g) { v.groups = [...(v.groups || []), { id: g.id, name: g.name }]; refresh(); }
        } }));
      anchor.parentNode.append(menu);
      const close = (e) => { if (!menu.contains(e.target) && e.target !== anchor) { menu.remove(); document.removeEventListener("click", close); } };
      setTimeout(() => document.addEventListener("click", close), 0);
    },

    /** 🗂️ Put channels in a group: an existing one, or a new one named here. */
    groupChannels(chans, done) {
      const dlg = $("#sourceDialog");
      const groups = (this.meta.channel_groups || []);
      const pick = h("select", { "aria-label": "Group" }, groups.map((g) => h("option", { value: String(g.id), text: `${g.name} (${g.channels.length})` })),
        h("option", { value: "new", text: "＋ New group…", selected: !groups.length }));
      const name = h("input", { type: "text", maxlength: 60, placeholder: "e.g. Podcasts", "aria-label": "New group name", hidden: groups.length > 0 });
      pick.addEventListener("change", () => { name.hidden = pick.value !== "new"; if (!name.hidden) name.focus(); });
      const err = h("p", { class: "error" });
      const keys = chans.map((c) => c.key);
      const go = async (e) => {
        e.preventDefault();
        try {
          if (pick.value === "new") {
            if (!name.value.trim()) { err.textContent = "Give the group a name."; return; }
            await api("POST", "/library/channel-groups", { name: name.value.trim(), channels: keys });
          } else {
            await api("PATCH", `/library/channel-groups/${pick.value}`, { add: keys });
          }
        } catch (ex) { err.textContent = ex.message; return; }
        dlg.close(); toast(`${chans.length} channel${chans.length === 1 ? "" : "s"} grouped`); done();
      };
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: `🗂️ Group ${chans.length === 1 ? chans[0].title : `${chans.length} channels`}` }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        h("div", { class: "grid-form" }, h("label", { text: "Group" }), pick, h("label", { text: "" }), name),
        h("p", { class: "muted small", text: "Pick the group in Channels ▾ to see all its channels' videos together. A channel can be in several groups." }),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Group" }))));
      if (!dlg.open) dlg.showModal();
      (groups.length ? pick : name).focus();
    },

    /** ☑ Which channels are in a group (tick boxes, with a search). */
    editChannelGroup(g, done) {
      const dlg = $("#sourceDialog");
      const inGroup = new Set(g.channels);
      const rows = this.meta.channels.map((c) => {
        const box = h("input", { type: "checkbox", checked: inGroup.has(c.key), value: c.key });
        return { c, box, el: h("label", { class: "tp-item" }, box, h("span", { class: "tp-name", text: c.title }), h("span", { class: "muted small", text: String(c.videos) })) };
      });
      const find = h("input", { type: "search", placeholder: "Find a channel…", "aria-label": "Find a channel" });
      find.addEventListener("input", () => { const q = find.value.trim().toLowerCase(); for (const r of rows) r.el.hidden = Boolean(q) && !r.c.title.toLowerCase().includes(q); });
      const err = h("p", { class: "error" });
      const go = async (e) => {
        e.preventDefault();
        const keys = rows.filter((r) => r.box.checked).map((r) => r.c.key);
        const ok = await api("PATCH", `/library/channel-groups/${g.id}`, { channels: keys }).catch((ex) => { err.textContent = ex.message; return null; });
        if (ok) { dlg.close(); toast(`${g.name}: ${keys.length} channel${keys.length === 1 ? "" : "s"}`); done(); }
      };
      fill(dlg, h("form", { class: "form source-wizard", onsubmit: go },
        h("div", { class: "sd-head" }, h("h3", { text: `🗂️ ${g.name} — channels` }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
        find, h("div", { class: "tp-list cg-list" }, rows.map((r) => r.el)),
        err,
        h("div", { class: "form-actions" },
          h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
          h("button", { type: "submit", class: "btn primary", text: "Save" }))));
      if (!dlg.open) dlg.showModal();
    },

    async renameChannelGroup(g, done) {
      const name = window.prompt("New name for the channel group:", g.name);
      if (!name || !name.trim() || name.trim() === g.name) return;
      if (await guarded(() => api("PATCH", `/library/channel-groups/${g.id}`, { name: name.trim() }), "Renamed")) done();
    },

    async deleteChannelGroup(g, done) {
      if (!window.confirm(`Delete the channel group “${g.name}”? Its channels and videos stay.`)) return;
      if (await guarded(() => api("DELETE", `/library/channel-groups/${g.id}`), "Group deleted")) {
        this.filters.channels = this.filters.channels.filter((k) => k !== `cg:${g.id}`);
        this.save(); done();
      }
    },

    /** ★ / ☆ channels (one or many). redraw: rebuild the header (menus); otherwise just update the stars in place. */
    async setFavorite(keys, on, redraw = false) {
      const res = await guarded(() => api("POST", "/library/favorite-channels", { channels: keys.slice(0, 500), favorite: on }));
      if (!res) return false;
      const favs = new Set(res.favorites);
      for (const c of this.meta.channels) c.favorite = favs.has(c.key);
      document.querySelectorAll("#libraryView .lib-fav[data-chan]").forEach((b) => {
        const f = favs.has(b.dataset.chan);
        b.classList.toggle("on", f); b.textContent = f ? "★" : "☆"; b.setAttribute("aria-pressed", String(f));
        b.title = f ? "Remove this channel from favourites" : "Add this channel to favourites";
      });
      const favChans = this.meta.channels.filter((c) => c.favorite);   // the "★ Favourite channels (n)" entry, open dropdown kept
      document.querySelectorAll("#libraryView .tp-item").forEach((row) => {
        const name = row.querySelector(".tp-name");
        if (!name || !name.textContent.startsWith("★ Favourite channels")) return;
        name.textContent = `★ Favourite channels (${favChans.length})`;
        const summary = row.closest("details") && row.closest("details").querySelector("summary");
        if (summary && summary.textContent.startsWith("★ Favourite channels")) summary.textContent = `★ Favourite channels (${favChans.length}) ▾`;
        const count = row.querySelector(".count");
        if (count) count.textContent = String(favChans.reduce((n, c) => n + c.videos, 0));
      });
      toast(on ? `★ ${keys.length === 1 ? "Channel added to" : `${keys.length} channels added to`} favourites`
        : `☆ ${keys.length === 1 ? "Channel removed from" : `${keys.length} channels removed from`} favourites`);
      if (redraw) this.renderShell();
      if (redraw || this.filters.channels.includes("fav")) this.reload();
      return true;
    },

    /** The channel name on a video card: followed → show its videos; not followed → follow it (the add dialog, with the
     *  usual choices: follow, its videos, its playlists, retention). */
    channelLink(v) {
      const name = v.channel_title || v.feed_title || "";
      const cid = /^UC[A-Za-z0-9_-]{22}$/.test(v.channel_id || "") ? v.channel_id : null;
      if (!cid) return name;
      const followed = (this.meta.channels || []).some((c) => c.key === cid && c.feed_id);
      const known = (this.meta.channels || []).find((c) => c.key === cid);
      const fav = known ? h("button", { type: "button", class: `link-btn lib-fav${known.favorite ? " on" : ""}`, "data-chan": cid, text: known.favorite ? "★" : "☆",
        title: known.favorite ? "Remove this channel from favourites" : "Add this channel to favourites", "aria-pressed": String(Boolean(known.favorite)),
        onclick: (e) => { e.stopPropagation(); this.setFavorite([cid], !e.currentTarget.classList.contains("on")); } }) : null;
      return h("span", { class: "lib-chan-wrap" }, fav, h("button", { type: "button", class: "link-btn lib-channel", text: name,
        title: followed ? `Show ${name}'s videos` : `Follow ${name} - choose to download its videos or playlists too`,
        onclick: () => {
          if (followed) {
            const f = this.filters;
            f.channels = [cid]; if (!["all", "topics"].includes(f.view)) f.view = "all";
            this.openGroup = null; this.save(); this.renderShell(); this.reload();
          } else {
            openAddChannels(`https://www.youtube.com/channel/${cid}`);
          }
        } }, followed ? null : h("span", { class: "lib-follow", text: " ＋" })));
    },

    card(v, topicsById, showImages, opts = {}) {
      const url = safeUrl(v.url);
      const thumb = safeUrl(v.thumbnail) || (v.video_id ? `https://i.ytimg.com/vi/${encodeURIComponent(v.video_id)}/hqdefault.jpg` : null);
      const open = async () => {  // plays in the app; YouTube in a new tab only if the video can't be embedded
        if (!playVideo(v, card) && url) window.open(url, "_blank", "noopener,noreferrer");
        if (!v.is_read) { v.is_read = true; card.classList.add("watched"); api("PATCH", `/articles/${v.id}`, { is_read: true }).catch(() => {}); }
      };
      const star = h("button", { type: "button", class: `icon-btn${v.is_starred ? " on" : ""}`, title: "Star", "aria-label": "Star", text: v.is_starred ? "★" : "☆", onclick: async () => {
        const r = await guarded(() => api("PATCH", `/articles/${v.id}`, { is_starred: !v.is_starred }));
        if (r) { v.is_starred = Boolean(r.is_starred); star.textContent = v.is_starred ? "★" : "☆"; star.classList.toggle("on", v.is_starred); }
      } });
      const inWatchedTab = this.filters.state === "watched";
      const watched = h("button", { type: "button", class: `icon-btn${v.is_read ? " on" : ""}`, text: v.is_read ? "↩" : "✓",
        title: v.is_read ? "Mark unwatched (back to your library)" : "Mark watched (then it is under Status ▾ → ✓ Watched)",
        "aria-label": v.is_read ? "Mark unwatched" : "Mark watched", onclick: async () => {
          const r = await guarded(() => api("PATCH", `/articles/${v.id}`, { is_read: !v.is_read }));
          if (!r) return;
          v.is_read = Boolean(r.is_read);
          card.classList.toggle("watched", v.is_read);
          watched.textContent = v.is_read ? "↩" : "✓";
          watched.classList.toggle("on", v.is_read);
          const leaves = (inWatchedTab && !v.is_read) || (!inWatchedTab && v.is_read && this.hidesWatched());
          if (leaves) {
            card.remove();
            this.total = Math.max(0, (this.total || 1) - 1);
            toast(v.is_read ? "Moved to ✓ Watched" : "Back in your library");
            this.refreshStarCount();
          }
        } });
      const badges = () => (v.groups || []).map((g) =>
        h("button", { type: "button", class: "lib-group-badge", title: `Open ${g.name}`, text: `${g.id.startsWith("p:") ? "▶" : "🗂️"} ${g.name}`,
          onclick: () => { this.filters.view = "groups"; this.openGroup = g.id; this.save(); this.renderShell(); this.reload(); } }));
      const groupsRow = h("div", { class: "lib-groups-row" }, badges());
      const card = h("article", { class: `lib-card${v.is_read ? " watched" : ""}`, "data-video": String(v.id) },
        h("button", { type: "button", class: "lib-thumb", "aria-label": `Watch ${v.title}`, onclick: open },
          showImages && thumb ? h("img", { src: thumb, alt: "", loading: "lazy", referrerpolicy: "no-referrer" }) : h("span", { class: "lib-noimg", text: "▶" }),
          v.duration_s != null ? h("span", { class: "lib-dur", text: fmtDuration(v.duration_s) }) : null,
          opts.number ? h("span", { class: "lib-num", text: String(opts.number) }) : null),
        h("div", { class: "lib-body" },
          h("a", { class: "lib-title", href: url || "#", target: "_blank", rel: "noopener noreferrer", text: v.title,
            onclick: (e) => { if (e.ctrlKey || e.metaKey || e.shiftKey) return; e.preventDefault(); open(); } }),  // Ctrl/⌘-click: YouTube tab
          h("div", { class: "muted small" }, this.channelLink(v), [relTime(v.published), fmtViews(v.views)].filter(Boolean).map((t) => ` · ${t}`).join("")),
          groupsRow,
          (() => {
            const picked = new Set(this.filters.topic_ids.map(Number));
            const all = v.topics.map((id) => topicsById[id]).filter(Boolean).sort((a, b) => (picked.has(b.id) ? 1 : 0) - (picked.has(a.id) ? 1 : 0));
            // folded behind 🏷️ n by default (the 🏷️ Tags toggle shows them on every card); unfolding one card shows all of its topics
            return FW.tagFold("videos", all.length, (single) => {
              const shown = single ? all : all.slice(0, 4);
              return h("div", { class: "lib-topics", title: all.map((t) => t.name).join(", ") },
                shown.map((t) => h("span", { class: `topic-tag${picked.has(t.id) ? " picked" : ""}` }, h("span", { class: "dot", style: { background: safeColor(t.color) } }), t.name)),
                all.length > shown.length ? h("span", { class: "topic-tag more", text: `+${all.length - shown.length}` }) : null);
            });
          })(),
          h("div", { class: "lib-actions" }, watched, star,
            h("button", { type: "button", class: "icon-btn", title: "Add to a group", "aria-label": "Add to a group", text: "＋",
              onclick: (e) => this.addToGroupMenu(v, e.currentTarget, () => fill(groupsRow, badges())) }),
            h("button", { type: "button", class: "icon-btn", text: "🗑︎",
              title: opts.inPlaylist ? "Remove this video from the playlist (and your library) for good" : "Remove this video from your library for good",
              "aria-label": "Remove this video", onclick: async () => {
                if (!window.confirm(`Remove “${v.title}”? It won't come back on later updates.`)) return;
                if (await guarded(() => api("DELETE", `/library/videos/${v.id}`), "Video removed")) card.remove();
              } }),
            opts.inGroup ? h("button", { type: "button", class: "icon-btn", title: "Remove from this group", "aria-label": "Remove from this group", text: "✕",
              onclick: async () => { if (await guarded(() => api("DELETE", `/library/groups/${opts.inGroup}/videos/${v.id}`), "Removed from the group")) card.remove(); } }) : null,
            h("button", { type: "button", class: "btn small", text: "Open in Articles", onclick: () => FW.openArticleInReader(v.id) }))));
      card._play = open;  // the player's ⏮ / ⏭ step through the cards on the page
      return card;
    },
  };

  // ======================================================================= in-app video player
  const YT_VIDEO_ID = /^[A-Za-z0-9_-]{11}$/;

  /** Play a library video inside the app: YouTube's privacy-enhanced player (youtube-nocookie.com) in a sandboxed
   *  frame - the CSP allows frames from that one host only. ⏮ / ⏭ step through the videos shown on the page
   *  (a playlist plays in its own order). Returns false when the video can't be embedded (the caller opens YouTube). */
  function playVideo(v, card) {
    if (!YT_VIDEO_ID.test(v.video_id || "")) return false;
    let dlg = document.getElementById("videoPlayerDialog");
    if (!dlg) {
      dlg = h("dialog", { id: "videoPlayerDialog", class: "dialog video-player-dialog", "aria-label": "Video player" });
      dlg.addEventListener("close", () => fill(dlg));                       // removing the frame stops playback
      dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });  // a click on the backdrop closes it
      document.body.append(dlg);
    }
    const sibling = (dir) => {  // the next / previous video card on the page
      let el = card;
      do { el = dir > 0 ? el.nextElementSibling : el.previousElementSibling; } while (el && !el._play);
      return el;
    };
    const prev = sibling(-1);
    const next = sibling(1);
    const src = `https://www.youtube-nocookie.com/embed/${v.video_id}?autoplay=1&rel=0&playsinline=1`;
    const watch = `https://www.youtube.com/watch?v=${v.video_id}`;
    fill(dlg,
      h("div", { class: "vp-head" },
        h("div", { class: "vp-title" }, h("strong", { text: v.title || v.video_id }),
          v.channel_title ? h("span", { class: "muted small", text: ` · ${v.channel_title}` }) : null),
        h("div", { class: "vp-actions" },
          h("button", { type: "button", class: "btn small", text: "⏮", title: "Previous video", "aria-label": "Previous video", disabled: !prev,
            onclick: () => prev && prev._play() }),
          h("button", { type: "button", class: "btn small", text: "⏭", title: "Next video", "aria-label": "Next video", disabled: !next,
            onclick: () => next && next._play() }),
          h("a", { class: "btn small", href: watch, target: "_blank", rel: "noopener noreferrer", text: "↗ YouTube", title: "Open on YouTube in a new tab",
            onclick: () => dlg.close() }),
          h("button", { type: "button", class: "btn small", text: "✕", title: "Close (Esc)", "aria-label": "Close player", onclick: () => dlg.close() }))),
      h("div", { class: "vp-frame" },
        // sandbox + allow list first, src last. YouTube's player needs to know which site embeds it: this frame alone
        // sends the app's origin (never the page path) - everything else keeps the app-wide no-referrer policy.
        h("iframe", { sandbox: "allow-scripts allow-same-origin allow-presentation allow-popups allow-popups-to-escape-sandbox",
          allow: "autoplay; encrypted-media; picture-in-picture; fullscreen", allowfullscreen: true,
          referrerpolicy: "strict-origin", title: v.title || "YouTube video", src })));
    if (!dlg.open) dlg.showModal();
    return true;
  }

  // ======================================================================= topics editor
  /** Wait for the background re-tag after a topic change, then refresh (new topics appear once tagged). */
  async function afterTopicChange(refresh) {
    await library.loadMeta();
    refresh();
    if (!library.meta.reclassifying) return;
    for (let i = 0; i < 150 && library.meta.reclassifying; i += 1) {
      await new Promise((r) => setTimeout(r, 3000));
      await library.loadMeta();
    }
    toast("Topics updated: every video is tagged");
    refresh();
  }

  /** Add (t = null) or edit one topic: name, colour, keywords, on/off. */
  function openTopicEditor(t, refresh) {
    const dlg = $("#sourceDialog");
    const name = h("input", { type: "text", maxlength: 60, value: t ? t.name : "", placeholder: "Topic name", required: true, "aria-label": "Topic name" });
    const color = h("input", { type: "color", value: safeColor(t ? t.color : "#64748b"), "aria-label": "Colour" });
    const words = h("textarea", { rows: 4, maxlength: 6000, required: true, "aria-label": "Keywords",
      placeholder: "keywords, comma separated — a video belongs to the topic when one of them is in its title or channel name" });
    words.value = t ? (t.keywords || []).join(", ") : "";
    const enabled = h("input", { type: "checkbox", checked: t ? t.enabled !== false : true, "aria-label": "Enabled" });
    const err = h("p", { class: "error" });
    const save = async (e) => {
      e.preventDefault();
      const kw = words.value.split(",").map((w) => w.trim()).filter(Boolean);
      const body = { name: name.value.trim(), color: color.value, keywords: kw, enabled: enabled.checked };
      try {
        if (t) await api("PATCH", `/topics/${t.id}`, body); else await api("POST", "/topics", body);
        dlg.close();
        toast(t ? `Saved “${body.name}” — re-tagging…` : `Added “${body.name}” — tagging videos…`);
        afterTopicChange(refresh);
      } catch (ex) { err.textContent = ex.message; }
    };
    fill(dlg, h("form", { class: "form source-wizard", onsubmit: save },
      h("div", { class: "sd-head" }, h("h3", { text: t ? `⚙ Edit topic — ${t.name}` : "＋ Add a topic" }),
        h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("div", { class: "grid-form" },
        h("label", { text: "Name" }), name, h("label", { text: "Colour" }), color,
        h("label", { text: "Keywords" }), words, h("label", { text: "Enabled" }), enabled),
      h("p", { class: "muted small", text: "Videos match on their title (and channel name); articles on their title or two mentions early in the text. Keep words specific for precise topics." }),
      err,
      h("div", { class: "form-actions" },
        t ? h("button", { type: "button", class: "btn danger", text: "Delete", onclick: () => { dlg.close(); deleteTopics([t], refresh); } }) : null,
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: () => dlg.close() }),
        h("button", { type: "submit", class: "btn primary", text: t ? "Save" : "Add topic" }))));
    if (!dlg.open) dlg.showModal();
    name.focus();
  }

  async function deleteTopics(list, refresh) {
    list = list.filter(Boolean);
    if (!list.length) return;
    if (!window.confirm(`Delete ${list.length === 1 ? `the topic “${list[0].name}”` : `${list.length} topics`}?\n\n${list.map((t) => `• ${t.name}`).join("\n")}\n\nVideos stay; they just lose these tags.`)) return;
    let done = 0;
    for (const t of list) {
      try { await api("DELETE", `/topics/${t.id}`); done += 1; } catch (err) { toast(err.message, true); break; }
    }
    library.filters.topic_ids = library.filters.topic_ids.filter((id) => !list.some((t) => String(t.id) === id));
    library.save();
    toast(`Deleted ${done} topic${done === 1 ? "" : "s"}`);
    await library.loadMeta();
    refresh();
  }

  async function openTopics() {
    const dlg = $("#sourceDialog");
    fill(dlg, h("p", { class: "muted", text: "Loading…" }));
    if (!dlg.open) dlg.showModal();
    const list = await guarded(() => api("GET", "/topics"));
    if (!list) { dlg.close(); return; }
    const done = async () => {
      const refresh = () => { if (FW.currentMode() === "library") { library.renderShell(); library.reload(); } };
      await library.loadMeta();
      refresh();
      if (!library.meta.reclassifying) return;
      // re-tagging every article and video takes a while: refresh again when it has finished
      for (let i = 0; i < 150 && library.meta.reclassifying; i += 1) {
        await new Promise((r) => setTimeout(r, 4000));
        await library.loadMeta();
      }
      toast("Topics updated: every video is tagged");
      refresh();
    };
    const row = (t) => {
      const name = h("input", { type: "text", maxlength: 60, value: t ? t.name : "", placeholder: "Topic name", required: true });
      const color = h("input", { type: "color", value: safeColor(t ? t.color : "#64748b") });
      const general = Boolean(t && t.builtin && !t.keywords.length);  // "General": no keywords on purpose
      const words = h("textarea", { rows: 2, maxlength: 6000, required: !general,
        placeholder: general ? "no keywords - videos nothing else fits go here" : "keywords, comma separated" });
      words.value = t ? t.keywords.join(", ") : "";
      const enabled = h("input", { type: "checkbox", checked: t ? t.enabled : true, title: "Enabled" });
      const payload = () => {
        const keywords = words.value.split(/[,\n]/).map((w) => w.trim()).filter(Boolean).slice(0, 100);
        return { name: name.value.trim(), color: color.value, enabled: enabled.checked, ...(keywords.length ? { keywords } : {}) };
      };
      return h("form", { class: "topic-edit card", onsubmit: async (e) => {
        e.preventDefault();
        const ok = t ? await guarded(() => api("PATCH", `/topics/${t.id}`, payload()), "Topic saved — re-tagging in the background")
          : await guarded(() => api("POST", "/topics", payload()), "Topic added — tagging in the background");
        if (ok) { openTopics(); setTimeout(done, 1500); }
      } },
        h("div", { class: "row-form" }, color, name, h("label", { class: "small" }, enabled, " enabled"),
          t && t.builtin ? h("span", { class: "muted small", text: "built-in" }) : null, h("span", { class: "spacer" }),
          h("button", { type: "submit", class: "btn small primary", text: t ? "Save" : "Add topic" }),
          t ? h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
            if (window.confirm(`Delete the topic “${t.name}”?`) && await guarded(() => api("DELETE", `/topics/${t.id}`), "Deleted")) { openTopics(); done(); }
          } }) : null),
        words);
    };
    fill(dlg, h("div", { class: "form topics-dialog" },
      h("div", { class: "sd-head" }, h("h3", { text: "Topics" }), h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => { dlg.close(); done(); } })),
      h("p", { class: "muted small", text: "Every topic with its color and keywords. A video gets every topic whose keywords appear as whole words in its title or channel name (articles: title or opening text); a video nothing matches gets its channel's main topic, or General. Changes re-tag in the background." }),
      row(null),
      list.map(row)));
  }

  FW.sources = { multiPicker, topicPicker, timeFramePicker, detectKind, openSourceWizard, sourceEditor, integrationsPanel, BACKFILL_HINT, KIND_LABEL, KIND_ICON };
  FW.library = library;
})();
