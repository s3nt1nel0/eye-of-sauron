/* Entity pages, the ATT&CK / ATLAS technique matrix and the "not this technique" feedback (loaded after app.js). */
(() => {
  "use strict";
  const FW = window.FW;
  const { h, fill, api, guarded, toast, safeUrl, relTime, fullDate, store } = FW;
  const dlg = () => document.getElementById("intelDialog");
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : (many || one + "s")}`;

  function show(cls, ...children) {
    const d = dlg();
    d.className = `dialog intel-dialog ${cls}`;
    fill(d, ...children);
    if (!d.open) d.showModal();
    d.scrollTop = 0;
  }
  function close() { const d = dlg(); if (d.open) d.close(); }
  function head(title, sub, ...tools) {
    return h("div", { class: "intel-head" },
      h("div", { class: "intel-title" }, h("h3", { text: title }), sub ? h("div", { class: "muted", text: sub }) : null),
      h("div", { class: "intel-tools" }, tools,
        h("button", { type: "button", class: "icon-btn", title: "Close (Esc)", "aria-label": "Close", text: "✕", onclick: close })));
  }

  // ===================================================================== one period for the matrix and the pages
  const PERIODS = [[7, "Last 7 days"], [30, "Last 30 days"], [90, "Last 90 days"], [365, "Last year"], [0, "All time"]];
  const periodDays = () => { const d = Number(FW.state.settings.matrix_days); return PERIODS.some(([x]) => x === d) ? d : 30; };
  const periodText = (d) => (PERIODS.find(([x]) => x === d) || PERIODS[4])[1].toLowerCase();
  /** The period picker: changing it is remembered (Settings → Appearance & reading) and redraws whatever is open. */
  function periodSelect(redraw) {
    const sel = h("select", { "aria-label": "Period", title: "Count mentions from this period (the matrix and the pages share it)" },
      PERIODS.map(([d, l]) => h("option", { value: d, text: l, selected: d === periodDays() })));
    sel.addEventListener("change", () => {
      const d = Number(sel.value);
      FW.state.settings.matrix_days = d;
      api("PATCH", "/settings", { matrix_days: d }).catch(() => {});  // remembered when you may change settings
      redraw();
    });
    return sel;
  }

  // ===================================================================== entity page
  let fromMatrix = null;  // "attack" / "atlas" when the page was opened from the matrix (← Matrix)
  const KINDS = [["articles", "Articles", "📰"], ["videos", "Videos", "▶"], ["podcasts", "Podcasts", "🎙"], ["posts", "Account posts", "💬"]];
  const trail = [];  // entity ids you came through (← Back)

  function timeline(p) {
    const max = Math.max(1, ...p.timeline.map((b) => b.n));
    const total = p.timeline.reduce((n, b) => n + b.n, 0);
    const unit = p.step === 86400 ? "day" : p.step === 7 * 86400 ? "week" : p.step === 30 * 86400 ? "month" : `${Math.round(p.step / (30 * 86400))} months`;
    return h("div", { class: "intel-section" },
      h("div", { class: "intel-section-head" },
        h("strong", { text: `Mentions per ${unit}` }),
        h("span", { class: "muted", text: ` · ${plural(total, "mention")}, ${periodText(p.days)}` })),
      h("div", { class: "intel-bars", role: "img", "aria-label": `Mentions per ${unit}, ${total} in total, highest ${max}` },
        p.timeline.map((b) => h("span", { class: `bar${b.n ? "" : " zero"}`, style: { "--v": String(b.n / max) },
          title: `${p.step === 86400 ? "" : "From "}${new Date(b.ts * 1000).toLocaleDateString()}: ${plural(b.n, "mention")}` }))),
      h("div", { class: "intel-axis muted" }, h("span", { text: new Date(p.timeline[0].ts * 1000).toLocaleDateString() }),
        h("span", { text: `highest: ${max} per ${unit}` }), h("span", { text: "now" })));
  }

  function itemRow(kind, it) {
    const inReader = kind === "articles";
    const url = safeUrl(it.url);
    const body = [h("span", { class: "intel-item-meta muted", text: `${it.feed_title} · ${relTime(it.sort_ts)}`, title: fullDate(it.sort_ts) }),
      h("span", { class: "intel-item-title", text: it.title })];
    if (inReader) return h("button", { type: "button", class: `intel-item${it.is_read ? " read" : ""}`, title: "Open in the reader",
      onclick: () => { close(); FW.openArticleInReader(it.id); } }, body);
    const main = url ? h("a", { class: `intel-item${it.is_read ? " read" : ""}`, href: url, target: "_blank", rel: "noopener noreferrer", title: "Open the original ↗" }, body)
      : h("div", { class: "intel-item" }, body);
    // videos and podcast episodes: a button that opens that very item in its own tab of the app
    const jump = kind === "videos" && FW.library ? ["▶ Open in Videos", "Show this video in the Videos tab", () => FW.library.goTo(it)]
      : kind === "podcasts" && FW.podcasts ? ["🎙 Open in Podcasts", "Show this episode in the Podcasts tab, with its description", () => FW.podcasts.goTo(it)] : null;
    if (!jump) return main;
    return h("div", { class: "intel-item-row" }, main,
      h("button", { type: "button", class: "btn small", text: jump[0], title: jump[1], onclick: () => { close(); jump[2](); } }));
  }

  function entityChip(e, sub) {
    return h("button", { type: "button", class: "chip intel-chip", title: `${e.watchlist ? e.watchlist + " · " : ""}open its page`,
      onclick: () => entityPage(e.entity_id || e.id) }, e.name, sub != null ? h("span", { class: "n", text: String(sub) }) : null);
  }

  async function entityPage(id, replace) {
    const days = periodDays();
    const p = await guarded(() => api("GET", `/entities/${Number(id)}/page?days=${days}`));
    if (!p) return;
    if (!dlg().open) fromMatrix = null;  // opened from the reader / a list: nothing to go back to
    if (!dlg().open || !dlg().classList.contains("entity")) trail.length = 0;
    if (!replace && trail[trail.length - 1] !== p.id) trail.push(p.id);
    const m = p.mitre;
    const total = KINDS.reduce((n, [k]) => n + (p.totals[k] || 0), 0);
    const listAll = () => {
      close(); FW.setMode("reader");
      const range = document.getElementById("rangeSelect");  // the list shows the same period as the page
      if (range) range.value = p.days ? String(p.days * 86400) : "";
      FW.selectView(m && m.kind === "technique" ? { type: "ttp", id: m.id, name: p.name.replace(/\s*\([^)]*\)$/, "") } : { type: "entity", id: p.id, name: p.name });
    };
    show("entity",
      head(p.name, `${p.watchlist.name}${p.first_seen ? ` · first seen ${new Date(p.first_seen * 1000).toLocaleDateString()} · last ${relTime(p.last_seen)}` : " · not mentioned yet"}`,
        fromMatrix ? h("button", { type: "button", class: "btn small", text: "← Matrix", title: `Back to the ${fromMatrix === "atlas" ? "ATLAS" : "ATT&CK"} matrix`,
          onclick: () => matrix(fromMatrix) }) : null,
        trail.length > 1 ? h("button", { type: "button", class: "btn small", text: "← Back", title: "Back to the previous page", onclick: () => { trail.pop(); entityPage(trail[trail.length - 1], true); } }) : null,
        periodSelect(() => entityPage(p.id, true)),
        m && m.url ? h("a", { class: "btn small", href: safeUrl(m.url), target: "_blank", rel: "noopener noreferrer", text: "MITRE ↗" }) : null),
      h("div", { class: "intel-body" },
        m && m.description ? h("p", { class: "intel-desc", text: m.description }) : null,
        p.actor ? h("div", { class: "intel-line actor-facts" }, h("span", { class: "chip sub-chip", text: `🎭 Threat actor${p.actor.kind && KIND_TEXT[p.actor.kind] ? ` · ${KIND_TEXT[p.actor.kind]}` : ""}` }),
          p.actor.country ? h("span", { class: "chip sub-chip", title: "Country the catalogue links it to", text: `${FLAG(p.actor.country)} ${p.actor.country}` }) : null,
          (p.actor.sources || []).length ? h("span", { class: "muted small", text: `Sources: ${p.actor.sources.join(", ")}` }) : null,
          p.actor.members > 1 ? h("span", { class: "muted small", title: "The numbers on this page count mentions under any of its names", text: ` · counts ${p.actor.members} lists' entries as one actor` }) : null) : null,
        p.actor && (p.actor.also || []).length ? h("div", { class: "intel-line muted small", title: "Every name the sources give this actor", text: `Also known as (${p.actor.also.length}): ${p.actor.also.join(" · ")}` }) : null,
        m && m.kind === "technique" && m.tactics.length ? h("div", { class: "intel-line" }, h("span", { class: "muted", text: "Tactics: " }), m.tactics.join(", ")) : null,
        m && m.kind === "technique" && m.parent ? h("div", { class: "intel-line" }, h("span", { class: "muted", text: "Sub-technique of: " }),
          m.parent.entity_id ? entityChip({ id: m.parent.entity_id, name: `${m.parent.id} ${m.parent.name}` }) : `${m.parent.id} ${m.parent.name}`) : null,
        m && m.kind === "tactic" ? h("p", { class: "intel-desc muted", text: "A tactic: the articles counted here name the tactic itself. Articles that name one of its techniques are in its collection in the sidebar." }) : null,
        h("div", { class: "intel-tiles" }, KINDS.map(([k, label, ico]) => h("div", { class: `intel-tile${p.totals[k] ? "" : " zero"}` },
          h("div", { class: "intel-tile-n", text: (p.totals[k] || 0).toLocaleString() }), h("div", { class: "muted", text: `${ico} ${label}` })))),
        total ? timeline(p) : h("p", { class: "muted", text: p.all_time
          ? `No mention ${periodText(p.days)} (${plural(p.all_time, "mention")} all time) - pick a longer period at the top.`
          : "No stored article, video, episode or post mentions this yet." }),
        p.totals.articles || p.totals.videos || p.totals.podcasts ? h("div", { class: "intel-line" },
          p.totals.articles ? h("button", { type: "button", class: "btn small primary",
            text: `List ${p.days ? "these" : "all"} ${plural(p.totals.articles, "article")} →`, title: `Articles that mention it, ${periodText(p.days)}`, onclick: listAll }) : null,
          p.totals.videos ? h("button", { type: "button", class: "btn small primary",
            text: `▶ List ${p.days ? "these" : "all"} ${plural(p.totals.videos, "video")} →`, title: `Open the Videos tab on the videos that mention it, ${periodText(p.days)}`,
            onclick: () => { close(); FW.library.listEntity({ id: p.id, name: p.name, days: p.days }); } }) : null,
          p.totals.podcasts ? h("button", { type: "button", class: "btn small primary",
            text: `🎙 List ${p.days ? "these" : "all"} ${plural(p.totals.podcasts, "podcast episode")} →`, title: `Open the Podcasts tab on the episodes that mention it, ${periodText(p.days)}`,
            onclick: () => { close(); FW.podcasts.listEntity({ id: p.id, name: p.name, days: p.days }); } }) : null) : null,
        KINDS.filter(([k]) => p.latest[k].length).map(([k, label, ico]) => h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: `${ico} Latest ${label.toLowerCase()}` }),
            h("span", { class: "muted", text: ` · ${p.latest[k].length} of ${p.totals[k].toLocaleString()}` })),
          p.latest[k].map((it) => itemRow(k, it)))),
        p.related.length ? h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: "Seen together with" }), h("span", { class: "muted", text: ` · in its mentions, ${periodText(p.days)}` })),
          h("div", { class: "chips" }, p.related.map((e) => entityChip(e, e.n)))) : null,
        m && m.kind === "technique" && m.groups.length ? h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: `Groups known to use it (${m.groups.length})` }), h("span", { class: "muted", text: " · from MITRE ATT&CK" })),
          h("div", { class: "chips" }, m.groups.map((g) => g.entity_id ? entityChip({ ...g, name: `${g.name} (${g.id})` }) : h("span", { class: "chip", text: `${g.name} (${g.id})` })))) : null,
        m && m.kind === "technique" && m.subtechniques.length ? h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: `Sub-techniques (${m.subtechniques.length})` }),
            h("span", { class: "muted", text: ` · ${m.subtechniques.filter((s) => s.n).length} named in its mentions, ${periodText(p.days)}` })),
          h("div", { class: "chips" }, m.subtechniques.map((s) => h(s.entity_id ? "button" : "span", {
            ...(s.entity_id ? { type: "button", onclick: () => entityPage(s.entity_id) } : {}),
            class: `chip sub-chip${s.entity_id ? " intel-chip" : ""}${s.n ? "" : " zero"}`,
            title: `${s.id}  ${s.name}
${s.n ? `${plural(s.n, "mention")} name this sub-technique, ${periodText(p.days)}` : `Not named ${periodText(p.days)}`}${s.entity_id ? "\nClick for its page" : ""}` },
            h("code", { text: `.${s.id.split(".").pop()}` }), ` ${s.name}`, s.n ? h("span", { class: "n", text: s.n.toLocaleString() }) : null)))) : null,
        m && m.kind === "tactic" && m.techniques.length ? h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: `Techniques of this tactic (${m.techniques.length})` }), h("span", { class: "muted", text: " · from MITRE" })),
          h("div", { class: "chips" }, m.techniques.map((t) => t.entity_id ? entityChip({ id: t.entity_id, name: `${t.id} ${t.name}` }) : h("span", { class: "chip", text: `${t.id} ${t.name}` })))) : null,
        m && m.kind === "group" && m.techniques.length ? h("div", { class: "intel-section" },
          h("div", { class: "intel-section-head" }, h("strong", { text: `Techniques it uses (${m.techniques.length})` }), h("span", { class: "muted", text: " · from MITRE ATT&CK" })),
          h("div", { class: "chips" }, m.techniques.map((t) => t.entity_id ? entityChip({ ...t, name: `${t.id} ${t.name}` }) : h("span", { class: "chip", text: `${t.id} ${t.name}` })))) : null,
        p.aliases.length ? h("div", { class: "intel-line muted small", title: p.actor ? "The names looked for in articles, videos and podcasts (names that are ordinary words, such as Leviathan, are shown above but not looked for on their own)" : "The names this entity is recognised by",
          text: `Recognised by${p.actor ? ` (${p.aliases.length})` : ""}: ${p.aliases.join(" · ")}` }) : null));
  }

  /** Open the page of a technique, sub-technique or tactic by its ID (T1566, T1566.001, TA0001, AML.T0051). */
  async function techniquePage(tid) {
    const hit = await api("GET", `/attack/techniques/${encodeURIComponent(tid)}/entity`).catch(() => null);
    if (hit && hit.entity_id) entityPage(hit.entity_id); else toast("That technique has no page yet (sync MITRE data in Settings → Watchlists)", true);
  }

  // ===================================================================== technique matrix
  function navigatorLayer(data) {
    const techniques = data.tactics.flatMap((t) => t.techniques).filter((t) => t.n && t.domain === "enterprise-attack");
    const seen = new Set();
    const period = periodText(data.days);
    const layer = {
      name: `Eye of Sauron - articles (${period})`, domain: "enterprise-attack",
      versions: { navigator: "5.1.0", layer: "4.5", ...(data.version ? { attack: String(parseInt(data.version, 10)) } : {}) },
      description: `How many stored articles name each technique (${period}). Exported ${new Date().toISOString().slice(0, 10)}.`,
      techniques: techniques.filter((t) => !seen.has(t.id) && seen.add(t.id)).map((t) => ({ techniqueID: t.id, score: t.n, comment: plural(t.n, "article") })),
      gradient: { colors: ["#ffffff", "#ff6666"], minValue: 0, maxValue: Math.max(1, data.max) },
      showTacticRowBackground: false,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" }));
    const a = h("a", { href: url, download: `attack-navigator-layer-${data.days || "all"}.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Layer saved - open it in the ATT&CK Navigator with “Open Existing Layer”");
  }

  async function matrix(fw) {
    fw = fw === "atlas" ? "atlas" : "attack";
    const days = periodDays();
    const data = await guarded(() => api("GET", `/attack/matrix?framework=${fw}&days=${days}`));
    if (!data) return;
    const showEmpty = store.get("fw-matrix-empty", false) === true;
    const period = periodSelect(() => matrix(fw));
    const named = data.tactics.reduce((n, t) => n + t.techniques.filter((x) => x.n).length, 0);
    const cell = (t) => h("button", { type: "button", class: `mx-cell${t.n ? "" : " zero"}`, style: { "--heat": t.n ? String(0.12 + 0.48 * Math.sqrt(t.n / Math.max(1, data.max))) : "0" },
      title: `${t.id}  ${t.name}\n${plural(t.n, "article")} - click for its page`, disabled: !t.entity_id,
      onclick: () => { fromMatrix = fw; entityPage(t.entity_id); } }, h("span", { class: "mx-name", text: t.name }), t.n ? h("span", { class: "mx-n", text: t.n.toLocaleString() }) : null);
    show("matrix",
      head(`${fw === "atlas" ? "MITRE ATLAS" : "MITRE ATT&CK"} technique matrix`,
        `${plural(named, "technique")} named in your articles, ${periodText(data.days)}${data.version ? ` · release ${data.version}` : ""}`,
        h("div", { class: "seg" }, [["attack", "ATT&CK"], ["atlas", "ATLAS"]].map(([k, l]) => h("button", { type: "button", class: `btn small${k === fw ? " primary" : ""}`,
          "aria-pressed": String(k === fw), text: l, onclick: () => matrix(k) }))),
        period,
        h("label", { class: "mx-check", title: "Also show techniques that no article names" },
          h("input", { type: "checkbox", checked: showEmpty, onchange: (e) => { store.set("fw-matrix-empty", e.currentTarget.checked); matrix(fw); } }), "Show all"),
        fw === "attack" ? h("button", { type: "button", class: "btn small", title: "Save the counts as a layer file for MITRE's ATT&CK Navigator", text: "⬇ Navigator layer",
          disabled: !named, onclick: () => navigatorLayer(data) }) : null),
      h("div", { class: "intel-body" },
        named || showEmpty ? null : h("p", { class: "muted", text: "No article in this period names a technique. Try a longer period." }),
        h("div", { class: "mx-grid", style: { "--cols": String(data.tactics.length) } }, data.tactics.map((t) => {
          const techs = showEmpty ? t.techniques : t.techniques.filter((x) => x.n);
          return h("div", { class: "mx-col" },
            h("div", { class: "mx-tactic", title: `${t.id ? `${t.id}  ` : ""}${t.name}: ${plural(t.total, "mention")}` }, h("span", { text: t.name }), h("span", { class: "muted", text: techs.length ? String(techs.length) : "" })),
            techs.map(cell));
        })),
        h("div", { class: "mx-legend muted" }, "fewer articles", [0.12, 0.28, 0.44, 0.6].map((v) => h("span", { class: "mx-swatch", style: { "--heat": String(v) } })), "more",
          h("span", { class: "spacer" }), "Click a technique for its page. The darker the cell, the more articles name it.")));
  }

  // ===================================================================== "not this technique"
  async function notThis(articleId, t, done) {
    const why = await guarded(() => api("GET", `/attack/techniques/${encodeURIComponent(t.id)}/why?article_id=${Number(articleId)}`));
    if (!why) return;
    const send = async (mute) => {
      const res = await guarded(() => api("POST", `/attack/techniques/${encodeURIComponent(t.id)}/reject`, mute ? { article_id: articleId, mute } : { article_id: articleId }));
      if (!res) return;
      close();
      toast(mute ? `“${mute}” no longer counts as ${t.id}. Articles are being re-checked.` : `${t.id} removed from this article`);
      if (done) done();
    };
    show("feedback",
      head(`Not ${t.id} ${t.name}?`, why.names.length ? `Matched because the article contains: ${why.names.map((n) => `“${n}”`).join(", ")}`
        : why.ids.length ? `Matched because the article names the ID ${why.ids.join(", ")}` : "The article no longer contains one of its names."),
      h("div", { class: "intel-body intel-feedback" },
        h("button", { type: "button", class: "btn primary", text: "Remove it from this article", onclick: () => send(null) }),
        h("div", { class: "muted", text: "Only this article changes. It will not be added to it again." }),
        why.names.slice(0, 4).map((n) => [
          h("button", { type: "button", class: "btn", text: `Stop matching “${n}” everywhere`, onclick: () => send(n) }),
          h("div", { class: "muted", text: `No article is tagged ${t.id} because of “${n}” any more. You can bring it back in Settings → Appearance & reading.` })]),
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: close })));
  }

  document.addEventListener("DOMContentLoaded", () => {
    const d = dlg();
    if (d) d.addEventListener("click", (e) => { if (e.target === d) close(); });  // click on the backdrop
  });

  // ===================================================================== threat actors
  const FLAG = (cc) => (/^[A-Z]{2}$/.test(cc || "") ? String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : "");
  const KIND_TEXT = { state: "state-linked", crime: "eCrime", hacktivist: "hacktivist" };
  let actorTimer = null;
  /** 🎭 Threat actors: every tracked actor (the same actor under several vendor names counts once) with its
   *  articles, videos and podcast episodes for the chosen period. */
  async function actors(query) {
    const days = periodDays();
    const q = String(query || "");
    const data = await guarded(() => api("GET", `/threat-actors?days=${days}&limit=300${q ? `&q=${encodeURIComponent(q)}` : ""}`));
    if (!data) return;
    const search = h("input", { type: "search", value: q, placeholder: "Find an actor or alias (Fancy Bear, VOLTZITE, Scattered Spider…)", "aria-label": "Find a threat actor",
      class: "actor-search" });
    search.addEventListener("input", () => { clearTimeout(actorTimer); actorTimer = setTimeout(() => actors(search.value.trim()), 300); });
    const go = (fn) => () => { close(); fn(); };
    const list = data.items.length ? data.items.map((a) => {
      const ent = { id: a.id, name: a.name, days };
      const also = (a.also || []).slice(0, 6).join(" · ");
      return h("div", { class: "actor-row" },
        h("button", { type: "button", class: "actor-name", title: "Its page: mentions over time, latest items, what it is seen with", onclick: () => entityPage(a.id) },
          h("strong", { text: `${FLAG(a.country)} ${a.name}`.trim() }),
          h("span", { class: "muted small", text: [KIND_TEXT[a.kind], also ? `also: ${also}` : "", (a.sources || []).join(", ")].filter(Boolean).join(" · ") })),
        h("button", { type: "button", class: "btn small", disabled: !a.articles, text: `📰 ${a.articles}`, title: `List the ${a.articles} article${a.articles === 1 ? "" : "s"} that mention it (${periodText(days)})`,
          onclick: go(() => { FW.setMode("reader"); const range = document.getElementById("rangeSelect"); if (range) range.value = days ? String(days * 86400) : "";
            FW.selectView({ type: "entity", id: a.id, name: a.name }); }) }),
        h("button", { type: "button", class: "btn small", disabled: !a.videos, text: `▶ ${a.videos}`, title: `Open the Videos tab on the ${a.videos} video${a.videos === 1 ? "" : "s"} that mention it`,
          onclick: go(() => FW.library.listEntity(ent)) }),
        h("button", { type: "button", class: "btn small", disabled: !a.podcasts, text: `🎙 ${a.podcasts}`, title: `Open the Podcasts tab on the ${a.podcasts} episode${a.podcasts === 1 ? "" : "s"} that mention it`,
          onclick: go(() => FW.podcasts.listEntity(ent)) }));
    }) : h("p", { class: "muted", text: q ? `No tracked actor matches “${q}”.` : `No tracked actor is mentioned ${periodText(days)} - pick a longer period.` });
    show("actors",
      head("🎭 Threat actors", `${data.tracked.toLocaleString()} tracked · ${q ? `${data.total} match “${q}”` : `${data.total} mentioned ${periodText(days)}`} · most mentioned first`,
        periodSelect(() => actors(search.value.trim()))),
      h("div", { class: "intel-body" }, search,
        h("div", { class: "muted small", text: "Click a name for its page, 📰 to list its articles, ▶ / 🎙 for its videos and podcast episodes. The same actor under several vendor names is one entry." }),
        h("div", { class: "actor-list" }, list)));
    if (q) { search.focus(); search.setSelectionRange(q.length, q.length); }
  }

  // ===================================================================== related videos / podcasts of an article
  async function related(article, kind) {
    const data = await guarded(() => api("GET", `/articles/${Number(article.id)}/related?kind=${kind}&limit=60`));
    if (!data) return;
    const isVideo = kind === "videos";
    const tab = isVideo ? FW.library : FW.podcasts;
    show("entity",
      head(`${isVideo ? "▶ Videos" : "🎙 Podcast episodes"} related to this article`, article.title,
        data.total && tab ? h("button", { type: "button", class: "btn small primary", text: `Open all ${data.total} in ${isVideo ? "Videos" : "Podcasts"} →`,
          title: `Open the ${isVideo ? "Videos" : "Podcasts"} tab showing exactly these, on one page`, onclick: () => { close(); tab.listRelated(article); } }) : null),
      h("div", { class: "intel-body" },
        h("p", { class: "muted small", text: "Related = it names the same specific things as the article (threat actors, malware, techniques…). Rare names count most; the chips show what each one shares." }),
        data.items.length ? data.items.map((it) => h("div", { class: "related-item" }, itemRow(kind, it),
          h("div", { class: "chips related-why" }, h("span", { class: "muted small", text: "Shares:" }), (it.shared || []).map((n) => h("span", { class: "chip sub-chip", text: n })))))
          : h("p", { class: "muted", text: "Nothing related yet." }),
        data.total > data.items.length ? h("p", { class: "muted small", text: `Showing the ${data.items.length} strongest of ${data.total}. Use “Open all” for the rest.` }) : null));
  }

  FW.intel = { entityPage, techniquePage, matrix, notThis, close, actors, related };
})();
