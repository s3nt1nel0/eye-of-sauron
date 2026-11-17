/* 🌍 Threat Map: a world map of where threats in YOUR feeds are reported, plus links to the public
 * live-attack maps run by security vendors (Kaspersky, Check Point, Fortinet…).
 *
 * Data = article mentions: for each country, how many articles in the period mention that country
 * together with the chosen threat (a category such as ransomware, one specific actor or malware family,
 * and optionally an attack method). The same filter drives the "sectors targeted" list. It is
 * reporting, not attack telemetry. The vendors' live maps have no public APIs, so they are linked, not
 * scraped or embedded.
 * Same rules as app.js: DOM built with h(), text via textContent, links via safeUrl. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, relTime, safeUrl } = FW;
  const $ = (sel) => document.querySelector(sel);
  const SVG = "http://www.w3.org/2000/svg";

  // `lists` filter the map; `actors` are the watchlists offered in the "Actor / family" picker.
  const LAYERS = [
    { key: "threat", label: "Threat actors & APTs", lists: ["threat-actors", "ot-threat-actors"] },
    { key: "ransomware", label: "Ransomware", lists: ["ransomware-groups"] },
    { key: "ot", label: "OT / ICS threat groups & ICS malware", lists: ["ot-threat-actors", "ics-malware"], attacks: "ot-attack-types" },
    { key: "ot-all", label: "All OT / ICS coverage", lists: ["ot-threat-actors", "ics-malware", "ot-context"],
      actors: ["ot-threat-actors", "ics-malware"], attacks: "ot-attack-types" },
    { key: "malware", label: "Malware families", lists: ["malware-families"] },
    { key: "all", label: "All coverage", lists: [], allLabel: "All actors & families",
      actors: ["threat-actors", "ransomware-groups", "ot-threat-actors", "malware-families", "ics-malware"] },
  ];
  // Attack-type picker: the general "attack-types" list; OT categories use the OT-specific methods.
  function attackList() { return st.lists[layer().attacks || "attack-types"] || st.lists["attack-types"] || st.lists["ot-attack-types"]; }
  const SECTOR_LISTS = ["sectors", "ot-sectors"];
  const PERIODS = [[7, "7 days"], [30, "30 days"], [90, "90 days"], [365, "1 year"], [3650, "All time"]];
  // Our watchlist names → map (Natural Earth) names, where they differ.
  const NAME_FIX = { "United States": "United States of America", "Türkiye": "Turkey" };

  const MONITORS = [
    ["Kaspersky Cybermap", "Kaspersky", "https://cybermap.kaspersky.com/", "Detections from Kaspersky products worldwide: file, web, mail and network attacks on an animated globe."],
    ["Check Point Live Cyber Threat Map", "Check Point", "https://threatmap.checkpoint.com/", "Attacks seen by Check Point gateways, with top targeted countries and industries."],
    ["FortiGuard Threat Map", "Fortinet", "https://threatmap.fortiguard.com/", "Intrusion, malware and botnet activity observed by Fortinet sensors."],
    ["Radware Live Threat Map", "Radware", "https://livethreatmap.radware.com/", "Attacks against Radware's global honeypot and sensor network."],
    ["Bitdefender Threat Map", "Bitdefender", "https://threatmap.bitdefender.com/", "Infections, attacks and spam reported by Bitdefender."],
    ["Cyber Threat Horizon", "NETSCOUT", "https://horizon.netscout.com/", "DDoS attack activity and trends from NETSCOUT's visibility."],
    ["Digital Attack Map", "Google Jigsaw & NETSCOUT", "https://www.digitalattackmap.com/", "Visualisation of DDoS attacks (data may be historical)."],
    ["Talos Intelligence Map", "Cisco Talos", "https://talosintelligence.com/fullpage_maps/pulse/", "Email and web threat traffic from Cisco Talos telemetry."],
    ["Worldwide Attacks", "SonicWall", "https://securitycenter.sonicwall.com/m/page/worldwide-attacks", "Attacks seen by the SonicWall Capture Threat Network."],
    ["Cyber Threat Attack Map", "Imperva", "https://www.imperva.com/cyber-threat-attack-map/", "Web application and DDoS attacks blocked by Imperva."],
    ["HTTPCS Cyber Map", "HTTPCS", "https://map.httpcs.com/", "Web attacks observed on websites scanned by HTTPCS."],
  ];

  const st = {
    layer: FW.store.get("fw-tm-layer", "threat"),
    days: Number(FW.store.get("fw-tm-days", 30)) || 30,
    actor: Number(FW.store.get("fw-tm-actor", 0)) || 0,     // entity id, 0 = whole category
    attack: Number(FW.store.get("fw-tm-attack", 0)) || 0,   // entity id, 0 = any method
    geo: null, lists: null, counts: new Map(), unmapped: [], sectors: [], actors: [], attacks: [], total: 0,
    selected: null, loaded: false, token: 0, labels: new Map(),
  };

  async function loadBase() {
    if (!st.geo) st.geo = await fetch("/static/world-map.json", { credentials: "same-origin" }).then((r) => r.json());
    const wl = await api("GET", "/watchlists");
    st.lists = Object.fromEntries(wl.filter((w) => w.slug).map((w) => [w.slug, w.id]));
  }

  function layer() { return LAYERS.find((l) => l.key === st.layer) || LAYERS[0]; }
  const listIds = (slugs) => slugs.map((s) => st.lists[s]).filter(Boolean);

  /** The current threat filter: one actor/family, or the whole category; plus the attack method. */
  function threatFilter(extraRequire = []) {
    const f = st.actor ? { entity_ids: [st.actor] } : (listIds(layer().lists).length ? { watchlist_ids: listIds(layer().lists) } : {});
    const req = [...(st.attack ? [st.attack] : []), ...extraRequire];
    if (req.length) f.require_entity_ids = req;
    return f;
  }

  const breakdown = (watchlistId, filters, limit = 50) => api("POST", "/analytics/query", {
    type: "breakdown", days: st.days, group_by: "watchlist", group_watchlist_id: watchlistId, limit, filters,
  }).then((r) => r.items || []);

  /** Merge breakdowns over several watchlists (e.g. general + OT sectors), de-duplicated by name. */
  async function mergedBreakdown(slugs, filters, limit = 50) {
    const lists = await Promise.all(listIds(slugs).map((id) => breakdown(id, filters, limit)));
    const byName = new Map();
    for (const it of lists.flat()) {
      const k = it.label.toLowerCase();
      const prev = byName.get(k);
      if (!prev || it.count > prev.count) byName.set(k, it);
    }
    return [...byName.values()].sort((a, b) => b.count - a.count);
  }

  async function loadAll() {
    const token = ++st.token;
    const countries = st.lists.countries;
    const filters = threatFilter();
    const actorFilter = st.attack ? { require_entity_ids: [st.attack] } : {};
    const base = st.actor ? { entity_ids: [st.actor] } : threatFilter();
    if (base.require_entity_ids) delete base.require_entity_ids;
    const [actors, attacks, countryItems, sectors, kpi] = await Promise.all([
      mergedBreakdown(layer().actors || layer().lists.filter((s) => s !== "ot-context"), actorFilter),
      attackList() ? breakdown(attackList(), base, 30) : [],
      countries ? breakdown(countries, filters, 50) : [],
      mergedBreakdown(SECTOR_LISTS, filters, 30),
      api("POST", "/analytics/query", { type: "kpi", days: st.days, filters }),
    ]);
    if (token !== st.token) return false;   // a newer refresh superseded this one
    st.actors = actors;
    st.attacks = attacks;
    st.sectors = sectors;
    st.total = kpi.value || 0;
    for (const it of [...actors, ...attacks]) st.labels.set(it.key, it.label);
    st.counts = new Map();
    st.unmapped = [];
    const mapNames = new Set(st.geo.countries.map((c) => c.name));
    for (const it of countryItems) {
      const name = NAME_FIX[it.label] || it.label;
      if (mapNames.has(name)) st.counts.set(name, { count: it.count, entityId: it.key, label: it.label });
      else st.unmapped.push({ label: it.label, count: it.count, entityId: it.key });
    }
    return true;
  }

  // 5-step multi-hue heat scale (yellow → orange → red → crimson → purple), quantised on a log scale so
  // a few hot spots don't wash out everything else. Level 0 = no mentions (neutral grey).
  function level(count, max) {
    if (!count) return 0;
    if (max <= 1) return 5;
    const t = Math.log(count) / Math.log(max);
    return Math.min(5, 1 + Math.floor(t * 4.999));
  }

  /** Legend rows [level, lo, hi]: walk the counts once so each colour shows the exact range it covers
   *  (with small maxima some colours are simply unused, instead of repeating the same number). */
  function legendBounds(max) {
    const rows = [];
    for (let n = 1; n <= max; n++) {
      const lv = level(n, max);
      const last = rows[rows.length - 1];
      if (last && last[0] === lv) last[2] = n;
      else rows.push([lv, n, n]);
    }
    return rows;
  }

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  /** "LockBit · Ransomware · via Phishing" — what the map currently shows. */
  function focusLabel() {
    const parts = [st.actor ? (st.labels.get(st.actor) || "Selected actor") : layer().label];
    if (st.attack) parts.push(`via ${st.labels.get(st.attack) || "selected attack type"}`);
    return parts.join(" · ");
  }

  function mapMax() { return Math.max(0, ...[...st.counts.values()].map((v) => v.count), ...st.unmapped.map((u) => u.count)); }

  function renderMap(container) {
    const g = st.geo;
    const max = mapMax();
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${g.width} ${g.height}`);
    svg.setAttribute("class", "tm-svg");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `World map: ${focusLabel()}, last ${st.days} days`);
    const tip = h("div", { class: "tm-tip", hidden: true });
    for (const c of g.countries) {
      const v = st.counts.get(c.name);
      const p = document.createElementNS(SVG, "path");
      p.setAttribute("d", c.d);
      p.setAttribute("class", `tm-country tm-l${level(v ? v.count : 0, max)}${st.selected === c.name ? " selected" : ""}`);
      const t = document.createElementNS(SVG, "title");
      t.textContent = v ? `${c.name}: ${plural(v.count, "article")}` : c.name;
      p.append(t);
      if (v) {
        p.setAttribute("tabindex", "0");
        const select = () => selectCountry(c.name, v.entityId, v.label);
        p.addEventListener("click", select);
        p.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(); } });
      }
      p.addEventListener("mousemove", (e) => {
        const box = container.getBoundingClientRect();
        tip.hidden = false;
        fill(tip, h("strong", { text: c.name }), h("div", { text: v ? `${plural(v.count, "article")} · ${focusLabel()}` : "no mentions in this period" }),
          v ? h("div", { class: "muted tiny", text: "Click for sectors and articles" }) : null);
        tip.style.setProperty("left", `${Math.min(e.clientX - box.left + 14, box.width - 230)}px`);
        tip.style.setProperty("top", `${e.clientY - box.top + 14}px`);
      });
      p.addEventListener("mouseleave", () => { tip.hidden = true; });
      svg.append(p);
    }
    const legend = max ? h("div", { class: "tm-legend" }, h("span", { class: "muted small", text: "Articles:" }),
      h("span", { class: "tm-legend-item" }, h("span", { class: "tm-swatch tm-l0" }), "none"),
      legendBounds(max).map(([lv, lo, hi]) => h("span", { class: "tm-legend-item" }, h("span", { class: `tm-swatch tm-l${lv}` }), lo === hi ? String(lo) : `${lo}–${hi}`)),
      h("span", { class: "muted tiny", text: "(yellow = few, purple = most)" }))
      : h("div", { class: "tm-legend muted small", text: "No country mentions for this selection and period." });
    fill(container, svg, tip, legend, h("div", { class: "muted tiny tm-attrib", text: g.attribution }));
  }

  /** A ranked bar list; colours follow the same heat scale as the map so the two read together. */
  function bars(items, isSelected, onPick) {
    const max = Math.max(1, ...items.map((x) => x.count));
    return h("ol", { class: "tm-bars" }, items.map((x) => h("li", { class: isSelected(x) ? "selected" : "" },
      h("button", { type: "button", class: "tm-bar-btn", onclick: () => onPick(x) },
        h("span", { class: "tm-bar-label", text: x.display || x.label, title: x.display || x.label }),
        h("span", { class: "tm-bar-track" }, h("span", { class: `tm-bar-fill tm-l${level(x.count, max)}`, style: { width: `${(x.count / max) * 100}%` } })),
        h("span", { class: "tm-bar-num", text: String(x.count) })))));
  }

  function countryList() {
    const ranked = [...[...st.counts.entries()].map(([name, v]) => ({ name, ...v })), ...st.unmapped.map((u) => ({ name: u.label, ...u, display: `${u.label} (not on map)` }))]
      .sort((a, b) => b.count - a.count);
    const all = ranked.slice(0, 20);
    return h("div", { class: "tm-top" }, h("h3", { text: `Countries (${ranked.length}${ranked.length > all.length ? `, top ${all.length} shown` : ""})` }),
      all.length ? bars(all, (x) => st.selected === x.name, (x) => selectCountry(x.name, x.entityId, x.label))
        : h("p", { class: "muted small", text: "Nothing yet — try a longer period or another selection." }));
  }

  function sectorList() {
    const top = st.sectors.slice(0, 12);
    return h("div", { class: "tm-top" }, h("h3", { text: `Sectors targeted (${st.sectors.length}${st.sectors.length > top.length ? `, top ${top.length} shown` : ""})` }),
      top.length ? bars(top, (x) => st.selected === `sector:${x.key}`, (x) => selectSector(x))
        : h("p", { class: "muted small", text: "No sector mentions for this selection." }));
  }

  function selectCountry(name, entityId, label) {
    st.selected = name;
    renderAll();
    showDetail(label || name, entityId, SECTOR_LISTS, "Sectors in this country");
  }

  function selectSector(x) {
    st.selected = `sector:${x.key}`;
    renderAll();
    showDetail(x.label, x.key, ["countries"], "Countries for this sector");
  }

  /** Detail panel: the other dimension (sectors for a country, countries for a sector) + articles. */
  async function showDetail(title, entityId, otherLists, otherTitle) {
    const box = st.detailEl;
    if (!box || !entityId) return;
    const token = st.token;
    fill(box, h("p", { class: "muted small", text: "Loading…" }));
    const filters = threatFilter([entityId]);
    const [res, other] = await Promise.all([
      api("POST", "/analytics/query", { type: "articles", days: st.days, limit: 15, filters }).catch(() => null),
      mergedBreakdown(otherLists, filters, 12).catch(() => []),
    ]);
    if (token !== st.token) return;
    const items = (res && res.items) || [];
    fill(box, h("div", { class: "tm-detail-head" }, h("h3", { text: `${title} · ${focusLabel()}` }),
      h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => { st.selected = null; fill(box); renderAll(); } })),
    other.length ? h("div", { class: "tm-chips" }, h("span", { class: "muted small", text: `${otherTitle}:` }),
      other.map((o) => h("span", { class: "tm-chip" }, o.label, h("b", { text: String(o.count) })))) : null,
    items.length ? h("ul", { class: "tm-articles" }, items.map((a) => h("li", null,
      h("a", { href: "#", text: a.title, onclick: (e) => { e.preventDefault(); FW.openArticleInReader(a.id); } }),
      h("div", { class: "muted small" }, `${a.feed_title} · ${relTime(a.sort_ts)} · `,
        safeUrl(a.url) ? h("a", { href: safeUrl(a.url), target: "_blank", rel: "noopener noreferrer", text: "original ↗" }) : null))))
      : h("p", { class: "muted small", text: "No articles." }));
  }

  function monitorsCard() {
    return h("section", { class: "tm-monitors" },
      h("h3", { text: "Live attack maps from security vendors" }),
      h("p", { class: "muted small", text: "Real-time telemetry maps run by vendors on their own sensors. They have no public data feeds, so Eye of Sauron links to them instead of copying their data; each opens in a new tab." }),
      h("div", { class: "tm-monitor-grid" }, MONITORS.map(([name, vendor, url, desc]) => {
        const link = safeUrl(url);
        return h("a", { class: "tm-monitor card", href: link, target: "_blank", rel: "noopener noreferrer" },
          h("strong", { text: name }), h("span", { class: "muted small", text: vendor }), h("span", { class: "small", text: desc }),
          h("span", { class: "tm-open small", text: "Open ↗" }));
      })));
  }

  function setAndRefresh(key, value, storeKey) {
    st[key] = value;
    FW.store.set(storeKey, value);
    st.selected = null;
    if (st.detailEl) fill(st.detailEl);
    return refresh();
  }

  function pickers() {
    const layerSel = h("select", { "aria-label": "Threat category", title: "Threat category",
      onchange: async (e) => {
        st.actor = 0; FW.store.set("fw-tm-actor", 0);
        st.attack = 0; FW.store.set("fw-tm-attack", 0);   // attack lists differ between OT and general categories
        await setAndRefresh("layer", e.target.value, "fw-tm-layer");
      } },
    LAYERS.map((l) => h("option", { value: l.key, text: l.label, selected: l.key === st.layer })));

    // Only actors active in the period (with the chosen attack method) are offered, with their counts.
    const actorOpts = [...st.actors];
    if (st.actor && !actorOpts.some((a) => a.key === st.actor)) actorOpts.unshift({ key: st.actor, label: st.labels.get(st.actor) || "Selected", count: 0 });
    const actorSel = h("select", { "aria-label": "Actor or family", title: "Pick one actor / group / family",
      onchange: (e) => setAndRefresh("actor", Number(e.target.value), "fw-tm-actor") },
    h("option", { value: 0, text: `${layer().allLabel || `All ${layer().label.toLowerCase()}`} (${actorOpts.length} active)`, selected: !st.actor }),
    actorOpts.map((a) => h("option", { value: a.key, text: `${a.label} (${a.count})`, selected: a.key === st.actor })));

    const attackOpts = [...st.attacks];
    if (st.attack && !attackOpts.some((a) => a.key === st.attack)) attackOpts.unshift({ key: st.attack, label: st.labels.get(st.attack) || "Selected", count: 0 });
    const attackSel = h("select", { "aria-label": "Attack type", title: "Narrow to one attack type (edit the lists under Settings → Watchlists)",
      onchange: (e) => setAndRefresh("attack", Number(e.target.value), "fw-tm-attack") },
    h("option", { value: 0, text: "Any attack type", selected: !st.attack }),
    attackOpts.map((a) => h("option", { value: a.key, text: `${a.label} (${a.count})`, selected: a.key === st.attack })));

    const periodSel = h("select", { "aria-label": "Period", onchange: (e) => setAndRefresh("days", Number(e.target.value), "fw-tm-days") },
      PERIODS.map(([d, l]) => h("option", { value: d, text: l, selected: d === st.days })));

    const reset = (st.actor || st.attack) ? h("button", { type: "button", class: "btn small", text: "Clear focus",
      onclick: async () => { st.actor = 0; FW.store.set("fw-tm-actor", 0); await setAndRefresh("attack", 0, "fw-tm-attack"); } }) : null;
    return [layerSel, actorSel, attackSel, periodSel, reset];
  }

  function summary() {
    const nCountries = st.counts.size + st.unmapped.length;
    const period = (PERIODS.find(([d]) => d === st.days) || [0, `${st.days} days`])[1].toLowerCase();
    return h("div", { class: "tm-summary" },
      h("strong", { text: focusLabel() }),
      h("span", { class: "muted", text: ` — ${plural(st.total, "article")} in the last ${period}, mentioning ${nCountries === 1 ? "1 country" : `${nCountries} countries`} and ${plural(st.sectors.length, "sector")}.` }));
  }

  function renderAll() {
    const view = $("#threatmapView");
    const mapBox = h("div", { class: "tm-map card" });
    st.detailEl = st.detailEl || h("div", { id: "tmDetail", class: "tm-detail" });
    fill(view,
      h("div", { class: "studio-header tm-header" }, h("h2", { text: "🌍 Threat Map" }), ...pickers(),
        h("button", { type: "button", class: "icon-btn", title: "Refresh", "aria-label": "Refresh", text: "⟳", onclick: refresh })),
      h("p", { class: "muted small tm-note", text: "Where threats in your feeds are reported — article mentions, not attack telemetry. Pick a category, then one actor or family and/or an attack type to see the countries and sectors it was reported against." }),
      summary(),
      h("div", { class: "tm-grid" }, h("div", { class: "tm-main" }, mapBox, st.detailEl),
        h("div", { class: "tm-side card" }, countryList(), sectorList())),
      monitorsCard());
    renderMap(mapBox);
  }

  async function refresh() {
    try {
      if (!(await loadAll())) return;
    } catch (err) {
      fill($("#threatmapView"), h("p", { class: "error", text: err.message }));
      return;
    }
    renderAll();
  }

  FW.threatmap = {
    async show() {
      const view = $("#threatmapView");
      if (!st.loaded) fill(view, h("p", { class: "muted lib-pad", text: "Loading map…" }));
      try { await loadBase(); st.loaded = true; } catch (err) { fill(view, h("p", { class: "error", text: `Could not load the map: ${err.message}` })); return; }
      await refresh();
    },
    hide() { /* nothing to tear down */ },
  };
})();
