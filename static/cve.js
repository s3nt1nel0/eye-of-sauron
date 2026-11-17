/* CVE tracking UI: sortable CVE tables, CVE detail drawer, and the Settings → CVE tracking panel.
 * Same rules as app.js: text via textContent only, links via safeUrl, no inline script/style. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, safeUrl, relTime } = FW;

  const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", NONE: "None", UNSCORED: "Unscored" };
  const SORTS = [["newest", "Newest"], ["score", "Highest CVSS"], ["kev_added", "Recently added to KEV"]];
  let metaCache = null;

  async function meta(force = false) {
    if (!metaCache || force) metaCache = await api("GET", "/cves/meta");
    return metaCache;
  }

  const fmtDate = (ts) => (ts ? FW.fmtDate(ts) : "—");

  function sevBadge(sev, score) {
    return h("span", { class: `sev sev-${String(sev).toLowerCase()}`, title: `CVSS ${score ?? "n/a"}` },
      SEV_LABEL[sev] || sev, score !== null && score !== undefined ? h("b", { text: ` ${Number(score).toFixed(1)}` }) : null);
  }

  /** Render a CVE list. opts: {onSort(sort), sort, dateField, compact} */
  function cveTable(host, items, opts = {}) {
    fill(host);
    if (!items.length) { host.append(h("div", { class: "chart-empty", text: "No matching CVEs in this period." })); return; }
    const sortBtn = (key, label) => opts.onSort
      ? h("button", { type: "button", class: `link-btn th-sort ${opts.sort === key ? "active" : ""}`, text: label + (opts.sort === key ? " ▼" : ""),
        onclick: () => opts.onSort(key) })
      : label;
    const dateKey = opts.dateField === "kev_added" ? "kev_added" : opts.dateField === "modified" ? "last_modified" : "published";
    const table = h("table", { class: "data compact cve-table" },
      h("thead", null, h("tr", null,
        h("th", null, "CVE"), h("th", null, sortBtn("score", "Severity")),
        h("th", null, sortBtn(dateKey === "kev_added" ? "kev_added" : "newest", dateKey === "kev_added" ? "KEV added" : dateKey === "last_modified" ? "Modified" : "Published")),
        opts.compact ? null : h("th", null, "Affected"), h("th", null, "Summary"))),
      h("tbody", null, items.map((c) => h("tr", { class: c.kev ? "is-kev" : "" },
        h("td", { class: "nowrap" },
          h("button", { type: "button", class: "link-btn mono", text: c.id, title: "Details", onclick: () => openCve(c.id) }),
          c.kev ? h("span", { class: "kev-flag", title: c.kev_ransomware ? "CISA KEV · known ransomware use" : "CISA Known Exploited Vulnerability", text: c.kev_ransomware ? " KEV☠" : " KEV" }) : null,
          !c.kev && c.exploitation === "active" ? h("span", { class: "kev-flag", title: "SSVC: actively exploited", text: " exploited" }) : null),
        h("td", { class: "nowrap" }, sevBadge(c.severity, c.score)),
        h("td", { class: "nowrap muted", text: fmtDate(c[dateKey]) }),
        opts.compact ? null : h("td", { class: "small", text: (c.vendors || []).slice(0, 2).join(", ") }),
        h("td", { class: "small cve-desc" },
          c.kev_name ? h("strong", { text: `${c.kev_name}. ` }) : null,
          (c.description || "").slice(0, opts.compact ? 160 : 260) + ((c.description || "").length > (opts.compact ? 160 : 260) ? "…" : ""),
          (c.categories || []).length ? h("div", { class: "chips" }, c.categories.slice(0, 4).map((k) => h("span", { class: "kw", text: k.name }))) : null)))));
    host.append(h("div", { class: "table-wrap" }, table));
  }

  async function openCve(id) {
    const drawer = document.querySelector("#drawer");
    const show = (content) => {
      fill(drawer,
        h("div", { class: "drawer-head" }, h("h3", { text: id }),
          h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => { drawer.hidden = true; } })),
        h("div", { class: "drawer-body" }, content));
      if (FW.enhanceDrawer) FW.enhanceDrawer(drawer);
      drawer.hidden = false;
    };
    show(h("div", { class: "chart-loading", text: "Loading…" }));
    let c;
    try { c = await api("GET", `/cves/${encodeURIComponent(id)}`); } catch (err) { show(h("p", { class: "error", text: err.message })); return; }
    const link = (url, text) => { const u = safeUrl(url); return u ? h("a", { href: u, target: "_blank", rel: "noopener noreferrer", text }) : null; };
    show(h("div", { class: "cve-detail" },
      h("div", { class: "row-form" }, sevBadge(c.severity, c.score), c.cvss_version ? h("span", { class: "muted small", text: `CVSS ${c.cvss_version}` }) : null,
        c.kev ? h("span", { class: "kev-flag", text: c.kev_ransomware ? "CISA KEV · ransomware" : "CISA KEV" }) : null,
        c.exploitation ? h("span", { class: "muted small", text: `SSVC exploitation: ${c.exploitation}` }) : null,
        h("span", { class: "muted small", text: c.status })),
      c.vector ? h("code", { class: "block small", text: c.vector }) : null,
      c.kev_name ? h("h4", { text: c.kev_name }) : null,
      h("p", { class: "cve-full-desc", text: c.description || "No description." }),
      h("dl", { class: "cve-facts" },
        h("dt", { text: "Published" }), h("dd", { text: fmtDate(c.published) }),
        h("dt", { text: "Last modified" }), h("dd", { text: fmtDate(c.last_modified) }),
        c.kev ? [h("dt", { text: "Added to KEV" }), h("dd", { text: fmtDate(c.kev_added) }), h("dt", { text: "CISA due date" }), h("dd", { text: fmtDate(c.kev_due) })] : null,
        h("dt", { text: "Weakness" }), h("dd", null, c.cwes.length ? c.cwes.map((w) => h("div", null, link(`https://cwe.mitre.org/data/definitions/${Number(w.id)}.html`, `CWE-${w.id}`), w.name ? ` ${w.name}` : "")) : "—"),
        h("dt", { text: "OWASP Top 10" }), h("dd", null, c.owasp.length ? c.owasp.map((o) => h("div", { text: `${o.code}:${o.edition} ${o.name}` })) : "—"),
        h("dt", { text: "Categories" }), h("dd", null, c.categories.length ? h("div", { class: "chips" }, c.categories.map((k) => h("span", { class: "kw", text: k.name }))) : "—"),
        h("dt", { text: "Affected" }), h("dd", null, c.products.length ? c.products.slice(0, 20).map((p) => h("div", { text: `${p.vendor_label} ${p.product_label}` })) : "—")),
      h("div", { class: "row-form" }, link(c.links.nvd, "NVD ↗"), link(c.links.cve_org, "CVE.org ↗")),
      c.refs.length ? h("div", null, h("h4", { text: "References" }), h("ul", { class: "small refs" }, c.refs.map((r) => h("li", null, link(r, r))))) : null));
  }

  // ===================================================================== settings panel
  async function renderPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    let s, m;
    try { [s, m] = await Promise.all([api("GET", "/cves/status"), meta(true)]); } catch (err) { fill(panel, h("p", { class: "error", text: err.message })); return; }
    const rerender = () => renderPanel(panel);
    const settings = FW.state.settings;
    const save = async (key, value) => {
      const res = await guarded(() => api("PATCH", "/settings", { [key]: value }), "Saved");
      if (res) Object.assign(FW.state.settings, res);
    };
    const enabled = h("input", { type: "checkbox", id: "cve-enabled", checked: settings.cve_enabled });
    enabled.addEventListener("change", () => save("cve_enabled", enabled.checked));
    const backfill = h("input", { type: "number", id: "cve-backfill", min: 1, max: 365, value: settings.cve_backfill_days });
    backfill.addEventListener("change", () => { const n = Number(backfill.value); if (Number.isInteger(n)) save("cve_backfill_days", n); });
    const every = h("select", { id: "cve-every" }, [[30, "30 minutes"], [60, "1 hour"], [120, "2 hours"], [360, "6 hours"], [720, "12 hours"], [1440, "Daily"]]
      .map(([v, l]) => h("option", { value: v, text: l, selected: Number(settings.cve_sync_minutes) === v })));
    every.addEventListener("change", () => save("cve_sync_minutes", Number(every.value)));
    const p = s.progress || {};
    const statusLine = s.running
      ? `⏳ Syncing — ${p.phase || "working"}${p.total ? ` (${p.done}/${p.total})` : ""}`
      : s.last_finished ? `Last sync ${relTime(s.last_finished)}` : "Not synced yet";

    const catList = h("div");
    fill(catList, m.categories.map((c) => categoryCard(c, rerender)));
    fill(panel,
      h("p", { class: "muted" }, "CVE data comes straight from the official sources: the ",
        h("strong", { text: "NVD CVE API 2.0" }), " (NIST's replacement for its retired RSS/JSON feeds), the ",
        h("strong", { text: "CISA Known Exploited Vulnerabilities" }), " catalog, and the ", h("strong", { text: "MITRE CWE" }),
        " catalog with its official OWASP Top 10 mappings. Build CVE widgets in Dashboards (template: “CVE tracker”)."),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("strong", { text: statusLine }),
          h("div", { class: "actions" },
            h("button", { type: "button", class: "btn small", text: "Sync now", disabled: s.running, onclick: async () => {
              if (await guarded(() => api("POST", "/cves/sync", { force: false }), "Sync started")) setTimeout(rerender, 1500);
            } }),
            h("button", { type: "button", class: "btn small", text: "Full refresh (incl. CWE & KEV)", disabled: s.running, onclick: async () => {
              if (await guarded(() => api("POST", "/cves/sync", { force: true }), "Sync started")) setTimeout(rerender, 1500);
            } }),
            h("button", { type: "button", class: "btn small", text: "↻", title: "Refresh status", onclick: rerender }))),
        h("div", { class: "muted small" },
          `${(s.total || 0).toLocaleString()} CVEs stored · ${(s.critical || 0).toLocaleString()} critical · ${(s.kev || 0).toLocaleString()} in CISA KEV · ${s.cwe_entries} CWE entries`,
          s.oldest ? ` · published ${fmtDate(s.oldest)} – ${fmtDate(s.newest)}` : ""),
        s.reclassifying ? h("div", { class: "muted small", text: "⏳ Re-classifying CVEs after a category change…" }) : null,
        s.last_error ? h("p", { class: "error small", text: s.last_error }) : null,
        h("div", { class: "muted small", text: s.nvd_api_key
          ? "NVD API key configured — fast sync."
          : "No NVD API key: syncing is limited to 5 requests per 30 s (the first back-fill takes a few minutes). A free key (nvd.nist.gov/developers/request-an-api-key) set as FEEDWARDEN_NVD_API_KEY makes it ~10× faster." })),
      h("div", { class: "panel-section" }, h("h4", { text: "Sync" }),
        h("div", { class: "grid-form" },
          h("label", { for: "cve-enabled", text: "Track CVEs" }), enabled,
          h("label", { for: "cve-backfill", text: "Initial history (days)" }), backfill,
          h("div", { class: "hint", text: "How far back the first sync goes (~1,000–2,500 new CVEs per day). Raising it later re-runs the back-fill only if the gap is large; use Full refresh." }),
          h("label", { for: "cve-every", text: "Check for changes every" }), every)),
      h("div", { class: "panel-section" },
        h("div", { class: "card-head" }, h("h4", { text: "Categories" }),
          h("button", { type: "button", class: "btn small primary", text: "+ New category", onclick: () => catList.prepend(categoryForm(null, rerender)) })),
        h("p", { class: "muted small", text: "A CVE joins a category when any CWE, keyword (whole word, in the description) or product pattern matches. Product patterns: vendor · vendor:product · *:product · prefix* (lowercase letters/digits, e.g. fortinet:fortios, microsoft:windows*). Changes re-classify all stored CVEs." }),
        catList));
  }

  function categoryCard(c, rerender) {
    const card = h("div", { class: "card" },
      h("div", { class: "card-head" },
        h("strong", { text: `${c.enabled ? "" : "⏸ "}${c.name}` }),
        h("div", { class: "actions" },
          h("span", { class: "muted small", text: `${c.cve_count.toLocaleString()} CVEs` }),
          h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => card.replaceWith(categoryForm(c, rerender)) }),
          h("button", { type: "button", class: "btn small", text: c.enabled ? "Disable" : "Enable", onclick: async () => {
            if (await guarded(() => api("PATCH", `/cves/categories/${c.id}`, { enabled: !c.enabled }))) rerender();
          } }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
            if (window.confirm(`Delete category “${c.name}”?${c.builtin ? " (built-in: it will not come back)" : ""}`) &&
              await guarded(() => api("DELETE", `/cves/categories/${c.id}`), "Deleted")) rerender();
          } }))),
      c.description ? h("div", { class: "muted small", text: c.description }) : null,
      h("div", { class: "muted small", text: [
        c.cwe_ids.length ? `CWE: ${c.cwe_ids.slice(0, 12).join(", ")}${c.cwe_ids.length > 12 ? "…" : ""}` : null,
        c.keywords.length ? `Keywords: ${c.keywords.slice(0, 6).join(", ")}${c.keywords.length > 6 ? "…" : ""}` : null,
        c.products.length ? `Products: ${c.products.length} pattern(s)` : null].filter(Boolean).join(" · ") }));
    return card;
  }

  function categoryForm(c, rerender) {
    const split = (v) => v.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
    const name = h("input", { type: "text", maxlength: 100, required: true, value: c ? c.name : "", placeholder: "e.g. Our vendors" });
    const desc = h("input", { type: "text", maxlength: 300, value: c ? c.description : "" });
    const cwes = h("input", { type: "text", value: c ? c.cwe_ids.join(", ") : "", placeholder: "79, 89, 502" });
    const kws = h("textarea", { rows: 2, value: c ? c.keywords.join(", ") : "", placeholder: "remote code execution, firewall" });
    const prods = h("textarea", { rows: 3, value: c ? c.products.join(", ") : "", placeholder: "fortinet:fortios, paloaltonetworks, *:pytorch, microsoft:windows*" });
    const err = h("p", { class: "error" });
    const form = h("form", { class: "card" },
      h("div", { class: "grid-form" },
        h("label", { text: "Name" }), name, h("label", { text: "Description" }), desc,
        h("label", { text: "CWE IDs" }), cwes, h("label", { text: "Keywords" }), kws,
        h("label", { text: "Product patterns" }), prods),
      err,
      h("div", { class: "form-actions" },
        h("button", { type: "button", class: "btn", text: "Cancel", onclick: rerender }),
        h("button", { type: "submit", class: "btn primary", text: c ? "Save" : "Create" })));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const ids = split(cwes.value).map((x) => Number(x.replace(/^cwe-/i, ""))).filter((n) => Number.isInteger(n) && n > 0);
      const body = { name: name.value.trim(), description: desc.value.trim(), cwe_ids: ids, keywords: split(kws.value), products: split(prods.value).map((x) => x.toLowerCase()) };
      try {
        await api(c ? "PATCH" : "POST", c ? `/cves/categories/${c.id}` : "/cves/categories", body);
        toast("Saved — re-classifying stored CVEs in the background");
        rerender();
      } catch (ex) { err.textContent = ex.message; }
    });
    return form;
  }

  FW.cve = { meta, cveTable, openCve, renderPanel, sevBadge, SORTS, SEV_LABEL };
})();
