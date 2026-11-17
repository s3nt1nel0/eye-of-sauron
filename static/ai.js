/* Stage 3 UI: AI provider settings, ✨ Summarize in the reader, and the "Alerts & digests" panel
 * (delivery channels, CVE alert rules, scheduled digests, alert log).
 * Same rules as app.js: textContent only (AI output is untrusted text), links via safeUrl. */
(function () {
  "use strict";
  const FW = window.FW;
  if (!FW) return;
  const { api, h, fill, toast, guarded, relTime, fullDate } = FW;
  const $ = (sel) => document.querySelector(sel);
  const row = (label, control, hint) => [h("label", { text: label }), control, hint ? h("div", { class: "hint", text: hint }) : null];
  const card = (title, ...children) => h("div", { class: "panel-section card" }, h("h4", { text: title }), ...children);
  const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  // ======================================================================= reader: summaries
  function showSummary(data, articleId) {
    const box = $("#aiSummary");
    if (!box || (FW.state.current && FW.state.current.id !== articleId)) return;
    box.hidden = false;
    fill(box,
      h("div", { class: "ai-summary-head" },
        h("strong", { text: "✨ AI summary" }),
        h("span", { class: "muted small", text: `${data.model} · ${relTime(data.created_at)}` }),
        h("span", { class: "spacer" }),
        h("button", { type: "button", class: "btn small", text: "Regenerate", onclick: () => summarize(articleId, true) })),
      h("div", { class: "ai-summary-text", text: data.summary }),  // untrusted model output: text only
      h("div", { class: "muted small", text: "AI-generated from the article text — check the original before acting on it." }));
  }

  async function loadCached(articleId) {
    const data = await api("GET", `/articles/${articleId}/summary`).catch(() => null);
    if (data && data.summary) showSummary(data, articleId);
  }

  async function summarize(articleId, force) {
    const box = $("#aiSummary");
    if (box) { box.hidden = false; fill(box, h("p", { class: "muted", text: "✨ Summarising…" })); }
    try {
      showSummary(await api("POST", `/articles/${articleId}/summary`, { force }), articleId);
    } catch (err) {
      if (box) fill(box, h("p", { class: "error", text: err.message }),
        /Settings → AI|configured|API key/.test(err.message) ? h("button", { type: "button", class: "btn small", text: "Open Settings → AI", onclick: () => FW.openSettings("ai") }) : null);
    }
  }

  // ======================================================================= Settings → AI
  const PROVIDER_LABEL = { anthropic: "Claude (Anthropic)", openai: "OpenAI", gemini: "Google Gemini", openai_compatible: "OpenAI-compatible / local (Ollama, LM Studio, vLLM…)" };
  const MODEL_HINT = {
    anthropic: "Default claude-opus-5-5. Other current models: claude-sonnet-5-5, claude-haiku-5-5, claude-fable-5-2.",
    openai: "Enter the model name exactly as shown in your OpenAI dashboard.",
    gemini: "Enter the Gemini model name from Google AI Studio.",
    openai_compatible: "The model name your server knows (for Ollama: the name from `ollama list`).",
  };

  async function settingsPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    let st;
    try { st = await api("GET", "/ai/settings"); } catch (err) { fill(panel, h("p", { class: "error", text: err.message })); return; }
    const c = st.config;
    const provider = h("select", null, h("option", { value: "none", text: "— AI off —" }),
      st.providers.map((p) => h("option", { value: p, text: PROVIDER_LABEL[p] || p, selected: c.provider === p })));
    const model = h("input", { type: "text", maxlength: 100, value: c.model || "", placeholder: "model name" });
    const modelHint = h("div", { class: "hint" });
    const baseUrl = h("input", { type: "url", maxlength: 300, value: c.base_url || "", placeholder: "http://ollama:11434/v1" });
    const effort = h("select", null, ["low", "medium", "high", "xhigh", "max"].map((e) => h("option", { value: e, text: e, selected: c.effort === e })));
    const key = h("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder: st.api_key_set ? "•••••• (set — leave empty to keep)" : "API key" });
    const limit = h("input", { type: "number", min: 0, max: 100000, value: c.daily_limit });
    const maxIn = h("input", { type: "number", min: 1000, max: 200000, step: 1000, value: c.max_input_chars });
    const language = h("input", { type: "text", maxlength: 40, value: c.language });
    const style = h("select", null, [["bullets", "Bullet points"], ["paragraph", "Paragraph"]].map(([v, l]) => h("option", { value: v, text: l, selected: c.summary_style === v })));
    const baseRow = row("Server base URL", baseUrl, "OpenAI-compatible endpoint, usually ending in /v1. May be on your LAN (the one SSRF exception, set by you only).");
    const effortRow = row("Effort (Claude)", effort, "How hard Claude thinks. medium is the model default; low is cheaper and fine for summaries.");
    const sync = () => {
      const p = provider.value;
      for (const el of baseRow) if (el) el.hidden = p !== "openai_compatible";
      for (const el of effortRow) if (el) el.hidden = p !== "anthropic";
      modelHint.textContent = MODEL_HINT[p] || "";
      if (p === "anthropic" && !model.value) model.value = st.default_models.anthropic;
    };
    provider.addEventListener("change", sync);
    const result = h("div", { class: "small" });
    const save = async (e) => {
      e.preventDefault();
      const body = { provider: provider.value, daily_limit: Number(limit.value), max_input_chars: Number(maxIn.value),
        language: language.value.trim(), summary_style: style.value, effort: effort.value };
      if (model.value.trim()) body.model = model.value.trim();
      if (provider.value === "openai_compatible" && baseUrl.value.trim()) body.base_url = baseUrl.value.trim();
      if (key.value.trim()) body.api_key = key.value.trim();
      if (await guarded(() => api("PUT", "/ai/settings", body), "AI settings saved")) settingsPanel(panel);
    };
    const usageRows = (st.usage || []).map((u) => h("tr", null, h("td", { text: u.day }), h("td", { text: String(u.requests) }),
      h("td", { text: u.tokens_in.toLocaleString() }), h("td", { text: u.tokens_out.toLocaleString() }), h("td", { text: String(u.failures) })));
    fill(panel,
      h("p", { class: "muted", text: "One AI provider powers article summaries (✨ Summarize, or automatically via rules), digest briefings and CVE alert explanations." }),
      st.configured ? h("p", { class: "status-ok", text: `✓ Using ${PROVIDER_LABEL[c.provider]} · ${c.model}` }) : h("p", { class: "muted", text: "AI is not configured yet." }),
      h("form", { class: "grid-form card", onsubmit: save },
        ...row("Provider", provider),
        ...row("Model", model), h("span"), modelHint,
        ...baseRow, ...effortRow,
        ...row("API key", h("div", { class: "row-form" }, key,
          st.api_key_set ? h("button", { type: "button", class: "btn small danger", text: "Remove key", onclick: async () => {
            if (await guarded(() => api("PUT", "/ai/settings", { clear_api_key: true }), "Key removed")) settingsPanel(panel);
          } }) : null), "Stored encrypted; never shown again. Not needed for most local servers."),
        ...row("Daily request limit", limit, "Hard cap per UTC day across summaries, digests and alerts (0 turns AI off)."),
        ...row("Max input per article", maxIn, "Characters of article text sent per summary. Lower = cheaper."),
        ...row("Language", language),
        ...row("Summary style", style),
        h("span"), h("div", { class: "row-form" }, h("button", { type: "submit", class: "btn primary", text: "Save" }),
          h("button", { type: "button", class: "btn", text: "Test connection", onclick: async () => {
            result.textContent = "Testing…";
            try { const r = await api("POST", "/ai/test"); result.textContent = `✓ ${r.model} replied: “${r.reply}”`; } catch (err) { result.textContent = `✗ ${err.message}`; }
          } }), result)),
      card("Usage (last 7 days)", usageRows.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Day (UTC)", "Requests", "Tokens in", "Tokens out", "Failures"].map((t) => h("th", { text: t })))),
        h("tbody", null, usageRows))) : h("p", { class: "muted small", text: "No AI requests yet." })),
      card("Privacy & safety",
        h("ul", { class: "small" },
          h("li", { text: "With a cloud provider, the text of the articles you summarise (and digest item excerpts) is sent to that provider. Use a local OpenAI-compatible server (e.g. Ollama) to keep everything on your network." }),
          h("li", { text: "Article text is treated as untrusted: the model is told to ignore instructions inside it, and its output is shown as plain text. Links in digests come from your database, not from the model." }),
          h("li", { text: "Claude requests enable Anthropic's server-side refusal fallback, because security news can trip safety classifiers; a final refusal is shown as an error, not retried." }))));
    sync();
  }

  // ======================================================================= Settings → Alerts & digests
  const KIND_LABEL = { email: "Email (SMTP)", telegram: "Telegram bot", ntfy: "ntfy push", discord: "Discord webhook", slack: "Slack webhook", webhook: "Signed webhook" };

  async function alertsPanel(panel) {
    fill(panel, h("p", { class: "muted", text: "Loading…" }));
    const [channels, rules, digestList, recent, folders, cats, topics, hooks] = await Promise.all([
      api("GET", "/delivery-channels").catch((e) => ({ error: e.message })), api("GET", "/alert-rules").catch(() => []),
      api("GET", "/digests").catch(() => []), api("GET", "/alerts/recent").catch(() => []),
      Promise.resolve(FW.state.sidebar.folders || []), api("GET", "/cves/meta").then((m) => m.categories).catch(() => []),
      api("GET", "/topics").catch(() => []), api("GET", "/webhooks").catch(() => [])]);
    if (channels.error) { fill(panel, h("p", { class: "error", text: channels.error })); return; }
    const rerender = () => alertsPanel(panel);
    fill(panel,
      h("p", { class: "muted", text: "Get told when it matters: instant CVE alerts, instant keyword-rule alerts (Settings → Rules → “Instant alert to”), and scheduled digests — delivered by email, Telegram, ntfy, Discord, Slack or a signed webhook." }),
      channelsCard(channels, hooks, rerender),
      cveRulesCard(rules, channels, cats, rerender),
      reportsCard(channels, rerender),
      digestsCard(digestList, channels, folders, topics, cats, rerender),
      card("Recent alerts", recent.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["When", "Source", "Item", "Status"].map((t) => h("th", { text: t })))),
        h("tbody", null, recent.slice(0, 50).map((a) => h("tr", null, h("td", { text: relTime(a.sent_at) }),
          h("td", { text: a.source === "cve_rule" ? "CVE rule" : a.source === "publication" ? "Report / guidance" : "Keyword rule" }), h("td", { text: a.title || a.item_key }),
          h("td", { class: a.status === "sent" ? "status-ok" : "status-err", text: a.status === "sent" ? "sent" : `failed: ${a.error || ""}` })))))) :
        h("p", { class: "muted small", text: "Nothing sent yet." })));
  }

  // ---- 📑 reports & guidance: instant alerts
  function reportsCard(channels, rerender) {
    const s = FW.state.settings;
    const chosen = new Set(s.report_alert_channels || []);
    const boxes = channels.map((c) => {
      const box = h("input", { type: "checkbox", checked: chosen.has(c.id), "aria-label": `Send to ${c.name}` });
      return [c.id, box, h("label", { class: "mx-check" }, box, ` ${c.name}`)];
    });
    const kinds = h("select", { "aria-label": "Which publications" }, [["all", "Government, CERTs and vendors"], ["government", "Government agencies and CERTs only"],
      ["vendor", "Vendor research only"]].map(([v, l]) => h("option", { value: v, text: l, selected: (s.report_alert_kinds || "all") === v })));
    const save = async () => {
      const ids = boxes.filter(([, box]) => box.checked).map(([id]) => id);
      const res = await guarded(() => api("PATCH", "/settings", { report_alert_channels: ids, report_alert_kinds: kinds.value }), ids.length ? "Report alerts on" : "Report alerts off");
      if (res) { Object.assign(s, { report_alert_channels: ids, report_alert_kinds: kinds.value }); rerender(); }
    };
    return card("📑 New reports & guidance",
      h("p", { class: "muted small", text: "Be told as soon as CISA, ASD's ACSC, NCSC, CERT-EU, ENISA, the Canadian Cyber Centre, CERT-FR, JPCERT, FBI IC3… or a vendor's research team "
        + "(Mandiant, Microsoft, CrowdStrike, Unit 42, Talos, Check Point, Recorded Future, SentinelLABS…) publishes an advisory, guidance or a threat report. "
        + "Several at once are sent as one message. Everything is also listed under 📑 Reports & guidance in Articles, and digests can include them." }),
      channels.length ? h("div", { class: "row-form" }, ...boxes.map(([, , l]) => l)) : h("p", { class: "muted small", text: "Add a delivery channel above first." }),
      h("div", { class: "row-form" }, kinds, h("button", { type: "button", class: "btn small primary", text: "Save", disabled: !channels.length, onclick: save })));
  }

  // ---- delivery channels
  function channelForm(hooks, onDone) {
    const kind = h("select", null, Object.entries(KIND_LABEL).map(([k, l]) => h("option", { value: k, text: l })));
    const name = h("input", { type: "text", maxlength: 80, placeholder: "Name, e.g. SOC inbox", required: true });
    const fields = h("div", { class: "grid-form" });
    let read = () => ({});
    const input = (attrs) => h("input", { maxlength: 600, ...attrs });
    const draw = () => {
      const k = kind.value;
      if (k === "email") {
        const host = input({ type: "text", placeholder: "smtp.example.com" }), port = input({ type: "number", value: 587 });
        const sec = h("select", null, [["starttls", "STARTTLS (587)"], ["ssl", "SSL/TLS (465)"]].map(([v, l]) => h("option", { value: v, text: l })));
        const user = input({ type: "text", placeholder: "username (optional)" }), pw = input({ type: "password", autocomplete: "off", placeholder: "password / app password" });
        const from = input({ type: "email", placeholder: "alerts@example.com" }), to = input({ type: "text", placeholder: "you@example.com, team@example.com" });
        fill(fields, ...row("SMTP host", host), ...row("Port", port), ...row("Security", sec, "TLS is always required."), ...row("Username", user), ...row("Password", pw),
          ...row("From", from), ...row("To", to, "Up to 10 addresses, comma-separated."));
        read = () => ({ config: { kind: k, host: host.value.trim(), port: Number(port.value), security: sec.value, username: user.value.trim(), sender: from.value.trim(),
          recipients: to.value.split(",").map((x) => x.trim()).filter(Boolean) }, credentials: pw.value ? { password: pw.value } : {} });
      } else if (k === "telegram") {
        const token = input({ type: "password", autocomplete: "off", placeholder: "123456:ABC… from @BotFather" }), chat = input({ type: "text", placeholder: "chat id (e.g. 123456789 or -100…) or @channel" });
        fill(fields, ...row("Bot token", token, "Create a bot with @BotFather, then send it /start (or add it to your group/channel)."), ...row("Chat", chat, "Your numeric chat id — message @userinfobot to find it."));
        read = () => ({ config: { kind: k, chat_id: chat.value.trim() }, credentials: { bot_token: token.value.trim() } });
      } else if (k === "ntfy") {
        const server = input({ type: "url", value: "https://ntfy.sh" }), topic = input({ type: "text", placeholder: "a-long-unguessable-topic" });
        const prio = h("select", null, [1, 2, 3, 4, 5].map((p) => h("option", { value: p, text: String(p), selected: p === 3 })));
        const token = input({ type: "password", autocomplete: "off", placeholder: "access token (optional)" });
        fill(fields, ...row("Server", server, "ntfy.sh or your own server (may be on your LAN)."), ...row("Topic", topic, "On ntfy.sh anyone who knows the topic can read it — use a long random name or your own server."),
          ...row("Priority", prio), ...row("Token", token));
        read = () => ({ config: { kind: k, server: server.value.trim(), topic: topic.value.trim(), priority: Number(prio.value) }, credentials: token.value ? { token: token.value.trim() } : {} });
      } else if (k === "discord" || k === "slack") {
        const url = input({ type: "password", autocomplete: "off", placeholder: k === "discord" ? "https://discord.com/api/webhooks/…" : "https://hooks.slack.com/services/…" });
        fill(fields, ...row("Webhook URL", url, "The URL is a secret; it is stored encrypted. Mentions (@everyone, <!channel>) in alert text are neutralised."));
        read = () => ({ config: { kind: k }, credentials: { webhook_url: url.value.trim() } });
      } else {
        const sel = h("select", null, (hooks || []).map((x) => h("option", { value: x.id, text: x.name })));
        fill(fields, ...row("Webhook", sel, hooks && hooks.length ? "Uses an existing signed webhook from Settings → Webhooks." : "Create a webhook in Settings → Webhooks first."));
        read = () => ({ config: { kind: k, webhook_id: Number(sel.value) } });
      }
    };
    kind.addEventListener("change", draw);
    draw();
    return h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      if (await guarded(() => api("POST", "/delivery-channels", { name: name.value.trim(), ...read() }), "Channel added")) onDone();
    } }, h("div", { class: "row-form" }, kind, name), fields, h("div", { class: "form-actions" }, h("button", { type: "submit", class: "btn primary small", text: "Add channel" })));
  }

  function channelsCard(channels, hooks, rerender) {
    const formBox = h("div");
    return card("Delivery channels",
      channels.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", null, h("tr", null, ["Name", "Type", "Last sent", "Status", ""].map((t) => h("th", { text: t })))),
        h("tbody", null, channels.map((c) => h("tr", null,
          h("td", { text: c.name }), h("td", { text: KIND_LABEL[c.kind] || c.kind }), h("td", { text: c.last_sent ? relTime(c.last_sent) : "never" }),
          h("td", { class: c.last_error ? "status-err" : "status-ok", text: c.last_error ? `⚠ ${c.last_error}` : c.enabled ? "OK" : "disabled" }),
          h("td", null, h("div", { class: "row-form" },
            h("button", { type: "button", class: "btn small", text: "Test", onclick: async () => { if (await guarded(() => api("POST", `/delivery-channels/${c.id}/test`), "Test message sent")) rerender(); } }),
            h("button", { type: "button", class: "btn small", text: c.enabled ? "Disable" : "Enable", onclick: async () => { if (await guarded(() => api("PATCH", `/delivery-channels/${c.id}`, { enabled: !c.enabled }))) rerender(); } }),
            h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => {
              if (window.confirm(`Delete channel “${c.name}”? Rules and digests using it stop sending there.`) && await guarded(() => api("DELETE", `/delivery-channels/${c.id}`), "Deleted")) rerender();
            } })))))))) : h("p", { class: "muted small", text: "No channels yet — add one below, then press Test." }),
      h("button", { type: "button", class: "btn small", text: "+ Add channel", onclick: () => fill(formBox, channelForm(hooks, rerender)) }),
      formBox);
  }

  const channelPicker = (channels, selected) => {
    const box = h("div", { class: "check-list" });
    for (const c of channels) box.append(h("label", { class: "small" }, h("input", { type: "checkbox", value: c.id, checked: selected.includes(c.id) }), ` ${c.name}`));
    if (!channels.length) box.append(h("span", { class: "muted small", text: "Add a delivery channel first." }));
    return { el: box, value: () => [...box.querySelectorAll("input:checked")].map((i) => Number(i.value)) };
  };
  const multiSelect = (items, selected, label) => {
    const sel = h("select", { multiple: true, size: Math.min(6, Math.max(3, items.length)), "aria-label": label },
      items.map(([v, l]) => h("option", { value: v, text: l, selected: selected.includes(v) })));
    return { el: sel, value: () => [...sel.selectedOptions].map((o) => Number(o.value)) };
  };
  const listInput = (values, placeholder) => {
    const el = h("input", { type: "text", maxlength: 2000, value: (values || []).join(", "), placeholder });
    return { el, value: () => el.value.split(",").map((x) => x.trim()).filter(Boolean).slice(0, 50) };
  };

  // ---- CVE alert rules
  function cveRuleForm(rule, channels, cats, done) {
    const c = rule ? rule.config : { min_score: 9, kev_only: false, include_kev_added: true, category_ids: [], vendors: [], keywords: [], channel_ids: [], ai_summary: false };
    const name = h("input", { type: "text", maxlength: 100, value: rule ? rule.name : "Critical CVEs", required: true });
    const score = h("input", { type: "number", min: 0, max: 10, step: 0.1, value: c.min_score });
    const kevOnly = h("input", { type: "checkbox", checked: c.kev_only });
    const kevAdded = h("input", { type: "checkbox", checked: c.include_kev_added });
    const catSel = multiSelect((cats || []).map((x) => [x.id, x.name]), c.category_ids, "Categories");
    const vendors = listInput(c.vendors, "fortinet, ivanti, cisco (optional)");
    const keywords = listInput(c.keywords, "words in the description (optional)");
    const aiSum = h("input", { type: "checkbox", checked: c.ai_summary });
    const chans = channelPicker(channels, c.channel_ids);
    const preview = h("div", { class: "small" });
    return h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      const body = { name: name.value.trim(), config: { min_score: Number(score.value), kev_only: kevOnly.checked, include_kev_added: kevAdded.checked,
        category_ids: catSel.value(), vendors: vendors.value(), keywords: keywords.value(), channel_ids: chans.value(), ai_summary: aiSum.checked } };
      const res = await guarded(() => (rule ? api("PATCH", `/alert-rules/${rule.id}`, body) : api("POST", "/alert-rules", body)), "Alert rule saved");
      if (!res) return;
      const p = await api("POST", `/alert-rules/${res.id}/preview`).catch(() => null);
      if (p) toast(`Saved. In the last 7 days this rule would have matched ${p.matches} CVE(s).`);
      done();
    } }, h("div", { class: "grid-form" },
      ...row("Name", name), ...row("Minimum CVSS", score, "New CVEs at or above this score fire (CVSS 9 = critical)."),
      ...row("Only KEV", kevOnly, "Only CVEs in CISA's Known Exploited Vulnerabilities catalog."),
      ...row("Alert when added to KEV", kevAdded, "Also fire when an existing CVE is added to KEV, whatever its score."),
      ...row("Categories", catSel.el, "Optional — e.g. Edge devices, RCE, AI. Ctrl/Cmd-click to pick several."),
      ...row("Vendors", vendors.el), ...row("Keywords", keywords.el),
      ...row("AI explanation", aiSum, "Add a 2-3 sentence AI explanation to single-CVE alerts (uses the AI budget)."),
      ...row("Send to", chans.el), h("span"), preview),
      h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn small", text: "Cancel", onclick: done }), h("button", { type: "submit", class: "btn primary small", text: "Save rule" })));
  }

  function cveRulesCard(rules, channels, cats, rerender) {
    const formBox = h("div");
    return card("CVE alerts",
      h("p", { class: "muted small", text: "Checked after every CVE sync. Only CVEs published (or added to KEV) after a rule is created can fire, and each fires once per rule. Several at once are combined into one message." }),
      rules.length ? h("ul", { class: "plain-list" }, rules.map((r) => h("li", null,
        h("strong", { text: r.name }), ` — CVSS ≥ ${r.config.min_score}${r.config.kev_only ? ", KEV only" : ""}${r.config.vendors.length ? `, vendors: ${r.config.vendors.join(", ")}` : ""}`,
        h("span", { class: "muted small", text: `  ${r.enabled ? "" : "(disabled) "}${r.last_fired ? `last fired ${relTime(r.last_fired)}` : "not fired yet"}` }),
        h("div", { class: "row-form" },
          h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => fill(formBox, cveRuleForm(r, channels, cats, rerender)) }),
          h("button", { type: "button", class: "btn small", text: "Preview 7 days", onclick: async () => {
            const p = await guarded(() => api("POST", `/alert-rules/${r.id}/preview`));
            if (p) window.alert(`${p.matches} match(es) in the last 7 days:\n` + p.sample.slice(0, 20).map((x) => `${x.id}  CVSS ${x.score ?? "n/a"}${x.kev ? "  KEV" : ""}`).join("\n"));
          } }),
          h("button", { type: "button", class: "btn small", text: r.enabled ? "Disable" : "Enable", onclick: async () => { if (await guarded(() => api("PATCH", `/alert-rules/${r.id}`, { enabled: !r.enabled }))) rerender(); } }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => { if (window.confirm(`Delete “${r.name}”?`) && await guarded(() => api("DELETE", `/alert-rules/${r.id}`), "Deleted")) rerender(); } }))))) :
        h("p", { class: "muted small", text: "No CVE alert rules yet." }),
      h("button", { type: "button", class: "btn small", text: "+ New CVE alert", onclick: () => fill(formBox, cveRuleForm(null, channels, cats, rerender)) }),
      formBox);
  }

  // ---- digests
  function digestForm(d, channels, folders, topics, cats, done) {
    const c = d ? d.config : { time: "07:30", days: [0, 1, 2, 3, 4], timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", window_hours: 24, max_items: 30,
      use_ai: true, instructions: "", skip_empty: true, channel_ids: [], scope: { folder_ids: [], feed_ids: [], tag_ids: [], topic_ids: [], keywords: [], starred_only: false, unread_only: false },
      cves: { enabled: true, min_score: 9, kev_only: false, category_ids: [], max_items: 15 },
      reports: { enabled: true, kinds: "all", max_items: 20 }, actors: { enabled: true, max_items: 10 } };
    c.reports = c.reports || { enabled: false, kinds: "all", max_items: 20 };
    c.actors = c.actors || { enabled: false, max_items: 10 };
    const name = h("input", { type: "text", maxlength: 100, value: d ? d.name : "Morning briefing", required: true });
    const time = h("input", { type: "time", value: c.time, required: true });
    const days = h("div", { class: "check-list" }, DAYS.map((l, i) => h("label", { class: "small" }, h("input", { type: "checkbox", value: i, checked: c.days.includes(i) }), ` ${l}`)));
    const tz = h("input", { type: "text", maxlength: 64, value: c.timezone, placeholder: "Europe/London" });
    const windowH = h("input", { type: "number", min: 1, max: 336, value: c.window_hours });
    const maxItems = h("input", { type: "number", min: 1, max: 100, value: c.max_items });
    const folderSel = multiSelect(folders.map((f) => [f.id, f.name]), c.scope.folder_ids, "Folders");
    const tagSel = multiSelect((FW.state.sidebar.tags || []).map((t) => [t.id, t.name]), c.scope.tag_ids, "Collections");
    const topicSel = multiSelect((topics || []).map((t) => [t.id, t.name]), c.scope.topic_ids, "Topics");
    const keywords = listInput(c.scope.keywords, "title keywords (optional)");
    const starred = h("input", { type: "checkbox", checked: c.scope.starred_only });
    const unread = h("input", { type: "checkbox", checked: c.scope.unread_only });
    const cveOn = h("input", { type: "checkbox", checked: c.cves.enabled });
    const cveScore = h("input", { type: "number", min: 0, max: 10, step: 0.1, value: c.cves.min_score });
    const cveKev = h("input", { type: "checkbox", checked: c.cves.kev_only });
    const cveCats = multiSelect((cats || []).map((x) => [x.id, x.name]), c.cves.category_ids, "CVE categories");
    const repOn = h("input", { type: "checkbox", checked: c.reports.enabled });
    const repKinds = h("select", null, [["all", "Government, CERTs and vendors"], ["government", "Government & CERTs only"], ["vendor", "Vendor research only"]]
      .map(([v, l]) => h("option", { value: v, text: l, selected: c.reports.kinds === v })));
    const actOn = h("input", { type: "checkbox", checked: c.actors.enabled });
    const useAi = h("input", { type: "checkbox", checked: c.use_ai });
    const instr = h("textarea", { rows: 2, maxlength: 600, placeholder: "Optional: e.g. focus on edge devices and anything affecting Microsoft 365" });
    instr.value = c.instructions || "";
    const skip = h("input", { type: "checkbox", checked: c.skip_empty });
    const chans = channelPicker(channels, c.channel_ids);
    const read = () => ({ name: name.value.trim(), config: {
      time: time.value, days: [...days.querySelectorAll("input:checked")].map((i) => Number(i.value)), timezone: tz.value.trim() || "UTC",
      window_hours: Number(windowH.value), max_items: Number(maxItems.value), use_ai: useAi.checked, instructions: instr.value.trim(), skip_empty: skip.checked,
      channel_ids: chans.value(),
      scope: { folder_ids: folderSel.value(), feed_ids: [], tag_ids: tagSel.value(), topic_ids: topicSel.value(), keywords: keywords.value(), starred_only: starred.checked, unread_only: unread.checked },
      cves: { enabled: cveOn.checked, min_score: Number(cveScore.value), kev_only: cveKev.checked, category_ids: cveCats.value(), max_items: 15 },
      reports: { enabled: repOn.checked, kinds: repKinds.value, max_items: 20 }, actors: { enabled: actOn.checked, max_items: 10 } } });
    return h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      if (await guarded(() => (d ? api("PATCH", `/digests/${d.id}`, read()) : api("POST", "/digests", read())), "Digest saved")) done();
    } }, h("div", { class: "grid-form" },
      ...row("Name", name), ...row("Send at", time), ...row("On", days), ...row("Time zone", tz, "IANA name, e.g. Europe/London, America/New_York, UTC."),
      ...row("Covers the last", windowH, "hours (also never repeats items already sent in the previous run)"), ...row("Max articles", maxItems),
      h("h5", { class: "span-2", text: "Threat intelligence" }),
      ...row("📑 Reports & guidance", h("span", { class: "row-form" }, repOn, repKinds), "New advisories, guidance and threat reports from agencies, CERTs and vendors."),
      ...row("🎭 Threat actors", actOn, "The actors most in the news in the period, with what was said about them."),
      h("h5", { class: "span-2", text: "Articles to include (leave everything empty for all feeds)" }),
      ...row("Folders", folderSel.el), ...row("Collections", tagSel.el), ...row("Topics", topicSel.el), ...row("Keywords", keywords.el),
      ...row("Starred only", starred), ...row("Unread only", unread),
      h("h5", { class: "span-2", text: "New CVEs" }),
      ...row("Include CVEs", cveOn), ...row("Minimum CVSS", cveScore, "KEV-listed CVEs are always included."), ...row("Only KEV", cveKev), ...row("CVE categories", cveCats.el),
      h("h5", { class: "span-2", text: "Write-up & delivery" }),
      ...row("AI briefing", useAi, "A short themed summary at the top (needs Settings → AI). The item list with links is always included."),
      ...row("Extra instructions", instr), ...row("Skip when empty", skip), ...row("Send to", chans.el)),
      h("div", { class: "form-actions" }, h("button", { type: "button", class: "btn small", text: "Cancel", onclick: done }), h("button", { type: "submit", class: "btn primary small", text: "Save digest" })));
  }

  function showRun(run) {
    const dlg = $("#sourceDialog");
    fill(dlg, h("div", { class: "form" },
      h("div", { class: "sd-head" }, h("h3", { text: run.subject || "Digest" }), h("button", { type: "button", class: "icon-btn", "aria-label": "Close", text: "✕", onclick: () => dlg.close() })),
      h("p", { class: "muted small", text: `${run.status} · ${fullDate(run.created_at)} · ${run.item_count} articles, ${run.cve_count} CVEs${run.error ? ` · ${run.error}` : ""}` }),
      h("pre", { class: "digest-body", text: run.body })));
    if (!dlg.open) dlg.showModal();
  }

  function digestsCard(list, channels, folders, topics, cats, rerender) {
    const formBox = h("div");
    return card("Digests",
      h("p", { class: "muted small", text: "Scheduled briefings of what happened since the last one. Preview builds one without sending." }),
      list.length ? h("ul", { class: "plain-list" }, list.map((d) => h("li", null,
        h("strong", { text: d.name }), ` — ${d.config.days.map((i) => DAYS[i]).join(", ")} at ${d.config.time} (${d.config.timezone})`,
        h("span", { class: "muted small", text: `  ${d.enabled ? `next ${d.next_run ? fullDate(d.next_run) : "—"}` : "(disabled)"}${d.last_run ? ` · last ${relTime(d.last_run)}` : ""}` }),
        h("div", { class: "row-form" },
          h("button", { type: "button", class: "btn small", text: "Preview", onclick: async () => { const r = await guarded(() => api("POST", `/digests/${d.id}/run`, { preview: true })); if (r) showRun(r); } }),
          h("button", { type: "button", class: "btn small", text: "Send now", onclick: async () => {
            if (!window.confirm(`Build and send “${d.name}” now?`)) return;
            const r = await guarded(() => api("POST", `/digests/${d.id}/run`, { preview: false }));
            if (r) { toast(`Digest ${r.status}${r.error ? `: ${r.error}` : ""}`, r.status === "failed"); rerender(); }
          } }),
          h("button", { type: "button", class: "btn small", text: "History", onclick: async () => {
            const runs = await guarded(() => api("GET", `/digests/${d.id}/runs`));
            if (runs && runs.length) showRun(runs[0]); else toast("No runs yet");
          } }),
          h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => fill(formBox, digestForm(d, channels, folders, topics, cats, rerender)) }),
          h("button", { type: "button", class: "btn small", text: d.enabled ? "Disable" : "Enable", onclick: async () => { if (await guarded(() => api("PATCH", `/digests/${d.id}`, { enabled: !d.enabled }))) rerender(); } }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: async () => { if (window.confirm(`Delete “${d.name}”?`) && await guarded(() => api("DELETE", `/digests/${d.id}`), "Deleted")) rerender(); } }))))) :
        h("p", { class: "muted small", text: "No digests yet." }),
      h("button", { type: "button", class: "btn small", text: "+ New digest", onclick: () => fill(formBox, digestForm(null, channels, folders, topics, cats, rerender)) }),
      formBox);
  }

  FW.ai = { summarize, loadCached, settingsPanel, alertsPanel };
})();
