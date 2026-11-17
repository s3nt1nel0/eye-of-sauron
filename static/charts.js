"use strict";
/*
 * Minimal SVG chart kit for Eye of Sauron dashboards (no dependencies, CSP-safe).
 * Follows the project's dataviz rules: thin marks (2px lines), 4px rounded data
 * ends, 2px surface gaps, recessive grid, legend for >= 2 series plus direct labels
 * for <= 4, hover tooltips everywhere, one hue for magnitude (hbar), fixed
 * categorical slots that follow the entity (never its rank), text in text tokens.
 * All labels are inserted as text nodes - never as HTML.
 */
(function () {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const nf = new Intl.NumberFormat();

  function s(tag, attrs, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v !== null && v !== undefined) el.setAttribute(k, String(v));
    }
    for (const c of children) if (c !== null && c !== undefined) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return el;
  }

  function div(cls, text) {
    const el = document.createElement("div");
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function seriesPalette() {
    return Array.from({ length: 8 }, (_, i) => cssVar(`--series-${i + 1}`) || "#3b82f6");
  }

  const safeHex = (c) => (typeof c === "string" && /^#[0-9a-f]{6}$/i.test(c) ? c : null);

  /**
   * Stable colours: slot = key mod 8 with collision probing, so an entity keeps
   * its colour when filters change. Collections keep their own user colour.
   */
  function assignColors(items) {
    const pal = seriesPalette();
    const used = new Set();
    const out = new Map();
    for (const it of items) {
      const own = safeHex(it.color);
      if (own) { out.set(it.key, own); continue; }
      const n = typeof it.key === "number" ? it.key : hashString(String(it.key));
      let slot = ((n % 8) + 8) % 8;
      for (let i = 0; i < 8 && used.has(slot); i++) slot = (slot + 1) % 8;
      used.add(slot);
      out.set(it.key, pal[slot]);
    }
    return out;
  }

  function hashString(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
    return Math.abs(h);
  }

  function niceMax(v) {
    if (v <= 4) return 4;
    const exp = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * exp >= v) return m * exp;
    return 10 * exp;
  }

  function fmtBucket(iso, bucket, long) {
    const [y, m, d] = iso.split("-").map(Number);
    const date = new Date(y, m - 1, d);
    // dd/mm/yyyy (axis labels drop the year: dd/mm; months: mm/yyyy)
    const p2 = (n) => String(n).padStart(2, "0");
    if (bucket === "month") return `${p2(date.getMonth() + 1)}/${date.getFullYear()}`;
    if (bucket === "half") return `${date.getMonth() < 6 ? "H1" : "H2"} ${date.getFullYear()}`;
    if (bucket === "year") return String(date.getFullYear());
    const base = `${p2(date.getDate())}/${p2(date.getMonth() + 1)}` + (long ? `/${date.getFullYear()}` : "");
    return bucket === "week" && long ? `Week of ${base}` : base;
  }

  // ------------------------------------------------------------------ tooltip
  function tooltip(host) {
    const tip = div("chart-tip");
    tip.hidden = true;
    host.append(tip);
    return {
      show(x, y, title, rows) {
        tip.replaceChildren(div("tip-title", title));
        for (const r of rows) {
          const row = div("tip-row");
          if (r.color) {
            const sw = div("swatch");
            sw.style.setProperty("--sw", r.color);
            row.append(sw);
          }
          row.append(div("tip-label", r.label), div("tip-value", nf.format(r.value)));
          tip.append(row);
        }
        tip.hidden = false;
        const hostRect = host.getBoundingClientRect();
        const w = tip.offsetWidth;
        const left = x + 14 + w > hostRect.width ? Math.max(4, x - w - 14) : x + 14;
        tip.style.setProperty("left", `${left}px`);
        tip.style.setProperty("top", `${Math.max(4, y - 10)}px`);
      },
      hide() { tip.hidden = true; },
    };
  }

  // ------------------------------------------------------------------ legend
  function legend(items, colors, onClick) {
    const box = div("chart-legend");
    for (const it of items) {
      const entry = document.createElement(onClick ? "button" : "span");
      entry.className = "legend-item";
      if (onClick) {
        entry.type = "button";
        entry.title = `Show articles: ${it.label}`;
        entry.addEventListener("click", () => onClick(it));
      }
      const sw = div("swatch");
      sw.style.setProperty("--sw", colors.get(it.key));
      entry.append(sw, document.createTextNode(it.label));
      if (it.total !== undefined) entry.append(div("legend-val", nf.format(it.total)));
      box.append(entry);
    }
    return box;
  }

  function emptyState(host, text) {
    host.replaceChildren(div("chart-empty", text || "No matching articles in this period."));
  }

  // ------------------------------------------------------------------ time charts
  /**
   * opts: { buckets, series:[{key,label,color,values,total}], bucket, kind: line|area|bar|stacked,
   *         height, onPick(bucketIndex, seriesKey|null) }
   */
  function timeChart(host, opts) {
    const { buckets, series, bucket } = opts;
    host.replaceChildren();
    if (!buckets.length || !series.length || series.every((x) => x.values.every((v) => v === 0))) {
      emptyState(host);
      return;
    }
    const colors = assignColors(series);
    const multi = series.length > 1;
    // Kinds: line · area · stackedarea · bar (first series) · stacked (bars) · percent (100% stacked bars)
    const percent = opts.kind === "percent";
    const stacked = opts.kind === "stacked" || percent;
    const stackedArea = opts.kind === "stackedarea";
    const isBar = opts.kind === "bar" || stacked;
    const directLabels = multi && series.length <= 4 && !isBar && !stackedArea;
    const width = Math.max(260, host.clientWidth || 600);
    const height = opts.height || 220;
    const m = { l: 40, r: directLabels ? 110 : 12, t: 10, b: 26 };
    const pw = width - m.l - m.r;
    const ph = height - m.t - m.b;

    const totals = buckets.map((_, i) => series.reduce((acc, x) => acc + x.values[i], 0));
    // What is drawn: shares of each bucket's total for "percent", raw counts otherwise (tooltips always show counts).
    const shown = percent ? series.map((ser) => ({ ...ser, values: ser.values.map((v, i) => (totals[i] ? (v / totals[i]) * 100 : 0)) })) : series;
    const rawMax = percent ? 100 : (stacked || stackedArea) ? Math.max(...totals) : Math.max(...series.flatMap((x) => x.values));
    const yMax = percent ? 100 : niceMax(Math.max(1, rawMax));
    const y = (v) => m.t + ph - (v / yMax) * ph;
    const n = buckets.length;
    const band = pw / n;
    const x = (i) => (isBar ? m.l + band * i + band / 2 : m.l + (n === 1 ? pw / 2 : (pw * i) / (n - 1)));

    const svg = s("svg", { width, height, viewBox: `0 0 ${width} ${height}`, class: "chart-svg", role: "img",
      "aria-label": `${opts.kind} chart, ${series.length} series over ${n} ${bucket}s` });

    // grid + y axis
    const grid = s("g", { class: "grid" });
    for (let t = 0; t <= 4; t++) {
      const v = (yMax / 4) * t;
      grid.append(s("line", { x1: m.l, x2: m.l + pw, y1: y(v), y2: y(v) }));
      grid.append(s("text", { x: m.l - 6, y: y(v) + 4, "text-anchor": "end", class: "axis-text" }, `${nf.format(Math.round(v))}${percent ? "%" : ""}`));
    }
    svg.append(grid);

    // x labels (about 6)
    const step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 80))));
    const xa = s("g");
    for (let i = 0; i < n; i += step) {
      xa.append(s("text", { x: x(i), y: height - 8, "text-anchor": "middle", class: "axis-text" }, fmtBucket(buckets[i], bucket, false)));
    }
    svg.append(xa);

    if (isBar) {
      const bw = Math.max(2, Math.min(28, band * 0.72));
      const g = s("g");
      for (let i = 0; i < n; i++) {
        let base = 0;
        const parts = stacked ? shown : [shown[0]];
        parts.forEach((ser, idx) => {
          const v = ser.values[i];
          if (!v) return;
          const y0 = y(base);
          const y1 = y(base + v);
          base += v;
          const top = stacked ? parts.slice(idx + 1).every((p) => !p.values[i]) : true;
          g.append(s("path", { d: barPath(x(i) - bw / 2, y1, bw, y0 - y1, top ? 4 : 0), fill: colors.get(ser.key), class: "bar-seg" }));
        });
      }
      svg.append(g);
    } else if (stackedArea) {
      // Each series sits on top of the ones before it; drawn top layer first so lower layers stay visible.
      const cum = [];
      let below = buckets.map(() => 0);
      for (const ser of series) {
        const top = below.map((b, i) => b + ser.values[i]);
        cum.push({ ser, below, top });
        below = top;
      }
      for (const { ser, below: lo, top } of cum.slice().reverse()) {
        const upper = top.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
        const lower = lo.map((v, i) => [x(i), y(v)]).reverse().map((p) => `L${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("");
        svg.append(s("path", { d: `${upper}${lower}Z`, fill: colors.get(ser.key), "fill-opacity": 0.55, stroke: colors.get(ser.key), "stroke-width": 1.5, "stroke-linejoin": "round" }));
      }
      series.forEach((ser, k) => { ser._cum = cum[k].top; });
    } else {
      for (const ser of series) {
        const pts = ser.values.map((v, i) => [x(i), y(v)]);
        const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("");
        if (opts.kind === "area") {
          svg.append(s("path", { d: `${d}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z`, fill: colors.get(ser.key), "fill-opacity": multi ? 0.08 : 0.15 }));
        }
        svg.append(s("path", { d, fill: "none", stroke: colors.get(ser.key), "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
      }
      if (directLabels) {
        const ends = series.map((ser) => ({ ser, y: y(ser.values[n - 1]) })).sort((a, b) => a.y - b.y);
        for (let i = 1; i < ends.length; i++) if (ends[i].y - ends[i - 1].y < 13) ends[i].y = ends[i - 1].y + 13;
        for (const e of ends) {
          svg.append(s("line", { x1: m.l + pw + 6, x2: m.l + pw + 16, y1: e.y, y2: e.y, stroke: colors.get(e.ser.key), "stroke-width": 2 }));
          const label = e.ser.label.length > 14 ? `${e.ser.label.slice(0, 13)}…` : e.ser.label;
          svg.append(s("text", { x: m.l + pw + 20, y: e.y + 4, class: "direct-label" }, label));
        }
      }
    }

    // hover layer
    const cross = s("line", { class: "crosshair", y1: m.t, y2: m.t + ph, visibility: "hidden" });
    const markers = s("g", { visibility: "hidden" });
    svg.append(cross, markers);
    const hit = s("rect", { x: m.l, y: m.t, width: pw, height: ph, fill: "transparent", class: "hit" });
    svg.append(hit);
    host.append(svg);
    const tip = tooltip(host);

    const indexAt = (evt) => {
      const r = svg.getBoundingClientRect();
      const px = evt.clientX - r.left;
      const i = isBar ? Math.floor((px - m.l) / band) : Math.round(((px - m.l) / pw) * (n - 1));
      return Math.min(n - 1, Math.max(0, i));
    };
    hit.addEventListener("mousemove", (evt) => {
      const i = indexAt(evt);
      cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i));
      cross.setAttribute("visibility", "visible");
      markers.replaceChildren();
      if (!isBar) {
        for (const ser of series) {
          const v = stackedArea ? ser._cum[i] : ser.values[i];
          markers.append(s("circle", { cx: x(i), cy: y(v), r: 4, fill: colors.get(ser.key), class: "marker" }));
        }
      }
      markers.setAttribute("visibility", "visible");
      const rows = series.map((ser) => ({
        label: percent && totals[i] ? `${ser.label} (${((ser.values[i] / totals[i]) * 100).toFixed(0)}%)` : ser.label,
        value: ser.values[i], color: colors.get(ser.key),
      })).sort((a, b) => b.value - a.value);
      if ((stacked || stackedArea) && multi) rows.push({ label: "Total", value: totals[i] });
      const r = svg.getBoundingClientRect();
      tip.show(evt.clientX - r.left, evt.clientY - r.top, fmtBucket(buckets[i], bucket, true), rows);
    });
    hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); markers.setAttribute("visibility", "hidden"); tip.hide(); });
    if (opts.onPick) {
      hit.classList.add("clickable");
      hit.addEventListener("click", (evt) => opts.onPick(indexAt(evt), null));
    }
    if (multi) host.append(legend(series, colors, opts.onSeries));
  }

  function barPath(x, y, w, h, r) {
    if (h <= 0) return "";
    r = Math.min(r, w / 2, h);
    if (!r) return `M${x},${y}h${w}v${h}h${-w}Z`;
    return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
  }

  // ------------------------------------------------------------------ breakdowns
  /** Horizontal bars: one hue (magnitude), value labels always visible. */
  function hbar(host, items, onPick) {
    host.replaceChildren();
    if (!items.length) { emptyState(host); return; }
    const max = Math.max(...items.map((i) => i.count));
    const list = div("hbar-list");
    for (const it of items) {
      const row = document.createElement(onPick ? "button" : "div");
      row.className = "hbar-row";
      if (onPick) { row.type = "button"; row.title = `Show articles: ${it.label}`; row.addEventListener("click", () => onPick(it)); }
      const track = div("hbar-track");
      const fill = div("hbar-fill");
      fill.style.setProperty("width", `${Math.max(1.5, (it.count / max) * 100)}%`);
      track.append(fill);
      row.append(div("hbar-label", it.label), track, div("hbar-value", nf.format(it.count)));
      list.append(row);
    }
    host.append(list);
  }

  /** Vertical bars ("columns") for a breakdown: one hue (magnitude), value on top, label under each bar. */
  function columns(host, items, onPick, height) {
    host.replaceChildren();
    const data = items.filter((i) => i.count > 0);
    if (!data.length) { emptyState(host); return; }
    const width = Math.max(260, host.clientWidth || 600);
    const h = height || 230;
    const m = { l: 10, r: 10, t: 18, b: 46 };
    const pw = width - m.l - m.r;
    const ph = h - m.t - m.b;
    const max = niceMax(Math.max(...data.map((d) => d.count)));
    const band = pw / data.length;
    const bw = Math.max(6, Math.min(56, band * 0.7));
    const fill = cssVar("--accent") || "#3b82f6";
    const svg = s("svg", { width, height: h, viewBox: `0 0 ${width} ${h}`, class: "chart-svg", role: "img",
      "aria-label": `Column chart of ${data.length} categories` });
    const plot = div("columns-plot");
    plot.append(svg);
    const tip = tooltip(plot);
    const maxChars = Math.max(4, Math.floor(band / 6.5));
    data.forEach((it, i) => {
      const cx = m.l + band * i + band / 2;
      const bh = (it.count / max) * ph;
      const bar = s("path", { d: barPath(cx - bw / 2, m.t + ph - bh, bw, bh, 4), fill, class: `bar-seg${onPick ? " clickable" : ""}` });
      bar.addEventListener("mousemove", (evt) => {
        const r = plot.getBoundingClientRect();
        tip.show(evt.clientX - r.left, evt.clientY - r.top, it.label, [{ label: "Count", value: it.count, color: fill }]);
      });
      bar.addEventListener("mouseleave", () => tip.hide());
      if (onPick) bar.addEventListener("click", () => onPick(it));
      svg.append(bar);
      svg.append(s("text", { x: cx, y: m.t + ph - bh - 4, "text-anchor": "middle", class: "axis-text" }, nf.format(it.count)));
      const label = it.label.length > maxChars ? `${it.label.slice(0, maxChars - 1)}…` : it.label;
      svg.append(s("text", { x: cx, y: m.t + ph + 16, "text-anchor": "middle", class: "axis-text" }, label));
    });
    host.append(plot);
  }

  /** Two KPIs side by side (combined news + CVE widgets). */
  function kpiPair(host, items, onPick) {
    host.replaceChildren();
    const row = div("kpi-pair");
    for (const it of items) {
      const box = document.createElement(onPick ? "button" : "div");
      box.className = "kpi";
      if (onPick) { box.type = "button"; box.title = `Show the ${it.label.toLowerCase()}`; box.addEventListener("click", () => onPick(it)); }
      const label = div("kpi-label", it.label);
      label.style.setProperty("color", it.color || "inherit");
      box.append(label, div("kpi-value", nf.format(it.value)));
      let delta;
      if (it.previous === 0 && it.value === 0) delta = "No change";
      else if (it.previous === 0) delta = "New this period";
      else delta = `${it.change_pct > 0 ? "▲" : it.change_pct < 0 ? "▼" : "■"} ${Math.abs(it.change_pct)}% vs previous period (${nf.format(it.previous)})`;
      box.append(div("kpi-delta", delta));
      row.append(box);
    }
    host.append(row);
  }

  function donut(host, items, onPick, pie = false) {
    host.replaceChildren();
    const data = items.slice(0, 8).filter((i) => i.count > 0);
    if (!data.length) { emptyState(host); return; }
    const colors = assignColors(data);
    const total = data.reduce((a, b) => a + b.count, 0);
    const size = 180;
    const R = 84;
    const r0 = pie ? 0 : 54;
    const cx = size / 2;
    const svg = s("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, class: "donut", role: "img",
      "aria-label": `${pie ? "Pie" : "Donut"} chart of ${data.length} categories` });
    const wrap = div("donut-wrap");
    const plot = div("donut-plot");
    plot.append(svg);
    const tip = tooltip(plot);
    let angle = -Math.PI / 2;
    for (const it of data) {
      const sweep = (it.count / total) * Math.PI * 2;
      const path = s("path", { d: arcPath(cx, cx, R, r0, angle, angle + sweep), fill: colors.get(it.key), class: `slice${onPick ? " clickable" : ""}` });
      angle += sweep;
      path.addEventListener("mousemove", (evt) => {
        const rect = plot.getBoundingClientRect();
        tip.show(evt.clientX - rect.left, evt.clientY - rect.top, it.label,
          [{ label: `${((it.count / total) * 100).toFixed(1)}% of shown`, value: it.count, color: colors.get(it.key) }]);
      });
      path.addEventListener("mouseleave", () => tip.hide());
      if (onPick) path.addEventListener("click", () => onPick(it));
      svg.append(path);
    }
    if (!pie) {
      svg.append(s("text", { x: cx, y: cx - 2, "text-anchor": "middle", class: "donut-total" }, nf.format(total)));
      svg.append(s("text", { x: cx, y: cx + 16, "text-anchor": "middle", class: "axis-text" }, "mentions"));
    }
    const leg = legend(data.map((d) => ({ ...d, total: d.count })), colors, onPick);
    leg.classList.add("vertical");
    wrap.append(plot, leg);
    host.append(wrap);
  }

  function arcPath(cx, cy, R, r, a0, a1) {
    if (a1 - a0 >= Math.PI * 2 - 1e-6) a1 = a0 + Math.PI * 2 - 1e-4;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const p = (rad, a) => `${(cx + rad * Math.cos(a)).toFixed(2)},${(cy + rad * Math.sin(a)).toFixed(2)}`;
    return `M${p(R, a0)}A${R},${R} 0 ${large} 1 ${p(R, a1)}L${p(r, a1)}A${r},${r} 0 ${large} 0 ${p(r, a0)}Z`;
  }

  function table(host, items, onPick, countLabel = "Articles") {
    host.replaceChildren();
    if (!items.length) { emptyState(host); return; }
    const total = items.reduce((a, b) => a + b.count, 0);
    const t = document.createElement("table");
    t.className = "data compact";
    const head = document.createElement("tr");
    for (const label of ["Name", countLabel, "Share"]) { const th = document.createElement("th"); th.textContent = label; head.append(th); }
    t.append(head);
    for (const it of items) {
      const tr = document.createElement("tr");
      const name = document.createElement("td");
      if (onPick) {
        const b = document.createElement("button");
        b.type = "button"; b.className = "link-btn"; b.textContent = it.label;
        b.addEventListener("click", () => onPick(it));
        name.append(b);
      } else name.textContent = it.label;
      const c = document.createElement("td"); c.className = "num"; c.textContent = nf.format(it.count);
      const sh = document.createElement("td"); sh.className = "num"; sh.textContent = `${((it.count / total) * 100).toFixed(1)}%`;
      tr.append(name, c, sh);
      t.append(tr);
    }
    host.append(t);
  }

  function seriesTable(host, buckets, series, bucket) {
    host.replaceChildren();
    const t = document.createElement("table");
    t.className = "data compact";
    const head = document.createElement("tr");
    for (const label of [bucket[0].toUpperCase() + bucket.slice(1), ...series.map((x) => x.label)]) {
      const th = document.createElement("th"); th.textContent = label; head.append(th);
    }
    t.append(head);
    for (let i = buckets.length - 1; i >= 0; i--) {
      const tr = document.createElement("tr");
      const td = document.createElement("td"); td.textContent = fmtBucket(buckets[i], bucket, true); tr.append(td);
      for (const ser of series) { const c = document.createElement("td"); c.className = "num"; c.textContent = nf.format(ser.values[i]); tr.append(c); }
      t.append(tr);
    }
    host.append(t);
  }

  function kpi(host, data, onPick) {
    host.replaceChildren();
    const box = document.createElement(onPick ? "button" : "div");
    box.className = "kpi";
    if (onPick) { box.type = "button"; box.title = "Show matching articles"; box.addEventListener("click", onPick); }
    box.append(div("kpi-value", nf.format(data.value)));
    let delta;
    if (data.previous === 0 && data.value === 0) delta = "No change";
    else if (data.previous === 0) delta = "New this period";
    else {
      const pct = data.change_pct;
      const arrow = pct > 0 ? "▲" : pct < 0 ? "▼" : "■";
      delta = `${arrow} ${Math.abs(pct)}% vs previous ${data.days}d (${nf.format(data.previous)})`;
    }
    box.append(div("kpi-delta", delta));
    host.append(box);
  }

  window.FWCharts = { timeChart, hbar, columns, donut, table, seriesTable, kpi, kpiPair, fmtBucket, assignColors };
})();
