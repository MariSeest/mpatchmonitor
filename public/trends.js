"use strict";

/* MPatchMonitor — Trends (/trends): twelve Patch Tuesdays at a glance.
 * Charts are plain SVG built from the dataset already published at /api/data. */

// Chart geometry; the width follows the container so text keeps its real size.
const CH = { w: 720, h: 260, top: 22, bottom: 30, left: 34, right: 8, gap: 2 };
let DATA = null, lastWidth = 0;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const root = $("#trends");
  let data;
  try { data = await fetchData(); } catch (err) { return showFatal(root, err); }
  DATA = data;
  render(root);
  initTips(root);
  addEventListener("resize", () => {
    clearTimeout(render.t);
    render.t = setTimeout(() => { if (Math.abs(root.clientWidth - lastWidth) > 60) render(root); }, 200);
  });
});

function render(root) {
  lastWidth = root.clientWidth;
  const open = $("details.table-view", root)?.open;
  setHTML(root, trendsPage(DATA, lastWidth));
  if (open) $("details.table-view", root).open = true;
  applyVars(root);
}

/** Per-month figures computed from the CVE list (the months array has only the totals). */
function monthStats(data) {
  return data.months.map((m) => {
    const cves = data.cves.filter((c) => c.release === m.id);
    const crit = cves.filter((c) => c.severity === "Critical").length;
    const imp = cves.filter((c) => c.severity === "Important").length;
    return {
      id: m.id, label: shortMonth(m.id), name: cap(monthName(m.id)), total: m.total, crit, imp,
      other: Math.max(0, m.total - crit - imp), exploited: m.exploited || 0,
      exploit: cves.filter((c) => c.exploit).length, mitig: cves.filter((c) => (c.mitigations || []).length).length,
    };
  });
}

function shortMonth(id) {
  const d = new Date(`${id.slice(0, 4)}-${String(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].indexOf(id.slice(5)) + 1).padStart(2, "0")}-15T00:00:00Z`);
  return d.toLocaleDateString(LOCALE, { month: "short", timeZone: "UTC" }).replace(".", "");
}

const median = (a) => {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y), h = s.length >> 1;
  return s.length % 2 ? s[h] : (s[h - 1] + s[h]) / 2;
};
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);

/** Nice round axis maximum and 3–4 gridlines. */
function niceMax(v) {
  if (v <= 4) return { max: 4, step: 1 };
  const raw = v / 4, pow = 10 ** Math.floor(Math.log10(raw)), step = [1, 2, 2.5, 5, 10].map((x) => x * pow).find((x) => x >= raw);
  return { max: Math.ceil(v / step) * step, step };
}

/** Bar whose data end (top) is rounded 4px and whose base sits on the baseline. */
function barPath(x, y, w, h, round) {
  if (h <= 0) return "";
  const r = round ? Math.min(4, h, w / 2) : 0;
  return `M${x},${y + h}V${y + r}${r ? `Q${x},${y} ${x + r},${y}` : ""}H${x + w - r}${r ? `Q${x + w},${y} ${x + w},${y + r}` : ""}V${y + h}Z`;
}

function axis(maxInfo, plotH) {
  let g = "";
  for (let v = 0; v <= maxInfo.max; v += maxInfo.step) {
    const y = CH.top + plotH - (v / maxInfo.max) * plotH;
    g += `<line class="grid${v ? "" : " base"}" x1="${CH.left}" x2="${CH.w - CH.right}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}"/>` +
      `<text class="tick" x="${CH.left - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end">${esc(v)}</text>`;
  }
  return g;
}

/** Stacked bars: Critical at the baseline, then Important, then the rest. */
function stackedChart(rows, width) {
  CH.w = width;
  const plotH = CH.h - CH.top - CH.bottom;
  const scale = niceMax(Math.max(...rows.map((r) => r.total), 1));
  const slot = (CH.w - CH.left - CH.right) / rows.length;
  const bw = Math.min(34, slot * 0.62);
  const series = [["crit", "c-1", t("Critical")], ["imp", "c-2", t("Important")], ["other", "c-3", t("Moderate and low")]];
  let marks = "";
  rows.forEach((r, i) => {
    const x = CH.left + i * slot + (slot - bw) / 2;
    let base = CH.top + plotH;
    const visible = series.filter(([k]) => r[k] > 0);
    visible.forEach(([k, cls], j) => {
      const h = (r[k] / scale.max) * plotH - (j ? CH.gap : 0);
      base -= (r[k] / scale.max) * plotH;
      marks += `<path class="${cls}" d="${barPath(x, base, bw, Math.max(0, h), j === visible.length - 1)}"/>`;
    });
    const last = i === rows.length - 1, top = CH.top + plotH - (r.total / scale.max) * plotH;
    // narrow screens: label only the latest and the highest month
    if (slot < 40 && !last && r.total !== Math.max(...rows.map((x) => x.total))) { /* no label */ } else
    marks += `<text class="val${last ? " strong" : ""}" x="${(x + bw / 2).toFixed(1)}" y="${(top - 6).toFixed(1)}" text-anchor="middle">${esc(r.total)}</text>`;
    marks += `<text class="tick" x="${(x + bw / 2).toFixed(1)}" y="${CH.h - 10}" text-anchor="middle">${esc(r.label)}</text>`;
    marks += `<rect class="hit" x="${(CH.left + i * slot).toFixed(1)}" y="${CH.top}" width="${slot.toFixed(1)}" height="${plotH}" tabindex="0" role="img"
      aria-label="${te("{month}: {n} vulnerabilities", { month: r.name, n: r.total })}"
      data-tip="${esc([`${r.name}: ${t("{n} vulnerabilities", { n: r.total })}`, `${t("Critical")}: ${r.crit}`, `${t("Important")}: ${r.imp}`, `${t("Moderate and low")}: ${r.other}`].join("\n"))}"/>`;
  });
  return `<ul class="legend" aria-hidden="true">${series.map(([, cls, name]) => `<li><i class="${cls}"></i>${esc(name)}</li>`).join("")}</ul>
    <svg class="chart" viewBox="0 0 ${CH.w} ${CH.h}" role="group" aria-label="${te("Vulnerabilities fixed each month, by severity")}">${axis(scale, plotH)}${marks}</svg>`;
}

/** One series of bars; only the latest and the highest value are labelled. */
function singleChart(rows, key, label, cls, width) {
  CH.w = width;
  const plotH = CH.h - CH.top - CH.bottom - 40;
  const h = CH.h - 40;
  const scale = niceMax(Math.max(...rows.map((r) => r[key]), 1));
  const slot = (CH.w - CH.left - CH.right) / rows.length;
  const bw = Math.min(34, slot * 0.62);
  const peak = Math.max(...rows.map((r) => r[key]));
  const peakAt = rows.findIndex((r) => r[key] === peak);
  let marks = "";
  rows.forEach((r, i) => {
    const x = CH.left + i * slot + (slot - bw) / 2;
    const bh = (r[key] / scale.max) * plotH;
    const y = CH.top + plotH - bh;
    marks += `<path class="${cls}" d="${barPath(x, y, bw, bh, true)}"/>`;
    const last = i === rows.length - 1;
    if (last || (i === peakAt && peak > 0)) marks += `<text class="val${last ? " strong" : ""}" x="${(x + bw / 2).toFixed(1)}" y="${(y - 6).toFixed(1)}" text-anchor="middle">${esc(r[key])}</text>`;
    marks += `<text class="tick" x="${(x + bw / 2).toFixed(1)}" y="${h - 10}" text-anchor="middle">${esc(r.label)}</text>`;
    marks += `<rect class="hit" x="${(CH.left + i * slot).toFixed(1)}" y="${CH.top}" width="${slot.toFixed(1)}" height="${plotH}" tabindex="0" role="img"
      aria-label="${esc(`${r.name}: ${r[key]}`)}" data-tip="${esc(`${r.name}\n${label}: ${r[key]}`)}"/>`;
  });
  return `<svg class="chart" viewBox="0 0 ${CH.w} ${h}" role="group" aria-label="${esc(label)}">${axis(scale, plotH)}${marks}</svg>`;
}

function hbarList(entries, fmt = (k) => k) {
  const max = Math.max(...entries.map((e) => e[1]), 1);
  return `<ul class="hbars">${entries.map(([k, n]) => `<li><span title="${esc(fmt(k))}">${esc(fmt(k))}</span><span class="hbar" data-w="${(n / max * 100).toFixed(1)}"></span><b>${esc(n)}</b></li>`).join("")}</ul>`;
}

function trendsPage(data, width = 1100) {
  const full = Math.max(320, Math.min(1200, width - 50));
  const half = width >= 900 ? Math.max(320, (width - 56) / 2 - 50) : full;
  const rows = monthStats(data);
  const cves = data.cves;
  const total = rows.reduce((a, r) => a + r.total, 0);
  const avg = Math.round(total / Math.max(1, rows.length));
  const zero = rows.reduce((a, r) => a + r.exploited, 0);
  const kevDays = cves.filter((c) => c.kev?.date_added && c.published)
    .map((c) => Math.max(0, Math.round((Date.parse(c.kev.date_added) - Date.parse(c.published)) / 86_400_000)));
  const kevMedian = median(kevDays);
  const withExploit = cves.filter((c) => c.exploit).length;
  const withMitig = cves.filter((c) => (c.mitigations || []).length).length;
  const last = rows[rows.length - 1];
  const diff = last ? Math.round(((last.total - avg) / Math.max(1, avg)) * 100) : 0;

  const fam = {}, imp = {};
  cves.forEach((c) => { fam[c.family] = (fam[c.family] || 0) + 1; imp[c.impact] = (imp[c.impact] || 0) + 1; });
  const fams = Object.entries(fam).filter(([k]) => k && k !== "undefined").sort((a, b) => b[1] - a[1]).slice(0, 10);
  const imps = Object.entries(imp).filter(([k]) => k && k !== "undefined").sort((a, b) => b[1] - a[1]);

  const lead = last ? (diff === 0
    ? t("{month} fixed {n} vulnerabilities, in line with the twelve-month average.", { month: cap(monthName(last.id)), n: last.total })
    : t(diff > 0 ? "{month} fixed {n} vulnerabilities, {p}% more than the twelve-month average of {avg}." : "{month} fixed {n} vulnerabilities, {p}% fewer than the twelve-month average of {avg}.",
      { month: cap(monthName(last.id)), n: last.total, p: Math.abs(diff), avg })) : "";

  return `
  <header class="cve-head"><h1>${te("Twelve months of Microsoft vulnerabilities")}</h1>
    <p class="byline">${esc(lead)} <a href="/analysis">${te("Read the monthly analysis")}</a></p></header>

  <dl class="figures">
    <div class="fig"><dt>${te("Vulnerabilities in 12 months")}</dt><dd>${esc(total)}</dd></div>
    <div class="fig"><dt>${te("Average per Patch Tuesday")}</dt><dd>${esc(avg)}</dd></div>
    <div class="fig crit"><dt>${te("Zero-days")} ${gloss("zero-day", t("Zero-days"))}</dt><dd>${esc(zero)}</dd></div>
    <div class="fig"><dt>${te("Days from fix to CISA KEV (median)")} ${gloss("kev", "CISA KEV")}</dt><dd>${kevMedian == null ? "–" : esc(Math.round(kevMedian))}</dd></div>
    <div class="fig warn"><dt>${te("With public exploit code")} ${gloss("public-exploit", t("Public exploit"))}</dt><dd>${esc(pct(withExploit, cves.length))}%</dd></div>
    <div class="fig"><dt>${te("With a Microsoft mitigation")} ${gloss("mitigation", t("Mitigation"))}</dt><dd>${esc(pct(withMitig, cves.length))}%</dd></div>
  </dl>

  <section class="chart-block" aria-labelledby="sevTitle">
    <h2 id="sevTitle">${te("Vulnerabilities fixed each month, by severity")} ${gloss("severity", t("Severity"))}</h2>
    ${stackedChart(rows, full)}
  </section>

  <div class="cve-grid">
    <section class="chart-block" aria-labelledby="zdTitle">
      <h2 id="zdTitle">${te("Zero-days each month")}</h2>
      <p class="hint">${te("Vulnerabilities already exploited when Microsoft released the fix.")}</p>
      ${singleChart(rows, "exploited", t("Zero-days"), "c-1", half)}
    </section>
    <section class="chart-block" aria-labelledby="xpTitle">
      <h2 id="xpTitle">${te("Public exploit code each month")}</h2>
      <p class="hint">${te("CVEs with a Metasploit module, a Nuclei template or a proof of concept on GitHub.")}</p>
      ${singleChart(rows, "exploit", t("Public exploit"), "c-3", half)}
    </section>
  </div>

  <details class="table-view">
    <summary>${te("Show the data as a table")}</summary>
    <div class="table-wrap"><table class="list-table"><thead><tr><th>${te("Release")}</th><th class="num">${te("Vulnerabilities")}</th><th class="num">${te("Critical")}</th>
      <th class="num">${te("Important")}</th><th class="num">${te("Moderate and low")}</th><th class="num">${te("Zero-days")}</th><th class="num">${te("Public exploit")}</th><th class="num">${te("With a Microsoft mitigation")}</th></tr></thead>
    <tbody>${[...rows].reverse().map((r) => `<tr><td><a href="/release/${esc(r.id)}">${esc(r.name)}</a></td><td class="num">${esc(r.total)}</td><td class="num">${esc(r.crit)}</td><td class="num">${esc(r.imp)}</td>
      <td class="num">${esc(r.other)}</td><td class="num">${esc(r.exploited)}</td><td class="num">${esc(r.exploit)}</td><td class="num">${esc(r.mitig)}</td></tr>`).join("")}</tbody></table></div>
    <p class="actions"><button type="button" class="btn ghost" id="trendCsv">${te("Download CSV")}</button></p>
  </details>

  <div class="cve-grid">
    <section aria-labelledby="famTitle"><h2 id="famTitle">${te("Most affected products")}</h2>${hbarList(fams)}</section>
    <section aria-labelledby="impTitle"><h2 id="impTitle">${te("What an attacker could do")}</h2>${hbarList(imps, impactName)}</section>
  </div>
  <p class="hint">${th("Counts cover the last twelve Patch Tuesdays and include out-of-band fixes. Severity is Microsoft's rating; see {link}.", { link: `<a href="/method">${te("how the ranking works")}</a>` })}</p>`;
}

document.addEventListener("click", (e) => {
  if (e.target.id !== "trendCsv") return;
  fetchData().then((data) => {
    const rows = monthStats(data);
    const head = ["release", "vulnerabilities", "critical", "important", "moderate_low", "zero_days", "public_exploit", "with_mitigation"];
    const csv = [head.join(","), ...rows.map((r) => [r.id, r.total, r.crit, r.imp, r.other, r.exploited, r.exploit, r.mitig].map(csvCell).join(","))].join("\r\n");
    downloadFile("mpatchmonitor-trends.csv", csv, "text/csv");
  });
});
