"use strict";

/* MPatchMonitor — service status (/status): freshness of every data source and of the live checks. */

/* Source -> [name, what it feeds, hours after which the data is considered late] */
const SOURCES = () => ({
  msrc: ["Microsoft Security Update Guide", t("Patch Tuesday, CVEs, updates, revisions"), 30],
  kev: ["CISA KEV", t("Exploited vulnerabilities and deadlines"), 30],
  epss: ["FIRST EPSS", t("Probability of exploitation"), 30],
  nvd: ["NVD", t("CVSS of other vendors' vulnerabilities"), 72],
  exploits: ["Metasploit, Nuclei, PoC-in-GitHub", t("Public exploit code"), 48],
  oss: ["GitHub Advisory Database", t("Open-source fixes"), 72],
  health: ["Windows release health", t("Windows known issues"), 30],
  attack: ["MITRE CTID Mappings Explorer", t("MITRE ATT&CK techniques"), 72],
  sigma: ["SigmaHQ", t("Detection rules"), 72],
  eol: ["endoflife.date", t("End of life"), 72],
  docs: ["Microsoft Learn", t("Microsoft docs tracker"), 72],
  breaches: ["Have I Been Pwned, SEC EDGAR", t("Data breaches"), 72],
  news: [t("Security news"), t("News on the overview"), 30],
});

const ICON = { ok: "✓", late: "!", fail: "×", off: "–" };
const LABEL = () => ({ ok: t("Up to date"), late: t("Late"), fail: t("Failing"), off: t("Not configured") });

function stateOf(ok, at, hours) {
  if (ok === null || ok === undefined) return "off";
  if (!ok) return "fail";
  if (!at || (Date.now() - Date.parse(at)) / 3_600_000 > hours) return "late";
  return "ok";
}

const badge = (s) => `<span class="st st-${s}"><i aria-hidden="true">${ICON[s]}</i>${esc(LABEL()[s])}</span>`;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const root = $("#status");
  const [sources, live] = await Promise.all([
    fetchJson("/api/sources").catch(() => null),
    fetchJson("/api/service-status").catch(() => null),
  ]);
  if (!sources && !live) return showFatal(root, new Error("status unavailable"));
  setHTML(root, page(sources, live));
});

function page(src, live) {
  const rows = [];
  const names = SOURCES();
  const checks = [];
  if (live) {
    const m = live.msrc || {};
    checks.push([t("Watch on Microsoft's update index"), t("every 5 minutes"), stateOf(m.ok ?? null, m.last_check, 0.5), m.last_check, m.ok === false ? m.error : ""]);
    const a = live.acn || {};
    checks.push([t("CSIRT Italia bulletins"), t("every 15 minutes"), stateOf(a.ok ?? null, a.last_check, 1), a.last_check, a.ok === false ? a.error : ""]);
    checks.push([t("Data pipeline"), t("when Microsoft changes something, and every day"), stateOf(live.version ? true : null, live.version, 30), live.version, ""]);
  }
  for (const [key, [name, use, hours]] of Object.entries(names)) {
    const s = src?.sources?.[key];
    rows.push([name, use, s ? stateOf(s.ok, s.checked, hours) : "off", s?.checked, s && !s.ok && s.updated ? t("Showing data from {date}", { date: fmtDateTime(s.updated) }) : s?.count != null ? t("{n} records", { n: s.count }) : ""]);
  }
  const all = [...checks, ...rows].map((r) => r[2]);
  const worst = all.includes("fail") ? "fail" : all.includes("late") ? "late" : "ok";
  const headline = { ok: t("Everything is working."), late: t("Some data is late. The site shows the last good data."), fail: t("A source is failing. The site shows the last good data.") }[worst];
  const table = (list, head) => `<div class="table-wrap"><table class="list-table status-table"><thead><tr><th>${esc(head)}</th><th>${te("Status")}</th><th>${te("Last check")}</th><th>${te("Notes")}</th></tr></thead>
    <tbody>${list.map(([name, use, st, at, note]) => `<tr><td><strong>${esc(name)}</strong><span class="id">${esc(use)}</span></td><td>${badge(st)}</td>
      <td>${at ? `${esc(timeAgo(at))}<span class="id">${esc(fmtDateTime(at))}</span>` : "–"}</td><td>${esc(note || "")}</td></tr>`).join("")}</tbody></table></div>`;
  return `<p class="status-head">${badge(worst)} <span>${esc(headline)}</span></p>
    ${checks.length ? `<section class="section-block" aria-labelledby="liveTitle"><h2 id="liveTitle">${te("Live checks")}</h2>${table(checks, t("Check"))}</section>` : ""}
    <section class="section-block" aria-labelledby="srcTitle"><h2 id="srcTitle">${te("Data sources")}</h2>${table(rows, t("Source"))}</section>
    ${live ? `<section class="section-block" aria-labelledby="qTitle"><h2 id="qTitle">${te("Alerts")}</h2>
      <ul class="plain"><li>${te("Telegram alerts waiting to be sent: {n}", { n: live.queue?.telegram ?? 0 })}</li><li>${te("Browser notifications waiting to be sent: {n}", { n: live.queue?.push ?? 0 })}</li></ul></section>` : ""}
    <p class="hint">${te("The site is served by Cloudflare's network: if this page loads, the site is up. Data is refreshed by a scheduled pipeline; a failed source never deletes data already published.")}</p>`;
}
