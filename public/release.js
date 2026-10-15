"use strict";

/* MPatchMonitor — Patch Tuesday index (/release) and one release (/release/<YYYY-Mon>) */

const rlink = (href, text) => `<a href="${esc(safeUrl(href))}" rel="noopener noreferrer" target="_blank">${esc(text)}</a>`;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const root = $("#release");
  const id = decodeURIComponent(location.pathname.split("/")[2] || "");
  let data, kb, acn;
  try {
    [data, kb, acn] = await Promise.all([fetchData(), fetchJson("/api/kb").catch(() => ({ kbs: [] })), fetchJson("/api/acn").catch(() => ({ items: [] }))]);
  } catch (err) { return showFatal(root, err); }
  if (!id) {
    setHTML($("#crumbs"), `<li><a href="/">${te("Overview")}</a></li><li aria-current="page">Patch Tuesday</li>`);
    setHTML(root, indexPage(data));
  } else {
    const m = data.months.find((x) => x.id === id);
    if (!m) {
      setHTML(root, `<header class="cve-head"><h1>${te("This release is not among the last twelve.")}</h1></header><p><a href="/release">${te("See every release")}</a></p>`);
      return;
    }
    document.title = `${t("{month} security updates", { month: monthName(m.id) })} – MPatchMonitor`;
    setHTML($("#crumbs"), `<li><a href="/release">Patch Tuesday</a></li><li aria-current="page">${esc(cap(monthName(m.id)))}</li>`);
    setHTML(root, monthPage(m, data, kb.kbs.filter((k) => k.release === m.id), acn.items || []));
  }
  applyVars(root);
});

function indexPage(data) {
  const months = [...data.months].reverse();
  const max = Math.max(...months.map((m) => m.total), 1);
  return `<header class="cve-head"><h1>${te("Every Patch Tuesday of the last twelve months.")}</h1>
    <p class="byline">${te("Microsoft releases security updates on the second Tuesday of each month. Open a release to see its zero-days, the most urgent fixes and the updates to deploy.")}</p>
    <p class="hint"><a href="/ics/patch-tuesday.ics">${te("Add the next Patch Tuesdays to your calendar")}</a></p></header>
  <div class="table-wrap"><table class="list-table release-table"><thead><tr><th>${te("Release")}</th><th>${te("Vulnerabilities")}</th><th class="num">${te("fig|Critical")}</th><th class="num">${te("Exploited")}</th><th class="num">${te("In KEV")}</th></tr></thead>
  <tbody>${months.map((m) => `<tr data-href="/release/${esc(m.id)}"><td><a href="/release/${esc(m.id)}"><strong>${esc(cap(monthName(m.id)))}</strong></a><span class="id">${esc(fmtLong(m.release_date))}</span></td>
    <td><span class="bar-row"><span class="hbar" data-w="${(m.total / max * 100).toFixed(1)}"></span><b>${esc(m.total)}</b></span></td>
    <td class="num">${esc(m.by_severity.Critical || 0)}</td><td class="num">${m.exploited ? `<span class="late">${esc(m.exploited)}</span>` : "0"}</td><td class="num">${esc(m.kev)}</td></tr>`).join("")}</tbody></table></div>`;
}

function monthPage(m, data, kbs, acn) {
  const cves = data.cves.filter((c) => c.release === m.id);
  const zero = cves.filter((c) => c.exploited || c.kev);
  const disclosed = cves.filter((c) => c.disclosed && !c.exploited);
  const top = [...cves].sort((a, b) => b.score - a.score).slice(0, 10);
  const fam = {};
  cves.forEach((c) => { fam[c.family] = (fam[c.family] || 0) + 1; });
  const fams = Object.entries(fam).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const fmax = Math.max(...fams.map((f) => f[1]), 1);
  const impact = {};
  cves.forEach((c) => { impact[c.impact] = (impact[c.impact] || 0) + 1; });
  const rel = Date.parse(m.release_date);
  const bulletins = acn.filter((a) => Date.parse(a.published) >= rel - 86_400_000 && Date.parse(a.published) - rel < 5 * 86_400_000)
    .sort((a, b) => /mensil|monthly/i.test(b.title) - /mensil|monthly/i.test(a.title));
  const row = (c) => `<tr><td><a href="/cve/${esc(c.cve)}"><strong>${esc(c.cve)}</strong></a><span class="id">${esc(c.title)}</span></td>
    <td>${esc(sevName(c.severity))}</td><td class="num">${esc(c.cvss ?? "–")}</td><td class="num">${scoreBadge(c.score, c.tier)}</td></tr>`;
  return `
  <header class="cve-head"><p class="cve-id">${esc(fmtLong(m.release_date))}</p><h1>${te("{month} security updates", { month: monthName(m.id) })}</h1>
    <p class="actions"><a class="btn ghost" href="/analysis/${esc(m.id)}">${te("Read the analysis of this release")}</a> <a class="btn ghost" href="/trends">${te("Twelve-month trends")}</a></p></header>
  <dl class="figures">
    <div class="fig"><dt>${te("Vulnerabilities")}</dt><dd>${esc(m.total)}</dd></div>
    <div class="fig crit"><dt>${te("Exploited (zero-days)")} ${gloss("zero-day", t("Zero-days"))}</dt><dd>${esc(m.exploited)}</dd></div>
    <div class="fig warn"><dt>${te("fig|Critical")}</dt><dd>${esc(m.by_severity.Critical || 0)}</dd></div>
    <div class="fig"><dt>${te("Security updates")}</dt><dd>${esc(kbs.length)}</dd></div>
  </dl>

  ${zero.length ? `<section class="kev-box" aria-labelledby="zTitle"><h2 id="zTitle">${te("Exploited vulnerabilities")} ${gloss("exploited", t("Exploited in the wild"))}</h2>
    <div class="table-wrap"><table class="list-table"><thead><tr><th>CVE</th><th>${te("Severity")}</th><th class="num">CVSS</th><th class="num">${te("Risk")}</th></tr></thead><tbody>${zero.map(row).join("")}</tbody></table></div></section>`
    : `<p class="hint">${te("No vulnerability of this release is known to be exploited.")}</p>`}

  <div class="cve-grid">
    <section aria-labelledby="topTitle"><h2 id="topTitle">${te("Most urgent")}</h2>
      <div class="table-wrap"><table class="list-table"><thead><tr><th>CVE</th><th>${te("Severity")}</th><th class="num">CVSS</th><th class="num">${te("Risk")}</th></tr></thead><tbody>${top.map(row).join("")}</tbody></table></div>
      ${disclosed.length ? `<p class="hint">${te("Publicly disclosed before the fix:")} ${disclosed.map((c) => `<a href="/cve/${esc(c.cve)}">${esc(c.cve)}</a>`).join(", ")}.</p>` : ""}
    </section>
    <section aria-labelledby="famTitle"><h2 id="famTitle">${te("Where the fixes are")}</h2>
      <ul class="hbars">${fams.map(([f, n]) => `<li><span>${esc(f)}</span><span class="hbar" data-w="${(n / fmax * 100).toFixed(1)}"></span><b>${esc(n)}</b></li>`).join("")}</ul>
      <h3>${te("By impact")}</h3>
      <ul class="plain">${Object.entries(impact).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<li>${esc(impactName(k))}: ${esc(n)}</li>`).join("")}</ul>
    </section>
  </div>

  <section aria-labelledby="kbTitle"><h2 id="kbTitle">${te("Updates to deploy")}</h2>
    <div class="table-wrap"><table class="list-table"><thead><tr><th>${te("Update")}</th><th>${te("Products")}</th><th class="num">CVE</th><th class="num">${te("Risk")}</th><th>${te("Known issues")}</th></tr></thead>
    <tbody>${kbs.sort((a, b) => b.score - a.score).map((k) => `<tr data-href="/kb/${esc(k.kb)}"><td><a href="/kb/${esc(k.kb)}"><strong>${esc(k.kb)}</strong></a></td>
      <td>${esc(k.products.slice(0, 2).join(", "))}${k.products.length > 2 ? `<span class="id">${te("and {n} more", { n: k.products.length - 2 })}</span>` : ""}</td>
      <td class="num">${esc(k.count)}</td><td class="num">${scoreBadge(k.score, k.tier)}</td><td>${k.known_issues.length ? `<span class="sig kev">${te("Yes")}</span>` : "–"}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">${te("The update catalog has not been published yet.")}</td></tr>`}</tbody></table></div>
  </section>

  <section class="sources-block" aria-labelledby="mSrc"><h2 id="mSrc">${te("Original sources")}</h2>
    <ul class="sources">
      <li>${rlink(`https://msrc.microsoft.com/update-guide/releaseNote/${encodeURIComponent(m.id)}`, t("Microsoft release notes"))}<span>Security Update Guide</span></li>
      <li>${rlink(`https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${encodeURIComponent(m.id)}`, t("CVRF document"))}<span>${te("Machine-readable data used by this page")}</span></li>
      ${bulletins.map((b) => `<li>${rlink(b.link, b.title)}<span>${te("CSIRT Italia bulletin")}</span></li>`).join("")}
    </ul>
  </section>`;
}

document.addEventListener("click", (e) => {
  if (e.target.closest("a")) return;
  const tr = e.target.closest("tr[data-href]");
  if (tr) location.href = tr.dataset.href;
});
