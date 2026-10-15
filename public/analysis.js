"use strict";

/* MPatchMonitor — monthly analysis (/analysis, /analysis/<YYYY-Mon>).
 * The text is written automatically from the published data, in Italian or English,
 * and can be shared on LinkedIn. */

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const root = $("#analysis");
  const id = decodeURIComponent(location.pathname.split("/")[2] || "");
  let data, kb;
  try {
    [data, kb] = await Promise.all([fetchData(), fetchJson("/api/kb").catch(() => ({ kbs: [] }))]);
  } catch (err) { return showFatal(root, err); }
  if (!id) {
    setHTML($("#crumbs"), `<li><a href="/">${te("Overview")}</a></li><li aria-current="page">${te("Monthly analysis")}</li>`);
    setHTML(root, indexPage(data));
    return;
  }
  const i = data.months.findIndex((x) => x.id === id);
  if (i < 0) {
    setHTML(root, `<header class="cve-head"><h1>${te("This release is not among the last twelve.")}</h1></header><p><a href="/analysis">${te("See every analysis")}</a></p>`);
    return;
  }
  const a = analyse(data, kb.kbs || [], i);
  document.title = `${t("Patch Tuesday {month}: the analysis", { month: monthName(id) })} – MPatchMonitor`;
  setHTML($("#crumbs"), `<li><a href="/analysis">${te("Monthly analysis")}</a></li><li aria-current="page">${esc(cap(monthName(id)))}</li>`);
  setHTML(root, monthPage(a));
  applyVars(root);
  $("#copyPost")?.addEventListener("click", (e) => copyText(postText(a), e.currentTarget));
});

const plural = (n, one, many, vars = {}) => t(n === 1 ? one : many, { n, ...vars });

function indexPage(data) {
  const months = [...data.months].reverse();
  return `<header class="cve-head"><h1>${te("Patch Tuesday, month by month, in plain words")}</h1>
    <p class="byline">${te("A short analysis of every release: what changed compared with previous months, the zero-days, what to install first and what to do if you cannot install yet.")}</p></header>
    <ul class="analysis-list">${months.map((m) => `<li><a href="/analysis/${esc(m.id)}"><strong>${esc(cap(monthName(m.id)))}</strong>
      <span>${esc(plural(m.total, "1 vulnerability", "{n} vulnerabilities"))} · ${esc(plural(m.exploited || 0, "1 zero-day", "{n} zero-days"))} · ${esc(plural(m.by_severity?.Critical || 0, "1 critical", "{n} critical"))}</span></a></li>`).join("")}</ul>`;
}

/** Everything the page and the post need, computed once. */
function analyse(data, kbs, i) {
  const m = data.months[i];
  const cves = data.cves.filter((c) => c.release === m.id);
  const prev = i > 0 ? data.months[i - 1] : null;
  const others = data.months.filter((x) => x.id !== m.id);
  const avg = others.length ? Math.round(others.reduce((s, x) => s + x.total, 0) / others.length) : m.total;
  const zero = cves.filter((c) => c.exploited || c.kev).sort((a, b) => b.score - a.score);
  const exploitCode = cves.filter((c) => c.exploit && !c.exploited).sort((a, b) => b.score - a.score);
  const mitig = cves.filter((c) => (c.mitigations || []).length).sort((a, b) => b.score - a.score);
  const crit = cves.filter((c) => c.severity === "Critical");
  const fam = {};
  cves.forEach((c) => { fam[c.family] = (fam[c.family] || 0) + 1; });
  const fams = Object.entries(fam).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const imp = {};
  cves.forEach((c) => { imp[c.impact] = (imp[c.impact] || 0) + 1; });
  const topImpact = Object.entries(imp).sort((a, b) => b[1] - a[1])[0];
  const monthKbs = kbs.filter((k) => k.release === m.id).sort((a, b) => b.score - a.score);
  const issues = monthKbs.filter((k) => (k.known_issues || []).length);
  const maxZero = Math.max(...data.months.map((x) => x.exploited || 0));
  return { m, cves, prev, avg, zero, exploitCode, mitig, crit, fams, topImpact, kbs: monthKbs.slice(0, 6), issues, maxZero, months: data.months.length };
}

function lede(a) {
  const { m, prev, avg } = a;
  const month = cap(monthName(m.id));
  const parts = [plural(m.total, "{month}: Microsoft fixed 1 vulnerability", "{month}: Microsoft fixed {n} vulnerabilities", { month })];
  const diff = Math.round(((m.total - avg) / Math.max(1, avg)) * 100);
  if (Math.abs(diff) >= 5) parts.push(t(diff > 0 ? "{p}% more than the average of the other months ({avg})" : "{p}% fewer than the average of the other months ({avg})", { p: Math.abs(diff), avg }));
  else parts.push(t("in line with the average of the other months ({avg})", { avg }));
  let s = parts.join(", ") + ". ";
  if (a.zero.length) {
    s += plural(a.zero.length, "1 was already exploited when the fix came out", "{n} were already exploited when the fix came out");
    s += a.zero.length === a.maxZero && a.months > 1 ? t(", the highest number of the year. ") : ". ";
  } else {
    s += t("None was exploited when the fix came out. ");
  }
  s += plural(a.crit.length, "1 is rated Critical", "{n} are rated Critical");
  s += a.topImpact ? t(" and the most common risk is {impact}.", { impact: impactName(a.topImpact[0]).toLowerCase() }) : ".";
  if (prev) {
    const d = m.total - prev.total;
    s += " " + (d === 0 ? t("The same number as {prev}.", { prev: monthName(prev.id) })
      : t(d > 0 ? "{n} more than {prev}." : "{n} fewer than {prev}.", { n: Math.abs(d), prev: monthName(prev.id) }));
  }
  return s;
}

function cveRow(c, extra = "") {
  return `<li><a href="/cve/${esc(c.cve)}"><strong>${esc(c.cve)}</strong></a> ${scoreBadge(c.score, c.tier)}<span class="id">${esc(c.title)}</span>${extra}</li>`;
}

function monthPage(a) {
  const { m } = a;
  const origin = location.origin;
  const shareUrl = `${origin}/analysis/${encodeURIComponent(m.id)}?lang=${MPM_LANG}`;
  const linkedIn = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`;
  const firstMitig = (c) => (c.mitigations || [])[0];
  return `
  <header class="cve-head"><p class="cve-id">${esc(fmtLong(m.release_date))}</p>
    <h1>${te("Patch Tuesday {month}: the analysis", { month: monthName(m.id) })}</h1>
    <p class="lede-text">${esc(lede(a))}</p>
    <p class="actions">
      <a class="btn" href="${esc(linkedIn)}" rel="noopener noreferrer" target="_blank">${te("Share on LinkedIn")}</a>
      <button type="button" class="btn ghost" id="copyPost">${te("Copy text for a post")}</button>
      <a class="btn ghost" href="/release/${esc(m.id)}">${te("Full release details")}</a>
    </p></header>

  <dl class="figures">
    <div class="fig"><dt>${te("Vulnerabilities")}</dt><dd>${esc(m.total)}</dd></div>
    <div class="fig crit"><dt>${te("Zero-days")} ${gloss("zero-day", t("Zero-days"))}</dt><dd>${esc(a.zero.length)}</dd></div>
    <div class="fig warn"><dt>${te("fig|Critical")}</dt><dd>${esc(a.crit.length)}</dd></div>
    <div class="fig"><dt>${te("Public exploit")} ${gloss("public-exploit", t("Public exploit"))}</dt><dd>${esc(a.cves.filter((c) => c.exploit).length)}</dd></div>
  </dl>

  <section aria-labelledby="zTitle"><h2 id="zTitle">${te("Already exploited")}</h2>
    ${a.zero.length ? `<p>${te("Install these first: attackers were using them before the fix was available.")}</p>
      <ul class="analysis-cves">${a.zero.map((c) => cveRow(c, c.kev?.due_date ? `<span class="id">${te("CISA deadline for US federal agencies: {date}", { date: fmtDate(c.kev.due_date) })}</span>` : "")).join("")}</ul>`
      : `<p>${te("No vulnerability of this release was exploited when Microsoft published it. Keep the normal update schedule.")}</p>`}
  </section>

  ${a.exploitCode.length ? `<section aria-labelledby="xTitle"><h2 id="xTitle">${te("Public exploit code, not yet seen in attacks")}</h2>
    <p>${te("Anyone can download working code for these. They are the most likely to be exploited next.")}</p>
    <ul class="analysis-cves">${a.exploitCode.slice(0, 5).map((c) => cveRow(c, `<span class="id">${esc(exploitSources(c.exploit))}</span>`)).join("")}</ul></section>` : ""}

  <section aria-labelledby="kTitle"><h2 id="kTitle">${te("What to install first")}</h2>
    ${a.kbs.length ? `<ol class="analysis-kbs">${a.kbs.map((k) => `<li><a href="/kb/${esc(k.kb)}"><strong>${esc(k.kb)}</strong></a> ${scoreBadge(k.score, k.tier)}
      <span class="id">${esc(k.products.slice(0, 2).join(", "))}${k.products.length > 2 ? esc(t(" and {n} more", { n: k.products.length - 2 })) : ""}</span></li>`).join("")}</ol>`
      : `<p class="hint">${te("The update catalog has not been published yet.")}</p>`}
    ${a.issues.length ? `<p class="hint">${te("Known issues reported by Microsoft:")} ${a.issues.map((k) => `<a href="/kb/${esc(k.kb)}">${esc(k.kb)}</a>`).join(", ")}. ${te("Read them before a wide rollout.")}</p>` : ""}
  </section>

  <section aria-labelledby="mTitle"><h2 id="mTitle">${te("If you cannot install yet")} ${gloss("mitigation", t("Mitigation"))}</h2>
    ${a.mitig.length ? `<p>${esc(plural(a.mitig.length, "Microsoft documents a workaround or mitigation for 1 vulnerability of this release.", "Microsoft documents a workaround or mitigation for {n} vulnerabilities of this release."))}</p>
      <ul class="analysis-cves">${a.mitig.slice(0, 3).map((c) => cveRow(c, `<p class="mitig-quote"${MPM_LANG === "it" ? ' lang="en"' : ""}>${esc(firstMitig(c).text.slice(0, 280))}${firstMitig(c).text.length > 280 ? "…" : ""}</p>`)).join("")}</ul>`
      : `<p>${te("Microsoft does not document workarounds for this release: installing the update is the only fix.")}</p>`}
  </section>

  <section aria-labelledby="pTitle"><h2 id="pTitle">${te("Most affected products")}</h2>
    <ul class="hbars">${a.fams.map(([f, n]) => `<li><span>${esc(f)}</span><span class="hbar" data-w="${(n / Math.max(1, a.fams[0][1]) * 100).toFixed(1)}"></span><b>${esc(n)}</b></li>`).join("")}</ul>
    <p class="hint"><a href="/trends">${te("See the twelve-month trends")}</a></p>
  </section>

  <p class="hint">${te("This analysis is written automatically from Microsoft's data, CISA KEV, FIRST EPSS and public exploit databases. Check the original advisories before acting.")}</p>`;
}

/** Plain text for a LinkedIn post (the site never posts anything itself). */
function postText(a) {
  const { m } = a;
  const lines = [
    t("Patch Tuesday {month}: the analysis", { month: monthName(m.id) }),
    "",
    lede(a),
  ];
  if (a.zero.length) lines.push("", t("Already exploited:"), ...a.zero.slice(0, 5).map((c) => `• ${c.cve} – ${c.title}`));
  if (a.kbs.length) lines.push("", t("What to install first:"), ...a.kbs.slice(0, 3).map((k) => `• ${k.kb} (${k.products[0] || ""})`));
  lines.push("", `${location.origin}/analysis/${m.id}?lang=${MPM_LANG}`, "", "#PatchTuesday #Microsoft #CyberSecurity #VulnerabilityManagement #NIS2");
  return lines.join("\n");
}
