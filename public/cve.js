"use strict";

/* MPatchMonitor — page for a single CVE: /cve/<id> */

const CVSS = {
  AV: [t("Attack vector"), { N: t("Network"), A: t("Adjacent network"), L: t("Local"), P: t("Physical") }],
  AC: [t("Attack complexity"), { L: t("cvss-f|Low"), H: t("cvss-f|High") }],
  PR: [t("Privileges required"), { N: t("cvss-m|None"), L: t("cvss-m|Low"), H: t("cvss-m|High") }],
  UI: [t("User interaction"), { N: t("cvss-f|None"), R: t("Required") }],
  S: [t("Scope"), { U: t("Unchanged"), C: t("cvss-m|Changed") }],
  C: [t("Confidentiality impact"), { H: t("cvss-m|High"), L: t("cvss-m|Low"), N: t("cvss-m|None") }],
  I: [t("Integrity impact"), { H: t("cvss-m|High"), L: t("cvss-m|Low"), N: t("cvss-m|None") }],
  A: [t("Availability impact"), { H: t("cvss-m|High"), L: t("cvss-m|Low"), N: t("cvss-m|None") }],
  E: [t("Exploit code maturity"), { U: t("Unproven"), P: t("Proof of concept"), F: t("Functional"), H: t("cvss-f|High"), X: t("Not defined") }],
  RL: [t("Remediation level"), { O: t("Official fix"), T: t("Temporary fix"), W: t("Workaround"), U: t("Unavailable"), X: t("Not defined") }],
  RC: [t("Report confidence"), { U: t("Unknown"), R: t("Reasonable"), C: t("Confirmed"), X: t("Not defined") }],
};

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const id = decodeURIComponent(location.pathname.split("/")[2] || "").toUpperCase();
  const root = $("#cve");
  if (!/^CVE-[A-Z0-9]{4}-\d{4,7}$/.test(id)) return notFound(root, id);

  let data;
  try { data = await fetchData(); } catch (err) { return showFatal(root, err); }
  const c = data.cves.find((x) => x.cve === id);
  if (!c) return notFound(root, id);

  document.title = `${c.cve}: ${c.title} – MPatchMonitor`;
  setHTML($("#crumbs"), `<li><a href="/">${te("Overview")}</a></li><li><a href="/release/${esc(c.release)}">${esc(cap(monthName(c.release)))}</a></li><li aria-current="page">${esc(c.cve)}</li>`);
  const changes = data.changes.filter((x) => x.cve === c.cve);
  setHTML(root, page(c, changes));
  applyVars(root);
  if (c.epss != null) renderEpssHistory($("#epssHistory"), c.cve); else $("#epssHistory")?.remove();
  fetchJson("/api/acn").then((a) => {
    const hits = (a.items || []).filter((x) => (x.cves || []).includes(c.cve));
    if (!hits.length) return;
    const box = document.createElement("section");
    box.className = "acn-box";
    setHTML(box, `<h2>${te("Mentioned by CSIRT Italia")}</h2><ul class="plain">${hits.map((h) => `<li>${link(h.link, h.title)} <span class="hint">${esc(fmtLong(h.published))}</span></li>`).join("")}</ul>`);
    $(".verdict", root)?.after(box);
  }).catch(() => {});
});

function notFound(root, id) {
  const q = encodeURIComponent(id);
  setHTML(root, `<header class="cve-head"><p class="cve-id">${esc(id || t("Unknown CVE"))}</p>
    <h1>${te("This CVE is not in the last 12 Microsoft releases.")}</h1></header>
    <p>${te("It may be older, not issued by Microsoft, or the identifier may be mistyped. You can look it up on the original sources:")}</p>
    <ul class="sources">
      <li>${link(`https://msrc.microsoft.com/update-guide/vulnerability/${q}`, "Microsoft Security Update Guide")}</li>
      <li>${link(`https://nvd.nist.gov/vuln/detail/${q}`, "NIST National Vulnerability Database")}</li>
      <li>${link(`https://www.cve.org/CVERecord?id=${q}`, t("CVE.org record"))}</li>
    </ul>`);
}

function link(href, text) {
  return `<a href="${esc(safeUrl(href))}" rel="noopener noreferrer" target="_blank">${esc(text)}</a>`;
}

function page(c, changes) {
  const q = encodeURIComponent(c.cve);
  const overdue = PRIO_RANK[c.priority] <= 2 && c.due < today();
  const kevDue = c.kev?.due_date && c.kev.due_date === c.due;

  const facts = [
    [t("Severity"), esc(sevName(c.severity)), "severity"],
    [t("Impact"), esc(impactName(c.impact))],
    [t("Product family"), esc(c.family)],
    [t("Release"), te("{month} Patch Tuesday", { month: monthName(c.release) })],
    [t("First published"), esc(fmtLong(c.published))],
    [t("Current version"), `${esc(c.revision)}, ${esc(fmtDateTime(c.revised_at))}`],
    [t("Microsoft exploitability"), esc(c.exploited ? t("Exploitation detected") : ASSESS_NAME[c.assessment] || c.assessment || t("Not stated")), "exploitability"],
    [t("Publicly disclosed"), c.disclosed ? te("Yes") : te("No"), "disclosed"],
    [t("Customer action required"), c.action_required ? te("Yes, install the update") : te("No")],
    [t("Public exploit"), c.exploit ? Object.entries(c.exploit).map(([k, u]) => link(u, EXPLOIT_NAME[k] || k)).join(", ") : te("None known"), "public-exploit"],
  ];

  const vector = String(c.vector || "").split("/").slice(1).map((p) => p.split(":"))
    .filter(([k, v]) => CVSS[k] && CVSS[k][1][v]);
  const epssPct = c.epss != null ? c.epss * 100 : null;
  const history = [...(c.history || [])].reverse();
  const en = MPM_LANG === "it" ? ' lang="en"' : "";

  return `
  <header class="cve-head">
    <p class="cve-id">${esc(c.cve)}</p>
    <h1${en}>${esc(c.title)}</h1>
    <div class="head-actions">${scoreBadge(c.score, c.tier)}${followButton(`cve:${c.cve}`)}<span class="hint">Telegram: <code>/watch ${esc(c.cve)}</code></span></div>
  </header>

  <section class="verdict p-${esc(c.priority.toLowerCase())}" aria-labelledby="verdictTitle">
    <div class="verdict-main">
      ${prioBadge(c.priority)}
      <h2 id="verdictTitle">${overdue ? te("Patch is overdue since {date}", { date: fmtLong(c.due) }) : te("Patch by {date}", { date: fmtLong(c.due) })}</h2>
      <p>${kevDue ? te("This is the deadline set by CISA for the KEV catalog.") : te("Priority {p} allows {n} days from the release.", { p: c.priority, n: c.sla_days })}</p>
    </div>
    <ul class="reasons">${priorityReasons(c).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
  </section>

  <div class="cve-grid">
    <section aria-labelledby="factsTitle">
      <h2 id="factsTitle">${te("Key facts")}</h2>
      <dl class="facts">${facts.map(([k, v, g]) => `<div><dt>${esc(k)}${g ? ` ${gloss(g, k)}` : ""}</dt><dd>${v}</dd></div>`).join("")}</dl>
    </section>

    <section aria-labelledby="scoreTitle">
      <h2 id="scoreTitle">${te("Scores")} ${gloss("risk-score", t("Risk score"))}</h2>
      <div class="scores">
        <div class="score">
          <p class="big">${c.cvss ?? "–"}</p>
          <p>${te("CVSS base score")}</p>
        </div>
        <div class="score">
          <p class="big">${epssPct != null ? epssPct.toFixed(1) + "%" : "–"}</p>
          <p>${te("EPSS, chance of exploitation in 30 days")}${c.epss_percentile != null ? te(", higher than {pct}% of all CVEs", { pct: (c.epss_percentile * 100).toFixed(0) }) : ""}</p>
          ${epssPct != null ? `<span class="meter" role="img" aria-label="${te("EPSS {pct} percent", { pct: epssPct.toFixed(1) })}"><span data-w="${Math.max(1, epssPct).toFixed(2)}"></span></span>` : ""}
        </div>
      </div>
      <div class="epss-history" id="epssHistory"></div>
      ${vector.length ? `<table class="vector"><caption>${te("CVSS vector")}</caption><tbody>
        ${vector.map(([k, v]) => `<tr><th scope="row">${esc(CVSS[k][0])}</th><td>${esc(CVSS[k][1][v])}</td></tr>`).join("")}
      </tbody></table>` : ""}
    </section>
  </div>

  ${c.kev ? `<section class="kev-box" aria-labelledby="kevTitle">
    <h2 id="kevTitle">${te("Known exploited vulnerability")} ${gloss("kev", "CISA KEV")}</h2>
    <p>${te("CISA added this CVE to its catalog on {added} and requires US federal agencies to fix it by {due}.", { added: fmtLong(c.kev.date_added), due: fmtLong(c.kev.due_date) })}${c.kev.ransomware ? " " + te("It is known to be used in ransomware campaigns.") : ""}</p>
  </section>` : ""}

  <section class="mitig-box" aria-labelledby="mitTitle">
    <h2 id="mitTitle">${te("If you cannot install yet")} ${gloss("workaround", t("Workaround"))}</h2>
    ${c.mitigations?.length
      ? `<p class="hint">${te("Microsoft publishes these workarounds and mitigations. They reduce the risk until the update is installed; they do not replace it.")}</p>${mitigationList(c.mitigations)}`
      : `<p>${te("Microsoft lists no workaround or mitigation for this vulnerability: install the update.")}</p>`}
  </section>

  <section class="hunt-box" aria-labelledby="huntTitle">
    <h2 id="huntTitle">${te("Detect and hunt")}</h2>
    <p class="hint">${te("Queries for Microsoft Defender XDR advanced hunting or Microsoft Sentinel, with the attack techniques and detection rules for this vulnerability.")}</p>
    <div class="hunt-grid">
      <div><h3>${te("MITRE ATT&CK techniques")} ${gloss("attack", "MITRE ATT&CK")}</h3>${attackList(c) || `<p class="hint">${te("No technique can be suggested from the data Microsoft publishes.")}</p>`}</div>
      <div><h3>${te("Detection rules")}</h3>${c.sigma
        ? `<p>${link(c.sigma.url, t(c.sigma.rules === 1 ? "1 Sigma rule for this CVE" : "{n} Sigma rules for this CVE", { n: c.sigma.rules }))}</p><p class="hint">${te("Sigma rules convert to KQL, Splunk and other SIEM languages with the free sigma-cli tool.")}</p>`
        : `<p class="hint">${te("No public Sigma rule targets this CVE yet.")}</p>`}</div>
    </div>
    ${MPMHunt.kqlForCve(c.cve, c.exploited || Boolean(c.kev)).map(kqlBlock).join("")}
  </section>

  <div class="cve-grid">
    <section aria-labelledby="histTitle">
      <h2 id="histTitle">${te("Revision history")}</h2>
      ${MPM_LANG === "it" ? `<p class="hint">${te("Revision notes are quoted as Microsoft published them, in English.")}</p>` : ""}
      <ol class="history">${history.map((r) => `<li><p class="when">${te("Version {n}, {date}", { n: r.n, date: fmtDateTime(r.date) })}</p><p${r.desc ? en : ""}>${r.desc ? esc(r.desc) : te("No description from Microsoft.")}</p></li>`).join("")}</ol>
      ${changes.length ? `<h3>${te("Changes detected by MPatchMonitor")}</h3>
        <ul class="plain">${changes.map((x) => `<li><strong>${esc(KINDS[x.kind]?.label || x.kind)}</strong>, ${esc(fmtDateTime(x.ts))}. ${esc(changeDetail(x.detail || ""))}</li>`).join("")}</ul>` : ""}
    </section>

    <section aria-labelledby="fixTitle">
      <h2 id="fixTitle">${te("How to fix it")}</h2>
      ${c.updates?.length ? `<p>${te("Install the security updates Microsoft released for the affected products:")}</p>
        <ul class="kbs">${[...new Map(c.updates.map((u) => [u.kb, u])).values()].map((u) => `<li>${/^KB\d{6,8}$/.test(u.kb) ? `<a href="/kb/${esc(u.kb)}">${esc(u.kb)}</a>` : link(u.url, u.kb)}</li>`).join("")}</ul>`
        : `<p>${te("The update details are on the Microsoft page for this CVE.")}</p>`}
      <h3>${te("Affected products")}</h3>
      <ul class="plain products">${(c.products || []).map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
      ${c.products_count > (c.products || []).length ? `<p class="hint">${te("And {n} more listed by Microsoft.", { n: c.products_count - c.products.length })}</p>` : ""}
    </section>
  </div>

  ${changes.some((x) => x.diff) ? `<section class="cve-changes" aria-labelledby="chgTitle">
    <h2 id="chgTitle">${te("What changed in later versions")}</h2>
    ${changes.filter((x) => x.diff).map((x) => `<div class="rev-card${x.action ? " needs-action" : ""}">
      <p class="kind">${esc(KINDS[x.kind]?.label || x.kind)}, ${x.kind === "silent" ? te("version {v} unchanged", { v: x.rev || "?" }) : te("version {a} → {b}", { a: x.diff.from_rev || "?", b: x.rev || "?" })}, ${esc(fmtDateTime(x.ts))}</p>
      ${x.action ? `<p class="action-flag">${x.action === "reinstall" ? te("Microsoft asks to install the update again") : te("Customer action required")}</p>` : ""}
      <div class="badges">${diffBadges(x.diff)}</div>${renderDiff(x.diff)}</div>`).join("")}
  </section>` : ""}

  <section class="sources-block" aria-labelledby="srcTitle">
    <h2 id="srcTitle">${te("Original sources")}</h2>
    <ul class="sources">
      <li>${link(`https://msrc.microsoft.com/update-guide/vulnerability/${q}`, "Microsoft Security Update Guide")}<span>${te("Official advisory, FAQ and updates")}</span></li>
      <li>${link(`https://nvd.nist.gov/vuln/detail/${q}`, "NIST National Vulnerability Database")}<span>${te("Independent analysis and references")}</span></li>
      <li>${link(`https://www.cve.org/CVERecord?id=${q}`, "CVE.org")}<span>${te("The official CVE record")}</span></li>
      ${c.kev ? `<li>${link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${q}`, t("CISA KEV catalog"))}<span>${te("Exploitation evidence and deadline")}</span></li>` : ""}
      <li>${link(`https://api.first.org/data/v1/epss?cve=${q}`, "FIRST EPSS")}<span>${te("Exploit prediction score")}</span></li>
    </ul>
  </section>`;
}
