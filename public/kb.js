"use strict";

/* MPatchMonitor — page for a single security update: /kb/<KBnnnnnnn> */

const xlink = (href, text) => `<a href="${esc(safeUrl(href))}" rel="noopener noreferrer" target="_blank">${esc(text)}</a>`;

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const id = decodeURIComponent(location.pathname.split("/")[2] || "").toUpperCase();
  const root = $("#kb");
  if (!/^KB\d{6,8}$/.test(id)) return kbNotFound(root, id);
  let cat, data;
  try { [cat, data] = await Promise.all([fetchJson("/api/kb"), fetchData().catch(() => null)]); }
  catch (err) { return showFatal(root, err); }
  const k = cat.kbs.find((x) => x.kb === id);
  if (!k) return kbNotFound(root, id);
  const byId = new Map((data?.cves || []).map((c) => [c.cve, c]));
  document.title = `${k.kb}: ${t("Microsoft security update")} – MPatchMonitor`;
  setHTML($("#crumbs"), `<li><a href="/kb">${te("Updates")}</a></li><li><a href="/release/${esc(k.release)}">${esc(cap(monthName(k.release)))}</a></li><li aria-current="page">${esc(k.kb)}</li>`);
  setHTML(root, kbPage(k, byId, cat.kbs));
  applyVars(root);
  root.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy]");
    if (b) copyText($(`#${b.dataset.copy}`).textContent, b);
  });
});

function kbNotFound(root, id) {
  const n = id.replace(/\D/g, "");
  setHTML(root, `<header class="cve-head"><p class="cve-id">${esc(id || t("Unknown update"))}</p>
    <h1>${te("This update is not among the security updates of the last 12 months.")}</h1></header>
    <p>${te("It may be older, a non-security update, or mistyped. Look it up on Microsoft's sites:")}</p>
    <ul class="sources">
      <li>${xlink(`https://catalog.update.microsoft.com/Search.aspx?q=KB${n}`, "Microsoft Update Catalog")}</li>
      <li>${xlink(`https://support.microsoft.com/help/${n}`, t("Microsoft Support article"))}</li>
    </ul>`);
}

function kbPage(k, byId, all) {
  const num = k.kb.slice(2);
  const cves = k.cves.map((id) => byId.get(id) || { cve: id, title: "", severity: "", score: null });
  cves.sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
  const known = new Set(all.map((x) => x.kb));
  const kbRef = (kb) => (known.has(kb) ? `<a href="/kb/${esc(kb)}">${esc(kb)}</a>` : xlink(`https://catalog.update.microsoft.com/Search.aspx?q=${kb}`, kb));
  const isWindows = k.products.some((p) => /^Windows/.test(p));
  const ps = isWindows
    ? `# ${t("Is {kb} (or a later cumulative update) installed?", { kb: k.kb })}\n$kb = "${k.kb}"\n$hit = Get-HotFix -Id $kb -ErrorAction SilentlyContinue\n$os = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"\n$build = "$($os.CurrentBuildNumber).$($os.UBR)"\nif ($hit) { "$kb installed on $($hit.InstalledOn)" } else { "$kb not listed. Current build: $build" }${Object.keys(k.fixed_builds).length ? `\n# ${t("Fixed builds published by Microsoft:")}\n${Object.entries(k.fixed_builds).map(([p, b]) => `#   ${p}: ${b}`).join("\n")}` : ""}`
    : `# ${t("{kb} applies to: {products}", { kb: k.kb, products: k.products.join(", ") })}\n# ${t("Check the installed version against the fixed build below, then deploy with your usual tool.")}\n${Object.entries(k.fixed_builds).map(([p, b]) => `#   ${p}: ${b}`).join("\n")}`;
  const superseded = k.superseded_by.length;
  const facts = [
    [t("Released"), `${esc(fmtLong(k.date))}, ${te("{month} Patch Tuesday", { month: monthName(k.release) })}`],
    [t("Highest severity"), esc(sevName(k.severity))],
    [t("Vulnerabilities fixed"), esc(k.count)],
    [t("Exploited among them"), k.exploited ? `<span class="late">${esc(k.exploited)}</span>` : te("None known")],
    [t("In CISA KEV"), esc(k.kev || t("None"))],
    [t("Highest CVSS"), esc(k.cvss ?? "–")],
    [t("Highest EPSS"), k.epss != null ? `${(k.epss * 100).toFixed(1)}%` : "–"],
    [t("Type"), esc(k.subtypes.map((x) => (x === "Security Update" ? t("Security update") : x)).join(", ") || t("Security update"))],
    [t("Restart"), esc(k.restart.map((x) => (/^yes$/i.test(x) ? t("Yes") : /^no$/i.test(x) ? t("No") : x)).join(", ") || t("Not stated"))],
  ];
  return `
  <header class="cve-head">
    <p class="cve-id">${esc(k.kb)}</p>
    <h1>${te("Security update for {products}", { products: k.products.slice(0, 2).join(t(" and ")) })}${k.products.length > 2 ? te(" and {n} more products", { n: k.products.length - 2 }) : ""}</h1>
    <div class="head-actions">${followButton(`kb:${k.kb}`)}<span class="hint">Telegram: <code>/watch ${esc(k.kb)}</code></span></div>
  </header>

  <section class="verdict ${{ "Patch now": "p-p1", High: "p-p2", Notable: "p-p3" }[k.tier] || "p-p4"}" aria-labelledby="kbVerdict">
    <div class="verdict-main">
      ${scoreBadge(k.score, k.tier)}
      <h2 id="kbVerdict">${superseded ? te("Replaced by a newer update") : k.exploited ? te("Install now: it fixes vulnerabilities already exploited") : k.severity === "Critical" ? te("Install soon: it fixes Critical vulnerabilities") : te("Install with your regular cycle")}</h2>
      <p>${superseded ? te("Deploy {kb} instead; it includes these fixes.", { kb: k.superseded_by.join(t(" or ")) }) : th("Risk score of the most urgent vulnerability it fixes. {link}", { link: `<a href="/method">${te("See how the ranking works.")}</a>` })}</p>
    </div>
    <ul class="reasons">
      ${k.exploited ? `<li>${te(k.exploited === 1 ? "1 of the fixed vulnerabilities is exploited in the wild" : "{n} of the fixed vulnerabilities are exploited in the wild", { n: k.exploited })}</li>` : ""}
      ${k.ransomware ? `<li>${te("At least one is used in ransomware campaigns")}</li>` : ""}
      ${k.public_exploit ? `<li>${te(k.public_exploit === 1 ? "1 has public exploit code" : "{n} have public exploit code", { n: k.public_exploit })}</li>` : ""}
      ${k.known_issues.length ? `<li>${te(k.known_issues.length > 1 ? "Microsoft lists {n} known issues: read before deploying" : "Microsoft lists 1 known issue: read before deploying", { n: k.known_issues.length })}</li>` : `<li>${te("No known issues listed by Microsoft")}</li>`}
      ${k.restart.some((r) => /yes/i.test(r)) ? `<li>${te("Requires a restart")}</li>` : ""}
    </ul>
  </section>

  <div class="cve-grid">
    <section aria-labelledby="kbFacts">
      <h2 id="kbFacts">${te("Key facts")}</h2>
      <dl class="facts">${facts.map(([a, b]) => `<div><dt>${esc(a)}</dt><dd>${b}</dd></div>`).join("")}</dl>
    </section>
    <section aria-labelledby="kbProducts">
      <h2 id="kbProducts">${te("Products and fixed builds")} ${gloss("build", t("Build"))}</h2>
      <table class="vector"><tbody>${k.products.map((p) => `<tr><th scope="row">${esc(p)}</th><td>${esc(k.fixed_builds[p] || "–")}</td></tr>`).join("")}</tbody></table>
      <p class="hint">${th("A device is protected when its build is equal to or later than the fixed build. {link}", { link: `<a href="/my">${te("Check your fleet on My devices.")}</a>` })}</p>
    </section>
  </div>

  ${k.known_issues.length ? `<section class="kev-box" aria-labelledby="kbIssues">
    <h2 id="kbIssues">${te("Known issues")} ${gloss("known-issue", t("Known issue"))}</h2>
    <ul class="plain">${k.known_issues.map((i) => `<li>${xlink(i.url, i.label || t("Microsoft known issue"))}</li>`).join("")}</ul>
  </section>` : ""}

  ${(k.health || []).length ? `<section class="kev-box" aria-labelledby="kbHealth">
    <h2 id="kbHealth">${te("Windows release health")} ${gloss("known-issue", t("Known issue"))}</h2>
    <ul class="health-list">${k.health.map((h) => `<li><strong>${xlink(h.url, h.title)}</strong>
      <span class="id">${h.role === "fixed" ? te("Fixed by this update") : te("Started with this update")} · ${esc(healthStatus(h.status))}${h.updated ? ` · ${esc(fmtDate(h.updated))}` : ""}</span></li>`).join("")}</ul>
    <p class="hint"><a href="/known-issues">${te("Every known issue of Windows updates")}</a></p>
  </section>` : ""}

  ${(() => {
    const withMit = cves.filter((c) => c.mitigations?.length);
    return withMit.length ? `<section class="mitig-box" aria-labelledby="kbMit">
    <h2 id="kbMit">${te("If you cannot install yet")} ${gloss("mitigation", t("Mitigation"))}</h2>
    <p class="hint">${te("Workarounds and mitigations Microsoft publishes for the vulnerabilities this update fixes. They reduce the risk until the update is installed.")}</p>
    ${withMit.slice(0, 12).map((c) => `<h3><a href="/cve/${esc(c.cve)}">${esc(c.cve)}</a></h3>${mitigationList(c.mitigations)}`).join("")}
  </section>` : "";
  })()}

  <section aria-labelledby="kbCves">
    <h2 id="kbCves">${te("Vulnerabilities it fixes")}</h2>
    <div class="table-wrap"><table class="list-table"><thead><tr><th>CVE</th><th>${te("Severity")}</th><th class="num">CVSS</th><th class="num">${te("Risk")}</th></tr></thead>
    <tbody>${cves.map((c) => `<tr><td><a href="/cve/${esc(c.cve)}"><strong>${esc(c.cve)}</strong></a><span class="id">${esc(c.title)}</span></td>
      <td>${esc(c.severity ? sevName(c.severity) : "–")}${c.kev || c.exploited ? ` <span class="sig ex">${te("pill|Exploited")}</span>` : ""}${c.exploit ? ` ${exploitPill()}` : ""}</td><td class="num">${esc(c.cvss ?? "–")}</td>
      <td class="num">${c.score != null ? scoreBadge(c.score, c.tier) : "–"}</td></tr>`).join("")}</tbody></table></div>
  </section>

  <div class="cve-grid">
    <section aria-labelledby="kbChain">
      <h2 id="kbChain">${te("Update chain")} ${gloss("supersedence", t("Supersedence"))}</h2>
      <dl class="facts">
        <div><dt>${te("Replaces")}</dt><dd>${k.supersedes.length ? k.supersedes.map(kbRef).join(", ") : te("Nothing stated")}</dd></div>
        <div><dt>${te("Replaced by")}</dt><dd>${k.superseded_by.length ? k.superseded_by.map(kbRef).join(", ") : te("Nothing yet: this is the latest")}</dd></div>
      </dl>
    </section>
    <section aria-labelledby="kbDeploy">
      <h2 id="kbDeploy">${te("Check and deploy")}</h2>
      <pre class="code" id="kbPs">${esc(ps)}</pre>
      <button type="button" class="ghost" data-copy="kbPs">${te("Copy PowerShell")}</button>
      ${isWindows ? `<h3>${te("Deploy fast with Intune")}</h3>
      <ol class="steps">
        <li>${te("Intune admin center, Devices, Windows updates, Quality updates, Create profile.")}</li>
        <li>${te("Choose the quality update released on {date} or later and set the days before a restart is forced.", { date: fmtLong(k.date) })}</li>
        <li>${te("Assign it to the group of affected devices and follow the report in the same page.")}</li>
      </ol>` : ""}
    </section>
  </div>

  <section class="hunt-box" aria-labelledby="kbHunt">
    <h2 id="kbHunt">${te("Find the devices that need it")}</h2>
    <p class="hint">${te("Queries for Microsoft Defender XDR advanced hunting or Microsoft Sentinel (Defender Vulnerability Management data).")}</p>
    ${MPMHunt.kqlForKb(k.kb).map(kqlBlock).join("")}
  </section>

  <section class="sources-block" aria-labelledby="kbSrc">
    <h2 id="kbSrc">${te("Original sources")}</h2>
    <ul class="sources">
      <li>${xlink(k.catalog_url, "Microsoft Update Catalog")}<span>${te("Download the packages")}</span></li>
      <li>${xlink(k.support_url, t("Microsoft Support article"))}<span>${te("Release notes and known issues")}</span></li>
      <li>${xlink(`https://msrc.microsoft.com/update-guide/releaseNote/${encodeURIComponent(k.release)}`, t("Security Update Guide release notes"))}<span>${te("The whole {month} release", { month: monthName(k.release) })}</span></li>
      <li>${xlink(`https://learn.microsoft.com/${MPM_LANG === "it" ? "it-it" : "en-us"}/intune/intune-service/protect/windows-10-expedite-updates`, t("Expedite quality updates in Intune"))}<span>Microsoft Learn</span></li>
    </ul>
    <p class="hint">${te("Data from the Microsoft Security Update Guide, CISA KEV and FIRST EPSS.")} KB ${esc(num)}.</p>
  </section>`;
}
