"use strict";

/* MPatchMonitor — one engine for every tracker page (/kb, /hot, /exploited, /open-source,
 * /end-of-life, /breaches, /docs-tracker, /acn). Each page is a configuration below. */

const daysBetween = (a, b = today()) => Math.round((Date.parse(b) - Date.parse(a)) / 86_400_000);
const pct = (v) => (v == null ? "–" : `${(v * 100).toFixed(1)}%`);
const sigs = (r) => [
  r.kev || r.exploited ? `<span class="sig ex">${te("pill|Exploited")}</span>` : "",
  r.ransomware ? `<span class="sig kev">${te("Ransomware")}</span>` : "",
  r.public_exploit || r.exploit ? exploitPill() : "",
].join("");
const extLink = (href, text) => `<a href="${esc(safeUrl(href))}" rel="noopener noreferrer" target="_blank">${esc(text)}</a>`;
const STATUS = { ended: [t("Out of support"), "ex"], ending: [t("Ends within 6 months"), "kev"], supported: [t("Supported"), "rev"] };

const PAGES_CFG = {
  "/kb": {
    title: t("Every Microsoft security update of the last twelve months, with what it fixes."),
    intro: t("Each update lists the CVEs it fixes, whether any is already exploited, Microsoft's known issues, which updates it replaces, and how to check and deploy it."),
    api: "/api/kb", rows: (d) => d.kbs, tableTitle: t("Security updates"), jump: true,
    search: (r) => `${r.kb} ${r.products.join(" ")} ${r.cves.join(" ")}`,
    filters: [
      { type: "select", label: t("Any product"), param: "product", options: (rows) => [...new Set(rows.flatMap((r) => r.products))].sort(), test: (r, v) => r.products.includes(v) },
      { type: "select", label: t("Any severity"), options: () => ["Critical", "Important", "Moderate", "Low"], optLabel: sevName, test: (r, v) => r.severity === v },
      { type: "check", label: t("Fixes an exploited CVE"), test: (r) => r.exploited > 0 },
      { type: "check", label: t("Has known issues"), test: (r) => r.known_issues.length > 0 },
      { type: "check", label: t("Public exploit"), test: (r) => r.public_exploit > 0 },
      { type: "check", label: t("Has mitigations"), test: (r) => r.mitigations > 0 },
    ],
    figures: (rows) => [[t("Security updates"), rows.length], [t("Fix an exploited CVE"), rows.filter((r) => r.exploited).length, "crit"],
      [t("Rated Critical"), rows.filter((r) => r.severity === "Critical").length, "warn"], [t("With known issues"), rows.filter((r) => r.known_issues.length).length, "rev"]],
    sort: "date", dir: -1,
    columns: [
      { label: t("Update"), key: "kb", html: (r) => `<a href="/kb/${esc(r.kb)}"><strong>${esc(r.kb)}</strong></a><span class="id">${esc(fmtDate(r.date))}</span>`, csv: (r) => r.kb },
      { label: t("Products"), key: "products", html: (r) => `${esc(r.products.slice(0, 2).join(", "))}${r.products.length > 2 ? `<span class="id">${te("and {n} more", { n: r.products.length - 2 })}</span>` : ""}`, csv: (r) => r.products.join("; ") },
      { label: "CVEs", key: "count", cls: "num", html: (r) => esc(r.count) },
      { label: t("Exploited"), key: "exploited", cls: "num", html: (r) => (r.exploited ? `<span class="late">${esc(r.exploited)}</span>` : "–") },
      { label: t("Severity"), key: "severity", html: (r) => esc(sevName(r.severity)) },
      { label: t("Risk"), key: "score", cls: "num", html: (r) => scoreBadge(r.score, r.tier), csv: (r) => r.score },
      { label: t("Known issues"), key: "known_issues", html: (r) => (r.known_issues.length ? `<span class="sig kev">${te("Yes")}</span>` : "–"), csv: (r) => r.known_issues.length },
      { label: t("Date"), key: "date", hidden: true, csv: (r) => r.date },
    ],
    link: (r) => `/kb/${r.kb}`,
    notes: t("Sources: Microsoft Security Update Guide (fixes, known issues, supersedence), CISA KEV, FIRST EPSS. Downloads are on the Microsoft Update Catalog, linked from each update page."),
  },

  "/hot": {
    title: t("What deserves your attention right now."),
    intro: t("The highest-risk vulnerabilities and Microsoft updates, ranked by a transparent score that puts confirmed exploitation first, then ransomware use, EPSS, CVSS and recency."),
    api: "/api/hot", tableTitle: t("Ranked list"),
    tabs: [{ id: "cves", label: t("Everything") }, { id: "cvesMs", label: "Microsoft" }, { id: "cvesNonMs", label: t("Other vendors") }, { id: "kbs", label: t("Updates to deploy") }],
    rows: (d, tab) => (d[tab] || []).map((r, i) => ({ ...r, rank: i + 1 })),
    search: (r) => `${r.id} ${r.title} ${r.vendor || ""}`,
    sort: "rank", dir: 1,
    columns: [
      { label: "#", key: "rank", cls: "num", html: (r) => esc(r.rank) },
      { label: t("Item"), key: "id", html: (r) => `<a href="${esc(safeUrl(r.link))}"${String(r.link).startsWith("http") ? ' rel="noopener noreferrer" target="_blank"' : ""}><strong>${esc(r.id)}</strong></a><span class="id">${esc(r.title)}</span>`, csv: (r) => r.id },
      { label: t("Risk"), key: "score", cls: "num", html: (r) => scoreBadge(r.score, r.tier), csv: (r) => r.score },
      { label: t("Signals"), key: "kev", html: (r) => sigs(r) || "–", csv: (r) => (r.kev ? t("exploited") : "") },
      { label: "EPSS", key: "epss", cls: "num", html: (r) => (r.cves != null ? te("{n} CVEs", { n: r.cves }) : pct(r.epss)), csv: (r) => r.epss ?? r.cves },
      { label: t("Vendor"), key: "vendor", html: (r) => esc(r.vendor || (r.microsoft !== false ? "Microsoft" : "")), csv: (r) => r.vendor || "Microsoft" },
    ],
    link: (r) => r.link,
    notes: t("How the score works: see “How the ranking works”. Exploitation from CISA KEV and Microsoft; EPSS from FIRST; CVSS from Microsoft and NIST NVD."),
  },

  "/exploited": {
    title: t("Vulnerabilities attackers are using, every vendor."),
    intro: t("Every entry in the CISA Known Exploited Vulnerabilities catalog, newest first, with EPSS, CVSS and the federal remediation deadline. Microsoft entries link to their full page here."),
    api: "/api/kev", rows: (d) => d.kev, tableTitle: t("Known exploited vulnerabilities"),
    tabs: [{ id: "7", label: t("Last 7 days") }, { id: "30", label: t("Last 30 days") }, { id: "365", label: t("Last 12 months") }, { id: "all", label: t("Entire catalog") }],
    defaultTab: "30",
    tabFilter: (r, tab) => tab === "all" || daysBetween(r.added) <= Number(tab),
    search: (r) => `${r.cve} ${r.vendor} ${r.product} ${r.name}`,
    filters: [
      { type: "select", label: t("Every vendor"), options: () => ["Microsoft", "other"], optLabel: (o) => (o === "other" ? t("Other vendors") : o), test: (r, v) => (v === "Microsoft" ? r.microsoft : !r.microsoft), param: "scope", map: { other: "other", microsoft: "Microsoft" } },
      { type: "check", label: t("Used in ransomware"), test: (r) => r.ransomware },
      { type: "check", label: t("Public exploit"), test: (r) => Boolean(r.exploit) },
    ],
    figures: (rows) => [[t("Added in this period"), rows.length], [t("Microsoft"), rows.filter((r) => r.microsoft).length, "warn"],
      [t("Used in ransomware"), rows.filter((r) => r.ransomware).length, "crit"], [t("Past their federal deadline"), rows.filter((r) => r.due && r.due < today()).length]],
    sort: "added", dir: -1,
    columns: [
      { label: t("Vulnerability"), key: "cve", html: (r) => `${r.microsoft ? `<a href="/cve/${esc(r.cve)}"><strong>${esc(r.cve)}</strong></a>` : extLink(r.nvd_url, r.cve)}<span class="id">${esc(r.name)}</span>`, csv: (r) => r.cve },
      { label: t("Vendor and product"), key: "vendor", html: (r) => `${esc(r.vendor)}<span class="id">${esc(r.product)}</span>`, csv: (r) => `${r.vendor} ${r.product}` },
      { label: t("Added"), key: "added", cls: "num", html: (r) => esc(fmtDate(r.added)), csv: (r) => r.added },
      { label: t("Deadline"), key: "due", cls: "num", html: (r) => `<span class="${r.due && r.due < today() ? "late" : ""}">${esc(fmtDate(r.due))}</span>`, csv: (r) => r.due },
      { label: "EPSS", key: "epss", cls: "num", html: (r) => pct(r.epss), csv: (r) => r.epss },
      { label: "CVSS", key: "cvss", cls: "num", html: (r) => esc(r.cvss ?? "–") },
      { label: t("Risk"), key: "score", cls: "num", html: (r) => `${scoreBadge(r.score, r.tier)}${r.ransomware ? `<span class="sig kev">${te("Ransomware")}</span>` : ""}${r.exploit ? exploitPill() : ""}`, csv: (r) => r.score },
      { label: "ATT&CK", key: "attack", html: (r) => ((r.attack || []).filter((x) => /^T\d{4}(\.\d{3})?$/.test(x)).map((x) => `<a class="sig" href="${esc(MPMHunt.attackUrl(x))}" rel="noopener noreferrer" target="_blank">${esc(x)}</a>`).join("") || "–")
        + (r.sigma ? `<span class="id">${extLink(r.sigma, "Sigma")}</span>` : ""), csv: (r) => (r.attack || []).join(" ") },
    ],
    kql: (rows) => MPMHunt.kqlForList(rows.map((r) => r.cve)),
    link: (r) => (r.microsoft ? `/cve/${r.cve}` : null),
    notes: t("Source: CISA Known Exploited Vulnerabilities catalog (public domain). EPSS from FIRST, CVSS from NIST NVD. The deadline is the one CISA sets for US federal agencies; it is a useful benchmark for everyone else."),
  },

  "/open-source": {
    title: t("Exploited open-source packages, and the version that fixes them."),
    intro: t("Known exploited vulnerabilities mapped to the open-source packages they affect, with the first patched version from the GitHub Advisory Database."),
    api: "/api/oss", rows: (d) => d.items, tableTitle: t("Packages to update"),
    search: (r) => `${r.cve} ${r.package} ${r.ecosystem} ${r.vendor}`,
    filters: [{ type: "select", label: t("Every ecosystem"), options: (rows) => [...new Set(rows.map((r) => r.ecosystem))].sort(), test: (r, v) => r.ecosystem === v }],
    figures: (rows, d) => [[t("Package advisories"), rows.length], [t("Ecosystems"), new Set(rows.map((r) => r.ecosystem)).size],
      [t("Used in ransomware"), rows.filter((r) => r.ransomware).length, "crit"], [t("Exploited CVEs checked"), d.checked ?? "–"]],
    sort: "score", dir: -1,
    columns: [
      { label: t("Package"), key: "package", html: (r) => `<strong>${esc(r.package)}</strong><span class="id">${esc(r.ecosystem)}</span>`, csv: (r) => `${r.ecosystem}:${r.package}` },
      { label: t("Vulnerable"), key: "affected", html: (r) => esc(r.affected || "–") },
      { label: t("Fixed in"), key: "fixed", html: (r) => (r.fixed ? `<strong class="ok">${esc(r.fixed)}</strong>` : `<span class="late">${te("No fix yet")}</span>`), csv: (r) => r.fixed },
      { label: t("Vulnerability"), key: "cve", html: (r) => `${extLink(r.url, r.ghsa || r.cve)}<span class="id">${esc(r.cve)}</span>`, csv: (r) => r.cve },
      { label: "EPSS", key: "epss", cls: "num", html: (r) => pct(r.epss) },
      { label: t("Risk"), key: "score", cls: "num", html: (r) => `${scoreBadge(r.score)}${r.ransomware ? `<span class="sig kev">${te("Ransomware")}</span>` : ""}`, csv: (r) => r.score },
    ],
    notes: t("Sources: GitHub Advisory Database (CC BY 4.0), CISA KEV, FIRST EPSS. Confirm the fixed version on the linked advisory before deploying."),
  },

  "/end-of-life": {
    title: t("Software that no longer gets security fixes."),
    intro: t("Support end dates for Microsoft products and other widely used software. Anything past its end of support stops receiving security updates, whatever its patch level."),
    api: "/api/eol", rows: (d) => d.items, tableTitle: t("Versions and support dates"),
    tabs: [{ id: "ms", label: "Microsoft" }, { id: "all", label: t("Everything") }], defaultTab: "ms",
    tabFilter: (r, tab) => tab === "all" || r.microsoft,
    search: (r) => `${r.product} ${r.label} ${r.cycle}`,
    filters: [{ type: "select", label: t("Any status"), options: () => Object.keys(STATUS), optLabel: (o) => STATUS[o][0], test: (r, v) => r.status === v }],
    figures: (rows) => [[t("Versions tracked"), rows.length], [t("Out of support"), rows.filter((r) => r.status === "ended").length, "crit"],
      [t("Ending within 6 months"), rows.filter((r) => r.status === "ending").length, "warn"], [t("Supported"), rows.filter((r) => r.status === "supported").length, "rev"]],
    sort: "status", dir: 1, sortValue: { status: (r) => ({ ended: 0, ending: 1, supported: 2 }[r.status]) },
    columns: [
      { label: t("Product"), key: "product", html: (r) => `<strong>${esc(r.product)}</strong><span class="id">${esc(r.label)}${r.lts ? te(", long-term support") : ""}</span>`, csv: (r) => `${r.product} ${r.label}` },
      { label: t("Released"), key: "released", cls: "num", html: (r) => esc(fmtDate(r.released)), csv: (r) => r.released },
      { label: t("Mainstream support ends"), key: "support_end", cls: "num", html: (r) => esc(fmtDate(r.support_end)), csv: (r) => r.support_end },
      { label: t("Security updates end"), key: "eol", cls: "num", html: (r) => `${esc(fmtDate(r.extended_end || r.eol))}${r.extended_end ? `<span class="id">${te("extended support")}</span>` : ""}`, csv: (r) => r.extended_end || r.eol },
      { label: t("Status"), key: "status", html: (r) => `<span class="sig ${STATUS[r.status]?.[1] || ""}">${esc(STATUS[r.status]?.[0] || r.status)}</span>${r.days_left != null && r.days_left >= 0 ? `<span class="id">${te("{n} days left", { n: r.days_left })}</span>` : ""}`, csv: (r) => r.status },
      { label: t("Latest"), key: "latest", html: (r) => `${esc(r.latest || "–")}<span class="id">${extLink(r.link, "endoflife.date")}</span>`, csv: (r) => r.latest },
    ],
    notes: t("Source: endoflife.date, a community project (MIT licence). Always confirm dates against the vendor's official lifecycle policy, such as the Microsoft Lifecycle site."),
  },

  "/breaches": {
    title: t("Data breaches, confirmed and disclosed."),
    intro: t("Verified breaches from Have I Been Pwned and cybersecurity incidents that US public companies must disclose to the SEC (Form 8-K, Item 1.05)."),
    api: "/api/breaches", tableTitle: t("Breaches"),
    tabs: [{ id: "hibp", label: t("Verified breaches") }, { id: "sec", label: t("SEC incident filings") }],
    rows: (d, tab) => d[tab] || [],
    search: (r) => `${r.name || r.company} ${r.domain || ""}`,
    sort: "date", dir: -1, sortValue: { date: (r) => r.added || r.filed },
    columnsFor: (tab) => tab === "sec" ? [
      { label: t("Company"), key: "company", html: (r) => `<strong>${esc(r.company)}</strong>` },
      { label: t("Filed"), key: "filed", cls: "num", html: (r) => esc(fmtDate(r.filed)), csv: (r) => r.filed },
      { label: t("Filing"), key: "url", html: (r) => extLink(r.url, t("{form} on SEC EDGAR", { form: r.form })), csv: (r) => r.url },
    ] : [
      { label: t("Breach"), key: "name", html: (r) => `<strong>${esc(r.name)}</strong><span class="id">${esc(r.domain || "")}</span>` },
      { label: t("Happened"), key: "breach_date", cls: "num", html: (r) => esc(fmtDate(r.breach_date)), csv: (r) => r.breach_date },
      { label: t("Published"), key: "added", cls: "num", html: (r) => esc(fmtDate(r.added)), csv: (r) => r.added },
      { label: t("Accounts"), key: "accounts", cls: "num", html: (r) => esc(Number(r.accounts).toLocaleString(LOCALE)) },
      { label: t("Data exposed"), key: "data", html: (r) => esc((r.data || []).join(", ")), csv: (r) => (r.data || []).join("; ") },
      { label: t("Source"), key: "url", html: (r) => extLink(r.url, "Have I Been Pwned"), csv: (r) => r.url },
    ],
    notes: t("Sources: Have I Been Pwned (CC BY 4.0; only verified, non-sensitive breaches are listed) and SEC EDGAR full-text search. Verify on the linked source before acting."),
  },

  "/docs-tracker": {
    title: t("What changed in Microsoft's security documentation."),
    intro: t("Changes of the last two weeks to the public documentation for Entra ID, Intune, Defender, Windows, Windows Server, Microsoft Graph and Microsoft support articles. Only the change note is shown, with a link to the change."),
    api: "/api/docs", rows: (d) => d.items, tableTitle: t("Documentation changes"),
    search: (r) => `${r.area} ${r.message}`,
    filters: [{ type: "select", label: t("Every area"), options: (rows) => [...new Set(rows.map((r) => r.area))].sort(), test: (r, v) => r.area === v }],
    sort: "date", dir: -1,
    columns: [
      { label: t("When"), key: "date", cls: "num", html: (r) => esc(fmtDateTime(r.date)), csv: (r) => r.date },
      { label: t("Area"), key: "area", html: (r) => esc(r.area) },
      { label: t("Change"), key: "message", html: (r) => esc(r.message) },
      { label: t("Source"), key: "url", html: (r) => extLink(r.url, r.repo), csv: (r) => r.url },
    ],
    notes: t("Source: Microsoft's public documentation repositories on GitHub. No article text is copied."),
  },

  "/known-issues": {
    title: t("Known issues of Windows updates."),
    intro: t("Problems Microsoft has confirmed after Windows updates, from its release health pages: which update started them, the workaround, and the update that fixes them. Check them before a wide rollout."),
    api: "/api/known-issues", rows: (d) => d.items, tableTitle: t("Known issues"),
    tabs: [{ id: "open", label: t("issues|Open") }, { id: "resolved", label: t("issues|Resolved") }, { id: "all", label: t("issues|All") }], defaultTab: "open",
    tabFilter: (r, tab) => tab === "all" || (tab === "resolved") === /^Resolved/.test(r.status),
    search: (r) => `${r.title} ${r.summary} ${(r.kbs || []).join(" ")} ${r.resolved_kb || ""} ${(r.products || []).join(" ")}`,
    filters: [
      { type: "select", label: t("Every Windows version"), options: (rows) => [...new Set(rows.flatMap((r) => r.products || []))].sort(), test: (r, v) => (r.products || []).includes(v) },
      { type: "check", label: t("Has a workaround"), test: (r) => Boolean(r.workaround) },
    ],
    figures: (rows, d) => {
      const all = d.items || [];
      return [[t("Open issues"), all.filter((r) => !/^Resolved/.test(r.status)).length, "warn"],
        [t("Confirmed, no fix yet"), all.filter((r) => r.status === "Confirmed").length, "crit"],
        [t("Resolved in the last 30 days"), all.filter((r) => /^Resolved/.test(r.status) && r.updated && daysBetween(r.updated) <= 30).length, "rev"],
        [t("With a workaround"), all.filter((r) => r.workaround).length]];
    },
    sort: "updated", dir: -1,
    columns: [
      { label: t("Issue"), key: "title", html: (r) => `${extLink(r.url, r.title)}${r.summary ? `<span class="id">${esc(r.summary)}</span>` : ""}${r.workaround
        ? `<details class="wa"><summary>${te("Workaround")}</summary><p${MPM_LANG === "it" ? ' lang="en"' : ""}>${esc(r.workaround)}</p></details>` : ""}`, csv: (r) => r.title },
      { label: t("Windows versions"), key: "products", html: (r) => esc((r.products || []).join(", ")), csv: (r) => (r.products || []).join("; ") },
      { label: t("Started with"), key: "kb", html: (r) => (r.kbs || []).map(kbLink).join(", ") || "–", csv: (r) => (r.kbs || []).join(" ") },
      { label: t("Status"), key: "status", html: (r) => `<span class="sig ${/^Resolved/.test(r.status) ? "rev" : r.status === "Confirmed" ? "ex" : "kev"}">${esc(healthStatus(r.status))}</span>${r.resolved_kb ? `<span class="id">${th("fixed by {kb}", { kb: kbLink(r.resolved_kb) })}</span>` : ""}`, csv: (r) => r.status },
      { label: t("Updated"), key: "updated", cls: "num", html: (r) => esc(fmtDate(r.updated)), csv: (r) => r.updated },
      { label: t("Workaround"), key: "workaround", hidden: true, csv: (r) => r.workaround || "" },
      { label: t("Link"), key: "url", hidden: true, csv: (r) => r.url },
    ],
    notes: t("Source: Windows release health on Microsoft Learn, checked every few hours. Microsoft's descriptions are quoted in English. Telegram: /watch issues."),
    extra: async () => {
      try { const k = await fetchJson("/api/kb"); window.MPM_KBS = new Set(k.kbs.map((x) => x.kb)); } catch { window.MPM_KBS = new Set(); }
    },
  },

  "/acn": {
    title: t("Microsoft in CSIRT Italia bulletins."),
    intro: t("The Italian national CSIRT, part of the Agenzia per la Cybersicurezza Nazionale, publishes alerts on vulnerabilities and updates. Every bulletin that mentions Microsoft is recorded here within minutes, with its CVEs linked to their pages."),
    api: "/api/acn", rows: (d) => d.items, tableTitle: t("Bulletins mentioning Microsoft"),
    search: (r) => `${r.title} ${(r.cves || []).join(" ")}`,
    figures: (rows, d) => [[t("Bulletins recorded"), rows.length], [t("Last 30 days"), rows.filter((r) => daysBetween(r.published) <= 30).length, "warn"],
      [t("CVEs referenced"), new Set(rows.flatMap((r) => r.cves || [])).size], [t("Feed checked"), d.status?.last_check ? timeAgo(d.status.last_check) : t("not yet"), d.status?.ok === false ? "crit" : "rev"]],
    sort: "published", dir: -1,
    columns: [
      { label: t("Published"), key: "published", cls: "num", html: (r) => esc(fmtDateTime(r.published)), csv: (r) => r.published },
      { label: t("Bulletin"), key: "title", html: (r) => `${extLink(r.link, r.title)}${r.summary ? `<span class="id">${esc(r.summary.slice(0, 220))}${r.summary.length > 220 ? "…" : ""}</span>` : ""}`, csv: (r) => r.title },
      { label: "CVEs", key: "cves", html: (r) => (r.cves || []).slice(0, 8).map((c) => (window.MPM_KNOWN?.has(c) ? `<a class="sig rev" href="/cve/${esc(c)}">${esc(c)}</a>` : `<span class="sig">${esc(c)}</span>`)).join("") + ((r.cves || []).length > 8 ? `<span class="id">${te("and {n} more", { n: (r.cves || []).length - 8 })}</span>` : "") || "–", csv: (r) => (r.cves || []).join(" ") },
      { label: t("Link"), key: "link", hidden: true, csv: (r) => r.link },
    ],
    notes: t("Source: CSIRT Italia public RSS feed on acn.gov.it, checked every 15 minutes. Monitoring the CSIRT Italia channels is part of measure ID.RA-08 of the ACN baseline specifications for NIS2; the evidence report includes these bulletins. Highlighted CVEs have their own page on this site."),
    extra: async () => {
      try { const d = await fetchData(); window.MPM_KNOWN = new Set(d.cves.map((c) => c.cve)); } catch { window.MPM_KNOWN = new Set(); }
    },
  },
};

const kbLink = (kb) => (/^KB\d{6,8}$/.test(kb) ? (window.MPM_KBS?.has(kb) ? `<a href="/kb/${esc(kb)}">${esc(kb)}</a>` : esc(kb)) : "");

const L = { cfg: null, data: null, rows: [], tab: null, sortKey: null, sortDir: 1 };

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  const path = location.pathname.replace(/\/$/, "") || "/";
  L.cfg = PAGES_CFG[path];
  if (!L.cfg) return showFatal($("#main"), new Error("unknown page"));
  const c = L.cfg;
  $("#lTitle").textContent = c.title;
  $("#lIntro").textContent = c.intro;
  $("#lTableTitle").textContent = c.tableTitle;
  setHTML($("#lNotes"), `<p class="hint">${esc(c.notes)}</p>`);
  L.sortKey = c.sort; L.sortDir = c.dir || 1;
  const qs = new URLSearchParams(location.search);
  L.tab = c.tabs ? (c.tabs.some((x) => x.id === qs.get("tab")) ? qs.get("tab") : c.defaultTab || c.tabs[0].id) : null;
  try {
    [L.data] = await Promise.all([fetchJson(c.api), c.extra ? c.extra() : null]);
  } catch (err) {
    if (err.empty) return setHTML($(".list-queue"), `<p class="fatal">${te("This dataset has not been published yet. It appears after the next data refresh.")}</p>`);
    return showFatal($("#main"), err);
  }
  const updated = L.data.generated_at || L.data.status?.last_check;
  $("#lMeta").textContent = updated ? t("Updated {ago}.", { ago: timeAgo(updated) }) : "";
  if (c.jump) initJump();
  buildFilters(qs);
  bindList();
  render();
});

function baseRows() { return L.cfg.rows ? L.cfg.rows(L.data, L.tab) : []; }

function buildFilters(qs) {
  const all = baseRows();
  const c = L.cfg;
  const parts = [`<input type="search" id="lQ" placeholder="${te("Search")}" aria-label="${te("Search")}">`];
  (c.filters || []).forEach((f, i) => {
    if (f.type === "select") {
      const opts = f.options(all);
      const pre = f.param ? (f.map ? f.map[qs.get(f.param)] : qs.get(f.param)) : null;
      parts.push(`<select id="lF${i}" aria-label="${esc(f.label)}"><option value="">${esc(f.label)}</option>${opts.map((o) => `<option value="${esc(o)}"${o === pre ? " selected" : ""}>${esc(f.optLabel ? f.optLabel(o) : o)}</option>`).join("")}</select>`);
    } else parts.push(`<label class="check"><input type="checkbox" id="lF${i}"> ${esc(f.label)}</label>`);
  });
  setHTML($("#lFilters"), parts.join(""));
  if (qs.get("q")) $("#lQ").value = qs.get("q").slice(0, 100);
  if (c.tabs) {
    setHTML($("#lTabs"), c.tabs.map((x) => `<button type="button" class="chip" data-tab="${esc(x.id)}" aria-pressed="${x.id === L.tab}">${esc(x.label)}</button>`).join(""));
  }
}

function bindList() {
  $("#lFilters").addEventListener("input", render);
  if (L.cfg.kql) {
    const b = Object.assign(document.createElement("button"), { type: "button", className: "btn ghost", id: "lKql", textContent: t("Copy KQL") });
    b.title = t("Defender XDR / Sentinel query for the vulnerabilities in this list (up to 500)");
    $("#lCsv").before(b);
    b.addEventListener("click", () => copyText(L.cfg.kql(filtered()), b));
  }
  $("#lTabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tab]");
    if (!b) return;
    L.tab = b.dataset.tab;
    $$("#lTabs [data-tab]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.tab === L.tab)));
    const u = new URL(location.href); u.searchParams.set("tab", L.tab); history.replaceState(null, "", u);
    render();
  });
  $("#lTable thead").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-k]");
    if (!th) return;
    L.sortDir = L.sortKey === th.dataset.k ? -L.sortDir : (["score", "count", "exploited", "epss", "cvss", "accounts"].includes(th.dataset.k) ? -1 : 1);
    L.sortKey = th.dataset.k;
    render();
  });
  $("#lTable tbody").addEventListener("click", (e) => {
    if (e.target.closest("a")) return;
    const tr = e.target.closest("tr[data-href]");
    if (tr && tr.dataset.href.startsWith("/")) location.href = tr.dataset.href;
  });
  $("#lCsv").addEventListener("click", () => {
    const cols = columns();
    const lines = [cols.map((c) => csvCell(c.label)).join(",")].concat(L.rows.map((r) =>
      cols.map((c) => csvCell(c.csv ? c.csv(r) : r[c.key])).join(",")));
    downloadFile(`mpatchmonitor${location.pathname.replace(/\//g, "-")}-${today()}.csv`, "﻿" + lines.join("\r\n"), "text/csv;charset=utf-8");
  });
  $("#lJson").addEventListener("click", () => downloadFile(`mpatchmonitor${location.pathname.replace(/\//g, "-")}-${today()}.json`,
    JSON.stringify(L.rows, null, 1), "application/json"));
}

function columns() { return L.cfg.columnsFor ? L.cfg.columnsFor(L.tab) : L.cfg.columns; }

function filtered() {
  const c = L.cfg;
  const q = ($("#lQ")?.value || "").trim().toLowerCase();
  let rows = baseRows();
  if (c.tabFilter) rows = rows.filter((r) => c.tabFilter(r, L.tab));
  if (q) rows = rows.filter((r) => c.search(r).toLowerCase().includes(q));
  (c.filters || []).forEach((f, i) => {
    const el = $(`#lF${i}`);
    if (f.type === "select" && el.value) rows = rows.filter((r) => f.test(r, el.value));
    if (f.type === "check" && el.checked) rows = rows.filter((r) => f.test(r));
  });
  const key = L.sortKey, dir = L.sortDir;
  const val = c.sortValue?.[key] || ((r) => { const v = r[key]; return Array.isArray(v) ? v.length : v; });
  return rows.sort((a, b) => {
    const x = val(a) ?? null, y = val(b) ?? null;
    if (x === y) return 0;
    if (x === null) return 1;
    if (y === null) return -1;
    return (x > y ? 1 : -1) * dir;
  });
}

function render() {
  const c = L.cfg;
  const cols = columns().filter((x) => !x.hidden);
  L.rows = filtered();
  if (c.figures) {
    setHTML($("#lFigures"), c.figures(L.rows, L.data).map(([label, n, cls]) =>
      `<div class="fig ${cls || ""}"><dt>${esc(label)}</dt><dd>${esc(n)}</dd></div>`).join(""));
  }
  setHTML($("#lTable thead"), `<tr>${cols.map((x) => `<th scope="col" data-k="${esc(x.key)}" class="${x.cls || ""}" aria-sort="${x.key === L.sortKey ? (L.sortDir > 0 ? "ascending" : "descending") : "none"}">${esc(x.label)}</th>`).join("")}</tr>`);
  $("#lCount").textContent = t("{n} of {total}", { n: L.rows.length, total: baseRows().length });
  setHTML($("#lTable tbody"), L.rows.slice(0, 500).map((r) => {
    const href = c.link ? c.link(r) : null;
    return `<tr${href && href.startsWith("/") ? ` data-href="${esc(href)}"` : ""}>${cols.map((x) => `<td class="${x.cls || ""}">${x.html(r)}</td>`).join("")}</tr>`;
  }).join("") || `<tr><td colspan="${cols.length}" class="empty">${te("Nothing matches. Clear the search or a filter.")}</td></tr>`);
}

function initJump() {
  $("#lJump").hidden = false;
  const go = () => {
    const n = $("#jump").value.toUpperCase().replace(/^KB/, "").replace(/\D/g, "");
    if (n.length >= 6 && n.length <= 8) location.href = `/kb/KB${n}`;
  };
  $("#jumpGo").addEventListener("click", go);
  $("#jump").addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
}
