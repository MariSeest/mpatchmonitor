"use strict";

/* MPatchMonitor — shared helpers for the dashboard and the CVE pages.
 * Every piece of data is escaped with esc() before it reaches the DOM; the page runs
 * under Trusted Types, so HTML can only be inserted through setHTML(). */

const MPM_POLICY = window.trustedTypes
  ? window.trustedTypes.createPolicy("mpm", {
    createHTML: (s) => s,
    // the only script URL the site ever loads dynamically is its own service worker
    createScriptURL: (s) => { if (s !== "/sw.js") throw new TypeError("script URL not allowed"); return s; },
  })
  : { createHTML: (s) => s, createScriptURL: (s) => s };

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const setHTML = (el, html) => { el.innerHTML = MPM_POLICY.createHTML(html); };

/** CSP forbids inline style attributes: geometry is passed as data-* and applied via CSSOM. */
function applyVars(root) {
  root.querySelectorAll("[data-h]").forEach((e) => e.style.setProperty("--h", `${e.dataset.h}%`));
  root.querySelectorAll("[data-w]").forEach((e) => e.style.setProperty("--w", `${e.dataset.w}%`));
}

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** Only allow absolute https links (data from the pipeline is already filtered). */
const safeUrl = (u) => {
  try { const x = new URL(u); return x.protocol === "https:" ? x.href : "#"; } catch { return "#"; }
};

const PRIO_RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };
const SEVERITIES = ["Critical", "Important", "Moderate", "Low"];
const KINDS = {
  release:   { label: t("Patch Tuesday") },
  published: { label: t("New CVE") },
  revised:   { label: t("Revised by Microsoft") },
  exploited: { label: t("Now exploited") },
  kev:       { label: t("Added to CISA KEV") },
  severity:  { label: t("Severity changed") },
  cvss:      { label: t("CVSS changed") },
  priority:  { label: t("Priority raised") },
  silent:    { label: t("Changed without a new version") },
};

/* Microsoft's vocabulary, shown in the page language (the data stays in English). */
const SEV_NAME = { Critical: t("Critical"), Important: t("Important"), Moderate: t("Moderate"), Low: t("Low"), Unrated: t("Unrated") };
const IMPACT_NAME = {
  "Remote Code Execution": t("Remote Code Execution"), "Elevation of Privilege": t("Elevation of Privilege"),
  "Information Disclosure": t("Information Disclosure"), "Denial of Service": t("Denial of Service"),
  "Security Feature Bypass": t("Security Feature Bypass"), Spoofing: t("Spoofing"), Tampering: t("Tampering"),
  "Defense in Depth": t("Defense in Depth"),
};
const ASSESS_NAME = {
  "Exploitation Detected": t("Exploitation Detected"), "Exploitation More Likely": t("Exploitation More Likely"),
  "Exploitation Less Likely": t("Exploitation Less Likely"), "Exploitation Unlikely": t("Exploitation Unlikely"),
};
const TIER_NAME = { "Patch now": t("Patch now"), High: t("High"), Notable: t("Notable"), Track: t("Track") };
const FIELD_NAME = { "CVSS score": t("CVSS score"), Severity: t("Severity"), Exploited: t("Exploited"),
  "Publicly disclosed": t("Publicly disclosed"), "Customer action required": t("Customer action required") };
const sevName = (s) => SEV_NAME[s] || s || "–";
const impactName = (s) => IMPACT_NAME[s] || s || "–";

/** Change notes written by the pipeline, in the page language. Microsoft's own revision notes stay as published. */
function changeDetail(detail) {
  const d = String(detail ?? "");
  if (MPM_LANG === "en") return d;
  let m;
  if (d === "Microsoft now reports exploitation detected") return t(d);
  if (d === "Microsoft changed the advisory without a new version number") return t(d);
  if ((m = d.match(/^Added to CISA KEV, due (\S+)$/))) return t("Added to CISA KEV, due {date}", { date: fmtDate(m[1]) });
  if ((m = d.match(/^Severity (\w+) → (\w+)$/))) return t("Severity {a} → {b}", { a: sevName(m[1]), b: sevName(m[2]) });
  if ((m = d.match(/^CVSS (\S+) → (\S+)$/))) return t("CVSS {a} → {b}", { a: m[1], b: m[2] });
  if ((m = d.match(/^Priority (P\d) → (P\d)$/))) return t("Priority {a} → {b}", { a: m[1], b: m[2] });
  if ((m = d.match(/^.* Security Updates - (\d+) CVEs$/))) return t("{n} CVEs", { n: m[1] });
  return d;
}

const today = () => new Date().toISOString().slice(0, 10);
const asDate = (d) => new Date(d.length === 10 ? d + "T00:00:00Z" : d);
const fmtDate = (d) => d ? asDate(d).toLocaleDateString(LOCALE, { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "–";
const fmtLong = (d) => d ? asDate(d).toLocaleDateString(LOCALE, { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }) : "–";
const fmtTime = (d) => d ? new Date(d).toLocaleTimeString(LOCALE, { hour: "2-digit", minute: "2-digit" }) : "";
const fmtDateTime = (d) => d ? `${fmtDate(d.slice(0, 10))}, ${fmtTime(d)}` : "–";
const addDays = (iso, n) => { const d = new Date(iso + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
const daysAgo = (iso) => (Date.now() - Date.parse(iso)) / 86_400_000;
const monthName = (id) => {
  const [y, m] = String(id).split("-");
  const d = new Date(`${m} 1, ${y}`);
  return isNaN(d) ? id : d.toLocaleDateString(LOCALE, { month: "long", year: "numeric" });
};

/** Upper-case first letter: Italian month names are lower case inside a sentence. */
const cap = (s) => String(s).charAt(0).toUpperCase() + String(s).slice(1);

function timeAgo(iso) {
  if (!iso) return "–";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return t("just now");
  if (s < 3600) return t("{n} min ago", { n: Math.floor(s / 60) });
  if (s < 86400) return t("{n} h ago", { n: Math.floor(s / 3600) });
  if (s < 86400 * 14) return t("{n} d ago", { n: Math.floor(s / 86400) });
  return fmtDate(iso.slice(0, 10));
}

function words(n) {
  return [t("No"), t("One"), t("Two"), t("Three"), t("Four"), t("Five"), t("Six"), t("Seven"), t("Eight"), t("Nine"), t("Ten")][n] ?? String(n);
}

/* ------------------------------------------------------------------ data */
async function fetchData() {
  const res = await fetch("/api/data", { cache: "no-cache" });
  if (res.status === 403) throw Object.assign(new Error("blocked"), { blocked: true });
  if (res.status === 429) throw Object.assign(new Error("rate"), { rate: true });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return prepare(await res.json());
}

function prepare(data) {
  const releaseDate = Object.fromEntries(data.months.map((m) => [m.id, m.release_date]));
  for (const c of data.cves) {
    const slaDue = addDays(releaseDate[c.release] || c.published || today(), c.sla_days);
    c.due = c.kev?.due_date && c.kev.due_date < slaDue ? c.kev.due_date : slaDue;
    c.recent = Boolean(c.revision && c.revision !== "1.0" && c.revised_at && daysAgo(c.revised_at) <= 14);
    c.release_date = releaseDate[c.release];
  }
  data.changes = data.changes || [];
  return data;
}

/** Plain-language reasons behind a CVE's priority. */
function priorityReasons(c) {
  const r = [];
  if (c.exploited) r.push(t("Microsoft reports exploitation in the wild"));
  if (c.kev) r.push(t("CISA lists it as a known exploited vulnerability since {date}", { date: fmtDate(c.kev.date_added) }));
  if (c.kev?.ransomware) r.push(t("It has been used in ransomware campaigns"));
  if (c.severity === "Critical") r.push(c.cvss ? t("Microsoft rates it Critical with a CVSS score of {cvss}", { cvss: c.cvss }) : t("Microsoft rates it Critical"));
  if (c.epss != null && c.epss >= 0.1) r.push(t("EPSS estimates a {pct}% chance of exploitation in the next 30 days", { pct: (c.epss * 100).toFixed(0) }));
  if (c.exploit) r.push(t("Exploit code is publicly available ({sources})", { sources: exploitSources(c.exploit) }));
  if (c.disclosed) r.push(t("Details were publicly disclosed before the fix"));
  if (!c.exploited && c.assessment === "Exploitation More Likely") r.push(t("Microsoft assesses exploitation as more likely"));
  if (!r.length) r.push(t("Microsoft rates it {sev} and there is no sign of exploitation", { sev: sevName(c.severity) }));
  return r;
}

const EXPLOIT_NAME = { metasploit: "Metasploit", nuclei: "Nuclei", poc: t("proof of concept on GitHub") };
const exploitSources = (x) => Object.keys(x || {}).map((k) => EXPLOIT_NAME[k] || k).join(", ");
const exploitPill = () => `<span class="sig xp" title="${te("Public exploit code: Metasploit, Nuclei or proof of concept on GitHub")}">${te("Public exploit")}</span>`;

/** "If you cannot install yet": Microsoft's workarounds and mitigations, quoted as published. */
function mitigationList(list) {
  if (!list?.length) return "";
  const en = MPM_LANG === "it" ? ' lang="en"' : "";
  return `<ul class="mitigations">${list.map((m) => `<li><span class="sig ${m.type === "workaround" ? "kev" : "rev"}">${
    m.type === "workaround" ? te("Workaround") : te("Mitigation")}</span><p${en}>${esc(m.text)}</p></li>`).join("")}</ul>`;
}

function prioBadge(p) {
  return `<span class="prio ${esc(p.toLowerCase())}" title="${te("Priority {p}", { p })}">${esc(p)}</span>`;
}

/* ------------------------------------------------------------------ chrome */
function markNav() {
  const here = location.pathname.replace(/\/$/, "") || "/";
  $$("[data-nav]").forEach((a) => {
    const on = a.dataset.nav === here || (a.dataset.nav !== "/" && here.startsWith(a.dataset.nav + "/"))
      || (a.dataset.nav === "/" && here.startsWith("/cve"));
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const cur = $(".nav [aria-current]");
  const nav = $(".nav");
  if (cur && nav && nav.scrollWidth > nav.clientWidth) {
    const box = cur.closest(".more") ? cur.closest(".more") : cur;
    nav.scrollLeft = box.offsetLeft - nav.clientWidth / 2 + box.offsetWidth / 2;
  }
  $$(".more").forEach((d) => document.addEventListener("click", (e) => { if (!d.contains(e.target)) d.open = false; }));
}

function initTheme() {
  markNav();
  initSearch();
  registerSW();
  const saved = store.get("mpm-theme");
  if (saved) document.documentElement.dataset.theme = saved;
  $("#theme")?.addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme;
    const dark = cur ? cur === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = dark ? "light" : "dark";
    store.set("mpm-theme", document.documentElement.dataset.theme);
    document.dispatchEvent(new Event("mpm:theme"));
  });
}

function showFatal(el, err) {
  const msg = err?.blocked
    ? t("Access from your network is temporarily blocked because of suspicious traffic. If this is a mistake, try again later.")
    : err?.rate
      ? t("Too many requests from your network. Wait a minute and reload the page.")
      : t("The data could not be loaded. Reload the page in a few minutes.");
  setHTML(el, `<p class="fatal">${esc(msg)}</p>`);
}

/* ------------------------------------------------------------------ revision diffs */

function diffBadges(d) {
  if (!d) return "";
  const b = [];
  if (d.reinstall) b.push(`<span class="sig ex">${te("Reinstall the update")}</span>`);
  if (d.products_added?.length) b.push(`<span class="sig rev">${te(d.products_added.length > 1 ? "{n} products added" : "{n} product added", { n: d.products_added.length })}</span>`);
  if (d.kbs_added?.length) b.push(`<span class="sig kev">${te("New update {kb}", { kb: d.kbs_added.join(", ") })}</span>`);
  for (const f of d.fields || []) b.push(`<span class="sig">${te("{field} changed", { field: FIELD_NAME[f.field] || f.field })}</span>`);
  if (d.text?.length) b.push(`<span class="sig">${te("Text changed")}</span>`);
  return b.join("");
}

function renderDiff(d) {
  if (!d) return "";
  const fmt = (v) => v === true ? t("Yes") : v === false ? t("No") : SEV_NAME[v] || (v ?? "–");
  const list = (title, items, cls) => items?.length
    ? `<div class="dlist ${cls}"><p>${esc(title)}</p><ul>${items.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : "";
  return `<div class="diff">
    ${d.fields?.length ? `<table class="dfields"><tbody>${d.fields.map((f) =>
      `<tr><th scope="row">${esc(FIELD_NAME[f.field] || f.field)}</th><td><del>${esc(fmt(f.before))}</del></td><td aria-hidden="true">→</td><td><ins>${esc(fmt(f.after))}</ins></td></tr>`).join("")}</tbody></table>` : ""}
    ${list(t("Products added"), d.products_added, "add")}${list(t("Products removed"), d.products_removed, "del")}
    ${list(t("Updates added"), d.kbs_added, "add")}${list(t("Updates removed"), d.kbs_removed, "del")}
    ${list(t("New fixed builds"), d.builds_added, "add")}${list(t("Fixed builds replaced"), d.builds_removed, "del")}
    ${d.text?.length ? `<div class="dtext" aria-label="${te("Changes in the advisory text")}"${MPM_LANG === "it" ? ' lang="en"' : ""}>${d.text.map(([op, s]) =>
      op === "+" ? `<p class="ins"><span class="sr">${te("Added:")} </span>${esc(s)}</p>`
      : op === "-" ? `<p class="del"><span class="sr">${te("Removed:")} </span>${esc(s)}</p>`
      : op === "…" ? `<p class="gap" aria-hidden="true">…</p>` : `<p>${esc(s)}</p>`).join("")}</div>` : ""}
  </div>`;
}

/* ------------------------------------------------------------------ shared helpers for the trackers */
async function fetchJson(url) {
  const res = await fetch(url, { cache: "no-cache" });
  if (res.status === 403) throw Object.assign(new Error("blocked"), { blocked: true });
  if (res.status === 429) throw Object.assign(new Error("rate"), { rate: true });
  if (res.status === 503) throw Object.assign(new Error("empty"), { empty: true });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const TIER_CLASS = { "Patch now": "t-now", High: "t-high", Notable: "t-notable", Track: "t-track" };
function scoreBadge(score, tier) {
  if (score == null) return "–";
  tier = tier || (score >= 80 ? "Patch now" : score >= 60 ? "High" : score >= 40 ? "Notable" : "Track");
  const name = TIER_NAME[tier] || tier;
  return `<span class="risk ${TIER_CLASS[tier] || ""}" title="${te("Risk score {score} of 100, {tier}", { score, tier: name })}"><b>${esc(score)}</b> ${esc(name)}</span>`;
}

function downloadFile(name, text, type) {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}

function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    if (button) { const was = button.textContent; button.textContent = t("Copied"); setTimeout(() => (button.textContent = was), 1500); }
  } catch { /* clipboard unavailable */ }
}

/* Items followed in this browser: ["cve:CVE-…", "kb:KB…"] */
const follows = {
  list() { try { return JSON.parse(store.get("mpm-follow") || "[]").filter((x) => /^(cve:CVE-[A-Z0-9]{4}-\d{4,7}|kb:KB\d{6,8})$/.test(x)); } catch { return []; } },
  has(id) { return this.list().includes(id); },
  toggle(id) {
    const l = this.list();
    const next = l.includes(id) ? l.filter((x) => x !== id) : [...l, id].slice(-100);
    store.set("mpm-follow", JSON.stringify(next));
    return next.includes(id);
  },
};

function followButton(id) {
  const on = follows.has(id);
  return `<button type="button" class="btn ghost follow" data-follow="${esc(id)}" aria-pressed="${on}">${on ? te("Following") : te("Follow")}</button>`;
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-follow]");
  if (!b) return;
  const on = follows.toggle(b.dataset.follow);
  b.setAttribute("aria-pressed", String(on));
  b.textContent = on ? t("Following") : t("Follow");
  document.dispatchEvent(new Event("mpm-follow"));
});

/** Status names of Windows release health, in the page language. */
const HEALTH_STATUS = () => ({ Confirmed: t("health|Confirmed"), Mitigated: t("health|Mitigated"), "Mitigated: External": t("health|Mitigated: external"),
  Investigating: t("health|Investigating"), Resolved: t("health|Resolved"), "Resolved: External": t("health|Resolved: external") });
const healthStatus = (s) => HEALTH_STATUS()[s] || s || "–";

/* ------------------------------------------------------------------ glossary links */
/** A small "?" link to the glossary entry for a term (ids are the anchors of /glossary). */
function gloss(id, term) {
  return `<a class="gl" href="/glossary#${esc(id)}" title="${te("What does it mean?")}" aria-label="${te("Glossary: {term}", { term })}">?</a>`;
}

/* ------------------------------------------------------------------ chart tooltips */
/** Hover / focus tooltip for chart marks carrying data-tip (plain text, lines split by "\n"). */
function initTips(root) {
  let tip = $("#chartTip");
  if (!tip) {
    tip = Object.assign(document.createElement("div"), { id: "chartTip", className: "chart-tip", role: "tooltip" });
    tip.hidden = true;
    document.body.append(tip);
  }
  const show = (el, x, y) => {
    tip.replaceChildren(...String(el.dataset.tip).split("\n").map((line, i) => Object.assign(document.createElement(i ? "span" : "b"), { textContent: line })));
    tip.hidden = false;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = `${Math.min(Math.max(8, x - w / 2), innerWidth - w - 8)}px`;
    tip.style.top = `${Math.max(8, y - h - 12)}px`;
  };
  const hide = () => { tip.hidden = true; };
  root.addEventListener("pointermove", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el) show(el, e.clientX, e.clientY); else hide();
  });
  root.addEventListener("pointerleave", hide);
  root.addEventListener("focusin", (e) => {
    const el = e.target.closest("[data-tip]");
    if (!el) return;
    const r = el.getBoundingClientRect();
    show(el, r.left + r.width / 2, r.top);
  });
  root.addEventListener("focusout", hide);
}

/* ------------------------------------------------------------------ installable app */
function registerSW() {
  if (!("serviceWorker" in navigator) || location.protocol !== "https:" && location.hostname !== "localhost") return;
  navigator.serviceWorker.register(MPM_POLICY.createScriptURL("/sw.js"), { scope: "/" }).catch(() => { /* not critical */ });
}

/* ------------------------------------------------------------------ global search */
const SEARCH = { items: null, loading: null, sel: -1, results: [] };
const SEARCH_PAGES = () => [
  ["/", t("Overview")], ["/release", "Patch Tuesday"], ["/kb", t("Updates")], ["/exploited", t("Exploited")],
  ["/changes", t("What changed")], ["/acn", "CSIRT Italia"], ["/my", t("My devices")], ["/hot", t("Hottest right now")],
  ["/open-source", t("Open-source fixes")], ["/end-of-life", t("End of life")], ["/breaches", t("Data breaches")],
  ["/docs-tracker", t("Microsoft docs tracker")], ["/known-issues", t("Windows known issues")], ["/trends", t("Trends")], ["/analysis", t("Monthly analysis")],
  ["/alerts", t("Free alerts")], ["/feeds", t("Feeds and API")], ["/glossary", t("Glossary")], ["/status", t("Service status")],
  ["/method", t("How the ranking works")], ["/report", t("NIS2 evidence report")],
];
const SEARCH_TYPE = () => ({ cve: "CVE", kb: "KB", kev: t("Exploited"), product: t("Product"), acn: "CSIRT Italia", page: t("Page") });

function searchHref(it) {
  const [type, id] = it;
  if (type === "cve") return `/cve/${encodeURIComponent(id)}`;
  if (type === "kb") return `/kb/${encodeURIComponent(id)}`;
  if (type === "kev") return `/exploited?tab=all&q=${encodeURIComponent(id)}`;
  if (type === "product") return `/kb?product=${encodeURIComponent(id)}`;
  if (type === "acn") return safeUrl(it[3]);
  return id;
}

async function loadSearch() {
  if (SEARCH.items) return SEARCH.items;
  SEARCH.loading ||= Promise.all([
    fetchJson("/api/search").then((d) => d.items || []).catch(() => []),
    fetchJson("/api/acn").then((d) => (d.items || []).slice(0, 100).map((a) => ["acn", a.title, (a.cves || []).join(" "), a.link])).catch(() => []),
  ]).then(([idx, acn]) => {
    SEARCH.items = [...SEARCH_PAGES().map(([p, name]) => ["page", p, name, ""]), ...idx, ...acn];
    return SEARCH.items;
  });
  return SEARCH.loading;
}

/** Ranks index rows for a query: exact identifier, identifier prefix, then every word in the text. */
function searchRank(items, query, limit = 8) {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const words = q.split(/\s+/);
  const out = [];
  for (const it of items) {
    const id = String(it[1]).toLowerCase();
    const hay = `${id} ${String(it[2]).toLowerCase()} ${String(it[3] || "").toLowerCase()}`;
    let score = 0;
    if (id === q || id === `kb${q}`) score = 100;
    else if (id.startsWith(q)) score = 60;
    else if (words.every((w) => hay.includes(w))) score = 20 + (it[0] === "page" ? 15 : it[0] === "product" ? 10 : it[0] === "kb" ? 6 : it[0] === "cve" ? 5 : 0);
    if (score) out.push([score, it]);
  }
  out.sort((a, b) => b[0] - a[0]);
  const res = out.slice(0, limit).map((x) => x[1]);
  const cve = q.toUpperCase().match(/^CVE-\d{4}-\d{4,7}$/);
  if (cve && !res.some((r) => String(r[1]).toUpperCase() === cve[0])) res.unshift(["cve", cve[0], t("Open the page for this CVE"), ""]);
  const kb = q.toUpperCase().replace(/^KB/, "").match(/^\d{6,8}$/);
  if (kb && !res.some((r) => r[1] === `KB${kb[0]}`)) res.unshift(["kb", `KB${kb[0]}`, t("Open the page for this update"), ""]);
  return res.slice(0, limit);
}

function initSearch() {
  const input = $("#gsearch"), list = $("#gsearchList");
  if (!input || !list) return;
  const close = () => { list.hidden = true; input.setAttribute("aria-expanded", "false"); SEARCH.sel = -1; };
  const paint = () => {
    const types = SEARCH_TYPE();
    setHTML(list, SEARCH.results.map((it, i) => {
      const href = searchHref(it);
      const ext = /^https:/.test(href) ? ' rel="noopener noreferrer" target="_blank"' : "";
      return `<li role="option" id="gs-${i}" aria-selected="${i === SEARCH.sel}"><a href="${esc(href)}"${ext}>
        <span class="gs-type">${esc(types[it[0]] || it[0])}</span><span class="gs-main"><b>${esc(it[0] === "acn" ? it[1] : it[1])}</b>${it[0] !== "acn" && it[2] && it[2] !== it[1] ? `<span>${esc(it[2])}</span>` : ""}</span></a></li>`;
    }).join("") || `<li class="gs-empty">${te("No results. Try a CVE, a KB number or a product name.")}</li>`);
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    if (SEARCH.sel >= 0) input.setAttribute("aria-activedescendant", `gs-${SEARCH.sel}`); else input.removeAttribute("aria-activedescendant");
  };
  const run = async () => {
    const q = input.value;
    if (q.trim().length < 2) return close();
    const items = await loadSearch();
    if (input.value !== q) return;
    SEARCH.results = searchRank(items, q);
    SEARCH.sel = SEARCH.results.length ? 0 : -1;
    paint();
  };
  input.addEventListener("focus", () => { loadSearch(); });
  input.addEventListener("input", run);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { input.value = ""; close(); input.blur(); return; }
    if (list.hidden || !SEARCH.results.length) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      SEARCH.sel = (SEARCH.sel + (e.key === "ArrowDown" ? 1 : -1) + SEARCH.results.length) % SEARCH.results.length;
      paint();
    } else if (e.key === "Enter" && SEARCH.sel >= 0) {
      e.preventDefault();
      const href = searchHref(SEARCH.results[SEARCH.sel]);
      if (/^https:/.test(href)) window.open(href, "_blank", "noopener"); else location.href = href;
    }
  });
  document.addEventListener("click", (e) => { if (!e.target.closest(".search-box")) close(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) { e.preventDefault(); input.focus(); }
  });
}
