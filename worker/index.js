/**
 * MPatchMonitor - public Cloudflare Worker
 *
 *  /                 dashboard (static asset, served through the guard)
 *  /cve/<id>         per-CVE page (static shell, rendered client side)
 *  /api/status       live status: last MSRC check, pending changes, data version
 *  /api/data         dataset from KV (ETag / 304 aware)
 *  anything else     404 (and scanner / attack detection)
 *
 * Static files (CSS, JS, fonts, icons) are served directly by Workers Static Assets:
 * they never invoke the Worker, are free and unlimited, and keep the site up even if
 * the daily Worker quota were exhausted.
 *
 * Cron (every 5 min): polls the MSRC Security Update Guide index and, when Microsoft
 * publishes or revises anything, triggers the GitHub Actions pipeline.
 */
import { guard } from "./security.js";
import { checkAcn } from "./acn.js";
import { drain, fanOut, handleWebhook, importAlerts } from "./watch.js";
import { handleMcp } from "./mcp.js";
import { acnRss, patchTuesdayIcs } from "./feeds.js";
import { getState, putState } from "./state.js";
import { I18N, pickLang, wt } from "./i18n.js";
import { handlePush, pushDrain, pushFanOut, PUSH_PER_RUN } from "./push.js";
import { embedSvg, EMBED_HEADERS, monthLabel } from "./embed.js";
import { decodePng, EPSS_URL, epssSeries, isMonth, robots, sitemap, structuredData } from "./seo.js";

const MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";
const TRACKED_RELEASES = 13;
const CVE_RE = /^CVE-[A-Z0-9]{4}-\d{4,7}$/;

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};
const HTML_HEADERS = {
  ...BASE_HEADERS,
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
    "upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types mpm",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "X-Permitted-Cross-Domain-Policies": "none",
};

const GRAPH_CSP = HTML_HEADERS["Content-Security-Policy"].replace(
  "connect-src 'self';", "connect-src 'self' https://login.microsoftonline.com https://graph.microsoft.com;");

/* Language: English is the source; the Worker translates the static HTML with HTMLRewriter
 * (see worker/i18n.js), so a page arrives complete in its language before any script runs. */
/* Page routes: path -> [asset, title, description] (English; Italian via wt()) */
const PAGES = {
  "/": ["/index.html"], "/index.html": ["/index.html"],
  "/my": ["/my.html"], "/changes": ["/changes.html"], "/report": ["/report.html"],
  "/release": ["/release.html", "Patch Tuesday", "Every Microsoft Patch Tuesday release: exploited zero-days, highest-risk fixes, breakdown by impact and product."],
  "/kb": ["/list.html", "Microsoft KB catalog", "Every Microsoft security update with the CVEs it fixes, exploitation, risk score, known issues and supersedence."],
  "/hot": ["/list.html", "Hottest right now", "The highest-risk CVEs and Microsoft updates right now, ranked by a transparent score."],
  "/exploited": ["/list.html", "Exploited vulnerabilities", "Vulnerabilities exploited in the wild, every vendor, from the CISA KEV catalog with EPSS and CVSS."],
  "/open-source": ["/list.html", "Open-source fixes", "Exploited vulnerabilities in open-source packages and the version that fixes them."],
  "/end-of-life": ["/list.html", "End of life", "Support end dates for Microsoft and other widely used products."],
  "/breaches": ["/list.html", "Data breaches", "Recent verified data breaches and SEC cybersecurity incident filings."],
  "/docs-tracker": ["/list.html", "Microsoft docs tracker", "What changed in Microsoft's security documentation in the last two weeks."],
  "/acn": ["/list.html", "CSIRT Italia monitor", "Bulletins from CSIRT Italia (ACN) that mention Microsoft, as soon as they are published."],
  "/feeds": ["/feeds.html", "Feeds and API", "Free RSS feeds, JSON API, calendar and MCP server for AI assistants."],
  "/method": ["/method.html", "Ranking method", "How MPatchMonitor scores and prioritises vulnerabilities."],
  "/alerts": ["/alerts.html", "Free alerts", "Free Telegram alerts for Patch Tuesday, exploited vulnerabilities, CVEs and updates you follow."],
  "/trends": ["/trends.html", "Trends", "Twelve months of Microsoft vulnerabilities: severity, zero-days, public exploits and the most affected products."],
  "/analysis": ["/analysis.html", "Monthly analysis", "A short analysis of every Microsoft Patch Tuesday, in plain words."],
  "/glossary": ["/glossary.html", "Glossary", "The words used on MPatchMonitor, explained simply."],
  "/known-issues": ["/list.html", "Windows known issues", "Known issues of Windows updates from Microsoft's release health, with workarounds and the update that fixes them."],
  "/status": ["/status.html", "Service status", "Whether every data source of MPatchMonitor is up to date."],
  "/offline": ["/offline.html", "Offline", "MPatchMonitor is not reachable right now."],
};
PAGES["/"].push("Microsoft patch monitor", "Microsoft security updates, tracked as they change: new CVEs, revisions, exploitation and a remediation queue prioritised for NIS2.");
PAGES["/index.html"] = PAGES["/"];
PAGES["/my"].push("My devices", "Which Microsoft updates are your Windows devices missing? Compared in your browser: files never leave your computer.");
PAGES["/changes"].push("What changed", "What Microsoft changed in its security advisories after publishing them, line by line.");
PAGES["/report"].push("NIS2 evidence report", "Vulnerability handling report for NIS2 and the ACN baseline specifications, generated in your browser.");
/* Make the titles and descriptions visible to tools/i18n.py */
const META_STRINGS = [
  wt("Microsoft patch monitor"), wt("Microsoft security updates, tracked as they change: new CVEs, revisions, exploitation and a remediation queue prioritised for NIS2."),
  wt("My devices"), wt("Which Microsoft updates are your Windows devices missing? Compared in your browser: files never leave your computer."),
  wt("What changed"), wt("What Microsoft changed in its security advisories after publishing them, line by line."),
  wt("NIS2 evidence report"), wt("Vulnerability handling report for NIS2 and the ACN baseline specifications, generated in your browser."),
  wt("Patch Tuesday"), wt("Every Microsoft Patch Tuesday release: exploited zero-days, highest-risk fixes, breakdown by impact and product."),
  wt("Microsoft KB catalog"), wt("Every Microsoft security update with the CVEs it fixes, exploitation, risk score, known issues and supersedence."),
  wt("Hottest right now"), wt("The highest-risk CVEs and Microsoft updates right now, ranked by a transparent score."),
  wt("Exploited vulnerabilities"), wt("Vulnerabilities exploited in the wild, every vendor, from the CISA KEV catalog with EPSS and CVSS."),
  wt("Open-source fixes"), wt("Exploited vulnerabilities in open-source packages and the version that fixes them."),
  wt("End of life"), wt("Support end dates for Microsoft and other widely used products."),
  wt("Data breaches"), wt("Recent verified data breaches and SEC cybersecurity incident filings."),
  wt("Microsoft docs tracker"), wt("What changed in Microsoft's security documentation in the last two weeks."),
  wt("CSIRT Italia monitor"), wt("Bulletins from CSIRT Italia (ACN) that mention Microsoft, as soon as they are published."),
  wt("Feeds and API"), wt("Free RSS feeds, JSON API, calendar and MCP server for AI assistants."),
  wt("Ranking method"), wt("How MPatchMonitor scores and prioritises vulnerabilities."),
  wt("Free alerts"), wt("Free Telegram alerts for Patch Tuesday, exploited vulnerabilities, CVEs and updates you follow."),
  wt("Microsoft security update {id}: CVEs fixed, exploitation, known issues, how to check and deploy it."),
  wt("Microsoft Patch Tuesday release in detail."), wt("Microsoft security update"),
  wt("Vulnerability details, priority, revisions and fixes."),
  wt("Trends"), wt("Twelve months of Microsoft vulnerabilities: severity, zero-days, public exploits and the most affected products."),
  wt("Monthly analysis"), wt("A short analysis of every Microsoft Patch Tuesday, in plain words."),
  wt("Glossary"), wt("The words used on MPatchMonitor, explained simply."),
  wt("Service status"), wt("Whether every data source of MPatchMonitor is up to date."),
  wt("Offline"), wt("MPatchMonitor is not reachable right now."),
  wt("Windows known issues"), wt("Known issues of Windows updates from Microsoft's release health, with workarounds and the update that fixes them."),
  wt("Patch Tuesday {month}: the analysis"), wt("What changed, the zero-days, what to install first and what to do if you cannot install yet."),
];
void META_STRINGS;
const KV_APIS = { data: "dashboard", fixes: "fixes", kb: "kb", "microsoft-patches": "kb", kev: "kev", hot: "hot", news: "news",
  eol: "eol", docs: "docs", breaches: "breaches", oss: "oss", search: "search", summary: "summary", sources: "sources",
  "known-issues": "health" };
const FEEDS = ["microsoft-patches", "exploited-this-week", "non-ms-kev", "patch-tuesday", "changes"];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/(.)\/$/, "$1");
    const post = path === "/mcp" || path === "/tg/webhook" || path === "/api/push/subscribe" || path === "/api/push/unsubscribe";
    const blocked = await guard(request, env, ctx, { allowedMethods: post ? ["GET", "HEAD", "POST"] : ["GET", "HEAD"] });
    if (blocked) return blocked;
    const base = env.PUBLIC_ORIGIN || url.origin;

    try {
      if (PAGES[path]) return asset(env, request, PAGES[path][0], PAGES[path].slice(1), path === "/my" ? GRAPH_CSP : null);
      if (path.startsWith("/cve/")) {
        const id = path.slice(5).toUpperCase();
        if (!CVE_RE.test(id)) return notFound(request);
        return asset(env, request, "/cve.html", [id, "Vulnerability details, priority, revisions and fixes."]);
      }
      if (path.startsWith("/kb/")) {
        const id = path.slice(4).toUpperCase();
        if (!/^KB\d{6,8}$/.test(id)) return notFound(request);
        return asset(env, request, "/kb.html", [id, "Microsoft security update {id}: CVEs fixed, exploitation, known issues, how to check and deploy it.", { id }]);
      }
      if (path.startsWith("/release/")) {
        if (!/^\/release\/\d{4}-[A-Z][a-z]{2}$/.test(path)) return notFound(request);
        return asset(env, request, "/release.html", [`Patch Tuesday ${path.slice(9)}`, "Microsoft Patch Tuesday release in detail."]);
      }
      if (path.startsWith("/analysis/")) {
        if (!/^\/analysis\/\d{4}-[A-Z][a-z]{2}$/.test(path)) return notFound(request);
        const month = monthLabel(path.slice(10), pickLang(request).lang);
        if (!month) return notFound(request);
        return asset(env, request, "/analysis.html", ["Patch Tuesday {month}: the analysis", "What changed, the zero-days, what to install first and what to do if you cannot install yet.", { month }],
          null, `/og/analysis/${path.slice(10)}.png`);
      }
      if (path === "/embed/patch-tuesday.svg") return await embed(env, request, url);
      if (path === "/sitemap.xml") return await sitemapXml(env, request, base, ctx);
      if (path === "/robots.txt") return new Response(robots(base), { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400", ...BASE_HEADERS } });
      if (path.startsWith("/og/analysis/")) {
        const id = path.slice(13).replace(/\.png$/, "");
        if (!isMonth(id) || !path.endsWith(".png")) return notFound(request);
        return await ogImage(env, id, url.searchParams.get("lang") === "en" ? "en" : "it", base);
      }
      if (path.startsWith("/api/epss-history/")) {
        const id = path.slice(18).replace(/\.json$/, "").toUpperCase();
        if (!CVE_RE.test(id) || !/^CVE-\d{4}-\d{4,7}$/.test(id)) return json({ error: "Invalid CVE identifier." }, 400);
        return await epssHistory(id, ctx);
      }
      if (path.startsWith("/api/push/")) return await handlePush(request, env, path, base);
      if (path === "/api/service-status") return await apiServiceStatus(env);
      if (path === "/mcp") return await handleMcp(request, env, base);
      if (path === "/tg/webhook") return request.method === "POST" ? await handleWebhook(request, env) : notFound(request);
      if (path === "/api/status") return await apiStatus(env);
      if (path === "/api/acn" || path === "/api/acn.json") return await apiAcn(env);
      if (path === "/api/watch-alerts" || path === "/api/watch-alerts.json") return await apiWatchAlerts(env);
      const api = path.match(/^\/api\/([a-z-]+?)(\.json)?$/);
      if (api && KV_APIS[api[1]]) return await apiKv(env, request, KV_APIS[api[1]]);
      const feed = path.match(/^\/feed\/([a-z-]+)\.xml$/);
      if (feed && FEEDS.includes(feed[1])) return await feedKv(env, feed[1]);
      if (path === "/feed/acn-microsoft.xml") return await feedAcn(env, base);
      if (path === "/ics/patch-tuesday.ics") {
        return new Response(patchTuesdayIcs(base), { headers: { "Content-Type": "text/calendar; charset=utf-8", "Cache-Control": "public, max-age=3600", ...BASE_HEADERS } });
      }
      if (path === "/api/health") return json({ ok: true });
    } catch (err) {
      console.error("route error", err);
      return json({ error: "Internal error." }, 500);
    }
    return notFound(request);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runCron(env, event.scheduledTime || Date.now()));
  },
};

export async function runCron(env, when = Date.now(), fetcher = fetch) {
  const minute = new Date(when).getUTCMinutes();
  const tasks = [checkMsrc(env, fetcher)];
  if (minute % 15 < 5 && env.DB) {
    tasks.push(checkAcn(env, fetcher).then(async (r) => {
      await putState(env, "acn_status", { ok: true, last_check: new Date().toISOString(), items: r.checked, new: r.new.length });
    }).catch(async (err) => {
      console.error("ACN check failed", err);
      await putState(env, "acn_status", { ok: false, last_check: new Date().toISOString(), error: String(err.message || err).slice(0, 200) });
    }));
  }
  await Promise.allSettled(tasks);
  if (env.DB) {
    try {
      await importAlerts(env);
      await fanOut(env);
      await pushFanOut(env);
      // Subrequests per run: MSRC + GitHub + ACN (3) + Telegram (25) + browser push (18) = 46 < 50 (Free plan)
      await drain(env, fetcher);
      await pushDrain(env, PUSH_PER_RUN, fetcher);
    } catch (err) {
      console.error("watch delivery failed", err);
    }
  }
}

/* ------------------------------------------------------------------ pages */
async function asset(env, request, file, meta = [], csp = null, ogImagePath = null) {
  const res = await env.ASSETS.fetch(new Request(new URL(file, request.url), { method: "GET" }));
  const { lang, set } = pickLang(request);
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(HTML_HEADERS)) headers.set(k, v);
  if (csp) headers.set("Content-Security-Policy", csp);
  headers.set("Cache-Control", "no-cache");
  headers.set("Content-Language", lang);
  headers.set("Vary", "Cookie, Accept-Language");
  if (set) headers.append("Set-Cookie", `mpm-lang=${lang}; Path=/; Max-Age=31536000; SameSite=Lax; Secure`);
  let out = new Response(request.method === "HEAD" ? null : res.body, { status: res.status, headers });
  if (typeof HTMLRewriter === "undefined" || request.method === "HEAD") return out;

  // Pinned origin: never trust the Host header for absolute URLs.
  const origin = env.PUBLIC_ORIGIN || new URL(request.url).origin;
  const url = new URL(request.url);
  const path = url.pathname.replace(/[^A-Za-z0-9/._-]/g, "");
  const clean = (t) => String(t).replace(/[<>&"]/g, "");
  const [title, description, vars = {}] = meta;
  const fill = (s) => s.replace(/\{(\w+)\}/g, (m, k) => (Object.hasOwn(vars, k) ? vars[k] : m));
  const other = lang === "it" ? "en" : "it";
  const params = new URLSearchParams(url.search);
  params.set("lang", other);
  const switchHref = `${path}?${params.toString()}`.replace(/[<>"]/g, "");

  let rw = new HTMLRewriter()
    .on("html", { element: (e) => e.setAttribute("lang", lang) })
    .on("#lang", { element: (e) => {
      e.setAttribute("href", switchHref);
      e.setAttribute("hreflang", other);
      e.setAttribute("lang", other);
      e.setAttribute("title", other === "it" ? "Leggi in italiano" : "Read in English");
      e.setInnerContent(other.toUpperCase());
    } })
    .on('meta[property="og:image"]', { element: (e) => e.setAttribute("content", ogImagePath ? `${origin}${ogImagePath}?lang=${lang}` : `${origin}/og.png`) })
    .on("head", { element: (e) => e.append(
      `<meta property="og:url" content="${origin}${path}">` +
      `<meta property="og:locale" content="${lang === "it" ? "it_IT" : "en_GB"}">` +
      `<link rel="alternate" hreflang="en" href="${origin}${path}?lang=en">` +
      `<link rel="alternate" hreflang="it" href="${origin}${path}?lang=it">` +
      `<link rel="alternate" hreflang="x-default" href="${origin}${path}">` +
      (ogImagePath ? `<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">` : "") +
      `<script type="application/ld+json">${structuredData(origin, path, lang, title ? clean(fill(wt(title, lang))) : "", description ? clean(fill(wt(description, lang))) : "")}</script>`,
      { html: true }) });
  if (title) {
    const full = `${clean(fill(wt(title, lang)))} – MPatchMonitor`;
    rw = rw.on("title", { element: (e) => e.setInnerContent(full) })
      .on('meta[property="og:title"]', { element: (e) => e.setAttribute("content", full) });
  }
  if (description) {
    const d = clean(fill(wt(description, lang)));
    rw = rw.on('meta[name="description"]', { element: (e) => e.setAttribute("content", d) })
      .on('meta[property="og:description"]', { element: (e) => e.setAttribute("content", d) });
  }
  if (lang === "it") {
    rw = rw.on("[data-i18n]", { element: (e) => {
      const html = I18N.units[e.getAttribute("data-i18n")];
      if (html !== undefined) e.setInnerContent(html, { html: true });
    } }).on("[data-i18n-attr]", { element: (e) => {
      for (const pair of (e.getAttribute("data-i18n-attr") || "").split(";")) {
        const [name, key] = pair.split(":");
        if (Object.hasOwn(I18N.attrs, key)) e.setAttribute(name, I18N.attrs[key]);
      }
    } });
  }
  return rw.transform(out);
}

function notFound(request) {
  const lang = request ? pickLang(request).lang : "en";
  const html = `<!doctype html><html lang="${lang}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${wt("Not found", lang)}</title><link rel="stylesheet" href="/styles.css"><body class="plain">
<main class="notfound"><h1>${wt("This page does not exist.", lang)}</h1><p><a href="/">${wt("Go to the dashboard", lang)}</a></p></main></body></html>`;
  return new Response(html, { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", ...HTML_HEADERS } });
}

/* ------------------------------------------------------------------ search engines and previews */
async function sitemapXml(env, request, base, ctx) {
  const cache = typeof caches !== "undefined" ? caches.default : null;
  const key = new Request(`${base}/sitemap.xml`);
  const hit = cache && (await cache.match(key));
  if (hit) return hit;
  const [search, summary, version] = await Promise.all([
    env.MPM.get("search", { type: "json", cacheTtl: 3600 }), env.MPM.get("summary", { type: "json", cacheTtl: 3600 }),
    env.MPM.get("version", { type: "json", cacheTtl: 300 })]);
  const res = new Response(sitemap(base, search, summary, version?.version), {
    headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=3600", ...BASE_HEADERS } });
  if (cache && ctx) ctx.waitUntil(cache.put(key, res.clone()));
  return res;
}

async function ogImage(env, id, lang, base) {
  const b64 = (await env.MPM.get(`og:${id}:${lang}`, { cacheTtl: 3600 })) || (await env.MPM.get(`og:${id}:en`, { cacheTtl: 3600 }));
  const png = decodePng(b64);
  if (!png) return Response.redirect(`${base}/og.png`, 302);
  return new Response(png, { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400", ...BASE_HEADERS, "Cross-Origin-Resource-Policy": "cross-origin" } });
}

/** EPSS of the last months from FIRST, cached for 12 hours (one outbound request per CVE and day at most). */
export async function epssHistory(cve, ctx, fetcher = fetch) {
  const cache = typeof caches !== "undefined" ? caches.default : null;
  const key = new Request(`https://cache.mpatchmonitor.invalid/epss/${cve}`);
  const hit = cache && (await cache.match(key));
  if (hit) return hit;
  let series = [];
  try {
    const res = await fetcher(`${EPSS_URL}?cve=${encodeURIComponent(cve)}&scope=time-series`, {
      headers: { Accept: "application/json", "User-Agent": "MPatchMonitor/1.0" }, cf: { cacheTtl: 43200, cacheEverything: true },
      signal: AbortSignal.timeout(5000) });
    if (!res.ok) return json({ error: "EPSS history is not available right now." }, 502, { "Cache-Control": "no-store" });
    series = epssSeries(await res.json(), cve);
  } catch {
    return json({ error: "EPSS history is not available right now." }, 502, { "Cache-Control": "no-store" });
  }
  const out = json({ cve, source: "FIRST EPSS", series }, 200, { "Cache-Control": "public, max-age=21600" });
  if (cache && ctx) ctx.waitUntil(cache.put(key, out.clone()));
  return out;
}

/* ------------------------------------------------------------------ embed */
async function embed(env, request, url) {
  const lang = url.searchParams.get("lang") === "it" ? "it" : "en";
  const theme = url.searchParams.get("theme") === "dark" ? "dark" : "light";
  const summary = await env.MPM.get("summary", { type: "json", cacheTtl: 300 });
  const host = new URL(env.PUBLIC_ORIGIN || url.origin).host;
  return new Response(request.method === "HEAD" ? null : embedSvg(summary, lang, theme, host), { headers: EMBED_HEADERS });
}

/* ------------------------------------------------------------------ API */
async function apiServiceStatus(env) {
  const [msrc, acn, version, tg, push] = await Promise.all([
    getState(env, "msrc_status"), getState(env, "acn_status"),
    env.MPM.get("version", { type: "json", cacheTtl: 30 }),
    env.DB.prepare("SELECT COUNT(*) AS n FROM watch_outbox").first().catch(() => null),
    env.DB.prepare("SELECT COUNT(*) AS n FROM push_outbox").first().catch(() => null),
  ]);
  const pick = (s) => (s ? { ok: s.ok ?? null, last_check: s.last_check || null, error: s.ok === false ? String(s.error || "").slice(0, 120) : undefined } : null);
  return json({ now: new Date().toISOString(), msrc: pick(msrc), acn: pick(acn), version: version?.version || null,
    queue: { telegram: tg?.n ?? 0, push: push?.n ?? 0 } }, 200, { "Cache-Control": "public, max-age=60" });
}

async function apiStatus(env) {
  const [status, version] = await Promise.all([
    getState(env, "msrc_status"),
    env.MPM.get("version", { type: "json", cacheTtl: 30 }),
  ]);
  const s = status || {};
  const v = version || {};
  const pending = Boolean(s.last_msrc_change && (!v.version || s.last_msrc_change > v.version));
  return json({
    now: new Date().toISOString(),
    last_check: s.last_check || null,
    check_ok: s.ok ?? null,
    msrc_last_update: s.msrc_last_update || null,
    latest_release: s.latest_release || null,
    last_msrc_change: s.last_msrc_change || null,
    changed_releases: s.changed_releases || [],
    pending,
    version: v.version || null,
    new_changes: v.new_changes ?? 0,
    watch_bot: /^[A-Za-z0-9_]{5,32}$/.test(env.WATCH_BOT_USERNAME || "") ? env.WATCH_BOT_USERNAME : null,
  }, 200, { "Cache-Control": "no-store" });
}

async function apiKv(env, request, key) {
  const version = await env.MPM.get("version", { type: "json", cacheTtl: 30 });
  const tag = version?.hashes?.[key] || version?.version;
  const etag = tag ? `"${key}-${tag}"` : null;
  if (etag && request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag, ...BASE_HEADERS } });
  }
  const body = await env.MPM.get(key, { type: "stream", cacheTtl: 60 });
  if (!body) return json({ error: "No data yet. The pipeline publishes it on its next run." }, 503);
  return new Response(request.method === "HEAD" ? null : body, {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-cache",
      ...(etag ? { ETag: etag } : {}),
      ...BASE_HEADERS,
    },
  });
}

async function feedKv(env, name) {
  const xml = await env.MPM.get(`feed:${name}`, { type: "stream", cacheTtl: 300 });
  if (!xml) return json({ error: "Feed not published yet." }, 503);
  return new Response(xml, { headers: { "Content-Type": "application/rss+xml; charset=utf-8", "Cache-Control": "public, max-age=600", ...BASE_HEADERS } });
}

async function feedAcn(env, base) {
  const rows = await env.DB.prepare("SELECT title, link, published, summary FROM acn_items ORDER BY published DESC LIMIT 50").all();
  return new Response(acnRss(base, rows.results), { headers: { "Content-Type": "application/rss+xml; charset=utf-8", "Cache-Control": "public, max-age=300", ...BASE_HEADERS } });
}

async function apiAcn(env) {
  const [rows, status] = await Promise.all([
    env.DB.prepare("SELECT title, link, published, summary, keyword, cves, first_seen FROM acn_items ORDER BY published DESC LIMIT 200").all(),
    getState(env, "acn_status"),
  ]);
  return json({ status: status || null, source: "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192",
    items: rows.results.map((r) => ({ ...r, cves: JSON.parse(r.cves || "[]") })) }, 200, { "Cache-Control": "no-cache" });
}

async function apiWatchAlerts(env) {
  const rows = await env.DB.prepare("SELECT id, ts, topics, title, text, link, title_it, text_it FROM watch_events ORDER BY id DESC LIMIT 100").all();
  return json({ note: "Public log of alerts sent by the MPatchMonitor Watch bot. Recipients are never shown.",
    alerts: rows.results.map((r) => ({ ...r, ts: new Date(r.ts).toISOString(), topics: r.topics.split(",") })) }, 200, { "Cache-Control": "no-cache" });
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...BASE_HEADERS, ...headers },
  });
}

/* ------------------------------------------------------------------ cron */
export async function checkMsrc(env, fetcher = fetch) {
  const now = new Date().toISOString();
  const prev = (await getState(env, "msrc_status")) || {};
  let next;

  try {
    const res = await fetcher(MSRC_UPDATES, {
      headers: { Accept: "application/json", "User-Agent": "MPatchMonitor/1.0" },
    });
    if (!res.ok) throw new Error(`MSRC HTTP ${res.status}`);
    const body = await res.json();

    const releases = (body.value || [])
      .filter((u) => u.ID && u.InitialReleaseDate)
      .sort((a, b) => b.InitialReleaseDate.localeCompare(a.InitialReleaseDate))
      .slice(0, TRACKED_RELEASES);
    const fingerprint = releases.map((u) => `${u.ID}@${u.CurrentReleaseDate}`).join("|");
    const msrcLastUpdate = releases.map((u) => u.CurrentReleaseDate || "").sort().pop() || null;

    const firstRun = !prev.fingerprint;
    const changed = !firstRun && prev.fingerprint !== fingerprint;
    let changedReleases = prev.changed_releases || [];
    if (changed) {
      const old = new Map(prev.fingerprint.split("|").map((p) => p.split("@")));
      changedReleases = releases.filter((u) => old.get(u.ID) !== u.CurrentReleaseDate).map((u) => u.ID);
    }

    let dispatched = null;
    if ((changed || firstRun) && env.GITHUB_TOKEN && env.GITHUB_REPO) {
      dispatched = await triggerPipeline(env, changedReleases, fetcher);
    }

    next = {
      ok: true,
      last_check: now,
      fingerprint,
      msrc_last_update: msrcLastUpdate,
      latest_release: releases[0]?.ID || null,
      last_msrc_change: changed ? now : prev.last_msrc_change || null,
      changed_releases: changedReleases,
      last_dispatch: dispatched === null ? prev.last_dispatch || null : { at: now, ok: dispatched },
    };
    if (changed) console.log("MSRC change detected", changedReleases.join(","));
  } catch (err) {
    console.error("MSRC check failed", err);
    next = { ...prev, ok: false, last_check: now, error: String(err.message || err).slice(0, 200) };
  }

  await putState(env, "msrc_status", next);
  return next;
}

async function triggerPipeline(env, releases, fetcher) {
  try {
    const res = await fetcher(`https://api.github.com/repos/${env.GITHUB_REPO}/dispatches`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "MPatchMonitor/1.0",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ event_type: "msrc-changed", client_payload: { releases } }),
    });
    if (res.status !== 204) console.error("GitHub dispatch failed", res.status);
    return res.status === 204;
  } catch (err) {
    console.error("GitHub dispatch error", err);
    return false;
  }
}
