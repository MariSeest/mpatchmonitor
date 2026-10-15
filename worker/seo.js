/**
 * Search engines and link previews: sitemap.xml, robots.txt, JSON-LD structured data,
 * social preview images of the monthly analysis, and the EPSS history proxy.
 */

const xml = (s) => String(s).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
const STATIC_PAGES = ["/", "/release", "/kb", "/exploited", "/changes", "/acn", "/my", "/hot", "/open-source", "/end-of-life", "/breaches",
  "/docs-tracker", "/known-issues", "/trends", "/analysis", "/alerts", "/feeds", "/method", "/glossary", "/status"];
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const KB_RE = /^KB\d{6,8}$/;
const MONTH_RE = /^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/;

/** search: KV "search" ({items: [[type, id, ...]]}); summary: KV "summary" ({months: [{id, release_date}]}) */
export function sitemap(origin, search, summary, lastmod) {
  const urls = [];
  const add = (path, mod) => urls.push(`<url><loc>${xml(origin + path)}</loc>` +
    `<xhtml:link rel="alternate" hreflang="en" href="${xml(`${origin}${path}?lang=en`)}"/>` +
    `<xhtml:link rel="alternate" hreflang="it" href="${xml(`${origin}${path}?lang=it`)}"/>` +
    (mod ? `<lastmod>${xml(mod)}</lastmod>` : "") + "</url>");
  const day = /^\d{4}-\d{2}-\d{2}/.test(lastmod || "") ? lastmod.slice(0, 10) : null;
  STATIC_PAGES.forEach((p) => add(p, day));
  for (const m of summary?.months || []) {
    if (!MONTH_RE.test(m.id)) continue;
    add(`/release/${m.id}`, /^\d{4}-\d{2}-\d{2}$/.test(m.release_date || "") ? m.release_date : null);
    add(`/analysis/${m.id}`, null);
  }
  const seen = new Set();
  for (const it of search?.items || []) {
    const [type, id] = it;
    const path = type === "cve" && CVE_RE.test(id) ? `/cve/${id}` : type === "kb" && KB_RE.test(id) ? `/kb/${id}` : null;
    if (!path || seen.has(path)) continue;
    seen.add(path);
    add(path, null);
    if (urls.length >= 20000) break;
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">${urls.join("")}</urlset>\n`;
}

export function robots(origin) {
  return `User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /mcp\nDisallow: /tg/\nDisallow: /embed/\n\nSitemap: ${origin}/sitemap.xml\n`;
}

/** JSON for a <script type="application/ld+json"> block: "<" is escaped so the data can never close the tag. */
export function ldJson(obj) {
  return JSON.stringify(obj).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

/** Structured data for a page: the site and its author everywhere, plus what the page is about. */
export function structuredData(origin, path, lang, title, description) {
  const site = { "@type": "WebSite", "@id": `${origin}/#site`, name: "MPatchMonitor", url: `${origin}/`, inLanguage: ["en", "it"],
    author: { "@type": "Person", name: "Luisa Mele", url: "https://github.com/MariSeest" } };
  const page = { "@type": "WebPage", "@id": `${origin}${path}`, url: `${origin}${path}`, name: title || "MPatchMonitor",
    description: description || undefined, inLanguage: lang, isPartOf: { "@id": `${origin}/#site` } };
  const graph = [site, page];
  const crumbs = [{ name: "MPatchMonitor", item: `${origin}/` }];
  let m;
  if ((m = path.match(/^\/cve\/(CVE-\d{4}-\d{4,7})$/))) {
    page.about = { "@type": "Thing", name: m[1], identifier: m[1], sameAs: [`https://www.cve.org/CVERecord?id=${m[1]}`, `https://msrc.microsoft.com/update-guide/vulnerability/${m[1]}`] };
    crumbs.push({ name: "CVE", item: `${origin}/hot` }, { name: m[1], item: `${origin}${path}` });
  } else if ((m = path.match(/^\/kb\/(KB\d{6,8})$/))) {
    page.about = { "@type": "SoftwareApplication", name: `Microsoft security update ${m[1]}`, identifier: m[1], applicationCategory: "SecurityUpdate",
      publisher: { "@type": "Organization", name: "Microsoft" } };
    crumbs.push({ name: "KB", item: `${origin}/kb` }, { name: m[1], item: `${origin}${path}` });
  } else if ((m = path.match(/^\/(release|analysis)\/(\d{4}-[A-Z][a-z]{2})$/))) {
    if (m[1] === "analysis") {
      graph[1] = { ...page, "@type": "Article", headline: title, author: site.author, publisher: site.author,
        image: `${origin}/og/analysis/${m[2]}.png?lang=${lang}` };
    }
    crumbs.push({ name: m[1] === "release" ? "Patch Tuesday" : "Analysis", item: `${origin}/${m[1]}` }, { name: m[2], item: `${origin}${path}` });
  } else if (path === "/feeds") {
    graph.push({ "@type": "Dataset", name: "MPatchMonitor open data", description: "Microsoft security updates, CVEs, exploitation, risk scores and feeds, free to reuse with credit.",
      url: `${origin}/feeds`, creator: site.author, isAccessibleForFree: true,
      license: "https://creativecommons.org/licenses/by/4.0/",
      distribution: ["data", "kb", "kev", "hot"].map((n) => ({ "@type": "DataDownload", encodingFormat: "application/json", contentUrl: `${origin}/api/${n}.json` })) });
  }
  if (crumbs.length > 1) {
    graph.push({ "@type": "BreadcrumbList", itemListElement: crumbs.map((c, i) => ({ "@type": "ListItem", position: i + 1, name: c.name, item: c.item })) });
  }
  return ldJson({ "@context": "https://schema.org", "@graph": graph });
}

/* ------------------------------------------------------------------ social preview image */
export function decodePng(b64) {
  if (typeof b64 !== "string" || b64.length > 700_000 || !/^[A-Za-z0-9+/]+=*$/.test(b64)) return null;
  const bin = atob(b64);
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return out[0] === 0x89 && out[1] === 0x50 && out[2] === 0x4e && out[3] === 0x47 ? out : null;
}

export const isMonth = (id) => MONTH_RE.test(String(id || ""));

/* ------------------------------------------------------------------ EPSS history */
export const EPSS_URL = "https://api.first.org/data/v1/epss";

/** FIRST time-series answer -> [{date, epss, percentile}] oldest first (at most 120 points). */
export function epssSeries(body, cve) {
  const row = (body?.data || []).find((r) => r.cve === cve);
  if (!row) return [];
  const pts = [{ date: row.date, epss: row.epss, percentile: row.percentile }, ...(row["time-series"] || [])];
  const seen = new Set();
  return pts.map((p) => ({ date: String(p.date || "").slice(0, 10), epss: Number(p.epss), percentile: Number(p.percentile) }))
    .filter((p) => /^\d{4}-\d{2}-\d{2}$/.test(p.date) && Number.isFinite(p.epss) && p.epss >= 0 && p.epss <= 1 && !seen.has(p.date) && seen.add(p.date))
    .sort((a, b) => a.date.localeCompare(b.date)).slice(-120);
}
