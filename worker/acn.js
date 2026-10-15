/**
 * CSIRT Italia (ACN) monitor.
 *
 * Every 15 minutes the cron reads the public CSIRT Italia RSS feed published by the
 * Agenzia per la Cybersicurezza Nazionale. Items that mention Microsoft (or any keyword
 * in ACN_KEYWORDS) are stored in D1, enriched with the CVE identifiers found on the
 * bulletin page, announced on Telegram and offered to Watch subscribers.
 *
 * Parsing is regex based and bounded in size so it fits the Workers Free plan CPU budget.
 */
import { escapeHtml, sendTelegram } from "./telegram.js";

export const ACN_FEED = "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192";
const MAX_FEED = 1_000_000;
const MAX_PAGE = 1_500_000;
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function decodeEntities(s) {
  return String(s || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/&#(\d{1,7});/g, (_, d) => safeChar(Number(d)))
    .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m);
}
const safeChar = (n) => (n > 0 && n < 0x110000 && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : "");
const strip = (s) => decodeEntities(decodeEntities(s)).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();

function tag(block, name) {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i"));
  return m ? m[1] : "";
}

/** RSS 2.0 or Atom -> [{ title, link, published, summary }] */
export function parseFeed(xml) {
  const text = String(xml || "").slice(0, MAX_FEED);
  const blocks = text.match(/<item[\s>][\s\S]*?<\/item>/gi) || text.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [];
  return blocks.slice(0, 100).map((b) => {
    let link = strip(tag(b, "link"));
    if (!link) link = (b.match(/<link[^>]*href="([^"]+)"/i) || [])[1] || "";
    link = decodeEntities(link).trim();
    return {
      title: strip(tag(b, "title")).slice(0, 300),
      link,
      published: strip(tag(b, "pubDate") || tag(b, "updated") || tag(b, "published") || tag(b, "dc:date")).slice(0, 60),
      summary: strip(tag(b, "description") || tag(b, "summary") || tag(b, "content")).slice(0, 600),
    };
  }).filter((i) => i.title && /^https:\/\/([a-z0-9-]+\.)*(acn|csirt)\.gov\.it\//i.test(i.link));
}

export function matchKeyword(item, keywords) {
  const hay = `${item.title} ${item.summary}`;
  return keywords.find((k) => new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(hay)) || null;
}

export function extractCves(html) {
  return [...new Set((String(html || "").slice(0, MAX_PAGE).match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()))].slice(0, 300);
}

function toIso(s) {
  const d = new Date(s);
  return isNaN(d) ? null : d.toISOString();
}

async function readCapped(res, cap) {
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < cap) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  try { await reader.cancel(); } catch { /* ignore */ }
  const all = new Uint8Array(Math.min(size, cap));
  let off = 0;
  for (const c of chunks) {
    const part = c.subarray(0, Math.min(c.length, all.length - off));
    all.set(part, off);
    off += part.length;
    if (off >= all.length) break;
  }
  return new TextDecoder().decode(all);
}

/**
 * Returns { checked, new: [items] }. New items are stored, announced and queued as Watch events.
 */
export async function checkAcn(env, fetcher = fetch, now = Date.now()) {
  const keywords = String(env.ACN_KEYWORDS || "Microsoft").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 10);
  const res = await fetcher(ACN_FEED, { headers: { Accept: "application/rss+xml, application/xml, text/xml", "User-Agent": "MPatchMonitor/1.0" } });
  if (!res.ok) throw new Error(`ACN feed HTTP ${res.status}`);
  const items = parseFeed(await readCapped(res, MAX_FEED));
  const fresh = [];
  for (const it of items) {
    const keyword = matchKeyword(it, keywords);
    if (!keyword) continue;
    const known = await env.DB.prepare("SELECT 1 FROM acn_items WHERE id = ?").bind(it.link).first();
    if (known) continue;
    let cves = [];
    try {
      const page = await fetcher(it.link, { headers: { Accept: "text/html", "User-Agent": "MPatchMonitor/1.0" } });
      if (page.ok) cves = extractCves(await readCapped(page, MAX_PAGE));
    } catch (err) {
      console.error("ACN page fetch failed", err);
    }
    cves = [...new Set([...cves, ...extractCves(it.summary)])];
    const row = { ...it, keyword, cves, published: toIso(it.published) || new Date(now).toISOString() };
    await env.DB.prepare("INSERT OR IGNORE INTO acn_items (id, title, link, published, summary, keyword, cves, first_seen) VALUES (?,?,?,?,?,?,?,?)")
      .bind(row.link, row.title, row.link, row.published, row.summary, keyword, JSON.stringify(cves), now).run();
    fresh.push(row);
    if (fresh.length >= 5) break;   // stay well inside the subrequest budget
  }
  for (const row of fresh) {
    await sendTelegram(env, [
      `🇮🇹 <b>CSIRT Italia: new bulletin mentioning ${escapeHtml(row.keyword)}</b>`,
      escapeHtml(row.title),
      row.cves.length ? `<b>CVE</b> ${escapeHtml(row.cves.slice(0, 12).join(", "))}${row.cves.length > 12 ? "…" : ""}` : "",
      `<a href="${escapeHtml(row.link)}">Read on acn.gov.it</a>`,
    ].filter(Boolean).join("\n"), fetcher);
    if (env.DB) {
      // CSIRT Italia writes in Italian: the bulletin title stays as published in both languages.
      const cveLine = row.cves.length ? `CVE: ${row.cves.slice(0, 12).join(", ")}${row.cves.length > 12 ? "…" : ""}` : "";
      await env.DB.prepare("INSERT OR IGNORE INTO watch_events (ts, topics, title, text, link, ref, title_it, text_it) VALUES (?,?,?,?,?,?,?,?)")
        .bind(now, ["acn", ...row.cves.slice(0, 20).map((c) => `cve:${c}`)].join(","),
          `CSIRT Italia: ${row.title}`.slice(0, 300), [row.summary.slice(0, 400), cveLine].filter(Boolean).join("\n"), row.link, `acn:${row.link}`,
          `CSIRT Italia: ${row.title}`.slice(0, 300), [row.summary.slice(0, 400), cveLine].filter(Boolean).join("\n")).run();
    }
  }
  return { checked: items.length, new: fresh };
}
