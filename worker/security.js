/**
 * MPatchMonitor - request guard
 *
 * Runs before every dynamic route of the public Worker:
 *   1. blocks banned IPs (cached ban list, refreshed every 60 s from D1)
 *   2. rejects oversized URLs and unexpected methods
 *   3. detects honeypot paths, attack payloads and scanner user agents -> automatic ban
 *   4. rate limits per IP (Workers Rate Limiting binding when available, in-memory fallback)
 *      repeated violations -> automatic ban
 *   5. sends Telegram alerts (throttled) for bans
 *
 * Designed for the Workers Free plan: no D1 work for normal traffic, at most one write
 * per suspicious IP every few seconds, IPv6 handled per /64 so an attacker cannot rotate
 * through its own prefix.
 */
import { sendTelegram, escapeHtml } from "./telegram.js";

export const MAX_URL = 2048;
const BAN_CACHE_MS = 60_000;
const STRIKE_WINDOW_MS = 10 * 60_000;
const STRIKES_TO_BAN = 5;
const MEM_LIMIT = { sustained: [120, 60_000], burst: [25, 10_000] };
const ESCALATION_H = [1, 24, 24 * 7];           // 1st, 2nd, 3rd+ offense
const ALERT_THROTTLE_MS = 60 * 60_000;

/* ------------------------------------------------------------------ detection rules */
const HONEYPOT = new RegExp([
  String.raw`(^|/)\.(env|git|svn|hg|aws|ssh|docker|npmrc|htaccess|htpasswd|ds_store|vscode|idea)(/|$|\.)`,
  String.raw`(^|/)(wp-admin|wp-login|wp-content|wp-includes|wp-json|xmlrpc\.php|wordpress)`,
  String.raw`(^|/)(phpmyadmin|pma|myadmin|adminer|phpinfo|server-status|server-info|cgi-bin|boaform|hnap1|actuator|jenkins|solr|telescope|_profiler|console|manager/html)`,
  String.raw`(^|/)(vendor/phpunit|config\.(php|json|ya?ml)|web\.config|settings\.py|id_rsa|id_dsa|credentials|secrets?\.(json|ya?ml))`,
  String.raw`\.(php\d?|asp|aspx|jsp|cgi|sql|bak|old|swp|tar|tgz|gz|7z|rar|zip|pem|key|db|sqlite)$`,
].join("|"), "i");

const ATTACK = [
  ["path-traversal", /(\.\.[/\\])|(%2e%2e)|(\/etc\/(passwd|shadow|hosts))|(win\.ini)|(boot\.ini)|(\/proc\/self)/i],
  ["sql-injection", /(\bunion\b[\s\S]{0,40}\bselect\b)|(\bselect\b[\s\S]{0,40}\bfrom\b[\s\S]{0,40}\binformation_schema)|('\s*(or|and)\s*'?\d+'?\s*=\s*'?\d)|(\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\()|(;\s*(drop|insert|update|delete)\s+)/i],
  ["xss", /(<\s*script)|(<\s*svg[\s\S]{0,40}on\w+\s*=)|(javascript\s*:)|(\bon(error|load|mouseover|focus)\s*=)|(<\s*iframe)|(document\.cookie)/i],
  ["template-injection", /(\$\{jndi:)|(\{\{\s*\d+\s*\*\s*\d+\s*\}\})|(\$\{\s*\d+\s*\*\s*\d+\s*\})|(<%=)/i],
  ["command-injection", /([;|`]\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b)|(\$\((id|whoami|uname)\))/i],
  ["ssrf", /(169\.254\.169\.254)|(metadata\.google\.internal)|(file:\/\/)|(gopher:\/\/)/i],
];

const SCANNER_UA = /\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|dirb|ffuf|wfuzz|feroxbuster|acunetix|nessus|openvas|w3af|burp(suite|collaborator)?|owasp[ _-]?zap|zaproxy|wpscan|whatweb|httpx|hydra|commix|arachni|jaeles|netsparker|qualys|xray|katana|dalfox)\b/i;

/* ------------------------------------------------------------------ IP helpers */
export function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "0.0.0.0";
}

/** IPv4 as is; IPv6 normalised to its /64 prefix. */
export function ipKey(ip) {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const full = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
  return full.slice(0, 4).map((x) => (parseInt(x, 16) || 0).toString(16)).join(":") + "::/64";
}

export function isValidIpKey(s) {
  if (typeof s !== "string" || s.length > 45) return false;
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s)) return true;
  return /^[0-9a-f]{1,4}(:[0-9a-f]{1,4}){3}::\/64$/i.test(s);
}

function safeDecode(s) {
  let out = s;
  for (let i = 0; i < 2; i++) {
    try { const d = decodeURIComponent(out); if (d === out) break; out = d; } catch { break; }
  }
  return out;
}

export function inspect(request) {
  const url = new URL(request.url);
  const path = safeDecode(url.pathname);
  const query = safeDecode(url.search);
  const ua = request.headers.get("User-Agent") || "";

  if (SCANNER_UA.test(ua)) return { kind: "scanner", detail: (ua.match(SCANNER_UA) || [""])[0] };
  if (HONEYPOT.test(path)) return { kind: "honeypot", detail: path.slice(0, 120) };
  const target = path + " " + query;
  for (const [name, re] of ATTACK) {
    if (re.test(target)) return { kind: "attack", detail: name };
  }
  return null;
}

/* ------------------------------------------------------------------ ban cache */
const cache = { at: 0, bans: new Map(), allow: new Set(), loading: null };
const strikesMem = new Map();      // ipKey -> { n, t }
const rateMem = new Map();         // ipKey -> { s:[start,count], b:[start,count] }
const lastWrite = new Map();       // ipKey -> epoch ms (throttle D1 writes)

export function _resetForTests() {
  cache.at = 0; cache.bans.clear(); cache.allow.clear(); cache.loading = null;
  strikesMem.clear(); rateMem.clear(); lastWrite.clear();
}

async function loadCache(env, now) {
  if (!env.DB) return;
  if (now - cache.at < BAN_CACHE_MS) return;
  if (!cache.loading) {
    cache.loading = (async () => {
      try {
        const [bans, allow] = await env.DB.batch([
          env.DB.prepare("SELECT ip, expires_at FROM bans WHERE expires_at > ?").bind(now),
          env.DB.prepare("SELECT ip FROM allowlist"),
        ]);
        cache.bans = new Map(bans.results.map((r) => [r.ip, r.expires_at]));
        cache.allow = new Set(allow.results.map((r) => r.ip));
        cache.at = now;
      } catch (err) {
        console.error("ban cache refresh failed", err);
        cache.at = now - BAN_CACHE_MS + 10_000;  // retry in 10 s, keep previous list
      } finally {
        cache.loading = null;
      }
    })();
  }
  await cache.loading;
}

/* ------------------------------------------------------------------ rate limiting */
function memLimited(key, now) {
  const e = rateMem.get(key) || { s: [now, 0], b: [now, 0] };
  for (const [slot, [limit, win]] of [["s", MEM_LIMIT.sustained], ["b", MEM_LIMIT.burst]]) {
    if (now - e[slot][0] > win) e[slot] = [now, 0];
    e[slot][1]++;
    if (e[slot][1] > limit) { rateMem.set(key, e); return true; }
  }
  rateMem.set(key, e);
  if (rateMem.size > 5000) rateMem.clear();     // bound memory
  return false;
}

async function rateLimited(env, key, now) {
  if (memLimited(key, now)) return true;
  try {
    if (env.RL_BURST && !(await env.RL_BURST.limit({ key })).success) return true;
    if (env.RL_SUSTAINED && !(await env.RL_SUSTAINED.limit({ key })).success) return true;
  } catch (err) {
    console.error("rate limit binding error", err);
  }
  return false;
}

/* ------------------------------------------------------------------ actions */
function meta(request) {
  const cf = request.cf || {};
  const url = new URL(request.url);
  return {
    method: request.method,
    path: (url.pathname + url.search).slice(0, 300),
    ua: (request.headers.get("User-Agent") || "").slice(0, 300),
    country: cf.country || null,
    asn: cf.asOrganization ? `AS${cf.asn || "?"} ${cf.asOrganization}`.slice(0, 120) : null,
  };
}

async function logEvent(env, key, kind, detail, m, action, now) {
  if (!env.DB) return;
  await env.DB.prepare(
    "INSERT INTO events (ts, ip, kind, detail, method, path, user_agent, country, asn, action) VALUES (?,?,?,?,?,?,?,?,?,?)",
  ).bind(now, key, kind, detail, m.method, m.path, m.ua, m.country, m.asn, action).run();
}

export async function banIp(env, key, reason, m, now, { hours, source = "auto" } = {}) {
  let offenses = 1;
  if (env.DB && source === "auto") {
    // Another isolate may already have banned this IP: do not escalate twice.
    const cur = await env.DB.prepare("SELECT expires_at, offense_count FROM bans WHERE ip = ?").bind(key).first();
    if (cur && cur.expires_at > now) {
      cache.bans.set(key, cur.expires_at);
      return { hours: Math.round((cur.expires_at - now) / 3600_000), offenses: cur.offense_count, expires: cur.expires_at, existing: true };
    }
  }
  if (env.DB) {
    const prev = await env.DB.prepare("SELECT offenses FROM ban_history WHERE ip = ?").bind(key).first();
    offenses = (prev?.offenses || 0) + 1;
  }
  const h = hours ?? ESCALATION_H[Math.min(offenses, ESCALATION_H.length) - 1];
  const expires = now + h * 3600_000;
  cache.bans.set(key, expires);
  if (env.DB) {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO bans (ip, reason, source, created_at, expires_at, offense_count, country, asn, last_path, user_agent)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, source=excluded.source, created_at=excluded.created_at,
          expires_at=excluded.expires_at, offense_count=excluded.offense_count, country=excluded.country,
          asn=excluded.asn, last_path=excluded.last_path, user_agent=excluded.user_agent`)
        .bind(key, reason, source, now, expires, offenses, m.country, m.asn, m.path, m.ua),
      env.DB.prepare(`INSERT INTO ban_history (ip, offenses, last_at) VALUES (?,?,?)
        ON CONFLICT(ip) DO UPDATE SET offenses=excluded.offenses, last_at=excluded.last_at`).bind(key, offenses, now),
    ]);
  }
  return { hours: h, offenses, expires };
}

async function alertBan(env, key, reason, m, ban, now) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  if (env.DB) {
    const row = await env.DB.prepare("SELECT last_at FROM alerts WHERE key = ?").bind(`ban:${key}`).first();
    if (row && now - row.last_at < ALERT_THROTTLE_MS) return;
    await env.DB.prepare(`INSERT INTO alerts (key, last_at) VALUES (?,?)
      ON CONFLICT(key) DO UPDATE SET last_at=excluded.last_at`).bind(`ban:${key}`, now).run();
  }
  const lines = [
    `🛡️ <b>MPatchMonitor: IP blocked</b>`,
    ``,
    `<b>IP</b> <code>${escapeHtml(key)}</code>`,
    `<b>Reason</b> ${escapeHtml(reason)}`,
    `<b>Request</b> <code>${escapeHtml(m.method)} ${escapeHtml(m.path)}</code>`,
    `<b>Origin</b> ${escapeHtml(m.country || "?")}, ${escapeHtml(m.asn || "unknown network")}`,
    `<b>User agent</b> ${escapeHtml(m.ua || "none")}`,
    `<b>Blocked for</b> ${ban.hours} h (offense ${ban.offenses})`,
  ];
  if (env.ADMIN_URL) lines.push("", `<a href="${escapeHtml(env.ADMIN_URL)}">Open the admin dashboard</a>`);
  await sendTelegram(env, lines.join("\n"));
}

async function strike(env, key, kind, detail, m, now) {
  const s = strikesMem.get(key);
  const cur = s && now - s.t < STRIKE_WINDOW_MS ? { n: s.n + 1, t: s.t } : { n: 1, t: now };
  strikesMem.set(key, cur);
  if (strikesMem.size > 5000) strikesMem.clear();

  // Persist at most one strike per IP every 5 s per isolate, count across isolates in D1.
  if (!env.DB || now - (lastWrite.get(key) || 0) < 5000) {
    return cur.n >= STRIKES_TO_BAN * 4;     // safety net if D1 is unavailable
  }
  lastWrite.set(key, now);
  await logEvent(env, key, kind, detail, m, "blocked", now);
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM events WHERE ip = ? AND ts > ? AND kind IN ('ratelimit','method','oversize')",
  ).bind(key, now - STRIKE_WINDOW_MS).first();
  return (row?.n || 0) >= STRIKES_TO_BAN;
}

/* ------------------------------------------------------------------ public API */
export function blockedResponse(status, message, extra = {}) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra,
    },
  });
}

/**
 * Returns a Response when the request must be stopped, otherwise null.
 * Heavy work (D1 writes, Telegram) is pushed to ctx.waitUntil.
 */
export async function guard(request, env, ctx, { allowedMethods = ["GET", "HEAD"] } = {}) {
  const now = Date.now();
  const key = ipKey(clientIp(request));
  await loadCache(env, now);

  const allowed = cache.allow.has(key);
  const bannedUntil = cache.bans.get(key);
  if (!allowed && bannedUntil && bannedUntil > now) {
    return blockedResponse(403, "Access from your network is temporarily blocked.", {
      "Retry-After": String(Math.ceil((bannedUntil - now) / 1000)),
    });
  }

  const m = meta(request);
  const background = (p) => ctx.waitUntil(p.catch((err) => console.error("guard background", err)));

  if (request.url.length > MAX_URL) {
    background(strike(env, key, "oversize", `url length ${request.url.length}`, m, now).then((ban) =>
      ban && !allowed && autoBan(env, key, "repeated oversized requests", m, now)));
    return blockedResponse(414, "Request URL too long.");
  }

  if (!allowedMethods.includes(request.method)) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { Allow: allowedMethods.join(", ") } });
    background(strike(env, key, "method", request.method, m, now).then((ban) =>
      ban && !allowed && autoBan(env, key, "repeated invalid methods", m, now)));
    return blockedResponse(405, "Method not allowed.", { Allow: allowedMethods.join(", ") });
  }

  const hit = inspect(request);
  if (hit) {
    const reason = `${hit.kind}: ${hit.detail}`;
    if (allowed) {
      // Trusted address (owner or authorised scanner): let it through, keep only a log line.
      console.log("allowlisted request matched", key, reason);
      return null;
    }
    cache.bans.set(key, now + 3600_000);           // block immediately in this isolate
    background(logEvent(env, key, hit.kind, hit.detail, m, "banned", now)
      .then(() => autoBan(env, key, reason, m, now)));
    return blockedResponse(403, "Request blocked.");
  }

  // Allowlisted addresses (the owner, an authorised scanner) are trusted: no rate limit.
  if (!allowed && await rateLimited(env, key, now)) {
    background(strike(env, key, "ratelimit", "too many requests", m, now).then((ban) =>
      ban && autoBan(env, key, "repeated rate limit violations", m, now)));
    return blockedResponse(429, "Too many requests. Slow down and try again in a minute.", { "Retry-After": "60" });
  }
  return null;
}

async function autoBan(env, key, reason, m, now) {
  if (cache.allow.has(key)) return;
  const ban = await banIp(env, key, reason, m, now);
  await logEvent(env, key, "ban", reason, m, "banned", now);
  await alertBan(env, key, reason, m, ban, now);
}
