/**
 * Web Push (browser notifications) without any third-party service.
 *
 *  - Subscriptions: the browser's push endpoint and keys plus the chosen topics. Nothing else.
 *  - Messages are encrypted for each browser (RFC 8291, aes128gcm) and signed with the site's
 *    VAPID key (RFC 8292), entirely with WebCrypto inside the Worker.
 *  - Delivery shares the cron run with Telegram, within the Free plan subrequest limit.
 */
import { getState, putState } from "./state.js";
import { wt } from "./i18n.js";

export const PUSH_TOPICS = ["all", "patchtuesday", "exploited", "kev", "oob", "reinstall", "acn", "issues"];
const MAX_TOPICS = 30;
const MAX_SUBSCRIPTIONS = 20000;      // D1 Free: plenty of room, and a hard ceiling against abuse
const MAX_BODY = 4096;
export const PUSH_PER_RUN = 18;       // + Telegram 25 + checks: stays under 50 subrequests
// Push services of the major browsers. Anything else is refused (no SSRF through the endpoint).
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^web\.push\.apple\.com$/,
  /^[a-z0-9-]+\.notify\.windows\.com$/, /^push\.services\.mozilla\.com$/];

const enc = new TextEncoder();
export const b64u = {
  encode(buf) {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(str) {
    if (typeof str !== "string" || !/^[A-Za-z0-9_-]*={0,2}$/.test(str)) throw new Error("bad base64url");
    const s = atob(str.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.replace(/=+$/, "").length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}

/** RFC 8291: encrypts one message for one browser. Returns the aes128gcm body. */
export async function encryptPayload(payload, p256dh, auth, { salt, keyPair } = {}) {
  const uaPublic = typeof p256dh === "string" ? b64u.decode(p256dh) : p256dh;
  const authSecret = typeof auth === "string" ? b64u.decode(auth) : auth;
  salt ||= crypto.getRandomValues(new Uint8Array(16));
  keyPair ||= await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, keyPair.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const data = concat(typeof payload === "string" ? enc.encode(payload) : payload, new Uint8Array([2]));   // last record, no padding
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data));
  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  return concat(header, asPublic, cipher);
}

/** RFC 8292: VAPID JWT (ES256) for the push service origin. */
export async function vapidAuth(endpoint, env, now = Date.now()) {
  const jwk = JSON.parse(env.VAPID_PRIVATE_KEY);
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = b64u.encode(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u.encode(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || env.PUBLIC_ORIGIN || "mailto:security@example.invalid",
  })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${head}.${body}`));
  return `vapid t=${head}.${body}.${b64u.encode(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

export const pushEnabled = (env) => Boolean(env.DB && env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY && /^[A-Za-z0-9_-]{80,90}$/.test(env.VAPID_PUBLIC_KEY));

export function validEndpoint(endpoint) {
  if (typeof endpoint !== "string" || endpoint.length > 1000) return false;
  let u;
  try { u = new URL(endpoint); } catch { return false; }
  return u.protocol === "https:" && !u.username && !u.password && (u.port === "" || u.port === "443") && PUSH_HOSTS.some((re) => re.test(u.hostname));
}

function validKeys(keys) {
  try {
    const p = b64u.decode(keys?.p256dh), a = b64u.decode(keys?.auth);
    return p.length === 65 && p[0] === 4 && a.length === 16;
  } catch { return false; }
}

export function cleanTopics(list) {
  if (!Array.isArray(list)) return null;
  const out = [...new Set(list.map(String).filter((t) => PUSH_TOPICS.includes(t) || /^cve:CVE-[A-Z0-9]{4}-\d{4,7}$/.test(t) || /^kb:KB\d{6,8}$/.test(t)))];
  return out.length && out.length <= MAX_TOPICS ? out : null;
}

async function subId(endpoint) {
  return b64u.encode(await crypto.subtle.digest("SHA-256", enc.encode(endpoint))).slice(0, 32);
}

async function readJson(request) {
  if (!/^application\/json\b/i.test(request.headers.get("Content-Type") || "")) return null;
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > MAX_BODY) return null;
  const text = await request.text();
  if (text.length > MAX_BODY) return null;
  try { return JSON.parse(text); } catch { return null; }
}

const reply = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin" },
});

/** POST /api/push/subscribe {subscription:{endpoint, keys:{p256dh, auth}}, topics:[...], lang}
 *  POST /api/push/unsubscribe {endpoint}
 *  GET  /api/push/key -> {key} */
export async function handlePush(request, env, path, origin) {
  if (path === "/api/push/key") {
    return pushEnabled(env) ? reply({ key: env.VAPID_PUBLIC_KEY, topics: PUSH_TOPICS }) : reply({ error: "Browser notifications are not configured." }, 503);
  }
  if (request.method !== "POST") return reply({ error: "Method not allowed." }, 405);
  if (!pushEnabled(env)) return reply({ error: "Browser notifications are not configured." }, 503);
  // Only the site's own pages may subscribe or unsubscribe (no cross-site requests).
  if (request.headers.get("Origin") !== origin || request.headers.get("Sec-Fetch-Site") && request.headers.get("Sec-Fetch-Site") !== "same-origin") {
    return reply({ error: "Forbidden." }, 403);
  }
  const body = await readJson(request);
  if (!body || typeof body !== "object") return reply({ error: "Invalid request." }, 400);
  const now = Date.now();

  if (path === "/api/push/unsubscribe") {
    if (!validEndpoint(body.endpoint)) return reply({ error: "Invalid request." }, 400);
    const id = await subId(body.endpoint);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM push_topics WHERE sub_id = ?").bind(id),
      env.DB.prepare("DELETE FROM push_outbox WHERE sub_id = ?").bind(id),
      env.DB.prepare("DELETE FROM push_subs WHERE id = ?").bind(id),
    ]);
    return reply({ ok: true });
  }

  if (path === "/api/push/subscribe") {
    const sub = body.subscription;
    const topics = cleanTopics(body.topics);
    if (!sub || !validEndpoint(sub.endpoint) || !validKeys(sub.keys) || !topics) return reply({ error: "Invalid request." }, 400);
    const id = await subId(sub.endpoint);
    const exists = await env.DB.prepare("SELECT 1 FROM push_subs WHERE id = ?").bind(id).first();
    if (!exists) {
      const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM push_subs").first();
      if ((n?.n || 0) >= MAX_SUBSCRIPTIONS) return reply({ error: "Too many subscriptions, try again later." }, 503);
    }
    const lang = body.lang === "it" ? "it" : "en";
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO push_subs (id, endpoint, p256dh, auth, lang, created_at, updated_at) VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET p256dh = excluded.p256dh, auth = excluded.auth, lang = excluded.lang, updated_at = excluded.updated_at`)
        .bind(id, sub.endpoint, sub.keys.p256dh, sub.keys.auth, lang, now, now),
      env.DB.prepare("DELETE FROM push_topics WHERE sub_id = ?").bind(id),
      ...topics.map((t) => env.DB.prepare("INSERT INTO push_topics (sub_id, topic) VALUES (?, ?)").bind(id, t)),
    ]);
    return reply({ ok: true, topics });
  }
  return reply({ error: "Not found." }, 404);
}

/** New alert events -> one outbox row per subscribed browser. */
export async function pushFanOut(env, now = Date.now()) {
  if (!pushEnabled(env)) return 0;
  const lastId = (await getState(env, "push_fanout_id")) ?? null;
  if (lastId === null) {
    // first run: start from the latest event, never replay history
    const top = await env.DB.prepare("SELECT MAX(id) AS id FROM watch_events").first();
    await putState(env, "push_fanout_id", top?.id || 0);
    return 0;
  }
  const events = await env.DB.prepare("SELECT id, topics FROM watch_events WHERE id > ? ORDER BY id LIMIT 20").bind(lastId).all();
  let queued = 0, maxId = lastId;
  for (const e of events.results) {
    const topics = ["all", ...e.topics.split(",")];
    const res = await env.DB.prepare(`INSERT OR IGNORE INTO push_outbox (event_id, sub_id, created_at)
      SELECT DISTINCT ?, sub_id, ? FROM push_topics WHERE topic IN (${topics.map(() => "?").join(",")}) LIMIT 20000`).bind(e.id, now, ...topics).run();
    queued += res.meta?.changes || 0;
    maxId = Math.max(maxId, e.id);
  }
  if (maxId !== lastId) await putState(env, "push_fanout_id", maxId);
  return queued;
}

/** Sends up to `budget` queued notifications. */
export async function pushDrain(env, budget = PUSH_PER_RUN, fetcher = fetch) {
  if (!pushEnabled(env) || budget <= 0) return 0;
  const origin = env.PUBLIC_ORIGIN || "";
  const rows = await env.DB.prepare(`SELECT o.id, o.sub_id, o.attempts, s.endpoint, s.p256dh, s.auth, s.lang, e.title, e.text, e.link, e.title_it, e.text_it, e.topics
    FROM push_outbox o JOIN push_subs s ON s.id = o.sub_id JOIN watch_events e ON e.id = o.event_id ORDER BY o.id LIMIT ?`).bind(budget).all();
  let sent = 0;
  for (const r of rows.results) {
    const lang = r.lang === "it" ? "it" : "en";
    let url = r.link || `${origin}/alerts`;
    if (!/acn\.gov\.it/.test(url)) url = `${url}${url.includes("?") ? "&" : "?"}lang=${lang}`;
    const payload = JSON.stringify({
      title: String((lang === "it" && r.title_it) || r.title).slice(0, 200),
      body: String((lang === "it" && r.text_it) || r.text || "").slice(0, 400),
      url, tag: `mpm-${r.id}`, lang, urgent: /exploited|kev|reinstall/.test(r.topics || ""),
      footer: wt("Turn off in Free alerts", lang),
    });
    let status = 0;
    try {
      if (!validEndpoint(r.endpoint)) throw Object.assign(new Error("endpoint"), { gone: true });
      const body = await encryptPayload(payload, r.p256dh, r.auth);
      const res = await fetcher(r.endpoint, {
        method: "POST",
        headers: { Authorization: await vapidAuth(r.endpoint, env), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
          TTL: "86400", Urgency: /exploited|kev/.test(r.topics || "") ? "high" : "normal" },
        body,
      });
      status = res.status;
    } catch (err) {
      status = err.gone ? 410 : 0;
    }
    if (status >= 200 && status < 300) {
      await env.DB.prepare("DELETE FROM push_outbox WHERE id = ?").bind(r.id).run();
      sent++;
    } else if (status === 404 || status === 410 || status === 400 || status === 403 || status === 413) {
      // subscription expired or rejected: forget the browser entirely
      await env.DB.batch([
        env.DB.prepare("DELETE FROM push_outbox WHERE sub_id = ?").bind(r.sub_id),
        env.DB.prepare("DELETE FROM push_topics WHERE sub_id = ?").bind(r.sub_id),
        env.DB.prepare("DELETE FROM push_subs WHERE id = ?").bind(r.sub_id),
      ]);
    } else if (r.attempts >= 4) {
      await env.DB.prepare("DELETE FROM push_outbox WHERE id = ?").bind(r.id).run();
    } else {
      await env.DB.prepare("UPDATE push_outbox SET attempts = attempts + 1 WHERE id = ?").bind(r.id).run();
    }
  }
  return sent;
}
