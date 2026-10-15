/**
 * MPatchMonitor Watch: free public alerts through a Telegram bot.
 *
 *   /watch patchtuesday | exploited | kev | oob | reinstall | acn | all
 *   /watch CVE-2026-12345   /watch KB5070112
 *   /unwatch <topic>   /list   /lang it|en   /stop (deletes every subscription)
 *
 * Only the Telegram chat id, the chosen topics and the language are stored. Alerts come from the data
 * pipeline (KV key "alerts") and from the CSIRT Italia monitor, are logged publicly in
 * watch_events (without recipients) and delivered from an outbox, 40 messages per cron run.
 */
import { escapeHtml } from "./telegram.js";
import { getState, putState } from "./state.js";
import { telegramLang, wt } from "./i18n.js";

const TOPICS = {
  all: wt("everything below"),
  patchtuesday: wt("Microsoft Patch Tuesday releases"),
  exploited: wt("Microsoft vulnerabilities newly exploited or added to CISA KEV"),
  kev: wt("every new CISA KEV entry, all vendors"),
  oob: wt("out-of-band Microsoft updates"),
  reinstall: wt("Microsoft asking to reinstall a re-released update"),
  acn: wt("CSIRT Italia bulletins that mention Microsoft"),
  issues: wt("new known issues of Windows updates (release health)"),
};
const MAX_SUBS = 50;
const SEND_PER_RUN = 25;   // keeps every cron run under the Free plan subrequest limit

export function normaliseTopic(raw) {
  const t = String(raw || "").trim();
  if (/^CVE-\d{4}-\d{4,7}$/i.test(t)) return `cve:${t.toUpperCase()}`;
  if (/^(KB)?\d{6,8}$/i.test(t)) return `kb:KB${t.toUpperCase().replace(/^KB/, "")}`;
  const k = t.toLowerCase().replace(/[^a-z]/g, "");
  return Object.hasOwn(TOPICS, k) ? k : null;
}

function timingSafeEqual(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

async function tg(env, method, payload, fetcher = fetch) {
  return fetcher(`https://api.telegram.org/bot${env.WATCH_BOT_TOKEN}/${method}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

const HELP = (lang) => [
  `<b>MPatchMonitor Watch</b>: ${wt("free alerts on Microsoft security updates.", lang)}`,
  "",
  wt("Follow a topic with <code>/watch topic</code>:", lang),
  ...Object.entries(TOPICS).map(([k, v]) => `• <code>${k}</code>: ${escapeHtml(wt(v, lang))}`),
  wt("• a CVE, for example <code>/watch CVE-2026-21345</code>", lang),
  wt("• a security update, for example <code>/watch KB5070112</code>", lang),
  "",
  wt("<code>/list</code> shows what you follow, <code>/unwatch topic</code> stops one, <code>/stop</code> deletes everything.", lang),
  wt("<code>/lang it</code> or <code>/lang en</code> sets the language.", lang),
  wt("Only your Telegram chat id, topics and language are stored.", lang),
].join("\n");

async function chatLang(env, chat, fallback) {
  const row = await env.DB.prepare("SELECT lang FROM watch_chats WHERE chat_id = ?").bind(chat).first();
  return row?.lang === "it" || row?.lang === "en" ? row.lang : fallback;
}

async function saveLang(env, chat, lang, now) {
  await env.DB.prepare("INSERT INTO watch_chats (chat_id, lang, updated_at) VALUES (?,?,?) ON CONFLICT(chat_id) DO UPDATE SET lang = excluded.lang, updated_at = excluded.updated_at")
    .bind(chat, lang, now).run();
}

/** POST /tg/webhook */
export async function handleWebhook(request, env, fetcher = fetch) {
  const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!env.WATCH_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET || !timingSafeEqual(secret, env.TELEGRAM_WEBHOOK_SECRET)) {
    return new Response("Not found", { status: 404 });
  }
  const raw = await request.text();
  if (raw.length > 65_536) return new Response("Too large", { status: 413 });
  let update;
  try { update = JSON.parse(raw); } catch { return new Response("ok"); }
  const msg = update?.message;
  if (!msg || msg.chat?.type !== "private" || typeof msg.text !== "string") return new Response("ok");
  const chat = String(msg.chat.id).slice(0, 32);
  if (!/^-?\d+$/.test(chat)) return new Response("ok");
  const [cmd, ...args] = msg.text.trim().slice(0, 200).split(/\s+/);
  const command = cmd.toLowerCase().replace(/@.*$/, "");
  const now = Date.now();
  let lang = await chatLang(env, chat, telegramLang(msg.from?.language_code));
  let reply;

  if (command === "/start" || command === "/help") reply = HELP(lang);
  else if (command === "/lang") {
    const want = String(args[0] || "").toLowerCase();
    if (want === "it" || want === "en") {
      lang = want;
      await saveLang(env, chat, lang, now);
      reply = wt("Language set to English.", lang);
    } else reply = wt("Send <code>/lang it</code> or <code>/lang en</code>.", lang);
  } else if (command === "/watch") {
    const topic = normaliseTopic(args[0]);
    if (!topic) reply = wt("Unknown topic. Send /help to see what you can follow.", lang);
    else {
      const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_subs WHERE chat_id = ?").bind(chat).first())?.n || 0;
      if (n >= MAX_SUBS) reply = wt("You already follow {n} topics. Remove one with /unwatch first.", lang, { n: MAX_SUBS });
      else {
        await env.DB.prepare("INSERT OR IGNORE INTO watch_subs (chat_id, topic, created_at) VALUES (?,?,?)").bind(chat, topic, now).run();
        await saveLang(env, chat, lang, now);
        reply = wt("Done. You will get an alert for <b>{topic}</b>.", lang, { topic: escapeHtml(topic.replace(/^(cve|kb):/, "")) });
      }
    }
  } else if (command === "/unwatch") {
    const topic = normaliseTopic(args[0]);
    if (topic) await env.DB.prepare("DELETE FROM watch_subs WHERE chat_id = ? AND topic = ?").bind(chat, topic).run();
    reply = topic ? wt("Removed.", lang) : wt("Unknown topic. Send /list to see what you follow.", lang);
  } else if (command === "/list") {
    const rows = await env.DB.prepare("SELECT topic FROM watch_subs WHERE chat_id = ? ORDER BY topic").bind(chat).all();
    reply = rows.results.length
      ? `${wt("You follow:", lang)}\n${rows.results.map((r) => `• ${escapeHtml(r.topic.replace(/^(cve|kb):/, ""))}`).join("\n")}`
      : wt("You don't follow anything yet. Try <code>/watch exploited</code>.", lang);
  } else if (command === "/stop") {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM watch_subs WHERE chat_id = ?").bind(chat),
      env.DB.prepare("DELETE FROM watch_outbox WHERE chat_id = ?").bind(chat),
      env.DB.prepare("DELETE FROM watch_chats WHERE chat_id = ?").bind(chat),
    ]);
    reply = wt("All your subscriptions and pending alerts have been deleted.", lang);
  } else reply = wt("Send /help to see the commands.", lang);

  await tg(env, "sendMessage", { chat_id: chat, text: reply, parse_mode: "HTML", disable_web_page_preview: true }, fetcher);
  return new Response("ok");
}

/** Copies new pipeline alerts (KV "alerts") into the public event log. */
export async function importAlerts(env) {
  const alerts = await env.MPM.get("alerts", { type: "json" });
  if (!alerts?.version) return 0;
  const last = await getState(env, "watch_alerts_version");
  if (last === alerts.version) return 0;
  let n = 0;
  for (const e of (alerts.events || []).slice(0, 200)) {
    const topics = (e.topics || []).map(String).filter((t) => /^[a-z]+(:[A-Z0-9-]+)?$/.test(t)).slice(0, 30);
    if (!topics.length || !e.title) continue;
    await env.DB.prepare("INSERT OR IGNORE INTO watch_events (ts, topics, title, text, link, ref, title_it, text_it) VALUES (?,?,?,?,?,?,?,?)")
      .bind(Date.parse(e.ts) || Date.now(), topics.join(","), String(e.title).slice(0, 300), String(e.text || "").slice(0, 600),
        String(e.link || "").slice(0, 300), String(e.ref || `${alerts.version}:${n}`).slice(0, 200),
        e.title_it ? String(e.title_it).slice(0, 300) : null, e.text_it ? String(e.text_it).slice(0, 600) : null).run();
    n++;
  }
  await putState(env, "watch_alerts_version", alerts.version);
  return n;
}

/** Turns new events into one outbox row per subscriber. */
export async function fanOut(env, now = Date.now()) {
  const lastId = (await getState(env, "watch_fanout_id")) || 0;
  const events = await env.DB.prepare("SELECT id, topics FROM watch_events WHERE id > ? ORDER BY id LIMIT 20").bind(lastId).all();
  let queued = 0, maxId = lastId;
  for (const e of events.results) {
    const topics = ["all", ...e.topics.split(",")];
    const placeholders = topics.map(() => "?").join(",");
    const subs = await env.DB.prepare(`SELECT DISTINCT chat_id FROM watch_subs WHERE topic IN (${placeholders}) LIMIT 5000`).bind(...topics).all();
    for (const s of subs.results) {
      await env.DB.prepare("INSERT OR IGNORE INTO watch_outbox (event_id, chat_id, created_at) VALUES (?,?,?)").bind(e.id, s.chat_id, now).run();
      queued++;
    }
    maxId = Math.max(maxId, e.id);
  }
  if (maxId !== lastId) await putState(env, "watch_fanout_id", maxId);
  return queued;
}

/** Sends up to SEND_PER_RUN queued alerts. */
export async function drain(env, fetcher = fetch) {
  if (!env.WATCH_BOT_TOKEN) return 0;
  const rows = await env.DB.prepare(`SELECT o.id, o.chat_id, o.attempts, e.title, e.text, e.link, e.title_it, e.text_it, c.lang
    FROM watch_outbox o JOIN watch_events e ON e.id = o.event_id LEFT JOIN watch_chats c ON c.chat_id = o.chat_id
    ORDER BY o.id LIMIT ?`).bind(SEND_PER_RUN).all();
  let sent = 0;
  for (const r of rows.results) {
    const lang = r.lang === "it" ? "it" : "en";
    const title = (lang === "it" && r.title_it) || r.title;
    const body = (lang === "it" && r.text_it) || r.text;
    const link = r.link ? `${r.link}${r.link.includes("?") ? "&" : "?"}lang=${lang}` : "";
    const text = [`<b>${escapeHtml(title)}</b>`, body ? escapeHtml(body) : "",
      link ? `<a href="${escapeHtml(/acn\.gov\.it/.test(r.link) ? r.link : link)}">${wt("Details", lang)}</a>` : ""]
      .filter(Boolean).join("\n").slice(0, 3900);
    let res;
    try { res = await tg(env, "sendMessage", { chat_id: r.chat_id, text, parse_mode: "HTML", disable_web_page_preview: true }, fetcher); }
    catch { res = { ok: false, status: 0 }; }
    if (res.ok) {
      await env.DB.prepare("DELETE FROM watch_outbox WHERE id = ?").bind(r.id).run();
      sent++;
    } else if (res.status === 403 || res.status === 400) {
      // the user blocked the bot or the chat no longer exists: forget it
      await env.DB.batch([
        env.DB.prepare("DELETE FROM watch_subs WHERE chat_id = ?").bind(r.chat_id),
        env.DB.prepare("DELETE FROM watch_outbox WHERE chat_id = ?").bind(r.chat_id),
      ]);
    } else if (r.attempts >= 4) {
      await env.DB.prepare("DELETE FROM watch_outbox WHERE id = ?").bind(r.id).run();
    } else {
      await env.DB.prepare("UPDATE watch_outbox SET attempts = attempts + 1 WHERE id = ?").bind(r.id).run();
    }
  }
  return sent;
}
