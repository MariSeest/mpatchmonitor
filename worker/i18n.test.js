import { test } from "node:test";
import assert from "node:assert/strict";
import { pickLang, wt, telegramLang, I18N } from "./i18n.js";
import { handleWebhook, importAlerts, fanOut, drain } from "./watch.js";
import { fakeD1, fakeKV } from "../test-support/fake-d1.js";

const req = (url, headers = {}) => new Request(url, { headers });

test("language: query beats cookie beats browser setting, default English", () => {
  assert.deepEqual(pickLang(req("https://x/?lang=it")), { lang: "it", set: true });
  assert.deepEqual(pickLang(req("https://x/?lang=en", { Cookie: "mpm-lang=it" })), { lang: "en", set: true });
  assert.equal(pickLang(req("https://x/", { Cookie: "a=1; mpm-lang=it" })).lang, "it");
  assert.equal(pickLang(req("https://x/", { "Accept-Language": "it-IT,it;q=0.9,en;q=0.8" })).lang, "it");
  assert.equal(pickLang(req("https://x/", { "Accept-Language": "en-GB,it;q=0.5" })).lang, "en");
  assert.equal(pickLang(req("https://x/")).lang, "en");
  assert.equal(pickLang(req("https://x/?lang=<script>")).lang, "en", "unknown values are ignored");
  assert.equal(pickLang(req("https://x/", { Cookie: "mpm-lang=itx" })).lang, "en");
});

test("translations: Italian strings exist for the Worker and the pages", () => {
  assert.equal(wt("This page does not exist.", "it"), "Questa pagina non esiste.");
  assert.equal(wt("This page does not exist.", "en"), "This page does not exist.");
  assert.equal(wt("You already follow {n} topics. Remove one with /unwatch first.", "it", { n: 50 }), "Segui già 50 argomenti. Prima togline uno con /unwatch.");
  assert.ok(Object.keys(I18N.units).length > 150);
  for (const html of Object.values(I18N.units)) assert.doesNotMatch(html, /<script|on\w+=|javascript:/i);
  assert.equal(telegramLang("it-IT"), "it");
  assert.equal(telegramLang("en"), "en");
});

const tgUpdate = (text, lang = "it") => ({ message: { chat: { id: 42, type: "private" }, from: { language_code: lang }, text } });
const webhook = (body) => new Request("https://x/tg/webhook", { method: "POST", headers: { "X-Telegram-Bot-Api-Secret-Token": "s" }, body: JSON.stringify(body) });

test("Watch bot answers in the user's language and remembers /lang", async () => {
  const env = { DB: fakeD1(), WATCH_BOT_TOKEN: "b", TELEGRAM_WEBHOOK_SECRET: "s" };
  const replies = [];
  const fetcher = async (_u, init) => { replies.push(JSON.parse(init.body)); return new Response("{}"); };
  await handleWebhook(webhook(tgUpdate("/watch exploited")), env, fetcher);
  assert.match(replies.at(-1).text, /^Fatto\./);
  await handleWebhook(webhook(tgUpdate("/lang en")), env, fetcher);
  assert.match(replies.at(-1).text, /Language set to English/);
  await handleWebhook(webhook(tgUpdate("/help")), env, fetcher);
  assert.match(replies.at(-1).text, /free alerts/);
  await handleWebhook(webhook(tgUpdate("/stop")), env, fetcher);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_chats").first("n"), 0, "/stop also forgets the language");
});

test("alerts are delivered in each chat's language", async () => {
  const env = { DB: fakeD1(), WATCH_BOT_TOKEN: "b", MPM: fakeKV({ alerts: { version: "v1", events: [
    { ts: "2026-10-14T08:00:00Z", topics: ["exploited"], title: "Now exploited: CVE-2026-1", title_it: "Ora sfruttata: CVE-2026-1",
      text: "Microsoft now reports exploitation detected", text_it: "Microsoft ora segnala uno sfruttamento rilevato", link: "https://x/cve/CVE-2026-1", ref: "a" },
  ] } }) };
  const now = Date.now();
  for (const [chat, lang] of [["1", "it"], ["2", "en"]]) {
    await env.DB.prepare("INSERT INTO watch_subs (chat_id, topic, created_at) VALUES (?,?,?)").bind(chat, "exploited", now).run();
    await env.DB.prepare("INSERT INTO watch_chats (chat_id, lang, updated_at) VALUES (?,?,?)").bind(chat, lang, now).run();
  }
  await importAlerts(env);
  await fanOut(env);
  const sent = {};
  await drain(env, async (_u, init) => { const b = JSON.parse(init.body); sent[b.chat_id] = b.text; return new Response("{}"); });
  assert.match(sent["1"], /Ora sfruttata/);
  assert.match(sent["1"], /lang=it">Dettagli/);
  assert.match(sent["2"], /Now exploited/);
  assert.match(sent["2"], /lang=en">Details/);
});
