import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { runCron } from "./index.js";
import { parseFeed, matchKeyword, extractCves, checkAcn, decodeEntities } from "./acn.js";
import { normaliseTopic, handleWebhook, importAlerts, fanOut, drain } from "./watch.js";
import { handleMcp } from "./mcp.js";
import { patchTuesdays, patchTuesdayIcs } from "./feeds.js";
import { _resetForTests } from "./security.js";
import { fakeD1, fakeKV, ctx } from "../test-support/fake-d1.js";

const RSS = `<?xml version="1.0"?><rss><channel>
<item><title>Aggiornamenti Mensili Microsoft</title><link>https://www.acn.gov.it/portale/w/aggiornamenti-mensili-microsoft-25</link>
<pubDate>Tue, 13 Oct 2026 20:15:00 GMT</pubDate><description><![CDATA[<p>Microsoft ha rilasciato gli aggiornamenti mensili di sicurezza.</p>]]></description></item>
<item><title>Risolte vulnerabilit&#224; in prodotti Fortinet</title><link>https://www.acn.gov.it/portale/w/risolte-vulnerabilita-in-prodotti-fortinet-1</link>
<pubDate>Tue, 13 Oct 2026 22:00:00 GMT</pubDate><description>FortiOS</description></item>
<item><title>Phishing Microsoft 365</title><link>https://evil.example/x</link></item>
</channel></rss>`;

test("ACN feed parsing, keyword match and CVE extraction", () => {
  const items = parseFeed(RSS);
  assert.equal(items.length, 2, "items linking outside acn.gov.it are dropped");
  assert.equal(items[1].title, "Risolte vulnerabilità in prodotti Fortinet");
  assert.equal(matchKeyword(items[0], ["Microsoft"]), "Microsoft");
  assert.equal(matchKeyword(items[1], ["Microsoft"]), null);
  assert.equal(matchKeyword({ title: "MicrosoftX", summary: "" }, ["Microsoft"]), null);
  assert.deepEqual(extractCves("cve-2026-1234 CVE-2026-1234 CVE-2025-99999"), ["CVE-2026-1234", "CVE-2025-99999"]);
  assert.equal(decodeEntities("&#x1F600;&#0;&lt;"), "😀<");
});

test("ACN check stores new Microsoft bulletins once, alerts and queues a Watch event", async () => {
  const sent = [];
  const fetcher = async (url, init) => {
    if (url.includes("feedrss")) return new Response(RSS);
    if (url.includes("api.telegram.org")) { sent.push(JSON.parse(init.body)); return new Response("{}"); }
    return new Response("<html>Vulnerabilità CVE-2026-21345, CVE-2026-21346</html>");
  };
  const env = { DB: fakeD1(), TELEGRAM_BOT_TOKEN: "t", TELEGRAM_CHAT_ID: "1" };
  const r1 = await checkAcn(env, fetcher);
  assert.equal(r1.new.length, 1);
  assert.deepEqual(r1.new[0].cves, ["CVE-2026-21345", "CVE-2026-21346"]);
  const r2 = await checkAcn(env, fetcher);
  assert.equal(r2.new.length, 0);
  assert.equal(sent.length, 1);
  assert.match(sent[0].text, /CSIRT Italia/);
  const ev = await env.DB.prepare("SELECT topics FROM watch_events").first();
  assert.match(ev.topics, /^acn,cve:CVE-2026-21345/);
});

test("Watch topics are validated", () => {
  assert.equal(normaliseTopic("exploited"), "exploited");
  assert.equal(normaliseTopic("cve-2026-12345"), "cve:CVE-2026-12345");
  assert.equal(normaliseTopic("5070112"), "kb:KB5070112");
  assert.equal(normaliseTopic("'; DROP TABLE"), null);
});

const tgUpdate = (text, chatType = "private") => ({ message: { chat: { id: 4242, type: chatType }, text } });
const webhook = (body, secret = "s3cret") => new Request("https://x/tg/webhook", {
  method: "POST", headers: { "X-Telegram-Bot-Api-Secret-Token": secret, "Content-Type": "application/json" }, body: JSON.stringify(body) });

test("Telegram webhook: secret required, subscribe, list, stop", async () => {
  const replies = [];
  const fetcher = async (_u, init) => { replies.push(JSON.parse(init.body)); return new Response("{}"); };
  const env = { DB: fakeD1(), WATCH_BOT_TOKEN: "b", TELEGRAM_WEBHOOK_SECRET: "s3cret" };
  assert.equal((await handleWebhook(webhook(tgUpdate("/watch kev"), "wrong"), env, fetcher)).status, 404);
  await handleWebhook(webhook(tgUpdate("/watch exploited")), env, fetcher);
  await handleWebhook(webhook(tgUpdate("/watch CVE-2026-21345")), env, fetcher);
  await handleWebhook(webhook(tgUpdate("/watch nonsense")), env, fetcher);
  await handleWebhook(webhook(tgUpdate("/watch kev", "group")), env, fetcher);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_subs").first("n"), 2);
  await handleWebhook(webhook(tgUpdate("/list")), env, fetcher);
  assert.match(replies.at(-1).text, /CVE-2026-21345/);
  await handleWebhook(webhook(tgUpdate("/stop")), env, fetcher);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_subs").first("n"), 0);
});

test("pipeline alerts reach only matching subscribers, once", async () => {
  const env = { DB: fakeD1(), MPM: fakeKV({ alerts: { version: "v1", events: [
    { ts: "2026-10-14T08:00:00Z", topics: ["exploited", "cve:CVE-2026-1"], title: "Now exploited: CVE-2026-1", link: "https://x/cve/CVE-2026-1", ref: "a" },
    { ts: "2026-10-14T08:00:00Z", topics: ["patchtuesday"], title: "Patch Tuesday", ref: "b" },
  ] } }), WATCH_BOT_TOKEN: "b" };
  const now = Date.now();
  for (const [chat, topic] of [["1", "exploited"], ["2", "patchtuesday"], ["3", "cve:CVE-2026-1"], ["3", "exploited"], ["4", "kb:KB1"]]) {
    await env.DB.prepare("INSERT INTO watch_subs (chat_id, topic, created_at) VALUES (?,?,?)").bind(chat, topic, now).run();
  }
  assert.equal(await importAlerts(env), 2);
  assert.equal(await importAlerts(env), 0, "same version is imported once");
  assert.equal(await fanOut(env), 3);   // chat 1, chat 3 (deduplicated) for event 1; chat 2 for event 2
  assert.equal(await fanOut(env), 0);
  const sent = [];
  const n = await drain(env, async (_u, init) => { const b = JSON.parse(init.body); sent.push(b); return b.chat_id === "2" ? new Response("blocked", { status: 403 }) : new Response("{}"); });
  assert.equal(n, 2);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_subs WHERE chat_id = '2'").first("n"), 0, "blocked chats are forgotten");
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM watch_outbox").first("n"), 0);
});

const mcpIndex = { cves: { "CVE-2026-1": ["Windows Kernel EoP", "P1", 95, "Important", 7.8, 0.4, true, true, "2026-Oct", ["KB5"]] },
  kbs: { KB5: ["2026-10-13", "Critical", 3, 1, 95, ["Windows 11"], ["CVE-2026-1"], [], 1] },
  kev_recent: [["CVE-2026-9", "Ivanti", "EPMM", new Date().toISOString().slice(0, 10), false, 0.5, 80]],
  months: [["2026-Oct", "2026-10-13", 88, 4, 4, 6]] };
const mcp = (body, headers = { "Content-Type": "application/json" }) => new Request("https://x/mcp", { method: "POST", headers, body: JSON.stringify(body) });

test("MCP: initialize, list and call tools, reject bad requests", async () => {
  const env = { MPM: fakeKV({ mcp: mcpIndex, version: { version: "v", hashes: { mcp: "h" } }, hot: { cves: [{ id: "CVE-2026-1" }] } }), DB: fakeD1() };
  let r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }), env, "https://x")).json();
  assert.equal(r.result.serverInfo.name, "mpatchmonitor");
  r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 2, method: "tools/list" }), env, "https://x")).json();
  assert.ok(r.result.tools.some((t) => t.name === "get_cve"));
  r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_cve", arguments: { id: "cve-2026-1" } } }), env, "https://x")).json();
  assert.match(r.result.content[0].text, /"priority": "P1"/);
  r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "search", arguments: { query: "kernel" } } }), env, "https://x")).json();
  assert.match(r.result.content[0].text, /CVE-2026-1/);
  r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "exploited_recent", arguments: { days: 3 } } }), env, "https://x")).json();
  assert.match(r.result.content[0].text, /"count": 1/);
  r = await (await handleMcp(mcp({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "drop_tables" } }), env, "https://x")).json();
  assert.equal(r.error.code, -32602);
  assert.equal((await handleMcp(mcp({ jsonrpc: "2.0", method: "notifications/initialized" }), env, "https://x")).status, 202);
  assert.equal((await handleMcp(mcp([{ jsonrpc: "2.0", id: 1, method: "ping" }]), env, "https://x")).status, 400);
  assert.equal((await handleMcp(mcp({ jsonrpc: "2.0", id: 1, method: "ping" }, { "Content-Type": "text/plain" }), env, "https://x")).status, 415);
  const big = new Request("https://x/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(70_000) });
  assert.equal((await handleMcp(big, env, "https://x")).status, 413);
});

test("Patch Tuesday calendar: second Tuesdays", () => {
  const days = patchTuesdays(new Date("2026-10-14T00:00:00Z"), 3).map((d) => d.toISOString().slice(0, 10));
  assert.deepEqual(days, ["2026-11-10", "2026-12-08", "2027-01-12"]);
  const ics = patchTuesdayIcs("https://x", new Date("2026-10-14T00:00:00Z"));
  assert.match(ics, /BEGIN:VCALENDAR/);
  assert.match(ics, /DTSTART;VALUE=DATE:20261110/);
});

test("routes validate identifiers; POST only where expected", async () => {
  _resetForTests();
  const assets = { fetch: async () => new Response("<!doctype html><title>x</title>", { headers: { "Content-Type": "text/html" } }) };
  const env = { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets };
  const get = (p, init = {}) => worker.fetch(new Request(`https://x${p}`, { ...init, headers: { "CF-Connecting-IP": "203.0.113.50", ...(init.headers || {}) } }), env, ctx());
  for (const p of ["/kb/KB5070112", "/release/2026-Oct", "/hot", "/exploited", "/acn", "/feeds", "/alerts", "/method", "/end-of-life"]) {
    assert.equal((await get(p)).status, 200, p);
  }
  for (const p of ["/kb/abc", "/release/2026-10", "/feed/unknown.xml"]) assert.equal((await get(p)).status, 404, p);
  assert.equal((await get("/kb", { method: "POST" })).status, 405);
  assert.equal((await get("/tg/webhook", { method: "POST", body: "{}" })).status, 404, "webhook without the secret looks absent");
  assert.equal((await get("/ics/patch-tuesday.ics")).headers.get("Content-Type"), "text/calendar; charset=utf-8");
  const acn = await (await get("/api/acn")).json();
  assert.deepEqual(acn.items, []);
});

test("cron runs MSRC and, every 15 minutes, the ACN monitor", async () => {
  const calls = [];
  const fetcher = async (url) => { calls.push(String(url)); return url.includes("feedrss") ? new Response(RSS) : Response.json({ value: [] }); };
  const env = { MPM: fakeKV(), DB: fakeD1() };
  await runCron(env, Date.parse("2026-10-14T10:07:00Z"), fetcher);
  assert.ok(!calls.some((u) => u.includes("feedrss")));
  await runCron(env, Date.parse("2026-10-14T10:15:00Z"), fetcher);
  assert.ok(calls.some((u) => u.includes("feedrss")));
});
