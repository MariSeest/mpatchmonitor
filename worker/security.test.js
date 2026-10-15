import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";
import { ipKey, isValidIpKey, inspect, _resetForTests } from "./security.js";
import { fakeD1, fakeKV, ctx } from "../test-support/fake-d1.js";

beforeEach(() => _resetForTests());
const assets = { fetch: async () => new Response("ok") };
const req = (path, { ip = "198.51.100.9", ua = "Mozilla/5.0", method = "GET" } = {}) =>
  new Request(`https://mpm.example${path}`, { method, headers: { "CF-Connecting-IP": ip, "User-Agent": ua } });

test("IPv6 addresses are grouped by /64", () => {
  assert.equal(ipKey("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(ipKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(ipKey("203.0.113.5"), "203.0.113.5");
  assert.ok(isValidIpKey("2001:db8:1:2::/64") && isValidIpKey("10.0.0.1"));
  assert.ok(!isValidIpKey("10.0.0.256") && !isValidIpKey("'; drop table bans;--"));
});

test("detection: traps, payloads and scanners", () => {
  const hit = (p, ua) => inspect(req(p, { ua }))?.kind;
  for (const p of ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql", "/server-status", "/vendor/phpunit/x"]) assert.equal(hit(p), "honeypot", p);
  for (const p of ["/x?q=1' OR '1'='1", "/api/data?f=../../etc/passwd", "/x?q=<script>alert(1)</script>", "/x?u=${jndi:ldap://a/b}", "/x?c=;cat /etc/hosts", "/x?q=%253Cscript%253E"]) assert.equal(hit(p), "attack", p);
  assert.equal(hit("/", "sqlmap/1.8"), "scanner");
  assert.equal(hit("/", "Mozilla/5.0 (compatible; Nuclei)"), "scanner");
});

test("detection: no false positives on normal traffic", () => {
  for (const p of ["/", "/cve/CVE-2026-21345", "/api/data", "/api/status", "/styles.css", "/cve/CVE-2026-1234?ref=linkedin"]) {
    assert.equal(inspect(req(p, { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/141.0" })), null, p);
  }
});

test("an attack bans the IP, logs it, alerts Telegram, and blocks later requests", async () => {
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { sent.push({ url: String(url), body: init?.body }); return new Response("{}"); };
  try {
    const env = { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets, TELEGRAM_BOT_TOKEN: "t", TELEGRAM_CHAT_ID: "1" };
    const c = ctx();
    const r = await worker.fetch(req("/.env"), env, c);
    assert.equal(r.status, 403);
    await c.flush();
    const ban = await env.DB.prepare("SELECT * FROM bans WHERE ip = ?").bind("198.51.100.9").first();
    assert.ok(ban && ban.expires_at > Date.now() && /honeypot/.test(ban.reason));
    assert.equal(sent.filter((s) => s.url.includes("api.telegram.org")).length, 1);
    assert.match(JSON.parse(sent[0].body).text, /198\.51\.100\.9/);
    const again = await worker.fetch(req("/"), env, ctx());
    assert.equal(again.status, 403);
    // a different IP is unaffected
    assert.equal((await worker.fetch(req("/", { ip: "198.51.100.10" }), env, ctx())).status, 200);
  } finally { globalThis.fetch = realFetch; }
});

test("repeat offenders get longer bans", async () => {
  const env = { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets };
  const c = ctx();
  await worker.fetch(req("/.git/HEAD"), env, c); await c.flush();
  const first = await env.DB.prepare("SELECT expires_at - created_at AS d FROM bans").first();
  await env.DB.prepare("UPDATE bans SET expires_at = 0").run();
  _resetForTests();
  await worker.fetch(req("/wp-admin/"), env, c); await c.flush();
  const second = await env.DB.prepare("SELECT expires_at - created_at AS d, offense_count FROM bans").first();
  assert.equal(first.d, 3600_000);
  assert.equal(second.d, 24 * 3600_000);
  assert.equal(second.offense_count, 2);
});

test("rate limit returns 429 and repeated violations end in a ban", async () => {
  const env = { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets };
  let limited = 0;
  for (let i = 0; i < 40; i++) {
    const c = ctx();
    const r = await worker.fetch(req("/api/health"), env, c);
    if (r.status === 429) limited++;
    await c.flush();
  }
  assert.ok(limited > 0, "burst limit applied");
  // simulate violations spread over time in D1
  const now = Date.now();
  for (let i = 0; i < 5; i++) {
    await env.DB.prepare("INSERT INTO events (ts, ip, kind, action) VALUES (?,?,?,?)").bind(now - i * 1000, "198.51.100.9", "ratelimit", "blocked").run();
  }
  _resetForTests();
  for (let i = 0; i < 30; i++) { const c = ctx(); await worker.fetch(req("/api/health"), env, c); await c.flush(); }
  const ban = await env.DB.prepare("SELECT reason FROM bans WHERE ip = ?").bind("198.51.100.9").first();
  assert.match(ban?.reason || "", /rate limit/);
});

test("allowlisted addresses are never banned", async () => {
  const env = { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets };
  await env.DB.prepare("INSERT INTO allowlist (ip, note, created_at) VALUES (?,?,?)").bind("198.51.100.9", "me", Date.now()).run();
  const c = ctx();
  const r = await worker.fetch(req("/.env"), env, c);
  await c.flush();
  assert.equal(r.status, 404);
  assert.equal(await env.DB.prepare("SELECT COUNT(*) AS n FROM bans").first("n"), 0);
});

test("oversized URLs are refused", async () => {
  const r = await worker.fetch(req("/" + "a".repeat(3000)), { MPM: fakeKV(), DB: fakeD1(), ASSETS: assets }, ctx());
  assert.equal(r.status, 414);
});
