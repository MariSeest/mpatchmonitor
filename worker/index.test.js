import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker, { checkMsrc } from "./index.js";
import { _resetForTests } from "./security.js";
import { fakeD1, fakeKV, ctx } from "../test-support/fake-d1.js";

const assets = { fetch: async () => new Response("<!doctype html><title>x</title>", { headers: { "Content-Type": "text/html" } }) };
const env = (extra = {}) => ({ MPM: fakeKV(), DB: fakeD1(), ASSETS: assets, ...extra });
const req = (path, init = {}, ip = "203.0.113.7") =>
  new Request(`https://mpm.example${path}`, { ...init, headers: { "CF-Connecting-IP": ip, "User-Agent": "Mozilla/5.0", ...(init.headers || {}) } });
beforeEach(() => _resetForTests());

const updates = (oct) => ({ value: [
  { ID: "2026-Sep", InitialReleaseDate: "2026-09-08T07:00:00Z", CurrentReleaseDate: "2026-09-20T07:00:00Z" },
  { ID: "2026-Oct", InitialReleaseDate: "2026-10-13T07:00:00Z", CurrentReleaseDate: oct },
] });
const fetcher = (body, calls) => async (url, init) => {
  calls.push({ url, init });
  if (url.includes("api.github.com")) return new Response(null, { status: 204 });
  return Response.json(body);
};

test("cron: first run dispatches once, unchanged index does not, a revision does", async () => {
  const calls = [];
  const e = { MPM: fakeKV(), DB: fakeD1(), GITHUB_TOKEN: "t", GITHUB_REPO: "o/r" };
  await checkMsrc(e, fetcher(updates("2026-10-13T07:00:00Z"), calls));
  await checkMsrc(e, fetcher(updates("2026-10-13T07:00:00Z"), calls));
  assert.equal(calls.filter((c) => c.url.includes("github")).length, 1);
  const s = await checkMsrc(e, fetcher(updates("2026-10-15T17:00:00Z"), calls));
  const gh = calls.filter((c) => c.url.includes("github"));
  assert.equal(gh.length, 2);
  assert.deepEqual(JSON.parse(gh[1].init.body).client_payload.releases, ["2026-Oct"]);
  assert.deepEqual(s.changed_releases, ["2026-Oct"]);
  assert.equal(e.MPM.writes, 0, "the cron never writes to KV");
});

test("cron: MSRC outage keeps the previous fingerprint", async () => {
  const e = { MPM: fakeKV(), DB: fakeD1() };
  await e.DB.prepare("INSERT INTO state (key, value, updated_at) VALUES ('msrc_status', ?, 0)").bind(JSON.stringify({ ok: true, fingerprint: "x" })).run();
  const s = await checkMsrc(e, async () => new Response("down", { status: 503 }));
  assert.equal(s.ok, false);
  assert.equal(s.fingerprint, "x");
});

test("status reports pending until a newer data version exists", async () => {
  const e = env({ MPM: fakeKV({ version: { version: "2026-10-15T16:00:00Z" } }) });
  await e.DB.prepare("INSERT INTO state (key, value, updated_at) VALUES ('msrc_status', ?, 0)")
    .bind(JSON.stringify({ last_check: "2026-10-15T17:05:00Z", last_msrc_change: "2026-10-15T17:05:00Z" })).run();
  let r = await worker.fetch(req("/api/status"), e, ctx());
  assert.equal((await r.json()).pending, true);
  e.MPM = fakeKV({ version: { version: "2026-10-15T17:08:00Z" } });
  r = await worker.fetch(req("/api/status"), e, ctx());
  assert.equal((await r.json()).pending, false);
});

test("data honours ETag", async () => {
  const r = await worker.fetch(req("/api/data", { headers: { "If-None-Match": '"dashboard-v1"' } }), env({ MPM: fakeKV({ version: { version: "v1" } }) }), ctx());
  assert.equal(r.status, 304);
});

test("pages carry strict security headers", async () => {
  const r = await worker.fetch(req("/"), env(), ctx());
  assert.equal(r.status, 200);
  assert.match(r.headers.get("Content-Security-Policy"), /script-src 'self'; style-src 'self'/);
  assert.match(r.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  assert.equal(r.headers.get("X-Frame-Options"), "DENY");
});

test("CVE pages accept only well-formed identifiers", async () => {
  assert.equal((await worker.fetch(req("/cve/CVE-2026-21345"), env(), ctx())).status, 200);
  assert.equal((await worker.fetch(req("/cve/not-a-cve"), env(), ctx())).status, 404);
});

test("unknown paths are 404 and POST is refused", async () => {
  assert.equal((await worker.fetch(req("/nothing-here"), env(), ctx())).status, 404);
  assert.equal((await worker.fetch(req("/api/status", { method: "POST" }), env(), ctx())).status, 405);
});
