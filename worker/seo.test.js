import { test } from "node:test";
import assert from "node:assert/strict";
import { decodePng, epssSeries, ldJson, robots, sitemap, structuredData } from "./seo.js";
import worker, { epssHistory } from "./index.js";
import { _resetForTests } from "./security.js";
import { fakeD1, fakeKV, ctx } from "../test-support/fake-d1.js";

const O = "https://mpm.example";

test("sitemap lists pages, months, CVEs and KBs with language alternates, and skips invalid ids", () => {
  const xml = sitemap(O, { items: [["cve", "CVE-2026-21345", "x"], ["kb", "KB5070112"], ["cve", "CVE-2026-21345"], ["cve", "<script>"],
    ["kb", "KB1\"><x"], ["product", "Windows"]] }, { months: [{ id: "2026-Oct", release_date: "2026-10-13" }, { id: "2026-Xyz" }] }, "2026-10-14T08:00:00Z");
  assert.match(xml, /<loc>https:\/\/mpm\.example\/cve\/CVE-2026-21345<\/loc>/);
  assert.equal(xml.match(/\/cve\/CVE-2026-21345<\/loc>/g).length, 1);
  assert.match(xml, /\/kb\/KB5070112</);
  assert.match(xml, /\/analysis\/2026-Oct</);
  assert.match(xml, /hreflang="it" href="https:\/\/mpm\.example\/release\/2026-Oct\?lang=it"/);
  assert.doesNotMatch(xml, /<script|Xyz|"><x/);
  assert.match(robots(O), /Sitemap: https:\/\/mpm\.example\/sitemap\.xml/);
});

test("JSON-LD cannot close its script element and describes the page", () => {
  assert.doesNotMatch(ldJson({ a: "</script><script>alert(1)</script>" }), /<\/script/i);
  const cve = JSON.parse(structuredData(O, "/cve/CVE-2026-21345", "it", "CVE-2026-21345", "d"));
  const page = cve["@graph"].find((g) => g["@type"] === "WebPage");
  assert.equal(page.about.identifier, "CVE-2026-21345");
  assert.ok(cve["@graph"].some((g) => g["@type"] === "BreadcrumbList"));
  const an = JSON.parse(structuredData(O, "/analysis/2026-Oct", "en", "Patch Tuesday October 2026: the analysis", ""));
  assert.equal(an["@graph"][1]["@type"], "Article");
  assert.match(an["@graph"][1].image, /\/og\/analysis\/2026-Oct\.png\?lang=en$/);
});

test("preview images are accepted only as real PNG data", () => {
  assert.equal(decodePng("PHN2Zz4="), null);              // "<svg>"
  assert.equal(decodePng("not base64!"), null);
  assert.ok(decodePng(Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2]).toString("base64")));
});

test("EPSS history is cleaned and sorted, failures answer 502", async () => {
  const body = { data: [{ cve: "CVE-2026-1", epss: "0.5", percentile: "0.9", date: "2026-10-14",
    "time-series": [{ epss: "0.4", percentile: "0.8", date: "2026-10-13" }, { epss: "7", date: "2026-10-12" }, { epss: "0.1", date: "<x>" }] }] };
  assert.deepEqual(epssSeries(body, "CVE-2026-1").map((p) => p.date), ["2026-10-13", "2026-10-14"]);
  assert.deepEqual(epssSeries(body, "CVE-2026-2"), []);
  const ok = await epssHistory("CVE-2026-1", null, async (url) => {
    assert.ok(url.startsWith("https://api.first.org/data/v1/epss?cve=CVE-2026-1&scope=time-series"));
    return Response.json(body);
  });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).series.length, 2);
  const bad = await epssHistory("CVE-2026-1", null, async () => new Response("x", { status: 500 }));
  assert.equal(bad.status, 502);
});

test("routes: robots, sitemap, invalid EPSS and preview requests", async () => {
  _resetForTests();
  const env = { MPM: fakeKV({ search: { items: [["cve", "CVE-2026-21345"]] }, summary: { months: [{ id: "2026-Oct" }] } }), DB: fakeD1(),
    ASSETS: { fetch: async () => new Response("<!doctype html><title>x</title>", { headers: { "Content-Type": "text/html" } }) }, PUBLIC_ORIGIN: O };
  const get = (p, ip) => worker.fetch(new Request(O + p, { headers: { "CF-Connecting-IP": ip, "User-Agent": "Mozilla/5.0" } }), env, ctx());
  let r = await get("/robots.txt", "203.0.113.30");
  assert.match(await r.text(), /Sitemap: https:\/\/mpm\.example\/sitemap\.xml/);
  r = await get("/sitemap.xml", "203.0.113.31");
  assert.equal(r.headers.get("Content-Type"), "application/xml; charset=utf-8");
  assert.match(await r.text(), /CVE-2026-21345/);
  r = await get("/api/epss-history/CVE-ABC", "203.0.113.32");
  assert.equal(r.status, 400);
  r = await get("/og/analysis/2026-Xyz.png", "203.0.113.33");
  assert.equal(r.status, 404);
  r = await get("/og/analysis/2026-Oct.png", "203.0.113.34");
  assert.equal(r.status, 302);
});
