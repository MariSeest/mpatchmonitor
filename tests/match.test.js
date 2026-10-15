import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ctx = {};
vm.runInNewContext(readFileSync(new URL("../public/match.js", import.meta.url), "utf8"), ctx);
const M = ctx.MPMMatch;
const plain = (x) => JSON.parse(JSON.stringify(x));   // values from the vm realm

const W24 = "Windows 11 Version 24H2 for x64-based Systems";
const S22C = "Windows Server 2022 (Server Core installation)";
const EDGE = "Microsoft Edge (Chromium-based)";
const fixIndex = {
  cves: ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
  products: [W24, S22C, EDGE],
  fixes: {
    0: [[0, "10.0.26100.2000", "KB1"], [1, "10.0.26100.2500", "KB2"]],
    1: [[2, "10.0.20348.3000", "KB3"]],
    2: [[3, "130.0.2849.46", ""]],
  },
};
const data = { cves: [
  { cve: "CVE-1", title: "A", priority: "P3", severity: "Important", due: "2026-09-01" },
  { cve: "CVE-2", title: "B", priority: "P1", severity: "Critical", exploited: true, due: "2026-10-20" },
  { cve: "CVE-3", title: "C", priority: "P2", severity: "Critical", due: "2026-08-01" },
  { cve: "CVE-4", title: "D", priority: "P2", severity: "Critical", due: "2026-10-27" },
] };
const collector = (o) => JSON.stringify({ schema: "mpm-inventory/1", device: "PC1", os: { caption: "Microsoft Windows 11 Pro", build: "26100", ubr: 2100, installation_type: "Client", arch: "AMD64" }, ...o });

test("version comparison", () => {
  assert.equal(M.cmpVersion("10.0.26100.2033", "10.0.26100.2100"), -1);
  assert.equal(M.cmpVersion("130.0.2849.46", "130.0.2849.46"), 0);
  assert.equal(M.cmpVersion("10.0.26100.10", "10.0.26100.9"), 1);
  assert.equal(M.cmpVersion("x", "1.0"), null);
});

test("collector JSON becomes a device with an exact build", () => {
  const [d] = M.readInput("a.json", "﻿" + collector({ edge: { version: "130.0.2849.10" } }));
  assert.equal(d.build, "10.0.26100.2100");
  assert.equal(d.edge, "130.0.2849.10");
  assert.deepEqual(plain(M.windowsCandidates(d)), [W24]);
});

test("Intune and Defender style CSV exports are understood", () => {
  const intune = 'Device name,OS,OS version,Ownership\n"FIN-01",Windows,10.0.26100.2100,Corporate\nPHONE,iOS,17.5,Personal\n';
  const devs = M.readInput("x.csv", intune);
  assert.equal(devs.length, 1);
  assert.equal(devs[0].name, "FIN-01");
  assert.equal(devs[0].build, "10.0.26100.2100");
  const defender = "Device Name;OS Platform;OS Version\nSRV1;WindowsServer2022;10.0.20348.2900\n";
  const [s] = M.readInput("d.csv", defender);
  assert.ok(s.server);
  assert.deepEqual(plain(M.windowsCandidates(s)), ["Windows Server 2022"]);
});

test("missing fixes are found by build, with the update to install", () => {
  const [d] = M.readInput("a.json", collector({ edge: { version: "130.0.2849.10" } }));
  const a = M.analyze([d], fixIndex, data, "2026-10-14");
  const r = a.results[0];
  assert.deepEqual(plain(r.missing.map((m) => m.cve)), ["CVE-2", "CVE-4"]);   // CVE-1 already fixed by build 2100
  assert.equal(r.counts.P1, 1);
  assert.equal(r.exploited, 1);
  assert.deepEqual(plain(r.recommended.map((x) => x.kb || x.fb).sort()), ["130.0.2849.46", "KB2"]);
  assert.equal(a.summary.with_p1, 1);
});

test("server core maps to its own product and overdue fixes are counted", () => {
  const dev = { name: "DC", source: "csv", caption: "Windows Server", server: true, core: true, arch: "AMD64", build: "10.0.20348.2900", edge: "", office: null, hotfixes: null };
  const r = M.analyze([dev], fixIndex, data, "2026-10-14").results[0];
  assert.equal(r.products[0].name, S22C);
  assert.equal(r.overdue, 1);
});

test("up-to-date, unsupported and hostile inputs", () => {
  const ok = { name: "OK", source: "csv", caption: "Windows", server: false, core: false, arch: "AMD64", build: "10.0.26100.9999", edge: "", office: null, hotfixes: null };
  const old = { ...ok, name: "XP", build: "5.1.2600" };
  const a = M.analyze([ok, old], fixIndex, data, "2026-10-14");
  assert.equal(a.results[0].status, "ok");
  assert.equal(a.results[1].status, "unsupported");
  assert.deepEqual(plain(M.readInput("bad.json", "{not json")), []);
  assert.deepEqual(plain(M.readInput("bad.json", JSON.stringify({ schema: "other" }))), []);
  const [x] = M.readInput("x.json", collector({ device: "<img src=x onerror=alert(1)>\u0007", hotfixes: ["KB1", "<script>"] }));
  assert.ok(!/\u0007/.test(x.name));
  assert.deepEqual(plain(x.hotfixes), ["KB1"]);
});

test("sample fleet is built from the live builds", () => {
  const devs = M.demoDevices(fixIndex);
  assert.ok(devs.length >= 1 && devs.every((d) => d.source === "sample"));
});
