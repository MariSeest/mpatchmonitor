import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ctx = {};
vm.runInNewContext(readFileSync(new URL("../public/hunt.js", import.meta.url), "utf8"), ctx);
const H = ctx.MPMHunt;

test("KQL: only valid identifiers reach a query, quoted", () => {
  const q = H.kqlForCve("CVE-2026-21345", true);
  assert.equal(q.length, 4);
  assert.match(q[0].query, /where CveId == "CVE-2026-21345"/);
  assert.equal(H.kqlForCve('CVE-2026-1" or 1==1 //', true).length, 0);
  assert.equal(H.kqlForCve("CVE-2026-21345", false).length, 3);
  const kb = H.kqlForKb("KB5070112");
  assert.match(kb[0].query, /RecommendedSecurityUpdateId == "5070112" or RecommendedSecurityUpdate has "KB5070112"/);
  assert.equal(H.kqlForKb("KB1; drop").length, 0);
  const list = H.kqlForList(["CVE-2026-1111", "x\" | evil", "CVE-2026-1111", "CVE-2025-2222"]);
  assert.match(list, /dynamic\(\[\n    "CVE-2026-1111", "CVE-2025-2222"\n\]\)/);
  assert.doesNotMatch(list, /evil/);
  assert.equal(H.kqlForList([]), "");
});

test("ATT&CK: CTID mapping wins, otherwise a labelled suggestion from impact and CVSS", () => {
  const mapped = H.attackFor({ attack: [{ id: "T1190", name: "Exploit Public-Facing Application", type: "exploitation" }, { id: "javascript:x" }] });
  assert.equal(mapped.source, "ctid");
  assert.equal(mapped.items.length, 1);
  assert.equal(H.attackFor({ impact: "Elevation of Privilege" }).items[0].id, "T1068");
  assert.equal(H.attackFor({ impact: "Remote Code Execution", vector: "CVSS:3.1/AV:N/UI:N", title: "Windows SMB Client RCE" }).items[0].id, "T1210");
  assert.equal(H.attackFor({ impact: "Remote Code Execution", vector: "CVSS:3.1/AV:N/UI:N", title: "Microsoft SharePoint Server RCE" }).items[0].id, "T1190");
  assert.equal(H.attackFor({ impact: "Remote Code Execution", vector: "CVSS:3.1/AV:L/UI:R", title: "Microsoft Excel RCE" }).items[0].id, "T1203");
  assert.equal(H.attackFor({ impact: "Tampering" }).items.length, 0);
  assert.equal(H.attackUrl("T1204.002"), "https://attack.mitre.org/techniques/T1204/002/");
  assert.equal(H.attackUrl("javascript:alert(1)"), "#");
});

test("EPSS sparkline geometry", () => {
  assert.equal(H.sparkline([{ date: "2026-10-01", epss: 0.1 }]), null);
  const s = H.sparkline([{ date: "2026-10-01", epss: 0.1 }, { date: "2026-10-02", epss: 0.2 }, { date: "bad", epss: 0.9 }]);
  assert.equal(s.points.length, 2);
  assert.ok(s.points[1].y < s.points[0].y);
  assert.equal(s.pct(s.last.epss), "20.0%");
});
