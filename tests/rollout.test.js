import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ctx = {};
vm.runInNewContext(readFileSync(new URL("../public/rollout.js", import.meta.url), "utf8"), ctx);
const R = ctx.MPMRollout;
const plain = (x) => JSON.parse(JSON.stringify(x));
const dev = (name, server, prios, oldest) => ({ device: { name, server }, status: prios.length ? "missing" : "ok",
  missing: prios.map((p) => ({ priority: p })), counts: { P1: prios.filter((p) => p === "P1").length }, oldest,
  recommended: prios.length ? [{ product: server ? "Windows Server 2022" : "Windows 11", kb: server ? "KB2" : "KB1" }] : [] });

test("waves: pilot, workstations, servers, dates from the most urgent priority", () => {
  const results = [dev("A", false, ["P3"], "2026-11-12"), dev("B", false, ["P1", "P3"], "2026-10-20"), dev("C", false, ["P2"], "2026-10-27"),
    dev("SRV", true, ["P2"], "2026-10-27"), dev("OK", false, [], null)];
  const p = plain(R.plan(results, "2026-10-15"));
  assert.equal(p.urgency, "P1");
  assert.deepEqual(p.waves.map((w) => w.devices.map((d) => d.name)), [["A"], ["B", "C"], ["SRV"]]);
  assert.deepEqual(p.waves.map((w) => w.start), ["2026-10-15", "2026-10-17", "2026-10-20"]);
  assert.equal(p.waves[1].due, "2026-10-20");
  assert.equal(p.waves[2].updates[0].kb, "KB2");
  const moved = plain(R.plan(results, "2026-10-15", { B: 1, NOPE: 2, C: 9 }));
  assert.deepEqual(moved.waves[0].devices.map((d) => d.name).sort(), ["A", "B"]);
});

test("calendar export escapes text and skips empty waves", () => {
  const p = R.plan([dev("PC;1,x", false, ["P4"], "2027-01-13")], "2026-10-15");
  const out = R.ics(p, { 1: "Wave 1, pilot", 2: "Wave 2", 3: "Wave 3" }, "20261015T000000Z", "https://x");
  assert.match(out, /SUMMARY:MPatchMonitor: Wave 1\\, pilot \(1\)/);
  assert.ok(out.includes("PC" + "\\" + ";1" + "\\" + ",x"));
  assert.equal((out.match(/BEGIN:VEVENT/g) || []).length, 1);
});

test("remediation scripts: only safe names and KBs reach the script, as quoted literals", () => {
  const mk = (name, server, kb, fb, product = "Windows 11") => ({ device: { name, server }, status: "missing", missing: [{ priority: "P1" }], counts: { P1: 1 },
    oldest: "2026-10-20", recommended: [{ product, kb, fb }] });
  const results = [mk("PC-01", false, "KB5070999", "10.0.26100.6584"), mk("EVIL'; Remove-Item C:\\ -Recurse #", false, "KB1"),
    mk("PC-02", false, "KB$(calc)", ""), mk("PC-03", false, "", "142.0.3010.51", "Microsoft Edge (Chromium-based)")];
  const p = R.plan(results, "2026-10-15", { "PC-01": 1, "PC-02": 1, "PC-03": 1, "EVIL'; Remove-Item C:\\ -Recurse #": 1 });
  const ps = R.scripts.powershell(p, 1, "Wave 1, pilot", "2026-10-15");
  assert.match(ps, /'PC-01' = @\{ KB = @\('KB5070999'\); Build = @\{ 'KB5070999' = '10\.0\.26100\.6584' \}; Edge = \$false; Office = \$false \}/);
  assert.doesNotMatch(ps, /Remove-Item|calc|EVIL/);
  assert.match(ps, /1 device name\(s\) with unusual characters were left out/);
  assert.match(ps, /'PC-03' = @\{ KB = @\(\); Build = @\{  \}; Edge = \$true/);
  assert.match(ps, /param\(\[switch\]\$Install\)/);
  const intune = R.scripts.intune(p, 1, "Wave 1, pilot", "2026-10-15", "2026-10-13");
  assert.match(intune, /qualityUpdateRelease = '2026-10-13T00:00:00Z'; daysUntilForcedReboot = 0/);
  assert.match(intune, /displayName = 'MPatchMonitor - Wave 1, pilot - 2026-10-13'/);
  assert.doesNotMatch(R.scripts.intune(p, 1, "x", "s", "2026-10-13'; evil"), /evil'/);
  const ws = R.scripts.wsus(p, 1, "Wave 1, pilot", "2026-10-15");
  assert.match(ws, /\$kbs = @\('5070999'\)/);
  assert.match(ws, /\$devices = @\('PC-01', 'PC-02', 'PC-03'\)/);
  assert.match(R.scripts.wsus(p, 1, "it's", "s"), /'MPatchMonitor it''s'/);
});
