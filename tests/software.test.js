import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const ctx = {};
vm.runInNewContext(readFileSync(new URL("../public/match.js", import.meta.url), "utf8"), ctx);
vm.runInNewContext(readFileSync(new URL("../public/software.js", import.meta.url), "utf8"), ctx);
const S = ctx.MPMSoftware;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("advisory ranges and versions", () => {
  assert.equal(S.inRange("1.9.9", "< 2.0.0"), true);
  assert.equal(S.inRange("2.0.0", "< 2.0.0"), false);
  assert.equal(S.inRange("1.2.0", ">= 1.0, < 1.2.3"), true);
  assert.equal(S.inRange("0.9", ">= 1.0, < 1.2.3"), false);
  assert.equal(S.inRange("4.1", "<= 4.1"), true);
  assert.equal(S.inRange("abc", "< 2.0"), null);
  assert.equal(S.inRange("1.0", "~1.0"), null);
});

test("package URLs", () => {
  assert.deepEqual(plain(S.purlInfo("pkg:npm/%40scope/lib@1.2.3")), { ecosystem: "npm", name: "@scope/lib", version: "1.2.3" });
  assert.deepEqual(plain(S.purlInfo("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")),
    { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", version: "2.14.1" });
  assert.equal(S.purlInfo("not a purl"), null);
});

test("reads CycloneDX, SPDX, winget, collector and CSV software lists", () => {
  const cdx = S.readSoftwareInput("bom.json", JSON.stringify({ bomFormat: "CycloneDX", components: [
    { name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      components: [{ name: "nested", version: "1.0.0", purl: "pkg:npm/nested@1.0.0" }] }] }));
  assert.equal(cdx.kind, "cyclonedx");
  assert.equal(cdx.components.length, 2);
  const spdx = S.readSoftwareInput("sbom.spdx.json", JSON.stringify({ spdxVersion: "SPDX-2.3", packages: [
    { name: "lodash", versionInfo: "4.17.20", externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/lodash@4.17.20" }] }] }));
  assert.equal(spdx.components[0].ecosystem, "npm");
  const winget = S.readSoftwareInput("w.json", JSON.stringify({ Sources: [{ Packages: [{ PackageIdentifier: "Mozilla.Firefox", Version: "115.0" }] }] }));
  assert.deepEqual(plain(winget.programs[0]), { name: "Firefox", version: "115.0", publisher: "Mozilla" });
  const csv = S.readSoftwareInput("apps.csv", "Application name,Application version,Application publisher\nPython 3.8.10 (64-bit),3.8.10,Python Software Foundation\n");
  assert.equal(csv.programs[0].publisher, "Python Software Foundation");
  assert.equal(S.readSoftwareInput("devices.csv", "Device name,OS version\nPC1,10.0.26100.1\n"), null, "device CSVs are not software lists");
  assert.equal(S.readSoftwareInput("x.json", "{bad json"), null);
});

test("matches end of life, exploited products and vulnerable components", () => {
  const eol = [{ product: "Python", cycle: "3.8", status: "ended", eol: "2024-10-07" }, { product: "Python", cycle: "3.12", status: "supported" },
    { product: "Java (Oracle)", cycle: "8", status: "supported" }];
  const kev = [{ cve: "CVE-2999-1", vendor: "Fortinet", product: "FortiClient EMS", microsoft: false },
    { cve: "CVE-2999-2", vendor: "Microsoft", product: "Edge", microsoft: true }];
  const oss = [{ cve: "CVE-2999-3", ecosystem: "Maven", package: "org.apache.logging.log4j:log4j-core", affected: ">= 2.0, < 2.15.0", fixed: "2.15.0", score: 95 }];
  const programs = S.mergePrograms([
    { device: "PC1", programs: [{ name: "Python 3.8.10 (64-bit)", version: "3.8.10", publisher: "Python Software Foundation" },
      { name: "FortiClient EMS", version: "7.0.1", publisher: "Fortinet Inc" }, { name: "Microsoft Edge", version: "120.0", publisher: "Microsoft" }] },
    { device: "PC2", programs: [{ name: "Python 3.8.10 (64-bit)", version: "3.8.10", publisher: "Python Software Foundation" }] },
  ]);
  const res = plain(S.analyzeSoftware(programs, [
    { name: "org.apache.logging.log4j:log4j-core", version: "2.14.1", ecosystem: "Maven" },
    { name: "org.apache.logging.log4j:log4j-core", version: "2.17.1", ecosystem: "Maven" },
  ], { eol, kev, oss }));
  const py = res.programs.find((p) => p.name.startsWith("Python"));
  assert.equal(py.status, "ended");
  assert.deepEqual(py.devices, ["PC1", "PC2"]);
  assert.equal(res.programs.find((p) => p.name === "FortiClient EMS").kev_count, 1);
  assert.equal(res.programs.find((p) => p.name === "Microsoft Edge").kev_count, 0, "Microsoft products are covered elsewhere");
  assert.equal(res.components.length, 1);
  assert.equal(res.components[0].findings[0].fixed, "2.15.0");
  assert.equal(res.summary.ended, 1);
});
