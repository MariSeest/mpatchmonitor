"use strict";

/* MPatchMonitor — "My software": third-party programs and SBOM components, checked in the
 * browser against end-of-life dates, known exploited vulnerabilities (CISA KEV) and exploited
 * open-source packages with their fixed versions. Nothing is uploaded. Also used by unit tests. */

(function (root) {
  const MAX_ITEMS = 20000;
  const clean = (s, n = 160) => String(s ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);
  const norm = (s) => clean(s).toLowerCase().replace(/[^a-z0-9.+#]+/g, " ").trim();

  /* ---------------------------------------------------------------- versions and ranges */
  function vparts(v) {
    const m = String(v || "").trim().replace(/^v/i, "").match(/^\d+(\.\d+)*/);
    return m ? m[0].split(".").map(Number) : null;
  }
  function vcmp(a, b) {
    const x = vparts(a), y = vparts(b);
    if (!x || !y) return null;
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d) return d < 0 ? -1 : 1;
    }
    return 0;
  }
  /** GitHub advisory ranges: "< 2.0.0", ">= 1.0, < 1.2.3", "<= 4.1", "= 1.2.3". Unknown = null. */
  function inRange(version, range) {
    const parts = String(range || "").split(",").map((p) => p.trim()).filter(Boolean);
    if (!parts.length || !vparts(version)) return null;
    for (const p of parts) {
      const m = p.match(/^(<=|>=|<|>|=)\s*v?([\d.]+)/);
      if (!m) return null;
      const c = vcmp(version, m[2]);
      if (c === null) return null;
      const ok = { "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c === 0 }[m[1]];
      if (!ok) return false;
    }
    return true;
  }

  /* ---------------------------------------------------------------- package URLs */
  const PURL_ECO = { npm: "npm", pypi: "PyPI", maven: "Maven", nuget: "NuGet", golang: "Go", gem: "RubyGems",
    composer: "Packagist", cargo: "crates.io", pub: "Pub", hex: "Hex", swift: "SwiftURL" };
  function purlInfo(purl) {
    const m = String(purl || "").match(/^pkg:([a-z]+)\/([^@?#]+)(?:@([^?#]+))?/i);
    if (!m) return null;
    const type = m[1].toLowerCase();
    const path = decodeURIComponent(m[2]);
    const name = type === "maven" ? path.replace("/", ":") : type === "npm" ? path : path.split("/").pop();
    return { ecosystem: PURL_ECO[type] || type, name: type === "golang" ? path : name, version: m[3] ? decodeURIComponent(m[3]) : "" };
  }
  const pkgKey = (eco, name) => `${String(eco).toLowerCase()}|${String(name).toLowerCase().replace(/[_.]/g, "-")}`;

  /* ---------------------------------------------------------------- inputs */
  function programsFromCollector(obj) {
    if (!obj || obj.schema !== "mpm-inventory/1" || !Array.isArray(obj.software)) return [];
    return obj.software.slice(0, 2000).map((p) => ({ name: clean(p.name), version: clean(p.version, 60), publisher: clean(p.publisher, 120) }))
      .filter((p) => p.name);
  }

  function components(list, out = []) {
    for (const c of list || []) {
      if (out.length >= MAX_ITEMS) break;
      if (!c || typeof c !== "object") continue;
      const p = purlInfo(c.purl);
      out.push({ name: clean(p?.name || c.name), version: clean(c.version || p?.version, 60), ecosystem: p?.ecosystem || "", purl: clean(c.purl, 300) });
      if (Array.isArray(c.components)) components(c.components, out);
    }
    return out;
  }

  /** Recognises CycloneDX, SPDX, winget export, collector files and CSV software lists. */
  function readSoftwareInput(fileName, text) {
    const s = String(text || "").replace(/^﻿/, "").trim();
    if (!s) return null;
    if (s.startsWith("{") || s.startsWith("[")) {
      let j;
      try { j = JSON.parse(s); } catch { return null; }
      if (j && j.bomFormat === "CycloneDX") return { kind: "cyclonedx", programs: [], components: components(j.components) };
      if (j && j.spdxVersion && Array.isArray(j.packages)) {
        return { kind: "spdx", programs: [], components: j.packages.slice(0, MAX_ITEMS).map((p) => {
          const ref = (p.externalRefs || []).find((r) => /purl/i.test(r.referenceType || ""));
          const info = purlInfo(ref?.referenceLocator);
          return { name: clean(info?.name || p.name), version: clean(p.versionInfo || info?.version, 60), ecosystem: info?.ecosystem || "", purl: clean(ref?.referenceLocator, 300) };
        }).filter((c) => c.name) };
      }
      if (j && Array.isArray(j.Sources)) {
        const programs = j.Sources.flatMap((src) => src.Packages || []).slice(0, 2000).map((p) => {
          const id = clean(p.PackageIdentifier);
          const [publisher, ...rest] = id.split(".");
          return { name: rest.join(" ") || id, version: clean(p.Version, 60), publisher };
        }).filter((p) => p.name);
        return { kind: "winget", programs, components: [] };
      }
      const list = Array.isArray(j) ? j : [j];
      const programs = list.flatMap(programsFromCollector);
      return programs.length ? { kind: "collector", programs, components: [] } : null;
    }
    const rows = root.MPMMatch?.parseCsv ? root.MPMMatch.parseCsv(s) : null;
    if (!rows || rows.length < 2) return null;
    const head = rows[0].map((h) => h.trim().toLowerCase().replace(/[^a-z]/g, ""));
    const col = (...n) => head.findIndex((h) => n.includes(h));
    const iName = col("applicationname", "displayname", "name", "software", "softwarename", "product", "app");
    const iVer = col("applicationversion", "displayversion", "version", "softwareversion");
    const iPub = col("applicationpublisher", "publisher", "vendor");
    if (iName < 0 || iVer < 0 || head.some((h) => ["osversion", "osbuild"].includes(h))) return null;
    const programs = rows.slice(1, 5001).map((r) => ({ name: clean(r[iName]), version: clean(r[iVer], 60), publisher: iPub >= 0 ? clean(r[iPub], 120) : "" }))
      .filter((p) => p.name);
    return programs.length ? { kind: "csv", programs, components: [] } : null;
  }

  /* ---------------------------------------------------------------- matching */
  // Installed program name -> product label used in the end-of-life dataset.
  const EOL_ALIASES = [
    [/^python \d/i, "Python"], [/^node\.?js/i, "Node.js"], [/^(java|jre|jdk)\b|java\(tm\)|java se/i, "Java (Oracle)"],
    [/^php\b/i, "PHP"], [/^postgresql/i, "PostgreSQL"], [/^mysql (server|community)/i, "MySQL"],
    [/^microsoft sql server \d{4}/i, "SQL Server"], [/^powershell \d/i, "PowerShell"],
    [/^microsoft \.net (runtime|sdk|desktop runtime)|^\.net (runtime|sdk)/i, ".NET"], [/^microsoft \.net framework/i, ".NET Framework"],
    [/^microsoft visual studio (community|professional|enterprise|\d{4})/i, "Visual Studio"],
    [/^microsoft (office|365)/i, "Microsoft Office"], [/^veeam backup/i, "Veeam Backup & Replication"],
    [/^vmware vcenter/i, "VMware vCenter"], [/^citrix virtual apps/i, "Citrix Virtual Apps and Desktops"],
    [/^mozilla firefox/i, "Mozilla Firefox"], [/^libreoffice/i, "LibreOffice"], [/^nginx/i, "nginx"],
    [/^apache http server|^apache httpd/i, "Apache HTTP Server"],
  ];

  function eolMatch(program, eolItems) {
    const alias = EOL_ALIASES.find(([re]) => re.test(program.name));
    if (!alias) return null;
    const cycles = eolItems.filter((e) => e.product === alias[1]);
    let best = null;
    for (const e of cycles) {
      const c = String(e.cycle);
      const v = program.version;
      const safe = c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const hit = v === c || v.startsWith(c + ".") || new RegExp(`(^|[^\\d.])${safe}([^\\d.]|$)`).test(program.name);
      if (hit && (!best || c.length > String(best.cycle).length)) best = e;
    }
    return best;
  }

  function kevMatch(program, kevRows) {
    const name = norm(program.name), pub = norm(program.publisher);
    const out = [];
    for (const k of kevRows) {
      if (k.microsoft) continue;   // Microsoft software is covered by the Microsoft data
      const vendor = norm(k.vendor), product = norm(k.product);
      if (!vendor || !product || product.length < 3) continue;
      const vendorHit = (pub && pub.includes(vendor.split(" ")[0])) || name.includes(vendor.split(" ")[0]);
      const productHit = product.split(" ").filter((w) => w.length > 2).every((w) => name.includes(w));
      if (vendorHit && productHit) out.push(k);
    }
    return out;
  }

  /**
   * programs: [{name, version, publisher, devices:[names]}]; components: [{name, version, ecosystem, purl}]
   * data: {eol: [...], kev: [...], oss: [...]} -> {programs: rows, components: rows, summary}
   */
  function analyzeSoftware(programs, comps, data) {
    const eol = data.eol || [], kev = data.kev || [], oss = data.oss || [];
    const progRows = programs.map((p) => {
      const e = eolMatch(p, eol);
      const k = kevMatch(p, kev);
      const status = e ? e.status : null;
      const rank = (status === "ended" ? 0 : status === "ending" ? 2 : 4) - (k.length ? 1 : 0);
      return { ...p, eol: e, kev: k.slice(0, 8), kev_count: k.length, status, rank };
    }).sort((a, b) => a.rank - b.rank || b.kev_count - a.kev_count || a.name.localeCompare(b.name));

    const byPkg = new Map();
    for (const o of oss) {
      const key = pkgKey(o.ecosystem, o.package);
      if (!byPkg.has(key)) byPkg.set(key, []);
      byPkg.get(key).push(o);
    }
    const compRows = [];
    for (const c of comps) {
      const hits = (byPkg.get(pkgKey(c.ecosystem, c.name)) || []).filter((o) => inRange(c.version, o.affected) !== false);
      if (hits.length) {
        compRows.push({ ...c, findings: hits.map((o) => ({ cve: o.cve, ghsa: o.ghsa, fixed: o.fixed, url: o.url, affected: o.affected,
          certain: inRange(c.version, o.affected) === true, ransomware: o.ransomware, score: o.score })) });
      }
    }
    compRows.sort((a, b) => Math.max(...b.findings.map((f) => f.score || 0)) - Math.max(...a.findings.map((f) => f.score || 0)));
    return {
      programs: progRows,
      components: compRows,
      summary: {
        programs: programs.length,
        ended: progRows.filter((r) => r.status === "ended").length,
        ending: progRows.filter((r) => r.status === "ending").length,
        with_kev: progRows.filter((r) => r.kev_count).length,
        components: comps.length,
        vulnerable_components: compRows.length,
      },
    };
  }

  /** Merges program lists from several devices: one row per name and version, with the devices. */
  function mergePrograms(entries) {
    const map = new Map();
    for (const { device, programs } of entries) {
      for (const p of programs) {
        const key = `${p.name.toLowerCase()}|${p.version}`;
        const e = map.get(key) || { ...p, devices: [] };
        if (device && !e.devices.includes(device)) e.devices.push(device);
        map.set(key, e);
      }
    }
    return [...map.values()];
  }

  root.MPMSoftware = { inRange, vcmp, purlInfo, readSoftwareInput, programsFromCollector, eolMatch, kevMatch, analyzeSoftware, mergePrograms };
})(typeof window !== "undefined" ? window : globalThis);
