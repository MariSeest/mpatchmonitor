"use strict";

/* MPatchMonitor — device matching (runs only in the browser; also loaded by the unit tests).
 * Turns collector JSON or an Intune / Defender CSV into devices, maps each device to the
 * product names Microsoft uses in its bulletins, and compares the installed build with the
 * build that contains each fix. */

(function (root) {
  const CLIENT = {
    26200: "Windows 11 Version 25H2", 26100: "Windows 11 Version 24H2", 22631: "Windows 11 Version 23H2",
    22621: "Windows 11 Version 22H2", 22000: "Windows 11 Version 21H2", 19045: "Windows 10 Version 22H2",
    19044: "Windows 10 Version 21H2", 17763: "Windows 10 Version 1809", 14393: "Windows 10 Version 1607",
  };
  const SERVER = {
    26100: "Windows Server 2025", 25398: "Windows Server, version 23H2", 20348: "Windows Server 2022",
    17763: "Windows Server 2019", 14393: "Windows Server 2016",
  };
  const ARCH = { AMD64: "x64-based Systems", X64: "x64-based Systems", ARM64: "ARM64-based Systems", X86: "32-bit Systems" };
  const MAX_DEVICES = 5000;

  /* ---------------------------------------------------------------- versions */
  function parseVersion(v) {
    const m = String(v || "").trim().match(/^\d+(\.\d+){1,4}$/);
    return m ? m[0].split(".").map(Number) : null;
  }
  function cmpVersion(a, b) {
    const x = parseVersion(a), y = parseVersion(b);
    if (!x || !y) return null;
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const d = (x[i] || 0) - (y[i] || 0);
      if (d) return d < 0 ? -1 : 1;
    }
    return 0;
  }

  /* ---------------------------------------------------------------- inputs */
  const clean = (s, n = 120) => String(s ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);

  function fromCollector(obj) {
    if (!obj || obj.schema !== "mpm-inventory/1" || !obj.os) return null;
    const os = obj.os;
    const build = String(os.build || "").replace(/\D/g, "");
    const ubr = String(os.ubr ?? "").replace(/\D/g, "");
    return {
      name: clean(obj.device) || (typeof t === "function" ? t("Unnamed device") : "Unnamed device"),
      source: "collector",
      collected_at: clean(obj.collected_at, 30),
      caption: clean(os.caption),
      server: /server/i.test(os.caption || "") || /server/i.test(os.installation_type || ""),
      core: /core/i.test(os.installation_type || ""),
      arch: clean(os.arch, 10).toUpperCase(),
      build: build && ubr ? `10.0.${build}.${ubr}` : build ? `10.0.${build}` : "",
      edge: parseVersion(obj.edge?.version) ? clean(obj.edge.version, 30) : "",
      office: obj.office && parseVersion(obj.office.version)
        ? { version: clean(obj.office.version, 30), platform: clean(obj.office.platform, 10).toLowerCase() } : null,
      hotfixes: Array.isArray(obj.hotfixes) ? obj.hotfixes.map((h) => clean(h, 12).toUpperCase()).filter((h) => /^KB\d+$/.test(h)) : null,
      software: Array.isArray(obj.software)
        ? obj.software.slice(0, 2000).map((p) => ({ name: clean(p?.name), version: clean(p?.version, 60), publisher: clean(p?.publisher) })).filter((p) => p.name)
        : null,
    };
  }

  function parseCsv(text) {
    const rows = [];
    let row = [], cell = "", q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) {
        if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
        else if (ch === '"') q = false;
        else cell += ch;
      } else if (ch === '"') q = true;
      else if (ch === "," || ch === ";" || ch === "\t") { row.push(cell); cell = ""; }
      else if (ch === "\n" || ch === "\r") {
        if (ch === "\r" && text[i + 1] === "\n") i++;
        row.push(cell); rows.push(row); row = []; cell = "";
        if (rows.length > MAX_DEVICES + 1) break;
      } else cell += ch;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows.filter((r) => r.some((c) => c.trim()));
  }

  /** Intune, Defender for Endpoint or any CSV with a device name and a 10.0.x.y version. */
  function fromCsv(text) {
    const rows = parseCsv(text);
    if (rows.length < 2) return [];
    const head = rows[0].map((h) => h.trim().toLowerCase().replace(/[^a-z]/g, ""));
    const col = (...names) => head.findIndex((h) => names.includes(h));
    const iName = col("devicename", "computername", "computerdnsname", "name", "hostname");
    const iVer = col("osversion", "osbuild", "version", "operatingsystemversion");
    const iOs = col("os", "osplatform", "operatingsystem", "platform");
    const iArch = col("osarchitecture", "architecture", "processorarchitecture");
    if (iVer < 0) return [];
    return rows.slice(1, MAX_DEVICES + 1).map((r) => {
      const ver = String(r[iVer] || "").trim();
      const os = iOs >= 0 ? r[iOs] : "";
      if (os && !/windows/i.test(os)) return null;
      const m = ver.match(/^10\.0\.(\d{5})(?:\.(\d+))?/) || ver.match(/^(\d{5})(?:\.(\d+))?$/);
      if (!m) return null;
      const arch = iArch >= 0 ? String(r[iArch]).toUpperCase().replace(/[^A-Z0-9]/g, "") : "";
      return {
        name: clean(iName >= 0 ? r[iName] : "") || (typeof t === "function" ? t("Unnamed device") : "Unnamed device"),
        source: "csv",
        caption: clean(os) || "Windows",
        server: /server/i.test(os),
        core: false,
        arch: /ARM/.test(arch) ? "ARM64" : /86|32/.test(arch) ? "X86" : "AMD64",
        build: m[2] ? `10.0.${m[1]}.${m[2]}` : `10.0.${m[1]}`,
        edge: "", office: null, hotfixes: null,
      };
    }).filter(Boolean);
  }

  function readInput(fileName, text) {
    const t = String(text || "").replace(/^﻿/, "").trim();
    if (!t) return [];
    if (t.startsWith("{") || t.startsWith("[")) {
      let j;
      try { j = JSON.parse(t); } catch { return []; }
      const list = Array.isArray(j) ? j : [j];
      return list.slice(0, MAX_DEVICES).map(fromCollector).filter(Boolean);
    }
    return fromCsv(t);
  }

  /* ---------------------------------------------------------------- products */
  function windowsCandidates(d) {
    const num = Number((d.build.match(/^10\.0\.(\d+)/) || [])[1]);
    if (!num) return [];
    if (d.server) {
      const base = SERVER[num];
      if (!base) return [];
      return d.core ? [`${base} (Server Core installation)`, base] : [base];
    }
    const base = CLIENT[num];
    if (!base) return [];
    return [`${base} for ${ARCH[d.arch] || ARCH.AMD64}`];
  }

  function findProducts(products, candidates) {
    for (const c of candidates) {
      const exact = products.indexOf(c);
      if (exact >= 0) return [exact];
    }
    for (const c of candidates) {
      const i = products.findIndex((p) => p.startsWith(c));
      if (i >= 0) return [i];
    }
    return [];
  }

  /* ---------------------------------------------------------------- analysis */
  function check(fixes, version, hotfixes) {
    const missing = new Map();   // cveIndex -> { fb, kb }
    let unknown = 0;
    for (const [ci, fb, kb] of fixes) {
      let miss = null;
      if (fb && version) miss = cmpVersion(version, fb) === -1;
      else if (kb && hotfixes) miss = !hotfixes.includes(kb);
      if (miss === null) { unknown++; continue; }
      if (miss) {
        const prev = missing.get(ci);
        if (!prev || (fb && cmpVersion(fb, prev.fb) === 1)) missing.set(ci, { fb, kb });
      }
    }
    return { missing, unknown };
  }

  function analyze(devices, fixIndex, data, today = new Date().toISOString().slice(0, 10)) {
    const byCve = new Map(data.cves.map((c) => [c.cve, c]));
    const products = fixIndex.products;
    const edgeIdx = products.findIndex((p) => /^Microsoft Edge \(Chromium-based\)$/.test(p));
    const prio = { P1: 1, P2: 2, P3: 3, P4: 4 };

    const results = devices.map((d) => {
      const r = { device: d, products: [], missing: [], unknown: 0, recommended: [], status: "ok" };
      const groups = [];
      const win = findProducts(products, windowsCandidates(d));
      if (win.length) groups.push({ label: products[win[0]], idx: win[0], version: d.build });
      if (d.edge && edgeIdx >= 0) groups.push({ label: products[edgeIdx], idx: edgeIdx, version: d.edge });
      if (d.office) {
        const bits = /x86|32/.test(d.office.platform) ? "32-bit" : "64-bit";
        const oi = products.findIndex((p) => p === `Microsoft 365 Apps for Enterprise for ${bits} Systems`);
        if (oi >= 0) groups.push({ label: products[oi], idx: oi, version: d.office.version });
      }
      if (!groups.length) { r.status = "unsupported"; return r; }
      if (!/^10\.0\.\d+\.\d+$/.test(d.build)) r.partial = true;

      const seen = new Set();
      for (const g of groups) {
        const fixes = fixIndex.fixes[String(g.idx)] || [];
        const { missing, unknown } = check(fixes, g.version, d.hotfixes);
        r.unknown += unknown;
        let best = null;
        for (const [ci, fx] of missing) {
          const id = fixIndex.cves[ci];
          const c = byCve.get(id);
          if (!c || seen.has(id)) continue;
          seen.add(id);
          r.missing.push({ cve: id, title: c.title, priority: c.priority, severity: c.severity, exploited: c.exploited,
            kev: Boolean(c.kev), epss: c.epss, release: c.release, due: c.due, product: g.label, kb: fx.kb, fixed_build: fx.fb,
            public_exploit: Boolean(c.exploit), mitigations: (c.mitigations || []).length });
          if (fx.fb && (!best || cmpVersion(fx.fb, best.fb) === 1)) best = { ...fx, product: g.label };
          else if (!best && fx.kb) best = { ...fx, product: g.label };
        }
        r.products.push({ name: g.label, version: g.version });
        if (best) r.recommended.push(best);
      }
      r.missing.sort((a, b) => prio[a.priority] - prio[b.priority] || (b.epss || 0) - (a.epss || 0));
      r.counts = { P1: 0, P2: 0, P3: 0, P4: 0 };
      r.missing.forEach((m) => r.counts[m.priority]++);
      r.exploited = r.missing.filter((m) => m.exploited || m.kev).length;
      r.overdue = r.missing.filter((m) => m.due && m.due < today).length;
      r.oldest = r.missing.reduce((o, m) => (!o || (m.due && m.due < o) ? m.due : o), null);
      r.status = r.missing.length ? "missing" : r.partial ? "partial" : "ok";
      return r;
    });

    const exposure = new Map();
    for (const r of results) for (const m of r.missing) {
      const e = exposure.get(m.cve) || { ...m, devices: 0 };
      e.devices++;
      exposure.set(m.cve, e);
    }
    const top = [...exposure.values()].sort((a, b) =>
      prio[a.priority] - prio[b.priority] || b.devices - a.devices || (b.epss || 0) - (a.epss || 0));

    return {
      results,
      top,
      summary: {
        devices: results.length,
        recognised: results.filter((r) => r.status !== "unsupported").length,
        up_to_date: results.filter((r) => r.status === "ok").length,
        missing: results.filter((r) => r.status === "missing").length,
        with_p1: results.filter((r) => r.counts?.P1).length,
        exploited_devices: results.filter((r) => r.exploited).length,
        overdue_devices: results.filter((r) => r.overdue).length,
        unique_cves: exposure.size,
      },
    };
  }

  /** Sample fleet built from the live data, so the demo always matches current builds. */
  function demoDevices(fixIndex) {
    const builds = (name) => {
      const i = fixIndex.products.indexOf(name);
      if (i < 0) return [];
      return [...new Set((fixIndex.fixes[String(i)] || []).map((f) => f[1]).filter(Boolean))]
        .sort((a, b) => cmpVersion(b, a));
    };
    const pick = (name, behind) => builds(name)[behind] || null;
    const edgeBuilds = builds("Microsoft Edge (Chromium-based)");
    const plan = [
      ["FIN-LT-014", "Windows 11 Pro", false, false, "Windows 11 Version 24H2 for x64-based Systems", 0, 0],
      ["HR-PC-007", "Windows 11 Enterprise", false, false, "Windows 11 Version 24H2 for x64-based Systems", 1, 2],
      ["OPS-LT-022", "Windows 11 Pro", false, false, "Windows 11 Version 23H2 for x64-based Systems", 4, 6],
      ["RECEPTION-PC", "Windows 10 Pro", false, false, "Windows 10 Version 22H2 for x64-based Systems", 2, 1],
      ["SRV-DC-01", "Windows Server 2022 Datacenter", true, true, "Windows Server 2022 (Server Core installation)", 3, null],
      ["SRV-FILE-02", "Windows Server 2025 Standard", true, false, "Windows Server 2025", 0, null],
    ];
    return plan.map(([name, caption, server, core, product, behind, edgeBehind]) => {
      const b = pick(product, behind);
      if (!b) return null;
      return {
        name, source: "sample", caption, server, core, arch: "AMD64", build: b,
        edge: edgeBehind === null ? "" : edgeBuilds[edgeBehind] || "", office: null, hotfixes: null,
      };
    }).filter(Boolean);
  }

  root.MPMMatch = { cmpVersion, parseVersion, fromCollector, fromCsv, readInput, parseCsv, windowsCandidates, findProducts, analyze, demoDevices };
})(typeof window !== "undefined" ? window : globalThis);
