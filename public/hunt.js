"use strict";

/* MPatchMonitor — detection and hunting: KQL queries for Microsoft Defender XDR / Sentinel,
 * MITRE ATT&CK techniques, Sigma rules, EPSS history. Pure helpers are exported as MPMHunt
 * for the unit tests; the HTML helpers use esc()/te() from common.js. */

(function (root) {
  const CVE = /^CVE-\d{4}-\d{4,7}$/;
  const KB = /^KB\d{6,8}$/;
  const TECH = /^T\d{4}(\.\d{3})?$/;

  const ATTACK_NAMES = {
    T1068: "Exploitation for Privilege Escalation", T1190: "Exploit Public-Facing Application",
    T1203: "Exploitation for Client Execution", T1210: "Exploitation of Remote Services",
    T1211: "Exploitation for Defense Evasion", T1212: "Exploitation for Credential Access",
    "T1499.004": "Application or System Exploitation", T1187: "Forced Authentication",
  };

  const attackUrl = (id) => (TECH.test(id) ? `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` : "#");

  /** Techniques for a CVE: the CTID mapping when there is one, otherwise a suggestion from impact and CVSS. */
  function attackFor(c) {
    const mapped = (c.attack || []).filter((x) => x && TECH.test(x.id || x));
    if (mapped.length) return { source: "ctid", items: mapped.map((x) => (typeof x === "string" ? { id: x, name: ATTACK_NAMES[x] || "", type: "" } : x)) };
    const v = String(c.vector || ""), title = String(c.title || "");
    const network = /AV:N/.test(v), noUser = /UI:N/.test(v);
    const items = [];
    switch (c.impact) {
      case "Elevation of Privilege": items.push("T1068"); break;
      case "Remote Code Execution":
        items.push(network && noUser ? (/Server|SharePoint|Exchange|IIS|HTTP|SQL|RPC|LDAP|DNS|Routing/i.test(title) ? "T1190" : "T1210") : "T1203");
        break;
      case "Security Feature Bypass": items.push("T1211"); break;
      case "Denial of Service": items.push("T1499.004"); break;
      case "Spoofing": if (/NTLM|hash|credential/i.test(title)) items.push("T1187"); break;
      case "Information Disclosure": if (/NTLM|Kerberos|credential|password|hash/i.test(title)) items.push("T1212"); break;
      default: break;
    }
    return { source: "inferred", items: items.map((id) => ({ id, name: ATTACK_NAMES[id], type: "" })) };
  }

  /* ---------------------------------------------------------------- KQL (Defender XDR advanced hunting, Sentinel) */
  const q = (s) => `"${String(s).replace(/[^A-Za-z0-9-]/g, "")}"`;

  function kqlForCve(cve, exploited) {
    if (!CVE.test(cve)) return [];
    const out = [
      { id: "exposure", title: "Devices exposed to this CVE",
        desc: "Defender Vulnerability Management: devices where the vulnerable software is still installed.",
        query: `DeviceTvmSoftwareVulnerabilities\n| where CveId == ${q(cve)}\n| summarize Devices = dcount(DeviceId), DeviceNames = make_set(DeviceName, 100)\n    by SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate\n| order by Devices desc` },
      { id: "context", title: "Exposed devices with their context",
        desc: "Adds operating system, build, exposure level and device group from DeviceInfo.",
        query: `DeviceTvmSoftwareVulnerabilities\n| where CveId == ${q(cve)}\n| join kind=leftouter (\n    DeviceInfo\n    | summarize arg_max(Timestamp, OSPlatform, OSBuild, ExposureLevel, MachineGroup, IsInternetFacing) by DeviceId\n  ) on DeviceId\n| project DeviceName, OSPlatform, OSBuild, ExposureLevel, IsInternetFacing, MachineGroup,\n    SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate\n| order by IsInternetFacing desc, ExposureLevel desc` },
      { id: "kb", title: "What Defender knows about it",
        desc: "CVSS, whether Defender sees a public exploit, and the affected software.",
        query: `DeviceTvmSoftwareVulnerabilitiesKB\n| where CveId == ${q(cve)}\n| project CveId, CvssScore, IsExploitAvailable, VulnerabilitySeverityLevel, PublishedDate, LastModifiedTime, AffectedSoftware` },
    ];
    if (exploited) {
      out.push({ id: "alerts", title: "Alerts that mention the CVE (last 30 days)",
        desc: "Defender XDR alerts and evidence that reference this CVE, a starting point for a hunt.",
        query: `AlertInfo\n| where Timestamp > ago(30d)\n| join kind=inner (AlertEvidence | where Timestamp > ago(30d)) on AlertId\n| where Title has ${q(cve)} or AdditionalFields has ${q(cve)}\n| summarize Devices = make_set(DeviceName, 50), Evidence = count() by AlertId, Title, Severity, ServiceSource\n| order by Evidence desc` });
    }
    return out;
  }

  function kqlForKb(kb) {
    if (!KB.test(kb)) return [];
    const num = kb.slice(2);
    return [
      { id: "missing", title: "Devices that still need this update",
        desc: "Defender Vulnerability Management recommends this update for these devices.",
        query: `DeviceTvmSoftwareVulnerabilities\n| where RecommendedSecurityUpdateId == ${q(num)} or RecommendedSecurityUpdate has ${q(kb)}\n| summarize CVEs = make_set(CveId, 200), Software = make_set(SoftwareName, 10) by DeviceId, DeviceName\n| extend MissingCVEs = array_length(CVEs)\n| order by MissingCVEs desc` },
      { id: "count", title: "How many devices, by operating system",
        desc: "A quick figure for a status report.",
        query: `DeviceTvmSoftwareVulnerabilities\n| where RecommendedSecurityUpdateId == ${q(num)} or RecommendedSecurityUpdate has ${q(kb)}\n| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, OSVersion) by DeviceId) on DeviceId\n| summarize Devices = dcount(DeviceId) by OSPlatform, OSVersion\n| order by Devices desc` },
    ];
  }

  function kqlForList(cves) {
    const ids = [...new Set((cves || []).filter((c) => CVE.test(c)))].slice(0, 500);
    if (!ids.length) return "";
    const lines = [];
    for (let i = 0; i < ids.length; i += 6) lines.push("    " + ids.slice(i, i + 6).map(q).join(", "));
    return `let cves = dynamic([\n${lines.join(",\n")}\n]);\nDeviceTvmSoftwareVulnerabilities\n| where CveId in (cves)\n| summarize Devices = dcount(DeviceId), DeviceNames = make_set(DeviceName, 50) by CveId, SoftwareVendor, SoftwareName\n| order by Devices desc`;
  }

  /* ---------------------------------------------------------------- EPSS sparkline (one series, no legend) */
  function sparkline(series, opts = {}) {
    const pts = (series || []).filter((p) => Number.isFinite(p.epss) && /^\d{4}-\d{2}-\d{2}$/.test(p.date));
    if (pts.length < 2) return null;
    const W = opts.width || 320, H = 96, L = 6, R = 52, T = 10, B = 22;
    const max = Math.max(...pts.map((p) => p.epss), 0.01) * 1.1;
    const x = (i) => L + (i / (pts.length - 1)) * (W - L - R);
    const y = (v) => T + (1 - v / max) * (H - T - B);
    const d = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.epss).toFixed(1)}`).join("");
    const last = pts[pts.length - 1], first = pts[0];
    const pct = (v) => `${(v * 100).toFixed(v < 0.01 ? 2 : 1)}%`;
    return { W, H, path: d, base: H - B, first, last, pct,
      lastX: x(pts.length - 1), lastY: y(last.epss),
      points: pts.map((p, i) => ({ x: x(i), y: y(p.epss), date: p.date, value: pct(p.epss) })),
      step: (W - L - R) / Math.max(1, pts.length - 1) };
  }

  root.MPMHunt = { attackFor, attackUrl, kqlForCve, kqlForKb, kqlForList, sparkline, ATTACK_NAMES };
})(typeof window !== "undefined" ? window : globalThis);

/* ------------------------------------------------------------------ HTML (browser only) */
if (typeof document !== "undefined") {
  // Visible texts of the KQL blocks, listed here so tools/i18n.py can find them.
  void [t("Devices exposed to this CVE"), t("Defender Vulnerability Management: devices where the vulnerable software is still installed."),
    t("Exposed devices with their context"), t("Adds operating system, build, exposure level and device group from DeviceInfo."),
    t("What Defender knows about it"), t("CVSS, whether Defender sees a public exploit, and the affected software."),
    t("Alerts that mention the CVE (last 30 days)"), t("Defender XDR alerts and evidence that reference this CVE, a starting point for a hunt."),
    t("Devices that still need this update"), t("Defender Vulnerability Management recommends this update for these devices."),
    t("How many devices, by operating system"), t("A quick figure for a status report.")];
  const ATTACK_TYPE = { exploitation: t("attack|exploitation"), primary: t("attack|primary impact"), secondary: t("attack|secondary impact") };

  /** A titled KQL block with a copy button. Titles and descriptions are translated. */
  window.kqlBlock = (k) => `<div class="kql"><div class="kql-head"><div><h3>${te(k.title)}</h3><p class="hint">${te(k.desc)}</p></div>
    <button type="button" class="btn ghost" data-copy-code>${te("Copy query")}</button></div><pre><code>${esc(k.query)}</code></pre></div>`;

  window.attackList = (c) => {
    const a = MPMHunt.attackFor(c);
    if (!a.items.length) return "";
    return `<ul class="attack">${a.items.map((x) => `<li><a href="${esc(MPMHunt.attackUrl(x.id))}" rel="noopener noreferrer" target="_blank"><b>${esc(x.id)}</b> ${esc(x.name || "")}</a>${ATTACK_TYPE[x.type] ? `<span class="hint"> ${esc(ATTACK_TYPE[x.type])}</span>` : ""}</li>`).join("")}</ul>
      <p class="hint">${a.source === "ctid" ? te("Mapped by the MITRE Center for Threat-Informed Defense (KEV mappings).") : te("Suggested from Microsoft's impact and the CVSS vector: a starting point, not an official mapping.")}</p>`;
  };

  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy-code]");
    if (!b) return;
    const code = b.closest(".kql, .code-copy")?.querySelector("pre code, code");
    if (code) copyText(code.textContent, b);
  });

  /** Fetches the EPSS history of a CVE and draws it into el. */
  window.renderEpssHistory = async (el, cve) => {
    let d;
    try { d = await fetchJson(`/api/epss-history/${encodeURIComponent(cve)}`); } catch { el.remove(); return; }
    const s = MPMHunt.sparkline(d.series, { width: Math.max(260, Math.min(520, el.clientWidth || 320)) });
    if (!s) { el.remove(); return; }
    const change = s.last.epss - s.first.epss;
    const vars = { a: s.pct(s.first.epss), b: s.pct(s.last.epss), date: fmtDate(s.first.date) };
    const summary = change > 0.005 ? t("EPSS rose from {a} to {b} since {date}.", vars)
      : change < -0.005 ? t("EPSS fell from {a} to {b} since {date}.", vars) : t("EPSS stayed around {b} since {date}.", vars);
    setHTML(el, `<h3>${te("EPSS over time")}</h3>
      <svg class="chart spark" viewBox="0 0 ${s.W} ${s.H}" role="img" aria-label="${esc(summary)}">
        <line class="grid base" x1="6" x2="${s.W - 52}" y1="${s.base}" y2="${s.base}"/>
        <path class="spark-line" d="${s.path}"/>
        <circle class="spark-dot" cx="${s.lastX.toFixed(1)}" cy="${s.lastY.toFixed(1)}" r="4"/>
        <text class="val strong" x="${(s.lastX + 8).toFixed(1)}" y="${(s.lastY + 4).toFixed(1)}">${esc(s.pct(s.last.epss))}</text>
        <text class="tick" x="6" y="${s.H - 6}">${esc(fmtDate(s.first.date))}</text>
        <text class="tick" x="${s.W - 52}" y="${s.H - 6}" text-anchor="end">${esc(fmtDate(s.last.date))}</text>
        ${s.points.map((p) => `<rect class="hit" x="${(p.x - s.step / 2).toFixed(1)}" y="0" width="${Math.max(4, s.step).toFixed(1)}" height="${s.base}" data-tip="${esc(`${fmtDate(p.date)}\nEPSS ${p.value}`)}"/>`).join("")}
      </svg><p class="hint">${esc(summary)} ${te("Source: FIRST EPSS, daily.")}</p>`);
    initTips(el);
  };
}
