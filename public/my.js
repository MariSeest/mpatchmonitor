"use strict";

/* MPatchMonitor — "My devices": everything happens in this browser. */

const M = window.MPMMatch;
const S = window.MPMSoftware;
const RO = window.MPMRollout;
const my = { data: null, fixes: null, devices: [], analysis: null, extraPrograms: [], components: [], software: null, swData: null,
  overrides: {}, plan: null };
const WAVE_LABEL = () => ({ 1: t("Wave 1, pilot"), 2: t("Wave 2, workstations"), 3: t("Wave 3, servers") });

/* Sample programs for the sample devices: some out of support, one with exploited vulnerabilities. */
const DEMO_SOFTWARE = [
  [{ name: "Python 3.8.10 (64-bit)", version: "3.8.10", publisher: "Python Software Foundation" },
    { name: "Node.js", version: "20.11.1", publisher: "Node.js Foundation" }, { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" }],
  [{ name: "Java 8 Update 401 (64-bit)", version: "8.0.4010.10", publisher: "Oracle Corporation" }, { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" }],
  [{ name: "Python 3.12.4 (64-bit)", version: "3.12.4", publisher: "Python Software Foundation" }, { name: "Node.js", version: "16.20.2", publisher: "Node.js Foundation" }],
  [{ name: "Python 3.8.10 (64-bit)", version: "3.8.10", publisher: "Python Software Foundation" }],
  [{ name: "MOVEit Transfer", version: "2023.0.1", publisher: "Progress Software Corporation" }, { name: "PostgreSQL 12", version: "12.18", publisher: "PostgreSQL Global Development Group" }],
  [{ name: "Veeam Backup & Replication", version: "12.1.2.172", publisher: "Veeam Software Group GmbH" }],
];

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  try {
    const [data, fixes] = await Promise.all([fetchData(), fetchFixes()]);
    my.data = data; my.fixes = fixes;
  } catch (err) {
    showFatal($("#main"), err);
    return;
  }
  bindMy();
  const saved = store.get("mpm-devices");
  if (saved) {
    try { my.devices = JSON.parse(saved); $("#remember").checked = true; run(); } catch { /* ignore */ }
  }
});


async function fetchFixes() {
  const res = await fetch("/api/fixes", { cache: "no-cache" });
  if (res.status === 403) throw Object.assign(new Error("blocked"), { blocked: true });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function bindMy() {
  const input = $("#files");
  $("#pick").addEventListener("click", () => input.click());
  input.addEventListener("change", () => load([...input.files]));
  const drop = $("#drop");
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => load([...(e.dataTransfer?.files || [])]));
  $("#demo").addEventListener("click", () => {
    my.devices = M.demoDevices(my.fixes);
    if (!my.devices.length) return toastMy(t("Sample devices are not available"), t("The current data has no Windows builds to compare with."));
    my.devices.forEach((d, i) => { d.software = DEMO_SOFTWARE[i % DEMO_SOFTWARE.length]; });
    my.demoSbom = true;
    run();
    $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("#showScript").addEventListener("click", async () => {
    const view = $("#scriptView");
    if (view.hidden) {
      const res = await fetch("/collect.ps1", { cache: "no-cache" });
      view.textContent = await res.text();
    }
    view.hidden = !view.hidden;
  });
  $("#clear").addEventListener("click", () => {
    my.devices = []; my.analysis = null; my.extraPrograms = []; my.components = []; my.software = null;
    my.overrides = {}; my.plan = null; my.demoSbom = false;
    $("#software").hidden = true;
    store.set("mpm-devices", "");
    try { sessionStorage.removeItem("mpm-report"); } catch { /* ignore */ }
    $("#results").hidden = true;
    $("#remember").checked = false;
  });
  $("#remember").addEventListener("change", (e) => store.set("mpm-devices", e.target.checked ? JSON.stringify(my.devices) : ""));
  $("#exportDevices").addEventListener("click", exportDevices);
  $("#exportSoftware").addEventListener("click", exportSoftware);
  $("#rolloutCsv").addEventListener("click", exportRolloutCsv);
  $("#rolloutIcs").addEventListener("click", exportRolloutIcs);
  $("#rollout").addEventListener("click", (e) => {
    const b = e.target.closest("[data-script]");
    if (b) downloadScript(b.dataset.script, Number(b.dataset.wave));
  });
  $("#rollout").addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-wave-for]");
    if (!sel) return;
    my.overrides[sel.dataset.waveFor] = Number(sel.value);
    renderRollout();
    saveForReport();
  });
  $("#toReport").addEventListener("click", () => saveForReport());
  $("#devices tbody").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-detail]");
    if (!b) return;
    const row = $(`#detail-${b.dataset.detail}`);
    row.hidden = !row.hidden;
    b.setAttribute("aria-expanded", String(!row.hidden));
  });
}

async function load(files) {
  const MAX = 10 * 1024 * 1024;
  let added = 0, skipped = 0, software = 0;
  for (const f of files.slice(0, 500)) {
    if (f.size > MAX) { skipped++; continue; }
    const text = await f.text();
    const list = M.readInput(f.name, text);
    if (!list.length) {
      const sw = S.readSoftwareInput(f.name, text);
      if (!sw || (!sw.programs.length && !sw.components.length)) { skipped++; continue; }
      if (sw.programs.length) my.extraPrograms.push({ device: f.name.slice(0, 80), programs: sw.programs });
      my.components.push(...sw.components);
      software++;
      continue;
    }
    for (const d of list) {
      const i = my.devices.findIndex((x) => x.name === d.name);
      if (i >= 0) my.devices[i] = d; else my.devices.push(d);
      added++;
    }
  }
  if (skipped) toastMy(skipped > 1 ? t("{n} files not recognised", { n: skipped }) : t("1 file not recognised"),
    t("Use the collector output (.json), a CSV with device name and OS version columns, an SBOM (CycloneDX or SPDX JSON) or a winget export."));
  if (added) run();
  else if (software) runSoftware();
}

function toastMy(title, body) {
  const box = document.createElement("div");
  box.className = "toast";
  setHTML(box, `<strong>${esc(title)}</strong><span>${esc(body)}</span>`);
  $("#toasts").append(box);
  setTimeout(() => box.remove(), 9000);
}

function run() {
  my.analysis = M.analyze(my.devices, my.fixes, my.data, today());
  if ($("#remember").checked) store.set("mpm-devices", JSON.stringify(my.devices));
  renderResults();
  renderRollout();
  saveForReport();
  runSoftware();
}

/* ------------------------------------------------------------------ rollout in waves */
function renderRollout() {
  my.plan = RO.plan(my.analysis.results, today(), my.overrides);
  const labels = WAVE_LABEL();
  const any = my.plan.waves.some((w) => w.devices.length);
  $("#rolloutTitle").hidden = !any;
  $("#rolloutIcs").closest(".result-actions").hidden = !any;
  $("#rolloutTitle").nextElementSibling.hidden = !any;
  setHTML($("#rollout"), any ? my.plan.waves.map((w) => `<article class="wave w${w.wave}">
    <header><h3>${esc(labels[w.wave])}</h3>
      <p>${w.devices.length ? te("Start {date}", { date: fmtLong(w.start) }) : te("No device in this wave")}${w.due ? ` <span class="${w.late ? "late" : "hint"}">${te("earliest patch-by date {date}", { date: fmtDate(w.due) })}</span>` : ""}</p></header>
    <ul class="wave-devices">${w.devices.map((d) => `<li><span><strong>${esc(d.name)}</strong> <span class="hint">${te(d.missing === 1 ? "1 missing fix" : "{n} missing fixes", { n: d.missing })}${d.p1 ? `, ${esc(d.p1)} P1` : ""}</span></span>
      <select data-wave-for="${esc(d.name)}" aria-label="${te("Move {name} to another wave", { name: d.name })}">${[1, 2, 3].map((n) => `<option value="${n}"${n === w.wave ? " selected" : ""}>${esc(labels[n])}</option>`).join("")}</select></li>`).join("")}</ul>
    ${w.updates.length ? `<p class="hint">${te("Install:")} ${esc(w.updates.map((u) => u.kb || `${u.product} ${u.fb}`).join(", "))}</p>` : ""}
    ${w.devices.length ? `<div class="wave-scripts"><span class="hint">${te("Remediation script:")}</span>
      <button type="button" class="chip" data-script="powershell" data-wave="${w.wave}" title="${te("Runs on each device: reports what is missing, installs it with -Install")}">PowerShell</button>
      <button type="button" class="chip" data-script="intune" data-wave="${w.wave}" title="${te("Creates an Intune expedited quality update profile through Microsoft Graph")}">Intune</button>
      <button type="button" class="chip" data-script="wsus" data-wave="${w.wave}" title="${te("Approves the updates for a WSUS computer group")}">WSUS</button></div>` : ""}
  </article>`).join("") : "");
}

/** Remediation scripts for one wave (PowerShell on the device, Intune expedite, WSUS approval). */
function downloadScript(kind, wave) {
  if (!my.plan || !RO.scripts[kind]) return;
  const label = WAVE_LABEL()[wave];
  const latest = [...(my.data?.months || [])].map((m) => m.release_date).sort().pop();
  const text = RO.scripts[kind](my.plan, wave, label, new Date().toISOString().slice(0, 16).replace("T", " "), latest);
  const name = { powershell: "windows-update", intune: "intune-expedite", wsus: "wsus-approve" }[kind];
  downloadFile(`mpatchmonitor-wave${wave}-${name}.ps1`, "\ufeff" + text, "text/plain;charset=utf-8");
}

function exportRolloutCsv() {
  if (!my.plan) return;
  const labels = WAVE_LABEL();
  const lines = [["device", "wave", "wave_name", "start", "earliest_patch_by", "updates"].map(csvCell).join(",")];
  for (const w of my.plan.waves) for (const d of w.devices) {
    lines.push([d.name, w.wave, labels[w.wave], w.start, d.due || "", w.updates.map((u) => u.kb || u.fb).join(" ")].map(csvCell).join(","));
  }
  downloadFile(`mpatchmonitor-rollout-${today()}.csv`, "\ufeff" + lines.join("\r\n"), "text/csv;charset=utf-8");
}

function exportRolloutIcs() {
  if (!my.plan) return;
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  downloadFile(`mpatchmonitor-rollout-${today()}.ics`, RO.ics(my.plan, WAVE_LABEL(), stamp, location.origin), "text/calendar;charset=utf-8");
}

/* ------------------------------------------------------------------ my software */
async function runSoftware() {
  const entries = my.devices.filter((d) => d.software?.length).map((d) => ({ device: d.name, programs: d.software }));
  entries.push(...my.extraPrograms);
  if (!entries.length && !my.components.length && !my.demoSbom) { $("#software").hidden = true; return; }
  if (!my.swData) {
    const get = (u, k) => fetchJson(u).then((d) => d[k] || []).catch(() => []);
    const [eol, kev, oss] = await Promise.all([get("/api/eol", "items"), get("/api/kev", "kev"), get("/api/oss", "items")]);
    my.swData = { eol, kev, oss };
  }
  let comps = my.components;
  if (my.demoSbom && !comps.length) {
    comps = my.swData.oss.slice(0, 3).map((o) => ({ name: o.package, version: "0.9.0", ecosystem: o.ecosystem, purl: "" }))
      .concat([{ name: "left-pad", version: "1.3.0", ecosystem: "npm", purl: "" }]);
  }
  my.software = S.analyzeSoftware(S.mergePrograms(entries), comps, my.swData);
  renderSoftware();
  saveForReport();
}

function supportCell(p) {
  if (!p.eol) return `<span class="hint">${te("Not tracked")}</span>`;
  const end = p.eol.extended_end || p.eol.eol;
  if (p.status === "ended") return `<span class="sig ex">${te("Out of support")}</span>${end ? `<span class="id">${te("since {date}", { date: fmtDate(end) })}</span>` : ""}`;
  if (p.status === "ending") return `<span class="sig kev">${te("Ends within 6 months")}</span>${end ? `<span class="id">${esc(fmtDate(end))}</span>` : ""}`;
  return `<span class="sig rev">${te("Supported")}</span>${end ? `<span class="id">${te("until {date}", { date: fmtDate(end) })}</span>` : ""}`;
}

function renderSoftware() {
  const sw = my.software, s = sw.summary;
  $("#software").hidden = false;
  setHTML($("#swFigures"), [
    [t("Programs"), s.programs, ""], [t("Out of support"), s.ended, "crit"], [t("Ending within 6 months"), s.ending, "warn"],
    [t("With exploited vulnerabilities to check"), s.with_kev, "warn"], [t("SBOM components with exploited vulnerabilities"), s.vulnerable_components, "crit"],
  ].map(([l, n, c]) => `<div class="fig ${c}"><dt>${esc(l)}</dt><dd>${esc(n)}</dd></div>`).join(""));
  $("#swProgTitle").hidden = $("#swProgWrap").hidden = !sw.programs.length;
  setHTML($("#swPrograms tbody"), sw.programs.slice(0, 400).map((p) => `<tr>
    <td class="vuln"><strong>${esc(p.name)}</strong><span class="id">${esc(p.publisher || "")}</span></td>
    <td>${esc(p.version || "–")}</td><td class="num" title="${esc(p.devices.join(", "))}">${esc(p.devices.length)}</td>
    <td>${supportCell(p)}</td>
    <td>${p.kev_count ? `<a href="/exploited?tab=all&amp;q=${encodeURIComponent(p.kev[0].vendor)}">${te(p.kev_count === 1 ? "1 to check" : "{n} to check", { n: p.kev_count })}</a><span class="id">${esc(p.kev.slice(0, 4).map((k) => k.cve).join(", "))}</span>` : "–"}</td></tr>`).join(""));
  $("#swCompTitle").hidden = $("#swCompWrap").hidden = !sw.components.length && !my.components.length;
  setHTML($("#swComponents tbody"), sw.components.slice(0, 300).map((c) => c.findings.map((f, i) => `<tr>
    ${i === 0 ? `<td class="vuln" rowspan="${c.findings.length}"><strong>${esc(c.name)}</strong><span class="id">${esc(c.ecosystem)}</span></td><td rowspan="${c.findings.length}">${esc(c.version || "–")}</td>` : ""}
    <td><a href="${esc(safeUrl(f.url))}" rel="noopener noreferrer" target="_blank">${esc(f.ghsa || f.cve)}</a><span class="id">${esc(f.cve)}${f.certain ? "" : `, ${te("version not comparable: check it")}`}</span></td>
    <td>${f.fixed ? `<strong class="ok">${esc(f.fixed)}</strong>` : `<span class="late">${te("No fix yet")}</span>`}</td></tr>`).join("")).join("")
    || `<tr><td colspan="4" class="empty">${te("No component matches an exploited vulnerability.")}</td></tr>`);
}

function exportSoftware() {
  if (!my.software) return;
  const lines = [["type", "name", "version", "publisher_or_ecosystem", "devices", "support", "support_end", "exploited_cves", "fixed_in"].map(csvCell).join(",")];
  for (const p of my.software.programs) {
    lines.push(["program", p.name, p.version, p.publisher, p.devices.join(" "), p.status || "", p.eol?.extended_end || p.eol?.eol || "",
      p.kev.map((k) => k.cve).join(" "), ""].map(csvCell).join(","));
  }
  for (const c of my.software.components) for (const f of c.findings) {
    lines.push(["component", c.name, c.version, c.ecosystem, "", "", "", f.cve, f.fixed || ""].map(csvCell).join(","));
  }
  downloadFile(`mpatchmonitor-software-${today()}.csv`, "\ufeff" + lines.join("\r\n"), "text/csv;charset=utf-8");
}

function saveForReport() {
  if (!my.analysis) return;
  try {
    sessionStorage.setItem("mpm-report", JSON.stringify({
      analysis: my.analysis, data_version: my.data.generated_at, sla_days: my.data.sla_days, created_at: new Date().toISOString(),
      rollout: my.plan, software: my.software ? { summary: my.software.summary,
        programs: my.software.programs.filter((p) => p.status === "ended" || p.status === "ending" || p.kev_count).slice(0, 40)
          .map((p) => ({ name: p.name, version: p.version, devices: p.devices.length, status: p.status, end: p.eol?.extended_end || p.eol?.eol || null, kev: p.kev.map((k) => k.cve).slice(0, 6) })),
        components: my.software.components.slice(0, 40).map((c) => ({ name: c.name, version: c.version, ecosystem: c.ecosystem, cves: c.findings.map((f) => f.cve), fixed: c.findings.map((f) => f.fixed).filter(Boolean) })) } : null,
    }));
  } catch { /* storage unavailable: the report page will ask to reload devices */ }
}

function renderResults() {
  const { summary: s, results, top } = my.analysis;
  $("#results").hidden = false;
  const lede = s.missing === 0
    ? (s.recognised === 1 ? t("The recognised device is up to date with Microsoft's security fixes.") : t("All {n} recognised devices are up to date with Microsoft's security fixes.", { n: s.recognised }))
    : (s.missing === 1 ? t("1 of {total} devices is missing security fixes", { total: s.devices }) : t("{n} of {total} devices are missing security fixes", { n: s.missing, total: s.devices }))
      + (s.exploited_devices ? (s.exploited_devices === 1 ? t(", and 1 is exposed to vulnerabilities already exploited.") : t(", and {n} are exposed to vulnerabilities already exploited.", { n: s.exploited_devices })) : ".");
  $("#resultLede").textContent = lede;

  setHTML($("#myFigures"), [
    [t("Devices analysed"), s.devices, ""],
    [t("Up to date"), s.up_to_date, "rev"],
    [t("Missing a P1 fix"), s.with_p1, "crit"],
    [t("Past their patch-by date"), s.overdue_devices, "warn"],
    [t("Distinct vulnerabilities open"), s.unique_cves, ""],
  ].map(([l, n, c]) => `<div class="fig ${c}"><dt>${esc(l)}</dt><dd>${n}</dd></div>`).join(""));

  const order = { missing: 0, partial: 1, ok: 2, unsupported: 3 };
  const rows = [...results].sort((a, b) => order[a.status] - order[b.status] || (b.counts?.P1 || 0) - (a.counts?.P1 || 0) || b.missing.length - a.missing.length);
  setHTML($("#devices tbody"), rows.map((r, i) => {
    const d = r.device;
    const system = r.products.length ? r.products.map((p) => `${esc(p.name)}<span class="id">${esc(p.version)}</span>`).join("") : `${esc(d.caption || t("Unknown"))}<span class="id">${esc(d.build || t("no build"))}</span>`;
    let missing;
    if (r.status === "unsupported") missing = `<span class="hint">${te("Not a supported Windows version")}</span>`;
    else if (r.status === "ok") missing = `<span class="ok">${te("Up to date")}</span>`;
    else if (r.status === "partial") missing = `<span class="hint">${te("Build revision unknown: run the collector for an exact check")}</span>`;
    else missing = `<button class="textbtn" type="button" data-detail="${i}" aria-expanded="false">${te(r.missing.length === 1 ? "1 vulnerability" : "{n} vulnerabilities", { n: r.missing.length })}</button>
      <span class="counts">${["P1", "P2", "P3", "P4"].filter((p) => r.counts[p]).map((p) => `${prioBadge(p)} ${r.counts[p]}`).join(" ")}</span>`;
    const install = r.recommended.map((x) => `${x.kb ? esc(x.kb) : /Edge/.test(x.product) ? te("Microsoft Edge update") : te("Latest update")}${x.fixed_build || x.fb ? `<span class="id">${te("build {b} or later", { b: x.fixed_build || x.fb })}</span>` : ""}`).join("") || "–";
    const due = r.oldest ? `<span class="${r.oldest < today() ? "late" : ""}">${esc(fmtDate(r.oldest))}</span>` : "–";
    const detail = r.missing.length ? `<tr class="detail-row" id="detail-${i}" hidden><td colspan="6"><ul class="missing-list">${
      r.missing.slice(0, 200).map((m) => `<li>${prioBadge(m.priority)} <a href="/cve/${encodeURIComponent(m.cve)}">${esc(m.title)}</a>
        <span class="id">${esc(m.cve)}, ${esc(m.product)}${m.kb ? te(", fixed by {kb}", { kb: m.kb }) : ""}${m.exploited || m.kev ? te(", exploited") : ""}</span></li>`).join("")
    }</ul></td></tr>` : "";
    return `<tr class="st-${r.status}"><td class="vuln"><strong>${esc(d.name)}</strong><span class="id">${esc(d.source === "sample" ? t("sample device") : d.source === "csv" ? t("from CSV") : t("collected {date}", { date: fmtDate((d.collected_at || "").slice(0, 10)) }))}</span></td>
      <td>${system}</td><td>${missing}</td><td class="num">${r.exploited || "–"}</td><td>${install}</td><td class="num">${due}</td></tr>${detail}`;
  }).join(""));

  setHTML($("#fleetTop tbody"), top.slice(0, 50).map((m) => `<tr data-cve="${esc(m.cve)}">
    <td>${prioBadge(m.priority)}</td>
    <td class="vuln"><a href="/cve/${encodeURIComponent(m.cve)}">${esc(m.title)}</a><span class="id">${esc(m.cve)}${m.kb ? te(", fixed by {kb}", { kb: m.kb }) : ""}</span></td>
    <td class="num">${m.devices}</td>
    <td class="sigs">${m.exploited ? `<span class="sig ex">${te("pill|Exploited")}</span>` : ""}${m.kev ? `<span class="sig kev">CISA KEV</span>` : ""}</td>
    <td class="num${m.due && m.due < today() ? " late" : ""}">${esc(fmtDate(m.due))}</td></tr>`).join("")
    || `<tr><td colspan="5" class="empty">${te("No open vulnerabilities. Nothing to patch right now.")}</td></tr>`);
}

function exportDevices() {
  if (!my.analysis) return;
  const cell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const lines = [["device", "system", "build", "status", "missing", "p1", "p2", "p3", "p4", "exploited", "overdue", "install", "patch_by"].join(",")];
  for (const r of my.analysis.results) {
    lines.push([r.device.name, r.products.map((p) => p.name).join(" | ") || r.device.caption, r.device.build, r.status, r.missing.length,
      r.counts?.P1 || 0, r.counts?.P2 || 0, r.counts?.P3 || 0, r.counts?.P4 || 0, r.exploited || 0, r.overdue || 0,
      r.recommended.map((x) => x.kb).join(" "), r.oldest || ""].map(cell).join(","));
  }
  const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `mpatchmonitor-devices-${today()}.csv` });
  a.click();
  URL.revokeObjectURL(a.href);
}
