"use strict";

/* MPatchMonitor — NIS2 / ACN evidence report, generated in the browser from "My devices". */

const T = {
  it: {
    title: "Rapporto di gestione delle vulnerabilità Microsoft",
    subtitle: "Evidenza per NIS2 e specifiche di base ACN",
    org: "Organizzazione", author: "Redatto da", date: "Data del rapporto", data: "Dati Microsoft aggiornati al", id: "Impronta del rapporto",
    summary: "Sintesi", scope: "Perimetro e metodo",
    scopeText: (n, m) => `Sono stati analizzati ${n} dispositivi Windows, di cui ${m} riconosciuti. Per ogni dispositivo la build installata di Windows, e quando disponibile di Microsoft Edge, è stata confrontata con la build che contiene la correzione di ciascuna vulnerabilità pubblicata da Microsoft negli ultimi dodici mesi. Le vulnerabilità sono classificate con la politica riportata sotto, che combina gravità Microsoft, CVSS, sfruttamento attivo, catalogo CISA KEV ed EPSS.`,
    sumLine: (s) => s.missing === 0
      ? `Tutti i ${s.recognised} dispositivi riconosciuti hanno installato le correzioni di sicurezza Microsoft disponibili.`
      : `${s.missing} dispositivi su ${s.devices} non hanno ancora tutte le correzioni di sicurezza; ${s.with_p1} mancano di almeno una correzione con priorità P1 e ${s.overdue_devices} hanno superato la data limite prevista dalla politica.`,
    figs: ["Dispositivi analizzati", "Aggiornati", "Con correzioni P1 mancanti", "Oltre la data limite", "Vulnerabilità aperte"],
    policy: "Politica di priorità applicata",
    policyRows: [["P1", "Sfruttata attivamente, presente in CISA KEV, Critica con CVSS ≥ 9 o EPSS ≥ 50%"], ["P2", "Critica, divulgata pubblicamente, EPSS ≥ 10% o sfruttamento ritenuto più probabile"], ["P3", "Importante"], ["P4", "Altre"]],
    within: (d) => `entro ${d} giorni dal rilascio`,
    kevNote: "Se CISA fissa una scadenza più vicina, vale quella.",
    plan: "Piano di intervento", planHead: ["Prodotto", "Aggiornamento", "Dispositivi", "Entro il", "Decisione", "Motivazione"],
    decisions: { install: "Installare", mitigate: "Mitigare", accept: "Accettare il rischio", "": "Da decidere" },
    devices: "Dettaglio per dispositivo", devHead: ["Dispositivo", "Sistema", "P1", "P2", "P3", "P4", "Sfruttate", "Data limite più vicina"],
    upToDate: "Aggiornato", unsupported: "Non supportato", partial: "Build incompleta",
    top: "Vulnerabilità con priorità più alta", topHead: ["Priorità", "Vulnerabilità", "Dispositivi", "Segnali", "Entro il"],
    exploited: "Sfruttata", kev: "CISA KEV", publicExploit: "Exploit pubblico",
    waves: "Calendario di installazione a ondate", wavesHead: ["Ondata", "Inizio", "Dispositivi", "Aggiornamenti", "Data limite più vicina"],
    waveNames: { 1: "1 – pilota", 2: "2 – postazioni", 3: "3 – server" },
    sw: "Software di terze parti", swIntro: "Programmi fuori supporto o in scadenza, prodotti con vulnerabilità sfruttate note da verificare e componenti SBOM con vulnerabilità sfruttate.",
    swHead: ["Software", "Versione", "Dispositivi", "Stato", "Vulnerabilità sfruttate"], swStatus: { ended: "Fuori supporto", ending: "In scadenza", supported: "Supportato" },
    swComp: "Componente SBOM", swFixed: "corretta in",
    mitig: "Mitigazioni per le azioni non ancora installate",
    mitigIntro: "Soluzioni alternative e mitigazioni pubblicate da Microsoft per le vulnerabilità delle azioni con decisione \"Mitigare\" o \"Accettare il rischio\". Riducono il rischio fino all'installazione, non la sostituiscono. Il testo è riportato in inglese, come pubblicato.",
    mitigNone: "Nessuna azione con decisione \"Mitigare\" o \"Accettare il rischio\".",
    mitigMissing: "Microsoft non pubblica mitigazioni per queste vulnerabilità: l'installazione resta l'unica correzione.",
    refs: "Riferimenti normativi e misure supportate", refsHead: ["Riferimento", "Requisito", "Come questo rapporto lo supporta"],
    refsNote: (d) => `Riferimenti verificati il ${d}. Controllarli sempre con i testi vigenti pubblicati su EUR-Lex, Normattiva e dal sito dell'ACN.`,
    limits: "Limiti",
    limitsText: "Il confronto riguarda Windows e Microsoft Edge e si basa sulle informazioni pubblicate da Microsoft. Non copre software di terze parti, configurazioni o mitigazioni alternative già applicate. I dispositivi importati da CSV senza revisione di build sono indicati come incompleti. Il rapporto non sostituisce una verifica tecnica indipendente.",
    sign: "Approvazione", signPrep: "Redatto da", signAppr: "Approvato dall'organo di amministrazione", signDate: "Data e firma",
    sources: "Fonti: Microsoft Security Update Guide (MSRC CVRF API), CSIRT Italia (ACN), CISA Known Exploited Vulnerabilities, FIRST EPSS. Generato con MPatchMonitor.",
    none: "Nessun dispositivo da riportare. Carica prima i dispositivi nella pagina I miei dispositivi.", myLink: "I miei dispositivi",
    noAction: "Nessun intervento necessario.",
    acn: "Bollettini CSIRT Italia ricevuti (ID.RA-08)",
    acnIntro: "Bollettini del CSIRT Italia che citano Microsoft negli ultimi 90 giorni, registrati automaticamente dal monitoraggio del feed pubblico dell'ACN, con le vulnerabilità ancora aperte sui dispositivi analizzati.",
    acnHead: ["Pubblicato", "Bollettino", "CVE citate", "Aperte sui dispositivi"],
    acnNone: "Nessun bollettino del CSIRT Italia che citi Microsoft negli ultimi 90 giorni.",
  },
  en: {
    title: "Microsoft vulnerability handling report",
    subtitle: "Evidence for NIS2 and the ACN baseline specifications",
    org: "Organisation", author: "Prepared by", date: "Report date", data: "Microsoft data as of", id: "Report fingerprint",
    summary: "Summary", scope: "Scope and method",
    scopeText: (n, m) => `${n} Windows devices were assessed, ${m} of them recognised. For each device the installed build of Windows, and of Microsoft Edge when available, was compared with the build that contains the fix for each vulnerability Microsoft published in the last twelve months. Vulnerabilities are ranked with the policy below, which combines Microsoft severity, CVSS, active exploitation, the CISA KEV catalog and EPSS.`,
    sumLine: (s) => s.missing === 0
      ? `All ${s.recognised} recognised devices have the available Microsoft security fixes installed.`
      : `${s.missing} of ${s.devices} devices are still missing security fixes; ${s.with_p1} miss at least one P1 fix and ${s.overdue_devices} are past the deadline set by the policy.`,
    figs: ["Devices assessed", "Up to date", "Missing a P1 fix", "Past their deadline", "Open vulnerabilities"],
    policy: "Priority policy applied",
    policyRows: [["P1", "Exploited in the wild, in CISA KEV, Critical with CVSS ≥ 9 or EPSS ≥ 50%"], ["P2", "Critical, publicly disclosed, EPSS ≥ 10% or exploitation more likely"], ["P3", "Important"], ["P4", "Other"]],
    within: (d) => `within ${d} days of release`,
    kevNote: "When CISA sets an earlier deadline, that deadline applies.",
    plan: "Action plan", planHead: ["Product", "Update", "Devices", "By", "Decision", "Rationale"],
    decisions: { install: "Install", mitigate: "Mitigate", accept: "Accept the risk", "": "To be decided" },
    devices: "Device detail", devHead: ["Device", "System", "P1", "P2", "P3", "P4", "Exploited", "Earliest deadline"],
    upToDate: "Up to date", unsupported: "Not supported", partial: "Incomplete build",
    top: "Highest-priority vulnerabilities", topHead: ["Priority", "Vulnerability", "Devices", "Signals", "By"],
    exploited: "Exploited", kev: "CISA KEV", publicExploit: "Public exploit",
    waves: "Rollout in waves", wavesHead: ["Wave", "Start", "Devices", "Updates", "Earliest patch-by date"],
    waveNames: { 1: "1 – pilot", 2: "2 – workstations", 3: "3 – servers" },
    sw: "Third-party software", swIntro: "Programs out of support or ending soon, products with known exploited vulnerabilities to check, and SBOM components with exploited vulnerabilities.",
    swHead: ["Software", "Version", "Devices", "Status", "Exploited vulnerabilities"], swStatus: { ended: "Out of support", ending: "Ending soon", supported: "Supported" },
    swComp: "SBOM component", swFixed: "fixed in",
    mitig: "Mitigations for actions not installed yet",
    mitigIntro: "Workarounds and mitigations Microsoft publishes for the vulnerabilities of actions decided \"Mitigate\" or \"Accept the risk\". They reduce the risk until installation; they do not replace it.",
    mitigNone: "No action is decided \"Mitigate\" or \"Accept the risk\".",
    mitigMissing: "Microsoft publishes no mitigation for these vulnerabilities: installing remains the only fix.",
    refs: "Regulatory references and supported measures", refsHead: ["Reference", "Requirement", "How this report supports it"],
    refsNote: (d) => `References checked on ${d}. Always verify them against the current texts published on EUR-Lex, Normattiva and by ACN.`,
    limits: "Limitations",
    limitsText: "The comparison covers Windows and Microsoft Edge and relies on the information Microsoft publishes. It does not cover third-party software, configuration, or alternative mitigations already in place. Devices imported from CSV without a build revision are marked as incomplete. The report does not replace an independent technical verification.",
    sign: "Approval", signPrep: "Prepared by", signAppr: "Approved by the management body", signDate: "Date and signature",
    sources: "Sources: Microsoft Security Update Guide (MSRC CVRF API), CSIRT Italia (ACN), CISA Known Exploited Vulnerabilities, FIRST EPSS. Generated with MPatchMonitor.",
    none: "No devices to report. Load your devices on the My devices page first.", myLink: "My devices",
    noAction: "No action needed.",
    acn: "CSIRT Italia bulletins received (ID.RA-08)",
    acnIntro: "CSIRT Italia bulletins mentioning Microsoft in the last 90 days, recorded automatically by monitoring ACN's public feed, with the vulnerabilities still open on the assessed devices.",
    acnHead: ["Published", "Bulletin", "CVEs mentioned", "Open on devices"],
    acnNone: "No CSIRT Italia bulletin mentioning Microsoft in the last 90 days.",
  },
};

const rep = { lang: store.get("mpm-report-lang") || MPM_LANG, input: null, decisions: {}, fingerprint: "", acn: [], mitig: new Map() };

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  try { rep.input = JSON.parse(sessionStorage.getItem("mpm-report") || "null"); } catch { rep.input = null; }
  try { rep.decisions = JSON.parse(store.get("mpm-report-decisions") || "{}"); } catch { rep.decisions = {}; }
  $("#org").value = store.get("mpm-report-org") || "";
  $("#author").value = store.get("mpm-report-author") || "";
  $$("[data-lang]").forEach((b) => b.addEventListener("click", () => { rep.lang = b.dataset.lang; store.set("mpm-report-lang", rep.lang); render(); }));
  for (const id of ["org", "author"]) $(`#${id}`).addEventListener("input", (e) => { store.set(`mpm-report-${id}`, e.target.value); render(); });
  $("#print").addEventListener("click", () => window.print());
  $("#evidence").addEventListener("click", downloadEvidence);
  const onEdit = (e) => {
    const el = e.target.closest("[data-action]");
    if (!el) return;
    const d = rep.decisions[el.dataset.action] || {};
    d[el.dataset.field] = el.value.slice(0, 300);
    rep.decisions[el.dataset.action] = d;
    store.set("mpm-report-decisions", JSON.stringify(rep.decisions));
    const mirror = el.parentElement.querySelector(".print-only");
    if (mirror) mirror.textContent = el.value;
    if (el.dataset.field === "decision" && e.type === "change") return render();
    updateFingerprint();
  };
  $("#report").addEventListener("change", onEdit);
  $("#report").addEventListener("input", onEdit);
  render();
  fetchData().then((d) => {
    for (const c of d.cves) if (c.mitigations?.length) rep.mitig.set(c.cve, c.mitigations);
    render();
  }).catch(() => {});
  fetchJson("/api/acn").then((d) => {
    const since = Date.now() - 90 * 86_400_000;
    rep.acn = (d.items || []).filter((i) => Date.parse(i.published) >= since)
      .map((i) => ({ title: String(i.title), link: String(i.link), published: String(i.published), cves: (i.cves || []).map(String) }));
    render();
  }).catch(() => {});
});

function acnRows(a) {
  const open = new Set(a.results.flatMap((r) => r.missing.map((m) => m.cve)));
  return rep.acn.map((b) => ({ ...b, open: b.cves.filter((c) => open.has(c)) }));
}

function wavesSection(t, dfmt) {
  const p = rep.input.rollout;
  if (!p?.waves?.some((w) => w.devices.length)) return "";
  return `<section><h2>${esc(t.waves)}</h2><table class="rep-table"><thead><tr>${t.wavesHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    p.waves.filter((w) => w.devices.length).map((w) => `<tr><td>${esc(t.waveNames[w.wave])}</td><td>${esc(dfmt(w.start))}</td>
      <td>${esc(w.devices.map((d) => d.name).join(", "))}</td><td>${esc(w.updates.map((u) => u.kb || `${u.product} ${u.fb}`).join(", "))}</td>
      <td class="${w.late ? "late" : ""}">${esc(dfmt(w.due))}</td></tr>`).join("")}</tbody></table></section>`;
}

function softwareSection(t, dfmt) {
  const sw = rep.input.software;
  if (!sw || (!sw.programs.length && !sw.components.length)) return "";
  const rows = sw.programs.map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.version || "–")}</td><td class="num">${esc(p.devices)}</td>
    <td>${p.status ? esc(t.swStatus[p.status] || p.status) + (p.end ? ` (${esc(dfmt(p.end))})` : "") : "–"}</td><td>${esc(p.kev.join(", ") || "–")}</td></tr>`)
    .concat(sw.components.map((c) => `<tr><td>${esc(c.name)}<span class="id">${esc(t.swComp)}, ${esc(c.ecosystem)}</span></td><td>${esc(c.version || "–")}</td><td class="num">–</td>
      <td>${c.fixed.length ? `${esc(t.swFixed)} ${esc(c.fixed.join(", "))}` : "–"}</td><td>${esc(c.cves.join(", "))}</td></tr>`));
  return `<section><h2>${esc(t.sw)}</h2><p>${esc(t.swIntro)}</p><table class="rep-table"><thead><tr>${t.swHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></section>`;
}

function mitigFor(acts) {
  return acts.filter((x) => ["mitigate", "accept"].includes(rep.decisions[x.key]?.decision))
    .map((x) => ({ action: x, items: [...x.cves].filter((c) => rep.mitig.has(c)).map((c) => ({ cve: c, list: rep.mitig.get(c) })) }));
}

function mitigSection(t, acts) {
  const rows = mitigFor(acts);
  const body = !rows.length ? `<p class="hint">${esc(t.mitigNone)}</p>` : rows.map(({ action, items }) =>
    `<h3>${esc(action.product)}${action.kb ? `, ${esc(action.kb)}` : ""}</h3>${items.length
      ? items.slice(0, 8).map((i) => `<p class="mit-cve"><strong>${esc(i.cve)}</strong></p>${mitigationList(i.list)}`).join("")
      : `<p class="hint">${esc(t.mitigMissing)}</p>`}`).join("");
  return `<section><h2>${esc(t.mitig)}</h2><p>${esc(t.mitigIntro)}</p>${body}</section>`;
}

function actions(a) {
  const map = new Map();
  for (const r of a.results) {
    for (const rec of r.recommended) {
      const key = `${rec.product}|${rec.kb || rec.fb}`;
      const due = r.missing.filter((m) => m.product === rec.product).reduce((o, m) => (!o || (m.due && m.due < o) ? m.due : o), null);
      const e = map.get(key) || { key, product: rec.product, kb: rec.kb, fb: rec.fb, devices: [], due: null, p1: false, cves: new Set() };
      e.devices.push(r.device.name);
      r.missing.filter((m) => m.product === rec.product).forEach((m) => e.cves.add(m.cve));
      if (due && (!e.due || due < e.due)) e.due = due;
      e.p1 ||= r.missing.some((m) => m.product === rec.product && m.priority === "P1");
      map.set(key, e);
    }
  }
  return [...map.values()].sort((x, y) => (x.due || "9") < (y.due || "9") ? -1 : 1);
}

function evidence() {
  const a = rep.input.analysis;
  return {
    schema: "mpm-evidence/1",
    organisation: $("#org").value.trim(),
    prepared_by: $("#author").value.trim(),
    created_at: rep.input.created_at,
    microsoft_data_version: rep.input.data_version,
    policy: { sla_days: rep.input.sla_days, model: T.en.policyRows },
    summary: a.summary,
    devices: a.results.map((r) => ({
      name: r.device.name, system: r.products.map((p) => `${p.name} ${p.version}`), status: r.status,
      missing: r.missing.map((m) => ({ cve: m.cve, priority: m.priority, product: m.product, kb: m.kb, fixed_build: m.fixed_build, due: m.due, exploited: m.exploited || m.kev })),
    })),
    actions: actions(a).map((x) => ({ product: x.product, update: x.kb || x.fb, devices: x.devices, due: x.due, ...(rep.decisions[x.key] || {}) })),
    rollout: rep.input.rollout || null,
    third_party_software: rep.input.software || null,
    mitigations: mitigFor(actions(a)).map(({ action, items }) => ({ product: action.product, update: action.kb || action.fb,
      cves: items.map((i) => ({ cve: i.cve, mitigations: i.list })) })),
    csirt_italia_bulletins: acnRows(a).map((b) => ({ published: b.published, title: b.title, link: b.link, cves: b.cves, open_on_devices: b.open })),
    references: window.MPM_REFS.items.map((r) => r.ref.en),
  };
}

async function digest(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function updateFingerprint() {
  if (!rep.input) return;
  rep.fingerprint = await digest(evidence());
  const el = $("#fp");
  if (el) el.textContent = `SHA-256 ${rep.fingerprint}`;
}

async function downloadEvidence() {
  if (!rep.input) return;
  const ev = evidence();
  const sha256 = await digest(ev);
  const blob = new Blob([JSON.stringify({ ...ev, sha256 }, null, 2)], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `mpatchmonitor-evidence-${today()}.json` });
  a.click();
  URL.revokeObjectURL(a.href);
}

function render() {
  const t = T[rep.lang];
  document.documentElement.lang = rep.lang;
  $$("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === rep.lang)));
  const root = $("#report");
  if (!rep.input?.analysis) { setHTML(root, `<p class="fatal">${esc(t.none)} <a href="/my">${esc(t.myLink)}</a></p>`); return; }
  const a = rep.input.analysis, s = a.summary, sla = rep.input.sla_days;
  const dfmt = (d) => d ? asDate(d).toLocaleDateString(rep.lang === "it" ? "it-IT" : "en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }) : "–";
  const nowDate = dfmt(new Date().toISOString().slice(0, 10));
  const acts = actions(a);
  const sel = (key, v) => `<select data-action="${esc(key)}" data-field="decision" aria-label="${esc(t.planHead[4])}">${
    Object.entries(t.decisions).map(([k, l]) => `<option value="${k}"${(v || "") === k ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>`;

  setHTML(root, `
  <header class="rep-head">
    <p class="rep-brand">MPatchMonitor</p>
    <h1>${esc(t.title)}</h1>
    <p class="rep-sub">${esc(t.subtitle)}</p>
    <dl class="rep-meta">
      <div><dt>${esc(t.org)}</dt><dd>${esc($("#org").value.trim() || "—")}</dd></div>
      <div><dt>${esc(t.author)}</dt><dd>${esc($("#author").value.trim() || "—")}</dd></div>
      <div><dt>${esc(t.date)}</dt><dd>${esc(nowDate)}</dd></div>
      <div><dt>${esc(t.data)}</dt><dd>${esc(dfmt(rep.input.data_version.slice(0, 10)))}</dd></div>
      <div><dt>${esc(t.id)}</dt><dd id="fp">…</dd></div>
    </dl>
  </header>

  <section><h2>${esc(t.summary)}</h2>
    <p class="rep-lede">${esc(t.sumLine(s))}</p>
    <dl class="figures">${[s.devices, s.up_to_date, s.with_p1, s.overdue_devices, s.unique_cves].map((n, i) =>
      `<div class="fig ${["", "rev", "crit", "warn", ""][i]}"><dt>${esc(t.figs[i])}</dt><dd>${n}</dd></div>`).join("")}</dl>
  </section>

  <section><h2>${esc(t.scope)}</h2><p>${esc(t.scopeText(s.devices, s.recognised))}</p>
    <h3>${esc(t.policy)}</h3>
    <table class="rep-table"><tbody>${t.policyRows.map(([p, d]) => `<tr><td>${prioBadge(p)}</td><td>${esc(d)}</td><td>${esc(t.within(sla[p]))}</td></tr>`).join("")}</tbody></table>
    <p class="hint">${esc(t.kevNote)}</p>
  </section>

  <section><h2>${esc(t.plan)}</h2>
    ${acts.length ? `<table class="rep-table"><thead><tr>${t.planHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${acts.map((x) => `<tr>
      <td>${esc(x.product)}${x.p1 ? ` ${prioBadge("P1")}` : ""}</td>
      <td>${esc(x.kb || "")}${x.fb ? `<span class="id">build ${esc(x.fb)}+</span>` : ""}</td>
      <td>${x.devices.length}<span class="id">${esc(x.devices.slice(0, 6).join(", "))}${x.devices.length > 6 ? "…" : ""}</span></td>
      <td class="${x.due && x.due < today() ? "late" : ""}">${esc(dfmt(x.due))}</td>
      <td>${sel(x.key, rep.decisions[x.key]?.decision)}</td>
      <td><input type="text" data-action="${esc(x.key)}" data-field="note" value="${esc(rep.decisions[x.key]?.note || "")}" maxlength="300" aria-label="${esc(t.planHead[5])}"><span class="print-only">${esc(rep.decisions[x.key]?.note || "")}</span></td>
    </tr>`).join("")}</tbody></table>` : `<p>${esc(t.noAction)}</p>`}
  </section>

  <section><h2>${esc(t.devices)}</h2>
    <table class="rep-table"><thead><tr>${t.devHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${a.results.map((r) => `<tr>
      <td>${esc(r.device.name)}</td>
      <td>${esc(r.products.map((p) => `${p.name} ${p.version}`).join("; ") || r.device.caption)}${r.status !== "missing" ? `<span class="id">${esc(r.status === "ok" ? t.upToDate : r.status === "partial" ? t.partial : t.unsupported)}</span>` : ""}</td>
      ${["P1", "P2", "P3", "P4"].map((p) => `<td class="num">${r.counts?.[p] || 0}</td>`).join("")}
      <td class="num">${r.exploited || 0}</td>
      <td class="${r.oldest && r.oldest < today() ? "late" : ""}">${esc(dfmt(r.oldest))}</td></tr>`).join("")}</tbody></table>
  </section>

  ${wavesSection(t, dfmt)}

  ${mitigSection(t, acts)}

  ${softwareSection(t, dfmt)}

  ${a.top.length ? `<section><h2>${esc(t.top)}</h2>
    <table class="rep-table"><thead><tr>${t.topHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${a.top.slice(0, 25).map((m) => `<tr>
      <td>${prioBadge(m.priority)}</td><td>${esc(m.title)}<span class="id">${esc(m.cve)}${m.kb ? `, ${esc(m.kb)}` : ""}</span></td>
      <td class="num">${m.devices}</td><td>${[m.exploited && t.exploited, m.kev && t.kev, m.public_exploit && t.publicExploit].filter(Boolean).map(esc).join(", ")}</td>
      <td>${esc(dfmt(m.due))}</td></tr>`).join("")}</tbody></table></section>` : ""}

  <section><h2>${esc(t.acn)}</h2><p>${esc(t.acnIntro)}</p>
    ${rep.acn.length ? `<table class="rep-table"><thead><tr>${t.acnHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${acnRows(a).map((b) => `<tr>
      <td>${esc(dfmt(b.published.slice(0, 10)))}</td><td><a href="${esc(safeUrl(b.link))}" rel="noopener noreferrer" target="_blank">${esc(b.title)}</a></td>
      <td class="num">${b.cves.length}</td><td class="${b.open.length ? "late" : ""}">${b.open.length ? esc(b.open.slice(0, 6).join(", ")) + (b.open.length > 6 ? "…" : "") : "0"}</td></tr>`).join("")}</tbody></table>`
      : `<p class="hint">${esc(t.acnNone)}</p>`}
  </section>

  <section><h2>${esc(t.refs)}</h2>
    <table class="rep-table refs"><thead><tr>${t.refsHead.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${window.MPM_REFS.items.map((r) =>
      `<tr><td><strong>${esc(r.ref[rep.lang])}</strong></td><td>${esc(r.what[rep.lang])}</td><td>${esc(r.how[rep.lang])}</td></tr>`).join("")}</tbody></table>
    <p class="hint">${esc(t.refsNote(dfmt(window.MPM_REFS.checked)))}</p>
  </section>

  <section><h2>${esc(t.limits)}</h2><p>${esc(t.limitsText)}</p></section>

  <section class="signatures"><h2>${esc(t.sign)}</h2>
    <div class="sig-grid">
      <div><p>${esc(t.signPrep)}</p><p class="line">${esc($("#author").value.trim())}</p><p class="hint">${esc(t.signDate)}</p></div>
      <div><p>${esc(t.signAppr)}</p><p class="line"></p><p class="hint">${esc(t.signDate)}</p></div>
    </div>
  </section>
  <p class="rep-foot">${esc(t.sources)}</p>`);
  updateFingerprint();
}
