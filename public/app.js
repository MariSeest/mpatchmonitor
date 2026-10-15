"use strict";

/* MPatchMonitor — dashboard */

const POLL_MS = 90_000;
const STALE_MIN = 15;
const CHIPS = [
  { id: "all", label: t("Everything"), kinds: null },
  { id: "rev", label: t("Revisions"), kinds: ["revised", "silent"] },
  { id: "new", label: t("New CVEs"), kinds: ["published", "release"] },
  { id: "expl", label: t("Exploitation"), kinds: ["exploited", "kev"] },
  { id: "score", label: t("Scores"), kinds: ["severity", "cvss", "priority"] },
];

const state = {
  data: null, month: null, chip: "all", sortKey: "priority", sortDir: 1,
  lastSeen: store.get("mpm-last-seen"), status: null, alerts: false,
};

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  initAlerts();
  try {
    state.data = await fetchData();
  } catch (err) {
    showFatal($("#main"), err);
    startLive();
    return;
  }
  state.month = state.data.months.at(-1)?.id;
  bind();
  render();
  startLive();
  loadAcn();
  addEventListener("pagehide", () => store.set("mpm-last-seen", state.data.generated_at));
});

/* ------------------------------------------------------------------ events */
function bind() {
  ["#q", "#sev", "#prio", "#onlyExploited", "#onlyKev", "#onlyChanged", "#onlyPublic", "#onlyMitigation"].forEach((id) =>
    $(id)?.addEventListener("input", renderTable));
  $("#csv").addEventListener("click", exportCsv);
  $("#markRead").addEventListener("click", () => {
    state.lastSeen = state.data.generated_at;
    store.set("mpm-last-seen", state.lastSeen);
    renderFeed();
    renderFigures();
  });
  $("#ribbon").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-month]");
    if (!b) return;
    state.month = b.dataset.month;
    render();
  });
  $("#ribbon").addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const ids = state.data.months.map((m) => m.id);
    const i = ids.indexOf(state.month) + (e.key === "ArrowRight" ? 1 : -1);
    if (i < 0 || i >= ids.length) return;
    state.month = ids[i];
    render();
    $(`#ribbon button[data-month="${ids[i]}"]`)?.focus();
  });
  $("#chips").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-chip]");
    if (!b) return;
    state.chip = b.dataset.chip;
    renderFeed();
  });
  $$("th[data-k]").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.k;
    state.sortDir = state.sortKey === k ? -state.sortDir : (["cvss", "epss", "revised_at"].includes(k) ? -1 : 1);
    state.sortKey = k;
    renderTable();
  }));
  $("#table tbody").addEventListener("click", (e) => {
    if (e.target.closest("a")) return;
    const tr = e.target.closest("tr[data-cve]");
    if (tr) location.href = `/cve/${encodeURIComponent(tr.dataset.cve)}`;
  });
}

function initAlerts() {
  const btn = $("#bell");
  const supported = "Notification" in window;
  state.alerts = supported && Notification.permission === "granted" && store.get("mpm-alerts") === "on";
  const sync = () => {
    btn.setAttribute("aria-pressed", String(state.alerts));
    btn.title = state.alerts ? t("Desktop alerts are on") : t("Turn on desktop alerts");
  };
  sync();
  btn.addEventListener("click", async () => {
    if (!supported) return toast(t("Desktop alerts are not available"), t("This browser does not support notifications."));
    if (state.alerts) {
      state.alerts = false; store.set("mpm-alerts", "off"); sync();
      return toast(t("Desktop alerts turned off"), t("You will still see changes on this page."));
    }
    state.alerts = (await Notification.requestPermission()) === "granted";
    store.set("mpm-alerts", state.alerts ? "on" : "off");
    sync();
    toast(state.alerts ? t("Desktop alerts turned on") : t("Desktop alerts are blocked"),
      state.alerts ? t("You will get an alert when Microsoft changes something while this page is open.")
        : t("Allow notifications for this site in the browser settings, then try again."));
  });
}

async function loadAcn() {
  try {
    const a = await fetchJson("/api/acn");
    const items = (a.items || []).slice(0, 3);
    if (!items.length) return;
    setHTML($("#acnList"), items.map((i) => `<li><a href="${esc(safeUrl(i.link))}" rel="noopener noreferrer" target="_blank">${esc(i.title)}</a><span class="hint"> ${esc(timeAgo(i.published))}</span></li>`).join(""));
    $("#acnStrip").hidden = false;
  } catch { /* optional panel */ }
}

/* ------------------------------------------------------------------ live */
function startLive() {
  checkStatus();
  setInterval(() => { if (!document.hidden) checkStatus(); }, POLL_MS);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) checkStatus(); });
  setInterval(() => { if (state.data && !document.hidden) { renderLive(); renderFeed(); } }, 30_000);
}

async function checkStatus() {
  try {
    const res = await fetch("/api/status", { cache: "no-store" });
    if (!res.ok) throw new Error(String(res.status));
    state.status = await res.json();
  } catch {
    state.status = { offline: true };
  }
  renderLive();
  const v = state.status.version;
  if (v && state.data && v !== state.data.generated_at) await liveReload();
}

function renderLive() {
  const s = state.status || {};
  const mins = s.last_check ? (Date.now() - Date.parse(s.last_check)) / 60000 : Infinity;
  const ok = !s.offline && s.check_ok !== false && mins <= STALE_MIN;
  const el = $("#live");
  el.dataset.state = ok ? "ok" : s.offline || s.last_check ? "late" : "wait";
  $("#liveText").textContent = ok
    ? t("Live, Microsoft checked {ago}", { ago: timeAgo(s.last_check) })
    : s.offline ? t("Offline, retrying") : s.last_check ? t("Last check {ago}", { ago: timeAgo(s.last_check) }) : t("Connecting to Microsoft");
  el.title = s.msrc_last_update ? t("Microsoft last changed the Security Update Guide on {date}", { date: fmtDateTime(s.msrc_last_update) }) : "";

  $("#pending").hidden = !s.pending;
  if (s.pending) {
    const rel = (s.changed_releases || []).map(monthName).join(", ");
    $("#pendingText").textContent = rel
      ? t("Microsoft changed the {rel} release {ago}. Reading the changes now.", { rel, ago: timeAgo(s.last_msrc_change) })
      : t("Microsoft changed the Security Update Guide {ago}. Reading the changes now.", { ago: timeAgo(s.last_msrc_change) });
  }
}

async function liveReload() {
  const before = new Set(state.data.changes.map((c) => c.key));
  let fresh;
  try { fresh = await fetchData(); } catch { return; }
  const added = fresh.changes.filter((c) => !before.has(c.key));
  const keep = fresh.months.some((m) => m.id === state.month);
  state.data = fresh;
  if (!keep) state.month = fresh.months.at(-1)?.id;
  render();
  if (!added.length) return;

  const top = added.find((c) => c.kind === "exploited") || added.find((c) => c.kind === "kev") || added[0];
  const title = added.length === 1 ? t("Microsoft changed something") : t("Microsoft made {n} changes", { n: added.length });
  const body = `${KINDS[top.kind]?.label || t("Change")}: ${top.cve ? `${top.cve}, ` : ""}${top.title || changeDetail(top.detail)}`;
  toast(title, body);
  if (state.alerts && document.hidden) {
    try { new Notification(title, { body, icon: "/favicon.svg", tag: "mpm" }); } catch { /* ignore */ }
  }
  const followed = new Set(follows.list());
  const kbOf = (cve) => (fresh.cves.find((x) => x.cve === cve)?.updates || []).map((u) => `kb:${u.kb}`);
  const mine = added.filter((c) => c.cve && (followed.has(`cve:${c.cve}`) || kbOf(c.cve).some((k) => followed.has(k))));
  if (mine.length) {
    const t2 = t("Something you follow changed");
    const b2 = `${mine[0].cve}: ${KINDS[mine[0].kind]?.label || t("Change")}${mine.length > 1 ? t(" and {n} more", { n: mine.length - 1 }) : ""}`;
    toast(t2, b2);
    if (state.alerts) { try { new Notification(t2, { body: b2, icon: "/favicon.svg", tag: "mpm-follow" }); } catch { /* ignore */ } }
  }
  const keys = new Set(added.map((c) => c.key));
  const cves = new Set(added.map((c) => c.cve).filter(Boolean));
  $$("#feed li[data-key]").forEach((li) => keys.has(li.dataset.key) && li.classList.add("arrived"));
  $$("#table tr[data-cve]").forEach((tr) => cves.has(tr.dataset.cve) && tr.classList.add("arrived"));
}

function toast(title, body) {
  const box = document.createElement("div");
  box.className = "toast";
  setHTML(box, `<strong>${esc(title)}</strong><span>${esc(body)}</span>`);
  $("#toasts").append(box);
  setTimeout(() => box.remove(), 9000);
}

/* ------------------------------------------------------------------ views */
const isUnread = (c) => state.lastSeen ? c.detected_at > state.lastSeen : daysAgo(c.ts) <= 1;
const inMonth = () => state.data.cves.filter((c) => c.release === state.month);
const month = () => state.data.months.find((m) => m.id === state.month);

function render() {
  renderHero();
  renderRibbon();
  renderFigures();
  renderFeed();
  renderBars();
  renderTable();
  const sla = state.data.sla_days;
  $("#sla").textContent = t("Patch within {p1} days for P1, {p2} for P2, {p3} for P3 and {p4} for P4. A CISA deadline applies when it is earlier.",
    { p1: sla.P1, p2: sla.P2, p3: sla.P3, p4: sla.P4 });
  $("#updated").textContent = t("Data last processed on {date}.", { date: fmtDateTime(state.data.generated_at) });
}

function renderHero() {
  const m = month();
  const list = inMonth();
  const ex = list.filter((c) => c.exploited).length;
  const isLatest = m.id === state.data.months.at(-1).id;
  const name = cap(monthName(m.id).split(" ")[0]);
  const first = isLatest
    ? t("This month, Microsoft fixed {n} vulnerabilities.", { n: list.length })
    : t("In {month}, Microsoft fixed {n} vulnerabilities.", { month: MPM_LANG === "it" ? name.toLowerCase() : name, n: list.length });
  const second = ex === 0 ? t("None was exploited before the fix.")
    : ex === 1 ? t("One was already being exploited.") : t("{n} were already being exploited.", { n: words(ex) });
  $("#lede").textContent = `${first} ${second}`;
  const revised = m.updated_at && m.updated_at.slice(0, 16) !== m.released_at.slice(0, 16)
    ? " " + t("Microsoft last revised it on {date}.", { date: fmtDateTime(m.updated_at) }) : "";
  $("#byline").textContent = t("{month} release, published {date}.", { month: monthName(m.id), date: fmtLong(m.release_date) }) + revised;
}

function renderRibbon() {
  const months = state.data.months;
  const max = Math.max(...months.map((m) => m.total), 1);
  let prevYear = null;
  setHTML($("#ribbon"), months.map((m) => {
    const [y] = m.id.split("-");
    const label = cap(monthName(m.id).split(" ")[0].slice(0, 3));
    const year = y !== prevYear ? `<span class="yr">${esc(y)}</span>` : "";
    prevYear = y;
    const segs = SEVERITIES.map((s) => {
      const n = m.by_severity[s] || 0;
      return n ? `<span class="seg s-${s.toLowerCase()}" data-h="${((n / max) * 100).toFixed(2)}"></span>` : "";
    }).join("");
    const dots = m.exploited ? `<span class="ex" title="${te("{n} exploited", { n: m.exploited })}">${"<i></i>".repeat(Math.min(m.exploited, 6))}</span>` : "";
    const sel = m.id === state.month;
    return `<button type="button" data-month="${esc(m.id)}" aria-pressed="${sel}" tabindex="${sel ? 0 : -1}"
      aria-label="${te("{month}: {n} CVEs, {x} exploited", { month: cap(monthName(m.id)), n: m.total, x: m.exploited })}">
      <span class="stack">${segs}${dots}</span>
      <span class="mlabel">${esc(label)}${year}</span>
      <span class="mcount">${m.total}</span></button>`;
  }).join(""));
  applyVars($("#ribbon"));
}

function renderFigures() {
  const list = inMonth();
  const week = state.data.changes.filter((c) => c.kind !== "release" && daysAgo(c.ts) <= 7).length;
  const figs = [
    [t("fig|Critical"), list.filter((c) => c.severity === "Critical").length, "crit"],
    [t("Exploited in the wild"), list.filter((c) => c.exploited).length, "crit"],
    [t("In the CISA KEV catalog"), list.filter((c) => c.kev).length, "warn"],
    [t("To patch within 7 days"), list.filter((c) => c.priority === "P1").length, ""],
    [t("Changes by Microsoft this week"), week, "rev"],
  ];
  setHTML($("#figures"), figs.map(([label, n, cls]) =>
    `<div class="fig ${cls}"><dt>${esc(label)}</dt><dd>${n}</dd></div>`).join(""));

  const unread = state.data.changes.filter(isUnread).length;
  const line = $("#unreadLine");
  line.hidden = !unread;
  line.textContent = unread
    ? (unread === 1 ? t("1 change has arrived since your last visit.") : t("{n} changes have arrived since your last visit.", { n: unread })) : "";
}

function renderFeed() {
  const all = state.data.changes;
  setHTML($("#chips"), CHIPS.map((ch) => {
    const n = ch.kinds ? all.filter((c) => ch.kinds.includes(c.kind)).length : all.length;
    return `<button type="button" class="chip" data-chip="${ch.id}" aria-pressed="${state.chip === ch.id}">${esc(ch.label)} <span>${n}</span></button>`;
  }).join(""));

  const kinds = CHIPS.find((c) => c.id === state.chip)?.kinds;
  const items = all.filter((c) => !kinds || kinds.includes(c.kind)).slice(0, 120);
  setHTML($("#feed"), items.map((c) => {
    const k = KINDS[c.kind] || { label: c.kind };
    const unread = isUnread(c);
    const head = c.cve
      ? `<a href="/cve/${encodeURIComponent(c.cve)}">${esc(c.title || c.cve)}</a>`
      : `<span>${esc(c.kind === "release" ? `${cap(monthName(c.release))}: ${changeDetail(c.detail)}` : changeDetail(c.detail))}</span>`;
    const sub = c.cve ? `<span class="id">${esc(c.cve)}</span>${c.priority ? prioBadge(c.priority) : ""}` : "";
    return `<li class="k-${esc(c.kind)}${unread ? " unread" : ""}" data-key="${esc(c.key)}">
      <time datetime="${esc(c.ts)}" title="${esc(fmtDateTime(c.ts))}">${esc(timeAgo(c.ts))}</time>
      <div class="item">
        <p class="kind">${esc(k.label)}${c.kind === "revised" && c.rev ? te(", version {v}", { v: c.rev }) : ""}${unread ? `<span class="new">${te("New")}</span>` : ""}</p>
        <p class="what">${head}</p>
        ${c.cve && c.detail ? `<p class="detail"${["published", "revised"].includes(c.kind) && MPM_LANG === "it" ? ' lang="en"' : ""}>${esc(changeDetail(c.detail))}</p>` : ""}
        ${c.diff ? `<p class="badges">${diffBadges(c.diff)} <a class="see" href="/changes#${encodeURIComponent(`${c.cve}-${c.rev || ""}`)}">${te("See what changed")}</a></p>` : ""}
        ${sub ? `<p class="sub">${sub}</p>` : ""}
      </div></li>`;
  }).join("") || `<li class="empty">${te("Nothing of this type in the last 60 days.")}</li>`);
}

function renderBars() {
  const list = inMonth();
  const draw = (id, key) => {
    const m = new Map();
    list.forEach((c) => m.set(c[key], (m.get(c[key]) || 0) + 1));
    const rows = [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7);
    const max = rows[0]?.[1] || 1;
    setHTML($(id), rows.map(([label, n]) =>
      `<li><button type="button" data-filter="${esc(label)}"><span class="lbl">${esc(key === "impact" ? impactName(label) : label)}</span>
        <span class="track"><span class="fill" data-w="${((n / max) * 100).toFixed(2)}"></span></span>
        <span class="n">${n}</span></button></li>`).join(""));
    applyVars($(id));
  };
  draw("#impact", "impact");
  draw("#family", "family");
  $$(".hbars button").forEach((b) => b.addEventListener("click", () => {
    $("#q").value = b.dataset.filter;
    renderTable();
    $("#queue").scrollIntoView({ behavior: "smooth", block: "start" });
  }));
}

/* ------------------------------------------------------------------ table */
function filtered() {
  const q = $("#q").value.trim().toLowerCase();
  const sev = $("#sev").value, prio = $("#prio").value;
  const ex = $("#onlyExploited").checked, kev = $("#onlyKev").checked, ch = $("#onlyChanged").checked;
  const px = $("#onlyPublic")?.checked, mi = $("#onlyMitigation")?.checked;
  const rows = inMonth().filter((c) =>
    (!q || `${c.cve} ${c.title} ${c.family} ${c.impact} ${impactName(c.impact)}`.toLowerCase().includes(q)) &&
    (!sev || c.severity === sev) && (!prio || c.priority === prio) &&
    (!ex || c.exploited) && (!kev || c.kev) && (!ch || c.recent) && (!px || c.exploit) && (!mi || c.mitigations?.length));
  const k = state.sortKey, dir = state.sortDir;
  const val = (c) => k === "priority" ? PRIO_RANK[c.priority] * 10 - (c.epss || 0) : (c[k] ?? null);
  return rows.sort((a, b) => {
    const x = val(a), y = val(b);
    if (x === y) return 0;
    if (x === null) return 1;
    if (y === null) return -1;
    return (x > y ? 1 : -1) * dir;
  });
}

function renderTable() {
  const rows = filtered();
  const now = today();
  $$("th[data-k]").forEach((th) =>
    th.setAttribute("aria-sort", th.dataset.k === state.sortKey ? (state.sortDir > 0 ? "ascending" : "descending") : "none"));
  $("#count").textContent = t("{n} of {total} CVEs in the {month} release", { n: rows.length, total: inMonth().length, month: monthName(state.month) });
  setHTML($("#table tbody"), rows.slice(0, 400).map((c) => {
    const signals = [
      c.recent && `<span class="sig rev" title="${te("Revised {date}", { date: fmtDateTime(c.revised_at) })}">${te("Revised {ago}", { ago: timeAgo(c.revised_at) })}</span>`,
      c.exploited && `<span class="sig ex">${te("pill|Exploited")}</span>`,
      c.kev && `<span class="sig kev">CISA KEV${c.kev.ransomware ? te(", ransomware") : ""}</span>`,
      c.disclosed && `<span class="sig">${te("pill|Disclosed")}</span>`,
      c.exploit && exploitPill(),
      c.mitigations?.length && `<span class="sig rev" title="${te("Microsoft publishes a workaround or mitigation")}">${te("Mitigation")}</span>`,
    ].filter(Boolean).join("");
    const overdue = PRIO_RANK[c.priority] <= 2 && c.due < now;
    return `<tr data-cve="${esc(c.cve)}" class="${c.recent ? "recent" : ""}">
      <td>${prioBadge(c.priority)}</td>
      <td class="vuln"><a href="/cve/${encodeURIComponent(c.cve)}">${esc(c.title)}</a><span class="id">${esc(c.cve)}, ${esc(impactName(c.impact))}</span></td>
      <td>${esc(c.family)}</td>
      <td class="num">${c.cvss ?? "–"}</td>
      <td class="num">${c.epss != null ? (c.epss * 100).toFixed(1) + "%" : "–"}</td>
      <td class="sigs">${signals}</td>
      <td class="num${overdue ? " late" : ""}">${esc(fmtDate(c.due))}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="empty">${te("No CVE matches these filters. Clear the search or a filter to see more.")}</td></tr>`);
}

function exportCsv() {
  const cols = ["priority", "cve", "title", "release", "family", "impact", "severity", "cvss", "epss",
    "exploited", "disclosed", "kev", "public_exploit", "mitigations", "revision", "revised_at", "due"];
  // Neutralise spreadsheet formulas (CSV injection) and quote every cell.
  const cell = (v) => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return `"${s.replace(/"/g, '""')}"`;
  };
  const lines = [cols.join(",")].concat(filtered().map((c) =>
    cols.map((k) => cell(k === "kev" ? (c.kev ? c.kev.date_added : "") : k === "public_exploit" ? exploitSources(c.exploit)
      : k === "mitigations" ? (c.mitigations || []).length : c[k])).join(",")));
  const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(blob), download: `mpatchmonitor-${state.month}-${today()}.csv`,
  });
  a.click();
  URL.revokeObjectURL(a.href);
}

window.MPM = { checkNow: checkStatus };
